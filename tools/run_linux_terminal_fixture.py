#!/usr/bin/env python3
"""Run the synthetic Vim PTY proof inside the dedicated disposable Lima VM."""
import hashlib
import io
import inspect
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import time
import uuid

from owned_process import initialize_process_ownership, run_owned
from source_manifest import source_inventory

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts/terminal-linux"
LIMA = "/opt/homebrew/bin/limactl"
VM = "lomi-e0"


def cleanup_owned_unit(unit, run=None, cgroup_root="/sys/fs/cgroup"):
    """Fail closed unless the exact synthetic unit and all its cgroups are empty."""
    import os
    from pathlib import Path
    import re
    import subprocess

    if not re.fullmatch(r"lomi-pty-proof-[0-9a-f]{32}\.service", unit):
        raise RuntimeError("invalid fixture unit")
    if run is None:
        run = subprocess.run
    properties = ("LoadState", "ActiveState", "SubState", "ControlGroup")

    def query():
        result = run(["systemctl", "show", unit,
                      *["--property=" + key for key in properties]],
                     capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            raise RuntimeError("unit query failed")
        values = {}
        for line in result.stdout.splitlines():
            key, separator, value = line.partition("=")
            if not separator or key not in properties or key in values:
                raise RuntimeError("invalid unit query")
            values[key] = value
        if set(values) != set(properties):
            raise RuntimeError("incomplete unit query")
        if values["LoadState"] not in ("loaded", "not-found"):
            raise RuntimeError("uncertain unit load state")
        if values["LoadState"] == "not-found" and (
                values["ActiveState"] != "inactive" or values["SubState"] != "dead"
                or values["ControlGroup"]):
            raise RuntimeError("inconsistent absent unit")
        return values

    before = query()
    paths = {"/system.slice/" + unit}
    if before["LoadState"] == "loaded":
        stopped = run(["systemctl", "stop", unit], capture_output=True, text=True, timeout=10)
        if stopped.returncode != 0:
            raise RuntimeError("unit stop failed")
        after = query()
    else:
        after = before
    if after["ActiveState"] != "inactive" or after["SubState"] != "dead":
        raise RuntimeError("unit did not stop")
    for state in (before, after):
        group = state["ControlGroup"]
        if group:
            if group != "/system.slice/" + unit:
                raise RuntimeError("invalid control group")
            paths.add(group)
    checked = 0
    for group in sorted(paths):
        path = Path(cgroup_root) / group.lstrip("/")
        # An ENOENT after the successful state query means systemd removed this
        # cgroup. Other traversal/read failures remain errors, never empty proof.
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        if path.is_symlink() or not path.is_dir():
            raise RuntimeError("invalid cgroup directory")

        def fail(error):
            raise error

        for directory, subdirs, _ in os.walk(path, onerror=fail, followlinks=False):
            if any((Path(directory) / child).is_symlink() for child in subdirs):
                raise RuntimeError("unexpected cgroup symlink")
            members = (Path(directory) / "cgroup.procs").read_text().split()
            if members:
                raise RuntimeError("cgroup still has members")
            checked += 1
    return {"queryVerified": True, "unitAbsent": after["LoadState"] == "not-found",
            "stopVerified": before["LoadState"] == "loaded", "cgroupsChecked": checked,
            "descendantCgroupsEmpty": True}


def main():
    initialize_process_ownership()
    run_id = uuid.uuid4().hex
    guest = "/home/lomi-e0/lomi-pty-source-" + run_id
    unit = "lomi-pty-proof-" + run_id + ".service"
    env = {key: os.environ[key] for key in ("HOME", "PATH", "TMPDIR") if key in os.environ}
    env.update(LIMA_HOME=str(ROOT / "artifacts/lima"), LANG="C", TERM="dumb")
    report = {"kind": "native-linux-interactive-terminal", "runId": run_id,
              "qualified": False, "complete": False, "passed": False, "checks": [],
              "controller": platform.platform(), "not_run": ["Windows", "multi-hour soak", "arbitrary CLI compatibility"]}
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    evidence = ARTIFACTS / "evidence.json"
    fixture = ARTIFACTS / "synthetic-fixtures.json"
    fixture.unlink(missing_ok=True)
    unit_may_exist = False
    code = 1

    def save():
        evidence.write_text(json.dumps(report, indent=2) + "\n")

    def invoke(name, argv, timeout=180):
        check = {"name": name, "command": argv, "timeoutSeconds": timeout,
                 "exitCode": None, "status": "running"}
        report["checks"].append(check)
        save()
        started = time.monotonic()
        try:
            result = run_owned(argv, cwd=ROOT, env=env, timeout=timeout)
            check.update(exitCode=result.returncode, status="passed" if result.returncode == 0 else "failed")
            if result.returncode:
                raise RuntimeError(name)
            return result.stdout
        finally:
            check["durationSeconds"] = round(time.monotonic() - started, 3)
            save()

    def shell(name, argv, timeout=180):
        return invoke(name, [LIMA, "shell", "--workdir=/", VM, *argv], timeout)

    save()
    try:
        inventory = source_inventory(ROOT)
        report["sourceInventorySha256"] = inventory["digest"]
        archive = ARTIFACTS / "approved-source.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            for relative, expected in inventory["files"].items():
                data = (ROOT / relative).read_bytes()
                if hashlib.sha256(data).hexdigest() != expected:
                    raise RuntimeError("source changed during packing")
                entry = tarfile.TarInfo(relative)
                entry.size, entry.mode = len(data), 0o644
                output.addfile(entry, io.BytesIO(data))
        report["sourceArchiveSha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
        guest_archive = "/home/lomi-e0/lomi-pty-source-" + run_id + ".tar.gz"
        invoke("copy-approved-sources", [LIMA, "copy", str(archive), VM + ":" + guest_archive])
        extract = (
            "import pathlib,tarfile; p=pathlib.Path(" + repr(guest) + "); p.mkdir(); "
            "t=tarfile.open(" + repr(guest_archive) + "); "
            "assert all(m.isfile() and not pathlib.PurePosixPath(m.name).is_absolute() "
            "and '..' not in pathlib.PurePosixPath(m.name).parts for m in t.getmembers()); "
            "t.extractall(p,filter='data')"
        )
        shell("extract-approved-sources", ["python3", "-c", extract])
        shell("verify-installed-vim", ["test", "-x", "/usr/bin/vim"])
        shell("build-native-fixture", ["env", "CARGO_BUILD_JOBS=2", "CARGO_TARGET_DIR=/home/lomi-e0/lomi-pty-target",
              "/home/lomi-e0/.cargo/bin/cargo", "build", "--locked", "--manifest-path", guest + "/Cargo.toml", "-p", "lomi-terminal-pty-fixture"], 600)
        unit_may_exist = True
        observed = shell("interactive-vim-in-owned-cgroup", ["sudo", "-n", "systemd-run", "--quiet", "--wait", "--pipe", "--collect",
                         "--unit=" + unit, "--uid=lomi-e0", "--property=KillMode=control-group", "--property=RuntimeMaxSec=45s",
                         "--property=TimeoutStopSec=3s", "/home/lomi-e0/lomi-pty-target/debug/lomi-terminal-pty-fixture",
                         "--fixtures", guest + "/synthetic-fixtures.json"], 60)
        observation = json.loads(observed)
        if (observation.get("qualified") is not False or observation.get("cleanExit") is not True
                or observation.get("childGroupGone") is not True or observation.get("rawPtyClientWrites") != 0
                or observation.get("syntheticFixtureUnchanged") is not True or len(observation.get("milestones", [])) != 7):
            raise RuntimeError("incomplete native fixture result")
        report["observation"] = observation
        invoke("copy-synthetic-states", [LIMA, "copy", VM + ":" + guest + "/synthetic-fixtures.json", str(fixture)])
        aggregate = invoke("project-native-states", ["node", "tests/terminal-state/rust-oracle.mjs", str(fixture)])
        report["projection"] = aggregate.strip()
        versions = "import json,platform,subprocess; print(json.dumps({'os':platform.platform(),'rustc':subprocess.check_output(['/home/lomi-e0/.cargo/bin/rustc','--version'],text=True).strip()}))"
        report["environment"] = json.loads(shell("guest-versions", ["python3", "-c", versions]))
        code = 0
    except KeyboardInterrupt:
        report["errorClass"], code = "KeyboardInterrupt", 130
    except subprocess.TimeoutExpired:
        report["errorClass"], code = "TimeoutExpired", 124
    except Exception as error:
        report["errorClass"] = type(error).__name__
    finally:
        if unit_may_exist:
            # Embed the same tested helper; query errors can never become absence.
            cleanup = (inspect.getsource(cleanup_owned_unit)
                       + "\nimport json\nprint(json.dumps(cleanup_owned_unit(" + repr(unit) + ")))\n")
            try:
                report["cleanupObservation"] = json.loads(shell(
                    "verify-owned-cgroup-stopped", ["sudo", "-n", "python3", "-c", cleanup], 25))
            except BaseException as error:
                report["cleanupErrorClass"], code = type(error).__name__, 1
        report.update(exitCode=code, complete=code == 0, passed=code == 0)
        if code:
            fixture.unlink(missing_ok=True)
        save()
    print(f"Linux interactive fixture: {'passed' if code == 0 else 'incomplete'} (exit {code})", flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
