#!/usr/bin/env python3
"""Run bounded native isolation fixtures; never report production qualification."""
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import platform
import sys
import tarfile
import time
import uuid
from owned_process import initialize_process_ownership, run_owned
from source_manifest import source_inventory

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts/git-linux-isolation"
LIMA = "/opt/homebrew/bin/limactl"
VM = "lomi-e0"
ENV = {"HOME": str(Path.home()), "PATH": "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
       "LIMA_HOME": str(ROOT / "artifacts/lima"), "LC_ALL": "C", "TERM": "dumb"}


class NamespaceBlocked(Exception):
    pass


def finish_report(report, outcome, cleanup_profile, cleanup, save):
    if cleanup_profile:
        try:
            report["prerequisiteCleanup"] = cleanup()
        except BaseException as error:
            report["cleanupErrorClass"] = type(error).__name__
            outcome = 130 if isinstance(error, KeyboardInterrupt) else 1
    report["complete"] = outcome == 0
    save()
    return outcome


def main():
    initialize_process_ownership()
    if sys.platform != "darwin" or not Path(ENV["LIMA_HOME"]).is_dir():
        raise SystemExit("requires the existing disposable native ARM64 lomi-e0 VM")
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    for name in ("native-build.log","native-clippy.log","native-isolation-regressions.log"):
        (ARTIFACTS/name).unlink(missing_ok=True)
    run_token = uuid.uuid4().hex
    guest = "/home/lomi-e0/lomi-git-isolation-source/run-" + run_token
    report = {"kind": "native-linux-git-isolation-primitives", "qualified": False,
              "complete": False, "generatedAt": datetime.now(timezone.utc).isoformat(),
              "host": platform.platform(), "environment": ENV, "guestSource": guest,
              "operations": [], "isolationAcceptance": "not_run"}

    def save():
        (ARTIFACTS / "evidence.json").write_text(json.dumps(report, indent=2) + "\n")

    def invoke(name, argv, timeout=30):
        step = {"name": name, "argv": argv, "timeoutSeconds": timeout,
                "status": "running", "exitCode": None}
        report["operations"].append(step)
        save()
        started = time.monotonic()
        try:
            result = run_owned(argv, cwd=ROOT, env=ENV, timeout=timeout)
            step.update(exitCode=result.returncode,
                        status="passed" if result.returncode == 0 else "failed")
            if result.returncode:
                if name in {"native-build","native-clippy","native-isolation-regressions","native-owner-loss-and-namespace-assertions"}:
                    (ARTIFACTS/(name+".log")).write_text(result.stderr)
                raise RuntimeError(name)
            return result.stdout
        except BaseException as error:
            step["errorClass"]=type(error).__name__
            if step["status"]=="running": step["status"]="incomplete"
            raise
        finally:
            step["durationSeconds"] = round(time.monotonic() - started, 3)
            save()

    def shell(name, argv):
        return invoke(name, [LIMA, "shell", "--workdir=/", VM, "--", *argv])

    cleanup_profile = False
    outcome = 1
    try:
        inventory = source_inventory(ROOT)
        selected = {p:h for p,h in inventory["files"].items() if p in {"Cargo.toml","Cargo.lock","rust-toolchain.toml"} or p.startswith(("crates/","vendor/","tests/git-linux-isolation/"))}
        archive = ARTIFACTS / "approved-source.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for relative,digest in selected.items():
                data=(ROOT/relative).read_bytes()
                if hashlib.sha256(data).hexdigest()!=digest:
                    raise RuntimeError("approved source changed during transfer")
                entry=tarfile.TarInfo(relative);entry.size=len(data);entry.mode=0o644
                tar.addfile(entry,io.BytesIO(data))
        report["source"] = {"files": selected, "fileCount": len(selected)}
        remote = guest + ".tar.gz"
        shell("create-synthetic-parent", ["mkdir", "-p", "/home/lomi-e0/lomi-git-isolation-source"])
        invoke("transfer-only-approved-code", [LIMA, "copy", str(archive), VM + ":" + remote])
        extraction = ("import pathlib,tarfile; p=pathlib.Path(" + repr(guest) + "); p.mkdir(); "
            "t=tarfile.open(" + repr(remote) + "); "
            "assert all(m.isfile() and not pathlib.PurePosixPath(m.name).is_absolute() "
            "and '..' not in pathlib.PurePosixPath(m.name).parts for m in t.getmembers()); "
            "t.extractall(p,filter='data')")
        shell("extract-new-synthetic-source", ["python3", "-c", extraction])
        report["profileLifecycle"] = json.loads(shell(
            "native-profile-lifecycle-regressions",
            ["python3", guest + "/tests/git-linux-isolation/profile_lifecycle.py"]))
        profile_helper = guest + "/tests/git-linux-isolation/profile_prerequisite.py"
        report["prerequisiteInitial"] = json.loads(shell(
            "inspect-exact-dev-profile", ["python3", profile_helper, "inspect", run_token]))
        cleanup_profile = report["prerequisiteInitial"]["initiallyAbsent"]
        save()  # Durable ownership intent before prepare can install anything.
        report["prerequisite"] = json.loads(shell(
            "prepare-exact-dev-profile", ["python3", profile_helper, "prepare", run_token]))
        report["native"] = json.loads(shell("native-nonroot-primitives", ["env", "-i",
            "PATH=/usr/bin:/bin", "HOME=/nonexistent", "LC_ALL=C", "python3",
            guest + "/tests/git-linux-isolation/primitive_probe.py"]))
        if report["native"]["namespaceSetupBlocked"]:
            report["blocker"]="AppArmor denies nonroot namespace setup"
            raise NamespaceBlocked
        shell("create-private-build-dirs",["mkdir","-p",guest+"/cargo-home",guest+"/tmp"])
        shell("compile-native-ABI-assertions",["cc","-Wall","-Wextra","-Werror",guest+"/tests/git-linux-isolation/headers.c","-o",guest+"/header-probe"])
        shell("run-native-ABI-assertions",[guest+"/header-probe"])
        cargo=["env","CARGO_HOME="+guest+"/cargo-home","TMPDIR="+guest+"/tmp","/home/lomi-e0/.cargo/bin/cargo"]
        for command in ["build","clippy"]:
            argv=[*cargo,command,"--locked","--manifest-path",guest+"/Cargo.toml","-p","lomi-linux-git-isolation-spike"]
            if command=="clippy": argv.extend(["--","-D","warnings"])
            invoke("native-"+command,[LIMA,"shell","--workdir=/",VM,"--",*argv],600)
        binary=guest+"/target/debug/lomi-linux-git-isolation-spike"
        report["regressions"]=json.loads(invoke("native-isolation-regressions",[LIMA,"shell","--workdir=/",VM,"--",binary,"regression"],120))
        report["lifecycle"]=json.loads(invoke("native-owner-loss-and-namespace-assertions",[LIMA,"shell","--workdir=/",VM,"--","python3",guest+"/tests/git-linux-isolation/lifecycle.py",binary],40))
        report["isolationAcceptance"]="experimental-fixture-checks-complete"
        outcome = 0
    except BaseException as error:
        report["errorClass"] = type(error).__name__
        print("Linux Git isolation probe incomplete: " + type(error).__name__, file=sys.stderr)
        outcome = 130 if isinstance(error, KeyboardInterrupt) else 2 if isinstance(error, NamespaceBlocked) else 1
    finally:
        def cleanup():
            return json.loads(shell("cleanup-exact-dev-profile", [
                "python3", guest + "/tests/git-linux-isolation/profile_prerequisite.py",
                "cleanup", run_token]))
        outcome = finish_report(report, outcome, cleanup_profile, cleanup, save)
    if outcome == 0:
        print(json.dumps({"qualified": False,
            "checksPassed": report["regressions"]["checksPassed"], "complete": True}))
    return outcome


if __name__ == "__main__":
    raise SystemExit(main())
