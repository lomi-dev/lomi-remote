#!/usr/bin/env python3
"""Source-bound integrated PTY proof for the default-off Mac coalition backend."""
import argparse
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time
import uuid

import build
from build import BuildRejected, MINIMAL, freeze_build, sha, verify
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from owned_process import initialize_process_ownership, run_owned, signal_group, stop_group

REPOSITORY = Path(__file__).resolve().parents[2]
BASE = Path.home() / ".lomi-pty-build"
RUNTIME = Path.home() / ".lomi-pty"


def private_base(path):
    path.mkdir(mode=0o700, exist_ok=True)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise RuntimeError("private_base_required")


def save(root, name, value):
    temporary = root / (name + ".tmp")
    with temporary.open("w") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, root / name)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def recover(binary, runtime, timeout=12):
    deadline = time.monotonic() + timeout
    while True:
        result = run_owned([str(binary), "recover", str(runtime)], env=MINIMAL, timeout=10)
        if result.returncode == 0:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError("owned_generation_recovery_uncertain: " + str(runtime))
        time.sleep(0.05)


def audit(root, binary, runtime, scenario):
    generations = runtime / "Library/Application Support/LomiRemote/pty-generations"
    records = []
    if not generations.is_dir():
        raise RuntimeError("product_generation_missing")
    for folder in generations.iterdir():
        if folder.name != str(uuid.UUID(folder.name)) or folder.is_symlink():
            raise RuntimeError("unexpected_generation_directory")
        record = json.loads((folder / "journal.json").read_text())
        if record["run"] != folder.name or record["stage"] != "Cleaned" or record.get("drained") is not True or record.get("disposed") is not True or record.get("leaderReaped") is not True or not record.get("controller"):
            raise RuntimeError("product_cleanup_proof_missing")
        namespace = Path("/private/tmp") / ("lomi-pty-" + str(os.geteuid()) + "-" + folder.name)
        if record.get("runtimeRemoved") is not True or namespace.exists() or namespace.is_symlink():
            raise RuntimeError("exact_socket_namespace_remains")
        label = "dev.lomi.pty." + folder.name.replace("-", "")
        domain = "user/" + str(os.geteuid())
        observed = run_owned(["/bin/launchctl", "print", domain + "/" + label], env=MINIMAL, timeout=5)
        if observed.returncode != 113 or (folder / "job.plist").exists() or (folder / "s").exists():
            raise RuntimeError("exact_product_job_or_registration_remains")
        override = run_owned(["/bin/launchctl", "print-disabled", domain], env=MINIMAL, timeout=5)
        # Never retain launchctl output: it may include unrelated environment.
        if override.returncode or any(line.strip().startswith('"' + label + '" => ') for line in override.stdout.splitlines()):
            raise RuntimeError("exact_label_override_changed")
        serialized = (folder / "journal.json").read_bytes()
        if b"never-persist-this-fixture-value" in serialized or b"--workload" in serialized or b"LOMI_FIXTURE_PROTECTED" in serialized:
            raise RuntimeError("protected_spawn_payload_persisted")
        replay = run_owned([str(binary), "--internal-pty-coalition", str(folder)], env=MINIMAL, timeout=5)
        if replay.returncode != 1 or (folder / "journal.json").read_bytes() != serialized:
            raise RuntimeError("retired_generation_replay_not_refused")
        destination = root / (scenario + "-" + folder.name + ".journal.json")
        destination.write_bytes(serialized)
        destination.chmod(0o600)
        records.append({"run": folder.name, "label": label, "domain": domain,
                        "controller": record["controller"], "lifetime": record["lifetime"],
                        "journalSha256": sha(destination), "journal": destination.name,
                        "cleanupConfirmed": True, "retiredControllerReplay": "refused", "job": "absent", "plist": "absent", "socket": "absent", "override": None, "socketNamespace": "absent", "profilePathLength": len(str(runtime / "Library/Application Support/LomiRemote"))})
    if not records:
        raise RuntimeError("no_actual_product_generation")
    # Demonstrate teardown-only recovery is idempotent; it never grants G.
    recover(binary, runtime)
    return records


def remove_owned_runtime(runtime):
    for folder, directories, files in os.walk(runtime, topdown=False, followlinks=False):
        parent = Path(folder)
        for name in files:
            path = parent / name
            metadata = path.lstat()
            allowed = name in {"journal.json", "journal.lock", "owner.lock", "controller.lock", "pty-operations.lock", "ordinary.pid", "ordinary.heartbeat", "leaf.ready", "fence.rejected", "host.ready", "host.stopped"}
            if not allowed or not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1:
                raise RuntimeError("unknown_owned_runtime_entry")
            path.unlink()
        for name in directories:
            path = parent / name
            metadata = path.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or (name not in {"Library", "Application Support", "LomiRemote", "pty-generations"} and name != str(uuid.UUID(name))):
                raise RuntimeError("unknown_owned_runtime_directory")
            path.rmdir()
    runtime.rmdir()


def native(root):
    receipt = verify(root)
    binary = root / "bin/pty-fixture"
    private_base(RUNTIME)
    report = {"passed": False, "cleanupConfirmed": False, "qualifiedProductRelease": False,
              "experimentalFeature": "experimental-macos-coalition-cleanup", "binarySha256": receipt["binarySha256"],
              "buildReceiptSha256": sha(root / "build-receipt.json"), "cases": [], "runtimeRoots": []}
    save(root, "native-evidence.json", report)
    sentinel_root = root / "sentinel"
    sentinel_root.mkdir(mode=0o700)
    sentinel = subprocess.Popen([str(binary), "--workload", str(sentinel_root), "sentinel"], env=MINIMAL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    owned_host = None
    try:
        deadline = time.monotonic() + 3
        while not (sentinel_root / "sentinel.heartbeat").exists():
            if time.monotonic() >= deadline:
                raise RuntimeError("manual_sentinel_unready")
            time.sleep(0.005)
        for scenario in ("stop", "host-eof", "leader-exit", "escaped-leader-exit", "fence-reject"):
            runtime = RUNTIME / uuid.uuid4().hex[:16]
            runtime.mkdir(mode=0o700)
            report["runtimeRoots"].append(str(runtime))
            save(root, "native-evidence.json", report)  # Durable intent before any job effect.
            before = int((sentinel_root / "sentinel.heartbeat").read_text())
            started_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
            if scenario != "host-eof":
                result = run_owned([str(binary), scenario, str(runtime)], env=MINIMAL, timeout=20)
                (root / (scenario + ".stdout.log")).write_text(result.stdout)
                (root / (scenario + ".stderr.log")).write_text(result.stderr)
                if result.returncode or (scenario == "fence-reject" and (not (runtime / "fence.rejected").exists() or (runtime / "ordinary.pid").exists())) or (scenario != "fence-reject" and (not (runtime / "host.ready").exists() or not (runtime / "host.stopped").exists())):
                    raise RuntimeError("actual_pty_stop_failed")
            else:
                owned_host = subprocess.Popen([str(binary), "host-eof", str(runtime)], env=MINIMAL,
                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
                deadline = time.monotonic() + 10
                while not (runtime / "host.ready").exists():
                    status = os.waitid(os.P_PID, owned_host.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    if status is not None or time.monotonic() >= deadline:
                        raise RuntimeError("actual_pty_host_unready")
                    time.sleep(0.005)
                signal_group(owned_host, signal.SIGKILL)  # Exact retained host, never a launchd/workload PID.
                stdout, stderr = owned_host.communicate(timeout=5)
                (root / "host-eof.stdout.log").write_text(stdout)
                (root / "host-eof.stderr.log").write_text(stderr)
                if owned_host.returncode != -signal.SIGKILL:
                    raise RuntimeError("owned_host_death_unconfirmed")
                owned_host = None
                recover(binary, runtime)
            completed_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
            proactive = None
            if scenario in {"leader-exit", "escaped-leader-exit"}:
                leaf = json.loads((runtime / "leaf.ready").read_text())
                proactive = {"caseStartedNs": started_ns, "cleanupCompletedNs": completed_ns,
                             "leafArmedAtNs": leaf["armedAtNs"], "leafDeadlineNs": leaf["deadlineNs"],
                             "cleanupBeforeSelfExpiry": completed_ns < leaf["deadlineNs"] - 1_000_000_000}
                if not proactive["cleanupBeforeSelfExpiry"] or completed_ns - started_ns >= 3_000_000_000:
                    raise RuntimeError("proactive_cleanup_before_leaf_expiry_unproven")
            records = audit(root, binary, runtime, scenario)
            time.sleep(0.05)
            status = os.waitid(os.P_PID, sentinel.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if status is not None or int((sentinel_root / "sentinel.heartbeat").read_text()) <= before:
                raise RuntimeError("unrelated_same_uid_sentinel_changed")
            remove_owned_runtime(runtime)
            report["cases"].append({"scenario": scenario, "actualPtyOutputObserved": scenario != "fence-reject", "cleanupConfirmed": True,
                                    "unrelatedSameUidSentinelSurvived": True, "runtimeProfile": "removed", "proactiveCleanup": proactive, "generations": records})
            save(root, "native-evidence.json", report)
        report["passed"] = True
    finally:
        if owned_host is not None and owned_host.returncode is None:
            stop_group(owned_host)
        if sentinel.returncode is None:
            stop_group(sentinel)
        cleanup = True
        for path in report["runtimeRoots"]:
            runtime = Path(path)
            if runtime.exists():
                try:
                    recover(binary, runtime)
                    audit(root, binary, runtime, "recovery")
                    remove_owned_runtime(runtime)
                except BaseException:
                    cleanup = False
        verify(root)
        report["cleanupConfirmed"] = cleanup and sentinel.returncode is not None
        report["passed"] = report["passed"] and report["cleanupConfirmed"]
        save(root, "native-evidence.json", report)
        print(root / "native-evidence.json")
    return report["passed"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-native", action="store_true")
    parser.add_argument("--frozen-run", type=Path)
    args = parser.parse_args()
    if not args.run_native or sys.platform != "darwin":
        parser.error("explicit --run-native on macOS required")
    initialize_process_ownership()
    if args.frozen_run:
        return 0 if native(args.frozen_run) else 1
    private_base(BASE)
    root = BASE / str(uuid.uuid4())
    root.mkdir(mode=0o700)
    print("Controlled build: " + str(root), flush=True)
    freeze_build(REPOSITORY, root)
    verify(root)
    try:
        result = run_owned([sys.executable, "-B", str(root / "inputs/tests/product-pty-macos/run_native.py"), "--run-native", "--frozen-run", str(root)], env=MINIMAL, timeout=90)
        (root / "native-driver.stdout.log").write_text(result.stdout)
        (root / "native-driver.stderr.log").write_text(result.stderr)
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        return result.returncode
    finally:
        # An outer timeout/interrupt cannot abandon launchd-owned resources.
        journal = root / "native-evidence.json"
        if journal.exists():
            report = json.loads(journal.read_text())
            binary = root / "bin/pty-fixture"
            for path in report["runtimeRoots"]:
                runtime = Path(path)
                if runtime.parent != RUNTIME or not re_runtime(runtime.name):
                    raise RuntimeError("outer_recovery_root_invalid")
                if runtime.exists():
                    recover(binary, runtime)
                    audit(root, binary, runtime, "outer-recovery")
                    remove_owned_runtime(runtime)


def re_runtime(name):
    return len(name) == 16 and all(character in "0123456789abcdef" for character in name)


if __name__ == "__main__":
    sys.exit(main())
