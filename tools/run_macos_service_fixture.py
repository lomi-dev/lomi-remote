#!/usr/bin/env python3
"""Bounded E0 native LaunchAgent and synthetic private file-keychain proof.

Only --run-native registers the ephemeral user-domain service and runs storage.
Never installs a LaunchDaemon or changes a default keychain/search list.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import signal
import shutil
import socket
import sys
import tempfile
import time
import uuid

from owned_process import initialize_process_ownership, run_owned

ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = ROOT / "artifacts/services-macos"
OWNER = ROOT / "target/debug/lomi-service-fixture"
STORAGE = ROOT / "target/debug/lomi-macos-storage-fixture"
ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"}


def launchagent(label, binary, state):
    if not label.startswith("dev.lomi.e0.") or not Path(binary).is_absolute() or not Path(state).is_absolute():
        raise ValueError("private fixture arguments required")
    return {"Label": label, "ProgramArguments": [str(binary), "owner", str(state)],
            "RunAtLoad": False, "KeepAlive": False, "ExitTimeOut": 10,
            "LimitLoadToSessionType": "Background",
            "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null",
            "EnvironmentVariables": ENV, "Umask": 0o077}


def ipc(state, request, timeout=2):
    if request not in {"status", "start", "resize", "after-detach", "ctrl-c", "exit"}:
        raise ValueError("unsupported synthetic request")
    deadline = time.monotonic() + timeout

    def remaining():
        budget = deadline - time.monotonic()
        if budget <= 0:
            raise TimeoutError("ipc_deadline_exceeded")
        return budget

    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(remaining())
        client.connect(str(state / "fixture.sock"))
        client.settimeout(remaining())
        client.sendall(request.encode("ascii") + b"\n")
        data = bytearray()
        while len(data) <= 8192:
            client.settimeout(remaining())
            chunk = client.recv(8193 - len(data))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > 8192:
            raise RuntimeError("bounded_reply_exceeded")
    remaining()
    result = json.loads(data)
    if not result.get("fixture") or "error" in result:
        raise RuntimeError("fixture_request_rejected")
    remaining()
    return result


def wait_for(probe, predicate, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = probe(deadline - time.monotonic())
            if time.monotonic() < deadline and predicate(result) and time.monotonic() < deadline:
                return result
        except (OSError, ValueError):
            pass
        time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    raise RuntimeError("fixture_deadline_exceeded")


def process_rows(timeout=3):
    # Do not inspect argv/environment or signal adopted numeric PIDs.
    result = run_owned(["/bin/ps", "-axo", "pid=,ppid=,pgid=,stat="], env=ENV, timeout=min(3, timeout))
    if result.returncode:
        raise RuntimeError("process_snapshot_failed")
    return {int(p): (int(parent), int(group), state) for p, parent, group, state in
            (line.split() for line in result.stdout.splitlines())}


def groups_gone(groups, timeout=3):
    return not any(group in groups and not state.startswith("Z")
                   for parent, group, state in process_rows(timeout).values())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def native_proof():
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    label = "dev.lomi.e0." + uuid.uuid4().hex
    domain = "user/" + str(os.getuid())
    target = domain + "/" + label
    private = None
    report = {"fixture": True, "qualifiedProductHost": False, "label": label,
              "domain": domain, "operations": [], "checks": [],
              "unqualified": ["LaunchDaemon", "before-login", "reboot", "FileVault", "locked-user-keychain", "production-secret-provider"],
              "resourcesPreserved": True, "passed": False}
    groups = set()
    owners = set()
    registered = False
    storage_cleanup_verified = True

    def save():
        temporary = ARTIFACTS / (label + ".json.tmp")
        temporary.write_text(json.dumps(report, indent=2) + "\n")
        os.replace(temporary, ARTIFACTS / (label + ".json"))
        temporary.write_text(json.dumps(report, indent=2) + "\n")
        os.replace(temporary, ARTIFACTS / "evidence.json")

    def invoke(name, argv, timeout=15, require=True):
        op = {"id": name, "command": [str(a) for a in argv], "exitCode": None}
        report["operations"].append(op)
        save()
        result = run_owned(op["command"], env=ENV, timeout=timeout)
        op["exitCode"] = result.returncode
        if name == "native_private_locked_storage" and result.returncode:
            # Fixture errors contain fixed identifiers and OSStatus only.
            op["fixtureError"] = result.stderr.strip()[:256]
        save()
        if require and result.returncode:
            raise RuntimeError(name)
        return result

    def check(name, condition):
        report["checks"].append({"id": name, "passed": bool(condition)})
        save()
        if not condition:
            raise RuntimeError(name)

    def status(timeout=2):
        return ipc(state, "status", timeout=min(2, timeout))

    def capture(st):
        rows = process_rows()
        owner, child, worker = st["ownerPid"], st["childPid"], st["stats"]["workerPid"]
        check("launchd_owned_process_tree", owner in rows and rows[owner][0] == 1
              and child in rows and rows[child][:2] == (owner, child)
              and worker in rows and rows[worker][1] == child)
        owners.add(owner)
        groups.add(child)
        report.setdefault("observedOwnerPids", []).append(owner)
        report.setdefault("observedChildGroups", []).append(child)
        save()

    def bootstrap():
        nonlocal registered
        # Mark uncertain registration before invoking, so timeout still bootouts.
        registered = True
        invoke("launchctl_bootstrap", ["/bin/launchctl", "bootstrap", domain, plist])
        invoke("launchctl_kickstart", ["/bin/launchctl", "kickstart", target])
        return wait_for(status, lambda st: st["state"] in {"idle", "lost"})

    def bootout():
        nonlocal registered
        result = invoke("launchctl_bootout", ["/bin/launchctl", "bootout", target], require=False)
        # launchctl print is read only; failure expected after successful removal.
        absent = wait_for(
            lambda budget: invoke("launchctl_verify_absent", ["/bin/launchctl", "print", target], timeout=budget, require=False),
            lambda result: result.returncode == 113)
        check("launchagent_removed", result.returncode == 0 and absent.returncode == 113)
        wait_for(lambda budget: groups_gone(groups, budget), bool)
        check("owned_groups_gone", groups_gone(groups))
        wait_for(process_rows, lambda rows: not any(pid in rows and not rows[pid][2].startswith("Z") for pid in owners))
        check("owner_processes_gone", all(pid not in process_rows() for pid in owners))
        registered = False

    save()
    try:
        private = Path(tempfile.mkdtemp(prefix="lomi-e0-mac-", dir="/tmp"))
        report["privateDirectoryCreated"] = True
        private = private.resolve()
        owner_binary = private / "lomi-service-fixture"
        storage_binary = private / "lomi-macos-storage-fixture"
        for source, destination in [(OWNER, owner_binary), (STORAGE, storage_binary)]:
            before_copy = sha(source)
            shutil.copy2(source, destination)
            if sha(source) != before_copy or sha(destination) != before_copy:
                raise RuntimeError("fixture_binary_changed_during_copy")
        state = private / "state"
        state.mkdir(mode=0o700)
        plist = private / "agent.plist"
        plist.write_bytes(plistlib.dumps(launchagent(label, owner_binary, state)))
        plist.chmod(0o600)
        save()
        report["versions"] = {
            "macOS": invoke("version_macos", ["/usr/bin/sw_vers"]).stdout.strip(),
            "kernel": invoke("version_kernel", ["/usr/bin/uname", "-mrs"]).stdout.strip(),
            "rustc": invoke("version_rustc", [str(Path.home() / ".cargo/bin/rustc"), "--version"]).stdout.strip(),
            "python": sys.version.split()[0],
            "sdkHeaders": json.loads((Path(invoke("sdk_path", ["/usr/bin/xcrun", "--show-sdk-path"]).stdout.strip()) / "SDKSettings.json").read_text())["Version"]}
        paths = [Path(__file__), OWNER, STORAGE, ROOT / "Cargo.lock"]
        paths += sorted((ROOT / "crates/lomi-macos-storage-fixture").rglob("*.rs"))
        paths += sorted((ROOT / "crates/lomi-service-fixture").rglob("*.rs"))
        report["sha256"] = {str(p.relative_to(ROOT)): sha(p) for p in paths}
        report["isolatedBinarySha256"] = {"owner": sha(owner_binary), "storage": sha(storage_binary)}
        initial = bootstrap()
        check("initial_idle_no_session", initial["state"] == "idle" and initial["requiresExplicitStart"])
        ipc(state, "start")
        first = wait_for(status, lambda st: st["stats"]["ready"] and st["stats"]["workerPid"] is not None)
        capture(first)
        # Distinct process clients each connect and exit; owner outlives both.
        for number in (1, 2):
            client = json.loads(invoke("ipc_client_" + str(number), [owner_binary, "client", state, "status"]).stdout)
            check("client_same_owner_" + str(number), client["ownerEpoch"] == first["ownerEpoch"])
        ipc(state, "resize")
        resized = wait_for(status, lambda st: st["stats"]["resizeObserved"])
        check("native_resize_and_model", resized["modelRows"] == 37 and resized["modelCols"] == 101)
        ipc(state, "after-detach")
        wait_for(status, lambda st: st["stats"]["detachObserved"])
        check("detached_clients_preserve_session", status()["sessionEpoch"] == first["sessionEpoch"])
        ipc(state, "ctrl-c")
        stopped = wait_for(status, lambda st: st["stats"]["ctrlCObserved"] and st["stats"]["cleanupComplete"])
        check("ctrl_c_exit_cleanup", stopped["state"] == "exited" and stopped["stats"]["exitCode"] == 0)
        ipc(state, "start")
        active = wait_for(status, lambda st: st["stats"]["ready"] and st["stats"]["workerPid"] is not None)
        capture(active)
        ipc(state, "after-detach")
        wait_for(status, lambda st: st["stats"]["detachObserved"])
        bootout()
        restarted = bootstrap()
        check("restart_lost_explicit_start", restarted["state"] == "lost" and restarted["requiresExplicitStart"]
              and restarted["sessionEpoch"] == active["sessionEpoch"] and restarted["stats"] is None
              and restarted["ownerEpoch"] != active["ownerEpoch"])
        rejected = invoke("reject_input_in_lost_session", [owner_binary, "client", state, "after-detach"], require=False)
        check("lost_input_rejected", rejected.returncode != 0)
        ipc(state, "start")
        fresh = wait_for(status, lambda st: st["stats"]["ready"] and st["stats"]["workerPid"] is not None)
        capture(fresh)
        check("no_input_replay", fresh["sessionEpoch"] != active["sessionEpoch"]
              and fresh["stats"]["inputWrites"] == 0 and not fresh["stats"]["detachObserved"])
        ipc(state, "exit")
        exited = wait_for(status, lambda st: st["stats"]["cleanupComplete"])
        check("explicit_exit_cleanup", exited["state"] == "exited" and exited["stats"]["exitCode"] == 0)
        bootout()
        storage_cleanup_verified = False
        storage = invoke("native_private_locked_storage", [storage_binary, "--synthetic-private-keychain", private], timeout=20)
        report["storage"] = json.loads(storage.stdout)
        storage_cleanup_verified = report["storage"].get("keychainDeleted") is True
        check("locked_storage_fail_closed", report["storage"]["lockedOSStatus"] in {-25293, -25308}
              and report["storage"]["defaultAndSearchListUnchanged"] and report["storage"]["keychainDeleted"])
        report["passed"] = True
    except BaseException as error:
        report["failureClass"] = type(error).__name__
        if isinstance(error, RuntimeError):
            report["failureId"] = str(error)[:128]
        report["passed"] = False
    finally:
        if registered:
            try:
                bootout()
            except BaseException as error:
                report["cleanupFailureClass"] = type(error).__name__
                report["passed"] = False
        report["storageCleanupVerified"] = storage_cleanup_verified
        try:
            if not registered and storage_cleanup_verified and (not groups or groups_gone(groups)):
                if private is not None:
                    shutil.rmtree(private)
                report["resourcesPreserved"] = False
                report["privateDirectoryRemoved"] = private is None or not private.exists()
            else:
                report["passed"] = False
        except BaseException as error:
            report["cleanupFailureClass"] = type(error).__name__
            report["passed"] = False
        finally:
            if report["resourcesPreserved"] and private is not None:
                report["preservedPrivateDirectory"] = str(private)
            save()
    return 0 if report["passed"] else 1


def main():
    initialize_process_ownership()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-native", action="store_true")
    args = parser.parse_args()
    if not args.run_native or sys.platform != "darwin":
        parser.error("native macOS and explicit --run-native are required")
    for binary in (OWNER, STORAGE):
        if not binary.is_file():
            parser.error("build both native fixture crates first")
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    return native_proof()


if __name__ == "__main__":
    raise SystemExit(main())
