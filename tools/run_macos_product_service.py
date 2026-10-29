#!/usr/bin/env python3
"""Disposable E1 product LaunchAgent proof; requires explicit --run-native.

Creates one UUID-owned artifact directory and one fresh per-profile label.
Never logs launchctl output/environment or changes existing LaunchAgents.
Does not qualify logout, before-login, reboot or full-session cleanup P1.
"""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pty
import re
import select
import shutil
import socket
import stat
import struct
import subprocess
import sys
import time
import termios
import uuid

from owned_process import initialize_process_ownership, run_owned, stop_group
from macos_service_build import controlled_build, verify_build, frozen_command

ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = Path.home() / ".lomi-service-artifacts"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stop_bound_runtime(profile, expected_runtime):
    """Fixture client: authenticate and stop one runtime on one connection."""
    directory = os.open(profile, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(directory)
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise RuntimeError("Unsafe fixture profile")
        fd = os.open("discovery.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        with os.fdopen(fd, "rb") as source:
            metadata = os.fstat(source.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1):
                raise RuntimeError("Unsafe fixture discovery")
            encoded = source.read(4097)
        if len(encoded) > 4096:
            raise RuntimeError("Oversized fixture discovery")
        discovery = json.loads(encoded)
        version = {"major": 1, "minor": 0}
        if discovery["runtimeId"] != expected_runtime or discovery["version"] != version:
            raise RuntimeError("Fixture runtime changed; preserve inputs")
        metadata = os.stat("host.sock", dir_fd=directory, follow_symlinks=False)
        if (not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise RuntimeError("Unsafe fixture socket")
        deadline = time.monotonic() + 15
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            def remaining():
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError("Bound runtime IPC deadline")
                channel.settimeout(left)

            def receive_exact(count):
                output = bytearray()
                while len(output) < count:
                    remaining()
                    part = channel.recv(count - len(output))
                    if not part:
                        raise RuntimeError("Bound runtime disconnected")
                    output.extend(part)
                return bytes(output)

            def receive():
                length = struct.unpack(">I", receive_exact(4))[0]
                if not 0 < length <= 1024 * 1024:
                    raise RuntimeError("Bound runtime frame limit")
                return json.loads(receive_exact(length))

            def send(value):
                payload = json.dumps(value, separators=(",", ":")).encode()
                remaining()
                channel.sendall(struct.pack(">I", len(payload)) + payload)

            remaining()
            channel.connect(str(profile / "host.sock"))
            peer_pid = struct.unpack("i", channel.getsockopt(0, 0x002, 4))[0]
            peer_uid = ctypes.c_uint()
            peer_gid = ctypes.c_uint()
            lib = ctypes.CDLL(None, use_errno=True)
            authenticated = lib.getpeereid(channel.fileno(), ctypes.byref(peer_uid), ctypes.byref(peer_gid)) == 0
            if not authenticated or peer_pid <= 0 or peer_uid.value != os.geteuid():
                raise RuntimeError("Fixture IPC owner mismatch")
            nonce = str(uuid.uuid4())
            send({"version": version, "profileId": discovery["profileId"], "nonce": nonce})
            hello = receive()
            expected = {"version": version, "profileId": discovery["profileId"],
                        "hostId": discovery["hostId"], "runtimeId": expected_runtime, "nonce": nonce}
            if hello != expected:
                raise RuntimeError("Fixture IPC binding mismatch")
            request_id = str(uuid.uuid4())
            send({"version": version, "requestId": request_id,
                  "call": {"method": "daemon.stop", "params": {"operatorIntent": "confirmed"}}})
            response = receive()
            if (response.get("version") != version or response.get("requestId") != request_id
                    or response.get("result") != {"Ok": {"type": "stopping", "value": {}}}):
                raise RuntimeError("Bound runtime stop unconfirmed")
    finally:
        os.close(directory)
    deadline = time.monotonic() + 15
    fd = os.open(profile / "owner.lock", os.O_RDWR | os.O_NOFOLLOW)
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("Bound runtime cleanup uncertain; preserve inputs")
                time.sleep(0.05)
    finally:
        os.close(fd)


def private_json(path, limit=32768):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1:
            raise RuntimeError("unsafe_recovery_record")
        encoded = source.read(limit + 1)
        if len(encoded) > limit:
            raise RuntimeError("oversized_recovery_record")
        return json.loads(encoded)


def recover_run(root):
    """Clean only this marked run after a failed/timed-out frozen child.

    Source mutation invalidates proof but must not prevent cleanup through the
    still byte-verified product. Uncertain manual identity preserves artifacts.
    """
    recovery = {"cleanupConfirmed": False}
    path = root / "outer-recovery.json"
    try:
        if root.parent != ARTIFACTS or root.is_symlink() or (root / ".fixture-marker").read_text() != str(uuid.UUID(root.name)):
            raise RuntimeError("unowned_recovery_run")
        receipt = json.loads((root / "build-receipt.json").read_text())
        binary = root / "bin/lomiremote"
        if not receipt.get("completed") or sha(binary) != receipt.get("binarySha256"):
            raise RuntimeError("recovery_binary_changed")
        environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"}
        profile = root / "s&"
        registration = profile / "service-registration-macos.json"
        report_path = root / "evidence.json"
        evidence = json.loads(report_path.read_text()) if report_path.exists() else {}
        label = evidence.get("label")
        if (root / "manual-runtime.json").exists():
            manual = private_json(root / "manual-runtime.json")
            if not manual.get("runtimeId"):
                raise RuntimeError("manual_start_identity_uncertain")
            lock = os.open(profile / "owner.lock", os.O_RDWR | os.O_NOFOLLOW)
            try:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    retired = True
                except BlockingIOError:
                    retired = False
            finally:
                os.close(lock)
            if not retired:
                stop_bound_runtime(profile, manual["runtimeId"])
            (root / "manual-runtime.json").unlink()
        if registration.exists():
            reg = private_json(registration)
            if reg.get("profile") != str(profile) or reg.get("executable") != str(binary) or not re.fullmatch(r"dev\.lomi\.remote\.[a-f0-9]{32}", reg.get("label", "")):
                raise RuntimeError("recovery_registration_changed")
            label = reg["label"]
            if reg.get("directory") != str(Path.home() / "Library/LaunchAgents"):
                raise RuntimeError("recovery_directory_changed")
            result = run_owned([str(binary), "--profile-dir", str(profile), "service", "uninstall"], env=environment, timeout=65)
            recovery["uninstallExit"] = result.returncode
            if result.returncode:
                raise RuntimeError("recovery_uninstall_uncertain")
        if label:
            if not re.fullmatch(r"dev\.lomi\.remote\.[a-f0-9]{32}", label):
                raise RuntimeError("recovery_label_changed")
            result = run_owned(["/bin/launchctl", "print", "gui/" + str(os.geteuid()) + "/" + label], env=environment, timeout=5)
            if result.returncode != 113 or (Path.home() / "Library/LaunchAgents" / (label + ".plist")).exists():
                raise RuntimeError("recovery_job_or_plist_remains")
        if profile.exists():
            descriptor = os.open(profile / "owner.lock", os.O_RDWR | os.O_NOFOLLOW)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(descriptor)
        observed = set(evidence.get("observedTreePids", []))
        deadline = time.monotonic() + 8
        while observed:
            result = run_owned(["/bin/ps", "-axo", "pid=,stat="], env=environment, timeout=3)
            if result.returncode:
                raise RuntimeError("recovery_tree_observation_failed")
            alive = {int(pid) for pid, state in (line.split() for line in result.stdout.splitlines()) if not state.startswith("Z")}
            if not observed & alive:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("recovery_tree_uncertain")
            time.sleep(0.05)
        recovery["cleanupConfirmed"] = True
    except BaseException as error:
        recovery["failureType"] = type(error).__name__
        raise
    finally:
        path.write_text(json.dumps(recovery, indent=2) + "\n")
        path.chmod(0o600)


def run_with_recovery(root, command, environment, timeout, runner=run_owned):
    try:
        result = runner(command, env=environment, timeout=timeout)
    except BaseException:
        recover_run(root)
        raise
    if result.returncode:
        recover_run(root)
    return result


def native(root):
    initialize_process_ownership()
    if sys.platform != "darwin" or root.parent != ARTIFACTS or root.is_symlink() or not root.is_dir():
        raise RuntimeError("native_owned_run_required")
    identifier = str(uuid.UUID(root.name))
    if (root / ".fixture-marker").read_text() != identifier or Path(__file__).resolve() != root / "inputs/tools/run_macos_product_service.py":
        raise RuntimeError("frozen_harness_identity_mismatch")
    verify_build(root)
    frozen = root / "bin/lomiremote"
    profile = root / "s&"
    project = root / "project"
    project.mkdir(mode=0o700)
    registration = profile / "service-registration-macos.json"
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "TERM": "xterm-256color"}
    report = {"runId": identifier, "binarySha256": sha(frozen), "harnessSha256": sha(Path(__file__)), "qualifiedSourceBuild": True,
              "buildReceiptSha256": sha(root / "build-receipt.json"),
              "inputManifestSha256": sha(root / "input-manifest.json"),
              "checks": [], "operations": [], "passed": False, "cleanupConfirmed": False,
              "qualification": "current-user Aqua domain; owned-group normal fixture only",
              "unqualified": ["actual-login", "logout", "reboot", "before-login", "full-session-cleanup-P1"]}
    manual_runtime = None
    checks_passed = False
    trees = set()
    target = None
    plist = None

    def save():
        temporary = root / "evidence.tmp"
        temporary.write_text(json.dumps(report, indent=2) + "\n")
        temporary.chmod(0o600)
        os.replace(temporary, root / "evidence.json")

    def check(name, condition):
        report["checks"].append({"id": name, "passed": bool(condition)})
        save()
        if not condition:
            report["failureCheck"] = name
            save()
            raise RuntimeError(name)

    def execute(name, argv, expected=0, timeout=65):
        report["operations"].append({"id": name, "exitCode": None})
        save()
        result = run_owned([str(arg) for arg in argv], env=environment, timeout=timeout)
        report["operations"][-1]["exitCode"] = result.returncode
        save()
        if expected is not None and result.returncode != expected:
            if target:
                observed = run_owned(["/bin/launchctl", "print", target], env=environment, timeout=5)
                report["failureManagerMetadata"] = [line.strip() for line in observed.stdout.splitlines()
                    if re.fullmatch(r"\t(?:state = [a-zA-Z0-9 _()/.-]{1,80}|pid = [0-9]+|last exit code = [0-9]+|last terminating signal = [A-Z0-9]+)", line)]
                probe = run_owned([str(frozen), "--profile-dir", str(profile), "status", "--json"], env=environment, timeout=3)
                report["failureStatusExit"] = probe.returncode
                report["failureProfileMetadata"] = [{"name": item.name, "mode": oct(stat.S_IMODE(item.lstat().st_mode)), "size": item.lstat().st_size} for item in profile.iterdir()]
                report["failureStatusCode"] = probe.stderr.strip() if re.fullmatch(r"[A-Z_]+", probe.stderr.strip()) else None
                save()
            report["fixedError"] = result.stderr.strip() if re.fullmatch(r"SERVICE_[A-Z_]+", result.stderr.strip()) else None
            save()
            raise RuntimeError(name + "_exit_" + str(result.returncode))
        return result

    def call(*args, expected=0):
        return execute("cli_" + "_".join(args[:2]), [frozen, "--profile-dir", profile, *args], expected).stdout

    def status():
        return json.loads(call("status", "--json"))["result"]["Ok"]["value"]

    def pane(workspace):
        return json.loads(call("terminal", "list", "--workspace", workspace, "--json"))["state"]["tabs"][0]["layout"]["pane"]

    def snapshot():
        result = execute("numeric_process_metadata", ["/bin/ps", "-axo", "pid=,ppid=,pgid=,stat="], timeout=3)
        return {int(pid): (int(parent), int(group), state) for pid, parent, group, state in
                (line.split() for line in result.stdout.splitlines())}

    def capture_tree():
        result = execute("manager_pid_observation", ["/bin/launchctl", "print", target], timeout=5)
        matches = re.findall(r"^\tpid = ([1-9][0-9]*)$", result.stdout, re.M)
        check("unique_manager_pid", len(matches) == 1)
        owner = int(matches[0])
        rows = snapshot()
        selected = {owner}
        while True:
            expanded = selected | {pid for pid, (parent, _, state) in rows.items()
                                   if parent in selected and not state.startswith("Z")}
            if expanded == selected:
                break
            selected = expanded
        trees.update(selected)
        report["observedTreePids"] = sorted(trees)
        save()
        return selected

    def gone(selected):
        deadline = time.monotonic() + 8
        while True:
            rows = snapshot()
            if not any(pid in rows and not rows[pid][2].startswith("Z") for pid in selected):
                return
            if time.monotonic() >= deadline:
                raise RuntimeError("owned_tree_cleanup_uncertain_preserve_inputs")
            time.sleep(0.1)

    def owner_free():
        fd = os.open(profile / "owner.lock", os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)

    def wait_runtime(previous):
        deadline = time.monotonic() + 18
        while time.monotonic() < deadline:
            result = execute("crash_readiness", [frozen, "--profile-dir", profile, "status", "--json"], expected=None, timeout=3)
            if result.returncode == 0:
                current = json.loads(result.stdout)["result"]["Ok"]["value"]
                if current["runtimeId"] != previous:
                    return current
            time.sleep(0.1)
        raise RuntimeError("crash_restart_deadline")

    def exit_view(workspace, pane_id):
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        child = subprocess.Popen([str(frozen), "--profile-dir", str(profile), "terminal", "attach",
                                  "--workspace", workspace, "--pane", pane_id], stdin=slave, stdout=slave,
                                 stderr=slave, env=environment, start_new_session=True)
        os.close(slave)
        try:
            deadline = time.monotonic() + 8
            received = False
            while time.monotonic() < deadline:
                if select.select([master], [], [], 0.1)[0]:
                    data = os.read(master, 65536)
                    if data:
                        received = True
                        break
                if child.poll() is not None:
                    break
            check("view_received_frame", received)
            os.write(master, b"\x1d")
            child.wait(timeout=5)
            check("view_exits_cleanly", child.returncode == 0)
        finally:
            if child.poll() is None:
                stop_group(child)
            os.close(master)

    save()
    try:
        call("service", "install", "--mode", "boot", "--account", str(os.geteuid()), expected=3)
        call("service", "install", "--mode", "login", "--account", str(os.geteuid() + 1), expected=3)
        check("unsupported_selection_no_profile", not profile.exists())
        call("service", "install", "--mode", "login", "--account", str(os.geteuid()))
        reg = json.loads(registration.read_text())
        check("exact_registration", reg["profile"] == str(profile) and reg["executable"] == str(frozen)
              and reg["mode"] == "login" and reg["label"].startswith("dev.lomi.remote."))
        target = "gui/" + str(os.geteuid()) + "/" + reg["label"]
        plist = Path(reg["directory"]) / (reg["label"] + ".plist")
        check("standard_launchagent_location", plist.parent == Path.home() / "Library/LaunchAgents")
        overrides = execute("exact_label_override_before", ["/bin/launchctl", "print-disabled", "gui/" + str(os.geteuid())], timeout=5)
        check("fresh_label_has_no_override", not any(line.strip().startswith('"' + reg["label"] + '" => ') for line in overrides.stdout.splitlines()))
        original_plist = plist.read_bytes()
        report["plistSha256"] = hashlib.sha256(original_plist).hexdigest()
        report["label"] = reg["label"]
        decoded = plistlib.loads(original_plist)
        check("fixed_literal_product_argv", decoded["ProgramArguments"] == [str(frozen), "--profile-dir", str(profile), "daemon", "run"])
        check("failure_only_keepalive", decoded["RunAtLoad"] and decoded["KeepAlive"] == {"SuccessfulExit": False})
        check("install_does_not_start", "Active: inactive" in call("service", "status"))
        # Interrupted install: the private registration journal remains, but its
        # exact owned plist was not published. Repeat install recovers it.
        plist.unlink()
        call("service", "install", "--mode", "login", "--account", str(os.geteuid()))
        check("interrupted_install_resumes", plist.read_bytes() == original_plist)
        call("service", "start")
        first = status()
        check("ready_no_sharing", "IPC ready: true" in call("service", "status") and first["sharing"] == "disabled")
        second = execute("second_owner", [frozen, "--profile-dir", profile, "daemon", "run"], expected=None, timeout=10)
        check("second_owner_excluded", second.returncode != 0)
        check("second_owner_preserves_runtime", status()["runtimeId"] == first["runtimeId"])
        call("workspace", "add", "--name", "Disposable managed PTY", "--path", str(project))
        workspace = json.loads(call("workspace", "list", "--json"))["result"]["Ok"]["value"][0]["workspaceId"]
        call("terminal", "create", "--workspace", workspace, "--json")
        before = pane(workspace)
        check("managed_pty_running", before["state"] == "running" and before["session"] is not None)
        exit_view(workspace, before["paneId"])
        check("view_exit_preserves_pty", pane(workspace)["session"] == before["session"])
        old_tree = capture_tree()
        call("service", "restart")
        gone(old_tree)
        stopped = pane(workspace)
        check("restart_stopped_no_replay", stopped["state"] == "stopped" and stopped["session"] is None)
        restarted = status()
        check("restart_preserves_identity", restarted["runtimeId"] != first["runtimeId"] and restarted["hostId"] == first["hostId"])
        call("terminal", "restart", "--workspace", workspace, "--pane", stopped["paneId"], "--confirm", "--json")
        crash_tree = capture_tree()
        execute("manager_owned_crash", ["/bin/launchctl", "kill", "SIGKILL", target], timeout=5)
        crashed = wait_runtime(restarted["runtimeId"])
        gone(crash_tree)
        lost = pane(workspace)
        check("crash_lost_no_replay", lost["state"] == "lost" and lost["session"] is None)
        check("crash_service_ready", "IPC ready: true" in call("service", "status") and crashed["hostId"] == first["hostId"])
        call("terminal", "restart", "--workspace", workspace, "--pane", lost["paneId"], "--confirm", "--json")
        stop_tree = capture_tree()
        call("service", "stop")
        gone(stop_tree)
        time.sleep(2.5)
        check("intentional_stop_stays_stopped", "Active: inactive" in call("service", "status"))
        call("service", "start")
        check("stop_persists_stopped", pane(workspace)["state"] == "stopped" and pane(workspace)["session"] is None)
        # Keep one accepted handshake incomplete so graceful host teardown must
        # retain owner.lock. Interrupt only our retained service-CLI child after
        # launchd acknowledges bootout, then retry after releasing the fixture.
        blocked = socket.socket(socket.AF_UNIX)
        blocked.settimeout(2)
        blocked.connect(str(profile / "host.sock"))
        blocked.sendall(b"\x00")
        time.sleep(0.15)
        interrupted = subprocess.Popen([str(frozen), "--profile-dir", str(profile), "service", "stop"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=environment, start_new_session=True)
        try:
            deadline = time.monotonic() + 3
            accepted = False
            while time.monotonic() < deadline:
                observation = execute("interrupted_stop_manager_observation", ["/bin/launchctl", "print", target], expected=None, timeout=3)
                if "\tstate = SIGTERMed" in observation.stdout:
                    accepted = True
                    break
                if interrupted.poll() is not None:
                    break
                time.sleep(0.025)
            check("interrupted_stop_accepted_before_cleanup", accepted and interrupted.poll() is None)
            try:
                owner_free()
                busy = False
            except BlockingIOError:
                busy = True
            check("interrupted_stop_retains_owner_lock", busy)
            stop_group(interrupted)
        finally:
            blocked.close()
            if interrupted.poll() is None:
                stop_group(interrupted)
        # A repeat of an accepted bootout may itself be uncertain until launchd
        # finishes removal. Preserve the exact registration and retry boundedly.
        deadline = time.monotonic() + 8
        while True:
            retry = execute("interrupted_stop_retry", [frozen, "--profile-dir", profile, "service", "stop"], expected=None, timeout=65)
            if retry.returncode == 0:
                break
            if retry.returncode not in (4, 7) or time.monotonic() >= deadline:
                raise RuntimeError("interrupted_stop_retry_failed")
            time.sleep(0.05)
        owner_free()
        check("interrupted_stop_recovers_without_stuck_registration", registration.is_file())
        call("service", "start")
        managed_runtime = status()["runtimeId"]
        stop_bound_runtime(profile, managed_runtime)
        execute("schedule_waiting_job", ["/bin/launchctl", "kickstart", target], timeout=5)
        call("service", "stop")
        owner_free()
        check("waiting_job_start_stop_interleaving_cleans_owner", True)
        call("service", "start")
        managed_runtime = status()["runtimeId"]
        stop_bound_runtime(profile, managed_runtime)
        (root / "manual-runtime.json").write_text(json.dumps({"runtimeId": None}))
        (root / "manual-runtime.json").chmod(0o600)
        call("daemon", "start")
        manual_runtime = status()["runtimeId"]
        (root / "manual-runtime.json").write_text(json.dumps({"runtimeId": manual_runtime}))
        (root / "manual-runtime.json").chmod(0o600)
        check("replacement_manual_new_runtime", manual_runtime != managed_runtime)
        call("terminal", "restart", "--workspace", workspace, "--pane", lost["paneId"], "--confirm", "--json")
        manual_session = pane(workspace)["session"]
        rows = snapshot()
        # Discovery contains kernel-authenticated runtime identity for cleanup;
        # numeric process metadata is only used to prove disappearance.
        discovery = json.loads((profile / "discovery.json").read_text())
        with socket.socket(socket.AF_UNIX) as channel:
            channel.connect(str(profile / "host.sock"))
            manual_pid = struct.unpack("i", channel.getsockopt(0, 0x002, 4))[0]
        manual_tree = {manual_pid}
        while True:
            expanded = manual_tree | {pid for pid, (parent, _, state) in rows.items() if parent in manual_tree and not state.startswith("Z")}
            if expanded == manual_tree:
                break
            manual_tree = expanded
        trees.update(manual_tree)
        report["observedTreePids"] = sorted(trees)
        save()
        call("service", "stop")
        check("replacement_manual_owner_survives_old_job_stop", status()["runtimeId"] == manual_runtime)
        check("replacement_manual_pty_survives_old_job_stop", pane(workspace)["session"] == manual_session)
        call("service", "start", expected=5)
        stop_bound_runtime(profile, manual_runtime)
        manual_runtime = None
        (root / "manual-runtime.json").unlink()
        gone(manual_tree)
        call("service", "start")
        capture_tree()
        # Exercise the actual outer timeout path while the LaunchAgent is live.
        # Only the owned sleeper child is killed; recovery uses exact product
        # registration/manager authority to uninstall the out-of-group host.
        try:
            run_with_recovery(root, [sys.executable, "-B", "-c", "import time; time.sleep(30)"], environment, timeout=0.1)
            raise RuntimeError("timeout_fixture_did_not_timeout")
        except subprocess.TimeoutExpired:
            pass
        check("outer_timeout_recovers_live_registered_job", json.loads((root / "outer-recovery.json").read_text())["cleanupConfirmed"] and not registration.exists())
        call("service", "install", "--mode", "login", "--account", str(os.geteuid()))
        call("service", "start")
        call("service", "stop")
        # Exact owned unlink simulates interruption before registration removal.
        check("exact_owned_plist_before_fault", plist.read_bytes() == original_plist and plist.stat().st_nlink == 1)
        plist.unlink()
        call("service", "uninstall")
        check("interrupted_uninstall_resumes", not registration.exists() and not plist.exists())
        check("uninstall_preserves_profile_workspace", (profile / "owner.lock").is_file() and project.is_dir())
        verify_build(root)
        checks_passed = True
    except BaseException as error:
        # Fixed test identifier only; never record arbitrary manager/CLI output.
        report["failureType"] = type(error).__name__
        report["lastOperation"] = report["operations"][-1]["id"] if report["operations"] else None
        raise
    finally:
        try:
            if manual_runtime:
                stop_bound_runtime(profile, manual_runtime)
                manual_runtime = None
                (root / "manual-runtime.json").unlink(missing_ok=True)
            if registration.exists():
                reg = json.loads(registration.read_text())
                if reg["profile"] != str(profile) or reg["executable"] != str(frozen):
                    raise RuntimeError("registration_changed_preserve_inputs")
                call("service", "uninstall")
            if target:
                execute("confirm_exact_job_absent", ["/bin/launchctl", "print", target], expected=113, timeout=5)
                overrides = execute("exact_label_override_after", ["/bin/launchctl", "print-disabled", "gui/" + str(os.geteuid())], timeout=5)
                check("uninstall_leaves_no_override", not any(line.strip().startswith('"' + target.rsplit("/", 1)[1] + '" => ') for line in overrides.stdout.splitlines()))
            if profile.exists():
                owner_free()
            gone(trees)
            if plist and plist.exists():
                raise RuntimeError("plist_removal_unconfirmed")
            if (root / ".fixture-marker").read_text() != identifier or root.parent != ARTIFACTS:
                raise RuntimeError("fixture_ownership_changed")
            if profile.exists():
                shutil.rmtree(profile)
            shutil.rmtree(project)
            report["cleanupConfirmed"] = True
        finally:
            verify_build(root)
            report["passed"] = checks_passed and report["cleanupConfirmed"]
            save()
    return root / "evidence.json"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-native", action="store_true")
    parser.add_argument("--frozen-run", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not args.run_native:
        parser.error("--run-native is required to install the disposable LaunchAgent")
    if args.frozen_run:
        print(native(args.frozen_run))
        return
    if sys.platform != "darwin":
        parser.error("native macOS required")
    initialize_process_ownership()
    ARTIFACTS.mkdir(mode=0o700, exist_ok=True)
    metadata = ARTIFACTS.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise RuntimeError("private_artifacts_directory_required")
    root = ARTIFACTS / str(uuid.uuid4())
    root.mkdir(mode=0o700)
    (root / ".fixture-marker").write_text(root.name)
    try:
        controlled_build(ROOT, root)
        environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "TERM": "xterm-256color"}
        result = run_with_recovery(root, frozen_command(sys.executable, root / "inputs/tools/run_macos_product_service.py", root), environment, timeout=300)
        (root / "native.stdout.log").write_text(result.stdout)
        (root / "native.stderr.log").write_text(result.stderr)
        if result.returncode:
            raise RuntimeError("frozen_native_proof_failed")
        print(root / "evidence.json")
    except BaseException:
        print("Proof did not pass; receipt: " + str(root), file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
