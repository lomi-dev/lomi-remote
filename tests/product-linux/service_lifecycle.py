#!/usr/bin/env python3
"""Product systemd-user probe, restricted to a marked disposable product run.

Invoke prepare and verify through independent SSH connections. This qualifies
current-account login lifecycle only; boot/reboot and other platforms remain
separate qualifications. Never enables linger or changes OS accounts.
"""
import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from owned_process import initialize_process_ownership, run_owned


def main():
    initialize_process_ownership()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "verify", "cleanup"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    identifier = str(uuid.UUID(args.run_id))
    root = args.root.resolve(strict=True)
    home = Path.home().resolve(strict=True)
    if (sys.platform != "linux" or args.root.is_symlink()
            or root.parent != home or root.name != "lomi-product-" + identifier
            or root.stat().st_uid != os.geteuid()
            or (root / ".fixture-marker").read_text() != identifier):
        raise RuntimeError("Invalid disposable fixture ownership")
    binary = root / "bin/lomiremote"
    profile = root / 's $%'
    state = root / "service-probe.json"
    registration = profile / "service-registration.json"
    manual_journal = root / "service-manual-owner.json"
    environment = {**os.environ, "PATH": "/usr/bin:/bin", "SHELL": "/bin/sh"}
    # The user manager reads its real account configuration. Do not point its
    # client at a synthetic HOME or XDG_CONFIG_HOME that the manager never saw.
    environment.pop("XDG_CONFIG_HOME", None)

    def execute(argv, expected=0):
        result = run_owned(argv, env=environment, timeout=65)
        if result.returncode != expected:
            # Keep closed diagnostics useful without copying arbitrary manager,
            # profile, shell, or token-bearing stderr into the report.
            permitted = {"SERVICE_INVALID_CONFIGURATION", "SERVICE_OWNERSHIP_CONFLICT",
                         "SERVICE_MANAGER_UNAVAILABLE", "SERVICE_OPERATION_UNCERTAIN",
                         "SERVICE_NOT_READY", "SERVICE_BOOT_REQUIRES_VERIFIED_LINGER",
                         "HOST_BUSY", "HOST_UNAVAILABLE", "INVALID_PROFILE", "HOST_STORAGE_ERROR"}
            reason = next((line for line in result.stderr.splitlines() if line in permitted),
                          "UNCLASSIFIED_FAILURE")
            raise RuntimeError("Unexpected bounded CLI/manager result: " + str(result.returncode) + " " + reason)
        return result.stdout

    def call(*arguments, expected=0):
        return execute([str(binary), "--profile-dir", str(profile), *arguments], expected)

    def status():
        return json.loads(call("status", "--json"))["result"]["Ok"]["value"]

    def service_status():
        return call("service", "status")

    def pane(workspace):
        return json.loads(call("terminal", "list", "--workspace", workspace, "--json"))["state"]["tabs"][0]["layout"]["pane"]

    def workspace_named(name):
        items = json.loads(call("workspace", "list", "--json"))["result"]["Ok"]["value"]
        return next(item["workspaceId"] for item in items if item["name"] == name)

    def owned_registration():
        reg = json.loads(registration.read_text())
        assert reg["profile"] == str(profile) and reg["executable"] == str(binary)
        assert reg["account"] and reg["mode"] == "login"
        assert reg["unit"].startswith("lomiremote-") and reg["unit"].endswith(".service")
        return reg

    def process_snapshot():
        processes = {}
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                data = (entry / "stat").read_text().rsplit(")", 1)[1].split()
                processes[int(entry.name)] = {"parent": int(data[1]), "start": data[19]}
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
        return processes

    def manual_process_tree():
        processes = process_snapshot()
        roots = set()
        for pid in processes:
            try:
                entry = Path("/proc") / str(pid)
                with (entry / "cmdline").open("rb") as source:
                    argv = source.read(8192).split(b"\0")
                if (entry / "exe").readlink() == binary and str(profile).encode() in argv:
                    roots.add(pid)
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
        selected = set(roots)
        while True:
            expanded = selected | {pid for pid, info in processes.items() if info["parent"] in selected}
            if expanded == selected:
                break
            selected = expanded
        return {str(pid): processes[pid]["start"] for pid in selected}

    def require_processes_gone(identities):
        deadline = time.monotonic() + 5
        while True:
            current = process_snapshot()
            alive = [pid for pid, start in identities.items() if int(pid) in current and current[int(pid)]["start"] == start]
            if not alive:
                return
            if time.monotonic() >= deadline:
                raise RuntimeError("Owned manual process cleanup uncertain; preserve inputs")
            time.sleep(0.05)

    def persist_manual(runtime, identities=None):
        temporary = root / (".manual-owner-" + str(uuid.uuid4()))
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as output:
            json.dump({"profile": str(profile), "runtime": runtime, "processes": identities or {}}, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, manual_journal)

    def stop_bound_runtime(expected_runtime):
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
                peer_pid, peer_uid, _ = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if peer_pid <= 0 or peer_uid != os.geteuid():
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

    def cleanup_manual():
        if not manual_journal.exists():
            return
        owned = json.loads(manual_journal.read_text())
        if owned["profile"] != str(profile) or not owned["runtime"]:
            raise RuntimeError("Manual owner completion uncertain; preserve inputs")
        result = run_owned([str(binary), "--profile-dir", str(profile), "status", "--json"], env=environment, timeout=20)
        if result.returncode == 0:
            current = json.loads(result.stdout)["result"]["Ok"]["value"]
            if current["runtimeId"] != owned["runtime"]:
                raise RuntimeError("Manual owner changed; preserve inputs")
            stop_bound_runtime(owned["runtime"])
        elif result.returncode == 4:
            # A failed readiness call cannot by itself prove the owner exited.
            fd = os.open(profile / "owner.lock", os.O_RDWR | os.O_NOFOLLOW)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
        else:
            raise RuntimeError("Manual owner cleanup uncertain; preserve inputs")
        require_processes_gone(owned.get("processes", {}))
        manual_journal.unlink()

    @contextmanager
    def manual_owner():
        if manual_journal.exists():
            raise RuntimeError("Previous manual owner requires cleanup")
        # A lost start response stays explicitly uncertain, never authorizes a
        # guessed runtime shutdown or deletion of its executable/profile.
        persist_manual(None)
        try:
            call("daemon", "start")
            persist_manual(status()["runtimeId"], manual_process_tree())
            yield
        finally:
            cleanup_manual()

    checks = []

    def check(name, condition):
        if not condition:
            raise RuntimeError(name)
        checks.append(name)

    if args.phase == "prepare":
        call("service", "install", "--mode", "login", "--account", str(os.geteuid() + 1), expected=2)
        check("foreign-account-rejected-without-profile", not profile.exists())
        check("fresh-profile", not profile.exists())
        call("service", "install", "--mode", "login", "--account", str(os.geteuid()))
        reg = owned_registration()
        check("no-profile-wide-stop-hook", execute(["/usr/bin/systemctl", "--user", "show", reg["unit"], "--property=ExecStop", "--value"]).strip() == "")
        check("graceful-main-owned-cgroup-fallback", execute(["/usr/bin/systemctl", "--user", "show", reg["unit"], "--property=KillMode", "--value"]).strip() == "mixed")
        observed = service_status()
        check("install-enables-without-start", "Autostart: enabled" in observed and "Active: inactive" in observed)
        call("service", "start")
        first = status()
        check("service-does-not-enable-sharing", first["sharing"] == "disabled")
        check("manager-and-authenticated-ipc-ready", "Active: active" in service_status() and "IPC ready: true" in service_status())
        # A second daemon owner must fail without replacing the managed runtime.
        result = run_owned([str(binary), "--profile-dir", str(profile), "daemon", "run"], env=environment, timeout=10)
        check("second-owner-excluded", result.returncode != 0 and status()["runtimeId"] == first["runtimeId"])
        project = root / "service-managed-project"
        project.mkdir(mode=0o700)
        call("workspace", "add", "--name", "Service managed PTY", "--path", str(project))
        workspace = workspace_named("Service managed PTY")
        call("terminal", "create", "--workspace", workspace, "--json")
        managed = pane(workspace)
        tree = manual_process_tree()
        check("managed-pty-running", managed["state"] == "running" and managed["session"] is not None and len(tree) >= 3)
        state.write_text(json.dumps({"unit": reg["unit"], "status": first, "workspace": workspace,
                                    "pane": managed, "processes": tree}))
        state.chmod(0o600)
    elif args.phase == "verify":
        saved = json.loads(state.read_text())
        reg = owned_registration()
        check("same-unit-after-disconnect", reg["unit"] == saved["unit"])
        check("same-runtime-after-disconnect", status()["runtimeId"] == saved["status"]["runtimeId"])
        workspace = saved["workspace"]
        check("managed-pty-survives-disconnect", pane(workspace)["session"] == saved["pane"]["session"])
        call("service", "restart")
        require_processes_gone(saved["processes"])
        check("managed-restart-reaps-old-pty-tree", True)
        stopped = pane(workspace)
        check("managed-restart-persists-stopped-no-respawn", stopped["state"] == "stopped" and stopped["session"] is None)
        call("terminal", "restart", "--workspace", workspace, "--pane", stopped["paneId"], "--confirm", "--json")
        crash_tree = manual_process_tree()
        check("managed-crash-pty-running", pane(workspace)["state"] == "running" and len(crash_tree) >= 3)
        restarted = status()
        check("controlled-restart-new-runtime", restarted["runtimeId"] != saved["status"]["runtimeId"])
        check("host-identity-preserved", restarted["hostId"] == saved["status"]["hostId"])
        execute(["/usr/bin/systemctl", "--user", "kill", "--kill-whom=main", "--signal=SIGKILL", reg["unit"]])
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            observation = service_status()
            if "IPC ready: true" in observation:
                now = status()
                if now["runtimeId"] != restarted["runtimeId"]:
                    break
            time.sleep(0.1)
        else:
            raise RuntimeError("crash restart readiness deadline")
        check("crash-restarts-with-new-runtime", now["runtimeId"] != restarted["runtimeId"])
        require_processes_gone(crash_tree)
        check("managed-crash-reaps-old-pty-tree", True)
        lost = pane(workspace)
        check("managed-crash-persists-lost-no-respawn", lost["state"] == "lost" and lost["session"] is None)
        call("terminal", "restart", "--workspace", workspace, "--pane", lost["paneId"], "--confirm", "--json")
        stopping_tree = manual_process_tree()
        call("service", "stop")
        require_processes_gone(stopping_tree)
        check("managed-stop-reaps-pty-tree", True)
        time.sleep(3)
        check("intentional-stop-stays-stopped", "Active: inactive" in service_status())
        call("service", "start")
        stopped = pane(workspace)
        check("managed-stop-persists-stopped-no-respawn", stopped["state"] == "stopped" and stopped["session"] is None)
        # Exit the managed main through its authenticated IPC, then immediately
        # replace it. The old manager unit must never stop a profile's new owner.
        call("daemon", "stop", "--confirm")
        with manual_owner():
            replacement = status()["runtimeId"]
            project = root / "service-race-project"
            project.mkdir(mode=0o700)
            call("workspace", "add", "--name", "Service replacement race", "--path", str(project))
            workspace = workspace_named("Service replacement race")
            call("terminal", "create", "--workspace", workspace, "--json")
            before = json.loads(call("terminal", "list", "--workspace", workspace, "--json"))["state"]["tabs"][0]["layout"]["pane"]["session"]
            tree = manual_process_tree()
            check("manual-process-tree-observed", bool(tree))
            persist_manual(replacement, tree)
            call("service", "stop")
            check("replacement-manual-owner-survives-old-unit-stop", status()["runtimeId"] == replacement)
            after = json.loads(call("terminal", "list", "--workspace", workspace, "--json"))["state"]["tabs"][0]["layout"]["pane"]["session"]
            check("replacement-manual-pty-survives-old-unit-stop", before == after)
            call("service", "start", expected=5)
        check("manual-owner-and-descendants-reaped", not manual_journal.exists())
        check("manual-owner-conflict-preserves-registration", registration.is_file())
        call("service", "start")
        # Simulate termination after the owned unit is unlinked and before the
        # manager reload. Only this marked fixture's exact registration is used.
        call("service", "stop")
        execute(["/usr/bin/systemctl", "--user", "disable", reg["unit"]])
        unit_path = Path(reg["unit_directory"]) / reg["unit"]
        check("fault-injection-owned-unit", unit_path.resolve() == unit_path and unit_path.stat().st_uid == os.geteuid() and unit_path.stat().st_nlink == 1)
        unit_path.unlink()
        call("service", "uninstall")
        check("partial-uninstall-resumed", not registration.exists())
        check("uninstall-preserves-profile", profile.is_dir() and (profile / "owner.lock").is_file())
        check("uninstall-removes-registration", not registration.exists())
    else:
        cleanup_manual()
        if registration.exists():
            owned_registration()
            call("service", "uninstall")
        check("owned-service-removed", not registration.exists())
    print(json.dumps({"phase": args.phase, "passed": True, "checks": checks,
                      "scope": "current-account systemd-user login lifecycle",
                      "bootQualified": False, "rebootTested": False,
                      "lingerChanged": False, "accountsChanged": False}))


if __name__ == "__main__":
    main()
