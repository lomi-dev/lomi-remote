#!/usr/bin/env python3
"""Synthetic product PTY continuity across two independent SSH connections."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import pty
import stat
import select
import struct
import subprocess
import termios
import time
import uuid


def owner_lock_is_held(profile, uid):
    """Return true only when a validated profile lock has a live owner."""
    directory = profile.lstat()
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != uid
            or stat.S_IMODE(directory.st_mode) != 0o700):
        raise RuntimeError("Unsafe continuity profile")
    path = profile / "owner.lock"
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RuntimeError("Cannot establish profile owner lock state") from error
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid
                or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1):
            raise RuntimeError("Unsafe profile owner lock")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return False
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "verify", "cleanup"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    identifier = str(uuid.UUID(args.run_id))
    root = args.root.resolve(strict=True)
    home = Path.home().resolve(strict=True)
    if (os.name != "posix" or not Path("/proc/self").exists()
            or args.root.is_symlink() or root.parent != home
            or root.name != "lomi-product-" + identifier
            or root.stat().st_uid != os.geteuid()
            or (root / ".fixture-marker").read_text() != identifier):
        raise RuntimeError("Invalid disposable fixture ownership")
    binary = root / "bin/lomiremote"
    profile = root / "profile"
    home = root / "home"
    project = root / "project"
    environment = {**os.environ, "HOME": str(home), "SHELL": "/bin/sh",
                   "PATH": "/usr/bin:/bin", "TERM": "xterm-256color"}

    def call(*arguments):
        completed = subprocess.run(
            [str(binary), "--profile-dir", str(profile), *arguments],
            stdin=subprocess.DEVNULL, capture_output=True,
            env=environment, timeout=20)
        if completed.returncode:
            raise RuntimeError("Synthetic CLI request failed")
        return json.loads(completed.stdout) if "--json" in arguments else None

    def pane(workspace):
        return call("terminal", "list", "--workspace", workspace,
                    "--json")["state"]["tabs"][0]["layout"]["pane"]

    def interact(workspace, pane_id, command, expected):
        master, slave = pty.openpty()
        process = None
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
            previous = termios.tcgetattr(slave)
            process = subprocess.Popen(
                [str(binary), "--profile-dir", str(profile), "terminal", "attach",
                 "--workspace", workspace, "--pane", pane_id, "--control"],
                stdin=slave, stdout=slave, stderr=slave, env=environment,
                start_new_session=True)

            def observe(marker, timeout=12):
                deadline = time.monotonic() + timeout
                tail = bytearray()
                while time.monotonic() < deadline:
                    if select.select([master], [], [], 0.05)[0]:
                        tail.extend(os.read(master, 65536))
                        if marker in tail:
                            return
                        del tail[:-131072]
                    if process.poll() is not None:
                        raise RuntimeError("Synthetic view exited before render")
                raise TimeoutError("Synthetic render deadline")

            observe(b"input and")
            time.sleep(0.2)
            os.write(master, command)
            observe(expected)
            os.write(master, b"\x1d")
            deadline = time.monotonic() + 8
            restored_screen = False
            while process.poll() is None and time.monotonic() < deadline:
                if select.select([master], [], [], 0.05)[0]:
                    restored_screen |= b"\x1b[?1049l" in os.read(master, 65536)
            if process.wait(timeout=1) != 0 or not restored_screen:
                raise RuntimeError("Synthetic view cleanup failed")
            if termios.tcgetattr(slave) != previous:
                raise RuntimeError("Terminal modes were not restored")
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            os.close(master)
            os.close(slave)

    saved = root / "continuity.json"
    if args.phase == "prepare":
        home.mkdir(mode=0o700)
        project.mkdir(mode=0o700)
        call("daemon", "start")
        call("workspace", "add", "--name", "Linux SSH fixture", "--path", str(project))
        workspace = call("workspace", "list", "--json")["result"]["Ok"]["value"][0]["workspaceId"]
        call("terminal", "create", "--workspace", workspace, "--json")
        initial = pane(workspace)
        interact(workspace, initial["paneId"],
                 b"n=1; printf '%s%s\\n' 'LMCONT_A' \"$n\"\r", b"LMCONT_A1")
        state = {"workspaceId": workspace, "paneId": initial["paneId"],
                 "session": initial["session"],
                 "status": call("status", "--json")["result"]["Ok"]["value"]}
        with saved.open("x") as output:
            os.chmod(saved, 0o600)
            json.dump(state, output)
        print(json.dumps({"phase": "prepare", "passed": True,
                          "viewStopped": True, "shellCounter": 1}))
    elif args.phase == "verify":
        state = json.loads(saved.read_text())
        if call("status", "--json")["result"]["Ok"]["value"] != state["status"]:
            raise RuntimeError("Host runtime changed across SSH disconnect")
        if pane(state["workspaceId"])["session"] != state["session"]:
            raise RuntimeError("PTY session changed across SSH disconnect")
        interact(state["workspaceId"], state["paneId"],
                 b"n=$((n+1)); printf '%s%s\\n' 'LMCONT_B' \"$n\"\r", b"LMCONT_B2")
        print(json.dumps({"phase": "verify", "passed": True,
                          "sameRuntime": True, "sameSession": True,
                          "shellCounter": 2, "viewStopped": True}))
    else:
        discovery = profile / "discovery.json"
        if discovery.exists() or discovery.is_symlink():
            metadata = discovery.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
                raise RuntimeError("Unsafe continuity discovery; preserve fixture")
        if discovery.exists():
            if owner_lock_is_held(profile, os.geteuid()):
                call("daemon", "stop", "--confirm")
        remaining = 0
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                executable = (entry / "exe").readlink()
                working_directory = (entry / "cwd").readlink()
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
            if executable.is_relative_to(root) or working_directory.is_relative_to(root):
                remaining += 1
        if remaining:
            raise RuntimeError("Owned executable remains; preserve fixture")
        print(json.dumps({"phase": "cleanup", "passed": True,
                          "ownedFixtureProcessesRemaining": 0}))


if __name__ == "__main__":
    main()
