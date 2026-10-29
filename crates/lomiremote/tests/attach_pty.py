"""Real crossterm PTY integration; all bytes are synthetic and kept in memory."""
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time

binary = str(Path(sys.argv[1]).resolve(strict=True))
root = Path(tempfile.mkdtemp(prefix="lomi-view-", dir=str(Path("/tmp").resolve())))
profile = root / "p"
project = root / "project"
project.mkdir()
home = root / "home"
home.mkdir(mode=0o700)
fixture_env = {**os.environ, "HOME": str(home), "SHELL": "/bin/sh", "PATH": "/usr/bin:/bin"}
children = []


def call(*args):
    result = subprocess.run([binary, "--profile-dir", str(profile), *args], stdin=subprocess.DEVNULL, capture_output=True, timeout=20, env=fixture_env)
    if result.returncode:
        raise AssertionError(f"CLI failed ({result.returncode}): {result.stderr.decode(errors='replace')}")
    return json.loads(result.stdout) if "--json" in args else None


def state(workspace):
    return call("terminal", "list", "--workspace", workspace, "--json")["state"]


def spawn(workspace, pane, control):
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    before = termios.tcgetattr(slave)
    cmd = [binary, "--profile-dir", str(profile), "terminal", "attach", "--workspace", workspace, "--pane", pane]
    if control:
        cmd.append("--control")
    process = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave, env={**fixture_env, "TERM": "xterm-256color"}, start_new_session=True)
    children.append(process)
    return process, master, slave, before


def wait_text(process, master, needle, timeout=15):
    end = time.monotonic() + timeout
    data = bytearray()
    while time.monotonic() < end:
        if select.select([master], [], [], 0.05)[0]:
            data.extend(os.read(master, 65536))
            if needle in data:
                return
        if process.poll() is not None:
            raise AssertionError(f"view exited early ({process.returncode}) before expected render; tail={bytes(data[-200:])!r}")
    raise AssertionError("bounded render deadline")


def quit_view(process, master, slave, before):
    os.write(master, b"\x1d")  # Ctrl-] is local-only exit.
    end = time.monotonic() + 10
    output = bytearray()
    while process.poll() is None and time.monotonic() < end:
        if select.select([master], [], [], 0.05)[0]:
            output.extend(os.read(master, 65536))
    assert process.wait(timeout=1) == 0, "local quit must succeed"
    # Cleanup must independently restore canonical/echo/raw input flags.
    assert termios.tcgetattr(slave) == before, "terminal attributes not restored"
    assert b"\x1b[?1049l" in output, "alternate screen was not left"
    os.close(master)
    os.close(slave)


try:
    call("daemon", "start")
    call("workspace", "add", "--name", "PTY", "--path", str(project))
    workspace = call("workspace", "list", "--json")["result"]["Ok"]["value"][0]["workspaceId"]
    call("terminal", "create", "--workspace", workspace, "--json")
    initial = state(workspace)["tabs"][0]["layout"]["pane"]
    pane, session = initial["paneId"], initial["session"]
    host = call("status", "--json")["result"]["Ok"]["value"]
    process, master, slave, before = spawn(workspace, pane, True)
    wait_text(process, master, b"input and")
    time.sleep(0.5)
    # Interactive input only, never command argv. Delay output across local view exit.
    sentinel = root / "view-closed"
    command = f"printf '%s%s\\n' 'LOMI_' 'VIEW_OK'; (while test ! -f '{sentinel}'; do sleep 0.1; done; printf '%s%s\\n' 'LOMI_' 'AFTER_VIEW') &\r"
    os.write(master, command.encode())
    wait_text(process, master, b"LOMI_VIEW_OK")
    # Ctrl-C interrupts a foreground PTY process rather than exiting the view.
    os.write(master, b"sleep 10\r")
    time.sleep(0.3)
    os.write(master, b"\x03")
    time.sleep(0.2)
    assert process.poll() is None
    os.write(master, b"printf '%s%s\\n' 'LOMI_' 'INTERRUPTED'\r")
    wait_text(process, master, b"LOMI_INTERRUPTED", timeout=4)
    quit_view(process, master, slave, before)
    sentinel.touch()  # Background output cannot be produced before view exit.
    time.sleep(0.4)
    assert state(workspace)["tabs"][0]["layout"]["pane"]["session"] == session
    assert call("status", "--json")["result"]["Ok"]["value"] == host
    observer, master, slave, before = spawn(workspace, pane, False)
    wait_text(observer, master, b"LOMI_AFTER_VIEW")
    quit_view(observer, master, slave, before)
    assert state(workspace)["tabs"][0]["layout"]["pane"]["session"] == session
    print("real attach: control/input/Ctrl-C/local quit/observer snapshot/host and shell survive: passed")
finally:
    for process in children:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    stopped = subprocess.run([binary, "--profile-dir", str(profile), "daemon", "stop", "--confirm"], capture_output=True, timeout=20, env=fixture_env)
    if stopped.returncode == 0 or not (profile / "discovery.json").exists():
        import shutil
        shutil.rmtree(root)
