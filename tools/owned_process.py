"""Bounded POSIX command execution with cleanup of the owned process group.

Commands that deliberately create another session (for example PostgreSQL and
PTY owners) still need their own lifecycle guards; this is not a global process
supervisor. Never use it to signal processes outside the new session it owns.

Standalone callers must initialize_process_ownership() before creating any
children or threads. They must not install another SIGCHLD disposition or reap
these private Popen children, including through a native library. Python's
getsignal() cache cannot detect a later native sigaction change.
"""
import os
import signal
import subprocess
import time

_initialized_pid = None


def initialize_process_ownership():
    """Establish normal child retention once, at standalone CLI startup."""
    global _initialized_pid
    if os.name != "posix" or not hasattr(os, "WNOWAIT"):
        raise OSError("command runner requires POSIX waitid/WNOWAIT ownership")
    if _initialized_pid == os.getpid():
        require_process_ownership()
        return
    # Installing a fresh disposition also clears inherited SA_NOCLDWAIT.
    # Do not call this from a library after other children/threads exist.
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    _initialized_pid = os.getpid()


def require_process_ownership():
    if (_initialized_pid != os.getpid()
            or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL):
        raise RuntimeError("owned command runner needs initialized SIGCHLD ownership")


def require_unreaped_child(child):
    require_process_ownership()
    if child.returncode is not None:
        raise RuntimeError("owned command cleanup identity is unconfirmed: child reaped")
    try:
        status = os.waitid(os.P_PID, child.pid,
                           os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError as error:
        # communicate() can reap on KeyboardInterrupt, even before it updates
        # Popen.returncode. Never use its old numeric PID as group authority.
        raise RuntimeError("owned command cleanup identity is unconfirmed: no child") from error
    if status is not None and status.si_pid != child.pid:
        raise RuntimeError("owned command cleanup identity is unconfirmed")


def group_has_live_members(group):
    # Darwin can return EPERM for a group consisting only of zombies. Read only
    # numeric group IDs and states, never process argv/environment. An error in
    # this check propagates; it must not hide a failed signal to live members.
    listing = subprocess.check_output(
        ["/bin/ps", "-axo", "pgid=,stat="], text=True, timeout=2,
    )
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) != 2:
            raise RuntimeError("unexpected process-group state")
        if int(fields[0]) == group and not fields[1].startswith("Z"):
            return True
    return False


def signal_group(child, sig):
    require_unreaped_child(child)
    try:
        os.killpg(child.pid, sig)
    except ProcessLookupError:
        pass
    except PermissionError:
        if group_has_live_members(child.pid):
            raise


def stop_group(child):
    # Keep the direct child unreaped during the grace period, so its PID cannot
    # be reused as another process group's identity before the final signal.
    try:
        signal_group(child, signal.SIGTERM)
        time.sleep(0.25)
        signal_group(child, signal.SIGKILL)
    finally:
        try:
            child.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            # An escaped process holding a pipe is outside group ownership.
            # Its dedicated fixture guard must supervise it. Bound our cleanup.
            for stream in (child.stdout, child.stderr):
                if stream is not None:
                    stream.close()
            child.wait(timeout=2)


def run_owned(argv, *, cwd=None, env=None, timeout=120):
    require_process_ownership()
    child = subprocess.Popen(
        argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=True,
    )
    try:
        stdout, stderr = child.communicate(timeout=timeout)
    except BaseException:
        stop_group(child)
        raise
    return subprocess.CompletedProcess(argv, child.returncode, stdout, stderr)
