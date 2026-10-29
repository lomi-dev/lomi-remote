"""Native, nonroot primitive inventory only. No repository input or Git execution."""
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import time

RUNTIME = (
    "/usr/bin/bwrap", "/usr/bin/git", "/etc/ld.so.cache",
    "/etc/apparmor.d/lomi-git-bwrap-experimental",
    "/usr/lib/aarch64-linux-gnu/libgcc_s.so.1",
    "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
    "/usr/lib/aarch64-linux-gnu/libpcre2-8.so.0.11.2",
    "/usr/lib/aarch64-linux-gnu/libz.so.1.3",
    "/usr/lib/aarch64-linux-gnu/libc.so.6",
)
ENV = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C"}

def main():
    assert os.getuid() != 0, "runtime must be nonroot"
    report = {"qualified": False, "complete": False, "uid": os.getuid(),
              "kernel": platform.release(), "arch": platform.machine(),
              "distribution": platform.freedesktop_os_release()["PRETTY_NAME"],
              "environment": ENV, "files": {}, "operations": []}
    for name in RUNTIME:
        path = Path(name)
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == 0
        assert info.st_mode & 0o6022 == 0, "root-owned immutable runtime required"
        report["files"][name] = {"uid": info.st_uid, "gid": info.st_gid,
            "mode": oct(info.st_mode), "device": info.st_dev, "inode": info.st_ino,
            "size": info.st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    for name in ("kernel.unprivileged_userns_clone", "kernel.apparmor_restrict_unprivileged_userns"):
        report[name] = Path("/proc/sys/" + name.replace(".", "/")).read_text().strip()
    commands = [
        ["/usr/bin/dpkg-query", "-W", "-f=${Version}", "bubblewrap"],
        ["/usr/bin/bwrap", "--version"],
        ["/usr/bin/unshare", "--user", "--map-root-user", "/usr/bin/true"],
        # Empty root, one exact regular binary only. On a usable namespace host,
        # missing ELF interpreter is distinguished from namespace setup failure.
        ["/usr/bin/bwrap", "--unshare-user", "--unshare-pid", "--unshare-net",
         "--unshare-ipc", "--unshare-uts", "--disable-userns", "--die-with-parent",
         "--cap-drop", "ALL", "--ro-bind", "/usr/bin/true", "/true", "--", "/true"],
    ]
    for argv in commands:
        started = time.monotonic()
        result = subprocess.run(argv, env=ENV, capture_output=True, text=True, timeout=10)
        report["operations"].append({"argv": argv, "exitCode": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr,
            "durationSeconds": round(time.monotonic() - started, 3)})
    failed = report["operations"][-1]
    report["namespaceSetupBlocked"] = failed["exitCode"] != 0 and any(
        reason in failed["stderr"] for reason in ("uid map", "loopback:", "Creating new namespace failed"))
    report["complete"] = True
    report["isolationAcceptance"] = "not_run"
    print(json.dumps(report))

if __name__ == "__main__":
    main()
