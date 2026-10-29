#!/usr/bin/env python3
"""Compile-first portable Git E0 experiment; synthetic input only, never qualified."""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "artifacts/git-wasi"
TEST = ROOT / "tests/git-wasi"
MAX_OUTPUT = 8 * 1024 * 1024


def kill_owned(child):
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except PermissionError:
        # Darwin returns EPERM for a process group containing only its exited
        # zombie leader. Observe exit without reaping before accepting that.
        for _ in range(20):
            info = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
            if info is not None and info.si_pid == child.pid:
                return
            time.sleep(0.005)
        raise


def run(argv, cwd, env, timeout=30):
    """Own a process group, drain both pipes with a combined byte/deadline bound."""
    child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True)
    selector = selectors.DefaultSelector()
    chunks = [bytearray(), bytearray()]
    for number, pipe in enumerate((child.stdout, child.stderr)):
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ, number)
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise RuntimeError("owned process deadline")
            for key, _ in selector.select(0.1):
                data = os.read(key.fd, 65536)
                if not data:
                    selector.unregister(key.fileobj)
                else:
                    chunks[key.data].extend(data)
                    if sum(map(len, chunks)) > MAX_OUTPUT:
                        raise RuntimeError("owned process output limit")
        # EOF may precede actual exit. Observe the leader without reaping it.
        while os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is None:
            if time.monotonic() >= deadline:
                raise RuntimeError("owned process deadline after output EOF")
            time.sleep(0.005)
        # Keep the unreaped leader as process group identity anchor until all
        # descendants are killed; never signal a process group after wait().
        kill_owned(child)
        code = child.wait(timeout=2)
        return code, *(bytes(chunk) for chunk in chunks)
    finally:
        if child.returncode is None:
            kill_owned(child)
            child.wait(timeout=2)
        selector.close()
        child.stdout.close()
        child.stderr.close()


def git_runtime():
    path = Path("/Library/Developer/CommandLineTools/usr/bin/git" if sys.platform == "darwin" else "/usr/bin/git").resolve(strict=True)
    for entry in (path, *path.parents):
        info = entry.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError("fixture Git must be root owned and non-writable")
    return path


def copy_snapshot(source, destination):
    """Private synthetic tree only. No links, specials, hardlinks or races accepted."""
    entries = 0
    total = 0
    destination.mkdir(mode=0o700)

    def copy(directory, target, depth):
        nonlocal entries, total
        if depth > 16:
            raise RuntimeError("snapshot depth limit")
        for entry in sorted(directory.iterdir()):
            entries += 1
            if entries > 2048:
                raise RuntimeError("snapshot entry limit")
            before = entry.lstat()
            output = target / entry.name
            if stat.S_ISDIR(before.st_mode):
                if entry.is_symlink():
                    raise RuntimeError("snapshot symlink")
                output.mkdir(mode=0o700)
                copy(entry, output, depth + 1)
            elif stat.S_ISREG(before.st_mode) and before.st_nlink == 1:
                total += before.st_size
                if total > 16 * 1024 * 1024:
                    raise RuntimeError("snapshot byte limit")
                fd = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    opened = os.fstat(fd)
                    if (before.st_dev, before.st_ino, before.st_size) != (opened.st_dev, opened.st_ino, opened.st_size):
                        raise RuntimeError("snapshot source changed")
                    data = bytearray()
                    while len(data) <= before.st_size:
                        chunk = os.read(fd, min(65536, before.st_size + 1 - len(data)))
                        if not chunk:
                            break
                        data.extend(chunk)
                    after = os.fstat(fd)
                    if len(data) != before.st_size or after.st_mtime_ns != before.st_mtime_ns or after.st_nlink != 1:
                        raise RuntimeError("snapshot source changed")
                    output.write_bytes(data)
                finally:
                    os.close(fd)
            else:
                raise RuntimeError("snapshot link, reparse point or special file")

    copy(source, destination, 0)
    return {"entries": entries, "bytes": total}


def tree_digest(path):
    digest = hashlib.sha256()
    for entry in sorted(path.rglob("*")):
        if entry.is_file():
            name = entry.relative_to(path).as_posix().encode()
            data = entry.read_bytes()
            digest.update(len(name).to_bytes(8, "big") + name + len(data).to_bytes(8, "big") + data)
    return digest.hexdigest()


def security_probes(work, host, wasm, source, git, git_env):
    results = {}
    def invoke(name, module, snapshot, expected=None, error=None):
        code, out, err = run([str(host), str(module), str(snapshot)], work,
                             {"LOMI_PRIVATE_CANARY": "synthetic-host-only"}, timeout=60)
        (ART / f"probe-{name}.stdout").write_bytes(out)
        (ART / f"probe-{name}.stderr").write_bytes(err)
        passed = code == 0 and out == expected if expected is not None else code != 0
        if error is not None:
            diagnostic = b"\n".join(line for line in err.lower().splitlines() if not line.startswith(b"allowed_imports="))
            passed = passed and any(item in diagnostic for item in error)
        if name == "output":
            passed = passed and len(out) == 64 * 1024
        results[name] = {"passed": passed, "exit": code}

    # Bypass the copy broker deliberately to attack the WASI capability boundary.
    denied = work / "denial-snapshot"
    denied.mkdir(mode=0o700)
    (work / "outside-canary").write_text("synthetic outside")
    (denied / "mode").write_text("denial")
    (denied / "inside").write_text("synthetic inside")
    (denied / "escape").symlink_to(work / "outside-canary")
    (denied / "escape-dir").symlink_to(work, target_is_directory=True)
    invoke("denial", wasm.with_name("sandbox_probe.wasm"), denied, b"sandbox_denial_probe_passed\n")
    results["denial"]["passed"] &= (denied / "inside").read_text() == "synthetic inside" and not (denied / "write-marker").exists() and not (denied / "helper-marker").exists()

    for mode, errors in [("fuel", [b"fuel", b"interrupt"]), ("memory", [b"memory", b"unreachable"]),
                         ("output", [b"i/o error", b"capacity", b"closed"]), ("stack", [b"stack"] )]:
        snapshot = work / f"{mode}-snapshot"
        snapshot.mkdir(mode=0o700)
        (snapshot / "mode").write_text(mode)
        invoke(mode, wasm.with_name("sandbox_probe.wasm"), snapshot, error=errors)

    # A valid minimal core module with an explicit socket import. Rejection is
    # established from actual module imports, independent of crate feature flags.
    def leb(value):
        out = bytearray()
        while value > 127:
            out.append((value & 127) | 128)
            value >>= 7
        return bytes(out + bytes([value]))
    def section(kind, data):
        return bytes([kind]) + leb(len(data)) + data
    def string(value):
        value = value.encode()
        return leb(len(value)) + value
    socket = work / "socket-import.wasm"
    socket.write_bytes(b"\0asm\x01\0\0\0" + section(1, b"\x01\x60\0\0") +
                       section(2, b"\x01" + string("wasi_snapshot_preview1") + string("sock_accept") + b"\0\0"))
    invoke("socket-import", socket, denied, error=[b"disallowed import wasi_snapshot_preview1::sock_accept"])
    for name, extra in [("memory-initial", section(5, b"\x01\0" + leb(2049))),
                        ("table-initial", section(4, b"\x01\x70\0" + leb(100001)))]:
        module = work / f"{name}.wasm"
        module.write_bytes(b"\0asm\x01\0\0\0" + extra)
        invoke(name, module, denied, error=[b"memory" if name.startswith("memory") else b"table"])

    policy = work / "policy-snapshot"
    policy.mkdir(mode=0o700)
    for name in ["ordinary", "attributes", "alternates", "metadata", "symlink", "commondir"]:
        copy_snapshot(source, policy / name)
    (policy / "attributes/.gitattributes").write_text("*.txt filter=synthetic-required working-tree-encoding=UTF-16\n")
    (policy / "alternates/.git/objects/info/alternates").write_text(str(work / "outside-canary"))
    (policy / "metadata/.git/config.worktree").write_text("[filter \"x\"]\nrequired=true\n")
    (policy / "symlink/escape").symlink_to(work / "outside-canary")
    # Keep an allowed decoy .git/config while actual objects/refs/config live
    # in a valid common repository. Native Git must resolve and read that data;
    # a missing or malformed common directory would prove the wrong rejection.
    shared = policy / "commondir"
    (shared / ".git").rename(shared / "common")
    (shared / ".git").mkdir(mode=0o700)
    for name in ["HEAD", "index", "config"]:
        shutil.copyfile(shared / "common" / name, shared / ".git" / name)
    (shared / ".git/commondir").write_text("../common\n")
    with (shared / "common/config").open("a") as config:
        config.write("[diff]\nexternal=synthetic-helper\n")
    code, out, err = run([str(git), "--no-pager", "show", "--no-ext-diff", "--no-textconv", "HEAD:tracked.txt"], shared, git_env)
    if code != 0 or out != b"alpha\nbeta\n":
        raise RuntimeError("common repository native Git reference failed")
    code, out, err = run([str(git), "config", "--get", "diff.external"], shared, git_env)
    if code != 0 or out != b"synthetic-helper\n":
        raise RuntimeError("common repository config was not resolved by native Git")
    invoke("policy", wasm.with_name("policy_probe.wasm"), policy, b"policy_probe_passed\n")
    invoke("policy-commondir", wasm, shared, error=[b"unsupported git metadata"])

    broker = work / "broker"
    broker.mkdir(mode=0o700)
    for name in ["symlink", "hardlink", "fifo", "depth", "bytes", "entries"]:
        src = broker / name
        src.mkdir(mode=0o700)
        if name == "symlink": (src / "item").symlink_to(work / "outside-canary")
        elif name == "hardlink": os.link(work / "outside-canary", src / "item")
        elif name == "fifo": os.mkfifo(src / "item")
        elif name == "depth":
            target = src
            for _ in range(18):
                target = target / "child"
                target.mkdir()
        elif name == "entries":
            for number in range(2049): (src / f"file-{number}").touch()
        else:
            with (src / "item").open("wb") as file: file.truncate(16 * 1024 * 1024 + 1)
        try:
            copy_snapshot(src, broker / f"{name}-copy")
            results[f"broker-{name}"] = {"passed": False}
        except RuntimeError:
            results[f"broker-{name}"] = {"passed": True}
    return results


def main():
    ART.mkdir(parents=True, exist_ok=True)
    for vendor in (TEST / "guest/vendor").iterdir():
        provenance = json.loads((vendor / "LOMI-PROVENANCE.json").read_text())
        changed = [name for name, digest in provenance["upstream_files"].items()
                   if hashlib.sha256((vendor / name).read_bytes()).hexdigest() != digest]
        if sorted(changed) != sorted(provenance["modified"]):
            raise RuntimeError("vendor patch inventory mismatch")
        actual_files = {str(path.relative_to(vendor)) for path in vendor.rglob("*") if path.is_file()}
        if actual_files != set(provenance["upstream_files"]) | set(provenance["added"]):
            raise RuntimeError("vendor file inventory mismatch")
    # This harness never opens caller-supplied repositories.
    work = ART / "synthetic"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(mode=0o700)
    home = work / "home"
    home.mkdir(mode=0o700)
    template = work / "empty-template"
    template.mkdir()
    source = work / "source"
    source.mkdir(mode=0o700)
    git = git_runtime()
    env = {"HOME": str(home), "TMPDIR": str(work), "LC_ALL": "C",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": "/dev/null",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_ATTR_NOSYSTEM": "1",
           "GIT_CONFIG_COUNT": "0", "GIT_AUTHOR_NAME": "Synthetic Fixture",
           "GIT_AUTHOR_EMAIL": "fixture@example.invalid", "GIT_COMMITTER_NAME": "Synthetic Fixture",
           "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
           "GIT_AUTHOR_DATE": "2001-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2001-01-01T00:00:00Z"}

    def capture(*args):
        result = run([str(git), "--no-pager", *args], source, env)
        if result[0] != 0:
            raise RuntimeError(f"synthetic Git failed: {args[0]}")
        return result[1].decode("utf-8")

    version = capture("--version").strip()
    capture("init", "--quiet", "--initial-branch=main", f"--template={template}")
    (source / "tracked.txt").write_text("alpha\nbeta\n", encoding="utf-8")
    capture("add", "--", "tracked.txt")
    capture("-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "synthetic base")
    capture("repack", "-ad")
    capture("prune-packed")
    (source / "tracked.txt").write_text("alpha\nstaged\n", encoding="utf-8")
    capture("add", "--", "tracked.txt")
    (source / "tracked.txt").write_text("alpha\nworktree\n", encoding="utf-8")
    (source / "untracked.txt").write_text("synthetic untracked\n", encoding="utf-8")
    expected = {
        "status": capture("status", "--porcelain=v1", "--untracked-files=all"),
        "diff": capture("diff", "--no-ext-diff", "--no-textconv", "--no-color", "--", "tracked.txt"),
        "staged_diff": capture("diff", "--cached", "--no-ext-diff", "--no-textconv", "--no-color", "--", "tracked.txt"),
        "log": capture("log", "-1", "--format=%H%x00%s"),
        "show": capture("show", "--no-ext-diff", "--no-textconv", "HEAD:tracked.txt"),
    }
    staged = capture("show", "--no-ext-diff", "--no-textconv", ":tracked.txt")
    worktree = (source / "tracked.txt").read_text()
    def structured_diff(before, after, args):
        numbers = capture("diff", *args, "--no-ext-diff", "--no-textconv", "--numstat", "--", "tracked.txt").split('\t')
        # The deliberately fixed two-line fixture has exactly one replacement.
        # Native Git supplies counts and both sides independently of gix.
        return {"before": before, "after": after, "removals": int(numbers[1]),
                "additions": int(numbers[0]), "hunks": [{"before": [1, 2], "after": [1, 2]}]}
    log_id, message = expected["log"].rstrip('\n').split('\0')
    structured = {"status": [{"path": line[3:], "index": line[0], "worktree": line[1]} for line in expected["status"].splitlines()],
                  "diff": structured_diff(staged, worktree, []),
                  "staged_diff": structured_diff(expected["show"], staged, ["--cached"]),
                  "log": [{"id": log_id, "message": message}], "show": expected["show"], "index_entries": 1}
    (ART / "expected.json").write_text(json.dumps(expected, indent=2) + "\n")
    (ART / "expected-structured.json").write_text(json.dumps(structured, indent=2) + "\n")
    snapshot = work / "snapshot"
    bounds = copy_snapshot(source, snapshot)
    before = tree_digest(snapshot)
    # Build tools may use normal Cargo/Rust installation configuration; only
    # synthetic Git and guest execution have empty environments.
    for project, target in (("guest", ["--release", "--target", "wasm32-wasip1"]), ("host", [])):
        if project == "host" and not (ART / "host-target/debug/lomi-git-wasi-host").exists() and shutil.disk_usage(ROOT).free < 8 * 1024**3:
            raise RuntimeError("initial Wasmtime build requires at least 8 GiB free headroom")
        argv = ["cargo", "+1.98.1", "build", "--locked", "--manifest-path", str(TEST / project / "Cargo.toml"),
                "--target-dir", str(ART / f"{project}-target"), *target]
        code, stdout, stderr = run(argv, ROOT, dict(os.environ), timeout=600)
        (ART / f"{project}-build.log").write_bytes(stdout + stderr)
        if code:
            raise RuntimeError(f"{project} build failed: exit {code}; see artifact log")
    wasm = ART / "guest-target/wasm32-wasip1/release/lomi-git-wasi-guest.wasm"
    host = ART / "host-target/debug/lomi-git-wasi-host"
    argv = [str(host), str(wasm), str(snapshot)]
    if sys.platform == "darwin":
        argv = ["/usr/bin/time", "-l", *argv]
    code, stdout, stderr = run(argv, work, {}, timeout=60)
    (ART / "worker.stdout").write_bytes(stdout)
    (ART / "worker.stderr").write_bytes(stderr)
    actual = json.loads(stdout) if code == 0 else None
    compared = actual == structured
    mmap_snapshot = work / "mmap-snapshot"
    mmap_snapshot.mkdir(mode=0o700)
    (mmap_snapshot / "mmap-probe.bin").write_bytes(b"abcdef")
    probe = wasm.with_name("mmap_probe.wasm")
    probe_code, probe_stdout, probe_stderr = run([str(host), str(probe), str(mmap_snapshot)], work, {}, timeout=30)
    (ART / "mmap-probe.stderr").write_bytes(probe_stderr)
    probe_passed = probe_code == 0 and probe_stdout == b"mmap_readonly_probe_passed\n"
    security = security_probes(work, host, wasm, source, git, env)
    report = {"qualified": False, "phase": "patched-gix-packed-repository", "platform": sys.platform,
              "git": version, "rust": "1.98.1", "gix": "0.88.0", "wasmtime": "49.0.3",
              "snapshot": bounds, "snapshot_sha256": before,
              "snapshot_unchanged": before == tree_digest(snapshot),
              "guest_bytes": wasm.stat().st_size, "host_bytes": host.stat().st_size,
              "guest_sha256": hashlib.sha256(wasm.read_bytes()).hexdigest(),
              "host_sha256": hashlib.sha256(host.read_bytes()).hexdigest(),
              "lockfile_sha256": {project: hashlib.sha256((TEST / project / "Cargo.lock").read_bytes()).hexdigest() for project in ["guest", "host"]},
              "maximum_rss_bytes": int(match.group(1)) if (match := re.search(rb"(\d+)  maximum resident set size", stderr)) else None,
              "worker_exit": code, "stdout": stdout.decode("utf-8", errors="replace"),
              "stderr": stderr.decode("utf-8", errors="replace"),
              "mmap_probe_passed": probe_passed, "exact_structured_comparison": compared,
              "security_probes": security,
              "actual": actual,
              "operations_compared": ["status", "diff", "staged_diff", "log", "show"] if compared else [], "windows": "not run"}
    (ART / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if compared and probe_passed and all(item["passed"] for item in security.values()) and report["snapshot_unchanged"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
