"""Run focused lifecycle checks with retained process control and source hashes.

No provider bytes are copied into evidence. The private fixture path is the sole
redacted argv entry; it is created 0700 below the allowlisted account home and
removed only after checking its retained inode/owner/mode.
"""
from pathlib import Path
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import time
import uuid

REPO = Path(__file__).resolve().parents[3]
CRATE = REPO / "crates/lomi-host-auth"
sys.path.insert(0, str(REPO / "tools"))
from owned_process import initialize_process_ownership, run_owned
from source_coverage import check_source_coverage


def sources():
    names = json.loads((CRATE / "tools/source-allowlist.json").read_text())
    check_source_coverage(REPO, names)
    result = {}
    for name in names:
        path = REPO / name
        if path.is_symlink() or not path.is_file() or path.resolve() != path:
            raise RuntimeError("unsafe explicit source input")
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def private_directory(path):
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
        raise RuntimeError("unsafe private evidence directory")


def exclusive_json(path, value):
    with path.open("x") as output:
        json.dump(value, output, indent=2)
        output.write("\n")


def main():
    initialize_process_ownership()
    os.chdir(REPO)
    os.umask(0o077)
    env = {"PATH": os.environ["PATH"], "HOME": "/Users/woro", "LANG": "C.UTF-8"}
    env.update(CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0", CARGO_PROFILE_RELEASE_DEBUG="0", CARGO_BUILD_JOBS="2", CARGO_TARGET_DIR=str(REPO / "target"))
    parent = REPO / "artifacts/rust-host-auth"
    private_directory(parent)
    destination = parent / str(uuid.uuid4())
    destination.mkdir(mode=0o700)
    print("host_auth_validation_started", destination.relative_to(REPO), flush=True)
    frozen = destination / "inputs"
    frozen.mkdir(mode=0o700)
    before = sources()
    for name, digest in before.items():
        source = REPO / name
        copied = frozen / name
        copied.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with copied.open("xb") as output:
            output.write(source.read_bytes())
        if hashlib.sha256(copied.read_bytes()).hexdigest() != digest:
            raise RuntimeError("source changed while freezing")
    exclusive_json(destination / "source-before.json", before)
    historical = CRATE / "evidence/local.json"
    if historical.is_file():
        with (destination / "historical-local.json").open("xb") as output:
            output.write(historical.read_bytes())
    evidence = {"scope": "Host credential library and explicitly selected Unix protected-file process/reopen; no HTTP/PostgreSQL/DPAPI/Keychain integration claim", "started_unix_seconds": int(time.time()), "source_before": before, "runs": [], "build_environment": {k: env[k] for k in ["CARGO_INCREMENTAL", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG", "CARGO_PROFILE_RELEASE_DEBUG", "CARGO_BUILD_JOBS", "CARGO_TARGET_DIR"]}}
    def run(argv, redact_last=False):
        result = run_owned(argv, cwd=REPO, env=env, timeout=240)
        evidence["runs"].append({"command": argv[:-1] + ["[private fixture directory]"] if redact_last else argv, "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        exclusive_json(destination / ("command-%02d.json" % len(evidence["runs"])), evidence["runs"][-1])
        if result.returncode:
            raise RuntimeError("focused command failed")
    success = False
    fixture = None
    pin = None
    try:
        run([sys.executable, "crates/lomi-host-auth/tools/test_source_coverage.py"])
        run(["rustc", "--version"])
        run(["cargo", "--version"])
        run(["rustfmt", "--edition", "2024", "--check", "crates/lomi-host-auth/src/lib.rs", "crates/lomi-host-auth/tests/lifecycle.rs", "crates/lomi-host-auth/examples/protected_file.rs"])
        run(["cargo", "test", "--offline", "--locked", "-p", "lomi-host-auth", "--all-targets"])
        run(["cargo", "clippy", "--offline", "--locked", "-p", "lomi-host-auth", "--all-targets", "--", "-D", "warnings"])
        run(["cargo", "build", "--offline", "--locked", "-p", "lomi-host-auth", "--example", "protected_file"])
        home = Path("/Users/woro")
        st = home.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o022:
            raise RuntimeError("unsafe allowlisted fixture parent")
        fixture = Path(tempfile.mkdtemp(prefix=".lomi-host-auth-", dir=home))
        pin = fixture.lstat()
        if pin.st_uid != os.getuid() or stat.S_IMODE(pin.st_mode) != 0o700 or not stat.S_ISDIR(pin.st_mode):
            raise RuntimeError("unsafe fixture directory")
        binary = str(REPO / "target/debug/examples/protected_file")
        run([binary, "create", str(fixture)], True)
        run([binary, "reopen", str(fixture)], True)
        success = True
    finally:
        if fixture is not None and pin is not None:
            current = fixture.lstat()
            if (current.st_dev, current.st_ino, current.st_uid, current.st_mode) != (pin.st_dev, pin.st_ino, pin.st_uid, pin.st_mode):
                raise RuntimeError("fixture identity changed; refuse cleanup")
            shutil.rmtree(fixture)
            evidence["private_fixture_removed"] = not fixture.exists()
        evidence["source_after"] = sources()
        evidence["source_stable"] = evidence["source_before"] == evidence["source_after"]
        evidence["passed"] = success and evidence["source_stable"]
        exclusive_json(destination / "receipt.json", evidence)
        for path in destination.rglob("*"):
            if path.is_file():
                path.chmod(0o400)
        for path in sorted((p for p in destination.rglob("*") if p.is_dir()), reverse=True):
            path.chmod(0o500)
        destination.chmod(0o500)
    if not evidence["passed"]:
        raise RuntimeError("source changed during validation")
    print("host_auth_frozen_validation:passed", str(destination.relative_to(REPO)))


if __name__ == "__main__":
    main()
