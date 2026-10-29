"""Bounded host HTTPS checks, explicit public snapshots and immutable receipts.

Cargo compiles the shared live workspace using its existing target directory.
Before/after hashes establish stability of the listed public inputs during this
run; copied inputs are review evidence, not an isolated/reconstructed build.
No provider material, environment files or generated TLS keys enter evidence.
"""
from pathlib import Path
import hashlib
import json
import os
import resource
import stat
import sys
import time
import uuid

REPO = Path(__file__).resolve().parents[3]
CRATE = REPO / "crates/lomi-host-http"
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
            raise RuntimeError("unsafe explicit public source input")
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def exclusive_json(path, value):
    with path.open("x") as output:
        json.dump(value, output, indent=2)
        output.write("\n")


def private_directory(path):
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError("unsafe evidence directory")


def main():
    initialize_process_ownership()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.chdir(REPO)
    os.umask(0o077)
    task_home = Path("/tmp") / ("lomi-host-http-home-" + str(uuid.uuid4()))
    task_home.mkdir(mode=0o700)
    env = {"PATH": os.environ["PATH"], "HOME": str(task_home), "LANG": "C.UTF-8",
           "CARGO_HOME": "/Users/woro/.cargo", "RUSTUP_HOME": "/Users/woro/.rustup",
           "RUSTUP_TOOLCHAIN": "1.98.1", "CARGO_NET_OFFLINE": "true"}
    env.update(CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0", CARGO_PROFILE_RELEASE_DEBUG="0", CARGO_BUILD_JOBS="2", CARGO_TARGET_DIR=str(REPO / "target"))
    parent = REPO / "artifacts/rust-host-http"
    private_directory(parent)
    destination = parent / str(uuid.uuid4())
    destination.mkdir(mode=0o700)
    print("host_http_validation_started", destination.relative_to(REPO), flush=True)
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
            raise RuntimeError("public source changed while freezing")
    exclusive_json(destination / "source-before.json", before)
    evidence = {
        "scope": "Blocking credential and host-access data HTTPS transport library, owned loopback TLS tests and bounded resolver; no host CLI/IPC/lifecycle/production integration claim",
        "build_claim": "Shared live workspace compilation; explicit listed public inputs stable before/after, frozen copies retained for review; no isolated-build claim",
        "started_unix_seconds": int(time.time()), "source_before": before, "runs": [],
        "build_environment": {key: env[key] for key in ["RUSTUP_TOOLCHAIN", "CARGO_NET_OFFLINE", "CARGO_INCREMENTAL", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG", "CARGO_PROFILE_RELEASE_DEBUG", "CARGO_BUILD_JOBS", "CARGO_TARGET_DIR"]},
    }
    success = False
    try:
        commands = [
            [sys.executable, "-B", "crates/lomi-host-http/tools/test_source_coverage.py"],
            ["rustfmt", "--edition", "2024", "--check", "crates/lomi-host-http/src/lib.rs", "crates/lomi-host-http/src/resolver.rs", "crates/lomi-host-http/src/tests.rs", "crates/lomi-host-http/src/data.rs", "crates/lomi-host-http/src/data_tests.rs"],
            ["cargo", "test", "--offline", "--locked", "-p", "lomi-host-http"],
            ["cargo", "clippy", "--offline", "--locked", "-p", "lomi-host-http", "--all-targets", "--", "-D", "warnings"],
        ]
        for argv in commands:
            run = {"command": argv}
            try:
                result = run_owned(argv, cwd=REPO, env=env, timeout=600)
                run.update(exit=result.returncode, stdout=result.stdout, stderr=result.stderr)
            except BaseException as error:
                run.update(exit=None, runner_failure=type(error).__name__)
                raise
            finally:
                evidence["runs"].append(run)
                exclusive_json(destination / ("command-%02d.json" % len(evidence["runs"])), run)
            print("host_http_command_completed", len(evidence["runs"]), "exit", result.returncode, flush=True)
            if result.returncode:
                raise RuntimeError("focused command failed; see retained command receipt")
        success = True
    finally:
        evidence["source_after"] = sources()
        evidence["source_stable"] = before == evidence["source_after"]
        evidence["passed"] = success and evidence["source_stable"]
        exclusive_json(destination / "receipt.json", evidence)
        for path in destination.rglob("*"):
            if path.is_file():
                path.chmod(0o400)
        for path in sorted((path for path in destination.rglob("*") if path.is_dir()), reverse=True):
            path.chmod(0o500)
        destination.chmod(0o500)
    if not evidence["passed"]:
        raise RuntimeError("listed public sources changed during checks")
    print("host_http_frozen_validation:passed", destination.relative_to(REPO), flush=True)


if __name__ == "__main__":
    main()
