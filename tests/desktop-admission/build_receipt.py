"""Build provenance for private E0 binaries. A receipt is local build evidence,
not a signature or a product supply-chain trust boundary.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

from owned_process import run_owned

SCHEMA = 1
FEATURES = {"host": ["default:host"], "desktop": ["e0-admission-probe"], "child": []}


def digest(path):
    checksum = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def command(argv, **kwargs):
    result = run_owned(argv, **kwargs)
    result.check_returncode()
    return result.stdout.strip()


def files_digest(root):
    """Do not follow dependency symlinks; bind both links and installed files."""
    root = Path(root)
    if not root.is_dir():
        raise RuntimeError("required installed dependency directory is missing")
    # scandir and onerror make unreadable roots/subdirectories fail closed.
    with os.scandir(root):
        pass
    def traversal_error(error):
        raise error
    checksum = hashlib.sha256()
    for folder, directories, files in os.walk(root, followlinks=False, onerror=traversal_error):
        directories[:] = sorted(name for name in directories if name not in {".cache", ".vite", ".tmp"})
        for name in sorted(files + [name for name in directories if (Path(folder) / name).is_symlink()]):
            path = Path(folder) / name
            relative = str(path.relative_to(root))
            value = "link:" + os.readlink(path) if path.is_symlink() else "file:" + digest(path)
            checksum.update(json.dumps([relative, value], separators=(",", ":")).encode())
    return checksum.hexdigest()


def dependency_inputs(checkout, main):
    dependencies = {}
    for relative in ["node_modules", "packages/ai-runtime/node_modules", "packages/remote-terminal-runtime/node_modules"]:
        actual = checkout / relative
        approved = (main / relative).resolve(strict=True)
        if not actual.is_symlink():
            raise RuntimeError("detached checkout dependency must be an approved symlink: " + relative)
        resolved = actual.resolve(strict=True)
        if resolved != approved:
            raise RuntimeError("detached checkout dependency target changed: " + relative)
        dependencies[relative] = {"link": os.readlink(actual), "resolvedTarget": str(resolved),
                                  "approvedTarget": str(approved), "sha256": files_digest(resolved)}
    return dependencies


def build_environment():
    # Explicit build inputs only: no production credentials or arbitrary Cargo,
    # compiler, Node, preload, or dotenv overrides inherited from the shell.
    return {"PATH": os.environ["PATH"], "HOME": str(Path.home()), "TMPDIR": "/private/tmp", "LANG": "en_US.UTF-8"}


def snapshot(root, source, checkout, target):
    env = build_environment()
    tracked = command(["git", "-C", str(checkout), "ls-files", "-z"], timeout=10).split("\0")
    paths = {str(Path("desktop") / name): checkout / name for name in tracked if name}
    for name in ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"]:
        paths["canonical/" + name] = root / name
    for folder in [root / "crates/lomi-admission-spike", source]:
        for path in folder.rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts:
                paths[str(path.relative_to(root))] = path
    for path in [root / "tools/run_desktop_admission.py", root / "tools/owned_process.py"]:
        paths[str(path.relative_to(root))] = path
    configs = {}
    for directory in [root / ".cargo", checkout / ".cargo", checkout / "src-tauri/.cargo", Path.home() / ".cargo"]:
        for name in ["config", "config.toml"]:
            path = directory / name
            configs[str(path)] = digest(path) if path.is_file() else None
    versions = {tool: command([tool, *arguments], env=env, cwd=root, timeout=10) for tool, arguments in {
        "rustc": ["-vV"], "cargo": ["--version"], "node": ["--version"], "/usr/bin/xcodebuild": ["-version"],
    }.items()}
    main = root.parent / "lomi"
    dependencies = dependency_inputs(checkout, main)
    return {"sources": {name: digest(path) for name, path in sorted(paths.items())},
            "dependencies": dependencies, "cargoConfiguration": configs, "toolchain": versions, "features": FEATURES,
            "targets": {"host": str(root / "target"), "desktop": str(target), "triple": next(line[6:] for line in versions["rustc"].splitlines() if line.startswith("host: "))},
            "buildEnvironmentSha256": hashlib.sha256(json.dumps(env, sort_keys=True).encode()).hexdigest()}


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def verify(receipt_path, inputs, binaries):
    receipt = json.loads(Path(receipt_path).read_text())
    expected = {"schema": SCHEMA, "inputs": inputs,
                "binaries": {name: digest(path) for name, path in binaries.items()}}
    if receipt != expected:
        raise RuntimeError("missing, stale, or changed E0 build receipt/input/binary")
    return receipt


def build(root, source, checkout, target, receipt_path, binaries):
    # Never leave a previous successful receipt valid after a failed new build.
    Path(receipt_path).unlink(missing_ok=True)
    before = snapshot(root, source, checkout, target)
    env = build_environment()
    command(["cargo", "build", "--locked", "-p", "lomi-admission-spike"], cwd=root, env=env, timeout=600)
    command(["cargo", "build", "--locked", "--manifest-path", str(checkout / "src-tauri/Cargo.toml"),
             "--features", "e0-admission-probe", "--bin", "lomi"], cwd=root,
            env={**env, "CARGO_TARGET_DIR": str(target)}, timeout=600)
    with tempfile.TemporaryDirectory(prefix="e0-admission-build-", dir=root / "artifacts") as temporary:
        stage = Path(temporary)
        command(["rustc", str(source / "controlled-child.rs"), "-o", str(stage / "controlled-child")], cwd=root, env=env, timeout=60)
        shutil.copy2(root / "target/debug/lomi-admission-spike", stage / "host")
        shutil.copy2(target / "debug/lomi", stage / "desktop")
        after = snapshot(root, source, checkout, target)
        if before != after:
            raise RuntimeError("E0 build inputs changed during controlled build")
        for name, destination in binaries.items():
            destination.parent.mkdir(exist_ok=True)
            if destination.parent.is_symlink() or destination.is_symlink():
                raise RuntimeError("private E0 binary destination must not be a symlink")
            os.replace(stage / name, destination)
        atomic_json(receipt_path, {"schema": SCHEMA, "inputs": after,
                                  "binaries": {name: digest(path) for name, path in binaries.items()}})
    return verify(receipt_path, after, binaries)
