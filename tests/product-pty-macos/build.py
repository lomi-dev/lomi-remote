"""Frozen terminal-fixture build using the reviewed shared locked registry."""
import hashlib
import ctypes
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tarfile
import tomllib

REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY / "tools"))
from owned_process import run_owned
from macos_service_build import BuildRejected, ancestor_config_absence, copy_tree, manifest, sha

SEED = Path.home() / ".lomi-service-artifacts/fc701e76-d184-4c71-9f5f-51bdd99ba472"
BINARY = "lomi_pty_macos_coalition_fixture"
MINIMAL = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}


def projection(source):
    selected = {}
    for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "tools/owned_process.py", "tools/macos_service_build.py"):
        selected[name] = sha(source / name)
    for path in (source / "crates").glob("*/Cargo.toml"):
        selected[str(path.relative_to(source))] = sha(path)
    for prefix in ("crates/lomi-terminal", "crates/lomi-terminal-state", "crates/lomi-remote-protocol", "vendor", ".cargo", "tests/product-pty-macos"):
        root = source / prefix
        if root.exists():
            for path in root.rglob("*"):
                if any(part in {"__pycache__", "target", ".git", "node_modules"} for part in path.relative_to(root).parts):
                    continue
                if path.is_symlink():
                    raise BuildRejected("symlink_in_compile_projection")
                if path.is_file():
                    selected[str(path.relative_to(source))] = sha(path)
    return selected


def registry_guard(lock):
    seed_registry = SEED / "inputs/registry"
    original = json.loads((SEED / "input-manifest.json").read_text())
    seed_expected = {name.removeprefix("registry/"): value for name, value in original.items() if name.startswith("registry/")}
    if manifest(seed_registry) != seed_expected:
        raise BuildRejected("reviewed_shared_registry_changed")
    packages = [package for package in lock["package"] if package.get("source", "").startswith("registry+")]
    cache_key = hashlib.sha256(json.dumps([(p["name"], p["version"], p["checksum"]) for p in packages]).encode()).hexdigest()
    base = Path.home() / ".lomi-pty-registry"
    base.mkdir(mode=0o700, exist_ok=True)
    if base.is_symlink() or stat.S_IMODE(base.stat().st_mode) != 0o700 or base.stat().st_uid != os.geteuid():
        raise BuildRejected("private_registry_cache_required")
    cache = base / cache_key
    with (base / "cache.lock").open("a+b") as lock_file:
        os.fchmod(lock_file.fileno(), 0o600)
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        if not cache.exists():
            import uuid
            temporary = base / (".prepare-" + str(uuid.uuid4()))
            temporary.mkdir(mode=0o700)
            registry = temporary / "registry"
            registry.mkdir(mode=0o700)
            clone = ctypes.CDLL(None, use_errno=True).clonefile
            clone.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
            # APFS copy-on-write clones preserve old proof inputs, do not create
            # shared writable hard links, and avoid another physical500MiB copy.
            for path in sorted(seed_registry.rglob("*")):
                relative = path.relative_to(seed_registry)
                destination = registry / relative
                if path.is_symlink():
                    raise BuildRejected("symlink_in_registry_seed")
                if path.is_dir():
                    destination.mkdir(mode=0o700)
                elif path.is_file():
                    if clone(os.fsencode(path), os.fsencode(destination), 0):
                        raise BuildRejected("apfs_registry_clone_failed")
            if manifest(registry) != seed_expected:
                raise BuildRejected("cloned_seed_mismatch")
            extensions = temporary / "archives"
            extensions.mkdir(mode=0o700)
            cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
            added = {}
            for package in packages:
                name = package["name"] + "-" + package["version"]
                if (registry / name).exists():
                    continue
                candidates = list((cargo_home / "registry/cache").glob("*/" + name + ".crate"))
                matching = [path for path in candidates if sha(path) == package["checksum"]]
                if len(matching) != 1:
                    raise BuildRejected("new_locked_archive_unavailable")
                archive = extensions / (name + ".crate")
                shutil.copyfile(matching[0], archive)
                archive.chmod(0o600)
                if sha(archive) != package["checksum"]:
                    raise BuildRejected("new_locked_archive_changed")
                with tarfile.open(archive) as tar:
                    seen = set()
                    for member in tar.getmembers():
                        parts = Path(member.name).parts
                        if not parts or parts[0] != name or any(part in {".", ".."} for part in parts) or member.name.startswith("/") or member.issym() or member.islnk() or member.name in seen or not (member.isfile() or member.isdir()):
                            raise BuildRejected("unsafe_locked_archive_member")
                        seen.add(member.name)
                    tar.extractall(registry, filter="data")
                package_root = registry / name
                for path in package_root.rglob("*"):
                    path.chmod(0o700 if path.is_dir() else 0o600)
                files = {str(path.relative_to(package_root)): sha(path) for path in package_root.rglob("*") if path.is_file() and path.name != ".cargo-checksum.json"}
                checksum = package_root / ".cargo-checksum.json"
                checksum.write_text(json.dumps({"package": package["checksum"], "files": files}))
                checksum.chmod(0o600)
                added[name] = package["checksum"]
            cache_manifest = temporary / "registry-manifest.json"
            cache_manifest.write_text(json.dumps(manifest(registry), sort_keys=True))
            cache_manifest.chmod(0o600)
            cache_receipt = temporary / "cache-receipt.json"
            cache_receipt.write_text(json.dumps({"sourceSeedReceiptSha256": sha(SEED / "build-receipt.json"), "seedInputManifestSha256": sha(SEED / "input-manifest.json"), "registryManifestSha256": sha(cache_manifest), "addedLockedArchives": added, "apfsClone": True}, indent=2))
            cache_receipt.chmod(0o600)
            os.rename(temporary, cache)
    registry = cache / "registry"
    expected = json.loads((cache / "registry-manifest.json").read_text())
    cache_receipt = json.loads((cache / "cache-receipt.json").read_text())
    if cache_receipt["registryManifestSha256"] != sha(cache / "registry-manifest.json"):
        raise BuildRejected("registry_cache_manifest_changed")
    actual = manifest(registry)
    if actual != expected:
        raise BuildRejected("shared_registry_changed")
    archives = {}
    for package in packages:
        name = package["name"] + "-" + package["version"]
        archive = SEED / "locked-dependency-archives" / (name + ".crate")
        if not archive.exists():
            archive = cache / "archives" / (name + ".crate")
        checksum = package["checksum"]
        if not archive.is_file() or sha(archive) != checksum:
            raise BuildRejected("locked_archive_missing_from_reviewed_cache")
        checksum_file = json.loads((registry / name / ".cargo-checksum.json").read_text())
        if checksum_file["package"] != checksum or any(actual[name + "/" + key]["sha256"] != value for key, value in checksum_file["files"].items()):
            raise BuildRejected("locked_registry_content_mismatch")
        archives[name] = checksum
    return registry, actual, archives


def freeze_build(source, root):
    source_before = projection(source)
    lock = tomllib.loads((source / "Cargo.lock").read_text())
    registry, cache_before, archives = registry_guard(lock)
    (root / "shared-registry-manifest.json").write_text(json.dumps(cache_before, sort_keys=True))
    (root / "locked-archives.json").write_text(json.dumps(archives, sort_keys=True))
    inputs = root / "inputs"
    inputs.mkdir(mode=0o700)
    for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml"):
        shutil.copyfile(source / name, inputs / name)
    for name in ("crates", "vendor", "tests"):
        copy_tree(source / name, inputs / name)
    (inputs / "tools").mkdir(mode=0o700)
    for name in ("owned_process.py", "macos_service_build.py"):
        shutil.copyfile(source / "tools" / name, inputs / "tools" / name)
    if (source / ".cargo").exists():
        copy_tree(source / ".cargo", inputs / ".cargo")
    if projection(source) != source_before or any(sha(inputs / name) != digest for name, digest in source_before.items()):
        raise BuildRejected("source_changed_during_freeze")
    config = inputs / ".cargo/config.toml"
    config.parent.mkdir(mode=0o700, exist_ok=True)
    if (config.parent / "config").exists():
        raise BuildRejected("legacy_cargo_config")
    original = config.read_text() if config.exists() else ""
    if "source" in tomllib.loads(original):
        raise BuildRejected("unreviewed_source_override")
    config.write_text(original + '\n[source.crates-io]\nreplace-with = "reviewed-cache"\n[source.reviewed-cache]\ndirectory = ' + json.dumps(str(registry)) + "\n")
    for path in inputs.rglob("*"):
        if path.is_file():
            # Defeat shared-target stale timestamp reuse, including sources
            # previously extracted from archives with old/fixed mtimes.
            os.utime(path, None)
            path.chmod(0o400)
    before = manifest(inputs)
    (root / "source-manifest.json").write_text(json.dumps(source_before, sort_keys=True))
    (root / "input-manifest.json").write_text(json.dumps(before, sort_keys=True))
    with tarfile.open(root / "compile-inputs.tar.gz", "w:gz") as archive:
        archive.add(inputs, arcname="inputs")
    channel = tomllib.loads((inputs / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    toolchains = list((Path.home() / ".rustup/toolchains").glob(channel + "-*-apple-darwin"))
    if len(toolchains) != 1:
        raise BuildRejected("pinned_toolchain_not_unique")
    tools = {name: toolchains[0] / "bin" / name for name in ("cargo", "rustc", "rustdoc")}
    versions = {}
    for name in ("cargo", "rustc"):
        result = run_owned([str(tools[name]), "-vV"], env=MINIMAL, timeout=10)
        if result.returncode:
            raise BuildRejected("tool_version_failed")
        versions[name] = {"sha256": sha(tools[name]), "version": result.stdout}
    sdk = run_owned(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"], env=MINIMAL, timeout=10)
    clang = run_owned(["/usr/bin/xcrun", "--sdk", "macosx", "--find", "clang"], env=MINIMAL, timeout=10)
    ar = run_owned(["/usr/bin/xcrun", "--sdk", "macosx", "--find", "ar"], env=MINIMAL, timeout=10)
    if any(result.returncode for result in (sdk, clang, ar)):
        raise BuildRejected("native_sdk_tools_missing")
    sdk_path, clang_path, ar_path = (Path(result.stdout.strip()) for result in (sdk, clang, ar))
    clang_version = run_owned([str(clang_path), "--version"], env=MINIMAL, timeout=10)
    versions.update(sdk={"path": str(sdk_path), "settingsSha256": sha(sdk_path / "SDKSettings.json")},
                    clang={"path": str(clang_path), "sha256": sha(clang_path), "version": clang_version.stdout},
                    ar={"path": str(ar_path), "sha256": sha(ar_path)}, os=list(os.uname()))
    (root / "tools.json").write_text(json.dumps(versions, indent=2))
    cargo_home = root / "cargo-home"
    cargo_home.mkdir(mode=0o700)
    environment = {**MINIMAL, "CARGO_HOME": str(cargo_home), "CARGO_TARGET_DIR": str(source / "target"),
                   "CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "2", "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0",
                   "RUSTC": str(tools["rustc"]), "RUSTDOC": str(tools["rustdoc"]), "SDKROOT": str(sdk_path), "CC": str(clang_path), "AR": str(ar_path)}
    nonce = "lomi_coalition_" + root.name.replace("-", "")
    command = [str(tools["cargo"]), "rustc", "--locked", "--offline", "-vv", "--message-format=json-render-diagnostics", "-p", "lomi-terminal", "--bin", "lomi-pty-macos-coalition-fixture", "--features", "experimental-macos-coalition-cleanup", "--", "-C", "metadata=" + nonce]
    receipt = {"completed": False, "qualifiedSourceBuild": False, "command": command, "environment": environment,
               "beforeManifestSha256": sha(root / "input-manifest.json"), "registryManifestSha256": sha(root / "shared-registry-manifest.json"),
               "registrySourceReceiptSha256": sha(SEED / "build-receipt.json"), "registryRoot": str(registry)}
    def save():
        (root / "build-receipt.json").write_text(json.dumps(receipt, indent=2))
    save()
    ancestors = ancestor_config_absence(inputs)
    result = run_owned(command, cwd=inputs, env=environment, timeout=300)
    (root / "build.stdout.log").write_text(result.stdout)
    (root / "build.stderr.log").write_text(result.stderr)
    receipt.update(exitCode=result.returncode, stdoutSha256=sha(root / "build.stdout.log"), stderrSha256=sha(root / "build.stderr.log"))
    save()
    if result.returncode or manifest(inputs) != before or registry_guard(lock)[1] != cache_before or projection(source) != source_before or ancestor_config_absence(inputs) != ancestors:
        raise BuildRejected("build_failure_or_changed_inputs")
    invocations = [line for line in result.stderr.splitlines() if "Running `" in line and "--crate-name " + BINARY + " " in line and "--crate-type bin" in line]
    if len(invocations) != 1 or ("metadata=" + nonce) not in invocations[0]:
        raise BuildRejected("unique_final_target_invocation_missing")
    hashes = re.findall(r"extra-filename=(-[a-f0-9]+)(?: |`)", invocations[0])
    if len(hashes) != 1:
        raise BuildRejected("unique_final_output_missing")
    linked = source / "target/debug/deps" / (BINARY + hashes[0])
    destination = root / "bin/pty-fixture"
    destination.parent.mkdir(mode=0o700)
    fd = os.open(linked, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        initial = os.fstat(fd)
        if not stat.S_ISREG(initial.st_mode):
            raise BuildRejected("link_output_not_regular")
        with os.fdopen(fd, "rb", closefd=False) as compiled, destination.open("xb") as output:
            shutil.copyfileobj(compiled, output)
            output.flush()
            os.fsync(output.fileno())
        final = os.fstat(fd)
        if (initial.st_ino, initial.st_dev, initial.st_size, initial.st_mtime_ns) != (final.st_ino, final.st_dev, final.st_size, final.st_mtime_ns):
            raise BuildRejected("binary_changed_while_copying")
    finally:
        os.close(fd)
    destination.chmod(0o500)
    if manifest(inputs) != before or registry_guard(lock)[1] != cache_before or projection(source) != source_before or any(sha(tools[name]) != versions[name]["sha256"] for name in ("cargo", "rustc")) or sha(clang_path) != versions["clang"]["sha256"] or sha(sdk_path / "SDKSettings.json") != versions["sdk"]["settingsSha256"]:
        raise BuildRejected("final_input_or_tool_guard_failed")
    receipt.update(binarySha256=sha(destination), linkedArtifact=str(linked), sourceManifestSha256=sha(root / "source-manifest.json"),
                   inputArchiveSha256=sha(root / "compile-inputs.tar.gz"), toolsSha256=sha(root / "tools.json"),
                   lockedArchivesSha256=sha(root / "locked-archives.json"), ancestorCargoConfigurationsAbsent=ancestors,
                   completed=True, qualifiedSourceBuild=True)
    save()
    return receipt


def verify(root):
    receipt = json.loads((root / "build-receipt.json").read_text())
    if not receipt.get("qualifiedSourceBuild") or not receipt.get("completed") or sha(root / "bin/pty-fixture") != receipt["binarySha256"]:
        raise BuildRejected("qualified_build_required")
    if sha(root / "input-manifest.json") != receipt["beforeManifestSha256"] or manifest(root / "inputs") != json.loads((root / "input-manifest.json").read_text()):
        raise BuildRejected("frozen_inputs_changed")
    if sha(root / "shared-registry-manifest.json") != receipt["registryManifestSha256"] or manifest(Path(receipt["registryRoot"])) != json.loads((root / "shared-registry-manifest.json").read_text()):
        raise BuildRejected("shared_registry_changed")
    return receipt
