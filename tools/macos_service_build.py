"""Frozen-input, offline native build receipt for the macOS product proof."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import tomllib

from owned_process import run_owned


class BuildRejected(RuntimeError):
    pass


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(root):
    result = {}
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise BuildRejected("symlink_in_frozen_inputs")
        if stat.S_ISREG(metadata.st_mode):
            result[str(path.relative_to(root))] = {"sha256": sha(path), "mode": stat.S_IMODE(metadata.st_mode)}
        elif not stat.S_ISDIR(metadata.st_mode):
            raise BuildRejected("special_frozen_input")
    return result


def copy_tree(source, destination):
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if any(part in {"target", "node_modules", ".git", "__pycache__"} for part in relative.parts):
            continue
        if path.is_symlink():
            raise BuildRejected("symlink_in_source_inputs")
        target = destination / relative
        if path.is_dir():
            target.mkdir(mode=0o700, parents=True, exist_ok=True)
        elif path.is_file():
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(path, target)


def freeze(source, root, cargo_home):
    inputs = root / "inputs"
    inputs.mkdir(mode=0o700)
    for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml"):
        shutil.copyfile(source / name, inputs / name)
    for name in ("crates", "vendor", "tests"):
        copy_tree(source / name, inputs / name)
    (inputs / "tools").mkdir(mode=0o700)
    for name in ("macos_service_build.py", "run_macos_product_service.py", "owned_process.py"):
        shutil.copyfile(source / "tools" / name, inputs / "tools" / name)
    if (source / ".cargo").exists():
        copy_tree(source / ".cargo", inputs / ".cargo")
    registry = inputs / "registry"
    registry.mkdir(mode=0o700)
    archives = root / "locked-dependency-archives"
    archives.mkdir(mode=0o700)
    packages = tomllib.loads((inputs / "Cargo.lock").read_text())["package"]
    dependency_hashes = {}
    for package in packages:
        if not package.get("source", "").startswith("registry+"):
            continue
        name = package["name"] + "-" + package["version"]
        candidates = list((cargo_home / "registry/cache").glob("*/" + name + ".crate"))
        matching = [path for path in candidates if sha(path) == package["checksum"]]
        archive = archives / (name + ".crate")
        if len(matching) == 1:
            shutil.copyfile(matching[0], archive)
        elif not candidates:
            # Fetch only an already-locked archive, with no index update or
            # dependency resolution. Its Cargo.lock checksum remains authority.
            url = "https://static.crates.io/crates/" + package["name"] + "/" + name + ".crate"
            fetched = run_owned(["/usr/bin/curl", "--disable", "--fail", "--silent", "--show-error", "--location", "--proto", "=https", "--tlsv1.2", "--max-time", "60", "--output", str(archive), url], env={"PATH": "/usr/bin:/bin", "LANG": "C"}, timeout=65)
            if fetched.returncode:
                raise BuildRejected("locked_dependency_archive_unavailable")
        else:
            raise BuildRejected("locked_dependency_archive_checksum_mismatch")
        if sha(archive) != package["checksum"]:
            raise BuildRejected("dependency_changed_during_freeze")
        dependency_hashes[name] = package["checksum"]
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                if not (member.name == name or member.name.startswith(name + "/")) or member.issym() or member.islnk():
                    raise BuildRejected("unsafe_dependency_archive")
            tar.extractall(registry, filter="data")
        package_root = registry / name
        files = {str(path.relative_to(package_root)): sha(path) for path in package_root.rglob("*") if path.is_file() and path.name != ".cargo-checksum.json"}
        (package_root / ".cargo-checksum.json").write_text(json.dumps({"package": package["checksum"], "files": files}))
    config_dir = inputs / ".cargo"
    config_dir.mkdir(mode=0o700, exist_ok=True)
    if (config_dir / "config").exists():
        raise BuildRejected("legacy_cargo_config_requires_explicit_review")
    config = config_dir / "config.toml"
    original = config.read_text() if config.exists() else ""
    if "source" in tomllib.loads(original):
        raise BuildRejected("repository_source_override_requires_explicit_review")
    config.write_text(original + '\n[source.crates-io]\nreplace-with = "frozen-registry"\n[source.frozen-registry]\ndirectory = ' + json.dumps(str(registry)) + "\n")
    for path in inputs.rglob("*"):
        if path.is_file():
            # Build scripts may fs::copy registry files into shared OUT_DIR.
            # Preserve owner write access there so subsequent ordinary builds
            # can replace generated copies. Private ancestors and pre/post byte
            # manifests, not same-UID readonly bits, bind these inputs.
            path.chmod(0o600 if path.is_relative_to(registry) else 0o400)
    return inputs, dependency_hashes


def build_frozen(root, inputs, command, environment, runner=run_owned, link_nonce=None):
    """Reject any failed build or changed frozen input before exposing a binary."""
    before = manifest(inputs)
    (root / "input-manifest.json").write_text(json.dumps(before, sort_keys=True, indent=2) + "\n")
    receipt = {"qualifiedSourceBuild": False, "command": [str(x) for x in command],
               "environment": environment, "beforeManifestSha256": sha(root / "input-manifest.json"),
               "exitCode": None}
    receipt_path = root / "build-receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
    result = runner([str(x) for x in command], env=environment, cwd=str(inputs), timeout=600)
    (root / "build.stdout.log").write_text(result.stdout)
    (root / "build.stderr.log").write_text(result.stderr)
    receipt["exitCode"] = result.returncode
    receipt["inputsUnchanged"] = manifest(inputs) == before
    receipt["stdoutSha256"] = sha(root / "build.stdout.log")
    receipt["stderrSha256"] = sha(root / "build.stderr.log")
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
    if result.returncode != 0 or not receipt["inputsUnchanged"]:
        raise BuildRejected("build_failed_or_inputs_changed")
    # The final-target-only UUID metadata argument makes Cargo's extra-args
    # hash unique to this run. Copy its exact linker output, never the mutable
    # convenience link or an ordinary source-independent Cargo disambiguator.
    invocations = [line for line in result.stderr.splitlines() if "Running `" in line and "--crate-name lomiremote " in line and "--crate-type bin" in line]
    if len(invocations) != 1 or not link_nonce or ("metadata=" + link_nonce) not in invocations[0]:
        raise BuildRejected("unique_product_link_invocation_missing")
    hashes = re.findall(r"extra-filename=(-[a-f0-9]+)(?: |`)", invocations[0])
    if len(hashes) != 1:
        raise BuildRejected("unique_product_link_output_missing")
    target = Path(environment["CARGO_TARGET_DIR"])
    linked = target / "debug/deps" / ("lomiremote" + hashes[0])
    destination = root / "bin/lomiremote"
    destination.parent.mkdir(mode=0o700, exist_ok=True)
    descriptor = os.open(linked, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        initial = os.fstat(descriptor)
        if not stat.S_ISREG(initial.st_mode):
            raise BuildRejected("product_link_output_not_regular")
        with os.fdopen(descriptor, "rb", closefd=False) as source, destination.open("xb") as output:
            shutil.copyfileobj(source, output)
            output.flush()
            os.fsync(output.fileno())
        final = os.fstat(descriptor)
        if (initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns) != (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns):
            raise BuildRejected("product_changed_while_copying")
    finally:
        os.close(descriptor)
    destination.chmod(0o500)
    if manifest(inputs) != before:
        raise BuildRejected("inputs_changed_before_binary_commit")
    receipt.update({"linkedBinaryVerified": True, "linkedArtifact": str(linked), "binarySha256": sha(destination)})
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def workspace_manifest(source):
    selected = {}
    for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml"):
        selected[name] = sha(source / name)
    for name in ("macos_service_build.py", "run_macos_product_service.py", "owned_process.py"):
        selected["tools/" + name] = sha(source / "tools" / name)
    for name in ("crates", "vendor", "tests", ".cargo"):
        folder = source / name
        if not folder.exists():
            continue
        for path in folder.rglob("*"):
            relative = path.relative_to(source)
            if any(part in {"target", "node_modules", ".git", "__pycache__"} for part in relative.parts):
                continue
            if path.is_symlink():
                raise BuildRejected("symlink_in_live_source")
            if path.is_file():
                # External acceptance drivers are archived but are not compiled
                # or executed by this product proof. Keep their unrelated edits
                # outside the live-source build projection.
                if name == "tests" and path.suffix not in {".rs", ".c", ".h", ".toml"}:
                    continue
                selected[str(relative)] = sha(path)
    return selected


def ancestor_config_absence(inputs):
    candidates = [parent / ".cargo" / name for parent in inputs.parents for name in ("config", "config.toml")]
    if any(path.exists() or path.is_symlink() for path in candidates):
        raise BuildRejected("unfrozen_ancestor_cargo_config")
    return [str(path) for path in candidates]


def verify_build(root):
    receipt = json.loads((root / "build-receipt.json").read_text())
    if not receipt.get("qualifiedSourceBuild") or not receipt.get("completed") or sha(root / "bin/lomiremote") != receipt["binarySha256"]:
        raise BuildRejected("qualified_source_build_required")
    if sha(root / "input-manifest.json") != receipt["beforeManifestSha256"]:
        raise BuildRejected("input_manifest_not_bound_to_build")
    if manifest(root / "inputs") != json.loads((root / "input-manifest.json").read_text()):
        raise BuildRejected("frozen_compile_inputs_changed")
    return receipt


def frozen_command(interpreter, harness, root):
    return [str(interpreter), "-B", str(harness), "--run-native", "--frozen-run", str(root)]


def controlled_build(source, root):
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    rustup = Path(os.environ.get("RUSTUP_HOME", Path.home() / ".rustup"))
    # Select the pinned toolchain directly. No user Cargo config, wrappers,
    # rustflags, credentials or inherited compilation environment enters build.
    channel = tomllib.loads((source / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    toolchains = list((rustup / "toolchains").glob(channel + "-*-apple-darwin"))
    if len(toolchains) != 1:
        raise BuildRejected("unique_pinned_native_toolchain_required")
    toolchain = toolchains[0]
    tools = {name: toolchain / "bin" / name for name in ("cargo", "rustc", "rustdoc")}
    minimal = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
    versions = {}
    for name in ("cargo", "rustc"):
        result = run_owned([str(tools[name]), "-vV"], env=minimal, timeout=10)
        if result.returncode:
            raise BuildRejected("tool_version_failed")
        versions[name] = {"version": result.stdout, "sha256": sha(tools[name])}
    sdk = run_owned(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"], env=minimal, timeout=10)
    clang = run_owned(["/usr/bin/xcrun", "clang", "--version"], env=minimal, timeout=10)
    if sdk.returncode or clang.returncode:
        raise BuildRejected("sdk_version_failed")
    sdk_path = Path(sdk.stdout.strip())
    versions["sdk"] = {"path": str(sdk_path), "settingsSha256": sha(sdk_path / "SDKSettings.json")}
    versions["clang"] = clang.stdout
    versions["host"] = {"system": os.uname().sysname, "release": os.uname().release, "machine": os.uname().machine}
    (root / "tool-versions.json").write_text(json.dumps(versions, indent=2) + "\n")
    source_before = workspace_manifest(source)
    inputs, dependencies = freeze(source, root, cargo_home)
    if workspace_manifest(source) != source_before:
        raise BuildRejected("source_changed_during_freeze")
    for name, digest in source_before.items():
        if name == ".cargo/config.toml":
            continue  # The preserved config is extended with frozen replacement.
        if sha(inputs / name) != digest:
            raise BuildRejected("source_copy_mismatch")
    (root / "source-manifest.json").write_text(json.dumps(source_before, sort_keys=True, indent=2) + "\n")
    with tarfile.open(root / "compile-inputs.tar.gz", "w:gz") as archive:
        archive.add(inputs, arcname="inputs", recursive=True)
    (root / "locked-dependencies.json").write_text(json.dumps(dependencies, sort_keys=True, indent=2) + "\n")
    private_cargo = root / "cargo-home"
    private_cargo.mkdir(mode=0o700)
    environment = {**minimal, "CARGO_HOME": str(private_cargo), "CARGO_TARGET_DIR": str(source / "target"),
                   "CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "2", "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0", "RUSTC": str(tools["rustc"]), "RUSTDOC": str(tools["rustdoc"]),
                   "SDKROOT": str(sdk_path)}
    link_nonce = "lomi_e1_" + root.name.replace("-", "")
    command = [tools["cargo"], "rustc", "--manifest-path", inputs / "Cargo.toml", "--locked", "--offline", "-vv", "--message-format=json-render-diagnostics", "-p", "lomiremote", "--bin", "lomiremote", "--", "-C", "metadata=" + link_nonce]
    ancestors = ancestor_config_absence(inputs)
    receipt = build_frozen(root, inputs, command, environment, link_nonce=link_nonce)
    if ancestor_config_absence(inputs) != ancestors:
        raise BuildRejected("ancestor_cargo_config_changed")
    receipt["ancestorCargoConfigurationsAbsent"] = ancestors
    if workspace_manifest(source) != source_before or any(sha(tools[name]) != versions[name]["sha256"] for name in ("cargo", "rustc")):
        receipt["qualifiedSourceBuild"] = False
        receipt["failure"] = "source_or_tool_changed_during_build"
        (root / "build-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        raise BuildRejected("source_or_tool_changed_during_build")
    receipt["sourceManifestSha256"] = sha(root / "source-manifest.json")
    receipt["inputArchiveSha256"] = sha(root / "compile-inputs.tar.gz")
    receipt["toolsSha256"] = sha(root / "tool-versions.json")
    receipt["lockedDependenciesSha256"] = sha(root / "locked-dependencies.json")
    receipt.update({"qualifiedSourceBuild": True, "completed": True})
    temporary = root / "build-receipt.tmp"
    temporary.write_text(json.dumps(receipt, indent=2) + "\n")
    with temporary.open("rb") as committed:
        os.fsync(committed.fileno())
    os.replace(temporary, root / "build-receipt.json")
    return receipt
