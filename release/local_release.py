#!/usr/bin/env python3
"""Build and serve isolated local Lomi Remote release-test bundles."""
from __future__ import annotations

import argparse
import fcntl
import base64
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path, PurePosixPath
import platform as host_platform
import pwd
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.parse

import publish_release
import trust


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STATE = Path.home() / ".local" / "share" / "lomi-remote-local"
LOCAL_ORIGIN = "https://127.0.0.1:18443/remote/releases/"
LOCAL_PORT = 18443
PLATFORMS = ("macos-aarch64", "linux-x86_64")
VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
SNAPSHOT_RE = re.compile(r"[0-9a-f]{64}\Z")
REMOTE_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*@(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9_.:-]+)\Z")
MAX_LOCAL_FILE = 2 * 1024 * 1024 * 1024


class LocalReleaseError(RuntimeError):
    pass


def fail(message: str):
    raise LocalReleaseError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path, limit: int = 1024 * 1024) -> dict:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        fail(f"expected a bounded regular JSON file: {path.name}")
    try:
        result = trust.loads(path.read_bytes())
    except (OSError, trust.TrustError) as error:
        fail(f"could not read {path.name}: {error}")
    if not isinstance(result, dict):
        fail(f"{path.name} must contain a JSON object")
    return result


def write_json(path: Path, value: object, mode: int = 0o644) -> None:
    path.write_bytes(trust.canonical(value) + b"\n")
    os.chmod(path, mode)


def real_dir(path: Path, mode: int, *, create: bool = True) -> Path:
    path = Path(os.path.abspath(path))
    if create:
        path.mkdir(mode=mode, parents=True, exist_ok=True)
    try:
        info = path.lstat()
    except OSError as error:
        raise LocalReleaseError(f"directory is unavailable: {path}") from error
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        fail(f"expected a real directory, not a symlink: {path}")
    if stat.S_IMODE(info.st_mode) & 0o077:
        if not create:
            fail(f"directory permissions are too broad: {path}")
        os.chmod(path, mode)
    return path


def state_paths(state: Path | None) -> dict[str, Path]:
    root = Path(os.path.abspath(Path(state or DEFAULT_STATE).expanduser()))
    production_trust = (ROOT / "release" / "trust").resolve()
    resolved = root.resolve(strict=False)
    if (resolved == production_trust or production_trust in resolved.parents
            or resolved in production_trust.parents):
        fail("local state must be separate from release/trust production materials")
    return {
        "root": root,
        "keys": root / "devkeys",
        "public": root / "public",
        "tls": root / "tls",
        "snapshots": root / "snapshots",
        "bundles": root / "bundles",
        "cache": root / "cache",
        "web": root / "web",
    }


def secure_state(state: Path | None) -> dict[str, Path]:
    paths = state_paths(state)
    real_dir(paths["root"], 0o700)
    for key in ("keys", "tls", "snapshots", "bundles", "cache"):
        real_dir(paths[key], 0o700)
    real_dir(paths["public"], 0o755)
    return paths


def _openssl() -> str:
    return trust._openssl()


def _openssl_run(command: list[str]) -> None:
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=False, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as error:
        fail(f"OpenSSL could not create local HTTPS trust material: {error}")
    if result.returncode:
        fail("OpenSSL could not create local HTTPS trust material")


def generate_tls_material(tls_dir: Path, openssl: str | None = None) -> dict[str, Path]:
    """Create a private local CA and a server cert valid only for loopback."""
    real_dir(tls_dir, 0o700)
    paths = {
        "ca_key": tls_dir / "local-test-ca.key.pem",
        "ca_pem": tls_dir / "local-test-ca.pem",
        "ca_der": tls_dir / "local-test-ca.der",
        "server_key": tls_dir / "server.key.pem",
        "server_cert": tls_dir / "server.pem",
    }
    if any(os.path.lexists(path) for path in paths.values()):
        fail("local HTTPS trust material already exists; refusing to replace it")
    command = openssl or _openssl()
    extension_file = None
    csr_path = None
    try:
        _openssl_run([command, "genpkey", "-algorithm", "RSA", "-pkeyopt",
                      "rsa_keygen_bits:3072", "-out", str(paths["ca_key"])])
        os.chmod(paths["ca_key"], 0o600)
        _openssl_run([command, "req", "-x509", "-new", "-key", str(paths["ca_key"]),
                      "-sha256", "-days", "3650", "-subj", "/CN=Lomi Local Release Test CA",
                      "-addext", "basicConstraints=critical,CA:TRUE",
                      "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                      "-out", str(paths["ca_pem"])])
        os.chmod(paths["ca_pem"], 0o644)
        _openssl_run([command, "genpkey", "-algorithm", "RSA", "-pkeyopt",
                      "rsa_keygen_bits:2048", "-out", str(paths["server_key"])])
        os.chmod(paths["server_key"], 0o600)
        with tempfile.NamedTemporaryFile("w", encoding="ascii", dir=tls_dir,
                                         prefix=".server-", suffix=".ext", delete=False) as f:
            extension_file = Path(f.name)
            f.write("basicConstraints=critical,CA:FALSE\n")
            f.write("keyUsage=critical,digitalSignature,keyEncipherment\n")
            f.write("extendedKeyUsage=serverAuth\n")
            f.write("subjectAltName=IP:127.0.0.1,DNS:localhost\n")
        os.chmod(extension_file, 0o600)
        with tempfile.NamedTemporaryFile("w", encoding="ascii", dir=tls_dir,
                                         prefix=".server-", suffix=".csr", delete=False) as f:
            csr_path = Path(f.name)
        _openssl_run([command, "req", "-new", "-key", str(paths["server_key"]),
                      "-subj", "/CN=127.0.0.1", "-out", str(csr_path)])
        _openssl_run([command, "x509", "-req", "-in", str(csr_path), "-CA",
                      str(paths["ca_pem"]), "-CAkey", str(paths["ca_key"]),
                      "-CAcreateserial", "-days", "825", "-sha256", "-extfile",
                      str(extension_file), "-out", str(paths["server_cert"])])
        os.chmod(paths["server_cert"], 0o644)
        _openssl_run([command, "x509", "-in", str(paths["ca_pem"]), "-outform",
                      "DER", "-out", str(paths["ca_der"])])
        os.chmod(paths["ca_der"], 0o644)
        serial = tls_dir / "local-test-ca.srl"
        if serial.exists():
            serial.unlink()
        return paths
    except BaseException:
        for path in paths.values():
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        raise
    finally:
        for path in (extension_file, csr_path):
            if path is not None:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass


def initialize(state: Path | None = None) -> dict[str, Path]:
    paths = secure_state(state)
    if (paths["public"] / "release-public.json").exists() or any(paths["keys"].iterdir()):
        fail("local development trust already exists; refusing to replace it")
    try:
        tls = generate_tls_material(paths["tls"])
        config = trust.initialize(paths["keys"], paths["public"])
        config_path = paths["public"] / "release-public.json"
        dev_config = read_json(config_path, 16 * 1024)
        if dev_config != config:
            fail("new development trust configuration changed unexpectedly")
        # The only edit to trust.initialize's public config is this local URL.
        dev_config["origin"] = LOCAL_ORIGIN
        write_json(config_path, dev_config)
    except (trust.TrustError, OSError) as error:
        for name in ("local-test-ca.key.pem", "local-test-ca.pem", "local-test-ca.der",
                     "server.key.pem", "server.pem", "local-test-ca.srl"):
            try:
                (paths["tls"] / name).unlink()
            except FileNotFoundError:
                pass
        fail(f"could not initialize local development trust: {error}")
    real_dir(paths["web"], 0o755)
    print(f"Initialized isolated local trust under {paths['root']}")
    print(f"Local origin: {LOCAL_ORIGIN}")
    print(f"CA certificate: {tls['ca_pem']}")
    return paths


def git(root: Path, *args: str, check: bool = True, stdout=None, text: bool = True):
    try:
        return subprocess.run(["git", "-C", str(root), *args], check=check,
                              stdout=stdout, text=text, timeout=120)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        fail(f"Git snapshot operation failed: {error}")


def git_output(root: Path, *args: str) -> str:
    return git(root, *args, stdout=subprocess.PIPE).stdout.strip()


def workspace_version(manifest: Path) -> str:
    try:
        with manifest.open("rb") as stream:
            document = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"could not read workspace version from Cargo.toml: {error}")
    version = document.get("workspace", {}).get("package", {}).get("version")
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        fail("workspace Cargo.toml must declare a stable X.Y.Z package version")
    return version


def set_workspace_version(manifest: Path, version: str) -> None:
    lines = manifest.read_text(encoding="utf-8").splitlines(keepends=True)
    start = next((i for i, line in enumerate(lines) if line.strip() == "[workspace.package]"), None)
    if start is None:
        fail("Cargo.toml has no [workspace.package] table")
    end = next((i for i in range(start + 1, len(lines))
                if re.fullmatch(r"\s*\[[^]]+\]\s*(?:#.*)?\s*", lines[i])), len(lines))
    hits = [i for i in range(start + 1, end) if re.match(r"^\s*version\s*=\s*", lines[i])]
    if len(hits) != 1:
        fail("Cargo.toml must declare exactly one workspace package version")
    lines[hits[0]] = re.sub(r"^(\s*version\s*=\s*)[^#\r\n]+(.*)$",
                            rf'\g<1>"{version}"\g<2>', lines[hits[0]])
    manifest.write_text("".join(lines), encoding="utf-8", newline="")


def tracked_files(root: Path) -> list[str]:
    try:
        result = subprocess.run(["git", "-C", str(root), "ls-files", "--stage", "-z"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=True, timeout=60)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        fail(f"could not enumerate tracked source files: {error}")
    entries = {}
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, _object_id, stage = header.decode("ascii").split(" ")
            name = os.fsdecode(raw_path)
        except (ValueError, UnicodeDecodeError) as error:
            fail(f"Git returned an invalid tracked-file entry: {error}")
        if stage != "0":
            fail("resolve Git merge conflicts before building a local release")
        if mode == "160000":
            fail(f"tracked submodule cannot be snapshotted safely: {name}")
        entries[name] = int(mode, 8)
    return sorted(entries, key=os.fsencode)


def _target_in_snapshot(snapshot: Path, relative: str) -> Path:
    pure = PurePosixPath(relative.replace(os.sep, "/"))
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        fail("Git tracked an unsafe path; refusing to create a snapshot")
    target = snapshot.joinpath(*pure.parts)
    if not target.resolve(strict=False).is_relative_to(snapshot.resolve()):
        fail("tracked path resolves outside the local snapshot")
    return target


def _copy_tracked(root: Path, snapshot: Path, paths: list[str]) -> list[str]:
    copied = []
    for relative in paths:
        source = root / relative
        try:
            if not source.parent.resolve(strict=True).is_relative_to(root.resolve(strict=True)):
                fail(f"tracked source parent resolves outside the checkout: {relative}")
            info = source.lstat()
        except FileNotFoundError:
            continue
        target = _target_in_snapshot(snapshot, relative)
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if stat.S_ISLNK(info.st_mode):
            link = os.readlink(source)
            if os.path.isabs(link) or not (target.parent / link).resolve(strict=False).is_relative_to(snapshot.resolve()):
                fail(f"tracked symlink escapes the local snapshot: {relative}")
            os.symlink(link, target)
        elif stat.S_ISREG(info.st_mode):
            shutil.copyfile(source, target)
            os.chmod(target, stat.S_IMODE(info.st_mode))
        else:
            fail(f"tracked source contains an unsupported file type: {relative}")
        copied.append(relative)
    return copied


def _remove_untracked_snapshot_files(snapshot: Path, tracked: set[str]) -> None:
    # `cargo update --workspace --offline` may create local bookkeeping files.
    # Keep the snapshot limited to its source tracked paths and edited lockfile.
    for directory, child_dirs, files in os.walk(snapshot, topdown=False, followlinks=False):
        base = Path(directory)
        for name in files:
            path = base / name
            relative = path.relative_to(snapshot).as_posix()
            if relative not in tracked:
                if path.is_symlink() or path.is_file():
                    path.unlink()
        for name in child_dirs:
            path = base / name
            if path.is_symlink():
                relative = path.relative_to(snapshot).as_posix()
                if relative not in tracked:
                    path.unlink()
            elif not any(path.iterdir()):
                path.rmdir()


def content_fingerprint(root: Path, names: list[str]) -> str:
    records = []
    for name in sorted(names, key=os.fsencode):
        path = root / name
        try:
            if not path.parent.resolve(strict=True).is_relative_to(root.resolve(strict=True)):
                fail(f"source parent resolves outside the snapshot: {name}")
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            data = os.readlink(path).encode("utf-8", errors="surrogateescape")
            kind, mode = "symlink", 0o777
        elif stat.S_ISREG(info.st_mode):
            data = path.read_bytes()
            kind, mode = "file", stat.S_IMODE(info.st_mode)
        else:
            fail(f"unsupported source file type in snapshot: {name}")
        records.append({"path": name, "kind": kind, "mode": mode,
                        "size": len(data), "sha256": _sha256_bytes(data)})
    return _sha256_bytes(trust.canonical(records))


def _source_identity(root: Path) -> tuple[str, str]:
    name = git_output(root, "config", "--get", "user.name")
    email = git_output(root, "config", "--get", "user.email")
    if not name or not email or any(ch in name + email for ch in "\r\n\x00"):
        fail("configure git user.name and user.email before creating a local snapshot")
    return name, email


def _snapshot_sidecar(paths: dict[str, Path], snapshot_id: str) -> Path:
    return paths["snapshots"] / f"{snapshot_id}.json"


def snapshot_source(root: Path = ROOT, state: Path | None = None,
                    version: str | None = None) -> dict:
    paths = secure_state(state)
    fd = os.open(paths["root"] / "snapshot.lock",
                 os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "r+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _snapshot_source(root, state, version)


def _snapshot_source(root: Path = ROOT, state: Path | None = None,
                     version: str | None = None) -> dict:
    """Capture tracked working-tree content in a clean, immutable Git commit."""
    root = Path(root).resolve(strict=True)
    paths = secure_state(state)
    source_head = git_output(root, "rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", source_head):
        fail("local release snapshots require a 40-character source Git commit")
    author, email = _source_identity(root)
    tracked = tracked_files(root)
    untracked = subprocess.run(["git", "-C", str(root), "ls-files", "--others",
                                "--exclude-standard", "-z"], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, check=True, timeout=60).stdout
    untracked_count = sum(bool(path) for path in untracked.split(b"\0"))
    work = Path(tempfile.mkdtemp(prefix="snapshot-", dir=paths["snapshots"]))
    os.chmod(work, 0o700)
    snapshot = work / "source"
    snapshot.mkdir(mode=0o700)
    try:
        copied = _copy_tracked(root, snapshot, tracked)
        if not (snapshot / "Cargo.toml").is_file():
            fail("tracked snapshot has no workspace Cargo.toml")
        effective_version = version or workspace_version(snapshot / "Cargo.toml")
        if not VERSION_RE.fullmatch(effective_version):
            fail("version must use stable X.Y.Z form")
        if version is not None:
            set_workspace_version(snapshot / "Cargo.toml", effective_version)
            try:
                subprocess.run(["cargo", "update", "--workspace", "--offline"],
                               cwd=snapshot, check=True, timeout=900)
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                fail(f"could not update the versioned snapshot lockfile offline: {error}")
        _remove_untracked_snapshot_files(snapshot, set(copied))
        content_sha = content_fingerprint(snapshot, copied)
        version_sha = _sha256_bytes(effective_version.encode("ascii"))
        snapshot_id = _sha256_bytes(trust.canonical({
            "sourceHead": source_head, "contentSha256": content_sha,
            "versionSha256": version_sha,
        }))
        if not SNAPSHOT_RE.fullmatch(snapshot_id):
            fail("failed to calculate the local snapshot identifier")
        expected = {"snapshotId": snapshot_id, "sourceHead": source_head,
                    "version": effective_version, "versionSha256": version_sha,
                    "contentSha256": content_sha, "trackedPaths": copied}
        destination = paths["snapshots"] / snapshot_id
        sidecar = _snapshot_sidecar(paths, snapshot_id)
        if os.path.lexists(destination) or os.path.lexists(sidecar):
            if not destination.is_dir() or destination.is_symlink() or not sidecar.is_file():
                fail("existing snapshot is incomplete; refusing to replace it")
            descriptor = read_json(sidecar, 4 * 1024 * 1024)
            revision = git_output(destination, "rev-parse", "HEAD")
            dirty = git_output(destination, "status", "--porcelain")
            if (any(descriptor.get(key) != expected.get(key) for key in expected)
                    or descriptor.get("snapshotRevision") != revision or dirty
                    or content_fingerprint(destination, copied) != content_sha):
                fail("existing local snapshot is incomplete or has changed")
            shutil.rmtree(work)
            if untracked_count:
                print(f"Excluded {untracked_count} untracked source path(s) from snapshot.")
            print(f"Snapshot {snapshot_id} ({effective_version}) reused at {destination}")
            return {**descriptor, "path": destination, "untrackedCount": untracked_count}

        # Cargo may have emitted untracked local files. Only the tracked path
        # list copied above is staged into the snapshot commit.
        git(snapshot, "init", "--quiet")
        git(snapshot, "add", "--force", "--all")
        message = (
            "build(release): snapshot local release test inputs\n\n"
            "Capture the tracked working tree for local release testing.\n"
            "Keep this immutable build input separate from the source checkout.\n\n"
            "Validation:\n- Tracked source snapshot: passed\n"
            "- Production signing keys: not accessed"
        )
        commit = subprocess.run([
            "git", "-C", str(snapshot), "-c", f"user.name={author}",
            "-c", f"user.email={email}", "-c", "core.hooksPath=/dev/null",
            "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", message,
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False, timeout=120)
        if commit.returncode:
            fail("could not create the local snapshot commit using the source Git identity")
        revision = git_output(snapshot, "rev-parse", "HEAD")
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            fail("local snapshot commit has an unsupported Git object format")
        descriptor = {**expected, "snapshotRevision": revision, "trackedFiles": len(copied)}
        os.replace(snapshot, destination)
        write_json(sidecar, descriptor, 0o600)
        if untracked_count:
            print(f"Excluded {untracked_count} untracked source path(s) from snapshot.")
        print(f"Snapshot {snapshot_id} ({effective_version}) created at {destination}")
        return {**descriptor, "path": destination, "untrackedCount": untracked_count}
    finally:
        if work.exists():
            shutil.rmtree(work, ignore_errors=True)


def local_config(paths: dict[str, Path]) -> dict:
    config = read_json(paths["public"] / "release-public.json", 16 * 1024)
    if config.get("format") != 1 or config.get("repo") != trust.REPO:
        fail("local public trust configuration is unsupported")
    if config.get("origin") != LOCAL_ORIGIN:
        fail("local origin is not configured; run init with a clean state directory")
    root = paths["public"] / config.get("root_file", "")
    if not root.is_file() or sha256(root) != config.get("root_sha256"):
        fail("local development TUF root does not match its independent public pin")
    return config


def artifact_origin(config: dict, version: str, snapshot_id: str) -> str:
    if not VERSION_RE.fullmatch(version) or not SNAPSHOT_RE.fullmatch(snapshot_id):
        fail("invalid local version or snapshot identifier")
    return f"{config['origin']}v{version}/{snapshot_id}/"


def minimum_schema() -> int:
    config = read_json(ROOT / "release" / "host-config.json", 64 * 1024)
    value = config.get("minimumProfileSchema")
    if type(value) is not int or not 0 <= value <= 2**64 - 1:
        fail("release/host-config.json has an invalid minimumProfileSchema")
    return value


def _bundle_complete(directory: Path, *, platform_name: str, version: str,
                     artifact_url: str, revision: str, config: dict) -> bool:
    try:
        entry = read_json(directory / "installation-entry.json", 64 * 1024)
        manifest = read_json(directory / "bundle" / "build-manifest.json", 1024 * 1024)
        if (entry.get("format") != 1 or entry.get("platform") != platform_name
                or entry.get("version") != version or entry.get("releaseOrigin") != artifact_url):
            return False
        if (manifest.get("platform") != platform_name or manifest.get("version") != version
                or manifest.get("sourceRevision") != revision
                or manifest.get("releaseOrigin") != config["origin"]
                or manifest.get("artifactOrigin") != artifact_url
                or manifest.get("publicTufRootSha256") != config["root_sha256"]):
            return False
        for descriptor in (entry.get("archive"), entry.get("publicRoot")):
            if not isinstance(descriptor, dict) or set(descriptor) != {"url", "sha256", "size"}:
                return False
            name = Path(urllib.parse.urlsplit(descriptor["url"]).path).name
            path = directory / name
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_size != descriptor["size"]
                    or sha256(path) != descriptor["sha256"]):
                return False
        if platform_name.startswith("macos-"):
            archive = directory / Path(entry["archive"]["url"]).name
            receipt = read_json(Path(str(archive) + ".notarization.json"), 64 * 1024)
            return receipt.get("status") == "Accepted" and receipt.get("archive_sha256") == entry["archive"]["sha256"]
        bootstrap = entry.get("linuxBootstrap")
        if not isinstance(bootstrap, dict) or not (directory / "install-command.txt").is_file():
            return False
        for field in ("preflight", "manifest", "signature", "publicKey"):
            value = bootstrap.get(field)
            if not isinstance(value, dict):
                return False
            path = directory / Path(urllib.parse.urlsplit(value["url"]).path).name
            if not path.is_file() or path.stat().st_size != value.get("size"):
                return False
        return True
    except (OSError, KeyError, TypeError, ValueError, LocalReleaseError):
        return False


def selected_snapshot(state, version=None, snapshot_id=None):
    if snapshot_id is None:
        return snapshot_source(ROOT, state, version)
    if not SNAPSHOT_RE.fullmatch(snapshot_id):
        fail("snapshot must be an existing 64-character identifier")
    paths = secure_state(state)
    descriptor = read_json(_snapshot_sidecar(paths, snapshot_id), 4 * 1024 * 1024)
    source = paths["snapshots"] / snapshot_id
    if (source.is_symlink() or not source.is_dir()
            or descriptor.get("snapshotId") != snapshot_id
            or git_output(source, "rev-parse", "HEAD") != descriptor.get("snapshotRevision")
            or git_output(source, "status", "--porcelain")
            or content_fingerprint(source, descriptor["trackedPaths"]) != descriptor.get("contentSha256")):
        fail("selected snapshot has changed or is incomplete")
    if version is not None and descriptor.get("version") != version:
        fail("selected snapshot has a different version")
    return {**descriptor, "path": source}


def build(platform_name: str, state: Path | None = None, *, version: str | None = None,
          snapshot_id: str | None = None,
          ssh: str | None = None, ssh_options: tuple[str, ...] = ()) -> Path:
    if platform_name not in PLATFORMS:
        fail(f"unsupported local build platform: {platform_name}")
    paths = secure_state(state)
    fd = os.open(paths["root"] / f"build-{platform_name}.lock",
                 os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "r+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _build(platform_name, state, version=version, snapshot_id=snapshot_id,
                      ssh=ssh, ssh_options=ssh_options)


def _build(platform_name: str, state: Path | None = None, *, version: str | None = None,
          snapshot_id: str | None = None,
          ssh: str | None = None, ssh_options: tuple[str, ...] = ()) -> Path:
    if platform_name not in PLATFORMS:
        fail(f"unsupported local build platform: {platform_name}")
    if platform_name == "linux-x86_64" and not ssh:
        fail("linux-x86_64 builds require --ssh USER@HOST")
    if platform_name == "macos-aarch64" and ssh:
        fail("macos-aarch64 must be built locally on a native Mac")
    if platform_name.startswith("macos-") and host_platform.system() != "Darwin":
        fail("macOS bundles must be built and notarized on a native Mac")
    snapshot = selected_snapshot(state, version, snapshot_id)
    paths = secure_state(state)
    config = local_config(paths)
    run_origin = artifact_origin(config, snapshot["version"], snapshot["snapshotId"])
    output = paths["bundles"] / snapshot["snapshotId"] / platform_name
    real_dir(output.parent, 0o700)
    if os.path.lexists(output):
        if output.is_symlink() or not output.is_dir():
            fail("bundle output path is not a real directory")
        if _bundle_complete(output, platform_name=platform_name, version=snapshot["version"],
                           artifact_url=run_origin, revision=snapshot["snapshotRevision"], config=config):
            print(f"Reusing completed {platform_name} bundle: {output}")
            return output
        shutil.rmtree(output)

    if platform_name == "macos-aarch64":
        host_config = read_json(snapshot["path"] / "release/host-config.json", 64 * 1024)
        command = [sys.executable, str(snapshot["path"] / "release" / "build_release.py"),
                   "--platform", platform_name, "--release-origin", config["origin"],
                   "--artifact-origin", run_origin,
                   "--target-name", "macos/aarch64/lomiremote",
                   "--minimum-profile-schema", str(host_config["minimumProfileSchema"]),
                   "--public-root", str(paths["public"] / config["root_file"]),
                   "--public-root-sha256", config["root_sha256"], "--output", str(output),
                   "--local-test-ca", str(paths["tls"] / "local-test-ca.der")]
        env = os.environ.copy()
        env.update(host_config["bootstrap"])
        env.pop("LOMI_LOCAL_TEST_CA_FILE", None)
        target_dir = Path(env.get("CARGO_TARGET_DIR", str(paths["cache"] / platform_name))).expanduser().resolve()
        target_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        env["CARGO_TARGET_DIR"] = str(target_dir)
        subprocess.run(command, cwd=snapshot["path"], env=env, check=True)
    else:
        if not REMOTE_RE.fullmatch(ssh or ""):
            fail("SSH destination must use USER@HOST form")
        try:
            import local_remote
        except ImportError as error:
            fail(f"local SSH release helper is unavailable: {error}")
        local_remote.build_remote(
            host=ssh,
            ssh_options=list(ssh_options),
            source=snapshot["path"],
            public=paths["public"],
            ca_der=paths["tls"] / "local-test-ca.der",
            bootstrap_key=paths["keys"] / "linux-bootstrap.pem",
            output=output,
            origin=config["origin"],
            artifact_origin=run_origin,
            platform=platform_name,
        )
    if not _bundle_complete(output, platform_name=platform_name, version=snapshot["version"],
                            artifact_url=run_origin, revision=snapshot["snapshotRevision"], config=config):
        fail(f"{platform_name} build did not produce a complete verified bundle")
    return output


def _relative(value: str) -> PurePosixPath:
    if not isinstance(value, str) or "\\" in value:
        fail("release index contains an unsafe logical path")
    path = PurePosixPath(value)
    if (path.is_absolute() or not path.parts
            or any(part in {"", ".", ".."}
                   or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", part)
                   for part in path.parts)):
        fail("release index contains an unsafe logical path")
    return path


def _copy_verified(source: Path, destination: Path, *, digest: str | None = None,
                   size: int | None = None) -> None:
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_LOCAL_FILE:
        fail(f"release asset is not a bounded regular file: {source.name}")
    if size is not None and info.st_size != size:
        fail(f"release asset size differs from its inventory: {source.name}")
    source_hash = sha256(source)
    if digest is not None and source_hash != digest:
        fail(f"release asset digest differs from its inventory: {source.name}")
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    if os.path.lexists(destination):
        existing = destination.lstat()
        if (stat.S_ISREG(existing.st_mode) and existing.st_size == info.st_size
                and sha256(destination) == source_hash):
            return
        fail(f"release paths collide with different bytes: {destination.name}")
    shutil.copyfile(source, destination)
    os.chmod(destination, 0o644)
    if destination.stat().st_size != info.st_size or sha256(destination) != source_hash:
        fail(f"could not verify copied release asset: {destination.name}")


def _public_index_key(config: dict) -> dict:
    try:
        raw = base64.b64decode(config["index_public_key_base64"], validate=True)
    except (KeyError, ValueError, TypeError):
        fail("local index public key is malformed")
    if len(raw) != 32:
        fail("local index public key has an invalid length")
    return {"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": raw.hex()}}


def _verify_candidate(candidate: Path, *, version: str, tag: str,
                      platforms: set[str], config: dict) -> dict:
    try:
        data = (candidate / "release-index.json").read_bytes()
        envelope = trust.loads(data)
        if (not isinstance(envelope, dict) or set(envelope) != {"signed", "signature"}
                or trust.canonical(envelope) != data):
            fail("local release-index envelope is malformed")
        index = envelope["signed"]
        signature = base64.b64decode(envelope["signature"], validate=True)
        if not trust.verify_bytes(trust.canonical(index), signature, _public_index_key(config)):
            fail("local release-index signature is invalid")
        if (index.get("repository") != trust.REPO or index.get("tag") != tag
                or index.get("version") != version or set(index.get("platforms", [])) != platforms):
            fail("local release-index does not match requested version and platforms")
        if (candidate / "release-index-recovery.json").read_bytes() != data:
            fail("local release-index recovery copy differs from its signed envelope")
        if (candidate / "release-index.sig").read_bytes() != signature:
            fail("local detached release-index signature differs from its envelope")
        files = index.get("files")
        if not isinstance(files, dict):
            fail("local release-index has no file inventory")
        for logical, record in files.items():
            relative = _relative(logical)
            if (not isinstance(record, dict) or set(record) != {"asset", "size", "sha256"}
                    or not isinstance(record.get("asset"), str)
                    or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", record["asset"])
                    or type(record.get("size")) is not int
                    or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256", "")))):
                fail("local release-index contains an invalid file declaration")
            for path in (candidate / record["asset"], candidate.joinpath(*relative.parts)):
                info = path.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_size != record["size"]
                        or sha256(path) != record["sha256"]):
                    fail(f"local candidate asset failed inventory verification: {logical}")
        latest = read_json(candidate / "latest.json", 16 * 1024)
        expected = {"version": version, "tag": tag, "platforms": sorted(platforms),
                    "releaseUrl": f"https://github.com/{trust.REPO}/releases/tag/{tag}"}
        if set(latest) != set(expected) or latest != expected:
            fail("local latest.json does not match the signed release index")
        return index
    except (OSError, ValueError, KeyError, TypeError, trust.TrustError) as error:
        if isinstance(error, LocalReleaseError):
            raise
        fail(f"could not verify local candidate: {error}")


def _write_candidate(flat: Path, index: dict, candidate: Path, *,
                     version: str, tag: str, config: dict) -> None:
    if os.path.lexists(candidate):
        fail("candidate destination already exists and will not be overwritten")
    pending = Path(tempfile.mkdtemp(prefix=f".{candidate.name}.pending-", dir=candidate.parent))
    try:
        for source in flat.iterdir():
            if not stat.S_ISREG(source.lstat().st_mode):
                fail("publisher output must contain only flat regular files")
            _copy_verified(source, pending / source.name)
        files = index.get("files")
        if not isinstance(files, dict) or not files:
            fail("assembled release index has no file inventory")
        for logical, record in files.items():
            relative = _relative(logical)
            if not isinstance(record, dict):
                fail("assembled release index contains an invalid file declaration")
            if (type(record.get("size")) is not int or record["size"] < 0
                    or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256", "")))):
                fail("assembled release index contains an invalid file hash or size")
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", str(record.get("asset", ""))):
                fail("assembled release index contains an invalid asset name")
            _copy_verified(flat / record["asset"], pending.joinpath(*relative.parts),
                           digest=record["sha256"], size=record["size"])
        _canonical = {
            "version": version, "tag": tag, "platforms": sorted(index["platforms"]),
            "releaseUrl": f"https://github.com/{trust.REPO}/releases/tag/{tag}",
        }
        write_json(pending / "latest.json", _canonical)
        for name in ("release-index.json", "release-index-recovery.json", "release-index.sig",
                     "install.sh", "latest.json"):
            path = pending / name
            if not path.is_file() or path.is_symlink():
                fail(f"assembled release is missing {name}")
        _verify_candidate(pending, version=version, tag=tag,
                          platforms=set(index["platforms"]), config=config)
        os.replace(pending, candidate)
    except BaseException:
        shutil.rmtree(pending, ignore_errors=True)
        raise


def _web_dirs(root: Path, relative: str) -> Path:
    current = root
    for part in _relative(relative).parts:
        current = current / part
        if os.path.lexists(current):
            info = current.lstat()
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                fail(f"local web tree contains a non-directory parent: {part}")
        else:
            current.mkdir(mode=0o755)
    return current


def _atomic_symlink(link: Path, target: str, web_root: Path) -> None:
    root = web_root.resolve(strict=True)
    if os.path.lexists(link):
        info = link.lstat()
        if not stat.S_ISLNK(info.st_mode):
            fail(f"refusing to replace a non-symlink web alias: {link}")
        try:
            old = link.resolve(strict=True)
        except OSError:
            fail(f"refusing to replace a broken web symlink: {link}")
        if not old.is_relative_to(root):
            fail(f"refusing to replace a symlink that escapes the web root: {link}")
    temporary = link.with_name(f".{link.name}.{os.urandom(5).hex()}.pending")
    os.symlink(target, temporary)
    try:
        os.replace(temporary, link)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _promote(web_root: Path, candidate: Path, index: dict) -> None:
    releases = web_root / "remote" / "releases"
    if not candidate.resolve(strict=True).is_relative_to(web_root.resolve(strict=True)):
        fail("local candidate resolves outside the web root")
    _atomic_symlink(releases / ".current", os.path.relpath(candidate, releases), web_root)
    aliases = {"latest.json", "release-index.json", "release-index-recovery.json", "release-index.sig"}
    for logical, record in index["files"].items():
        aliases.add(logical)
        aliases.add(record["asset"])
    for alias in sorted(aliases):
        relative = _relative(alias)
        link = releases.joinpath(*relative.parts)
        _web_dirs(web_root, link.parent.relative_to(web_root).as_posix())
        target_path = os.path.relpath(releases.joinpath(".current", *relative.parts), link.parent)
        _atomic_symlink(link, target_path, web_root)
    _atomic_symlink(web_root / "remote" / "install.sh", "releases/.current/install.sh", web_root)


def assemble(state: Path | None = None, *, version: str | None = None,
             snapshot_id: str | None = None) -> Path:
    paths = secure_state(state)
    config = local_config(paths)
    snapshot = selected_snapshot(state, version, snapshot_id)
    version = snapshot["version"]
    tag = f"v{version}"
    run_origin = artifact_origin(config, version, snapshot["snapshotId"])
    bundles = paths["bundles"] / snapshot["snapshotId"]
    selected = set(PLATFORMS)
    for name in selected:
        if not _bundle_complete(bundles / name, platform_name=name, version=version,
                                artifact_url=run_origin, revision=snapshot["snapshotRevision"],
                                config=config):
            fail(f"no complete {name} bundle exists for this source snapshot")

    web = real_dir(paths["web"], 0o755)
    _web_dirs(web, "remote/releases")
    _web_dirs(web, f"remote/releases/{tag}")
    candidate = web / "remote" / "releases" / tag / snapshot["snapshotId"]
    if os.path.lexists(candidate):
        if candidate.is_symlink() or not candidate.is_dir():
            fail("existing candidate path is not a real directory")
        index = _verify_candidate(candidate, version=version, tag=tag,
                                  platforms=selected, config=config)
        _promote(web, candidate, index)
        print(f"Reused immutable local candidate: {candidate}")
        return candidate

    with tempfile.TemporaryDirectory(prefix="assemble-", dir=paths["root"]) as temp:
        flat = Path(temp) / "assets"
        try:
            index = publish_release.assemble(
                bundles, flat, tag, snapshot["snapshotRevision"], paths["keys"], paths["public"],
                expected_platforms=selected, expected_origin=LOCAL_ORIGIN,
                artifact_origin=run_origin,
            )
        except TypeError as error:
            fail(f"local assembly requires origin overrides in publish_release: {error}")
        _write_candidate(flat, index, candidate, version=version, tag=tag, config=config)
    _promote(web, candidate, index)
    print(f"Assembled immutable local candidate: {candidate}")
    return candidate


def _web_file(web_root: Path, raw_path: str) -> Path | None:
    """Map a URL path to a regular file, rejecting traversal and escapes."""
    try:
        decoded = urllib.parse.unquote(raw_path, errors="strict")
        if "\x00" in decoded or "\\" in decoded or decoded.startswith("//"):
            return None
        parts = decoded.split("/")
        if any(part in {".", ".."} for part in parts):
            return None
        relative = PurePosixPath(decoded.lstrip("/"))
        if (relative.is_absolute() or not relative.parts
                or any(part.startswith(".") for part in relative.parts)):
            return None
        root = web_root.resolve(strict=True)
        resolved = root.joinpath(*relative.parts).resolve(strict=True)
        if not resolved.is_relative_to(root) or not stat.S_ISREG(resolved.stat().st_mode):
            return None
        return resolved
    except (OSError, RuntimeError, UnicodeError, ValueError):
        return None


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "LomiLocalRelease/1"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:
        print(f"local HTTPS: {self.address_string()} {format % args}", file=sys.stderr)

    def _respond(self, include_body: bool) -> None:
        request = urllib.parse.urlsplit(self.path)
        if request.query or request.fragment:
            self.send_error(404)
            return
        path = _web_file(self.server.web_root, request.path)
        if path is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(path.stat().st_size))
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if include_body:
            try:
                with path.open("rb") as source:
                    shutil.copyfileobj(source, self.wfile)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def do_GET(self) -> None:
        self._respond(True)

    def do_HEAD(self) -> None:
        self._respond(False)

    def do_POST(self) -> None:
        self.send_error(405)

    do_PUT = do_POST
    do_DELETE = do_POST


class _HTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, web_root: Path):
        self.web_root = web_root.resolve(strict=True)
        super().__init__(address, _Handler)

    def shutdown_request(self, request):
        # TCPServer's default shutdown cuts the TLS stream without its closing
        # alert. Rustls correctly treats that as truncation, even when curl's
        # more permissive client happened to finish the same download.
        try:
            request.settimeout(2)
            request.unwrap()
        except (ssl.SSLError, OSError, ValueError):
            pass
        super().shutdown_request(request)


def _https_server(web_root: Path, tls_dir: Path, port: int = LOCAL_PORT):
    server = _HTTPServer(("127.0.0.1", port), web_root)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(tls_dir / "server.pem"), str(tls_dir / "server.key.pem"))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def serve(state: Path | None = None, *, ssh: str | None = None,
          ssh_options: tuple[str, ...] = ()) -> None:
    paths = secure_state(state)
    for name in ("server.pem", "server.key.pem", "local-test-ca.pem"):
        if not (paths["tls"] / name).is_file():
            fail("run init before serve so local TLS credentials are available")
    server = _https_server(paths["web"], paths["tls"])
    forward = None
    if ssh:
        if not REMOTE_RE.fullmatch(ssh):
            server.server_close()
            fail("SSH destination must use USER@HOST form")
        try:
            import local_remote
            forward = local_remote.start_forward(host=ssh, ssh_options=list(ssh_options), port=LOCAL_PORT)
            time.sleep(0.25)
            if forward.poll() is not None:
                fail("SSH reverse tunnel failed; check the remote host and port 18443")
        except BaseException:
            server.server_close()
            raise
    print(f"CA certificate: {paths['tls'] / 'local-test-ca.pem'}")
    print("Check the local release endpoint with:")
    print(f"  curl --cacert {paths['tls'] / 'local-test-ca.pem'} -fsSL {LOCAL_ORIGIN}latest.json")
    print(f"Serving https://127.0.0.1:{LOCAL_PORT}/remote/ from {paths['web']}")
    if ssh:
        print(f"SSH reverse tunnel active for {ssh}; keep this process running.")
    server.timeout = 0.5
    try:
        while True:
            if forward is not None and forward.poll() is not None:
                fail("SSH reverse tunnel exited; fix SSH and restart serve")
            server.handle_request()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if forward is not None and forward.poll() is None:
            forward.terminate()
            try:
                forward.wait(timeout=5)
            except subprocess.TimeoutExpired:
                forward.kill()
                forward.wait()


def _check_local_server(ca_pem: Path) -> None:
    context = ssl.create_default_context(cafile=str(ca_pem))
    connection = http.client.HTTPSConnection("127.0.0.1", LOCAL_PORT, context=context, timeout=3)
    try:
        connection.request("GET", "/remote/releases/latest.json")
        response = connection.getresponse()
        if response.status != 200:
            fail("local server has no latest.json; run assemble and serve first")
        response.read(16 * 1024)
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        fail(f"local release server is unavailable; run serve first: {error}")
    finally:
        connection.close()


def install(state: Path | None = None, *, account: str | None = None,
            ssh: str | None = None, ssh_options: tuple[str, ...] = ()) -> None:
    paths = secure_state(state)
    ca_pem = paths["tls"] / "local-test-ca.pem"
    if not ca_pem.is_file():
        fail("run init before install so the local CA is available")
    if ssh:
        if account:
            fail("--account is only used for a local macOS install")
        if not REMOTE_RE.fullmatch(ssh):
            fail("Linux installation requires --ssh USER@HOST")
        try:
            import local_remote
        except ImportError as error:
            fail(f"local SSH release helper is unavailable: {error}")
        local_remote.install_remote(host=ssh, ssh_options=list(ssh_options),
                                     ca_pem=ca_pem, origin=LOCAL_ORIGIN)
        return
    if host_platform.system() != "Darwin":
        fail("local install is supported only on macOS; use --ssh USER@HOST for Linux")
    if not account or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}", account):
        fail("macOS install requires --account with the selected existing test account")
    try:
        selected = pwd.getpwnam(account)
    except KeyError:
        fail(f"create the test account first: sudo sysadminctl -addUser {account} "
             f"-home /Users/{account} -shell /bin/zsh -password -")
    if selected.pw_uid in {0, os.getuid()}:
        fail("select a separate ordinary macOS test account, not the current account")
    _check_local_server(ca_pem)
    environment = os.environ.copy()
    environment["CURL_CA_BUNDLE"] = str(ca_pem)
    environment["LOMI_REMOTE_ACCOUNT"] = account
    print(f"Running the local installer for existing account {account}.")
    shell = subprocess.Popen(["sh"], stdin=subprocess.PIPE, env=environment)
    assert shell.stdin is not None
    try:
        subprocess.run(["curl", "-fsSL", "https://127.0.0.1:18443/remote/install.sh"],
                       stdout=shell.stdin, env=environment, check=True)
        shell.stdin.close()
        result = shell.wait()
        if result:
            fail(f"local installer exited with status {result}")
    except BaseException:
        if shell.poll() is None:
            shell.terminate()
            shell.wait()
        raise


def _arguments(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, help="private local state directory")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="create a separate local TUF root and HTTPS CA")

    build_parser = commands.add_parser("build", help="build a local macOS or remote Linux bundle")
    build_parser.add_argument("--platform", required=True, choices=PLATFORMS)
    build_parser.add_argument("--ssh", help="Linux build destination in USER@HOST form")
    build_parser.add_argument("--version", help="override workspace version in the snapshot only")
    build_parser.add_argument("--snapshot", help="reuse a specific immutable source snapshot")
    build_parser.add_argument("--ssh-option", action="append", default=[],
                              help="pass one OpenSSH -o option; repeatable")

    assemble_parser = commands.add_parser("assemble", help="make a local immutable candidate")
    assemble_parser.add_argument("--version", help="snapshot workspace version override")
    assemble_parser.add_argument("--snapshot", help="assemble a specific built source snapshot")

    serve_parser = commands.add_parser("serve", help="serve loopback HTTPS on port 18443")
    serve_parser.add_argument("--ssh", help="open a reverse tunnel to a Linux test host")
    serve_parser.add_argument("--ssh-option", action="append", default=[],
                              help="pass one OpenSSH -o option; repeatable")

    install_parser = commands.add_parser("install", help="run the local HTTPS installer")
    install_parser.add_argument("--account", help="explicit existing macOS test account")
    install_parser.add_argument("--ssh", help="install on Linux through an active reverse tunnel")
    install_parser.add_argument("--ssh-option", action="append", default=[],
                                help="pass one OpenSSH -o option; repeatable")
    return parser, parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    parser, args = _arguments(argv)
    try:
        if args.command == "init":
            initialize(args.state)
        elif args.command == "build":
            build(args.platform, args.state, version=args.version, ssh=args.ssh,
                  ssh_options=tuple(args.ssh_option), snapshot_id=args.snapshot)
        elif args.command == "assemble":
            assemble(args.state, version=args.version, snapshot_id=args.snapshot)
        elif args.command == "serve":
            serve(args.state, ssh=args.ssh, ssh_options=tuple(args.ssh_option))
        elif args.command == "install":
            install(args.state, account=args.account, ssh=args.ssh,
                    ssh_options=tuple(args.ssh_option))
        return 0
    except (LocalReleaseError, trust.TrustError, OSError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired, ValueError, ssl.SSLError, tarfile.TarError) as error:
        parser.exit(1, f"local release: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
