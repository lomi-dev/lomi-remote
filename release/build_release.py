#!/usr/bin/env python3
"""Build signed platform bundles around a TUF-verified lomiremote target.

This tool never creates signing keys, signs TUF metadata, or publishes artifacts.
The TUF root is an offline, operator-supplied public file checked against a
separately supplied digest before Cargo embeds it in the updater executable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import selectors
import stat
import subprocess
import sys
import time
import urllib.parse
import zipfile
from typing import NoReturn

from macos_signing import (
    MacOSSigningError,
    load_config as load_macos_signing_config,
    notarize_archive as notarize_macos_archive,
    preflight as check_macos_signing,
    sign_file as sign_macos_file,
)


ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = {
    "linux-x86_64": "x86_64-unknown-linux-gnu",
    "linux-aarch64": "aarch64-unknown-linux-gnu",
    "macos-x86_64": "x86_64-apple-darwin",
    "macos-aarch64": "aarch64-apple-darwin",
    "windows-x86_64": "x86_64-pc-windows-msvc",
    "windows-aarch64": "aarch64-pc-windows-msvc",
}

LINUX_BOOTSTRAP_PUBLIC_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
LINUX_BOOTSTRAP_MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
LINUX_BOOTSTRAP_MAX_OPENSSL_OUTPUT = 4096
LINUX_BOOTSTRAP_OPENSSL_TIMEOUT_SECONDS = 30


def fail(message: str) -> NoReturn:
    raise SystemExit(f"release build: {message}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_digest(value: str) -> str:
    value = value.lower()
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        fail("public trust-root digest must be 64 hexadecimal characters")
    return value


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_linux_bootstrap_public_key(path: Path, expected_digest: str) -> bytes:
    expected_digest = require_digest(expected_digest)
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size != 44:
            fail("Linux bootstrap public key must be a regular 44-byte Ed25519 SPKI DER file")
        with path.open("rb") as source:
            public_key = source.read(45)
    except OSError:
        fail("could not read Linux bootstrap public key")
    if len(public_key) != 44 or public_key[:12] != LINUX_BOOTSTRAP_PUBLIC_DER_PREFIX:
        fail("Linux bootstrap public key is not canonical Ed25519 SPKI DER")
    if sha256_bytes(public_key) != expected_digest:
        fail("Linux bootstrap public key does not match its independent SHA-256 pin")
    return public_key


def run_openssl_bounded(command: list[str], *, extra_env: dict[str, str] | None = None) -> bytes:
    """Run one OpenSSL command with closed stdin, bounded output, and a deadline."""
    env = {
        key: value
        for key, value in os.environ.items()
        if key in {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "OPENSSL_CONF", "OPENSSL_MODULES"}
    }
    if extra_env:
        env.update(extra_env)
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            close_fds=True,
        )
    except OSError:
        fail("OpenSSL 3 could not be started for Linux bootstrap signing")

    assert process.stdout is not None
    assert process.stderr is not None
    captured = bytearray()
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    selector.register(process.stderr, selectors.EVENT_READ)
    deadline = time.monotonic() + LINUX_BOOTSTRAP_OPENSSL_TIMEOUT_SECONDS
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait()
                fail("OpenSSL Linux bootstrap signing exceeded its time limit")
            for key, _ in selector.select(min(remaining, 0.25)):
                chunk = os.read(key.fileobj.fileno(), 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if len(captured) + len(chunk) > LINUX_BOOTSTRAP_MAX_OPENSSL_OUTPUT:
                    process.kill()
                    process.wait()
                    fail("OpenSSL Linux bootstrap signing produced excessive output")
                captured.extend(chunk)
        remaining = max(0.01, deadline - time.monotonic())
        return_code = process.wait(timeout=remaining)
    except (OSError, subprocess.TimeoutExpired):
        process.kill()
        process.wait()
        fail("OpenSSL Linux bootstrap signing failed or timed out")
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            if not stream.closed:
                stream.close()
    if return_code != 0:
        fail("OpenSSL Linux bootstrap signing or verification failed")
    return bytes(captured)


def sign_linux_bootstrap_manifest(
    manifest_path: Path,
    signature_path: Path,
    signing_key_path: Path,
    public_key_path: Path,
    passphrase: str | None,
) -> None:
    try:
        key_info = signing_key_path.lstat()
        if not stat.S_ISREG(key_info.st_mode) or key_info.st_size > 1024 * 1024:
            fail("Linux bootstrap signing key must be a bounded regular PEM file")
    except OSError:
        fail("Linux bootstrap signing key is unavailable")

    sign_command = [
        "openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(signing_key_path),
        "-in", str(manifest_path), "-out", str(signature_path.with_suffix(".sig.pending")),
    ]
    pending_signature_path = signature_path.with_suffix(".sig.pending")
    signer_env = None
    if passphrase is not None:
        # Pass only the environment-variable name to OpenSSL; never put the
        # secret itself in argv, output, or a generated release file.
        sign_command.extend(["-passin", "env:LOMI_LINUX_BOOTSTRAP_KEY_PASSPHRASE"])
        signer_env = {"LOMI_LINUX_BOOTSTRAP_KEY_PASSPHRASE": passphrase}
    try:
        run_openssl_bounded(sign_command, extra_env=signer_env)
        try:
            signature_info = pending_signature_path.lstat()
            if not stat.S_ISREG(signature_info.st_mode) or signature_info.st_size != 64:
                fail("OpenSSL produced an invalid Linux bootstrap signature")
        except OSError:
            fail("OpenSSL did not produce the Linux bootstrap signature")

        verify_command = [
            "openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER",
            "-inkey", str(public_key_path), "-in", str(manifest_path),
            "-sigfile", str(pending_signature_path),
        ]
        run_openssl_bounded(verify_command)
        os.replace(pending_signature_path, signature_path)
    finally:
        try:
            pending_signature_path.unlink()
        except FileNotFoundError:
            pass


def linux_bootstrap_manifest(
    *, platform: str, target_name: str, version: str, root_sha256: str,
    archive_name: str, archive_size: int, archive_sha256: str,
) -> bytes:
    if archive_size <= 0 or archive_size > LINUX_BOOTSTRAP_MAX_ARCHIVE_BYTES:
        fail("Linux bootstrap archive exceeds the supported size limit")
    fields = (
        "LOMI-LINUX-BOOTSTRAP-V1",
        f"platform={platform}",
        f"target={target_name}",
        f"version={version}",
        f"public-tuf-root-sha256={root_sha256}",
        f"archive={archive_name}",
        f"archive-size={archive_size}",
        f"archive-sha256={archive_sha256}",
    )
    try:
        result = ("\n".join(fields) + "\n").encode("ascii")
    except UnicodeEncodeError:
        fail("Linux bootstrap manifest contains non-ASCII data")
    if len(result) > 2048:
        fail("Linux bootstrap manifest exceeds its size limit")
    return result


def require_openssl3() -> None:
    output = run_openssl_bounded(["openssl", "version"])
    if not output.startswith(b"OpenSSL 3."):
        fail("Linux bootstrap signing requires OpenSSL 3")


def create_linux_bootstrap_outputs(
    *,
    output: Path,
    archive: Path,
    platform: str,
    target_name: str,
    version: str,
    root_sha256: str,
    release_origin: str,
    public_key: bytes,
    public_key_sha256: str,
    signing_key_path: Path,
    signing_key_passphrase: str | None,
) -> None:
    archive_name = archive.name
    archive_size = archive.stat().st_size
    archive_sha256 = sha256(archive)
    manifest_bytes = linux_bootstrap_manifest(
        platform=platform,
        target_name=target_name,
        version=version,
        root_sha256=root_sha256,
        archive_name=archive_name,
        archive_size=archive_size,
        archive_sha256=archive_sha256,
    )

    base = archive.with_suffix("").name
    manifest_path = output / f"{base}.bootstrap-manifest"
    signature_path = output / f"{base}.sig"
    public_key_path = output / f"{base}.der"
    preflight_path = output / f"{base}.install.sh"
    manifest_path.write_bytes(manifest_bytes)
    public_key_path.write_bytes(public_key)
    sign_linux_bootstrap_manifest(
        manifest_path,
        signature_path,
        signing_key_path,
        public_key_path,
        signing_key_passphrase,
    )

    replacements = {
        "@@BOOTSTRAP_ORIGIN_SHELL@@": shlex.quote(release_origin),
        "@@BOOTSTRAP_PLATFORM_SHELL@@": shlex.quote(platform),
        "@@BOOTSTRAP_TARGET_SHELL@@": shlex.quote(target_name),
        "@@BOOTSTRAP_VERSION_SHELL@@": shlex.quote(version),
        "@@BOOTSTRAP_ROOT_SHA256_SHELL@@": shlex.quote(root_sha256),
        "@@BOOTSTRAP_KEY_SHA256_SHELL@@": shlex.quote(public_key_sha256),
        "@@BOOTSTRAP_ARCHIVE_NAME_SHELL@@": shlex.quote(archive_name),
        "@@BOOTSTRAP_ARCHIVE_SIZE_SHELL@@": str(archive_size),
        "@@BOOTSTRAP_ARCHIVE_SHA256_SHELL@@": shlex.quote(archive_sha256),
        "@@BOOTSTRAP_ARCHIVE_MAX_BYTES_SHELL@@": str(LINUX_BOOTSTRAP_MAX_ARCHIVE_BYTES),
        "@@BOOTSTRAP_MANIFEST_NAME_SHELL@@": shlex.quote(manifest_path.name),
        "@@BOOTSTRAP_MANIFEST_SIZE_SHELL@@": str(len(manifest_bytes)),
        "@@BOOTSTRAP_SIGNATURE_NAME_SHELL@@": shlex.quote(signature_path.name),
        "@@BOOTSTRAP_PUBLIC_KEY_NAME_SHELL@@": shlex.quote(public_key_path.name),
    }
    render(ROOT / "release/linux-bootstrap.sh.in", preflight_path, replacements)
    os.chmod(preflight_path, 0o500)
    preflight_size = preflight_path.stat().st_size
    preflight_sha256 = sha256(preflight_path)
    command_path = output / "install-command.txt"
    preflight_url = shlex.quote(f"{release_origin}{preflight_path.name}")
    body = f"""set -eu
umask 077
bootstrap_tmp=$(mktemp -d "${{TMPDIR:-/tmp}}/lomi-bootstrap-command.XXXXXXXX") || exit 1
trap 'rm -rf "$bootstrap_tmp"' 0
trap 'exit 1' HUP INT TERM
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \\
    --connect-timeout 20 --max-time 120 \\
    {preflight_url} | head -c {preflight_size + 1} > "$bootstrap_tmp/preflight.sh"
actual_size=$(LC_ALL=C wc -c < "$bootstrap_tmp/preflight.sh" | tr -d '[:space:]')
[ "$actual_size" = '{preflight_size}' ] || {{ printf '%s\\n' 'bootstrap script size mismatch' >&2; exit 1; }}
actual_sha256=$(sha256sum "$bootstrap_tmp/preflight.sh")
actual_sha256=${{actual_sha256%% *}}
[ "$actual_sha256" = '{preflight_sha256}' ] || {{ printf '%s\\n' 'bootstrap script signature pin mismatch' >&2; exit 1; }}
/bin/sh "$bootstrap_tmp/preflight.sh" "$@"
"""
    command = f"/bin/sh -c {shlex.quote(body)} lomi-linux-bootstrap\n"
    command_path.write_text(command, encoding="utf-8", newline="\n")
    os.chmod(command_path, 0o600)


def create_installation_entry(
    output: Path, archive: Path, platform: str, version: str,
    release_origin: str, public_root: Path, root_sha256: str,
) -> None:
    """Public presentation data; its catalog still requires independent approval."""
    root_bytes = public_root.read_bytes()
    if not root_bytes or len(root_bytes) > 1024 * 1024 or hashlib.sha256(root_bytes).hexdigest() != root_sha256:
        fail("public root changed before installation entry creation")
    root_copy = output / f"release-root-{root_sha256}.json"
    root_copy.write_bytes(root_bytes)

    def artifact(path: Path) -> dict[str, object]:
        return {"url": release_origin + path.name, "sha256": sha256(path), "size": path.stat().st_size}

    entry: dict[str, object] = {
        "format": 1, "version": version, "releaseOrigin": release_origin,
        "publicRoot": artifact(root_copy), "platform": platform, "archive": artifact(archive),
    }
    if platform.startswith("linux-"):
        base = archive.with_suffix("").name
        command = (output / "install-command.txt").read_text(encoding="utf-8")
        entry["linuxBootstrap"] = {
            "preflight": artifact(output / f"{base}.install.sh"),
            "manifest": artifact(output / f"{base}.bootstrap-manifest"),
            "signature": artifact(output / f"{base}.sig"),
            "publicKey": artifact(output / f"{base}.der"),
            "command": command, "commandSha256": hashlib.sha256(command.encode()).hexdigest(),
        }
    (output / "installation-entry.json").write_text(
        json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8",
    )


def require_origin(value: str) -> str:
    if not value.isascii() or any(ord(character) <= 32 or ord(character) == 127 for character in value):
        fail("release origin must not contain whitespace or control characters")
    parsed = urllib.parse.urlsplit(value)
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        fail("release origin has an invalid host or port")
    if (
        parsed.scheme != "https"
        or not hostname
        or hostname != hostname.lower()
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not hostname.isascii()
        or hostname.endswith(".")
        or not parsed.path.endswith("/")
        or not re.fullmatch(r"/[A-Za-z0-9._~/-]*", parsed.path)
        or any(part in {"", ".", ".."} for part in parsed.path.split("/")[1:-1])
        or "\\" in value
        or any(part in {".", ".."} for part in parsed.path.split("/"))
    ):
        fail("release origin must be a credential-free canonical HTTPS directory URL")
    if port == 443:
        fail("release origin must omit the default HTTPS port")
    require_public_host_authority(parsed.netloc, "release origin")
    return value


def require_target(value: str) -> str:
    if (
        not value
        or len(value.encode("utf-8")) > 255
        or value.startswith("/")
        or "\\" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or not re.fullmatch(r"[A-Za-z0-9._/-]+", value)
    ):
        fail("TUF target name must be a bounded, relative path without traversal")
    return value


def require_public_host_authority(value: str, field: str) -> str:
    if not value.isascii() or any(character in value for character in "/?#@\\"):
        fail(f"{field} is not a canonical public host authority")
    hostname, separator, port = value.partition(":")
    if (
        not hostname
        or len(hostname) > 253
        or hostname.startswith(".")
        or hostname.endswith(".")
        or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not re.fullmatch(r"[a-z0-9-]+", label)
            for label in hostname.split(".")
        )
    ):
        fail(f"{field} has an invalid canonical DNS or IPv4 host")
    if separator:
        if not port or port.startswith("0") or port == "443" or not port.isascii() or not port.isdigit():
            fail(f"{field} has a noncanonical TLS port")
        try:
            if not 1 <= int(port) <= 65535:
                fail(f"{field} has an invalid TLS port")
        except ValueError:
            fail(f"{field} has an invalid TLS port")
    last_label = hostname.rsplit(".", 1)[-1]
    numeric_ending = last_label.isdigit() or (
        last_label.startswith("0x")
        and all(character in "0123456789abcdef" for character in last_label[2:])
    )
    if numeric_ending:
        parts = hostname.split(".")
        if len(parts) != 4 or any(
            not part.isdigit() or (part.startswith("0") and part != "0") or int(part) > 255
            for part in parts
        ):
            fail(f"{field} has a noncanonical numeric host")
    return value


def require_public_https_origin(value: str, field: str) -> str:
    authority = value.removeprefix("https://")
    if not value.startswith("https://") or not authority:
        fail(f"{field} must be a canonical HTTPS origin")
    require_public_host_authority(authority, field)
    return value


def require_public_relay_endpoint(value: str) -> str:
    prefix = "wss://"
    suffix = "/v2/relay"
    if not value.startswith(prefix) or not value.endswith(suffix) or len(value) > 189:
        fail("LOMI_HOST_RELAY_ENDPOINT must be a canonical WSS /v2/relay endpoint")
    authority = value[len(prefix) : -len(suffix)]
    require_public_host_authority(authority, "LOMI_HOST_RELAY_ENDPOINT")
    return value


def public_host_bootstrap_pins() -> dict[str, str]:
    keys = (
        "LOMI_HOST_IDENTITY_ORIGIN",
        "LOMI_HOST_REMOTE_API_ORIGIN",
        "LOMI_HOST_RELAY_ENDPOINT",
        "LOMI_HOST_CLIENT_ID",
        "LOMI_HOST_REMOTE_WEB_ORIGIN",
    )
    pins = {key: os.environ.get(key, "") for key in keys}
    if any(not value for value in pins.values()):
        fail("release builds require all five public LOMI_HOST_* bootstrap pins")
    identity = require_public_https_origin(
        pins["LOMI_HOST_IDENTITY_ORIGIN"], "LOMI_HOST_IDENTITY_ORIGIN"
    )
    remote_api = require_public_https_origin(
        pins["LOMI_HOST_REMOTE_API_ORIGIN"], "LOMI_HOST_REMOTE_API_ORIGIN"
    )
    require_public_https_origin(
        pins["LOMI_HOST_REMOTE_WEB_ORIGIN"], "LOMI_HOST_REMOTE_WEB_ORIGIN"
    )
    if identity == remote_api:
        fail("identity and Remote API origins must be separately pinned")
    require_public_relay_endpoint(pins["LOMI_HOST_RELAY_ENDPOINT"])
    client_id = pins["LOMI_HOST_CLIENT_ID"]
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", client_id):
        fail("LOMI_HOST_CLIENT_ID is not a bounded public client identifier")
    return pins


def run(command: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, cwd=cwd, env=env, check=True)


def render(template: Path, destination: Path, replacements: dict[str, str]) -> None:
    text = template.read_text(encoding="utf-8")
    for marker, replacement in replacements.items():
        if marker not in text:
            fail(f"template is missing marker {marker}")
        text = text.replace(marker, replacement)
    if "@@" in text:
        fail(f"unexpanded installer template marker in {destination.name}")
    destination.write_text(text, encoding="utf-8", newline="\n")


def hash_files(directory: Path) -> dict[str, str]:
    return {
        path.relative_to(directory).as_posix(): sha256(path)
        for path in sorted(directory.rglob("*"))
        if path.is_file() and path.name != "build-manifest.json"
    }


def source_manifest() -> tuple[str, str, dict[str, object], str]:
    try:
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        git_tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip()
        dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)
    except (OSError, subprocess.CalledProcessError):
        fail("release builds require a Git checkout with a commit")
    if (
        not re.fullmatch(r"[0-9a-f]{40,64}", revision)
        or not re.fullmatch(r"[0-9a-f]{40,64}", git_tree)
        or dirty
    ):
        fail("release builds require a clean committed source tree")
    protocol_files = {
        path.relative_to(ROOT).as_posix(): sha256(path)
        for path in sorted((ROOT / "crates/lomi-remote-protocol/src").glob("*.rs"))
    }
    lock_hash = sha256(ROOT / "Cargo.lock")
    workspace_hash = sha256(ROOT / "Cargo.toml")
    source_data = {
        "format": 1,
        "sourceRevision": revision,
        "gitTree": git_tree,
        "cargoLockSha256": lock_hash,
        "workspaceManifestSha256": workspace_hash,
        "updateTrustManifestSha256": sha256(ROOT / "crates/lomi-update-trust/Cargo.toml"),
        "applicationManifestSha256": sha256(ROOT / "crates/lomiremote/Cargo.toml"),
        "rustToolchainSha256": sha256(ROOT / "rust-toolchain.toml"),
        "protocolFiles": protocol_files,
    }
    canonical = json.dumps(source_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return revision, git_tree, source_data, hashlib.sha256(canonical).hexdigest()


def build_toolchain() -> dict[str, str]:
    try:
        active_toolchain = subprocess.check_output(
            ["rustup", "show", "active-toolchain"], cwd=ROOT, text=True
        ).strip().split(" (", 1)[0]
        return {
            "rustc": subprocess.check_output(["rustc", "--version", "--verbose"], cwd=ROOT, text=True).strip(),
            "cargo": subprocess.check_output(["cargo", "--version"], cwd=ROOT, text=True).strip(),
            "activeToolchain": active_toolchain,
        }
    except (OSError, subprocess.CalledProcessError):
        fail("could not capture the pinned Rust build toolchain")


def product_metadata(binary: Path, target: str) -> tuple[str, int]:
    try:
        rustc_info = subprocess.check_output(
            ["rustc", "--version", "--verbose"], cwd=ROOT, text=True
        )
    except (OSError, subprocess.CalledProcessError):
        fail("could not identify the native release build host")
    host = next(
        (line.removeprefix("host: ") for line in rustc_info.splitlines() if line.startswith("host: ")),
        None,
    )
    if host != target:
        # Apple Silicon can execute an Intel build through Rosetta. Read the
        # identity from that actual executable rather than editing Cargo.toml
        # or guessing its schema/version from a cross-compilation manifest.
        rosetta = host == "aarch64-apple-darwin" and target == "x86_64-apple-darwin"
        if not rosetta or subprocess.run(
            ["arch", "-x86_64", "/usr/bin/true"], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
        ).returncode:
            fail("release packaging must execute its built metadata command natively or through verified Rosetta support")

    # This command is deliberately available before profile resolution and
    # does not open the host database. Do not pass CI/signing credentials.
    allowed_environment = {
        "PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LANG", "LC_ALL"
    }
    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in allowed_environment
    }
    try:
        output = subprocess.check_output(
            [str(binary), "version", "--json"],
            cwd=ROOT,
            env=env,
            text=True,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        metadata = json.loads(output)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError):
        fail("built product did not return valid release self-description")
    if len(output.encode("utf-8")) > 4096:
        fail("built product release self-description exceeds its output limit")
    if (
        not isinstance(metadata, dict)
        or set(metadata) != {"programVersion", "profileSchema"}
        or not isinstance(metadata.get("programVersion"), str)
        or not re.fullmatch(
            r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)",
            metadata["programVersion"],
        )
        or type(metadata.get("profileSchema")) is not int
        or metadata["profileSchema"] < 1
        or metadata["profileSchema"] > 2**64 - 1
    ):
        fail("built product release self-description has an unsupported shape")
    return metadata["programVersion"], metadata["profileSchema"]


def main() -> None:
    # Do not let the optional signing passphrase leak to rustup, Cargo, native
    # build scripts, or metadata commands. Only the OpenSSL signer receives it.
    linux_bootstrap_key_passphrase = os.environ.pop(
        "LOMI_LINUX_BOOTSTRAP_KEY_PASSPHRASE", None
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True, choices=PLATFORMS)
    parser.add_argument("--release-origin", required=True)
    parser.add_argument("--artifact-origin", help="Versioned bootstrap and initial-install origin; updates retain --release-origin")
    parser.add_argument("--target-name", required=True)
    parser.add_argument("--companion-target-name")
    parser.add_argument("--minimum-profile-schema", required=True, type=int)
    parser.add_argument("--public-root", required=True, type=Path)
    parser.add_argument("--public-root-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--macos-signing-identity")
    parser.add_argument("--macos-team-id")
    parser.add_argument("--macos-notary-profile")
    parser.add_argument("--macos-keychain", type=Path)
    parser.add_argument("--windows-signer-thumbprint")
    parser.add_argument("--windows-timestamp-url", default="https://timestamp.digicert.com")
    parser.add_argument("--linux-bootstrap-public-key", type=Path)
    parser.add_argument("--linux-bootstrap-key-sha256")
    parser.add_argument("--linux-bootstrap-signing-key", type=Path)
    args = parser.parse_args()

    platform = args.platform
    target = PLATFORMS[platform]
    origin = require_origin(args.release_origin)
    artifact_origin = require_origin(args.artifact_origin) if args.artifact_origin else origin
    target_name = require_target(args.target_name)
    companion_target_name = (
        require_target(args.companion_target_name)
        if args.companion_target_name
        else None
    )
    if platform.startswith("windows-"):
        if companion_target_name is None or companion_target_name == target_name:
            fail("Windows release requires a distinct TUF target for lomiremote-host.exe")
        if not target_name.lower().endswith(".exe") or not companion_target_name.lower().endswith(".exe"):
            fail("Windows TUF target names must identify PE executables")
    elif companion_target_name is not None:
        fail("companion TUF target is currently reserved for Windows host releases")
    if (
        args.minimum_profile_schema < 0
        or args.minimum_profile_schema > 2**64 - 1
    ):
        fail("profile-schema compatibility range is invalid")

    linux_bootstrap_options = (
        args.linux_bootstrap_public_key,
        args.linux_bootstrap_key_sha256,
        args.linux_bootstrap_signing_key,
    )
    linux_bootstrap_public_key = None
    linux_bootstrap_signing_key = None
    linux_bootstrap_key_sha256 = None
    if platform.startswith("linux-"):
        if any(value is None for value in linux_bootstrap_options):
            fail(
                "Linux releases require --linux-bootstrap-public-key, "
                "--linux-bootstrap-key-sha256, and --linux-bootstrap-signing-key"
            )
        assert args.linux_bootstrap_public_key is not None
        assert args.linux_bootstrap_key_sha256 is not None
        assert args.linux_bootstrap_signing_key is not None
        linux_bootstrap_key_sha256 = require_digest(args.linux_bootstrap_key_sha256)
        linux_bootstrap_public_key = read_linux_bootstrap_public_key(
            args.linux_bootstrap_public_key,
            linux_bootstrap_key_sha256,
        )
        try:
            if not stat.S_ISREG(args.linux_bootstrap_signing_key.lstat().st_mode):
                fail("Linux bootstrap signing key must be a regular PEM file")
            linux_bootstrap_signing_key = args.linux_bootstrap_signing_key.resolve(strict=True)
        except OSError:
            fail("Linux bootstrap signing key is unavailable")
        require_openssl3()
    elif any(value is not None for value in linux_bootstrap_options):
        fail("Linux bootstrap signing options are supported only for Linux releases")

    macos_config = None
    if platform.startswith("macos-"):
        macos_config = load_macos_signing_config(
            identity=args.macos_signing_identity,
            team_id=args.macos_team_id,
            notary_profile=args.macos_notary_profile,
            keychain=args.macos_keychain,
        )
        check_macos_signing(macos_config)
        args.macos_signing_identity = macos_config.identity
        args.macos_team_id = macos_config.team_id
        args.macos_notary_profile = macos_config.notary_profile

    root_path = args.public_root.resolve(strict=True)
    if not root_path.is_file() or root_path.stat().st_size > 1024 * 1024:
        fail("operator-supplied public root must be a regular file no larger than 1 MiB")
    root_pin = require_digest(args.public_root_sha256)
    if sha256(root_path) != root_pin:
        fail("operator-supplied public root does not match its independent digest")
    bootstrap_pins = public_host_bootstrap_pins()

    if platform.startswith("windows-"):
        if not args.windows_signer_thumbprint or not re.fullmatch(r"[A-Fa-f0-9]{40}", args.windows_signer_thumbprint):
            fail("Windows release requires a certificate thumbprint in the current-user store")
        timestamp = urllib.parse.urlsplit(args.windows_timestamp_url)
        try:
            timestamp_hostname = timestamp.hostname
            timestamp_port = timestamp.port
        except ValueError:
            fail("Windows timestamp service has an invalid host or port")
        if (
            timestamp.scheme != "https"
            or not timestamp_hostname
            or not timestamp_hostname.isascii()
            or timestamp.username is not None
            or timestamp.password is not None
            or timestamp.query
            or timestamp.fragment
        ):
            fail("Windows timestamp service must use HTTPS")
        if timestamp_port == 443:
            fail("Windows timestamp service must omit the default HTTPS port")

    output = args.output.resolve()
    if output.exists():
        if not output.is_dir():
            fail("output path must be a directory")
        if any(output.iterdir()):
            fail("output directory must be absent or empty")
    # Capture cleanliness before creating any release files. This allows a
    # clean checkout to place an empty output directory inside the repository
    # without making its own provenance check fail.
    revision, git_tree, source_data, source_fingerprint = source_manifest()
    output.mkdir(parents=True, exist_ok=True)
    os.chmod(output, 0o700)
    stage = output / "bundle"
    stage.mkdir(mode=0o700)
    if platform.startswith("windows-"):
        native_signer_pin = (args.windows_signer_thumbprint or "").replace(" ", "").upper()
    elif platform.startswith("macos-"):
        native_signer_pin = args.macos_team_id or ""
    else:
        native_signer_pin = ""
    env = os.environ.copy()
    env["LOMI_UPDATE_ROOT_FILE"] = str(root_path)
    env["LOMI_UPDATE_ROOT_SHA256"] = root_pin
    env.update(bootstrap_pins)
    env.update({
        "LOMI_RELEASE_ORIGIN": origin,
        "LOMI_RELEASE_PRIMARY_TARGET": target_name,
        "LOMI_RELEASE_HELPER_TARGET": companion_target_name or "",
        "LOMI_RELEASE_PLATFORM": platform,
        "LOMI_RELEASE_NATIVE_SIGNER": native_signer_pin,
    })
    if platform.startswith("linux-"):
        env.update({
            "LOMI_LINUX_RELEASE_ORIGIN": origin,
            "LOMI_LINUX_PRIMARY_TARGET": target_name,
            "LOMI_LINUX_PLATFORM": platform,
        })
    if platform.startswith("windows-"):
        env.update({
            "LOMI_WINDOWS_RELEASE_ORIGIN": origin,
            "LOMI_WINDOWS_PRIMARY_TARGET": target_name,
            "LOMI_WINDOWS_HELPER_TARGET": companion_target_name,
            "LOMI_WINDOWS_PLATFORM": platform,
        })
    run(["rustup", "target", "add", target])

    app_build = [
        "cargo", "build", "--locked", "--release", "--target", target,
        "-p", "lomiremote", "--bin", "lomiremote", "--features", "release-maintenance",
    ]
    if platform.startswith("linux-"):
        app_build[-1] = "release-maintenance,linux-setup-handoff"
    if platform.startswith("windows-"):
        app_build.extend(["--bin", "lomiremote-host"])
    run(app_build, env=env)
    suffix = ".exe" if platform.startswith("windows-") else ""
    target_directory = Path(env.get("CARGO_TARGET_DIR", str(ROOT / "target")))
    if not target_directory.is_absolute():
        target_directory = ROOT / target_directory
    built = target_directory / target / "release"
    product_binary = built / f"lomiremote{suffix}"
    release_version, maximum_profile_schema = product_metadata(product_binary, target)
    if args.minimum_profile_schema > maximum_profile_schema:
        fail("minimum existing-profile schema exceeds the built product schema")
    run([
        "cargo", "build", "--locked", "--release", "--target", target,
        "-p", "lomi-update-trust", "--features", "release-root",
        "--bin", "lomi-update-trust",
    ], env=env)

    # Exercise the feature-gated parser that is actually shipped, including
    # responses serialized by the Host protocol. Reject a broken updater
    # before signing or publishing any bundle.
    run([
        "cargo", "test", "--locked", "--release", "--target", target,
        "-p", "lomi-update-trust", "--features", "release-root",
        "--bin", "lomi-update-trust",
    ], env=env)
    if not platform.startswith("windows-"):
        test_env = env.copy()
        test_env["LOMI_TEST_MAINTENANCE_UPDATER"] = str(built / "lomi-update-trust")
        run([
            sys.executable, "-m", "unittest", "release.test_installer_output", "-v",
        ], env=test_env)

    binaries = {
        "lomiremote": product_binary,
        "lomi-update-trust": built / f"lomi-update-trust{suffix}",
    }
    if platform.startswith("windows-"):
        binaries["lomiremote-host"] = built / "lomiremote-host.exe"
    for name, source in binaries.items():
        if not source.is_file():
            fail(f"Cargo did not produce required binary {source.name}")
        shutil.copyfile(source, stage / source.name)
        if not platform.startswith("windows-"):
            os.chmod(stage / source.name, 0o500)

    expected_team = args.macos_team_id or ""
    expected_thumbprint = (args.windows_signer_thumbprint or "").replace(" ", "").upper()
    replacements = {
        "@@RELEASE_ORIGIN_SHELL@@": shlex.quote(artifact_origin),
        "@@TARGET_NAME_SHELL@@": shlex.quote(target_name),
        "@@PLATFORM_SHELL@@": shlex.quote(platform),
        "@@VERSION_SHELL@@": shlex.quote(release_version),
        "@@ROOT_SHA256_SHELL@@": shlex.quote(root_pin),
        "@@TEAM_ID_SHELL@@": shlex.quote(expected_team),
        "@@RELEASE_ORIGIN_PS@@": json.dumps(artifact_origin),
        "@@TARGET_NAME_PS@@": json.dumps(target_name),
        "@@COMPANION_TARGET_NAME_PS@@": json.dumps(companion_target_name or ""),
        "@@PLATFORM_PS@@": json.dumps(platform),
        "@@VERSION_PS@@": json.dumps(release_version),
        "@@ROOT_SHA256_PS@@": json.dumps(root_pin),
        "@@SIGNER_THUMBPRINT_PS@@": json.dumps(expected_thumbprint),
    }
    if platform.startswith("windows-"):
        render(ROOT / "release/install.ps1.in", stage / "install.ps1",
               {key: value for key, value in replacements.items() if key.endswith("_PS@@")})
        for binary in stage.glob("*.exe"):
            run([
                "signtool", "sign", "/s", "My", "/sha1", expected_thumbprint,
                "/fd", "SHA256", "/tr", args.windows_timestamp_url,
                "/td", "SHA256", str(binary),
            ])
            run(["signtool", "verify", "/pa", "/all", str(binary)])
        signing_env = env.copy()
        signing_env["LOMI_BUILD_SIGNING_SCRIPT_PATH"] = str(stage / "install.ps1")
        signing_env["LOMI_BUILD_SIGNING_CERT_THUMBPRINT"] = expected_thumbprint
        signing_env["LOMI_BUILD_SIGNING_TIMESTAMP_URL"] = args.windows_timestamp_url
        run([
            "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
            "$p = $env:LOMI_BUILD_SIGNING_SCRIPT_PATH; $thumb = $env:LOMI_BUILD_SIGNING_CERT_THUMBPRINT; $c = Get-ChildItem -LiteralPath ('Cert:\\CurrentUser\\My\\' + $thumb); if (-not $c) { exit 2 }; Set-AuthenticodeSignature -FilePath $p -Certificate $c -TimestampServer $env:LOMI_BUILD_SIGNING_TIMESTAMP_URL | Out-Null; if ((Get-AuthenticodeSignature -FilePath $p).Status -ne 'Valid') { exit 3 }",
        ], env=signing_env)
    else:
        render(ROOT / "release/install.sh.in", stage / "install.sh",
               {key: value for key, value in replacements.items() if key.endswith("_SHELL@@")})
        os.chmod(stage / "install.sh", 0o500)
        if platform.startswith("macos-"):
            assert macos_config is not None
            for binary in stage.iterdir():
                if binary.is_file() and binary.name != "targets":
                    sign_macos_file(binary, macos_config)

    target_path = stage / "targets" / target_name
    target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(stage / f"lomiremote{suffix}", target_path)
    if not platform.startswith("windows-"):
        os.chmod(target_path, 0o500)
    companion_path = None
    if companion_target_name:
        companion_path = stage / "targets" / companion_target_name
        companion_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(stage / "lomiremote-host.exe", companion_path)

    (stage / "source-manifest.json").write_text(
        json.dumps({**source_data, "sourceFingerprintSha256": source_fingerprint}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manifest = {
        "format": 1,
        "platform": platform,
        "version": release_version,
        "releaseOrigin": origin,
        "artifactOrigin": artifact_origin,
        "tufTargetName": target_name,
        "tufCompanionTargetName": companion_target_name,
        "profileSchema": {
            "minimum": args.minimum_profile_schema,
            "maximum": maximum_profile_schema,
        },
        "publicTufRootSha256": root_pin,
        "hostBootstrapPins": bootstrap_pins,
        "tufTargetCustom": {
            "lomiRelease": {
                "format": 1,
                "platform": platform,
                "version": release_version,
                "minProfileSchema": args.minimum_profile_schema,
                "maxProfileSchema": maximum_profile_schema,
            },
            **({"lomiAuthenticode": {"format": 1, "thumbprint": expected_thumbprint}}
               if platform.startswith("windows-") else {}),
        },
        "sourceRevision": revision,
        "sourceGitTree": git_tree,
        "sourceFingerprintSha256": source_fingerprint,
        "cargoLockSha256": sha256(ROOT / "Cargo.lock"),
        "protocolSourceSha256": sha256(ROOT / "crates/lomi-remote-protocol/src/ipc.rs"),
        "targetTriple": target,
        "buildToolchain": build_toolchain(),
        "files": hash_files(stage),
    }
    (stage / "build-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    archive = output / f"lomi-remote-{platform}-{release_version}.zip"
    if platform.startswith("macos-"):
        # Preserve the extended-attribute code signatures on the shell
        # installer as well as the embedded Mach-O signatures.
        run(["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", str(stage), str(archive)])
        assert macos_config is not None
        notarize_macos_archive(archive, macos_config)
    else:
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
            for path in sorted(stage.rglob("*")):
                if path.is_file():
                    bundle.write(path, path.relative_to(stage).as_posix())
    if platform.startswith("linux-"):
        assert linux_bootstrap_public_key is not None
        assert linux_bootstrap_key_sha256 is not None
        assert linux_bootstrap_signing_key is not None
        create_linux_bootstrap_outputs(
            output=output,
            archive=archive,
            platform=platform,
            target_name=target_name,
            version=release_version,
            root_sha256=root_pin,
            release_origin=artifact_origin,
            public_key=linux_bootstrap_public_key,
            public_key_sha256=linux_bootstrap_key_sha256,
            signing_key_path=linux_bootstrap_signing_key,
            signing_key_passphrase=linux_bootstrap_key_passphrase,
        )
    create_installation_entry(output, archive, platform, release_version, artifact_origin, root_path, root_pin)
    print(f"Built {archive}")
    if platform.startswith("linux-"):
        print(f"Linux bootstrap manifest: {archive.with_suffix('.bootstrap-manifest')}")
        print(f"Linux bootstrap signature: {archive.with_suffix('.sig')}")
        print(f"Linux bootstrap public key: {archive.with_suffix('.der')}")
        print(f"Linux bootstrap command: {output / 'install-command.txt'}")
    print(f"TUF target candidate: {target_path}")
    if companion_path is not None:
        print(f"TUF companion target candidate: {companion_path}")
    print("No TUF metadata was signed and no artifact was published.")


if __name__ == "__main__":
    try:
        main()
    except MacOSSigningError as error:
        fail(str(error))
