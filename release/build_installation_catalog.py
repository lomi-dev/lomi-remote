#!/usr/bin/env python3
"""Build public installation-page input offline; never sign, execute or publish."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import urlsplit

import release_set

PLATFORMS = {f"{system}-{architecture}" for system in ("linux", "macos", "windows") for architecture in ("x86_64", "aarch64")}
MAX_ENTRY = 48 * 1024


def fail() -> None:
    raise release_set.ManifestError("installation catalog input is missing, inconsistent or not release-ready")


def keys(value: object, expected: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        fail()
    return value


def read(path: Path, limit: int) -> bytes:
    if not hasattr(os, "O_NOFOLLOW"):
        fail()
    def identity(value: os.stat_result) -> tuple:
        return (value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode), value.st_size,
                value.st_mtime_ns, value.st_ctime_ns)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
        fail()
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or identity(before) != identity(opened):
            fail()
        with os.fdopen(descriptor, "rb") as source:
            descriptor = None
            data = source.read(limit + 1)
            after = os.fstat(source.fileno())
        if not 0 < len(data) <= limit or len(data) != before.st_size or identity(after) != identity(opened) or identity(path.lstat()) != identity(opened):
            fail()
        return data
    finally:
        if descriptor is not None:
            os.close(descriptor)


def parse_json(raw: bytes) -> object:
    value = json.loads(raw.decode("utf-8"),
                       object_pairs_hook=release_set._object_without_duplicates,
                       parse_float=release_set._reject_non_integer_number,
                       parse_constant=release_set._reject_json_constant)
    value = release_set._normalize(value)
    release_set._bound_tree(value)
    return value


def artifact(value: object, directory: Path, origin: str) -> dict:
    value = keys(value, {"url", "sha256", "size"})
    url, expected, size = value["url"], value["sha256"], value["size"]
    if not isinstance(url, str) or not url.startswith(origin):
        fail()
    name = url[len(origin):]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}", name) or name in {".", ".."}:
        fail()
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected) or type(size) is not int or not 0 < size <= 2 ** 34:
        fail()
    actual, actual_size = release_set._sha256_file(directory / name)
    if actual != expected or actual_size != size:
        fail()
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-set", required=True, type=Path)
    parser.add_argument("--release-set-sha256", required=True)
    parser.add_argument("--release-origin", required=True)
    parser.add_argument("--bundle", action="append", default=[], metavar="PLATFORM=DIRECTORY")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        raw = read(args.release_set, release_set.MAX_MANIFEST_BYTES)
        if not re.fullmatch(r"[0-9a-f]{64}", args.release_set_sha256) or hashlib.sha256(raw).hexdigest() != args.release_set_sha256:
            fail()
        # Parse the exact bytes whose independently supplied digest was checked,
        # rather than reopening a mutable path after that check.
        manifest = parse_json(raw)
        schema = release_set._load_schema()
        release_set._validate_schema(manifest, schema, schema)
        release_set._walk_strings(manifest)
        release_set._validate_references(manifest)
        release_set._validate_artifact_targets(manifest)
        release_set._validate_release_ready(manifest)
        if release_set._canonical_bytes(manifest) != raw:
            fail()
        origin = args.release_origin
        parsed = urlsplit(origin)
        if not origin.isascii() or re.search(r"[\s\\%?#]", origin) or parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or not origin.endswith("/"):
            fail()
        directories: dict[str, Path] = {}
        if len(args.bundle) != len(PLATFORMS):
            fail()
        for mapping in args.bundle:
            platform, separator, directory = mapping.partition("=")
            if not separator or platform not in PLATFORMS or platform in directories:
                fail()
            directories[platform] = Path(directory)
        host = manifest["components"]["host"]
        targets = []
        root = None
        for platform, directory in sorted(directories.items()):
            entry = parse_json(read(directory / "installation-entry.json", MAX_ENTRY))
            required = {"format", "version", "releaseOrigin", "publicRoot", "platform", "archive"}
            linux = platform.startswith("linux-")
            entry = keys(entry, required | ({"linuxBootstrap"} if linux else set()))
            if entry["format"] != 1 or entry["platform"] != platform or entry["version"] != host["product_version"] or entry["releaseOrigin"] != origin:
                fail()
            current_root = artifact(entry["publicRoot"], directory, origin)
            if current_root["sha256"] != manifest["update_trust"]["public_tuf_root"]["sha256"] or (root is not None and current_root != root):
                fail()
            root = current_root
            archive = artifact(entry["archive"], directory, origin)
            system, architecture = platform.split("-", 1)
            def require_approved_artifact(value: dict, kind: str) -> None:
                if not any(item["kind"] == kind and item["target"]["os"] == system and item["target"]["architecture"] == architecture and item["sha256"] == value["sha256"] and item["size_bytes"] == value["size"] for item in host["artifacts"]):
                    fail()
            require_approved_artifact(archive, "binary")
            target = {"platform": platform, "archive": archive}
            if linux:
                bootstrap = keys(entry["linuxBootstrap"], {"preflight", "manifest", "signature", "publicKey", "command", "commandSha256"})
                for name in ("preflight", "manifest", "signature", "publicKey"):
                    checked = artifact(bootstrap[name], directory, origin)
                    require_approved_artifact(checked, "installer_metadata")
                command = read(directory / "install-command.txt", 24 * 1024)
                if command.decode("ascii") != bootstrap["command"] or hashlib.sha256(command).hexdigest() != bootstrap["commandSha256"]:
                    fail()
                if bootstrap["preflight"]["url"] not in bootstrap["command"] or bootstrap["preflight"]["sha256"] not in bootstrap["command"]:
                    fail()
                require_approved_artifact({"sha256": hashlib.sha256(command).hexdigest(), "size": len(command)}, "installer_metadata")
                target["linuxBootstrap"] = bootstrap
            targets.append(target)
        catalog = {"format": 1, "version": host["product_version"], "releaseOrigin": origin,
                   "releaseSet": {"url": origin + "release-set.json", "sha256": args.release_set_sha256, "size": len(raw)},
                   "publicRoot": root, "targets": targets}
        data = json.dumps(catalog, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        if len(data) > 128 * 1024:
            fail()
        # Exclusive output avoids replacing a previously reviewed catalog/pin.
        with args.output.open("xb") as destination:
            destination.write(data)
        print(f"Installation catalog SHA-256: {hashlib.sha256(data).hexdigest()}")
        print("No artifacts were signed or published. Review this exact catalog before enabling site downloads.")
        return 0
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError, release_set.ManifestError):
        print("Installation catalog rejected; inputs remain unchanged.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
