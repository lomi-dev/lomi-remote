#!/usr/bin/env python3
"""Verify and stage the frozen successor2 source closure, without admission."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "artifacts/consumer-private-positive-controller/2026-10-22-eleven-source-only-successor2"
FREEZE_SHA256 = "0b64db4a29f4f3104353d13f321a75390e4d8de5f3e01bd80968fb3632623476"
LAUNCHER_SOURCE = REPO / "tests/consumer-private-positive-controller/trusted_launcher.py"
LAUNCHER_SHA256 = "bb2e1e3481936636924851478e4125dc516dff64e53e01216ca236e2527cfc47"
MANIFEST_PATH = REPO / "staging/s5-successor2-source-manifest.json"
FREEZE_SUPPORT_FILES = {
    "frozen-sources.tar", "preservation-receipt.json",
    "production-adapter.diff", "pure-test-receipt.json",
    "readonly-input-receipt.json", "source-additions.diff",
    "source-correspondence.json",
}


class ClosureError(ValueError):
    pass


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ClosureError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def manifest(source: Path = SOURCE) -> dict[str, str]:
    freeze = source / "freeze.json"
    if freeze.is_symlink() or not freeze.is_file() or sha256(freeze) != FREEZE_SHA256:
        raise ClosureError("freeze.json is missing, nonregular, or not the pinned freeze")
    data = json.loads(freeze.read_text(encoding="utf-8"))
    pins = data.get("sourceSha256")
    if data.get("schemaVersion") != 1 or not isinstance(pins, dict) or len(pins) != 88:
        raise ClosureError("freeze.json does not describe the expected 88-file closure")
    if any(not isinstance(name, str) or name.startswith("/") or ".." in Path(name).parts
           or not isinstance(digest, str) or len(digest) != 64 for name, digest in pins.items()):
        raise ClosureError("freeze.json contains an invalid source pin")
    result = dict(pins)
    result["freeze.json"] = FREEZE_SHA256
    if LAUNCHER_SOURCE.is_symlink() or not LAUNCHER_SOURCE.is_file() or sha256(LAUNCHER_SOURCE) != LAUNCHER_SHA256:
        raise ClosureError("trusted launcher is missing, nonregular, or not pinned")
    result["launcher.py"] = LAUNCHER_SHA256
    try:
        recorded = json.loads(
            MANIFEST_PATH.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ClosureError(f"staging manifest cannot be read: {exc}") from exc
    if (not isinstance(recorded, dict)
            or set(recorded) != {
                "schemaVersion", "freezePath", "freezeSha256", "files",
                "sourceOnly", "admissionGenerated",
            }
            or type(recorded.get("schemaVersion")) is not int
            or recorded.get("schemaVersion") != 1
            or recorded.get("freezePath") != (SOURCE / "freeze.json").relative_to(REPO).as_posix()
            or recorded.get("freezeSha256") != FREEZE_SHA256
            or recorded.get("files") != result
            or recorded.get("sourceOnly") is not True
            or recorded.get("admissionGenerated") is not False):
        raise ClosureError("recorded staging manifest differs from pinned closure")
    return result


def verify(source: Path = SOURCE) -> dict[str, str]:
    expected = manifest(source)
    actual: dict[str, Path] = {}
    for root, dirs, files in os.walk(source, followlinks=False):
        root_path = Path(root)
        for name in list(dirs):
            path = root_path / name
            if path.is_symlink() or not stat.S_ISDIR(path.lstat().st_mode):
                raise ClosureError(f"symlink or non-directory in source tree: {path.relative_to(source)}")
        for name in files:
            path = root_path / name
            rel = path.relative_to(source).as_posix()
            if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
                raise ClosureError(f"symlink or nonregular source: {rel}")
            if rel not in FREEZE_SUPPORT_FILES:
                actual[rel] = path
    expected_source = set(expected) - {"launcher.py"}
    if set(actual) != expected_source:
        raise ClosureError(f"source file set mismatch (missing={sorted(expected_source-set(actual))}, extra={sorted(set(actual)-expected_source)})")
    for rel, digest in expected.items():
        if rel != "launcher.py" and sha256(actual[rel]) != digest:
            raise ClosureError(f"source hash mismatch: {rel}")
    return expected


def stage(destination: Path, source: Path = SOURCE) -> None:
    pins = verify(source)
    if os.geteuid() == 0:
        raise ClosureError("refusing to create staging output as root")
    if destination.exists() or destination.is_symlink():
        raise ClosureError("destination must not already exist")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir(mode=0o700)
    try:
        for rel in sorted(pins):
            origin = LAUNCHER_SOURCE if rel == "launcher.py" else source / rel
            target = destination / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(origin, target)
            os.chmod(target, stat.S_IMODE(origin.stat().st_mode))
        if os.stat(destination).st_uid != os.geteuid():
            raise ClosureError("staging tree is not owned by the current user")
        staged = verify_staged(destination, pins)
        if staged != pins:
            raise ClosureError("staged closure verification failed")
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def verify_staged(root: Path, pins: dict[str, str]) -> dict[str, str]:
    actual = {}
    for base, dirs, files in os.walk(root, followlinks=False):
        for d in dirs:
            p = Path(base) / d
            if p.is_symlink() or not stat.S_ISDIR(p.lstat().st_mode):
                raise ClosureError("symlink or non-directory in staged tree")
        for name in files:
            p = Path(base) / name
            if p.is_symlink() or not stat.S_ISREG(p.lstat().st_mode):
                raise ClosureError("symlink or nonregular staged file")
            actual[p.relative_to(root).as_posix()] = p
    if set(actual) != set(pins):
        raise ClosureError("staged file set mismatch")
    for rel, digest in pins.items():
        if sha256(actual[rel]) != digest:
            raise ClosureError(f"staged hash mismatch: {rel}")
    return pins


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("verify", help="verify the pinned source closure")
    stage_parser = sub.add_parser("stage", help="copy verified files to a new user-owned directory")
    stage_parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        pins = verify()
        if args.command == "stage":
            stage(args.destination)
        print(f"verified {len(pins)} source files; source-only, no admission generated")
        return 0
    except (ClosureError, OSError, ValueError) as exc:
        print(f"s5-source-stage: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
