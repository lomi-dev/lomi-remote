#!/usr/bin/env python3
"""Install a locally built lomiremote binary without network or OS setup."""

import argparse
import hashlib
import os
from pathlib import Path
import platform
import re
import stat
import tempfile
import uuid


SUPPORTED_ARCHES = {"x86_64", "aarch64"}
OBJECTS_DIR = ".lomiremote-objects"


def _owned_directory(path: Path, uid: int) -> None:
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise RuntimeError(f"refusing non-directory or symlink: {path}")
        if info.st_uid != uid:
            raise RuntimeError(f"directory is not owned by current user: {path}")
        if info.st_mode & 0o022:
            raise RuntimeError(f"directory is writable by other users: {path}")
    else:
        previous_umask = os.umask(0o077)
        try:
            path.mkdir(mode=0o700)
        finally:
            os.umask(previous_umask)
        created = path.lstat()
        if (not stat.S_ISDIR(created.st_mode) or stat.S_ISLNK(created.st_mode)
                or created.st_uid != uid or created.st_mode & 0o022):
            raise RuntimeError(f"created directory failed ownership checks: {path}")


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def install(binary: Path, expected_sha256: str, home: Path, *, os_name=None, arch=None) -> Path:
    os_name = os_name or platform.system()
    arch = arch or platform.machine()
    if os_name != "Linux" or arch not in SUPPORTED_ARCHES:
        raise RuntimeError(f"unsupported platform: {os_name}/{arch}")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        raise RuntimeError("expected SHA-256 must contain exactly 64 hexadecimal characters")

    uid = os.getuid()
    home = Path(home)
    home_info = home.lstat() if home.exists() or home.is_symlink() else None
    if (home_info is None or not stat.S_ISDIR(home_info.st_mode) or stat.S_ISLNK(home_info.st_mode)
            or home_info.st_uid != uid or home_info.st_mode & 0o022):
        raise RuntimeError(f"home directory must be a current-user-owned directory: {home}")
    source_info = binary.stat()
    if not stat.S_ISREG(source_info.st_mode):
        raise RuntimeError("source binary must be a regular file")
    actual = _digest(binary)
    expected = expected_sha256.lower()
    if actual != expected:
        raise RuntimeError(f"SHA-256 mismatch: expected {expected}, got {actual}")

    local = home / ".local"
    _owned_directory(local, uid)
    bindir = local / "bin"
    _owned_directory(bindir, uid)
    target = bindir / "lomiremote"
    objects = bindir / OBJECTS_DIR
    object_path = objects / expected

    if target.exists() or target.is_symlink():
        info = target.lstat()
        if not stat.S_ISLNK(info.st_mode) or info.st_uid != uid:
            raise RuntimeError(f"refusing to replace a non-installer file: {target}")
        link = os.readlink(target)
        match = re.fullmatch(re.escape(OBJECTS_DIR) + r"/([0-9a-f]{64})", link)
        if not match:
            raise RuntimeError(f"refusing to replace an unrelated symlink: {target}")
        _owned_directory(objects, uid)
        active_object = objects / match.group(1)
        if not active_object.is_file() or active_object.is_symlink() or active_object.stat().st_uid != uid:
            raise RuntimeError(f"installed symlink does not point to an owned binary object: {target}")
        if _digest(active_object) != match.group(1):
            raise RuntimeError(f"installed binary object failed its content hash: {active_object}")

    _owned_directory(objects, uid)

    staged = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".staging-", dir=objects, delete=False) as output:
            staged = Path(output.name)
            with binary.open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if _digest(staged) != expected:
            raise RuntimeError("SHA-256 mismatch after staging; source changed during installation")
        staged.chmod(0o555)
        with staged.open("rb") as handle:
            os.fsync(handle.fileno())
        if object_path.exists() or object_path.is_symlink():
            if object_path.is_symlink() or not object_path.is_file() or object_path.stat().st_uid != uid:
                raise RuntimeError(f"refusing an invalid content-addressed object: {object_path}")
            if _digest(object_path) != expected:
                raise RuntimeError(f"content-addressed object failed its hash: {object_path}")
            if object_path.stat().st_mode & 0o022:
                raise RuntimeError(f"content-addressed object is writable by other users: {object_path}")
            object_path.chmod(0o555)
            staged.unlink()
            staged = None
        else:
            os.replace(staged, object_path)
            staged = None
            _fsync_directory(objects)

        pointer_tmp = bindir / f".lomiremote-link-{uuid.uuid4().hex}"
        os.symlink(f"{OBJECTS_DIR}/{expected}", pointer_tmp)
        try:
            os.replace(pointer_tmp, target)
            _fsync_directory(bindir)
        finally:
            pointer_tmp.unlink(missing_ok=True)
        return target
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Install a local lomiremote binary on Linux")
    parser.add_argument("--binary", required=True, type=Path, help="path to the already-built binary")
    parser.add_argument("--sha256", required=True, help="expected SHA-256 of that binary")
    args = parser.parse_args()
    try:
        destination = install(args.binary, args.sha256, Path.home())
    except (OSError, RuntimeError) as error:
        parser.error(str(error))
    print(f"Installed unsigned, unreleased local build at {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
