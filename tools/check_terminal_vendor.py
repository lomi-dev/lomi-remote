#!/usr/bin/env python3
"""Verify pinned terminal sources, licenses and explicitly recorded local patches."""
import argparse
import hashlib
import json
from pathlib import Path
import stat
import tarfile


PACKAGES = {
    "alacritty_terminal": ("0.26.0", "bda177466b9524d59f1b12f0dd30b68696788e9992a7e959021c4a0ed96fcf59",
                          {"src/term/cell.rs", "src/term/mod.rs"}, {"LICENSE-APACHE"}),
    "vte": ("0.15.0", "a5924018406ce0063cd67f8e008104968b74b563ee1b85dde3ed1f7cb87d3dbd",
            {"src/lib.rs"}, {"LICENSE-APACHE", "LICENSE-MIT"}),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular_file(root, relative):
    rel = Path(relative)
    if rel.is_absolute() or not rel.parts or ".." in rel.parts:
        raise ValueError("unsafe vendor path")
    current = root
    if current.is_symlink():
        raise ValueError("symlink vendor root")
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("symlink vendor path")
    if not stat.S_ISREG(current.stat().st_mode):
        raise ValueError("nonregular vendor file")
    return current


def inventory(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("invalid vendor directory")
    files = set()
    for path in root.rglob("*"):
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise ValueError("nonregular vendor entry")
        if stat.S_ISREG(mode):
            files.add(path.relative_to(root).as_posix())
    return files


def verify(root, archive_dir=None):
    vendor = root / "vendor"
    manifest = json.loads(regular_file(vendor, "provenance.json").read_text())
    if manifest["format"] != 1 or set(manifest["packages"]) != set(PACKAGES):
        raise ValueError("unexpected vendor manifest identity")
    total, patch_files = 0, set()
    for name, (version, archive_hash, changed, licenses) in PACKAGES.items():
        entry = manifest["packages"][name]
        if (entry["version"] != version or entry["archiveSha256"] != archive_hash
                or entry["source"] != f"https://static.crates.io/crates/{name}/{name}-{version}.crate"):
            raise ValueError("unexpected vendor source identity")
        files = entry["upstreamFiles"]
        if not licenses <= set(files) or inventory(vendor / name) != set(files):
            raise ValueError("vendor source or license inventory drift")
        patches = {item["path"]: item for item in entry["patches"]}
        if len(patches) != len(entry["patches"]) or set(patches) != changed:
            raise ValueError("unexpected vendor patches")
        for relative, upstream_hash in files.items():
            actual = digest(regular_file(vendor / name, relative).read_bytes())
            patch = patches.get(relative)
            if patch is None:
                expected = upstream_hash
            else:
                expected = patch["patchedSha256"]
                if patch["upstreamSha256"] != upstream_hash or not patch["purpose"]:
                    raise ValueError("undocumented vendor adaptation")
                patch_path = patch["patchFile"]
                if not patch_path.startswith("patches/") or patch_path in patch_files:
                    raise ValueError("unexpected patch file")
                patch_files.add(patch_path)
                if digest(regular_file(vendor, patch_path).read_bytes()) != patch["patchSha256"]:
                    raise ValueError("patch artifact drift")
            if actual != expected:
                raise ValueError(f"vendor source drift: {name}/{relative}")
            total += 1
        if archive_dir is not None:
            archive = regular_file(archive_dir, f"{name}-{version}.crate")
            if digest(archive.read_bytes()) != archive_hash:
                raise ValueError("upstream archive digest mismatch")
            with tarfile.open(archive) as source:
                upstream = {}
                prefix = f"{name}-{version}/"
                for member in source:
                    if member.isdir():
                        continue
                    if not member.isfile() or not member.name.startswith(prefix):
                        raise ValueError("unexpected upstream archive entry")
                    relative = member.name.removeprefix(prefix)
                    # Cargo-generated metadata is intentionally not vendored.
                    if relative in {"Cargo.lock", ".cargo-checksum.json", ".cargo-ok"}:
                        continue
                    if relative in upstream:
                        raise ValueError("duplicate upstream archive entry")
                    upstream[relative] = digest(source.extractfile(member).read())
                if upstream != files:
                    raise ValueError("upstream archive source inventory mismatch")
    if inventory(vendor / "patches") != {p.removeprefix("patches/") for p in patch_files}:
        raise ValueError("patch file inventory drift")
    return total


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive-dir", type=Path,
                        help="also verify the exact original .crate archives")
    args = parser.parse_args()
    try:
        count = verify(Path(__file__).resolve().parents[1], args.archive_dir)
    except (ValueError, KeyError, OSError, tarfile.TarError) as error:
        parser.exit(1, f"terminal vendor provenance failed: {error}\n")
    print(f"terminal vendor provenance passed: {count} source/license files, 3 patches")


if __name__ == "__main__":
    main()
