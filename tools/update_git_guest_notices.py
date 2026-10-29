#!/usr/bin/env python3
"""Generate the locked WASI guest dependency notice inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = Path("crates/lomi-git/guest/Cargo.toml")
LOCKFILE = Path("crates/lomi-git/guest/Cargo.lock")
OUTPUT = Path("crates/lomi-git/THIRD_PARTY_NOTICES.md")
TARGET = "wasm32-wasip1"
ROOT_PACKAGE = "lomi-git-wasi-guest"
LEGAL_PREFIXES = ("license", "licence", "notice", "copying")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_metadata() -> dict:
    command = [
        "cargo",
        "metadata",
        "--locked",
        "--format-version",
        "1",
        "--filter-platform",
        TARGET,
        "--manifest-path",
        str(MANIFEST),
    ]
    result = subprocess.run(command, cwd=ROOT, check=False, capture_output=True)
    if result.returncode:
        raise ValueError(
            f"cargo metadata failed ({result.returncode}):\n"
            f"{result.stderr.decode(errors='replace')[-4000:]}"
        )
    return json.loads(result.stdout)


def dependency_closure(metadata: dict) -> tuple[dict[str, dict], set[str]]:
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    roots = [package_id for package_id, package in packages.items()
             if package["name"] == ROOT_PACKAGE]
    if len(roots) != 1:
        raise ValueError(f"expected one {ROOT_PACKAGE} package, found {len(roots)}")
    if roots[0] not in nodes:
        raise ValueError(f"Cargo did not resolve {ROOT_PACKAGE}")

    closure: set[str] = set()
    pending = [roots[0]]
    while pending:
        package_id = pending.pop()
        if package_id in closure:
            continue
        closure.add(package_id)
        for dependency in nodes[package_id]["deps"]:
            kinds = dependency.get("dep_kinds", [])
            if any(kind.get("kind") != "dev" for kind in kinds):
                pending.append(dependency["pkg"])
    return packages, closure


def legal_files(source: Path, package: dict) -> list[Path]:
    candidates = {
        path for path in source.rglob("*")
        if path.is_file() and path.name.lower().startswith(LEGAL_PREFIXES)
    }
    declared = package.get("license_file")
    if declared:
        path = source / declared
        if not path.is_file():
            raise ValueError(
                f"declared license file is missing: {package['name']} "
                f"{package['version']} ({declared})"
            )
        candidates.add(path)
    return sorted(candidates, key=lambda path: path.relative_to(source).as_posix())


def vcs_revision(source: Path) -> str | None:
    path = source / ".cargo_vcs_info.json"
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("git", {}).get("sha1")


def same_revision_license_files(package: dict, source: Path,
                                packages: dict[str, dict]) -> list[tuple[Path, dict]]:
    """Find shared repository notices only when Cargo records the same git SHA."""
    repository = package.get("repository")
    revision = vcs_revision(source)
    if not repository or not revision:
        return []

    matches: list[tuple[Path, dict]] = []
    ordered_peers = sorted(
        packages.values(),
        key=lambda item: (item["name"], item["version"], item.get("source") or ""),
    )
    for peer in ordered_peers:
        if peer is package or peer.get("repository") != repository:
            continue
        peer_source = Path(peer["manifest_path"]).parent
        if vcs_revision(peer_source) != revision:
            continue
        for path in legal_files(peer_source, peer):
            matches.append((path, peer))
    return matches


def file_text(path: Path) -> str:
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError(f"license file path contains a symlink: {path}")
    try:
        return path.read_bytes().decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"license file is not UTF-8 text: {path}") from error


def package_source(package: dict, source: Path) -> tuple[str, str | None]:
    registry = package.get("source") or ""
    if registry.startswith("registry+"):
        if "crates.io-index" in registry:
            url = f"https://crates.io/crates/{package['name']}/{package['version']}"
            return url, package.get("repository")
        return registry, package.get("repository")
    try:
        local_path = source.relative_to(ROOT).as_posix()
    except ValueError:
        local_path = source.as_posix()
    return local_path, package.get("repository")


def fence_for(text: str) -> str:
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def inventory(metadata: dict) -> bytes:
    packages, closure = dependency_closure(metadata)
    roots = [package_id for package_id in closure
             if packages[package_id]["name"] == ROOT_PACKAGE]
    lock_hash = sha256((ROOT / LOCKFILE).read_bytes())
    lock_metadata = run_lock_package_count()
    filtered_count = len(closure)
    omitted_count = max(0, lock_metadata - filtered_count)

    entries: list[str] = []
    dependency_ids = sorted(
        closure - set(roots),
        key=lambda package_id: (packages[package_id]["name"],
                                packages[package_id]["version"],
                                packages[package_id]["source"] or ""),
    )
    for package_id in dependency_ids:
        package = packages[package_id]
        source = Path(package["manifest_path"]).parent
        files = legal_files(source, package)
        provenance_note = ""
        if not files:
            fallback = same_revision_license_files(package, source, packages)
            if fallback:
                # A sibling package at the same repository revision can carry
                # a shared root license omitted from this subcrate's archive.
                by_name: dict[str, set[bytes]] = {}
                for path, _peer in fallback:
                    by_name.setdefault(path.name, set()).add(file_text(path).encode("utf-8"))
                if any(len(contents) != 1 for contents in by_name.values()):
                    raise ValueError(
                        f"ambiguous shared license files for {package['name']} "
                        f"{package['version']}"
                    )
                files = []
                fallback_peers: set[str] = set()
                for name in sorted(by_name):
                    path, peer = min(
                        [(path, peer) for path, peer in fallback if path.name == name],
                        key=lambda item: (item[0].as_posix(), item[1]["name"],
                                          item[1]["version"]),
                    )
                    files.append(path)
                    fallback_peers.add(f"{peer['name']} {peer['version']}")
                fallback_peers_text = ", ".join(sorted(fallback_peers))
                revision = vcs_revision(source)
                provenance_note = (
                    " The crate archive omits these shared repository-root "
                    f"files; identical-revision copies from {fallback_peers_text} "
                    f"at git revision `{revision}` are included."
                )
        if not files:
            raise ValueError(
                f"no upstream license or notice files found for "
                f"{package['name']} {package['version']}"
            )
        if not package.get("license"):
            raise ValueError(
                f"Cargo metadata has no license expression for "
                f"{package['name']} {package['version']}"
            )

        source_label, repository = package_source(package, source)
        lines = [f"## {package['name']} {package['version']}", "",
                 f"- License expression: `{package['license']}`",
                 f"- Source: <{source_label}>"]
        if repository:
            lines.append(f"- Repository: <{repository}>")
        if provenance_note:
            lines.append(f"- Notice provenance:{provenance_note}")
        lines.append("")

        for path in files:
            # Keep paths relative to the package whose license is being
            # reproduced, including an explicitly marked shared-source path.
            if path.is_relative_to(source):
                displayed_path = path.relative_to(source).as_posix()
            else:
                displayed_path = path.name
            text = file_text(path)
            fence = fence_for(text)
            lines.extend((f"### `{displayed_path}`", "", f"{fence}text", text))
            if not text.endswith("\n"):
                lines.append("")
            lines.extend((fence, ""))
        entries.append("\n".join(lines).rstrip())

    header = [
        "# Third-party notices for the Lomi Git guest",
        "",
        "This inventory covers non-development dependencies reachable from "
        f"`{ROOT_PACKAGE}` for `{TARGET}`, as resolved by Cargo. It includes "
        "normal and build dependencies, including vendored path patches. "
        "Dependencies for other targets and development-only dependencies "
        "are outside this inventory.",
        "",
        "Regenerate with `python3 tools/update_git_guest_notices.py`; verify "
        "with `python3 tools/update_git_guest_notices.py --check`.",
        "",
        f"Guest `Cargo.lock` SHA-256: `{lock_hash}`.",
        f"Locked packages outside this target closure: {omitted_count}.",
        "",
        "No license grant is inferred for private Lomi sources.",
        "",
    ]
    return ("\n".join(header) + "\n\n" + "\n\n".join(entries) + "\n").encode("utf-8")


def run_lock_package_count() -> int:
    """Count lockfile package records without depending on Python 3.11 tomllib."""
    text = (ROOT / LOCKFILE).read_text(encoding="utf-8")
    return sum(line == "[[package]]" for line in text.splitlines())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="fail if the checked-in inventory is missing or stale")
    args = parser.parse_args()

    try:
        data = inventory(run_metadata())
        destination = ROOT / OUTPUT
        if args.check:
            if not destination.is_file():
                raise ValueError(f"generated inventory is missing: {OUTPUT}")
            if destination.read_bytes() != data:
                raise ValueError(f"generated inventory is stale: {OUTPUT}")
            print(f"verified {OUTPUT}")
        else:
            destination.write_bytes(data)
            print(f"wrote {OUTPUT}")
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"update_git_guest_notices.py: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
