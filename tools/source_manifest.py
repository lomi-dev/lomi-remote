#!/usr/bin/env python3
"""Record source provenance without collecting credentials or application data.

This creates development evidence, not signed release metadata or a TUF verifier.
Release mode fails until canonical source migration and clean revisions exist.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


REPOSITORIES = ("lomi", "auth-app", "remote-web", "mobile-app", "auth-frontend")
SPEC_FILES = (
    "README.md", "00-cel-i-wymagania.md", "01-obecny-system.md",
    "02-architektura.md", "03-instalacja-tui-usluga.md",
    "04-protokol-workspace.md", "05-logowanie-bezpieczenstwo.md",
    "06-przebudowa-aplikacji.md", "07-realizacja-i-odbior.md",
    "08-decyzje-i-zrodla.md", "09-kontrakty-i-stany.md",
    "10-operacje-i-weryfikacja.md", "AUDYT.md", "prompt.md",
)


def git(repo, *args):
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, check=False,
    )
    return result.stdout if result.returncode == 0 else None


def repository_state(repo):
    # A directory under a different repository is not a separate Git repository.
    top = git(repo, "rev-parse", "--show-toplevel")
    if top is None or Path(top.decode().strip()).resolve() != repo.resolve():
        return {"state": "missing"}
    head = git(repo, "rev-parse", "--verify", "HEAD")
    status = git(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    tree = git(repo, "rev-parse", "HEAD^{tree}") if head else None
    return {
        "state": "present", "revision": head.decode().strip() if head else None,
        "tree": tree.decode().strip() if tree else None,
        "dirty": bool(status) if status is not None else None,
    }


def source_inventory(repo):
    # Explicit source surfaces; no env, credential, user-data, build or log scan.
    roots = ("crates", "contracts", "packages", "vendor", "tools", "tests", ".github", "docs")
    ctas_test_package = Path("tests/consumer-derivatives-v2-s5-pre012-ctas-successor")
    ctas_runtime_view = re.compile(r"\.ctas-runner-view-[0-9a-f]{32}\Z")

    def generated_directory(relative_parent, name):
        if name in {"node_modules", "target", "__pycache__", ".git"}:
            return True
        return relative_parent == ctas_test_package and ctas_runtime_view.fullmatch(name) is not None

    def scan_failed(error):
        raise error

    paths = [repo / name for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "README.md", ".gitignore")]
    for name in roots:
        folder = repo / name
        if folder.is_symlink():
            raise ValueError("source inventory refuses directory symlinks")
        if folder.exists():
            if not folder.is_dir():
                raise ValueError("named source root must be a directory")
            for directory, directories, files in os.walk(folder, followlinks=False, onerror=scan_failed):
                current = Path(directory)
                relative_parent = current.relative_to(repo)
                # The CTAS test materializes a UUID-named private Postgres.app
                # runtime view beside its source. It contains toolchain links
                # and is neither project source nor transferable test input.
                # Keep refusing symlinks in every included source directory.
                for name in directories:
                    if (relative_parent == ctas_test_package
                            and ctas_runtime_view.fullmatch(name) is not None
                            and (current / name).is_symlink()):
                        raise ValueError("source inventory refuses directory symlinks")
                directories[:] = sorted(d for d in directories if not generated_directory(relative_parent, d))
                # os.walk refuses traversal through nested links, but silently
                # omitting them would also make the source digest incomplete.
                if any((current / d).is_symlink() for d in directories):
                    raise ValueError("source inventory refuses directory symlinks")
                paths.extend(Path(directory) / name for name in files)
    inventory = {}
    for path in sorted(set(paths)):
        relative = path.relative_to(repo)
        if any(part in {"node_modules", "target", "__pycache__", ".git"} for part in relative.parts):
            continue
        if path.is_symlink():
            raise ValueError("source inventory refuses symlinks")
        if path.name.startswith(".env") or path.suffix in {".log", ".sqlite", ".pyc"}:
            continue
        if path.exists():
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError("source inventory requires regular files")
            inventory[relative.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    encoded = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    return {"algorithm": "sha256", "digest": hashlib.sha256(encoded).hexdigest(), "files": inventory}


def capture(repo):
    workspace = repo.parent
    specs = workspace / "remote-server"
    baseline = {
        name: hashlib.sha256((specs / name).read_bytes()).hexdigest()
        for name in SPEC_FILES if (specs / name).is_file()
    }
    copy_path = workspace / "auth-app/Dockerfile.remote-web"
    old_web_build = copy_path.is_file() and "apps/remote-web" in copy_path.read_text()
    crypto_path = repo / "crates/lomi-remote-crypto/Cargo.toml"
    return {
        "formatVersion": 1, "purpose": "development-evidence", "releaseReady": False,
        "axes": {"product": "v1", "remoteApiMajor": 2, "applicationMajor": 2,
                 "grantContext": 3, "terminalProfile": None, "contracts": "draft"},
        "implementation": repository_state(repo),
        "applications": {name: repository_state(workspace / name) for name in REPOSITORIES},
        "specification": {"files": baseline, "complete": len(baseline) == len(SPEC_FILES)},
        "source": source_inventory(repo),
        "canonicalSources": {
            "contracts": "lomi-remote/crates/lomi-remote-protocol",
            "crypto": {"path": "lomi-remote/crates/lomi-remote-crypto", "present": crypto_path.is_file()},
            "web": {"repository": "remote-web", "legacyCopyStillBuilt": old_web_build},
        },
        "signatures": "no-release-signatures", "tufQualification": "rejected-raw-loader-persistence",
    }


def release_blockers(manifest):
    blockers = []
    for name, state in {"lomi-remote": manifest["implementation"], **manifest["applications"]}.items():
        if state.get("state") != "present" or not state.get("revision") or state.get("dirty") is not False:
            blockers.append(f"{name}: clean immutable source revision required")
    if not manifest["canonicalSources"]["crypto"]["present"]:
        blockers.append("canonical crypto migration is incomplete")
    if manifest["canonicalSources"]["web"]["legacyCopyStillBuilt"]:
        blockers.append("auth-app still builds the duplicate Remote Web source")
    blockers.extend([
        "complete frozen contracts and qualified terminal profile required",
        "signed artifacts, persistent TUF trust and OS qualification required",
        "staging acceptance, independent security review and operator publication authorization required",
    ])
    return blockers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    parser.add_argument("--release", action="store_true", help="Fail closed on incomplete release provenance")
    args = parser.parse_args()
    manifest = capture(args.repo.resolve())
    manifest["releaseBlockers"] = release_blockers(manifest)
    encoded = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded)
    else:
        sys.stdout.write(encoded)
    if args.release:
        for blocker in manifest["releaseBlockers"]:
            print(blocker, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
