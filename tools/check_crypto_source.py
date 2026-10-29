#!/usr/bin/env python3
"""Check the audited crypto extraction without reading application data."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import subprocess

SOURCE_COMMIT = "2cef452c39eb8b455c8d2ae1251310dc870c50bb"
SOURCE_PREFIX = "src-tauri/crates/lomi-remote-crypto/"
ADAPTED = {"Cargo.toml", "src/lib.rs", "src/channel.rs", "src/identity.rs", "src/browser.rs"}
ADDED = {"README.md", "src/enrollment.rs", "tests/enrollment.rs", "src/grant_v3.rs",
         "src/host_key_enrollment.rs", "tests/host_key_enrollment.rs",
         "tests/fixtures/host-key-commitment-v1.json", "src/browser_v3.rs",
         "examples/v3_browser_interop.rs", "src/enrollment_wire.rs",
         "src/browser_authority.rs", "tests/enrollment_wire.rs",
         "tests/fixtures/enrollment-wire-v1.json", "src/host_refresh.rs",
         "tests/host_refresh.rs", "tests/fixtures/host-refresh-v1.json",
         "src/public_identity_wire.rs", "src/consumer_window.rs",
         "src/grant_v3_wire.rs", "src/browser_authority_v3.rs",
         "tests/public_identity_wire.rs", "tests/consumer_window.rs",
         "tests/grant_v3_wire.rs"}
PROOF = {"tests/grant-v3/proof.rs", "tests/grant-v3/vectors.json",
         "docs/implementation/grant-context-v3.md",
         "docs/implementation/host-key-enrollment.md",
         "tests/crypto-v3-browser/browser.mjs",
         "tests/crypto-v3-browser/native-vectors.json",
         "tests/crypto-v3-browser/test_native_bounds.py",
         "tests/crypto-v3-browser/README.md",
         "tools/run_crypto_v3_browser.py", "tools/owned_process.py",
         "packages/authority-crypto-wasm/package.json",
         "packages/authority-crypto-wasm/README.md",
         "packages/authority-crypto-wasm/scripts/build.mjs",
         "packages/authority-crypto-wasm/src/index.mjs",
         "packages/authority-crypto-wasm/src/index.d.ts",
         "packages/authority-crypto-wasm/test/authority.test.mjs",
         "packages/authority-crypto-wasm/test/types.ts",
         "packages/authority-crypto-wasm/test/window-identity.test.mjs",
         "packages/authority-crypto-wasm/test/authority-v3.test.mjs",
         "packages/authority-crypto-wasm/test/fixtures/registered-host-public.json",
         "packages/authority-crypto-wasm/test/fixtures/authority-v3-public.json",
         "packages/authority-crypto-wasm/THIRD_PARTY_NOTICES.json",
         "tools/package_authority_crypto.py",
         "tools/test_package_authority_crypto.py"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_file(root, relative):
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError("unsafe provenance path")
    path = root / rel
    if root.is_symlink() or any((root / Path(*rel.parts[:i])).is_symlink()
                                for i in range(1, len(rel.parts) + 1)):
        raise ValueError("symlink in provenance path")
    if not path.is_file():
        raise ValueError(f"missing source file: {relative}")
    return path


def verify(root, source_repo=None):
    manifest = json.loads((root / "tests/crypto-provenance/source.json").read_text())
    if (manifest["format"] != 1 or manifest["source_commit"] != SOURCE_COMMIT
            or manifest["source_prefix"] != SOURCE_PREFIX):
        raise ValueError("unexpected source identity")
    crate = root / "crates/lomi-remote-crypto"
    expected = set()
    upstream = set()
    for entry in manifest["files"]:
        src, dst = entry["source_path"], entry["destination_path"]
        if src in upstream or dst in expected:
            raise ValueError("duplicate provenance entry")
        upstream.add(src)
        expected.add(dst)
        for key in ("source_sha256", "imported_sha256"):
            if not re.fullmatch(r"[0-9a-f]{64}", entry[key]):
                raise ValueError(f"invalid SHA-256: {dst}")
        actual = digest(safe_file(crate, dst).read_bytes())
        if actual != entry["imported_sha256"]:
            raise ValueError(f"destination drift: {dst}")
        if entry["source_sha256"] != actual and src not in ADAPTED:
            raise ValueError(f"unapproved extraction adaptation: {src}")
        if src in ADAPTED and entry["source_sha256"] != actual and entry["changes"] == "none":
            raise ValueError(f"undocumented extraction adaptation: {src}")
    for entry in manifest["excluded"]:
        if entry["source_path"] != "Cargo.lock":
            raise ValueError("unexpected exclusion")
        upstream.add(entry["source_path"])
    if {entry["destination_path"] for entry in manifest["added_files"]} != ADDED:
        raise ValueError("unexpected added source inventory")
    for entry in manifest["added_files"]:
        dst = entry["destination_path"]
        if dst in expected:
            raise ValueError("duplicate added source entry")
        expected.add(dst)
        if digest(safe_file(crate, dst).read_bytes()) != entry["sha256"]:
            raise ValueError(f"added source drift: {dst}")
    actual = {p.relative_to(crate).as_posix() for p in crate.rglob("*") if p.is_file()}
    if actual != expected:
        raise ValueError("missing or unexpected crypto source files")
    proof = manifest["proof_files"]
    if (len(proof) != len(PROOF)
            or {entry["destination_path"] for entry in proof} != PROOF):
        raise ValueError("unexpected grant/context proof inventory")
    for entry in proof:
        dst = entry["destination_path"]
        if not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise ValueError(f"invalid SHA-256: {dst}")
        if digest(safe_file(root, dst).read_bytes()) != entry["sha256"]:
            raise ValueError(f"grant/context proof drift: {dst}")
    proof_roots = ("tests/grant-v3", "tests/crypto-v3-browser")
    actual_proof = {p.relative_to(root).as_posix()
                    for relative in proof_roots
                    for p in (root / relative).rglob("*")
                    if p.is_file() and "__pycache__" not in p.parts}
    if actual_proof != {p for p in PROOF if p.startswith(proof_roots)}:
        raise ValueError("unexpected grant/context proof files")
    if source_repo is not None:
        prefix = SOURCE_PREFIX
        files = subprocess.check_output([
            "git", "-C", str(source_repo), "ls-tree", "-r", "--name-only",
            SOURCE_COMMIT, prefix,
        ], text=True).splitlines()
        if {p.removeprefix(prefix) for p in files} != upstream:
            raise ValueError("upstream inventory mismatch")
        for entry in manifest["files"] + manifest["excluded"]:
            data = subprocess.check_output([
                "git", "-C", str(source_repo), "show",
                f"{SOURCE_COMMIT}:{prefix}{entry['source_path']}",
            ])
            if digest(data) != entry["source_sha256"]:
                raise ValueError(f"upstream blob mismatch: {entry['source_path']}")
    return len(expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repo", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        count = verify(root, args.source_repo)
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"crypto provenance failed: {error}\n")
    print(f"crypto provenance passed: {count} files; source {SOURCE_COMMIT}")


if __name__ == "__main__":
    main()
