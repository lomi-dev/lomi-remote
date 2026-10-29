#!/usr/bin/env python3
"""Check that the client RPC parity inventory covers canonical Rust methods."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "crates/lomi-remote-protocol/src/lib.rs"
MANIFEST = ROOT / "contracts/client-rpc-parity.json"
CLIENTS = {"desktop", "remote-web", "mobile"}
STATUSES = {"source_call_present", "unverified", "blocked"}


def canonical_methods(source: str) -> dict[str, str]:
    try:
        block = source.split("methods! {", 1)[1].split("\n}", 1)[0]
    except IndexError as exc:
        raise ValueError("could not find methods! declaration") from exc
    pairs = re.findall(r'^\s*(\w+)\s*=>\s*"([^"]+)"', block, re.MULTILINE)
    if not pairs:
        raise ValueError("methods! declaration contained no method entries")
    if len({variant for variant, _ in pairs}) != len(pairs):
        raise ValueError("methods! declaration contains duplicate Rust variants")
    if len({wire for _, wire in pairs}) != len(pairs):
        raise ValueError("methods! declaration contains duplicate wire names")
    return dict(pairs)


def validate(source: str, manifest: dict) -> list[str]:
    errors = []
    try:
        expected = canonical_methods(source)
    except ValueError as exc:
        return [f"canonical source invalid: {exc}"]
    methods = manifest.get("methods")
    if not isinstance(methods, dict):
        return ["manifest methods must be an object keyed by wire method"]
    actual = {entry.get("rustVariant"): wire for wire, entry in methods.items() if isinstance(entry, dict)}
    if set(actual) != set(expected):
        errors.append("Rust variant coverage does not match the canonical declaration")
    missing = sorted(set(expected.values()) - set(methods))
    extra = sorted(set(methods) - set(expected.values()))
    if missing:
        errors.append("missing canonical wire methods: " + ", ".join(missing))
    if extra:
        errors.append("unknown wire methods: " + ", ".join(extra))
    for wire, entry in methods.items():
        if not isinstance(entry, dict):
            errors.append(f"{wire}: entry must be an object")
            continue
        variant = next((name for name, value in expected.items() if value == wire), None)
        if variant and entry.get("rustVariant") != variant:
            errors.append(f"{wire}: rustVariant must be {variant}")
        clients = entry.get("clients")
        if not isinstance(clients, dict) or set(clients) != CLIENTS:
            errors.append(f"{wire}: clients must be exactly {', '.join(sorted(CLIENTS))}")
            continue
        for client, details in clients.items():
            if not isinstance(details, dict):
                errors.append(f"{wire}/{client}: client entry must be an object")
                continue
            if details.get("status") not in STATUSES:
                errors.append(f"{wire}/{client}: invalid or missing status")
            if wire.startswith("git.") and details.get("status") != "blocked":
                errors.append(f"{wire}/{client}: Git methods must remain blocked")
            if details.get("status") == "source_call_present":
                evidence = details.get("evidence")
                if not isinstance(evidence, str) or not evidence:
                    errors.append(f"{wire}/{client}: source evidence path is required")
                else:
                    path = (ROOT / evidence).resolve()
                    try:
                        path.relative_to(ROOT.parent.resolve())
                    except ValueError:
                        errors.append(f"{wire}/{client}: source evidence escapes the project tree")
                    else:
                        if not path.is_file():
                            errors.append(f"{wire}/{client}: source evidence file does not exist")
        if entry.get("acceptanceTest") != "not_claimed":
            errors.append(f"{wire}: acceptanceTest must remain not_claimed")
    return errors


def main() -> int:
    manifest = json.loads(MANIFEST.read_text())
    errors = validate(SOURCE.read_text(), manifest)
    if errors:
        print("RPC parity manifest invalid:")
        print("\n".join(f"- {error}" for error in errors))
        return 1
    print(f"RPC parity manifest covers {len(manifest['methods'])} canonical methods")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
