#!/usr/bin/env python3
"""Controlled same-session product-provider proof; only a fresh custom Keychain."""
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from owned_process import initialize_process_ownership, run_owned

SDK = Path("/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inputs():
    paths = [ROOT / name for name in ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "tools/owned_process.py"]]
    for crate in ["lomi-platform", "lomi-remote-protocol", "lomi-macos-storage-fixture"]:
        directory = ROOT / "crates" / crate
        paths.append(directory / "Cargo.toml")
        paths.extend(directory.rglob("*.rs"))
    paths.extend(Path(__file__).parent.glob("*.py"))
    paths.append(Path(__file__).parent / "README.md")
    for name in ["SecItem.h", "SecAccess.h", "SecKeychain.h", "SecBase.h", "SecTrustedApplication.h"]:
        paths.append(SDK / "System/Library/Frameworks/Security.framework/Headers" / name)
    for name in ["CFBase.h", "CFArray.h", "CFDictionary.h", "CFData.h", "CFString.h"]:
        paths.append(SDK / "System/Library/Frameworks/CoreFoundation.framework/Headers" / name)
    paths.append(SDK / "SDKSettings.json")
    return {str(path): sha(path) for path in sorted(set(paths))}


def retain_frozen_inputs(artifacts, expected):
    """Keep exact reviewed bytes; compilation still uses guarded originals."""
    frozen = artifacts / "frozen-inputs"
    frozen.mkdir(mode=0o700)
    copies = {}
    for original, digest in expected.items():
        original = Path(original)
        if original.is_relative_to(ROOT):
            relative = Path("repository") / original.relative_to(ROOT)
        else:
            relative = Path("sdk") / original.relative_to(SDK)
        destination = frozen / relative
        destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        data = original.read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError("source changed before frozen copy")
        with destination.open("xb") as output:
            output.write(data)
        destination.chmod(0o400)
        if sha(destination) != digest:
            raise RuntimeError("frozen copy identity differs")
        copies[str(original)] = {"path": str(destination.relative_to(artifacts)), "sha256": digest}
    for directory in sorted((path for path in frozen.rglob("*") if path.is_dir()), reverse=True):
        directory.chmod(0o500)
    frozen.chmod(0o500)
    if inputs() != expected:
        raise RuntimeError("source changed across frozen copy")
    return copies


def main():
    if sys.platform != "darwin":
        raise SystemExit("native macOS required")
    initialize_process_ownership()
    run_id = str(uuid.uuid4())
    artifacts = ROOT / "artifacts/product-keychain-macos" / run_id
    artifacts.mkdir(parents=True, mode=0o700)
    artifacts.chmod(0o700)
    owned = artifacts / "owned"
    owned.mkdir(mode=0o700)
    report = {"format": 1, "runId": run_id, "passed": False, "operations": [],
              "scope": "Synthetic custom file Keychain, fresh same-executable helpers in the same Security session. No production login-Keychain, code-sign upgrade, launch-agent, reboot or power-loss qualification.",
              "platform": platform.platform(), "sdk": str(SDK), "sourceBefore": inputs()}
    evidence = artifacts / "report.json"

    def save():
        evidence.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        evidence.chmod(0o600)

    save()  # Frozen inputs and intent exist before compilation/native effects.
    report["frozenInputCopies"] = retain_frozen_inputs(artifacts, report["sourceBefore"])
    report["sourceBeforeCopyAfterUnchanged"] = True
    report["compilationSource"] = "shared workspace originals guarded by before/after SHA-256; retained read-only input copies"
    save()
    env = os.environ.copy()
    env.update({"SDKROOT": str(SDK), "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0",
                "CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "2",
                "RUSTC_LOG": "rustc_codegen_ssa::back::link=info",
                "RUSTFLAGS": "-C link-arg=-isysroot -C link-arg=" + str(SDK)})

    def command(name, argv, timeout=120):
        result = run_owned(argv, cwd=ROOT, env=env, timeout=timeout)
        stdout = result.stdout.decode() if isinstance(result.stdout, bytes) else result.stdout
        stderr = result.stderr.decode() if isinstance(result.stderr, bytes) else result.stderr
        # Commands carry only source/binary/owned public paths, never secrets.
        for suffix, text in [("stdout", stdout), ("stderr", stderr)]:
            log = artifacts / (name + "." + suffix)
            log.write_text(text)
            log.chmod(0o600)
        report["operations"].append({"name": name, "argv": list(map(str, argv)), "exitCode": result.returncode})
        save()
        if result.returncode != 0:
            raise RuntimeError(name + " failed; inspect private evidence")
        return stdout

    try:
        report["sdkVersion"] = command("sdk-version", ["/usr/bin/xcrun", "--sdk", str(SDK), "--show-sdk-version"]).strip()
        if report["sdkVersion"] != "26.5":
            raise RuntimeError("controlled SDK 26.5 required")
        # Distinct final-crate metadata forces this run's actual link command
        # to be logged, while all dependency builds share the normal cache.
        command("build", ["cargo", "rustc", "--locked", "--offline", "-p", "lomi-macos-storage-fixture", "--bin", "lomi-macos-storage-fixture", "--verbose", "--", "-C", "metadata=keychain_fixture_" + run_id.replace("-", "")])
        command("strict-clippy", ["cargo", "clippy", "--locked", "--offline", "-p", "lomi-platform", "-p", "lomi-macos-storage-fixture", "--all-targets", "--", "-D", "warnings"])
        command("keychain-unit-tests", ["cargo", "test", "--locked", "--offline", "-p", "lomi-platform", "unix::keychain::tests"])
        command("protected-file-tests", ["cargo", "test", "--locked", "--offline", "-p", "lomi-platform", "--test", "unix_secrets"])
        binary = ROOT / "target/debug/lomi-macos-storage-fixture"
        report["binaryBefore"] = sha(binary)
        report["buildEnvironment"] = {key: env[key] for key in ["SDKROOT", "CARGO_PROFILE_DEV_DEBUG", "CARGO_INCREMENTAL", "CARGO_BUILD_JOBS", "RUSTFLAGS", "RUSTC_LOG"]}
        report["linkCommandLog"] = str(artifacts / "build.stderr")
        save()
        result = command("native-product", [str(binary), "--product-private-keychain", str(owned)], timeout=60)
        proof = json.loads(result)
        report["proof"] = proof
        required = ["productProvider", "roundTripAndReopen", "lockedFreshHelperDenied", "tamperAndMissingKeyDenied",
                    "profileBindingAndExclusiveLock", "sameKeyDifferentProfileAadDenied", "validDifferentKeyAuthenticationDenied",
                    "originalKeyRestoredPositive", "defaultAndSearchListUnchanged", "keychainDeleted", "temporaryDirectoryRemoved"]
        if any(proof.get(name) is not True for name in required):
            raise RuntimeError("native proof incomplete")
        report["binaryAfter"] = sha(binary)
        report["sourceAfter"] = inputs()
        report["sourceUnchanged"] = report["sourceBefore"] == report["sourceAfter"]
        report["ownedDirectoryEmpty"] = not any(owned.iterdir())
        report["passed"] = report["sourceUnchanged"] and report["ownedDirectoryEmpty"] and report["binaryBefore"] == report["binaryAfter"]
        if not report["passed"]:
            raise RuntimeError("frozen identity or cleanup failed")
        owned.rmdir()
    finally:
        report["sourceAfter"] = inputs()
        report["sourceUnchanged"] = report["sourceBefore"] == report["sourceAfter"]
        save()
    print(str(evidence))


if __name__ == "__main__":
    main()
