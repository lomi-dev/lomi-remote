#!/usr/bin/env python3
"""Self-owned SDK primitive probe; no product or arbitrary-descendant qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tarfile
import uuid

REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY / "tools"))
from owned_process import initialize_process_ownership, run_owned

BASE = Path.home() / ".lomi-process-death-artifacts"
ENVIRONMENT = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
CASES = {
    "normal": "DeathObserved",
    "natural-before": "Unknown",
    "natural-during": "Unknown",
    "invalid-token": "Unknown",
    "registration-failure": "Unknown",
    "timeout": "Unknown",
    "truncated-list": "Unknown",
    "symbol-absent": "Unsupported",
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def capture(root, name, command, timeout=15):
    result = run_owned([str(value) for value in command], env=ENVIRONMENT, timeout=timeout)
    stdout = root / (name + ".stdout.log")
    stderr = root / (name + ".stderr.log")
    stdout.write_text(result.stdout)
    stderr.write_text(result.stderr)
    return result, {"command": [str(value) for value in command], "exitCode": result.returncode,
                    "stdoutSha256": sha(stdout), "stderrSha256": sha(stderr)}


def native():
    initialize_process_ownership()
    if sys.platform != "darwin":
        raise RuntimeError("native_macos_required")
    BASE.mkdir(mode=0o700, exist_ok=True)
    metadata = BASE.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise RuntimeError("private_fixture_artifacts_required")
    root = BASE / str(uuid.uuid4())
    root.mkdir(mode=0o700)
    (root / ".fixture-marker").write_text(root.name)
    source = root / "source"
    source.mkdir(mode=0o700)
    original = {"probe.c": Path(__file__).with_name("probe.c"), "run_native.py": Path(__file__),
                "owned_process.py": REPOSITORY / "tools/owned_process.py", "README.md": Path(__file__).with_name("README.md")}
    report = {"runId": root.name, "passed": False, "cleanupConfirmed": False,
              "scope": "self-owned unreaped child; primitive capability only",
              "qualifiedProduct": False, "qualifiedDescendantContainment": False,
              "unproved": ["arbitrary descendants", "PID reuse rehearsal", "fork-drain theorem", "SID escape", "UID escape", "NOTE_TRACK", "release support", "macOS P1 closure"],
              "environment": ENVIRONMENT, "sources": {}, "cases": {}, "commands": {}}

    def save():
        temporary = root / "evidence.tmp"
        temporary.write_text(json.dumps(report, indent=2) + "\n")
        temporary.chmod(0o600)
        os.replace(temporary, root / "evidence.json")

    save()
    try:
        for name, path in original.items():
            shutil.copyfile(path, source / name)
            (source / name).chmod(0o400)
            report["sources"][name] = sha(source / name)
            if sha(path) != report["sources"][name]:
                raise RuntimeError("source_changed_during_freeze")
        with tarfile.open(root / "source.tar.gz", "w:gz") as archive:
            archive.add(source, arcname="source")
        report["sourceArchiveSha256"] = sha(root / "source.tar.gz")
        sdk_result, report["commands"]["sdk"] = capture(root, "sdk", ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"])
        compiler_result, report["commands"]["compiler"] = capture(root, "compiler", ["/usr/bin/xcrun", "--sdk", "macosx", "--find", "clang"])
        if sdk_result.returncode or compiler_result.returncode:
            raise RuntimeError("sdk_or_compiler_unavailable")
        sdk = Path(sdk_result.stdout.strip())
        compiler = Path(compiler_result.stdout.strip())
        version, report["commands"]["compilerVersion"] = capture(root, "compiler-version", [compiler, "--version"])
        macos, report["commands"]["macosVersion"] = capture(root, "macos-version", ["/usr/bin/sw_vers"])
        if version.returncode or macos.returncode:
            raise RuntimeError("compiler_version_failed")
        report["platform"] = {"system": os.uname().sysname, "release": os.uname().release,
                              "machine": os.uname().machine, "macosVersion": macos.stdout, "sdk": str(sdk),
                              "sdkSettingsSha256": sha(sdk / "SDKSettings.json"),
                              "compiler": str(compiler), "compilerSha256": sha(compiler)}
        report["sdkHeadersSha256"] = {name: sha(sdk / "usr/include" / name) for name in
            ["libproc.h", "sys/event.h", "mach/task_info.h", "mach/message.h", "bsm/audit.h", "bsm/libbsm.h"]}
        binary = root / "probe"
        command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-g0", "-isysroot", sdk, source / "probe.c", "-lbsm", "-o", binary]
        compiled, report["commands"]["build"] = capture(root, "build", command, timeout=30)
        if compiled.returncode:
            raise RuntimeError("fixture_build_failed")
        binary.chmod(0o500)
        report["binarySha256"] = sha(binary)
        if any(sha(path) != report["sources"][name] or sha(source / name) != report["sources"][name] for name, path in original.items()):
            raise RuntimeError("source_changed_during_compile")
        save()
        for name, expected in CASES.items():
            result, invocation = capture(root, name, [binary, name], timeout=8)
            report["commands"][name] = invocation
            if result.returncode or len(result.stdout) > 8192:
                raise RuntimeError("fixture_command_failed")
            case = json.loads(result.stdout)
            report["cases"][name] = case
            save()
            if case["outcome"] != expected or not case["cleanupConfirmed"] or case["numericSignalsUsed"]:
                raise RuntimeError("fixture_outcome_or_cleanup_failed")
            if name == "normal" and not all(case[field] for field in ["retainedChildChecked", "auditIdentityChecked", "sessionChecked", "identityPrecheck", "identityPostcheck", "registrationAccepted", "exitEventObserved", "signalAttempted", "signalSucceeded", "ownedWaitConfirmed"]):
                raise RuntimeError("positive_primitive_observation_incomplete")
            if name != "normal" and case["signalAttempted"]:
                raise RuntimeError("negative_case_used_signal")
            if name == "invalid-token" and case["reason"] != "invalid-token-rejected":
                raise RuntimeError("invalid_token_api_not_rejected")
            if name == "timeout" and case["reason"] != "exit-observation-timeout":
                raise RuntimeError("timeout_case_did_not_timeout")
        if sha(binary) != report["binarySha256"] or sha(compiler) != report["platform"]["compilerSha256"] or any(sha(path) != report["sources"][name] or sha(source / name) != report["sources"][name] for name, path in original.items()):
            raise RuntimeError("inputs_changed_during_probe")
        if sha(sdk / "SDKSettings.json") != report["platform"]["sdkSettingsSha256"] or any(sha(sdk / "usr/include" / name) != digest for name, digest in report["sdkHeadersSha256"].items()):
            raise RuntimeError("sdk_changed_during_probe")
        report["cleanupConfirmed"] = all(case["cleanupConfirmed"] for case in report["cases"].values())
        report["passed"] = True
    except BaseException as error:
        report["failureType"] = type(error).__name__
        raise
    finally:
        save()
        print(root / "evidence.json")
    return root


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-native", action="store_true")
    options = parser.parse_args()
    if not options.run_native:
        parser.error("--run-native is required")
    native()
