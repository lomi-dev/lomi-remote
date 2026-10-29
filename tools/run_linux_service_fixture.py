#!/usr/bin/env python3
"""Run the synthetic user-service proof only in disposable Lima VM lomi-e0."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time
import uuid
from datetime import datetime, timezone

from source_manifest import source_inventory
from owned_process import initialize_process_ownership, run_owned

ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = ROOT / "artifacts/services-linux"
LIMA = "/opt/homebrew/bin/limactl"
VM = "lomi-e0"
GUEST_HOME = "/home/lomi-e0"
ENV = {"HOME": str(Path.home()), "PATH": "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
       "LIMA_HOME": str(ROOT / "artifacts/lima"), "LANG": "C", "TERM": "dumb"}
report = {"fixture": True, "qualifiedProductHost": False, "vm": VM, "operations": [], "phases": []}


def save():
    report["driverSha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    counts = {}
    latest = {}
    latest_any = {}
    for attempt in report["phases"]:
        name = attempt["phase"]
        counts[name] = counts.get(name, 0) + 1
        attempt["attempt"] = counts[name]
        latest_any[name] = attempt
        if not attempt.get("invalidatedByInvocation"):
            latest[name] = attempt
    for attempt in report["phases"]:
        name = attempt["phase"]
        attempt["current"] = attempt is latest.get(name)
        if attempt is not latest_any[name]:
            attempt["supersededByAttempt"] = latest_any[name]["attempt"]
        else:
            attempt.pop("supersededByAttempt", None)
    required = ["prepare", "after-disconnect", "after-reboot", "cleanup"]
    report["latestPhaseResults"] = {
        name: {"attempt": attempt["attempt"], "passed": attempt["passed"],
               "checksPassed": sum(c["passed"] for c in attempt.get("checks", [])),
               "checksTotal": len(attempt.get("checks", []))}
        for name, attempt in latest.items()
    }
    report["finalComplete"] = all(name in latest for name in required)
    report["allRequiredLatestPhasesPassed"] = report["finalComplete"] and all(latest[name]["passed"] for name in required)
    report["latestChecksPassed"] = sum(v["checksPassed"] for v in report["latestPhaseResults"].values())
    report["latestChecksTotal"] = sum(v["checksTotal"] for v in report["latestPhaseResults"].values())
    failed = report.get("failedOperation")
    if failed in latest and latest[failed]["passed"]:
        report.setdefault("historicalFailures", []).append({"id": failed, "superseded": True,
                                                            "supersededByAttempt": latest[failed]["attempt"]})
        del report["failedOperation"]
    report["passed"] = report["allRequiredLatestPhasesPassed"] and report.get("invocationPassed", True) and report.get("invocationState") != "running"
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    temporary = ARTIFACTS / "evidence.json.tmp"
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    os.replace(temporary, ARTIFACTS / "evidence.json")


def begin_invocation(selected):
    identifier = uuid.uuid4().hex
    if selected in ["all", "transfer-build"]:
        # Each source build gets an isolated home-owned tree. Never probe or
        # reuse an existing tree, which may belong to a previous run.
        report["guestSourceRoot"] = GUEST_HOME + "/lomi-source-" + identifier
    else:
        source_root = report.get("guestSourceRoot")
        if not isinstance(source_root, str) or not source_root.startswith(GUEST_HOME + "/lomi-source-"):
            raise RuntimeError("continuation_source_root_unavailable")
        suffix = source_root.removeprefix(GUEST_HOME + "/lomi-source-")
        if len(suffix) != 32 or any(c not in "0123456789abcdef" for c in suffix):
            raise RuntimeError("continuation_source_root_invalid")
    if report.get("passed"):
        report.setdefault("completedProofHistory", []).append({
            "latestPhaseResults": report["latestPhaseResults"], "checksPassed": report["latestChecksPassed"],
            "sourceInventoryDigest": report.get("sourceInventoryDigest"), "supersededByInvocation": identifier})
    invalidates = {
        "all": ["prepare", "after-disconnect", "after-reboot", "cleanup"],
        "transfer-build": ["prepare", "after-disconnect", "after-reboot", "cleanup"],
        "prepare": ["prepare", "after-disconnect", "after-reboot", "cleanup"],
        "after-disconnect": ["after-disconnect", "after-reboot", "cleanup"],
        "reboot": ["after-reboot", "cleanup"],
        "after-reboot": ["after-reboot", "cleanup"], "cleanup": ["cleanup"],
        "native-validation": [],
    }[selected]
    for attempt in report["phases"]:
        if attempt["phase"] in invalidates and not attempt.get("invalidatedByInvocation"):
            attempt["invalidatedByInvocation"] = identifier
            attempt["invalidatedReason"] = "new " + selected + " invocation"
    report["invocationId"] = identifier
    report["invocationPassed"] = False
    report["invocationState"] = "running"
    report.setdefault("invocations", []).append({"id": identifier, "phase": selected,
        "state": "running", "startedAtUtc": datetime.now(timezone.utc).isoformat()})
    save()


def invoke(label, argv, timeout=120):
    print(json.dumps({"operation": label, "state": "running"}), flush=True)
    start = time.monotonic()
    operation = {"id": label, "command": list(argv), "state": "running", "exitCode": None,
                 "invocationId": report.get("invocationId")}
    report["operations"].append(operation)
    save()
    try:
        result = run_owned(argv, env=ENV, timeout=timeout)
    except BaseException as error:
        operation.update(state="interrupted" if isinstance(error, KeyboardInterrupt) else "failed",
                         errorClass=type(error).__name__, elapsedSeconds=round(time.monotonic() - start, 2))
        save()
        raise
    operation.update(exitCode=result.returncode, state="completed", elapsedSeconds=round(time.monotonic() - start, 2))
    save()
    if result.returncode:
        raise RuntimeError(label)
    return result.stdout


def shell(label, argv, workdir="/", timeout=120):
    return invoke(label, [LIMA, "shell", "--workdir=" + workdir, VM, *argv], timeout)


def transfer_build():
    guest = report["guestSourceRoot"]
    inventory = source_inventory(ROOT)
    report["sourceInventoryDigest"] = {"algorithm": "sha256", "value": inventory["digest"]}
    report["sourceFileCount"] = len(inventory["files"])
    report["fixtureSource"] = {name: digest for name, digest in inventory["files"].items()
                               if name.startswith(("crates/lomi-service-fixture/", "tests/services-linux/"))}
    archive = ARTIFACTS / "approved-source.tar.gz"
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "w:gz") as tar:
        for relative, digest in inventory["files"].items():
            data = (ROOT / relative).read_bytes()
            if hashlib.sha256(data).hexdigest() != digest:
                raise RuntimeError("source changed during inventory transfer")
            entry = tarfile.TarInfo(relative)
            entry.size = len(data)
            entry.mode = 0o644
            tar.addfile(entry, io.BytesIO(data))
    report["archiveDigest"] = {"algorithm": "sha256", "value": hashlib.sha256(archive.read_bytes()).hexdigest()}
    invoke("copy_approved_source", [LIMA, "copy", str(archive), VM + ":/home/lomi-e0/approved-service-source.tar.gz"])
    extract = (
        "import pathlib,tarfile; p=pathlib.Path(" + repr(guest) + "); p.mkdir(); "
        "t=tarfile.open('/home/lomi-e0/approved-service-source.tar.gz'); "
        "assert all(not m.issym() and not m.islnk() and not pathlib.PurePosixPath(m.name).is_absolute() "
        "and '..' not in pathlib.PurePosixPath(m.name).parts for m in t.getmembers()); t.extractall(p,filter='data')"
    )
    shell("extract_fresh_approved_source", ["python3", "-c", extract])
    shell("cargo_build_native_fixture", ["env", "CARGO_BUILD_JOBS=2", "/home/lomi-e0/.cargo/bin/cargo", "build", "--locked", "-p", "lomi-service-fixture"], guest, 1200)
    tests = shell("cargo_test_native_fixture", ["env", "CARGO_BUILD_JOBS=2", "/home/lomi-e0/.cargo/bin/cargo", "test", "--locked", "-p", "lomi-service-fixture"], guest, 180)
    import re
    report["nativeIntegrationTestsPassed"] = sum(int(count) for count in re.findall(r"test result: ok\. (\d+) passed", tests))
    versions = (
        "import json,platform,subprocess; print(json.dumps({'os':platform.platform(),"
        "'systemd':subprocess.check_output(['systemctl','--version'],text=True).splitlines()[0],"
        "'rustc':subprocess.check_output(['/home/lomi-e0/.cargo/bin/rustc','--version'],text=True).strip(),"
        "'cargo':subprocess.check_output(['/home/lomi-e0/.cargo/bin/cargo','--version'],text=True).strip()}))"
    )
    report["versions"] = json.loads(shell("record_guest_versions", ["python3", "-c", versions], guest))
    save()


def native_validation():
    # Update only this fixture's reviewed regular source. Do not alter systemd
    # state or reboot the VM shared with other native qualification workers.
    inventory = source_inventory(ROOT)
    names = native_validation_sources(inventory)
    report["lifecycleProofScope"] = "historical archived fixture snapshot; review fixes validated by native tests only"
    report["nativeReviewSourceInventoryDigest"] = {"algorithm": "sha256", "value": inventory["digest"]}
    report["nativeReviewSource"] = {name: inventory["files"][name] for name in names}
    archive = ARTIFACTS / "approved-native-review-source.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for name in names:
            data = (ROOT / name).read_bytes()
            if hashlib.sha256(data).hexdigest() != inventory["files"][name]:
                raise RuntimeError("fixture source changed during native validation transfer")
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            entry.mode = 0o644
            tar.addfile(entry, io.BytesIO(data))
    report["nativeReviewArchiveDigest"] = {"algorithm": "sha256", "value": hashlib.sha256(archive.read_bytes()).hexdigest()}
    invoke("copy_approved_native_review_source", [LIMA, "copy", str(archive), VM + ":/home/lomi-e0/approved-native-review-source.tar.gz"])
    guest = report["guestSourceRoot"]
    extract = (
        "import pathlib,tarfile; t=tarfile.open('/home/lomi-e0/approved-native-review-source.tar.gz'); "
        "assert all(not m.issym() and not m.islnk() and not pathlib.PurePosixPath(m.name).is_absolute() "
        "and '..' not in pathlib.PurePosixPath(m.name).parts for m in t.getmembers()); "
        "t.extractall(" + repr(guest) + ",filter='data')"
    )
    shell("extract_approved_native_review_source", ["python3", "-c", extract])
    # Patch archives have normalized mtimes. Cargo's timestamp fingerprints can
    # otherwise reuse an older fixture binary despite changed source contents.
    shell("cargo_clean_reviewed_fixture_only", ["/home/lomi-e0/.cargo/bin/cargo", "clean", "-p", "lomi-service-fixture"], guest, 30)
    tests = shell("cargo_test_reviewed_native_fixture", ["env", "CARGO_BUILD_JOBS=2", "/home/lomi-e0/.cargo/bin/cargo", "test", "--locked", "-p", "lomi-service-fixture"], guest, 180)
    import re
    count = sum(int(n) for n in re.findall(r"test result: ok\. (\d+) passed", tests))
    python_runner = (
        "import json,unittest; s=unittest.defaultTestLoader.discover('tests/tools',pattern='test_linux_service_runner.py'); "
        "r=unittest.TextTestRunner().run(s); print(json.dumps({'testsRun':r.testsRun,'passed':r.wasSuccessful()})); "
        "raise SystemExit(0 if r.wasSuccessful() else 1)"
    )
    summary = shell("python_test_reviewed_service_driver", ["python3", "-c", python_runner], guest, 30)
    python_result = json.loads(summary.splitlines()[-1])
    report["nativeReviewValidation"] = {"passed": python_result["passed"], "rustTestsPassed": count,
                                        "pythonDriverTestsPassed": python_result["testsRun"], "systemdLifecycleRerun": False}
    save()


def native_validation_sources(inventory):
    return [name for name in inventory["files"]
            if name.startswith(("crates/lomi-service-fixture/", "tests/services-linux/"))
            or name in ["tools/run_linux_service_fixture.py", "tools/owned_process.py",
                        "tests/tools/test_linux_service_runner.py"]]


def ensure_guest_phase_finished():
    if not report.get("remotePhaseCompletionUnverified"):
        return
    if time.time() < report.get("remotePhaseDeadlineUnix", float("inf")):
        report["cleanupDeferred"] = True
        raise RuntimeError("guest_phase_completion_unverified_cleanup_deferred")
    shell("verify_guest_phase_lock_released", ["sudo", "-n", "flock", "--nonblock",
          "/run/lomi-service-fixture-phase.lock", "/usr/bin/true"], timeout=15)
    report["remotePhaseCompletionUnverified"] = False
    report["cleanupDeferred"] = False
    save()


def phase(name):
    ensure_guest_phase_finished()
    token = uuid.uuid4().hex
    deadline = time.time() + 95
    guest = report.get("guestSourceRoot")
    if not isinstance(guest, str) or not guest.startswith(GUEST_HOME + "/lomi-source-"):
        raise RuntimeError("guest_source_root_unavailable")
    argv = ["sudo", "-n", "timeout", "--signal=TERM", "--kill-after=2s", "90s", "python3",
            guest + "/tests/services-linux/guest_probe.py", name, "--disposable-vm", VM,
            "--invocation-id", token, "--deadline-unix", str(deadline)]
    if name == "prepare":
        argv += ["--binary", guest + "/target/debug/lomi-service-fixture",
                 "--unit", guest + "/tests/services-linux/lomi-service-fixture.service"]
    command = [LIMA, "shell", "--workdir=/", VM, *argv]
    attempt = {"phase": name, "passed": False, "state": "running", "checks": [],
               "command": command, "driverInvocationId": report.get("invocationId"), "guestInvocationId": token}
    report["phases"].append(attempt)
    report["remotePhaseCompletionUnverified"] = True
    report["remotePhaseDeadlineUnix"] = deadline
    save()
    try:
        result = run_owned(command, env=ENV, timeout=110)
        result_json = json.loads(result.stdout)
        if result_json.get("invocationId") != token or result_json.get("phase") != name or not result_json.get("completed"):
            raise RuntimeError("guest_completion_not_verified")
    except BaseException as error:
        attempt.update(state="interrupted" if isinstance(error, KeyboardInterrupt) else "failed",
                       errorClass=type(error).__name__)
        save()
        raise
    report["remotePhaseCompletionUnverified"] = False
    attempt.update(result_json)
    attempt["state"] = "completed"
    save()
    print(json.dumps({"phase": name, "passed": attempt.get("passed", False)}), flush=True)
    if result.returncode or not attempt.get("passed"):
        raise RuntimeError(name)


def disconnect():
    # Close the actual SSH ControlMaster transport after its command channel
    # finished. The next probe reconnects as the distinct administrative user.
    config = Path(ENV["LIMA_HOME"]) / VM / "ssh.config"
    invoke("close_admin_ssh_transport", ["/usr/bin/ssh", "-F", str(config), "-O", "exit", "lima-" + VM])


def reboot():
    invoke("stop_disposable_vm", [LIMA, "stop", VM], 90)
    invoke("start_disposable_vm", [LIMA, "start", "--tty=false", VM], 120)


def main():
    initialize_process_ownership()
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=["all", "transfer-build", "prepare", "after-disconnect", "reboot", "after-reboot", "cleanup", "native-validation"], default="all")
    args = parser.parse_args()
    if sys.platform != "darwin" or not Path(ENV["LIMA_HOME"]).is_dir():
        raise SystemExit("This driver requires the dedicated local disposable Lima VM setup")
    if (ARTIFACTS / "evidence.json").exists():
        report.update(json.loads((ARTIFACTS / "evidence.json").read_text()))
    begin_invocation(args.phase)
    exit_code = 0
    try:
        if args.phase == "native-validation":
            native_validation()
        if args.phase in ["all", "transfer-build"]:
            transfer_build()
        if args.phase in ["all", "prepare"]:
            phase("prepare")
        if args.phase in ["all", "after-disconnect"]:
            disconnect()
            phase("after-disconnect")
        if args.phase in ["all", "reboot"]:
            reboot()
        if args.phase in ["all", "after-reboot"]:
            phase("after-reboot")
        if args.phase == "cleanup":
            phase("cleanup")
    except KeyboardInterrupt:
        exit_code = 130
        report["failedOperation"] = "interrupted"
    except Exception as error:
        exit_code = 1
        report["failedOperation"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    finally:
        if args.phase == "all":
            try:
                if report.get("remotePhaseCompletionUnverified"):
                    report["cleanupDeferred"] = True
                else:
                    phase("cleanup")
            except KeyboardInterrupt:
                exit_code = 130
                report["cleanupDeferred"] = True
            except Exception:
                if exit_code != 130:
                    exit_code = 1
                report["cleanupFailed"] = True
        report["invocationPassed"] = exit_code == 0
        report["invocationState"] = "interrupted" if exit_code == 130 else "completed" if exit_code == 0 else "failed"
        report["invocations"][-1].update(state=report["invocationState"], exitCode=exit_code,
                                         finishedAtUtc=datetime.now(timezone.utc).isoformat())
        save()
    return exit_code



if __name__ == "__main__":
    raise SystemExit(main())
