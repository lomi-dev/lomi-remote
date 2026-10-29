#!/usr/bin/env python3
"""Native test coordinator for the specifically authorized Windows test host."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from owned_process import initialize_process_ownership, run_owned
from prepare_native import OPTIONS, PEER


def main():
    initialize_process_ownership()
    if len(sys.argv) != 2:
        raise ValueError("explicit prepared snapshot UUID required")
    snapshot = sys.argv[1]
    if len(snapshot) != 32 or any(c not in "0123456789abcdef" for c in snapshot):
        raise ValueError("invalid prepared snapshot")
    prepared = json.loads((ROOT / "artifacts/windows" / ("prepare-" + snapshot + ".json")).read_text())
    if prepared.get("complete") is not True:
        raise ValueError("prepared snapshot incomplete")
    source = prepared["source"]["sourceDirectory"].replace("'", "''")
    run = str(uuid.uuid4())
    evidence = ROOT / "artifacts/windows" / ("native-" + run + ".json")
    report = {"kind": "native-windows-service-synthetic", "runId": run,
              "snapshot": snapshot, "controllerSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "sourceInventoryDigest": prepared["sourceInventoryDigest"],
              "archiveDigest": prepared["archiveDigest"], "qualified": False,
              "complete": False, "passed": False, "operations": [],
              "not_run": ["reboot/headless boot", "SSH disconnect across logins", "multi-hour soak", "other architectures"]}
    installed_maybe = False
    native_test_attempted = False
    operator = None
    code = 1

    def save():
        evidence.write_text(json.dumps(report, indent=2) + "\n")

    def powershell(name, script, timeout=120, required=True):
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        argv = ["ssh", *OPTIONS, PEER, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded]
        row = {"name": name, "command": argv, "timeoutSeconds": timeout, "passed": False}
        report["operations"].append(row)
        save()
        started = time.monotonic()
        try:
            result = run_owned(argv, cwd=ROOT, timeout=timeout)
            row.update(exitCode=result.returncode, passed=result.returncode == 0)
            if result.returncode:
                row["diagnostic"] = (result.stdout + result.stderr)[-12000:]
                if required:
                    raise RuntimeError(name)
            return result.stdout.strip(), result.returncode
        finally:
            row["durationSeconds"] = round(time.monotonic() - started, 3)
            save()

    save()
    try:
        preflight = f"""$ErrorActionPreference='Stop'; $p='{source}'; $binary=Join-Path $p 'target\\debug\\lomi-windows-service-fixture.exe';
$i=[Security.Principal.WindowsIdentity]::GetCurrent();
@{{operatorSid=$i.User.Value;admin=([Security.Principal.WindowsPrincipal]::new($i)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);
windowsBuild=[Environment]::OSVersion.Version.ToString();architecture=[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString();
binarySha256=(Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant();
rustc=(& rustc.exe +1.98.1 --version);cargo=(& cargo.exe +1.98.1 --version);defaultToolchain=(& rustup.exe default)}}|ConvertTo-Json -Compress"""
        output, _ = powershell("readonly-preflight-binary-digest-account-versions", preflight)
        report["environment"] = json.loads(output)
        operator = report["environment"]["operatorSid"]
        if report["environment"]["admin"] is not True or not operator.startswith("S-1-5-21-"):
            raise RuntimeError("administrator operator required")
        policy = f"""$ErrorActionPreference='Stop'; Set-Location -LiteralPath '{source}';
& '.\\tests\\services-windows\\Test-PolicyRegression.ps1' -DisposableSyntheticResources -Binary (Join-Path (Get-Location).Path 'target\\debug\\lomi-windows-service-fixture.exe') -WorkDirectory (Get-Location).Path"""
        output, _ = powershell("native-parent-and-partial-cleanup-policy-regressions", policy)
        report["policy"] = json.loads(output)
        if report["policy"].get("passed") is not True or len(report["policy"].get("checks", [])) != 4:
            raise RuntimeError("incomplete policy proof")
        installed_maybe = True
        install = f"""$ErrorActionPreference='Stop'; Set-Location -LiteralPath '{source}';
& '.\\tests\\services-windows\\Install-Fixture.ps1' -DisposableSyntheticResources -RunId '{run}' -OperatorSid '{operator}' -Binary (Join-Path (Get-Location).Path 'target\\debug\\lomi-windows-service-fixture.exe')"""
        output, _ = powershell("install-fresh-exact-UUID-manual-LocalService", install)
        report["installation"] = json.loads(output)
        test = f"""$ErrorActionPreference='Stop'; Set-Location -LiteralPath '{source}';
& '.\\tests\\services-windows\\Test-Fixture.ps1' -DisposableSyntheticResources -RunId '{run}' -OperatorSid '{operator}' -Evidence (Join-Path (Get-Location).Path 'native-fixture-{run}.json') -FaultInjection"""
        native_test_attempted = True
        report["nativeTestAttempted"] = True
        save()
        _, test_code = powershell("native-SCM-ConPTY-DPAPI-IPC-fault-regressions", test, 240, required=False)
        read = f"""$ErrorActionPreference='Stop'; Get-Content -LiteralPath '{source}\\native-fixture-{run}.json' -Raw"""
        output, _ = powershell("read-own-class-only-test-evidence", read)
        report["native"] = json.loads(output.lstrip("\ufeff"))
        if test_code != 0:
            scm = f"""$ErrorActionPreference='Stop'; $s=Get-CimInstance Win32_Service -Filter \"Name='LomiFixture-{run}'\";
@{{state=$s.State;win32ExitCode=$s.ExitCode;specificExitCode=$s.ServiceSpecificExitCode}}|ConvertTo-Json -Compress"""
            output, _ = powershell("readonly-exact-service-SCM-exit-diagnostics", scm)
            report["scmDiagnostic"] = json.loads(output)
            diagnostic = f"""$ErrorActionPreference='Stop'; Set-Location -LiteralPath '{source}';
& '.\\target\\debug\\lomi-windows-service-fixture.exe' trust-probe '{run}' '{operator}'"""
            output, _ = powershell("synthetic-boolean-native-trust-diagnostics", diagnostic, required=False)
            if output:
                report["trustDiagnostic"] = json.loads(output)
            startup = f"""$ErrorActionPreference='Stop'; Set-Location -LiteralPath '{source}';
& '.\\target\\debug\\lomi-windows-service-fixture.exe' read-startup '{run}' '{operator}'"""
            output, _ = powershell("synthetic-startup-stage-diagnostics", startup, required=False)
            if output:
                report["startupDiagnostic"] = json.loads(output)
        status = f"""$ErrorActionPreference='Stop'; Set-Location -LiteralPath '{source}';
& '.\\tests\\services-windows\\Status-Fixture.ps1' -RunId '{run}' -OperatorSid '{operator}'"""
        output, _ = powershell("status-exact-owned-service", status)
        report["status"] = json.loads(output)
        checks = report["native"].get("checks", [])
        if (test_code != 0 or report["native"].get("passed") is not True
                or report["native"].get("qualified") is not False
                or len(checks) != 16 or len({c["name"] for c in checks}) != 16
                or not all(c.get("passed") is True for c in checks)):
            raise RuntimeError("native regression failure or incomplete check set")
        code = 0
    except KeyboardInterrupt:
        report["errorClass"], code = "KeyboardInterrupt", 130
    except Exception as error:
        report["errorClass"] = type(error).__name__
    finally:
        uncertain_cleanup = native_test_attempted and report.get("native", {}).get("cleanupVerified") is not True
        if uncertain_cleanup:
            report["cleanupDeferredUncertain"] = True
            code = 1
        if installed_maybe and operator is not None and not uncertain_cleanup:
            cleanup = f"""$ErrorActionPreference='Stop'; Set-Location -LiteralPath '{source}';
& '.\\tests\\services-windows\\Remove-Fixture.ps1' -DisposableSyntheticResources -RunId '{run}' -OperatorSid '{operator}'"""
            try:
                output, _ = powershell("remove-only-verified-exact-UUID-resources", cleanup)
                report["cleanup"] = json.loads(output)
                if report["cleanup"].get("removed") is not True:
                    raise RuntimeError("incomplete cleanup")
                absence = f"""$ErrorActionPreference='Stop'; $root='C:\\ProgramData\\LomiWindowsFixture\\{run}';
$exe=(Join-Path $root 'lomi-windows-service-fixture.exe').Replace('\\','\\\\');
@{{serviceAbsent=($null -eq (Get-CimInstance Win32_Service -Filter \"Name='LomiFixture-{run}'\"));privateUuidDirectoryAbsent=(-not (Test-Path -LiteralPath $root));ownedFixtureProcesses=@(Get-CimInstance Win32_Process -Filter (\"ExecutablePath='\"+$exe+\"'\")).Count}}|ConvertTo-Json -Compress"""
                output, _ = powershell("independent-readonly-final-exact-UUID-absence-and-processes", absence, 30)
                report["finalAbsence"] = json.loads(output)
                if report["finalAbsence"] != {"serviceAbsent": True, "privateUuidDirectoryAbsent": True, "ownedFixtureProcesses": 0}:
                    raise RuntimeError("owned resource absence not verified")
            except BaseException as error:
                report["cleanupErrorClass"], code = type(error).__name__, 1
        if code == 0:
            report["aggregate"] = {"policyPassed": 4, "policyTotal": 4,
                                   "nativePassed": 16, "nativeTotal": 16,
                                   "allRequiredChecksPassed": True,
                                   "cleanupAndIndependentAbsenceVerified": True}
        report.update(complete=code == 0, passed=code == 0, exitCode=code)
        save()
    print(json.dumps({"complete": report["complete"], "passed": report["passed"], "qualified": False,
                      "evidence": str(evidence.relative_to(ROOT))}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
