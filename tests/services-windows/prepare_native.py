#!/usr/bin/env python3
"""Approved source-only transfer/build; never installs or starts a service."""
import base64
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from owned_process import initialize_process_ownership, run_owned
from source_manifest import source_inventory

ARTIFACTS = ROOT / "artifacts/windows"
PEER = "woro-server@192.168.1.129"
OPTIONS = ["-F", "/dev/null", "-oBatchMode=yes", "-oConnectTimeout=8", "-oLogLevel=ERROR",
           "-oStrictHostKeyChecking=yes", "-oUserKnownHostsFile=" + str(ARTIFACTS / "known_hosts"),
           "-oGlobalKnownHostsFile=/dev/null"]


def main():
    initialize_process_ownership()
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    identity = uuid.uuid4().hex
    evidence = ARTIFACTS / ("prepare-" + identity + ".json")
    archive = ARTIFACTS / ("source-" + identity + ".tar.gz")
    report = {"kind": "windows-native-build-preparation", "runId": identity,
              "complete": False, "qualified": False, "serviceInstalled": False,
              "nativeServiceTests": "not_run", "operations": []}

    def save():
        evidence.write_text(json.dumps(report, indent=2) + "\n")

    def command(name, argv, timeout):
        row = {"name": name, "command": argv, "timeoutSeconds": timeout, "passed": False}
        report["operations"].append(row)
        save()
        started = time.monotonic()
        try:
            result = run_owned(argv, cwd=ROOT, timeout=timeout)
            row.update(exitCode=result.returncode, passed=result.returncode == 0)
            if result.returncode:
                # Cargo/rustup diagnostics only; never ask for environment or
                # arbitrary process listings. Bound retained text.
                row["diagnostic"] = (result.stdout + result.stderr)[-12000:]
                raise RuntimeError(name)
            return result.stdout.strip()
        finally:
            row["durationSeconds"] = round(time.monotonic() - started, 3)
            save()

    def powershell(name, script, timeout=120):
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        return command(name, ["ssh", *OPTIONS, PEER, "powershell.exe", "-NoLogo", "-NoProfile",
                              "-NonInteractive", "-EncodedCommand", encoded], timeout)

    save()
    try:
        inventory = source_inventory(ROOT)
        report["sourceInventoryDigest"] = inventory["digest"]
        with tarfile.open(archive, "w:gz") as output:
            for relative, digest in inventory["files"].items():
                data = (ROOT / relative).read_bytes()
                if hashlib.sha256(data).hexdigest() != digest:
                    raise RuntimeError("source changed during packing")
                entry = tarfile.TarInfo(relative)
                entry.size, entry.mode = len(data), 0o644
                output.addfile(entry, io.BytesIO(data))
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        report["archiveDigest"] = digest
        remote_archive = "lomi-windows-source-" + identity + ".tar.gz"
        remote_source = "lomi-windows-source-" + identity
        command("copy-approved-source-only", ["scp", *OPTIONS, str(archive), PEER + ":" + remote_archive], 180)
        setup = f"""$ErrorActionPreference='Stop'; $p=Join-Path ([Environment]::GetFolderPath('UserProfile')) '{remote_source}';
$a=Join-Path ([Environment]::GetFolderPath('UserProfile')) '{remote_archive}';
if(Test-Path -LiteralPath $p){{throw 'Fresh source path exists'}};
if((Get-FileHash -LiteralPath $a -Algorithm SHA256).Hash.ToLowerInvariant() -cne '{digest}'){{throw 'Archive digest mismatch'}};
$null=New-Item -ItemType Directory -Path $p;
& tar.exe -xzf $a -C $p; if($LASTEXITCODE -ne 0){{throw 'Source extraction failed'}};
@{{sourceDirectory=$p;archiveDigestVerified=$true}}|ConvertTo-Json -Compress"""
        report["source"] = json.loads(powershell("extract-fresh-source-verify-digest", setup))
        remote_path = report["source"]["sourceDirectory"]
        escaped = remote_path.replace("'", "''")
        parser = f"""$ErrorActionPreference='Stop'; $p='{escaped}'; $rows=@();
Get-ChildItem -LiteralPath (Join-Path $p 'tests\\services-windows') -Filter '*.ps1'|ForEach-Object{{
$t=$null;$e=$null; $null=[Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$t,[ref]$e);
$rows+=@{{name=$_.Name;parseErrors=@($e).Count}} }};
@{{scripts=$rows;passed=(@($rows|Where-Object{{$_.parseErrors -ne 0}}).Count -eq 0)}}|ConvertTo-Json -Depth 5 -Compress"""
        report["powershellParser"] = json.loads(powershell("powershell-parser-only", parser))
        if report["powershellParser"]["passed"] is not True:
            raise RuntimeError("PowerShell parser failure")
        install = """$ErrorActionPreference='Stop'; & rustup.exe toolchain install 1.98.1 --no-self-update --profile minimal --component clippy --component rustfmt;
if($LASTEXITCODE -ne 0){exit $LASTEXITCODE};
& rustc.exe +1.98.1 --version; if($LASTEXITCODE -ne 0){exit $LASTEXITCODE};
& cargo.exe +1.98.1 --version; exit $LASTEXITCODE"""
        report["toolchain"] = powershell("install-side-by-side-pinned-toolchain-no-default-change", install, 900)
        build = f"""$ErrorActionPreference='Stop'; Set-Location -LiteralPath '{escaped}';
& cargo.exe +1.98.1 build --locked -p lomi-windows-service-fixture --features fixture-test-hooks; exit $LASTEXITCODE"""
        command_output = powershell("native-build-only-no-service-registration", build, 900)
        report["nativeBuild"] = {"passed": True, "output": command_output[-2000:]}
        report["complete"] = True
    except KeyboardInterrupt:
        report["errorClass"] = "KeyboardInterrupt"
    except Exception as error:
        report["errorClass"] = type(error).__name__
    finally:
        save()
    print(json.dumps({"complete": report["complete"], "qualified": False, "serviceInstalled": False,
                      "evidence": str(evidence.relative_to(ROOT))}))
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
