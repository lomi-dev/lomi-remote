#!/usr/bin/env python3
"""Frozen native Windows synthetic user-DPAPI cross-account proof; disposable Manual LocalService only."""
from pathlib import Path
import base64
import hashlib
import json
import re
import sys
import subprocess
import tomllib
import tempfile
import uuid

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from run_windows_git_wasi_spike import Evidence, archive, extract_script
from owned_process import initialize_process_ownership

ART=ROOT/'artifacts/product-dpapi-windows'

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def require_build_pass(report):
    names=['fixture-build','dpapi-unit-tests','fixture-clippy','platform-tests-clippy']
    if any(report.get(name,{}).get('exitCode') != 0 for name in names):raise RuntimeError('Native checks incomplete')
    if report.get('dpapi-unit-tests',{}).get('verifiedPassedTests') != 4:raise RuntimeError('Exact native units missing')

def require_proof(proof):
    if proof.get('passed') is not True or proof.get('fixtureRootAbsent') is not True or proof.get('ownedProcessesRemaining') != 0:raise RuntimeError('Fixture cleanup incomplete')
    if proof.get('taskSchedulerMutations') != 0 or proof.get('accountChanges') != 0 or proof.get('syntheticPayloadOnly') is not True:raise RuntimeError('Fixture scope invalid')
    export=proof['export'];run=proof['run'];finish=proof['finish'];crypto=run['proof'];deleted=proof['deleted'];created=proof['created']
    if created.get('created') is not True or created.get('started') is not False or created.get('manualLocalService') is not True or created.get('intentBeforeCreate') is not True or created.get('service') != 'LomiProductServiceProbe-'+proof.get('runId',''):raise RuntimeError('Manual never-started installation proof missing')
    if export.get('operatorSameAccountBefore') is not True or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+',str(export.get('operatorSid'))) :raise RuntimeError('Operator positive control missing')
    if any(crypto.get(key) is not True for key in ['same_account_before','same_account_after','provider_kind_windows_dpapi','provider_available_after','transport_acl_verified','ciphertext_readable','ciphertext_unchanged','wrong_sid_rejected']):raise RuntimeError('Cryptographic controls incomplete')
    if crypto.get('provider_error') != 'SECRET_STORAGE_UNAVAILABLE' or crypto.get('local_service_sid') != 'S-1-5-19':raise RuntimeError('Wrong provider rejection')
    if not re.fullmatch('[0-9a-f]{64}',str(export.get('ciphertextSha256'))) or type(export.get('ciphertextBytes')) is not int or not 13 <= export['ciphertextBytes'] <= 65548:raise RuntimeError('Invalid ciphertext identity')
    if crypto.get('ciphertext_sha256') != export.get('ciphertextSha256') or crypto.get('ciphertext_bytes') != export.get('ciphertextBytes'):raise RuntimeError('Ciphertext not identical')
    if run.get('processExitCode') != 0 or run.get('serviceStoppedExitCode') != 0 or run.get('ownerSession') != 0 or run.get('processHandleRetained') is not True or run.get('localServiceProfileAbsent') is not True:raise RuntimeError('Native owner cleanup unproved')
    if any(finish.get(key) is not True for key in ['operatorSameAccountAfter','originalCiphertextUnchanged','operatorProfileAbsent']):raise RuntimeError('Operator post control missing')
    if deleted.get('serviceAbsent') is not True or deleted.get('nativeAbsenceError') != 1060:raise RuntimeError('Native service absence missing')

def require_cleanup(result):
    if result.get('ownedSourceAbsent') is not True or result.get('ownedArchiveAbsent') is not True:raise RuntimeError('Transferred UUID artifacts remain')
    if type(result.get('ownedProcessesRemaining')) is not int or result['ownedProcessesRemaining'] != 0:raise RuntimeError('Owned native worker remains')

def main():
    initialize_process_ownership()
    ART.mkdir(parents=True,exist_ok=True)
    run=str(uuid.uuid4())
    report={'format':1,'runId':run,'kind':'native-windows-dpapi-cross-account','passed':False,'complete':False,'remoteCompletionKnown':True,'operations':[],'taskSchedulerMutations':0,'ordinaryInteractiveLifecycleQualified':False,'scope':'Synthetic current SSH operator vs existing LocalService user-DPAPI proof only. Disposable UUID Manual service; no Task, accounts, credentials, boot, reboot or logoff.'}
    evidence=Evidence(ART/f'{run}.json',report)
    evidence.save()
    with tempfile.TemporaryDirectory(prefix='lomi-windows-input-') as staging:
        staging=Path(staging)
        manifest=staging/'Cargo.toml'
        manifest.write_text('[workspace]\nmembers = ["crates/lomiremote", "crates/lomi-host", "crates/lomi-host-store", "crates/lomi-platform", "crates/lomi-windows-pty", "crates/lomi-terminal", "crates/lomi-terminal-state", "crates/lomi-remote-protocol"]\nexclude = ["vendor/alacritty_terminal", "vendor/vte"]\nresolver = "3"\n[workspace.package]\nedition = "2024"\nrust-version = "1.98.1"\nversion = "0.1.0"\npublish = false\n[patch.crates-io]\nalacritty_terminal = { path = "vendor/alacritty_terminal" }\nvte = { path = "vendor/vte" }\n')
        files={'Cargo.toml':manifest,'Cargo.lock':ROOT/'Cargo.lock','rust-toolchain.toml':ROOT/'rust-toolchain.toml','Run-Bounded.ps1':ROOT/'tests/git-wasi-windows/Run-Bounded.ps1','tests/product-dpapi-windows/test_acceptance.py':ROOT/'tests/product-dpapi-windows/test_acceptance.py','tests/product-dpapi-windows/Run-Proof.ps1':ROOT/'tests/product-dpapi-windows/Run-Proof.ps1','tests/services-windows/Common.ps1':ROOT/'tests/services-windows/Common.ps1','tests/product-dpapi-windows/Audit-Absence.ps1':ROOT/'tests/product-dpapi-windows/Audit-Absence.ps1'}
        for crate in ['lomiremote','lomi-host','lomi-host-store','lomi-platform','lomi-windows-pty', 'lomi-terminal', 'lomi-terminal-state', 'lomi-remote-protocol']:
            directory=ROOT/'crates'/crate
            files[f'crates/{crate}/Cargo.toml']=directory/'Cargo.toml'
            if (directory/'README.md').exists():files[f'crates/{crate}/README.md']=directory/'README.md'
            for source in sorted(directory.rglob('*')):
                if source.is_file() and source.suffix in ['.rs','.c','.h','.txt','.py']:
                    files[source.relative_to(ROOT).as_posix()]=source
        for vendor in ['alacritty_terminal','vte']:
            directory=ROOT/'vendor'/vendor
            for source in [directory/'Cargo.toml',directory/'README.md',*sorted((directory/'src').rglob('*.rs'))]:
                if source.is_file():files[source.relative_to(ROOT).as_posix()]=source
        qualification=ROOT/'tests/terminal-state-native/qualification.rs'
        files[qualification.relative_to(ROOT).as_posix()]=qualification
        for source in [Path(__file__).resolve(),ROOT/'tools/owned_process.py',ROOT/'tools/run_windows_git_wasi_spike.py']:
            files[source.relative_to(ROOT).as_posix()]=source
        # Cargo must prune unrelated workspace/patch entries in the isolated
        # harness lock. Derive it offline, then prove that no dependency version,
        # registry source or checksum differs from the genuine workspace lock.
        for name,source_file in list(files.items()):
            target=staging/name
            if target==source_file:continue
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(source_file.read_bytes())
        lock_result=subprocess.run(['cargo','metadata','--offline','--format-version','1','--filter-platform','x86_64-pc-windows-msvc','--manifest-path',str(manifest)],cwd=ROOT,capture_output=True)
        if lock_result.returncode:raise RuntimeError(lock_result.stderr.decode('utf-8','replace'))
        original=tomllib.loads((ROOT/'Cargo.lock').read_text())
        subset=tomllib.loads((staging/'Cargo.lock').read_text())
        frozen={(p['name'],p['version'],p.get('source'),p.get('checksum')) for p in original['package']}
        for package in subset['package']:
            identity=(package['name'],package['version'],package.get('source'),package.get('checksum'))
            if identity not in frozen:raise RuntimeError('Harness dependency differs from frozen workspace lock')
        files['Cargo.lock']=staging/'Cargo.lock'
        report['originalWorkspaceLockSha256']=digest(ROOT/'Cargo.lock')
        report['subsetLockSha256']=digest(staging/'Cargo.lock')
        report['subsetDependenciesMatchWorkspace']=True
        source=ART/f'{run}.tar.gz'
        report['inputs']=archive(source,files)
        report['workspaceRecipe']='Explicit eight-crate product harness workspace with exact vendored parser sources; offline-derived subset lock verified against original root dependency versions/sources/checksums; all crate sources/manifests unchanged.'
        report['originalWorkspaceManifestSha256']=digest(ROOT/'Cargo.toml')
        report['harnessSha256']=digest(Path(__file__).resolve())
        report['knownHostsSha256']=digest(ROOT/'artifacts/windows/known_hosts')
        evidence.save()
    remote='lomi-product-dpapi-'+run
    remote_archive=remote+'.tar.gz'
    evidence.transfer('copy-frozen-inputs',source,remote_archive)
    location=json.loads(evidence.ps('hash-verify-and-extract',extract_script(remote,remote_archive,report['inputs']['archiveDigest'])))
    directory=location['directory']; report['remoteDirectory']=directory
    report['versions']=json.loads(evidence.ps('readonly-native-os-toolchain',"$ErrorActionPreference='Stop';$o=Get-CimInstance Win32_OperatingSystem;@{caption=$o.Caption;version=$o.Version;build=$o.BuildNumber;rust=(& rustc.exe +1.98.1 --version);session=[Diagnostics.Process]::GetCurrentProcess().SessionId}|ConvertTo-Json -Compress"))
    if report['versions']['session']!=0 or 'Windows 10' not in report['versions']['caption']:raise RuntimeError('Exact Windows 10 Session0 scope required')
    report['osScope']='Recorded Windows 10 LTSC build only; not Windows 11/Server qualification.'
    report['buildFeatures']={'fixture':['dpapi-fixture'],'defaultReleaseHook':False,'remoteEnvironment':{'CARGO_INCREMENTAL':'0','profileDebug':'Cargo default'}}
    for name,args in [
        ('fixture-build',"@('+1.98.1','build','--locked','-p','lomiremote','--example','windows-service-proof','--features','dpapi-fixture')"),
        ('dpapi-unit-tests',"@('+1.98.1','test','--locked','-p','lomi-platform','--lib','--features','dpapi-fixture','windows::dpapi_fixture::tests::','--','--test-threads=1')"),
        ('fixture-clippy',"@('+1.98.1','clippy','--locked','-p','lomiremote','--example','windows-service-proof','--features','dpapi-fixture','--','-D','warnings')"),
        ('platform-tests-clippy',"@('+1.98.1','clippy','--locked','-p','lomi-platform','--tests','--features','dpapi-fixture','--','-D','warnings')"),
    ]:
        script=f"$ErrorActionPreference='Stop';$env:CARGO_INCREMENTAL='0';$p='{directory}';$cargo=(Get-Command cargo.exe).Source;& (Join-Path $p 'Run-Bounded.ps1') -Executable $cargo -ArgumentList {args} -Directory $p -TimeoutSeconds 300"
        result=evidence.worker('native-'+name,script,320)
        output=base64.b64decode(result['stdoutBase64']);error=base64.b64decode(result['stderrBase64'])
        (ART/f'{run}.{name}.log').write_bytes(output+error)
        report[name]={k:v for k,v in result.items() if not k.endswith('Base64')}
        report[name]['cargoArguments']=args
        report[name]['stdoutSha256']=hashlib.sha256(output).hexdigest();report[name]['stderrSha256']=hashlib.sha256(error).hexdigest();evidence.save()
        if result['exitCode']!=0:raise RuntimeError('Native '+name+' failed; preserve frozen inputs')
        if name=='dpapi-unit-tests':
            if 'test result: ok. 4 passed; 0 failed' not in output.decode('utf-8','replace'):raise RuntimeError('Exact native test count missing')
            report[name]['verifiedPassedTests']=4;evidence.save()
    require_build_pass(report)
    powershell=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    script=fr"$ErrorActionPreference='Stop';$p='{directory}'; & (Join-Path $p 'Run-Bounded.ps1') -Executable '{powershell}' -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $p 'tests\product-dpapi-windows\Run-Proof.ps1'),'-RunId','{run}','-Source',$p) -Directory $p -TimeoutSeconds 150"
    result=evidence.worker('native-synthetic-dpapi-proof',script,170)
    output=base64.b64decode(result['stdoutBase64']);error=base64.b64decode(result['stderrBase64'])
    (ART/f'{run}.native-proof.log').write_bytes(output+error)
    report['nativeProofWorker']={k:v for k,v in result.items() if not k.endswith('Base64')}
    report['nativeProofWorker']['stdoutSha256']=hashlib.sha256(output).hexdigest();report['nativeProofWorker']['stderrSha256']=hashlib.sha256(error).hexdigest();evidence.save()
    if result['exitCode']!=0:raise RuntimeError('Native DPAPI proof failed; preserve exact resources')
    report['proof']=json.loads(output.decode('utf-8-sig'));evidence.save();require_proof(report['proof'])
    inventory=ART/f'{run}.source-inventory.json'
    inventory.write_text(json.dumps(report['inputs']['files'],sort_keys=True))
    evidence.transfer('copy-exact-source-cleanup-inventory',inventory,directory+'/source-inventory.json')
    inventory_digest=digest(inventory)
    cleanup=f"$ErrorActionPreference='Stop';$p='{directory}';$archive=Join-Path $env:USERPROFILE '{remote_archive}';if((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){{throw 'UUID root is a reparse point'}};if((Get-Item -LiteralPath $archive -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){{throw 'Archive is a reparse point'}};if((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne '{report['inputs']['archiveDigest']}'){{throw 'Archive changed; preserve'}};if([IO.Path]::GetFileName($p) -cne '{remote}'){{throw 'Cleanup UUID mismatch'}};if(@(Get-CimInstance Win32_Process|Where-Object{{$_.ExecutablePath -and $_.ExecutablePath.StartsWith($p+'\\',[StringComparison]::OrdinalIgnoreCase)}}).Count -ne 0){{throw 'Owned build worker remains'}};$manifest=Join-Path $p 'source-inventory.json';if((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant() -cne '{inventory_digest}'){{throw 'Inventory digest mismatch'}};$inventory=Get-Content -LiteralPath $manifest -Raw|ConvertFrom-Json;foreach($item in Get-ChildItem -LiteralPath $p -Recurse -Force){{if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){{throw 'Unknown reparse entry'}};if($item.PSIsContainer){{continue}};$relative=$item.FullName.Substring($p.Length+1).Replace('\\','/');if($relative -eq 'source-inventory.json' -or $relative.StartsWith('target/')){{continue}};$entry=$inventory.PSObject.Properties[$relative];if($null -eq $entry -or (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.Value.sha256){{throw 'Unknown or modified source; preserve'}}}};Remove-Item -LiteralPath $p -Recurse -Force;Remove-Item -LiteralPath $archive -Force;@{{ownedSourceAbsent=(!(Test-Path -LiteralPath $p));ownedArchiveAbsent=(!(Test-Path -LiteralPath $archive));ownedProcessesRemaining=0}}|ConvertTo-Json -Compress"
    report['cleanup']=json.loads(evidence.ps('remove-only-completed-UUID-source',cleanup))
    require_cleanup(report['cleanup'])
    audit_script=(ROOT/'tests/product-dpapi-windows/Audit-Absence.ps1').read_text()
    audit_command='& {\n'+audit_script+f"\n}} -RunId '{run}' -Source '{directory}' -Archive (Join-Path $env:USERPROFILE '{remote_archive}')"
    report['finalAudit']=json.loads(evidence.ps('independent-fresh-transport-absence',audit_command))
    require_cleanup(report['finalAudit'])
    if report['finalAudit'].get('fixtureRootAbsent') is not True or any(value != 1060 for value in report['finalAudit'].get('serviceAbsence',{}).values()) or len(report['finalAudit'].get('serviceAbsence',{})) != 3:raise RuntimeError('Final native absence unconfirmed')
    report['complete']=report['passed']=True;evidence.save()
    print(json.dumps({'report':str(evidence.path.relative_to(ROOT)),'passed':True,'runId':run}))
if __name__=='__main__':main()
