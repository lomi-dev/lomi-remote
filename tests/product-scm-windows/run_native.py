#!/usr/bin/env python3
"""Frozen native product SCM proof: UUID Manual LocalService resources only."""
from pathlib import Path
import base64
import hashlib
import json
import sys
import subprocess
import tempfile
import uuid

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from run_windows_git_wasi_spike import Evidence, archive, extract_script
from owned_process import initialize_process_ownership
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'product-login-windows'))
from source_closure import public_dependency_closure, workspace_manifest, verify_subset_lock

ART=ROOT/'artifacts/product-scm-windows'

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def subset_metadata_command(manifest):
    # Cargo prunes unrelated lock entries for the staged workspace, so
    # --locked cannot be used here. verify_subset_lock rejects any package
    # identity absent from the checked-in lock after resolution completes.
    return ['cargo','metadata','--format-version','1','--filter-platform',
            'x86_64-pc-windows-msvc','--manifest-path',str(manifest)]

def require_native_pass(result):
    """A claimed pass cannot override missing cleanup or lifecycle evidence."""
    for field in ('passed','serviceAbsent','profileRootAbsent','controlledJobTreeGone',
                  'crashedJobTreeGone','sentinelPreserved','foreignAccountRejected'):
        if result.get(field) is not True:
            raise RuntimeError('Native proof incomplete: '+field)
    if type(result.get('ownedProcessesRemaining')) is not int or result['ownedProcessesRemaining'] != 0:
        raise RuntimeError('Native owned processes remain or are unproven')
    observer=result.get('observerExample',{})
    if (not all(observer.get(key) is True for key in ('passed','twoClients','ptyInput','ptyResize','ptyCtrlC','dpapiSameAccountRoundtrip'))
            or observer.get('consoleAttached') is not False):
        raise RuntimeError('Product PTY/IPC/account proof incomplete')
    if not all(result.get('actualCliEntry',{}).get(key) is True for key in ('running','controlledStop','crashNonzero','restart')):
        raise RuntimeError('Default CLI SCM entry proof incomplete')
    timeout=result.get('productionTimeout',{})
    if (type(timeout.get('processExitCode')) is not int or timeout['processExitCode'] != 1
            or not all(timeout.get(key) is True for key in ('scmFailed','ownedTreeGone','realScmStop'))):
        raise RuntimeError('Production deadline failure unproven')
    restart=result.get('restart',{})
    if (restart.get('oldSessionLost') is not True or restart.get('automaticShell') is not False
            or restart.get('inputReplayed') is not False):
        raise RuntimeError('Restart loss/no-replay evidence incomplete')


def main():
    initialize_process_ownership()
    ART.mkdir(parents=True,exist_ok=True)
    run=str(uuid.uuid4())
    report={'format':1,'runId':run,'kind':'native-windows-product-scm','passed':False,'complete':False,'remoteCompletionKnown':True,'operations':[],'scope':'Manual UUID SCM LocalService: actual default CLI entry and production dispatcher observer example. Exact Windows build only; no dedicated-account production qualification, autostart, reboot, logoff or credentials.'}
    evidence=Evidence(ART/f'{run}.json',report)
    evidence.save()
    with tempfile.TemporaryDirectory(prefix='lomi-windows-input-') as staging:
        staging=Path(staging)
        manifest=staging/'Cargo.toml'
        files,packages=public_dependency_closure(ROOT,('crates/lomiremote','crates/lomi-host','crates/lomi-platform'))
        workspace_manifest(ROOT,packages)
        required={'crates/lomi-files','crates/lomiremote','crates/lomi-host','crates/lomi-platform'}
        if not required.issubset(packages):raise RuntimeError('Current SCM product path-dependency closure is incomplete')
        example=ROOT/'crates/lomiremote/examples/windows-scm-proof.rs'
        if example.relative_to(ROOT).as_posix() not in files:raise RuntimeError('SCM fixture example missing from source closure')
        manifest.write_bytes((ROOT/'Cargo.toml').read_bytes())
        files.update({'Cargo.lock':ROOT/'Cargo.lock','rust-toolchain.toml':ROOT/'rust-toolchain.toml','Run-Bounded.ps1':ROOT/'tests/git-wasi-windows/Run-Bounded.ps1','tests/product-scm-windows/test_acceptance.py':ROOT/'tests/product-scm-windows/test_acceptance.py','tests/product-scm-windows/README.md':ROOT/'tests/product-scm-windows/README.md','tests/product-scm-windows/Run-Proof.ps1':ROOT/'tests/product-scm-windows/Run-Proof.ps1','tests/services-windows/Common.ps1':ROOT/'tests/services-windows/Common.ps1','tests/product-login-windows/source_closure.py':ROOT/'tests/product-login-windows/source_closure.py'})
        qualification=ROOT/'tests/terminal-state-native/qualification.rs'
        files[qualification.relative_to(ROOT).as_posix()]=qualification
        for source in [Path(__file__).resolve(),ROOT/'tools/owned_process.py',ROOT/'tools/run_windows_git_wasi_spike.py']:
            files[source.relative_to(ROOT).as_posix()]=source
        # Cargo must prune unrelated workspace/patch entries in the isolated
        # harness lock. Allow Cargo to seed a fresh local cache; the exact
        # version/source/checksum check below rejects any identity outside the
        # genuine workspace lock.
        for name,source_file in list(files.items()):
            target=staging/name
            if target==source_file:continue
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(source_file.read_bytes())
        lock_result=subprocess.run(subset_metadata_command(manifest),cwd=ROOT,capture_output=True)
        if lock_result.returncode:raise RuntimeError(lock_result.stderr.decode('utf-8','replace'))
        verify_subset_lock((ROOT/'Cargo.lock').read_text(),(staging/'Cargo.lock').read_text())
        files['Cargo.lock']=staging/'Cargo.lock'
        report['originalWorkspaceLockSha256']=digest(ROOT/'Cargo.lock')
        report['subsetLockSha256']=digest(staging/'Cargo.lock')
        report['subsetDependenciesMatchWorkspace']=True
        source=ART/f'{run}.tar.gz'
        report['inputs']=archive(source,files)
        report['pathDependencyPackages']=sorted(packages)
        report['workspaceRecipe']='Manifest-derived public path-dependency and workspace-patch closure, including explicit Rust targets and literal includes; locked subset resolution verified against original root dependency versions/sources/checksums; all crate sources/manifests unchanged.'
        report['originalWorkspaceManifestSha256']=digest(ROOT/'Cargo.toml')
        report['harnessSha256']=digest(Path(__file__).resolve())
        report['knownHostsSha256']=digest(ROOT/'artifacts/windows/known_hosts')
        evidence.save()
    remote='lomi-windows-scm-'+run
    remote_archive=remote+'.tar.gz'
    evidence.transfer('copy-frozen-inputs',source,remote_archive)
    location=json.loads(evidence.ps('hash-verify-and-extract',extract_script(remote,remote_archive,report['inputs']['archiveDigest'])))
    directory=location['directory']; report['remoteDirectory']=directory
    report['versions']=json.loads(evidence.ps('readonly-native-os-toolchain',"$ErrorActionPreference='Stop';$o=Get-CimInstance Win32_OperatingSystem;@{caption=$o.Caption;version=$o.Version;build=$o.BuildNumber;rust=(& rustc.exe +1.98.1 --version);session=[Diagnostics.Process]::GetCurrentProcess().SessionId}|ConvertTo-Json -Compress"))
    if report['versions']['session']!=0 or 'Windows 10' not in report['versions']['caption']:raise RuntimeError('Exact Windows 10 Session0 scope required')
    report['osScope']='Recorded Windows 10 LTSC build only; not Windows 11/Server qualification.'
    report['buildFeatures']={'actualCli':[], 'observerExample':['scm-fixture'], 'remoteEnvironment':{'CARGO_INCREMENTAL':'0','profileDebug':'Cargo default'}}
    for name,args in [
        ('default-cli-build',"@('+1.98.1','build','--locked','-p','lomiremote','--bin','lomiremote')"),
        ('fixture-example-build',"@('+1.98.1','build','--locked','-p','lomiremote','--example','windows-scm-proof','--features','scm-fixture')"),
        ('platform-timeout-test',"@('+1.98.1','test','--locked','-p','lomi-platform','--lib','windows::tests::native_request_timeout_rejects_late_response_and_poisons_connection','--','--exact')"),
        ('default-cli-clippy',"@('+1.98.1','clippy','--locked','-p','lomiremote','-p','lomi-host','--bin','lomiremote','--','-D','warnings')"),
        ('fixture-example-clippy',"@('+1.98.1','clippy','--locked','-p','lomiremote','--example','windows-scm-proof','--features','scm-fixture','--','-D','warnings')"),
    ]:
        script=f"$ErrorActionPreference='Stop';$env:CARGO_INCREMENTAL='0';$p='{directory}';$cargo=(Get-Command cargo.exe).Source;& (Join-Path $p 'Run-Bounded.ps1') -Executable $cargo -ArgumentList {args} -Directory $p -TimeoutSeconds 300"
        result=evidence.worker('native-'+name,script,320)
        output=base64.b64decode(result['stdoutBase64']);error=base64.b64decode(result['stderrBase64'])
        (ART/f'{run}.{name}.log').write_bytes(output+error)
        report[name]={k:v for k,v in result.items() if not k.endswith('Base64')}
        report[name]['cargoArguments']=args
        report[name]['stdoutSha256']=hashlib.sha256(output).hexdigest();report[name]['stderrSha256']=hashlib.sha256(error).hexdigest();evidence.save()
        if result['exitCode']!=0:raise RuntimeError('Native '+name+' failed; preserve frozen inputs')
    report['binaries']=json.loads(evidence.ps('separate-frozen-binary-digests',f"$p='{directory}';@((Join-Path $p 'target\\debug\\lomiremote.exe'),(Join-Path $p 'target\\debug\\examples\\windows-scm-proof.exe'))|ForEach-Object{{$f=Get-Item -LiteralPath $_;@{{name=$f.Name;sha256=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant();bytes=$f.Length}}}}|ConvertTo-Json -Compress"))
    if '--build-only' in sys.argv:
        evidence.save();print(json.dumps({'report':str(evidence.path),'buildPassed':True,'preserved':True}));return
    script=f"$ErrorActionPreference='Stop';try{{$p='{directory}';& (Join-Path $p 'tests\\product-scm-windows\\Run-Proof.ps1') -RunId '{run}' -Source $p}}catch{{@{{passed=$false;errorType=$_.Exception.GetType().Name;errorId=$_.FullyQualifiedErrorId;line=$_.InvocationInfo.ScriptLineNumber}}|ConvertTo-Json -Compress}}"
    report['native']=json.loads(evidence.ps('manual-LocalService-production-SCM-proof',script,240))
    evidence.save()
    require_native_pass(report['native'])
    inventory=ART/f'{run}.source-inventory.json'
    inventory.write_text(json.dumps(report['inputs']['files'],sort_keys=True))
    evidence.transfer('copy-exact-source-cleanup-inventory',inventory,directory+'/source-inventory.json')
    inventory_digest=digest(inventory)
    cleanup=f"$ErrorActionPreference='Stop';$p='{directory}';if([IO.Path]::GetFileName($p) -cne '{remote}'){{throw 'Cleanup UUID mismatch'}};if(@(Get-CimInstance Win32_Process|Where-Object{{$_.ExecutablePath -and $_.ExecutablePath.StartsWith($p+'\\',[StringComparison]::OrdinalIgnoreCase)}}).Count -ne 0){{throw 'Owned build worker remains'}};$manifest=Join-Path $p 'source-inventory.json';if((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant() -cne '{inventory_digest}'){{throw 'Inventory digest mismatch'}};$inventory=Get-Content -LiteralPath $manifest -Raw|ConvertFrom-Json;foreach($item in Get-ChildItem -LiteralPath $p -Recurse -Force){{if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){{throw 'Unknown reparse entry'}};if($item.PSIsContainer){{continue}};$relative=$item.FullName.Substring($p.Length+1).Replace('\\','/');if($relative -eq 'source-inventory.json' -or $relative.StartsWith('target/')){{continue}};$entry=$inventory.PSObject.Properties[$relative];if($null -eq $entry -or (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.Value.sha256){{throw 'Unknown or modified source; preserve'}}}};Remove-Item -LiteralPath $p -Recurse -Force;Remove-Item -LiteralPath (Join-Path $env:USERPROFILE '{remote_archive}') -Force;@{{ownedSourceAbsent=(!(Test-Path -LiteralPath $p));ownedProcessesRemaining=0}}|ConvertTo-Json -Compress"
    report['cleanup']=json.loads(evidence.ps('remove-only-completed-UUID-source',cleanup))
    if report['cleanup'].get('ownedSourceAbsent') is not True or report['cleanup'].get('ownedProcessesRemaining') != 0:raise RuntimeError('Source cleanup incomplete')
    report['complete']=report['passed']=True;evidence.save()
    print(json.dumps({'report':str(evidence.path.relative_to(ROOT)),'passed':True,'runId':run}))
if __name__=='__main__':main()
