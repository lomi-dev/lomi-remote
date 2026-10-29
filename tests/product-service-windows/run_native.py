#!/usr/bin/env python3
"""Frozen native product SCM proof: UUID Manual LocalService resources only."""
from pathlib import Path
import base64
import hashlib
import json
import sys
import subprocess
import tomllib
import tempfile
import uuid

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from run_windows_git_wasi_spike import Evidence, archive, extract_script
from owned_process import initialize_process_ownership

ART=ROOT/'artifacts/product-service-windows'

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def require_native_pass(result):
    for key in ('passed','actualHostDbDigestPreserved','workspacePreserved','manualLocalServiceOnly',
                'servicesAbsent','rootAbsent','registrationAbsent','sameAccountCleanup'):
        if result.get(key) is not True:raise RuntimeError('Native manager proof incomplete: '+key)
    if type(result.get('ownedProcessesRemaining')) is not int or result['ownedProcessesRemaining']!=0:raise RuntimeError('Owned manager processes remain')
    checks=result.get('checks',[])
    if len(checks)<20 or not all(row.get('passed') is True for row in checks):raise RuntimeError('Native manager check set incomplete')
    if result.get('publicBootCredentialsQualified') is not False:raise RuntimeError('Public boot credentials were not qualified')

def main():
    initialize_process_ownership()
    ART.mkdir(parents=True,exist_ok=True)
    run=str(uuid.uuid4())
    report={'format':1,'runId':run,'kind':'native-windows-product-service','passed':False,'complete':False,'remoteCompletionKnown':True,'operations':[],'scope':'Native manager lifecycle using actual default CLI host under UUID Manual LocalService; separate read-only same-account SQLite probes and explicit fixture cleanup. Public ordinary-account credentials/boot not qualified; no autostart, accounts, credentials, reboot or logoff changes.'}
    evidence=Evidence(ART/f'{run}.json',report)
    evidence.save()
    with tempfile.TemporaryDirectory(prefix='lomi-windows-input-') as staging:
        staging=Path(staging)
        manifest=staging/'Cargo.toml'
        manifest.write_text('[workspace]\nmembers = ["crates/lomiremote", "crates/lomi-host", "crates/lomi-host-store", "crates/lomi-platform", "crates/lomi-windows-pty", "crates/lomi-terminal", "crates/lomi-terminal-state", "crates/lomi-remote-protocol"]\nexclude = ["vendor/alacritty_terminal", "vendor/vte"]\nresolver = "3"\n[workspace.package]\nedition = "2024"\nrust-version = "1.98.1"\nversion = "0.1.0"\npublish = false\n[patch.crates-io]\nalacritty_terminal = { path = "vendor/alacritty_terminal" }\nvte = { path = "vendor/vte" }\n')
        files={'Cargo.toml':manifest,'Cargo.lock':ROOT/'Cargo.lock','rust-toolchain.toml':ROOT/'rust-toolchain.toml','Run-Bounded.ps1':ROOT/'tests/git-wasi-windows/Run-Bounded.ps1','tests/product-service-windows/test_acceptance.py':ROOT/'tests/product-service-windows/test_acceptance.py','tests/product-service-windows/Run-Proof.ps1':ROOT/'tests/product-service-windows/Run-Proof.ps1','tests/services-windows/Common.ps1':ROOT/'tests/services-windows/Common.ps1'}
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
    remote='lomi-windows-service-'+run
    remote_archive=remote+'.tar.gz'
    evidence.transfer('copy-frozen-inputs',source,remote_archive)
    location=json.loads(evidence.ps('hash-verify-and-extract',extract_script(remote,remote_archive,report['inputs']['archiveDigest'])))
    directory=location['directory']; report['remoteDirectory']=directory
    report['versions']=json.loads(evidence.ps('readonly-native-os-toolchain',"$ErrorActionPreference='Stop';$o=Get-CimInstance Win32_OperatingSystem;@{caption=$o.Caption;version=$o.Version;build=$o.BuildNumber;rust=(& rustc.exe +1.98.1 --version);session=[Diagnostics.Process]::GetCurrentProcess().SessionId}|ConvertTo-Json -Compress"))
    if report['versions']['session']!=0 or 'Windows 10' not in report['versions']['caption']:raise RuntimeError('Exact Windows 10 Session0 scope required')
    report['osScope']='Recorded Windows 10 LTSC build only; not Windows 11/Server qualification.'
    report['buildFeatures']={'actualCli':[], 'managerControllerAndObserver':['service-fixture'], 'remoteEnvironment':{'CARGO_INCREMENTAL':'0','profileDebug':'Cargo default'}}
    for name,args in [
        ('default-cli-build',"@('+1.98.1','build','--locked','-p','lomiremote','--bin','lomiremote')"),
        ('fixture-example-build',"@('+1.98.1','build','--locked','-p','lomiremote','--example','windows-service-proof','--features','service-fixture')"),
        ('manager-unit-tests',"@('+1.98.1','test','--locked','-p','lomi-platform','--lib','windows::service::tests::')"),
        ('default-cli-clippy',"@('+1.98.1','clippy','--locked','-p','lomiremote','-p','lomi-host','--bin','lomiremote','--','-D','warnings')"),
        ('fixture-example-clippy',"@('+1.98.1','clippy','--locked','-p','lomiremote','--example','windows-service-proof','--features','service-fixture','--','-D','warnings')"),
    ]:
        script=f"$ErrorActionPreference='Stop';$env:CARGO_INCREMENTAL='0';$p='{directory}';$cargo=(Get-Command cargo.exe).Source;& (Join-Path $p 'Run-Bounded.ps1') -Executable $cargo -ArgumentList {args} -Directory $p -TimeoutSeconds 300"
        result=evidence.worker('native-'+name,script,320)
        output=base64.b64decode(result['stdoutBase64']);error=base64.b64decode(result['stderrBase64'])
        (ART/f'{run}.{name}.log').write_bytes(output+error)
        report[name]={k:v for k,v in result.items() if not k.endswith('Base64')}
        report[name]['cargoArguments']=args
        report[name]['stdoutSha256']=hashlib.sha256(output).hexdigest();report[name]['stderrSha256']=hashlib.sha256(error).hexdigest();evidence.save()
        if result['exitCode']!=0:raise RuntimeError('Native '+name+' failed; preserve frozen inputs')
    report['binaries']=json.loads(evidence.ps('separate-frozen-binary-digests',f"$p='{directory}';@((Join-Path $p 'target\\debug\\lomiremote.exe'),(Join-Path $p 'target\\debug\\examples\\windows-service-proof.exe'))|ForEach-Object{{$f=Get-Item -LiteralPath $_;@{{name=$f.Name;sha256=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant();bytes=$f.Length}}}}|ConvertTo-Json -Compress"))
    if '--build-only' in sys.argv:
        evidence.save();print(json.dumps({'report':str(evidence.path),'buildPassed':True,'preserved':True}));return
    script=f"$ErrorActionPreference='Stop';try{{$p='{directory}';& (Join-Path $p 'tests\\product-service-windows\\Run-Proof.ps1') -RunId '{run}' -Source $p}}catch{{@{{passed=$false;errorType=$_.Exception.GetType().Name;errorId=$_.FullyQualifiedErrorId;line=$_.InvocationInfo.ScriptLineNumber}}|ConvertTo-Json -Compress}}"
    report['native']=json.loads(evidence.ps('manual-LocalService-product-manager-proof',script,240))
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
