#!/usr/bin/env python3
"""Frozen native Windows login adapter build/unit proof. No Task Scheduler mutations."""
from pathlib import Path
import argparse
import base64
import hashlib
import json
import sys
import tomllib
import tempfile
import uuid

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from run_windows_git_wasi_spike import Evidence, archive, extract_script
from owned_process import initialize_process_ownership, run_owned
sys.path.insert(0,str(Path(__file__).resolve().parent))
from source_closure import public_dependency_closure, workspace_manifest, verify_subset_lock, package_source_files as selected_crate_sources

ART=ROOT/'artifacts/product-login-windows'
LAUNCH_SOURCES = (
    'crates/lomi-platform/src/lib.rs',
    'crates/lomi-platform/src/windows/task.rs',
    'crates/lomi-platform/src/windows_login_start_policy.rs',
)

def require_launch_sources(files):
    if not all(name in files for name in LAUNCH_SOURCES):
        raise RuntimeError('Current launch policy source closure missing')

def native_checks(fixture_diagnostics=False):
    feature="'--features','service-fixture'," if fixture_diagnostics else ''
    return [
        ('product-binaries-build',"@('+1.98.1','build','--offline','--locked','-p','lomiremote',"+feature+"'--bins')",None),
        ('login-unit-tests',"@('+1.98.1','test','--offline','--locked','-p','lomi-platform','--lib','windows::task::tests::','--','--test-threads=1')",16),
        ('policy-unit-tests',"@('+1.98.1','test','--offline','--locked','-p','lomi-platform','--lib','windows_login_start_policy::tests::','--','--test-threads=1')",5),
        ('scm-regression-tests',"@('+1.98.1','test','--offline','--locked','-p','lomi-platform','--lib','windows::service::tests::')",5),
        ('product-clippy',"@('+1.98.1','clippy','--offline','--locked','-p','lomiremote','-p','lomi-host','-p','lomi-platform',"+feature+"'--bins','--','-D','warnings')",None),
        ('platform-tests-clippy',"@('+1.98.1','clippy','--offline','--locked','-p','lomi-platform','--tests','--','-D','warnings')",None),
    ]

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def require_native_build_tools(value):
    if set(value)!={'msvcCompilerDiscovered','msvcLinkerDiscovered','windowsSdkDiscovered','nativeCBuildRequired','compilerExecuted'}:raise RuntimeError('Unexpected native build preflight fields')
    for name in ['msvcCompilerDiscovered','msvcLinkerDiscovered','windowsSdkDiscovered','nativeCBuildRequired']:
        if value.get(name) is not True:raise RuntimeError('Native Windows MSVC C/linker/SDK prerequisites missing')
    if value.get('compilerExecuted') is not False:raise RuntimeError('Unexpected preflight compiler execution')

def require_build_pass(report):
    names=[name for name,_,_ in native_checks()]
    if report.get('taskSchedulerMutations') != 0 or report.get('ordinaryInteractiveLifecycleQualified') is not False:raise RuntimeError('Unexpected lifecycle claim')
    if any(report.get(name,{}).get('exitCode') != 0 for name in names):raise RuntimeError('Native build checks incomplete')
    if report.get('peSubsystems') != {'lomiremote.exe':3,'lomiremote-host.exe':2}:raise RuntimeError('Managed helper subsystem not proved')
    for name,_,count in native_checks():
        if count is not None and report.get(name,{}).get('verifiedPassedTests') != count:raise RuntimeError('Exact native unit counts missing')
    require_launch_sources(report.get('inputs',{}).get('files',{}))
    if report.get('freshBuildDirectoryVerified') is not True:raise RuntimeError('Fresh native rebuild not proved')
    require_native_build_tools(report.get('nativeBuildTools',{}))
    if report.get('lifecycleInputs') is True and report.get('harness-script-tests',{}).get('exitCode') != 0:raise RuntimeError('Native harness script tests missing')

def require_cleanup(result):
    if result.get('ownedSourceAbsent') is not True or result.get('ownedArchiveAbsent') is not True:raise RuntimeError('Transferred UUID artifacts remain')
    if type(result.get('ownedProcessesRemaining')) is not int or result['ownedProcessesRemaining'] != 0:raise RuntimeError('Owned native worker remains')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lifecycle',action='store_true',help='Require active ordinary test-user session and validate actual login adapter lifecycle')
    parser.add_argument('--prepare-lifecycle',action='store_true',help='Build and retain frozen lifecycle inputs without any Scheduler mutations')
    parser.add_argument('--fixture-diagnostics',action='store_true',help='Build service-fixture CLI/helper for closed launch-stage diagnostics; fixture qualification only')
    args=parser.parse_args()
    if args.lifecycle and args.prepare_lifecycle:parser.error('Choose lifecycle or prepare-lifecycle')
    if args.fixture_diagnostics and not (args.lifecycle or args.prepare_lifecycle):parser.error('Fixture diagnostics require lifecycle inputs')
    initialize_process_ownership()
    ART.mkdir(parents=True,exist_ok=True)
    run=str(uuid.uuid4())
    report={'format':1,'runId':run,'kind':'native-windows-login-build-tests','passed':False,'complete':False,'remoteCompletionKnown':True,'operations':[],'taskSchedulerMutations':0,'ordinaryInteractiveLifecycleQualified':False,'scope':'Windows build/unit/Clippy only. No Task Scheduler registration, task start/stop/delete, accounts, credentials, reboot or logoff. Ordinary-user interactive login lifecycle not run.'}
    report.update(lifecycleInputs=bool(args.lifecycle or args.prepare_lifecycle),logonTriggerQualified=False,visibleConsoleQualified=False,defaultProductLifecycleQualified=False)
    evidence=Evidence(ART/f'{run}.json',report)
    evidence.save()
    if args.lifecycle or args.prepare_lifecycle:
        report['scope']='Opt-in Windows10LTSC current ordinary active interactive session manual login-task lifecycle; no account/policy/password/logoff/reboot changes; actual logon trigger and visible console unqualified.'
        import lifecycle
        try:lifecycle.preflight(evidence)
        except RuntimeError as error:
            report['environmentBlocker']=str(error);evidence.save()
    with tempfile.TemporaryDirectory(prefix='lomi-windows-input-') as staging:
        staging=Path(staging)
        manifest=staging/'Cargo.toml'
        dependency_files,packages=public_dependency_closure(ROOT)
        workspace_manifest(ROOT,packages)
        manifest.write_bytes((ROOT/'Cargo.toml').read_bytes())
        files={**dependency_files,'Cargo.toml':ROOT/'Cargo.toml','Cargo.lock':ROOT/'Cargo.lock','rust-toolchain.toml':ROOT/'rust-toolchain.toml','Run-Bounded.ps1':ROOT/'tests/git-wasi-windows/Run-Bounded.ps1','tests/product-login-windows/test_acceptance.py':ROOT/'tests/product-login-windows/test_acceptance.py','tests/product-login-windows/source_closure.py':ROOT/'tests/product-login-windows/source_closure.py','tests/product-login-windows/build-preflight.ps1':ROOT/'tests/product-login-windows/build-preflight.ps1'}
        for source in [Path(__file__).resolve(),ROOT/'tools/owned_process.py',ROOT/'tools/run_windows_git_wasi_spike.py']:
            files[source.relative_to(ROOT).as_posix()]=source
        if args.lifecycle or args.prepare_lifecycle:
            for name in ['lifecycle.py','lifecycle-recover.py','lifecycle.ps1','lifecycle-admin.ps1','lifecycle-identity.ps1','lifecycle-tests.ps1','test_lifecycle.py']:
                files['tests/product-login-windows/'+name]=ROOT/'tests/product-login-windows'/name
        source_guard={'Cargo.toml':digest(ROOT/'Cargo.toml'),**{str(path.relative_to(ROOT)):digest(path) for path in files.values() if path.is_relative_to(ROOT)}}
        require_launch_sources(files)
        # Cargo must prune unrelated workspace/patch entries in the isolated
        # harness lock. Derive it offline, then prove that no dependency version,
        # registry source or checksum differs from the genuine workspace lock.
        for name,source_file in list(files.items()):
            target=staging/name
            if target==source_file:continue
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(source_file.read_bytes())
        private_home=staging/'private-home';private_home.mkdir()
        cache=Path.home()/'.cargo';rustup=Path.home()/'.rustup'
        environment={'PATH':str(cache/'bin')+':/usr/bin:/bin','HOME':str(private_home),'CARGO_HOME':str(cache),'RUSTUP_HOME':str(rustup),'CARGO_NET_OFFLINE':'true','CARGO_INCREMENTAL':'0'}
        lock_result=run_owned([str(cache/'bin/rustup'),'run','1.98.1','cargo','metadata','--offline','--format-version','1','--filter-platform','x86_64-pc-windows-msvc','--manifest-path',str(manifest)],cwd=staging,env=environment,timeout=180)
        if lock_result.returncode:raise RuntimeError('Offline harness dependency resolution failed')
        verify_subset_lock((ROOT/'Cargo.lock').read_text(),(staging/'Cargo.lock').read_text())
        files['Cargo.lock']=staging/'Cargo.lock'
        report['originalWorkspaceLockSha256']=digest(ROOT/'Cargo.lock')
        report['subsetLockSha256']=digest(staging/'Cargo.lock')
        report['subsetDependenciesMatchWorkspace']=True
        source=ART/f'{run}.tar.gz'
        report['inputs']=archive(source,files)
        report['liveSourceGuard']=source_guard
        report['pathDependencyPackages']=sorted(packages)
        report['workspaceRecipe']='Manifest-derived public path-dependency and workspace-patch closure, including explicit external targets and literal Rust data/module includes; offline-derived subset lock verified against original root dependency versions/sources/checksums; all crate sources/manifests unchanged.'
        report['originalWorkspaceManifestSha256']=digest(ROOT/'Cargo.toml')
        report['harnessSha256']=digest(Path(__file__).resolve())
        report['knownHostsSha256']=digest(ROOT/'artifacts/windows/known_hosts')
        evidence.save()
    remote='lomi-windows-login-'+run
    remote_archive=remote+'.tar.gz'
    evidence.transfer('copy-frozen-inputs',source,remote_archive)
    location=json.loads(evidence.ps('hash-verify-and-extract',extract_script(remote,remote_archive,report['inputs']['archiveDigest'])))
    directory=location['directory']; report['remoteDirectory']=directory
    # The newly extracted UUID source must have no old target artifacts. Both
    # binaries below are built here; no previous build receipt can supply them.
    fresh=json.loads(evidence.ps('readonly-fresh-native-build-directory',f"$ErrorActionPreference='Stop';$p='{directory}';if(Test-Path -LiteralPath (Join-Path $p 'target')){{throw 'Fresh native build required'}};@{{freshBuildDirectoryVerified=$true}}|ConvertTo-Json -Compress"))
    if fresh.get('freshBuildDirectoryVerified') is not True:raise RuntimeError('Fresh native build directory missing')
    report.update(fresh)
    preflight=directory+'\\tests\\product-login-windows\\build-preflight.ps1'
    report['nativeBuildTools']=json.loads(evidence.ps('readonly-native-msvc-sdk-discovery',f"& '{preflight}'"));evidence.save()
    require_native_build_tools(report['nativeBuildTools'])
    report['versions']=json.loads(evidence.ps('readonly-native-os-toolchain',"$ErrorActionPreference='Stop';$o=Get-CimInstance Win32_OperatingSystem;@{caption=$o.Caption;version=$o.Version;build=$o.BuildNumber;rust=(& rustc.exe +1.98.1 --version);session=[Diagnostics.Process]::GetCurrentProcess().SessionId}|ConvertTo-Json -Compress"))
    if report['versions']['session']!=0 or 'Windows 10' not in report['versions']['caption']:raise RuntimeError('Exact Windows 10 Session0 scope required')
    report['osScope']='Recorded Windows 10 LTSC build only; not Windows 11/Server qualification.'
    report['fixtureDiagnostics']=args.fixture_diagnostics
    report['buildFeatures']={'actualCliAndHelper':['service-fixture'] if args.fixture_diagnostics else [], 'qualification':'private fixture only' if args.fixture_diagnostics else 'default product features', 'remoteEnvironment':{'CARGO_INCREMENTAL':'0','profileDebug':'0','CARGO_PROFILE_DEV_DEBUG':'0','CARGO_PROFILE_TEST_DEBUG':'0','CARGO_BUILD_JOBS':'2','CARGO_NET_OFFLINE':'true'}}
    for name,cargo_args,count in native_checks(args.fixture_diagnostics):
        script=f"$ErrorActionPreference='Stop';$env:CARGO_INCREMENTAL='0';$env:CARGO_PROFILE_DEV_DEBUG='0';$env:CARGO_PROFILE_TEST_DEBUG='0';$env:CARGO_BUILD_JOBS='2';$env:CARGO_NET_OFFLINE='true';$p='{directory}';$cargo=(Get-Command cargo.exe).Source;& (Join-Path $p 'Run-Bounded.ps1') -Executable $cargo -ArgumentList {cargo_args} -Directory $p -TimeoutSeconds 300"
        result=evidence.worker('native-'+name,script,320)
        output=base64.b64decode(result['stdoutBase64']);error=base64.b64decode(result['stderrBase64'])
        (ART/f'{run}.{name}.log').write_bytes(output+error)
        report[name]={k:v for k,v in result.items() if not k.endswith('Base64')}
        report[name]['cargoArguments']=cargo_args
        report[name]['stdoutSha256']=hashlib.sha256(output).hexdigest();report[name]['stderrSha256']=hashlib.sha256(error).hexdigest();evidence.save()
        if result['exitCode']!=0:raise RuntimeError('Native '+name+' failed; preserve frozen inputs')
        if count is not None:
            if ('test result: ok. '+str(count)+' passed; 0 failed') not in output.decode('utf-8','replace'):raise RuntimeError('Exact native test count missing')
            report[name]['verifiedPassedTests']=count;evidence.save()
    if report['lifecycleInputs']:
        script=f"$ErrorActionPreference='Stop';$p='{directory}';$program=Join-Path $env:SystemRoot 'System32\\WindowsPowerShell\\v1.0\\powershell.exe';& (Join-Path $p 'Run-Bounded.ps1') -Executable $program -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $p 'tests\\product-login-windows\\lifecycle-tests.ps1'),'-Source',(Join-Path $p 'tests\\product-login-windows')) -Directory $p -TimeoutSeconds 120"
        result=evidence.worker('native-harness-script-tests',script,140)
        output=base64.b64decode(result['stdoutBase64']);error=base64.b64decode(result['stderrBase64'])
        (ART/f'{run}.harness-script-tests.log').write_bytes(output+error)
        report['harness-script-tests']={k:v for k,v in result.items() if not k.endswith('Base64')};evidence.save()
        if result['exitCode']!=0:raise RuntimeError('Native harness script tests failed')
    report['binaries']=json.loads(evidence.ps('separate-frozen-binary-digests',f"$p='{directory}';@((Join-Path $p 'target\\debug\\lomiremote.exe'),(Join-Path $p 'target\\debug\\lomiremote-host.exe'))|ForEach-Object{{$f=Get-Item -LiteralPath $_;@{{name=$f.Name;sha256=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant();bytes=$f.Length}}}}|ConvertTo-Json -Compress"))
    report['peSubsystems']=json.loads(evidence.ps('readonly-PE-subsystem-proof',f"$ErrorActionPreference='Stop';$p='{directory}';$result=@{{}};foreach($name in @('lomiremote.exe','lomiremote-host.exe')){{$bytes=[IO.File]::ReadAllBytes((Join-Path $p ('target\\debug\\'+$name)));$offset=[BitConverter]::ToInt32($bytes,60);if([Text.Encoding]::ASCII.GetString($bytes,0,2) -cne 'MZ' -or [BitConverter]::ToInt32($bytes,$offset) -ne 17744){{throw 'PE signature invalid'}};$result[$name]=[int][BitConverter]::ToUInt16($bytes,$offset+92)}};$result|ConvertTo-Json -Compress"))
    evidence.save();require_build_pass(report)
    changed=[name for name,value in source_guard.items() if digest(ROOT/name)!=value]
    report['liveSourcesUnchangedBeforeLifecycle']=not changed;evidence.save()
    if changed:raise RuntimeError('Frozen live sources changed; preserve native artifacts')
    if args.prepare_lifecycle:
        report['buildPassed']=True;report['retainedFrozenSource']=directory;report['scope']='Frozen build/unit tests passed; retained inputs for reviewed ordinary lifecycle. No Scheduler mutations.';evidence.save()
        print(json.dumps({'report':str(evidence.path.relative_to(ROOT)),'buildPassed':True,'lifecycleComplete':False,'retainedFrozenSource':directory}));return
    if args.lifecycle:
        import lifecycle
        try:
            lifecycle.execute(evidence,directory,report['binaries'])
        except BaseException:
            report['lifecycleIncomplete']=True;report['retainedFrozenSource']=directory;evidence.save();raise
        report['ordinaryInteractiveLifecycleQualified']=True
        report['defaultProductLifecycleQualified']=not args.fixture_diagnostics
        report['taskSchedulerMutationsAttempted']=True
        report.pop('environmentBlocker',None)
        # The ordinary UUID/helper cleanup passed. Build source uses its
        # original independent frozen-inventory cleanup below.

    inventory=ART/f'{run}.source-inventory.json'
    inventory.write_text(json.dumps(report['inputs']['files'],sort_keys=True))
    evidence.transfer('copy-exact-source-cleanup-inventory',inventory,directory+'/source-inventory.json')
    inventory_digest=digest(inventory)
    cleanup=f"$ErrorActionPreference='Stop';$p='{directory}';$archive=Join-Path $env:USERPROFILE '{remote_archive}';if((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){{throw 'UUID root is a reparse point'}};if((Get-Item -LiteralPath $archive -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){{throw 'Archive is a reparse point'}};if((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne '{report['inputs']['archiveDigest']}'){{throw 'Archive changed; preserve'}};if([IO.Path]::GetFileName($p) -cne '{remote}'){{throw 'Cleanup UUID mismatch'}};if(@(Get-CimInstance Win32_Process|Where-Object{{$_.ExecutablePath -and $_.ExecutablePath.StartsWith($p+'\\',[StringComparison]::OrdinalIgnoreCase)}}).Count -ne 0){{throw 'Owned build worker remains'}};$manifest=Join-Path $p 'source-inventory.json';if((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant() -cne '{inventory_digest}'){{throw 'Inventory digest mismatch'}};$inventory=Get-Content -LiteralPath $manifest -Raw|ConvertFrom-Json;foreach($item in Get-ChildItem -LiteralPath $p -Recurse -Force){{if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){{throw 'Unknown reparse entry'}};if($item.PSIsContainer){{continue}};$relative=$item.FullName.Substring($p.Length+1).Replace('\\','/');if($relative -eq 'source-inventory.json' -or $relative.StartsWith('target/')){{continue}};$entry=$inventory.PSObject.Properties[$relative];if($null -eq $entry -or (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.Value.sha256){{throw 'Unknown or modified source; preserve'}}}};Remove-Item -LiteralPath $p -Recurse -Force;Remove-Item -LiteralPath $archive -Force;@{{ownedSourceAbsent=(!(Test-Path -LiteralPath $p));ownedArchiveAbsent=(!(Test-Path -LiteralPath $archive));ownedProcessesRemaining=0}}|ConvertTo-Json -Compress"
    report['cleanup']=json.loads(evidence.ps('remove-only-completed-UUID-source',cleanup))
    require_cleanup(report['cleanup'])
    report['complete']=report['passed']=True;evidence.save()
    print(json.dumps({'report':str(evidence.path.relative_to(ROOT)),'passed':True,'runId':run}))
if __name__=='__main__':main()
