#!/usr/bin/env python3
"""Bounded, pinned-host native Windows IPC proof; no SCM or user-data changes."""
from pathlib import Path
import base64
import hashlib
import json
import sys
import tempfile
import uuid

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from run_windows_git_wasi_spike import Evidence, archive, extract_script
from owned_process import initialize_process_ownership
sys.path.insert(0,str(ROOT/'tests/product-login-windows'))
from source_closure import public_dependency_closure

ART=ROOT/'artifacts/product-host-windows'

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    initialize_process_ownership()
    ART.mkdir(parents=True,exist_ok=True)
    run=str(uuid.uuid4())
    report={'format':1,'runId':run,'kind':'native-windows-product-host','passed':False,'complete':False,'remoteCompletionKnown':True,'operations':[],'scope':'Product CLI/host/SQLite/IPC/ConPTY; synthetic private workspace only; no SCM or credentials.'}
    evidence=Evidence(ART/f'{run}.json',report)
    evidence.save()
    with tempfile.TemporaryDirectory(prefix='lomi-windows-input-') as staging:
        staging=Path(staging)
        manifest=staging/'Cargo.toml'
        workspace_crates={path.parent.relative_to(ROOT).as_posix() for path in sorted((ROOT/'crates').glob('*/Cargo.toml'))}
        dependency_files,packages=public_dependency_closure(ROOT,tuple(sorted(workspace_crates)))
        if not workspace_crates.issubset(packages):raise RuntimeError('Workspace crate source closure is incomplete')
        files={**dependency_files,'Cargo.toml':ROOT/'Cargo.toml','Cargo.lock':ROOT/'Cargo.lock','rust-toolchain.toml':ROOT/'rust-toolchain.toml','Run-Bounded.ps1':ROOT/'tests/git-wasi-windows/Run-Bounded.ps1'}
        qualification=ROOT/'tests/terminal-state-native/qualification.rs'
        files[qualification.relative_to(ROOT).as_posix()]=qualification
        for source in [Path(__file__).resolve(),ROOT/'tests/product-login-windows/source_closure.py',ROOT/'tools/owned_process.py',ROOT/'tools/run_windows_git_wasi_spike.py']:
            files[source.relative_to(ROOT).as_posix()]=source
        for name,source_file in list(files.items()):
            target=staging/name
            if target==source_file:continue
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(source_file.read_bytes())
        report['originalWorkspaceLockSha256']=digest(ROOT/'Cargo.lock')
        report['subsetLockSha256']=digest(staging/'Cargo.lock')
        report['workspaceLockStagedUnchanged']=report['subsetLockSha256']==report['originalWorkspaceLockSha256']
        if not report['workspaceLockStagedUnchanged']:raise RuntimeError('Staged workspace lock differs from checked-in lock')
        report['workspaceManifestStagedUnchanged']=digest(staging/'Cargo.toml')==digest(ROOT/'Cargo.toml')
        if not report['workspaceManifestStagedUnchanged']:raise RuntimeError('Staged workspace manifest differs from checked-in manifest')
        report['workspaceCrateCount']=len(workspace_crates)
        report['pathDependencyPackages']=sorted(packages)
        source=ART/f'{run}.tar.gz'
        report['inputs']=archive(source,files)
        report['workspaceRecipe']='Complete manifest-derived public workspace path-dependency and patch closure; original workspace manifest and lock staged byte-for-byte, with remote Cargo --locked commands enforcing the checked-in dependency graph; all crate sources/manifests unchanged.'
        report['originalWorkspaceManifestSha256']=digest(ROOT/'Cargo.toml')
        report['harnessSha256']=digest(Path(__file__).resolve())
        report['knownHostsSha256']=digest(ROOT/'artifacts/windows/known_hosts')
        evidence.save()
    remote='lomi-windows-host-'+run
    remote_archive=remote+'.tar.gz'
    evidence.transfer('copy-frozen-inputs',source,remote_archive)
    location=json.loads(evidence.ps('hash-verify-and-extract',extract_script(remote,remote_archive,report['inputs']['archiveDigest'])))
    directory=location['directory']
    report['remoteDirectory']=directory
    versions=evidence.ps('native-os-and-toolchain',"$ErrorActionPreference='Stop';$o=Get-CimInstance Win32_OperatingSystem;@{caption=$o.Caption;version=$o.Version;build=$o.BuildNumber;rust=(& rustc.exe +1.98.1 --version);cargo=(& cargo.exe +1.98.1 --version);session=[Diagnostics.Process]::GetCurrentProcess().SessionId}|ConvertTo-Json -Compress")
    report['versions']=json.loads(versions)
    report['osScope']='Exact recorded Windows 10 LTSC machine/build only; Windows 11/Server not qualified.'
    if report['versions']['session']!=0:raise RuntimeError('Expected Session0; preserve owned inputs')
    if 'Windows 10' not in report['versions']['caption']:raise RuntimeError('Unexpected Windows OS; preserve proof inputs')
    script=f"$ErrorActionPreference='Stop';$p='{directory}';$cargo=(Get-Command cargo.exe).Source;& (Join-Path $p 'Run-Bounded.ps1') -Executable $cargo -ArgumentList @('+1.98.1','build','--locked','-p','lomiremote','--bins','--examples') -Directory $p -TimeoutSeconds 300"
    result=evidence.worker('native-product-build',script,320)
    output=base64.b64decode(result['stdoutBase64']);error=base64.b64decode(result['stderrBase64'])
    report['build']={k:v for k,v in result.items() if not k.endswith('Base64')}
    report['build']['stdoutSha256']=hashlib.sha256(output).hexdigest();report['build']['stderrSha256']=hashlib.sha256(error).hexdigest()
    (ART/f'{run}.build.log').write_bytes(output+error)
    evidence.save()
    if result['exitCode']!=0:raise RuntimeError('Native Windows product build failed; preserve owned inputs')
    if '--build-only' in sys.argv:
        print(json.dumps({'report':str(evidence.path.relative_to(ROOT)),'buildPassed':True,'preserved':True,'runId':run}));return
    script=f"$ErrorActionPreference='Stop';$p='{directory}';$exe=Join-Path $p 'target\\debug\\examples\\windows-host-proof.exe';& (Join-Path $p 'Run-Bounded.ps1') -Executable $exe -ArgumentList @('{run}') -Directory $p -TimeoutSeconds 120"
    result=evidence.worker('native-product-host-proof',script,140)
    output=base64.b64decode(result['stdoutBase64']);error=base64.b64decode(result['stderrBase64'])
    report['host']={k:v for k,v in result.items() if not k.endswith('Base64')}
    report['host']['stdoutSha256']=hashlib.sha256(output).hexdigest();report['host']['stderrSha256']=hashlib.sha256(error).hexdigest()
    (ART/f'{run}.host.log').write_bytes(output+error)
    evidence.save()
    if result['exitCode']!=0 or b'PRODUCT_WINDOWS_HOST_PASS' not in output:raise RuntimeError('Native product host proof failed; preserve owned inputs')
    # Each worker uses a new SSH transport with connection multiplexing disabled.
    # The first deliberately leaves the exact authenticated runtime running.
    prepared=None
    for phase in ['continuity-start','continuity-stop']:
        arguments=f"@('{run}','{phase}'"+(f",'{prepared['runtimeId']}'" if prepared else '')+")"
        script=f"$ErrorActionPreference='Stop';$p='{directory}';$exe=Join-Path $p 'target\\debug\\examples\\windows-host-proof.exe';& (Join-Path $p 'Run-Bounded.ps1') -Executable $exe -ArgumentList {arguments} -Directory $p -TimeoutSeconds 45"
        receipt=evidence.worker('independent-ssh-'+phase,script,65)
        output=base64.b64decode(receipt['stdoutBase64']);error=base64.b64decode(receipt['stderrBase64'])
        (ART/f'{run}.{phase}.log').write_bytes(output+error)
        if receipt['exitCode']!=0:raise RuntimeError('Independent SSH continuity failed; preserve exact owned host/profile')
        public=json.loads(output)
        report[phase]=public
        if prepared is None:
            prepared=public
            probe=f"$ErrorActionPreference='Stop';$p='{directory}';$owners=@(Get-CimInstance Win32_Process|Where-Object{{$_.ExecutablePath -and $_.ExecutablePath.Equals((Join-Path $p 'target\\debug\\lomiremote.exe'),[StringComparison]::OrdinalIgnoreCase)}});if($owners.Count -ne 1 -or $owners[0].SessionId -ne 0){{throw 'Owned owner/session mismatch'}};@{{ownedOwners=1;session=0}}|ConvertTo-Json -Compress"
            report['independentOwnerSession']=json.loads(evidence.ps('independent-ssh-owned-owner-session',probe))
        elif public['runtimeId']!=prepared['runtimeId'] or public['hostId']!=prepared['hostId']:
            raise RuntimeError('Independent SSH runtime identity changed')
        evidence.save()
    for name,args in [
        ('native-msvc-clippy', "@('+1.98.1','clippy','--locked','-p','lomiremote','-p','lomi-host','-p','lomi-host-store','-p','lomi-platform','-p','lomi-windows-pty','-p','lomi-terminal','--all-targets','--','-D','warnings')"),
        ('native-rustfmt-check', "@('+1.98.1','fmt','-p','lomiremote','-p','lomi-host','-p','lomi-host-store','-p','lomi-platform','-p','lomi-windows-pty','-p','lomi-terminal','--','--check')"),
    ]:
        script=f"$ErrorActionPreference='Stop';$p='{directory}';$cargo=(Get-Command cargo.exe).Source;& (Join-Path $p 'Run-Bounded.ps1') -Executable $cargo -ArgumentList {args} -Directory $p -TimeoutSeconds 300"
        check=evidence.worker(name,script,320)
        output=base64.b64decode(check['stdoutBase64']);error=base64.b64decode(check['stderrBase64'])
        report[name]={k:v for k,v in check.items() if not k.endswith('Base64')}
        report[name]['stdoutSha256']=hashlib.sha256(output).hexdigest();report[name]['stderrSha256']=hashlib.sha256(error).hexdigest()
        (ART/f'{run}.{name}.log').write_bytes(output+error)
        evidence.save()
        if check['exitCode']!=0:raise RuntimeError(name+' failed; inspect bounded synthetic check log')
    receipt=evidence.ps('native-binary-digests',f"$ErrorActionPreference='Stop';$p='{directory}';@((Join-Path $p 'target\\debug\\lomiremote.exe'),(Join-Path $p 'target\\debug\\examples\\windows-host-proof.exe'))|ForEach-Object{{ $f=Get-Item -LiteralPath $_;@{{name=$f.Name;bytes=$f.Length;sha256=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}} }}|ConvertTo-Json -Compress")
    report['binaries']=json.loads(receipt)
    report['profileAclVerified']=b'PRODUCT_WINDOWS_PROFILE_ACL_PASS' in base64.b64decode(result['stdoutBase64'])
    cleanup=f"$ErrorActionPreference='Stop';$p='{directory}';if([IO.Path]::GetFileName($p) -cne '{remote}'){{throw 'Cleanup path mismatch'}};$active=@(Get-CimInstance Win32_Process|Where-Object{{$_.ExecutablePath -and $_.ExecutablePath.StartsWith($p+'\\',[StringComparison]::OrdinalIgnoreCase)}});if($active.Count -ne 0){{throw 'Owned worker still active'}};$profile=Join-Path $env:USERPROFILE '.lomiRemote-proof-{run}';if([IO.Path]::GetFileName($profile) -cne '.lomiRemote-proof-{run}'){{throw 'Profile cleanup mismatch'}};if((Get-Item -LiteralPath $profile -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){{throw 'Profile reparse point'}};Remove-Item -LiteralPath $profile -Recurse -Force;Remove-Item -LiteralPath $p -Recurse -Force;Remove-Item -LiteralPath (Join-Path $env:USERPROFILE '{remote_archive}') -Force;@{{removed=$true;ownedProcessesRemaining=0}}|ConvertTo-Json -Compress"
    report['cleanup']=json.loads(evidence.ps('remove-only-owned-uuid-inputs',cleanup))
    report['passed']=report['complete']=True
    evidence.save()
    print(json.dumps({'report':str(evidence.path.relative_to(ROOT)),'passed':True,'runId':run}))
if __name__=='__main__':main()
