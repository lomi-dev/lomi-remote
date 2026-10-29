#!/usr/bin/env python3
"""Bounded pinned-host Windows IPC and synthetic DPAPI proof; no SCM changes."""
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

ART=ROOT/'artifacts/platform-windows'

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    initialize_process_ownership()
    ART.mkdir(parents=True,exist_ok=True)
    run=str(uuid.uuid4())
    report={'format':1,'runId':run,'kind':'native-windows-platform-ipc-and-dpapi','passed':False,'complete':False,'remoteCompletionKnown':True,'operations':[],'scope':'Local IPC and explicit user-scope DPAPI with synthetic bundles in owned UUID fixtures; no SCM, autostart, PTY or real credentials.'}
    evidence=Evidence(ART/f'{run}.json',report)
    evidence.save()
    with tempfile.TemporaryDirectory(prefix='lomi-windows-input-') as staging:
        staging=Path(staging)
        manifest=staging/'Cargo.toml'
        manifest.write_text('[workspace]\nmembers = ["crates/lomi-platform", "crates/lomi-remote-protocol"]\nresolver = "3"\n[workspace.package]\nedition = "2024"\nrust-version = "1.98.1"\nversion = "0.1.0"\npublish = false\n')
        files={'Cargo.toml':manifest,'Cargo.lock':ROOT/'Cargo.lock','rust-toolchain.toml':ROOT/'rust-toolchain.toml','Run-Bounded.ps1':ROOT/'tests/git-wasi-windows/Run-Bounded.ps1'}
        for crate in ['lomi-platform','lomi-remote-protocol']:
            directory=ROOT/'crates'/crate
            files[f'crates/{crate}/Cargo.toml']=directory/'Cargo.toml'
            if (directory/'README.md').exists():files[f'crates/{crate}/README.md']=directory/'README.md'
            for source in sorted((directory/'src').rglob('*.rs')):files[source.relative_to(ROOT).as_posix()]=source
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
        report['workspaceRecipe']='Explicit two-crate harness workspace; offline-derived subset lock verified against original root dependency versions/sources/checksums; all crate sources/manifests unchanged.'
        report['originalWorkspaceManifestSha256']=digest(ROOT/'Cargo.toml')
        report['harnessSha256']=digest(Path(__file__).resolve())
        report['knownHostsSha256']=digest(ROOT/'artifacts/windows/known_hosts')
        evidence.save()
    remote='lomi-platform-'+run
    remote_archive=remote+'.tar.gz'
    evidence.transfer('copy-frozen-inputs',source,remote_archive)
    location=json.loads(evidence.ps('hash-verify-and-extract',extract_script(remote,remote_archive,report['inputs']['archiveDigest'])))
    directory=location['directory']
    report['remoteDirectory']=directory
    versions=evidence.ps('native-os-and-toolchain',"$ErrorActionPreference='Stop';$o=Get-CimInstance Win32_OperatingSystem;@{caption=$o.Caption;version=$o.Version;build=$o.BuildNumber;rust=(& rustc.exe +1.98.1 --version);cargo=(& cargo.exe +1.98.1 --version)}|ConvertTo-Json -Compress")
    report['versions']=json.loads(versions)
    report['wrongOsAccountDpapiProof']='Not performed: same-account new-process tests do not prove wrong-OS-account isolation; no alternate OS account provisioned or impersonated.'
    report['cargoIncremental']='0'
    report['osScope']='Exact recorded Windows 10 LTSC machine/build only; Windows 11/Server not qualified.'
    if 'Windows 10' not in report['versions']['caption']:raise RuntimeError('Unexpected Windows OS; preserve proof inputs')
    script=f"$ErrorActionPreference='Stop';$env:CARGO_INCREMENTAL='0';$p='{directory}';$cargo=(Get-Command cargo.exe).Source;& (Join-Path $p 'Run-Bounded.ps1') -Executable $cargo -ArgumentList @('+1.98.1','test','--locked','-p','lomi-platform','--lib','--','--test-threads=1') -Directory $p -TimeoutSeconds 300"
    result=evidence.worker('native-locked-unit-tests',script,320)
    output=base64.b64decode(result['stdoutBase64']);error=base64.b64decode(result['stderrBase64'])
    report['test']={k:v for k,v in result.items() if not k.endswith('Base64')}
    report['test']['stdoutSha256']=hashlib.sha256(output).hexdigest();report['test']['stderrSha256']=hashlib.sha256(error).hexdigest()
    # Logs contain synthetic test diagnostics only, never environment dumps.
    (ART/f'{run}.test.log').write_bytes(output+error)
    evidence.save()
    if result['exitCode']!=0:raise RuntimeError('Native Windows tests failed; inspect bounded synthetic test log')
    for name,args in [
        ('native-msvc-clippy', "@('+1.98.1','clippy','--locked','-p','lomi-platform','--lib','--tests','--','-D','warnings')"),
        ('native-rustfmt-check', "@('+1.98.1','fmt','-p','lomi-platform','--','--check')"),
    ]:
        script=f"$ErrorActionPreference='Stop';$env:CARGO_INCREMENTAL='0';$p='{directory}';$cargo=(Get-Command cargo.exe).Source;& (Join-Path $p 'Run-Bounded.ps1') -Executable $cargo -ArgumentList {args} -Directory $p -TimeoutSeconds 300"
        check=evidence.worker(name,script,320)
        output=base64.b64decode(check['stdoutBase64']);error=base64.b64decode(check['stderrBase64'])
        report[name]={k:v for k,v in check.items() if not k.endswith('Base64')}
        report[name]['stdoutSha256']=hashlib.sha256(output).hexdigest();report[name]['stderrSha256']=hashlib.sha256(error).hexdigest()
        (ART/f'{run}.{name}.log').write_bytes(output+error)
        evidence.save()
        if check['exitCode']!=0:raise RuntimeError(name+' failed; inspect bounded synthetic check log')
    receipt=evidence.ps('native-binary-digests',f"$ErrorActionPreference='Stop';$p='{directory}';@(Get-ChildItem -LiteralPath (Join-Path $p 'target\\debug\\deps') -Filter 'lomi_platform-*.exe'|ForEach-Object{{@{{name=$_.Name;bytes=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}}}})|ConvertTo-Json -Compress")
    report['binaries']=json.loads(receipt)
    cleanup=f"$ErrorActionPreference='Stop';$p='{directory}';if([IO.Path]::GetFileName($p) -cne '{remote}'){{throw 'Cleanup path mismatch'}};$active=@(Get-CimInstance Win32_Process|Where-Object{{$_.ExecutablePath -and $_.ExecutablePath.StartsWith($p+'\\',[StringComparison]::OrdinalIgnoreCase)}});if($active.Count -ne 0){{throw 'Owned worker still active'}};Remove-Item -LiteralPath $p -Recurse -Force;Remove-Item -LiteralPath (Join-Path $env:USERPROFILE '{remote_archive}') -Force;@{{removed=$true;ownedProcessesRemaining=0}}|ConvertTo-Json -Compress"
    report['cleanup']=json.loads(evidence.ps('remove-only-owned-uuid-inputs',cleanup))
    report['passed']=report['complete']=True
    evidence.save()
    print(json.dumps({'report':str(evidence.path.relative_to(ROOT)),'passed':True,'runId':run}))
if __name__=='__main__':main()
