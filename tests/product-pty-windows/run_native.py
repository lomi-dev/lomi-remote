#!/usr/bin/env python3
"""Bounded, pinned-host native Windows IPC proof; no SCM or user-data changes."""
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

ART=ROOT/'artifacts/product-pty-windows'

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    initialize_process_ownership()
    ART.mkdir(parents=True,exist_ok=True)
    run=str(uuid.uuid4())
    report={'format':1,'runId':run,'kind':'native-windows-product-pty','passed':False,'complete':False,'remoteCompletionKnown':True,'operations':[],'scope':'Product ConPTY backend with synthetic children; no SCM or credential changes.'}
    evidence=Evidence(ART/f'{run}.json',report)
    evidence.save()
    with tempfile.TemporaryDirectory(prefix='lomi-windows-input-') as staging:
        staging=Path(staging)
        manifest=staging/'Cargo.toml'
        manifest.write_text('[workspace]\nmembers = ["crates/lomi-windows-pty", "crates/lomi-terminal", "crates/lomi-terminal-state", "crates/lomi-remote-protocol"]\nexclude = ["vendor/alacritty_terminal", "vendor/vte"]\nresolver = "3"\n[workspace.package]\nedition = "2024"\nrust-version = "1.98.1"\nversion = "0.1.0"\npublish = false\n[patch.crates-io]\nalacritty_terminal = { path = "vendor/alacritty_terminal" }\nvte = { path = "vendor/vte" }\n')
        files={'Cargo.toml':manifest,'Cargo.lock':ROOT/'Cargo.lock','rust-toolchain.toml':ROOT/'rust-toolchain.toml','Run-Bounded.ps1':ROOT/'tests/git-wasi-windows/Run-Bounded.ps1'}
        for crate in ['lomi-windows-pty', 'lomi-terminal', 'lomi-terminal-state', 'lomi-remote-protocol']:
            directory=ROOT/'crates'/crate
            files[f'crates/{crate}/Cargo.toml']=directory/'Cargo.toml'
            if (directory/'README.md').exists():files[f'crates/{crate}/README.md']=directory/'README.md'
            for source in sorted(directory.rglob('*')):
                if source.is_file() and source.suffix in ['.rs','.c','.h']:files[source.relative_to(ROOT).as_posix()]=source
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
        report['workspaceRecipe']='Explicit four-crate harness workspace with exact vendored parser sources; offline-derived subset lock verified against original root dependency versions/sources/checksums; all crate sources/manifests unchanged.'
        report['originalWorkspaceManifestSha256']=digest(ROOT/'Cargo.toml')
        report['harnessSha256']=digest(Path(__file__).resolve())
        report['knownHostsSha256']=digest(ROOT/'artifacts/windows/known_hosts')
        evidence.save()
    remote='lomi-windows-pty-'+run
    remote_archive=remote+'.tar.gz'
    evidence.transfer('copy-frozen-inputs',source,remote_archive)
    location=json.loads(evidence.ps('hash-verify-and-extract',extract_script(remote,remote_archive,report['inputs']['archiveDigest'])))
    directory=location['directory']
    report['remoteDirectory']=directory
    versions=evidence.ps('native-os-and-toolchain',"$ErrorActionPreference='Stop';$o=Get-CimInstance Win32_OperatingSystem;@{caption=$o.Caption;version=$o.Version;build=$o.BuildNumber;rust=(& rustc.exe +1.98.1 --version);cargo=(& cargo.exe +1.98.1 --version)}|ConvertTo-Json -Compress")
    report['versions']=json.loads(versions)
    report['osScope']='Exact recorded Windows 10 LTSC machine/build only; Windows 11/Server not qualified.'
    if 'Windows 10' not in report['versions']['caption']:raise RuntimeError('Unexpected Windows OS; preserve proof inputs')
    script=f"$ErrorActionPreference='Stop';$p='{directory}';$cargo=(Get-Command cargo.exe).Source;& (Join-Path $p 'Run-Bounded.ps1') -Executable $cargo -ArgumentList @('+1.98.1','run','--locked','-p','lomi-windows-pty','--bin','pty-proof','--features','proof-hooks') -Directory $p -TimeoutSeconds 300"
    result=evidence.worker('native-locked-unit-tests',script,320)
    output=base64.b64decode(result['stdoutBase64']);error=base64.b64decode(result['stderrBase64'])
    report['test']={k:v for k,v in result.items() if not k.endswith('Base64')}
    report['test']['stdoutSha256']=hashlib.sha256(output).hexdigest();report['test']['stderrSha256']=hashlib.sha256(error).hexdigest()
    # Logs contain synthetic test diagnostics only, never environment dumps.
    (ART/f'{run}.test.log').write_bytes(output+error)
    evidence.save()
    if result['exitCode']!=0 or b'PRODUCT_PTY_SMOKE_PASS' not in output:raise RuntimeError('Native Windows tests failed; inspect bounded synthetic test log')
    script=f"$ErrorActionPreference='Stop';$p='{directory}';$cargo=(Get-Command cargo.exe).Source;& (Join-Path $p 'Run-Bounded.ps1') -Executable $cargo -ArgumentList @('+1.98.1','run','--locked','-p','lomi-terminal','--example','windows-product-proof','--features','windows-pty-proof-hooks') -Directory $p -TimeoutSeconds 300"
    result=evidence.worker('native-terminal-service',script,320)
    output=base64.b64decode(result['stdoutBase64']);error=base64.b64decode(result['stderrBase64'])
    report['terminalService']={k:v for k,v in result.items() if not k.endswith('Base64')}
    (ART/f'{run}.service.log').write_bytes(output+error)
    report['terminalService']['stdoutSha256']=hashlib.sha256(output).hexdigest();report['terminalService']['stderrSha256']=hashlib.sha256(error).hexdigest()
    evidence.save()
    if result['exitCode']!=0 or b'PRODUCT_TERMINAL_SERVICE_PASS' not in output:raise RuntimeError('Native terminal service proof failed; preserve owned inputs')
    for name,args in [
        ('native-msvc-clippy', "@('+1.98.1','clippy','--locked','-p','lomi-windows-pty','--all-targets','--all-features','-p','lomi-terminal','--','-D','warnings')"),
        ('native-rustfmt-check', "@('+1.98.1','fmt','-p','lomi-windows-pty','-p','lomi-terminal','--','--check')"),
    ]:
        script=f"$ErrorActionPreference='Stop';$p='{directory}';$cargo=(Get-Command cargo.exe).Source;& (Join-Path $p 'Run-Bounded.ps1') -Executable $cargo -ArgumentList {args} -Directory $p -TimeoutSeconds 300"
        check=evidence.worker(name,script,320)
        output=base64.b64decode(check['stdoutBase64']);error=base64.b64decode(check['stderrBase64'])
        report[name]={k:v for k,v in check.items() if not k.endswith('Base64')}
        report[name]['stdoutSha256']=hashlib.sha256(output).hexdigest();report[name]['stderrSha256']=hashlib.sha256(error).hexdigest()
        (ART/f'{run}.{name}.log').write_bytes(output+error)
        evidence.save()
        if check['exitCode']!=0:raise RuntimeError(name+' failed; inspect bounded synthetic check log')
    receipt=evidence.ps('native-binary-digests',f"$ErrorActionPreference='Stop';$p='{directory}';@((Join-Path $p 'target\\debug\\pty-proof.exe'),(Join-Path $p 'target\\debug\\examples\\windows-product-proof.exe'))|ForEach-Object{{ $f=Get-Item -LiteralPath $_;@{{name=$f.Name;bytes=$f.Length;sha256=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}} }}|ConvertTo-Json -Compress")
    report['binaries']=json.loads(receipt)
    cleanup=f"$ErrorActionPreference='Stop';$p='{directory}';if([IO.Path]::GetFileName($p) -cne '{remote}'){{throw 'Cleanup path mismatch'}};$active=@(Get-CimInstance Win32_Process|Where-Object{{$_.ExecutablePath -and $_.ExecutablePath.StartsWith($p+'\\',[StringComparison]::OrdinalIgnoreCase)}});if($active.Count -ne 0){{throw 'Owned worker still active'}};Remove-Item -LiteralPath $p -Recurse -Force;Remove-Item -LiteralPath (Join-Path $env:USERPROFILE '{remote_archive}') -Force;@{{removed=$true;ownedProcessesRemaining=0}}|ConvertTo-Json -Compress"
    report['cleanup']=json.loads(evidence.ps('remove-only-owned-uuid-inputs',cleanup))
    report['passed']=report['complete']=True
    evidence.save()
    print(json.dumps({'report':str(evidence.path.relative_to(ROOT)),'passed':True,'runId':run}))
if __name__=='__main__':main()
