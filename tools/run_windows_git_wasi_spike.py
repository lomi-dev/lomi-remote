#!/usr/bin/env python3
"""One-use Windows native runtime feasibility proof; synthetic fixed inputs only."""
from __future__ import annotations
import argparse
import base64
import hashlib
import io
import json
import os
import ntpath
import re
from pathlib import Path
import stat
import sys
import tarfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from owned_process import initialize_process_ownership, run_owned
ART = ROOT / 'artifacts/windows-git-wasi'
PEER = 'woro-server@192.168.1.129'
OPTIONS = ['-F', '/dev/null', '-oBatchMode=yes', '-oConnectTimeout=8', '-oLogLevel=ERROR',
           '-oStrictHostKeyChecking=yes', '-oUserKnownHostsFile=' + str(ROOT / 'artifacts/windows/known_hosts'),
           '-oGlobalKnownHostsFile=/dev/null']
TRANSPORT = ['-T', '-oRequestTTY=no', '-oControlMaster=no', '-oControlPath=none', '-oControlPersist=no']
HOST_FILES = ['tests/git-wasi/host/Cargo.toml', 'tests/git-wasi/host/Cargo.lock', 'tests/git-wasi/host/src/main.rs']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def regular(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 64 * 1024 * 1024:
        raise ValueError('inventory rejects links/special/oversized input')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        data = bytearray()
        while len(data) <= before.st_size:
            chunk = os.read(descriptor, min(65536, before.st_size + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or opened.st_ino != before.st_ino or len(data) != before.st_size:
            raise ValueError('inventory changed during read')
        return bytes(data)
    finally:
        os.close(descriptor)


def archive(path, files):
    """files maps exact POSIX archive destinations to explicitly chosen local inputs."""
    inventory = {}
    with tarfile.open(path, 'w:gz') as output:
        for name, source in sorted(files.items()):
            if Path(name).is_absolute() or '..' in Path(name).parts:
                raise ValueError('unsafe archive destination')
            data = regular(source)
            inventory[name] = {'sha256': sha(data), 'bytes': len(data)}
            entry = tarfile.TarInfo(name)
            entry.mode, entry.size = 0o600, len(data)
            output.addfile(entry, io.BytesIO(data))
    return {'files': inventory, 'sourceInventoryDigest': sha(json.dumps(inventory, sort_keys=True, separators=(',', ':')).encode()), 'archiveDigest': sha(path.read_bytes())}


class Evidence:
    def __init__(self, path, report):
        self.path, self.report = path, report
        self.known = True

    def save(self):
        temporary = self.path.with_suffix('.tmp')
        temporary.write_text(json.dumps(self.report, indent=2) + '\n')
        temporary.replace(self.path)

    def command(self, name, argv, timeout, *, owned_worker=False):
        if not self.known:
            raise RuntimeError('prior remote completion uncertain; preserve without more commands')
        row = {'name': name, 'command': argv, 'timeoutSeconds': timeout, 'passed': False, 'completionKnown': False}
        self.report['operations'].append(row)
        self.save()
        self.known = False
        started = time.monotonic()
        try:
            result = run_owned(argv, cwd=ROOT, timeout=timeout)
            transport_known = result.returncode >= 0 and result.returncode != 255
            self.known = transport_known and not (owned_worker and result.returncode != 0)
            row.update(exitCode=result.returncode, transportCompletionKnown=transport_known, completionKnown=self.known,
                       stdoutBytes=len(result.stdout.encode()), stderrBytes=len(result.stderr.encode()),
                       stdoutDigest=sha(result.stdout.encode()), stderrDigest=sha(result.stderr.encode()))
            if result.returncode != 0:
                raise RuntimeError(name + ': command failed')
            row['passed'] = True
            return result.stdout.lstrip('\ufeff').strip()
        finally:
            row['durationSeconds'] = round(time.monotonic() - started, 3)
            self.report['remoteCompletionKnown'] = self.known
            self.save()

    def ps(self, name, script, timeout=120, *, owned_worker=False):
        encoded = base64.b64encode(script.encode('utf-16-le')).decode()
        argv = ['ssh', *OPTIONS, *TRANSPORT, PEER, 'powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded]
        if len(' '.join(argv[argv.index(PEER) + 1:])) > 7600:
            raise ValueError('Windows command budget')
        return self.command(name, argv, timeout, owned_worker=owned_worker)

    def worker(self, name, script, timeout):
        # A completed SSH/PowerShell transport is not proof that its owned
        # native worker and output drains completed. Require a typed envelope.
        index = len(self.report['operations'])
        try:
            result = json.loads(self.ps(name, script, timeout, owned_worker=True))
            if (result.get('completionKnown') is not True or result.get('timedOut') is not False
                    or result.get('outputOverflow') is not False or type(result.get('exitCode')) is not int):
                raise ValueError('owned worker completion not verified')
            for key in ('stdoutBase64', 'stderrBase64'):
                data = base64.b64decode(result[key], validate=True)
                if len(data) > 131072:
                    raise ValueError('owned worker capture bound')
            operation = self.report['operations'][-1]
            operation.update(ownedWorkerCompletionKnown=True,
                             workerExitCode=result['exitCode'],
                             workerPassed=result['exitCode'] == 0)
            self.save()
            return result
        except BaseException:
            self.known = False
            self.report['remoteCompletionKnown'] = False
            if len(self.report['operations']) > index:
                self.report['operations'][-1].update(ownedWorkerCompletionKnown=False, completionKnown=False, passed=False)
            self.save()
            raise

    def transfer(self, name, source, destination):
        return self.command(name, ['scp', *OPTIONS, str(source), PEER + ':' + destination], 180)


def extract_script(remote_name, archive_name, digest, subdir=''):
    # Names are generated UUID literals, never supplied paths or shell snippets.
    return f"""$ErrorActionPreference='Stop';$p=Join-Path $env:USERPROFILE '{remote_name}';$a=Join-Path $env:USERPROFILE '{archive_name}';
if((Get-FileHash -LiteralPath $a -Algorithm SHA256).Hash.ToLowerInvariant() -cne '{digest}'){{throw 'Archive digest mismatch'}};
$d=Join-Path $p '{subdir or '.'}';if(Test-Path -LiteralPath $d){{throw 'Fresh extraction destination exists'}};
$null=New-Item -ItemType Directory -Path $d;& tar.exe -xzf $a -C $d;if($LASTEXITCODE -ne 0){{throw 'Extraction failed'}};
@{{directory=[IO.Path]::GetFullPath($d);archiveDigestVerified=$true}}|ConvertTo-Json -Compress"""


def prepare(evidence):
    report = evidence.report
    identity = report['runId']
    remote = 'lomi-git-wasi-' + identity
    path = ART / ('host-' + identity + '.tar.gz')
    files = {name.removeprefix('tests/git-wasi/host/'): ROOT / name for name in HOST_FILES}
    files['Run-Bounded.ps1'] = ROOT / 'tests/git-wasi-windows/Run-Bounded.ps1'
    report['source'] = archive(path, files)
    report['hostLockDigest'] = sha(regular(ROOT / HOST_FILES[1]))
    evidence.save()
    remote_archive = 'lomi-git-wasi-host-' + identity + '.tar.gz'
    evidence.transfer('copy-explicit-host-source', path, remote_archive)
    location = json.loads(evidence.ps('extract-source-hash-verified', extract_script(remote, remote_archive, report['source']['archiveDigest'])))
    report['remoteDirectory'] = location['directory']
    p = location['directory']
    versions = f"""$ErrorActionPreference='Stop';$p='{p}';$t=$null;$e=$null;$null=[Management.Automation.Language.Parser]::ParseFile((Join-Path $p 'Run-Bounded.ps1'),[ref]$t,[ref]$e);if(@($e).Count -ne 0){{throw 'Parser errors'}};
@{{rust=(& rustc.exe +1.98.1 --version);cargo=(& cargo.exe +1.98.1 --version);host=(& rustc.exe +1.98.1 -vV|Select-String '^host:'|ForEach-Object{{$_.ToString()}});os=[Environment]::OSVersion.VersionString;parserPassed=$true}}|ConvertTo-Json -Compress"""
    report['versions'] = json.loads(evidence.ps('native-versions-and-parser', versions))
    build = f"""$ErrorActionPreference='Stop';$p='{p}';$cargo=(Get-Command cargo.exe).Source;
& (Join-Path $p 'Run-Bounded.ps1') -Executable $cargo -ArgumentList @('+1.98.1','build','--locked','-j','2') -Directory $p -TimeoutSeconds 1500"""
    result = evidence.worker('native-msvc-locked-build', build, 1520)
    stdout, stderr = (base64.b64decode(result[key]) for key in ('stdoutBase64', 'stderrBase64'))
    (ART / ('build-' + identity + '.log')).write_bytes(stdout + stderr)
    report['build'] = {key: value for key, value in result.items() if not key.endswith('Base64')}
    report['build']['logDigest'] = sha(stdout + stderr)
    if result['exitCode'] != 0 or result['timedOut'] or result['outputOverflow'] or result['completionKnown'] is not True:
        raise RuntimeError('native host build failed')
    binary = f"""$ErrorActionPreference='Stop';$p=Join-Path '{p}' 'target\\debug\\lomi-git-wasi-host.exe';@{{sha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant();bytes=(Get-Item -LiteralPath $p).Length}}|ConvertTo-Json -Compress"""
    report['nativeBinary'] = json.loads(evidence.ps('native-host-binary-digest', binary))
    report['complete'] = report['passed'] = True


def collect_tree(source, destination, files):
    for entry in sorted(source.iterdir()):
        info = entry.lstat()
        relative = destination + '/' + entry.name
        if stat.S_ISDIR(info.st_mode):
            collect_tree(entry, relative, files)
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            files[relative] = entry
        else:
            raise ValueError('frozen tree contains a link or special file')


def verify_inventory_script(directory):
    return f"""$ErrorActionPreference='Stop';$p='{directory}';$manifest=Get-Content -Raw -LiteralPath (Join-Path $p 'inventory.json')|ConvertFrom-Json;$all=@(Get-ChildItem -LiteralPath $p -Force -Recurse);if(@($all|Where-Object{{($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0}}).Count -ne 0){{throw 'Reparse input'}};$actual=@($all|Where-Object{{-not $_.PSIsContainer}});$checked=0;
foreach($file in $actual){{if(($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){{throw 'Reparse input'}};if($file.FullName -ceq (Join-Path $p 'inventory.json')){{continue}};$name=$file.FullName.Substring($p.Length+1).Replace('\\','/');$entry=$manifest.PSObject.Properties[$name];if($null -eq $entry){{throw 'Unexpected input'}};if($file.Length -ne $entry.Value.bytes -or (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.Value.sha256){{throw 'Input changed'}};$checked++}};
if($checked -ne @($manifest.PSObject.Properties).Count){{throw 'Missing input'}};
@{{passed=$true;checkedFiles=$checked}}|ConvertTo-Json -Compress"""


def run_fixture(evidence, prepared_path):
    report = evidence.report
    prepared_bytes = regular(prepared_path)
    prepared = json.loads(prepared_bytes)
    if prepared.get('kind') != 'windows-native-wasi-host-build' or prepared.get('passed') is not True:
        raise ValueError('successful native preparation required')
    identity = prepared['runId']
    if str(uuid.UUID(identity)) != identity:
        raise ValueError('invalid preparation UUID')
    remote = 'lomi-git-wasi-' + identity
    p = ntpath.normpath(prepared['remoteDirectory'])
    if p != 'C:\\Users\\woro-server\\' + remote:
        raise ValueError('unexpected fixed remote preparation path')
    report.update(preparedEvidence=prepared_path.name, preparedEvidenceDigest=sha(prepared_bytes),
                  source=prepared['source'], hostLockDigest=prepared['hostLockDigest'],
                  versions=prepared['versions'], nativeBinary=prepared['nativeBinary'], remoteDirectory=p,
                  not_run=['Windows snapshot broker race/reparse/ACL guarantees', 'actual symlink escape and symlink policy fixtures',
                           'full symlink-dependent policy probe', 'other architectures', 'production repository integration'])
    # Accept only the final frozen synthetic Mac proof, never a caller repository.
    mac = ROOT / 'artifacts/git-wasi'
    reference = json.loads(regular(mac / 'report.json'))
    if reference['exact_structured_comparison'] is not True or reference['snapshot_unchanged'] is not True or not all(v['passed'] for v in reference['security_probes'].values()):
        raise ValueError('frozen trusted Mac proof incomplete')
    expected_bytes = regular(mac / 'expected-structured.json')
    expected = json.loads(expected_bytes)
    if expected != reference['actual']:
        raise ValueError('native Git expected fixture mismatch')
    report['reference'] = {'nativeGitVersion': reference['git'], 'reportDigest': sha(regular(mac / 'report.json')),
                           'expectedDigest': sha(expected_bytes), 'guestDigest': reference['guest_sha256'],
                           'snapshotDigest': reference['snapshot_sha256'], 'operationsCompared': ['status','diff','staged_diff','log','show']}
    files = {'expected-structured.json': mac / 'expected-structured.json', 'Run-Bounded.ps1': ROOT / 'tests/git-wasi-windows/Run-Bounded.ps1'}
    binaries = mac / 'guest-target/wasm32-wasip1/release'
    for name in ['lomi-git-wasi-guest', 'sandbox_probe', 'mmap_probe']:
        files['modules/' + name + '.wasm'] = binaries / (name + '.wasm')
    if sha(regular(files['modules/lomi-git-wasi-guest.wasm'])) != reference['guest_sha256']:
        raise ValueError('frozen guest digest mismatch')
    for name in ['socket-import', 'memory-initial', 'table-initial']:
        files['modules/' + name + '.wasm'] = mac / 'synthetic' / (name + '.wasm')
    for name in ['snapshot', 'mmap-snapshot', 'fuel-snapshot', 'memory-snapshot', 'output-snapshot', 'stack-snapshot']:
        collect_tree(mac / 'synthetic' / name, name, files)
    snapshot_hash = hashlib.sha256()
    for name in sorted(key for key in files if key.startswith('snapshot/')):
        relative = name.removeprefix('snapshot/').encode()
        data = regular(files[name])
        snapshot_hash.update(len(relative).to_bytes(8, 'big') + relative + len(data).to_bytes(8, 'big') + data)
    if snapshot_hash.hexdigest() != reference['snapshot_sha256']:
        raise ValueError('frozen snapshot differs from trusted native reference')
    # No Windows symlink privilege is requested. Missing escape entries are not
    # represented as a tested symlink boundary; actual outside reads still deny.
    for name in ['mode','inside']:
        files['denial-snapshot/' + name] = mac / 'synthetic/denial-snapshot' / name
    files['outside-canary'] = ROOT / 'tests/git-wasi-windows/fixtures/outside-canary.txt'
    collect_tree(mac / 'synthetic/policy-snapshot/commondir', 'commondir-snapshot', files)
    bundle = ART / ('inputs-' + report['runId'] + '.tar.gz')
    report['inputs'] = archive(bundle, files)
    # Add a self-contained verification manifest; its digest is protected by the
    # archive digest. Each source is reopened and revalidated during packing.
    manifest = ART / ('inventory-' + report['runId'] + '.json')
    manifest.write_text(json.dumps(report['inputs']['files'], sort_keys=True) + '\n')
    files['inventory.json'] = manifest
    report['inputs'] = archive(bundle, files)
    evidence.save()
    remote_archive = 'lomi-git-wasi-inputs-' + report['runId'] + '.tar.gz'
    evidence.transfer('copy-frozen-explicit-synthetic-inputs', bundle, remote_archive)
    subdir = 'inputs-' + report['runId']
    location = json.loads(evidence.ps('extract-frozen-inputs-hash-verified', extract_script(remote, remote_archive, report['inputs']['archiveDigest'], subdir)))
    d = location['directory']
    report['inputVerificationBefore'] = json.loads(evidence.ps('verify-frozen-input-inventory-before', verify_inventory_script(d)))
    host_digest = json.loads(evidence.ps('verify-native-host-unchanged', f"$ErrorActionPreference='Stop';@{{sha256=(Get-FileHash -LiteralPath '{p}\\target\\debug\\lomi-git-wasi-host.exe' -Algorithm SHA256).Hash.ToLowerInvariant()}}|ConvertTo-Json -Compress"))
    if host_digest['sha256'] != prepared['nativeBinary']['sha256']:
        raise ValueError('native binary changed')
    results = {}

    def invoke(name, module, snapshot, exact=None, errors=(), structured=False):
        script = f"""$ErrorActionPreference='Stop';$p='{p}';$d='{d}';
& (Join-Path $d 'Run-Bounded.ps1') -Executable (Join-Path $p 'target\\debug\\lomi-git-wasi-host.exe') -ArgumentList @((Join-Path $d 'modules\\{module}.wasm'),(Join-Path $d '{snapshot}')) -Directory $d -TimeoutSeconds 90 -Canary"""
        raw = evidence.worker('worker-' + name, script, 105)
        out, err = (base64.b64decode(raw[key]) for key in ('stdoutBase64','stderrBase64'))
        bounded = raw['completionKnown'] is True and raw['timedOut'] is False and raw['outputOverflow'] is False
        passed = bounded and (raw['exitCode'] == 0 if exact is not None or structured else raw['exitCode'] != 0)
        if exact is not None:
            passed = passed and out == exact
        if structured:
            try:
                passed = passed and json.loads(out) == expected
            except (ValueError, UnicodeDecodeError):
                passed = False
        if errors:
            diagnostic = b'\n'.join(line for line in err.lower().splitlines() if not line.startswith(b'allowed_imports='))
            passed = passed and any(item in diagnostic for item in errors)
        if name == 'output':
            passed = passed and out == b'x' * 65536
        match = re.search(rb'module_compile_ms=(\d+)', err)
        results[name] = {'passed': passed, 'exitCode': raw['exitCode'], 'stdoutBytes': len(out), 'stderrBytes': len(err),
                         'stdoutDigest': sha(out), 'stderrDigest': sha(err), 'durationMilliseconds': raw['durationMilliseconds'],
                         'moduleCompileMilliseconds': int(match.group(1)) if match else None,
                         'timedOut': raw['timedOut'], 'outputOverflow': raw['outputOverflow']}
        report['cases'] = results
        evidence.save()
        if not bounded:
            evidence.known = False
            report['remoteCompletionKnown'] = False
            evidence.save()
            raise RuntimeError('worker completion/bounds failure; preserve inputs')

    invoke('native-git-structured-comparison','lomi-git-wasi-guest','snapshot',structured=True)
    invoke('mmap-readonly','mmap_probe','mmap-snapshot',exact=b'mmap_readonly_probe_passed\n')
    invoke('readonly-env-process-network-denial','sandbox_probe','denial-snapshot',exact=b'sandbox_denial_probe_passed\n')
    for mode, errors in [('fuel',(b'fuel',b'interrupt')),('memory',(b'memory',b'unreachable')),('output',(b'i/o error',b'capacity',b'closed')),('stack',(b'stack',))]:
        invoke(mode,'sandbox_probe',mode+'-snapshot',errors=errors)
    invoke('socket-import','socket-import','denial-snapshot',errors=(b'disallowed import wasi_snapshot_preview1::sock_accept',))
    invoke('memory-initial','memory-initial','denial-snapshot',errors=(b'memory',))
    invoke('table-initial','table-initial','denial-snapshot',errors=(b'table',))
    invoke('policy-commondir','lomi-git-wasi-guest','commondir-snapshot',errors=(b'unsupported git metadata',))
    report['inputVerificationAfter'] = json.loads(evidence.ps('verify-frozen-input-inventory-after',verify_inventory_script(d)))
    report['snapshotUnchanged'] = report['inputVerificationBefore']['passed'] is True and report['inputVerificationAfter']['passed'] is True
    report['complete'] = True
    report['passed'] = report['snapshotUnchanged'] and all(value['passed'] for value in results.values())


def main():
    initialize_process_ownership()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared', type=Path)
    args = parser.parse_args()
    ART.mkdir(mode=0o700, parents=True, exist_ok=True)
    identity = str(uuid.uuid4())
    prefix = 'native-' if args.prepared else 'prepare-'
    path = ART / (prefix + identity + '.json')
    report = {'kind': 'windows-native-wasi-runtime-proof' if args.prepared else 'windows-native-wasi-host-build', 'runId': identity, 'qualified': False, 'complete': False, 'passed': False, 'operations': [], 'runnerDigest': sha(Path(__file__).read_bytes())}
    with path.open('x'):
        pass
    evidence = Evidence(path, report)
    evidence.save()
    code = 1
    try:
        if args.prepared:
            run_fixture(evidence, args.prepared.resolve())
        else:
            prepare(evidence)
        code = 0 if report['passed'] else 1
    except KeyboardInterrupt:
        report['errorClass'], code = 'KeyboardInterrupt', 130
    except Exception as error:
        report['errorClass'] = type(error).__name__
    finally:
        report['exitCode'] = code
        evidence.save()
    print(json.dumps({'passed': report['passed'], 'qualified': False, 'evidence': str(path.relative_to(ROOT))}))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
