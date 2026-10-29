#!/usr/bin/env python3
"""One-use native Linux WASI feasibility proof in the dedicated disposable VM."""
from __future__ import annotations
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from owned_process import initialize_process_ownership, run_owned
ART = ROOT / 'artifacts/git-wasi-linux'
LIMA = '/opt/homebrew/bin/limactl'
ENV = dict(os.environ, LIMA_HOME=str(ROOT / 'artifacts/lima'))
SHELL = [LIMA, 'shell', '--workdir=/', 'lomi-e0', '--']
GIB = 1024 ** 3


def sha(data):
    return hashlib.sha256(data).hexdigest()


def regular(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 64 * 1024 * 1024:
        raise ValueError('inventory refuses links/special/oversized inputs')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        data = bytearray()
        while len(data) <= before.st_size:
            chunk = os.read(fd, min(65536, before.st_size + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or len(data) != before.st_size:
            raise ValueError('inventory source changed')
        return bytes(data)
    finally:
        os.close(fd)


def collect(source, prefix, files):
    for entry in sorted(source.iterdir()):
        info = entry.lstat()
        name = prefix + '/' + entry.name
        if stat.S_ISDIR(info.st_mode):
            collect(entry, name, files)
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            files[name] = entry
        else:
            raise ValueError('synthetic input link/special file refused')


def pack(path, files):
    inventory = {}
    with tarfile.open(path, 'w:gz') as output:
        for name, source in sorted(files.items()):
            if Path(name).is_absolute() or '..' in Path(name).parts:
                raise ValueError('unsafe archive destination')
            data = regular(source)
            inventory[name] = {'bytes': len(data), 'sha256': sha(data)}
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(data), 0o600
            output.addfile(entry, io.BytesIO(data))
    return {'files': inventory, 'sourceInventoryDigest': sha(json.dumps(inventory, sort_keys=True, separators=(',', ':')).encode()), 'archiveDigest': sha(path.read_bytes())}


class Evidence:
    def __init__(self, path, report):
        self.path, self.report, self.known = path, report, True

    def save(self):
        temporary = self.path.with_suffix('.tmp')
        temporary.write_text(json.dumps(self.report, indent=2) + '\n')
        temporary.replace(self.path)

    def command(self, name, argv, timeout):
        if not self.known:
            raise RuntimeError('prior completion uncertain: preserve without further operations')
        row = {'name': name, 'command': argv, 'timeoutSeconds': timeout, 'passed': False, 'transportCompletionKnown': False}
        self.report['operations'].append(row)
        self.known = False
        self.report['remoteCompletionKnown'] = False
        self.save()
        started = time.monotonic()
        try:
            result = run_owned(argv, cwd=ROOT, env=ENV, timeout=timeout)
            # Nonzero Lima may be a transport error. Without a worker envelope
            # it never establishes remote completion, even if Lima itself exits.
            self.known = result.returncode == 0
            row.update(exitCode=result.returncode, transportCompletionKnown=self.known,
                       stdoutBytes=len(result.stdout.encode()), stderrBytes=len(result.stderr.encode()),
                       stdoutDigest=sha(result.stdout.encode()), stderrDigest=sha(result.stderr.encode()))
            if result.returncode != 0:
                raise RuntimeError('transport command failed')
            row['passed'] = True
            return result.stdout.strip()
        finally:
            row['durationSeconds'] = round(time.monotonic() - started, 3)
            self.report['remoteCompletionKnown'] = self.known
            self.save()

    def python(self, name, code, timeout=30):
        return json.loads(self.command(name, [*SHELL, '/usr/bin/python3', '-c', code], timeout))

    def worker(self, name, source, request):
        remote_request = source + '/request-' + str(uuid.uuid4()) + '.json'
        encoded = base64.b64encode(json.dumps(request).encode()).decode()
        create = f"import pathlib,base64,json;p=pathlib.Path({remote_request!r});p.open('xb').write(base64.b64decode({encoded!r}));print(json.dumps({{'written':True}}))"
        self.python('write-' + name + '-fixed-request', create)
        index = len(self.report['operations'])
        try:
            result = json.loads(self.command(name, [*SHELL, '/usr/bin/python3', source + '/worker.py', remote_request], request['timeoutSeconds'] + 20))
            if result.get('completionKnown') is not True or type(result.get('exitCode')) is not int:
                raise ValueError('owned worker completion not proved')
            for key in ['stdoutBase64', 'stderrBase64']:
                if len(base64.b64decode(result[key], validate=True)) > 131072:
                    raise ValueError('owned worker capture bound')
            self.report['operations'][-1]['workerCompletionKnown'] = True
            self.save()
            return result
        except BaseException:
            self.known = False
            self.report['remoteCompletionKnown'] = False
            if len(self.report['operations']) > index:
                self.report['operations'][-1].update(workerCompletionKnown=False, passed=False)
            self.save()
            raise


def extract_code(archive, destination, digest):
    return f"""import pathlib,hashlib,tarfile,json,os
archive=pathlib.Path({archive!r}); destination=pathlib.Path({destination!r})
if hashlib.sha256(archive.read_bytes()).hexdigest()!={digest!r}: raise ValueError('archive digest mismatch')
destination.mkdir(mode=0o700)
with tarfile.open(archive) as source:
 for entry in source.getmembers():
  p=pathlib.PurePosixPath(entry.name)
  if not entry.isfile() or p.is_absolute() or '..' in p.parts: raise ValueError('unsafe archive member')
  target=destination.joinpath(*p.parts);target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
  with target.open('xb') as output: output.write(source.extractfile(entry).read())
print(json.dumps({{'directory':str(destination),'archiveDigestVerified':True}}))"""


def inventory_code(directory, expected, links=None):
    encoded = base64.b64encode(json.dumps(expected, sort_keys=True).encode()).decode()
    links = links or {}
    return f"""import pathlib,json,base64,stat,hashlib,os
root=pathlib.Path({directory!r});expected=json.loads(base64.b64decode({encoded!r}));links={links!r};actual={{}};observed_links=set()
for p in sorted(root.rglob('*')):
 info=p.lstat();name=p.relative_to(root).as_posix()
 if stat.S_ISLNK(info.st_mode):
  if name not in links or os.readlink(p)!=links[name]: raise ValueError('unexpected or changed synthetic link')
  observed_links.add(name);continue
 if not (stat.S_ISDIR(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink==1)): raise ValueError('nonregular input')
 if p.is_file(): actual[name]={{'bytes':info.st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}}
if actual!=expected or observed_links!=set(links): raise ValueError('input inventory changed')
print(json.dumps({{'passed':True,'checkedFiles':len(actual),'unchangedSyntheticLinks':len(observed_links)}}))"""


def execute(e):
    r = e.report
    identity = r['runId']
    source = '/home/lomi-e0/lomi-wasi-runtime-' + identity
    r['remoteDirectory'] = source
    free = os.statvfs(ROOT)
    r['macFreeBeforeBytes'] = free.f_bavail * free.f_frsize
    if r['macFreeBeforeBytes'] < 4 * GIB:
        raise RuntimeError('Mac physical disk headroom below reserve')
    check = "import json,os,platform;v=os.statvfs('/home/lomi-e0');print(json.dumps({'freeBytes':v.f_bavail*v.f_frsize,'platform':platform.platform(),'machine':platform.machine()}))"
    r['guestBefore'] = e.python('readonly-guest-disk-platform', check)
    if r['guestBefore']['freeBytes'] < 3 * GIB:
        raise RuntimeError('projected build headroom less than 1GiB after 2GiB estimate')
    files = {name: ROOT / 'tests/git-wasi/host' / name for name in ['Cargo.toml', 'Cargo.lock', 'src/main.rs']}
    files['worker.py'] = ROOT / 'tests/git-wasi-linux/worker.py'
    archive = ART / ('host-' + identity + '.tar.gz')
    r['source'] = pack(archive, files)
    r['hostLockDigest'] = sha(regular(ROOT / 'tests/git-wasi/host/Cargo.lock'))
    remote_archive = '/home/lomi-e0/lomi-wasi-host-' + identity + '.tar.gz'
    e.command('copy-explicit-host-source', [LIMA, 'copy', str(archive), 'lomi-e0:' + remote_archive], 120)
    e.python('extract-fresh-host-source', extract_code(remote_archive, source, r['source']['archiveDigest']))
    versions = {'kind': 'build', 'argv': ['/home/lomi-e0/.cargo/bin/rustc', '+1.98.1', '-vV'], 'cwd': source, 'timeoutSeconds': 10}
    version = e.worker('native-rust-version', source, versions)
    r['rustVersion'] = base64.b64decode(version['stdoutBase64']).decode().strip()
    version = e.worker('native-cargo-version', source, dict(versions, argv=['/home/lomi-e0/.cargo/bin/cargo', '+1.98.1', '--version']))
    r['cargoVersion'] = base64.b64decode(version['stdoutBase64']).decode().strip()
    request = {'kind': 'build', 'argv': ['/home/lomi-e0/.cargo/bin/cargo', '+1.98.1', 'build', '--locked', '-j', '2'],
               'cwd': source, 'timeoutSeconds': 900, 'minimumFreeBytes': GIB,
               'environment': {'CARGO_INCREMENTAL': '0', 'CARGO_PROFILE_DEV_DEBUG': '0'}}
    result = e.worker('native-locked-host-build', source, request)
    out, err = (base64.b64decode(result[key]) for key in ['stdoutBase64','stderrBase64'])
    (ART / ('build-' + identity + '.log')).write_bytes(out + err)
    r['build'] = {'exitCode': result['exitCode'], 'durationMilliseconds': result['durationMilliseconds'], 'logDigest': sha(out + err), 'settings': request['environment'], 'diskReserveBytes': GIB}
    e.save()
    if result['exitCode'] != 0:
        raise RuntimeError('native standalone host build failed')
    host = source + '/target/debug/lomi-git-wasi-host'
    r['nativeBinary'] = e.python('native-host-binary-digest', f"import pathlib,hashlib,json;p=pathlib.Path({host!r});print(json.dumps({{'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size}}))")
    run_inputs(e, source, host)


def run_inputs(e, source, host):
    r = e.report
    mac = ROOT / 'artifacts/git-wasi'
    reference = json.loads(regular(mac / 'report.json'))
    expected_bytes = regular(mac / 'expected-structured.json')
    expected = json.loads(expected_bytes)
    if not reference['snapshot_unchanged'] or not reference['exact_structured_comparison'] or expected != reference['actual']:
        raise ValueError('trusted native reference incomplete')
    r['reference'] = {'nativeGitVersion': reference['git'], 'reportDigest': sha(regular(mac/'report.json')), 'expectedDigest': sha(expected_bytes), 'guestDigest': reference['guest_sha256'], 'snapshotDigest': reference['snapshot_sha256']}
    files = {'expected-structured.json': mac / 'expected-structured.json', 'outside-canary': ROOT / 'tests/git-wasi-linux/fixtures/outside-canary.txt'}
    for name in ['lomi-git-wasi-guest','sandbox_probe','mmap_probe','policy_probe']:
        files['modules/' + name + '.wasm'] = mac / 'guest-target/wasm32-wasip1/release' / (name + '.wasm')
    if sha(regular(files['modules/lomi-git-wasi-guest.wasm'])) != reference['guest_sha256']:
        raise ValueError('frozen guest digest mismatch')
    for name in ['socket-import','memory-initial','table-initial']:
        files['modules/' + name + '.wasm'] = mac / 'synthetic' / (name + '.wasm')
    for name in ['snapshot','mmap-snapshot','fuel-snapshot','memory-snapshot','output-snapshot','stack-snapshot']:
        collect(mac / 'synthetic' / name, name, files)
    framed = hashlib.sha256()
    for name in sorted(key for key in files if key.startswith('snapshot/')):
        relative = name.removeprefix('snapshot/').encode();data=regular(files[name])
        framed.update(len(relative).to_bytes(8,'big')+relative+len(data).to_bytes(8,'big')+data)
    if framed.hexdigest() != reference['snapshot_sha256']:
        raise ValueError('frozen snapshot differs from native reference')
    for name in ['mode','inside']:
        files['denial-snapshot/' + name] = mac / 'synthetic/denial-snapshot' / name
    for name in ['ordinary','attributes','alternates','metadata','commondir']:
        collect(mac / 'synthetic/policy-snapshot' / name, 'policy-snapshot/' + name, files)
    # Construct symlink policy root from the same frozen ordinary tree, then add
    # only our own synthetic links inside the new guest UUID directory.
    collect(mac / 'synthetic/policy-snapshot/ordinary', 'policy-snapshot/symlink', files)
    archive = ART / ('inputs-' + r['runId'] + '.tar.gz')
    r['inputs'] = pack(archive, files)
    destination = source + '/inputs-' + r['runId']
    remote_archive = source + '/inputs-' + r['runId'] + '.tar.gz'
    e.command('copy-frozen-synthetic-inputs', [LIMA, 'copy', str(archive), 'lomi-e0:' + remote_archive], 120)
    e.python('extract-frozen-inputs', extract_code(remote_archive, destination, r['inputs']['archiveDigest']))
    r['inputVerificationBefore'] = e.python('verify-frozen-inputs-before', inventory_code(destination, r['inputs']['files']))
    links = f"""import pathlib,json
p=pathlib.Path({destination!r});(p/'denial-snapshot/escape').symlink_to(p/'outside-canary');(p/'denial-snapshot/escape-dir').symlink_to(p,target_is_directory=True);(p/'policy-snapshot/symlink/escape').symlink_to(p/'outside-canary')
print(json.dumps({{'createdOwnSyntheticSymlinks':3}}))"""
    r['syntheticLinks'] = e.python('create-own-capability-escape-links', links)
    results = {}
    def invoke(name, module, snapshot, exact=None, errors=(), structured=False):
        request = {'kind':'runtime','argv':[host,destination+'/modules/'+module+'.wasm',destination+'/'+snapshot],
                   'cwd':destination,'timeoutSeconds':90,'environment':{'LOMI_PRIVATE_CANARY':'synthetic-host-only'}}
        raw=e.worker('worker-'+name,source,request)
        out,err=(base64.b64decode(raw[key]) for key in ['stdoutBase64','stderrBase64'])
        passed=raw['exitCode']==0 if exact is not None or structured else raw['exitCode']!=0
        if exact is not None:passed=passed and out==exact
        if structured:
            try:passed=passed and json.loads(out)==expected
            except ValueError:passed=False
        if errors:
            diagnostic=b'\n'.join(line for line in err.lower().splitlines() if not line.startswith(b'allowed_imports='))
            passed=passed and any(error in diagnostic for error in errors)
        if name=='output':passed=passed and out==b'x'*65536
        match=re.search(rb'module_compile_ms=(\d+)',err)
        results[name]={'passed':passed,'exitCode':raw['exitCode'],'stdoutBytes':len(out),'stderrBytes':len(err),'stdoutDigest':sha(out),'stderrDigest':sha(err),
                       'durationMilliseconds':raw['durationMilliseconds'],'moduleCompileMilliseconds':int(match.group(1))if match else None}
        r['cases']=results;e.save()
    invoke('native-git-structured-comparison','lomi-git-wasi-guest','snapshot',structured=True)
    invoke('mmap-readonly','mmap_probe','mmap-snapshot',exact=b'mmap_readonly_probe_passed\n')
    invoke('readonly-metadata-symlink-env-process-network-denial','sandbox_probe','denial-snapshot',exact=b'sandbox_denial_probe_passed\n')
    for mode,errors in [('fuel',(b'fuel',b'interrupt')),('memory',(b'memory',b'unreachable')),('output',(b'i/o error',b'capacity',b'closed')),('stack',(b'stack',))]:
        invoke(mode,'sandbox_probe',mode+'-snapshot',errors=errors)
    invoke('socket-import','socket-import','denial-snapshot',errors=(b'disallowed import wasi_snapshot_preview1::sock_accept',))
    invoke('memory-initial','memory-initial','denial-snapshot',errors=(b'memory',))
    invoke('table-initial','table-initial','denial-snapshot',errors=(b'table',))
    invoke('full-policy','policy_probe','policy-snapshot',exact=b'policy_probe_passed\n')
    invoke('policy-commondir','lomi-git-wasi-guest','policy-snapshot/commondir',errors=(b'unsupported git metadata',))
    # Verify links themselves and every transferred regular file without following
    # links; unchanged input proof includes the deliberately hostile link targets.
    expected = r['inputs']['files']
    links = {'denial-snapshot/escape': destination + '/outside-canary',
             'denial-snapshot/escape-dir': destination,
             'policy-snapshot/symlink/escape': destination + '/outside-canary'}
    r['inputVerificationAfter'] = e.python('verify-frozen-inputs-and-links-after', inventory_code(destination, expected, links))
    r['snapshotUnchanged']=r['inputVerificationAfter']['passed'] is True
    absence=f"""import pathlib,json,os
host={host!r};count=0
for p in pathlib.Path('/proc').iterdir():
 if p.name.isdigit():
  try: count+=os.readlink(p/'exe')==host
  except (FileNotFoundError,PermissionError,ProcessLookupError): pass
space=os.statvfs({source!r});print(json.dumps({{'ownedHostProcesses':count,'absent':count==0,'guestFreeBytes':space.f_bavail*space.f_frsize}}))"""
    r['independentAbsence']=e.python('independent-exact-host-process-absence',absence)
    r['complete']=True
    r['passed']=all(v['passed'] for v in results.values()) and r['snapshotUnchanged'] and r['independentAbsence']['absent'] is True


def reuse_host(e, prepared_path):
    prepared_bytes = regular(prepared_path)
    previous = json.loads(prepared_bytes)
    if previous.get('kind') != 'linux-native-wasi-runtime-proof' or previous.get('passed') is not True:
        raise ValueError('successful prepared native proof required')
    source = previous['remoteDirectory']
    if re.fullmatch(r'/home/lomi-e0/lomi-wasi-runtime-[0-9a-f-]{36}', source) is None:
        raise ValueError('unexpected native host directory')
    for key in ['remoteDirectory', 'source', 'hostLockDigest', 'rustVersion', 'cargoVersion', 'build', 'nativeBinary']:
        e.report[key] = previous[key]
    e.report['reusedNativeHostFromProof'] = {'evidence': prepared_path.name, 'evidenceDigest': sha(prepared_bytes)}
    host = source + '/target/debug/lomi-git-wasi-host'
    code = f"""import pathlib,hashlib,json,os
host=pathlib.Path({host!r});worker=pathlib.Path({source!r})/'worker.py';space=os.statvfs({source!r})
print(json.dumps({{'hostDigest':hashlib.sha256(host.read_bytes()).hexdigest(),'workerDigest':hashlib.sha256(worker.read_bytes()).hexdigest(),'freeBytes':space.f_bavail*space.f_frsize}}))"""
    verified = e.python('verify-retained-host-worker-and-disk', code)
    if verified['hostDigest'] != previous['nativeBinary']['sha256'] or verified['workerDigest'] != sha(regular(ROOT/'tests/git-wasi-linux/worker.py')):
        raise ValueError('retained native host/worker changed')
    if verified['freeBytes'] < GIB:
        raise ValueError('guest disk below runtime reserve')
    e.report['retainedHostVerified'] = verified
    space = os.statvfs(ROOT)
    e.report['macFreeBeforeBytes'] = space.f_bavail * space.f_frsize
    if e.report['macFreeBeforeBytes'] < 4 * GIB:
        raise ValueError('Mac physical disk below runtime reserve')
    run_inputs(e, source, host)


def main():
    initialize_process_ownership()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared', type=Path)
    args = parser.parse_args()
    ART.mkdir(mode=0o700, parents=True, exist_ok=True)
    identity = str(uuid.uuid4())
    path = ART / ('native-' + identity + '.json')
    report = {'kind': 'linux-native-wasi-runtime-proof', 'runId': identity, 'qualified': False,
              'complete': False, 'passed': False, 'operations': [],
              'runnerDigest': sha(Path(__file__).read_bytes()),
              'not_run': ['production Linux snapshot broker', 'Windows reparse/ACL guarantees',
                          'other Linux architectures', 'production latency acceptance']}
    with path.open('x'):
        pass
    e = Evidence(path, report)
    e.save()
    code = 1
    try:
        if args.prepared:
            reuse_host(e, args.prepared.resolve())
        else:
            execute(e)
        code = 0 if report['passed'] else 1
    except KeyboardInterrupt:
        report['errorClass'], code = 'KeyboardInterrupt', 130
    except Exception as error:
        report['errorClass'] = type(error).__name__
    finally:
        space = os.statvfs(ROOT)
        report['macFreeAfterBytes'] = space.f_bavail * space.f_frsize
        report['exitCode'] = code
        e.save()
    print(json.dumps({'passed': report['passed'], 'qualified': False, 'evidence': str(path.relative_to(ROOT))}))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
