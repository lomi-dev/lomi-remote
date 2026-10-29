#!/usr/bin/env python3
"""Build-guarded, source-bound internal npm tarball; never publish or install."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

from owned_process import initialize_process_ownership, run_owned

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = Path('packages/authority-crypto-wasm')
GENERATED = ('authority_crypto.d.ts', 'authority_crypto.js', 'authority_crypto_bg.wasm',
             'authority_crypto_bg.wasm.d.ts')
FILES = ('README.md', 'package.json', 'THIRD_PARTY_NOTICES.json', 'src/index.mjs',
         'src/index.d.ts', *(f'generated/{name}' for name in GENERATED),
         'generated/provenance.json')
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
API = {'BrowserChannel', 'BrowserHandshake', 'BrowserHandshakeV3', 'BrowserIdentity',
       'live_production_qualified', 'pairing_fingerprint', 'prepare_host_enrollment_challenge',
       'production_qualified', 'remote_v3_production_qualified', 'validate_channel_approval',
       'verified_v3_artifacts', 'verify_host_enrollment_proof', 'verify_host_key_initiation',
       'verify_peer_approval', 'verify_public_bundle', 'verify_host_refresh_proof',
       'verify_registered_host_identity', 'verify_consumer_window_identity',
       'prepare_consumer_window_challenge', 'verify_consumer_window_proof',
       'prepare_grant_proposal_v3', 'verify_grant_proposal_v3',
       'prepare_channel_context_v3', 'verify_channel_admission_v3', 'initSync'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode()


def regular(path):
    # Reject links in every path component, including linked directories.
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError(f'symlink forbidden: {path}')
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
        raise ValueError(f'not a bounded regular file: {path}')
    data = path.read_bytes()
    if len(data) != info.st_size or len(data) > MAX_FILE:
        raise ValueError(f'file changed while reading: {path}')
    return data


def command(argv, root=ROOT, timeout=300):
    env = dict(os.environ, CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_RELEASE_DEBUG='0',
               CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='2')
    result = run_owned(argv, cwd=root, env=env, timeout=timeout)
    if result.returncode:
        raise ValueError(f'command failed: {argv!r}\n{result.stderr[-4000:]}')
    return result.stdout.strip()


def notices(root=ROOT):
    metadata = json.loads(command(['cargo', 'metadata', '--locked', '--format-version', '1',
        '--filter-platform', 'wasm32-unknown-unknown', '--no-default-features',
        '--features', 'lomi-remote-crypto/browser'], root))
    packages = {p['id']: p for p in metadata['packages']}
    nodes = {n['id']: n for n in metadata['resolve']['nodes']}
    pending = [p['id'] for p in packages.values() if p['name'] == 'lomi-remote-crypto']
    if len(pending) != 1:
        raise ValueError('expected one crypto root')
    closure = set()
    while pending:
        item = pending.pop()
        if item in closure:
            continue
        closure.add(item)
        pending.extend(d['pkg'] for d in nodes[item]['deps']
                       if any(k['kind'] != 'dev' for k in d['dep_kinds']))
    records = []
    for item in sorted(closure, key=lambda key: (packages[key]['name'], packages[key]['version'])):
        p = packages[item]
        source = Path(p['manifest_path']).parent
        local = p['name'] in ('lomi-remote-crypto', 'lomi-remote-protocol')
        source_id = p['source'] or source.relative_to(root).as_posix()
        licenses = []
        # Workspace crate licenses are unspecified; nested Snow is its own package.
        candidates = [] if local else sorted(source.rglob('*'))
        for path in candidates:
            relative = path.relative_to(source).as_posix()
            if (path.name.lower().startswith(('license', 'licence', 'notice', 'copying'))
                    or relative == p.get('license_file')):
                if path.is_dir() and not path.is_symlink():
                    continue
                data = regular(path)
                licenses.append({'path': relative, 'sha256': sha(data),
                                 'text': data.decode('utf-8')})
        if not local and (not p['license'] or not licenses):
            raise ValueError(f'missing upstream license: {p["name"]} {p["version"]}')
        records.append({'name': p['name'], 'version': p['version'], 'source': source_id,
                        'licenseExpression': p['license'], 'licenseFiles': licenses})
    return encoded({'format': 1, 'scope': 'Locked wasm32 crypto dependency closure; excludes dev edges; includes build dependencies and conservatively unified workspace features.',
        'ownerLicense': 'No license grant is inferred for private Lomi sources.',
        'cargoLockSha256': sha(regular(root / 'Cargo.lock')), 'packages': records})


def snapshot(root):
    names = ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml']
    def visit(directory):
        for path in sorted(directory.iterdir()):
            if path.name in ('node_modules', 'generated', '__pycache__', 'target', '.git'):
                continue
            if path.is_symlink():
                raise ValueError(f'source symlink: {path}')
            if path.is_dir():
                visit(path)
            else:
                names.append(path.relative_to(root).as_posix())
    for directory in ('crates/lomi-remote-crypto', 'crates/lomi-remote-protocol', str(PACKAGE)):
        visit(root / directory)
    return {name: sha(regular(root / name)) for name in sorted(names)}


def verified_files(root=ROOT):
    pkg = root / PACKAGE
    data = {name: regular(pkg / name) for name in FILES}
    if sum(map(len, data.values())) > MAX_TOTAL:
        raise ValueError('package size limit exceeded')
    if sorted(p.name for p in (pkg / 'generated').iterdir()) != sorted((*GENERATED, 'provenance.json')):
        raise ValueError('unexpected generated files')
    provenance = json.loads(data['generated/provenance.json'])
    expected = {'format': 1, 'package': '@lomi/authority-crypto-wasm',
                'target': 'wasm32-unknown-unknown', 'profile': 'release',
                'features': ['browser'], 'testFixtures': False}
    if (any(provenance.get(k) != v for k, v in expected.items())
            or provenance.get('testFixtures') is not False):
        raise ValueError('not canonical browser release provenance')
    if snapshot(root) != provenance['sourceSha256']:
        raise ValueError('source provenance mismatch; rebuild canonical package')
    if provenance['generatedSha256'] != {name: sha(data[f'generated/{name}']) for name in GENERATED}:
        raise ValueError('generated artifact hash mismatch')
    if not re.fullmatch('[a-f0-9]{64}', provenance['inputWasmSha256']):
        raise ValueError('missing input WASM pin')
    js = data['generated/authority_crypto.js'].decode()
    exports = set(re.findall(r'export (?:function|class) (\w+)', js))
    exports.update(re.findall(r'export \{ (\w+)', js))
    if exports != API or re.search(r'fixture', js, re.I):
        raise ValueError('unexpected generated API')
    manifest = json.loads(data['package.json'])
    if manifest.get('private') is not True or manifest.get('name') != expected['package']:
        raise ValueError('expected private canonical npm package')
    if manifest.get('files') != list(FILES):
        raise ValueError('package files allowlist mismatch')
    if manifest.get('dependencies') or manifest.get('optionalDependencies') or manifest.get('bundledDependencies'):
        raise ValueError('unexpected runtime dependencies')
    return data, provenance


def tarball(files):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(files.items()):
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts:
                raise ValueError('unsafe package path')
            info = tarfile.TarInfo(f'package/{name}')
            info.size = len(data)
            info.mode = 0o644
            info.mtime = info.uid = info.gid = 0
            info.uname = info.gname = ''
            archive.addfile(info, io.BytesIO(data))
    compressed = io.BytesIO()
    with gzip.GzipFile(filename='', fileobj=compressed, mode='wb', mtime=0, compresslevel=9) as output:
        output.write(raw.getvalue())
    return compressed.getvalue()


def write_immutable(path, data):
    if path.exists() or path.is_symlink():
        if regular(path) != data:
            raise ValueError(f'refusing to overwrite artifact: {path}')
    else:
        with path.open('xb') as output:
            output.write(data)


def pack(output, root=ROOT):
    # Verification before and after the guard prevents normal concurrent edits.
    before, provenance = verified_files(root)
    if before['THIRD_PARTY_NOTICES.json'] != notices(root):
        raise ValueError('dependency notices drift; regenerate notices then rebuild')
    command(['npm', 'run', 'check', '--prefix', str(PACKAGE)], root, timeout=600)
    files, after_provenance = verified_files(root)
    if before != files or provenance != after_provenance:
        raise ValueError('package changed during build guard')
    for key, argv in [('rustc', ['rustc', '--version']), ('cargo', ['cargo', '--version']),
                      ('wasmBindgen', ['wasm-bindgen', '--version'])]:
        if provenance['tools'][key] != command(argv, root):
            raise ValueError(f'tool pin mismatch: {key}')
    payload = tarball(files)
    digest = sha(payload)
    name = f'lomi-authority-crypto-wasm-sha256-{digest}.tgz'
    receipt = encoded({'format': 1, 'scope': 'Local internal canonical package; unsigned; release gates remain open.',
        'filename': name, 'sha256': digest, 'size': len(payload),
        'filesSha256': {f'package/{k}': sha(v) for k, v in sorted(files.items())},
        'sourceSha256': provenance['sourceSha256'], 'inputWasmSha256': provenance['inputWasmSha256'],
        'tools': provenance['tools'], 'provenanceSha256': sha(files['generated/provenance.json']),
        'packerSha256': sha(regular(Path(__file__)))})
    output.mkdir(parents=True, exist_ok=True)
    write_immutable(output / name, payload)
    write_immutable(output / f'{name}.json', receipt)
    return {'path': str(output / name), 'sha256': digest, 'size': len(payload)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'artifacts/authority-package')
    parser.add_argument('--write-notices', action='store_true', help='refresh exact dependency notices; rebuild WASM afterward')
    args = parser.parse_args()
    initialize_process_ownership()
    try:
        if args.write_notices:
            (ROOT / PACKAGE / 'THIRD_PARTY_NOTICES.json').write_bytes(notices())
            print('Notices refreshed; rebuild canonical WASM provenance before packing.')
        else:
            print(json.dumps(pack(args.output_dir)))
    except (ValueError, OSError, KeyError) as error:
        parser.exit(1, f'authority package refused: {error}\n')


if __name__ == '__main__':
    main()
