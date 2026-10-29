#!/usr/bin/env python3
"""Freeze explicit public inputs and verify the local identity/admission packages."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

from owned_process import initialize_process_ownership, run_owned

ROOT = Path(__file__).resolve().parents[1]


def checked_source_path(root, name):
    relative = Path(name)
    if relative.is_absolute() or '..' in relative.parts:
        raise RuntimeError('source boundary rejected')
    for part in relative.parts:
        lower = part.lower()
        if (lower.startswith(('.env', 'env.')) or lower.endswith('.env')
                or '.env.' in lower):
            raise RuntimeError('source boundary rejected')
    path = root / relative
    if path.is_symlink() or any(p.is_symlink() for p in path.parents) or not path.is_file():
        raise RuntimeError('source boundary rejected')
    return path


def inputs():
    names = {
        'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
        'tests/crypto-provenance/source.json', 'tools/check_crypto_source.py',
        'tools/package_authority_crypto.py', 'tools/test_package_authority_crypto.py',
        'tools/owned_process.py', 'tools/run_identity_admission_integration.py',
        'tools/test_identity_admission_source_boundary.py',
    }
    manifest = json.loads((ROOT / 'tests/crypto-provenance/source.json').read_text())
    for entry in manifest['files'] + manifest['added_files']:
        names.add('crates/lomi-remote-crypto/' + entry['destination_path'])
    names.update(entry['destination_path'] for entry in manifest['proof_files'])
    for directory in ['crates/lomi-remote-protocol', 'crates/lomi-host-auth', 'crates/lomi-platform']:
        for path in (ROOT / directory).rglob('*'):
            if path.is_file() and (path.suffix in ['.rs', '.toml', '.py']
                                   or path.name in ['README.md', 'source-allowlist.json']):
                names.add(path.relative_to(ROOT).as_posix())
    names.update(path.relative_to(ROOT).as_posix() for path in (ROOT / 'crates').glob('*/Cargo.toml'))
    for directory in ['contracts/fixtures', 'tests/crypto-provenance']:
        for path in (ROOT / directory).rglob('*'):
            if path.is_file() and path.suffix in ['.json', '.py', '.md'] and '__pycache__' not in path.parts:
                names.add(path.relative_to(ROOT).as_posix())
    for package in ['protocol-codec-wasm', 'remote-contracts']:
        for relative in ['package.json', 'README.md', 'src', 'scripts', 'test']:
            path = ROOT / 'packages' / package / relative
            for item in ([path] if path.is_file() else path.rglob('*')):
                if item.is_file() and item.suffix in ['.json', '.mjs', '.ts', '.md']:
                    names.add(item.relative_to(ROOT).as_posix())
    for name in names:
        checked_source_path(ROOT, name)
    return sorted(names)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def commands(output):
    node = '/Users/woro/.local/bin/node'
    bun = str(ROOT / 'artifacts/toolchains/bun-1.4.2-darwin-arm64/bun')
    authority_tests = sorted((ROOT / 'packages/authority-crypto-wasm/test').glob('*.test.mjs'))
    return [
        ('crypto-source-provenance', [sys.executable, 'tools/check_crypto_source.py', '--source-repo', '../lomi']),
        ('crypto-provenance-negative-tests', [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests/crypto-provenance', '-v']),
        ('native-crypto-full-tests', ['cargo', 'test', '--locked', '-p', 'lomi-remote-crypto', '--features', 'test-fixtures']),
        ('native-protocol-credential-tests', ['cargo', 'test', '--locked', '-p', 'lomi-remote-protocol', '-p', 'lomi-host-auth', '--tests']),
        ('native-strict-clippy', ['cargo', 'clippy', '--locked', '-p', 'lomi-remote-crypto', '-p', 'lomi-remote-protocol', '-p', 'lomi-host-auth', '--all-targets', '--features', 'lomi-remote-crypto/test-fixtures', '--', '-D', 'warnings']),
        ('authority-release-wasm-build', [node, 'packages/authority-crypto-wasm/scripts/build.mjs']),
        ('authority-node-tests', [node, '--test', *map(str, authority_tests)]),
        ('authority-bun142-tests', [bun, '--no-env-file', 'test', *map(str, authority_tests)]),
        ('authority-strict-types', [node, 'packages/enrollment-spike/node_modules/typescript/bin/tsc', '--project', str(output / 'types-config.json')]),
        ('authority-package-boundary-tests', [sys.executable, '-m', 'unittest', 'discover', '-s', 'tools', '-p', 'test_package_authority_crypto.py', '-v']),
        ('authority-immutable-pack-first', [sys.executable, 'tools/package_authority_crypto.py']),
        ('authority-immutable-pack-second', [sys.executable, 'tools/package_authority_crypto.py', '--output-dir', str(output / 'second-package')]),
        ('protocol-release-wasm-build', [node, 'packages/protocol-codec-wasm/scripts/build.mjs']),
        ('contract-generation', ['cargo', 'run', '--locked', '-p', 'lomi-remote-protocol', '--bin', 'generate-contracts']),
        ('contract-sdk-generation', [node, 'packages/remote-contracts/scripts/generate.mjs']),
        ('contract-manifest-finalization', ['cargo', 'run', '--locked', '-p', 'lomi-remote-protocol', '--bin', 'generate-contracts']),
        ('contract-generation-check', ['cargo', 'run', '--locked', '-p', 'lomi-remote-protocol', '--bin', 'generate-contracts', '--', '--check']),
        ('contract-sdk-generation-check', [node, 'packages/remote-contracts/scripts/generate.mjs', '--check']),
        ('protocol-node-codec-tests', [node, '--test', str(ROOT / 'packages/protocol-codec-wasm/test/codec.test.mjs')]),
        ('contract-node-sdk-tests', [node, '--test', *map(str, sorted((ROOT / 'packages/remote-contracts/test').glob('*.test.mjs')))]),
    ]


def main():
    initialize_process_ownership()
    # This check touches only its synthetic temporary fixtures, never user env.
    from test_identity_admission_source_boundary import verify_source_boundary
    verify_source_boundary()
    output = ROOT / 'artifacts/identity-admission-integration' / str(uuid.uuid4())
    output.mkdir(mode=0o700, parents=True)
    names = inputs()
    before = {name: digest(ROOT / name) for name in names}
    (output / 'sources-before.json').write_text(json.dumps(before, indent=2) + '\n')
    for name in names:
        target = output / 'source' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes())
        target.chmod(0o400)
        if digest(target) != before[name]:
            raise RuntimeError('source copy changed')
    config = {
        'compilerOptions': {'noEmit': True, 'strict': True, 'module': 'NodeNext', 'target': 'ES2022',
                            'paths': {'@lomi/authority-crypto-wasm': [str(ROOT / 'packages/authority-crypto-wasm/src/index.d.ts')]}},
        'files': [str(ROOT / 'packages/authority-crypto-wasm/test/types.ts')],
    }
    (output / 'types-config.json').write_text(json.dumps(config, indent=2) + '\n')
    env = os.environ.copy()
    env.pop('AUTHORITY_CRYPTO_TEST_ARTIFACTS', None)
    env.update(CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0',
               CARGO_PROFILE_RELEASE_DEBUG='0', CARGO_BUILD_JOBS='2', CARGO_TARGET_DIR=str(ROOT / 'target'),
               CARGO_NET_OFFLINE='true')
    report = {'format': 1, 'scope': 'Guarded live-original compilation and retained read-only explicit public input copies; package integration only, no server/deployment qualification',
              'inputCount': len(names), 'sourceStable': False, 'passed': False, 'commands': [],
              'startedUtc': datetime.datetime.now(datetime.timezone.utc).isoformat()}

    def save():
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')

    save()
    print(json.dumps({'artifact': str(output), 'inputs': len(names)}), flush=True)
    try:
        for label, argv in commands(output):
            result = run_owned(argv, cwd=ROOT, env=env, timeout=600)
            for suffix, contents in [('stdout', result.stdout), ('stderr', result.stderr)]:
                (output / (label + '.' + suffix + '.log')).write_text(contents)
            report['commands'].append({'name': label, 'argv': argv, 'exitCode': result.returncode,
                                       'stdoutSha256': hashlib.sha256(result.stdout.encode()).hexdigest(),
                                       'stderrSha256': hashlib.sha256(result.stderr.encode()).hexdigest()})
            save()
            print(json.dumps({'name': label, 'exitCode': result.returncode}), flush=True)
            if result.returncode:
                raise RuntimeError('check failed: ' + label)
        report['passed'] = True
    except BaseException as error:
        report['failure'] = type(error).__name__ + ': ' + str(error)
    finally:
        after = {name: digest(ROOT / name) for name in names}
        (output / 'sources-after.json').write_text(json.dumps(after, indent=2) + '\n')
        report['sourceStable'] = before == after
        report['passed'] = report['passed'] and report['sourceStable']
        report['finishedUtc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
    print(json.dumps({'artifact': str(output), 'passed': report['passed'], 'sourceStable': report['sourceStable'], 'failure': report.get('failure')}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
