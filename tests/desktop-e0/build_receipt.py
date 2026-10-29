"""Controlled local build evidence; historical executables cannot acquire receipts."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

AUDIT = '2cef452c39eb8b455c8d2ae1251310dc870c50bb'
PATCHED = ['src-tauri/Cargo.toml', 'src-tauri/build.rs', 'src-tauri/src/lib.rs',
           'src-tauri/src/terminal.rs', 'src/Workbench.tsx', 'src/main.tsx',
           'src/e0-desktop-probe.ts', 'tests/native/e0-desktop-support.rs']
LINKS = ['node_modules', 'packages/ai-runtime/node_modules', 'packages/remote-terminal-runtime/node_modules']


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def git(checkout, *args):
    return subprocess.check_output(['git', '-C', str(checkout), *args], timeout=30)


def exact_checkout(repo, checkout):
    if git(checkout, 'rev-parse', 'HEAD').decode().strip() != AUDIT:
        raise RuntimeError('Desktop audit revision mismatch')
    source = repo / 'tests/desktop-e0'
    provenance = json.loads((source / 'provenance.json').read_text())
    if provenance['auditRevision'] != AUDIT:
        raise RuntimeError('Fixture provenance audit mismatch')
    for name, expected in provenance['sources'].items():
        if digest(repo / name) != expected:
            raise RuntimeError('Fixture provenance mismatch: ' + name)
    patch = (source / 'patches/desktop.patch').read_bytes()
    with tempfile.TemporaryDirectory(prefix='e0-replay-') as temporary:
        replay = Path(temporary)
        for name in PATCHED:
            result = subprocess.run(['git', '-C', str(checkout), 'show', AUDIT + ':' + name], capture_output=True)
            if result.returncode == 0:
                path = replay / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(result.stdout)
        subprocess.run(['git', 'apply', '--unsafe-paths', '-'], input=patch, cwd=replay, check=True, timeout=10)
        replay_files = sorted(str(p.relative_to(replay)) for p in replay.rglob('*') if p.is_file())
        if replay_files != sorted(PATCHED):
            raise RuntimeError('Canonical patch must reconstruct exactly eight files')
        for name in PATCHED:
            path = checkout / name
            if path.is_symlink() or digest(path) != digest(replay / name):
                raise RuntimeError('Checkout differs from canonical patch: ' + name)
    changed = git(checkout, 'diff', '--name-only', AUDIT).decode().splitlines()
    if set(changed) - set(PATCHED):
        raise RuntimeError('Unexpected desktop source edits')
    untracked = git(checkout, 'ls-files', '--others', '--exclude-standard').decode().splitlines()
    if set(untracked) - set(PATCHED) - set(LINKS):
        raise RuntimeError('Unexpected desktop untracked input')
    for name in LINKS:
        if not (checkout / name).is_symlink() or not (checkout / name).resolve().is_dir():
            raise RuntimeError('Desktop dependency must be a valid symlink: ' + name)
    if (checkout / 'src/e0-desktop-probe.ts').read_bytes() != (source / 'probe.ts').read_bytes() or (checkout / 'tests/native/e0-desktop-support.rs').read_bytes() != (source / 'support.rs').read_bytes():
        raise RuntimeError('Canonical fixture source mismatch')


def dependency_digest(path):
    """Bind actual linked contents, including package links outside node_modules."""
    value = hashlib.sha256()
    visited = set()
    def visit(path):
        resolved = path.resolve(strict=False)
        if path.is_symlink() and not resolved.exists():
            # Some unused pnpm entries contain historical dangling links. Bind
            # their exact missing target too; repairing one changes the receipt.
            value.update(json.dumps([str(path), "dangling", os.readlink(path), str(resolved)]).encode())
            return
        value.update(json.dumps([str(path), str(resolved)]).encode())
        if resolved in visited:
            return
        visited.add(resolved)
        if resolved.is_dir():
            for child in sorted(resolved.iterdir()):
                if child.name not in {'.cache', '.vite', '.tmp'}:
                    visit(child)
        else:
            value.update(digest(resolved).encode())
    visit(Path(path))
    return value.hexdigest()


def snapshot(repo, checkout, target, env):
    exact_checkout(repo, checkout)
    paths = {str(Path('desktop') / name): checkout / name for name in git(checkout, 'ls-files', '-z').decode().split('\0') if name}
    paths.update({'desktop/' + name: checkout / name for name in PATCHED})
    for folder in ['tests/desktop-e0', 'crates/lomi-domain-spike', 'crates/lomi-remote-protocol', 'vendor']:
        for path in (repo / folder).rglob('*'):
            if path.is_file() and not any(part in {'target', '__pycache__'} for part in path.relative_to(repo).parts):
                paths[str(path.relative_to(repo))] = path
    for name in ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'tools/run_desktop_e0.py', 'tools/owned_process.py']:
        paths[name] = repo / name
    # Build scripts consume the pinned archive from this audited manifest/cache.
    for path in (checkout / 'src-tauri/target/ai-runtime').glob('*.tar.gz'):
        paths['runtime-cache/' + path.name] = path
    configs = {}
    for folder in [repo / '.cargo', checkout / '.cargo', checkout / 'src-tauri/.cargo', Path.home() / '.cargo']:
        for name in ['config', 'config.toml']:
            p = folder / name
            configs[str(p)] = digest(p) if p.is_file() else None
    return {'auditRevision': AUDIT, 'sources': {name: digest(path) for name, path in sorted(paths.items())},
            'dependencies': {name: dependency_digest(checkout / name) for name in LINKS},
            'cargoConfiguration': configs, 'target': str(target), 'features': ['e0-desktop-probe'],
            'environment': dict(sorted(env.items())),
            'toolchain': {name: subprocess.check_output([name, *args], env=env, text=True, timeout=20).strip()
                          for name, args in {'rustc': ['-vV'], 'cargo': ['--version'], 'node': ['--version']}.items()}}


def receipt(inputs, binaries, checks):
    if len(checks) != 3 or any(c['exitCode'] != 0 for c in checks):
        raise RuntimeError('Controlled build did not complete all commands')
    return {'schemaVersion': 1, 'inputs': inputs,
            'binaries': {name: digest(path) for name, path in binaries.items()}, 'commands': checks}


def verify(path, inputs, binaries, checks):
    actual = json.loads(Path(path).read_text())
    if actual != receipt(inputs, binaries, checks):
        raise RuntimeError('Missing, stale, or changed desktop E0 controlled build receipt')
    return actual
