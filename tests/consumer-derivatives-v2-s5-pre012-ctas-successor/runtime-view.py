"""Prepare only pinned Postgres.app symlinks and executable mode in a private view."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import os
import posixpath
import re
import stat

HERE = Path(__file__).resolve().parent
PLAN = json.loads((HERE / 'runtime-view-plan.json').read_bytes())
BASE_LOCK = HERE.parents[0] / 'consumer-derivatives-v2' / 'inputs.lock.json'
TOOLCHAIN = HERE.parents[1] / 'artifacts/toolchains/postgres-18.6-04eba2aa-bceb-4ee1-846d-95238052dd0d/Postgres.app/Contents/Versions/18'
SHARE_MANIFEST = HERE / 'postgres-share-manifest.json'
SHARE_MANIFEST_SHA256 = 'b6d36d239078eb8641111ea50bdf361809be4587cecfba23646c46b3da78394d'
VIEW_NAME = re.compile(r'\.ctas-runner-view-[0-9a-f]{32}\Z')
BASE = PurePosixPath('Contents/Versions/18')


def _no_symlink_components(path, stop=None):
    path = Path(os.path.abspath(path))
    stop = Path(os.path.abspath(stop)) if stop is not None else None
    current = path
    while True:
        if current.is_symlink():
            raise ValueError('symlink component in protected path: ' + str(current))
        if stop is not None and current == stop:
            break
        if current.parent == current:
            if stop is not None:
                raise ValueError('protected path is outside private view')
            break
        current = current.parent


def _hash_regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('target is not a regular non-symlink file: ' + str(path))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_view(path):
    raw = Path(path)
    if not raw.is_absolute() or '..' in raw.parts:
        raise ValueError('view must be an absolute traversal-free package child')
    view = Path(os.path.abspath(raw))
    if view.parent != HERE or not VIEW_NAME.fullmatch(view.name):
        raise ValueError('view must be a UUID-named direct child of package')
    info = view.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError('view must be an existing private directory')
    _no_symlink_components(view)
    if view.resolve(strict=True) != view:
        raise ValueError('view escaped package')
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('view must be owned by current user with mode 0700')
    return view


def _fixed_regular(path):
    _no_symlink_components(path)
    info = Path(path).lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('expected regular non-symlink file: ' + str(path))


def _safe_relative(value):
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in ('', '.', '..') for part in path.parts):
        raise ValueError('unsafe share-tree path: ' + value)
    return path


def _link_target_path(relative, target):
    if not isinstance(target, str) or not target or target.startswith('/'):
        raise ValueError('unsafe absolute/empty share symlink target')
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(relative), target))
    if resolved == '..' or resolved.startswith('../') or resolved.startswith('/'):
        raise ValueError('share symlink escapes tree: ' + relative)
    return resolved


def _load_share_manifest():
    _fixed_regular(SHARE_MANIFEST)
    raw = SHARE_MANIFEST.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SHARE_MANIFEST_SHA256:
        raise ValueError('share manifest pin mismatch')
    doc = json.loads(raw)
    if doc.get('format') != 'lomi-postgresql-share-tree-v1' or not isinstance(doc.get('entries'), list):
        raise ValueError('invalid share manifest')
    entries = {}
    previous = None
    for item in doc['entries']:
        relative = item.get('path')
        _safe_relative(relative)
        if previous is not None and relative <= previous:
            raise ValueError('share manifest entries are not uniquely sorted')
        previous = relative
        kind = item.get('type')
        if kind not in ('directory', 'file', 'symlink'):
            raise ValueError('invalid share manifest entry type')
        if kind == 'file' and not re.fullmatch(r'[0-9a-f]{64}', item.get('sha256', '')):
            raise ValueError('invalid share file hash')
        if kind == 'symlink':
            _link_target_path(relative, item.get('target'))
        entries[relative] = item
    for relative, item in entries.items():
        if item['type'] == 'symlink':
            target = _link_target_path(relative, item['target'])
            if entries.get(target, {}).get('type') != 'file':
                raise ValueError('share symlink must resolve directly to a regular file: ' + relative)
    return entries


def _scan_tree(root):
    found = {}
    def descend(directory, prefix=''):
        with os.scandir(directory) as scan:
            children = sorted(scan, key=lambda entry: entry.name)
        for child in children:
            relative = (prefix + '/' if prefix else '') + child.name
            if child.is_symlink():
                found[relative] = {'path': relative, 'type': 'symlink', 'target': os.readlink(child.path)}
            elif child.is_dir(follow_symlinks=False):
                found[relative] = {'path': relative, 'type': 'directory'}
                descend(Path(child.path), relative)
            elif child.is_file(follow_symlinks=False):
                found[relative] = {'path': relative, 'type': 'file',
                                   'sha256': hashlib.sha256(Path(child.path).read_bytes()).hexdigest()}
            else:
                raise ValueError('unsupported filesystem entry in share tree: ' + child.path)
    descend(root)
    return found


def _validate_source_tree(source_share, manifest):
    _no_symlink_components(source_share)
    if not source_share.is_dir():
        raise ValueError('source share tree missing')
    found = _scan_tree(source_share)
    if found != manifest:
        raise ValueError('source share tree differs from pinned manifest')
    for relative, item in manifest.items():
        if item['type'] == 'symlink':
            target = _link_target_path(relative, item['target'])
            target_path = source_share.joinpath(*PurePosixPath(target).parts)
            if target_path.is_symlink() or not target_path.is_file():
                raise ValueError('source share symlink target is not a regular file: ' + relative)


def _validate_destination_tree(destination, manifest, view):
    _no_symlink_components(destination, view)
    if not destination.exists():
        raise ValueError('private share tree missing')
    if destination.is_symlink() or not destination.is_dir():
        raise ValueError('private share tree root is not a directory')
    if stat.S_IMODE(destination.lstat().st_mode) != 0o700:
        raise ValueError('private share tree root mode mismatch')
    found = _scan_tree(destination)
    for relative, actual in found.items():
        expected = manifest.get(relative)
        if expected is None or actual != expected:
            raise ValueError('private share tree collision: ' + relative)
        path = destination.joinpath(*PurePosixPath(relative).parts)
        info = path.lstat()
        if actual['type'] == 'directory' and stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('private share directory mode mismatch: ' + relative)
        if actual['type'] == 'file' and stat.S_IMODE(info.st_mode) != 0o444:
            raise ValueError('private share file mode mismatch: ' + relative)
    return found


def prepare(view):
    """Validate and add the exact allowlisted relative links to an existing view."""
    view = _safe_view(view)
    source = TOOLCHAIN
    _no_symlink_components(source)
    if source.resolve(strict=True) != source:
        raise ValueError('source toolchain path differs from fixed path')
    _fixed_regular(BASE_LOCK)
    lock = json.loads(BASE_LOCK.read_bytes())
    pins = lock['toolchainCoreSha256']
    toolchain_root = PurePosixPath(lock['toolchainRoot'])
    if (toolchain_root.is_absolute() or not toolchain_root.parts or
            any(part in ('', '.', '..') for part in toolchain_root.parts)):
        raise ValueError('unsafe locked toolchain root')
    private_app = view.joinpath(*toolchain_root.parts, 'Postgres.app')
    libdir = private_app / 'Contents/Versions/18/lib'
    _no_symlink_components(libdir, view)
    if not libdir.is_dir():
        raise ValueError('private view library directory missing or unsafe')
    allowed = {}
    for alias, basename in PLAN['aliases'].items():
        if Path(alias).name != alias or Path(basename).name != basename:
            raise ValueError('alias plan must contain basenames only')
        source_alias = source / 'lib' / alias
        _no_symlink_components(source_alias.parent)
        if not source_alias.is_symlink() or os.readlink(source_alias) != basename:
            raise ValueError('source alias relation mismatch: ' + alias)
        target_rel = (BASE / 'lib' / basename).as_posix()
        if target_rel not in pins:
            raise ValueError('alias target is absent from base lock pins: ' + basename)
        digest = pins[target_rel]
        source_target = source / 'lib' / basename
        _no_symlink_components(source_target.parent)
        if _hash_regular(source_target) != digest:
            raise ValueError('source target hash mismatch: ' + basename)
        view_target = private_app.joinpath(*PurePosixPath(target_rel).parts)
        _no_symlink_components(view_target, view)
        if _hash_regular(view_target) != digest:
            raise ValueError('private view target hash mismatch: ' + basename)
        allowed[alias] = (basename, view_target)

    executables = []
    for relative in PLAN['executables']:
        rel = PurePosixPath(relative)
        if rel.is_absolute() or any(part in ('', '.', '..') for part in rel.parts):
            raise ValueError('unsafe executable path')
        if relative not in pins:
            raise ValueError('executable is absent from base lock pins')
        path = private_app.joinpath(*rel.parts)
        _no_symlink_components(path, view)
        if _hash_regular(path) != pins[relative]:
            raise ValueError('executable hash mismatch: ' + relative)
        executables.append(path)

    share_manifest = _load_share_manifest()
    source_share = source / 'share/postgresql'
    _validate_source_tree(source_share, share_manifest)
    for relative, digest in lock['toolchainInitdbSha256'].items():
        prefix = 'Contents/Versions/18/share/postgresql/'
        if not relative.startswith(prefix):
            raise ValueError('unexpected base-lock initdb path')
        share_relative = relative[len(prefix):]
        item = share_manifest.get(share_relative)
        if item is None or item.get('type') != 'file' or item.get('sha256') != digest:
            raise ValueError('share manifest disagrees with base-lock initdb pin: ' + relative)
    private_share = private_app / 'Contents/Versions/18/share/postgresql'
    destination_share = _validate_destination_tree(private_share, share_manifest, view)
    for relative in lock['toolchainInitdbSha256']:
        share_relative = relative.removeprefix('Contents/Versions/18/share/postgresql/')
        if share_relative not in destination_share:
            raise ValueError('base-lock initdb file missing from private view: ' + relative)
    share_payloads = {}
    for relative, item in share_manifest.items():
        if item['type'] == 'file' and relative not in destination_share:
            payload = source_share.joinpath(*PurePosixPath(relative).parts).read_bytes()
            if hashlib.sha256(payload).hexdigest() != item['sha256']:
                raise ValueError('source share file changed during preparation: ' + relative)
            share_payloads[relative] = payload

    # Preflight every destination before making any filesystem change.
    for alias, (basename, target) in allowed.items():
        path = libdir / alias
        _no_symlink_components(path.parent, view)
        if path.is_symlink():
            if os.readlink(path) != basename:
                raise ValueError('unexpected preexisting alias: ' + alias)
        elif path.exists():
            raise ValueError('unexpected preexisting alias/path: ' + alias)
        else:
            pass
    for relative, item in share_manifest.items():
        if item['type'] == 'directory':
            path = private_share.joinpath(*PurePosixPath(relative).parts)
            if not path.exists():
                path.mkdir(mode=0o700)
                path.chmod(0o700)
    for relative, item in share_manifest.items():
        path = private_share.joinpath(*PurePosixPath(relative).parts)
        if relative in destination_share:
            continue
        if item['type'] == 'file':
            payload = share_payloads[relative]
            with path.open('xb') as stream:
                stream.write(payload)
            path.chmod(0o444)
        elif item['type'] == 'symlink':
            path.symlink_to(item['target'])
    for alias, (basename, target) in allowed.items():
        path = libdir / alias
        if not path.is_symlink():
            os.symlink(basename, path)
    for path in executables:
        path.chmod(0o555)
    return {'view': view, 'aliases': len(allowed), 'executables': len(PLAN['executables']),
            'shareEntries': len(share_manifest)}
