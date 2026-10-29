"""Collision-aware exact-source writer for the supervised runner preflight."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import os
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
INVENTORY = json.loads((HERE / 'runner-source-inventory.json').read_bytes())
DESTINATION = re.compile(r'\.ctas-runner-view-[0-9a-f]{32}\Z')


def _relative(value):
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in ('', '.', '..') for part in path.parts):
        raise ValueError('unsafe source path: ' + value)
    return path


def _no_symlinks(path):
    path = Path(os.path.abspath(path))
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError('symlink in source view')
    if path.resolve(strict=False) != path:
        raise ValueError('source view escaped lexical root')


def _payload(entry):
    for relative in entry['candidates']:
        path = _relative(relative)
        candidate = ROOT.joinpath(*path.parts)
        _no_symlinks(candidate)
        try:
            raw = candidate.read_bytes()
        except OSError:
            continue
        if hashlib.sha256(raw).hexdigest() == entry['sha256']:
            return raw, relative
    raise FileNotFoundError('no exact candidate: ' + entry['id'])


def materialize(destination):
    raw = Path(destination)
    if not raw.is_absolute() or '..' in raw.parts:
        raise ValueError('destination must be absolute and traversal-free')
    dest = Path(os.path.abspath(raw))
    _no_symlinks(dest)
    if dest.parent != HERE or not DESTINATION.fullmatch(dest.name) or dest.exists():
        raise ValueError('destination must be a new UUID-named direct package child')
    dest.mkdir(mode=0o700)
    _no_symlinks(dest)
    dest.chmod(0o700)
    entries = {entry['id']: entry for entry in INVENTORY['entries']}
    if len(entries) != len(INVENTORY['entries']):
        raise ValueError('duplicate runner source entry id')
    sources = {}
    for lock in INVENTORY['locks']:
        sources[(lock['path'], lock['sha256'])] = lock['entryId']
    for edge in INVENTORY['edges']:
        logical = edge.get('materializedPath')
        _relative(logical)
        key = (logical, edge['sha256'])
        previous = sources.get(key)
        if previous is not None and previous != edge['toEntry']:
            if entries[previous]['sha256'] != entries[edge['toEntry']]['sha256']:
                raise ValueError('materialized source path collision: ' + logical)
        sources[key] = edge['toEntry']
    path_hashes = {}
    for logical, digest in sources:
        prior = path_hashes.setdefault(logical, set())
        prior.add(digest)
        if len(prior) > 1:
            raise ValueError('materialized source path collision: ' + logical)
    for (logical, digest), entry_id in sorted(sources.items()):
        entry = entries.get(entry_id)
        if entry is None or entry['sha256'] != digest:
            raise ValueError('edge does not bind exact source entry')
        payload, provenance = _payload(entry)
        if hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError('resolver hash mismatch')
        target = dest.joinpath(*_relative(logical).parts)
        parent = dest
        for part in _relative(logical).parts[:-1]:
            parent = parent / part
            _no_symlinks(parent)
            parent.mkdir(mode=0o700, exist_ok=True)
            parent.chmod(0o700)
        _no_symlinks(target)
        if target.exists():
            if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                raise ValueError('existing materialized file collision')
            continue
        with target.open('xb') as stream:
            stream.write(payload)
        target.chmod(0o444)
    return {'root': dest, 'fullS5Qualified': False,
            'files': len(path_hashes), 'sourceOnly': True}
