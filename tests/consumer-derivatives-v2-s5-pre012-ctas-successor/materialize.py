"""Strict read-only materializer for the recursive historical lock view."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import os
import re
import stat

HERE = Path(__file__).resolve().parent
INVENTORY = json.loads((HERE / 'source-inventory.json').read_bytes())
ROOT = HERE.parents[1]
HISTORIC_CONSTRUCT = '7edfc912fbc079812ac2e35ace9cd2d56505d12c4ffd7f399e22be676759a3fd'
CURRENT_CONSTRUCT = 'b9ec75b1b593ce9ef94c72706e66ca10a847efac49a79c749424496eee19cf7c'
DESTINATION_PATTERN = re.compile(r'\.ctas-successor-view-[0-9a-f]{32}\Z')


def _safe_relative(value):
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in ('', '.', '..') for part in path.parts):
        raise ValueError('unsafe inventory path: ' + value)
    return path


def _check_no_symlink(path):
    path = Path(os.path.abspath(path))
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError('symlink in materialized source path')
    if path.resolve(strict=False) != path:
        raise ValueError('path resolution escaped lexical source path')


def _entry_map():
    entries = INVENTORY['entries']
    ids = [entry['id'] for entry in entries]
    if len(ids) != len(set(ids)):
        raise ValueError('duplicate source inventory entry id')
    return {entry['id']: entry for entry in entries}


def materialize(destination):
    """Write all recursive lock-edge files, then chmod files read-only.

    The destination must be a new UUID-named direct child of HERE. Historical
    construct.py is selected at its lock edge; current bytes are isolated under
    successor-inputs/. Path checks reject symlinks but are not race-proof if a
    concurrent writer can replace a checked directory component (TOCTOU).
    """
    entries = _entry_map()
    edge_keys = [(edge['fromLock'], edge['path'], edge['sha256'], edge['kind'])
                 for edge in INVENTORY['closureEdges']]
    if len(edge_keys) != len(set(edge_keys)):
        raise ValueError('duplicate lock edge')
    hashes_by_path = {}
    sources = {}
    for lock in INVENTORY['locks']:
        hashes_by_path.setdefault(lock['path'], set()).add(lock['sha256'])
        sources[(lock['path'], lock['sha256'])] = lock['entryId']
    for edge in INVENTORY['closureEdges']:
        _safe_relative(edge['path'])
        hashes_by_path.setdefault(edge['path'], set()).add(edge['sha256'])
        sources[(edge['path'], edge['sha256'])] = edge['toEntry']
    for edge in INVENTORY['sourceManifestEdges']:
        _safe_relative(edge['sourcePath'])
        hashes_by_path.setdefault(edge['sourcePath'], set()).add(edge['sourceSha256'])
        sources[(edge['sourcePath'], edge['sourceSha256'])] = edge['sourceEntryId']
    for proof in INVENTORY['proofManifests']:
        _safe_relative(proof['path'])
        hashes_by_path.setdefault(proof['path'], set()).add(proof['sha256'])
        sources[(proof['path'], proof['sha256'])] = proof['entryId']
    for path, hashes in hashes_by_path.items():
        if len(hashes) != 1:
            raise ValueError('lock-edge path collision: ' + path)

    historic = [entry for entry in INVENTORY['entries']
                if entry['logicalPath'] == 'tests/consumer-derivatives-v2-sealing/construct.py'
                and entry['sha256'] == HISTORIC_CONSTRUCT]
    current = entries.get('current-construct-b9ec')
    if len(historic) != 1 or current is None or current['sha256'] != CURRENT_CONSTRUCT:
        raise ValueError('historical/current constructor pin separation invalid')
    if historic[0]['logicalPath'] in hashes_by_path and hashes_by_path[historic[0]['logicalPath']] != {HISTORIC_CONSTRUCT}:
        raise ValueError('historical constructor lock-edge pin conflict')

    raw_dest = Path(destination)
    if '..' in raw_dest.parts or not raw_dest.is_absolute():
        raise ValueError('destination must be an absolute package-local path without traversal')
    dest = Path(os.path.abspath(raw_dest))
    _check_no_symlink(dest)
    if dest.parent != HERE or not DESTINATION_PATTERN.fullmatch(dest.name):
        raise ValueError('destination must be a UUID-named direct child of the package directory')
    if dest.exists():
        raise ValueError('destination must not already exist')
    dest.mkdir(mode=0o700)
    _check_no_symlink(dest)
    dest.chmod(0o700)
    written = {}
    for (logical, digest), entry_id in sorted(sources.items()):
        payload, provenance = _resolve(entry_id, entries)
        if hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError('resolver returned bytes outside lock pin')
        relative = _safe_relative(logical)
        target = dest.joinpath(*relative.parts)
        parent = target.parent
        current_parent = dest
        for part in relative.parts[:-1]:
            current_parent = current_parent / part
            _check_no_symlink(current_parent)
            current_parent.mkdir(mode=0o700, exist_ok=True)
            current_parent.chmod(0o700)
        _check_no_symlink(target)
        previous = written.get(logical)
        if previous is not None:
            if previous != digest:
                raise ValueError('materialization path hash collision: ' + logical)
            continue
        with target.open('xb') as stream:
            stream.write(payload)
        target.chmod(0o444)
        written[logical] = digest

    current_payload, current_source = _resolve(current['id'], entries)
    current_relative = _safe_relative('successor-inputs/tests/consumer-derivatives-v2-sealing/construct.py')
    current_target = dest.joinpath(*current_relative.parts)
    parent = dest
    for part in current_relative.parts[:-1]:
        parent = parent / part
        _check_no_symlink(parent)
        parent.mkdir(mode=0o700, exist_ok=True)
        parent.chmod(0o700)
    _check_no_symlink(current_target)
    if current_relative.as_posix() in written:
        raise ValueError('successor input collides with historical view')
    if hashlib.sha256(current_payload).hexdigest() != CURRENT_CONSTRUCT:
        raise ValueError('current construct pin mismatch')
    with current_target.open('xb') as stream:
        stream.write(current_payload)
    current_target.chmod(0o444)
    written[current_relative.as_posix()] = CURRENT_CONSTRUCT

    materialized_construct = dest / 'tests/consumer-derivatives-v2-sealing/construct.py'
    if hashlib.sha256(materialized_construct.read_bytes()).hexdigest() != HISTORIC_CONSTRUCT:
        raise ValueError('historical view did not select construct 7ed')
    if current_target == materialized_construct:
        raise ValueError('current source leaked into historical path')
    return {'root': dest, 'files': len(written), 'historicalConstructSha256': HISTORIC_CONSTRUCT,
            'currentConstructSha256': CURRENT_CONSTRUCT, 'currentConstructSource': current_source,
            'fullS5Qualified': False}


def _resolve(entry_id, entries):
    entry = entries.get(entry_id)
    if entry is None:
        raise KeyError('missing source inventory entry')
    for relative in entry['candidates']:
        path = _safe_relative(relative)
        candidate = ROOT.joinpath(*path.parts)
        _check_no_symlink(candidate)
        try:
            payload = candidate.read_bytes()
        except OSError:
            continue
        if hashlib.sha256(payload).hexdigest() == entry['sha256']:
            return payload, relative
    raise FileNotFoundError('no exact pinned candidate: ' + entry_id)
