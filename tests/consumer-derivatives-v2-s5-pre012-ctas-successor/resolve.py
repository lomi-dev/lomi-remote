"""Read-only resolver for the pinned CTAS source inventory."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
INVENTORY = json.loads((HERE / 'source-inventory.json').read_bytes())


def resolve(entry_id):
    """Return (bytes, provenance path) from an exact-hash candidate."""
    matches = [entry for entry in INVENTORY['entries'] if entry['id'] == entry_id]
    if len(matches) != 1:
        raise KeyError('unknown or duplicate source inventory id')
    entry = matches[0]
    for relative in entry['candidates']:
        path = Path(relative)
        if path.is_absolute() or '..' in path.parts:
            continue
        candidate = ROOT / path
        if any(part.is_symlink() for part in (candidate, *candidate.parents)):
            continue
        try:
            payload = candidate.read_bytes()
        except OSError:
            continue
        if hashlib.sha256(payload).hexdigest() == entry['sha256']:
            return payload, relative
    raise FileNotFoundError('no exact pinned source candidate: ' + entry_id)
