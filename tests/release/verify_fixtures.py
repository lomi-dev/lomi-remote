"""Verify vendored public test bytes against the reviewed provenance manifest."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
manifest = json.loads((root / "fixtures/provenance.json").read_text())
for entry in manifest["files"]:
    actual = hashlib.sha256((root / entry["path"]).read_bytes()).hexdigest()
    if actual != entry["sha256"]:
        raise SystemExit(f"fixture digest mismatch: {entry['path']}")
print(f"Verified {len(manifest['files'])} fixture/license SHA-256 digests")
