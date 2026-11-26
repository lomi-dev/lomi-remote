#!/bin/bash
# Verifies the vendored relay frame vectors against the auth-app original and the recorded hash.
# AUTH_APP_DIR defaults to ../auth-app next to the repo checkout parent (override for worktrees).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOCAL="$ROOT/crates/lomi-remote-core/test-vectors/relay-frames.v1.json"
ORIG="${AUTH_APP_DIR:-$ROOT/../auth-app}/test-vectors/relay-frames.v1.json"
sum() { shasum -a 256 "$1" | cut -d' ' -f1; }
want="$(grep -o 'SHA-256: `[0-9a-f]*`' "$ROOT/crates/lomi-remote-core/test-vectors/PROVENANCE.md" | grep -o '[0-9a-f]\{64\}')"
[ "$(sum "$LOCAL")" = "$want" ] || { echo "vectors differ from PROVENANCE.md hash" >&2; exit 1; }
[ -f "$ORIG" ] || { echo "auth-app vectors not found at $ORIG (set AUTH_APP_DIR)" >&2; exit 1; }
cmp -s "$LOCAL" "$ORIG" || { echo "vectors differ from $ORIG" >&2; exit 1; }
echo "relay vectors match auth-app ($want)"
