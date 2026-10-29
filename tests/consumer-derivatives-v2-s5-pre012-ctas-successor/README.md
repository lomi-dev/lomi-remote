# CTAS S5 recursive source inventory

This source-only package walks the hash-pinned `inputs.lock.json` graph from
the four pre-012 CTAS cases through pre012-extended, pre012, operator-faults,
owner-faults, its qualification-source lock, and sealing. It records every
lock edge and each source hash declared by the three freeze manifests, plus
the two preparation records that bind the CTAS freeze to its root lock. Every
source resolves from an exact live path or an artifact snapshot; the unresolved
list is empty. The CTAS freeze is explicitly bound
through the artifact preparation records to the exact CTAS root lock.

The recursive graph contains 8 locks and 2,466 lock edges. The inventory has
5 proof-manifest documents, 2,013 unique source entries, and 215 explicit
source-manifest edges. Sealing's
historical `construct.py` (`7edfc912…`), `s5.py`, and `sealing.test.py` resolve
from the exact sealing preparation snapshot. The current mutable
`construct.py` (`b9ec75b1…`) is a separate pin.

The strict temporary materializer writes a historical source view from exact
resolver bytes, selects `7edfc912…` at its logical path, and stores `b9ec75b1…`
only under `successor-inputs/`. It accepts only a new UUID-named direct child
of the package directory and rejects path traversal, symlinks, duplicate edges,
and logical-path hash collisions. Its temporary root and child directories are
mode `0700`; materialized files are read-only. Path checks are not race-proof
against a concurrent writer replacing directory components (TOCTOU).

The no-child pure test invokes only the historical extended-S5
`dependencies()` function against that view. It denies every `socket.*` event,
process exec/spawn/fork events, and unscoped descriptor mutations. Path mutation
events, including truncate, utime, and chflags, are allowed only below the exact
UUID-named temporary test root, which is cleaned afterward. The test performs
source/hash/import validation only: zero CTAS cases execute, no SQL runs, and
`fullS5Qualified` remains false. This does not establish database behavior or
runtime admission.

## Supervised runner source inventory addendum

`runner-source-inventory.json` records the separate four-case supervised
runner lock graph: 14 locks, 3,039 exact edges, 2,227 logical-path/hash
entries, and no unresolved source bytes. Its read-only graph test derives
path/hash collisions from reachable edges and compares them with the inventory.
It denies process, network, and filesystem mutation events.

The separate runner view was materialized from exact candidates with the live
recording source at 320f…. Importing its pinned entrypoint and calling only
`dependencies()` passed under a no-child/network audit and temporary-root-only
write scope. The pinned admission source routes its historical helper check
for 14312… through the immutable archive. The test also passed historical
extended `dependencies()`, `load_constructor()` with construct hash 7edfc912…,
and `constructor.load_admitted()` in both runner view B and historical view A.

For constructor admission, the test adds only files named by the exact sealing
constructor lock and its pinned S0-S4 preparation/admission locks, checking
all source hashes before writing them read-only into each temporary view. The
existing materializer alone omitted some of those named proof inputs; no
historical source or lock was edited. `main()` was not called. This source-only
preflight does not establish runtime admission: zero CTAS cases ran, no SQL or
runtime was invoked, and `fullS5Qualified` remains false.

## Private runtime-view preparation

`runtime-view.py` reads the explicit alias plan and base toolchain lock, then
validates the 14 source symlink relations and each target hash in both the
source toolchain and an existing UUID-named `.ctas-runner-view-*` package child.
It adds only those relative library symlinks and changes the four pinned
Postgres executables to mode `0555`. It also verifies the full
`share/postgresql` tree against `postgres-share-manifest.json`, whose SHA-256
is pinned in the helper. The closure includes 1,027 files, 26 directories,
and 875 relative symlinks. Files use mode `0444`, directories use `0700`, and
links preserve their exact relative targets. Existing base-lock initdb files
must match the manifest. It never runs executables. The focused
`runtime-view.test.py` checks tree closure and rejects altered source entries
and destination collisions without native execution or SQL.
