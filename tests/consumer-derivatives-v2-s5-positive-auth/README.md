# Legitimate direct-principal positive fixture: source only

`positive-auth.sql` is prepared SQL, not an executed qualification. Full S5 is
false; this directory supplies no driver or runtime admission. Do not invoke it
through any earlier `f.sql`, psql raw-output wrapper or controller. Those paths
were approved only for schema-only payloads and can retain credentials on error.

The future prerequisite is the exact accepted v2 target after both derived
helper/root seals, final frozen ops plus fixture grants, and an independent
exact catalog/metadata comparison. The source freeze binds the admitted derived
operators, source contracts, reference captures and accepted review receipts.
It does not execute seals, refill original pins, grant privileges or normalize
definitions. A fresh appointment and a separately reviewed credential-safe
recorder/integration are required before running this SQL.

Setup runs as `lomi_runtime` and inserts an active user, opaque ASCII browser
session, browser metadata, epoch-one identity, web binding and matching direct
consumer authorization in foreign-key order. Identity creation uses only the
permitted `INSERT("userId")`; its generated UUID/epoch are returned by ordinary
INSERT. No owner insertion bypass, disabled guard, added grant, repair or fake
consent is used. This matches the direct browser shape in auth-app's existing
consumer-authority/inventory runtime fixtures, without invoking HTTP or Prisma.
One millisecond expiry captured from the database clock plus five minutes is
reused as parent UTC timestamp, consumer timestamptz and exact assertion ms.
All constraints are forced immediate after setup. The global transaction lock
is acquired before inserts and the unchanged guards also acquire it normally.

The actual synthetic token is generated inside the setup DO block, inserted
into the ordinary session row, hashed as SHA256 of its UTF8 bytes, and cleared
from the variable. It is never a SQL literal, argv value, GUC or result row.
Local GUCs contain only fixture identifiers, expiry and the needed hash. Those
values are still private and must not be logged. Expected recipient and
inventory JSON are constructed from independently chosen fixture values and
the ordinary identity default, never from a tested function's returned value.
An empty host list is legitimate because this new account has no hosts.

Each role switch uses `SET SESSION AUTHORIZATION`, asserting BOTH session_user
and current_user. The initial authenticated fixture identity must be e2_owner;
its ability to switch to NOLOGIN inventory/pairing owners does not make their
actual calls execute as superuser. Original exact-role/membership admission
remains mandatory. The scalar INVOKER is tested directly as inventory owner;
the sealed scalar/recipient roots as pairing owner; the typed inventory API as
remote API. The latter genuinely reaches the third sealed inventory root and
typed assertion guard. Three wrong-hash paths flip one byte of the real hash,
require exact SQLSTATE28000/message `actual credential required`, and then
repeat the valid invocation. There are eleven declared call checks, all NOT_RUN.

The outer transaction always ends with ROLLBACK; the final fixed marker checks
the original e2_owner identity and disappearance of the local credential hash.
A future parent must independently capture exact catalog/metadata and six-table
row counts before/after (user, session, session_metadata, remote_account_identity,
remote_session_binding, consumer_authorization), require equality in the same
private database, and require connection closure/positive owned PG cleanup.
Rollback markers alone do not prove those conditions. Failure must close the
session and positively clean the owned fixture; no revoke-and-bless recovery.

## Required future privacy boundary

`recorder.py` is a pure in-memory source-only recorder and is not integrated or
approved for runtime use. It consumes already captured bytes, accepts only the
closed parser protocol, and returns only the exact allowlist of thirteen fixed
NOTICE markers, a fixed stage identifier, a canonical five-character SQLSTATE,
and exit/deadline/cleanup facts. Failure envelopes are fixed
`positive-auth:<stage>:<SQLSTATE>` strings for initial-identity, setup-runtime,
principal-runtime, scalar-group, roots-group, typed-group, or rollback.
Unknown, oversized or malformed output becomes a fixed generic failure with
no retained diagnostics. This is defense in depth, not a complete redactor:
PostgreSQL can still emit CONTEXT, source queries, failing-row DETAIL, uncaught
declaration or connection errors, and server diagnostics outside those handlers.

Pure validation only:
`python3 -I -S -B tests/consumer-derivatives-v2-s5-positive-auth/recorder.test.py`

Any future integration must never archive raw stdout/stderr, DB DETAIL/HINT/CONTEXT,
query text, error MESSAGE outside that exact envelope, result rows, GUC values,
token/hash/IDs, or unknown diagnostics. Unknown/oversized/malformed output is a
closed generic failure; discard the raw bytes and do not include them in an
exception, manifest or traceback. Use no SQL echo, statement/error logging,
server log persistence, or client history that can retain payload. Explicitly
review PostgreSQL server diagnostic settings as well as the client recorder.
Do not derive an allowlist by observing secret-bearing output. Completion still
requires independently retained controller exit0, original deadline, exact
source/tool gates, rollback comparison and positive cleanup; manifest alone
cannot admit this group.

No SQL parse/runtime/grant success is claimed. Remaining real uncertainties are
the actual runtime INSERT/trigger privilege chain and sealed calls under the
exact final grants, and the runtime agreement with these independently traced
return contracts. A grant failure stops the future appointment without an
owner bypass. Populated host/pair/channel operations, derivative issuance,
canonical crypto, lifecycle/planner/concurrency, S6/S7, HTTP/BetterAuth/Prisma
and production remain NOT_RUN. This fixture requires no window/proof for the
direct principal checks and does not qualify those separate protocols.
