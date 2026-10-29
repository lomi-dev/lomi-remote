# Pure source constructor for independent reference states

**PREPARED_NOT_EXECUTED.** The new module and test source have not been run,
parsed by Node, hashed, or tested locally. Windows has not been contacted. The
Mac stream restriction and Windows single-owner/fresh-login barrier remain in
force. Future execution requires root coordination of a new isolated Windows
namespace and native Windows process ownership. These files do not launch PG,
Node, a shell, a service, network traffic or any other process.

Only `reference-build.mjs`, `reference-build.test.mjs` and this document are new.
The earlier eight preparation files, reviewed fourteen-file staging manifest,
candidate SQL, Auth source and NULL catalog files remain frozen.

## Input admission and output

`buildReferences(input)` accepts in-memory byte buffers only. It imports only
`node:crypto`. It has no filesystem, tar extraction, process, database, catalog,
environment or pin-filling API. Target catalog data is not an accepted input;
extra top-level/per-file names reject. The future Windows job must verify archive
acquisition, file provenance and process admission separately before supplying
these buffers. The constructor cannot prove archive membership from extracted
bytes alone; it verifies each exact named member against the independently pinned
closed FC66 receipt and its frozen-archive identity.

The accepted input fields are:

- `baselineReceipt`: exact closed FC66 runtime-proof JSON bytes.
- `baselineFiles`: the fixed 24 migrations, three ops files and original harness
  source, keyed by the exported `BASELINE_FILES` allowlist.
- `candidateManifest` and `candidateFiles`: the exact reviewed manifest and its
  fourteen named SQL/code/doc buffers. No mutable live Auth source is consulted.
- `catalogContract` and `helperContract`: the two original NULL-pin JSON buffers.
- `preparationManifest` and `preparationFiles`: the eight frozen preparation
  sources from plan `bcf93985-5a17-463a-aa2e-2446fb413e93`, including its admission
  lock, exact fixture grants and one-time ownership bootstrap.

Top-level manifest/receipt hashes are fixed in the module. Their per-file hashes
then admit every buffer used in SQL construction. Altering a manifest together
with a body cannot bypass those fixed admission hashes. Both original pin sets
must remain NULL. Definitions are correlated with their intended fixed signatures,
not selected by discovering what currently exists in a target database.

The result contains ordered `referenceOld.steps` and `referenceNew.steps` plus
source/statement SHA256 metadata. Each step is an exact SQL string with a source
identity. It is a transcript for a future independently admitted fixture runner,
not an execution result or a claim that SQL parses/permissions succeed. The
constructor does not concatenate files, normalize line endings, execute the
aggregate runtime harness, or call either NULL-pin operator.

## Reference ordering and fixed extraction

Both independent reference databases start from the exact 24 frozen migrations,
then the three frozen baseline ops scripts twice. The four synthetic baseline
roles must already have been created once in the owned cluster using the frozen
recipe. They are cluster-global; both references and the later target share
those role OIDs. No supplied database name or untrusted SQL identifier is
interpolated. The recipe's direct-SQL baseline replay still does not qualify a
Prisma migration ledger or any HTTP/BetterAuth/UI path.

Both references next install the four exact candidate SQL files, execute the
exact one-time fixture ownership bootstrap, then the frozen fixture grants.
That bootstrap precedes any helper seal and must never be reapplied after it.
Reference-old keeps the frozen 006/007/008 bodies and candidate helper bodies in
the intended old owner/ACL state. Its predecessor snapshots must byte-match the
function definitions extracted from the frozen matching migration files.

Reference-new adds **one indivisible transaction-group entry** containing BEGIN,
the global Auth lock, the exact once-only body-owner CREATE ROLE statement,
exactly two literal helper owner transitions, the fixed revoke/two-grant helper
ACL transition, exactly three literal root definitions, the exact inventory ACL
post-state and COMMIT. The group fixes one database and role and requires
`singleScript`, `sameSession`, `noInterleaving` and
`onAnyErrorRollbackAndStop`. Its single `sql` script is the only executable work
item; deeply frozen ordered `fragments` and their hashes are provenance metadata,
never independently schedulable steps. Only a separating newline joins the
unchanged fragment bytes. BEGIN, COMMIT, lock, role creation and transitions are
not separate outer-level entries.
The unchanged preparatory source files retain their own complete transactions,
initial ACL setup and locks. Repeated initial inventory grants in that admitted
setup are not standalone transition entries; the complete new-state transition
is the single grouped work item after preparation. Its fragment IDs never appear
as outer work items, and its new owner/root definition statements appear only
inside the group.
Those statements are extracted only from the hash-pinned reviewed operators;
the surrounding DO guards and NULL pin JSON are never emitted or executed.
The body owner must be absent before that atomic reference-only transition. An existing
role is a fixture-precondition failure, not permission to drop/repair it. After
both references are constructed, collect metadata with global roles stable.

The constructor does not interpret generic dynamic SQL. Root extraction admits
only `$literal0$`, `$literal1$`, `$literal2$`, exact expected leading function
names, one definition per literal and the known terminator. Missing, duplicate,
extra, wrongly named, modified or unexpected dynamic statements reject. Helper
extraction admits the exact two owner statements and fixed role/revoke/grant
statements and rejects extra recognized DDL or dynamic execution. Whole-file
admission remains mandatory before these low-level parsers are used to construct
a reference; exported parser helpers alone are not source authorization APIs.

The reviewed root manifest hashes the `CREATE FUNCTION` source form while the
reviewed operator emits `CREATE OR REPLACE FUNCTION`. Root approved a narrowly
scoped **manifest-hash-only** correlation adapter: require the exact known emitted
prefix, incrementally hash `CREATE FUNCTION` plus the untouched remainder, and
record both actual emitted-literal SHA256 and manifest CREATE-form SHA256 with
adapter version/reason. Emitted SQL is never rewritten. No other whitespace,
prefix or body adaptation is allowed. This is not a pg_get_functiondef rule;
future raw catalog bytes/owners/ACLs require separate exact equality checks.

## Future verification and remaining SQL work

The future runner must submit the entire group on one retained connection (for
example one psql script with ON_ERROR_STOP), check every error, roll back on that
same connection when possible and stop the stage. It must not run one psql process
per fragment, split a group across sessions or interleave another operation.
Source grouping does not prove a future runner obeys this requirement: actual
PostgreSQL qualification must show the lock spans all transitions and an induced
middle error leaves no partial owner/ACL/root state. Group failure cannot trigger
an individual-statement retry or a privilege-repair fallback.

The test source uses only fixed public file paths and Node standard-library
tests/assert/fs. It is written for eventual pinned Node22.22.3 on Windows. It
covers missing/duplicate/extra/wrong roots, body/prefix changes, helper transition
drift, whole-file admission, altered old snapshot/baseline, extra target/config
inputs, unchanged NULL pins, nonemission of guarded operators, transcript
ordering, and the single immutable same-session transaction group with no
transition fragments outside it. **No test result or syntax validation is claimed.** Root must coordinate
the exact Windows source namespace and per-file verification before any run.

The future driver must still own the Windows cluster/clients, install these
transcripts in separate reference DBs, prove temporary schema privileges revoked,
capture exact raw catalogs from both references, and compare independently
admitted expected records against the target. It must then prepare a reviewable
transition manifest and private derived pin copies without changing original
SQL bodies or NULL-pin sources. Only a later explicit review/admission permits
the measured operator transitions and their actual denial/idempotency tests.

Do not treat constructor output as a substitute for actual PostgreSQL owner,
default/column ACL, function language/security/config, trigger, dependency or
query-plan qualification. If installation or ALTER OWNER needs an unreviewed
privilege, stop at that stage. Lifecycle, TTL, cascades, races, populated unforced
plans and production/HTTP/BetterAuth/UI integration remain separate unrun work.
