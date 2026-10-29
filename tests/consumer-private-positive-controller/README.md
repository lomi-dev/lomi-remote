# Private positive-auth eleven-call controller: source only, NOT RUN

This separate staging namespace is a proposal for root review and a later
runtime appointment after the six benign pipe/GUC probes are accepted. No PG,
Node, native pipe, selector, process signal or SQL parser was executed here.
The default controller invocation starts no child and reports NOT_RUN. Actual
execution requires a root-reviewed admission tied to the complete new freeze.
An independent actual outer exit0/deadline receipt and root review remain
required even after a provisional eleven-call result. Full S5, S6 and S7 remain
unqualified. This does not add product routes, drivers or production grants.

## Trusted bootstrap prototype and staging status

`trusted_bootstrap.c` is a macOS C prototype that verifies `launcher.py` before
Python interprets it. Its unprivileged test build compiles and exercises the
same source against a temporary fixture; the test build accepts root-owned
system ancestors plus a current-user-owned test root. The production build
requires uid 0 for every traversed directory and trusted input. Fourteen focused
tests passed on macOS. This verifies the prototype's checks only: no bootstrap
or launcher was installed under `/Library`, no admission was created, and no
controller, PostgreSQL, or SQL was run.

The production bootstrap accepts only its fixed path with no extra arguments
and the controller's exact environment allowlist. It requires fixed `PATH`,
the explicit UID-bound CF marker, allowed locale/time-zone values, and absolute
`HOME`/`TMPDIR` directories that are no-follow traversed and owned mode 0700.
Unknown or duplicate environment keys are rejected, and only the validated
environment reaches Python. It walks the fixed trusted-root path using
directory fds and `O_NOFOLLOW`, rejects macOS extended ACLs on every traversed
directory and opened file, then opens `admission.json`, `freeze.json`,
`controller.py`, and `launcher.py` relative to that root. Each input must be a
single-link regular root-owned file with no write bits. It also no-follow checks
the fixed pinned interpreter path and its root-owned, non-group/world-writable
executable, rejecting extended ACLs there too. It checks the exact admission
keys and scope, hashes the raw freeze, controller, and launcher bytes, and
requires the unique `freeze.sourceSha256.controller.py` pin to match the
admission and exact controller bytes before calling Python 3.14. The admission
parser rejects duplicate/unknown keys and invalid JSON trailing commas. It rewinds and
preserves the same validated launcher descriptor across `execve`, passing it
as `/dev/fd/N` with `-I -S -B`. The bootstrap passes only the validated
environment; callers cannot supply unrecognized or malformed values.

The production build also validates the complete Python framework's strict
code signature against Python Software Foundation's Developer ID and checks
all architectures, nested code, and sealed resources. The current lab
framework fails this check (`codesign --verify --deep --strict` reports added
unsealed files such as `pip3.14` and documentation pages), so it is not a
runtime candidate. The unprivileged test build compiles this path but skips
signature validation to keep the temporary shim usable; it does not claim an
accepted installed Python runtime.

After Python starts, the authenticated `trusted_launcher.py` applies the
controller/freeze checks and requires the separate exact-key
`run-admission.json` before it can execute controller bytes. That per-run
native admission remains `NOT_GRANTED`. The bootstrap binary, fixed trusted
root, full project closure, source admission, and run admission are all
unstaged. The plan remains `SOURCE_ONLY_NOT_RUN`,
`nativeAdmission: NOT_GRANTED`, and `fullS5Qualified: false`; the prototype
test result does not authorize runtime execution or establish an installed
root trust boundary. The reviewed source rejects ACL-based write grants, binds
the controller digest to the freeze and bytes before Python starts, and rejects
trailing-comma admissions. A privileged installer must serialize interpreter
replacement with bootstrap use; tests still do not verify a root-installed
binary or runtime.

## Closed sources and public setup

The immutable c98 reference transcript is reused as SQL source, with SHA256
`df12fac4ab1e0a156c47354f7d33e3203f058e5c975b278953aaf060abe943a5`.
No fresh Node constructor is run. Pure preparation re-admits the original
constructor, archive28/candidate14/preparation8 inputs, old36/new37 source
provenance, every emitted SQL hash, 49 tool pins and the accepted reference
proof chain. Each old SQL step must equal its original admitted source bytes.
The new transition must match its pinned fragments. The four derived sealing
files and full correlation manifest are reconstructed using the unchanged
reviewed Python constructor and must equal the existing frozen copies exactly.
Original seventeen positive-auth inputs and the positive SQL/case plan remain
unchanged and are rechecked. `source-inputs.json` closes these public inputs;
the same complete source/tool hashes are checked before and after runtime.

`prepare.py` constructs a fixed registry of 46 SQL files and 134 ordered public
operations. One fresh cluster contains the fixture and two reference databases.
Each receives the exact twenty-four migrations, empty fixture-only Prisma
ledger, six baseline ops, approval-intent, whole012, authority core, typed
entrypoints, one-time ownership bootstrap and initial fixture ops. The separate
reference-new transition runs once in reference-new. All three databases must
match independently admitted old/old/new references before target sealing.
Only the target receives the exact derived helper/root seals followed by two
rounds of frozen database/remote/push/fixture ops; it must then match reference
new. No target data supplies expected authority. The source-only ledger is not
a Prisma migration execution or migration-history qualification.

Before any credential exists, these exact scripts use the original bounded
public Guardian result/log path. The unchanged reviewed Python authority
module parses whole27 function/catalog and full metadata rows and applies its
existing cross-database OID/generated-trigger rules against the independent
frozen references. Raw public results are consumed only in this phase and
never become new snapshot evidence. Each original stdout/stderr inode and raw
digest must pass the unchanged `retire_result` operation, including its release
acknowledgement, before the schedule advances. Compact receipts contain only
fixed script IDs, public source hashes, exits and retirement/equality booleans.
Retirement failure prevents any credential phase. Failed public setup may
retain only credential-free public work and remains unqualified.

All eleven reviewed PrivateGuardian sources are exact copies, including
Guardian24e396, streamsaf064 and parser4c424. `source-original/` saves all eleven
before the separate subclass adds its registry/wrapper seams; production
sources are not edited. The new subclass accepts only the next exact script,
bytes, database, phase and argv. It rejects generic psql, Node, version calls,
arbitrary SQL/hash arguments, public retries after latching and a replaced
wrapper/include before the process factory. Unknown output is never used to
create a diagnostic allowlist.

## Private phase and silent same-database postconditions

After all public results are retired, the unchanged fixed GUC DO gate requires
actual retained exit0 and exact empty raw stdout/stderr before latching. Its
empty result is also retired. Foreground PostgreSQL stdout/stderr are DEVNULL
from its first spawn, with every original private logging GUC. Server settings
are not claimed verified during source preparation.

Exactly one fixed private argv runs `--file private-positive-driver.sql` with
the reviewed no-password/no-echo/terse/no-context client flags. The wrapper
contains exactly one literal `\ir positive-auth.sql`; both files and ancestry
are source-pinned. The included SQL remains byte-identical at SHA256
`1fe715e2245f05b372cb2dd8904d3dee08aeed893ae75f8f367a996df1c375c8`.
Its thirteen original psql filename/line NOTICE envelopes remain unchanged.

The wrapper creates a session TEMP view of the unchanged six catalog and ten
metadata SELECTs plus six counts, and commits a TEMP bytea baseline before the
included BEGIN. JSONB rows are collected in a fixed C-order representation;
no metadata field or raw UTF8 function-definition hex is removed. The six
count values must all be pristine zero, with exactly 27 functions. TEMP objects
are outside public and survive the included ROLLBACK. After the unchanged
eleven calls, RESET/ROLLBACK and thirteenth marker, the wrapper asserts current
and session role e2_owner, cleared local credential-hash GUC and bidirectional
bytea EXCEPT equality for all seventeen sections in the same database. It then
drops its TEMP objects. No snapshot, row, token, credential hash or extra NOTICE
is emitted. A failed postcheck exits nonzero under ON_ERROR_STOP; thirteen
markers followed by nonzero cannot complete the pinned parser.

These are in-server raw byte comparisons with no retained raw snapshots.
The root does not compare stored private before/after snapshots. Python/source
review and later actual PG execution must still validate the whole closed
query and its empty-output semantics; no SQL parse/runtime success is claimed.

The new pipe observer wraps the exact reviewed AnonymousPipeIO/RetainedHooks/
pump. Routing selects binary anonymous PIPE before Popen, whose actual retained
handle returns to frozen base registration before fallible setup. Native
provenance requires the exact pinned factory/routing binding and exclusive
distinct retained read descriptors, FIFO/nonblocking/non-inheritable properties.
Every read is <=256 bytes; only the pinned per-byte closed grammar sees output.
No raw private chunks, MESSAGE/DETAIL/CONTEXT/rows, argv, error repr or traceback
reach receipts. Completion requires actual EOF on both pipes and retained
WNOWAIT/group-quiet/actual reap, followed by literal cancel/deadline checks.
There is no independent wait/poll, numeric PID signal or process driver.

## Cleanup, privacy disposal and receipts

All constructor/body/read/cancel/deadline/recording failures run finish_owner.
The original Guardian may retain an unresolved owner indefinitely; elapsed
acceptance limits never authorize dropping a child or external timeout kill.
Only after finish_owner returns can public summaries or disposal be attempted.
Even a receipt-reconciliation fault still attempts the separate privacy gate.

Before credentials, `disposal.acquire` binds the original owned0700 work/data,
ancestor device/inodes, original owned0600 single-link Guardian marker and UUID,
socket identity, and a new owned0600 PG-data marker carrying public identities.
After cleanup it independently requires normal PG exit0, exact startup status0,
stop0/status3, all retained children reaped/group quiet, PID-file absence, empty
original socket, same marker bytes/inodes/UID/modes and original deadlines.
It preflights only file metadata under the original data fd, rejecting links,
nonregular objects, different devices, changed roots, more than 32768 entries,
depth32 or 2GiB. It never reads PG file contents. It then unlinks only those
owned data entries using no-follow directory-relative fds and identity checks,
removes the original data root and verifies absence plus the retained work
marker. Work/public proof metadata remain. This is logical unlink disposal,
not a forensic secure-erase claim. Exclusive private-work ownership and no
remaining writer after group/reap proof are explicit prerequisites.

No PG data/WAL archive is ever made: generated synthetic token bytes may remain
physically in WAL after ROLLBACK. A failed or partial disposal, changed marker,
remaining PID/socket, expired bound or malformed metadata keeps qualification
false with a fixed privacy-gap code. The attempt cannot be renewed or bless a
new root. No other fixture/user directory is deleted. The caller makes no
Guardian cleanup/finish call after disposal; the subclass rejects both.

Public receipts identify exact owned paths, marker/runId/hash and inode/UID
metadata, original monotonic start/840/900/960/elapsed values, and a bounded
record per retained operation with fixed enum, process role, historical exact
positive PID, exact exit and reap/group-quiet facts. A PID describes only the
owned reap observation and never authorizes a later kill/current ownership
inference; PIDs can be reused. Root must bind exact paths/identities/marker and
independently recheck socket/data/PID absence without a filesystem search.

## Bounds and root runtime admission plan

Use the source-frozen entry point with pinned Python81c `-I -S -B`; private
owned0700 HOME/TMPDIR, empty inherited environment except the explicit allowed
locale/path fields and the deterministic optional macOS CF marker. Root sets
`__CF_USER_TEXT_ENCODING=f'0x{os.getuid():X}:0x0:0x0'` explicitly and never forwards
an ambient value. Private child environment is constructed independently.
Core0 and inherited hard32MiB per-file limits precede any child, with original
shared512MiB log reservations/128MiB cleanup reserve, 256MiB compact store,
default16MiB WAL admission, >=2GiB free floor and monitored2GiB owned work.
Native libraries/tools are the unchanged accepted47PG+Python+Node map; no Node
is executed by this controller. All statements remain socket-only max2.

One original monotonic start controls work840/qualification900/cleanup960.
The private client is further bounded by 60 seconds and the original840 end.
No bound is reset by setup, private phase, cleanup, disposal or final hashes.
The monitored clock keeps the cleanup reserve available after work ends.
Final source hashes, resource facts and receipt construction must remain under
the original900 qualification bound. The root separately retains actual outer
exit0 and verifies the completion receipt/source pins and cleanup/privacy
evidence. It admits no full S5 or broader populated/crypto/S6/S7 behavior.

Pure tests use retained fake children and synthetic owned files only. They
cannot claim actual eleven SQL calls, effective private GUCs, native pipes,
in-server comparison or authentication. Failed canary, nonzero-after-markers,
reference drift, retirement refusal, wrapper replacement and disposal/metadata
failures exercise the gates; the audit rejects any process/network/pipe/signal
attempt. Actual six-probe acceptance and this new source review/admission are
still outstanding runtime prerequisites.
