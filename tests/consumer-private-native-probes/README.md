# Six benign private-pipe/GUC probes: source only, NOT RUN

This is a separate test-only controller proposed for root review and admission.
Import and default invocation start no child. No PostgreSQL, Node, native pipe,
selector, signal or tool-version execution was performed during preparation.
The default JSON lists all six cases NOT_RUN. An actual run requires an exact
root-reviewed admission tied to the new `freeze.json` hash; the actual owner
exit receipt remains a separate root responsibility.

The probes emit synthetic protocol text, not SQL results. Thirteen NOTICE-shaped
lines from Node establish only the byte-stream protocol shape. They execute
zero positive-auth SQL calls, create no credentials, and establish no authority,
authentication, full S5, S6 or S7 qualification. The known canary exists only as
scoped synthetic input in `emitter.cjs`, never as output evidence.

## Closed test-only seams

All eleven sources from correction freeze
`23412ec852b2112c2c0f074e1254471b0ff5e9617ba6593cacd728c497dbb6d3`
are copied byte-for-byte under `closed_dependencies/private_guardian_staging/`.
Production PrivateGuardian, Guardian24e396, streamsaf064 and parser4c424 remain
unchanged. `ProbeGuardian` adds only one pinned Node emitter with a fixed mode
enum, plus one pinned public database-creation script. It does not weaken the
production Node/private-SQL allowlists or replace positive-auth's source hash.

For the emitter, the subclass verifies the known script/argv, arms the existing
SinkRouting PIPE route before the factory, then calls the exact frozen base
Guardian `_launch`. The pinned Popen factory returns its actual handle directly;
base registers it under nonraising cancellation handlers before pipe setup or
any pumping. The adapter's exact RetainedHooks and pump then own read/reap
ordering. There is no independent Popen poll/wait, numeric PID signaling,
child driver, external timeout kill or unregistered process recovery.

Native anonymous provenance is checked by construction: the exact pinned
PrivateNative/SinkRouting/Popen binding selects PIPE before creation; the two
distinct retained Popen binary read handles are the exact descriptors registered
in the pinned anonymous-pipe adapter. Native observations require FIFO mode,
nonblocking mode and non-inheritable parent read ends. Only that adapter consumes
those descriptors; no duplication or second reader is created. FIFO mode alone
would not distinguish a named FIFO and is not used as that proof.

CPython's local pinned `subprocess.py` source confirms that the POSIX stdout and
stderr PIPE branches each call os.pipe (lines1748-1764), and Popen opens the
returned read ends in binary mode with the requested buffering (lines1029-1034).
Its SHA256 is `6628ffdd65c093a6c08cae01ffe82877d3ced515aac9e7be0cff16512c30a7d9`.
The prior selectors source pin is also rechecked. These are implementation
traces; actual kernel pipe/EOF/reap behavior remains NOT_RUN until root executes.

Every read requests at most 256 bytes through the unchanged adapter. The
observer retains only bounded counters and fixed booleans, never raw chunks,
exception text, repr, traceback, argv, descriptor identity or output hashes
in evidence. The parser sees each byte before evidence construction. Private
and server metadata log files must remain exactly empty by original inode
checks. Output canaries are never archived or searched into an allowlist.

## Six sequential cases

1. `valid`: Node emits the thirteen exact fixed markers, exits zero, and both
   pipes reach EOF. The pump must confirm retained reap before completion.
2. `malformed`: a fixed synthetic canary is invalid protocol. Generic failure,
   retained cleanup and empty metadata logs are required.
3. `trailing`: valid markers followed by that canary must fail generically and
   discard the partial marker summary.
4. `cancel-writer`: Node emits slowly. Only after a real nonempty read and an
   unreaped retained WNOWAIT observation showing it still live does the parent
   latch cancellation. Existing retained stop/reap machinery must finish it.
5. `eof-alive`: Node closes stdout and stderr but keeps its event loop alive.
   The parent must observe both EOFs while the retained child is still live;
   no parser completion is allowed before reap. A fixed two-second stream
   deadline produces generic failure and retained cleanup.
6. `private-guc`: fresh initdb, inherited file-cap/data admission, foreground
   PostgreSQL with DEVNULL from first spawn and every explicit private GUC.
   A single closed public script creates only lomi_derivative_fixture via
   postgres; its actual exit must be zero and raw stdout/stderr empty. The
   unchanged public GUC assertion then verifies effective settings on that empty
   database before any possible credential work. No application schema is
   needed. Normal retained postmaster exit0, pg_ctl stop0/status3, PID absence,
   socket emptiness and group/reap proof are required.

The database-creation seam permits only the pinned fixed script and exact
public verbose argv, before the private phase latch. Unknown scripts/argv,
source replacements, repeated emitter launch and arbitrary production entry
points remain rejected. Utilities use DEVNULL; GUC/setup output is public,
credential-free and required empty. No positive-auth SQL is launched.

## Bounds, ownership and publication

The parent interpreter must be pinned Python81c with `-I -S -B`, empty inherited
environment except the declared public environment keys, private owned0700
HOME/TMPDIR, PATH=/usr/bin:/bin and core dumps zero before any child. Accepted
Node5d9 and the unchanged 47-file PostgreSQL map give 49 tool pins. No acquisition,
version probe or network operation is part of the controller.

macOS framework Python may insert `__CF_USER_TEXT_ENCODING` even under env-i.
The root launcher must set this public marker explicitly to the ASCII string
`f'0x{os.getuid():X}:0x0:0x0'` computed from its current UID. The parent gate
permits that one platform key only with that exact value; different UID, case,
charset, padding, suffix, whitespace or other keys reject before any child.
The launcher constructs the constant rather than forwarding an ambient value.
The marker is a parent launch detail and is not inherited into Guardian's
separately constructed private child environment.

All six owners share the original outer monotonic start: work840,
qualification900, emergency cleanup960 are never renewed. Per-case work limits
are five seconds for Node and sixty for PG; acceptance additionally requires
actual elapsed case time <=15/120 seconds and aggregate <=300. EOF-alive's
stream deadline is two seconds. These are qualification bounds, not permission
to abandon an unresolved owner or externally kill a driver. Ownership uncertainty
retains the process even beyond an elapsed-time acceptance bound.

Use fresh short `/private/tmp/lpp-*` owned0700 work, check the Darwin socket path
byte limit before spawn and at least 2GiB free space before each case. The exact
reviewed resource policy installs inherited hard32MiB per-file caps with the
sole owner ignoring SIGXFSZ, preserves cleanup reservations, and admits default
16MiB WAL before foreground PG. Aggregate allocated/logical work is monitored
against 2GiB at most once per second and before/after cases; this is not a hard
filesystem quota. Resource/clock failures latch cancellation without raw errors.
All temporary work is credential-free and retained by plan.

Constructor failures call finish_owner before returning a fixed failure. Every
body/read/cancellation/timeout/GUC failure executes finish_owner in finally.
Summaries are built only after it returns, which requires resolved retained
ownership. The actual owner may remain in the inherited terminal-retention loop
forever if ownership cannot be proved closed. Pipe handles are not discarded.
No evidence is published from that unresolved owner. Raw errors are never
stringified into a receipt. The final result contains only closed protocol
fields, fixed case IDs, bounded counts and booleans, and the validated public
ownership metadata described below; the outer root exit record is separate.

After finish_owner, the controller revalidates the original owned0700 work and
socket directory device/inode/UID/mode, original owned0600 single-link marker
identity and exact bounded bytes, UUID runId and marker SHA256. Native work has
the closed `/private/tmp/lpp-XXXXXXXX` locator. It records those exact paths and
identities, the PG data identity captured after initdb, the exact postmaster PID
file path and its measured absence, and the exact socket path and measured
emptiness. A replaced marker, wrong ownership/mode, changed deadline, reappeared
PID file or socket rejects metadata with a fixed code. Root review must bind to
these exact paths and independently recheck the marker/identities and PID/socket
absence; no broad filesystem search is required or authorized.

The receipt records finite original start/work840/qualification900/cleanup960,
aggregate300, case start/end/measured elapsed, work/stream/actual case deadlines.
Every retained operation carries an ordinal, closed operation/process-role enum,
exact positive integer historical retained PID, exact integer exit code and
reaped/groupQuiet/foreground/forced booleans. These are retained owner records
observed after finish_owner; they describe group quiet at that owner's reap,
not present ownership of a PID that may subsequently be reused. They never
authorize a later kill or ownership inference from a receipt PID. PG acceptance
requires exactly initdb0, foreground PG0, status0, createDB0, GUC0, stop0, status3
in registration order, all retained and reaped/group quiet. A failed operation
can retain its validated public exit record while the case remains unqualified.
Malformed metadata never contributes a partial record or raw exception text.

## Pure validation and remaining private-controller work

`controller.test.py` uses the exact closed fake classes from the reviewed
31-test fixture, with fake process factory, clock, signals, pipes and selector.
The controller fake models initdb's owned0700 data directory before startup;
the eleven copied dependency sources remain unchanged. The original twenty
test bodies remain unchanged, with twelve additional public-metadata checks.
The environment correction preserves all thirty-two existing test bodies and
adds three fake-environment checks for the exact framework marker boundary.
It never invokes the native entry point. Native process/network/signal/library
operations are audited/rejected after CPython's ctypes bootstrap, and native
pipe entry points are replaced with rejecting functions. Fake provenance stays
false, so those tests cannot report an actual native-pipe or DEVNULL proof.
Source-only test receipts and copied sources do not admit execution.

The full eleven-call controller remains a separate task: freeze the complete
public schema/seal/grant registry, independently compare same-database catalog,
metadata and six-table rollback counts, prove connection closure and all original
resource/exit/deadline/cleanup gates. Synthetic generated token bytes may remain
in PostgreSQL WAL/data after ROLLBACK. Never archive/promote those contents as
evidence. After normal stop0/status3, all retained groups reaped and PID/socket
absence, a future private caller must separately verify marker/uid/inode-safe
disposal of its owned PRIVATE PG data after finish_owner and before qualified
publication, with no later g.cleanup call; otherwise retain an explicit
unqualified privacy gap. Do not alter Guardian's retained-work contract or touch
other fixtures/user directories. These six credential-free probes do not perform
that future disposal or any private SQL qualification.
