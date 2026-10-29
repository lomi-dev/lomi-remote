# Staged private Guardian adapter — source only, NOT NATIVE-INTEGRATED

This namespace composes byte-identical frozen Guardian, stream and parser
sources. It changes none of their reviewed APIs or files. The only supported
outer driver is `run_appointment(...)`; it creates the adapter through `__new__`
and always calls `finish_owner()` from `finally`, including constructor,
registration, pipe setup, pump, caller recording and cancellation failures.
The actual owner may remain in the inherited terminal-retention loop forever
when ownership cannot be proved closed. An incomplete constructor never starts
a child; partial private work is retained without claiming cleanup proof.

## Source gate and phases

Before installing handlers or spawning, the outer driver verifies the original
17-input source manifest and every pinned input, including both admitted
reference catalog/metadata captures. Source hashing uses bounded 64KiB chunks
with a 64MiB per-source ceiling. This is a read-only source gate, not a live
catalog comparison or grant/runtime admission. Pass the original project root
as `source_root` when running a frozen copy outside this source tree.

The public phase permits only the exact pinned copies of
`fixture-ownership-bootstrap.sql`, `fixture-ops.sql` and
`verify-private-policy.sql`. No caller-supplied SQL/hash/argv can extend this
registry. The inherited psql command is accepted only when database, socket,
user, verbose flags, path and actual source hash match that closed registry.
Its stdout contract is exact per script: the bootstrap's single advisory-lock
SELECT produces one LF (`"\n"`); ops and GUC produce the empty string. Stderr
must always be empty. Missing/extra blank lines and all other output fail;
no whitespace stripping or output normalization broadens these contracts.
The inherited result reader normalizes newlines, so the adapter also requires
its raw stdout/stderr SHA256 fields to match the exact expected bytes. CRLF or
a bare CR cannot substitute for the bootstrap's single LF.
All unknown SQL, Node commands, versions and arbitrary psql argv are rejected
before the process factory. These scripts are synthetic public schema or fixed
GUC assertions and create no credentials.

After the existing owner proves the foreground server ready and retains its
PID/data/socket identity, `verify_private_policy()` runs the fixed public DO
through `base.Guardian.psql/result`. The query asserts all eleven private server
logging settings, UTF8 encoding and both e2_owner identities. It emits no rows,
NOTICEs, or credential material. Latching requires actual retained exit zero,
quiet group/reap, complete evidence, empty stdout AND stderr, unchanged source
hash, a fresh original-budget checkpoint, and a reverified owned server identity.
Wrong GUCs, a missing exit, any output, or a replaced script fail closed.

This public path may retain only public schema/GUC diagnostics before any token
generation. After successful verification the phase latches `private-ready`;
public SQL is rejected permanently, including another GUC attempt. A public
schema or policy failure also permanently fails the phase. There is no repair,
grant bypass, fallback redactor, or retry into a new owner/deadline.

## Private launch and retained ownership

`launch_private_sql()` permits one exact pinned `positive-auth.sql` invocation.
The fixed argv contains `-X --no-password -qAt`, ON_ERROR_STOP=1,
VERBOSITY=terse, SHOW_CONTEXT=never, ECHO=none, ECHO_HIDDEN=off, the owned private
socket/port/database/user, and `--file positive-auth.sql`. The SQL and thirteen
marker parser are unchanged. It does not manufacture NOTICEs for the public
GUC check and does not weaken the stream pump's exact parser-type check.

`PrivateNative` applies routing BEFORE Popen: the exact private client gets
binary unbuffered anonymous PIPE stdout/stderr; foreground PostgreSQL gets
DEVNULL from creation; approved initdb and pg_ctl status/stop utilities also get
DEVNULL. The public pre-token SQL path alone uses base's bounded metadata log
pair. Base `_launch` may create empty private/server log metadata files, but no
private or server output descriptor ever points to them. The factory directly
returns the actual Popen handle, with no fallible post-factory setup before
base `_launch` registers it. Nonraising cancellation handlers remain inherited.
Registration-close failure still leaves the handle in base's retained list.

Only after registration does the adapter construct the anonymous-pipe backend
and call the pinned pump. The pump's read size remains 256 bytes; stdout must
be empty and stderr must match the exact thirteen-marker grammar. Its hooks
prove exact retained record identity and delegate WNOWAIT/group inspection,
actual reaping and stop escalation to existing Guardian `_finish`/`_stop`.
There is no independent Popen poll/wait, numeric PID signaling, renewed timer,
ownership transfer or child removal. Cancel/fault handoff retains the child for
the mandatory outer `finish_owner`. Pipe objects close only after that inherited
owner has returned with ownership resolved; resource cleanup faults remain
unqualified. Unresolved native ownership never
returns and does not close/discard live handles.

Original work840, qualification900, emergency cleanup960, child60, max2
connections, socket-only settings and all original server timeout settings are
preserved. Every private logging GUC is appended explicitly to foreground argv.
Inherited environment starts closed; private UTF8/locale/no-history policy is
added without reading ambient PGOPTIONS, PGPASSWORD, service files or shell
startup. No credential belongs in argv or environment.

The public raw `result`, arbitrary `psql`, Node and version entry points are
disabled on this adapter. `AppointmentResult.evidence()` contains only a fixed
stage, the closed stream result, cleanup and owner-eligibility booleans, and
`full_s5_qualified=False`. `owner_qualification_eligible` describes only the
inherited owner's budget/cleanup latch; it is not SQL or runtime qualification.
Public base cleanup error strings are reduced to fixed failure identifiers
before returning. Raw exception strings, output chunks and tracebacks are never
added to the appointment result. Callback code is trusted and must not log them.

## Explicit remaining controller and native gaps

The two schema scripts are only a small closed registry, not the full target
construction sequence. The admitted target migrations, derived helper/root
seals, final frozen ops/grants and synthetic public schema prefix must first be
materialized as a separately frozen known-public script registry. Do not admit
arbitrary generated SQL or reroute the original credential-bearing raw wrapper.

The actual controller must compare exact same-database catalog AND metadata to
the accepted target/reference before token generation, capture the baseline
counts of public.user, session, session_metadata, remote_account_identity,
remote_session_binding and consumer_authorization, and compare the same
catalog/metadata/counts after positive-auth's ROLLBACK. It must independently
prove connection closure, marked foreground PG's normal stop/status/absence,
resource/file admission, actual outer exit zero and cleanup, while preserving
the eleven declared call checks. The adapter does not invent these receipts.
`source-admission-plan.json` makes those required remaining gates explicit.
Do not claim completion from the rollback NOTICE or stream result alone.

No Popen, PostgreSQL, Node, native pipe, native selector, tool-version, signal,
native cleanup or eleven-call execution occurs in these tests. Real launch
registration, anonymous-pipe EOF/readiness, SIGCHLD/cancellation, private server
routing, GUC effectiveness, resource limits and owner retention require separate
small native probes and independent root admission. No such admission is granted
by this staged source or its pure receipt. Existing Guardian, four probes,
supervised fixture, stream seam and parser freezes remain untouched.

## Pure tests

Run `private_guardian.test.py` only with pinned Python 3.14.7 `-I -S -B`, empty
inherited environment, private 0700 HOME/TMPDIR. All process factories, clock,
signals, pipe data and selector I/O are fake; tools are inert text fixtures.
The audit gate rejects child/network/native signal/library operations after
CPython's own ctypes bootstrap. Native pipe calls are replaced with rejecting
functions. Tests assert routing before the fake factory, registration before
pump/cancellation, retained reap/group checks, exact argv and deadlines, source
replacements, simulated wrong GUC/nonempty/no-exit rejection, post-latch public
rejection, canary isolation, and cleanup across constructor/registration/pump/
recording failures. Fake GUC success does not verify an actual server setting.
