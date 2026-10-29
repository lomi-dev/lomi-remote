# Private stream adapter: source only, NOT INTEGRATED

`streams.py` is a separately reviewable adapter for one already-registered,
retained client child and its two anonymous output pipes. It does not spawn,
signal by PID, reap independently, write raw logs, or modify Guardian. The
byte-identical parser under `closed_dependencies/` is pinned to SHA256
`4c4248088591e64f95008758682967b6e1e39c645609a769497f06b613d53328`.
Import verifies this dependency before loading it. Hash-gate this adapter and
its dependency from the frozen source receipt before any private workload.

## Contract

Call `pump(owner, retained_child, pipe_io, new_parser(), end=absolute_deadline,
clock=monotonic_callback, cancelled=literal_bool_callback)` inside the owning
controller's outer `try/finally`. That controller must retain the exact child
record and perform its final owned cleanup in `finally`, for every result.
Ownership never transfers to this function. No callback may log raw diagnostics,
raise asynchronously in a spawn/registration seam, block without a bound, or
release the retained child on failure.

The owner supplies these hooks:

- `retains(child)` returns literal True only for the same registered record,
  including after reaping; preserve the record for the final ownership audit.
- `reap_if_ready(child)` returns None while not safely reapable. Return an
  exact integer exit code only after the existing owner proves retained
  identity, quiet owned group, and actual reap, updating its retained record.
  Do not use numeric PID lookup, an exit marker, or an unreaped peek as proof.
  This callback must be nonblocking/bounded; it is never called after it
  reports the reap.
- `request_stop(child)` requests cancellation through the existing retained
  ownership machinery without removing the record. It must be idempotent if
  reaped; final bounded termination/reap/resource cleanup remains the caller's
  obligation, including if this hook itself fails.

`AnonymousPipeIO(stdout_fd, stderr_fd)` configures two exclusive pipe read
descriptors as nonblocking and registers read readiness with DefaultSelector.
The owner guarantees anonymous provenance, no concurrent reads/close/reuse,
and no inherited duplicate read handles. FIFO mode rejects regular files but
does not distinguish a named FIFO. This adapter owns only the selector; it
never closes pipe descriptors. The caller closes its exclusive read ends in
final cleanup. Blocking mode remains nonblocking until caller closure.

The loop requests at most 256 bytes from each ready pipe per tick, processes
both fairly, and holds only the current chunk. It feeds the pinned parser
immediately; its per-byte closed grammar accepts no arbitrary raw buffer.
No raw spool, accumulated string, output digest, output artifact, exception
message, exception type, or traceback enters evidence. Readiness is advisory:
BlockingIOError/InterruptedError from a read retries on a later tick. Each
selector wait is at most 50ms and never exceeds the remaining deadline.
Cancellation is checked between ticks. Exact booleans and finite clock/deadline
numbers are required; hostile object conversions are never invoked.

Only after empty-byte EOF from BOTH actual pipe reads AND a confirmed retained
reap may the adapter call parser.finish(actual_exit, deadline=False,
cancelled=False). Validated stage/SQLSTATE envelopes remain private parser
state until this gate. An EOF without reap, reap without EOF, cancellation,
deadline, malformed protocol, oversized/non-byte backend read, selector/read
fault, or ownership fault cannot qualify. Failure clears parser state and
returns a fixed generic diagnostic. Stop is requested if ownership was admitted;
failed requests never authorize releasing the child. A selector-close failure
also invalidates an otherwise complete result.

Only `StreamResult.evidence()` is suitable for persistence. It contains a fixed
outcome, the parser's closed six-field diagnostic, EOF/reap/stop booleans, and
`cleanup_required=True`. No descriptor, child, handle, argv, path, payload,
exception, PID, or callback enters the result. Even `stream-finished` plus
diagnostic `complete` does not establish the independent database postconditions,
server policy, connection closure, or positive resource cleanup.

## Wiring plan and remaining native gap

The current Guardian raw-file launch/result APIs remain unsuitable for this
fixture. No adapter from those APIs is provided and no existing qualification
or native probe is changed. A future separately reviewed launch seam must
register the actual retained client before cancellation can strand it, install
anonymous PIPE endpoints from spawn without an intervening raw-file path, and
provide the hooks above using Guardian's existing identity/group/reap rules.
It must call this pump synchronously and retain ownership across every handoff.

The foreground PostgreSQL process must have stdout/stderr routed to DEVNULL
from spawn, with no pg_ctl/postgres.log, and use every explicit SERVER_SETTINGS
from the pinned parser policy. Before token generation, independently verify
effective private GUCs and binary/source admission with a separate closed
credential-free probe. Apply CLIENT_FLAGS, empty inherited environment,
private HOME/socket/TMPDIR, no history/password prompt, and controlled
`--file positive-auth.sql` filename/line prefixes. This module does not perform
or claim any of those launch/server checks. Preserve the original outer deadline,
cleanup reserve, resource and concurrency limits and all eleven declared
positive-auth call checks. Exact same-database catalog/metadata and six-table
counts, connection closure, and positive owned cleanup still gate acceptance.

Native pipe readiness, EOF behavior, actual retained reaping, launch registration,
SIGCHLD/cancellation handling, server routing, effective GUC verification, and
the eleven actual private SQL checks remain **NOT INTEGRATED / NOT RUN**.

## Pure validation and local implementation trace

`streams.test.py` uses fake descriptor numbers, fake selector/read callbacks,
synthetic canaries, and a fake retained owner. No native selector, native pipe,
child, server, Node process, or network client is exercised. It audits/rejects
child/network attempts and replaces native pipe I/O entry points with rejecting
functions, except explicit fake replacements in the adapter wiring test.
Run only the pinned Python 3.14.7 with `-I -S -B`, empty inherited environment,
private 0700 HOME/TMPDIR. The tests cover every positive chunk boundary,
one-byte chunks, fixed errors, trailing diagnostics/canaries, wrong markers,
invalid UTF-8, oversize, fairness/readiness races, cancellation/deadline,
mid-read/selector/owner failures, hostile repr/str/bool, EOF without reap and
reap without EOF. They assert parser.finish is gated by EOF plus actual fake
owner reap, literal bool flags, retained child identity, and sanitized artifacts.

Local CPython 3.14 stdlib `selectors.py` was read, including BaseSelector's
register/select contracts and KqueueSelector's read registration/select/close.
Its SHA256 is `4b8a60cfbb619d080f87dffe1578372e56e8c0ac826f043224a154cf7b77606d`.
It accepts descriptors, returns `(key, event)` readiness entries, bounds positive
timeouts, tolerates interrupted waits, and closes its selector resource.
Installed `os.set_blocking` documentation confirms False sets O_NONBLOCK;
`os.read` documents descriptor input and bytes output. Source trace and fake
tests support the adapter design; they do not establish platform/kernel behavior.
The native readiness/EOF and bounded cancellation checks above need their own
separately admitted proof before use with private SQL.
