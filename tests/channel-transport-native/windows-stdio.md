# Windows test-only stdio adapter

Status: **PREPARED_NOT_EXECUTED**. No local or Windows tests, type checks,
Bun executions, builds, executable hashes, or runtime checks were performed.
The existing POSIX bridge tests do not validate this adapter.

`windows-stdio.ts` is additive preparation for the synthetic
`transport_authority.exe` helper. It does not replace the Python bridge or
Auth fixture, and is not a product signer. The operations are the existing
JSONL `init`, signing, handshake, seal/open, dispose, and shutdown operations.
Helper limits remain 128 KiB per line including LF, 8192 lifetime commands,
and 528 lifetime slots. Shutdown consumes a command. Slots and operation
payloads are checked by the existing typed Rust helper.

The native launcher MUST create the pinned Bun 1.4.2 process suspended,
assign it to a nonbreakaway Job with kill-on-close, and only then resume it.
The launcher owns the Job handle and must confirm tree teardown independently.
All Bun descendants must inherit that Job. This adapter cannot establish or
verify that containment. VM teardown alone does not kill descendants.

The controller supplies a fixed absolute local executable path, expected SHA256,
private working-directory root, and SystemRoot. These are trusted configuration,
not values from operator environment or helper output. The adapter rejects
noncanonical paths and symlinks, checks realpaths and file kinds, streams the
hash with Bun.CryptoHasher, and spawns the absolute executable without a shell.
The controller must keep the executable and its ancestors immutable from
verification through process exit, and provision/ACL the exact private root;
path checks do not replace those native controls or close a filesystem race.
Only SystemRoot, TEMP, and TMP are supplied to the child environment.

The adapter retains the exact Bun.Subprocess, with three binary pipes, and
uses only its retained kill method. No PID-based targeting, detached processes,
PID files, network, named-pipe bridge, or dependencies are introduced. On Windows,
pinned Bun's retained process handle behavior still requires native validation;
the native Job is required even when the retained kill succeeds.

Commands have one in-flight exchange, a five-second total write/flush/reply
budget, a five-second connection setup budget, and a 60-second idle deadline.
The shared deadline captures a monotonic end time and installs its timer before
invoking the I/O factory. It rejects elapsed completions even when their promise
microtasks run before a delayed timer callback. The whole write/flush/reply
exchange and the whole graceful-close sequence each keep their original budget.
Concurrent requests poison the boundary. Replies use byte-counted LF framing,
strict UTF-8, a bounded line buffer, exact success envelopes, and no unsolicited
or extra lines. Stderr chunks are immediately discarded without accumulation.
A saturating
lifetime byte counter permanently fails the boundary above 64 KiB; it never
records stderr contents.
Every protocol error, rejection, timeout, or unexpected exit permanently fails
the adapter. No automatic retry can duplicate a state-changing operation.
Only a constant failure code is exposed, never helper contents or diagnostics.

Call and await `close()` in a finally block. Healthy close sends shutdown,
ends stdin, and awaits exit zero plus positive EOF on stdout and stderr within
five seconds. Failure closes stdin and
calls the retained child kill method, then waits up to five more seconds for
positive `.exited` confirmation and both stream drains. `directChildExited`
reports only the direct helper exit. `confirmed: true` additionally requires
awaited stdin end, positive stdout/stderr EOF, and no reader error; it never
certifies descendants.
`confirmed: false` means cleanup is uncertain and the native controller must
tear down/verify the Job. `graceful` additionally requires successful shutdown.
A failed boundary is never reusable. Setup uses monotonic performance.now plus
a sticky cancellation latch set
on timeout or error. Outstanding filesystem work may finish after rejection,
but the final synchronous pre-spawn check rejects the cancelled setup. No await
occurs between that check and spawn. The setup test seam exercises the same
cancellation guard without injecting or replacing the production spawn path.

Prepared tests cover sequential exchanges, fragmented UTF-8/LF, coalesced and
pending extra replies, oversize/unterminated lines, invalid UTF-8/JSON, stderr
flood, early exit, timeout, concurrent requests, permanent failure, and explicit
cleanup uncertainty, both never-EOF streams, late stderr-reader failure,
stderr overflow, short/zero writes, prevention of a late setup spawn, and
elapsed completions before timer delivery using a deterministic clock seam.
They use retained child doubles and are Windows/Bun-version
gated; they do not establish native process containment or real pipe behavior.

Pinned local bun-types/s3.d.ts declares FileSink write/flush/end as
number or Promise<number>. The source review supplied by the researcher found
whole-chunk acceptance in Bun 1.4.2 FileSink.rs lines 1308–1311 and Windows
PipeWriter.rs lines 2246–2259. The adapter writes once, requires the awaited
count to equal the entire frame, and then awaits flush (zero is valid). It
retains and awaits stdin end, which may be asynchronous. Short/zero write counts fail
permanently; no suffix is resent. Bun can report exit before either output
stream drains; both EOFs are checked independently. Sources:
[FileSink.rs](https://raw.githubusercontent.com/oven-sh/bun/bun-v1.4.2/src/runtime/webcore/FileSink.rs),
[PipeWriter.rs](https://raw.githubusercontent.com/oven-sh/bun/bun-v1.4.2/src/io/PipeWriter.rs),
[subprocess.rs](https://raw.githubusercontent.com/oven-sh/bun/bun-v1.4.2/src/runtime/api/bun/subprocess.rs).

Pending review and Windows-only validation: real FileSink flush/end and EOF
semantics; streaming CryptoHasher API; realpath/reparse-point
handling; minimal-environment process startup; real helper operation round trips;
five-second blocked-pipe deadlines; exit/stdout ordering; 60-second idle expiry;
Job membership, parent crash, kill/exit races, and descendant teardown. Tests must
be integrated with the native controller harness before any execution claim.
