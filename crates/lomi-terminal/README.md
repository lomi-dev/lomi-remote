# Host-owned terminal service

`TerminalService` owns existing RAM PTYs and a single Rust `TerminalState` per
session. The host coordinator resolves trusted `SpawnProfile` configuration and
persists durable intent before calling `spawn`; this crate has no database,
remote command DTO, process adoption, or automatic input replay.

`spawn_with_checks` accepts trusted coordinator callbacks around startup. Its
pre-exec fence runs after model/PTY allocation immediately before child exec;
rejection proves no executable ran. A rejected post-exec integrity check or
reader/writer/thread setup failure reports `SpawnOutcomeUnknown`, attempts owned
cleanup, and cannot undo shell startup effects. Callbacks are bounded local code,
never request fields. The coordinator records uncertainty without replaying it.

Use a new `AuthenticatedConnection` for each OS-authenticated connection. Clone
it only within that connection. `attach` atomically checkpoints the model and
registers a bounded subscriber. A renderer must acknowledge its snapshot before
`claim`. A lease binds an acknowledged attachment, connection, actor, token and version, expires against
`Instant`, and controls both input and resize. `disconnect` invalidates it;
reattachment/reconnect does not restore control. `renew` returns refreshed input
ID/sequence and resize sequence high-watermarks. `wire_binding` exports only the
opaque token/version for the coordinator's canonical transport mapping.

The reader runs independently of observers and continues updating the sole
model after detach. Natural exit retains the final RAM snapshot for read-only
snapshot/attach; control, input and resize reject the exited epoch. A late
attachment checkpoints sequence S, then receives a closing `Exit` at shared
auxiliary sequence S+1 after its snapshot completes. This lets transports retire
the binding without forking sequence history or repeating a durable exit. The owner
polls lifecycle identities independently of views and persists an exact-session
`Exited` transition once. Under the 32-session capacity bound, it may retire the
oldest exited model only when it has no attachments or control, after atomically
persisting `Stopped` with no current session. Retained unacknowledged views block
retirement. Explicit restart uses a fresh epoch, and owner recovery clears old
exited session identities without adopting a process or replaying a command. Only that model generates DSR/DA replies. Subscriber queues
are limited to 1 MiB and 128 events, with at most 64 attachments per session and
32 sessions. Overflow clears and tears down only that subscriber and reports
`ResyncRequired`; a control lease loses authority immediately when its acknowledged attachment is
removed. An unacknowledged sibling or a fresh reattachment cannot preserve or
restore it.
Experimental `grid-patch-v1` updates carry sparse changed cells and complete
buffer/cursor/mode/title/palette metadata. They retain no full snapshot in queued
sparse updates and are charged by their serialized size. Initial snapshots remain
unchanged. History growth and eviction retain matching rows and append run-length cells.
Geometry changes use a checkpoint bounded to 8 MiB;
an update larger than the unchanged 1 MiB subscriber queue requires resync. A
client applies patches only to the matching epoch, sequence and baseline geometry,
then validates the resulting complete state. Legacy full `Delta` fixtures remain
available for the earlier experimental proof format.

Input is limited to 16 KiB. Input IDs and sequences use session-global monotonic
high-watermarks exposed by the lease. The last 128 receipts contain only actor/
connection identifiers, IDs, counts and outcome; no keystrokes, payload hashes,
logs or persistence. Repeated IDs/seq/length return the original receipt without
writing again, even if a caller substitutes different same-length bytes. Evicted
IDs cannot be reused. Partial writes or a lost fence return `Unknown` and never
automatically retry the whole payload. A trusted nonblocking coordinator fence
predicate and monotonic lease validity are rechecked before each write syscall.
Resize similarly reserves its sequence before the syscall and reports uncertain
I/O as `OutcomeUnknown`.
Destructive coordinator stops use a trusted final gate under session-map
exclusion, so waiting behind another startup cannot stop a child after the
request deadline. Rejected gates leave ownership and durable state unchanged.

The Unix production host constructs `TerminalService::with_worker` with its own
executable. Its private `--internal-pty-worker` entry runs before CLI parsing.
Each worker owns the shell and PTY lifetime; a private inherited Unix socket
carries a trusted profile bounded to 64 KiB, startup authorization, a single
master-FD transfer, and cleanup acknowledgement. Terminal bytes, parsing,
nonblocking input and resize stay in the host. All retained descriptors are
close-on-exec; the shell replaces inherited stdio and portable-pty closes other
inherited descriptors. Startup handshakes have a three-second deadline. A worker
cannot exec the shell before the host's final pre-exec authorization. The worker has its own process group so a host-group signal cannot kill its
watchdog. It resets inherited SIGCHLD disposition/SA_NOCLDWAIT before spawning
children to preserve the unreaped leader identity. Loss of
the host endpoint initiates cleanup; no PID files, adoption, old-worker
reattachment or command replay are supported. At most 32 workers, including
uncertain cleanup held for reaping, are retained. Cleanup uncertainty preserves
the owned worker handle rather than killing its watchdog or claiming success.

The worker sends HUP and CONT only to its owned original group, closes its PTY
handles, allows 300 ms for ordinary shell job cleanup, then sends the final
SIGKILL before reaping the original leader. Linux establishes child-subreaper
ownership before spawning the shell, verifies adopted-child ownership with the
kernel before opening and signalling pidfds, and repeats cleanup until waitid
reports ECHILD. A process scan only supplies candidates; an empty scan is never
completion proof. This mode assumes neither extra privileges nor delegated
cgroups. Linux native qualification is recorded separately in implementation
evidence.

Default native macOS host-SIGKILL tests cover live interactive sh, Bash and Zsh
with ordinary foreground, background and pipeline jobs, plus an unrelated
same-user sentinel. This does not establish complete descendant containment.
Deliberately disowned HUP-ignoring processes remain outside the guarantee. A
mandatory release blocker is natural shell exit: an ordinary Bash background
job survives when its leader exits before HUP propagation. The default regression
asserts this bounded counterexample, then waits for the short-lived fixture to
exit; a passing test records the rejected containment candidate. A default
macOS cleanup acknowledgement means original-group/PTY/leader cleanup only.

The opt-in Cargo feature `experimental-macos-session-cleanup` is **off by
default**. Its isolated module resolves SDK-visible private libproc SPI with
dlsym and acquires audit tokens through task-name ports before rechecking birth
time and owned SID. Only token-bound signals target additional session members;
numeric descendant PID or discovered PGID signals are forbidden. A macOS-only
SDK C shim copies bounded public kinfo_proc metadata without hardcoded ABI
offsets; it is compiled only when that feature is enabled. Neither the SPI nor
this feature is a supported macOS-version/App-Store guarantee. In particular,
KERN_PROC_ALL uses proc_iterate, omits SIDL and vanished PIDs, and is not an atomic
complete snapshot. Equal process-identity maps do not prove empty session
membership under fork/exec churn. Experimental convergence is therefore not
complete-containment proof and cannot close the release blocker. Detached
setsid escapes also remain outside this candidate's scope.

The host probes worker status once per bounded PTY read iteration, including
continuous output. EOF or an invalid acknowledgement immediately closes control
and reports cleanup uncertainty. A valid acknowledgement revokes the lease and
rejects new control/input before entering a final drain bounded to 256 KiB and
100 ms. The drain stops at the first empty read or budget/deadline, then closes
the model and host PTY handles. This preserves pending output within that budget
without letting a surviving slave writer retain a model indefinitely. The peek
preserves the acknowledgement for stop's validation/reap; lifecycle observations
wait for that validation before persisting the platform's limited exit outcome.

`TerminalService::new` retains direct in-process Unix PTYs for focused fixtures;
it is not the production crash-supervised factory or a fallback. That fixture
path keeps its original group leader unreaped until the final signal and bounds
child reap to two seconds, but has no host-crash containment or independent hard
startup deadline. Both Unix paths bound nonblocking input and complete host-reply
batches to 100 ms. Darwin zombie-only EPERM is accepted only after bounded
original-group/state inspection; no process argv or environment is inspected.

Validation:

```sh
cargo test --locked -p lomi-terminal -p lomi-terminal-state --lib
cargo test --locked -p lomi-terminal --test pty
cargo test --locked -p lomi-terminal --test supervision
cargo clippy --locked -p lomi-terminal --all-targets -- -D warnings
```

Tests use synthetic Unix processes/PTYs and temporary directories. They cover
atomic attach epochs, two observers/one writer, one host DSR reply, detached
output/model updates, slow consumers, render ACK, real lease expiry, resize and
input deduplication, unknown partial-write receipts, receipt eviction, ordered
final output/exit, intentional new-epoch restart and owned-group cleanup, cross-thread interactive shutdown, slow-drain reply-flood
shutdown and immediate control revocation before overflow reattachment.

Supervision fixtures additionally cover host death during startup and active
jobs, explicit cleanup acknowledgement, stalled startup, known versus uncertain
spawn failure, transferred-FD parser replies/input/resize, natural final-output
drain, and Linux adopted descendants that escape sessions and ignore HUP.

Continuous-output regressions cover both loss of an actual owned worker and a
valid original-group acknowledgement while a short-lived macOS background
writer survives. Both stop further control promptly; synthetic writers expire
under a fixed alarm and the test waits for their exit.
