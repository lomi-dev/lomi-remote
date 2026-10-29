# Implementation decisions

## ADR-E0-001 — qualification precedes application migration

Status: accepted for E0, 2026-10-19.

Keep all feasibility probes in the independent `lomi-remote` repository. Existing
applications remain unchanged while blocking terminal, boot, Git isolation and
credential-lifecycle questions are unresolved. A small synthetic proof is not
evidence of production integration. Stages E1–E7 remain gated.

## ADR-E0-002 — distinguish axes and qualification

Status: accepted for E0.

Product v1, Remote API/application major 2, signed grant/context 3, local IPC and
terminal profile are independent axes. Initial schemas are draft subsets, not a
frozen complete API. No unqualified terminal profile is advertised as supported.
Old grants are never expanded and optional `git.execute` is absent by default.

## ADR-E0-003 — pin the tested toolchain

Status: accepted for E0.

Use Rust/Cargo 1.98.1, available on this macOS arm64 machine, with edition 2024
and exact Cargo.lock resolution. This is the tested build requirement, not a
claim of the lowest possible MSRV or of any qualified release platform.

## ADR-E0-004 — unknown writer lifetime stays fenced

Status: accepted for admission probe; desktop integration pending.

An admitted participating writer can outlive its IPC connection or host process.
Persist admission before reporting success. Disconnect, lease expiry and host
restart quarantine an unsettled admission; they do not prove process termination.
Only an explicit settled completion or local reconciliation can resolve it.
Physical project/common-directory identity matters, not workspace IDs. External
shells remain outside cooperative admission and require effect-time revalidation.

## ADR-E0-005 — reject the stock vt100 checkpoint

Status: rejected candidate; Alacritty export remains open.

`vt100=0.16.2` with `Screen::state_formatted()` does not meet the required
checkpoint contract. Ten of thirteen fixtures differ from actual xterm 6.0.0
after restore and continuation; seven also fail the weaker native active-screen
comparison. Failures include inactive buffers, partial CSI/UTF-8/OSC, saved
cursor, origin/scroll region, title/hyperlink, reflow and evicted scrollback.
Do not ship this profile or substitute unbounded replay or Node.

The `alacritty_terminal=0.26.0` probe establishes both-buffer model behavior and
two actual DSR/DA response events, but has no complete xterm serializer or
pending-parser adapter. It remains a candidate, not a qualified engine. The
development-only xterm oracle uses an exact pinned private API to distinguish
human input from parser replies in two observers; production response routing
and all client adapters remain unqualified.

## ADR-E0-006 — Tough is a verifier component, not durable installer state

Status: candidate library accepted for investigation; raw integration rejected.

Use `tough=0.24.0` with default HTTP features disabled for offline synthetic
tests. Consume target streams completely before using bytes. The probe verifies
valid signatures/hash and rejects tampered target, bad signature, expired signed
timestamp and metadata downgrade with intact persisted state.

Raw loader persistence fails three required behaviors: malformed timestamp and
snapshot state permit rollback, malformed clock state is ignored, and supplying
the original bootstrap root on restart can overwrite the newer cached root.
The caller must supply its newest trusted root, serialize updates across
processes and implement fail-closed, crash-safe state commits. No installer may
activate a target until that wrapper and the remaining release gates pass.
Published upstream snakeoil keys are fixture-only and never release trust.

## ADR-E0-007 — macOS Git isolation is a bounded experiment

Status: partial evidence only; no production capability enabled.

Use the fixed root-owned Command Line Tools Git executable for the macOS probe.
`/usr/bin/git` is a launcher requiring another exec and is rejected under the
policy. Never widen allowed execution or use a PATH fallback to make it work.
Any stderr rejects the result, including optional-filter fallback after exit 0.
Seatbelt deprecation, broad runtime read allowances, hardlinks and replacement
races require resolution. Linux/Windows return unsupported without executing
Git until actual native isolation is qualified. The terminal remains a separate
explicit OS execution capability; this probe does not sandbox the shell.

## ADR-E0-008 — authoritative Rust state with a pinned xterm renderer

Status: experimental profile decision; qualification in progress.

The exact Alacritty/VTE and xterm sources show incompatible private parser and
saved state. ANSI drawing followed by raw PTY bytes would keep two competing
output interpreters. Investigate `lomi-rust-grid-v1-experimental`: Rust alone
parses PTY output and generates replies; clients apply structured snapshots and
ordered state deltas to a version-pinned xterm rendering/input adapter. Clients
never feed raw PTY output into xterm.write. This changes the preferred profile
under specification 04/09's S0.1 decision gate, not the product's Rust-only or
single-owner requirements. All ordinary terminal input still passes the host's
control lease, epoch and effect-time authorization checks.

Both buffers, retained history/wrap flags, cell widths/attributes/links, cursor,
palette and input modes are projected. Pending parser state stays in the live
host across attachment/reconnect; observers do not execute or reconstruct that
parser. A bounded control-string policy is required on the host. Host restart
still loses the live session, as the product specifies; this is not process or
interpreter recovery across a host crash.

Qualification has two distinct checks: Rust state must project exactly through
attach and subsequent state deltas at every byte boundary; separately, Rust
must correctly run the declared escape/input profile and real CLI fixtures.
Projection equality does not prove compatibility with uninterrupted raw xterm.
Private xterm APIs and patched upstream Rust sources require immutable source
digests, license retention and requalification after upgrades. No production
profile or broader platform acceptance is inferred from this ADR.


## ADR-009: portable isolated Git read candidate

Status: selected for further implementation; production qualification open.

Use a Rust/WASI Git read worker as the portable candidate. The host supplies only
an immutable private repository snapshot through a read-only WASI preopen. The
worker has no inherited environment, directories, sockets or process capability;
imports, memory, fuel, stack, output and execution time are bounded. Host-native
Git remains relevant to write/network operations and reference qualification.
No read operation falls back to unrestricted native Git.

The pinned gix 0.88.0 / Wasmtime 49.0.3 experiment passes packed-repository/index
status, staged/unstaged diff, log and blob show against the same native Git
reference on macOS arm64, Windows 10 LTSC x64 and Linux arm64. Native denial
coverage is recorded separately: 16 macOS security/broker groups, 11 Windows
runtime groups and 12 Linux runtime groups. Windows symlink/broker/ACL tests
remain unrun; Linux adds actual owned symlink escape probes. Both guest-only
WASI portability patches retain upstream archives, complete patch inventories
and licenses. All observed policy/lifecycle review findings are closed.

This selects a feasible isolation boundary, not a complete Git service or a
qualified repository grammar. The current guest accepts a small ordinary ASCII
fixture, rejects common-directory metadata and executable configuration, and
uses a 16 MiB synthetic snapshot budget. A production broker must pin root,
gitdir/commondir and opened file identities, reject prohibited links/specials,
revalidate concurrent writes and preserve a private immutable view. Linked
worktrees, broad status/diff semantics, hostile parser cases and per-platform
reparse/hardlink/race behavior require implementation and native qualification.
The reviewed Linux namespace executor remains independent evidence and a
possible platform-specific route; historical unrestricted candidates retain
their documented counterexamples.

Debug JIT observations (about 46 s macOS, 76 s Windows, 20 s Linux) are not product
latency acceptance. Installation/build-time precompilation or a cache with an
explicit trusted-artifact binding must be evaluated before serving requests.
The host's idle budget does not justify loading or compiling this worker at
startup without measurement. Every candidate and release capability remains
unqualified until the full File/Git service and platform matrix pass.

## ADR-010: supervised Unix PTY workers

Status: Linux candidate passed frozen native product/service checks; macOS release
blocked by incomplete descendant containment.

A dedicated mode of the same Rust executable owns each PTY and shell.
The coordinator keeps domain authority and the sole terminal parser. A private
inherited channel establishes the lifetime and transfers the owned master FD;
the coordinator reads and parses PTY output directly. Loss of its
host-owned lifetime endpoint triggers worker cleanup. No PID file authorizes
adoption or signalling. A replacement host restores descriptors as lost and
never reconnects to an old worker or replays commands.

On Linux, establish child-subreaper ownership before spawning the shell. Keep
the original session leader unreaped through the final group signal. Reaping
and signalling belong to one supervisor; verify adopted children through the
kernel and retain pidfds while signalling them. An empty process scan does not
prove completion: the worker must establish that it has no remaining children.
The ordinary manual mode cannot assume delegated cgroups. A qualified systemd
mode may additionally use cgroup containment and verify an empty cgroup.

On macOS, HUP/CONT, master closure and a bounded grace before the final group
kill pass owner-loss tests with live interactive sh/Bash/Zsh leaders. A separate
native counterexample shows that ordinary background jobs can survive a natural
Bash exit; acknowledging the original group alone does not prove session cleanup.
Process-group scans followed by numeric signals have a PID-reuse race and are
rejected as a replacement for exact process identity.

Investigate a narrowly isolated SDK-visible SPI candidate: keep the owned
leader unreaped to pin its SID, obtain a Mach task-name audit token, recheck the
candidate SID, then signal through `proc_signal_with_audittoken`. The token's
PID version binds the target through the kernel signal operation. Use no
delegated-signalling entitlement and no copied private process-info structure.
The SDK declares this libproc interface private and subject to change. Runtime
availability, native race/failure tests and release-mode declarations are
mandatory; no macOS 14+ or App Store compatibility is inferred. This experiment
is behind `experimental-macos-session-cleanup`, disabled by default. Its missing
SPI support fails before starting a shell only when that feature is selected.
The default macOS path still has the measured background-job counterexample;
it is not accepted for release. Identity-bound signalling alone does not prove
that a process enumeration found all descendants. Neither the snapshot-based
experiment nor the default implementation establishes full session cleanup.

A stopped-set barrier is rejected: XNU suspension waits for threads to leave
user execution, so a preempted kernel fork may publish a child after apparently
stable stopped-process snapshots. A separate true-death candidate remains under
investigation. XNU posts `NOTE_EXIT` only after the process's last active thread
and child-list drain; a generation-bound, preinstalled `EVFILT_PROC` knote may
therefore provide a fork-drain barrier. Registration and SID observation would
require successful audit-token generation checks before and after numeric PID
operations, with every failed check retained as unknown. `NOTE_TRACK` is
unsupported in the inspected XNU implementation. Even this stronger candidate
assumes descendants retain their SID and discoverable UID, and cannot qualify
arbitrary escaped descendants or bounded termination. No production behavior or
release status changes on the strength of this source analysis.

Public-API follow-up on 2026-10-24 preserves this release blocker. The
[public XPC counterexample](../../artifacts/macos-public-xpc-20261024/8aff1883-4301-4052-a7e8-022d0a48cf49/report.json)
left escaped descendants alive after controller loss and natural leader exit.
The job's process-group cleanup therefore does not establish complete workload
cleanup. Apple's launchd documentation limits that cleanup to the job's process
group, while `setsid` permits a descendant to create another group.
[launchd.plist](https://github.com/apple-oss-distributions/launchd/blob/main/man/launchd.plist.5),
[setsid](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/setsid.2.html).

Apple now documents `es_new_descendants_client` for existing and future recursive
descendants. The official documentation metadata and installed SDK declaration
both specify macOS 27.0 availability. It requires the Endpoint Security client
entitlement; its documentation removes root and TCC requirements. This is a
candidate for separate investigation on that version, without establishing the
required macOS 14+ matrix.
[Descendants client](https://developer.apple.com/documentation/endpointsecurity/es_new_descendants_client%28_%3A_%3A%29).

An Endpoint Security design would still need a reviewed response to event loss,
a custodian lifetime independent of the host/PTY, and native fault evidence.
Apple documents sequence gaps when notifications are dropped. Discovery of the
API does not qualify descendant discovery or cleanup after custodian failure.
The default product backend, experimental feature status and supported target
requirements remain unchanged.
[Endpoint Security event sequence](https://developer.apple.com/documentation/endpointsecurity/es_message_t/global_seq_num).

Sources: [portable-pty 0.9.0 Unix implementation](https://docs.rs/crate/portable-pty/0.9.0/source/src/unix.rs),
[Linux child subreapers](https://www.man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html),
[pidfd ownership](https://man7.org/linux/man-pages/man2/pidfd_open.2.html),
[pidfd signalling](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html),
[cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html), and
[Apple process-event definitions](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/event.h#L334).
The audit-token candidate additionally uses Apple's
[identity-bound signal wrapper](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/libsyscall/wrappers/libproc/libproc.c#L486),
[kernel signal permission check](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/proc_info.c#L3563), and
[task-name permission path](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_proc.c#L5859).

## ADR-011: investigate coalition provenance in an isolated macOS fixture

Status: experimental feasibility work authorized; no production ABI selected.

The SDK-only inherited-session candidate cannot discover an unobserved child
that changes SID. Apple documents coalition membership as inherited across
fork/exec/spawn and immutable after creation. This may provide a stronger
ownership identity, but the inspected membership query uses a private flavor
and structure absent from the installed SDK. A root helper alone does not gain
coalition creation authority; launchd owns that management boundary.

Permit a separate, explicitly opted-in fixture to examine the source-pinned
private coalition query. This extends the investigation beyond ADR-010's
SDK-only signal candidate; it does not change the default product or promise
private ABI compatibility. Record the exact Apple source/layout/license,
compiler, SDK, kernel, return sizes and native results. First query only the
fixture itself and known owned children. Then test whether two disposable
launchd jobs receive distinct coalitions and descendants retain membership.
Never signal a discovered coalition as a whole: an unqualified or shared ID
could include unrelated processes. Use only retained child ownership or exact
UUID job registration for fixture cleanup, and require absence checks.

Production would additionally need a reviewed per-PTY job architecture,
generation-bound membership observations, a sound true-exit/rescan empty proof,
failure retention and native OS-matrix qualification. Cross-UID visibility and
external broker-created work remain separate questions. Neither intentional
session detachment nor an unavailable mandatory capability silently exempts
descendants from the process-tree requirement. Full macOS containment remains
blocked throughout this experiment.

The pinned resource-usage implementation exposes `tasks_started` and
`tasks_exited` under one coalition lock. Its syscall explicitly permits copying
only their 16-byte prefix. Adoption increments the first counter before a new
task executes, and removal increments the second when that task terminates.
This offers a candidate completion condition stronger than an empty process
scan: in a distinct coalition with an authenticated live controller, a
non-wrapping difference of one means no other executable member at that instant.
It becomes a stable descendant-empty certificate only after the controller has
stopped creating tasks and all external admission is closed. Query errors,
unsupported symbols, malformed counters and denied identity observations must
retain uncertainty. The counter does not certify reaping of BSD zombies.

The isolated native probe observes four distinct jobs across Aqua and Background
domains, inherited IDs across fork/setsid/exec, and count differences
`1,2,2,2,1`. These observations do not establish actual headless login,
`LaunchOnlyOnce` admission closure, arbitrary reparented descendants or product
cleanup. Review requires durable exact-run recovery and independent controller
termination evidence before further persistent-controller fault experiments.

Sources: [Apple coalition semantics](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/doc/observability/coalitions.md),
[private process-info definitions](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/proc_info_private.h),
and [coalition syscall authorization](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/sys_coalition.c).
The counter candidate uses the pinned
[adoption and removal accounting](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/coalition.c#L622),
[locked counter snapshot](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/coalition.c#L781),
and [bounded prefix copy](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/sys_coalition.c#L254).

## ADR-012: one experimental macOS coalition per PTY generation

Status: accepted for implementation behind a disabled experimental feature;
native product qualification remains open.

`experimental-macos-coalition-cleanup` selects a distinct supervisor backend.
Each PTY generation uses a private UUID launchd job in the current user's
Background domain. Its plist stays inside the private profile generation
directory. This does not install a login item. The existing backend retains
its recorded containment limitation until the new backend is qualified.

The host authenticates the controller's private socket against the exact job,
fresh kernel audit identity, generation nonce and independently queried
resource/jetsam coalition IDs before transferring a spawn profile. Environment,
arguments and PTY bytes travel only over that connection. The durable journal
contains public identifiers and ownership pins, never the spawn profile.

Admission is consumed durably before the one workload grant. The original
controller forks that workload once and permanently stops creating tasks.
`LaunchOnlyOnce` is a property of one loaded registration: the native probe
shows that unloading and reloading the same label permits another launch.
Consequently neither a failed operation nor recovery may rebootstrap or reuse
an ambiguous generation. Recovery only tears down recorded generations.

Cleanup closes admission durably, discovers candidates through bounded scans,
and signals only after fresh audit identity and coalition checks agree on both
sides of the query. A truncated or empty scan is never a completion proof.
Ordinary exec changes the audit token's PID version; failed identity checks
cause a fresh observation or retain uncertainty, rather than proving death.

The completion certificate requires the original controller to remain live
across a valid locked resource-counter sample with a difference of one, after
admission closes and the controller stops forking. The owned workload leader
must also be reaped and the PTY disposed. Only then may the controller exit and
the host confirm its lifetime release and remove the exact job registration.
A query error, controller death, lost connection or partial journal write
retains the generation and its capacity reservation as unknown. Never boot out
the sole controller while descendant cleanup remains unresolved.

The first implementation rejects excessive Darwin socket paths before effects.
Private ABI availability, fault/reparent/exec/fork-churn cases, host/controller
crashes, independent cleanup and OS-version coverage still require native
product evidence and review. Prerequisite fixture success alone closes none
of those product gates.

Sources: the pinned Apple sources in ADR-011 and
[exec PID-version changes](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_exec.c#L7096).

## ADR-013: bounded production authorization foundations before migration

Status: accepted for local E2 implementation; production activation is pending.

Extend ADR-E0-001's initial isolation boundary to permit additive, local changes
to the existing auth application. Preserve existing clients and credentials.
New enrollment behavior stays disabled by default until actual handler,
database-role and credential-isolation acceptance passes. No production
migration or deployment follows from this decision.

Better Auth user and session identifiers are opaque strings. Remote accounts
have a separate stable UUID mapping and a monotonic authorization epoch.
Immutable session bindings distinguish browser (`web`), mobile, desktop and
bootstrap credentials. A host enrollment binds the full signed three-key
commitment before approval and the approved account/epoch once afterward.
The bootstrap UUID in the canonical challenge is distinct from the actual
opaque Better Auth session identifier; both are bound through database keys.

Canonical verification and challenge construction use the shared Rust/WASM
authority package. TypeScript coordinates the transaction and does not
reimplement signatures, canonical CBOR or account-bound key fingerprints.
The actual device-token endpoint may add `host_enrollment` containing only
`accountId` and canonical `challenge` bytes when stored enrollment state
authorizes the exact issued bootstrap session. A public client identifier
cannot select that credential class. Ordinary desktop responses retain their
existing shape.

Code consumption, account/class binding and bootstrap creation share the
existing global authorization transaction. Failure after session creation
rolls the operation back. A bootstrap credential is restricted to completing
its enrollment; normal account, browser-approval, mobile, push and remote
consumer paths must reject it without extending its expiry. Revocation and
account suspension share the same lock and invalidate outstanding enrollment
authority. Reactivation cannot revive a previous epoch.

## ADR-014: key-bound credential rotation and protected response recovery

Status: accepted for local E2 implementation; production activation is pending.

Use a five-minute access credential, a rotating random refresh credential with
a 90-day idle lifetime, and a 30-second recovery receipt. These are distinct
from Better Auth sessions. Exchange starts an unconfirmed family. Until the
host durably stores its credentials, only registration may use that family's
access credential; refresh and normal host operations must refuse it.
Registration confirms the family and destroys its bootstrap session and
exchange receipt atomically. Expired unconfirmed families are fenced even
before maintenance runs. A new enrollment cannot revive a previous family.
Enrollment proof audience is the configured origin plus the exact
`/v2/remote/host-authorizations/exchange` path. Identity and native host setup
must agree on that canonical endpoint; an origin-only value is not equivalent.

Refresh uses canonical Rust proof bytes with this fixed CBOR array:
`["lomi-remote-host-refresh-proof-v1", 1, accountId, hostId,
hostAuthorizationId, hostKeyFingerprint, rotationId, refreshHash, audience]`.
UUIDs are 16-byte values and hashes are 32-byte values. The fingerprint binds
the approved account and all three committed host keys. `refreshHash` is
SHA-256 of the exact ASCII wire credential, without trimming or decoding.
The audience is the configured canonical HTTPS origin plus the exact
`/v2/remote/host-authorizations/refresh` path; request headers cannot select it.
The proof has a distinct domain from enrollment. This is a private protocol,
not a claim of DPoP conformance.

Verify proof of possession before allowing a conflicting refresh to revoke
the family. Under the shared authorization transaction, check account status,
account and host epochs, confirmation, idle expiry and the retained refresh
tombstone. Consume the old credential, advance the family exactly once, insert
the next credential and persist one protected response in the same commit.
An identical authorized retry returns the same response within its original
recovery window. It never mints another credential or extends expiry. A later
rotation invalidates earlier recovery responses; delayed retries must not
return already-consumed replacements. Keep consumed-token tombstones for the
family's lifetime. Conflicting or expired recovery fails closed and fences the
family after valid proof. Invalid proof alone cannot revoke it.

Protect receipt plaintext with AES-256-GCM using a separate server key outside
the database, a CSPRNG 96-bit nonce and a full 128-bit authentication tag. The
versioned envelope includes a bounded key identifier and authenticates it.
Authenticate a fixed ordered context containing the recovery domain/version,
kind, family, enrollment where applicable, operation, account, prior credential
hash, verified canonical request hash, creation time and expiry. Exchange binds
the exact bootstrap credential hash. Rotation binds the exact old refresh hash.
Reject malformed, missing-key, expired or unauthenticated receipts without
minting replacements. Verify decrypted result identifiers against the trusted
context before returning them. Never log or archive plaintext credentials,
receipt keys or protected host bundles. Recovery reads reuse the stored sealed
response; they do not encrypt it again. Operators must rotate a key well before
the aggregate random-IV GCM limit of 2^32 encryptions across all instances.

The host keeps its pending operation and old/new credentials inside its
explicitly selected OS secret store. Installing a response and clearing pending
intent must be durable before registration confirmation. Domain SQLite, argv,
URLs and ordinary operation logs never carry this state. Lost keys require
re-enrollment; restoring a domain backup cannot roll credentials backward.

A captured valid request and old token may race first use or recover the same
response during the short window. This design relies on TLS and uncompromised
endpoints; a timestamp without server state would not remove that race. Actual
coordinator, crash, concurrency, encryption and platform-store tests are required
before claiming acceptance.

Sources: [RFC 9700 section 4.14](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14),
[RFC 9449 sections 4.3 and 11](https://www.rfc-editor.org/rfc/rfc9449.html),
[NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf),
and [Node crypto authenticated encryption API](https://nodejs.org/api/crypto.html).

## ADR-015: isolated noninteractive Keychain access and encrypted host bundles

Status: accepted for bounded macOS provider implementation and synthetic tests;
login-Keychain deployment and production activation remain pending.

The macOS provider stores one random 32-byte encryption key per logical profile
in an explicitly selected file Keychain. The host bundle remains encrypted in
the validated private profile directory. Bundle updates use the existing
exclusive storage ownership boundary, exclusive temporary creation, file sync,
atomic rename and directory sync. They do not update the Keychain item. The
versioned ChaCha20-Poly1305 envelope authenticates its profile binding and uses
a fresh random 96-bit nonce and full 128-bit tag. This format is independent
of the server's AES-GCM recovery receipts.

Establish a key only for an explicitly initialized empty store. Verify the exact
key through a fresh helper before first ciphertext publication. Existing
ciphertext with an absent, malformed, locked or inaccessible key fails closed;
never generate a replacement or try plaintext storage. Keep the same persistent
storage lock across providers and reject an existing plaintext bundle when
Keychain storage is selected. Read the key afresh for each load or replacement,
without caching it in the provider. A lock cannot revoke bytes already returned
to an in-progress operation; do not promise instantaneous revocation.

Explicit file-Keychain queries use the legacy Security implementation. SDK 26.5
states that per-call no-authentication-UI flags do not prevent legacy UI.
Run Security operations in a short-lived private route of the same installed
executable. Its first Security call must successfully disable user interaction
for that process. The multithreaded host's interaction state stays untouched.
Use only exact namespaced service/profile selectors and an explicit non-null
Keychain reference. Never change default/search lists, unlock a user's Keychain
or broaden item access to every application. Key material crosses only bounded
anonymous private pipes, never arguments, environment or ordinary logs.

Report Locked only when the selected Keychain's own status establishes it.
Authentication or denied-interaction errors while unlocked mean Unavailable.
Accept item absence only after an explicitly scoped lookup and unlocked status
checks. Profile directory and lock identity, ancestry, UID and ACL checks remain
mandatory. Logical profile binding does not solve cloned-profile ownership;
restore/re-enrollment fencing remains a separate E2 requirement.

The public Keychain update API supplies no verified drive-flush contract. The
static-key design removes Keychain mutation from normal credential rotation,
but initial establishment remains subject to verification and uncertainty.
Filesystem sync/rename tests qualify the recorded process-crash boundary;
neither ordinary fsync nor a successful Keychain call is an unconditional
power-loss guarantee. Post-publication confirmation failure returns
CommitUncertain and requires inspection instead of an automatic fresh write.

Native acceptance uses only a throwaway custom Keychain and RAM-held password,
with default/search-list snapshots and exact owned cleanup. It must exercise
the actual provider/helper and fresh-process reads, lock/unlock denial, profile
separation, corruption, missing key and publication failures. It does not qualify
the user's login Keychain, signed upgrades, cross-session access or boot mode.

Sources: SDK 26.5 Security framework headers (`SecItem.h`, `SecKeychain.h`,
`SecAccess.h`, `SecBase.h`), [Apple TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains),
[Security Globals implementation](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_keychain/lib/Globals.cpp),
[legacy SecItem implementation](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_keychain/lib/SecItem.cpp),
and [Apple fsync documentation](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fsync.2.html).
Research observations about upstream main do not identify the running kernel
or Security daemon; native receipts must bind the SDK and tested OS separately.

## ADR-016: complete identity and admission inputs before v2 persistence

Status: accepted. The 23-route identity/admission contracts and canonical
native/WASM identity, window-proof and v3 wire helpers now pass frozen bounded
integration. Host identity publication passes actual PostgreSQL tests.
Direct browser/desktop consumer persistence passes bounded database acceptance;
derivative consumers, runtime/publication and pairing/channel remain incomplete.
Existing v1 clients and grants are unchanged.

The initial fifteen-route draft cannot carry every input used by the verified
v3 handshake. A single consumer signing key does not determine the account-bound
fingerprint of its three-key identity bundle. The current pairing response also
omits the host's expected grant proposal, while channel creation supplies neither
the host-signed channel admission nor the independent current authority needed
by the browser verifier. E0 supplied these inputs directly; that was a crypto
proof, not an implemented HTTP lifecycle.

Complete the canonical contracts before creating consumer, pairing or channel
tables. Add explicit identity-owned consumer issuance/discovery under a new gate,
with an empty request body and server-derived class. The result supplies the
stable account UUID, consumer authorization UUID, original opaque account-session
ID and expiry. Web and mobile authorizations retain their actual derivative
principal and browser parent; a mobile derivative never reclassifies its browser
Better Auth session. A legacy account-read authorization alone creates no v3
grant. Idempotency is tied to the actual authenticated origin principal, and a
revoked consumer cannot mint a replacement from the same still-valid origin.

Use the existing canonical public-bundle bytes and self-signature as a bounded
signed identity wire envelope. Strict Rust decoding and verification derive the
account, role, subject and full three-key fingerprint; duplicate unsigned key
claims cannot supply authority. Register the finalized host bundle against its
retained enrollment commitment. Authenticated inventory supplies that verified
bundle for consumer pinning. Window registration additionally requires a fresh
server challenge binding account, consumer authorization, opaque parent session,
window identity, full fingerprint, operation, nonce, audience and expiry. Copying
a public bundle does not satisfy that proof of possession.

Add bounded host pending-pairing polling and an independently stored expected
grant proposal containing the actual consumer identity and current authority.
The host checks local sharing policy before signing; approval may narrow rights
and expiry without changing ownership, epochs, runtime or nonce. Channel creation
then produces a pending expected channel context. The host signs a separate
admission; peer-owned detail supplies verified grant/admission, both verified
bundles and independently assembled current authority. Tickets are unavailable
until admission succeeds. Every reconnect uses a fresh channel, admission,
ticket and Noise handshake.

Canonical Rust owns these identity codecs, challenge signatures, proposal
binding and v3 verification. TypeScript owns trusted row lookup and transaction
ordering. Consumer/window, runtime/publication and pairing/channel persistence
remain distinct bounded migrations. The shared relay owner continues to fence
both protocol versions; v2 tickets and admission never fall through to v1.

The first consumer persistence phase admits direct Better Auth browser/desktop
origins only. Server-owned metadata supplies immutable class and account
management authority; the original opaque session ID is retained. Issue is
idempotent per origin, including revoked/expired tombstones, and does not renew
the parent session. A new login is required after that origin's fixed authority
expires or is revoked. Window challenges last at most 300 seconds, are capped
by authority/parent expiry and require current authority at finalization. Exact
operation/proof retries are idempotent only while those bounds remain live.
Each authorization retains at most 64 challenge records and 64 finalized
windows; exhaustion returns a resource-limit error. Derivative web/mobile
issuance requires separate scope/consent integration and a later bounded schema
extension; legacy account-read grants never acquire Remote v3 rights implicitly.

Pinned Prisma PostgreSQL adapter date conversion requires UTC on every actual
connection and before authorization transaction reads. Append the UTC setting
last inside parsed connection URL options, rather than relying on pool options
that the URL can override. Consumer SQL writes use explicit UTC instants/epoch
seconds; independent three-timezone tests compare against the original parent
instant and actual database epoch. Do not alter pinned dependencies to mask the
boundary. This behavior is covered by the private PostgreSQL 17.8 receipt, not
production PostgreSQL 18.6 qualification.

## ADR-017: integrate authorization into the existing host owner

Status: accepted implementation direction; durable store fence implemented and
reviewed, product worker/IPC integration pending.

The existing host owner will run one bounded authorization worker, rather than
let a CLI process own credentials or issue background requests. The worker opens
the explicitly selected provider from the already retained owner endpoint,
constructs the durable credential manager locally and performs blocking HTTPS
outside the PTY/store locks. IPC carries closed status and operation IDs. Public
user-code presentation is a separate explicit login action; device, bootstrap,
access, refresh and private-key material never cross IPC or enter SQLite.

SQLite owns a nonsecret monotonic authorization generation, locked/pending-revoke
state and trusted-clock floor. Logout commits the new generation, disabled
workspace consents, advanced workspace fences, events and coalesced revokes in
one transaction before cloud work. Revoke acknowledgement cannot unlock access;
verified login may unlock only the exact current generation with no pending
revoke. Neither action restores a previous workspace consent. Delayed login and
publication acknowledgements must carry and match the local generation.

Use schema v3 and an exact reusable pre-v3 backup so an older host cannot ignore
the new authorization fence. Preserve identities, project paths, terminal state,
operation receipts and shell configuration across migration. A persisted clock
floor and a runtime Instant projection prevent backward wall time from extending
credential deadlines across restart. Store only these nonsecret controls; the
selected secret provider retains credential/rotation recovery state.

Pending-enrollment reset, durable poll scheduling, public user-code/expiry
presentation and refresh deadlines still need narrow credential-library APIs.
The trusted verification route is the existing Auth frontend `/device` on the
configured canonical origin. Revoke must authenticate the host independently
from account cookies; the current owner-account-only route requires a contract
extension before claiming cloud logout. Uncertain exchange/rotation material
must remain available for exact recovery or revoke. Locked/unavailable providers
leave local PTYs operational and never select another provider automatically.

## ADR-018: acknowledge host revocation without restoring authority

Status: implemented server boundary; actual host integration under review.

Allow a current host access principal to revoke its own host/family without
account-management permission. A consumer needs a live, actually issued
management authorization for the same account; legacy account-read derivatives
do not acquire that right. Resolve a known host access hash before consumer
session resolution, including when the family is expired or revoked. Mixed
host credentials and browser cookies are denied rather than falling through.

Under the shared authorization lock, verify the expected host epoch, revoke
every active family for that host and then advance the host epoch once. Existing
SQL guards independently enforce that order. A lost commit acknowledgement is
reported as outcome unknown, never as effect none.

An exact retained revoked-family credential may acknowledge that family's
revocation with its original expected epoch, even after credential expiry or
account suspension. This path performs no writes and grants no access. It
returns the current nondecreasing host epoch; a retry cannot revoke a newer
enrollment. Every ordinary access/refresh endpoint still rejects that revoked
family. A stale consumer management request fails before effects. A generic
authentication error is never proof that cloud revocation completed.

The protected host bundle retains a durable Revoked state after a verified TLS
acknowledgement, with account and prior/acknowledged epochs and no credentials.
Only then may SQLite clear pending revoke for its current generation. A crash
between these writes recovers the retained acknowledgement. Explicit later
login retires this acknowledgement after the local handoff and preserves the
identity keys and first approved account binding. The account binding is
distinct from the original account-independent key commitment. A different
account requires a separate authorized host/profile identity transition.

Uncertain exchange/rotation material is retained until exact recovery or a
verified revocation acknowledgement. An expired unconfirmed exchange or lost
rotation recovery outside its server window may still require account-side
revoke; the bounded worker does not discard that uncertainty or claim success.
Transient network failures preserve consent and do not become permanent logout.
No runtime, publication, grant, channel or relay cutoff is qualified by the new
credential endpoint alone.

## ADR-019: advance the real host epoch when claiming a remote runtime

Status: bounded host-only migration005 and default-off HTTP implementation;
actual PostgreSQL acceptance and independent final evidence review closed.
Consumer lookup/inventory and later channel/relay acceptance remain pending.

The architecture requires every new runtime owner to advance host access epoch.
Migration 002 currently forbids that while a live family exists and makes the
family's epoch immutable. Advancing only the identity would invalidate the same
credential family needed for heartbeat and refresh. Use one real host epoch,
advanced atomically in identity and the exact live family by a narrowly
privileged claim routine. Credential hashes, rotation, recovery receipts,
account binding and deadlines remain unchanged. This does not reissue or revive
credentials; existing account/revocation/expiry checks still apply.

A dedicated NOLOGIN function owner, unavailable through application-role
membership or SET ROLE, owns the claim entry point. Neither Auth nor Remote API
gets a general exception to immutable epochs. Invoker-security row guards allow
only that execution identity and an exact protected current-transaction claim
transition: same host/account/family, next epoch and next runtime generation,
otherwise unchanged family and identity. The restricted routine validates live
authority and the shared global lock before creating this transition evidence.
No custom-GUC bypass, trigger disabling or revoke/unrevoke sequence is allowed.
Functions use trusted fixed search paths and qualified objects; default public
execution is revoked in the creation transaction.

The first claim moves generation zero to one and resets publication sequence to
zero. A live different owner receives HOST_BUSY. An exact same-owner claim retry
returns the retained binding without extending its lease or increasing epochs.
After lease expiry, even the same runtime ID needs current-generation CAS and a
new generation/epoch. Heartbeat requires exact binding and a live lease;
publication requires that binding plus sequence CAS and never renews the lease.
Initial bounded defaults are a 30-second owner lease and five-second freshness.
Replacement clears publication. Names, roots and terminal content remain absent
from cloud publication; the canonical contract contains routing IDs only.

Add a host-only current-runtime lookup before persistence integration. It must
represent unclaimed generation zero without fabricating a runtime ID, and expose
the current epoch, optional binding, publication sequence and remaining lease/
freshness durations. This permits restart/lost-response CAS recovery. The local
credential manager needs a narrow authenticated nondecreasing epoch update,
subject to the owner's local logout generation. Delayed replies cannot unlock
or roll back local authority.

Remote API receives narrow current-authority functions, not credential-table
reads. Host lookup takes the 32-byte access hash and returns only current typed
principal fields/bounds. Consumer resolution first uses private Auth outside the
Remote transaction lock; Auth verifies the actual credential/cookie and returns
the original parent ID, credential hash and issued direct consumer context.
Inside the global lock, SQL rechecks the hidden parent token hash, immutable
binding/class, account status/epoch, revocation and parent/consumer expiries.
Submitted session IDs alone are insufficient. Cookie-signing keys, plaintext
stored sessions, refresh credentials and sealed recovery remain outside Remote
API permissions. Legacy derivative consumers require their separate scope work.

Real restricted-role PostgreSQL tests must demonstrate direct epoch/role/GUC
forgery denial, rollback between both epoch updates, claim/revoke/refresh races,
unchanged rotation/recovery behavior, lost-response lookup, stale bindings,
publication limits and consumer invalidation between private resolution and
locked recheck. Pairing, grants, channels and relay remain a later migration.

References: [SECURITY DEFINER](https://www.postgresql.org/docs/17/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY),
[execution identity](https://www.postgresql.org/docs/17/functions-info.html),
[advisory locks](https://www.postgresql.org/docs/17/explicit-locking.html#ADVISORY-LOCKS)
and [built-in SHA-256](https://www.postgresql.org/docs/17/functions-binarystring.html).
The exact new trigger/role mechanism remains subject to actual database tests.

Migration005 now implements the protected transaction proof and sealed execution
owner. The permission scripts validate its role attributes/memberships and assign
only designated functions after migration; ordinary migration does not require
CREATEROLE. Remote API receives function execution, with no runtime/proof-table
or credential-table reads. Actual limited-role PostgreSQL run `fb0914f0` passes
seven database tests / 1,304 assertions and 176 regressions / 1,147 assertions,
with one metadata conditional skip, grants twice and complete private cleanup.
The first three failed runs remain unchanged. New claims contend, maximum
generation fails without effects, and real signed refresh and runtime claim
are observed waiting on the same database lock before the race is released.

Distinguish failed credentials from a stale runtime: after live host access
resolution, missing/expired/mismatched heartbeat binding returns STALE_EPOCH,
permitting lookup/reclaim without clearing local consent. Revoked credentials
still return AUTH_REQUIRED. Prisma 7.10 preserves PostgreSQL SQLSTATE under its
typed driver-adapter cause; response mapping uses that field and never parses
exception text. Both boundaries have actual and focused regression coverage.
No feature is enabled by this evidence.

## ADR-020: resolve direct consumers through a private Auth boundary

Status: bounded implementation and independent review closed against 46b880c6
and 58f7e9af; all deployment gates remain off.

The existing private exchange process deliberately lacks the Auth cookie key
and token-table privileges. Keep that boundary. Main Auth may bind a separate,
explicitly configured default-off private listener using its existing config and
database connection. Do not mount its consumer-context route in the public Auth
app. Do not add the cookie key to RemoteServiceConfig. The dedicated listener
defaults to loopback; a container-network bind is an explicit operator setting,
with no published port or public ingress configuration.

Use the existing service HMAC over the exact POST path, timestamp and bounded
body. The body carries exactly one original authorization or cookie header.
Auth verifies that envelope before reconstructing the original credential,
then resolves an already-issued direct browser/desktop consumer. Never renew,
issue or create bindings during lookup. Return only typed account, consumer,
parent session, class, account epoch, exact fixed expiry, management flag and
the SHA-256 of the verified underlying parent token. That hash is a private
authority assertion: never expose it in public responses, logs or evidence.

Remote resolves this private assertion before taking the global authorization
lock. A separate sealed NOLOGIN read-only inventory owner rechecks every field,
the hidden parent token hash, class/binding, revocation, expiry and account epoch
under that lock. Remote receives only inventory-function execution and no
credential/consumer-table reads. The epoch-mutating runtime owner gains no
session-token read privilege. Neither submitted IDs nor a cached assertion alone
authorize access. Private fetch/parse/timeout failures fail closed.

The existing canonical InventoryResult requires both authorization and hosts.
Return the public six-field ConsumerAuthorizationContext from the rechecked
consumer row, with expiry truncated to whole epoch seconds. The public parent
session ID is part of that contract; its underlying token and token hash remain
private. The HTTP boundary binds every public context field to the verified
private assertion before returning the result. Validate successful responses
independently with the pinned Rust/WASM codec; do not extend the contract.

The first Remote HTTP adapter accepts direct desktop bearer credentials only
and rejects any cookie header. Private Auth can verify both existing direct
classes, but host-only Auth browser cookies cannot naturally reach the separate
Remote origin. Browser/mobile derivative scope and handoff require their own
implementation; legacy account-read sessions gain no v3 rights here.

Inventory uses finalized signed identities and routing IDs from the new runtime
publication, never legacy remote_host data. Include only same-account confirmed,
nonrevoked current-epoch families with a matching retained runtime and nonempty
published workspaces/positive publication sequence. A fresh live lease and live
credential deadlines give online status and current resource IDs. Otherwise
return offline with empty workspaces, retaining the last matching binding only
as a descriptor, not authority. A replaced/revoked epoch, unclaimed host or empty
publication is omitted. No fabricated runtime ID or broadened DTO is needed;
the publishing enum is reserved for later explicitly defined transitions.

Enforce 256 hosts and existing per-host publication budgets; a response exceeding
the one-MiB control frame fails RESOURCE_EXHAUSTED rather than truncating an
unpaginated inventory. Actual restricted-role tests must cover forged assertions,
resolution/recheck invalidation, class confusion, cross-account filtering, stale
runtime/credential state, privilege denial and canonical public output.

## ADR-021: persist bounded pairing proposals before host approval

Status: bounded creation/retry implementation and independent review closed
against 0d5a4f35 and cfd78302; pairing remains off.

Use the existing PairingCreateParams, PairingResult and GrantV3 contracts.
Direct desktop consumer resolution precedes the global authorization lock.
Creation rechecks the original eight-field assertion, the finalized window
belonging to that exact consumer, and the same-account finalized host's current
family, runtime lease, freshness and published workspace epoch under that lock.
The proposal carries requested capabilities; local host policy and a separate
verified signed approval remain necessary before any grant becomes usable.

Set pending lifetime to 120 seconds and maximum proposed grant lifetime to
600 seconds, capped by the current consumer and host credential deadlines.
Keep at most 64 outstanding proposals per host across all consumers/windows,
matching the canonical pending poll bound. Retain at most 1,024 operation
receipts per consumer until that consumer is removed. Expiry frees outstanding
capacity but never deletes a live consumer's receipt or resurrects its operation.
These bounded defaults may be revised explicitly before deployment.

Scope idempotency by consumer authorization and operation ID. Compare normalized
request fields including capability-set membership. An exact retry retains IDs,
nonce, maximum grant and deadlines; conflicting parameters return the canonical
IDEMPOTENCY_CONFLICT. An expired or invalidated retained proposal yields expired
after rechecking the caller; it cannot regain authority after an epoch, runtime,
window, family or published-workspace change.
An observed stale retained operation is tombstoned expired monotonically;
restoring freshness or re-publishing cannot revive that same operation.

A separate sealed NOLOGIN pairing owner owns proposal writes. It receives no
parent-token reads. A narrowly executable helper under the existing read-only
inventory owner rechecks direct consumer authority without returning secrets;
neither the runtime owner nor public API receives its execution privilege.
Preparation and canonical Rust/WASM generation/finalization share one locked
database transaction. If a draft row is used, a deferred constraint must forbid
committing it before its maximum canonical proposal is finalized in that same
transaction. SQL retains independently derived relational bindings; later signed
approval must verify against both the saved maximum and freshly assembled rows.

This phase supplies creation and retained proposals only. Host approval, usable
grants, channels, tickets and relay require their own acceptance. Terminal channel
admission additionally needs an independently trusted terminal profile source;
the current routing-only publication cannot supply one.

## ADR-022: verify host decisions against retained and current authority

Status: bounded implementation and independent review closed against c1cf89f7
and c5bedaf5; host polling and decisions remain off.

Keep the canonical pending GET and decision POST contracts. The GET has no body
or query runtime: authenticate the host and infer its current live runtime from
stored rows. A decision carries the canonical current runtime binding. Reuse the
sealed host-access lookup wrapper through narrow execution privileges; the
pairing owner still cannot read access hashes or parent session tokens.

An inventory-owner helper may recheck a retained proposal's consumer lifecycle
without the original consumer credential. This is recipient liveness for an
already host-authorized operation, not authentication of a submitted consumer.
Resolve parent, class, account epoch, fixed expiry and window state from rows.
Revalidate current host family, runtime, freshness and published workspace under
the same global authorization lock. Regenerate maximum canonical CBOR from the
retained trusted grant and independently rechecked identities for every pending
poll and decision. Syntax-valid stored hex alone never establishes a ceiling.

Approval verifies the submitted signature with canonical Rust against that
regenerated maximum and independently assembled current authority. Only rights
and expiry may narrow. Persist its signed wire, verified narrowed fields and
independent relational binding atomically; denial persists no usable grant.
Decision receipts and signed material are immutable. Observed invalidation is
terminal. Approval/denial immediately release pending capacity while their
operation receipts still count toward the consumer lifetime bound.

Authenticate current host credentials and validate the submitted current runtime
before processing a decision retry. Invalid credentials return AUTH_REQUIRED;
a mismatched owner runtime returns STALE_EPOCH. A stale/expired retained pending
or approval becomes expired. A live exact repeated decision retains its original
result; an opposite decision or changed approval wire returns IDEMPOTENCY_CONFLICT.
A terminal denial cannot become approved. An approved grant uses its narrowed
signed expiry and current authority, not the earlier pending 120-second timeout.
For decisions, first compare the submitted tuple with the current stored owner;
a matching tuple with expired lease/freshness reaches retained-proposal liveness
and becomes expired permanently. A pending poll may reject an unusable current
runtime before exposing any specific proposal.
The peer-bound decision lookup uses the same AUTH_REQUIRED frame for an unknown
pairing and an unproven host scope, avoiding an existence oracle. A host client
must not treat that resource-scoped response alone as proof that its global
credential is revoked; credential liveness has the independent host-access path.

Creation retries and peer-owned reads must expose approved/denied states once
implemented, verifying persisted signatures again before returning usable grant
material. Consumer reads keep private Auth resolution outside database locks.
Channels, relay tickets, revocation revisions and terminal profile sourcing remain
separate boundaries; this implementation cannot enable them implicitly.

## ADR-023: authenticate either pairing peer and retain grant revocation

Status: bounded implementation and independent review closed against 8b7cba7f
and a588eb7d; all gates remain off.

Implement the existing pairing GET and grant revoke contracts without adding
fields. Bearer credentials are opaque: try a bounded host lookup against the
resource's stored host ID first. Only an explicit authentication rejection from
that function permits consumer fallback. Roll back and finish that transaction
before private Auth resolution, then recheck all eight consumer assertion fields
and exact issuing-consumer ownership in a new locked transaction. Lock failures,
unknown query outcomes and commit failures never trigger credential fallback.
Unknown resources and unproven host ownership have the same authentication frame.
Consumer authentication precedes a concealed not-found result for unowned IDs.

Peer reads return the direct PairingResult. Pending and approved reads regenerate
the saved maximum from trusted metadata and independently rechecked identities;
approved reads verify the persisted signature again against current authority.
Stale observations commit a permanent expired tombstone. Since a read can write
that tombstone, a lost commit acknowledgement yields OUTCOME_UNKNOWN. Host reads
need current host credentials, without a caller-supplied runtime body.

Keep original signed grants immutable at revision one. A separate immutable
grant_revocation receipt advances effective revision to two and atomically marks
its pairing expired. A deferred consistency guard forbids a receipt without the
tombstone. Existing creation retries and host decision paths already honor that
monotonic tombstone, so they cannot expose a revoked grant. Future channel
authority must also consult effective revision; channels do not exist here yet.

The first revoke with expected revision one returns revision two. An exact retry
with expected one returns the same receipt; expected current revision two on an
already revoked grant is a successful no-op. Other expectations conflict with
the actual effective revision after ownership verification. Preserve the full
canonical unsigned decimal request range, including values above PostgreSQL's
signed bigint, using a bounded integral numeric argument. Public conflicts use
the canonical REVISION_CONFLICT and exactly expectedRevision/actualRevision
details. Successful responses contain exactly grantId and grantRevision.

Reducing authority may use a current credential from the exact issuing host
family after runtime turnover or recipient expiry; it does not require the old
runtime or recipient to be live. Host peer reads and revocation bind the stored
host authorization ID as well as account and host, matching EitherOwnPeer policy.
A consumer must still prove its exact live issuing authorization. Revoking one
grant does not revoke its parent consumer or prevent a new pairing operation.
No channel, relay or production qualification follows from this boundary.

## ADR-024: retain independently assembled experimental channel admissions

Status: bounded implementation independently reviewed at2a5b0fb5/e8086075; relay and product gates stay off.

Use the existing channel creation, retained GET, host pending and admission
contracts. Creation returns the required channel wrapper; GET and admission
return direct ChannelResult. Tickets remain a separate boundary until a one-use
authority consumer and actual relay integration exist. No plaintext workspace
names, paths or terminal data belong in these control-plane rows.

Channel creation derives its trusted context from the verified narrowed approved
grant, a server-generated channel ID, fixed device/host roles, submitted target
IDs and independently current publication membership. Both host- and consumer-
created channels retain those crypto roles. Opaque peer authentication follows
ADR-023, including exact issuing host-family or consumer ownership and private
Auth resolution outside the global authorization lock.

The sole supported bounded profile is the server-owned constant
lomi-rust-grid-v1-experimental. It denotes the snapshot/delta protocol, not a
shell configuration. Attach it to a terminal tuple independently resolved from
current publication; never copy a profile from submitted signed context. The
host must compare it with its actual local TerminalContext.profile and exact
local membership before signing admission. Canonical signing alone does not
perform that local check. A future profile needs explicit contract/publication
policy; this fixed experimental policy does not qualify production terminals.

Set context issued time from PostgreSQL and expiry to at most 30 seconds later,
capped by the verified grant and credential deadlines. This is a handshake
window, not a relay lifetime or cached freshness lease. Every usable path still
checks live runtime lease, publication freshness and current authority under the
shared lock. After that fixed context expires, its retained HTTP channel result
becomes expired; reconnect uses a new operation and admission. Future active
relay lifetime needs its own continuous authority policy.

Keep at most 64 unexpired pending/admitted contexts per host and 1,024 retained
operation receipts per creator authorization. The creator namespace records H
or C plus its exact authorization ID. Exact operation retries preserve context,
channel ID, issued time and expiry; different normalized grant/revision/runtime/
target parameters conflict. Cap pending polls at 64 candidates before filtering,
and bound the complete response to one MiB. Expiry releases live capacity while
receipts survive until their creator authority is removed.
Retain immutable source IDs without cascading source-resource foreign keys:
removing the other peer or its grant must not erase a still-live creator's
operation receipt. Only creator lifecycle removal reaps that receipt. A missing
source grant or authority makes retained state expired; authenticated ownership
from the snapshot permits terminal recovery, never fresh authority or creation.

A sealed additive writer retains immutable context metadata and canonical bytes.
Use a same-transaction draft/finalize constraint so unchecked JSON/hex cannot
commit as a ready context. Recheck effective grant revision, revocation overlay,
pairing tombstone, identities, recipient/window, runtime, workspace and exact
terminal tuple on every path. Regenerate expected canonical context with the
existing Rust helper and compare its saved bytes before returning pending or
admitted data. Persisted admission signatures require fresh canonical verification
against independently assembled authority on every usable read.

The first valid host admission atomically retains its immutable wire. An exact
wire retry returns admitted while authority/context remain valid; changed wire
conflicts. Expired or invalidated contexts commit a monotonic tombstone and never
resurrect after publication or freshness returns. Reads and polls can write that
tombstone, so uncertain commit acknowledgement remains OUTCOME_UNKNOWN.

## ADR-025: separate one-use relay attachment from short admission proofs

Status: accepted implementation policy; implementation pending ADR-024 closure.
All product gates remain off.

The signed v3 context's maximum 30-second expiry is admission expiry. It does
not impose a 30-second lifetime on an established Noise transport. The crypto
verification token is point-in-time evidence; healthy established channels still
require continuously current grant, recipient, runtime and membership authority.
The product must not repeatedly reconnect solely to renew the admission clock.
Reconnect always needs a fresh channel and handshake. Preserve immutable signed
context bytes and deadlines.

Implement the canonical ticket endpoint with exactly runtime in its request
and channelId/ticket/expiresInMs in its response. Authenticate the exact issuing
H family or C, derive H as host and C as device, and verify the saved narrowed
grant/context/admission against fresh independent metadata before issuance.
Under the global authorization lock, cap each ticket at five seconds and the
remaining admission/authority deadlines. Store only a cryptographic token hash.
Return raw tickets only after successful commit; response loss cannot recover
raw secrets. A fresh issuance replaces an unconsumed predecessor for that role.
Retain at most eight issuance attempts per channel/role. A consumed role cannot
obtain a replacement attachment; it needs a new channel.

Use sealed ticket and transport-attachment records, with exact channel/role,
immutable expiry, consumed state and server-recorded attachment timestamp.
Both roles must consume within the original context window. Retain one relay
owner ID/epoch for the channel; a different owner can never resume it. A first
peer alone does not create an indefinitely live channel. Once both peers are
attached, the immutable upper transport deadline is the approved grant expiry,
with every current authority deadline checked independently. Enforce the
specified 256 active channels per host separately from the 64 pending-context
budget and the retained per-creator operation-receipt bound.

A relay attachment is routing authorization, not evidence that Noise completed:
the relay cannot inspect the encrypted handshake. Each endpoint must enforce
the original admission deadline through handshake completion, as well as the
local runtime/freshness fence before application effects. Starting a handshake
just before expiry does not authorize completing it after expiry.

Active validation must not reuse010's deadline-expiring retained HTTP helper as
its complete authority. Regenerate and verify the approved grant at actual
current server time. Reverify the immutable historical admission against a
server-retained, immutable attachment timestamp within its original window,
never a caller-supplied old clock. The historical proof alone grants no current
authority and must not produce a reusable new-handshake token. Recheck exact
account, host family/access epoch, C/window/parent, grant revision/revoke,
runtime generation/lease/freshness, workspace and terminal membership under the
shared lock on each validation. Authority invalidation permanently closes the
transport. Represent that reason separately from mere HTTP admission-window
expiry so a late descriptor GET cannot close a healthy active transport, and a
previously observed authority failure cannot be erased by restored publication.

Use one relay server and the existing single global owner lease across protocol
versions. Add an explicit v2 path and exact channelId/ticket first frame, bounded
to 16 KiB and five seconds, with no version autodetection or authority fallback.
Keep legacy authority and token scope isolated during staged coexistence; the
release cutover must separately disable the old product path. Add distinct
private v2 consume/validate routines with explicit channel ID, owner ID/epoch,
service authentication and fresh canonical verification. Private APIs return
only bounded routing/authorization metadata. Neither public clients nor relay
receive credential-table reads.

Preserve the relay's bounded quotas, one socket per role, disabled compression,
reserved renewal/validation slots, no application retry queue and five-second
fail-closed freshness measured from the start of successful authority work.
A late response cannot reopen a closed socket or extend an earlier deadline.
Owner loss, grant expiry and observed authority invalidation close both peers.
An already consumed ticket never becomes usable through restart or renewal.

Acceptance requires real restricted-role PostgreSQL and loopback WebSockets:
concurrent consume with exactly one success, wrong channel/role/owner, replay,
expiry during lock/verification, both peers exchanging opaque bytes, a genuine
Noise handshake and traffic beyond 30 seconds, late handshake completion denial,
HTTP context expiry without active transport loss, revoke/runtime/window/member
fences, immutable grant deadline, missing-peer timeout and owner replacement.
Run the 264-channel authority-lock/stall/revoke workload through actual v2 paths,
using multiple hosts to respect the per-host 256 bound, including competing
ticket churn and bounded in-flight validation. Preserve the earlier v1 baseline
as historical evidence; it cannot qualify v2.


ADR-025 migration boundary: existing010 routines are owned by the sealed
NOLOGIN execution role. The migrator receives no membership or replacement
right. Add an expiry-transition trigger under the same held global lock and
transaction: independently current authority failure, backward time or an
expiry observation before the signed deadline inserts the immutable invalidation
latch. Mere admission-window expiry with live authority leaves an established
transport untouched. Current authority can only become stricter as time passes;
publication cannot be restored concurrently while that lock is held. Active
validation always rechecks the latch and current state. No asynchronous
classification or operator source-template replacement is introduced.


ADR-025 private routing metadata includes both immutable admissionExpiresAt and
transportExpiresAt (Unix milliseconds), an authoritative active flag, and the
effective expiresAt selected from that stage. Both SQL role consumptions may
finish before their HTTP responses arrive, and responses may arrive in reverse
order. Socket arrival order therefore cannot determine activation. The relay
accepts an active response arriving first, requires identical account/channel/
owner and bounds for its peer, and never downgrades activation. It retains an
activation generation so a pre-activation validation response cannot undo the
promotion or refresh current authority. Actual deferred/reversed loopback
regressions exercise both races. Private fields do not change the public
canonical ticket DTO, whose expiresInMs remains a decimal string.

## ADR-026: explicit derivative consent and sealed authentication upgrade

Status: accepted architecture; implementation candidate and actual restricted-role
acceptance pending. This does not enable an application gate or qualify E2.

Legacy Remote web and mobile derivatives carry account-read authority. Neither
that scope nor renewal is consent to the v2 Remote data plane. Request the
additional exact scope `remote:v3:consumer` only during a fresh derivative login.
Consent version one must bind the displayed permission, approving browser
parent, actual target client/origin, single-use handoff and derivative principal.
The scope identifies v3 cryptographic consumer authority; the HTTP major remains
two. Existing derivatives receive no implicit upgrade or replacement authority.

Retain separate immutable consent and consumer deadlines, at most seven days
and no later than the original browser parent and derivative authorization
deadlines at consent. Later legacy renewal or mobile refresh cannot extend or
reclassify either record, clear its tombstone or mint replacement consent.
Reaching the fixed deadline requires a fresh login and consent. Derivative
consumers have `canManageAccount=false`; account management requires a separate
future decision. Consumer self-revoke retires its v3 authority. Derivative
logout, refresh replay or parent/account revoke additionally denies all related
consumer, window, grant and channel authority through current-state checks.

Preserve the actual opaque Better Auth parent ID and a distinct tagged origin
(`remote_web` or `mobile`) with its real derivative and service authorization
identities. Mobile does not change the browser parent's class. Private Auth
assertions form a strict versioned provenance union. A direct branch proves
the actual Better Auth credential; a derivative branch proves the actual web
token or current mobile access credential. No derivative hash is described as
proof of the parent token. Resolve outside the global database lock, then
recheck every submitted provenance field and current credential under that lock.
Host/relay recipient liveness checks the derivative principal and fixed consent,
rather than requiring an expired short mobile access token to remain usable.

Remote web mutations use its existing HttpOnly derivative cookie with exact
Remote origin, same-origin admission and CSRF marker; ambiguous credentials fail
closed. Native mobile uses its actual access bearer with browser credentials
rejected. Fresh handoffs bind the new permission through attempt, review, code
and exchange. The consent screen must describe remote terminal/file/Git access
and the host's separate local sharing/approval requirement before approval.

Three sealed routines currently enforce direct-only authority: inventory006,
assertion recheck007 and recipient recheck008. Every later consumer path and
host/relay retained-state path reaches these checks. Additive wrappers alone
cannot extend them, while cloning the entire lifecycle graph duplicates its
authorization algorithms. Unlike ADR-025's stricter expiry fence, this change
requires accepting a new authenticated principal class.

Use additive012 objects and versioned consumer wrappers, plus a literal,
checked-in operator upgrade limited to those three authentication routines.
Before any change, verify exact supported catalog definitions, signatures,
owners, definer/search-path properties and ACLs, plus role attributes and absent
memberships. Definition hashes must be measured on the pinned database fixture;
unknown or incomplete state aborts. One operator transaction holds the shared
authorization lock, seals new objects, grants exact derivative/consent columns,
installs the three literal definitions, removes API execution on old scalar
consumer roots and grants only new versioned wrappers. Old scalar operations
remain internal to their sealed owners. Both permission scripts and bootstrap
must preserve and verify the final state on reapplication. No sealed-owner
membership, login or permanent schema CREATE is granted to runtime or migrator.

This bounded operator step is an explicit exception to the additive-only
strategy used for011, not a general source-template replacement mechanism.
Before sealing, new entrypoints fail closed. A separate default-off gate requires
complete upgraded readiness. Acceptance must cover unknown catalog/ACL states,
transaction interruption/reapplication, direct-principal regression, legacy
scope denial, fresh web/mobile consent, exact provenance/credential races,
immutable expiry across refresh, tombstones and all downstream revoke paths.
Production execution remains subject to the deployment authorization boundary.
