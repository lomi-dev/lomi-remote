# Local host store

`lomi-host-store` is the durable SQLite coordinator for the local host foundation.
It owns projects, their private local roots, canonical protocol workspace state,
sharing consent/fences, terminal descriptors, operation receipts, a bounded event
journal and a coalescing publication outbox. It does not implement IPC, shell/PTY
execution, credential storage, cloud authorization or a network publisher.

Open one `HostStore` per profile on a local filesystem with working SQLite locks.
The platform layer should also hold its profile owner lock. The connection keeps
SQLite `locking_mode=EXCLUSIVE` for its lifetime, uses WAL with `synchronous=FULL`
and foreign keys, and starts mutations with `BEGIN IMMEDIATE`. A competing store
returns `Busy`. No transaction is held across an external effect.

The stable host/profile identity is initialized once in metadata. Each open
creates a fresh runtime ID and advances a durable local owner generation; that
counter is a local fencing input, not a cloud-issued runtime lease or proof of
remote authority. Workspace IDs/epochs remain stable across restart. Root changes
and their epoch transitions are intentionally not implemented. Removing an empty
registration and adding its path again creates fresh workspace identity/epoch;
the removed identity and audit rows remain fenced.

`add_project` canonicalizes an existing directory and stores the root only in
local project records. `remove_project` removes only an empty registration with
no pending operation, preserves disk contents, and commits its fence/revoke
tombstone while retaining audit rows. Removed records consume a workspace slot
until a future retention policy safely expires them. `workspace` returns the canonical `WorkspaceState`.
`rename_tab` applies the protocol `terminal.rename` mutation with domain CAS;
state, next revision, canonical success receipt, event and outbox update commit
atomically. This foundation does not yet implement every terminal layout command.

Callers construct `OperationBinding` from an independently authenticated actor
and `StoredOperationRights`. The parameter hash must cover a canonical record of
method, targets, parameters and preconditions; exclude transport request IDs and
timeouts. The store binds actor/workspace/operation ID/method/hash. An identical
retry returns its prior receipt; changing method/hash or the admitted effective
rights/execution requirement for that key conflicts. Retry/start cannot downgrade `git.execute` or rewrite
immutable admitted rights.
Lookup checks current rights before exposing a receipt and returns `None` for
absent or foreign actor/workspace/method/hash bindings. `lookup_operation` resolves
an operation ID using its immutable stored rights, without trusting a new method
or parameter hash from the status request. `cancel_operation` cancels accepted
intent without an effect; a running intent only sets `cancelRequested`, preserving
its running state and finalization reservation. It never claims that a process
stopped. Final receipts remain unchanged; stale fences reject new cancellation
mutations. Cancellation requests survive finalization and crash recovery. No
plaintext effect parameters, credentials, keystrokes, commands or PIDs are stored
in operation rows.

For an external effect:

1. `admit_external` commits an accepted intent and reserves its two later events.
2. `start_external` commits running state and returns a one-shot `ExternalPermit`.
   Calling it again never grants another permit.
3. The trusted executor calls `check_external_fence` immediately before the effect
   while serializing effect admission against local unshare. This store cannot
   globally lock arbitrary processes or make an OS effect atomic with SQLite.
4. `complete_external` records a checked final receipt and optional next canonical
   projection atomically. It borrows the permit so a failed storage/validation
   transaction can be corrected and retried; a final receipt cannot be finalized
   again. An uncertain effect must be reported as outcome unknown, never retried.

Reopening after owner death changes running operations to `outcome_unknown` and
accepted, never-started operations to `cancelled`, in one recovery transaction.
Running terminal descriptors and their canonical panes become `Lost`
with no active session. Reopen never adopts a PID, spawns a process or replays an
operation/input. The trusted coordinator may call `record_clean_shutdown` only after terminal
shutdown has returned success. It records `Stopped` panes/descriptors without
active sessions, atomically advances revisions and emits events/outbox updates.
Repeated recording is idempotent. This API records confirmed shutdown; it cannot
stop or inspect an OS process itself.

`unshare` always increments and commits the local fence, clears consent and
replaces the workspace's pending publication with one revoke tombstone before
returning. This succeeds at ordinary admission capacity. A delayed old token
cannot acknowledge the tombstone. A real cloud publisher must independently
send/check the monotonic fence; rejecting a stale local acknowledgement alone
cannot undo an already-sent network publication. Consent and fence survive restart.

The outbox has one coalesced row per workspace; the workspace limit reserves that
row even when nothing is pending. Ordinary admission rejects a full event or
operation budget before an effect. External finalization uses reserved event
capacity. Unshare/cancellation/shutdown/recovery may evict the oldest journal entries and advance an
explicit low-watermark: `events_after` reports `resync_required` for lagging
readers. `prune_events_through` explicitly releases journal capacity. Operations
are not automatically expired or replayed: tombstone/retention policy and trusted
quarantine reconciliation remain work for later host integration.

Cloud publication persistence uses two strict version-1 JSON metadata records
without changing the SQLite schema: `CloudRuntimeState` and an immutable
`HostPublicationIntent`. A trusted caller constructs `CloudRuntimeScope` only
after independently validating the canonical Remote API origin and credential
family. The store checks bounded origin shape, current authorization generation,
unlocked authorization, pending revoke, process-local seal, host identity and
local owner runtime/generation. This scope is not a credential or authorization
proof. The installed server runtime ID must be the current local owner's runtime
ID; its server-issued generation is independent of the local owner generation.

`compare_and_set_cloud_runtime` records a verified fresh runtime claim with exact
state CAS. `prepare_host_publication` freezes one whole-host `PublicationParams`
and all current workspace outbox tokens under `BEGIN IMMEDIATE`. It includes
only consented, nonremoved workspaces, including empty ones, and canonical
running terminals whose local descriptors are running. Membership order is
deterministic. The intent stores IDs, epochs and revision/fence tokens, never
local roots, names or terminal titles. Local edits cannot rewrite a pending
intent; repeated preparation returns that same snapshot. Sequence advancement
is checked and bounded by SQLite's signed 64-bit maximum.

The caller must validate response provenance, origin, family, volatile logout
state and request association before acknowledging. A `PublicationResult` DTO
alone does not prove those facts. `acknowledge_host_publication` atomically
checks the exact intent, runtime and sequence, advances durable acknowledged
sequence, and clears only captured workspace tokens that still match. Later
unshare/edit tokens survive. A lost PUT response requires a verified runtime GET
with the exact host, epoch, generation, runtime and intended sequence through
`acknowledge_host_publication_from_runtime`; an advanced sequence is a conflict.
An already completed intent is rejected, rather than granting duplicate success.

Reopen retains predecessor runtime/intent as reconciliation evidence while
fencing its preparation and ACK. It never adopts predecessor sessions. The
current authorized owner can read that evidence, make an explicit reconciliation
decision, and invalidate the exact old state and intent while preserving the
workspace outbox. This also permits cleanup after an authorization-generation
change. Replacement requires a fresh claim for the current runtime ID.
No lease/freshness duration is persisted or grants authority; cloud freshness,
networking, response verification and publisher wiring remain caller work.
These APIs and their source tests do not establish runtime qualification.

Schema `user_version=1` is installed transactionally. An existing empty version-0
SQLite database receives a verified backup before initialization. Unrecognized
schemas/future versions are rejected; no upgrade from a released older store
schema exists yet. `checked_backup` uses SQLite's backup API, verifies integrity,
foreign keys and schema version, and fsyncs the completed snapshot. Backups are restricted to the same canonical protected directory as the
database; arbitrary export destinations are rejected. Unix parent directories
must have no group/other mode access, Darwin extended allow ACLs are rejected,
and backup files are created with mode `0600` before any bytes are written.
On Windows the same parent must have the private profile ACL established by
the native platform owner, which backup files inherit. Existing backup paths
are never overwritten. Network filesystems, disk/OS failures and
malicious database modification are outside this crate's durability guarantees.

Run `cargo test -p lomi-host-store` and
`cargo clippy -p lomi-host-store --all-targets -- -D warnings`. Tests use real
SQLite files, transaction rollback, owner contention, backups, stale CAS,
deduplication, capacity, delayed publication and a subprocess that exits without
running destructors to exercise crash recovery.
