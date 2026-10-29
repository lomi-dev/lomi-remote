# Durable TUF caller trust state

This crate resolves the three raw Tough persistence failures demonstrated by
`lomi-release-spike`. It uses pinned `tough=0.24.0` for TUF signatures, metadata
verification, expiration and target hashing. It provides bounded local mirrors,
HTTPS release transport, Unix/Windows activation adapters, and an opt-in release
CLI and its installer lifecycle whose bootstrap root is embedded during a
pinned release build. See
[`release/README.md`](../../release/README.md) for the build and install flow.
It does not generate keys, sign TUF metadata, or publish artifacts.

`TrustStore::initialize` creates a new canonical, owned 0700 directory exactly
once. A durable initialization marker precedes database creation. An existing
or interrupted initialization is never silently reset. `TrustStore::open`
requires the marker, existing SQLite database, complete committed state, valid
checksums/signatures and clock; missing, malformed, empty or truncated state
fails closed. Administrative recovery of an interrupted initialization remains
an explicit operator task; there is no automatic reset command.

An owned private 0600 `owner.lock` file carries an exclusive OS `flock` for the
handle's entire lifetime. A competing process receives `WouldBlock` and must
retry after the owner exits. Directories must use their canonical path. Symlink
state files, hardlinked state files and loose permissions are rejected. Ancestors
must be owned by root or this UID; writable ancestors require the sticky bit.
Unix uses `flock`; Windows uses a protected current-user-only DACL and an
exclusive file lock. Cross-platform release acceptance remains pending.

Each update follows this order:

1. Validate the last committed row before handing anything to Tough. Root,
   timestamp, snapshot and top-level targets signatures and version links are
   checked. SHA-256 detects accidental corruption of the complete row, including
   the unsigned clock watermark. This checksum is not an authentication scheme.
2. Seed a private temporary Tough datastore from that row. Supply the **newest
   committed root**, never the original bootstrap root after advancement.
3. Verify metadata with default Safe expiration enforcement. Optionally consume
   the entire target stream and its final hash result into bounded memory.
4. Validate all five staged metadata/clock records, recheck expiration after
   target verification, and advance the final nondecreasing clock watermark.
   Replace the complete row in one SQLite transaction using rollback journaling,
   `synchronous=FULL` and macOS `fullfsync=ON`. Failed verification never modifies
   the committed row. A filesystem directory sync follows successful commit.
5. Return verified target bytes only after the durable commit completes.

The row includes root, timestamp, snapshot, targets, latest-known-time, generation
and a framed integrity digest. SQLite lengths are checked before copying BLOBs
into Rust. Metadata files are limited to 1 MiB each, executable targets to
256 MiB, each verification to 576 MiB, and root rotations to 32. The aggregate
bound admits a Windows release pair containing a CLI and managed-login helper,
each up to the per-target limit. Bounded transports
enforce limits even where Tough would honor a larger signed metadata length.
Nonempty delegated roles fail closed, since their rollback state is not
implemented. Release HTTPS uses a fixed credential-free origin, disables
redirects and proxies, and only fetches from the origin's `metadata/` and
`targets/` paths.

Validation from the repository root:

```sh
cargo test -p lomi-update-trust --all-features
cargo clippy -p lomi-update-trust --all-targets --all-features -- -D warnings
cargo check -p lomi-update-trust --no-default-features
```

The `fault-injection` feature is disabled by default. It enables test CLI hooks
that call `_exit` immediately before or after transaction commit, and a lock
holder controlled through stdin. Ten integration tests use real child
processes and bundled SQLite to verify corruption rejection, exclusive owner
serialization, crashes on each side of commit, persisted root rotation without
re-fetching `2.root.json`, rollback after restart, expiration, bad signatures,
payload tampering, allocation limits, FIFO mirror rejection with child-process
deadlines, and exact verified byte delivery. Nonblocking file opens precede
regular-file checks, so a FIFO cannot indefinitely hold the update lock.

Test code alone references the already vendored published Tough RSA test key,
root and rotated-root fixtures in `tests/release/fixtures`. Their immutable
source URLs, SHA-256 digests and upstream licenses are recorded there. No test
key or fixture path is present in the library or normal CLI. The rotated fixture
expires on 2029-07-27; tests must be reviewed and refreshed when it expires,
without disabling Safe expiration enforcement.

The crash tests exercise abrupt process death, not power cuts or filesystem
corruption during device cache loss. SQLite durability assumes a correct local
filesystem and storage device. Same-UID malicious writers, restoring a complete
older database/marker backup, hardware clock compromise, and operator bootstrap
trust are outside these filesystem checks. Orphaned staging directories after
crashes are not reused as trust state; automatic cleanup and disk quotas remain
future lifecycle work. Delegations, automatic network retries, platform
qualification, bootstrap key ceremony, and production release signing remain
unimplemented or unqualified. The original negative spike remains unchanged.

## Stable executable activation

Unix builds also expose `TrustStore::update_and_activate` and the matching
`activate DIR METADATA TARGETS TARGET INSTALL_DIR` CLI command. This API accepts
metadata and target mirror paths, a target name, and an install directory; it
does not accept caller-supplied content bytes. It uses the same private TUF
verification and durable trust commit as `update`, then stages only the
verified target under `objects/sha256/<digest>`, maintains relative active and
previous pointers, and atomically replaces a stable regular `lomiremote`
executable path. The install directory must already be
canonical, owned by the effective UID, mode 0700, and have no symlink path
components. Each path component must be owned by root or the effective UID;
group/world-writable ancestors must be sticky. Object directories are created
mode 0700 and files are stored read-only as mode 0500. The staged file and
relevant directories are synced before and after the pointer swap.

The macOS release CLI also has a separate administrator-managed boot path.
It requires an explicit account name, a preexisting profile and `owner.lock`
owned by that account, a root-owned mode 0755 activation directory, and an
exact boot-service registration bound to the selected account and stable path.
An O_EXCL root-only binding records the account UID and canonical profile path
and survives release uninstall with the TUF state. The native adapter stops
that LaunchDaemon before taking the account-owned `owner.lock`; the updater
holds both locks while it opens the database and sidecars relative to the
retained profile directory, copies a bounded snapshot (at most 1 GiB) into a
private directory under the install root, and checks SQLite integrity and
schema on that copy. It removes and syncs the temporary snapshot before
activation, recovery, rollback, or uninstall proceeds. Profile directories and
database ownership are never changed by this updater path. Activation objects
and state remain root-private. Stable executables use mode
0555 so the selected LaunchDaemon account can execute the root-owned copy.
The ordinary per-user mode retains its existing 0700 directory and 0500 stable
executable policy.

The durable `activation.pending` journal is also the startup deny marker. Its
v2 record binds active/previous main and companion pointers; it remains until
stable executables and pointer directories are synced. The host CLI and helper
refuse startup whenever the marker exists or is unreadable. An interrupted
update restores the journaled prior state before clearing the marker.

Release installers inspect and repair that journal with the standalone updater
before invoking the installed CLI. The updater stops an existing managed
service through the native service adapter, then holds the profile OwnerLock
while reading the actual SQLite schema read-only. It validates every journal
and pointer object's hash, private metadata sidecar, and signed policy shape,
then checks the restored active pair against the schema before restoring the
whole executable pair. Retained rollback targets are schema-checked again at
rollback time. The startup deny marker is
cleared only after pointers and stable executable files agree. Unknown service
state, a busy owner, malformed schema, or incompatible object leaves recovery
pending and blocks startup; the updater does not infer schema zero.

Windows release installs independently verify the CLI and `lomiremote-host.exe`
from one TUF snapshot, require matching signed release policy, stage both
objects, and update both stable paths in the same journaled activation. Rollback
checks the previous signed profile schema range before replacing either file.
The installer leaves service enablement untouched and resumes the prior host
mode after update.

Activation covers process-crash recovery, not power cuts or storage-device
cache loss. Linux/macOS/Windows service-manager acceptance, production root
provisioning, notarization, Authenticode signing, and TUF publication have not
been performed in this workspace.
