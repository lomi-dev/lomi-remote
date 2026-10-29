# Native local transport

The Unix and Windows adapters expose `OwnerLock`, `OwnerEndpoint`, `LocalClient`,
`LocalConnection`, `LocalDiscovery` and closed diagnostic errors. Windows accepts
its native `PipeStream` rather than `UnixStream`. Both use the canonical protocol
IPC 1 hello, checked request/response codecs, stream envelopes and correlation.
They do not implement host services, SCM installation, credentials or PTYs.

The Windows adapter pins each canonical local directory component with handles
that deny delete sharing. It rejects UNC/noncanonical/reparse paths, untrusted
ancestor replacement rights, wrong owner SIDs, hardlinked regular files and
non-private profile DACLs. The profile has an explicit protected owner-only DACL;
private files may inherit the same owner-only grant. Inherit-only allow ACEs
on the profile are also rejected, so new SQLite databases and WAL/SHM sidecars
cannot inherit an untrusted grant. Deny-only ACEs are accepted
because they cannot grant authority. SYSTEM, Administrators and TrustedInstaller
are trusted OS authorities for ancestor ownership/replacement, not IPC peers.
The lifelong owner file uses `LockFileEx` and is never unlinked.

Use a protected user-profile child for the profile. The tested Windows 10 LTSC
machine grants AppPackage DELETE permissions on AppData/Local/Temp ancestors;
the adapter deliberately rejects those chains. Tests create exclusive UUID
folders directly beneath USERPROFILE and never change existing user directory ACLs.

The initial named-pipe instance uses `FILE_FLAG_FIRST_PIPE_INSTANCE`, a restrictive
owner SID ACL and `PIPE_REJECT_REMOTE_CLIENTS`. Acceptance creates a replacement
listener before handing off the connected instance, including after a peer
abandons its connection. The pipe name stays owned continuously. Active accepted
connections are limited to 32; the coordinator also bounds its handshake workers.

The connected pipe's kernel server/client PID is used to open and retain a live
process handle and query its token SID. This authentication happens before JSON
parsing. The client opens with `SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION`;
a server cannot obtain the client's impersonation authority. JSON SID/PID claims
are never used. The canonical hello then binds profile, host, runtime and nonce.

Connect/read/write use overlapped handles. Frame I/O keeps one absolute deadline,
checks the length prefix before payload allocation, and cancels pending I/O with
`CancelIoEx`. Cancellation drain is bounded to 500 ms so kernel-referenced buffers
cannot be freed while pending. If cancellation is not confirmed, the process-wide
adapter fails closed and retains that bounded operation until process exit;
already pending connections can each retain one operation. Ordinary deadline
handling drains cancellation and releases buffers. This does not claim recovery
from a stalled or malfunctioning OS driver. Client correlation/stream failures
close and poison the connection before returning.

Native Windows evidence is produced by `tests/platform-windows/run_native.py`.
It uses the pinned SSH host, a fresh owned UUID directory, exact source inventories
and hashes, an offline-derived subset Cargo lock whose dependency versions,
sources and checksums must match the workspace lock, and a bounded native process
runner. It records actual OS/toolchain and test binary hashes, then removes only
its owned remote inputs after confirming no owned process remains. The tested
scope is the recorded Windows 10 Enterprise LTSC build; Windows 11 and Windows
Server are not qualified. Cross-compilation alone is not qualification.

The `secrets` module defines the E1 host secret-storage boundary separately from
local transport. It holds one opaque, nonempty bundle of at most 32 KiB, without
serde or plaintext diagnostics. Owned secret buffers are zeroized on drop;
callers remain responsible for erasing their input and any exposed copies.
Selection reports `Unconfigured`, `Available`, `Locked` or `Unavailable` with a
provider kind. macOS Keychain, Windows DPAPI and Secret Service are explicit
unimplemented selections and report unavailable, with no fallback or file effects.
No host/coordinator/CLI/enrollment or existing Chat/AI keychain is wired here.

On Unix, `unix::secrets::ProtectedFile::open` requires a borrowed validated
`PrivateProfile` and an explicit `Selection::ProtectedFile` acknowledgement of
OS-permissions-only protection. This is plaintext storage, not an encrypted
store. Use the account and profile that will actually run the host. The provider
accepts no arbitrary filenames and never writes secrets to SQLite. It revalidates
ancestry and pinned directory identity, rejects non-private owners/modes, links,
nonregular files and ACL grants (Linux POSIX ACL entries are rejected entirely).
Its persistent `host-secrets.lock` is exclusively locked and never removed;
contention reports locked. A missing bundle is available but empty. An invalid
existing bundle fails opening rather than being silently overwritten.

`host-secrets.bundle` has a fixed magic, big-endian length and bounded payload.
Reads validate regular-file metadata and the header before allocation. Writes
create an exclusive UUID temporary file with mode 0600, sync its contents, rename
atomically without hardlinks, and sync the directory. Errors before rename
preserve the prior bundle. A directory sync failure after rename reports
`CommitUncertain`: callers must inspect state before retrying. A process crash
may leave a private `.host-secrets-*.tmp` remnant; it is never reused, restored or
published automatically. Backup/restore fencing, controlled remnant cleanup and
cross-system credential rotation recovery remain separate deliverables. No
protection against malicious processes under the same UID or administrators is
claimed, and disk copies contain plaintext.

Focused native checks: `CARGO_INCREMENTAL=0 cargo test -p lomi-platform --locked
--offline --test unix_secrets` and `CARGO_INCREMENTAL=0 cargo test -p lomi-platform
--locked --offline --lib failed_atomic_update`. These use fixture bytes only.
