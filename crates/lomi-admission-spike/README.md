# S0.3 cooperative write admission experiment

This crate proves a bounded slice of `remote-server/02` and `09`: a separate
native writer asks the host before beginning its task, while separate file/Git
mutation clients use the same persisted coordinator. It is not the product
LocalApi, does not integrate Tauri, and performs no file or Git mutations.
The existing process-local `project_write_guard.rs` and session-host endpoint
were studied; the endpoint is adapted from that implementation.

Run from the workspace:

```sh
cargo test -p lomi-admission-spike
```

`host ABSOLUTE_PRIVATE_DIRECTORY` retains an exclusive `flock` owner for its
lifetime. The canonical directory must belong to the effective UID and have
mode 0700; the Unix socket has mode 0600. Accepted peers must have the same UID
(macOS/BSD getpeereid or Linux SO_PEERCRED; unsupported targets fail closed).
Length-prefixed JSON frames are capped at 16 KiB with a two-second total read
deadline, a 500 ms write timeout, 16 concurrent connections, 256 requests per
connection and 256 outstanding admissions. Git pointer files are capped at
4 KiB. SQLite FULL synchronous WAL commits the identity scope before success.
Capacity rejects new work; quarantine rows are never evicted to make room.

Acquire resolves physical device/inode identities, directory ancestry, Git
`gitdir`, `commondir`, and the worktree root. All three admission kinds use the
same conservative conflict policy, including common-directory collisions
across worktrees. Scopes and state survive process death. Namespace drift in
an outstanding identity fences all new admissions. Acquire replies only after
commit. A client must hold the same IPC connection during its protected task;
Renew extends its two-second lease, and Finish is the original connection's
assertion that its task is settled. Another connection cannot Finish, even
with the token. Disconnect, timeout, expiry and host restart quarantine the
admission. They never release it. An expiry sweep runs every 100 ms, and every
request also checks expiry before admission.

Reconcile is deliberately an explicit local operator assertion requiring
`confirmed_terminated=true` and a quarantined token. **It does not confirm
termination itself.** The process tests wait for the actual synthetic writer
child to exit before making that assertion. PID existence, lease age and IPC
liveness are never treated as proof of termination. Production needs a trusted
operator/reconciliation surface with audited termination evidence.

The process tests spawn the host, a long-lived cooperative native writer, and
independent mutation client processes. They show file/rename and Git admission
refused while the writer runs, refusal after its IPC disconnect while it stays
alive, refusal after host kill/restart, and admission after confirmed completion
or explicit reconciliation. They also cover directory ancestors, symlink
aliases, common-dir/worktree aliases, owner-only finish, renewal, expiry,
namespace replacement, exclusive ownership, oversized and partial frames.

## Explicit limits

- **Discovery credentials and challenge handshake are missing. This is not a
  secure product IPC protocol.** Private-directory access plus same UID is the
  experiment's boundary; any same-UID process that knows a token can claim a
  reconciliation assertion. There is no production host identity, client
  enrollment, reconnect proof, generation binding or authorization policy.
- Writers cooperate voluntarily. Editors, shells, independently invoked Git,
  and malicious same-UID processes can bypass this protocol. The host neither
  launches nor supervises the native writer. No OS sandbox or global filesystem
  serialization is claimed. Synthetic tests admit operations without executing
  their effects, so no effect CAS/durability/revision proof is claimed.
- This is Unix-only, exercised locally on macOS; Linux peer credentials have
  source support but require their own runtime qualification. Windows is absent.
- Directory identities and Git pointer resolution are checked, but this is not
  a race-resistant filesystem broker. No retained directory descriptors,
  openat capability traversal, mount/rename race defense, linked metadata
  validation, submodule qualification, arbitrary bare-repository discovery or
  hostile repository configuration support is claimed. Invalid Git pointers
  fail closed. Git scopes conservatively serialize sibling worktrees.
- Lease deadlines use the wall clock; backwards jumps can delay quarantine.
  Disconnect and startup still quarantine unconditionally; delayed quarantine
  does not release a fence. Renew after quarantine cannot revive an admission.
- The single mutex/SQLite coordinator and fixed limits are feasibility choices,
  not a load or denial-of-service qualification. SQLite failures must surface;
  storage corruption, disk exhaustion, migrations, GC and operator UX need
  product work. The database is local ephemeral experiment state, not a stable
  schema or API contract. Stop and remove the private runtime directory only
  after every experimental writer has been confirmed stopped.
