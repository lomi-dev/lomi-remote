# Remote host recovery and credential handling

These procedures describe the implemented control paths. They do not certify
target operating systems or replace release acceptance. Use the installed,
verified CLI and its explicit `--profile-dir PATH` when several profiles exist.
Do not copy credentials, device codes, relay tickets, or private keys into logs.

## Stop sharing or revoke a host

For one workspace, read its ID with `lomiremote workspace list --json`, then run:

```sh
lomiremote workspace unshare WORKSPACE_ID --confirm
```

Unshare persists the local sharing fence before returning. It preserves local
terminal sessions and project files. Reconnect does not restore consent.

To disconnect this host from the account, run:

```sh
lomiremote logout --confirm --json
```

Logout first fences remote access locally and then attempts central revocation.
Keep a pending revocation pending if the network is unavailable; do not remove
the profile or manually reset its authentication rows to make it appear done.
Use `lomiremote login status --json` and `lomiremote doctor --json` for bounded
diagnostics. Diagnostics must not be used as an alternate authorization path.

For a lost host, revoke its host authorization from the account's device/host
management interface. For a lost consumer, revoke that consumer window or its
parent account session. A window revoke does not create another identity or
restore its grants. If the account is compromised, use the account's global
revocation control as well; local unshare alone cannot revoke other hosts.

During publication uncertainty, existing connections fail closed until Cloud
acknowledges the current state. Do not change this to queued writes or automatic
mutation replay during recovery. An uncertain push, commit, file mutation, or
terminal command must remain uncertain until its retained operation ID has an
authoritative receipt. Inspection is safe; submitting a new operation ID can
perform the mutation a second time.

## Rotation and login recovery

Host access/refresh rotation runs inside the host. Its retained rotation ID and
proof recover a lost response; do not rotate by editing the database or replacing
the native secret. A locked Keychain, unavailable DPAPI context, or unreadable
protected file is an error, not permission to generate another key.

After deliberate logout or central revoke, use a new explicit device login:

```sh
lomiremote login
lomiremote login code
```

Approve only the displayed trusted verification origin and intended host. The
host continues polling after the CLI exits. Login alone does not share a
workspace; sharing requires a separate explicit consent.

Git credentials are separate from host enrollment. Update or remove the exact
HTTPS remote's native credential using the hidden terminal prompt:

```sh
lomiremote git-credentials set --url https://git.example.invalid/team/repo --confirm
lomiremote git-credentials clear --url https://git.example.invalid/team/repo --confirm
```

The example URL must be replaced with the intended credential-free HTTPS URL.
On Linux, protected-file storage additionally requires
`--ack-os-permissions-only`. For an explicitly configured macOS Keychain, provide
the existing `--keychain-path`. Passwords/tokens are never command-line arguments.

Release signing keys and TUF role keys are operator assets, separate from host
credentials. Rotate TUF root keys with sequential, threshold-signed root metadata
under the established repository ceremony. Never replace an installed client's
embedded root pin or delete its retained `trust/` state to bypass verification.
Prepare the next signed bundle with [the release builder](../../release/README.md).
Publishing metadata or a release is a separate explicit operation.

## Offline backup and restore

Back up project directories independently of the host profile. The profile
contains identity, policy, receipts, and credential references; it is sensitive
even if the project itself is public. Use encrypted, access-controlled backups.

1. Stop a registered service with `lomiremote service stop`. For a macOS
   administrator-managed installation, use its protected CLI as administrator
   with the exact profile, account and recorded mode: `service stop --mode MODE
   --account ACCOUNT`. This mode-aware path also stops a Manual Host without
   reinterpreting it as a Login service. For an ordinary manual host, use
   `lomiremote daemon stop --confirm`. Close local clients which could start
   another owner. Require the owned service to be stopped and the native owner
   lock to be released before taking an offline filesystem snapshot. A process
   listing alone does not prove lock ownership.
2. Back up the complete private profile as one consistent offline snapshot,
   including SQLite sidecars when present, immutable identity files, and the
   persistent owner lock. Preserve ownership, restrictive permissions, ACLs, and
   directory structure. Do not restore a live `host.sqlite3` by copying only that
   file. Back up the updater's install/trust state separately if release rollback
   or TUF anti-rollback continuity is required.
3. Use the operating system's supported backup/recovery path for Keychain or
   DPAPI credentials. A profile copy does not transfer those credentials to a
   different OS account or machine. Protected-file credentials are part of the
   sensitive profile and must retain their permission boundary.
4. Restore only while all owners are stopped. Restore into a private directory
   for the intended original account, without following untrusted symlinks or
   reparse points. Never run two hosts from the same identity/profile backup.
   Keep the original backup immutable until recovery is complete.
5. If `activation.pending` exists, use the matching verified bundle's installer
   recovery path before invoking the installed host. Never delete the marker
   manually or start an older binary against a newer profile schema. The updater
   checks the actual offline database schema and signed object policy.
6. Restore a compatible release, then start the owned service or manual daemon.
   Read `status --json`, `doctor --json`, and `login status --json`. A restored
   terminal descriptor represents lost/stopped state; merely opening a view must
   not start a replacement shell. Restart a terminal only as an explicit action.

If native credentials cannot be recovered, keep the restored identity fenced,
revoke the old host centrally, and enroll a fresh host/profile. Do not synthesize
a new key inside an enrolled identity. Re-import project directories and obtain
new sharing consent. This preserves the distinction between recovering files
and reviving previously revoked authority.
