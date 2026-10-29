# E0 enrollment store experiment

This executable experiment tests proposed host enrollment/rotation invariants in
an isolated PostgreSQL 17 database using Bun and pg 8.23.0. It is not a second
control plane, backend server, Better Auth plugin or production migration. The
central platform remains auth-app/Bun/Better Auth/PostgreSQL; no application is
modified and no real platform request is made.

Run from the new repository root:

```sh
python3 tools/run_enrollment_spike.py \
  --pg-bin /Applications/Postgres.app/Contents/Versions/17/bin \
  --output tests/enrollment/evidence.json
```

The runner creates a new private Unix-socket-only PG17 cluster, applies the
experiment schema, creates a restricted runtime role, builds the Rust canonical
proof fixture, runs TypeScript checks and Bun tests, and stops/removes its
cluster. It ignores inherited database URLs, PostgreSQL credentials and .env
files. Fsync remains enabled. Synthetic setup uses a database owner; store calls
use a non-superuser role without DDL or enrollment-approval permissions. Errors
retain only check outcomes and runner totals, without credential values or SQL
result payloads. If PostgreSQL cannot be stopped, its files are preserved.

## Implemented proof

Approved enrollment records bind account/epoch, host ID/key fingerprint, exact
bootstrap session, fixed host-enrollment class and the canonical challenge.
Bindings cannot be changed by SQL updates, even by the fixture setup owner.
Enrollment/account ownership is checked by composite foreign key. Runtime cannot
create or rebind approved enrollments. Account locks serialize store mutations,
refresh and global revoke across processes. This coarse lock is a correctness
fixture; account-lock contention still needs measurement.

`crates/lomi-enrollment-fixtures` is a test-only bridge to the canonical Rust
crypto API. It uses intentionally public synthetic fixture seeds and can only
prove that one fixture host/account. Bun never implements signature bytes or
signature verification. Proof exchange checks the independently stored expected
challenge, approved bootstrap and class, exact operation, trusted host fingerprint
and expiry. This does not establish an actual Better Auth principal: test setup
seeds the approved record, and platform hook binding is still required.

A repeated exchange uses the same operation and host proof to recover the exact
same encrypted response for 30 seconds; it cannot create another family. A host
acknowledgement closes exchange recovery. Expired unconfirmed exchange receipts
cause family revocation before deletion. A pending approval from an older account
epoch cannot survive global revoke/reactivation.

Refresh challenge/rotation binds the existing credential hash, operation and a
fresh signed challenge. The actor merges the same operation and refuses another
while one is in flight. SQL also serializes independent processes. Exact-operation
recovery returns the same ciphertext; consumed-token reuse with another operation
or after recovery is lost/expired revokes the family. Refresh invalidates the old
access token. Global revoke increments the account epoch and revokes families and
recovery in one transaction; suspend/reactivate never restores old credentials.

The database stores random credential hashes and short encrypted receipts, never
plaintext refresh/access tokens. Recovery uses Node's maintained AES-256-GCM with
random 96-bit nonce and associated data binding domain, kind, subject, operation,
account and prior credential hash. The runner injects a fresh 256-bit test key in
the worker environment; it is never written to the database or report. Production
key storage/rotation and KMS policy are not implemented. One receipt is retained
per enrollment/family scope, capped at 4096 bytes and 30 seconds. `purgeExpired`
is explicit maintenance; no background retention scheduler or total tenant
budget is claimed. Successful retry does not extend the retention deadline.

Tests launch real child processes and exit them before DB commit, after commit
before receipt delivery, and after receipt is held in memory but before caller
storage. DB rollback or exact recovery prevents duplicate families/rotations.
These tests do not simulate a machine power cut or an OS keychain's atomic write.
They do not log credentials, raw proof payloads or database results.

## Remaining acceptance decisions

1. Keep these isolated exchange/rotation/global-revoke results as E0 evidence;
   integrate into actual Better Auth enrollment/class hooks only after a reviewed
   schema and explicit principal/session binding tests.
2. Implement consumer web/mobile/desktop SQL FK ownership and multiple window-key
   lifecycle in a separate proof. They are not implemented or qualified here.
3. Choose production recovery TTL, total quotas and key backend after platform
   credential-receipt crash tests and account-lock contention measurements. The
   30-second test value is provisional.

No HTTP route, production capability, host secret store, consumer grant/window,
mobile ABI, relay channel, deployment or global account-platform integration is
claimed by this package. The SQL script is confined to a fresh experiment schema.
