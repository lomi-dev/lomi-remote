# Actual Better Auth enrollment binding experiment

This E0 proof runs Better Auth **1.7.6**, Kysely **0.29.6** and pg **8.23.0**
against a disposable PostgreSQL 17 cluster. These versions match the audited
`auth-app` installation. It is an isolated implementation-path experiment, not a
second platform or a replacement auth server. No existing application is edited,
no production route is mounted and no request leaves the process.

Run from the new repository root:

```sh
python3 tools/run_auth_binding_spike.py \
  --pg-bin /Applications/Postgres.app/Contents/Versions/17/bin \
  --output tests/auth-binding/evidence.json
```

The runner builds the existing canonical Rust enrollment fixture, installs the
package from its frozen Bun lockfile, checks types, creates a private socket-only
PG17 cluster with fsync enabled, generates Better Auth's real schema using its
pinned migration API, installs the experiment schema and restricted runtime role,
runs real handler/SQL tests, and stops/removes the cluster. It ignores inherited
DB URLs, PostgreSQL credential files and dotenv files. Failed shutdown preserves
the cluster instead of deleting files under a running server. Reports contain
versions, source digests, check exits and runner totals, without session tokens,
proof payloads, secret values or environment contents.

## Verified APIs and transaction boundary

Official references: [Device Authorization](https://better-auth.com/docs/plugins/device-authorization),
[PostgreSQL adapter](https://better-auth.com/docs/adapters/postgresql), and
[database concepts](https://better-auth.com/docs/concepts/database). Version-specific
behavior was checked against the installed 1.7.6 sources, especially
`better-auth/dist/plugins/device-authorization/routes.mjs`,
`@better-auth/kysely-adapter/dist/index.mjs`, and
`@better-auth/core/dist/db/schema-check.mjs`. The runner records source SHA-256.

The actual `/device/code`, `/device`, `/device/approve`, `/device/token` and
`/sign-out` handlers run in-process. Device redemption uses the plugin's
`consumeOne` path and creates an ordinary Better Auth session. The supplied
Kysely transaction is passed as `database.db` with `type: "postgres"`, explicit
schemaName and `transaction: false`; every binding hook and SQL statement shares
that connection and transaction. A deliberately coarse advisory transaction lock
serializes these auth mutations and global revoke. A forced exception after
handler session creation rolls back the consumed code, issued session, class and
bootstrap mapping; retry can then redeem once.

The pinned Kysely adapter's runtime schema introspector calls `.connection()`,
which a Kysely `Transaction` rejects. Setup therefore runs the **actual schema
validation on the outer connection**, after Better Auth generates its schema,
then uses the documented-in-source
`advanced.database.validateSchema: false` only on transaction-bound instances.
No adapter or dependency source is patched. Schema validation must be repeated
after a production migration/configuration change; this proof does not establish
a general production transaction integration policy.

Email/password is disabled, no OAuth providers are configured, cookie caching is
disabled and Better Auth logging is disabled. Request rate limiting is disabled
only in this finite fixture; production rate limiting remains required. Tests
seed synthetic browser cookies with Better Auth's real `makeSignature`. Better
Auth's normal database schema stores synthetic session tokens; this package does
not claim to change that framework storage policy or issue host credentials.

## Binding demonstrated

Public `client_id`, body class, headers and caller session IDs never select the
host bootstrap class. A host-enrollment entrypoint creates an immutable
server-owned record binding the actual device-code hash, signed account-independent
host-key descriptor, initial commitment, nonce, operation and new Remote bootstrap
UUID **before approval**. There is no account or bound-bundle fingerprint yet.
The real browser handler claims/approves the code for its authenticated account;
the coordinator asks the canonical Rust API to derive the bound bundle/fingerprint
from that stored descriptor and the approved remote account, then commits the
account/epoch/fingerprint binding in the same transaction. Plain device-code requests using
the public host client name still produce ordinary desktop sessions and cannot
exchange for a host principal.

On redemption the coordinator reads that existing approved record, invokes the
real token handler and binds the exact issued **text Better Auth session ID** to
the separately allocated **UUID Remote bootstrap principal**. IDs are deliberately
non-UUID text in the Better Auth fixture. Composite foreign keys bind bootstrap,
enrollment, account and server-owned session class. The bootstrap session cannot
create a consumer, approve another enrollment, or become a host authorization
without canonical proof of possession.

Proof verification invokes `lomi-enrollment-fixtures` from the extracted Rust
crypto source. It signs/verifies only public synthetic fixture seeds; Bun does
not implement canonical signature bytes or algorithms. Same-account foreign
sessions, another bootstrap, key/context changes and replay fail. Successful
proof consumes the bootstrap, expires its ordinary Better Auth session and
creates an independently scoped host-authorization record. `hostAllowed` is a
DB policy assertion over that synthetic record, **not an authenticated production
endpoint or a bearer credential format**. Host credential issuance and the
existing enrollment-store recovery experiment are not integrated here.

## Consumers and windows

Each consumer has exactly one web/mobile/desktop session FK, with a matching
constant class and account in a composite FK. Shape checks and immutable triggers
reject multiple parents, wrong class, cross-account linkage and reparenting.
The web fixture is a synthetic browser session; desktop sessions are issued by
the actual device handler. Mobile rows model a trusted existing native session
classification; a mobile login/refresh protocol is not implemented or qualified.

Two window identities under the same consumer/session can coexist. A database
trigger serializes inserts on the consumer and enforces at most two active
identities, including concurrent direct SQL from the restricted runtime role.
Refresh retires only the old identity for that window. The other window survives.
Actual Better Auth sign-out deletes the session and cascades consumer/window
bindings. Immutable triggers prevent identity reparenting and retired-key reuse.
Window fingerprints are synthetic opaque identity references, not implemented
Noise sessions, ephemeral key generation or per-window grant issuance.

The global-revoke experiment increments the remote account epoch, revokes host
principals/enrollments and deletes account sessions and pending device codes in
one transaction. It races redemption and canonical exchange. Suspending then
reactivating the account cannot restore old tokens, bootstrap mappings or window
identities. This is not wired to the existing platform's global revoke endpoints.

Remaining gates: production auth-app route mounting and all-handler bypass audit,
reviewed migrations and role policy, actual consent UI/client-class provisioning,
mobile login binding, account-lock contention, host credential/recovery receipt,
per-window crypto/grants, relay admission, platform integration and deployment.

The first-login account-unknown binding is now demonstrated by the isolated real
PG path. `PendingHostIdentity` commits keys before approval; the server stores
`SignedHostKeyCommitment` and its canonical pin immutably. Approval derives the
bound fingerprint without replacing any public key. The fixture's `pending-sign`
consumes a recreated pending wrapper for the approved account, and canonical
`verify_committed_host` checks PoP from stored init bytes plus that account, with
no request-supplied replacement bundle. Tests approve either synthetic account
from an account-free init, reject key/host/commitment substitution, valid proofs
for the wrong account, reparenting and bootstrap reuse.

The native seed blob is unchanged and can recreate a pending wrapper. Consuming
one wrapper is not a durable anti-rebinding guarantee: the cloud enrollment's
immutable approved-account CAS rejects reapproval/rebinding of the same init
record to another account. The tests explicitly reconstruct the same fixture
seed to produce a mathematically valid foreign-account proof and show the stored
record rejects it. OS credential receipt/storage, real initial-key pin delivery,
host-installation ownership across separate enrollments, release profile and
production deployment remain unqualified.

The runner keeps `exitCode: 1` until both native shutdown and private-directory
cleanup complete. Stop attempts that time out or are interrupted are recorded
without payloads. The real-cluster failure regressions run the actual successful
suite, inject shutdown timeout/interrupt, assert failed evidence and preserved
cluster files, then explicitly stop and remove only their own test cluster:

```sh
AUTH_BINDING_TEST_PG_BIN=/Applications/Postgres.app/Contents/Versions/17/bin \
  python3 -m unittest discover -s tests/auth-binding -p 'test_runner_shutdown.py'
```
