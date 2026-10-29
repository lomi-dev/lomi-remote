`lomi-host-auth` is the native product library for one host credential lifecycle.
It performs no network requests and selects no storage provider. Callers retain
exclusive ownership of the explicitly configured `SecretStorage` implementation
and borrow it into `HostAuth::open` with trusted host, profile, origin, client
configuration and a trusted Unix-second time anchor. Missing storage is reported as `Empty`; creating a new identity
requires an explicit `initialize`. Unreadable storage never creates a replacement.

The lifecycle is `PendingInit → AwaitingApproval → Approved → ExchangePrepared →
Unconfirmed → Ready → Rotating → Ready`. Each transition replaces one protected
bundle. Request getters become available only after the relevant transition
succeeds. A failed write before publication keeps the previous state. An uncertain
commit seals the manager and erases its in-memory record; drop it and explicitly
reopen the provider to inspect the published state. Explicit pending cancellation
cannot discard an exchange, rotation or unconfirmed credential intent.

Protected bundle v3 retains the first approved account independently of the
account-independent key commitment. Opening older bundles validates their exact
state before durably migrating scheduling/account bindings. Public presentation
exposes only the user code and local deadlines. Polling durably reserves its next
eligible time before exposing the device code; authenticated slow-down adds five
seconds. Restart cannot accelerate polling.

After a validated TLS revoke acknowledgement, `Revoked` durably retains account
and prior/acknowledged epochs while retiring credentials. The owner can recover
that acknowledgement after a crash and finish its SQLite pending-revoke handoff.
Only explicit subsequent login calls `restart_after_revocation`; it preserves
keys and the account binding. `revocation_credential` deliberately permits an
expired Ready/Rotating credential solely for the revoke acknowledgement endpoint;
it grants no ordinary access. A different account requires a separately
authorized new host/profile identity transition.

`accept_tls_approval` requires the caller to authenticate the response using TLS
to `Config::origin()`. Its origin argument is an assertion about that authenticated
connection, not proof supplied by this library or a field to trust from a response.
The library checks the approved account, retained enrollment, complete committed
three-key identity, fingerprint, canonical challenge and fixed exchange audience
before finalizing its own pending identity. Audiences derive from a canonical
HTTPS origin and fixed protocol paths. The currently accepted authority syntax
is lowercase DNS/IPv4 with an optional nondefault numeric port, without user
information, path, trailing slash, query, fragment or IPv6 literals.

`Unconfirmed` permits only `registration_request`; normal `access_credential` and
rotation remain blocked. Registration success commits the epoch and removes
bootstrap/device/enrollment material. `Rotating` preserves the old credential,
rotation ID and canonical proof for exact retries; it blocks normal access and
cannot create a second rotation. A validated response replaces credentials and
clears rotation intent in one storage write. Duplicate current responses do not
extend expiry. Access responses must specify exactly 300 seconds.

Status and errors are redacted and secret state has no `Debug` implementation.
Owned seeds and tokens are zeroizing. JSON serialization writes directly into a
bounded zeroizing buffer, and parsing rejects input over 32 KiB, unknown fields,
unsupported versions and inconsistent identity/state. Public request DTOs and
returned access credentials contain transport secrets in the protocol crate's
redacted wrappers: the caller must protect their lifetimes and serialization and
use them only for their documented request. They are not loggable artifacts.

Tests use an injected provider for publication failures and uncertain commits.
The `protected_file` example is a native Unix process/reopen probe requiring an
explicit `OsPermissionsOnly` acknowledgement and a trusted private fixture path.
These tests establish library/storage behavior, not HTTP, PostgreSQL, DPAPI or
native Keychain integration.

Every time argument, including the required open/restart anchor, must use trusted
Unix seconds projected onto a nondecreasing timeline across reopen. The
host caller owns that clock projection; raw `Instant` units and separately sampled
adjustable wall-clock values do not satisfy this contract. The manager rejects
backward observations in memory and persists the latest observed time on existing
state writes. Read-only observations do not trigger a storage write, so their
latest time is not retained across restart: the caller's clock contract still
applies there. Approval and exchange retain the exact canonical server challenge
and require both its signed expiry and the local conservative enrollment deadline
to remain live; the signed challenge may expire later than the local estimate.
Credential deadlines derive from the original durably prepared exchange/rotation
request time plus 300 seconds, never retry-response arrival. Server-side expiry
remains authoritative.

Protected JSON accepts only bounded ASCII bytes without backslash escapes before
serde parsing. Its own serializer needs no escapes for the strict field alphabets;
rejection prevents escaped secret strings from entering serde scratch allocations.
Validation checks secret alphabets and lengths through borrowed bytes.

`tools/validate.py` uses an explicit source allowlist and writes a fresh private
UUID directory under `artifacts/rust-host-auth`. Exact source copies and hashes
are captured before commands; after hashes must match. Every command gets a
separate retained receipt, including failures. Completed evidence is read-only.
The earlier `evidence/local.json` receipt is historical and is never overwritten.

Scoped v3 crypto is available only from unsealed, confirmed `Ready` credentials
before their local access deadline. `public_host_identity(now)` returns only the
public account, host, signed three-key identity wire envelope, full fingerprint,
credential family and verified access epoch. `sign_grant_v3` and
`sign_channel_admission_v3` take canonical typed inputs and trusted Unix seconds;
they additionally require the saved account, host, fingerprint, family and epoch
and current grant/admission expiry. No seed, `Identity`, general signer or
arbitrary-byte signing API is exposed. Pending, unconfirmed, rotating, revoked,
expired and commit-uncertain instances cannot create new cryptographic authority.

`accept_runtime_observation(expected_local_epoch, snapshot, now)` synchronizes
only the authoritative host access epoch from a typed `HostRuntimeGetResult`.
Before calling, the owner must authenticate the runtime GET over TLS against its
independently pinned Remote API using this current credential family's host
access credential, then recheck its store generation and volatile logout gate
before mutation. The method does not authenticate TLS or accept a URL/assertion
as transport proof. The expected epoch is the saved local epoch captured for the
request, not caller time. A fresh, confirmed `Ready` record and an exact epoch
comparison are required. The full snapshot must satisfy host, epoch, generation,
publication and lease/freshness invariants even for an equal-epoch retry, which
performs no provider write. A higher epoch is durably committed while preserving
the account, family, keys, seed and credentials. Old-epoch scoped signing inputs
then fail the existing saved-binding checks. Backward epochs are rejected.

This synchronization grants no runtime lease ownership, readiness or local
workspace context. The future owner data worker must separately implement the
authenticated GET/store-generation/logout-gate integration and its SQLite
claim/outbox/lease handoff. This source preparation is not execution-qualified;
the historical 42 HostAuth tests and seven coverage proofs at `a364878d` do not
validate these changes. New lifecycle cases require the designated Windows run.

`start_host_channel_v3(HostChannelAdmissionV3)` takes an independently expected
context, stored host-signed grant, signed admission, pinned consumer identity and
independently current authority. It derives its own host identity and pin solely
from the validated record and constructs only a host responder. The owner must
independently check the expected proposal and any approval narrowing, local
consent, workspace fence, runtime, capabilities, terminal membership and
generation. Supplying copied signed fields as independent authority does not
satisfy that caller contract. These helpers do not authorize application effects.

The responder owns its original immutable admission deadline. Starting uses an
internal monotonic projection of the required trusted open anchor, advanced by
later trusted observations, and uses the later of that projection and internally
sampled wall time for
credential/admission freshness and the remaining admission lifetime. Internal
freshness samples retain a separate monotonic floor, including fractional seconds,
even when admission fails. A backward wall correction cannot revive an expired
admission. They do not advance the caller-owned observed-time watermark;
ordinary trusted time arguments retain their existing rollback checks. No public
handshake method accepts a clock or a deadline override. Checks before and after every read, write and finish reject
late completion and discard output; any error permanently disposes the wrapper.
The established channel exposes bounded binary `seal`, `open` and `dispose`,
with routing fixed internally to the admitted channel ID. A wrong routing header
closes the channel permanently. It can continue after admission expiry. Its owner
must enforce ongoing authority
and the local effect gate for every operation, including grant expiry and any
observed revocation, runtime or membership failure. Reconnection requires a new
admission and handshake. Deterministic private-clock tests cover deadline
crossings; a native crypto consumer test exercises the same Noise initiator
profile used by the browser, without claiming browser/HTTP product integration.
