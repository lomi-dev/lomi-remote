# Pre-account host key commitment

The existing ordinary `PublicBundle` fingerprint includes account ID. A new host
cannot know that ID before login is approved. `PendingHostIdentity` generates
keys once before login, exposes a separately signed account-independent public
descriptor, then consumes itself to produce the ordinary account-bound identity
after authority approval. All actual signing, Noise and HPKE keys, host subject,
key version and native seed bytes remain unchanged. The historical key derivation,
public-bundle format, enrollment challenge v1 and historical vectors are preserved.
No algorithm or production qualification changes.

## Canonical public descriptor

`AccountIndependentHostKey` contains version, host ID, host role, key version and
the three existing public keys. Its canonical bytes are the definite eight-entry
CBOR array, with shortest unsigned integer encoding:

`["lomi-remote-host-key-commitment-v1", 1, hostId, 1, keyVersion, identityKey, channelKey, mailboxKey]`

Host ID is a nonzero 16-byte string. Keys are 32-byte strings. Role code 1 is
Host, the only accepted role. Key version is a positive u32. Zero keys are
rejected; Ed25519 parsing and `VerifyingKey::is_weak` reject invalid/weak signing
keys, and signature verification uses the existing strict verifier. Channel DH
peer authentication and low-order rejection remain with the existing Snow profile
when the keys are used. The commitment is SHA-256 of this complete canonical
array. `SignedHostKeyCommitment {descriptor, signature}` signs the same canonical
bytes with the existing Ed25519 identity key. It verifies only against an
independently retained init commitment, never a request's self-derived pin.

JSON uses camelCase, rejects unknown/duplicate fields and u32 overflow, and has
the existing 128 KiB input limit through `from_json`. Cryptographic entry points
revalidate descriptor semantics. Public descriptor/proof types contain no seeds.

## Lifecycle and authority binding

1. `PendingHostIdentity::generate(host_id, key_version)` generates the existing
   `Identity` once with a private zero account placeholder and Host role. It
   exposes neither that identity nor its ordinary zero-account bundle. There is
   no conversion from arbitrary/bound identities into the pending wrapper.
2. `signed_commitment()` provides the public init descriptor/self-proof. The
   authority must validate it and retain the exact descriptor and commitment
   immutably at init, before approval, together with enrollment/session state.
3. Better Auth approval supplies the actual account through the authenticated
   authority record, not the host's asserted replacement account/bundle. The
   authority verifies the retained commitment and calls
   `descriptor.account_bound_bundle(approved_account_id)` to derive the exact
   ordinary public bundle and its account-bound fingerprint. Zero accounts fail.
4. After authenticated TLS approval, the host calls
   `pending.finalize(approved_account_id, initial_commitment)`. It checks the
   retained commitment and nonzero account, preserves every secret/public key and
   signs the ordinary existing public bundle. Finalization consumes the wrapper;
   its return value is an ordinary `Identity`, with no rebind/finalize method.
   Any failure drops the consumed wrapper and runs the existing identity disposal
   path. Explicit `dispose()` disables export, signing and finalization as well.
5. Enrollment challenge v1 uses the server-derived ordinary bundle fingerprint,
   approved bootstrap session UUID, nonce, operation ID and other trusted binding
   fields. The account is cryptographically bound through that complete bundle
   fingerprint. The finalized host signs the existing canonical challenge.
6. `SignedEnrollmentProof::verify_committed_host(expected, committed, init_pin,
   approved_account_id, now)` verifies the retained init self-proof/pin, derives
   the account-bound bundle itself, compares complete expected challenge and
   host/fingerprint/expiry, then uses the existing strict Ed25519 verifier over
   the unchanged challenge bytes. It accepts no replacement bundle argument.

The `expected` challenge must come from independently approved database state
(binding init descriptor/pin, approved account, bootstrap, enrollment, nonce and
operation), not from the exchange request. The authority must atomically consume
that nonce/operation/bootstrap when creating host authorization and must preserve
its existing concurrency/replay/ownership checks. A self-signed init commitment is
a stable public key commitment and possession proof, not fresh one-time account
or enrollment authorization. Replaying it can at most start a rate-limited pending
request; it cannot replace approval or final PoP. The local `finalize` function
cannot authenticate a server response by itself: TLS, authority record integrity
and account approval checks are required before effects.

Two accounts derive different ordinary fingerprints from the same committed key
material. Changing even an encryption key while retaining the same signing key
also changes the commitment and derived fingerprint; a fresh self-signature cannot
replace the authority's stored init binding. The pending wrapper keeps its
ordinary identity private, and pending keys cannot be passed as an ordinary
`Identity` to grant or Noise APIs.

## Native persistence

Native `export_secret_seed_blob` / `import_secret_seed_blob` reuse the existing
version-1 fixed 97-byte format and `Zeroizing<Vec<u8>>`: one version byte and the
three 32-byte seeds. Import validates exact length/version, verifies the retained
public init proof/pin, invokes the original private key derivation with forced
Host/zero-account context, and rejects any resulting descriptor mismatch. There
is no public arbitrary-seed constructor or general rebind API. Browser builds do not expose native seed persistence.

Consuming finalization enforces one-time use of that in-memory wrapper only. The
unchanged seed format carries no account/lifecycle marker: a retained seed copy
can recreate a pending wrapper and mathematically sign a different account's
binding. Durable one-time enrollment and the immutable approved-account CAS in
authority storage must reject that reuse across seed copies. The existing native
export API does not create a plaintext file automatically. Production key receipt,
logout and new-enrollment identity policy belong to the storage/lifecycle adapter.

OS keychain persistence, atomic receipt and crash recovery across approval and
finalization remain pending platform evidence. This module writes no files and
makes no claim about a durable OS credential receipt. Existing bounded enrollment
store/CAS proofs and a future keychain adapter must own those effects. The wrapper
does not itself deliver host authorization, implement TLS or alter auth/store
schemas. Remote production qualification remains false.
