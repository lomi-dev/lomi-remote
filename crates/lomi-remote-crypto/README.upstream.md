# Shared native/WASM live protocol

The profile is `lomi-remote-live-v1`. `LIVE_PRODUCTION_QUALIFIED` is true;
`PRODUCTION_QUALIFIED` and `MAILBOX_PRODUCTION_QUALIFIED` remain false. Native
live hosting is enabled only on macOS ARM64. The mailbox HPKE path remains
experimental and is not qualified.

Desktop release 0.5.3 is published. The local 0.5.2 native/browser run passed
15 checks; release 0.5.3 passed 12 checks each against the public staging and
production services. Its signed ARM64 artifact was verified for code signing,
notarization, updater signature and bundled terminal helper operation.
Production live services are deployed; general crypto and mailbox qualification
remain disabled.

The live suite remains `Noise_XX_25519_ChaChaPoly_SHA256`, Device initiator and
Host responder. Vendored Snow 0.10.0 provenance and archive checksum are in
`vendor/snow/UPSTREAM.md`; MIT and Apache-2.0 licenses are retained. The narrow
patch preserves the Noise construction while adding owned-memory erasure and
all-zero X25519 shared-secret rejection. Snow SHA-256 uses sha2 0.11.0 with its
`zeroize` feature, digest 0.11.3, and block-buffer 0.12.1. SHA-256 public
fingerprints still use sha2 0.10.9. Ed25519 uses Dalek 2.2.0 with zeroize.

Signed bundles bind account, subject, role, key version and all three public
keys. A self-signature does not establish trust: callers supply the full bundle
fingerprint from trusted pairing. Noise prologue binds both fingerprints and
ChannelContext fields: version, account_id, host_id, device_id, initiator_role,
responder_role, channel_id, grant_id, session_id, access_epoch, revision.

PeerApproval fields are version, account_id, host_id, device_id,
host_fingerprint, device_fingerprint, pairing_nonce, grant_id, session_ids,
permissions (`observe` or `control`), access_epoch, revision, expires_at.
V1 sessions are ordered, nonempty, unique and at most 32. Only a matching Host
identity can sign. Verification pins the complete host bundle, checks its role
and identity, requires exact equality to caller-provided trusted approval state,
requires the current epoch, and rejects at or after the trusted deadline.
The caller must never construct expected state from the received approval.
The full pairing comparison digest is SHA-256 over UTF-8
`lomi-remote-pairing-v1\0`, then account16, host16, device16, host fingerprint32,
device fingerprint32, nonce32, in that order. Browser helper returns 64 lowercase
hexadecimal characters; display and compare the complete digest.

Canonical signed data uses definite CBOR arrays beginning with the profile and
domain strings. The public-bundle array has 10 elements, channel-context 13,
noise-prologue 5, peer-approval 15 (session_ids is an array of byte strings).
The field order above is the canonical order. JSON is an adapter, not signature
encoding. Byte arrays are arrays of integers in JSON. Keep u64 values exact;
WASM time/epoch arguments use BigInt. Applications must bound inputs before the
WASM bridge, which copies JS inputs before Rust validation.

Native-only export_secret_seed_blob returns Zeroizing bytes: version byte 1
plus three 32-byte identity/channel/mailbox seeds (97 bytes total). Import accepts
that exact format and the trusted immutable SignedBundle, verifies its signature,
reconstructs keys and requires full signed bundle equality. Store the blob only
in native secure credential storage. There is no browser private-key export or
import; browser identities are ephemeral. Imported bundle trust and rollback
protection belong to the authoritative native persistence layer.

Transport binary format is sequence u64 big endian (8 bytes), routing (16 bytes),
then Snow ciphertext. Encrypted plaintext repeats the sequence and routing before
the application payload, authenticating external metadata. Maximum plaintext is
16 KiB; total binary frame length is plaintext + 64 bytes, minimum 64 bytes.
The receive API checks bounds before allocating ciphertext and closes on invalid
length, authentication, order or routing. Mutable non-Clone handles serialize
nonces; each direction permits 1,000,000 frames, then requires a fresh handshake.
Handshake frames permit at most 512 bytes and no application payload. Explicit
dispose and Drop release channel/handshake state. Authentication failures are
terminal; reconnect starts a fresh handshake.

Owned-memory erasure covers application identity seeds, channel secret,
mailbox secret bytes, Dalek signing state, live plaintext buffers and native
export blobs; Snow default resolver DH private arrays and ChaCha key arrays;
symmetric chaining-key/hash state and non-Copy rollback checkpoints; scoped DH,
HMAC pads/output, HKDF intermediate/output, cipher split and rekey buffers.
SHA-256 core state and buffered blocks use upstream zeroizing Drop. The patch
avoids an explicit temporary conversion of the ChaCha key and uses the maintained
AEAD implementation's Drop. This is an owned-buffer claim, not erasure of every
compiler temporary, register, allocator remnant, operating-system snapshot,
WASM copy or JavaScript buffer. HPKE internals are not qualified by this work.
Only the selected Noise suite has compatibility evidence; other vendored Snow
algorithms and profiles are outside the claim.

Validation on macOS ARM64: native tests cover signed key substitution, grants
and every approval field, expiry/current epoch, durable identity reconstruction,
binary framing, disposal, replay/tamper/order, and low-order X25519 rejection.
The upstream bundled Cacophony XX/25519/ChaChaPoly/SHA256 vector checks all
handshake and bidirectional transport ciphertexts and handshake hash. Chromium
runs actual WASM entropy, Noise, abort/dispose/tamper and full native-process to
WASM Noise exchange in both directions with matching transcript and replay
failure. Legacy HPKE compatibility tests remain experimental evidence only.

```sh
cargo test --locked
cargo test --locked --features browser,test-fixtures
cargo clippy --locked --all-targets --features browser,test-fixtures -- -D warnings
cargo fmt --check
cargo build --locked --example live_interoperability --features test-fixtures
cargo build --locked --target wasm32-unknown-unknown --features browser,test-fixtures
wasm-bindgen target/wasm32-unknown-unknown/debug/lomi_remote_crypto.wasm --out-dir pkg --target web
node tests/browser.mjs
```

The browser runner requires the enclosing project's Playwright dependency and
installed Chromium. Generated pkg/ and target/ files are ignored. Test fixture
seeds require the explicit test-fixtures feature; release compilation rejects
that feature. Default release builds contain no fixture constructor. Other
browser engines, external security review, fuzzing and broader product
qualification remain outstanding. General crypto and mailbox qualification
remain disabled. Production deployment and normal-auth native/browser live
qualification are recorded separately from these cryptographic protocol tests.

## Workspace approval and channel context v2

V1 JSON omits all new fields and retains identical canonical bytes. V2 approval
requires `workspace_id`, `workspace_epoch`, and one `session_epochs` entry per
ordered session ID. IDs remain unique and limited to 32; an empty scope permits
metadata only. The 18-element approval array inserts workspace ID and epoch
before the session IDs array, followed by the session epochs array and the
existing permission, access epoch, revision and expiry fields.

V2 contexts require `workspace_id`, `workspace_epoch`, `session_epoch`, and
`purpose` (`terminal` or `metadata`). The 17-element context array appends these
fields after revision; purpose codes are terminal=1 and metadata=2. Metadata
uses workspace ID as session ID and workspace epoch as session epoch. Bundles,
pins, the profile string, and the Noise construction remain unchanged.

After verifying the host signature against trusted grant state, call
`ChannelContext::validate_approval` (WASM: `validate_channel_approval`) before
starting Noise. It requires exact grant identity, revision, workspace scope and
access epoch; terminal contexts additionally require an approved session and
its corresponding PTY epoch. Metadata contexts never authorize PTY output or
input; the application must enforce that purpose when processing payloads.
`Handshake::new` validates the context and binds its canonical bytes in Noise,
but does not replace approval verification. Scope refresh, monotonic revisions,
expiry and revocation remain the responsibility of authoritative callers.

`workspace_interoperability` emits deterministic signed terminal and empty-scope
metadata fixtures with canonical hex. `tests/fixtures/legacy-v1.json` fixes the
old wire output; `tests/fixtures/workspace-v2.json` fixes the new wire output.
Workspace tests cover signed-field tampering, downgrade, omitted fields,
duplicates and bounds, stale PTY/workspace epochs, revision, purpose and Noise
prologue mismatches. Live crypto is qualified; general crypto and mailbox
qualification remain disabled. Native hosting is limited to macOS ARM64.
