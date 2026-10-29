# Canonical crypto source: imported baseline and enrollment proof

This crate is extracted from `lomi` commit
`2cef452c39eb8b455c8d2ae1251310dc870c50bb`, path
`src-tauri/crates/lomi-remote-crypto`. It is the new source location for further
Remote work; application copies are untouched in this extraction. It is not a
qualified implementation of Remote API/application major 2 or grant/context v3.
`REMOTE_V2_PRODUCTION_QUALIFIED` is false. No backward negotiation or fallback is
added to the new product.

[README.upstream.md](README.upstream.md), existing examples, fixtures, historical
qualification constants and compatibility tests describe the imported old live
profile. Passing them preserves historical security evidence; it does not admit
old grants into the new Remote product. New context/grant encoding and terminal
profile binding still require a separately reviewed contract.

The patched Snow source is retained at `vendor/snow`, including its original
MIT/Apache licenses, upstream digest inventory, low-order DH rejection and secret
erasure changes. No upstream Snow substitution or cryptographic algorithm change
is made. Identity seed ownership, Zeroizing storage, Dalek zeroize feature and
explicit disposal are unchanged. The enrollment API borrows the existing signing
key and does not export or retain a second secret.

The provenance inventory at `tests/crypto-provenance/source.json` records every
upstream file's SHA-256 at that commit, its destination hash and any adaptation.
The nested Cargo.lock is excluded in favor of the root workspace lock; serde and
serde_json are pinned to root-compatible versions. The historical README is
relocated without changing its bytes. Every vendored Snow file is byte-identical.

From the repository root:

```sh
python3 tools/check_crypto_source.py --source-repo ../lomi
cargo test --locked -p lomi-remote-crypto --features test-fixtures
cargo check --locked -p lomi-remote-crypto --features browser --target wasm32-unknown-unknown
```

The provenance checker also works without `--source-repo` for destination drift;
with that argument it independently reads every source blob from the pinned Git
commit, without depending on the source working tree.

## Isolated enrollment proof API

`Identity::sign_enrollment_proof` signs a fixed-length canonical CBOR array under
the independent domain `lomi-remote-host-enrollment-proof-v1`, using the existing
Ed25519 identity seed. The positional fields are domain, proof version (1),
enrollment ID, host ID, complete public-bundle fingerprint, bootstrap session ID,
audience, expiry (Unix seconds), nonce and exchange operation ID. Binary IDs have
fixed lengths; expiry is a canonical decimal u64 string in JSON. Unknown fields
are rejected. This proof version is separate from crypto grant/context v3.

`SignedEnrollmentProof::verify` requires the independently stored expected
challenge, approved host bundle, immutable host fingerprint and current time. It
checks every binding, host role, signature and exclusive expiry. Server-side
creation of that expected record must validate the enrolled client class and
approved bootstrap session. Callers must atomically consume the challenge and
bind operation recovery/replay policy in storage. This stateless API does not
implement enrollment exchange, replay storage, credentials, device approval,
clock authority, token recovery, WASM exports or native mobile ABI.


Canonical public identity wire adapters retain the historical encoder and add
strict bounded decoding of its signed three-key bundle. Finalized host identity
verification derives the complete approved account projection from the retained
enrollment commitment. Consumer-window registration has a separate domain-bound
challenge that includes the actual opaque parent session, authorization, window,
operation, nonce, fingerprint, audience and exclusive expiry.

Grant/context v3 wire adapters decode only the exact existing canonical forms.
Host approval may narrow a retained maximum proposal's capabilities and expiry;
all other fields and independently read current authority must match. Public
WASM adapters use these Rust checks for identity, window possession, proposal
approval and channel admission. Signature checks alone do not issue nonces,
consume replay state or establish transaction freshness.
