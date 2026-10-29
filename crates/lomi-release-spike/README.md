# Signed TUF verification qualification probe

This is an experiment using `tough=0.24.0`, **not a production verifier, installer,
or installable host**. It has no publication or installer execution path. The
qualification result is deliberately rejected until a durable caller trust-state
wrapper and the remaining release requirements are qualified.

Run from the repository root:

```sh
cargo test -p lomi-release-spike
cargo run -p lomi-release-spike -- regression
cargo run -p lomi-release-spike -- qualify # expected status 1
```

Every execution generates temporary signed metadata through Tough's public
`RepositoryEditor` and `LocalKeySource` APIs. The payload is a synthetic text
string with a `.bin` suffix and is never executed. Verification consumes the
entire `Repository::read_target` stream through `IntoVec` before considering
bytes usable; a partial stream is not verified content. No signature algorithm,
canonical-signature format, or custom crypto is implemented here.

The signing key is the **published upstream `snakeoil.pem` test key**, copied
with its matching test root. It is not an operator key and must never be used
for release trust. The fixture provenance manifest records immutable upstream
source URLs and SHA-256 digests. These bytes come from `awslabs/tough` tag
`tough-v0.24.0`, commit `98d8eb8b2ce63515d9b4981c938ef6453c5b5771`:

- `tough/tests/data/simple-rsa/root.json`
- `tough/tests/data/snakeoil.pem`
- `tough/tests/data/rotated-root/{1.root.json,2.root.json,1.snapshot.json,1.targets.json,timestamp.json}`

The rotated-root metadata expires on 2029-07-27. Tests keep default Safe
expiration enforcement; after that date they should fail until fixtures are
reviewed and refreshed. Generated good metadata expires in 2099 and the
explicit freeze fixture expired in 2000. The static RSA root expires in 3000.

The eight probes cover valid signed target verification, payload tampering,
bad timestamp signatures, expired signed timestamps, persisted metadata rollback
rejection across a fresh loader, and three explicit persistence counterexamples:

- Truncated cached timestamp and snapshot JSON allow version 1 after version 2
  was previously trusted. Raw Tough ignores malformed cached metadata.
- A malformed cached clock watermark is ignored, although a valid future
  watermark correctly blocks a backward clock.
- Restarting with the original bootstrap root does not select the cached newest
  root. With the rotation file unavailable, loading fails and the cached root
  can be overwritten with the old supplied root. Explicitly supplying the saved
  version 2 root succeeds. This shows the caller's missing trust-state logic;
  the library documents that callers should supply their most recent root.

These are counterexamples for this incomplete integration, not a claim that
Tough provides a complete installer persistence contract. Regression success
asserts the exact observed outcomes; qualification always remains false.
Cross-process serialization, corrupt-state fail-closed handling, atomic writes,
fsync/crash recovery and durable newest-root selection are not implemented.
The source review in Tough's `src/datastore.rs` shows direct filesystem writes
and per-instance locks; `src/lib.rs` loads the passed root and conditionally
checks parseable cached timestamp/snapshot metadata. No crash or concurrency
qualification is claimed from that review.
