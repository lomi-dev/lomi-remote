# Canonical authority crypto bridge

This private package runs the canonical Rust enrollment verifier in WASM, with
the same bounded wire types and canonical CBOR decoders used natively. Auth
routes consume its immutable internal archive for host enrollment, credential
proofs, consumer identity and grant/channel verification. This source integration
does not establish production qualification or accept the release gates.

Build with `npm run build --prefix packages/authority-crypto-wasm`. The build
uses the pinned release toolchain, only the `browser` feature, and rejects
generated fixture APIs. `npm run check --prefix packages/authority-crypto-wasm`
rebuilds and checks every output and its source/dependency provenance. The
generated bindings are an internal implementation; applications use `src`.

Initialize once with the verified WASM artifact bytes at trusted application
startup. `verifyHostKeyInitiation` accepts the canonical initiation JSON and
returns public signed commitment JSON after checking all committed keys and its
self-signature. A caller's client ID grants no trusted class or account access.
Authority must retain the exact commitment before account approval.

`prepareHostEnrollmentChallenge` accepts a stored commitment and original pin,
the approved Remote account UUID, and server-owned enrollment/bootstrap/operation
IDs, nonce, audience and expiry. It derives the host ID and account-bound
fingerprint in Rust and returns the challenge plus canonical CBOR hex. The
bootstrap UUID identifies the binding record, separately from Better Auth's
opaque session ID. This helper does not approve an account or sign a proof.

`verifyHostEnrollmentProof` receives request proof separately from the expected
challenge, stored commitment, original pin and approved account. Those expected
inputs must come from trusted storage. Time is an unsigned 64-bit BigInt. The
function verifies exact context, canonical encoding, signature and expiry;
atomic single use, session binding, revocation, rate limits and authorization
remain the authority transaction's responsibility. `verifyHostRefreshProof` accepts a domain-separated refresh proof, stored
commitment, original pin, approved account and trusted server context. Rust
derives and checks the account-bound host ID and fingerprint, authorization ID,
rotation ID, refresh hash and audience against the canonical signed statement.
The server context must come from trusted storage and configured audience.
Atomic rotation, recovery, idle expiry, revocation and current account/host
epochs remain the authority transaction's responsibility. A captured signed
request can be replayed within the recovery window; this is not DPoP and does
not prove fresh key possession on replay. Enrollment signatures cannot
authorize credential rotation.

The wrapper provides initialization, twelve verifier/preparation functions,
and three Rust-backed browser classes: `BrowserIdentity`,
`BrowserHandshakeV3`, and `BrowserChannel`. Initialize the WASM once before
constructing an identity or handshake. `BrowserIdentity` keeps keys in Rust
and exposes public identity data, proof signing, scoped restore, and a one-time
`seedBlobForEncryption()` bridge for local persistence. The browser adapter
encrypts that 97-byte blob with WebCrypto before storing it in IndexedDB, then
zeros its returned buffer. The plaintext briefly exists in JavaScript and
WASM bindings; runtime copies cannot be reliably erased. `restore()` rechecks
the decrypted seed blob against the persisted public bundle and requested
account/window scope. Fixture APIs are absent from the release artifact.

`signConsumerWindowProof(canonicalCbor)` delegates to the Rust generated
signer. Rust accepts only a complete canonical challenge and checks the
identity's account, device role, window ID, and disposal state. It does not
sign arbitrary JSON or expose a general signing primitive. For channel setup,
`BrowserHandshakeV3` accepts the signed admission JSON, expected context,
current authority, endpoint pins, and current time as independent inputs. Rust
reverifies them before starting Noise. Its `finish()` consumes the handshake
and returns a `BrowserChannel`; channel methods carry bounded binary frames.
Call `dispose()` to close cryptographic state and `free()` to release the WASM
allocation. `free()` also disposes an object if needed; it is safe to call from
a `finally` block. Verification errors are bounded generic codes and do not
include request material.

The generated library and the product remain
unqualified for release until their integration and platform gates pass.

Create an internal npm-format archive with
`python3 tools/package_authority_crypto.py` from the repository root. The packer
checks locked dependency notices, all source and generated hashes, the generated
API, pinned build tools, and `npm run check` before writing a deterministic
`artifacts/authority-package/lomi-authority-crypto-wasm-sha256-<full-sha256>.tgz`
and its `.tgz.json` receipt. `--output-dir PATH` selects another destination;
existing artifacts are never replaced with different bytes. The explicit file
allowlist includes the wrapper, types, four generated bindings/WASM files,
provenance, this README, package manifest and third-party notices. It excludes
tests, fixtures, build caches and dependencies. Consumers should vendor the
archive by digest and import `@lomi/authority-crypto-wasm`; no sibling workspace
runtime import is required. The archive is a local internal package, unsigned
and unqualified for release. To update notices after a locked dependency change,
run `python3 tools/package_authority_crypto.py --write-notices`, then rebuild
the canonical WASM before packing. The notices conservatively include build
dependencies and workspace-unified features; they grant no owner license for
private Lomi sources.

Full finalized host identities are verified against the retained preapproval
commitment and authenticated account. Consumer windows supply the complete
three-key signed public bundle and a fresh server-bound possession proof.
Identity verification returns JSON `{identity, fingerprint}`; challenge helpers
return `{challenge, canonicalCbor}`. A self-signature alone grants no authority.

Grant approval verifies an independently retained maximum proposal and permits
only dependency-closed capability and expiry narrowing. Channel admission binds
a separate host signature to an independently stored context and current
authority. These helpers do not issue nonces or consume replay state. Trusted
arguments must originate in server rows, not fields copied from submitted data.
