import { initSync, BrowserIdentity as RustBrowserIdentity, BrowserHandshakeV3 as RustBrowserHandshakeV3, verify_host_key_initiation, verify_host_enrollment_proof, prepare_host_enrollment_challenge, verify_host_refresh_proof, verify_registered_host_identity, verify_consumer_window_identity, prepare_consumer_window_challenge, verify_consumer_window_proof, prepare_grant_proposal_v3, verify_grant_proposal_v3, prepare_channel_context_v3, verify_channel_admission_v3 } from '../generated/authority_crypto.js';

let initialized = false;
const JSON_LIMIT = 32 * 1024;
const U64_MAX = (1n << 64n) - 1n;
const MAX_WINDOW_CHALLENGE = 1024;
const MAX_HANDSHAKE = 512;
const MAX_PLAINTEXT = 16 * 1024;
const MAX_BINARY_FRAME = MAX_PLAINTEXT + 64;
const HANDLE_TOKEN = Symbol('authority crypto handle');
const handles = new WeakMap();
const disposedHandles = new WeakSet();
const freedHandles = new WeakSet();
const exportedSeedBlobs = new WeakSet();
function fail(code = 'INVALID_ARGUMENT') { throw new Error(code); }
function ready() { if (!initialized) fail('CRYPTO_NOT_INITIALIZED'); }
function text(value) {
  if (typeof value !== 'string' || value.length > JSON_LIMIT) fail();
  // Check before wasm-bindgen copies; lone surrogates must never be repaired.
  let bytes = 0;
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) fail();
      bytes += 4;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) fail();
    else bytes += unit <= 0x7f ? 1 : unit <= 0x7ff ? 2 : 3;
    if (bytes > JSON_LIMIT) fail();
  }
  return value;
}
function fixed(value, length) {
  if (!(value instanceof Uint8Array) || value.length !== length) fail();
  return value;
}
function boundedBytes(value, minimum, maximum) {
  if (!(value instanceof Uint8Array) || value.length < minimum || value.length > maximum) fail();
  return value;
}
function unsignedU64(value) {
  if (typeof value !== 'bigint' || value < 0n || value > U64_MAX) fail();
  return value;
}
function liveHandle(owner) {
  ready();
  const handle = handles.get(owner);
  if (!handle || freedHandles.has(owner) || disposedHandles.has(owner)) fail('CRYPTO_OBJECT_DISPOSED');
  return handle;
}
function disposeHandle(owner) {
  const handle = handles.get(owner);
  if (!handle || freedHandles.has(owner) || disposedHandles.has(owner)) return;
  try { handle.dispose(); } finally { disposedHandles.add(owner); }
}
function freeHandle(owner) {
  const handle = handles.get(owner);
  if (!handle || freedHandles.has(owner)) return;
  try {
    if (!disposedHandles.has(owner)) {
      try { handle.dispose(); } finally { disposedHandles.add(owner); }
    }
  } finally {
    try { handle.free(); } finally {
      handles.delete(owner);
      freedHandles.add(owner);
    }
  }
}
function attachHandle(owner, handle) {
  handles.set(owner, handle);
}
function wasmText(value) {
  const output = text(value);
  return output;
}
function wasmBytes(value, minimum, maximum) {
  return boundedBytes(value, minimum, maximum);
}
function createRustBrowserIdentity(accountId, subjectId, host, keyVersion) {
  return new RustBrowserIdentity(accountId, subjectId, host, keyVersion);
}
function restoreRustBrowserIdentity(accountId, subjectId, seedBlob, expectedBundleJson) {
  return RustBrowserIdentity.restore(accountId, subjectId, seedBlob, expectedBundleJson);
}
class ManagedWasmHandle {
  constructor(token) {
    if (token !== HANDLE_TOKEN) { ready(); fail(); }
  }
  dispose() { disposeHandle(this); }
  free() { freeHandle(this); }
}
function checked(call) {
  try { return call(); } catch { fail(); }
}

/** Trusted application startup only; generated release WASM excludes fixtures. */
export function initializeAuthorityCrypto(moduleOrBytes) {
  if (initialized) fail('CRYPTO_ALREADY_INITIALIZED');
  initSync({ module: moduleOrBytes });
  initialized = true;
}

/**
 * A Rust-held identity that exposes a one-time seed-blob bridge so trusted
 * callers can encrypt generated identities with WebCrypto. Callers must zero
 * the returned JavaScript buffer; runtime copies cannot be reliably erased.
 */
export class BrowserIdentity extends ManagedWasmHandle {
  constructor(options) {
    super(HANDLE_TOKEN);
    ready();
    if (!options || typeof options !== 'object') fail();
    const { accountId, subjectId, host, keyVersion } = options;
    fixed(accountId, 16); fixed(subjectId, 16);
    if (typeof host !== 'boolean' || !Number.isInteger(keyVersion) || keyVersion < 1 || keyVersion > 0xffffffff) fail();
    attachHandle(this, checked(() => createRustBrowserIdentity(accountId, subjectId, host, keyVersion)));
  }
  /** Restores a scoped identity from a browser-decrypted encrypted record. */
  static restore(options) {
    ready();
    if (!options || typeof options !== 'object') fail();
    const { accountId, subjectId, seedBlob, expectedBundleJson } = options;
    fixed(accountId, 16); fixed(subjectId, 16); fixed(seedBlob, 97); text(expectedBundleJson);
    const identity = Object.create(BrowserIdentity.prototype);
    attachHandle(identity, checked(() => restoreRustBrowserIdentity(accountId, subjectId, seedBlob, expectedBundleJson)));
    return identity;
  }
  fingerprint() {
    const handle = liveHandle(this);
    const output = checked(() => handle.fingerprint());
    fixed(output, 32);
    return output;
  }
  publicBundle() {
    const handle = liveHandle(this);
    return wasmText(checked(() => handle.public_bundle()));
  }
  publicIdentityWire() {
    const handle = liveHandle(this);
    return wasmText(checked(() => handle.public_identity_wire()));
  }
  /** One-time plaintext bridge for immediate encryption with WebCrypto. */
  seedBlobForEncryption() {
    const handle = liveHandle(this);
    if (exportedSeedBlobs.has(this)) fail('SEED_BLOB_ALREADY_EXPORTED');
    const output = checked(() => handle.seed_blob_for_encryption());
    fixed(output, 97);
    exportedSeedBlobs.add(this);
    return output;
  }
  /** Signs only an exact canonical challenge accepted by the Rust signer. */
  signConsumerWindowProof(canonicalCbor) {
    wasmBytes(canonicalCbor, 1, MAX_WINDOW_CHALLENGE);
    const handle = liveHandle(this);
    return wasmText(checked(() => handle.sign_consumer_window_proof(canonicalCbor)));
  }
  signConsumerWindowProofBound(canonicalCbor, expectedJson, now) {
    wasmBytes(canonicalCbor, 1, MAX_WINDOW_CHALLENGE);
    text(expectedJson); unsignedU64(now);
    const handle = liveHandle(this);
    return wasmText(checked(() => handle.sign_consumer_window_proof_bound(canonicalCbor, expectedJson, now)));
  }
}

/** Construct a Rust-verified v3 handshake from independently retained state. */
export class BrowserHandshakeV3 extends ManagedWasmHandle {
  constructor(options) {
    super(HANDLE_TOKEN);
    ready();
    if (!options || typeof options !== 'object') fail();
    const { initiator, identity, signedJson, expectedJson, authorityJson,
      hostPin, consumerPin, now } = options;
    if (typeof initiator !== 'boolean' || !(identity instanceof BrowserIdentity)) fail();
    wasmText(signedJson); wasmText(expectedJson); wasmText(authorityJson);
    fixed(hostPin, 32); fixed(consumerPin, 32); unsignedU64(now);
    const identityHandle = liveHandle(identity);
    attachHandle(this, checked(() => new RustBrowserHandshakeV3(initiator, identityHandle,
      signedJson, expectedJson, authorityJson, hostPin, consumerPin, now)));
  }
  write() {
    const handle = liveHandle(this);
    return wasmBytes(checked(() => handle.write()), 1, MAX_HANDSHAKE);
  }
  read(message) {
    wasmBytes(message, 1, MAX_HANDSHAKE);
    const handle = liveHandle(this);
    checked(() => handle.read(message));
  }
  finish() {
    const handle = liveHandle(this);
    // The generated finish method consumes its Rust allocation on success or failure.
    handles.delete(this);
    freedHandles.add(this);
    const channel = checked(() => handle.finish());
    return new BrowserChannel(HANDLE_TOKEN, channel);
  }
}

/** V3 transport channel returned by BrowserHandshakeV3.finish(). */
export class BrowserChannel extends ManagedWasmHandle {
  constructor(token, handle) {
    super(token);
    ready();
    if (token !== HANDLE_TOKEN || !handle) fail();
    attachHandle(this, handle);
  }
  sealBinary(routing, plaintext) {
    fixed(routing, 16); boundedBytes(plaintext, 0, MAX_PLAINTEXT);
    const handle = liveHandle(this);
    return wasmBytes(checked(() => handle.seal_binary(routing, plaintext)), 64, MAX_BINARY_FRAME);
  }
  openBinary(routing, frame) {
    fixed(routing, 16); boundedBytes(frame, 64, MAX_BINARY_FRAME);
    const handle = liveHandle(this);
    return wasmBytes(checked(() => handle.open_binary(routing, frame)), 0, MAX_PLAINTEXT);
  }
  transcriptHash() {
    const handle = liveHandle(this);
    const output = checked(() => handle.transcript_hash());
    fixed(output, 32);
    return output;
  }
}
if (typeof Symbol.dispose === 'symbol') {
  for (const Type of [BrowserIdentity, BrowserHandshakeV3, BrowserChannel]) {
    Object.defineProperty(Type.prototype, Symbol.dispose, { value: Type.prototype.free });
  }
}

/** Public commitment consistency and PoP only; grants no account/session class. */
export function verifyHostKeyInitiation(initJson) {
  ready();
  text(initJson);
  return checked(() => verify_host_key_initiation(initJson));
}

/** Trusted server state only; derives host ID/fingerprint and canonical bytes. */
export function prepareHostEnrollmentChallenge(storedCommitmentJson, initialPin,
  approvedAccount, contextJson) {
  ready();
  text(storedCommitmentJson); text(contextJson);
  fixed(initialPin, 32); fixed(approvedAccount, 16);
  return checked(() => prepare_host_enrollment_challenge(storedCommitmentJson,
    initialPin, approvedAccount, contextJson));
}

/** All expected values must come from independently retained authority state. */
export function verifyHostEnrollmentProof(proofJson, expectedChallengeJson,
  storedCommitmentJson, initialPin, approvedAccount, now) {
  ready();
  text(proofJson); text(expectedChallengeJson); text(storedCommitmentJson);
  fixed(initialPin, 32); fixed(approvedAccount, 16);
  if (typeof now !== 'bigint' || now < 0n || now > U64_MAX) fail();
  checked(() => verify_host_enrollment_proof(proofJson, expectedChallengeJson,
    storedCommitmentJson, initialPin, approvedAccount, now));
}

/** Context, commitment, pin and account must come from independent server state. */
export function verifyHostRefreshProof(proofJson, storedCommitmentJson, initialPin,
  approvedAccount, trustedContextJson) {
  ready();
  text(proofJson); text(storedCommitmentJson); text(trustedContextJson);
  fixed(initialPin, 32); fixed(approvedAccount, 16);
  checked(() => verify_host_refresh_proof(proofJson, storedCommitmentJson,
    initialPin, approvedAccount, trustedContextJson));
}

/** Returns JSON {identity: SignedBundle, fingerprint: number[32]} after native verification. */
export function verifyRegisteredHostIdentity(proofJson, storedCommitmentJson, initialPin, approvedAccount) {
  ready();
  text(proofJson); text(storedCommitmentJson);
  fixed(initialPin, 32); fixed(approvedAccount, 16);
  return checked(() => verify_registered_host_identity(proofJson, storedCommitmentJson, initialPin, approvedAccount));
}

/** Account and window ID are authenticated authority inputs. Returns the same verified identity JSON. */
export function verifyConsumerWindowIdentity(wireJson, approvedAccount, windowId) {
  ready();
  text(wireJson); fixed(approvedAccount, 16); fixed(windowId, 16);
  return checked(() => verify_consumer_window_identity(wireJson, approvedAccount, windowId));
}

/** Returns JSON {challenge, canonicalCbor}; all context is trusted retained server state. */
export function prepareConsumerWindowChallenge(wireJson, approvedAccount, trustedContextJson) {
  ready();
  text(wireJson); text(trustedContextJson); fixed(approvedAccount, 16);
  return checked(() => prepare_consumer_window_challenge(wireJson, approvedAccount, trustedContextJson));
}

/** Expected challenge and account are trusted state; caller atomically consumes the nonce. */
export function verifyConsumerWindowProof(proofJson, expectedChallengeJson, identityWireJson, approvedAccount, now) {
  ready();
  text(proofJson); text(expectedChallengeJson); text(identityWireJson); fixed(approvedAccount, 16);
  if (typeof now !== 'bigint' || now < 0n || now > U64_MAX) fail();
  checked(() => verify_consumer_window_proof(proofJson, expectedChallengeJson, identityWireJson, approvedAccount, now));
}

/** Server-assembled grant only; returns JSON {grant, canonicalCbor}. */
export function prepareGrantProposalV3(trustedGrantJson, hostWireJson, consumerWireJson,
  approvedAccount, hostPin, consumerPin) {
  ready();
  text(trustedGrantJson); text(hostWireJson); text(consumerWireJson);
  fixed(approvedAccount, 16); fixed(hostPin, 32); fixed(consumerPin, 32);
  return checked(() => prepare_grant_proposal_v3(trustedGrantJson, hostWireJson,
    consumerWireJson, approvedAccount, hostPin, consumerPin));
}

/** Maximum CBOR and current authority must come from independent server storage.
 * Returns JSON {grant, signature, canonicalCbor} after native verification. */
export function verifyGrantProposalV3(submittedWireJson, maximumCborHex, hostWireJson,
  consumerWireJson, hostPin, consumerPin, currentAuthorityJson, now) {
  ready();
  text(submittedWireJson); text(maximumCborHex); text(hostWireJson);
  text(consumerWireJson); text(currentAuthorityJson);
  fixed(hostPin, 32); fixed(consumerPin, 32);
  if (typeof now !== 'bigint' || now < 0n || now > U64_MAX) fail();
  return checked(() => verify_grant_proposal_v3(submittedWireJson, maximumCborHex,
    hostWireJson, consumerWireJson, hostPin, consumerPin, currentAuthorityJson, now));
}

/** Saved server context and stored approval only; returns JSON {context, canonicalCbor}. */
export function prepareChannelContextV3(trustedContextJson, storedGrantWireJson,
  hostWireJson, consumerWireJson, hostPin, consumerPin, currentAuthorityJson, now) {
  ready();
  text(trustedContextJson); text(storedGrantWireJson); text(hostWireJson);
  text(consumerWireJson); text(currentAuthorityJson);
  fixed(hostPin, 32); fixed(consumerPin, 32);
  if (typeof now !== 'bigint' || now < 0n || now > U64_MAX) fail();
  return checked(() => prepare_channel_context_v3(trustedContextJson, storedGrantWireJson,
    hostWireJson, consumerWireJson, hostPin, consumerPin, currentAuthorityJson, now));
}

/** Expected CBOR, approval and current authority are independently stored state.
 * Returns verified {admission, grant, host, consumer} JSON for BrowserHandshakeV3. */
export function verifyChannelAdmissionV3(submittedWireJson, expectedCborHex,
  storedGrantWireJson, hostWireJson, consumerWireJson, hostPin, consumerPin,
  currentAuthorityJson, now) {
  ready();
  text(submittedWireJson); text(expectedCborHex); text(storedGrantWireJson);
  text(hostWireJson); text(consumerWireJson); text(currentAuthorityJson);
  fixed(hostPin, 32); fixed(consumerPin, 32);
  if (typeof now !== 'bigint' || now < 0n || now > U64_MAX) fail();
  return checked(() => verify_channel_admission_v3(submittedWireJson, expectedCborHex,
    storedGrantWireJson, hostWireJson, consumerWireJson, hostPin, consumerPin,
    currentAuthorityJson, now));
}
