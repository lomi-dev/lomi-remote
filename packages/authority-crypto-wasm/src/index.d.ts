export function initializeAuthorityCrypto(moduleOrBytes: BufferSource | WebAssembly.Module): void;
export interface BrowserIdentityOptions {
  accountId: Uint8Array;
  subjectId: Uint8Array;
  host: boolean;
  keyVersion: number;
}
export interface BrowserIdentityRestoreOptions {
  accountId: Uint8Array;
  subjectId: Uint8Array;
  /** Decrypted 97-byte blob; caller must zero it after restore. */
  seedBlob: Uint8Array;
  /** Previously persisted public SignedBundle JSON used for exact Rust matching. */
  expectedBundleJson: string;
}
/** Rust-backed identity. Seed access is limited to a one-time WebCrypto bridge. */
export class BrowserIdentity {
  constructor(options: BrowserIdentityOptions);
  static restore(options: BrowserIdentityRestoreOptions): BrowserIdentity;
  fingerprint(): Uint8Array;
  publicBundle(): string;
  publicIdentityWire(): string;
  /** One-time 97-byte plaintext bridge; encrypt it with WebCrypto and zero it. */
  seedBlobForEncryption(): Uint8Array;
  /** Signs only an exact canonical consumer-window challenge through Rust. */
  signConsumerWindowProof(canonicalCbor: Uint8Array): string;
  /** Checks the retained Cauth/session/operation tuple and expiry before signing. */
  signConsumerWindowProofBound(canonicalCbor: Uint8Array, expectedJson: string, now: bigint): string;
  /** Closes and zeroizes the Rust identity while retaining its allocation. */
  dispose(): void;
  /** Disposes if needed and releases the WASM allocation. */
  free(): void;
}
export interface BrowserHandshakeV3Options {
  initiator: boolean;
  identity: BrowserIdentity;
  /** JSON {grant, admission, host, consumer}, verified again in Rust. */
  signedJson: string;
  /** Independently retained expected channel context JSON. */
  expectedJson: string;
  /** Independently retained current authority state JSON. */
  authorityJson: string;
  hostPin: Uint8Array;
  consumerPin: Uint8Array;
  now: bigint;
}
export class BrowserHandshakeV3 {
  constructor(options: BrowserHandshakeV3Options);
  write(): Uint8Array;
  read(message: Uint8Array): void;
  /** Consumes this handshake and returns its transport channel. */
  finish(): BrowserChannel;
  dispose(): void;
  free(): void;
}
export class BrowserChannel {
  private constructor();
  sealBinary(routing: Uint8Array, plaintext: Uint8Array): Uint8Array;
  openBinary(routing: Uint8Array, frame: Uint8Array): Uint8Array;
  transcriptHash(): Uint8Array;
  dispose(): void;
  free(): void;
}
/** Returns JSON {identity: SignedBundle, fingerprint: number[32]} containing verified full public keys. */
export function verifyRegisteredHostIdentity(proofJson: string, storedCommitmentJson: string,
  initialPin: Uint8Array, approvedAccount: Uint8Array): string;
/** Account and window ID must come from authenticated authority state; same verified identity JSON. */
export function verifyConsumerWindowIdentity(wireJson: string, approvedAccount: Uint8Array,
  windowId: Uint8Array): string;
/** Returns JSON {challenge, canonicalCbor}; canonicalCbor is lowercase hex, context is trusted state. */
export function prepareConsumerWindowChallenge(wireJson: string, approvedAccount: Uint8Array,
  trustedContextJson: string): string;
/** Caller owns trusted expected state and atomic nonce consumption. Time must be an unsigned u64 BigInt. */
export function verifyConsumerWindowProof(proofJson: string, expectedChallengeJson: string,
  identityWireJson: string, approvedAccount: Uint8Array, now: bigint): void;
/** Returns canonical public SignedHostKeyCommitment JSON; does not approve an account. */
export function verifyHostKeyInitiation(initJson: string): string;
/** Returns JSON {challenge, canonicalCbor}; context is trusted server state. */
export function prepareHostEnrollmentChallenge(
  storedCommitmentJson: string,
  initialPin: Uint8Array,
  approvedAccount: Uint8Array,
  contextJson: string,
): string;
/** Expected challenge, stored commitment, pin and approved account are trusted DB inputs. */
export function verifyHostEnrollmentProof(
  proofJson: string,
  expectedChallengeJson: string,
  storedCommitmentJson: string,
  initialPin: Uint8Array,
  approvedAccount: Uint8Array,
  now: bigint,
): void;

/** Trusted context derives account-bound host claims inside canonical Rust. */
export function verifyHostRefreshProof(
  proofJson: string,
  storedCommitmentJson: string,
  initialPin: Uint8Array,
  approvedAccount: Uint8Array,
  trustedContextJson: string,
): void;

/** Server-owned grant; returns JSON {grant, canonicalCbor} with lowercase hex. */
export function prepareGrantProposalV3(trustedGrantJson: string, hostWireJson: string,
  consumerWireJson: string, approvedAccount: Uint8Array, hostPin: Uint8Array,
  consumerPin: Uint8Array): string;
/** Independent maximum CBOR and current state; returns {grant, signature, canonicalCbor} JSON. */
export function verifyGrantProposalV3(submittedWireJson: string, maximumCborHex: string,
  hostWireJson: string, consumerWireJson: string, hostPin: Uint8Array,
  consumerPin: Uint8Array, currentAuthorityJson: string, now: bigint): string;
/** Independent saved context and stored grant; returns {context, canonicalCbor} JSON. */
export function prepareChannelContextV3(trustedContextJson: string, storedGrantWireJson: string,
  hostWireJson: string, consumerWireJson: string, hostPin: Uint8Array,
  consumerPin: Uint8Array, currentAuthorityJson: string, now: bigint): string;
/** Independent expected CBOR and current state; returns verified BrowserHandshakeV3 input JSON. */
export function verifyChannelAdmissionV3(submittedWireJson: string, expectedCborHex: string,
  storedGrantWireJson: string, hostWireJson: string, consumerWireJson: string,
  hostPin: Uint8Array, consumerPin: Uint8Array, currentAuthorityJson: string, now: bigint): string;
