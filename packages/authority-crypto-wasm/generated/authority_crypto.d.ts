/* tslint:disable */
/* eslint-disable */

export class BrowserChannel {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    dispose(): void;
    open(routing: Uint8Array, frame_json: string): Uint8Array;
    open_binary(routing: Uint8Array, frame: Uint8Array): Uint8Array;
    seal(routing: Uint8Array, plaintext: Uint8Array): string;
    seal_binary(routing: Uint8Array, plaintext: Uint8Array): Uint8Array;
    transcript_hash(): Uint8Array;
}

export class BrowserHandshake {
    free(): void;
    [Symbol.dispose](): void;
    dispose(): void;
    finish(): BrowserChannel;
    constructor(initiator: boolean, identity: BrowserIdentity, context_json: string, peer_json: string, pinned_peer: Uint8Array);
    read(message: Uint8Array): void;
    write(): Uint8Array;
}

export class BrowserHandshakeV3 {
    free(): void;
    [Symbol.dispose](): void;
    dispose(): void;
    finish(): BrowserChannel;
    /**
     * Expected context, current membership, endpoint pins and now are independent
     * trusted inputs supplied by the caller's authority adapter. Never derive
     * them from the signed JSON received over the channel.
     */
    constructor(initiator: boolean, identity: BrowserIdentity, signed_json: string, expected_json: string, authority_json: string, host_pin: Uint8Array, consumer_pin: Uint8Array, now: bigint);
    read(message: Uint8Array): void;
    write(): Uint8Array;
}

/**
 * Rust-held identity with a one-time seed-blob bridge for immediate WebCrypto
 * encryption. JavaScript copies remain outside Rust zeroization guarantees.
 */
export class BrowserIdentity {
    free(): void;
    [Symbol.dispose](): void;
    dispose(): void;
    fingerprint(): Uint8Array;
    constructor(account_id: Uint8Array, subject_id: Uint8Array, host: boolean, key_version: number);
    open_mailbox(envelope_json: string, sender_json: string, pinned_sender: Uint8Array, policy_json: string, now: bigint): Uint8Array;
    public_bundle(): string;
    /**
     * Bounded public EnrollmentProof carrier; contains no secret key material.
     */
    public_identity_wire(): string;
    /**
     * Restore only from a browser-decrypted seed blob and an exact public
     * bundle previously persisted beside it. The requested scope is checked
     * in Rust before the keys are reconstructed.
     */
    static restore(account_id: Uint8Array, subject_id: Uint8Array, seed_blob: Uint8Array, expected_bundle_json: string): BrowserIdentity;
    seal_mailbox(recipient_json: string, pinned_recipient: Uint8Array, policy_json: string, now: bigint, expires_at: bigint, payload: Uint8Array): string;
    /**
     * Returns the seed blob once so the caller can encrypt it with WebCrypto.
     * Callers must zero the returned JavaScript buffer immediately.
     */
    seed_blob_for_encryption(): Uint8Array;
    /**
     * Sign only an exact native-decoded canonical window challenge. Identity
     * binding and disposal checks remain in the native signer.
     */
    sign_consumer_window_proof(canonical_cbor: Uint8Array): string;
    sign_consumer_window_proof_bound(canonical_cbor: Uint8Array, expected_json: string, now: bigint): string;
}

export function live_production_qualified(): boolean;

export function pairing_fingerprint(account_id: Uint8Array, host_id: Uint8Array, device_id: Uint8Array, host_fingerprint: Uint8Array, device_fingerprint: Uint8Array, pairing_nonce: Uint8Array): string;

/**
 * Context is assembled from a saved server row; grant is the stored approval.
 */
export function prepare_channel_context_v3(trusted_context_json: string, stored_grant_wire_json: string, host_wire_json: string, consumer_wire_json: string, host_pin: Uint8Array, consumer_pin: Uint8Array, authority_json: string, now: bigint): string;

/**
 * Context is independently retained authority state. Returns JSON
 * {challenge, canonicalCbor}, with canonicalCbor encoded as lowercase hex.
 */
export function prepare_consumer_window_challenge(wire_json: string, approved_account_id: Uint8Array, context_json: string): string;

/**
 * Trusted grant is assembled from independently retained authority rows.
 */
export function prepare_grant_proposal_v3(trusted_grant_json: string, host_wire_json: string, consumer_wire_json: string, approved_account: Uint8Array, host_pin: Uint8Array, consumer_pin: Uint8Array): string;

/**
 * Derive host claims from the retained init record and authenticated approval.
 * Context IDs and nonce must come from independently stored authority state.
 */
export function prepare_host_enrollment_challenge(committed_json: string, initial_commitment: Uint8Array, approved_account_id: Uint8Array, context_json: string): string;

export function production_qualified(): boolean;

export function remote_v3_production_qualified(): boolean;

/**
 * The approval must first be verified against trusted host and grant state.
 */
export function validate_channel_approval(context_json: string, approval_json: string): void;

/**
 * Cross-runtime diagnostic over already verified admission, not a signing API.
 */
export function verified_v3_artifacts(signed_json: string, expected_json: string, authority_json: string, host_pin: Uint8Array, consumer_pin: Uint8Array, now: bigint): string;

/**
 * Expected CBOR, stored approval, pins and current authority are independent state.
 * Result is the verified AdmissionInput JSON accepted by BrowserHandshakeV3.
 */
export function verify_channel_admission_v3(submitted_wire_json: string, expected_cbor_hex: string, stored_grant_wire_json: string, host_wire_json: string, consumer_wire_json: string, host_pin: Uint8Array, consumer_pin: Uint8Array, authority_json: string, now: bigint): string;

/**
 * Returns JSON {identity: SignedBundle, fingerprint: number[32]}. The account
 * and window ID must come from authenticated authority state.
 */
export function verify_consumer_window_identity(wire_json: string, approved_account_id: Uint8Array, window_id: Uint8Array): string;

/**
 * Expected challenge and approved account are independently retained server
 * state. The authority also owns atomic single use of the operation and nonce.
 */
export function verify_consumer_window_proof(proof_json: string, expected_json: string, identity_wire_json: string, approved_account_id: Uint8Array, now: bigint): void;

/**
 * Maximum CBOR, endpoint pins and current authority are independent stored state.
 */
export function verify_grant_proposal_v3(submitted_wire_json: string, maximum_cbor_hex: string, host_wire_json: string, consumer_wire_json: string, host_pin: Uint8Array, consumer_pin: Uint8Array, authority_json: string, now: bigint): string;

/**
 * Trusted arguments must come from independent authority storage, never from
 * the proof request. The caller must atomically consume enrollment state.
 */
export function verify_host_enrollment_proof(proof_json: string, expected_json: string, committed_json: string, initial_commitment: Uint8Array, approved_account_id: Uint8Array, now: bigint): void;

/**
 * Verify preapproval possession only. The authority independently retains the
 * result; a public client ID grants neither account approval nor class.
 */
export function verify_host_key_initiation(request_json: string): string;

/**
 * All context is independently retained authority state, never request claims.
 */
export function verify_host_refresh_proof(proof_json: string, committed_json: string, initial_commitment: Uint8Array, approved_account_id: Uint8Array, context_json: string): void;

export function verify_peer_approval(approval_json: string, host_json: string, pin: Uint8Array, expected_json: string, now: bigint, current_epoch: bigint): void;

export function verify_public_bundle(bundle_json: string, pin: Uint8Array): void;

/**
 * Returns JSON {identity: SignedBundle, fingerprint: number[32]}. Commitment,
 * pin and approved account must come from independently retained server state.
 */
export function verify_registered_host_identity(proof_json: string, committed_json: string, initial_commitment: Uint8Array, approved_account_id: Uint8Array): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_browserchannel_free: (a: number, b: number) => void;
    readonly __wbg_browserhandshake_free: (a: number, b: number) => void;
    readonly __wbg_browseridentity_free: (a: number, b: number) => void;
    readonly browserchannel_dispose: (a: number) => void;
    readonly browserchannel_open: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly browserchannel_open_binary: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly browserchannel_seal: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly browserchannel_seal_binary: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly browserchannel_transcript_hash: (a: number) => [number, number];
    readonly browserhandshake_dispose: (a: number) => void;
    readonly browserhandshake_finish: (a: number) => [number, number, number];
    readonly browserhandshake_new: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly browserhandshake_read: (a: number, b: number, c: number) => [number, number];
    readonly browserhandshake_write: (a: number) => [number, number, number, number];
    readonly browserhandshakev3_new: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: any) => [number, number, number];
    readonly browseridentity_dispose: (a: number) => void;
    readonly browseridentity_fingerprint: (a: number) => [number, number, number, number];
    readonly browseridentity_new: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly browseridentity_open_mailbox: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: bigint) => [number, number, number, number];
    readonly browseridentity_public_bundle: (a: number) => [number, number, number, number];
    readonly browseridentity_public_identity_wire: (a: number) => [number, number, number, number];
    readonly browseridentity_restore: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly browseridentity_seal_mailbox: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: bigint, i: bigint, j: number, k: number) => [number, number, number, number];
    readonly browseridentity_seed_blob_for_encryption: (a: number) => [number, number, number, number];
    readonly browseridentity_sign_consumer_window_proof: (a: number, b: number, c: number) => [number, number, number, number];
    readonly browseridentity_sign_consumer_window_proof_bound: (a: number, b: number, c: number, d: number, e: number, f: bigint) => [number, number, number, number];
    readonly live_production_qualified: () => number;
    readonly pairing_fingerprint: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => [number, number, number, number];
    readonly prepare_channel_context_v3: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: any) => [number, number, number, number];
    readonly prepare_consumer_window_challenge: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly prepare_grant_proposal_v3: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => [number, number, number, number];
    readonly prepare_host_enrollment_challenge: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly production_qualified: () => number;
    readonly validate_channel_approval: (a: number, b: number, c: number, d: number) => [number, number];
    readonly verified_v3_artifacts: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: any) => [number, number, number, number];
    readonly verify_channel_admission_v3: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: any) => [number, number, number, number];
    readonly verify_consumer_window_identity: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly verify_consumer_window_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: any) => [number, number];
    readonly verify_grant_proposal_v3: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: any) => [number, number, number, number];
    readonly verify_host_enrollment_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: any) => [number, number];
    readonly verify_host_key_initiation: (a: number, b: number) => [number, number, number, number];
    readonly verify_host_refresh_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number];
    readonly verify_peer_approval: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint, j: bigint) => [number, number];
    readonly verify_public_bundle: (a: number, b: number, c: number, d: number) => [number, number];
    readonly verify_registered_host_identity: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly browserhandshakev3_dispose: (a: number) => void;
    readonly browserhandshakev3_read: (a: number, b: number, c: number) => [number, number];
    readonly remote_v3_production_qualified: () => number;
    readonly browserhandshakev3_write: (a: number) => [number, number, number, number];
    readonly browserhandshakev3_finish: (a: number) => [number, number, number];
    readonly __wbg_browserhandshakev3_free: (a: number, b: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
