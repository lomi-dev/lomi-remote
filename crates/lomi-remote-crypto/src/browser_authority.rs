//! Thin public-data browser adapters for authority enrollment verification.
use crate::{
    browser::{decode, encode, error, fixed},
    browser_v3::{now_u64, BrowserNow},
    prepare_host_enrollment_challenge, verify_host_enrollment_proof, verify_host_key_initiation,
    EnrollmentChallenge, HostEnrollmentChallengeContext, SignedHostKeyCommitment,
};
use lomi_remote_protocol::{EnrollmentInitiateParams, EnrollmentProof};
use wasm_bindgen::prelude::*;

#[derive(serde::Serialize)]
struct VerifiedPublicIdentity {
    identity: crate::SignedBundle,
    fingerprint: [u8; 32],
}

fn verified_identity(identity: crate::SignedBundle) -> Result<String, JsValue> {
    let fingerprint = identity.bundle.fingerprint().map_err(error)?;
    encode(&VerifiedPublicIdentity {
        identity,
        fingerprint,
    })
}

/// Returns JSON {identity: SignedBundle, fingerprint: number[32]}. Commitment,
/// pin and approved account must come from independently retained server state.
#[wasm_bindgen(js_name = verify_registered_host_identity)]
pub fn verify_registered_host_identity_json(
    proof_json: &str,
    committed_json: &str,
    initial_commitment: &[u8],
    approved_account_id: &[u8],
) -> Result<String, JsValue> {
    let proof: EnrollmentProof = decode(proof_json)?;
    let committed: SignedHostKeyCommitment = decode(committed_json)?;
    verified_identity(
        crate::verify_registered_host_identity(
            &committed,
            &fixed(initial_commitment)?,
            fixed(approved_account_id)?,
            &proof,
        )
        .map_err(error)?,
    )
}

/// Returns JSON {identity: SignedBundle, fingerprint: number[32]}. The account
/// and window ID must come from authenticated authority state.
#[wasm_bindgen(js_name = verify_consumer_window_identity)]
pub fn verify_consumer_window_identity_json(
    wire_json: &str,
    approved_account_id: &[u8],
    window_id: &[u8],
) -> Result<String, JsValue> {
    let wire: EnrollmentProof = decode(wire_json)?;
    verified_identity(
        crate::verify_consumer_window_identity(
            &wire,
            fixed(approved_account_id)?,
            fixed(window_id)?,
        )
        .map_err(error)?,
    )
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct PreparedConsumerWindowChallenge {
    challenge: crate::ConsumerWindowChallenge,
    canonical_cbor: String,
}

/// Context is independently retained authority state. Returns JSON
/// {challenge, canonicalCbor}, with canonicalCbor encoded as lowercase hex.
#[wasm_bindgen(js_name = prepare_consumer_window_challenge)]
pub fn prepare_consumer_window_challenge_json(
    wire_json: &str,
    approved_account_id: &[u8],
    context_json: &str,
) -> Result<String, JsValue> {
    let wire: EnrollmentProof = decode(wire_json)?;
    let context: crate::ConsumerWindowChallengeContext = decode(context_json)?;
    let challenge =
        crate::prepare_consumer_window_challenge(&wire, fixed(approved_account_id)?, &context)
            .map_err(error)?;
    let canonical_cbor = crate::public_identity_wire::hex(&challenge.canonical().map_err(error)?);
    encode(&PreparedConsumerWindowChallenge {
        challenge,
        canonical_cbor,
    })
}

/// Expected challenge and approved account are independently retained server
/// state. The authority also owns atomic single use of the operation and nonce.
#[wasm_bindgen(js_name = verify_consumer_window_proof)]
pub fn verify_consumer_window_proof_json(
    proof_json: &str,
    expected_json: &str,
    identity_wire_json: &str,
    approved_account_id: &[u8],
    now: &BrowserNow,
) -> Result<(), JsValue> {
    let now = now_u64(now)?;
    let proof: EnrollmentProof = decode(proof_json)?;
    let expected: crate::ConsumerWindowChallenge = decode(expected_json)?;
    let wire: EnrollmentProof = decode(identity_wire_json)?;
    crate::verify_consumer_window_proof(&proof, &expected, &wire, fixed(approved_account_id)?, now)
        .map_err(error)
}

/// Verify preapproval possession only. The authority independently retains the
/// result; a public client ID grants neither account approval nor class.
#[wasm_bindgen(js_name = verify_host_key_initiation)]
pub fn verify_host_key_initiation_json(request_json: &str) -> Result<String, JsValue> {
    let request: EnrollmentInitiateParams = decode(request_json)?;
    encode(&verify_host_key_initiation(&request).map_err(error)?)
}

/// Trusted arguments must come from independent authority storage, never from
/// the proof request. The caller must atomically consume enrollment state.
#[wasm_bindgen(js_name = verify_host_enrollment_proof)]
pub fn verify_host_enrollment_proof_json(
    proof_json: &str,
    expected_json: &str,
    committed_json: &str,
    initial_commitment: &[u8],
    approved_account_id: &[u8],
    now: &BrowserNow,
) -> Result<(), JsValue> {
    let now = now_u64(now)?;
    let proof: EnrollmentProof = decode(proof_json)?;
    let expected: EnrollmentChallenge = decode(expected_json)?;
    let committed: SignedHostKeyCommitment = decode(committed_json)?;
    verify_host_enrollment_proof(
        &proof,
        &expected,
        &committed,
        &fixed(initial_commitment)?,
        fixed(approved_account_id)?,
        now,
    )
    .map_err(error)
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct PreparedChallenge {
    challenge: EnrollmentChallenge,
    canonical_cbor: String,
}
/// Derive host claims from the retained init record and authenticated approval.
/// Context IDs and nonce must come from independently stored authority state.
#[wasm_bindgen(js_name = prepare_host_enrollment_challenge)]
pub fn prepare_host_enrollment_challenge_json(
    committed_json: &str,
    initial_commitment: &[u8],
    approved_account_id: &[u8],
    context_json: &str,
) -> Result<String, JsValue> {
    let committed: SignedHostKeyCommitment = decode(committed_json)?;
    let context: HostEnrollmentChallengeContext = decode(context_json)?;
    let challenge = prepare_host_enrollment_challenge(
        &committed,
        &fixed(initial_commitment)?,
        fixed(approved_account_id)?,
        &context,
    )
    .map_err(error)?;
    let canonical_cbor = challenge
        .canonical()
        .map_err(error)?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    encode(&PreparedChallenge {
        challenge,
        canonical_cbor,
    })
}

/// All context is independently retained authority state, never request claims.
#[wasm_bindgen(js_name = verify_host_refresh_proof)]
pub fn verify_host_refresh_proof_json(
    proof_json: &str,
    committed_json: &str,
    initial_commitment: &[u8],
    approved_account_id: &[u8],
    context_json: &str,
) -> Result<(), JsValue> {
    let proof: EnrollmentProof = decode(proof_json)?;
    let committed: SignedHostKeyCommitment = decode(committed_json)?;
    let context: crate::HostRefreshContext = decode(context_json)?;
    let pin = fixed(initial_commitment)?;
    let account = fixed(approved_account_id)?;
    let expected = crate::prepare_host_refresh_statement(&committed, &pin, account, &context)
        .map_err(error)?;
    crate::verify_host_refresh_proof(&proof, &expected, &committed, &pin, account).map_err(error)
}
