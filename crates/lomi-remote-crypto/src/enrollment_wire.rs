//! Public HTTP envelopes verified using canonical enrollment cryptography.
use crate::{
    AccountIndependentHostKey, EnrollmentChallenge, Result, SignedEnrollmentProof,
    SignedHostKeyCommitment,
};
use lomi_remote_protocol::{DecimalU64, EnrollmentInitiateParams, EnrollmentProof};
use serde::{Deserialize, Serialize};

// Both canonical schemas fit below this cap; their decoders enforce exact limits.
const MAX_CANONICAL_CBOR: usize = 1024;
pub(crate) fn hex_bytes(value: &str, max: usize) -> Result<Vec<u8>> {
    if value.is_empty()
        || value.len() > max * 2
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid bounded enrollment hex".into());
    }
    let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    Ok(value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| nibble(pair[0]) * 16 + nibble(pair[1]))
        .collect())
}
fn fixed_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 {
        return Err("invalid enrollment hex length".into());
    }
    hex_bytes(value, N)?
        .try_into()
        .map_err(|_| "invalid enrollment hex length".into())
}
pub(crate) fn signature(proof: &EnrollmentProof) -> Result<Vec<u8>> {
    Ok(fixed_hex::<64>(proof.signature.expose_wire())?.to_vec())
}

/// Verify public possession of a complete preapproval host descriptor.
///
/// The authority must independently retain the returned commitment before
/// approval. Public client IDs confer neither an authorization class nor account
/// approval; this result is not an account-bound identity or enrollment approval.
pub fn verify_host_key_initiation(
    request: &EnrollmentInitiateParams,
) -> Result<SignedHostKeyCommitment> {
    let pin = fixed_hex::<32>(request.key_commitment.expose_wire())?;
    let bytes = hex_bytes(
        request.proof.canonical_cbor.expose_wire(),
        MAX_CANONICAL_CBOR,
    )?;
    let signed = SignedHostKeyCommitment {
        descriptor: AccountIndependentHostKey::from_canonical(&bytes)?,
        signature: signature(&request.proof)?,
    };
    signed.verify(&pin)?;
    Ok(signed)
}

/// Verify a final wire proof against independently retained authority state.
///
/// None of the expected challenge, init commitment, initial pin or approved
/// account may be derived from the request. The authority must also atomically
/// consume enrollment/nonce/operation state to prevent replay.
pub fn verify_host_enrollment_proof(
    proof: &EnrollmentProof,
    expected: &EnrollmentChallenge,
    committed: &SignedHostKeyCommitment,
    initial_commitment: &[u8; 32],
    approved_account_id: [u8; 16],
    now: u64,
) -> Result<()> {
    let bytes = hex_bytes(proof.canonical_cbor.expose_wire(), MAX_CANONICAL_CBOR)?;
    SignedEnrollmentProof {
        challenge: EnrollmentChallenge::from_canonical(&bytes)?,
        signature: signature(proof)?,
    }
    .verify_committed_host(
        expected,
        committed,
        initial_commitment,
        approved_account_id,
        now,
    )
}

/// Server-owned context supplied only after account approval and bootstrap
/// session creation. Host identity and fingerprint are derived separately.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostEnrollmentChallengeContext {
    pub enrollment_id: [u8; 16],
    pub bootstrap_session_id: [u8; 16],
    pub operation_id: [u8; 16],
    pub nonce: [u8; 32],
    #[serde(deserialize_with = "bounded_audience")]
    pub audience: String,
    pub expires_at: DecimalU64,
}
fn validate_audience(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 256 || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("invalid enrollment audience".into());
    }
    Ok(())
}
fn bounded_audience<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<String, D::Error> {
    struct Audience;
    impl serde::de::Visitor<'_> for Audience {
        type Value = String;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a bounded ASCII enrollment audience")
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<String, E> {
            // Validate borrowed text before allocating its owned representation.
            validate_audience(value).map_err(E::custom)?;
            Ok(value.to_owned())
        }
    }
    d.deserialize_str(Audience)
}

/// Prepare the exact challenge using independently stored authority context.
///
/// Approval and the bootstrap session binding must already be authenticated by
/// the authority. This helper verifies the retained init commitment and derives
/// all host claims; it neither approves accounts nor signs or consumes a proof.
pub fn prepare_host_enrollment_challenge(
    committed: &SignedHostKeyCommitment,
    initial_commitment: &[u8; 32],
    approved_account_id: [u8; 16],
    context: &HostEnrollmentChallengeContext,
) -> Result<EnrollmentChallenge> {
    validate_audience(&context.audience)?;
    committed.verify(initial_commitment)?;
    let host = committed
        .descriptor
        .account_bound_bundle(approved_account_id)?;
    let challenge = EnrollmentChallenge {
        version: 1,
        enrollment_id: context.enrollment_id,
        host_id: host.subject_id,
        host_key_fingerprint: host.fingerprint()?,
        bootstrap_session_id: context.bootstrap_session_id,
        audience: context.audience.clone(),
        expires_at: context.expires_at.0,
        nonce: context.nonce,
        operation_id: context.operation_id,
    };
    challenge.canonical()?;
    Ok(challenge)
}
