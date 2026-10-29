//! Account-session-bound window possession. The server owns fresh nonces,
//! short challenge lifetimes and atomic single use; signatures alone do not
//! prevent replay or approve an account.
use crate::{
    Identity, Result, Role,
    identity::verify_signature,
    public_identity_wire::{fixed, wire},
    verify_consumer_window_identity,
};
use ed25519_dalek::Signer;
use lomi_remote_protocol::{AccountSessionId, DecimalU64, EnrollmentProof};
use serde::{Deserialize, Serialize};
pub const CONSUMER_WINDOW_PROOF_DOMAIN: &str = "lomi-remote-consumer-window-proof-v1";
fn validate_session(value: &str) -> Result<()> {
    // Keep the same exact opaque token semantics as protocol AccountSessionId.
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err("invalid account session ID".into());
    }
    Ok(())
}
fn validate_audience(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 256 || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("invalid consumer window audience".into());
    }
    Ok(())
}
fn bounded_text<'de, D: serde::Deserializer<'de>>(
    d: D,
    session: bool,
) -> std::result::Result<String, D::Error> {
    struct Text(bool);
    impl serde::de::Visitor<'_> for Text {
        type Value = String;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("bounded ASCII text")
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<String, E> {
            if self.0 {
                validate_session(v)
            } else {
                validate_audience(v)
            }
            .map_err(E::custom)?;
            Ok(v.to_owned())
        }
    }
    d.deserialize_str(Text(session))
}
fn bounded_session<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<String, D::Error> {
    bounded_text(d, true)
}
fn bounded_audience<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<String, D::Error> {
    bounded_text(d, false)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsumerWindowChallenge {
    pub version: u8,
    pub account_id: [u8; 16],
    pub consumer_authorization_id: [u8; 16],
    #[serde(deserialize_with = "bounded_session")]
    pub account_session_id: String,
    pub window_identity_id: [u8; 16],
    pub window_key_fingerprint: [u8; 32],
    pub operation_id: [u8; 16],
    pub nonce: [u8; 32],
    #[serde(deserialize_with = "bounded_audience")]
    pub audience: String,
    pub expires_at: DecimalU64,
}
impl ConsumerWindowChallenge {
    pub fn canonical(&self) -> Result<Vec<u8>> {
        validate_session(&self.account_session_id)?;
        validate_audience(&self.audience)?;
        // Verify against the protocol type as well, preventing semantic drift.
        AccountSessionId::try_from(self.account_session_id.clone())
            .map_err(|_| "invalid account session ID")?;
        if self.version != 1
            || [
                self.account_id,
                self.consumer_authorization_id,
                self.window_identity_id,
                self.operation_id,
            ]
            .contains(&[0; 16])
            || [self.window_key_fingerprint, self.nonce].contains(&[0; 32])
            || self.expires_at.0 == 0
        {
            return Err("invalid consumer window challenge".into());
        }
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(11).unwrap();
        e.str(CONSUMER_WINDOW_PROOF_DOMAIN).unwrap();
        e.u8(self.version).unwrap();
        e.bytes(&self.account_id).unwrap();
        e.bytes(&self.consumer_authorization_id).unwrap();
        e.str(&self.account_session_id).unwrap();
        e.bytes(&self.window_identity_id).unwrap();
        e.bytes(&self.window_key_fingerprint).unwrap();
        e.bytes(&self.operation_id).unwrap();
        e.bytes(&self.nonce).unwrap();
        e.str(&self.audience).unwrap();
        e.u64(self.expires_at.0).unwrap();
        Ok(e.into_writer())
    }
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        const MAX: usize = 1
            + 2
            + CONSUMER_WINDOW_PROOF_DOMAIN.len()
            + 1
            + 4 * 17
            + 2 * 34
            + 2
            + 128
            + 3
            + 256
            + 9;
        let invalid = "invalid canonical consumer window challenge";
        if bytes.len() > MAX {
            return Err(invalid.into());
        }
        let mut d = minicbor::Decoder::new(bytes);
        if d.array().map_err(|_| invalid)? != Some(11)
            || d.str().map_err(|_| invalid)? != CONSUMER_WINDOW_PROOF_DOMAIN
        {
            return Err(invalid.into());
        }
        let version = d.u8().map_err(|_| invalid)?;
        let account_id = fixed(&mut d)?;
        let consumer_authorization_id = fixed(&mut d)?;
        let session = d.str().map_err(|_| invalid)?;
        validate_session(session)?;
        let window_identity_id = fixed(&mut d)?;
        let window_key_fingerprint = fixed(&mut d)?;
        let operation_id = fixed(&mut d)?;
        let nonce = fixed(&mut d)?;
        let audience = d.str().map_err(|_| invalid)?;
        validate_audience(audience)?;
        let expires_at = DecimalU64(d.u64().map_err(|_| invalid)?);
        if d.position() != bytes.len() {
            return Err(invalid.into());
        }
        let value = Self {
            version,
            account_id,
            consumer_authorization_id,
            account_session_id: session.to_owned(),
            window_identity_id,
            window_key_fingerprint,
            operation_id,
            nonce,
            audience: audience.to_owned(),
            expires_at,
        };
        if value.canonical()? != bytes {
            return Err(invalid.into());
        }
        Ok(value)
    }
}
/// Every field comes from independently authenticated, retained server state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsumerWindowChallengeContext {
    pub consumer_authorization_id: [u8; 16],
    #[serde(deserialize_with = "bounded_session")]
    pub account_session_id: String,
    pub window_identity_id: [u8; 16],
    pub operation_id: [u8; 16],
    pub nonce: [u8; 32],
    #[serde(deserialize_with = "bounded_audience")]
    pub audience: String,
    pub expires_at: DecimalU64,
}
pub fn prepare_consumer_window_challenge(
    submitted: &EnrollmentProof,
    approved_account_id: [u8; 16],
    context: &ConsumerWindowChallengeContext,
) -> Result<ConsumerWindowChallenge> {
    validate_session(&context.account_session_id)?;
    validate_audience(&context.audience)?;
    let signed = verify_consumer_window_identity(
        submitted,
        approved_account_id,
        context.window_identity_id,
    )?;
    let challenge = ConsumerWindowChallenge {
        version: 1,
        account_id: approved_account_id,
        consumer_authorization_id: context.consumer_authorization_id,
        account_session_id: context.account_session_id.clone(),
        window_identity_id: context.window_identity_id,
        window_key_fingerprint: signed.bundle.fingerprint()?,
        operation_id: context.operation_id,
        nonce: context.nonce,
        audience: context.audience.clone(),
        expires_at: context.expires_at,
    };
    challenge.canonical()?;
    Ok(challenge)
}
pub fn verify_consumer_window_proof(
    proof: &EnrollmentProof,
    expected: &ConsumerWindowChallenge,
    submitted: &EnrollmentProof,
    approved_account_id: [u8; 16],
    now: u64,
) -> Result<()> {
    expected.canonical()?;
    let signed = verify_consumer_window_identity(
        submitted,
        approved_account_id,
        expected.window_identity_id,
    )?;
    if expected.account_id != approved_account_id
        || expected.window_key_fingerprint != signed.bundle.fingerprint()?
        || now >= expected.expires_at.0
    {
        return Err("consumer window trusted context mismatch or expiry".into());
    }
    let bytes = crate::enrollment_wire::hex_bytes(proof.canonical_cbor.expose_wire(), 1024)?;
    if ConsumerWindowChallenge::from_canonical(&bytes)? != *expected {
        return Err("consumer window trusted challenge mismatch".into());
    }
    verify_signature(
        &signed.bundle.identity_key,
        &bytes,
        &crate::enrollment_wire::signature(proof)?,
    )
}
impl Identity {
    /// Bind a client-side proof to independently retained authenticated state.
    /// A challenge from a different login must never adopt a durable window.
    pub fn sign_consumer_window_proof_bound(
        &self,
        challenge: &ConsumerWindowChallenge,
        expected: &ConsumerWindowProofBinding,
        now: u64,
    ) -> Result<EnrollmentProof> {
        validate_session(&expected.account_session_id)?;
        if expected.consumer_authorization_id == [0; 16]
            || expected.operation_id == [0; 16]
            || challenge.consumer_authorization_id != expected.consumer_authorization_id
            || challenge.account_session_id != expected.account_session_id
            || challenge.operation_id != expected.operation_id
            || challenge.expires_at.0 <= now
        {
            return Err("consumer window authorization binding changed or expired".into());
        }
        self.sign_consumer_window_proof(challenge)
    }

    pub fn sign_consumer_window_proof(
        &self,
        challenge: &ConsumerWindowChallenge,
    ) -> Result<EnrollmentProof> {
        let b = &self.signed.bundle;
        if self.disposed
            || b.role != Role::Device
            || b.account_id == [0; 16]
            || challenge.account_id != b.account_id
            || challenge.window_identity_id != b.subject_id
            || challenge.window_key_fingerprint != b.fingerprint()?
        {
            return Err("consumer window signer mismatch or disposed".into());
        }
        self.signed.verify(&b.fingerprint()?)?;
        let bytes = challenge.canonical()?;
        wire(&bytes, &self.signing.sign(&bytes).to_bytes())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsumerWindowProofBinding {
    pub consumer_authorization_id: [u8; 16],
    #[serde(deserialize_with = "bounded_session")]
    pub account_session_id: String,
    pub operation_id: [u8; 16],
}
