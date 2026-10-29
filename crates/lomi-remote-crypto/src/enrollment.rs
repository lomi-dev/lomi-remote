//! Isolated enrollment proof; this is not a grant or a Noise context.
use crate::{identity::verify_signature, Identity, Result, Role, SignedBundle};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};

/// Independent domain; historical live-profile signatures cannot be reused.
pub const ENROLLMENT_PROOF_DOMAIN: &str = "lomi-remote-host-enrollment-proof-v1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentChallenge {
    pub version: u8,
    pub enrollment_id: [u8; 16],
    pub host_id: [u8; 16],
    /// Fingerprint of the complete pinned host PublicBundle, not a client string.
    pub host_key_fingerprint: [u8; 32],
    pub bootstrap_session_id: [u8; 16],
    pub audience: String,
    /// Absolute Unix seconds, serialized as a canonical decimal u64 string.
    #[serde(with = "decimal_u64")]
    pub expires_at: u64,
    pub nonce: [u8; 32],
    pub operation_id: [u8; 16],
}
impl EnrollmentChallenge {
    pub fn canonical(&self) -> Result<Vec<u8>> {
        if self.version != 1
            || self.enrollment_id == [0; 16]
            || self.host_id == [0; 16]
            || self.host_key_fingerprint == [0; 32]
            || self.bootstrap_session_id == [0; 16]
            || self.operation_id == [0; 16]
            || self.nonce == [0; 32]
            || self.expires_at == 0
            || self.audience.is_empty()
            || self.audience.len() > 256
            || !self.audience.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err("invalid enrollment challenge".into());
        }
        // Fixed-length CBOR array, positional fields, shortest integer encoding.
        // Encode directly: wire::domain belongs to the historical live profile.
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(10).map_err(|_| "enrollment encoding failed")?;
        e.str(ENROLLMENT_PROOF_DOMAIN)
            .map_err(|_| "enrollment encoding failed")?;
        e.u8(self.version)
            .map_err(|_| "enrollment encoding failed")?;
        e.bytes(&self.enrollment_id)
            .map_err(|_| "enrollment encoding failed")?;
        e.bytes(&self.host_id)
            .map_err(|_| "enrollment encoding failed")?;
        e.bytes(&self.host_key_fingerprint)
            .map_err(|_| "enrollment encoding failed")?;
        e.bytes(&self.bootstrap_session_id)
            .map_err(|_| "enrollment encoding failed")?;
        e.str(&self.audience)
            .map_err(|_| "enrollment encoding failed")?;
        e.u64(self.expires_at)
            .map_err(|_| "enrollment encoding failed")?;
        e.bytes(&self.nonce)
            .map_err(|_| "enrollment encoding failed")?;
        e.bytes(&self.operation_id)
            .map_err(|_| "enrollment encoding failed")?;
        Ok(e.into_writer())
    }
    /// Decode only the bounded, exact canonical enrollment representation.
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        // Array, domain, version, four UUIDs, two hashes, audience and u64.
        const MAX_CBOR: usize =
            1 + 2 + ENROLLMENT_PROOF_DOMAIN.len() + 1 + 4 * 17 + 2 * 34 + 3 + 256 + 9;
        let invalid = "invalid canonical enrollment challenge";
        if bytes.len() > MAX_CBOR {
            return Err(invalid.into());
        }
        let mut d = minicbor::Decoder::new(bytes);
        if d.array().map_err(|_| invalid)? != Some(10)
            || d.str().map_err(|_| invalid)? != ENROLLMENT_PROOF_DOMAIN
        {
            return Err(invalid.into());
        }
        let version = d.u8().map_err(|_| invalid)?;
        let enrollment_id = d
            .bytes()
            .map_err(|_| invalid)?
            .try_into()
            .map_err(|_| invalid)?;
        let host_id = d
            .bytes()
            .map_err(|_| invalid)?
            .try_into()
            .map_err(|_| invalid)?;
        let host_key_fingerprint = d
            .bytes()
            .map_err(|_| invalid)?
            .try_into()
            .map_err(|_| invalid)?;
        let bootstrap_session_id = d
            .bytes()
            .map_err(|_| invalid)?
            .try_into()
            .map_err(|_| invalid)?;
        let audience = d.str().map_err(|_| invalid)?;
        // Check the borrowed string before making the sole variable-size copy.
        if audience.is_empty()
            || audience.len() > 256
            || !audience.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(invalid.into());
        }
        let value = Self {
            version,
            enrollment_id,
            host_id,
            host_key_fingerprint,
            bootstrap_session_id,
            audience: audience.to_owned(),
            expires_at: d.u64().map_err(|_| invalid)?,
            nonce: d
                .bytes()
                .map_err(|_| invalid)?
                .try_into()
                .map_err(|_| invalid)?,
            operation_id: d
                .bytes()
                .map_err(|_| invalid)?
                .try_into()
                .map_err(|_| invalid)?,
        };
        if d.position() != bytes.len() || value.canonical()? != bytes {
            return Err(invalid.into());
        }
        Ok(value)
    }
    fn validate_host(&self, host: &SignedBundle) -> Result<()> {
        if host.bundle.role != Role::Host
            || host.bundle.subject_id != self.host_id
            || host.bundle.fingerprint()? != self.host_key_fingerprint
        {
            return Err("enrollment host binding mismatch".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedEnrollmentProof {
    pub challenge: EnrollmentChallenge,
    pub signature: Vec<u8>,
}
impl Identity {
    /// Reuses the existing identity signing seed without exporting secret bytes.
    pub fn sign_enrollment_proof(
        &self,
        challenge: &EnrollmentChallenge,
    ) -> Result<SignedEnrollmentProof> {
        if self.disposed {
            return Err("identity disposed".into());
        }
        challenge.validate_host(&self.signed)?;
        let canonical = challenge.canonical()?;
        Ok(SignedEnrollmentProof {
            challenge: challenge.clone(),
            signature: self.signing.sign(&canonical).to_bytes().to_vec(),
        })
    }
}
impl SignedEnrollmentProof {
    /// `expected` must come from the independently stored approved enrollment,
    /// and the fingerprint from its immutable host binding, never the request.
    /// The caller must atomically consume nonce/enrollment/operation in storage;
    /// signature verification alone does not stop replay or enforce session class.
    pub fn verify(
        &self,
        expected: &EnrollmentChallenge,
        host: &SignedBundle,
        pinned_host_fingerprint: &[u8; 32],
        now_unix_seconds: u64,
    ) -> Result<()> {
        if self.challenge != *expected {
            return Err("enrollment challenge mismatch".into());
        }
        let canonical = expected.canonical()?;
        if now_unix_seconds >= expected.expires_at {
            return Err("enrollment challenge expired".into());
        }
        host.verify(pinned_host_fingerprint)?;
        expected.validate_host(host)?;
        verify_signature(&host.bundle.identity_key, &canonical, &self.signature)
    }
}
mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(n: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&n.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s.is_empty()
            || !s.bytes().all(|b| b.is_ascii_digit())
            || (s.len() > 1 && s.starts_with('0'))
        {
            return Err(serde::de::Error::custom(
                "expected canonical decimal u64 string",
            ));
        }
        s.parse().map_err(serde::de::Error::custom)
    }
}
