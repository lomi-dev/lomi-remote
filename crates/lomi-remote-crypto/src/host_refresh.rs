//! Domain-separated refresh possession proof. Storage must enforce rotation,
//! recovery, idle expiry and current account/host epochs atomically. A captured
//! signed request can be replayed within the server's recovery window; this is
//! not DPoP and does not prove fresh key possession on replay.
use crate::{identity::verify_signature, Identity, Result, Role, SignedHostKeyCommitment};
use ed25519_dalek::Signer;
use lomi_remote_protocol::EnrollmentProof;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const HOST_REFRESH_PROOF_DOMAIN: &str = "lomi-remote-host-refresh-proof-v1";

pub(crate) fn validate_audience(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 256 || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("invalid refresh audience".into());
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
            f.write_str("a bounded ASCII refresh audience")
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<String, E> {
            validate_audience(value).map_err(E::custom)?;
            Ok(value.to_owned())
        }
    }
    d.deserialize_str(Audience)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostRefreshStatement {
    pub version: u8,
    pub account_id: [u8; 16],
    pub host_id: [u8; 16],
    pub host_authorization_id: [u8; 16],
    pub host_key_fingerprint: [u8; 32],
    pub rotation_id: [u8; 16],
    pub refresh_hash: [u8; 32],
    #[serde(deserialize_with = "bounded_audience")]
    pub audience: String,
}
impl HostRefreshStatement {
    pub fn canonical(&self) -> Result<Vec<u8>> {
        validate_audience(&self.audience)?;
        if self.version != 1
            || [
                self.account_id,
                self.host_id,
                self.host_authorization_id,
                self.rotation_id,
            ]
            .contains(&[0; 16])
            || [self.host_key_fingerprint, self.refresh_hash].contains(&[0; 32])
        {
            return Err("invalid host refresh statement".into());
        }
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(9).unwrap();
        e.str(HOST_REFRESH_PROOF_DOMAIN).unwrap();
        e.u8(self.version).unwrap();
        e.bytes(&self.account_id).unwrap();
        e.bytes(&self.host_id).unwrap();
        e.bytes(&self.host_authorization_id).unwrap();
        e.bytes(&self.host_key_fingerprint).unwrap();
        e.bytes(&self.rotation_id).unwrap();
        e.bytes(&self.refresh_hash).unwrap();
        e.str(&self.audience).unwrap();
        Ok(e.into_writer())
    }
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        const MAX_CBOR: usize =
            1 + 2 + HOST_REFRESH_PROOF_DOMAIN.len() + 1 + 4 * 17 + 2 * 34 + 3 + 256;
        let invalid = "invalid canonical host refresh statement";
        if bytes.len() > MAX_CBOR {
            return Err(invalid.into());
        }
        let mut d = minicbor::Decoder::new(bytes);
        if d.array().map_err(|_| invalid)? != Some(9)
            || d.str().map_err(|_| invalid)? != HOST_REFRESH_PROOF_DOMAIN
        {
            return Err(invalid.into());
        }
        let version = d.u8().map_err(|_| invalid)?;
        let account_id = d
            .bytes()
            .map_err(|_| invalid)?
            .try_into()
            .map_err(|_| invalid)?;
        let host_id = d
            .bytes()
            .map_err(|_| invalid)?
            .try_into()
            .map_err(|_| invalid)?;
        let host_authorization_id = d
            .bytes()
            .map_err(|_| invalid)?
            .try_into()
            .map_err(|_| invalid)?;
        let host_key_fingerprint = d
            .bytes()
            .map_err(|_| invalid)?
            .try_into()
            .map_err(|_| invalid)?;
        let rotation_id = d
            .bytes()
            .map_err(|_| invalid)?
            .try_into()
            .map_err(|_| invalid)?;
        let refresh_hash = d
            .bytes()
            .map_err(|_| invalid)?
            .try_into()
            .map_err(|_| invalid)?;
        let audience = d.str().map_err(|_| invalid)?;
        validate_audience(audience)?;
        let value = Self {
            version,
            account_id,
            host_id,
            host_authorization_id,
            host_key_fingerprint,
            rotation_id,
            refresh_hash,
            audience: audience.to_owned(),
        };
        if d.position() != bytes.len() || value.canonical()? != bytes {
            return Err(invalid.into());
        }
        Ok(value)
    }
}

/// Independently stored authority context. Audience configuration must be the
/// canonical HTTPS origin plus exact refresh path, without query or fragment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostRefreshContext {
    pub host_authorization_id: [u8; 16],
    pub rotation_id: [u8; 16],
    pub refresh_hash: [u8; 32],
    #[serde(deserialize_with = "bounded_audience")]
    pub audience: String,
}
pub fn prepare_host_refresh_statement(
    committed: &SignedHostKeyCommitment,
    initial_commitment: &[u8; 32],
    approved_account_id: [u8; 16],
    context: &HostRefreshContext,
) -> Result<HostRefreshStatement> {
    validate_audience(&context.audience)?;
    committed.verify(initial_commitment)?;
    let host = committed
        .descriptor
        .account_bound_bundle(approved_account_id)?;
    let statement = HostRefreshStatement {
        version: 1,
        account_id: approved_account_id,
        host_id: host.subject_id,
        host_authorization_id: context.host_authorization_id,
        host_key_fingerprint: host.fingerprint()?,
        rotation_id: context.rotation_id,
        refresh_hash: context.refresh_hash,
        audience: context.audience.clone(),
    };
    statement.canonical()?;
    Ok(statement)
}

/// The shared HTTP carrier contains domain-specific canonical bytes; its name
/// does not permit enrollment signatures to authorize refresh.
pub fn verify_host_refresh_proof(
    proof: &EnrollmentProof,
    expected: &HostRefreshStatement,
    committed: &SignedHostKeyCommitment,
    initial_commitment: &[u8; 32],
    approved_account_id: [u8; 16],
) -> Result<()> {
    validate_audience(&expected.audience)?;
    let trusted = prepare_host_refresh_statement(
        committed,
        initial_commitment,
        approved_account_id,
        &HostRefreshContext {
            host_authorization_id: expected.host_authorization_id,
            rotation_id: expected.rotation_id,
            refresh_hash: expected.refresh_hash,
            audience: expected.audience.clone(),
        },
    )?;
    let bytes = crate::enrollment_wire::hex_bytes(proof.canonical_cbor.expose_wire(), 1024)?;
    if *expected != trusted || HostRefreshStatement::from_canonical(&bytes)? != trusted {
        return Err("refresh trusted context mismatch".into());
    }
    verify_signature(
        &committed.descriptor.identity_key,
        &bytes,
        &crate::enrollment_wire::signature(proof)?,
    )
}

impl Identity {
    /// Hash the exact bounded ASCII wire credential, with no normalization or
    /// decoding, and sign using the retained seed without exporting it.
    pub fn sign_host_refresh_proof(
        &self,
        host_authorization_id: [u8; 16],
        rotation_id: [u8; 16],
        refresh_credential: &str,
        audience: &str,
    ) -> Result<EnrollmentProof> {
        validate_audience(audience)?;
        if self.disposed
            || self.signed.bundle.role != Role::Host
            || self.signed.bundle.account_id == [0; 16]
            || refresh_credential.is_empty()
            || refresh_credential.len() > 2048
            || !refresh_credential
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err("invalid host refresh signer or credential".into());
        }
        self.signed.verify(&self.signed.bundle.fingerprint()?)?;
        let statement = HostRefreshStatement {
            version: 1,
            account_id: self.signed.bundle.account_id,
            host_id: self.signed.bundle.subject_id,
            host_authorization_id,
            host_key_fingerprint: self.signed.bundle.fingerprint()?,
            rotation_id,
            refresh_hash: Sha256::digest(refresh_credential.as_bytes()).into(),
            audience: audience.to_owned(),
        };
        let canonical = statement.canonical()?;
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        Ok(EnrollmentProof {
            canonical_cbor: hex(&canonical)
                .try_into()
                .map_err(|_| "invalid refresh CBOR")?,
            signature: hex(&self.signing.sign(&canonical).to_bytes())
                .try_into()
                .map_err(|_| "invalid refresh signature")?,
        })
    }
}
