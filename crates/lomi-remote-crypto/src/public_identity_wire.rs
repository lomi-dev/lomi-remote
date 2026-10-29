//! Canonical public identities. A self-signature proves possession, not approval.
use crate::{
    identity::verify_signature, PublicBundle, Result, Role, SignedBundle, SignedHostKeyCommitment,
    PROFILE,
};
use lomi_remote_protocol::EnrollmentProof;

impl PublicBundle {
    /// Decode the historical encoder's exact representation, without changing
    /// its semantics (including account-zero pending host projections).
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        const MAX: usize = 1 + 1 + PROFILE.len() + 1 + 13 + 5 + 2 * 17 + 1 + 5 + 3 * 34;
        let invalid = "invalid canonical public bundle";
        if bytes.len() > MAX {
            return Err(invalid.into());
        }
        let mut d = minicbor::Decoder::new(bytes);
        if d.array().map_err(|_| invalid)? != Some(10)
            || d.str().map_err(|_| invalid)? != PROFILE
            || d.str().map_err(|_| invalid)? != "public-bundle"
        {
            return Err(invalid.into());
        }
        let version = d.u32().map_err(|_| invalid)?;
        let account_id = fixed(&mut d)?;
        let subject_id = fixed(&mut d)?;
        let role = match d.u8().map_err(|_| invalid)? {
            1 => Role::Host,
            2 => Role::Device,
            _ => return Err(invalid.into()),
        };
        let value = Self {
            version,
            account_id,
            subject_id,
            role,
            key_version: d.u32().map_err(|_| invalid)?,
            identity_key: fixed(&mut d)?,
            channel_key: fixed(&mut d)?,
            mailbox_key: fixed(&mut d)?,
        };
        if d.position() != bytes.len() || value.canonical()? != bytes {
            return Err(invalid.into());
        }
        Ok(value)
    }
}
pub(crate) fn fixed<const N: usize>(d: &mut minicbor::Decoder<'_>) -> Result<[u8; N]> {
    d.bytes()
        .map_err(|_| "invalid fixed canonical bytes")?
        .try_into()
        .map_err(|_| "invalid fixed canonical length".into())
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) fn wire(bytes: &[u8], signature: &[u8]) -> Result<EnrollmentProof> {
    Ok(EnrollmentProof {
        canonical_cbor: hex(bytes)
            .try_into()
            .map_err(|_| "invalid canonical wire bytes")?,
        signature: hex(signature)
            .try_into()
            .map_err(|_| "invalid canonical wire signature")?,
    })
}
impl SignedBundle {
    pub fn to_wire(&self) -> Result<EnrollmentProof> {
        self.verify(&self.bundle.fingerprint()?)?;
        wire(&self.bundle.canonical()?, &self.signature)
    }
    pub fn from_wire(value: &EnrollmentProof) -> Result<Self> {
        let bytes = crate::enrollment_wire::hex_bytes(value.canonical_cbor.expose_wire(), 256)?;
        let signed = Self {
            bundle: PublicBundle::from_canonical(&bytes)?,
            signature: crate::enrollment_wire::signature(value)?,
        };
        verify_signature(&signed.bundle.identity_key, &bytes, &signed.signature)?;
        Ok(signed)
    }
}
/// `approved_account_id` and `window_id` come from authenticated authority state.
pub fn verify_consumer_window_identity(
    value: &EnrollmentProof,
    approved_account_id: [u8; 16],
    window_id: [u8; 16],
) -> Result<SignedBundle> {
    let signed = SignedBundle::from_wire(value)?;
    let b = &signed.bundle;
    if approved_account_id == [0; 16]
        || window_id == [0; 16]
        || b.account_id != approved_account_id
        || b.subject_id != window_id
        || b.role != Role::Device
        || [b.identity_key, b.channel_key, b.mailbox_key].contains(&[0; 32])
    {
        return Err("consumer window identity context mismatch".into());
    }
    Ok(signed)
}
/// Verify the finalized account-bound self-signature against the independently
/// retained init commitment, deriving every public field inside Rust.
pub fn verify_registered_host_identity(
    committed: &SignedHostKeyCommitment,
    pin: &[u8; 32],
    approved_account_id: [u8; 16],
    value: &EnrollmentProof,
) -> Result<SignedBundle> {
    committed.verify(pin)?;
    let expected = committed
        .descriptor
        .account_bound_bundle(approved_account_id)?;
    let signed = SignedBundle::from_wire(value)?;
    if signed.bundle != expected {
        return Err("registered host identity context mismatch".into());
    }
    Ok(signed)
}
