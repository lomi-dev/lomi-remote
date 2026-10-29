//! Commit host keys before the approved account is known, then bind them once.
use crate::{identity::verify_signature, Identity, PublicBundle, Result, Role};
use ed25519_dalek::{Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(not(target_arch = "wasm32"))]
use zeroize::Zeroizing;

pub const HOST_KEY_COMMITMENT_DOMAIN: &str = "lomi-remote-host-key-commitment-v1";

/// Account-independent public keys. The trusted server must retain this exact
/// descriptor at init, before account approval; request replacements are invalid.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountIndependentHostKey {
    pub version: u8,
    pub host_id: [u8; 16],
    pub role: Role,
    pub key_version: u32,
    pub identity_key: [u8; 32],
    pub channel_key: [u8; 32],
    pub mailbox_key: [u8; 32],
}
impl AccountIndependentHostKey {
    pub fn canonical(&self) -> Result<Vec<u8>> {
        let key = VerifyingKey::from_bytes(&self.identity_key)
            .map_err(|_| "invalid host commitment signing key")?;
        if self.version != 1
            || self.host_id == [0; 16]
            || self.role != Role::Host
            || self.key_version == 0
            || key.is_weak()
            || [self.identity_key, self.channel_key, self.mailbox_key].contains(&[0; 32])
        {
            return Err("invalid account-independent host key".into());
        }
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(8).unwrap();
        e.str(HOST_KEY_COMMITMENT_DOMAIN).unwrap();
        e.u8(self.version).unwrap();
        e.bytes(&self.host_id).unwrap();
        e.u8(1).unwrap();
        e.u32(self.key_version).unwrap();
        for bytes in [self.identity_key, self.channel_key, self.mailbox_key] {
            e.bytes(&bytes).unwrap();
        }
        Ok(e.into_writer())
    }
    /// Decode only the bounded, exact canonical commitment representation.
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        // Array, domain, version, UUID, role, u32 and three 32-byte keys.
        const MAX_CBOR: usize = 1 + 2 + HOST_KEY_COMMITMENT_DOMAIN.len() + 1 + 17 + 1 + 5 + 3 * 34;
        let invalid = "invalid canonical host key commitment";
        if bytes.len() > MAX_CBOR {
            return Err(invalid.into());
        }
        let mut d = minicbor::Decoder::new(bytes);
        if d.array().map_err(|_| invalid)? != Some(8)
            || d.str().map_err(|_| invalid)? != HOST_KEY_COMMITMENT_DOMAIN
        {
            return Err(invalid.into());
        }
        let version = d.u8().map_err(|_| invalid)?;
        let host_id = d
            .bytes()
            .map_err(|_| invalid)?
            .try_into()
            .map_err(|_| invalid)?;
        if d.u8().map_err(|_| invalid)? != 1 {
            return Err(invalid.into());
        }
        let value = Self {
            version,
            host_id,
            role: Role::Host,
            key_version: d.u32().map_err(|_| invalid)?,
            identity_key: d
                .bytes()
                .map_err(|_| invalid)?
                .try_into()
                .map_err(|_| invalid)?,
            channel_key: d
                .bytes()
                .map_err(|_| invalid)?
                .try_into()
                .map_err(|_| invalid)?,
            mailbox_key: d
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
    pub fn commitment(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.canonical()?).into())
    }
    /// Derive, do not accept from an approval/exchange request. This is an unsigned
    /// public bundle projection, not an authenticated host or proof of approval.
    pub fn account_bound_bundle(&self, approved_account_id: [u8; 16]) -> Result<PublicBundle> {
        self.canonical()?;
        if approved_account_id == [0; 16] {
            return Err("approved account must be nonzero".into());
        }
        Ok(self.bundle(approved_account_id))
    }
    fn bundle(&self, account_id: [u8; 16]) -> PublicBundle {
        PublicBundle {
            version: 1,
            account_id,
            subject_id: self.host_id,
            role: Role::Host,
            key_version: self.key_version,
            identity_key: self.identity_key,
            channel_key: self.channel_key,
            mailbox_key: self.mailbox_key,
        }
    }
    pub fn from_json(json: &str) -> Result<Self> {
        let value: Self = parse(json)?;
        value.canonical()?;
        Ok(value)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedHostKeyCommitment {
    pub descriptor: AccountIndependentHostKey,
    pub signature: Vec<u8>,
}
impl SignedHostKeyCommitment {
    /// `expected_commitment` must be the independently retained init commitment.
    /// Self-signature verification alone does not approve an account/enrollment.
    pub fn verify(&self, expected_commitment: &[u8; 32]) -> Result<()> {
        if self.descriptor.commitment()? != *expected_commitment {
            return Err("host key init commitment mismatch".into());
        }
        verify_signature(
            &self.descriptor.identity_key,
            &self.descriptor.canonical()?,
            &self.signature,
        )
    }
    pub fn from_json(json: &str) -> Result<Self> {
        let value: Self = parse(json)?;
        value.descriptor.canonical()?;
        Ok(value)
    }
}

/// A pending host exposes neither an ordinary bundle nor an `Identity` reference.
/// Only consuming finalization produces an account-bound identity.
///
/// ```compile_fail
/// use lomi_remote_crypto::{PendingHostIdentity, Identity};
/// fn expose(pending: &PendingHostIdentity) -> &Identity { &pending.identity }
/// ```
/// ```compile_fail
/// use lomi_remote_crypto::Identity;
/// fn rebind(identity: Identity) { identity.finalize([1;16], &[2;32]); }
/// ```
pub struct PendingHostIdentity {
    identity: Identity,
}
impl PendingHostIdentity {
    pub fn generate(host_id: [u8; 16], key_version: u32) -> Result<Self> {
        if host_id == [0; 16] || key_version == 0 {
            return Err("invalid pending host identity".into());
        }
        let pending = Self {
            identity: Identity::generate([0; 16], host_id, Role::Host, key_version)?,
        };
        pending.check_pending()?;
        Ok(pending)
    }
    fn check_pending(&self) -> Result<()> {
        let b = &self.identity.signed.bundle;
        if self.identity.disposed || b.account_id != [0; 16] || b.role != Role::Host {
            return Err("pending host disposed or already account bound".into());
        }
        self.descriptor().canonical()?;
        Ok(())
    }
    fn descriptor(&self) -> AccountIndependentHostKey {
        let b = &self.identity.signed.bundle;
        AccountIndependentHostKey {
            version: 1,
            host_id: b.subject_id,
            role: b.role,
            key_version: b.key_version,
            identity_key: b.identity_key,
            channel_key: b.channel_key,
            mailbox_key: b.mailbox_key,
        }
    }
    pub fn signed_commitment(&self) -> Result<SignedHostKeyCommitment> {
        self.check_pending()?;
        let descriptor = self.descriptor();
        let signature = self
            .identity
            .signing
            .sign(&descriptor.canonical()?)
            .to_bytes()
            .to_vec();
        Ok(SignedHostKeyCommitment {
            descriptor,
            signature,
        })
    }
    /// Caller must authenticate authority approval and its account/commitment over
    /// TLS before calling. On any failure self is dropped and secrets are disposed.
    pub fn finalize(
        mut self,
        approved_account_id: [u8; 16],
        expected_commitment: &[u8; 32],
    ) -> Result<Identity> {
        self.check_pending()?;
        let signed = self.signed_commitment()?;
        signed.verify(expected_commitment)?;
        let bound = signed
            .descriptor
            .account_bound_bundle(approved_account_id)?;
        let signature = self
            .identity
            .signing
            .sign(&bound.canonical()?)
            .to_bytes()
            .to_vec();
        self.identity.signed = crate::SignedBundle {
            bundle: bound,
            signature,
        };
        Ok(self.identity)
    }
    pub fn dispose(&mut self) {
        self.identity.dispose();
    }
    /// Same bounded native version-1 97-byte seed format as existing Identity.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn export_secret_seed_blob(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.check_pending()?;
        self.identity.export_secret_seed_blob()
    }
    /// Expected public descriptor and commitment must come from the retained init
    /// record, not be substituted by the stored seed blob or an exchange request.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn import_secret_seed_blob(
        blob: &[u8],
        expected: &SignedHostKeyCommitment,
        pin: &[u8; 32],
    ) -> Result<Self> {
        expected.verify(pin)?;
        let identity = Identity::pending_host_from_seed_blob(
            blob,
            expected.descriptor.host_id,
            expected.descriptor.key_version,
        )?;
        let pending = Self { identity };
        pending.check_pending()?;
        if pending.signed_commitment()? != *expected {
            return Err("persisted pending host key mismatch".into());
        }
        Ok(pending)
    }

}
fn parse<T: serde::de::DeserializeOwned>(json: &str) -> Result<T> {
    if json.len() > crate::MAX_JSON {
        return Err("host key JSON limit".into());
    }
    serde_json::from_str(json).map_err(|_| "invalid host key JSON".into())
}

impl crate::SignedEnrollmentProof {
    /// Verify final PoP using only the immutable init descriptor and the account
    /// approved by authority. No request-supplied replacement bundle is accepted.
    pub fn verify_committed_host(
        &self,
        expected: &crate::EnrollmentChallenge,
        committed: &SignedHostKeyCommitment,
        initial_commitment: &[u8; 32],
        approved_account_id: [u8; 16],
        now: u64,
    ) -> Result<()> {
        committed.verify(initial_commitment)?;
        let host = committed
            .descriptor
            .account_bound_bundle(approved_account_id)?;
        if self.challenge != *expected
            || now >= expected.expires_at
            || expected.host_id != host.subject_id
            || expected.host_key_fingerprint != host.fingerprint()?
        {
            return Err("committed enrollment trusted context mismatch or expiry".into());
        }
        verify_signature(&host.identity_key, &expected.canonical()?, &self.signature)
    }
}
