use crate::{identity::verify_signature, wire, Identity, Result, Role, SignedBundle};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Permissions {
    Observe,
    Control,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerApproval {
    pub version: u32,
    pub account_id: [u8; 16],
    pub host_id: [u8; 16],
    pub device_id: [u8; 16],
    pub host_fingerprint: [u8; 32],
    pub device_fingerprint: [u8; 32],
    pub pairing_nonce: [u8; 32],
    pub grant_id: [u8; 16],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<[u8; 16]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_epoch: Option<[u8; 16]>,
    pub session_ids: Vec<[u8; 16]>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub session_epochs: Vec<[u8; 16]>,
    pub permissions: Permissions,
    pub access_epoch: u64,
    pub revision: u64,
    pub expires_at: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedPeerApproval {
    pub approval: PeerApproval,
    pub signature: Vec<u8>,
}
impl PeerApproval {
    pub fn canonical(&self) -> Result<Vec<u8>> {
        if !matches!(self.version, 1 | 2)
            || self.access_epoch == 0
            || self.revision == 0
            || self.expires_at == 0
        {
            return Err("unsupported peer approval".into());
        }
        if (self.version == 1
            && (self.workspace_id.is_some()
                || self.workspace_epoch.is_some()
                || !self.session_epochs.is_empty()))
            || (self.version == 2
                && (self.workspace_id.is_none()
                    || self.workspace_epoch.is_none()
                    || self.session_epochs.len() != self.session_ids.len()))
        {
            return Err("invalid approval workspace scope".into());
        }
        if (self.version == 1 && self.session_ids.is_empty())
            || self.session_ids.len() > 32
            || self
                .session_ids
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.session_ids.len()
        {
            return Err("invalid approval sessions".into());
        }
        let mut e = wire::encoder();
        wire::domain(
            &mut e,
            if self.version == 1 { 15 } else { 18 },
            "peer-approval",
        );
        wire::number(&mut e, u64::from(self.version));
        for bytes in [
            &self.account_id[..],
            &self.host_id,
            &self.device_id,
            &self.host_fingerprint,
            &self.device_fingerprint,
            &self.pairing_nonce,
            &self.grant_id,
        ] {
            wire::bytes(&mut e, bytes);
        }
        if self.version == 2 {
            wire::bytes(&mut e, &self.workspace_id.unwrap());
            wire::bytes(&mut e, &self.workspace_epoch.unwrap());
        }
        e.array(self.session_ids.len() as u64).unwrap();
        for id in &self.session_ids {
            wire::bytes(&mut e, id);
        }
        if self.version == 2 {
            e.array(self.session_epochs.len() as u64).unwrap();
            for epoch in &self.session_epochs {
                wire::bytes(&mut e, epoch);
            }
        }
        wire::number(
            &mut e,
            match self.permissions {
                Permissions::Observe => 1,
                Permissions::Control => 2,
            },
        );
        wire::number(&mut e, self.access_epoch);
        wire::number(&mut e, self.revision);
        wire::number(&mut e, self.expires_at);
        Ok(e.into_writer())
    }
}
impl Identity {
    pub fn sign_peer_approval(&self, approval: PeerApproval) -> Result<SignedPeerApproval> {
        let b = &self.signed.bundle;
        if self.disposed
            || b.role != Role::Host
            || approval.account_id != b.account_id
            || approval.host_id != b.subject_id
            || approval.host_fingerprint != b.fingerprint()?
        {
            return Err("peer approval signing context mismatch".into());
        }
        let signature = self
            .signing
            .sign(&approval.canonical()?)
            .to_bytes()
            .to_vec();
        Ok(SignedPeerApproval {
            approval,
            signature,
        })
    }
}
impl SignedPeerApproval {
    /// `expected` must come from trusted pairing/grant state, never from this signed input.
    pub fn verify(
        &self,
        host: &SignedBundle,
        pin: &[u8; 32],
        expected: &PeerApproval,
        now: u64,
        current_epoch: u64,
    ) -> Result<()> {
        host.verify(pin)?;
        let a = &self.approval;
        let b = &host.bundle;
        if a != expected
            || a.expires_at <= now
            || a.access_epoch != current_epoch
            || b.role != Role::Host
            || a.account_id != b.account_id
            || a.host_id != b.subject_id
            || a.host_fingerprint != *pin
        {
            return Err("peer approval trusted context mismatch".into());
        }
        verify_signature(&b.identity_key, &a.canonical()?, &self.signature)
    }
}

/// Full digest of the public pairing context; callers display the entire hexadecimal digest.
pub fn pairing_fingerprint(
    account_id: &[u8; 16],
    host_id: &[u8; 16],
    device_id: &[u8; 16],
    host_fingerprint: &[u8; 32],
    device_fingerprint: &[u8; 32],
    pairing_nonce: &[u8; 32],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"lomi-remote-pairing-v1\0");
    for bytes in [
        &account_id[..],
        host_id,
        device_id,
        host_fingerprint,
        device_fingerprint,
        pairing_nonce,
    ] {
        hash.update(bytes);
    }
    hash.finalize().into()
}
