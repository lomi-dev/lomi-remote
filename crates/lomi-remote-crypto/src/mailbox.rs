use crate::{
    identity::verify_signature,
    random,
    wire::{self, Id},
    Identity, Result, Role, SignedBundle, MAX_MAILBOX_PAYLOAD,
};
use ed25519_dalek::Signer;
use hpke::{
    aead::ChaCha20Poly1305,
    kdf::HkdfSha256,
    kem::{Kem, X25519HkdfSha256},
    Deserializable, OpModeR, OpModeS, Serializable,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
const MAX_RETENTION: u64 = 7 * 24 * 60 * 60;
const MAX_SEEN: usize = 5000;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeMetadata {
    pub version: u32,
    pub account_id: Id,
    pub sender_host_id: Id,
    pub recipient_device_id: Id,
    pub recipient_key_version: u32,
    pub envelope_id: Id,
    pub grant_ref: Id,
    pub access_epoch: u64,
    pub grant_revision: u64,
    pub created_at: u64,
    pub expires_at: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub metadata: EnvelopeMetadata,
    pub enc: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxPolicy {
    pub account_id: Id,
    pub sender_host_id: Id,
    pub recipient_device_id: Id,
    pub grant_ref: Id,
    pub access_epoch: u64,
    pub grant_revision: u64,
    pub grant_deadline: u64,
}
impl EnvelopeMetadata {
    pub fn canonical(&self) -> Vec<u8> {
        let mut e = wire::encoder();
        wire::domain(&mut e, 13, "mailbox-metadata");
        wire::number(&mut e, u64::from(self.version));
        wire::bytes(&mut e, &self.account_id);
        wire::bytes(&mut e, &self.sender_host_id);
        wire::bytes(&mut e, &self.recipient_device_id);
        wire::number(&mut e, u64::from(self.recipient_key_version));
        wire::bytes(&mut e, &self.envelope_id);
        wire::bytes(&mut e, &self.grant_ref);
        wire::number(&mut e, self.access_epoch);
        wire::number(&mut e, self.grant_revision);
        wire::number(&mut e, self.created_at);
        wire::number(&mut e, self.expires_at);
        e.into_writer()
    }
    fn validate(&self, policy: &MailboxPolicy, now: u64) -> Result<()> {
        if self.version != 1
            || self.account_id != policy.account_id
            || self.sender_host_id != policy.sender_host_id
            || self.recipient_device_id != policy.recipient_device_id
            || self.grant_ref != policy.grant_ref
            || self.access_epoch != policy.access_epoch
            || self.grant_revision != policy.grant_revision
            || self.access_epoch == 0
            || self.grant_revision == 0
            || self.recipient_key_version == 0
            || self.created_at > now
            || self.expires_at <= now
            || self.expires_at <= self.created_at
            || self.expires_at > policy.grant_deadline
            || self.expires_at - self.created_at > MAX_RETENTION
        {
            return Err("mailbox policy/context/expiry mismatch".into());
        }
        Ok(())
    }
}
fn info(
    metadata: &EnvelopeMetadata,
    sender: &SignedBundle,
    recipient: &SignedBundle,
) -> Result<Vec<u8>> {
    let mut e = wire::encoder();
    wire::domain(&mut e, 5, "hpke-info");
    wire::bytes(&mut e, &metadata.canonical());
    wire::bytes(&mut e, &sender.bundle.fingerprint()?);
    wire::bytes(&mut e, &recipient.bundle.fingerprint()?);
    Ok(e.into_writer())
}
impl Envelope {
    pub fn canonical_unsigned(&self) -> Result<Vec<u8>> {
        if self.enc.len() != 32
            || self.ciphertext.len() < 16
            || self.ciphertext.len() > MAX_MAILBOX_PAYLOAD + 16
        {
            return Err("mailbox size limit".into());
        }
        let mut e = wire::encoder();
        wire::domain(&mut e, 5, "signed-envelope");
        wire::bytes(&mut e, &self.metadata.canonical());
        wire::bytes(&mut e, &self.enc);
        wire::bytes(&mut e, &self.ciphertext);
        Ok(e.into_writer())
    }
}
impl Identity {
    pub fn seal_mailbox(
        &self,
        recipient: &SignedBundle,
        pinned_recipient: &[u8; 32],
        policy: &MailboxPolicy,
        now: u64,
        expires_at: u64,
        payload: &[u8],
    ) -> Result<Envelope> {
        if payload.len() > MAX_MAILBOX_PAYLOAD {
            return Err("mailbox payload limit".into());
        }
        if self.disposed {
            return Err("identity disposed".into());
        }
        recipient.verify(pinned_recipient)?;
        let local = &self.signed.bundle;
        let target = &recipient.bundle;
        if local.role != Role::Host
            || target.role != Role::Device
            || local.account_id != policy.account_id
            || target.account_id != policy.account_id
            || local.subject_id != policy.sender_host_id
            || target.subject_id != policy.recipient_device_id
        {
            return Err("mailbox identities/policy mismatch".into());
        }
        let metadata = EnvelopeMetadata {
            version: 1,
            account_id: policy.account_id,
            sender_host_id: policy.sender_host_id,
            recipient_device_id: policy.recipient_device_id,
            recipient_key_version: target.key_version,
            envelope_id: random()?,
            grant_ref: policy.grant_ref,
            access_epoch: policy.access_epoch,
            grant_revision: policy.grant_revision,
            created_at: now,
            expires_at,
        };
        metadata.validate(policy, now)?;
        let public = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&target.mailbox_key)
            .map_err(|_| "invalid HPKE recipient")?;
        let (enc, ciphertext) =
            hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
                &OpModeS::Base,
                &public,
                &info(&metadata, &self.signed, recipient)?,
                payload,
                &metadata.canonical(),
            )
            .map_err(|_| "HPKE encryption failed")?;
        let mut envelope = Envelope {
            metadata,
            enc: enc.to_bytes().to_vec(),
            ciphertext,
            signature: vec![],
        };
        envelope.signature = self
            .signing
            .sign(&envelope.canonical_unsigned()?)
            .to_bytes()
            .to_vec();
        Ok(envelope)
    }
    pub fn open_mailbox(
        &mut self,
        envelope: &Envelope,
        sender: &SignedBundle,
        pinned_sender: &[u8; 32],
        policy: &MailboxPolicy,
        now: u64,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let canonical = envelope.canonical_unsigned()?;
        if now < self.last_now {
            return Err("clock moved backwards; revalidation required".into());
        }
        envelope.metadata.validate(policy, now)?;
        if self.disposed {
            return Err("identity disposed".into());
        }
        sender.verify(pinned_sender)?;
        let local = &self.signed.bundle;
        let host = &sender.bundle;
        if local.role != Role::Device
            || host.role != Role::Host
            || local.account_id != policy.account_id
            || host.account_id != policy.account_id
            || local.subject_id != policy.recipient_device_id
            || host.subject_id != policy.sender_host_id
            || envelope.metadata.recipient_key_version != local.key_version
        {
            return Err("mailbox sender/recipient mismatch".into());
        }
        verify_signature(&host.identity_key, &canonical, &envelope.signature)?;
        let replay_key = (
            envelope.metadata.sender_host_id,
            envelope.metadata.envelope_id,
        );
        if self.seen.contains_key(&replay_key) {
            return Err("mailbox replay rejected".into());
        }
        if self.seen.values().filter(|expiry| **expiry > now).count() >= MAX_SEEN {
            return Err("replay cache limit; refusing new envelopes".into());
        }
        let private = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&self.mailbox_secret)
            .map_err(|_| "invalid HPKE private key")?;
        let enc = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&envelope.enc)
            .map_err(|_| "invalid HPKE enc")?;
        let plaintext = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &private,
            &enc,
            &info(&envelope.metadata, sender, &self.signed)?,
            &envelope.ciphertext,
            &envelope.metadata.canonical(),
        )
        .map_err(|_| "HPKE authentication failed")?;
        // Cache pruning and its clock watermark commit only after authenticated
        // decryption, so failed envelopes cannot remove earlier replay fences.
        self.seen.retain(|_, expiry| *expiry > now);
        self.seen.insert(replay_key, envelope.metadata.expires_at);
        self.last_now = now;
        Ok(Zeroizing::new(plaintext))
    }
}

#[cfg(test)]
mod replay_tests {
    use super::*;
    #[test]
    fn signed_bad_hpke_cannot_prune_replay_cache_before_clock_rollback() {
        let host = Identity::generate([1; 16], [2; 16], Role::Host, 1).unwrap();
        let mut device = Identity::generate([1; 16], [3; 16], Role::Device, 1).unwrap();
        let sender = host.public_bundle();
        let recipient = device.public_bundle();
        let host_pin = sender.bundle.fingerprint().unwrap();
        let device_pin = recipient.bundle.fingerprint().unwrap();
        let policy = MailboxPolicy {
            account_id: [1; 16],
            sender_host_id: [2; 16],
            recipient_device_id: [3; 16],
            grant_ref: [4; 16],
            access_epoch: 1,
            grant_revision: 1,
            grant_deadline: 1000,
        };
        let old = host
            .seal_mailbox(&recipient, &device_pin, &policy, 0, 20, b"already received")
            .unwrap();
        device
            .open_mailbox(&old, &sender, &host_pin, &policy, 10)
            .unwrap();
        let mut invalid = host
            .seal_mailbox(&recipient, &device_pin, &policy, 25, 50, b"invalid HPKE")
            .unwrap();
        invalid.ciphertext[0] ^= 1;
        invalid.signature = host
            .signing
            .sign(&invalid.canonical_unsigned().unwrap())
            .to_bytes()
            .to_vec();
        assert!(device
            .open_mailbox(&invalid, &sender, &host_pin, &policy, 30)
            .unwrap_err()
            .contains("HPKE authentication"));
        assert_eq!(device.last_now, 10);
        assert_eq!(device.seen.len(), 1);
        assert!(device
            .open_mailbox(&old, &sender, &host_pin, &policy, 15)
            .unwrap_err()
            .contains("replay"));
        let next = host
            .seal_mailbox(
                &recipient,
                &device_pin,
                &policy,
                25,
                50,
                b"successful later event",
            )
            .unwrap();
        device
            .open_mailbox(&next, &sender, &host_pin, &policy, 30)
            .unwrap();
        assert_eq!(device.last_now, 30);
        assert_eq!(device.seen.len(), 1);
        assert!(device
            .open_mailbox(&old, &sender, &host_pin, &policy, 15)
            .unwrap_err()
            .contains("clock moved backwards"));
    }
}
