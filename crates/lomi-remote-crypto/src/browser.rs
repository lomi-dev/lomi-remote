//! Historical live/mailbox browser exports. New Remote callers use BrowserHandshakeV3.
use crate::{
    Channel, ChannelContext, Envelope, Handshake, Identity, MAX_JSON, MailboxPolicy, Role,
    SignedBundle, TransportFrame,
};
use serde::{Serialize, de::DeserializeOwned};
use wasm_bindgen::prelude::*;
pub(crate) fn error(message: impl AsRef<str>) -> JsValue {
    JsValue::from_str(message.as_ref())
}
pub(crate) fn decode<T: DeserializeOwned>(json: &str) -> Result<T, JsValue> {
    if json.len() > MAX_JSON {
        return Err(error("JSON size limit"));
    }
    serde_json::from_str(json).map_err(|_| error("invalid JSON input"))
}
pub(crate) fn encode<T: Serialize>(value: &T) -> Result<String, JsValue> {
    let json = serde_json::to_string(value).map_err(|_| error("JSON encoding failed"))?;
    if json.len() > MAX_JSON {
        return Err(error("JSON reply limit"));
    }
    Ok(json)
}
pub(crate) fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], JsValue> {
    bytes
        .try_into()
        .map_err(|_| error("wrong byte array length"))
}
fn role(host: bool) -> Role {
    if host { Role::Host } else { Role::Device }
}
/// Rust-held identity with a one-time seed-blob bridge for immediate WebCrypto
/// encryption. JavaScript copies remain outside Rust zeroization guarantees.
#[wasm_bindgen]
pub struct BrowserIdentity(pub(crate) Identity);
#[wasm_bindgen]
impl BrowserIdentity {
    #[wasm_bindgen(constructor)]
    pub fn new(
        account_id: &[u8],
        subject_id: &[u8],
        host: bool,
        key_version: u32,
    ) -> Result<BrowserIdentity, JsValue> {
        Identity::generate(
            fixed(account_id)?,
            fixed(subject_id)?,
            role(host),
            key_version,
        )
        .map(Self)
        .map_err(error)
    }
    /// Restore only from a browser-decrypted seed blob and an exact public
    /// bundle previously persisted beside it. The requested scope is checked
    /// in Rust before the keys are reconstructed.
    #[wasm_bindgen(js_name = restore)]
    pub fn restore(
        account_id: &[u8],
        subject_id: &[u8],
        seed_blob: &[u8],
        expected_bundle_json: &str,
    ) -> Result<BrowserIdentity, JsValue> {
        let account_id = fixed(account_id)?;
        let subject_id = fixed(subject_id)?;
        let expected: SignedBundle = decode(expected_bundle_json)?;
        if expected.bundle.account_id != account_id
            || expected.bundle.subject_id != subject_id
            || expected.bundle.role != Role::Device
            || expected.bundle.key_version != 1
        {
            return Err(error("persisted identity scope mismatch"));
        }
        Identity::import_secret_seed_blob(seed_blob, &expected)
            .map(Self)
            .map_err(error)
    }
    pub fn dispose(&mut self) {
        self.0.dispose();
    }
    pub fn public_bundle(&self) -> Result<String, JsValue> {
        encode(&self.0.public_bundle())
    }
    /// Returns the seed blob once so the caller can encrypt it with WebCrypto.
    /// Callers must zero the returned JavaScript buffer immediately.
    pub fn seed_blob_for_encryption(&self) -> Result<Vec<u8>, JsValue> {
        self.0
            .export_secret_seed_blob()
            .map(|blob| blob.to_vec())
            .map_err(error)
    }
    /// Bounded public EnrollmentProof carrier; contains no secret key material.
    pub fn public_identity_wire(&self) -> Result<String, JsValue> {
        encode(&self.0.public_bundle().to_wire().map_err(error)?)
    }
    /// Sign only an exact native-decoded canonical window challenge. Identity
    /// binding and disposal checks remain in the native signer.
    pub fn sign_consumer_window_proof(&self, canonical_cbor: &[u8]) -> Result<String, JsValue> {
        let challenge =
            crate::ConsumerWindowChallenge::from_canonical(canonical_cbor).map_err(error)?;
        encode(
            &self
                .0
                .sign_consumer_window_proof(&challenge)
                .map_err(error)?,
        )
    }
    pub fn fingerprint(&self) -> Result<Vec<u8>, JsValue> {
        self.0
            .public_bundle()
            .bundle
            .fingerprint()
            .map(|p| p.to_vec())
            .map_err(error)
    }
    pub fn sign_consumer_window_proof_bound(
        &self,
        canonical_cbor: &[u8],
        expected_json: &str,
        now: u64,
    ) -> Result<String, JsValue> {
        let challenge =
            crate::ConsumerWindowChallenge::from_canonical(canonical_cbor).map_err(error)?;
        let expected: crate::ConsumerWindowProofBinding = decode(expected_json)?;
        encode(
            &self
                .0
                .sign_consumer_window_proof_bound(&challenge, &expected, now)
                .map_err(error)?,
        )
    }
    pub fn seal_mailbox(
        &self,
        recipient_json: &str,
        pinned_recipient: &[u8],
        policy_json: &str,
        now: u64,
        expires_at: u64,
        payload: &[u8],
    ) -> Result<String, JsValue> {
        let recipient: SignedBundle = decode(recipient_json)?;
        let policy: MailboxPolicy = decode(policy_json)?;
        encode(
            &self
                .0
                .seal_mailbox(
                    &recipient,
                    &fixed(pinned_recipient)?,
                    &policy,
                    now,
                    expires_at,
                    payload,
                )
                .map_err(error)?,
        )
    }
    pub fn open_mailbox(
        &mut self,
        envelope_json: &str,
        sender_json: &str,
        pinned_sender: &[u8],
        policy_json: &str,
        now: u64,
    ) -> Result<Vec<u8>, JsValue> {
        let envelope: Envelope = decode(envelope_json)?;
        let sender: SignedBundle = decode(sender_json)?;
        let policy: MailboxPolicy = decode(policy_json)?;
        self.0
            .open_mailbox(&envelope, &sender, &fixed(pinned_sender)?, &policy, now)
            .map(|p| p.to_vec())
            .map_err(error)
    }

}
#[wasm_bindgen]
pub struct BrowserHandshake(Handshake);
#[wasm_bindgen]
impl BrowserHandshake {
    #[wasm_bindgen(constructor)]
    pub fn new(
        initiator: bool,
        identity: &BrowserIdentity,
        context_json: &str,
        peer_json: &str,
        pinned_peer: &[u8],
    ) -> Result<BrowserHandshake, JsValue> {
        let context: ChannelContext = decode(context_json)?;
        let peer: SignedBundle = decode(peer_json)?;
        Handshake::new(
            initiator,
            &identity.0,
            &context,
            &peer,
            &fixed(pinned_peer)?,
        )
        .map(Self)
        .map_err(error)
    }
    pub fn dispose(&mut self) {
        self.0.dispose();
    }
    pub fn write(&mut self) -> Result<Vec<u8>, JsValue> {
        self.0.write().map_err(error)
    }
    pub fn read(&mut self, message: &[u8]) -> Result<(), JsValue> {
        self.0.read(message).map_err(error)
    }
    pub fn finish(self) -> Result<BrowserChannel, JsValue> {
        self.0.finish().map(BrowserChannel).map_err(error)
    }
}
#[wasm_bindgen]
pub struct BrowserChannel(pub(crate) Channel);
#[wasm_bindgen]
impl BrowserChannel {
    pub fn dispose(&mut self) {
        self.0.dispose();
    }
    pub fn seal_binary(&mut self, routing: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.0
            .seal_binary(fixed(routing)?, plaintext)
            .map_err(error)
    }
    pub fn open_binary(&mut self, routing: &[u8], frame: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.0
            .open_binary(fixed(routing)?, frame)
            .map(|p| p.to_vec())
            .map_err(error)
    }
    pub fn seal(&mut self, routing: &[u8], plaintext: &[u8]) -> Result<String, JsValue> {
        encode(&self.0.seal(fixed(routing)?, plaintext).map_err(error)?)
    }
    pub fn open(&mut self, routing: &[u8], frame_json: &str) -> Result<Vec<u8>, JsValue> {
        let frame: TransportFrame = decode(frame_json)?;
        self.0
            .open(fixed(routing)?, &frame)
            .map(|p| p.to_vec())
            .map_err(error)
    }
    pub fn transcript_hash(&self) -> Vec<u8> {
        self.0.transcript_hash.to_vec()
    }
}
#[wasm_bindgen]
pub fn verify_public_bundle(bundle_json: &str, pin: &[u8]) -> Result<(), JsValue> {
    decode::<SignedBundle>(bundle_json)?
        .verify(&fixed(pin)?)
        .map_err(error)
}
#[wasm_bindgen]
pub fn production_qualified() -> bool {
    crate::PRODUCTION_QUALIFIED
}

#[wasm_bindgen]
pub fn verify_peer_approval(
    approval_json: &str,
    host_json: &str,
    pin: &[u8],
    expected_json: &str,
    now: u64,
    current_epoch: u64,
) -> Result<(), JsValue> {
    let approval: crate::SignedPeerApproval = decode(approval_json)?;
    let host: SignedBundle = decode(host_json)?;
    let expected: crate::PeerApproval = decode(expected_json)?;
    approval
        .verify(&host, &fixed(pin)?, &expected, now, current_epoch)
        .map_err(error)
}
#[wasm_bindgen]
pub fn live_production_qualified() -> bool {
    crate::LIVE_PRODUCTION_QUALIFIED
}

#[wasm_bindgen]
pub fn pairing_fingerprint(
    account_id: &[u8],
    host_id: &[u8],
    device_id: &[u8],
    host_fingerprint: &[u8],
    device_fingerprint: &[u8],
    pairing_nonce: &[u8],
) -> Result<String, JsValue> {
    let digest = crate::pairing_fingerprint(
        &fixed(account_id)?,
        &fixed(host_id)?,
        &fixed(device_id)?,
        &fixed(host_fingerprint)?,
        &fixed(device_fingerprint)?,
        &fixed(pairing_nonce)?,
    );
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// The approval must first be verified against trusted host and grant state.
#[wasm_bindgen]
pub fn validate_channel_approval(context_json: &str, approval_json: &str) -> Result<(), JsValue> {
    let context: ChannelContext = decode(context_json)?;
    let approval: crate::PeerApproval = decode(approval_json)?;
    context.validate_approval(&approval).map_err(error)
}
