//! V3-only browser admission. No caller-provided prologue or legacy fallback.
use crate::{
    browser::{decode, encode, error, fixed, BrowserChannel, BrowserIdentity},
    ChannelContextV3, CurrentAuthorityV3, Handshake, SignedBundle, SignedChannelAdmissionV3,
    SignedGrantV3, TerminalTargetV3,
};
use lomi_remote_protocol::DecimalU64;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "bigint")]
    pub type BrowserNow;
    #[wasm_bindgen(js_name = String)]
    fn decimal_string(value: &BrowserNow) -> String;
}
pub(crate) fn now_u64(now: &BrowserNow) -> Result<u64, JsValue> {
    let value: &JsValue = now.as_ref();
    if !value.is_bigint() {
        return Err(error("now requires a u64 BigInt"));
    }
    DecimalU64::try_from(decimal_string(now))
        .map(|n| n.0)
        .map_err(error)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdmissionInput {
    grant: SignedGrantV3,
    admission: SignedChannelAdmissionV3,
    host: SignedBundle,
    consumer: SignedBundle,
}
/// Boundary DTO only; canonical authority semantics remain in grant_v3.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthorityInput {
    host_authorization_id: [u8; 16],
    consumer_authorization_id: [u8; 16],
    account_session_id: String,
    access_epoch: DecimalU64,
    grant_revision: DecimalU64,
    workspace_epoch: [u8; 16],
    runtime_id: [u8; 16],
    runtime_generation: DecimalU64,
    terminal_membership: Option<TerminalTargetV3>,
}
impl From<AuthorityInput> for CurrentAuthorityV3 {
    fn from(v: AuthorityInput) -> Self {
        Self {
            host_authorization_id: v.host_authorization_id,
            consumer_authorization_id: v.consumer_authorization_id,
            account_session_id: v.account_session_id,
            access_epoch: v.access_epoch.0,
            grant_revision: v.grant_revision.0,
            workspace_epoch: v.workspace_epoch,
            runtime_id: v.runtime_id,
            runtime_generation: v.runtime_generation.0,
            terminal_membership: v.terminal_membership,
        }
    }
}
pub(crate) fn current_authority_json(json: &str) -> Result<CurrentAuthorityV3, JsValue> {
    Ok(decode::<AuthorityInput>(json)?.into())
}
#[wasm_bindgen]
pub struct BrowserHandshakeV3(Handshake);
#[wasm_bindgen]
impl BrowserHandshakeV3 {
    /// Expected context, current membership, endpoint pins and now are independent
    /// trusted inputs supplied by the caller's authority adapter. Never derive
    /// them from the signed JSON received over the channel.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        initiator: bool,
        identity: &BrowserIdentity,
        signed_json: &str,
        expected_json: &str,
        authority_json: &str,
        host_pin: &[u8],
        consumer_pin: &[u8],
        now: &BrowserNow,
    ) -> Result<Self, JsValue> {
        let now = now_u64(now)?;
        let signed: AdmissionInput = decode(signed_json)?;
        let expected = ChannelContextV3::from_json(expected_json).map_err(error)?;
        let current: CurrentAuthorityV3 = decode::<AuthorityInput>(authority_json)?.into();
        let host_pin = fixed(host_pin)?;
        let consumer_pin = fixed(consumer_pin)?;
        let verified = signed
            .admission
            .verify(
                &signed.grant,
                &expected,
                &signed.host,
                &host_pin,
                &signed.consumer,
                &consumer_pin,
                &current,
                now,
            )
            .map_err(error)?;
        let (peer, pin) = if initiator {
            (&signed.host, &host_pin)
        } else {
            (&signed.consumer, &consumer_pin)
        };
        Handshake::new_v3(initiator, &identity.0, verified, peer, pin, now)
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
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalArtifacts {
    grant_json: String,
    context_json: String,
    grant_cbor: Vec<u8>,
    context_cbor: Vec<u8>,
    grant_signature: Vec<u8>,
    context_signature: Vec<u8>,
}
/// Cross-runtime diagnostic over already verified admission, not a signing API.
#[wasm_bindgen]
pub fn verified_v3_artifacts(
    signed_json: &str,
    expected_json: &str,
    authority_json: &str,
    host_pin: &[u8],
    consumer_pin: &[u8],
    now: &BrowserNow,
) -> Result<String, JsValue> {
    let now = now_u64(now)?;
    let signed: AdmissionInput = decode(signed_json)?;
    let expected = ChannelContextV3::from_json(expected_json).map_err(error)?;
    let current = decode::<AuthorityInput>(authority_json)?.into();
    signed
        .admission
        .verify(
            &signed.grant,
            &expected,
            &signed.host,
            &fixed(host_pin)?,
            &signed.consumer,
            &fixed(consumer_pin)?,
            &current,
            now,
        )
        .map_err(error)?;
    encode(&CanonicalArtifacts {
        grant_json: encode(&expected.grant)?,
        context_json: encode(&expected)?,
        grant_cbor: expected.grant.canonical().map_err(error)?,
        context_cbor: expected.canonical().map_err(error)?,
        grant_signature: signed.grant.signature,
        context_signature: signed.admission.signature,
    })
}
#[wasm_bindgen]
pub fn remote_v3_production_qualified() -> bool {
    crate::REMOTE_V2_PRODUCTION_QUALIFIED
}
