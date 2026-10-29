//! Public-only authority adapters. Every trusted argument is independently stored
//! server state, never a projection of the submitted request.
use crate::{
    browser::{decode, encode, error, fixed},
    browser_v3::{current_authority_json, now_u64, BrowserNow},
    ChannelContextV3, GrantV3, SignedBundle, SignedChannelAdmissionV3, SignedGrantV3,
};
use lomi_remote_protocol::{EnrollmentProof, SignedChannelAdmissionWire, SignedGrantWire};
use serde::Serialize;
use wasm_bindgen::prelude::*;

fn identity(json: &str, pin: &[u8]) -> Result<SignedBundle, JsValue> {
    let wire: EnrollmentProof = decode(json)?;
    let identity = SignedBundle::from_wire(&wire).map_err(error)?;
    identity.verify(&fixed(pin)?).map_err(error)?;
    Ok(identity)
}
fn grant(json: &str) -> Result<SignedGrantV3, JsValue> {
    SignedGrantV3::from_wire(&decode::<SignedGrantWire>(json)?).map_err(error)
}
fn canonical(hex: &str) -> Result<Vec<u8>, JsValue> {
    crate::enrollment_wire::hex_bytes(hex, 8 * 1024).map_err(error)
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreparedGrant {
    grant: GrantV3,
    canonical_cbor: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifiedGrant {
    grant: GrantV3,
    signature: Vec<u8>,
    canonical_cbor: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreparedContext {
    context: ChannelContextV3,
    canonical_cbor: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifiedAdmission {
    admission: SignedChannelAdmissionV3,
    grant: SignedGrantV3,
    host: SignedBundle,
    consumer: SignedBundle,
}

/// Trusted grant is assembled from independently retained authority rows.
#[wasm_bindgen(js_name = prepare_grant_proposal_v3)]
pub fn prepare_grant_proposal_v3_json(
    trusted_grant_json: &str,
    host_wire_json: &str,
    consumer_wire_json: &str,
    approved_account: &[u8],
    host_pin: &[u8],
    consumer_pin: &[u8],
) -> Result<String, JsValue> {
    let grant = GrantV3::from_json(trusted_grant_json).map_err(error)?;
    let account = fixed::<16>(approved_account)?;
    if account == [0; 16] || grant.account_id != account {
        return Err(error("grant account mismatch"));
    }
    let host = identity(host_wire_json, host_pin)?;
    let consumer = identity(consumer_wire_json, consumer_pin)?;
    grant.bind(&host, &consumer).map_err(error)?;
    let canonical_cbor = crate::public_identity_wire::hex(&grant.canonical().map_err(error)?);
    encode(&PreparedGrant {
        grant,
        canonical_cbor,
    })
}

/// Maximum CBOR, endpoint pins and current authority are independent stored state.
#[wasm_bindgen(js_name = verify_grant_proposal_v3)]
#[allow(clippy::too_many_arguments)]
pub fn verify_grant_proposal_v3_json(
    submitted_wire_json: &str,
    maximum_cbor_hex: &str,
    host_wire_json: &str,
    consumer_wire_json: &str,
    host_pin: &[u8],
    consumer_pin: &[u8],
    authority_json: &str,
    now: &BrowserNow,
) -> Result<String, JsValue> {
    let now = now_u64(now)?;
    let submitted = grant(submitted_wire_json)?;
    let maximum = GrantV3::from_canonical(&canonical(maximum_cbor_hex)?).map_err(error)?;
    let host = identity(host_wire_json, host_pin)?;
    let consumer = identity(consumer_wire_json, consumer_pin)?;
    let current = current_authority_json(authority_json)?;
    let grant = crate::verify_grant_proposal_v3(
        &maximum,
        &submitted,
        &host,
        &fixed(host_pin)?,
        &consumer,
        &fixed(consumer_pin)?,
        &current,
        now,
    )
    .map_err(error)?;
    let canonical_cbor = crate::public_identity_wire::hex(&grant.canonical().map_err(error)?);
    encode(&VerifiedGrant {
        grant,
        signature: submitted.signature,
        canonical_cbor,
    })
}

/// Context is assembled from a saved server row; grant is the stored approval.
#[wasm_bindgen(js_name = prepare_channel_context_v3)]
#[allow(clippy::too_many_arguments)]
pub fn prepare_channel_context_v3_json(
    trusted_context_json: &str,
    stored_grant_wire_json: &str,
    host_wire_json: &str,
    consumer_wire_json: &str,
    host_pin: &[u8],
    consumer_pin: &[u8],
    authority_json: &str,
    now: &BrowserNow,
) -> Result<String, JsValue> {
    let now = now_u64(now)?;
    let context = ChannelContextV3::from_json(trusted_context_json).map_err(error)?;
    let grant = grant(stored_grant_wire_json)?;
    let host = identity(host_wire_json, host_pin)?;
    let consumer = identity(consumer_wire_json, consumer_pin)?;
    let current = current_authority_json(authority_json)?;
    if current.terminal_membership != context.terminal
        || now < context.issued_at
        || now >= context.expires_at
    {
        return Err(error("channel context mismatch or expiry"));
    }
    grant
        .verify(
            &context.grant,
            &host,
            &fixed(host_pin)?,
            &consumer,
            &fixed(consumer_pin)?,
            &current,
            now,
        )
        .map_err(error)?;
    let canonical_cbor = crate::public_identity_wire::hex(&context.canonical().map_err(error)?);
    encode(&PreparedContext {
        context,
        canonical_cbor,
    })
}

/// Expected CBOR, stored approval, pins and current authority are independent state.
/// Result is the verified AdmissionInput JSON accepted by BrowserHandshakeV3.
#[wasm_bindgen(js_name = verify_channel_admission_v3)]
#[allow(clippy::too_many_arguments)]
pub fn verify_channel_admission_v3_json(
    submitted_wire_json: &str,
    expected_cbor_hex: &str,
    stored_grant_wire_json: &str,
    host_wire_json: &str,
    consumer_wire_json: &str,
    host_pin: &[u8],
    consumer_pin: &[u8],
    authority_json: &str,
    now: &BrowserNow,
) -> Result<String, JsValue> {
    let now = now_u64(now)?;
    let admission = SignedChannelAdmissionV3::from_wire(&decode::<SignedChannelAdmissionWire>(
        submitted_wire_json,
    )?)
    .map_err(error)?;
    let expected =
        ChannelContextV3::from_canonical(&canonical(expected_cbor_hex)?).map_err(error)?;
    let grant = grant(stored_grant_wire_json)?;
    let host = identity(host_wire_json, host_pin)?;
    let consumer = identity(consumer_wire_json, consumer_pin)?;
    let current = current_authority_json(authority_json)?;
    admission
        .verify(
            &grant,
            &expected,
            &host,
            &fixed(host_pin)?,
            &consumer,
            &fixed(consumer_pin)?,
            &current,
            now,
        )
        .map_err(error)?;
    encode(&VerifiedAdmission {
        admission,
        grant,
        host,
        consumer,
    })
}
