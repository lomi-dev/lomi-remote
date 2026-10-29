//! Bounded canonical v3 carriers and independently retained proposal binding.
use crate::{
    public_identity_wire::{fixed, hex},
    ChannelContextV3, ChannelPurposeV3, CurrentAuthorityV3, GrantPurposeV3, GrantV3, Result, Role,
    SignedBundle, SignedChannelAdmissionV3, SignedGrantV3, TerminalTargetV3, CONTEXT_V3_DOMAIN,
    GRANT_V3_DOMAIN,
};
use lomi_remote_protocol::{
    Capability, CapabilitySet, SignedChannelAdmissionWire, SignedGrantWire,
};

const MAX_CANONICAL: usize = 8 * 1024;
const INVALID: &str = "invalid canonical grant/context 3";

impl GrantV3 {
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CANONICAL {
            return Err(INVALID.into());
        }
        let mut d = minicbor::Decoder::new(bytes);
        if d.array().map_err(|_| INVALID)? != Some(23)
            || d.str().map_err(|_| INVALID)? != GRANT_V3_DOMAIN
        {
            return Err(INVALID.into());
        }
        let value = Self {
            version: d.u8().map_err(|_| INVALID)?,
            api_major: d.u8().map_err(|_| INVALID)?,
            application_major: d.u8().map_err(|_| INVALID)?,
            account_id: fixed(&mut d)?,
            host_id: fixed(&mut d)?,
            host_fingerprint: fixed(&mut d)?,
            host_authorization_id: fixed(&mut d)?,
            access_epoch: d.u64().map_err(|_| INVALID)?,
            consumer_authorization_id: fixed(&mut d)?,
            account_session_id: bounded_text(&mut d, 128)?,
            consumer_id: fixed(&mut d)?,
            consumer_fingerprint: fixed(&mut d)?,
            grant_id: fixed(&mut d)?,
            grant_revision: d.u64().map_err(|_| INVALID)?,
            workspace_id: fixed(&mut d)?,
            workspace_epoch: fixed(&mut d)?,
            runtime_id: fixed(&mut d)?,
            runtime_generation: d.u64().map_err(|_| INVALID)?,
            capabilities: capabilities(&mut d)?,
            nonce: fixed(&mut d)?,
            expires_at: d.u64().map_err(|_| INVALID)?,
            purpose: match d.str().map_err(|_| INVALID)? {
                "workspace" => GrantPurposeV3::Workspace,
                _ => return Err(INVALID.into()),
            },
        };
        if d.position() != bytes.len() || value.canonical()? != bytes {
            return Err(INVALID.into());
        }
        Ok(value)
    }
}
fn bounded_text(d: &mut minicbor::Decoder<'_>, max: usize) -> Result<String> {
    let text = d.str().map_err(|_| INVALID)?;
    if text.len() > max {
        return Err(INVALID.into());
    }
    Ok(text.to_owned())
}
fn capabilities(d: &mut minicbor::Decoder<'_>) -> Result<CapabilitySet> {
    let count = d.array().map_err(|_| INVALID)?.ok_or(INVALID)?;
    if count > Capability::ALL.len() as u64 {
        return Err(INVALID.into());
    }
    let mut values = Vec::with_capacity(count as usize);
    let mut previous = None;
    for _ in 0..count {
        let name = d.str().map_err(|_| INVALID)?;
        if previous.is_some_and(|p| p >= name) {
            return Err(INVALID.into());
        }
        let cap = Capability::ALL
            .into_iter()
            .find(|c| {
                serde_json::to_value(c)
                    .ok()
                    .and_then(|v| v.as_str().map(|s| s == name))
                    == Some(true)
            })
            .ok_or(INVALID)?;
        values.push(cap);
        previous = Some(name);
    }
    CapabilitySet::try_from(values).map_err(str::to_owned)
}
impl ChannelContextV3 {
    pub fn from_canonical(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CANONICAL {
            return Err(INVALID.into());
        }
        let mut d = minicbor::Decoder::new(bytes);
        if d.array().map_err(|_| INVALID)? != Some(10)
            || d.str().map_err(|_| INVALID)? != CONTEXT_V3_DOMAIN
        {
            return Err(INVALID.into());
        }
        let version = d.u8().map_err(|_| INVALID)?;
        let grant = GrantV3::from_canonical(d.bytes().map_err(|_| INVALID)?)?;
        let channel_id = fixed(&mut d)?;
        if d.str().map_err(|_| INVALID)? != "device" || d.str().map_err(|_| INVALID)? != "host" {
            return Err(INVALID.into());
        }
        let purpose = match d.str().map_err(|_| INVALID)? {
            "workspace" => ChannelPurposeV3::Workspace,
            "terminal" => ChannelPurposeV3::Terminal,
            _ => return Err(INVALID.into()),
        };
        let terminal = if d.datatype().map_err(|_| INVALID)? == minicbor::data::Type::Null {
            d.null().map_err(|_| INVALID)?;
            None
        } else {
            if d.array().map_err(|_| INVALID)? != Some(4) {
                return Err(INVALID.into());
            }
            Some(TerminalTargetV3 {
                pane_id: fixed(&mut d)?,
                session_id: fixed(&mut d)?,
                session_epoch: fixed(&mut d)?,
                terminal_profile: bounded_text(&mut d, 64)?,
            })
        };
        let value = Self {
            version,
            grant,
            channel_id,
            initiator_role: Role::Device,
            responder_role: Role::Host,
            purpose,
            terminal,
            issued_at: d.u64().map_err(|_| INVALID)?,
            expires_at: d.u64().map_err(|_| INVALID)?,
        };
        if d.position() != bytes.len() || value.canonical()? != bytes {
            return Err(INVALID.into());
        }
        Ok(value)
    }
}
fn check_signature(signature: &[u8]) -> Result<()> {
    if signature.len() != 64 {
        return Err("invalid grant/context signature length".into());
    }
    Ok(())
}
fn decode_signature(value: &str) -> Result<Vec<u8>> {
    let signature = crate::enrollment_wire::hex_bytes(value, 64)?;
    check_signature(&signature)?;
    Ok(signature)
}
impl SignedGrantV3 {
    /// Encode validated canonical bytes. Verification additionally requires trusted pins/state.
    pub fn to_wire(&self) -> Result<SignedGrantWire> {
        check_signature(&self.signature)?;
        let bytes = self.grant.canonical()?;
        GrantV3::from_canonical(&bytes)?;
        Ok(SignedGrantWire {
            canonical_cbor: hex(&bytes).try_into().map_err(|_| INVALID)?,
            signature: hex(&self.signature).try_into().map_err(|_| INVALID)?,
        })
    }
    /// Decode the strict carrier; authenticate separately with trusted pins and current state.
    pub fn from_wire(value: &SignedGrantWire) -> Result<Self> {
        let bytes =
            crate::enrollment_wire::hex_bytes(value.canonical_cbor.expose_wire(), MAX_CANONICAL)?;
        Ok(Self {
            grant: GrantV3::from_canonical(&bytes)?,
            signature: decode_signature(value.signature.expose_wire())?,
        })
    }
}
impl SignedChannelAdmissionV3 {
    /// Encode validated canonical bytes. Verification additionally requires trusted pins/state.
    pub fn to_wire(&self) -> Result<SignedChannelAdmissionWire> {
        check_signature(&self.signature)?;
        let bytes = self.context.canonical()?;
        ChannelContextV3::from_canonical(&bytes)?;
        Ok(SignedChannelAdmissionWire {
            canonical_cbor: hex(&bytes).try_into().map_err(|_| INVALID)?,
            signature: hex(&self.signature).try_into().map_err(|_| INVALID)?,
        })
    }
    /// Decode the strict carrier; authenticate separately against independent expected context.
    pub fn from_wire(value: &SignedChannelAdmissionWire) -> Result<Self> {
        let bytes =
            crate::enrollment_wire::hex_bytes(value.canonical_cbor.expose_wire(), MAX_CANONICAL)?;
        Ok(Self {
            context: ChannelContextV3::from_canonical(&bytes)?,
            signature: decode_signature(value.signature.expose_wire())?,
        })
    }
}
/// Validate host approval against a maximum proposal retained independently by the authority.
/// Only dependency-closed capabilities and expiry may narrow. Pins and current state must
/// also be independently trusted; this does not consume proposal/nonce or replay state.
#[allow(clippy::too_many_arguments)]
pub fn verify_grant_proposal_v3(
    expected_maximum: &GrantV3,
    submitted: &SignedGrantV3,
    host: &SignedBundle,
    host_pin: &[u8; 32],
    consumer: &SignedBundle,
    consumer_pin: &[u8; 32],
    current: &CurrentAuthorityV3,
    now: u64,
) -> Result<GrantV3> {
    expected_maximum.canonical()?;
    submitted.grant.canonical()?;
    let mut immutable = submitted.grant.clone();
    immutable.capabilities = expected_maximum.capabilities.clone();
    immutable.expires_at = expected_maximum.expires_at;
    if &immutable != expected_maximum
        || submitted.grant.expires_at > expected_maximum.expires_at
        || Vec::<Capability>::from(submitted.grant.capabilities.clone())
            .into_iter()
            .any(|cap| !expected_maximum.capabilities.contains(cap))
    {
        return Err("grant 3 approval exceeds retained proposal".into());
    }
    submitted.verify(
        &submitted.grant,
        host,
        host_pin,
        consumer,
        consumer_pin,
        current,
        now,
    )?;
    Ok(submitted.grant.clone())
}
