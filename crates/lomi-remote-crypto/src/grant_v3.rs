//! Isolated grant/context 3 proof. No legacy permission conversion is provided.
use crate::{identity::verify_signature, Identity, Result, Role, SignedBundle};
use ed25519_dalek::Signer;
use lomi_remote_protocol::{Capability, CapabilitySet};
use serde::{Deserialize, Serialize};

pub const GRANT_V3_DOMAIN: &str = "lomi-remote-grant-v3";
pub const CONTEXT_V3_DOMAIN: &str = "lomi-remote-channel-context-v3";
type Id = [u8; 16];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantPurposeV3 {
    Workspace,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelPurposeV3 {
    Workspace,
    Terminal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantV3 {
    pub version: u8,
    pub api_major: u8,
    pub application_major: u8,
    pub account_id: Id,
    pub host_id: Id,
    pub host_fingerprint: [u8; 32],
    pub host_authorization_id: Id,
    #[serde(with = "decimal_u64")]
    pub access_epoch: u64,
    pub consumer_authorization_id: Id,
    pub account_session_id: String,
    pub consumer_id: Id,
    pub consumer_fingerprint: [u8; 32],
    pub grant_id: Id,
    #[serde(with = "decimal_u64")]
    pub grant_revision: u64,
    pub workspace_id: Id,
    pub workspace_epoch: Id,
    pub runtime_id: Id,
    #[serde(with = "decimal_u64")]
    pub runtime_generation: u64,
    pub capabilities: CapabilitySet,
    pub nonce: [u8; 32],
    #[serde(with = "decimal_u64")]
    pub expires_at: u64,
    pub purpose: GrantPurposeV3,
}
impl GrantV3 {
    pub fn canonical(&self) -> Result<Vec<u8>> {
        if self.version != 3
            || self.api_major != 2
            || self.application_major != 2
            || self.access_epoch == 0
            || self.grant_revision == 0
            || self.runtime_generation == 0
            || self.expires_at == 0
            || [
                self.account_id,
                self.host_id,
                self.host_authorization_id,
                self.consumer_authorization_id,
                self.consumer_id,
                self.grant_id,
                self.workspace_id,
                self.workspace_epoch,
                self.runtime_id,
            ]
            .contains(&[0; 16])
            || [self.host_fingerprint, self.consumer_fingerprint, self.nonce].contains(&[0; 32])
            || !opaque_session(&self.account_session_id)
            || !self.capabilities.contains(Capability::WorkspaceRead)
        {
            return Err("invalid grant/context 3 grant".into());
        }
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(23).unwrap();
        e.str(GRANT_V3_DOMAIN).unwrap();
        for n in [self.version, self.api_major, self.application_major] {
            e.u8(n).unwrap();
        }
        for b in [
            &self.account_id[..],
            &self.host_id,
            &self.host_fingerprint,
            &self.host_authorization_id,
        ] {
            e.bytes(b).unwrap();
        }
        e.u64(self.access_epoch).unwrap();
        e.bytes(&self.consumer_authorization_id).unwrap();
        e.str(&self.account_session_id).unwrap();
        for b in [
            &self.consumer_id[..],
            &self.consumer_fingerprint,
            &self.grant_id,
        ] {
            e.bytes(b).unwrap();
        }
        e.u64(self.grant_revision).unwrap();
        for b in [
            &self.workspace_id[..],
            &self.workspace_epoch,
            &self.runtime_id,
        ] {
            e.bytes(b).unwrap();
        }
        e.u64(self.runtime_generation).unwrap();
        // Sort the registry wire names, independent of enum declaration order.
        let mut names: Vec<String> = Vec::<Capability>::from(self.capabilities.clone())
            .into_iter()
            .map(|c| {
                serde_json::to_value(c)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        names.sort();
        e.array(names.len() as u64).unwrap();
        for name in names {
            e.str(&name).unwrap();
        }
        e.bytes(&self.nonce).unwrap();
        e.u64(self.expires_at).unwrap();
        e.str("workspace").unwrap();
        Ok(e.into_writer())
    }
    pub(crate) fn bind(&self, host: &SignedBundle, consumer: &SignedBundle) -> Result<()> {
        if host.bundle.role != Role::Host
            || consumer.bundle.role != Role::Device
            || host.bundle.account_id != self.account_id
            || consumer.bundle.account_id != self.account_id
            || host.bundle.subject_id != self.host_id
            || consumer.bundle.subject_id != self.consumer_id
            || host.bundle.fingerprint()? != self.host_fingerprint
            || consumer.bundle.fingerprint()? != self.consumer_fingerprint
        {
            return Err("grant endpoint binding mismatch".into());
        }
        Ok(())
    }
    pub fn from_json(json: &str) -> Result<Self> {
        let value: Self = parse(json)?;
        value.canonical()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalTargetV3 {
    pub pane_id: Id,
    pub session_id: Id,
    pub session_epoch: Id,
    pub terminal_profile: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelContextV3 {
    pub version: u8,
    pub grant: GrantV3,
    pub channel_id: Id,
    pub initiator_role: Role,
    pub responder_role: Role,
    pub purpose: ChannelPurposeV3,
    pub terminal: Option<TerminalTargetV3>,
    #[serde(with = "decimal_u64")]
    pub issued_at: u64,
    #[serde(with = "decimal_u64")]
    pub expires_at: u64,
}
impl ChannelContextV3 {
    pub fn canonical(&self) -> Result<Vec<u8>> {
        let grant = self.grant.canonical()?;
        if self.issued_at == 0
            || self.expires_at <= self.issued_at
            || self.expires_at > self.grant.expires_at
            || self.expires_at - self.issued_at > 30
            || self.version != 3
            || self.channel_id == [0; 16]
            || self.initiator_role != Role::Device
            || self.responder_role != Role::Host
        {
            return Err("invalid channel 3 roles/version".into());
        }
        match (&self.purpose, &self.terminal) {
            (ChannelPurposeV3::Workspace, None) => (),
            (ChannelPurposeV3::Terminal, Some(t))
                if self
                    .grant
                    .capabilities
                    .contains(Capability::TerminalObserve)
                    && ![t.pane_id, t.session_id, t.session_epoch].contains(&[0; 16])
                    && t.terminal_profile == "lomi-rust-grid-v1-experimental" => {}
            _ => return Err("invalid channel 3 purpose/target".into()),
        }
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(10).unwrap();
        e.str(CONTEXT_V3_DOMAIN).unwrap();
        e.u8(self.version).unwrap();
        e.bytes(&grant).unwrap();
        e.bytes(&self.channel_id).unwrap();
        e.str("device").unwrap();
        e.str("host").unwrap();
        e.str(match self.purpose {
            ChannelPurposeV3::Workspace => "workspace",
            ChannelPurposeV3::Terminal => "terminal",
        })
        .unwrap();
        if let Some(t) = &self.terminal {
            e.array(4).unwrap();
            for b in [t.pane_id, t.session_id, t.session_epoch] {
                e.bytes(&b).unwrap();
            }
            e.str(&t.terminal_profile).unwrap();
        } else {
            e.null().unwrap();
        }
        e.u64(self.issued_at).unwrap();
        e.u64(self.expires_at).unwrap();
        Ok(e.into_writer())
    }
    pub fn from_json(json: &str) -> Result<Self> {
        let value: Self = parse(json)?;
        value.canonical()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedGrantV3 {
    pub grant: GrantV3,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedChannelAdmissionV3 {
    pub context: ChannelContextV3,
    pub signature: Vec<u8>,
}

/// Independently read current authority state, never copied from signed input.
/// Membership is required for terminal admission and absent for workspace channels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentAuthorityV3 {
    pub host_authorization_id: Id,
    pub consumer_authorization_id: Id,
    pub account_session_id: String,
    pub access_epoch: u64,
    pub grant_revision: u64,
    pub workspace_epoch: Id,
    pub runtime_id: Id,
    pub runtime_generation: u64,
    pub terminal_membership: Option<TerminalTargetV3>,
}
impl CurrentAuthorityV3 {
    fn check(&self, g: &GrantV3) -> Result<()> {
        if self.host_authorization_id != g.host_authorization_id
            || self.consumer_authorization_id != g.consumer_authorization_id
            || self.account_session_id != g.account_session_id
            || self.access_epoch != g.access_epoch
            || self.grant_revision != g.grant_revision
            || self.workspace_epoch != g.workspace_epoch
            || self.runtime_id != g.runtime_id
            || self.runtime_generation != g.runtime_generation
        {
            return Err("stale grant authority".into());
        }
        Ok(())
    }
}
/// Constructed only after both host signatures, endpoint pins and trusted state pass.
/// This token is a point-in-time admission, not a freshness lease for later operations.
pub struct VerifiedChannelContextV3 {
    pub(crate) context: ChannelContextV3,
}
impl Identity {
    pub fn sign_grant_v3(&self, grant: &GrantV3) -> Result<SignedGrantV3> {
        self.check_host_v3(grant)?;
        Ok(SignedGrantV3 {
            grant: grant.clone(),
            signature: self.signing.sign(&grant.canonical()?).to_bytes().to_vec(),
        })
    }
    pub fn sign_channel_admission_v3(
        &self,
        context: &ChannelContextV3,
    ) -> Result<SignedChannelAdmissionV3> {
        self.check_host_v3(&context.grant)?;
        Ok(SignedChannelAdmissionV3 {
            context: context.clone(),
            signature: self.signing.sign(&context.canonical()?).to_bytes().to_vec(),
        })
    }
    fn check_host_v3(&self, grant: &GrantV3) -> Result<()> {
        if self.disposed
            || self.signed.bundle.role != Role::Host
            || self.signed.bundle.account_id != grant.account_id
            || self.signed.bundle.subject_id != grant.host_id
            || self.signed.bundle.fingerprint()? != grant.host_fingerprint
        {
            return Err("grant 3 signing context mismatch".into());
        }
        Ok(())
    }
}
impl SignedGrantV3 {
    // Keep independently trusted pins/state explicit at the verification boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        expected: &GrantV3,
        host: &SignedBundle,
        host_pin: &[u8; 32],
        consumer: &SignedBundle,
        consumer_pin: &[u8; 32],
        current: &CurrentAuthorityV3,
        now: u64,
    ) -> Result<()> {
        if &self.grant != expected || now >= expected.expires_at {
            return Err("grant 3 trusted state mismatch or expiry".into());
        }
        host.verify(host_pin)?;
        consumer.verify(consumer_pin)?;
        expected.bind(host, consumer)?;
        current.check(expected)?;
        verify_signature(
            &host.bundle.identity_key,
            &expected.canonical()?,
            &self.signature,
        )
    }
    pub fn from_json(json: &str) -> Result<Self> {
        let value: Self = parse(json)?;
        value.grant.canonical()?;
        Ok(value)
    }
}
impl SignedChannelAdmissionV3 {
    /// Both expected context and current membership must come from independent authority state.
    // Keep independently trusted pins/state explicit at the verification boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        grant: &SignedGrantV3,
        expected: &ChannelContextV3,
        host: &SignedBundle,
        host_pin: &[u8; 32],
        consumer: &SignedBundle,
        consumer_pin: &[u8; 32],
        current: &CurrentAuthorityV3,
        now: u64,
    ) -> Result<VerifiedChannelContextV3> {
        if now < expected.issued_at
            || now >= expected.expires_at
            || &self.context != expected
            || current.terminal_membership != expected.terminal
        {
            return Err("channel 3 trusted context/membership mismatch".into());
        }
        grant.verify(
            &expected.grant,
            host,
            host_pin,
            consumer,
            consumer_pin,
            current,
            now,
        )?;
        verify_signature(
            &host.bundle.identity_key,
            &expected.canonical()?,
            &self.signature,
        )?;
        Ok(VerifiedChannelContextV3 {
            context: expected.clone(),
        })
    }
    pub fn from_json(json: &str) -> Result<Self> {
        let value: Self = parse(json)?;
        value.context.canonical()?;
        Ok(value)
    }
}
fn parse<T: serde::de::DeserializeOwned>(json: &str) -> Result<T> {
    if json.len() > crate::MAX_JSON {
        return Err("grant/context JSON limit".into());
    }
    serde_json::from_str(json).map_err(|_| "invalid grant/context 3 JSON".into())
}
mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(n: &u64, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&n.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<u64, D::Error> {
        let s = String::deserialize(d)?;
        if s.is_empty()
            || !s.bytes().all(|b| b.is_ascii_digit())
            || (s.len() > 1 && s.starts_with('0'))
        {
            return Err(serde::de::Error::custom("canonical decimal u64 required"));
        }
        s.parse().map_err(serde::de::Error::custom)
    }
}

fn opaque_session(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
