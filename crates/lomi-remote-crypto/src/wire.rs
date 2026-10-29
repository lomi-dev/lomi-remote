use crate::{Result, PROFILE};
use serde::{Deserialize, Serialize};
pub type Id = [u8; 16];
pub(crate) type Encoder = minicbor::Encoder<Vec<u8>>;
pub(crate) fn encoder() -> Encoder {
    minicbor::Encoder::new(Vec::new())
}
pub(crate) fn bytes(e: &mut Encoder, b: &[u8]) {
    e.bytes(b).unwrap();
}
pub(crate) fn number(e: &mut Encoder, n: u64) {
    e.u64(n).unwrap();
}
pub(crate) fn domain(e: &mut Encoder, n: u64, name: &str) {
    e.array(n).unwrap();
    e.str(PROFILE).unwrap();
    e.str(name).unwrap();
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Host,
    Device,
}
impl Role {
    pub(crate) fn code(self) -> u64 {
        match self {
            Self::Host => 1,
            Self::Device => 2,
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChannelPurpose {
    Terminal,
    Metadata,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelContext {
    pub version: u32,
    pub account_id: Id,
    pub host_id: Id,
    pub device_id: Id,
    pub initiator_role: Role,
    pub responder_role: Role,
    pub channel_id: Id,
    pub grant_id: Id,
    pub session_id: Id,
    pub access_epoch: u64,
    pub revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_epoch: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_epoch: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<ChannelPurpose>,
}
impl ChannelContext {
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.version, 1 | 2)
            || self.initiator_role != Role::Device
            || self.responder_role != Role::Host
            || self.access_epoch == 0
            || self.revision == 0
        {
            return Err("unsupported channel context".into());
        }
        let fields = [
            self.workspace_id.is_some(),
            self.workspace_epoch.is_some(),
            self.session_epoch.is_some(),
            self.purpose.is_some(),
        ];
        if (self.version == 1 && fields.iter().any(|present| *present))
            || (self.version == 2 && fields.iter().any(|present| !*present))
            || (self.purpose == Some(ChannelPurpose::Metadata)
                && (Some(self.session_id) != self.workspace_id
                    || self.session_epoch != self.workspace_epoch))
        {
            return Err("invalid channel workspace scope".into());
        }
        Ok(())
    }
    /// Call after verifying the approval against trusted host and grant state.
    pub fn validate_approval(&self, approval: &crate::PeerApproval) -> Result<()> {
        self.validate()?;
        approval.canonical()?;
        if self.version != approval.version
            || self.account_id != approval.account_id
            || self.host_id != approval.host_id
            || self.device_id != approval.device_id
            || self.grant_id != approval.grant_id
            || self.access_epoch != approval.access_epoch
            || self.revision != approval.revision
            || self.workspace_id != approval.workspace_id
            || self.workspace_epoch != approval.workspace_epoch
        {
            return Err("channel approval context mismatch".into());
        }
        if self.purpose == Some(ChannelPurpose::Metadata) {
            return Ok(());
        }
        let index = approval
            .session_ids
            .iter()
            .position(|id| *id == self.session_id)
            .ok_or("channel session outside approval")?;
        if self.version == 2 && self.session_epoch != Some(approval.session_epochs[index]) {
            return Err("channel session epoch mismatch".into());
        }
        Ok(())
    }
    pub fn canonical(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut e = encoder();
        domain(
            &mut e,
            if self.version == 1 { 13 } else { 17 },
            "channel-context",
        );
        number(&mut e, u64::from(self.version));
        bytes(&mut e, &self.account_id);
        bytes(&mut e, &self.host_id);
        bytes(&mut e, &self.device_id);
        number(&mut e, self.initiator_role.code());
        number(&mut e, self.responder_role.code());
        bytes(&mut e, &self.channel_id);
        bytes(&mut e, &self.grant_id);
        bytes(&mut e, &self.session_id);
        number(&mut e, self.access_epoch);
        number(&mut e, self.revision);
        if self.version == 2 {
            bytes(&mut e, &self.workspace_id.unwrap());
            bytes(&mut e, &self.workspace_epoch.unwrap());
            bytes(&mut e, &self.session_epoch.unwrap());
            number(
                &mut e,
                match self.purpose.unwrap() {
                    ChannelPurpose::Terminal => 1,
                    ChannelPurpose::Metadata => 2,
                },
            );
        }
        Ok(e.into_writer())
    }
}
