//! Pure preparation policy for owner-account peers, without signing or network IO.
//!
//! Every `SnapshotInput` is caller-trusted state: authenticate the separately pinned
//! Remote API, independently observe its identity/pin/current authority and expiry,
//! and recheck local authorization generation, volatile gates and ownership before
//! constructing it. Never copy those trusted fields from proposed signed claims.
//! ACKed membership must be the complete confirmed snapshot for this exact runtime,
//! not an intent or a sequence number. This module cannot establish TLS provenance,
//! read local consent, consume nonces, persist decisions or grant ongoing authority.
use crate::{Config, PublicHostIdentity};
use lomi_remote_crypto::{
    ChannelContextV3, ChannelPurposeV3, CurrentAuthorityV3, GrantV3, Role, SignedBundle,
    SignedGrantV3, TerminalTargetV3, verify_consumer_window_identity, verify_grant_proposal_v3,
};
use lomi_remote_protocol::{
    AccountId, Capability, CapabilitySet, EnrollmentProof, RuntimeId, TerminalProfile,
    WindowIdentityId, WorkspaceEpoch, WorkspaceId,
    http::{CurrentAuthorityBinding, PublicationTerminals, PublicationWorkspaces, RuntimeBinding},
};
use std::time::{Duration, Instant};

const MAX: u64 = i64::MAX as u64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyError {
    Invalid,
    Denied,
    Stale,
    ClockRollback,
}
impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "PEER_POLICY_INVALID",
            Self::Denied => "PEER_POLICY_DENIED",
            Self::Stale => "PEER_POLICY_STALE",
            Self::ClockRollback => "PEER_POLICY_CLOCK_ROLLBACK",
        })
    }
}
impl std::error::Error for PolicyError {}
type Result<T> = std::result::Result<T, PolicyError>;
fn valid<T>(result: lomi_remote_crypto::Result<T>) -> Result<T> {
    result.map_err(|_| PolicyError::Invalid)
}

/// An explicit trusted configuration pin. No response or deserialization constructor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteOrigin(String);
impl RemoteOrigin {
    pub fn new(identity: &Config, pin: String) -> Result<Self> {
        identity.validate().map_err(|_| PolicyError::Invalid)?;
        let mut remote = identity.clone();
        remote.origin = pin.clone();
        remote.validate().map_err(|_| PolicyError::Invalid)?;
        if pin == identity.origin() {
            return Err(PolicyError::Invalid);
        }
        Ok(Self(pin))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Volatile clock watermark. Keep one across observations; never serialize or
/// reset it to make an expired preparation valid. Reopen needs the caller's
/// trusted nondecreasing wall-clock anchor, just like HostAuth.
pub struct PolicyClock {
    wall: u64,
    monotonic: Instant,
    anchor_wall: u64,
    anchor: Instant,
}
impl PolicyClock {
    pub fn new(wall: u64, monotonic: Instant) -> Result<Self> {
        if wall == 0 || wall > MAX {
            return Err(PolicyError::Invalid);
        }
        Ok(Self {
            wall,
            monotonic,
            anchor_wall: wall,
            anchor: monotonic,
        })
    }
    fn observe(&mut self, wall: u64, monotonic: Instant) -> Result<u64> {
        if wall < self.wall || monotonic < self.monotonic {
            return Err(PolicyError::ClockRollback);
        }
        let projected = self
            .anchor_wall
            .checked_add(monotonic.duration_since(self.anchor).as_secs())
            .ok_or(PolicyError::Invalid)?;
        let now = wall.max(projected);
        if now > MAX {
            return Err(PolicyError::Invalid);
        }
        // Preserve elapsed expiry after a forward wall observation even if the
        // next wall samples stop advancing. Do not reset on ordinary subsecond
        // observations, which would discard fractional monotonic progress.
        if wall > projected {
            self.anchor_wall = wall;
            self.anchor = monotonic;
        }
        self.wall = now;
        self.monotonic = monotonic;
        Ok(now)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerScope {
    pub authorization_generation: u64,
    pub owner_runtime_id: RuntimeId,
    pub owner_generation: u64,
    pub runtime: RuntimeBinding,
}
/// Current local state, not remote inventory. Only running terminals belong here.
#[derive(Clone)]
pub struct LocalWorkspace {
    pub workspace_id: WorkspaceId,
    pub workspace_epoch: WorkspaceEpoch,
    pub fence: u64,
    pub consent: bool,
    pub running_terminals: PublicationTerminals,
    /// None uses control_with_workspace_tools, which excludes git.execute.
    pub capability_ceiling: Option<CapabilitySet>,
}
/// Independently authenticated current control-plane state, not a signed claim.
pub struct PeerObservation {
    pub account_id: AccountId,
    pub window_id: WindowIdentityId,
    pub identity: EnrollmentProof,
    pub fingerprint: [u8; 32],
    pub authority: CurrentAuthorityBinding,
    pub authority_expires_at: u64,
}
pub struct SnapshotInput {
    /// Obtain directly from the current protected HostAuth manager.
    pub protected_host: PublicHostIdentity,
    pub remote_origin: RemoteOrigin,
    pub owner: OwnerScope,
    pub acknowledged_runtime: RuntimeBinding,
    pub acknowledged_workspaces: PublicationWorkspaces,
    pub local: LocalWorkspace,
    pub peer: PeerObservation,
    pub request_started: Instant,
    pub wall_at_request_start: u64,
    pub lease_ms: u64,
    pub freshness_ms: u64,
}
/// Immutable evidence for one preparation, never an authorization lease for IO.
pub struct PolicySnapshot {
    host: PublicHostIdentity,
    host_bundle: SignedBundle,
    origin: RemoteOrigin,
    owner: OwnerScope,
    acknowledged: PublicationWorkspaces,
    local: LocalWorkspace,
    consumer: SignedBundle,
    consumer_pin: [u8; 32],
    current: CurrentAuthorityV3,
    authority_expires_at: u64,
    started: Instant,
    wall_at_start: u64,
    lease_until: Instant,
    fresh_until: Instant,
}
impl PolicySnapshot {
    pub fn new(input: SnapshotInput) -> Result<Self> {
        let SnapshotInput {
            protected_host: host,
            remote_origin: origin,
            owner,
            acknowledged_runtime,
            acknowledged_workspaces: acknowledged,
            local,
            peer,
            request_started: started,
            wall_at_request_start: wall_at_start,
            lease_ms,
            freshness_ms,
        } = input;
        if owner.owner_generation == 0
            || owner.owner_generation > MAX
            || owner.authorization_generation > MAX
            || owner.owner_runtime_id != owner.runtime.runtime_id
            || owner.runtime.runtime_generation.0 == 0
            || owner.runtime.runtime_generation.0 > MAX
            || owner.runtime.host_access_epoch.0 != host.access_epoch
            || host.access_epoch == 0
            || host.access_epoch > MAX
            || acknowledged_runtime != owner.runtime
            || wall_at_start == 0
            || wall_at_start > MAX
            || lease_ms == 0
            || lease_ms > 30_000
            || freshness_ms == 0
            || freshness_ms > 5_000
            || freshness_ms > lease_ms
            || peer.authority_expires_at == 0
            || peer.authority_expires_at > MAX
        {
            return Err(PolicyError::Invalid);
        }
        if !local.consent || local.fence == 0 || peer.account_id != host.account_id {
            return Err(PolicyError::Denied);
        }
        let host_bundle = valid(SignedBundle::from_wire(&host.identity))?;
        valid(host_bundle.verify(&host.fingerprint))?;
        if host_bundle.bundle.role != Role::Host
            || host_bundle.bundle.account_id != host.account_id.to_bytes()
            || host_bundle.bundle.subject_id != host.host_id.to_bytes()
            || [
                host_bundle.bundle.identity_key,
                host_bundle.bundle.channel_key,
                host_bundle.bundle.mailbox_key,
            ]
            .contains(&[0; 32])
        {
            return Err(PolicyError::Denied);
        }
        let consumer = valid(verify_consumer_window_identity(
            &peer.identity,
            host.account_id.to_bytes(),
            peer.window_id.to_bytes(),
        ))?;
        valid(consumer.verify(&peer.fingerprint))?;
        let a = &peer.authority;
        if a.host_authorization_id != host.host_authorization_id
            || a.access_epoch.0 != host.access_epoch
            || a.runtime_id != owner.runtime.runtime_id
            || a.runtime_generation != owner.runtime.runtime_generation
            || a.workspace_epoch != local.workspace_epoch
            || a.grant_revision.0 == 0
            || a.grant_revision.0 > MAX
        {
            return Err(PolicyError::Denied);
        }
        if !acknowledged.as_slice().iter().any(|w| {
            w.workspace_id == local.workspace_id && w.workspace_epoch == local.workspace_epoch
        }) {
            return Err(PolicyError::Denied);
        }
        let terminal_membership = a.terminal_membership.as_ref().map(|t| TerminalTargetV3 {
            pane_id: t.pane_id.to_bytes(),
            session_id: t.session_id.to_bytes(),
            session_epoch: t.session_epoch.to_bytes(),
            terminal_profile: match t.terminal_profile {
                TerminalProfile::ExperimentalRustGridV1 => {
                    "lomi-rust-grid-v1-experimental".to_owned()
                }
            },
        });
        let current = CurrentAuthorityV3 {
            host_authorization_id: a.host_authorization_id.to_bytes(),
            consumer_authorization_id: a.consumer_authorization_id.to_bytes(),
            account_session_id: a.account_session_id.as_str().to_owned(),
            access_epoch: a.access_epoch.0,
            grant_revision: a.grant_revision.0,
            workspace_epoch: a.workspace_epoch.to_bytes(),
            runtime_id: a.runtime_id.to_bytes(),
            runtime_generation: a.runtime_generation.0,
            terminal_membership,
        };
        Ok(Self {
            host,
            host_bundle,
            origin,
            owner,
            acknowledged,
            local,
            consumer,
            consumer_pin: peer.fingerprint,
            current,
            authority_expires_at: peer.authority_expires_at,
            started,
            wall_at_start,
            lease_until: started
                .checked_add(Duration::from_millis(lease_ms))
                .ok_or(PolicyError::Invalid)?,
            fresh_until: started
                .checked_add(Duration::from_millis(freshness_ms))
                .ok_or(PolicyError::Invalid)?,
        })
    }
    fn now(&self, clock: &mut PolicyClock, wall: u64, monotonic: Instant) -> Result<u64> {
        let now = clock.observe(wall, monotonic)?;
        if monotonic < self.started {
            return Err(PolicyError::ClockRollback);
        }
        let request_projection = self
            .wall_at_start
            .checked_add(monotonic.duration_since(self.started).as_secs())
            .ok_or(PolicyError::Invalid)?;
        if now < request_projection {
            return Err(PolicyError::ClockRollback);
        }
        if monotonic >= self.lease_until
            || monotonic >= self.fresh_until
            || now >= self.authority_expires_at
        {
            return Err(PolicyError::Stale);
        }
        Ok(now)
    }
    fn check_grant(&self, g: &GrantV3, now: u64) -> Result<()> {
        valid(g.canonical())?;
        if g.access_epoch > MAX
            || g.runtime_generation > MAX
            || g.grant_revision > MAX
            || g.expires_at > MAX
        {
            return Err(PolicyError::Invalid);
        }
        if g.account_id != self.host.account_id.to_bytes()
            || g.host_id != self.host.host_id.to_bytes()
            || g.host_fingerprint != self.host.fingerprint
            || g.host_authorization_id != self.current.host_authorization_id
            || g.access_epoch != self.current.access_epoch
            || g.consumer_id != self.consumer.bundle.subject_id
            || g.consumer_fingerprint != self.consumer_pin
            || g.consumer_authorization_id != self.current.consumer_authorization_id
            || g.account_session_id != self.current.account_session_id
            || g.grant_revision != self.current.grant_revision
            || g.workspace_id != self.local.workspace_id.to_bytes()
            || g.workspace_epoch != self.current.workspace_epoch
            || g.runtime_id != self.current.runtime_id
            || g.runtime_generation != self.current.runtime_generation
        {
            return Err(PolicyError::Denied);
        }
        if now >= g.expires_at {
            return Err(PolicyError::Stale);
        }
        Ok(())
    }
    pub fn prepare_grant(
        &self,
        maximum_cbor: &[u8],
        narrowing: GrantNarrowing,
        clock: &mut PolicyClock,
        wall: u64,
        monotonic: Instant,
    ) -> Result<PreparedGrant> {
        let now = self.now(clock, wall, monotonic)?;
        if self.current.terminal_membership.is_some() {
            return Err(PolicyError::Denied);
        }
        let maximum = valid(GrantV3::from_canonical(maximum_cbor))?;
        self.check_grant(&maximum, now)?;
        let ceiling = self
            .local
            .capability_ceiling
            .clone()
            .unwrap_or_else(CapabilitySet::control_with_workspace_tools);
        let mut grant = maximum.clone();
        grant.capabilities = CapabilitySet::try_from(
            Vec::<Capability>::from(maximum.capabilities.clone())
                .into_iter()
                .filter(|c| ceiling.contains(*c) && narrowing.capabilities.contains(*c))
                .collect::<Vec<_>>(),
        )
        .map_err(|_| PolicyError::Denied)?;
        grant.expires_at = maximum
            .expires_at
            .min(narrowing.expires_at)
            .min(self.authority_expires_at);
        self.check_grant(&grant, now)?;
        let canonical = valid(grant.canonical())?;
        Ok(PreparedGrant {
            grant,
            canonical,
            binding: self.binding(),
        })
    }
    fn binding(&self) -> PreparationBinding {
        PreparationBinding {
            host: self.host.clone(),
            origin: self.origin.clone(),
            owner: self.owner.clone(),
            workspace: self.local.workspace_id,
            epoch: self.local.workspace_epoch,
            fence: self.local.fence,
            consumer: self.consumer.clone(),
            pin: self.consumer_pin,
        }
    }
    fn check_capabilities(&self, grant: &GrantV3) -> Result<()> {
        let ceiling = self
            .local
            .capability_ceiling
            .clone()
            .unwrap_or_else(CapabilitySet::control_with_workspace_tools);
        if Vec::<Capability>::from(grant.capabilities.clone())
            .into_iter()
            .any(|capability| !ceiling.contains(capability))
        {
            return Err(PolicyError::Denied);
        }
        Ok(())
    }
    pub fn retain_approved_grant(
        &self,
        prepared: &PreparedGrant,
        signed: SignedGrantV3,
        clock: &mut PolicyClock,
        wall: u64,
        monotonic: Instant,
    ) -> Result<ApprovedGrant> {
        let now = self.now(clock, wall, monotonic)?;
        if prepared.binding != self.binding()
            || signed.grant != prepared.grant
            || signed.grant.expires_at > self.authority_expires_at
        {
            return Err(PolicyError::Denied);
        }
        self.check_grant(&signed.grant, now)?;
        self.check_capabilities(&signed.grant)?;
        valid(verify_grant_proposal_v3(
            &prepared.grant,
            &signed,
            &self.host_bundle,
            &self.host.fingerprint,
            &self.consumer,
            &self.consumer_pin,
            &self.current,
            now,
        ))?;
        Ok(ApprovedGrant {
            signed,
            binding: prepared.binding.clone(),
        })
    }
    pub fn prepare_channel(
        &self,
        approved: &ApprovedGrant,
        context_cbor: &[u8],
        clock: &mut PolicyClock,
        wall: u64,
        monotonic: Instant,
    ) -> Result<PreparedChannel> {
        let now = self.now(clock, wall, monotonic)?;
        if approved.binding != self.binding() {
            return Err(PolicyError::Denied);
        }
        self.check_grant(&approved.signed.grant, now)?;
        valid(approved.signed.verify(
            &approved.signed.grant,
            &self.host_bundle,
            &self.host.fingerprint,
            &self.consumer,
            &self.consumer_pin,
            &self.current,
            now,
        ))?;
        let context = valid(ChannelContextV3::from_canonical(context_cbor))?;
        if context.grant != approved.signed.grant
            || context.issued_at > now
            || now >= context.expires_at
            || context.expires_at > self.authority_expires_at
        {
            return Err(PolicyError::Denied);
        }
        self.check_capabilities(&context.grant)?;
        match context.purpose {
            ChannelPurposeV3::Workspace
                if context.terminal.is_none() && self.current.terminal_membership.is_none() => {}
            ChannelPurposeV3::Terminal => {
                let target = context.terminal.as_ref().ok_or(PolicyError::Denied)?;
                if self.current.terminal_membership.as_ref() != Some(target)
                    || !self
                        .local
                        .running_terminals
                        .as_slice()
                        .iter()
                        .any(|t| terminal_matches(t, target))
                    || !self
                        .acknowledged
                        .as_slice()
                        .iter()
                        .filter(|w| {
                            w.workspace_id == self.local.workspace_id
                                && w.workspace_epoch == self.local.workspace_epoch
                        })
                        .flat_map(|w| w.terminals.as_slice())
                        .any(|t| terminal_matches(t, target))
                {
                    return Err(PolicyError::Denied);
                }
            }
            _ => return Err(PolicyError::Denied),
        }
        Ok(PreparedChannel {
            canonical: valid(context.canonical())?,
            context,
            binding: self.binding(),
        })
    }
}
fn terminal_matches(
    t: &lomi_remote_protocol::http::PublishedTerminal,
    target: &TerminalTargetV3,
) -> bool {
    t.pane_id.to_bytes() == target.pane_id
        && t.session_id.to_bytes() == target.session_id
        && t.session_epoch.to_bytes() == target.session_epoch
}
#[derive(Clone, PartialEq, Eq)]
struct PreparationBinding {
    host: PublicHostIdentity,
    origin: RemoteOrigin,
    owner: OwnerScope,
    workspace: WorkspaceId,
    epoch: WorkspaceEpoch,
    fence: u64,
    consumer: SignedBundle,
    pin: [u8; 32],
}
pub struct GrantNarrowing {
    pub capabilities: CapabilitySet,
    pub expires_at: u64,
}
/// Frozen values for an exact retry, not permission to send or sign after state changes.
pub struct PreparedGrant {
    grant: GrantV3,
    canonical: Vec<u8>,
    binding: PreparationBinding,
}
impl PreparedGrant {
    pub fn grant(&self) -> &GrantV3 {
        &self.grant
    }
    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }
    pub fn owner_scope(&self) -> &OwnerScope {
        &self.binding.owner
    }
    pub fn workspace_fence(&self) -> u64 {
        self.binding.fence
    }
}
/// Only constructed after exact prepared-byte binding and existing signature verification.
pub struct ApprovedGrant {
    signed: SignedGrantV3,
    binding: PreparationBinding,
}
impl ApprovedGrant {
    pub fn signed(&self) -> &SignedGrantV3 {
        &self.signed
    }
}
pub struct PreparedChannel {
    context: ChannelContextV3,
    canonical: Vec<u8>,
    binding: PreparationBinding,
}
impl PreparedChannel {
    pub fn context(&self) -> &ChannelContextV3 {
        &self.context
    }
    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }
    pub fn owner_scope(&self) -> &OwnerScope {
        &self.binding.owner
    }
    pub fn workspace_fence(&self) -> u64 {
        self.binding.fence
    }
}
