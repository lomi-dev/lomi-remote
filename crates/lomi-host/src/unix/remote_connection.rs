//! PRIVATE UNWIRED SOURCE STAGE. No dispatcher, transport IO, effects or serialization.
//! Frame crypto is gated privately; this module still has no production ingress wiring.
//! OwnerFacts/PeerRead are trusted owner observations, not deserializable authority.
//! The owner must collect durable facts under its serialization discipline, load
//! volatile gates freshly, and supply a lock-free trusted clock projection. Never
//! acquire Store from a terminal-core callback. See CONTRACT.md before integration.
use super::{
    cloud::HeartbeatObservation,
    owner_domain::{Operation, OperationIdentity},
};
use lomi_host_auth::{
    HostAuth, HostChannelAdmissionV3, HostChannelV3, HostResponderHandshakeV3, PublicHostIdentity,
    peer_policy::{LocalWorkspace, RemoteOrigin},
};
use lomi_host_store::{CloudRuntimeScope, HostAcknowledgedPublication};
use lomi_platform::secrets::SecretStorage;
use lomi_remote_crypto::{
    ChannelContextV3, ChannelPurposeV3, CurrentAuthorityV3, SignedBundle, SignedChannelAdmissionV3,
    SignedGrantV3, TerminalTargetV3, verify_consumer_window_identity,
};
use lomi_remote_protocol::{http::RuntimeBinding, rpc::*, *};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum GateError {
    Denied,
    Busy,
    Disposed,
}
type Result<T> = std::result::Result<T, GateError>;

trait PublicationReceiptProof {
    fn current_for(&self, connection: uuid::Uuid) -> bool;
    fn started_git_current_for(&self, _connection: uuid::Uuid) -> bool {
        false
    }
}
struct StartedGitTerminalPermit<'a> {
    active: &'a super::shared_owner::StartedGitContinuation,
    observation: &'a super::peer::StartedGitPeerObservation,
    operation: &'a Operation<'a>,
}
impl PublicationReceiptProof
    for super::super::shared_owner::RemoteRenameReceiptTurn<'_, '_, '_, '_, '_, '_, '_>
{
    fn current_for(&self, connection: uuid::Uuid) -> bool {
        super::super::shared_owner::RemoteRenameReceiptTurn::current_for(self, connection)
    }
}
impl PublicationReceiptProof
    for super::super::shared_owner::RemoteGitReceiptTurn<'_, '_, '_, '_, '_, '_, '_, '_>
{
    fn current_for(&self, connection: uuid::Uuid) -> bool {
        super::super::shared_owner::RemoteGitReceiptTurn::current_for(self, connection)
    }
}
impl PublicationReceiptProof
    for super::super::shared_owner::RemoteGitStartedReceiptTurn<'_, '_, '_, '_>
{
    fn current_for(&self, connection: uuid::Uuid) -> bool {
        super::super::shared_owner::RemoteGitStartedReceiptTurn::current_for(self, connection)
    }
    fn started_git_current_for(&self, connection: uuid::Uuid) -> bool {
        self.current_for(connection)
    }
}
fn checked<T>(r: lomi_remote_crypto::Result<T>) -> Result<T> {
    r.map_err(|_| GateError::Disposed)
}

/// Full precision trusted Unix time + monotonic sample. Never raw Instant units.
#[derive(Clone, Copy)]
pub(in super::super) struct TrustedNow {
    pub(in super::super) wall: Duration,
    pub(in super::super) monotonic: Instant,
}
struct Clock {
    last_input: Duration,
    last_tick: Instant,
    anchor_wall: Duration,
    anchor: Instant,
}
impl Clock {
    fn new(now: TrustedNow) -> Result<Self> {
        if now.wall.is_zero() || now.wall.as_secs() > i64::MAX as u64 {
            return Err(GateError::Disposed);
        }
        Ok(Self {
            last_input: now.wall,
            last_tick: now.monotonic,
            anchor_wall: now.wall,
            anchor: now.monotonic,
        })
    }
    fn observe(&mut self, now: TrustedNow) -> Result<Duration> {
        if now.wall < self.last_input || now.monotonic < self.last_tick {
            return Err(GateError::Disposed);
        }
        let elapsed = now
            .monotonic
            .checked_duration_since(self.anchor)
            .ok_or(GateError::Disposed)?;
        let projected = self
            .anchor_wall
            .checked_add(elapsed)
            .ok_or(GateError::Disposed)?;
        let effective = projected.max(now.wall);
        if effective.as_secs() > i64::MAX as u64 {
            return Err(GateError::Disposed);
        }
        if now.wall > projected {
            self.anchor_wall = now.wall;
            self.anchor = now.monotonic;
        }
        self.last_input = now.wall;
        self.last_tick = now.monotonic;
        Ok(effective)
    }
}

/// Volatile latches are read again after validation. Durable booleans must come
/// from a CURRENT owner snapshot; this type neither reads SQLite nor proves TLS.
pub(in super::super) struct OwnerFacts<'a> {
    pub(in super::super) protected_host: &'a PublicHostIdentity,
    pub(in super::super) origin: &'a RemoteOrigin,
    pub(in super::super) scope: &'a CloudRuntimeScope,
    pub(in super::super) runtime: &'a RuntimeBinding,
    pub(in super::super) heartbeat: &'a HeartbeatObservation,
    pub(in super::super) acknowledged: &'a HostAcknowledgedPublication,
    pub(in super::super) local: &'a LocalWorkspace,
    /// Actual Running descriptors with session epoch AND profile, not inventory alone.
    pub(in super::super) running: &'a [TerminalContext],
    pub(in super::super) auth_ready: bool,
    pub(in super::super) access_expires_at: u64,
    pub(in super::super) refresh_at: u64,
    pub(in super::super) authorization_locked: bool,
    pub(in super::super) pending_login: bool,
    pub(in super::super) pending_logout: bool,
    pub(in super::super) pending_revoke: bool,
    pub(in super::super) pending_publication: bool,
    /// Connection/grant revocation only; never a global host-credential fence.
    pub(in super::super) peer_revoked: bool,
    /// Borrow the actual runtime gate: true means denied, matching auth/Cloud.
    /// Never replace it with a copied or inverted point-in-time atomic.
    pub(in super::super) gate_denied: &'a AtomicBool,
    pub(in super::super) paused: &'a AtomicBool,
    pub(in super::super) stopping: &'a AtomicBool,
    pub(in super::super) cancelled: &'a AtomicBool,
}
/// A NEW authenticated current-peer read from the separately pinned Remote API.
/// All fields except signed_grant come independently from that current owner/TLS
/// observation, never copied from context/admission or an ACK journal. The ongoing
/// authority endpoint/adapter remains an integration prerequisite, NOT channelGET
/// presumed usable after its short admission expiry. No response-selected origin.
pub(in super::super) struct PeerRead<'a> {
    pub(in super::super) origin: &'a RemoteOrigin,
    pub(in super::super) request_started: Instant,
    pub(in super::super) wall_at_request_start: u64,
    pub(in super::super) original_heartbeat: &'a HeartbeatObservation,
    pub(in super::super) consumer_window: WindowIdentityId,
    pub(in super::super) consumer_identity: &'a EnrollmentProof,
    pub(in super::super) consumer_pin: [u8; 32],
    pub(in super::super) signed_grant: &'a SignedGrantV3,
    pub(in super::super) authority: &'a CurrentAuthorityV3,
    /// Current recipient/account-session/grant ceiling, NOT context.expires_at.
    pub(in super::super) authority_expires_at: u64,
}
struct PeerProof {
    consumer: SignedBundle,
    pin: [u8; 32],
    authority: CurrentAuthorityV3,
    started: Instant,
    valid_until: Instant,
    authority_expires_at: Duration,
}
struct Binding {
    context: ChannelContextV3,

    signed_grant: SignedGrantV3,
    host: PublicHostIdentity,
    origin: RemoteOrigin,
    scope: CloudRuntimeScope,
    fence: u64,
    actor: ConsumerAuthorizationId,
}
struct GateCore {
    binding: Binding,
    peer: PeerProof,
    clock: Clock,
    disposed: bool,
    connection: uuid::Uuid,
    sequence: u64,
    pending: Option<u64>,
}

fn deadline(start: Instant, ms: u64) -> Result<Instant> {
    start
        .checked_add(Duration::from_millis(ms))
        .ok_or(GateError::Disposed)
}
fn heartbeat_live(h: &HeartbeatObservation, b: &Binding, now: TrustedNow, wall: Duration) -> bool {
    h.scope == b.scope
        && h.runtime.runtime_id.to_bytes() == b.context.grant.runtime_id
        && h.runtime.runtime_generation.0 == b.context.grant.runtime_generation
        && h.runtime.host_access_epoch.0 == b.context.grant.access_epoch
        && h.request_started <= now.monotonic
        && h.wall_at_request_start > 0
        && h.wall_at_request_start <= i64::MAX as u64
        && h.wall_at_request_start <= wall.as_secs()
        && (1..=30_000).contains(&h.lease_ms)
        && (1..=5_000).contains(&h.freshness_ms)
        && h.freshness_ms <= h.lease_ms
        && deadline(h.request_started, h.lease_ms).is_ok_and(|d| now.monotonic < d)
        && deadline(h.request_started, h.freshness_ms).is_ok_and(|d| now.monotonic < d)
}
fn target_v3(t: &TerminalContext) -> TerminalTargetV3 {
    TerminalTargetV3 {
        pane_id: t.pane_id.to_bytes(),
        session_id: t.session_id.to_bytes(),
        session_epoch: t.session_epoch.to_bytes(),
        terminal_profile: match &t.profile {
            TerminalProfile::ExperimentalRustGridV1 => "lomi-rust-grid-v1-experimental".into(),
        },
    }
}

fn operation_control_context(call: &RpcCall) -> Option<&WorkspaceContext> {
    match call {
        RpcCall::OperationStatus(params) => Some(&params.context),
        RpcCall::OperationCancel(params) => Some(&params.context),
        _ => None,
    }
}

fn git_receipt_context(call: &RpcCall) -> Option<&WorkspaceContext> {
    match call {
        RpcCall::GitStage(p) => Some(&p.mutation.context),
        RpcCall::GitUnstage(p) => Some(&p.mutation.context),
        RpcCall::GitCommit(p) => Some(&p.mutation.context),
        RpcCall::GitFetch(p) | RpcCall::GitPush(p) => Some(&p.mutation.context),
        RpcCall::GitPull(p) => Some(&p.mutation.context),
        _ => None,
    }
}

fn operation_control_context_matches(binding: &Binding, request: &RpcRequest) -> bool {
    let Some(context) = operation_control_context(&request.call) else {
        return false;
    };
    let grant = &binding.context.grant;
    binding.context.purpose == ChannelPurposeV3::Workspace
        && request.call.validate().is_ok()
        && binding.workspace_matches(context)
        && context.workspace_id.to_bytes() == grant.workspace_id
        && context.workspace_epoch.to_bytes() == grant.workspace_epoch
        && context.runtime_id.to_bytes() == grant.runtime_id
        && context.runtime_generation.0 == grant.runtime_generation
        && context.host_access_epoch.0 == grant.access_epoch
        && context.grant_revision.0 == grant.grant_revision
}

impl Binding {
    fn workspace_matches(&self, w: &WorkspaceContext) -> bool {
        let g = &self.context.grant;
        w.workspace_id.to_bytes() == g.workspace_id
            && w.workspace_epoch.to_bytes() == g.workspace_epoch
            && w.runtime_id.to_bytes() == g.runtime_id
            && w.runtime_generation.0 == g.runtime_generation
            && w.host_access_epoch.0 == g.access_epoch
            && w.grant_revision.0 == g.grant_revision
    }
    fn target_live(&self, t: &TerminalContext, f: &OwnerFacts<'_>) -> bool {
        self.workspace_matches(&t.workspace)
            && f.running.iter().any(|r| {
                target_v3(r) == target_v3(t)
                    && r.workspace.workspace_id == f.local.workspace_id
                    && r.workspace.workspace_epoch == f.local.workspace_epoch
            })
            && f.local.running_terminals.as_slice().iter().any(|r| {
                r.pane_id == t.pane_id
                    && r.session_id == t.session_id
                    && r.session_epoch == t.session_epoch
            })
            && f.acknowledged
                .workspaces
                .as_slice()
                .iter()
                .filter(|w| {
                    w.workspace_id.to_bytes() == self.context.grant.workspace_id
                        && w.workspace_epoch.to_bytes() == self.context.grant.workspace_epoch
                })
                .flat_map(|w| w.terminals.as_slice())
                .any(|r| {
                    r.pane_id == t.pane_id
                        && r.session_id == t.session_id
                        && r.session_epoch == t.session_epoch
                })
    }
    fn projected_authority(
        &self,
        current: &CurrentAuthorityV3,
        f: &OwnerFacts<'_>,
    ) -> Result<CurrentAuthorityV3> {
        let mut authority = current.clone();
        match (&self.context.purpose, &self.context.terminal) {
            (ChannelPurposeV3::Workspace, None) if current.terminal_membership.is_none() => {}
            (ChannelPurposeV3::Terminal, Some(target)) => {
                if current
                    .terminal_membership
                    .as_ref()
                    .is_some_and(|membership| membership != target)
                {
                    return Err(GateError::Disposed);
                }
                let selected = f
                    .running
                    .iter()
                    .find(|candidate| {
                        target_v3(candidate) == *target && self.target_live(candidate, f)
                    })
                    .ok_or(GateError::Disposed)?;
                // The signed channel target is accepted only after matching a
                // real current TerminalContext in all three owner snapshots.
                // Preserve an already-current exact membership; fill only the
                // fresh-pairing GET's intentionally absent membership.
                authority.terminal_membership = Some(target_v3(selected));
            }
            _ => return Err(GateError::Disposed),
        }
        Ok(authority)
    }
    fn peer_proof(
        &self,
        read: PeerRead<'_>,
        f: &OwnerFacts<'_>,
        now: TrustedNow,
        wall: Duration,
    ) -> Result<PeerProof> {
        let g = &self.context.grant;
        let authority = self
            .projected_authority(read.authority, f)
            .map_err(|error| error)?;
        if read.origin != &self.origin
            || read.signed_grant != &self.signed_grant
            || read.consumer_window.to_bytes() != g.consumer_id
            || read.consumer_pin != g.consumer_fingerprint
            || read.request_started > now.monotonic
            || read.request_started < read.original_heartbeat.request_started
            || read.wall_at_request_start < read.original_heartbeat.wall_at_request_start
            || read.wall_at_request_start > wall.as_secs()
            || !heartbeat_live(read.original_heartbeat, self, now, wall)
            || read.authority_expires_at == 0
            || read.authority_expires_at > i64::MAX as u64
            || wall >= Duration::from_secs(read.authority_expires_at)
        {
            return Err(GateError::Disposed);
        }
        let host = checked(SignedBundle::from_wire(&self.host.identity))?;
        let consumer = checked(verify_consumer_window_identity(
            read.consumer_identity,
            g.account_id,
            g.consumer_id,
        ))?;
        checked(consumer.verify(&read.consumer_pin))?;
        checked(read.signed_grant.verify(
            g,
            &host,
            &self.host.fingerprint,
            &consumer,
            &read.consumer_pin,
            &authority,
            wall.as_secs(),
        ))?;
        let valid_until = deadline(read.request_started, 5_000)?
            .min(deadline(
                read.original_heartbeat.request_started,
                read.original_heartbeat.freshness_ms,
            )?)
            .min(deadline(
                read.original_heartbeat.request_started,
                read.original_heartbeat.lease_ms,
            )?);
        if now.monotonic >= valid_until {
            return Err(GateError::Disposed);
        }
        Ok(PeerProof {
            consumer,
            pin: read.consumer_pin,
            authority,
            started: read.request_started,
            valid_until,
            authority_expires_at: Duration::from_secs(read.authority_expires_at),
        })
    }
}
impl GateCore {
    // Private only. Production callers cannot use this as a completed-handshake
    // constructor.
    fn new(
        canonical: &[u8],
        grant: &SignedGrantV3,
        admission: &SignedChannelAdmissionV3,
        read: PeerRead<'_>,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<Self> {
        let context = checked(ChannelContextV3::from_canonical(canonical))?;
        if context.canonical().map_err(|_| GateError::Disposed)? != canonical
            || context.grant != grant.grant
            || f.protected_host.account_id.to_bytes() != context.grant.account_id
            || f.protected_host.host_id.to_bytes() != context.grant.host_id
            || f.protected_host.fingerprint != context.grant.host_fingerprint
            || f.protected_host.host_authorization_id.to_bytes()
                != context.grant.host_authorization_id
            || f.protected_host.access_epoch != context.grant.access_epoch
        {
            return Err(GateError::Disposed);
        }
        let now = sample();
        let mut clock = Clock::new(now)?;
        let wall = clock.observe(now)?;
        let binding = Binding {
            actor: ConsumerAuthorizationId::from_bytes(context.grant.consumer_authorization_id)
                .map_err(|_| GateError::Disposed)?,
            context,

            signed_grant: grant.clone(),
            host: f.protected_host.clone(),
            origin: f.origin.clone(),
            scope: f.scope.clone(),
            fence: f.local.fence,
        };
        let peer = binding.peer_proof(read, f, now, wall)?;
        if Duration::from_secs(binding.context.expires_at) > peer.authority_expires_at {
            return Err(GateError::Disposed);
        }
        let host = checked(SignedBundle::from_wire(&binding.host.identity))?;
        checked(admission.verify(
            grant,
            &binding.context,
            &host,
            &binding.host.fingerprint,
            &peer.consumer,
            &peer.pin,
            &peer.authority,
            wall.as_secs(),
        ))?;
        let mut core = Self {
            binding,
            peer,
            clock,
            disposed: false,
            connection: uuid::Uuid::new_v4(),
            sequence: 0,
            pending: None,
        };
        core.live(f, sample)?;
        core.admission_live(sample())?;
        Ok(core)
    }
    fn poison<T>(&mut self) -> Result<T> {
        self.disposed = true;
        self.pending = None;
        Err(GateError::Disposed)
    }
    fn admission_live(&mut self, now: TrustedNow) -> Result<()> {
        if self.disposed {
            return Err(GateError::Disposed);
        }
        let wall = match self.clock.observe(now) {
            Ok(w) => w,
            Err(_) => return self.poison(),
        };
        if wall < Duration::from_secs(self.binding.context.issued_at)
            || wall >= Duration::from_secs(self.binding.context.expires_at)
        {
            return self.poison();
        }
        Ok(())
    }
    fn live_once(&mut self, f: &OwnerFacts<'_>, now: TrustedNow) -> Result<()> {
        self.live_once_inner(f, now, None, None)
    }
    fn live_once_inner(
        &mut self,
        f: &OwnerFacts<'_>,
        now: TrustedNow,
        receipt: Option<&dyn PublicationReceiptProof>,
        started_git_terminal: Option<&StartedGitTerminalPermit<'_>>,
    ) -> Result<()> {
        if self.disposed {
            return Err(GateError::Disposed);
        }
        let wall = match self.clock.observe(now) {
            Ok(w) => w,
            Err(_) => return self.poison(),
        };
        let b = &self.binding;
        let g = &b.context.grant;
        let started_git_receipt =
            receipt.is_some_and(|proof| proof.started_git_current_for(self.connection));
        let started_git_terminal = started_git_terminal.is_some_and(|proof| {
            proof
                .observation
                .current_for(proof.active, proof.operation, self.connection)
                && proof.observation.target.context == self.binding.context
                && proof.observation.target.signed_grant == self.binding.signed_grant
                && proof.observation.target.authority == self.peer.authority
                && proof.observation.target.origin == self.binding.origin
                && proof.observation.target.scope == self.binding.scope
        });
        let ceiling = f
            .local
            .capability_ceiling
            .clone()
            .unwrap_or_else(CapabilitySet::control_with_workspace_tools);
        if f.peer_revoked
            || !f.auth_ready
            || f.authorization_locked
            || f.pending_login
            || f.pending_logout
            || f.pending_revoke
            || (f.pending_publication && !receipt.is_some_and(|r| r.current_for(self.connection)))
            || f.gate_denied.load(Ordering::Acquire)
            || f.paused.load(Ordering::Acquire)
            || f.stopping.load(Ordering::Acquire)
            || f.cancelled.load(Ordering::Acquire)
            || wall >= Duration::from_secs(f.access_expires_at)
            || wall >= Duration::from_secs(f.refresh_at)
            || wall >= Duration::from_secs(g.expires_at)
            || wall >= self.peer.authority_expires_at
            || (!started_git_receipt
                && !started_git_terminal
                && now.monotonic >= self.peer.valid_until)
            || now.monotonic < self.peer.started
            || f.protected_host != &b.host
            || f.origin != &b.origin
            || f.scope != &b.scope
            || f.scope.remote_api_origin != f.origin.as_str()
            || f.scope.host_id != b.host.host_id
            || f.scope.owner_generation == 0
            || f.scope.owner_generation > i64::MAX as u64
            || f.scope.authorization_generation > i64::MAX as u64
            || g.access_epoch > i64::MAX as u64
            || g.grant_revision > i64::MAX as u64
            || g.runtime_generation > i64::MAX as u64
            || g.expires_at > i64::MAX as u64
            || f.access_expires_at > i64::MAX as u64
            || f.refresh_at > i64::MAX as u64
            || f.scope.owner_runtime_id.to_bytes() != g.runtime_id
            || f.runtime.runtime_id.to_bytes() != g.runtime_id
            || f.runtime.runtime_generation.0 != g.runtime_generation
            || f.runtime.host_access_epoch.0 != g.access_epoch
            || (!started_git_receipt
                && !started_git_terminal
                && !heartbeat_live(f.heartbeat, b, now, wall))
            || f.acknowledged.state.scope != *f.scope
            || f.acknowledged.state.server_runtime != *f.runtime
            || f.acknowledged.state.acknowledged_publication_seq.0 == 0
            || !f.local.consent
            || f.local.fence != b.fence
            || f.local.fence == 0
            || f.local.workspace_id.to_bytes() != g.workspace_id
            || f.local.workspace_epoch.to_bytes() != g.workspace_epoch
            || !f.acknowledged.workspaces.as_slice().iter().any(|w| {
                w.workspace_id == f.local.workspace_id
                    && w.workspace_epoch == f.local.workspace_epoch
            })
            || Vec::<Capability>::from(g.capabilities.clone())
                .iter()
                .any(|c| !ceiling.contains(*c))
        {
            return self.poison();
        }
        if let Some(target) = &b.context.terminal
            && (self.peer.authority.terminal_membership.as_ref() != Some(target)
                || !f
                    .running
                    .iter()
                    .any(|t| target_v3(t) == *target && b.target_live(t, f)))
        {
            return self.poison();
        }
        // Deliberately no context.expires_at check for an established connection.
        Ok(())
    }
    fn live(&mut self, f: &OwnerFacts<'_>, sample: &mut dyn FnMut() -> TrustedNow) -> Result<()> {
        self.live_once(f, sample())?;
        self.live_once(f, sample())
    }
    fn refresh(
        &mut self,
        read: PeerRead<'_>,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<()> {
        self.live(f, sample)?; // An expired old observation is permanent loss, never revived.
        if read.request_started <= self.peer.started {
            return Err(GateError::Denied);
        }
        let now = sample();
        let wall = match self.clock.observe(now) {
            Ok(w) => w,
            Err(_) => return self.poison(),
        };
        let next = match self.binding.peer_proof(read, f, now, wall) {
            Ok(p) => p,
            Err(_) => return self.poison(),
        };
        // Crypto/owner validation time is charged to BOTH old and new observations.
        self.live(f, sample)?;
        let finished = sample();
        self.live_once(f, finished)?;
        let effective = match self.clock.observe(finished) {
            Ok(w) => w,
            Err(_) => return self.poison(),
        };
        if finished.monotonic >= next.valid_until || effective >= next.authority_expires_at {
            return self.poison();
        }
        self.peer = next;
        self.live(f, sample)
    }
    fn request_allowed(&self, call: &RpcCall, f: &OwnerFacts<'_>) -> bool {
        if call.validate().is_err() {
            return false;
        }
        let target = match call {
            RpcCall::WorkspaceGet(p) | RpcCall::WorkspaceCapabilities(p) => {
                Some((&p.context, None))
            }
            RpcCall::WorkspaceSubscribe(p) => Some((&p.context, None)),
            RpcCall::FilesList(p) => Some((&p.context, None)),
            RpcCall::FilesStat(p) => Some((&p.context, None)),
            RpcCall::FilesRead(p) => Some((&p.context, None)),
            RpcCall::FilesSearchNames(p) => Some((&p.context, None)),
            RpcCall::FilesWatch(p) => Some((&p.context, None)),
            RpcCall::GitRepositories(p) => Some((&p.context, None)),
            RpcCall::GitStatus(p) => Some((&p.context, None)),
            RpcCall::GitDiff(p) => Some((&p.context, None)),
            RpcCall::GitLog(p) => Some((&p.context, None)),
            RpcCall::GitShow(p) => Some((&p.context, None)),
            RpcCall::GitStage(p) => Some((&p.mutation.context, None)),
            RpcCall::GitUnstage(p) => Some((&p.mutation.context, None)),
            RpcCall::GitCommit(p) => Some((&p.mutation.context, None)),
            RpcCall::GitFetch(p) | RpcCall::GitPush(p) => Some((&p.mutation.context, None)),
            RpcCall::GitPull(p) => Some((&p.mutation.context, None)),
            RpcCall::FilesCreate(p) | RpcCall::FilesMkdir(p) => Some((&p.mutation.context, None)),
            RpcCall::FilesRename(p) => Some((&p.mutation.context, None)),
            RpcCall::FilesRemove(p) => Some((&p.mutation.context, None)),
            RpcCall::TerminalRename(p) => Some((&p.mutation.context, None)),
            RpcCall::TerminalMove(p) => Some((&p.mutation.context, None)),
            RpcCall::TerminalCreate(p) => Some((&p.mutation.context, None)),
            RpcCall::TerminalSplit(p) => Some((&p.mutation.context, None)),
            RpcCall::TerminalAttach(p) | RpcCall::TerminalSnapshot(p) => {
                Some((&p.terminal.workspace, Some(&p.terminal)))
            }
            RpcCall::TerminalAck(p) => Some((&p.terminal.workspace, Some(&p.terminal))),
            RpcCall::TerminalClaim(p) => Some((&p.terminal.workspace, Some(&p.terminal))),
            RpcCall::TerminalRenew(p) | RpcCall::TerminalRelease(p) => {
                Some((&p.terminal.workspace, Some(&p.terminal)))
            }
            RpcCall::TerminalInput(p) => Some((&p.terminal.workspace, Some(&p.terminal))),
            RpcCall::TerminalResize(p) => Some((&p.terminal.workspace, Some(&p.terminal))),
            // Close/Restart on a workspace channel are workspace-scoped mutations
            // like rename/move: the signed mutation context binds the workspace
            // and terminal.manage is the authority. `expected_session` is only a
            // compare-and-set token that the plan checks against the stored
            // descriptor. It must NOT require a still-live target there: an exact
            // retry after reconnect must reach duplicate lookup and read back its
            // durable receipt even though the target is already gone. A
            // terminal-scoped channel keeps the strict live-target requirement.
            RpcCall::TerminalClose(p) => {
                match (self.binding.context.purpose, &p.expected_session) {
                    (ChannelPurposeV3::Workspace, _) | (_, None) => {
                        Some((&p.mutation.context, None))
                    }
                    (_, Some(t)) => Some((&t.workspace, Some(t))),
                }
            }
            RpcCall::TerminalRestart(p) => {
                match (self.binding.context.purpose, &p.expected_session) {
                    (ChannelPurposeV3::Workspace, _) | (_, None) => {
                        Some((&p.mutation.context, None))
                    }
                    (_, Some(t)) => Some((&t.workspace, Some(t))),
                }
            }
            // No lifecycle target invention, stored-operation static fallback,
            // repository-execution consent inference or capability advertisement.
            _ => None,
        };
        let Some((workspace, terminal)) = target else {
            return false;
        };
        if !self.binding.workspace_matches(workspace) {
            return false;
        }
        match (self.binding.context.purpose, terminal) {
            (ChannelPurposeV3::Workspace, None) => (),
            (_, Some(t))
                if self.binding.target_live(t, f)
                    && self
                        .binding
                        .context
                        .terminal
                        .as_ref()
                        .is_none_or(|expected| *expected == target_v3(t)) => {}
            _ => return false,
        }
        match call.method().rights() {
            MethodRights::Static(rights) => rights
                .iter()
                .all(|c| self.binding.context.grant.capabilities.contains(*c)),
            MethodRights::StoredOperationRights => false,
        }
    }
    fn evaluate(
        &mut self,
        call: &RpcCall,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<()> {
        self.live(f, sample)?;
        let allowed = self.request_allowed(call, f);
        self.live(f, sample)?;
        if allowed {
            Ok(())
        } else {
            Err(GateError::Denied)
        }
    }
    fn live_started_git_terminal(
        &mut self,
        f: &OwnerFacts<'_>,
        sample: &mut (impl FnMut() -> TrustedNow + ?Sized),
        active: &super::shared_owner::StartedGitContinuation,
        observation: &super::peer::StartedGitPeerObservation,
        operation: &Operation<'_>,
    ) -> Result<()> {
        let permit = StartedGitTerminalPermit {
            active,
            observation,
            operation,
        };
        let live = self.live_once_inner(f, sample(), None, Some(&permit));
        live?;
        let live = self.live_once_inner(f, sample(), None, Some(&permit));
        live
    }
    fn evaluate_started_git_terminal(
        &mut self,
        call: &RpcCall,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
        active: &super::shared_owner::StartedGitContinuation,
        observation: &super::peer::StartedGitPeerObservation,
        operation: &Operation<'_>,
    ) -> Result<()> {
        self.live_started_git_terminal(f, sample, active, observation, operation)?;
        let allowed = self.request_allowed(call, f);
        self.live_started_git_terminal(f, sample, active, observation, operation)?;
        if allowed {
            Ok(())
        } else {
            Err(GateError::Denied)
        }
    }
    fn validate_queued_started_git_terminal(
        &mut self,
        queued: &QueuedRequest,
        operation: &Operation<'_>,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
        active: &super::shared_owner::StartedGitContinuation,
        observation: &super::peer::StartedGitPeerObservation,
    ) -> Result<RpcRequest> {
        if self.disposed {
            return Err(GateError::Disposed);
        }
        if queued.connection != self.connection
            || self.pending != Some(queued.sequence)
            || !operation.is_same_admission(&queued.operation)
        {
            return Err(GateError::Denied);
        }
        self.evaluate_started_git_terminal(
            &queued.request.call,
            f,
            sample,
            active,
            observation,
            operation,
        )?;
        self.live_started_git_terminal(f, sample, active, observation, operation)?;
        let finished = sample();
        self.live_once_inner(
            f,
            finished,
            None,
            Some(&StartedGitTerminalPermit {
                active,
                observation,
                operation,
            }),
        )?;
        operation.check().map_err(|_| GateError::Denied)?;
        if finished.monotonic >= queued.deadline || finished.monotonic >= operation.deadline() {
            return Err(GateError::Denied);
        }
        Ok(queued.request.clone())
    }
    fn queue_started_git_terminal(
        &mut self,
        request: &RpcRequest,
        request_deadline: Instant,
        operation: &Operation<'_>,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
        active: &super::shared_owner::StartedGitContinuation,
        observation: &super::peer::StartedGitPeerObservation,
    ) -> Result<QueuedRequest> {
        operation.check().map_err(|_| GateError::Denied)?;
        let started = sample();
        self.live_started_git_terminal(f, sample, active, observation, operation)?;
        if started.monotonic >= request_deadline {
            return Err(GateError::Denied);
        }
        self.evaluate_started_git_terminal(
            &request.call,
            f,
            sample,
            active,
            observation,
            operation,
        )?;
        operation.check().map_err(|_| GateError::Denied)?;
        if self.pending.is_some() {
            return Err(GateError::Busy);
        }
        let deadline = operation.deadline().min(request_deadline);
        let finished = sample();
        self.live_once_inner(
            f,
            finished,
            None,
            Some(&StartedGitTerminalPermit {
                active,
                observation,
                operation,
            }),
        )?;
        operation.check().map_err(|_| GateError::Denied)?;
        if finished.monotonic >= deadline {
            return Err(GateError::Denied);
        }
        self.sequence = match self.sequence.checked_add(1) {
            Some(sequence) => sequence,
            None => return self.poison(),
        };
        self.pending = Some(self.sequence);
        Ok(QueuedRequest {
            request: request.clone(),
            operation: operation.retained_identity(),
            connection: self.connection,
            sequence: self.sequence,
            deadline,
        })
    }
    fn queue(
        &mut self,
        request: &RpcRequest,
        operation: &Operation<'_>,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<QueuedRequest> {
        operation.check().map_err(|_| GateError::Denied)?;
        let started = sample();
        self.live_once(f, started)?;
        let request_deadline = match deadline(started.monotonic, request.timeout_ms.get()) {
            Ok(d) => d,
            Err(_) => return self.poison(),
        };
        // The ingress owner caps its logical Operation before evidence capture.
        // Retain both bounds without requiring mutable access through evidence.
        self.evaluate(&request.call, f, sample)?;
        operation.check().map_err(|_| GateError::Denied)?;
        if self.pending.is_some() {
            return Err(GateError::Busy);
        }
        let deadline = operation.deadline().min(request_deadline);
        let finished = sample();
        self.live_once(f, finished)?;
        operation.check().map_err(|_| GateError::Denied)?;
        if finished.monotonic >= deadline {
            return Err(GateError::Denied);
        }
        self.sequence = match self.sequence.checked_add(1) {
            Some(s) => s,
            None => return self.poison(),
        };
        self.pending = Some(self.sequence);
        Ok(QueuedRequest {
            request: request.clone(),
            operation: operation.retained_identity(),
            connection: self.connection,
            sequence: self.sequence,
            deadline,
        })
    }
    fn queue_operation_control(
        &mut self,
        request: &RpcRequest,
        operation: &Operation<'_>,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<QueuedRequest> {
        operation.check().map_err(|_| GateError::Denied)?;
        let started = sample();
        self.live_once(f, started)?;
        if !operation_control_context_matches(&self.binding, request)
            || !self
                .binding
                .context
                .grant
                .capabilities
                .contains(Capability::WorkspaceRead)
        {
            return Err(GateError::Denied);
        }
        let request_deadline =
            deadline(started.monotonic, request.timeout_ms.get()).map_err(|_| GateError::Denied)?;
        self.live(f, sample)?;
        operation.check().map_err(|_| GateError::Denied)?;
        if self.pending.is_some() {
            return Err(GateError::Busy);
        }
        let deadline = operation.deadline().min(request_deadline);
        let finished = sample();
        self.live_once(f, finished)?;
        operation.check().map_err(|_| GateError::Denied)?;
        if finished.monotonic >= deadline {
            return Err(GateError::Denied);
        }
        self.sequence = self.sequence.checked_add(1).ok_or(GateError::Disposed)?;
        self.pending = Some(self.sequence);
        Ok(QueuedRequest {
            request: request.clone(),
            operation: operation.retained_identity(),
            connection: self.connection,
            sequence: self.sequence,
            deadline,
        })
    }
    fn validate_queued_operation_control(
        &mut self,
        queued: &QueuedRequest,
        operation: &Operation<'_>,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
        authorization: Option<&super::super::remote_operations::RemoteOperationAuthorization>,
    ) -> Result<RpcRequest> {
        if self.disposed {
            return Err(GateError::Disposed);
        }
        if queued.connection != self.connection
            || self.pending != Some(queued.sequence)
            || !operation.is_same_admission(&queued.operation)
        {
            return Err(GateError::Denied);
        }
        let result = (|| {
            self.live(f, sample)?;
            if !operation_control_context_matches(&self.binding, &queued.request)
                || !self
                    .binding
                    .context
                    .grant
                    .capabilities
                    .contains(Capability::WorkspaceRead)
            {
                return Err(GateError::Denied);
            }
            if let Some(authorization) = authorization
                && !operation_control_context(&queued.request.call).is_some_and(|context| {
                    authorization.allows(
                        &queued.request,
                        context,
                        self.binding.actor,
                        &self.binding.context.grant.capabilities,
                        self.connection,
                        Some(queued.sequence),
                    )
                })
            {
                return Err(GateError::Denied);
            }
            let finished = sample();
            self.live_once(f, finished)?;
            operation.check().map_err(|_| GateError::Denied)?;
            if finished.monotonic >= queued.deadline {
                return Err(GateError::Denied);
            }
            Ok(queued.request.clone())
        })();
        if !matches!(&result, Err(GateError::Busy)) {
            self.pending = None;
        }
        result
    }
    fn cached_operation_control_response(
        &mut self,
        original: &RpcRequest,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
        authorization: Option<&super::super::remote_operations::RemoteOperationAuthorization>,
    ) -> Result<()> {
        self.live(f, sample)?;
        if !operation_control_context_matches(&self.binding, original)
            || !self
                .binding
                .context
                .grant
                .capabilities
                .contains(Capability::WorkspaceRead)
            || authorization.is_some_and(|authorization| {
                !operation_control_context(&original.call).is_some_and(|context| {
                    authorization.allows(
                        original,
                        context,
                        self.binding.actor,
                        &self.binding.context.grant.capabilities,
                        self.connection,
                        None,
                    )
                })
            })
        {
            return Err(GateError::Denied);
        }
        let now = sample();
        self.live_once(f, now)?;
        Ok(())
    }
    fn cached_git_receipt_response(
        &mut self,
        original: &RpcRequest,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
        disclosure: &super::super::shared_owner::GitReceiptDisclosure,
    ) -> Result<()> {
        self.live(f, sample)?;
        let allowed = git_receipt_context(&original.call).is_some_and(|context| {
            self.binding.context.purpose == ChannelPurposeV3::Workspace
                && self.binding.context.terminal.is_none()
                && original.call.validate().is_ok()
                && self.binding.workspace_matches(context)
                && context == disclosure.context()
                && disclosure.allows(
                    original,
                    self.binding.actor,
                    &self.binding.context.grant.capabilities,
                    self.connection,
                )
        });
        self.live(f, sample)?;
        if allowed {
            Ok(())
        } else {
            Err(GateError::Denied)
        }
    }
    fn cached_operation_control_started_git_response(
        &mut self,
        original: &RpcRequest,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
        active: &super::shared_owner::StartedGitContinuation,
        observation: &super::peer::StartedGitPeerObservation,
        operation: &Operation<'_>,
        authorization: Option<&super::super::remote_operations::RemoteOperationAuthorization>,
    ) -> Result<()> {
        self.live_started_git_terminal(f, sample, active, observation, operation)?;
        if !operation_control_context_matches(&self.binding, original)
            || !self
                .binding
                .context
                .grant
                .capabilities
                .contains(Capability::WorkspaceRead)
            || authorization.is_some_and(|authorization| {
                !operation_control_context(&original.call).is_some_and(|context| {
                    authorization.allows(
                        original,
                        context,
                        self.binding.actor,
                        &self.binding.context.grant.capabilities,
                        self.connection,
                        None,
                    )
                })
            })
        {
            return Err(GateError::Denied);
        }
        self.live_started_git_terminal(f, sample, active, observation, operation)
    }
    fn cached_git_receipt_started_git_response(
        &mut self,
        original: &RpcRequest,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
        active: &super::shared_owner::StartedGitContinuation,
        observation: &super::peer::StartedGitPeerObservation,
        operation: &Operation<'_>,
        disclosure: &super::shared_owner::GitReceiptDisclosure,
    ) -> Result<()> {
        self.live_started_git_terminal(f, sample, active, observation, operation)?;
        let allowed = git_receipt_context(&original.call).is_some_and(|context| {
            self.binding.context.purpose == ChannelPurposeV3::Workspace
                && self.binding.context.terminal.is_none()
                && original.call.validate().is_ok()
                && self.binding.workspace_matches(context)
                && context == disclosure.context()
                && disclosure.allows(
                    original,
                    self.binding.actor,
                    &self.binding.context.grant.capabilities,
                    self.connection,
                )
        });
        self.live_started_git_terminal(f, sample, active, observation, operation)?;
        if allowed {
            Ok(())
        } else {
            Err(GateError::Denied)
        }
    }
    fn after_wait(
        &mut self,
        queued: &QueuedRequest,
        operation: &Operation<'_>,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<RpcRequest> {
        let result = self.validate_queued(queued, operation, f, sample);
        // A contention result never consumes the caller-owned request or ticket.
        if !matches!(&result, Err(GateError::Busy)) {
            self.pending = None;
        }
        result
    }
    /// Revalidate queued request data without consuming its one-shot ticket.
    /// This is used while a bounded Git preparation job runs. The result is
    /// request data only; callers must consume the same ticket with
    /// `after_wait` immediately before journal admission.
    fn peek_after_wait(
        &mut self,
        queued: &QueuedRequest,
        operation: &Operation<'_>,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<RpcRequest> {
        let result = self.validate_queued(queued, operation, f, sample);
        // Preserve the ticket on a successful peek. A stale/denied/deadline
        // result cannot leave a reusable pending request behind.
        if let Err(error) = &result
            && *error != GateError::Busy
        {
            self.pending = None;
        }
        result
    }
    fn validate_queued(
        &mut self,
        queued: &QueuedRequest,
        operation: &Operation<'_>,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<RpcRequest> {
        if self.disposed {
            return Err(GateError::Disposed);
        }
        if queued.connection != self.connection
            || self.pending != Some(queued.sequence)
            || !operation.is_same_admission(&queued.operation)
        {
            return Err(GateError::Denied);
        }
        let result = (|| {
            self.evaluate(&queued.request.call, f, sample)?;
            self.live(f, sample)?;
            let finished = sample();
            self.live_once(f, finished)?;
            operation.check().map_err(|_| GateError::Denied)?;
            if finished.monotonic >= queued.deadline || finished.monotonic >= operation.deadline() {
                return Err(GateError::Denied);
            }
            Ok(queued.request.clone()) // Request DATA, not reusable authority or an effect.
        })();
        result
    }
}

/// One bounded outstanding request. No Clone, Deserialize, rights field or public constructor.
pub(in super::super) struct QueuedRequest {
    request: RpcRequest,
    operation: OperationIdentity,
    connection: uuid::Uuid,
    sequence: u64,
    deadline: Instant,
}
impl QueuedRequest {
    pub(in super::super) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(in crate::unix) fn sequence(&self) -> u64 {
        self.sequence
    }
    pub(in crate::unix) fn connection_identity(&self) -> uuid::Uuid {
        self.connection
    }
}
pub(in super::super) struct AdmissionInputs<'a> {
    pub(in super::super) canonical_context: &'a [u8],
    pub(in super::super) signed_grant: &'a SignedGrantV3,
    pub(in super::super) admission: &'a SignedChannelAdmissionV3,
    pub(in super::super) peer: PeerRead<'a>,
}
/// Sealed ownership chain: only this wrapper can finish its own HostAuth responder.
pub(in super::super) struct PendingRemoteConnection {
    core: GateCore,
    handshake: Option<HostResponderHandshakeV3>,
}
impl PendingRemoteConnection {
    pub(in super::super) fn dispose(&mut self) {
        self.core.disposed = true;
        if let Some(handshake) = &mut self.handshake {
            handshake.dispose();
        }
        self.handshake = None;
    }

    pub(in super::super) fn begin<S: SecretStorage + ?Sized>(
        auth: &HostAuth<'_, S>,
        input: AdmissionInputs<'_>,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<Self> {
        let mut core = GateCore::new(
            input.canonical_context,
            input.signed_grant,
            input.admission,
            input.peer,
            f,
            sample,
        )?;
        let now = sample();
        core.live_once(f, now)?;
        let effective = core.clock.observe(now)?;
        if auth
            .public_host_identity(effective.as_secs())
            .map_err(|_| GateError::Disposed)?
            != core.binding.host
        {
            return Err(GateError::Disposed);
        }
        let handshake = auth
            .start_host_channel_v3(HostChannelAdmissionV3 {
                expected: &core.binding.context,
                stored_grant: &core.binding.signed_grant,
                admission: input.admission,
                consumer_identity: &core.peer.consumer,
                consumer_fingerprint: &core.peer.pin,
                current_authority: &core.peer.authority,
            })
            .map_err(|_| GateError::Disposed)?;
        let mut pending = Self {
            core,
            handshake: Some(handshake),
        };
        pending.check(f, sample)?;
        Ok(pending)
    }
    fn check(&mut self, f: &OwnerFacts<'_>, sample: &mut impl FnMut() -> TrustedNow) -> Result<()> {
        let result = self
            .core
            .live(f, sample)
            .and_then(|_| self.core.admission_live(sample()));
        if result.is_err() {
            self.core.disposed = true;
            if let Some(h) = &mut self.handshake {
                h.dispose();
            }
        }
        result
    }
    pub(in super::super) fn read(
        &mut self,
        bytes: &[u8],
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<()> {
        self.check(f, sample)?;
        let result = self
            .handshake
            .as_mut()
            .ok_or(GateError::Disposed)?
            .read(bytes);
        if result.is_err() {
            self.core.disposed = true;
            self.handshake.take();
            return Err(GateError::Disposed);
        }
        self.check(f, sample)
    }
    pub(in super::super) fn write(
        &mut self,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<Vec<u8>> {
        self.check(f, sample)?;
        let result = self.handshake.as_mut().ok_or(GateError::Disposed)?.write();
        let bytes = match result {
            Ok(bytes) => bytes,
            Err(_) => {
                self.core.disposed = true;
                self.handshake.take();
                return Err(GateError::Disposed);
            }
        };
        self.check(f, sample)?;
        Ok(bytes)
    }
    pub(in super::super) fn finish(
        mut self,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<RemoteConnectionState> {
        self.check(f, sample)?;
        let channel = self
            .handshake
            .take()
            .ok_or(GateError::Disposed)?
            .finish()
            .map_err(|_| GateError::Disposed)?;
        self.check(f, sample)?;
        Ok(RemoteConnectionState {
            core: self.core,
            completed_channel: channel,
        })
    }
}
/// No public constructor or transport IO entrypoint in this unwired slice.
/// A PolicySnapshot, Store ACK or arbitrary completed channel cannot construct it.
pub(in super::super) struct RemoteConnectionState {
    core: GateCore,
    completed_channel: HostChannelV3,
}
impl RemoteConnectionState {
    fn finish_gate<T>(&mut self, result: Result<T>) -> Result<T> {
        if self.core.disposed {
            self.completed_channel.dispose();
        }
        result
    }
    /// Authenticate one bounded encrypted frame with live gates on both sides.
    /// The opaque result preserves HostChannelV3's zeroizing plaintext ownership.
    pub(in super::super) fn open_frame(
        &mut self,
        frame: &[u8],
        f: &OwnerFacts<'_>,
        sample: &mut dyn FnMut() -> TrustedNow,
    ) -> Result<impl AsRef<[u8]> + use<>> {
        use lomi_remote_protocol::message_framing::{
            MAX_PLAINTEXT_FRAME_LEN, MAX_TRANSPORT_FRAME_LEN,
        };
        // Reject the input bound before the crypto parser can allocate plaintext.
        if frame.len() > MAX_TRANSPORT_FRAME_LEN {
            self.dispose();
            return Err(GateError::Disposed);
        }
        let result = self.core.live(f, sample);
        self.finish_gate(result)?;
        let plaintext = match self.completed_channel.open(frame) {
            Ok(value) => value,
            Err(_) => {
                self.dispose();
                return Err(GateError::Disposed);
            }
        };
        if plaintext.len() > MAX_PLAINTEXT_FRAME_LEN {
            self.dispose();
            return Err(GateError::Disposed);
        }
        let result = self.core.live(f, sample);
        self.finish_gate(result)?;
        Ok(plaintext)
    }
    /// Seal only a bounded frame that survives the post-crypto live check.
    pub(in super::super) fn seal_frame(
        &mut self,
        plaintext: &[u8],
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<Vec<u8>> {
        use lomi_remote_protocol::message_framing::{
            MAX_PLAINTEXT_FRAME_LEN, MAX_TRANSPORT_FRAME_LEN,
        };
        if plaintext.len() > MAX_PLAINTEXT_FRAME_LEN {
            self.dispose();
            return Err(GateError::Disposed);
        }
        let result = self.core.live(f, sample);
        self.finish_gate(result)?;
        let frame = match self.completed_channel.seal(plaintext) {
            Ok(value) => value,
            Err(_) => {
                self.dispose();
                return Err(GateError::Disposed);
            }
        };
        if frame.len() > MAX_TRANSPORT_FRAME_LEN {
            self.dispose();
            return Err(GateError::Disposed);
        }
        let result = self.core.live(f, sample);
        self.finish_gate(result)?;
        Ok(frame)
    }
    pub(in super::super) fn is_workspace_channel(&self) -> bool {
        !self.core.disposed && self.core.binding.context.purpose == ChannelPurposeV3::Workspace
    }
    pub(in super::super) fn active_rpc_purpose(context: &ChannelContextV3) -> bool {
        matches!(
            (&context.purpose, &context.terminal),
            (ChannelPurposeV3::Workspace, None) | (ChannelPurposeV3::Terminal, Some(_))
        )
    }
    pub(in super::super) fn supports_active_rpc_purpose(&self) -> bool {
        if self.core.disposed {
            return false;
        }
        match (
            &self.core.binding.context.purpose,
            &self.core.binding.context.terminal,
            &self.core.peer.authority.terminal_membership,
        ) {
            (ChannelPurposeV3::Workspace, None, None) => true,
            (ChannelPurposeV3::Terminal, Some(expected), Some(current)) => expected == current,
            _ => false,
        }
    }
    pub(in super::super) fn connection_identity(&self) -> uuid::Uuid {
        self.core.connection
    }
    pub(in super::super) fn consumer_actor(&self) -> ConsumerAuthorizationId {
        self.core.binding.actor
    }

    pub(in super::super) fn refresh_peer(
        &mut self,
        read: PeerRead<'_>,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<()> {
        let result = self.core.refresh(read, f, sample);
        self.finish_gate(result)
    }
    pub(in super::super) fn before_queue(
        &mut self,
        request: &RpcRequest,
        operation: &Operation<'_>,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<QueuedRequest> {
        let result = self.core.queue(request, operation, f, sample);
        self.finish_gate(result)
    }
    pub(in super::super) fn before_operation_queue(
        &mut self,
        request: &RpcRequest,
        operation: &Operation<'_>,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<QueuedRequest> {
        let result = self
            .core
            .queue_operation_control(request, operation, f, sample);
        self.finish_gate(result)
    }
    /// Call after domain/lock wait immediately before the effect, under the owner
    /// lock-order contract. This returns only the original request, not authority.
    pub(in super::super) fn after_wait(
        &mut self,
        queued: &QueuedRequest,
        operation: &Operation<'_>,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<RpcRequest> {
        let result = self.core.after_wait(queued, operation, f, sample);
        self.finish_gate(result)
    }
    pub(in super::super) fn after_operation_wait(
        &mut self,
        queued: &QueuedRequest,
        operation: &Operation<'_>,
        authorization: Option<&super::super::remote_operations::RemoteOperationAuthorization>,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<RpcRequest> {
        let result = self.core.validate_queued_operation_control(
            queued,
            operation,
            f,
            sample,
            authorization,
        );
        self.finish_gate(result)
    }
    /// Revalidate without consuming the queued ticket. Git's heavyweight
    /// preparation runs after this check; callers must run `after_wait` on the
    /// same ticket under fresh owner proof immediately before journal admission.
    pub(in super::super) fn peek_after_wait(
        &mut self,
        queued: &QueuedRequest,
        operation: &Operation<'_>,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<RpcRequest> {
        let result = self.core.peek_after_wait(queued, operation, f, sample);
        self.finish_gate(result)
    }
    /// Return the signed grant's capability ceiling only for the exact gated
    /// workspace.capabilities request after its retained wait has completed.
    /// The owner turn intersects it with implemented services before exposure.
    pub(in super::super) fn workspace_capabilities_after_wait(
        &mut self,
        queued: &QueuedRequest,
        operation: &Operation<'_>,
        expected_workspace: &WorkspaceContext,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<CapabilitySet> {
        let request = self.after_wait(queued, operation, f, sample)?;
        if self.core.binding.context.purpose != ChannelPurposeV3::Workspace
            || !matches!(
                &request.call,
                RpcCall::WorkspaceCapabilities(params) if params.context == *expected_workspace
            )
        {
            self.dispose();
            return Err(GateError::Denied);
        }
        let result = self
            .core
            .live(f, sample)
            .map(|()| self.core.binding.context.grant.capabilities.clone());
        self.finish_gate(result)
    }
    pub(in super::super) fn cached_response(
        &mut self,
        original: &RpcRequest,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<()> {
        let result = self.core.evaluate(&original.call, f, sample);
        self.finish_gate(result)
    }
    pub(in super::super) fn cached_git_receipt_response(
        &mut self,
        original: &RpcRequest,
        disclosure: &super::super::shared_owner::GitReceiptDisclosure,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<()> {
        let result = self
            .core
            .cached_git_receipt_response(original, f, sample, disclosure);
        self.finish_gate(result)
    }
    pub(in super::super) fn cached_operation_response(
        &mut self,
        original: &RpcRequest,
        authorization: Option<&super::super::remote_operations::RemoteOperationAuthorization>,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<()> {
        let result =
            self.core
                .cached_operation_control_response(original, f, sample, authorization);
        self.finish_gate(result)
    }
    pub(in super::super) fn terminal_stream(
        &mut self,
        target: &TerminalContext,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<()> {
        let call = RpcCall::TerminalSnapshot(TerminalReadParams {
            terminal: target.clone(),
        });
        let result = self.core.evaluate(&call, f, sample);
        self.finish_gate(result)
    }
    pub(in super::super) fn dispose(&mut self) {
        self.core.disposed = true;
        self.core.pending = None;
        self.completed_channel.dispose();
    }
}

/// Minted only from the established channel's current gate/time projection.
/// Callers cannot construct or extend the original absolute expiry cap.
pub(in super::super) struct RemoteRenameExpiry(Instant);
impl RemoteRenameExpiry {
    pub(in super::super) fn deadline(&self) -> Instant {
        self.0
    }
}
impl RemoteConnectionState {
    /// Return the exact current channel tuple for a separately authenticated
    /// Started Git pairing GET. This does not refresh or extend the channel.
    pub(in crate::unix) fn started_git_pairing_target(
        &self,
    ) -> Result<super::peer::StartedGitPairingTarget> {
        if self.core.disposed {
            return Err(GateError::Disposed);
        }
        let consumer_identity = self
            .core
            .peer
            .consumer
            .to_wire()
            .map_err(|_| GateError::Disposed)?;
        Ok(super::peer::StartedGitPairingTarget {
            connection: self.core.connection,
            context: self.core.binding.context.clone(),
            signed_grant: self.core.binding.signed_grant.clone(),
            consumer_window_id: self.core.binding.context.grant.consumer_id,
            consumer_identity,
            authority: self.core.peer.authority.clone(),
            origin: self.core.binding.origin.clone(),
            scope: self.core.binding.scope.clone(),
        })
    }

    pub(in crate::unix) fn before_queue_started_git_terminal(
        &mut self,
        request: &RpcRequest,
        request_deadline: Instant,
        operation: &Operation<'_>,
        facts: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
        active: &super::shared_owner::StartedGitContinuation,
        observation: &super::peer::StartedGitPeerObservation,
    ) -> Result<QueuedRequest> {
        if !self.matches_started_git_peer(active, operation, observation) {
            self.dispose();
            return Err(GateError::Disposed);
        }
        let result = self.core.queue_started_git_terminal(
            request,
            request_deadline,
            operation,
            facts,
            sample,
            active,
            observation,
        );
        self.finish_gate(result)
    }

    pub(in crate::unix) fn open_frame_started_git_terminal(
        &mut self,
        frame: &[u8],
        operation: &Operation<'_>,
        facts: &OwnerFacts<'_>,
        sample: &mut dyn FnMut() -> TrustedNow,
        active: &super::shared_owner::StartedGitContinuation,
        observation: &super::peer::StartedGitPeerObservation,
    ) -> Result<impl AsRef<[u8]> + use<>> {
        use lomi_remote_protocol::message_framing::{
            MAX_PLAINTEXT_FRAME_LEN, MAX_TRANSPORT_FRAME_LEN,
        };
        if !self.matches_started_git_peer(active, operation, observation)
            || frame.len() > MAX_TRANSPORT_FRAME_LEN
        {
            self.dispose();
            return Err(GateError::Disposed);
        }
        self.core
            .live_started_git_terminal(facts, sample, active, observation, operation)?;
        let plaintext = match self.completed_channel.open(frame) {
            Ok(plaintext) => plaintext,
            Err(_) => {
                self.dispose();
                return Err(GateError::Disposed);
            }
        };
        if plaintext.len() > MAX_PLAINTEXT_FRAME_LEN {
            self.dispose();
            return Err(GateError::Disposed);
        }
        let result =
            self.core
                .live_started_git_terminal(facts, sample, active, observation, operation);
        self.finish_gate(result)?;
        Ok(plaintext)
    }

    pub(in crate::unix) fn seal_frame_started_git_terminal(
        &mut self,
        plaintext: &[u8],
        operation: &Operation<'_>,
        facts: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
        active: &super::shared_owner::StartedGitContinuation,
        observation: &super::peer::StartedGitPeerObservation,
    ) -> Result<Vec<u8>> {
        use lomi_remote_protocol::message_framing::{
            MAX_PLAINTEXT_FRAME_LEN, MAX_TRANSPORT_FRAME_LEN,
        };
        if !self.matches_started_git_peer(active, operation, observation)
            || plaintext.len() > MAX_PLAINTEXT_FRAME_LEN
        {
            self.dispose();
            return Err(GateError::Disposed);
        }
        self.core
            .live_started_git_terminal(facts, sample, active, observation, operation)?;
        let frame = match self.completed_channel.seal(plaintext) {
            Ok(frame) => frame,
            Err(_) => {
                self.dispose();
                return Err(GateError::Disposed);
            }
        };
        if frame.len() > MAX_TRANSPORT_FRAME_LEN {
            self.dispose();
            return Err(GateError::Disposed);
        }
        let result =
            self.core
                .live_started_git_terminal(facts, sample, active, observation, operation);
        self.finish_gate(result)?;
        Ok(frame)
    }

    pub(in crate::unix) fn matches_started_git_peer(
        &self,
        active: &super::shared_owner::StartedGitContinuation,
        operation: &Operation<'_>,
        observation: &super::peer::StartedGitPeerObservation,
    ) -> bool {
        let target = &observation.target;
        !self.core.disposed
            && observation.current_for(active, operation, self.core.connection)
            && target.connection == self.core.connection
            && target.context == self.core.binding.context
            && target.signed_grant == self.core.binding.signed_grant
            && target.authority == self.core.peer.authority
            && target.origin == self.core.binding.origin
            && target.scope == self.core.binding.scope
    }

    pub(in crate::unix) fn after_wait_started_git_terminal(
        &mut self,
        queued: &QueuedRequest,
        operation: &Operation<'_>,
        facts: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
        active: &super::shared_owner::StartedGitContinuation,
        observation: &super::peer::StartedGitPeerObservation,
    ) -> Result<RpcRequest> {
        if !self.matches_started_git_peer(active, operation, observation) {
            self.dispose();
            return Err(GateError::Disposed);
        }
        let result = self.core.validate_queued_started_git_terminal(
            queued,
            operation,
            facts,
            sample,
            active,
            observation,
        );
        if !matches!(&result, Err(GateError::Busy)) {
            self.core.pending = None;
        }
        self.finish_gate(result)
    }

    pub(in crate::unix) fn cached_response_started_git_terminal(
        &mut self,
        original: &RpcRequest,
        operation: &Operation<'_>,
        facts: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
        active: &super::shared_owner::StartedGitContinuation,
        observation: &super::peer::StartedGitPeerObservation,
    ) -> Result<()> {
        if !self.matches_started_git_peer(active, operation, observation) {
            self.dispose();
            return Err(GateError::Disposed);
        }
        let result = self.core.evaluate_started_git_terminal(
            &original.call,
            facts,
            sample,
            active,
            observation,
            operation,
        );
        self.finish_gate(result)
    }

    pub(in crate::unix) fn cached_git_receipt_response_started_git_terminal(
        &mut self,
        original: &RpcRequest,
        operation: &Operation<'_>,
        disclosure: &super::shared_owner::GitReceiptDisclosure,
        facts: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
        active: &super::shared_owner::StartedGitContinuation,
        observation: &super::peer::StartedGitPeerObservation,
    ) -> Result<()> {
        if !self.matches_started_git_peer(active, operation, observation) {
            self.dispose();
            return Err(GateError::Disposed);
        }
        let result = self.core.cached_git_receipt_started_git_response(
            original,
            facts,
            sample,
            active,
            observation,
            operation,
            disclosure,
        );
        self.finish_gate(result)
    }

    pub(in crate::unix) fn cached_operation_response_started_git_terminal(
        &mut self,
        original: &RpcRequest,
        operation: &Operation<'_>,
        authorization: Option<&super::super::remote_operations::RemoteOperationAuthorization>,
        facts: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
        active: &super::shared_owner::StartedGitContinuation,
        observation: &super::peer::StartedGitPeerObservation,
    ) -> Result<()> {
        if !self.matches_started_git_peer(active, operation, observation) {
            self.dispose();
            return Err(GateError::Disposed);
        }
        let result = self.core.cached_operation_control_started_git_response(
            original,
            facts,
            sample,
            active,
            observation,
            operation,
            authorization,
        );
        self.finish_gate(result)
    }

    pub(in crate::unix) fn terminal_stream_started_git(
        &mut self,
        target: &TerminalContext,
        operation: &Operation<'_>,
        facts: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
        active: &super::shared_owner::StartedGitContinuation,
        observation: &super::peer::StartedGitPeerObservation,
    ) -> Result<()> {
        if !self.matches_started_git_peer(active, operation, observation) {
            self.dispose();
            return Err(GateError::Disposed);
        }
        let call = RpcCall::TerminalSnapshot(TerminalReadParams {
            terminal: target.clone(),
        });
        let result = self.core.evaluate_started_git_terminal(
            &call,
            facts,
            sample,
            active,
            observation,
            operation,
        );
        self.finish_gate(result)
    }

    pub(in super::super) fn before_remote_rename(
        &mut self,
        queued: &QueuedRequest,
        operation: &Operation<'_>,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<(RpcRequest, RemoteRenameExpiry)> {
        let request = self.after_wait(queued, operation, f, sample)?;
        if self.core.binding.context.purpose != ChannelPurposeV3::Workspace
            || !matches!(
                &request.call,
                RpcCall::TerminalRename(_)
                    | RpcCall::TerminalMove(_)
                    | RpcCall::TerminalCreate(_)
                    | RpcCall::TerminalSplit(_)
                    | RpcCall::TerminalClose(_)
                    | RpcCall::TerminalRestart(_)
                    | RpcCall::FilesCreate(_)
                    | RpcCall::FilesMkdir(_)
                    | RpcCall::FilesRename(_)
                    | RpcCall::FilesRemove(_)
                    | RpcCall::GitStage(_)
                    | RpcCall::GitUnstage(_)
                    | RpcCall::GitCommit(_)
                    | RpcCall::GitFetch(_)
                    | RpcCall::GitPull(_)
                    | RpcCall::GitPush(_)
            )
        {
            return Err(GateError::Denied);
        }
        let now = sample();
        let live = self.core.live_once(f, now);
        self.finish_gate(live)?;
        let wall = self
            .core
            .clock
            .observe(now)
            .map_err(|_| GateError::Disposed)?;
        let wall_ceiling = [
            self.core.binding.context.grant.expires_at,
            f.access_expires_at,
            f.refresh_at,
        ]
        .into_iter()
        .map(Duration::from_secs)
        .min()
        .ok_or(GateError::Disposed)?
        .min(self.core.peer.authority_expires_at);
        let remaining = wall_ceiling.checked_sub(wall).ok_or(GateError::Disposed)?;
        let absolute = now
            .monotonic
            .checked_add(remaining)
            .ok_or(GateError::Disposed)?
            .min(self.core.peer.valid_until)
            .min(deadline(f.heartbeat.request_started, f.heartbeat.lease_ms)?)
            .min(deadline(
                f.heartbeat.request_started,
                f.heartbeat.freshness_ms,
            )?)
            .min(operation.deadline())
            .min(queued.deadline);
        if now.monotonic >= absolute {
            self.dispose();
            return Err(GateError::Disposed);
        }
        Ok((request, RemoteRenameExpiry(absolute)))
    }

    /// Git phase continuation is bounded by the original operation/request,
    /// credential window and signed heartbeat lease. It deliberately does not
    /// reuse the five-second cached-peer lifetime after this exact Started
    /// Shared ticket has been registered.
    pub(in super::super) fn before_remote_git_mutation(
        &mut self,
        queued: &QueuedRequest,
        operation: &Operation<'_>,
        f: &OwnerFacts<'_>,
        sample: &mut impl FnMut() -> TrustedNow,
    ) -> Result<(RpcRequest, Instant, Instant)> {
        let request = self.after_wait(queued, operation, f, sample)?;
        if self.core.binding.context.purpose != ChannelPurposeV3::Workspace
            || !matches!(
                &request.call,
                RpcCall::GitStage(_)
                    | RpcCall::GitUnstage(_)
                    | RpcCall::GitCommit(_)
                    | RpcCall::GitFetch(_)
                    | RpcCall::GitPull(_)
                    | RpcCall::GitPush(_)
            )
        {
            return Err(GateError::Denied);
        }
        let now = sample();
        let live = self.core.live_once(f, now);
        self.finish_gate(live)?;
        let wall = self
            .core
            .clock
            .observe(now)
            .map_err(|_| GateError::Disposed)?;
        let wall_ceiling = [
            self.core.binding.context.grant.expires_at,
            f.access_expires_at,
            f.refresh_at,
        ]
        .into_iter()
        .map(Duration::from_secs)
        .min()
        .ok_or(GateError::Disposed)?
        .min(self.core.peer.authority_expires_at);
        let remaining = wall_ceiling.checked_sub(wall).ok_or(GateError::Disposed)?;
        let hard_absolute = now
            .monotonic
            .checked_add(remaining)
            .ok_or(GateError::Disposed)?
            .min(operation.deadline())
            .min(queued.deadline);
        let heartbeat_expiry = deadline(f.heartbeat.request_started, f.heartbeat.lease_ms)?
            .min(deadline(
                f.heartbeat.request_started,
                f.heartbeat.freshness_ms,
            )?)
            .min(hard_absolute);
        if now.monotonic >= hard_absolute || now.monotonic >= heartbeat_expiry {
            self.dispose();
            return Err(GateError::Disposed);
        }
        let live = self.core.live_once(f, sample());
        self.finish_gate(live)?;
        Ok((request, hard_absolute, heartbeat_expiry))
    }
    /// Consumes the actual response frame and exports only an opaque one-send
    /// capability. Ciphertext creation/storage stays private to this module.
    pub(in super::super) fn seal_remote_rename_receipt<'d, 'o, 'e, 'w, 'p, 's>(
        &mut self,
        frame: super::super::remote_terminal_rename::RemoteRenameResponseFrame<
            'd,
            'o,
            'e,
            'w,
            'p,
            's,
        >,
    ) -> std::result::Result<
        SealedRemoteRenameReceipt<'d, 'o, 'e, 'w, 'p, 's>,
        super::super::shared_owner::RemoteRenameError,
    > {
        use lomi_remote_protocol::message_framing::{
            MAX_PLAINTEXT_FRAME_LEN, MAX_TRANSPORT_FRAME_LEN,
        };
        let result: std::result::Result<_, super::super::shared_owner::RemoteRenameError> =
            (|| {
                let bytes = {
                    let turn = frame.receipt().capture()?;
                    if !turn.current_for(self.core.connection)
                        || !turn.matches(frame.receipt())
                        || frame.bytes().len() > MAX_PLAINTEXT_FRAME_LEN
                    {
                        return Err(GateError::Disposed.into());
                    }
                    let facts = turn.facts();
                    let live = self
                        .core
                        .live_once_inner(&facts, turn.sample(), Some(&turn), None);
                    self.finish_gate(live)?;
                    let bytes = self
                        .completed_channel
                        .seal(frame.bytes())
                        .map_err(|_| GateError::Disposed)?;
                    let live = self
                        .core
                        .live_once_inner(&facts, turn.sample(), Some(&turn), None);
                    self.finish_gate(live)?;
                    if bytes.len() > MAX_TRANSPORT_FRAME_LEN
                        || !turn.current_for(self.core.connection)
                    {
                        return Err(GateError::Disposed.into());
                    }
                    bytes
                }; // Domain/Store turns drop before socket watcher/output ownership.
                let watch = frame.consume_into_io_watch();
                watch.check()?;
                Ok(SealedRemoteRenameReceipt {
                    bytes,
                    watch,
                    connection: self.connection_identity(),
                })
            })();
        if result.is_err() {
            self.dispose();
        }
        result
    }

    pub(in super::super) fn seal_remote_git_receipt<'e, 'w, 'p, 's, 'op>(
        &mut self,
        frame: super::remote_ingress::RemoteGitReceiptFrame<'e, 'w, 'p, 's, 'op>,
    ) -> std::result::Result<
        SealedRemoteGitReceipt<'e, 'w, 'p, 's, 'op>,
        super::super::shared_owner::RemoteRenameError,
    > {
        use lomi_remote_protocol::message_framing::{
            MAX_PLAINTEXT_FRAME_LEN, MAX_TRANSPORT_FRAME_LEN,
        };
        let result: std::result::Result<_, super::super::shared_owner::RemoteRenameError> =
            (|| {
                let bytes = {
                    let turn = frame.receipt().capture()?;
                    if !turn.current_for(self.core.connection)
                        || !turn.matches(frame.receipt())
                        || frame.bytes().len() > MAX_PLAINTEXT_FRAME_LEN
                    {
                        return Err(GateError::Disposed.into());
                    }
                    let facts = turn.facts();
                    let live = self.core.live_once_inner(
                        &facts,
                        turn.sample(),
                        Some(&turn as &dyn PublicationReceiptProof),
                        None,
                    );
                    self.finish_gate(live)?;
                    let bytes = self
                        .completed_channel
                        .seal(frame.bytes())
                        .map_err(|_| GateError::Disposed)?;
                    let live = self.core.live_once_inner(
                        &facts,
                        turn.sample(),
                        Some(&turn as &dyn PublicationReceiptProof),
                        None,
                    );
                    self.finish_gate(live)?;
                    if bytes.len() > MAX_TRANSPORT_FRAME_LEN
                        || !turn.current_for(self.core.connection)
                    {
                        return Err(GateError::Disposed.into());
                    }
                    bytes
                };
                let watch = frame.consume_into_io_watch();
                watch.check()?;
                Ok(SealedRemoteGitReceipt {
                    bytes,
                    watch,
                    connection: self.connection_identity(),
                })
            })();
        if result.is_err() {
            self.dispose();
        }
        result
    }

    pub(in super::super) fn seal_remote_git_started_receipt<'e, 'op, 'd>(
        &mut self,
        frame: super::remote_ingress::RemoteGitStartedReceiptFrame<'e, 'op>,
        gate_denied: &'d AtomicBool,
        paused: &'d AtomicBool,
        stopping: &'d AtomicBool,
        public_pending: &'d AtomicBool,
    ) -> std::result::Result<
        SealedRemoteGitStartedReceipt<'d, 'op>,
        super::super::shared_owner::RemoteRenameError,
    >
    where
        'e: 'op,
    {
        use lomi_remote_protocol::message_framing::{
            MAX_PLAINTEXT_FRAME_LEN, MAX_TRANSPORT_FRAME_LEN,
        };
        let result: std::result::Result<_, super::super::shared_owner::RemoteRenameError> =
            (|| {
                let bytes = {
                    let turn = frame.receipt().capture(gate_denied, paused, stopping)?;
                    if !turn.current_for(self.core.connection)
                        || !turn.matches(frame.receipt())
                        || frame.bytes().len() > MAX_PLAINTEXT_FRAME_LEN
                    {
                        return Err(GateError::Disposed.into());
                    }
                    let facts = turn.facts();
                    let live = self.core.live_once_inner(
                        &facts,
                        turn.sample(),
                        Some(&turn as &dyn PublicationReceiptProof),
                        None,
                    );
                    self.finish_gate(live)?;
                    let bytes = self
                        .completed_channel
                        .seal(frame.bytes())
                        .map_err(|_| GateError::Disposed)?;
                    let live = self.core.live_once_inner(
                        &facts,
                        turn.sample(),
                        Some(&turn as &dyn PublicationReceiptProof),
                        None,
                    );
                    self.finish_gate(live)?;
                    if bytes.len() > MAX_TRANSPORT_FRAME_LEN
                        || !turn.current_for(self.core.connection)
                    {
                        return Err(GateError::Disposed.into());
                    }
                    bytes
                };
                let watch =
                    frame.consume_into_io_watch(gate_denied, paused, stopping, public_pending);
                watch.check()?;
                Ok(SealedRemoteGitStartedReceipt {
                    bytes,
                    watch,
                    connection: self.connection_identity(),
                })
            })();
        if result.is_err() {
            self.dispose();
        }
        result
    }
}

/// Private fields and module-local construction prevent raw ciphertext export,
/// borrowed resealing or alternate sibling construction. No Clone/bytes API.
pub(in super::super) struct SealedRemoteRenameReceipt<'d, 'o, 'e, 'w, 'p, 's> {
    bytes: Vec<u8>,
    watch: super::super::shared_owner::RemoteRenameIoWatch<'d, 'o, 'e, 'w, 'p, 's>,
    connection: uuid::Uuid,
}
pub(in super::super) struct SealedRemoteGitReceipt<'e, 'w, 'p, 's, 'op> {
    bytes: Vec<u8>,
    watch: super::super::shared_owner::RemoteGitReceiptIoWatch<'e, 'w, 'p, 's, 'op>,
    connection: uuid::Uuid,
}
pub(in super::super) struct SealedRemoteGitStartedReceipt<'d, 'op> {
    bytes: Vec<u8>,
    watch: super::super::shared_owner::RemoteGitStartedReceiptIoWatch<'d, 'op>,
    connection: uuid::Uuid,
}
#[derive(Clone, Copy, Debug)]
pub(in super::super) enum RemoteRenameDeliveryError {
    Closed,
    Io,
}
impl SealedRemoteRenameReceipt<'_, '_, '_, '_, '_, '_> {
    /// Consumes exactly one ciphertext write. Any partial/uncertain send drops
    /// the socket rather than exporting bytes or enabling replay.
    pub(in super::super) fn send(
        self,
        connection: &mut RemoteConnectionState,
        socket: &mut lomi_host_http::RelayConnection,
    ) -> std::result::Result<(), RemoteRenameDeliveryError> {
        if connection.connection_identity() != self.connection
            || !connection.is_workspace_channel()
            || self.watch.check().is_err()
        {
            socket.close();
            connection.dispose();
            return Err(RemoteRenameDeliveryError::Closed);
        }
        let result = {
            // Only sealed Sync atoms enter the physical socket callback. The
            // !Sync worker/HostAuth borrow remains outside that callback.
            let atoms = self.watch.atoms();
            let check = || atoms.check();
            socket.send_binary(&self.bytes, atoms.deadline(), &check)
        };
        if result.is_err() || self.watch.check().is_err() {
            socket.close();
            connection.dispose();
            return Err(RemoteRenameDeliveryError::Io);
        }
        Ok(())
    }
}
impl SealedRemoteGitReceipt<'_, '_, '_, '_, '_> {
    pub(in super::super) fn send(
        self,
        connection: &mut RemoteConnectionState,
        socket: &mut lomi_host_http::RelayConnection,
    ) -> std::result::Result<(), RemoteRenameDeliveryError> {
        if connection.connection_identity() != self.connection
            || !connection.is_workspace_channel()
            || self.watch.check().is_err()
        {
            socket.close();
            connection.dispose();
            return Err(RemoteRenameDeliveryError::Closed);
        }
        let result = {
            let atoms = self.watch.atoms();
            let check = || atoms.check();
            socket.send_binary(&self.bytes, atoms.deadline(), &check)
        };
        if result.is_err() || self.watch.check().is_err() {
            socket.close();
            connection.dispose();
            return Err(RemoteRenameDeliveryError::Io);
        }
        Ok(())
    }
}
impl SealedRemoteGitStartedReceipt<'_, '_> {
    pub(in super::super) fn send(
        self,
        connection: &mut RemoteConnectionState,
        socket: &mut lomi_host_http::RelayConnection,
    ) -> std::result::Result<(), RemoteRenameDeliveryError> {
        if connection.connection_identity() != self.connection
            || !connection.is_workspace_channel()
            || self.watch.check().is_err()
        {
            socket.close();
            connection.dispose();
            return Err(RemoteRenameDeliveryError::Closed);
        }
        let result = {
            let watch = &self.watch;
            let check = || {
                watch
                    .check()
                    .map_err(|_| lomi_host_http::BudgetStop::Cancelled)
            };
            socket.send_binary(&self.bytes, self.watch.deadline(), &check)
        };
        if result.is_err() || self.watch.check().is_err() {
            socket.close();
            connection.dispose();
            return Err(RemoteRenameDeliveryError::Io);
        }
        Ok(())
    }
}
