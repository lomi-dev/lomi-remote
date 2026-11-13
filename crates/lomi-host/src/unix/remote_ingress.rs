//! Auth-worker-owned WSS, Noise responder and encrypted workspace ingress.
//! Ticket possession is never ongoing peer authority or a usable channel.
use super::super::{
    Coordinator,
    remote_terminal::{RemoteTerminalState, RemoteTerminalStreamFrame},
};
use super::remote_connection::{PendingRemoteConnection, RemoteConnectionState};
use super::{
    HostAuth, Runtime, RuntimeWithOperation, SecretStorage, channel, cloud::PeerEligibility, peer,
};
use lomi_host_http::{BudgetStop, DataTransport, RelayConnection, RelayTransport, RemoteApiOrigin};
use lomi_remote_protocol::{ChannelId, http::*};
use lomi_remote_protocol::{
    DecimalU64, OperationReceipt, WorkspaceContext,
    admission::WssAdmissionFrame,
    message_framing::{
        MAX_FRAGMENT_PAYLOAD_LEN, MAX_MESSAGE_LEN, MessageAssembler, MessageEncoder, MessageKind,
    },
    rpc::*,
};
use std::{collections::VecDeque, sync::Weak};
use std::{sync::atomic::AtomicBool, task::Poll};
use std::{
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

#[cfg(not(test))]
type IngressSocket = RelayConnection;
#[cfg(test)]
enum IngressSocket {
    Relay(RelayConnection),
    Memory(MemoryIngressSocket),
}
#[cfg(test)]
#[derive(Default)]
struct MemoryIngressSocket {
    incoming: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
    closed: bool,
    cancel_before_send: Option<std::sync::Arc<AtomicBool>>,
    fail_after_write: bool,
}
#[cfg(test)]
impl IngressSocket {
    fn relay(socket: RelayConnection) -> Self {
        Self::Relay(socket)
    }
    fn memory(incoming: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self::Memory(MemoryIngressSocket {
            incoming: incoming.into_iter().collect(),
            ..MemoryIngressSocket::default()
        })
    }
    fn close(&mut self) {
        match self {
            Self::Relay(socket) => socket.close(),
            Self::Memory(socket) => socket.closed = true,
        }
    }
    fn is_closed(&self) -> bool {
        match self {
            Self::Relay(socket) => socket.is_closed(),
            Self::Memory(socket) => socket.closed,
        }
    }
    fn poll_binary(
        &mut self,
        deadline: Instant,
        check: &(dyn Fn() -> Result<(), BudgetStop> + Sync),
    ) -> Result<Poll<Vec<u8>>, lomi_host_http::Error> {
        match self {
            Self::Relay(socket) => socket.poll_binary(deadline, check),
            Self::Memory(socket) => {
                if socket.closed {
                    return Err(lomi_host_http::Error::RelayClosed);
                }
                if Instant::now() >= deadline || check().is_err() {
                    return Err(lomi_host_http::Error::Cancelled);
                }
                Ok(socket
                    .incoming
                    .pop_front()
                    .map_or(Poll::Pending, Poll::Ready))
            }
        }
    }
    fn send_binary(
        &mut self,
        bytes: &[u8],
        deadline: Instant,
        check: &(dyn Fn() -> Result<(), BudgetStop> + Sync),
    ) -> Result<(), lomi_host_http::Error> {
        match self {
            Self::Relay(socket) => socket.send_binary(bytes, deadline, check),
            Self::Memory(socket) => {
                if let Some(cancelled) = socket.cancel_before_send.take() {
                    cancelled.store(true, Ordering::Release);
                }
                if socket.closed {
                    return Err(lomi_host_http::Error::RelayClosed);
                }
                if bytes.is_empty() || Instant::now() >= deadline || check().is_err() {
                    socket.closed = true;
                    return Err(lomi_host_http::Error::Cancelled);
                }
                socket.sent.push(bytes.to_vec());
                if socket.fail_after_write {
                    socket.closed = true;
                    return Err(lomi_host_http::Error::RelayClosed);
                }
                Ok(())
            }
        }
    }
    fn sent(&self) -> &[Vec<u8>] {
        match self {
            Self::Relay(_) => &[],
            Self::Memory(socket) => &socket.sent,
        }
    }
}
#[cfg(not(test))]
fn ingress_socket(socket: RelayConnection) -> IngressSocket {
    socket
}
#[cfg(test)]
fn ingress_socket(socket: RelayConnection) -> IngressSocket {
    IngressSocket::relay(socket)
}
#[cfg(test)]
fn relay_socket_mut(socket: &mut IngressSocket) -> &mut RelayConnection {
    match socket {
        IngressSocket::Relay(socket) => socket,
        IngressSocket::Memory(_) => unreachable!("receipt publication requires a relay socket"),
    }
}
#[cfg(not(test))]
fn relay_socket_mut(socket: &mut IngressSocket) -> &mut RelayConnection {
    socket
}

#[path = "remote_ingress_registry.rs"]
mod registry;
pub(super) use registry::Registry;

/// Keep the ordinary idle wait unless a successful stage left work for the next pass.
pub(super) const fn actor_wait_duration(immediate_pass: bool) -> Duration {
    if immediate_pass {
        Duration::ZERO
    } else {
        Duration::from_millis(250)
    }
}

// Current-peer proofs are valid for at most five seconds. Start a bounded
// refresh with three seconds left so one slow owner/network turn cannot use up
// the entire freshness window before the next ingress pass.
const PEER_REFRESH_MARGIN: Duration = Duration::from_secs(3);
// A slow established channel may retain only a small number of already
// authorized messages while Started Git continues to service terminal input.
// The active encoder is included in both limits.
const MAX_STARTED_GIT_OUTPUT_MESSAGES: usize = 8;
const MAX_STARTED_GIT_OUTPUT_BYTES: usize = 2 * MAX_MESSAGE_LEN + MAX_FRAGMENT_PAYLOAD_LEN;

macro_rules! invalid_at {
    () => {
        invalid
    };
}

macro_rules! owner_error_at {
    () => {
        peer::owner_error
    };
}

type WatchCheck<'a> = dyn Fn() -> Result<(), BudgetStop> + Sync + 'a;
struct TicketedAdmission {
    handoff: channel::AdmittedChannelHandoff,
    channel_id: ChannelId,
    ticket: RelayTicket,
    request_started: Instant,
    expires_in_ms: u64,
    expires_at: Instant,
}
fn ticket_grammar(ticket: &RelayTicket) -> bool {
    let bytes = ticket.expose_wire().as_bytes();
    (43..=128).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
fn ticket_bounds_current_at(
    now: Instant,
    request_started: Instant,
    expires_in_ms: u64,
    expires_at: Instant,
    handoff_deadline: Instant,
    channel_id: ChannelId,
    handoff_channel_id: ChannelId,
    ticket: &RelayTicket,
) -> bool {
    (1..=5000).contains(&expires_in_ms)
        && request_started <= now
        && now < expires_at
        && request_started
            .checked_add(Duration::from_millis(expires_in_ms))
            .is_some_and(|expiry| expires_at == expiry.min(handoff_deadline))
        && channel_id == handoff_channel_id
        && ticket_grammar(ticket)
}
impl TicketedAdmission {
    fn bounds_current_at(&self, now: Instant) -> bool {
        ticket_bounds_current_at(
            now,
            self.request_started,
            self.expires_in_ms,
            self.expires_at,
            self.handoff.deadline(),
            self.channel_id,
            self.handoff.channel_id(),
            &self.ticket,
        )
    }

    fn peer_refresh_deadline(&self, now: Instant) -> Option<Instant> {
        if !self.bounds_current_at(now) {
            return None;
        }
        handoff_peer_refresh_deadline(&self.handoff, Some(self.expires_at), now)
    }

    // Registry polling only decides whether to retain this one-shot ticket.
    // Keep the original operation, handoff, observation, scope, and trusted
    // configuration current without recapturing provider or Store evidence.
    fn poll_current(
        &self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'_, '_>,
        eligibility: &PeerEligibility,
    ) -> bool {
        if !self.bounds_current_at(Instant::now()) || peer::check_peer_runtime(runtime).is_err() {
            return false;
        }
        let Some(binding) = self.handoff.ticket_binding(runtime.operation, eligibility) else {
            return false;
        };
        binding.scope() == &self.handoff.source().intent.preparation.scope
            && binding.trusted() == auth.trusted_configuration()
            && self.handoff.observation().current_operation(runtime)
            && Instant::now() < self.expires_at
    }

    fn current(
        &self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'_, '_>,
        eligibility: &PeerEligibility,
    ) -> bool {
        let now = Instant::now();
        if !self.bounds_current_at(now) {
            return false;
        }
        // Consumed connect revalidates the named current ACK/source/local join
        // against fresh provider and owner evidence before relay IO.
        let current = (|| {
            self.handoff.check_current(auth, runtime, eligibility)?;
            let provider = peer::ProviderCapture::read(auth, runtime, eligibility)?;
            let mut effect = peer::owner_turn(runtime, || {
                runtime.owner.capture_channel_ticket(
                    runtime.operation,
                    eligibility,
                    &self.handoff,
                    runtime.base,
                    runtime.anchor,
                )
            })?;
            peer::owner_turn(runtime, || effect.try_validate(&provider))?;
            effect
                .check_boundary(&provider)
                .map_err(owner_error_at!())?;
            self.handoff.check_current(auth, runtime, eligibility)
        })();
        current.is_ok() && Instant::now() < self.expires_at
    }
}

#[derive(Default)]
pub(super) struct Driver<'cancel> {
    coordinator: Weak<Coordinator>,
    cancelled: Option<&'cancel AtomicBool>,
    defer_network: bool,
    connection: Option<Connection<'cancel>>,
    candidate: Option<channel::AdmittedChannelHandoff>,
    ticketed: Option<TicketedAdmission>,
    // Static diagnostic only; retained across discard so failure remains visible.
}
struct PendingResponse<'cancel> {
    operation: super::OwnerOperation<'cancel>,
    aborted: std::cell::Cell<bool>,
    request: RpcRequest,
    peer: Option<peer::VerifiedCurrentPeer>,
    operation_control: bool,
    operation_disclosure: Option<super::super::remote_operations::RemoteOperationDisclosure>,
    git_receipt_disclosure: Option<super::super::shared_owner::GitReceiptDisclosure>,
    remaining: usize,
}
struct PendingGitRead<'cancel> {
    operation: super::OwnerOperation<'cancel>,
    aborted: std::cell::Cell<bool>,
    request: RpcRequest,
    peer: Option<peer::VerifiedCurrentPeer>,
    read: super::super::remote_git::Read,
}
struct PendingGitMutation<'cancel> {
    operation: super::OwnerOperation<'cancel>,
    aborted: std::cell::Cell<bool>,
    request: RpcRequest,
    peer: Option<peer::VerifiedCurrentPeer>,
    publication_peer: Option<peer::VerifiedCurrentPeer>,
    queued: Option<super::super::auth::remote_connection::QueuedRequest>,
    context: WorkspaceContext,
    target: super::super::shared_owner::FilesTarget,
    control: lomi_git::RequestControl,
    cancellation: lomi_git::CancellationToken,
    _cancel_on_drop: CancelGitOnDrop,
    started: Option<StartedGitPermit>,
    lease: Option<super::super::owner_domain::RemoteGitWriterLease>,
    continuation: Option<super::shared_owner::StartedGitContinuation>,
    invalidated: bool,
    state: Option<PendingGitMutationState>,
}
enum PendingGitMutationState {
    Preparing(super::super::remote_git_mutations::PrepareJob),
    Prepared(super::super::remote_git_mutations::PreparedGitOperation),
    Network(
        super::super::remote_git_mutations::StepJob<
            super::super::remote_git_mutations::NetworkResult,
        >,
    ),
    NeedPublish(super::super::remote_git_mutations::PreparedGitPublication),
    Publishing(super::super::remote_git_mutations::StepJob<lomi_git::PublishedGitMutation>),
    NeedCapture(lomi_git::PublishedGitMutation),
    Capturing(super::super::remote_git_mutations::StepJob<lomi_remote_protocol::RepoStateToken>),
    Finalize {
        state: lomi_remote_protocol::OperationState,
        effect: lomi_remote_protocol::Effect,
        repo_state: Option<lomi_remote_protocol::RepoStateToken>,
    },
    Deliver(
        OperationReceipt,
        super::super::shared_owner::GitReceiptDisclosure,
    ),
    Reject(lomi_remote_protocol::RemoteError),
}

/// A single-frame response for the exact committed Git receipt. This value is
/// constructed only after Store completion and consumed once by the connection
/// sealing boundary; it cannot be replayed or reused for another request.
pub(in crate::unix) struct RemoteGitReceiptFrame<'e, 'w, 'p, 's, 'o> {
    receipt: super::shared_owner::RemoteGitReceipt<'e, 'w, 'p, 's, 'o>,
    bytes: Vec<u8>,
}
impl<'e, 'w, 'p, 's, 'o> RemoteGitReceiptFrame<'e, 'w, 'p, 's, 'o> {
    fn encode(
        receipt: super::shared_owner::RemoteGitReceipt<'e, 'w, 'p, 's, 'o>,
        encoder: &mut MessageEncoder,
    ) -> Result<Self, peer::PeerError> {
        let bytes =
            serde_json::to_vec(&receipt.response()).map_err(|_| peer::PeerError::Invalid)?;
        if bytes.is_empty() || bytes.len() > MAX_FRAGMENT_PAYLOAD_LEN {
            return Err(peer::PeerError::Invalid);
        }
        encoder
            .begin(MessageKind::RpcResponse, bytes)
            .map_err(|_| peer::PeerError::Invalid)?;
        let bytes = encoder
            .next_frame()
            .map_err(|_| peer::PeerError::Invalid)?
            .ok_or(peer::PeerError::Invalid)?;
        if encoder
            .next_frame()
            .map_err(|_| peer::PeerError::Invalid)?
            .is_some()
        {
            return Err(peer::PeerError::Invalid);
        }
        Ok(Self { receipt, bytes })
    }
    pub(in crate::unix) fn receipt(
        &self,
    ) -> &super::shared_owner::RemoteGitReceipt<'e, 'w, 'p, 's, 'o> {
        &self.receipt
    }
    pub(in crate::unix) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    fn seal(
        self,
        connection: &mut RemoteConnectionState,
    ) -> Result<super::remote_connection::SealedRemoteGitReceipt<'e, 'w, 'p, 's, 'o>, peer::PeerError>
    {
        connection
            .seal_remote_git_receipt(self)
            .map_err(|_| peer::PeerError::Invalid)
    }
    pub(in crate::unix) fn consume_into_io_watch(
        self,
    ) -> super::shared_owner::RemoteGitReceiptIoWatch<'e, 'w, 'p, 's, 'o> {
        self.receipt.into_io_watch()
    }
}

/// One-frame final receipt for a Git mutation that completed through the
/// Started-only control-plane lane. It is bound to the exact continuation and
/// cannot be used to authorize another RPC.
pub(in crate::unix) struct RemoteGitStartedReceiptFrame<'e, 'op> {
    receipt: super::shared_owner::RemoteGitStartedReceipt<'e, 'op>,
    bytes: Vec<u8>,
}
impl<'e: 'op, 'op> RemoteGitStartedReceiptFrame<'e, 'op> {
    fn encode(
        receipt: super::shared_owner::RemoteGitStartedReceipt<'e, 'op>,
        encoder: &mut MessageEncoder,
    ) -> Result<Self, peer::PeerError> {
        let bytes =
            serde_json::to_vec(&receipt.response()).map_err(|_| peer::PeerError::Invalid)?;
        if bytes.is_empty() || bytes.len() > MAX_FRAGMENT_PAYLOAD_LEN {
            return Err(peer::PeerError::Invalid);
        }
        encoder
            .begin(MessageKind::RpcResponse, bytes)
            .map_err(|_| peer::PeerError::Invalid)?;
        let bytes = encoder
            .next_frame()
            .map_err(|_| peer::PeerError::Invalid)?
            .ok_or(peer::PeerError::Invalid)?;
        if encoder
            .next_frame()
            .map_err(|_| peer::PeerError::Invalid)?
            .is_some()
        {
            return Err(peer::PeerError::Invalid);
        }
        Ok(Self { receipt, bytes })
    }
    pub(in crate::unix) fn receipt(
        &self,
    ) -> &super::shared_owner::RemoteGitStartedReceipt<'e, 'op> {
        &self.receipt
    }
    pub(in crate::unix) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    fn seal<'d>(
        self,
        connection: &mut RemoteConnectionState,
        gate_denied: &'d AtomicBool,
        paused: &'d AtomicBool,
        stopping: &'d AtomicBool,
        public_pending: &'d AtomicBool,
    ) -> Result<super::remote_connection::SealedRemoteGitStartedReceipt<'d, 'op>, peer::PeerError>
    {
        connection
            .seal_remote_git_started_receipt(self, gate_denied, paused, stopping, public_pending)
            .map_err(|_| peer::PeerError::Invalid)
    }
    pub(in crate::unix) fn consume_into_io_watch<'d>(
        self,
        gate_denied: &'d AtomicBool,
        paused: &'d AtomicBool,
        stopping: &'d AtomicBool,
        public_pending: &'d AtomicBool,
    ) -> super::shared_owner::RemoteGitStartedReceiptIoWatch<'d, 'op>
    where
        'e: 'd,
    {
        self.receipt
            .into_io_watch(gate_denied, paused, stopping, public_pending)
    }
}
struct CancelGitOnDrop(lomi_git::CancellationToken);
impl Drop for CancelGitOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
struct StartedGitPermit {
    binding: lomi_host_store::OperationBinding,
    permit: Option<lomi_host_store::ExternalPermit>,
    completion: super::super::rpc::CompletionSlot<'static>,
    credential_configuration: Option<lomi_remote_protocol::ipc::LocalAuthConfiguration>,
}
impl StartedGitPermit {
    fn confirm(&mut self) {
        self.permit.take();
    }
}
impl Drop for StartedGitPermit {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            self.completion
                .defer(super::super::rpc::DeferredCompletion::Complete {
                    binding: self.binding.clone(),
                    permit,
                    state: lomi_remote_protocol::OperationState::OutcomeUnknown,
                    effect: lomi_remote_protocol::Effect::Unknown,
                    result: None,
                    projection: None,
                });
        }
    }
}
impl PendingGitMutation<'_> {
    fn is_ready(&self) -> bool {
        match self.state.as_ref() {
            Some(PendingGitMutationState::Preparing(job)) => job.is_ready(),
            Some(PendingGitMutationState::Network(job)) => job.is_ready(),
            Some(PendingGitMutationState::Publishing(job)) => job.is_ready(),
            Some(PendingGitMutationState::Capturing(job)) => job.is_ready(),
            Some(
                PendingGitMutationState::Prepared(_)
                | PendingGitMutationState::NeedPublish(_)
                | PendingGitMutationState::NeedCapture(_)
                | PendingGitMutationState::Finalize { .. }
                | PendingGitMutationState::Deliver(..)
                | PendingGitMutationState::Reject(_),
            ) => true,
            None => false,
        }
    }
}
struct PendingStream<'cancel> {
    operation: super::OwnerOperation<'cancel>,
    aborted: std::cell::Cell<bool>,
    peer: Option<peer::VerifiedCurrentPeer>,
    kind: MessageKind,
    authorization_call: Option<RpcRequest>,
    /// `None` for workspace/watch frames, which have no terminal delivery ledger.
    delivery: Option<RemoteTerminalStreamFrame>,
    /// Only normal terminal producer messages may continue a bounded burst
    /// under this original maintenance admission. Started Git and RPC stream
    /// messages carry no burst marker.
    burst_pending_first_send: bool,
    burst_started: Option<Instant>,
    remaining: usize,
}

fn transfer_maintenance_to_stream<'cancel, Peer>(
    maintenance: &mut super::OwnerOperation<'cancel>,
    maintenance_aborted: &mut std::cell::Cell<bool>,
    peer: &mut Option<Peer>,
    replacement_maintenance: super::OwnerOperation<'cancel>,
) -> (
    super::OwnerOperation<'cancel>,
    std::cell::Cell<bool>,
    Option<Peer>,
) {
    let operation = std::mem::replace(maintenance, replacement_maintenance);
    let aborted = std::mem::replace(maintenance_aborted, std::cell::Cell::new(false));
    (operation, aborted, peer.take())
}

fn restore_terminal_stream_operation<'cancel>(
    maintenance: &mut super::OwnerOperation<'cancel>,
    maintenance_aborted: &mut std::cell::Cell<bool>,
    operation: super::OwnerOperation<'cancel>,
    aborted: std::cell::Cell<bool>,
) {
    *maintenance = operation;
    *maintenance_aborted = aborted;
}

fn terminal_burst_can_continue(
    burst_started: Option<Instant>,
    now: Instant,
    proof_fresh_until: Instant,
    operation_deadline: Instant,
    operation_live: bool,
    proof_current: bool,
    producer_pending: bool,
) -> bool {
    burst_started.is_some_and(|started| {
        operation_live
            && proof_current
            && producer_pending
            && now
                .checked_duration_since(started)
                .is_some_and(|elapsed| elapsed < registry::STAGED_MESSAGE_BATCH_QUANTUM)
            && registry::terminal_emission_retains_operation(operation_deadline, now)
            && now
                .checked_add(PEER_REFRESH_MARGIN)
                .is_some_and(|refresh_by| refresh_by < proof_fresh_until)
    })
}

fn start_terminal_burst_at_first_send(
    pending_first_send: &mut bool,
    burst_started: &mut Option<Instant>,
    send_started: Instant,
) {
    if std::mem::replace(pending_first_send, false) {
        // Preserve an existing start if state is unexpectedly inconsistent;
        // later messages must never renew the original burst window.
        burst_started.get_or_insert(send_started);
    }
}

struct QueuedStartedOutput<'cancel> {
    kind: MessageKind,
    bytes: Box<[u8]>,
    response: Option<PendingResponse<'cancel>>,
    stream: Option<PendingStream<'cancel>>,
}
impl Drop for QueuedStartedOutput<'_> {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}
struct Connection<'cancel> {
    coordinator: Weak<Coordinator>,
    terminal: Option<RemoteTerminalState>,
    watch: Option<super::remote_files_watch::RemoteWatch>,
    watch_generation: u64,
    workspace_stream: Option<super::super::local_streams::Workspace>,
    workspace_stream_call: Option<RpcRequest>,
    next_stream_class: u8,
    stream: Option<PendingStream<'cancel>>,
    watch_call: Option<RpcRequest>,
    started_git_outputs: VecDeque<QueuedStartedOutput<'cancel>>,
    /// Reserved output bytes for a pending asynchronous Git response.
    git_output_reservation: usize,
    socket: IngressSocket,
    maintenance: super::OwnerOperation<'cancel>,
    suspended: bool,
    maintenance_aborted: std::cell::Cell<bool>,
    peer: Option<peer::VerifiedCurrentPeer>,
    source: lomi_host_store::AcknowledgedWorkspaceGrant,
    workspace: WorkspaceContext,
    crypto: Crypto,
    assembler: MessageAssembler,
    encoder: MessageEncoder,
    origin: Instant,
    peer_cutoff: Instant,
    applied_observation: Instant,
    started_git_peer: Option<peer::StartedGitPeerObservation>,

    response: Option<PendingResponse<'cancel>>,
    git_read: Option<PendingGitRead<'cancel>>,
    git_mutation: Option<PendingGitMutation<'cancel>>,
}

fn connection_retains_worker_unit(
    bound_work: impl IntoIterator<Item = bool>,
    terminal_output: bool,
    maintenance_deadline: Instant,
    now: Instant,
) -> bool {
    bound_work.into_iter().any(|retained| retained)
        || (terminal_output
            && registry::terminal_emission_retains_operation(maintenance_deadline, now))
}

fn may_suspend_at_message_boundary(
    established: bool,
    peer_cutoff_live: bool,
    retained_operation: bool,
) -> bool {
    established && peer_cutoff_live && !retained_operation
}

enum Crypto {
    Vacant,
    ReadFirst(PendingRemoteConnection),
    WriteSecond(PendingRemoteConnection),
    ReadThird(PendingRemoteConnection),
    Established(RemoteConnectionState),
}
impl<'cancel> Driver<'cancel> {
    /// Operational count only. It is never used to authorize a request.
    pub(super) fn observed_window(
        &self,
        now: Instant,
    ) -> Option<(lomi_remote_protocol::WindowIdentityId, Instant)> {
        let connection = self.connection.as_ref()?;
        if connection.suspended
            || connection.peer_cutoff <= now
            || !matches!(&connection.crypto, Crypto::Established(_))
        {
            return None;
        }
        Some((
            connection.source.intent.preparation.window_identity_id,
            connection.peer_cutoff,
        ))
    }

    pub(super) fn with_coordinator(
        cancelled: &'cancel AtomicBool,
        coordinator: Weak<Coordinator>,
    ) -> Self {
        Self {
            cancelled: Some(cancelled),
            coordinator,
            ..Self::default()
        }
    }
    pub(super) fn has_retained_operation(&self) -> bool {
        self.has_retained_operation_at(Instant::now())
    }
    pub(super) fn has_retained_operation_at(&self, now: Instant) -> bool {
        self.candidate.is_some()
            || self.ticketed.is_some()
            || self
                .connection
                .as_ref()
                .is_some_and(|connection| connection.has_retained_operation_at(now))
    }
    pub(super) fn can_suspend_at_message_boundary(&self, now: Instant) -> bool {
        self.candidate.is_none()
            && self.ticketed.is_none()
            && self
                .connection
                .as_ref()
                .is_none_or(|connection| connection.can_suspend_at_message_boundary(now))
    }
    pub(super) fn suspend_at_message_boundary(&mut self, now: Instant) -> bool {
        if !self.can_suspend_at_message_boundary(now) {
            return false;
        }
        self.connection
            .as_mut()
            .is_none_or(|connection| connection.suspend_at_message_boundary(now))
    }
    pub(super) fn has_pending_setup(&self) -> bool {
        self.candidate.is_some()
            || self.ticketed.is_some()
            || self
                .connection
                .as_ref()
                .is_some_and(Connection::has_pending_setup)
    }
    pub(super) fn has_active_git_writer(&self) -> bool {
        self.connection
            .as_ref()
            .is_some_and(Connection::has_active_git_writer)
    }
    pub(super) fn started_git_continuation(
        &self,
    ) -> Option<super::shared_owner::StartedGitContinuation> {
        self.connection
            .as_ref()
            .and_then(Connection::started_git_continuation)
    }
    pub(super) fn started_git_auth_status(
        &self,
        owner: &super::shared_owner::SharedOwner,
    ) -> Result<Option<super::shared_owner::AuthStatusSnapshot>, super::shared_owner::Error> {
        self.connection
            .as_ref()
            .map(|connection| connection.started_git_auth_status(owner))
            .transpose()
    }
    pub(super) fn started_git_publication_observation(
        &self,
        owner: &super::shared_owner::SharedOwner,
    ) -> Result<super::shared_owner::CloudPublicationFenceObservation, super::shared_owner::Error>
    {
        self.connection
            .as_ref()
            .ok_or(super::shared_owner::Error::Domain(
                super::DomainError::Stale,
            ))?
            .started_git_publication_observation(owner)
    }
    pub(super) fn advance_started_git(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
    ) -> bool {
        let Some(mut connection) = self.connection.take() else {
            return false;
        };
        match connection.advance_started_git(auth, runtime) {
            Ok(advanced) => {
                self.connection = Some(connection);
                advanced
            }
            Err(_) => {
                connection.socket.close();
                false
            }
        }
    }
    pub(super) fn advance_started_git_terminal_from_active(
        &mut self,
        sibling: &mut Driver<'cancel>,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
    ) -> bool {
        let Some(connection) = self.connection.take() else {
            return false;
        };
        let Some(mutation) = connection
            .git_mutation
            .as_ref()
            .filter(|mutation| mutation.lease.is_some())
        else {
            self.connection = Some(connection);
            return false;
        };
        let Some(active) = mutation.continuation.as_ref().cloned() else {
            self.connection = Some(connection);
            return false;
        };
        let active_cancellation = mutation.cancellation.clone();
        let request_runtime = runtime.with_operation(&mutation.operation, &mutation.aborted);
        let advanced = sibling.advance_started_git_terminal(
            auth,
            request_runtime,
            &active,
            request_runtime.started_git_terminal_latches(),
            Some(request_runtime.operation.cancellation_latch()),
            &active_cancellation,
            true,
        );
        self.connection = Some(connection);
        advanced
    }
    fn advance_started_git_terminal(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
        active: &super::shared_owner::StartedGitContinuation,
        latches: super::owner_domain::StartedGitTerminalLatches<'_>,
        cancelled: Option<&'cancel AtomicBool>,
        active_cancellation: &lomi_git::CancellationToken,
        allow_new_terminal_frame: bool,
    ) -> bool {
        let Some(mut connection) = self.connection.take() else {
            return false;
        };
        match connection.advance_started_git_terminal(
            auth,
            runtime,
            active,
            latches,
            cancelled,
            active_cancellation,
            allow_new_terminal_frame,
        ) {
            Ok(advanced) => {
                self.connection = Some(connection);
                advanced
            }
            Err(_) => {
                connection.socket.close();
                false
            }
        }
    }
    pub(super) fn has_established_connection(&self) -> bool {
        self.connection
            .as_ref()
            .is_some_and(Connection::is_established)
    }
    pub(super) fn established_peer_refresh_deadline(&self, now: Instant) -> Option<Instant> {
        self.connection
            .as_ref()
            .filter(|connection| connection.is_established())
            .and_then(|connection| connection.peer_refresh_deadline(now))
    }
    pub(super) fn cancel_started_git(&mut self) {
        if let Some(mutation) = self
            .connection
            .as_mut()
            .and_then(|connection| connection.git_mutation.as_mut())
            .filter(|mutation| mutation.lease.is_some())
        {
            mutation.invalidated = true;
            if let Some(continuation) = &mutation.continuation {
                continuation.invalidate();
            }
            mutation.cancellation.cancel();
        }
    }

    pub(super) fn peer_refresh_deadline(&self, now: Instant) -> Option<Instant> {
        let candidate = self
            .candidate
            .as_ref()
            .and_then(|handoff| handoff_peer_refresh_deadline(handoff, None, now));
        let ticketed = self
            .ticketed
            .as_ref()
            .and_then(|ticketed| ticketed.peer_refresh_deadline(now));
        let connection = self
            .connection
            .as_ref()
            .and_then(|connection| connection.peer_refresh_deadline(now));
        [candidate, ticketed, connection]
            .into_iter()
            .flatten()
            .min()
    }
    pub(super) fn has_immediate_output(&self) -> bool {
        self.candidate.is_some()
            || self.ticketed.is_some()
            || self
                .connection
                .as_ref()
                .is_some_and(|connection| connection.has_immediate_output())
    }
    /// True only for output already staged for send. A terminal producer with
    /// another event ready cannot start a batch; only an explicitly marked
    /// normal terminal stream may replenish one within its bounded burst.
    pub(super) fn has_staged_output(&self) -> bool {
        self.connection
            .as_ref()
            .is_some_and(Connection::has_staged_output)
    }
    pub(super) fn has_staged_message(&self) -> bool {
        self.connection
            .as_ref()
            .is_some_and(Connection::has_staged_message)
    }
    /// Remaining fragments in the response/stream that `turn` would send
    /// first. Started Git owns its own output scheduler, so it has no staged
    /// message count for registry batching.
    pub(super) fn staged_message_remaining(&self) -> Option<usize> {
        if self.has_active_git_writer() {
            return None;
        }
        self.connection
            .as_ref()
            .and_then(Connection::staged_message_remaining)
    }
    pub(super) fn has_staged_terminal_burst(&self) -> bool {
        !self.has_active_git_writer()
            && self
                .connection
                .as_ref()
                .is_some_and(Connection::has_staged_terminal_burst)
    }
    /// Empty means no candidate, ticket, or live transport. A live transport
    /// can outlast its maintenance operation and must remain in the registry.
    pub(super) fn is_empty(&self) -> bool {
        self.candidate.is_none() && self.ticketed.is_none() && self.connection.is_none()
    }
    pub(super) fn discard(&mut self) {
        self.candidate = None;
        self.ticketed = None;
        self.connection = None;
    }
    pub(super) fn accept(
        &mut self,
        handoff: channel::AdmittedChannelHandoff,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
        eligibility: &PeerEligibility,
    ) -> bool {
        if self.has_retained_operation()
            || self.connection.is_some()
            || handoff.check_current(auth, runtime, eligibility).is_err()
        {
            return false;
        }
        self.candidate = Some(handoff);
        true
    }

    /// Runs the ticket POST as the one selected registry stage. A successful
    /// POST sets `defer_network`; consuming that flag here preserves the
    /// standalone Driver's separate actor-pass behavior without allowing a
    /// second aggregate stage in the Registry's selected pass.
    pub(super) fn advance_registry_stage(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
        eligibility: Option<&PeerEligibility>,
    ) -> bool {
        if self.candidate.is_some() {
            if self.poll(auth, runtime, eligibility)
                && let Some(eligibility) = eligibility
                && self.candidate.is_some()
                && self.request_ticket_stage(auth, runtime, eligibility)
                && self.ticketed.is_some()
            {
                let consumed = std::mem::take(&mut self.defer_network);
                debug_assert!(
                    consumed,
                    "a retained ticket must defer its next network stage"
                );
                return true;
            }
            return false;
        }
        self.advance(auth, runtime, eligibility)
    }
    fn request_ticket_stage(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
        eligibility: &PeerEligibility,
    ) -> bool {
        if self.candidate.is_none() {
            return false;
        }

        if self.request_ticket(auth, runtime, eligibility).is_err() {
            self.discard();
            return false;
        }
        true
    }
    pub(super) fn poll(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
        eligibility: Option<&PeerEligibility>,
    ) -> bool {
        if self.connection.is_some() {
            let now = Instant::now();
            if self.connection.as_ref().is_some_and(|connection| {
                peer_cutoff_requires_discard(
                    connection.has_pending_setup(),
                    eligibility.is_some(),
                    connection.peer_cutoff,
                    now,
                )
            }) {
                self.discard();
                return false;
            }
            if peer::check_peer_runtime(runtime).is_err() {
                self.discard();
                return false;
            }
            if eligibility.is_none() {
                // Normal worker-unit settlement deliberately clears Cloud's
                // cache. Pause all IO and force a fresh read on legitimate resume.
                if let Some(c) = self.connection.as_mut() {
                    c.suspended = true;
                }
                return false;
            }
            return true;
        }
        let current =
            eligibility.is_some_and(|eligibility| match (&self.candidate, &self.ticketed) {
                (Some(candidate), None) => {
                    candidate.check_current(auth, runtime, eligibility).is_ok()
                }
                (None, Some(ticketed)) => ticketed.poll_current(auth, runtime, eligibility),
                _ => false,
            });
        if !current {
            self.discard();
        }
        current
    }
    /// Run after normal cloud/peer/channel priority work. One socket frame or
    /// outgoing fragment at most; idle reads never block on a synthetic timeout.
    pub(super) fn advance(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
        eligibility: Option<&PeerEligibility>,
    ) -> bool {
        if std::mem::take(&mut self.defer_network) {
            return false;
        }
        if self.connection.is_some() {
            let Some(eligibility) = eligibility else {
                return false;
            };
            match self.connection_turn(auth, runtime, eligibility) {
                Ok(advanced) => return advanced,
                Err(_) => {
                    self.discard();
                    return false;
                }
            }
        }
        if self.ticketed.is_some() {
            let result = eligibility
                .ok_or(peer::PeerError::Invalid)
                .and_then(|e| self.connect(auth, runtime, e));
            if result.is_ok() {
                return true;
            }
            self.discard();
            return false;
        }
        false
    }
    fn request_ticket(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
        eligibility: &PeerEligibility,
    ) -> peer::ResultPeer<()> {
        // Take before every fallible stage, especially before POST. Uncertainty
        // can never restore/requeue the candidate or replay this ticket request.
        let handoff = self.candidate.take().ok_or(peer::PeerError::Invalid)?;
        handoff.check_current(auth, runtime, eligibility)?;
        let transport = DataTransport::new(
            RemoteApiOrigin::new(
                auth.trusted_configuration(),
                eligibility.binding.scope.remote_api_origin.clone(),
            )
            .map_err(|_| peer::PeerError::Invalid)?,
        )
        .map_err(|_| peer::PeerError::Invalid)?;
        let provider = peer::ProviderCapture::read(auth, runtime, eligibility)?;
        let mut effect = peer::owner_turn(runtime, || {
            runtime.owner.capture_channel_ticket(
                runtime.operation,
                eligibility,
                &handoff,
                runtime.base,
                runtime.anchor,
            )
        })?;
        peer::owner_turn(runtime, || effect.try_validate(&provider))?;
        let now = runtime
            .base
            .saturating_add(runtime.anchor.elapsed().as_secs());
        let access = peer::managed(auth.access_credential(now))?;
        let params = handoff.ticket_params();
        let operation = runtime.operation;
        let gate = runtime.gate;
        let paused = runtime.paused;
        let stopping = runtime.stopping;
        let public_pending = &runtime.public_io.setup().pending;
        // Sync enforces a watcher which cannot capture HostAuth/provider,
        // Runtime's Cell, Store/Domain turns, or the mutable driver/handoff.
        let watch = || {
            operation.check().map_err(|error| match error {
                super::DomainError::Deadline => BudgetStop::Deadline,
                _ => BudgetStop::Cancelled,
            })?;
            if gate.load(Ordering::Acquire)
                || paused.load(Ordering::Acquire)
                || stopping.load(Ordering::Acquire)
                || public_pending.load(Ordering::Acquire)
            {
                return Err(BudgetStop::Cancelled);
            }
            Ok(())
        };
        let watch: &WatchCheck<'_> = &watch;
        handoff.check_current(auth, runtime, eligibility)?;
        effect
            .check_boundary(&provider)
            .map_err(owner_error_at!())?;
        let budget = transport.with_budget(handoff.deadline(), watch);
        let request_started = Instant::now();
        let response = budget.channel_ticket(handoff.channel_id(), &params, &access);
        let response = response.map_err(|_| peer::PeerError::Invalid)?;
        let provider = peer::ProviderCapture::read(auth, runtime, eligibility)?;
        peer::owner_turn(runtime, || effect.try_validate(&provider))?;
        effect
            .check_boundary(&provider)
            .map_err(owner_error_at!())?;
        handoff.check_current(auth, runtime, eligibility)?;
        let received_at = Instant::now();
        let expires_in_ms = response.expires_in_ms.0;
        let expires_at = request_started
            .checked_add(Duration::from_millis(expires_in_ms))
            .ok_or(peer::PeerError::Invalid)?
            .min(handoff.deadline());
        if !ticket_bounds_current_at(
            received_at,
            request_started,
            expires_in_ms,
            expires_at,
            handoff.deadline(),
            response.channel_id,
            handoff.channel_id(),
            &response.ticket,
        ) {
            return Err(peer::PeerError::Invalid);
        }
        drop(effect);
        self.defer_network = true;
        self.ticketed = Some(TicketedAdmission {
            handoff,
            channel_id: response.channel_id,
            ticket: response.ticket,
            request_started,
            expires_in_ms,
            expires_at,
        });
        Ok(())
    }
    fn connect(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
        eligibility: &PeerEligibility,
    ) -> peer::ResultPeer<()> {
        // Consume once before any fallible IO. A connect failure cannot replay.
        let ticketed = self.ticketed.take().ok_or(peer::PeerError::Invalid)?;
        if !ticketed.current(auth, runtime, eligibility) {
            return Err(peer::PeerError::Invalid);
        }
        let handoff = ticketed.handoff;
        let grant = &handoff.signed_grant().grant;
        if !RemoteConnectionState::active_rpc_purpose(&handoff.signed_admission().context) {
            return Err(peer::PeerError::Invalid);
        }
        let workspace = WorkspaceContext {
            workspace_id: lomi_remote_protocol::WorkspaceId::from_bytes(grant.workspace_id)
                .map_err(|_| peer::PeerError::Invalid)?,
            workspace_epoch: lomi_remote_protocol::WorkspaceEpoch::from_bytes(
                grant.workspace_epoch,
            )
            .map_err(|_| peer::PeerError::Invalid)?,
            runtime_id: lomi_remote_protocol::RuntimeId::from_bytes(grant.runtime_id)
                .map_err(|_| peer::PeerError::Invalid)?,
            runtime_generation: DecimalU64(grant.runtime_generation),
            host_access_epoch: DecimalU64(grant.access_epoch),
            grant_revision: DecimalU64(grant.grant_revision),
        };
        let source = handoff.source().clone();
        let current = peer::Worker::default().read_current_pairing(
            auth,
            runtime,
            eligibility,
            source.clone(),
        )?;
        let evidence = runtime.remote_worker_evidence(auth, eligibility)?;
        let (pending, endpoint) = {
            let turn = peer::owner_turn(runtime, || {
                runtime
                    .owner
                    .try_remote_workspace_turn(&evidence, &current, &workspace)
            })?;
            let endpoint = turn
                .relay_endpoint()
                .map_err(|_| peer::PeerError::Invalid)?;
            let pending = turn
                .begin_connection(
                    handoff.canonical_context(),
                    handoff.signed_grant(),
                    handoff.signed_admission(),
                )
                .map_err(|_| peer::PeerError::Invalid)?;
            (pending, endpoint)
        };
        let connect_deadline = current
            .io_deadline(&evidence)
            .ok_or(peer::PeerError::Invalid)?
            .min(handoff.deadline());
        let cutoff = current.fresh_until();
        let applied_observation = current.observed_at();
        drop(evidence);
        let operation = runtime.operation;
        let gate = runtime.gate;
        let paused = runtime.paused;
        let stopping = runtime.stopping;
        let public_pending = &runtime.public_io.setup().pending;
        let owner = runtime.owner;
        let continuation = current.continuation();
        let check = || {
            watch(operation, gate, paused, stopping, public_pending)?;
            owner
                .peer_original_boundary(operation, continuation)
                .map_err(|_| BudgetStop::Cancelled)
        };
        let relay = RelayTransport::new(endpoint).map_err(|_| peer::PeerError::Invalid)?;

        let socket = relay
            .connect(
                &WssAdmissionFrame {
                    channel_id: ticketed.channel_id,
                    ticket: ticketed.ticket,
                },
                ticketed.request_started,
                ticketed.expires_in_ms,
                connect_deadline,
                &check,
            )
            .map_err(|_| peer::PeerError::Invalid)?;
        self.connection = Some(Connection {
            coordinator: self.coordinator.clone(),
            terminal: None,
            watch: None,
            watch_generation: 0,
            workspace_stream: None,
            workspace_stream_call: None,
            next_stream_class: 0,
            stream: None,
            watch_call: None,
            started_git_outputs: VecDeque::new(),
            git_output_reservation: 0,
            socket: ingress_socket(socket),
            source,
            workspace,
            crypto: Crypto::ReadFirst(pending),
            maintenance: super::OwnerOperation::new(
                runtime.operation.deadline(),
                self.cancelled.ok_or(peer::PeerError::Invalid)?,
            ),
            peer: None,
            suspended: false,
            maintenance_aborted: std::cell::Cell::new(false),
            assembler: MessageAssembler::new(),
            encoder: MessageEncoder::new(),
            origin: Instant::now(),
            peer_cutoff: cutoff,
            applied_observation,
            started_git_peer: None,

            response: None,
            git_read: None,
            git_mutation: None,
        });
        Ok(())
    }
    fn connection_turn(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
        eligibility: &PeerEligibility,
    ) -> peer::ResultPeer<bool> {
        let mut c = self.connection.take().ok_or(peer::PeerError::Invalid)?;

        let result = c.turn(auth, runtime, eligibility, self.cancelled);
        if result.is_ok() {
            self.connection = Some(c);
        }
        result
    }
}

fn invalid<E>(_: E) -> peer::PeerError {
    peer::PeerError::Invalid
}
fn watch(
    operation: &super::OwnerOperation<'_>,
    gate: &AtomicBool,
    paused: &AtomicBool,
    stopping: &AtomicBool,
    public_pending: &AtomicBool,
) -> Result<(), BudgetStop> {
    operation.check().map_err(|e| match e {
        super::DomainError::Deadline => BudgetStop::Deadline,
        _ => BudgetStop::Cancelled,
    })?;
    if [gate, paused, stopping, public_pending]
        .iter()
        .any(|a| a.load(Ordering::Acquire))
    {
        return Err(BudgetStop::Cancelled);
    }
    Ok(())
}
impl<'cancel> Connection<'cancel> {
    fn started_git_output_usage_for(
        encoder: &MessageEncoder,
        outputs: &VecDeque<QueuedStartedOutput<'cancel>>,
        reservation: usize,
    ) -> (usize, usize) {
        let encoder_bytes = encoder.retained_bytes();
        let current_frames = usize::from(encoder_bytes != 0);
        let (queued_count, queued_bytes) =
            outputs
                .iter()
                .fold((0usize, 0usize), |(count, bytes), output| {
                    (
                        count.saturating_add(1),
                        bytes.saturating_add(output.bytes.len()),
                    )
                });
        (
            current_frames
                .saturating_add(queued_count)
                .saturating_add(usize::from(reservation != 0)),
            encoder_bytes
                .saturating_add(queued_bytes)
                .saturating_add(reservation),
        )
    }

    fn reserve_started_git_output_for(
        encoder: &MessageEncoder,
        outputs: &VecDeque<QueuedStartedOutput<'cancel>>,
        reservation: usize,
        bytes: usize,
    ) -> peer::ResultPeer<()> {
        let (count, used_bytes) = Self::started_git_output_usage_for(encoder, outputs, reservation);
        if bytes == 0
            || bytes > MAX_MESSAGE_LEN
            || count >= MAX_STARTED_GIT_OUTPUT_MESSAGES
            || used_bytes
                .checked_add(bytes)
                .is_none_or(|total| total > MAX_STARTED_GIT_OUTPUT_BYTES)
        {
            return Err(peer::PeerError::Invalid);
        }
        Ok(())
    }

    fn reserve_async_git_output_for(
        encoder: &MessageEncoder,
        outputs: &VecDeque<QueuedStartedOutput<'cancel>>,
        reservation: &mut usize,
        bytes: usize,
    ) -> peer::ResultPeer<()> {
        if *reservation != 0 {
            return Err(peer::PeerError::Invalid);
        }
        Self::reserve_started_git_output_for(encoder, outputs, *reservation, bytes)?;
        *reservation = bytes;
        Ok(())
    }

    fn reserve_started_git_output(&self, bytes: usize) -> peer::ResultPeer<()> {
        Self::reserve_started_git_output_for(
            &self.encoder,
            &self.started_git_outputs,
            self.git_output_reservation,
            bytes,
        )
    }

    fn has_pending_output(&self) -> bool {
        self.response.is_some() || self.stream.is_some() || !self.started_git_outputs.is_empty()
    }

    fn enqueue_started_git_response(
        &mut self,
        bytes: Vec<u8>,
        response: PendingResponse<'cancel>,
    ) -> peer::ResultPeer<()> {
        self.reserve_started_git_output(bytes.len())?;
        if response.remaining != frame_count(bytes.len()) || response.remaining == 0 {
            return Err(peer::PeerError::Invalid);
        }
        self.started_git_outputs.push_back(QueuedStartedOutput {
            kind: MessageKind::RpcResponse,
            bytes: bytes.into_boxed_slice(),
            response: Some(response),
            stream: None,
        });
        Ok(())
    }

    fn enqueue_reserved_git_response(
        &mut self,
        bytes: Vec<u8>,
        response: PendingResponse<'cancel>,
    ) -> peer::ResultPeer<()> {
        let reservation = self.git_output_reservation;
        if reservation == 0 || bytes.len() > reservation {
            return Err(peer::PeerError::Invalid);
        }
        self.git_output_reservation = 0;
        if let Err(error) = self.enqueue_started_git_response(bytes, response) {
            self.git_output_reservation = reservation;
            return Err(error);
        }
        Ok(())
    }

    fn enqueue_started_git_stream(
        &mut self,
        kind: MessageKind,
        bytes: Vec<u8>,
        stream: PendingStream<'cancel>,
    ) -> peer::ResultPeer<()> {
        self.reserve_started_git_output(bytes.len())?;
        if stream.remaining != frame_count(bytes.len()) || stream.remaining == 0 {
            return Err(peer::PeerError::Invalid);
        }
        self.started_git_outputs.push_back(QueuedStartedOutput {
            kind,
            bytes: bytes.into_boxed_slice(),
            response: None,
            stream: Some(stream),
        });
        Ok(())
    }

    fn activate_started_git_output(&mut self) -> peer::ResultPeer<bool> {
        if self.response.is_some() || self.stream.is_some() {
            return Ok(false);
        }
        let Some(mut queued) = self.started_git_outputs.pop_front() else {
            return Ok(false);
        };
        let kind = queued.kind;
        let bytes = std::mem::take(&mut queued.bytes).into_vec();
        let response = queued.response.take();
        let stream = queued.stream.take();
        if response.is_some() == stream.is_some() {
            return Err(peer::PeerError::Invalid);
        }
        self.encoder.begin(kind, bytes).map_err(invalid_at!())?;
        self.response = response;
        self.stream = stream;
        Ok(true)
    }

    fn is_established(&self) -> bool {
        matches!(&self.crypto, Crypto::Established(_)) && !self.socket.is_closed()
    }
    /// A live socket and its bounded terminal producer queue are resources, not
    /// unfinished owner operations. Keep the worker unit for the handshake,
    /// partial inbound message, RPC/stream operation, or Git continuation whose
    /// original deadline is still retained here. Near unit expiry, terminal
    /// producer output can wait across a fresh unit at a completed-message
    /// boundary.
    fn has_retained_operation_at(&self, now: Instant) -> bool {
        let terminal_output = self
            .terminal
            .as_ref()
            .is_some_and(RemoteTerminalState::has_immediate_output);
        connection_retains_worker_unit(
            [
                self.response.is_some(),
                self.stream.is_some(),
                !self.started_git_outputs.is_empty(),
                self.git_output_reservation != 0,
                self.git_read.is_some(),
                self.git_mutation.is_some(),
                !matches!(&self.crypto, Crypto::Established(_)),
                self.assembler.has_pending_message(),
                self.peer_refresh_deadline(now).is_some(),
            ],
            terminal_output,
            self.maintenance.deadline(),
            now,
        )
    }

    fn can_suspend_at_message_boundary(&self, now: Instant) -> bool {
        may_suspend_at_message_boundary(
            self.is_established(),
            now < self.peer_cutoff,
            self.has_retained_operation_at(now),
        )
    }

    fn suspend_at_message_boundary(&mut self, now: Instant) -> bool {
        if !self.can_suspend_at_message_boundary(now) {
            return false;
        }
        self.peer = None;
        self.started_git_peer = None;
        self.suspended = true;
        true
    }

    fn has_pending_setup(&self) -> bool {
        matches!(
            &self.crypto,
            Crypto::ReadFirst(_) | Crypto::WriteSecond(_) | Crypto::ReadThird(_)
        )
    }

    fn has_active_git_writer(&self) -> bool {
        self.git_mutation
            .as_ref()
            .is_some_and(|mutation| mutation.lease.is_some())
    }

    fn started_git_continuation(&self) -> Option<super::shared_owner::StartedGitContinuation> {
        self.git_mutation
            .as_ref()
            .filter(|mutation| mutation.lease.is_some())
            .and_then(|mutation| mutation.continuation.clone())
    }

    fn started_git_auth_status(
        &self,
        owner: &super::shared_owner::SharedOwner,
    ) -> Result<super::shared_owner::AuthStatusSnapshot, super::shared_owner::Error> {
        let mutation = self
            .git_mutation
            .as_ref()
            .filter(|mutation| mutation.lease.is_some())
            .ok_or(super::shared_owner::Error::Domain(
                super::DomainError::Stale,
            ))?;
        let continuation =
            mutation
                .continuation
                .as_ref()
                .ok_or(super::shared_owner::Error::Domain(
                    super::DomainError::Stale,
                ))?;
        owner.auth_status_started_git(&mutation.operation, continuation)
    }

    fn started_git_publication_observation(
        &self,
        owner: &super::shared_owner::SharedOwner,
    ) -> Result<super::shared_owner::CloudPublicationFenceObservation, super::shared_owner::Error>
    {
        let mutation = self
            .git_mutation
            .as_ref()
            .filter(|mutation| mutation.lease.is_some())
            .ok_or(super::shared_owner::Error::Domain(
                super::DomainError::Stale,
            ))?;
        let continuation =
            mutation
                .continuation
                .as_ref()
                .ok_or(super::shared_owner::Error::Domain(
                    super::DomainError::Stale,
                ))?;
        owner.cloud_publication_fence_observation_started_git(
            &mutation.operation,
            continuation,
            continuation.runtime().scope.authorization_generation,
            Some(&continuation.runtime().scope),
        )
    }

    fn advance_started_git(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
    ) -> peer::ResultPeer<bool> {
        // Move the active operation out while terminal callbacks borrow the
        // connection mutably. Its OwnerOperation, deadline, and cancellation
        // identity remain the original objects; restore it before polling the
        // executor or returning a recoverable result.
        let mut mutation = self.git_mutation.take().ok_or(peer::PeerError::Invalid)?;
        if mutation.lease.is_none() {
            self.git_mutation = Some(mutation);
            return Err(peer::PeerError::Invalid);
        }
        let Some(continuation) = mutation.continuation.as_ref().cloned() else {
            self.git_mutation = Some(mutation);
            return Err(peer::PeerError::Invalid);
        };
        let request_runtime = runtime.with_operation(&mutation.operation, &mutation.aborted);
        let active_cancellation = mutation.cancellation.clone();
        let finalizing = mutation
            .state
            .as_ref()
            .is_some_and(|state| matches!(state, PendingGitMutationState::Finalize { .. }));
        let invalidated = mutation.invalidated;
        if !invalidated {
            match super::cloud::maintain_started_git_control_plane(
                auth,
                request_runtime,
                &continuation,
            ) {
                Ok(_) => {}
                Err(_) => {
                    continuation.invalidate();
                    active_cancellation.cancel();
                    mutation.invalidated = true;
                }
            }
        } else {
            continuation.invalidate();
            active_cancellation.cancel();
        }
        let terminal_result = self.advance_started_git_terminal(
            auth,
            request_runtime,
            &continuation,
            request_runtime.started_git_terminal_latches(),
            Some(request_runtime.operation.cancellation_latch()),
            &active_cancellation,
            !finalizing,
        );
        self.git_mutation = Some(mutation);
        let terminal_advanced = terminal_result?;
        let mutation_advanced = self.poll_git_mutation(auth, runtime, None)?;
        Ok(terminal_advanced || mutation_advanced)
    }

    fn started_git_peer_for(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
        active: &super::shared_owner::StartedGitContinuation,
    ) -> peer::ResultPeer<Option<peer::StartedGitPeerObservation>> {
        let target = match &self.crypto {
            Crypto::Established(connection) => connection
                .started_git_pairing_target()
                .map_err(|_| peer::PeerError::Invalid)?,
            _ => return Err(peer::PeerError::Invalid),
        };
        if let Some(observation) = self.started_git_peer.as_ref()
            && observation.target().connection == target.connection
            && observation.current_for(active, runtime.operation, target.connection)
            && Instant::now()
                .checked_add(PEER_REFRESH_MARGIN)
                .is_some_and(|refresh_by| refresh_by < observation.fresh_until())
        {
            return Ok(Some(observation.clone()));
        }
        match peer::refresh_established_started_git_pairing(auth, runtime, active, target.clone())?
        {
            Some(observation) => {
                self.started_git_peer = Some(observation.clone());
                Ok(Some(observation))
            }
            None => {
                let observation = self
                    .started_git_peer
                    .as_ref()
                    .filter(|observation| {
                        observation.target().connection == target.connection
                            && observation.current_for(active, runtime.operation, target.connection)
                    })
                    .cloned();
                Ok(observation)
            }
        }
    }

    /// Services one established channel while the exact Git writer remains
    /// Started. It resumes already-produced output, admits bounded terminal
    /// input/control, and answers unrelated requests with a no-effect busy
    /// response. It never polls new nonterminal streams or admits effects.
    fn advance_started_git_terminal(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
        active: &super::shared_owner::StartedGitContinuation,
        latches: super::owner_domain::StartedGitTerminalLatches<'_>,
        cancelled: Option<&'cancel AtomicBool>,
        active_cancellation: &lomi_git::CancellationToken,
        allow_new_terminal_frame: bool,
    ) -> peer::ResultPeer<bool> {
        runtime.check()?;
        if !active.is_current(runtime.operation) || !latches.current() {
            return Err(peer::PeerError::Invalid);
        }
        let Some(observation) = self.started_git_peer_for(auth, runtime, active)? else {
            return Ok(false);
        };
        if !observation.current_for(active, runtime.operation, observation.target().connection) {
            return Ok(false);
        }
        self.peer_cutoff = observation.fresh_until();
        self.peer = None;
        self.suspended = false;
        self.activate_started_git_output()?;
        let mut advanced = false;
        if let Some(mut response) = self.response.take() {
            let sent = if terminal_call(&response.request.call) {
                self.send_started_git_terminal_response(
                    runtime,
                    active,
                    &observation,
                    latches,
                    &mut response,
                )?
            } else {
                self.send_started_git_response(
                    runtime,
                    active,
                    &observation,
                    latches,
                    &mut response,
                )?
            };
            advanced |= sent;
            if response.remaining > 0 {
                self.response = Some(response);
            }
        } else if self.stream.is_some() {
            let terminal_delivery = self
                .stream
                .as_ref()
                .is_some_and(|stream| stream.delivery.is_some());
            let sent = if terminal_delivery {
                self.send_started_git_terminal_stream(runtime, active, &observation, latches)?
            } else {
                self.send_started_git_nonterminal_stream(runtime, active, &observation, latches)?
            };
            advanced |= sent;
        }
        self.activate_started_git_output()?;

        let deadline = runtime
            .operation
            .deadline()
            .min(active.hard_deadline())
            .min(active.heartbeat_deadline())
            .min(active.peer_deadline())
            .min(observation.fresh_until());
        if Instant::now() >= deadline {
            return Err(peer::PeerError::Invalid);
        }
        self.assembler
            .expire(u64::try_from(self.origin.elapsed().as_millis()).map_err(invalid_at!())?)
            .map_err(invalid_at!())?;
        let mut request = None;
        let received_frame;
        {
            let Crypto::Established(connection) = &mut self.crypto else {
                return Err(peer::PeerError::Invalid);
            };
            let mut channel_turn = runtime
                .owner
                .try_started_git_terminal_channel_turn(
                    runtime.operation,
                    active,
                    &observation,
                    latches,
                    connection,
                )
                .map_err(owner_error_at!())?;
            let channel_watch = channel_turn.into_io_watch();
            let check = || {
                if Instant::now() >= deadline {
                    return Err(BudgetStop::Deadline);
                }
                if !runtime.operation.check().is_ok()
                    || !active.is_current(runtime.operation)
                    || !latches.current()
                    || !observation.current_for(
                        active,
                        runtime.operation,
                        observation.target().connection,
                    )
                    || !channel_watch.current()
                {
                    return Err(BudgetStop::Cancelled);
                }
                Ok(())
            };
            let incoming = if allow_new_terminal_frame {
                self.socket
                    .poll_binary(deadline, &check)
                    .map_err(invalid_at!())?
            } else {
                Poll::Pending
            };
            received_frame = matches!(incoming, Poll::Ready(_));
            if let Poll::Ready(frame) = incoming {
                let plaintext = channel_watch
                    .open_frame(connection, &frame)
                    .map_err(invalid_at!())?;
                let now_ms =
                    u64::try_from(self.origin.elapsed().as_millis()).map_err(invalid_at!())?;
                if let Some(message) = self
                    .assembler
                    .push(plaintext.as_ref(), now_ms)
                    .map_err(invalid_at!())?
                {
                    if message.kind != MessageKind::RpcRequest {
                        return Err(peer::PeerError::Invalid);
                    }
                    let decoded = lomi_remote_protocol::rpc::decode_request(&message.bytes)
                        .map_err(invalid_at!())?;
                    if request.is_some() {
                        return Err(peer::PeerError::Invalid);
                    }
                    request = Some((decoded, Instant::now()));
                }
            }
        }

        let received_request = request.is_some();
        if let Some((request, received)) = request {
            self.execute_started_git_terminal_request(
                runtime,
                active,
                &observation,
                latches,
                cancelled.ok_or(peer::PeerError::Invalid)?,
                active_cancellation,
                request,
                received,
            )?;
            advanced = true;
        }

        if allow_new_terminal_frame
            && !received_request
            && self.stream.is_none()
            && self.reserve_started_git_output(MAX_MESSAGE_LEN).is_ok()
        {
            let Some(cancelled) = cancelled else {
                return Err(peer::PeerError::Invalid);
            };
            let Some(terminal) = self.terminal.as_mut() else {
                return Err(peer::PeerError::Invalid);
            };
            let Crypto::Established(connection) = &mut self.crypto else {
                return Err(peer::PeerError::Invalid);
            };
            if let Some(frame) = terminal
                .next_frame_started_git(
                    connection,
                    runtime.operation,
                    active,
                    &observation,
                    latches,
                )
                .map_err(invalid_at!())?
            {
                let bytes = serde_json::to_vec(frame.frame()).map_err(invalid_at!())?;
                let remaining = frame_count(bytes.len());
                let stream = PendingStream {
                    operation: super::OwnerOperation::new(runtime.operation.deadline(), cancelled),
                    aborted: std::cell::Cell::new(false),
                    peer: None,
                    kind: MessageKind::TerminalFrame,
                    authorization_call: None,
                    delivery: Some(frame),
                    burst_pending_first_send: false,
                    burst_started: None,
                    remaining,
                };
                self.enqueue_started_git_stream(MessageKind::TerminalFrame, bytes, stream)?;
                advanced = true;
            }
        }
        self.activate_started_git_output()?;
        Ok(advanced || received_frame)
    }

    fn execute_started_git_terminal_request(
        &mut self,
        runtime: RuntimeWithOperation<'cancel, '_>,
        active: &super::shared_owner::StartedGitContinuation,
        observation: &peer::StartedGitPeerObservation,
        latches: super::owner_domain::StartedGitTerminalLatches<'_>,
        cancelled: &'cancel AtomicBool,
        active_cancellation: &lomi_git::CancellationToken,
        request: RpcRequest,
        received: Instant,
    ) -> peer::ResultPeer<()> {
        if operation_control_call(&request.call)
            && active_started_git_operation_control_call(&request.call, active)
        {
            return self.execute_started_git_operation_control(
                runtime,
                active,
                observation,
                latches,
                cancelled,
                active_cancellation,
                request,
                received,
            );
        }
        if operation_control_call(&request.call) {
            return self.queue_started_git_busy_response(
                runtime,
                active,
                observation,
                latches,
                cancelled,
                request,
                received,
            );
        }
        if !terminal_call(&request.call) {
            return self.queue_started_git_busy_response(
                runtime,
                active,
                observation,
                latches,
                cancelled,
                request,
                received,
            );
        }
        let request_deadline = received
            .checked_add(Duration::from_millis(request.timeout_ms.get()))
            .ok_or(peer::PeerError::Invalid)?
            .min(runtime.operation.deadline());
        if Instant::now() >= request_deadline {
            return Err(peer::PeerError::Invalid);
        }
        // Reserve before the terminal effect so an accepted input can always
        // retain its acknowledgement within the per-channel queue bounds.
        self.reserve_started_git_output(MAX_MESSAGE_LEN)?;
        let target = terminal_target(&request.call)
            .cloned()
            .ok_or(peer::PeerError::Invalid)?;
        let coordinator = self.coordinator.upgrade().ok_or(peer::PeerError::Invalid)?;
        let actor = coordinator
            .workspace_lock(target.workspace.workspace_id)
            .map_err(|_| peer::PeerError::Invalid)?;
        let queued = {
            let _actor =
                super::super::rpc::actor_lock(&actor, runtime.operation).map_err(invalid_at!())?;
            let Crypto::Established(connection) = &mut self.crypto else {
                return Err(peer::PeerError::Invalid);
            };
            let turn = runtime
                .owner
                .try_started_git_terminal_turn(
                    runtime.operation,
                    active,
                    observation,
                    latches,
                    connection,
                    &target,
                )
                .map_err(owner_error_at!())?;
            turn.before_queue(connection, &request, request_deadline)
                .map_err(invalid_at!())?
        };
        let Some(terminal) = self.terminal.as_mut() else {
            return Err(peer::PeerError::Invalid);
        };
        let operation = super::OwnerOperation::new(request_deadline, cancelled);
        let aborted = std::cell::Cell::new(false);
        let response = match terminal.execute_started_git(
            match &mut self.crypto {
                Crypto::Established(connection) => connection,
                _ => return Err(peer::PeerError::Invalid),
            },
            runtime.operation,
            active,
            observation,
            latches,
            &request,
            &queued,
        ) {
            Ok(result) => RpcResponse::Result {
                v: request.v,
                request_id: request.request_id.clone(),
                result,
            },
            Err(error)
                if error.effect() == lomi_remote_protocol::Effect::Unknown
                    || matches!(
                        error.code(),
                        lomi_remote_protocol::ErrorCode::ScopeDenied
                            | lomi_remote_protocol::ErrorCode::ServiceUnavailable
                    ) =>
            {
                return Err(peer::PeerError::Invalid);
            }
            Err(error) => RpcResponse::Error {
                v: request.v,
                request_id: request.request_id.clone(),
                operation_id: None,
                error,
            },
        };
        let bytes = serde_json::to_vec(&response).map_err(invalid_at!())?;
        let remaining = frame_count(bytes.len());
        self.enqueue_started_git_response(
            bytes,
            PendingResponse {
                operation,
                aborted,
                request,
                peer: None,
                operation_control: false,
                operation_disclosure: None,
                git_receipt_disclosure: None,
                remaining,
            },
        )?;
        Ok(())
    }

    fn queue_started_git_busy_response(
        &mut self,
        runtime: RuntimeWithOperation<'cancel, '_>,
        active: &super::shared_owner::StartedGitContinuation,
        observation: &peer::StartedGitPeerObservation,
        latches: super::owner_domain::StartedGitTerminalLatches<'_>,
        cancelled: &'cancel AtomicBool,
        request: RpcRequest,
        received: Instant,
    ) -> peer::ResultPeer<()> {
        let request_deadline = received
            .checked_add(Duration::from_millis(request.timeout_ms.get()))
            .ok_or(peer::PeerError::Invalid)?
            .min(runtime.operation.deadline());
        if Instant::now() >= request_deadline {
            return Err(peer::PeerError::Invalid);
        }
        // Reserve before the durable cancel annotation can be committed.
        self.reserve_started_git_output(MAX_FRAGMENT_PAYLOAD_LEN)?;
        let Crypto::Established(connection) = &mut self.crypto else {
            return Err(peer::PeerError::Invalid);
        };
        let mut turn = runtime
            .owner
            .try_started_git_terminal_channel_turn(
                runtime.operation,
                active,
                observation,
                latches,
                connection,
            )
            .map_err(owner_error_at!())?;
        if operation_control_call(&request.call) {
            turn.cached_operation_response(connection, &request, request_deadline, None)
        } else {
            turn.cached_response(connection, &request, request_deadline)
        }
        .map_err(invalid_at!())?;
        let watch = turn.into_io_watch();
        if !watch.current() {
            connection.dispose();
            return Err(peer::PeerError::Invalid);
        }
        drop(watch);
        drop(turn);

        let response = RpcResponse::Error {
            v: request.v,
            request_id: request.request_id.clone(),
            operation_id: None,
            error: host_busy_error(),
        };
        let bytes = serde_json::to_vec(&response).map_err(invalid_at!())?;
        let remaining = frame_count(bytes.len());
        let operation_control = operation_control_call(&request.call);
        let pending = PendingResponse {
            operation: super::OwnerOperation::new(request_deadline, cancelled),
            aborted: std::cell::Cell::new(false),
            request,
            peer: None,
            operation_control,
            operation_disclosure: None,
            git_receipt_disclosure: None,
            remaining,
        };
        self.enqueue_started_git_response(bytes, pending)
    }

    fn execute_started_git_operation_control(
        &mut self,
        runtime: RuntimeWithOperation<'cancel, '_>,
        active: &super::shared_owner::StartedGitContinuation,
        observation: &peer::StartedGitPeerObservation,
        latches: super::owner_domain::StartedGitTerminalLatches<'_>,
        cancelled: &'cancel AtomicBool,
        active_cancellation: &lomi_git::CancellationToken,
        request: RpcRequest,
        received: Instant,
    ) -> peer::ResultPeer<()> {
        let request_deadline = received
            .checked_add(Duration::from_millis(request.timeout_ms.get()))
            .ok_or(peer::PeerError::Invalid)?
            .min(runtime.operation.deadline())
            .min(active.hard_deadline())
            .min(active.heartbeat_deadline())
            .min(active.peer_deadline())
            .min(observation.fresh_until());
        if Instant::now() >= request_deadline {
            return Err(peer::PeerError::Invalid);
        }
        // Reserve before the durable cancel annotation can be committed.
        self.reserve_started_git_output(MAX_FRAGMENT_PAYLOAD_LEN)?;
        let (workspace, operation_id) = match &request.call {
            RpcCall::OperationStatus(params) => (params.context.workspace_id, params.operation_id),
            RpcCall::OperationCancel(params) => (params.context.workspace_id, params.operation_id),
            _ => return Err(peer::PeerError::Invalid),
        };
        if workspace != active.context_workspace() || operation_id != active.operation_id() {
            return Err(peer::PeerError::Invalid);
        }
        let coordinator = self.coordinator.upgrade().ok_or(peer::PeerError::Invalid)?;
        let actor = coordinator
            .workspace_lock(workspace)
            .map_err(|_| peer::PeerError::Invalid)?;
        let local_operation = super::OwnerOperation::new(request_deadline, cancelled);
        let actor_guard =
            super::super::rpc::actor_lock(&actor, &local_operation).map_err(invalid_at!())?;
        let Crypto::Established(connection) = &mut self.crypto else {
            return Err(peer::PeerError::Invalid);
        };
        let mut turn = runtime
            .owner
            .try_started_git_terminal_channel_turn(
                runtime.operation,
                active,
                observation,
                latches,
                connection,
            )
            .map_err(owner_error_at!())?;
        let actor_id = connection.consumer_actor();
        let outcome = turn
            .operation_control(connection, &request, actor_id, request_deadline, cancelled)
            .map_err(owner_error_at!())?;
        let (response, disclosure) = match outcome {
            Some((receipt, signal_executor)) => {
                if signal_executor {
                    active_cancellation.cancel();
                }
                let disclosure = super::super::remote_operations::RemoteOperationDisclosure::from_started_git_receipt(
                    receipt,
                    &request,
                    actor_id,
                    active.capabilities(),
                    connection.connection_identity(),
                    request_deadline,
                )
                .ok_or(peer::PeerError::Invalid)?;
                let response = disclosure.response(&request).map_err(invalid_at!())?;
                (response, Some(disclosure))
            }
            None => {
                turn.cached_operation_response(connection, &request, request_deadline, None)
                    .map_err(invalid_at!())?;
                (
                    RpcResponse::Error {
                        v: request.v,
                        request_id: request.request_id.clone(),
                        operation_id: None,
                        error: operation_not_found(),
                    },
                    None,
                )
            }
        };
        let bytes = serde_json::to_vec(&response).map_err(invalid_at!())?;
        if bytes.is_empty() || bytes.len() > MAX_FRAGMENT_PAYLOAD_LEN {
            return Err(peer::PeerError::Invalid);
        }
        drop(actor_guard);
        let remaining = frame_count(bytes.len());
        let pending = PendingResponse {
            operation: local_operation,
            aborted: std::cell::Cell::new(false),
            request,
            peer: None,
            operation_control: true,
            operation_disclosure: disclosure,
            git_receipt_disclosure: None,
            remaining,
        };
        self.enqueue_started_git_response(bytes, pending)
    }

    fn send_started_git_terminal_response(
        &mut self,
        runtime: RuntimeWithOperation<'cancel, '_>,
        active: &super::shared_owner::StartedGitContinuation,
        observation: &peer::StartedGitPeerObservation,
        latches: super::owner_domain::StartedGitTerminalLatches<'_>,
        response: &mut PendingResponse<'cancel>,
    ) -> peer::ResultPeer<bool> {
        response
            .operation
            .check()
            .map_err(|_| peer::PeerError::Invalid)?;
        if response.aborted.get() {
            return Err(peer::PeerError::Invalid);
        }
        let target = terminal_target(&response.request.call)
            .cloned()
            .ok_or(peer::PeerError::Invalid)?;
        let deadline = response
            .operation
            .deadline()
            .min(runtime.operation.deadline())
            .min(active.hard_deadline())
            .min(active.heartbeat_deadline())
            .min(active.peer_deadline())
            .min(observation.fresh_until());
        let Crypto::Established(connection) = &mut self.crypto else {
            return Err(peer::PeerError::Invalid);
        };
        let mut turn = runtime
            .owner
            .try_started_git_terminal_turn(
                runtime.operation,
                active,
                observation,
                latches,
                connection,
                &target,
            )
            .map_err(owner_error_at!())?;
        turn.check_terminal_request(connection, &response.request)
            .map_err(invalid_at!())?;
        let terminal_watch = turn.into_io_watch();
        if !terminal_watch.terminal_current() {
            return Err(peer::PeerError::Invalid);
        }
        let mut channel_turn = runtime
            .owner
            .try_started_git_terminal_channel_turn(
                runtime.operation,
                active,
                observation,
                latches,
                connection,
            )
            .map_err(owner_error_at!())?;
        let channel_watch = channel_turn.into_io_watch();
        let frame = self
            .encoder
            .next_frame()
            .map_err(invalid_at!())?
            .ok_or(peer::PeerError::Invalid)?;
        let sealed = channel_watch
            .seal_frame(connection, &frame)
            .map_err(invalid_at!())?;
        let check = || {
            if Instant::now() >= deadline || response.operation.check().is_err() {
                return Err(BudgetStop::Deadline);
            }
            if !runtime.operation.check().is_ok()
                || !active.is_current(runtime.operation)
                || !latches.current()
                || !terminal_watch.terminal_current()
                || !channel_watch.current()
                || !observation.current_for(
                    active,
                    runtime.operation,
                    observation.target().connection,
                )
            {
                return Err(BudgetStop::Cancelled);
            }
            Ok(())
        };
        self.socket
            .send_binary(&sealed, deadline, &check)
            .map_err(invalid_at!())?;
        response.remaining = response
            .remaining
            .checked_sub(1)
            .ok_or(peer::PeerError::Invalid)?;
        if response.remaining > 0 {
            response.peer = None;
        }
        Ok(true)
    }

    fn send_started_git_response(
        &mut self,
        runtime: RuntimeWithOperation<'cancel, '_>,
        active: &super::shared_owner::StartedGitContinuation,
        observation: &peer::StartedGitPeerObservation,
        latches: super::owner_domain::StartedGitTerminalLatches<'_>,
        response: &mut PendingResponse<'cancel>,
    ) -> peer::ResultPeer<bool> {
        response
            .operation
            .check()
            .map_err(|_| peer::PeerError::Invalid)?;
        if response.aborted.get() {
            return Err(peer::PeerError::Invalid);
        }
        let deadline = response
            .operation
            .deadline()
            .min(runtime.operation.deadline())
            .min(active.hard_deadline())
            .min(active.heartbeat_deadline())
            .min(active.peer_deadline())
            .min(observation.fresh_until());
        let Crypto::Established(connection) = &mut self.crypto else {
            return Err(peer::PeerError::Invalid);
        };
        let mut turn = runtime
            .owner
            .try_started_git_terminal_channel_turn(
                runtime.operation,
                active,
                observation,
                latches,
                connection,
            )
            .map_err(owner_error_at!())?;
        if let Some(disclosure) = response.git_receipt_disclosure.as_ref() {
            turn.cached_git_receipt_response(connection, &response.request, deadline, disclosure)
        } else if response.operation_control {
            turn.cached_operation_response(
                connection,
                &response.request,
                deadline,
                response
                    .operation_disclosure
                    .as_ref()
                    .map(|disclosure| disclosure.authorization()),
            )
        } else {
            turn.cached_response(connection, &response.request, deadline)
        }
        .map_err(invalid_at!())?;
        let channel_watch = turn.into_io_watch();
        let frame = self
            .encoder
            .next_frame()
            .map_err(invalid_at!())?
            .ok_or(peer::PeerError::Invalid)?;
        let sealed = channel_watch
            .seal_frame(connection, &frame)
            .map_err(invalid_at!())?;
        let check = || {
            if Instant::now() >= deadline || response.operation.check().is_err() {
                return Err(BudgetStop::Deadline);
            }
            if !runtime.operation.check().is_ok()
                || !active.is_current(runtime.operation)
                || !latches.current()
                || !channel_watch.current()
                || !observation.current_for(
                    active,
                    runtime.operation,
                    observation.target().connection,
                )
            {
                return Err(BudgetStop::Cancelled);
            }
            Ok(())
        };
        self.socket
            .send_binary(&sealed, deadline, &check)
            .map_err(invalid_at!())?;
        response.remaining = response
            .remaining
            .checked_sub(1)
            .ok_or(peer::PeerError::Invalid)?;
        if response.remaining > 0 {
            response.peer = None;
        }
        Ok(true)
    }

    fn send_started_git_terminal_stream(
        &mut self,
        runtime: RuntimeWithOperation<'cancel, '_>,
        active: &super::shared_owner::StartedGitContinuation,
        observation: &peer::StartedGitPeerObservation,
        latches: super::owner_domain::StartedGitTerminalLatches<'_>,
    ) -> peer::ResultPeer<bool> {
        let mut stream = self.stream.take().ok_or(peer::PeerError::Invalid)?;
        let Some(frame) = stream.delivery.as_ref() else {
            self.stream = Some(stream);
            return Ok(false);
        };
        stream
            .operation
            .check()
            .map_err(|_| peer::PeerError::Invalid)?;
        if stream.aborted.get() {
            return Err(peer::PeerError::Invalid);
        }
        let deadline = stream
            .operation
            .deadline()
            .min(runtime.operation.deadline())
            .min(active.hard_deadline())
            .min(active.heartbeat_deadline())
            .min(active.peer_deadline())
            .min(observation.fresh_until());
        let Crypto::Established(connection) = &mut self.crypto else {
            return Err(peer::PeerError::Invalid);
        };
        let terminal = self.terminal.as_mut().ok_or(peer::PeerError::Invalid)?;
        terminal
            .check_fragment_started_git(
                frame,
                connection,
                runtime.operation,
                active,
                observation,
                latches,
            )
            .map_err(invalid_at!())?;
        let mut terminal_turn = runtime
            .owner
            .try_started_git_terminal_turn(
                runtime.operation,
                active,
                observation,
                latches,
                connection,
                frame.terminal_context(),
            )
            .map_err(owner_error_at!())?;
        terminal_turn
            .check_terminal_stream(connection)
            .map_err(invalid_at!())?;
        let terminal_watch = terminal_turn.into_io_watch();
        if !terminal_watch.terminal_current() {
            return Err(peer::PeerError::Invalid);
        }
        let mut channel_turn = runtime
            .owner
            .try_started_git_terminal_channel_turn(
                runtime.operation,
                active,
                observation,
                latches,
                connection,
            )
            .map_err(owner_error_at!())?;
        let channel_watch = channel_turn.into_io_watch();
        let frame_bytes = self
            .encoder
            .next_frame()
            .map_err(invalid_at!())?
            .ok_or(peer::PeerError::Invalid)?;
        let sealed = channel_watch
            .seal_frame(connection, &frame_bytes)
            .map_err(invalid_at!())?;
        let check = || {
            if Instant::now() >= deadline || stream.operation.check().is_err() {
                return Err(BudgetStop::Deadline);
            }
            if !runtime.operation.check().is_ok()
                || !active.is_current(runtime.operation)
                || !latches.current()
                || !terminal_watch.terminal_current()
                || !channel_watch.current()
                || !observation.current_for(
                    active,
                    runtime.operation,
                    observation.target().connection,
                )
            {
                return Err(BudgetStop::Cancelled);
            }
            Ok(())
        };
        self.socket
            .send_binary(&sealed, deadline, &check)
            .map_err(invalid_at!())?;
        stream.remaining = stream
            .remaining
            .checked_sub(1)
            .ok_or(peer::PeerError::Invalid)?;
        if stream.remaining == 0 {
            let frame = stream.delivery.take().ok_or(peer::PeerError::Invalid)?;
            self.terminal
                .as_mut()
                .ok_or(peer::PeerError::Invalid)?
                .complete_delivery(connection, frame)
                .map_err(invalid_at!())?;
        } else {
            self.stream = Some(stream);
        }
        Ok(true)
    }

    fn send_started_git_nonterminal_stream(
        &mut self,
        runtime: RuntimeWithOperation<'cancel, '_>,
        active: &super::shared_owner::StartedGitContinuation,
        observation: &peer::StartedGitPeerObservation,
        latches: super::owner_domain::StartedGitTerminalLatches<'_>,
    ) -> peer::ResultPeer<bool> {
        let mut stream = self.stream.take().ok_or(peer::PeerError::Invalid)?;
        let request = stream
            .authorization_call
            .as_ref()
            .ok_or(peer::PeerError::Invalid)?;
        stream
            .operation
            .check()
            .map_err(|_| peer::PeerError::Invalid)?;
        if stream.aborted.get() || stream.delivery.is_some() {
            return Err(peer::PeerError::Invalid);
        }
        let deadline = stream
            .operation
            .deadline()
            .min(runtime.operation.deadline())
            .min(active.hard_deadline())
            .min(active.heartbeat_deadline())
            .min(active.peer_deadline())
            .min(observation.fresh_until());
        let Crypto::Established(connection) = &mut self.crypto else {
            return Err(peer::PeerError::Invalid);
        };
        let mut turn = runtime
            .owner
            .try_started_git_terminal_channel_turn(
                runtime.operation,
                active,
                observation,
                latches,
                connection,
            )
            .map_err(owner_error_at!())?;
        turn.cached_response(connection, request, deadline)
            .map_err(invalid_at!())?;
        let channel_watch = turn.into_io_watch();
        let frame = self
            .encoder
            .next_frame()
            .map_err(invalid_at!())?
            .ok_or(peer::PeerError::Invalid)?;
        let sealed = channel_watch
            .seal_frame(connection, &frame)
            .map_err(invalid_at!())?;
        let check = || {
            if Instant::now() >= deadline || stream.operation.check().is_err() {
                return Err(BudgetStop::Deadline);
            }
            if !runtime.operation.check().is_ok()
                || !active.is_current(runtime.operation)
                || !latches.current()
                || !channel_watch.current()
                || !observation.current_for(
                    active,
                    runtime.operation,
                    observation.target().connection,
                )
            {
                return Err(BudgetStop::Cancelled);
            }
            Ok(())
        };
        self.socket
            .send_binary(&sealed, deadline, &check)
            .map_err(invalid_at!())?;
        stream.remaining = stream
            .remaining
            .checked_sub(1)
            .ok_or(peer::PeerError::Invalid)?;
        if stream.remaining > 0 {
            stream.peer = None;
            self.stream = Some(stream);
        }
        Ok(true)
    }

    /// Retain the current worker unit while a pending handshake or established
    /// connection is inside the pre-expiry refresh window. The existing cutoff
    /// remains absolute; failure to refresh before it expires closes the channel.
    fn peer_refresh_deadline(&self, now: Instant) -> Option<Instant> {
        let refreshable = matches!(
            &self.crypto,
            Crypto::ReadFirst(_)
                | Crypto::WriteSecond(_)
                | Crypto::ReadThird(_)
                | Crypto::Established(_)
        );
        peer_refresh_deadline_for(refreshable, self.peer_cutoff, now)
    }

    fn poll_git_mutation(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
        eligibility: Option<&PeerEligibility>,
    ) -> peer::ResultPeer<bool> {
        let Some(mut pending) = self.git_mutation.take() else {
            return Ok(false);
        };
        let request_runtime = Runtime {
            operation: &pending.operation,
            aborted: &pending.aborted,
            ..runtime
        };
        let started = pending.lease.is_some();
        let mut current = if started {
            let Some(continuation) = pending.continuation.as_ref() else {
                pending.invalidated = true;
                pending.cancellation.cancel();
                return Err(peer::PeerError::Invalid);
            };
            let connection_id = match &self.crypto {
                Crypto::Established(connection) => connection.connection_identity(),
                _ => {
                    pending.invalidated = true;
                    pending.cancellation.cancel();
                    return Err(peer::PeerError::Invalid);
                }
            };
            if pending.invalidated
                || !continuation.matches_request(
                    &pending.operation,
                    connection_id,
                    &pending.request,
                )
                || !pending.lease.as_ref().is_some_and(|lease| lease.current())
            {
                pending.invalidated = true;
                continuation.invalidate();
                pending.cancellation.cancel();
            }
            None
        } else {
            let eligibility = eligibility.ok_or(peer::PeerError::Invalid)?;
            let current = current_proof(
                pending.peer.take(),
                auth,
                request_runtime,
                eligibility,
                &self.source,
                self.peer_cutoff,
            )?;
            let evidence = request_runtime.remote_worker_evidence(auth, eligibility)?;
            {
                let turn = peer::owner_turn(request_runtime, || {
                    request_runtime.owner.try_remote_workspace_turn(
                        &evidence,
                        &current,
                        &pending.context,
                    )
                })?;
                let Crypto::Established(crypto) = &mut self.crypto else {
                    return Err(peer::PeerError::Invalid);
                };
                if current.observed_at() > self.applied_observation {
                    turn.refresh_peer(crypto).map_err(invalid_at!())?;
                    self.applied_observation = current.observed_at();
                }
                if let Some(queued) = pending.queued.as_ref() {
                    let target = turn
                        .git_mutation_peek_after_wait(crypto, queued)
                        .map_err(invalid_at!())?;
                    if target.workspace_id != pending.target.workspace_id
                        || target.epoch != pending.target.epoch
                        || target.root != pending.target.root
                    {
                        return Err(peer::PeerError::Invalid);
                    }
                } else {
                    turn.check_response(crypto, &pending.request)
                        .map_err(invalid_at!())?;
                }
            }
            self.peer_cutoff = current.fresh_until();
            Some(current)
        };

        let mut state = pending.state.take().ok_or(peer::PeerError::Invalid)?;
        loop {
            match state {
                PendingGitMutationState::Preparing(mut job) => match job.poll() {
                    Poll::Pending => {
                        pending.state = Some(PendingGitMutationState::Preparing(job));
                        self.git_mutation = Some(pending);
                        return Ok(false);
                    }
                    Poll::Ready(Ok(prepared)) => {
                        drop(job);
                        state = PendingGitMutationState::Prepared(prepared);
                    }
                    Poll::Ready(Err(error)) => {
                        drop(job);
                        state = PendingGitMutationState::Reject(error);
                    }
                },
                PendingGitMutationState::Prepared(prepared) if pending.lease.is_none() => {
                    let coordinator = self.coordinator.upgrade().ok_or(peer::PeerError::Invalid)?;
                    let workspace = pending.context.workspace_id;
                    super::super::rpc::ensure_workspace_settled(&coordinator, workspace)
                        .map_err(|_| peer::PeerError::Invalid)?;
                    let slot = super::super::rpc::CompletionSlot::reserve_owned(
                        coordinator.clone(),
                        &pending.operation,
                        workspace,
                    )
                    .map_err(invalid_at!())?;
                    let actor = coordinator
                        .workspace_lock(workspace)
                        .map_err(|_| peer::PeerError::Invalid)?;
                    let actor_guard = match actor.try_lock() {
                        Ok(guard) => guard,
                        Err(std::sync::TryLockError::WouldBlock) => {
                            drop(slot);
                            pending.state = Some(PendingGitMutationState::Prepared(prepared));
                            self.git_mutation = Some(pending);
                            return Ok(false);
                        }
                        Err(std::sync::TryLockError::Poisoned(_)) => {
                            return Err(peer::PeerError::Invalid);
                        }
                    };
                    let current_peer = current.as_ref().ok_or(peer::PeerError::Invalid)?;
                    let Crypto::Established(crypto) = &mut self.crypto else {
                        return Err(peer::PeerError::Invalid);
                    };
                    let eligibility = eligibility.ok_or(peer::PeerError::Invalid)?;
                    let evidence = request_runtime.remote_worker_evidence(auth, eligibility)?;
                    let Some(queued) = pending.queued.as_ref() else {
                        return Err(peer::PeerError::Invalid);
                    };
                    let begin = runtime.owner.begin_remote_git_mutation(
                        &evidence,
                        current_peer,
                        crypto,
                        &pending.request,
                        queued,
                        pending.operation.cancellation_latch(),
                        &slot,
                        &pending.target.root,
                    );
                    drop(actor_guard);
                    match begin.map_err(remote_git_owner_error)? {
                        super::super::shared_owner::RemoteGitMutationBegin::Duplicate(
                            receipt,
                            disclosure,
                        ) => {
                            pending.queued.take();
                            state = PendingGitMutationState::Deliver(receipt, disclosure);
                            continue;
                        }
                        super::super::shared_owner::RemoteGitMutationBegin::Started {
                            lease,
                            continuation,
                            permit,
                            binding,
                            credential_configuration,
                            ..
                        } => {
                            pending.queued.take();
                            pending.started = Some(StartedGitPermit {
                                binding,
                                permit: Some(permit),
                                completion: slot,
                                credential_configuration,
                            });
                            pending.lease = Some(lease);
                            pending.continuation = Some(continuation);
                            pending.peer = None;
                            pending.publication_peer = current.take();
                            state = PendingGitMutationState::Prepared(prepared);
                            // The journal is now durably Running and the owned
                            // Shared gate remains live; only now can a worker
                            // start network or publication.
                            continue;
                        }
                    }
                }
                PendingGitMutationState::Prepared(prepared) if pending.lease.is_some() => {
                    let coordinator = self.coordinator.upgrade().ok_or(peer::PeerError::Invalid)?;
                    let lease = pending.lease.as_ref().ok_or(peer::PeerError::Invalid)?;
                    let cancellation = pending.cancellation.clone();
                    let gate = lease.gate();
                    let deadline = pending.operation.deadline();
                    let control = pending.control.clone();
                    let launched = match prepared {
                        super::super::remote_git_mutations::PreparedGitOperation::Publish(
                            mutation,
                        ) => super::super::remote_git_mutations::PreparedGitOperation::Publish(
                            mutation,
                        )
                        .publication()
                        .and_then(|publication| {
                            coordinator
                                .git_mutations
                                .start_publish(publication, cancellation, control, deadline, gate)
                                .map(PendingGitMutationState::Publishing)
                                .map_err(|_| lomi_git::GitServiceError::ExecutorUnavailable)
                        }),
                        operation => {
                            let configuration = pending
                                .started
                                .as_ref()
                                .and_then(|started| started.credential_configuration.clone());
                            let credentials =
                                super::super::remote_git_mutations::credentials_provider(
                                    coordinator.profile.clone(),
                                    configuration,
                                );
                            coordinator
                                .git_mutations
                                .start_network(
                                    operation,
                                    cancellation,
                                    control,
                                    deadline,
                                    credentials,
                                    gate,
                                )
                                .map(PendingGitMutationState::Network)
                                .map_err(|_| lomi_git::GitServiceError::ExecutorUnavailable)
                        }
                    };
                    state = match launched {
                        Ok(state) => state,
                        Err(error) => {
                            let unknown = matches!(
                                error,
                                lomi_git::GitServiceError::MutationOutcomeUnknown
                                    | lomi_git::GitServiceError::NetworkOutcomeUnknown
                            );
                            PendingGitMutationState::Finalize {
                                state: if unknown {
                                    lomi_remote_protocol::OperationState::OutcomeUnknown
                                } else {
                                    lomi_remote_protocol::OperationState::Failed
                                },
                                effect: if unknown {
                                    lomi_remote_protocol::Effect::Unknown
                                } else {
                                    lomi_remote_protocol::Effect::None
                                },
                                repo_state: None,
                            }
                        }
                    };
                    continue;
                }
                PendingGitMutationState::Prepared(_) => {
                    return Err(peer::PeerError::Invalid);
                }
                PendingGitMutationState::Network(mut job) => match job.poll() {
                    Poll::Pending => {
                        pending.state = Some(PendingGitMutationState::Network(job));
                        self.git_mutation = Some(pending);
                        return Ok(false);
                    }
                    Poll::Ready(Ok(
                        super::super::remote_git_mutations::NetworkResult::Publication(publication),
                    )) => state = PendingGitMutationState::NeedPublish(publication),
                    Poll::Ready(Ok(super::super::remote_git_mutations::NetworkResult::Push {
                        outcome,
                        repo_state_token,
                    })) => {
                        let (final_state, effect, token) = match outcome {
                            lomi_git::GitPushOutcome::Committed => (
                                lomi_remote_protocol::OperationState::Succeeded,
                                lomi_remote_protocol::Effect::Committed,
                                Some(repo_state_token),
                            ),
                            lomi_git::GitPushOutcome::PossibleRemoteEffect => (
                                lomi_remote_protocol::OperationState::OutcomeUnknown,
                                lomi_remote_protocol::Effect::Unknown,
                                None,
                            ),
                            lomi_git::GitPushOutcome::NoEffect
                            | lomi_git::GitPushOutcome::Rejected
                            | lomi_git::GitPushOutcome::FailedNoEffect(_) => (
                                lomi_remote_protocol::OperationState::Failed,
                                lomi_remote_protocol::Effect::None,
                                None,
                            ),
                        };
                        state = PendingGitMutationState::Finalize {
                            state: final_state,
                            effect,
                            repo_state: token,
                        };
                    }
                    Poll::Ready(Err(error)) => {
                        let unknown = matches!(
                            error,
                            lomi_git::GitServiceError::NetworkOutcomeUnknown
                                | lomi_git::GitServiceError::MutationOutcomeUnknown
                        );
                        state = PendingGitMutationState::Finalize {
                            state: if unknown {
                                lomi_remote_protocol::OperationState::OutcomeUnknown
                            } else {
                                lomi_remote_protocol::OperationState::Failed
                            },
                            effect: if unknown {
                                lomi_remote_protocol::Effect::Unknown
                            } else {
                                lomi_remote_protocol::Effect::None
                            },
                            repo_state: None,
                        };
                    }
                },
                PendingGitMutationState::NeedPublish(publication) => {
                    let coordinator = self.coordinator.upgrade().ok_or(peer::PeerError::Invalid)?;
                    let lease = pending.lease.as_ref().ok_or(peer::PeerError::Invalid)?;
                    match coordinator.git_mutations.start_publish(
                        publication,
                        pending.cancellation.clone(),
                        pending.control.clone(),
                        pending.operation.deadline(),
                        lease.gate(),
                    ) {
                        Ok(job) => state = PendingGitMutationState::Publishing(job),
                        Err(_) => {
                            state = PendingGitMutationState::Finalize {
                                state: lomi_remote_protocol::OperationState::Failed,
                                effect: lomi_remote_protocol::Effect::None,
                                repo_state: None,
                            }
                        }
                    }
                }
                PendingGitMutationState::Publishing(mut job) => match job.poll() {
                    Poll::Pending => {
                        pending.state = Some(PendingGitMutationState::Publishing(job));
                        self.git_mutation = Some(pending);
                        return Ok(false);
                    }
                    Poll::Ready(Ok(published)) => {
                        state = PendingGitMutationState::NeedCapture(published)
                    }
                    Poll::Ready(Err(error)) => {
                        let unknown =
                            matches!(error, lomi_git::GitServiceError::MutationOutcomeUnknown);
                        state = PendingGitMutationState::Finalize {
                            state: if unknown {
                                lomi_remote_protocol::OperationState::OutcomeUnknown
                            } else {
                                lomi_remote_protocol::OperationState::Failed
                            },
                            effect: if unknown {
                                lomi_remote_protocol::Effect::Unknown
                            } else {
                                lomi_remote_protocol::Effect::None
                            },
                            repo_state: None,
                        };
                    }
                },
                PendingGitMutationState::NeedCapture(published) => {
                    let coordinator = self.coordinator.upgrade().ok_or(peer::PeerError::Invalid)?;
                    let lease = pending.lease.as_ref().ok_or(peer::PeerError::Invalid)?;
                    match coordinator.git_mutations.start_capture(
                        published,
                        pending.cancellation.clone(),
                        pending.control.clone(),
                        pending.operation.deadline(),
                        lease.gate(),
                    ) {
                        Ok(job) => state = PendingGitMutationState::Capturing(job),
                        Err(_) => {
                            state = PendingGitMutationState::Finalize {
                                state: lomi_remote_protocol::OperationState::OutcomeUnknown,
                                effect: lomi_remote_protocol::Effect::Unknown,
                                repo_state: None,
                            }
                        }
                    }
                }
                PendingGitMutationState::Capturing(mut job) => match job.poll() {
                    Poll::Pending => {
                        pending.state = Some(PendingGitMutationState::Capturing(job));
                        self.git_mutation = Some(pending);
                        return Ok(false);
                    }
                    Poll::Ready(Ok(token)) => {
                        state = PendingGitMutationState::Finalize {
                            state: lomi_remote_protocol::OperationState::Succeeded,
                            effect: lomi_remote_protocol::Effect::Committed,
                            repo_state: Some(token),
                        }
                    }
                    Poll::Ready(Err(_)) => {
                        state = PendingGitMutationState::Finalize {
                            state: lomi_remote_protocol::OperationState::OutcomeUnknown,
                            effect: lomi_remote_protocol::Effect::Unknown,
                            repo_state: None,
                        }
                    }
                },
                PendingGitMutationState::Finalize {
                    state: final_state,
                    effect,
                    repo_state,
                } => {
                    if pending.lease.is_some() && self.has_pending_output() {
                        pending.state = Some(PendingGitMutationState::Finalize {
                            state: final_state,
                            effect,
                            repo_state,
                        });
                        self.git_mutation = Some(pending);
                        return Ok(false);
                    }
                    let coordinator = self.coordinator.upgrade().ok_or(peer::PeerError::Invalid)?;
                    let actor = coordinator
                        .workspace_lock(pending.context.workspace_id)
                        .map_err(|_| peer::PeerError::Invalid)?;
                    let actor_guard = match actor.try_lock() {
                        Ok(guard) => guard,
                        Err(std::sync::TryLockError::WouldBlock) => {
                            pending.state = Some(PendingGitMutationState::Finalize {
                                state: final_state,
                                effect,
                                repo_state,
                            });
                            self.git_mutation = Some(pending);
                            return Ok(false);
                        }
                        Err(std::sync::TryLockError::Poisoned(_)) => {
                            return Err(peer::PeerError::Invalid);
                        }
                    };
                    if pending.lease.is_some() {
                        if pending.invalidated {
                            // The executor/repository job reached its final
                            // state before we release this writer. Its exact
                            // effect cannot be disclosed under invalidated
                            // authority; the permit's Drop records
                            // OutcomeUnknown for status-only recovery.
                            drop(actor_guard);
                            pending.started.take();
                            pending.lease.take();
                            pending.continuation.take();
                            pending.publication_peer.take();
                            return Err(peer::PeerError::Invalid);
                        }
                        let connection_id = match &self.crypto {
                            Crypto::Established(connection) => connection.connection_identity(),
                            _ => {
                                drop(actor_guard);
                                pending.started.take();
                                pending.lease.take();
                                return Err(peer::PeerError::Invalid);
                            }
                        };
                        let continuation = pending
                            .continuation
                            .take()
                            .ok_or(peer::PeerError::Invalid)?;
                        let lease = pending.lease.take().ok_or(peer::PeerError::Invalid)?;
                        let mut started = pending.started.take().ok_or(peer::PeerError::Invalid)?;
                        let permit = started.permit.as_ref().ok_or(peer::PeerError::Invalid)?;
                        let binding = started.binding.clone();
                        let receipt = runtime
                            .owner
                            .complete_remote_git_mutation_started(
                                &pending.operation,
                                continuation,
                                lease,
                                permit,
                                &binding,
                                pending.request.clone(),
                                final_state,
                                effect,
                                repo_state,
                                connection_id,
                            )
                            .map_err(remote_git_owner_error)?;
                        drop(actor_guard);
                        started.confirm();
                        pending.publication_peer.take();
                        let (receipt_request, bytes, git_receipt_disclosure) = receipt
                            .into_queued_response(
                                runtime.gate,
                                runtime.paused,
                                runtime.stopping,
                                &runtime.public_io.setup().pending,
                                pending.operation.deadline(),
                            )
                            .map_err(remote_git_owner_error)?;
                        if receipt_request != pending.request {
                            return Err(peer::PeerError::Invalid);
                        }
                        let response = PendingResponse {
                            operation: pending.operation,
                            aborted: pending.aborted,
                            request: pending.request,
                            peer: None,
                            operation_control: false,
                            operation_disclosure: None,
                            git_receipt_disclosure: Some(git_receipt_disclosure),
                            remaining: frame_count(bytes.len()),
                        };
                        self.enqueue_reserved_git_response(bytes, response)?;
                        return Ok(true);
                    }
                    let eligibility = eligibility.ok_or(peer::PeerError::Invalid)?;
                    let evidence = request_runtime.remote_worker_evidence(auth, eligibility)?;
                    let Some(publication_peer) = pending.publication_peer.take() else {
                        return Err(peer::PeerError::Invalid);
                    };
                    let Crypto::Established(connection) = &mut self.crypto else {
                        return Err(peer::PeerError::Invalid);
                    };
                    let connection_id = connection.connection_identity();
                    let lease = pending.lease.take().ok_or(peer::PeerError::Invalid)?;
                    let started_permit =
                        pending.started.as_ref().ok_or(peer::PeerError::Invalid)?;
                    let permit = started_permit
                        .permit
                        .as_ref()
                        .ok_or(peer::PeerError::Invalid)?;
                    let receipt = runtime
                        .owner
                        .complete_remote_git_mutation(
                            &evidence,
                            publication_peer,
                            connection_id,
                            &pending.context,
                            pending.request.clone(),
                            lease,
                            permit,
                            &started_permit.binding,
                            final_state,
                            effect,
                            repo_state,
                        )
                        .map_err(remote_git_owner_error)?;
                    drop(actor_guard);
                    if let Some(mut started) = pending.started.take() {
                        started.confirm();
                    }
                    let (receipt_request, bytes, git_receipt_disclosure) = receipt
                        .into_queued_response(pending.operation.deadline())
                        .map_err(remote_git_owner_error)?;
                    if receipt_request != pending.request {
                        return Err(peer::PeerError::Invalid);
                    }
                    let response = PendingResponse {
                        operation: pending.operation,
                        aborted: pending.aborted,
                        request: pending.request,
                        peer: None,
                        operation_control: false,
                        operation_disclosure: None,
                        git_receipt_disclosure: Some(git_receipt_disclosure),
                        remaining: frame_count(bytes.len()),
                    };
                    self.enqueue_reserved_git_response(bytes, response)?;
                    return Ok(true);
                }
                PendingGitMutationState::Deliver(receipt, git_receipt_disclosure) => {
                    if pending.lease.is_some() {
                        // A completed owner ticket changed its authority
                        // revision. Re-establish ordinary current proof next
                        // actor turn before disclosing the operation receipt.
                        pending.state = Some(PendingGitMutationState::Deliver(
                            receipt,
                            git_receipt_disclosure,
                        ));
                        pending.peer = None;
                        self.git_mutation = Some(pending);
                        return Ok(false);
                    }
                    let Some(current_peer) = current.as_ref() else {
                        return Err(peer::PeerError::Invalid);
                    };
                    let Crypto::Established(crypto) = &mut self.crypto else {
                        return Err(peer::PeerError::Invalid);
                    };
                    let eligibility = eligibility.ok_or(peer::PeerError::Invalid)?;
                    let evidence = request_runtime.remote_worker_evidence(auth, eligibility)?;
                    let turn = peer::owner_turn(request_runtime, || {
                        request_runtime.owner.try_remote_workspace_turn(
                            &evidence,
                            current_peer,
                            &pending.context,
                        )
                    })?;
                    turn.check_response(crypto, &pending.request)
                        .map_err(invalid_at!())?;
                    drop(turn);
                    let response = RpcResponse::Result {
                        v: pending.request.v,
                        request_id: pending.request.request_id.clone(),
                        result: super::super::rpc::git_receipt_result(
                            pending.request.call.method(),
                            receipt,
                        ),
                    };
                    let bytes = serde_json::to_vec(&response).map_err(invalid_at!())?;
                    let remaining = frame_count(bytes.len());
                    let operation = pending.operation;
                    let aborted = pending.aborted;
                    let request = pending.request;
                    self.enqueue_reserved_git_response(
                        bytes,
                        PendingResponse {
                            operation,
                            aborted,
                            request,
                            peer: current.take(),
                            operation_control: false,
                            operation_disclosure: None,
                            git_receipt_disclosure: Some(git_receipt_disclosure),
                            remaining,
                        },
                    )?;
                    return Ok(true);
                }
                PendingGitMutationState::Reject(error) => {
                    if pending.started.is_some() {
                        return Err(peer::PeerError::Invalid);
                    }
                    let Some(current_peer) = current.as_ref() else {
                        return Err(peer::PeerError::Invalid);
                    };
                    let Crypto::Established(crypto) = &mut self.crypto else {
                        return Err(peer::PeerError::Invalid);
                    };
                    let eligibility = eligibility.ok_or(peer::PeerError::Invalid)?;
                    let evidence = request_runtime.remote_worker_evidence(auth, eligibility)?;
                    let turn = peer::owner_turn(request_runtime, || {
                        request_runtime.owner.try_remote_workspace_turn(
                            &evidence,
                            current_peer,
                            &pending.context,
                        )
                    })?;
                    turn.check_response(crypto, &pending.request)
                        .map_err(invalid_at!())?;
                    drop(turn);
                    let response = RpcResponse::Error {
                        v: pending.request.v,
                        request_id: pending.request.request_id.clone(),
                        operation_id: pending
                            .request
                            .call
                            .operation_binding()
                            .map(|b| b.operation_id),
                        error,
                    };
                    let bytes = serde_json::to_vec(&response).map_err(invalid_at!())?;
                    let remaining = frame_count(bytes.len());
                    let operation = pending.operation;
                    let aborted = pending.aborted;
                    let request = pending.request;
                    self.enqueue_reserved_git_response(
                        bytes,
                        PendingResponse {
                            operation,
                            aborted,
                            request,
                            peer: current.take(),
                            operation_control: false,
                            operation_disclosure: None,
                            git_receipt_disclosure: None,
                            remaining,
                        },
                    )?;
                    return Ok(true);
                }
            }
        }
    }

    fn has_immediate_output(&self) -> bool {
        let now = Instant::now();
        if self.suspended || now >= self.peer_cutoff {
            return false;
        }
        if matches!(&self.crypto, Crypto::WriteSecond(_)) {
            return true;
        }
        if let Some(read) = &self.git_read {
            return read.read.is_ready()
                && !read.aborted.get()
                && !read.operation.cancellation_latch().load(Ordering::Acquire)
                && now < read.operation.deadline();
        }
        if let Some(mutation) = &self.git_mutation {
            return mutation.is_ready()
                && !mutation
                    .operation
                    .cancellation_latch()
                    .load(Ordering::Acquire)
                && now < mutation.operation.deadline();
        }
        if let Some(response) = &self.response {
            return !response.aborted.get()
                && !response
                    .operation
                    .cancellation_latch()
                    .load(Ordering::Acquire)
                && now < response.operation.deadline();
        }
        if !self.started_git_outputs.is_empty() {
            return true;
        }
        if let Some(stream) = &self.stream {
            return stream.remaining > 0
                && !stream.aborted.get()
                && !stream
                    .operation
                    .cancellation_latch()
                    .load(Ordering::Acquire)
                && now < stream.operation.deadline();
        }
        self.terminal
            .as_ref()
            .is_some_and(|terminal| terminal.has_immediate_output())
    }

    fn has_staged_output(&self) -> bool {
        let now = Instant::now();
        let response_ready = self.response.as_ref().is_some_and(|response| {
            staged_message_is_live(
                now,
                self.peer_cutoff,
                self.suspended,
                response.remaining,
                response.aborted.get(),
                response
                    .operation
                    .cancellation_latch()
                    .load(Ordering::Acquire),
                response.operation.deadline(),
            )
        });
        let stream_ready = self.stream.as_ref().is_some_and(|stream| {
            staged_message_is_live(
                now,
                self.peer_cutoff,
                self.suspended,
                stream.remaining,
                stream.aborted.get(),
                stream
                    .operation
                    .cancellation_latch()
                    .load(Ordering::Acquire),
                stream.operation.deadline(),
            )
        });
        response_ready || stream_ready
    }

    fn has_staged_message(&self) -> bool {
        self.response
            .as_ref()
            .is_some_and(|response| response.remaining > 0)
            || self
                .stream
                .as_ref()
                .is_some_and(|stream| stream.remaining > 0)
    }

    fn staged_message_remaining(&self) -> Option<usize> {
        if self.has_active_git_writer() {
            return None;
        }
        prioritized_staged_remaining(
            self.response.as_ref().map(|response| response.remaining),
            self.stream.as_ref().map(|stream| stream.remaining),
            false,
        )
    }

    fn has_staged_terminal_burst(&self) -> bool {
        self.stream.as_ref().is_some_and(|stream| {
            stream.remaining > 0
                && stream.burst_started.is_some()
                && stream.kind == MessageKind::TerminalFrame
                && stream.delivery.is_some()
                && stream.authorization_call.is_none()
        })
    }

    fn turn(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
        eligibility: &PeerEligibility,
        cancelled: Option<&'cancel AtomicBool>,
    ) -> peer::ResultPeer<bool> {
        let worker_deadline = runtime.operation.deadline();
        if self.suspended {
            self.peer = None;
            if let Some(response) = self.response.as_mut() {
                response.peer = None;
            }
            if let Some(stream) = self.stream.as_mut() {
                stream.peer = None;
            }
            if let Some(read) = self.git_read.as_mut() {
                read.peer = None;
            }
            if let Some(mutation) = self.git_mutation.as_mut() {
                mutation.peer = None;
            }
            self.maintenance_aborted.set(false);
            self.maintenance = super::OwnerOperation::new(
                worker_deadline,
                cancelled.ok_or(peer::PeerError::Invalid)?,
            );
            self.suspended = false;
        }
        let now_ms = u64::try_from(self.origin.elapsed().as_millis()).map_err(invalid_at!())?;
        self.assembler.expire(now_ms).map_err(invalid_at!())?;
        if self.git_mutation.is_some() {
            if self.has_active_git_writer() {
                return self.advance_started_git(auth, runtime);
            }
            return self.poll_git_mutation(auth, runtime, Some(eligibility));
        }
        self.activate_started_git_output()?;
        if self.git_read.is_some() && !self.has_pending_output() {
            let Some(mut read) = self.git_read.take() else {
                return Err(peer::PeerError::Invalid);
            };
            let request_runtime = Runtime {
                operation: &read.operation,
                aborted: &read.aborted,
                ..runtime
            };
            let current = current_proof(
                read.peer.take(),
                auth,
                request_runtime,
                eligibility,
                &self.source,
                self.peer_cutoff,
            )?;
            let evidence = request_runtime.remote_worker_evidence(auth, eligibility)?;
            {
                let turn = peer::owner_turn(request_runtime, || {
                    request_runtime.owner.try_remote_workspace_turn(
                        &evidence,
                        &current,
                        &self.workspace,
                    )
                })?;
                let Crypto::Established(crypto) = &mut self.crypto else {
                    return Err(peer::PeerError::Invalid);
                };
                if current.observed_at() > self.applied_observation {
                    turn.refresh_peer(crypto).map_err(invalid_at!())?;
                    self.applied_observation = current.observed_at();
                }
                // A failed live gate drops the ticket, cancelling computation.
                // Even an already-completed result cannot bypass this check.
                turn.check_response(crypto, &read.request)
                    .map_err(invalid_at!())?;
            }
            drop(evidence);
            self.peer_cutoff = current.fresh_until();
            match read.read.poll() {
                std::task::Poll::Pending => {
                    read.peer = Some(current);
                    self.git_read = Some(read);
                    return Ok(false);
                }
                std::task::Poll::Ready(result) => {
                    let bytes = super::super::remote_git::encode_response(&read.request, result)
                        .map_err(invalid_at!())?;
                    let remaining = frame_count(bytes.len());
                    self.enqueue_reserved_git_response(
                        bytes,
                        PendingResponse {
                            operation: read.operation,
                            aborted: read.aborted,
                            request: read.request,
                            peer: Some(current),
                            operation_control: false,
                            operation_disclosure: None,
                            git_receipt_disclosure: None,
                            remaining,
                        },
                    )?;
                    return Ok(true);
                }
            }
        }
        // The original request Operation is moved out, never reconstructed. Its
        // identity and absolute deadline cover fresh GET, queue, wait and output.
        if let Some(mut response) = self.response.take() {
            let request_runtime = Runtime {
                operation: &response.operation,
                aborted: &response.aborted,
                ..runtime
            };
            let current = current_proof(
                response.peer.take(),
                auth,
                request_runtime,
                eligibility,
                &self.source,
                self.peer_cutoff,
            )?;
            let evidence = request_runtime.remote_worker_evidence(auth, eligibility)?;
            let frame = {
                let turn = peer::owner_turn(request_runtime, || {
                    request_runtime.owner.try_remote_workspace_turn(
                        &evidence,
                        &current,
                        &self.workspace,
                    )
                })?;
                let Crypto::Established(crypto) = &mut self.crypto else {
                    return Err(peer::PeerError::Invalid);
                };
                if current.observed_at() > self.applied_observation {
                    turn.refresh_peer(crypto).map_err(invalid_at!())?;
                    self.applied_observation = current.observed_at();
                }
                if let Some(disclosure) = response.git_receipt_disclosure.as_ref() {
                    turn.cached_git_receipt_response(crypto, &response.request, disclosure)
                        .map_err(invalid_at!())?;
                } else if response.operation_control {
                    turn.cached_operation_response(
                        crypto,
                        &response.request,
                        response
                            .operation_disclosure
                            .as_ref()
                            .map(|value| value.authorization()),
                    )
                    .map_err(invalid_at!())?;
                } else {
                    turn.check_response(crypto, &response.request)
                        .map_err(invalid_at!())?;
                }
                self.encoder
                    .next_frame()
                    .map_err(invalid_at!())?
                    .map(|frame| turn.seal_frame(crypto, &frame))
                    .transpose()
                    .map_err(invalid_at!())?
            };
            self.peer_cutoff = current.fresh_until();
            let send_deadline = current
                .io_deadline(&evidence)
                .ok_or(peer::PeerError::Invalid)?;
            drop(evidence);
            if let Some(frame) = frame {
                let operation = &response.operation;
                let owner = runtime.owner;
                let continuation = current.continuation();
                let gate = runtime.gate;
                let paused = runtime.paused;
                let stopping = runtime.stopping;
                let public_pending = &runtime.public_io.setup().pending;
                let check = || {
                    watch(operation, gate, paused, stopping, public_pending)?;
                    owner
                        .peer_original_boundary(operation, continuation)
                        .map_err(|_| BudgetStop::Cancelled)
                };
                self.socket
                    .send_binary(&frame, send_deadline, &check)
                    .map_err(invalid_at!())?;
                response.remaining = response
                    .remaining
                    .checked_sub(1)
                    .ok_or(peer::PeerError::Invalid)?;
                if response.remaining > 0 {
                    response.peer = Some(current);
                    self.response = Some(response);
                }
            }
            return Ok(true);
        }
        if let Some(mut stream) = self.stream.take() {
            match (
                &stream.delivery,
                stream.kind,
                stream.authorization_call.is_some(),
            ) {
                (Some(_), MessageKind::TerminalFrame, false)
                | (None, MessageKind::WorkspaceFrame | MessageKind::FileWatchFrame, true) => {}
                _ => return Err(peer::PeerError::Invalid),
            }
            let stream_runtime = Runtime {
                operation: &stream.operation,
                aborted: &stream.aborted,
                ..runtime
            };
            let current = current_proof(
                stream.peer.take(),
                auth,
                stream_runtime,
                eligibility,
                &self.source,
                self.peer_cutoff,
            )?;
            let evidence = stream_runtime.remote_worker_evidence(auth, eligibility)?;
            let Crypto::Established(crypto) = &mut self.crypto else {
                return Err(peer::PeerError::Invalid);
            };
            let ciphertext = if let Some(delivery) = &stream.delivery {
                self.terminal
                    .as_mut()
                    .ok_or(peer::PeerError::Invalid)?
                    .seal_fragment(
                        delivery,
                        crypto,
                        &mut self.encoder,
                        &evidence,
                        &current,
                        &mut self.applied_observation,
                    )
                    .map_err(invalid_at!())?
            } else {
                {
                    let turn = peer::owner_turn(stream_runtime, || {
                        stream_runtime.owner.try_remote_workspace_turn(
                            &evidence,
                            &current,
                            &self.workspace,
                        )
                    })?;
                    if current.observed_at() > self.applied_observation {
                        turn.refresh_peer(crypto).map_err(invalid_at!())?;
                        self.applied_observation = current.observed_at();
                    }
                    if let Some(request) = stream.authorization_call.as_ref() {
                        turn.check_response(crypto, request)
                            .map_err(invalid_at!())?;
                    }
                }
                let turn = peer::owner_turn(stream_runtime, || {
                    stream_runtime.owner.try_remote_workspace_turn(
                        &evidence,
                        &current,
                        &self.workspace,
                    )
                })?;
                let frame = self
                    .encoder
                    .next_frame()
                    .map_err(invalid_at!())?
                    .ok_or(peer::PeerError::Invalid)?;
                turn.seal_frame(crypto, &frame).map_err(invalid_at!())?
            };
            let deadline = current
                .io_deadline(&evidence)
                .ok_or(peer::PeerError::Invalid)?;
            self.peer_cutoff = current.fresh_until();
            let operation = &stream.operation;
            let owner = runtime.owner;
            let continuation = current.continuation();
            let gate = runtime.gate;
            let paused = runtime.paused;
            let stopping = runtime.stopping;
            let public_pending = &runtime.public_io.setup().pending;
            let check = || {
                watch(operation, gate, paused, stopping, public_pending)?;
                owner
                    .peer_original_boundary(operation, continuation)
                    .map_err(|_| BudgetStop::Cancelled)
            };
            let send_started = Instant::now();
            start_terminal_burst_at_first_send(
                &mut stream.burst_pending_first_send,
                &mut stream.burst_started,
                send_started,
            );
            self.socket
                .send_binary(&ciphertext, deadline, &check)
                .map_err(invalid_at!())?;
            check().map_err(invalid_at!())?;
            stream.remaining = stream
                .remaining
                .checked_sub(1)
                .ok_or(peer::PeerError::Invalid)?;
            if stream.remaining == 0 {
                if let Some(delivery) = stream.delivery.take() {
                    self.terminal
                        .as_mut()
                        .ok_or(peer::PeerError::Invalid)?
                        .complete_delivery(crypto, delivery)
                        .map_err(invalid_at!())?;
                }
                let now = Instant::now();
                let producer_pending = self
                    .terminal
                    .as_ref()
                    .is_some_and(RemoteTerminalState::has_immediate_output);
                let can_continue_burst = terminal_burst_can_continue(
                    stream.burst_started,
                    now,
                    current.fresh_until(),
                    stream.operation.deadline(),
                    !stream.aborted.get() && stream.operation.check().is_ok(),
                    current.current(&evidence),
                    producer_pending,
                );
                let next_delivery = if can_continue_burst {
                    self.terminal
                        .as_mut()
                        .ok_or(peer::PeerError::Invalid)?
                        .next_frame(crypto, &evidence, &current)
                        .map_err(invalid_at!())?
                } else {
                    None
                };
                drop(evidence);
                if let Some(delivery) = next_delivery {
                    watch(operation, gate, paused, stopping, public_pending)
                        .map_err(invalid_at!())?;
                    owner
                        .peer_original_boundary(operation, continuation)
                        .map_err(owner_error_at!())?;
                    let bytes = serde_json::to_vec(delivery.frame()).map_err(invalid_at!())?;
                    let remaining = frame_count(bytes.len());
                    if remaining == 0 {
                        return Err(peer::PeerError::Invalid);
                    }
                    self.encoder
                        .begin(MessageKind::TerminalFrame, bytes)
                        .map_err(invalid_at!())?;
                    stream.delivery = Some(delivery);
                    stream.remaining = remaining;
                    stream.peer = Some(current);
                    self.stream = Some(stream);
                } else if stream.burst_started.is_some() {
                    // The replacement admission has not run while this staged
                    // normal terminal message owned the connection turn. Return
                    // the exact original operation (and deadline) for the next
                    // proof check; never carry it across a worker-unit boundary.
                    restore_terminal_stream_operation(
                        &mut self.maintenance,
                        &mut self.maintenance_aborted,
                        stream.operation,
                        stream.aborted,
                    );
                    self.peer = Some(current);
                } else {
                    self.peer = None;
                }
            } else {
                stream.peer = Some(current);
                self.stream = Some(stream);
            }
            return Ok(true);
        }
        if self.maintenance.check().is_err() {
            self.maintenance_aborted.set(false);
            self.maintenance = super::OwnerOperation::new(
                runtime.operation.deadline(),
                cancelled.ok_or(peer::PeerError::Invalid)?,
            );
            self.peer = None;
        }
        let maintenance_runtime = Runtime {
            operation: &self.maintenance,
            aborted: &self.maintenance_aborted,
            ..runtime
        };
        let current = current_proof(
            self.peer.take(),
            auth,
            maintenance_runtime,
            eligibility,
            &self.source,
            self.peer_cutoff,
        )?;
        self.assembler
            .expire(u64::try_from(self.origin.elapsed().as_millis()).map_err(invalid_at!())?)
            .map_err(invalid_at!())?;
        let evidence = maintenance_runtime.remote_worker_evidence(auth, eligibility)?;
        let io_deadline = current
            .io_deadline(&evidence)
            .ok_or(peer::PeerError::Invalid)?;
        let operation = maintenance_runtime.operation;
        let owner = maintenance_runtime.owner;
        let continuation = current.continuation();
        let gate = maintenance_runtime.gate;
        let paused = maintenance_runtime.paused;
        let stopping = maintenance_runtime.stopping;
        let public_pending = &maintenance_runtime.public_io.setup().pending;
        let check = || {
            watch(operation, gate, paused, stopping, public_pending)?;
            owner
                .peer_original_boundary(operation, continuation)
                .map_err(|_| BudgetStop::Cancelled)
        };
        if current.observed_at() > self.applied_observation
            && let Crypto::ReadFirst(pending)
            | Crypto::WriteSecond(pending)
            | Crypto::ReadThird(pending) = &mut self.crypto
        {
            let turn = peer::owner_turn(maintenance_runtime, || {
                maintenance_runtime.owner.try_remote_workspace_turn(
                    &evidence,
                    &current,
                    &self.workspace,
                )
            })?;
            turn.refresh_pending_peer(pending).map_err(invalid_at!())?;
            self.applied_observation = current.observed_at();
        }
        let stage = std::mem::replace(&mut self.crypto, Crypto::Vacant);
        let mut request = None;
        let mut advanced = false;
        match stage {
            Crypto::WriteSecond(mut pending) => {
                let bytes = {
                    let turn = peer::owner_turn(maintenance_runtime, || {
                        maintenance_runtime.owner.try_remote_workspace_turn(
                            &evidence,
                            &current,
                            &self.workspace,
                        )
                    })?;
                    turn.handshake_write(&mut pending).map_err(invalid_at!())?
                };
                self.socket
                    .send_binary(&bytes, io_deadline, &check)
                    .map_err(invalid_at!())?;
                self.crypto = Crypto::ReadThird(pending);
                advanced = true;
            }
            other => {
                let frame = if request.is_some() {
                    Poll::Pending
                } else {
                    self.socket
                        .poll_binary(io_deadline, &check)
                        .map_err(invalid_at!())?
                };
                match (other, frame) {
                    (Crypto::Established(mut crypto), Poll::Pending) => {
                        let turn = peer::owner_turn(maintenance_runtime, || {
                            maintenance_runtime.owner.try_remote_workspace_turn(
                                &evidence,
                                &current,
                                &self.workspace,
                            )
                        })?;
                        if current.observed_at() > self.applied_observation {
                            turn.refresh_peer(&mut crypto).map_err(invalid_at!())?;
                            self.applied_observation = current.observed_at();
                        }
                        self.crypto = Crypto::Established(crypto);
                    }
                    (stage, Poll::Pending) => self.crypto = stage,
                    (Crypto::ReadFirst(mut pending), Poll::Ready(bytes)) => {
                        let turn = peer::owner_turn(maintenance_runtime, || {
                            maintenance_runtime.owner.try_remote_workspace_turn(
                                &evidence,
                                &current,
                                &self.workspace,
                            )
                        })?;
                        turn.handshake_read(&mut pending, &bytes)
                            .map_err(invalid_at!())?;
                        self.crypto = Crypto::WriteSecond(pending);
                        advanced = true;
                    }
                    (Crypto::ReadThird(mut pending), Poll::Ready(bytes)) => {
                        let turn = peer::owner_turn(maintenance_runtime, || {
                            maintenance_runtime.owner.try_remote_workspace_turn(
                                &evidence,
                                &current,
                                &self.workspace,
                            )
                        })?;
                        turn.handshake_read(&mut pending, &bytes)
                            .map_err(invalid_at!())?;
                        let established = turn.finish_connection(pending).map_err(invalid_at!())?;
                        if !established.supports_active_rpc_purpose() {
                            return Err(peer::PeerError::Invalid);
                        }
                        self.terminal = Some(
                            RemoteTerminalState::new(self.coordinator.clone(), &established)
                                .map_err(invalid_at!())?,
                        );
                        self.crypto = Crypto::Established(established);
                        advanced = true;
                    }
                    (Crypto::Established(mut crypto), Poll::Ready(bytes)) => {
                        let plain = {
                            let turn = peer::owner_turn(maintenance_runtime, || {
                                maintenance_runtime.owner.try_remote_workspace_turn(
                                    &evidence,
                                    &current,
                                    &self.workspace,
                                )
                            })?;
                            if current.observed_at() > self.applied_observation {
                                turn.refresh_peer(&mut crypto).map_err(invalid)?;
                                self.applied_observation = current.observed_at();
                            }
                            turn.open_frame(&mut crypto, &bytes).map_err(invalid)?
                        };
                        if let Some(message) = self
                            .assembler
                            .push(
                                plain.as_ref(),
                                u64::try_from(self.origin.elapsed().as_millis())
                                    .map_err(invalid_at!())?,
                            )
                            .map_err(invalid_at!())?
                        {
                            if message.kind == MessageKind::WorkspaceFrame {
                                let acknowledged =
                                    match lomi_remote_protocol::decode_workspace_frame(
                                        &message.bytes,
                                    ) {
                                        Ok(lomi_remote_protocol::WorkspaceStreamFrame::Ack(
                                            ack,
                                        )) => self
                                            .workspace_stream
                                            .as_mut()
                                            .is_some_and(|stream| stream.ack(&ack)),
                                        _ => false,
                                    };
                                if !acknowledged {
                                    return Err(peer::PeerError::Invalid);
                                }
                            } else if message.kind == MessageKind::FileWatchFrame {
                                // Only the client's acknowledgement of this
                                // connection's own watch is accepted.
                                let acknowledged = match lomi_remote_protocol::decode_watch_frame(
                                    &message.bytes,
                                ) {
                                    Ok(lomi_remote_protocol::FileWatchFrame::Ack(ack)) => {
                                        self.watch.as_mut().is_some_and(|watch| watch.ack(&ack))
                                    }
                                    _ => false,
                                };
                                if !acknowledged {
                                    return Err(peer::PeerError::Invalid);
                                }
                            } else if message.kind != MessageKind::RpcRequest {
                                return Err(peer::PeerError::Invalid);
                            } else {
                                let decoded =
                                    lomi_remote_protocol::rpc::decode_request(&message.bytes)
                                        .map_err(invalid_at!())?;
                                request = Some((decoded, Instant::now()));
                            }
                        }
                        self.crypto = Crypto::Established(crypto);
                        advanced = true;
                    }
                    _ => return Err(peer::PeerError::Invalid),
                }
            }
        }
        self.peer_cutoff = current.fresh_until();
        drop(evidence);
        self.peer = Some(current);
        if request.is_none()
            && let Crypto::Established(crypto) = &mut self.crypto
        {
            let current = self.peer.as_ref().ok_or(peer::PeerError::Invalid)?;
            let evidence = maintenance_runtime.remote_worker_evidence(auth, eligibility)?;
            let mut outbound = None;
            // Rotate stream classes so a busy terminal or directory cannot
            // indefinitely delay workspace changes on the same connection.
            for offset in 0..3 {
                let class = (self.next_stream_class + offset) % 3;
                outbound = match class {
                    0 => self
                        .terminal
                        .as_mut()
                        .ok_or(peer::PeerError::Invalid)?
                        .next_frame(crypto, &evidence, current)
                        .map_err(invalid_at!())?
                        .map(|delivery| {
                            serde_json::to_vec(delivery.frame())
                                .map(|bytes| (MessageKind::TerminalFrame, bytes, Some(delivery)))
                        })
                        .transpose()
                        .map_err(invalid_at!())?,
                    1 if self.workspace_stream.is_some() => {
                        let state = {
                            let turn = peer::owner_turn(maintenance_runtime, || {
                                maintenance_runtime.owner.try_remote_workspace_turn(
                                    &evidence,
                                    current,
                                    &self.workspace,
                                )
                            })?;
                            turn.workspace_stream_state(crypto).map_err(invalid_at!())?
                        };
                        self.workspace_stream
                            .as_mut()
                            .and_then(|stream| stream.next_projected(state))
                            .map(|frame| {
                                serde_json::to_vec(&frame)
                                    .map(|bytes| (MessageKind::WorkspaceFrame, bytes, None))
                            })
                            .transpose()
                            .map_err(invalid_at!())?
                    }
                    2 => self
                        .watch
                        .as_mut()
                        .and_then(|watch| watch.poll(Instant::now()))
                        .map(|frame| {
                            serde_json::to_vec(&frame)
                                .map(|bytes| (MessageKind::FileWatchFrame, bytes, None))
                        })
                        .transpose()
                        .map_err(invalid_at!())?,
                    _ => None,
                };
                if outbound.is_some() {
                    self.next_stream_class = (class + 1) % 3;
                    break;
                }
            }
            drop(evidence);
            if let Some((kind, bytes, delivery)) = outbound {
                let cancellation = cancelled.ok_or(peer::PeerError::Invalid)?;
                let authorization_call = match kind {
                    MessageKind::WorkspaceFrame => self.workspace_stream_call.clone(),
                    MessageKind::FileWatchFrame => self.watch_call.clone(),
                    MessageKind::TerminalFrame => None,
                    _ => return Err(peer::PeerError::Invalid),
                };
                let replacement_maintenance =
                    super::OwnerOperation::new(worker_deadline, cancellation);
                let remaining = bytes
                    .len()
                    .div_ceil(lomi_remote_protocol::message_framing::MAX_FRAGMENT_PAYLOAD_LEN);
                let burst_pending_first_send =
                    kind == MessageKind::TerminalFrame && delivery.is_some();
                self.encoder.begin(kind, bytes).map_err(invalid_at!())?;
                // Serialization follows dropping actor/Domain/Core turns.
                // Transfer the exact maintenance admission and proof that
                // authorized this output to its first physical fragment.
                let (operation, aborted, peer) = transfer_maintenance_to_stream(
                    &mut self.maintenance,
                    &mut self.maintenance_aborted,
                    &mut self.peer,
                    replacement_maintenance,
                );
                self.stream = Some(PendingStream {
                    operation,
                    aborted,
                    peer,
                    kind,
                    authorization_call,
                    delivery,
                    burst_pending_first_send,
                    burst_started: None,
                    remaining,
                });
                advanced = true;
            }
        }
        if let Some((request, received)) = request {
            let terminal_renew = matches!(&request.call, RpcCall::TerminalRenew(_));
            let request_deadline = received
                .checked_add(Duration::from_millis(request.timeout_ms.get()))
                .ok_or(peer::PeerError::Invalid)?
                .min(worker_deadline);
            let (mut operation, aborted, cached_peer) = if terminal_renew {
                let replacement_maintenance = super::OwnerOperation::new(
                    worker_deadline,
                    cancelled.ok_or(peer::PeerError::Invalid)?,
                );
                let (operation, aborted, peer) = transfer_maintenance_to_stream(
                    &mut self.maintenance,
                    &mut self.maintenance_aborted,
                    &mut self.peer,
                    replacement_maintenance,
                );
                (operation, aborted, peer)
            } else {
                // Other RPCs use a different admission and cannot refresh the
                // channel from this maintenance observation.
                self.peer = None;
                (
                    super::OwnerOperation::new(
                        request_deadline,
                        cancelled.ok_or(peer::PeerError::Invalid)?,
                    ),
                    std::cell::Cell::new(false),
                    None,
                )
            };
            if terminal_renew {
                operation.cap_deadline(request_deadline);
            }
            let request_runtime = Runtime {
                operation: &operation,
                aborted: &aborted,
                ..runtime
            };
            let (current, evidence) = if terminal_renew {
                let evidence = request_runtime.remote_worker_evidence(auth, eligibility)?;
                if let Some(current) = terminal_renew_cached_proof(
                    cached_peer,
                    request_runtime,
                    self.peer_cutoff,
                    &evidence,
                ) {
                    (current, evidence)
                } else {
                    drop(evidence);
                    let current = peer::Worker::default().read_current_pairing_bounded(
                        auth,
                        request_runtime,
                        eligibility,
                        self.source.clone(),
                        self.peer_cutoff,
                    )?;
                    let evidence = request_runtime.remote_worker_evidence(auth, eligibility)?;
                    (current, evidence)
                }
            } else {
                let current = peer::Worker::default().read_current_pairing_bounded(
                    auth,
                    request_runtime,
                    eligibility,
                    self.source.clone(),
                    self.peer_cutoff,
                )?;
                let evidence = request_runtime.remote_worker_evidence(auth, eligibility)?;
                (current, evidence)
            };
            let Crypto::Established(crypto) = &mut self.crypto else {
                return Err(peer::PeerError::Invalid);
            };
            let (queued, workspace_result, workspace_subscription, workspace_capabilities) = {
                let turn = peer::owner_turn(request_runtime, || {
                    request_runtime.owner.try_remote_workspace_turn(
                        &evidence,
                        &current,
                        &self.workspace,
                    )
                })?;
                if current.observed_at() > self.applied_observation {
                    turn.refresh_peer(crypto).map_err(invalid_at!())?;
                    self.applied_observation = current.observed_at();
                }
                let queued = if operation_control_call(&request.call) {
                    turn.before_operation_queue(crypto, &request)
                } else {
                    turn.before_queue(crypto, &request)
                }
                .map_err(invalid_at!())?;
                let workspace = if matches!(&request.call, RpcCall::WorkspaceGet(_)) {
                    Some(
                        turn.workspace_get_after_wait(crypto, &queued)
                            .map_err(invalid_at!())?,
                    )
                } else {
                    None
                };
                let capabilities = if matches!(&request.call, RpcCall::WorkspaceCapabilities(_)) {
                    Some(
                        turn.workspace_capabilities_after_wait(crypto, &queued)
                            .map_err(invalid_at!())?,
                    )
                } else {
                    None
                };
                let subscription = if matches!(&request.call, RpcCall::WorkspaceSubscribe(_)) {
                    Some(
                        turn.workspace_subscribe_after_wait(crypto, &queued)
                            .map_err(invalid_at!())?,
                    )
                } else {
                    None
                };
                (queued, workspace, subscription, capabilities)
            };
            if operation_control_call(&request.call) {
                let preflight = runtime
                    .owner
                    .lookup_remote_operation(&evidence, &current, crypto, &request, &queued)
                    .map_err(owner_error_at!())?;
                let coordinator = self.coordinator.upgrade().ok_or(peer::PeerError::Invalid)?;
                let actor = coordinator
                    .workspace_lock(self.workspace.workspace_id)
                    .map_err(|_| peer::PeerError::Invalid)?;
                let actor_guard =
                    super::super::rpc::actor_lock(&actor, &operation).map_err(invalid_at!())?;
                let ready = {
                    let turn = peer::owner_turn(request_runtime, || {
                        request_runtime.owner.try_remote_workspace_turn(
                            &evidence,
                            &current,
                            &self.workspace,
                        )
                    })?;
                    turn.after_operation_wait(
                        crypto,
                        &queued,
                        preflight
                            .as_ref()
                            .map(|disclosure| disclosure.authorization()),
                    )
                    .map_err(invalid_at!())?
                };
                let ready_request = ready.request().clone();
                let disclosure = if matches!(&ready_request.call, RpcCall::OperationCancel(_))
                    && preflight.is_some()
                {
                    let mut cancel_turn = runtime
                        .owner
                        .begin_remote_operation_cancel(
                            &evidence,
                            &current,
                            crypto,
                            &ready_request,
                            &queued,
                            &ready,
                        )
                        .map_err(owner_error_at!())?;
                    // The registered Shared writer now excludes relevant
                    // workspace/auth writers; do not hold the workspace actor
                    // while retrying pre-Store contention.
                    drop(actor_guard);
                    loop {
                        operation.check().map_err(invalid_at!())?;
                        match cancel_turn.try_finish().map_err(owner_error_at!())? {
                            super::super::shared_owner::RemoteOperationCancelProgress::Retry => {
                                std::thread::park_timeout(
                                    operation
                                        .deadline()
                                        .saturating_duration_since(Instant::now())
                                        .min(Duration::from_millis(1)),
                                );
                            }
                            super::super::shared_owner::RemoteOperationCancelProgress::Finished(
                                disclosure,
                            ) => break disclosure,
                        }
                    }
                } else {
                    drop(actor_guard);
                    preflight
                };

                // Store cancellation can race authorization maintenance. A
                // response always re-enters the ordinary current-pairing and
                // WorkspaceRead/stored-rights gates before disclosure.
                let response_current = peer::Worker::default().read_current_pairing_bounded(
                    auth,
                    request_runtime,
                    eligibility,
                    self.source.clone(),
                    self.peer_cutoff,
                )?;
                let response_evidence =
                    request_runtime.remote_worker_evidence(auth, eligibility)?;
                {
                    let turn = peer::owner_turn(request_runtime, || {
                        request_runtime.owner.try_remote_workspace_turn(
                            &response_evidence,
                            &response_current,
                            &self.workspace,
                        )
                    })?;
                    let Crypto::Established(crypto) = &mut self.crypto else {
                        return Err(peer::PeerError::Invalid);
                    };
                    if response_current.observed_at() > self.applied_observation {
                        turn.refresh_peer(crypto).map_err(invalid_at!())?;
                        self.applied_observation = response_current.observed_at();
                    }
                    turn.cached_operation_response(
                        crypto,
                        &ready_request,
                        disclosure.as_ref().map(|value| value.authorization()),
                    )
                    .map_err(invalid_at!())?;
                }
                let response = match disclosure.as_ref() {
                    Some(disclosure) => {
                        disclosure.response(&ready_request).map_err(invalid_at!())?
                    }
                    None => RpcResponse::Error {
                        v: ready_request.v,
                        request_id: ready_request.request_id.clone(),
                        operation_id: None,
                        error: operation_not_found(),
                    },
                };
                self.peer_cutoff = response_current.fresh_until();
                drop(response_evidence);
                let bytes = serde_json::to_vec(&response).map_err(invalid_at!())?;
                let remaining = frame_count(bytes.len());
                self.encoder
                    .begin(MessageKind::RpcResponse, bytes)
                    .map_err(invalid_at!())?;
                self.response = Some(PendingResponse {
                    operation,
                    aborted,
                    request: ready_request,
                    peer: Some(response_current),
                    operation_control: true,
                    operation_disclosure: disclosure,
                    git_receipt_disclosure: None,
                    remaining,
                });
                self.peer = None;
                return Ok(true);
            }
            // The workspace Domain turn is gone before terminal actor acquisition.
            let mut git_receipt_disclosure = None;
            let result = if let Some(workspace) = workspace_result {
                Ok(RpcResult::WorkspaceGet(workspace))
            } else if let Some(workspace) = workspace_subscription {
                self.workspace_stream = None;
                self.workspace_stream_call = Some(request.clone());
                match super::super::local_streams::Workspace::open_projected(workspace, 0) {
                    Ok((stream, metadata)) => {
                        self.workspace_stream = Some(stream);
                        Ok(RpcResult::WorkspaceSubscribe(metadata))
                    }
                    Err(error) => Err(error),
                }
            } else if let Some(capabilities) = workspace_capabilities {
                Ok(RpcResult::WorkspaceCapabilities(capabilities))
            } else if matches!(
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
            ) {
                // Preserve resource-local Invalid/withhold classification while
                // passing the actual closed gate cause to safe type diagnostics.
                let rename_invalid = |error| match error {
                    super::super::shared_owner::RemoteRenameError::Gate(gate) => invalid(gate),
                    error => invalid(error),
                };
                // The original request operation, abort latch, fresh peer and
                // evidence remain borrowed through this synchronous one-frame
                // receipt send. Never manufacture a PendingResponse/new budget.
                match super::super::remote_terminal_rename::execute(
                    &self.coordinator,
                    crypto,
                    &evidence,
                    &current,
                    request_runtime.owner,
                    &request,
                    &queued,
                )
                .map_err(rename_invalid)?
                {
                    super::super::remote_terminal_rename::RemoteRenameOutcome::Duplicate(
                        receipt,
                    ) => {
                        // Ordinary current response/disclosure path; duplicates
                        // never receive an own-publication exception.
                        Ok(match &request.call {
                            RpcCall::TerminalRename(_) => RpcResult::TerminalRename(receipt),
                            RpcCall::TerminalMove(_) => RpcResult::TerminalMove(receipt),
                            RpcCall::TerminalCreate(_) => RpcResult::TerminalCreate(receipt),
                            RpcCall::TerminalSplit(_) => RpcResult::TerminalSplit(receipt),
                            RpcCall::TerminalClose(_) => RpcResult::TerminalClose(receipt),
                            RpcCall::TerminalRestart(_) => RpcResult::TerminalRestart(receipt),
                            RpcCall::FilesCreate(_) => RpcResult::FilesCreate(receipt),
                            RpcCall::FilesMkdir(_) => RpcResult::FilesMkdir(receipt),
                            RpcCall::FilesRename(_) => RpcResult::FilesRename(receipt),
                            RpcCall::FilesRemove(_) => RpcResult::FilesRemove(receipt),
                            _ => unreachable!("closed terminal edit ingress branch"),
                        })
                    }
                    super::super::remote_terminal_rename::RemoteRenameOutcome::Rejected(error) => {
                        // Nothing was journaled or executed and every owner turn
                        // is gone: an ordinary error response, never a receipt.
                        Err(error)
                    }
                    super::super::remote_terminal_rename::RemoteRenameOutcome::Committed(
                        receipt,
                    ) => {
                        // execute dropped actor/Domain/Store turns. This is the
                        // SAME connection encoder used for every RPC/stream.
                        let frame = match super::super::remote_terminal_rename::RemoteRenameResponseFrame::encode(*receipt, &mut self.encoder) {
                            Ok(frame) => frame,
                            Err(error) => { crypto.dispose(); return Err(rename_invalid(error)); }
                        };
                        let sealed = frame.seal(crypto).map_err(rename_invalid)?;
                        sealed
                            .send(crypto, relay_socket_mut(&mut self.socket))
                            .map_err(invalid_at!())?;
                        // Any subsequent request still needs ordinary fresh
                        // authority after publication; never replay this result.
                        self.peer_cutoff = current.fresh_until();
                        return Ok(true);
                    }
                }
            } else if matches!(
                &request.call,
                RpcCall::FilesList(_)
                    | RpcCall::FilesStat(_)
                    | RpcCall::FilesRead(_)
                    | RpcCall::FilesSearchNames(_)
                    | RpcCall::FilesWatch(_)
            ) {
                let turn = peer::owner_turn(request_runtime, || {
                    request_runtime.owner.try_remote_workspace_turn(
                        &evidence,
                        &current,
                        &self.workspace,
                    )
                })?;
                let (_, target) = turn
                    .files_after_wait(crypto, &queued)
                    .map_err(invalid_at!())?;
                // The Domain/Store turn is gone before any file IO; the result
                // still passes the ordinary live gate when it is sent.
                drop(turn);
                let coordinator = self.coordinator.upgrade().ok_or(peer::PeerError::Invalid)?;
                if let RpcCall::FilesWatch(params) = &request.call {
                    // One watch per connection; a new one replaces the old.
                    self.watch_generation += 1;
                    self.watch_call = Some(request.clone());
                    let generation = self.watch_generation;
                    let opened = super::super::remote_files_watch::RemoteWatch::replace(
                        &mut self.watch,
                        || {
                            coordinator
                                .files
                                .get(target.workspace_id, target.epoch, &target.root)
                                .and_then(|files| {
                                    super::super::remote_files_watch::RemoteWatch::open(
                                        files,
                                        params,
                                        generation,
                                        Instant::now(),
                                    )
                                })
                        },
                    );
                    match opened {
                        Ok(result) => Ok(RpcResult::FilesWatch(result)),
                        Err(error) => Err(error),
                    }
                } else {
                    coordinator
                        .files
                        .get(target.workspace_id, target.epoch, &target.root)
                        .and_then(|files| {
                            super::super::remote_files::execute_read(&files, &request.call)
                        })
                }
            } else if matches!(
                &request.call,
                RpcCall::GitRepositories(_)
                    | RpcCall::GitStatus(_)
                    | RpcCall::GitDiff(_)
                    | RpcCall::GitLog(_)
                    | RpcCall::GitShow(_)
            ) {
                let turn = peer::owner_turn(request_runtime, || {
                    request_runtime.owner.try_remote_workspace_turn(
                        &evidence,
                        &current,
                        &self.workspace,
                    )
                })?;
                let target = turn
                    .git_read_after_wait(crypto, &queued)
                    .map_err(invalid_at!())?;
                drop(turn);
                Self::reserve_async_git_output_for(
                    &self.encoder,
                    &self.started_git_outputs,
                    &mut self.git_output_reservation,
                    MAX_MESSAGE_LEN,
                )?;
                let coordinator = self.coordinator.upgrade().ok_or(peer::PeerError::Invalid)?;
                match coordinator.git_reads.start(
                    self.workspace.clone(),
                    target.root,
                    request.call.clone(),
                    operation.deadline(),
                ) {
                    Ok(read) => {
                        self.peer_cutoff = current.fresh_until();
                        self.git_read = Some(PendingGitRead {
                            operation,
                            aborted,
                            request,
                            peer: Some(current),
                            read,
                        });
                        return Ok(true);
                    }
                    Err(error) => {
                        self.git_output_reservation = 0;
                        Err(error)
                    }
                }
            } else if git_mutation_call(&request.call) {
                let preflight = runtime
                    .owner
                    .preflight_remote_git_mutation(&evidence, &current, crypto, &request, &queued)
                    .map_err(remote_git_owner_error)?;
                match preflight {
                    super::super::shared_owner::RemoteGitMutationPreflight::Duplicate(
                        receipt,
                        disclosure,
                    ) => {
                        git_receipt_disclosure = Some(disclosure);
                        Ok(super::super::rpc::git_receipt_result(
                            request.call.method(),
                            receipt,
                        ))
                    }
                    super::super::shared_owner::RemoteGitMutationPreflight::Conflict => Err(
                        super::super::rpc::stored(lomi_host_store::StoreError::IdempotencyConflict),
                    ),
                    super::super::shared_owner::RemoteGitMutationPreflight::New(target) => {
                        Self::reserve_async_git_output_for(
                            &self.encoder,
                            &self.started_git_outputs,
                            &mut self.git_output_reservation,
                            MAX_FRAGMENT_PAYLOAD_LEN,
                        )?;
                        let coordinator =
                            self.coordinator.upgrade().ok_or(peer::PeerError::Invalid)?;
                        match coordinator.git_mutations.start(
                            self.workspace.clone(),
                            target.root.clone(),
                            request.call.clone(),
                            operation.deadline(),
                        ) {
                            Ok(job) => {
                                let cancellation = job.cancellation();
                                let control = lomi_git::RequestControl::with_deadline(
                                    cancellation.clone(),
                                    operation.deadline(),
                                );
                                self.peer_cutoff = current.fresh_until();
                                self.git_mutation = Some(PendingGitMutation {
                                    operation,
                                    aborted,
                                    request,
                                    peer: Some(current),
                                    publication_peer: None,
                                    queued: Some(queued),
                                    context: self.workspace.clone(),
                                    target,
                                    control,
                                    cancellation: cancellation.clone(),
                                    _cancel_on_drop: CancelGitOnDrop(cancellation),
                                    started: None,
                                    lease: None,
                                    continuation: None,
                                    invalidated: false,
                                    state: Some(PendingGitMutationState::Preparing(job)),
                                });
                                return Ok(true);
                            }
                            Err(error) => {
                                self.git_output_reservation = 0;
                                Err(error)
                            }
                        }
                    }
                }
            } else if terminal_call(&request.call) {
                self.terminal
                    .as_mut()
                    .ok_or(peer::PeerError::Invalid)?
                    .execute(crypto, &evidence, &current, &request, &queued)
            } else {
                let turn = peer::owner_turn(request_runtime, || {
                    request_runtime.owner.try_remote_workspace_turn(
                        &evidence,
                        &current,
                        &self.workspace,
                    )
                })?;
                turn.finish_unsupported_after_wait(crypto, &queued)
                    .map_err(invalid_at!())?;
                Err(unsupported())
            };
            let response = match result {
                Ok(result) => RpcResponse::Result {
                    v: request.v,
                    request_id: request.request_id.clone(),
                    result,
                },
                Err(error) => {
                    if error.effect() == lomi_remote_protocol::Effect::Unknown
                        || matches!(
                            error.code(),
                            lomi_remote_protocol::ErrorCode::ScopeDenied
                                | lomi_remote_protocol::ErrorCode::ServiceUnavailable
                        )
                    {
                        // Early actor/owner/coordinator failures can precede
                        // after_wait consumption. Dispose rather than retaining
                        // an ambiguous queued continuation or retrying an effect.
                        return Err(peer::PeerError::Invalid);
                    }
                    RpcResponse::Error {
                        v: request.v,
                        request_id: request.request_id.clone(),
                        operation_id: None,
                        error,
                    }
                }
            };
            self.peer_cutoff = current.fresh_until();
            let bytes = serde_json::to_vec(&response).map_err(invalid_at!())?;
            // Only the response flush is shared; ACK/Claim keep fresh proofs.
            let terminal_control_response = matches!(
                &request.call,
                RpcCall::TerminalRenew(_)
                    | RpcCall::TerminalAck(_)
                    | RpcCall::TerminalClaim(_)
                    | RpcCall::TerminalInput(_)
                    | RpcCall::TerminalResize(_)
            );
            if terminal_control_response && frame_count(bytes.len()) == 1 {
                self.encoder
                    .begin(MessageKind::RpcResponse, bytes)
                    .map_err(invalid_at!())?;
                let frame = {
                    let turn = peer::owner_turn(request_runtime, || {
                        request_runtime.owner.try_remote_workspace_turn(
                            &evidence,
                            &current,
                            &self.workspace,
                        )
                    })?;
                    let Crypto::Established(crypto) = &mut self.crypto else {
                        return Err(peer::PeerError::Invalid);
                    };
                    if current.observed_at() > self.applied_observation {
                        turn.refresh_peer(crypto).map_err(invalid_at!())?;
                        self.applied_observation = current.observed_at();
                    }
                    turn.check_response(crypto, &request)
                        .map_err(invalid_at!())?;
                    self.encoder
                        .next_frame()
                        .map_err(invalid_at!())?
                        .map(|frame| turn.seal_frame(crypto, &frame))
                        .transpose()
                        .map_err(invalid_at!())?
                        .ok_or(peer::PeerError::Invalid)?
                };
                let send_deadline = current
                    .io_deadline(&evidence)
                    .ok_or(peer::PeerError::Invalid)?;
                let operation = &operation;
                let owner = runtime.owner;
                let continuation = current.continuation();
                let gate = runtime.gate;
                let paused = runtime.paused;
                let stopping = runtime.stopping;
                let public_pending = &runtime.public_io.setup().pending;
                let check = || {
                    watch(operation, gate, paused, stopping, public_pending)?;
                    owner
                        .peer_original_boundary(operation, continuation)
                        .map_err(|_| BudgetStop::Cancelled)
                };
                self.socket
                    .send_binary(&frame, send_deadline, &check)
                    .map_err(invalid_at!())?;
                return Ok(true);
            }
            drop(evidence);
            let remaining = frame_count(bytes.len());
            self.encoder
                .begin(MessageKind::RpcResponse, bytes)
                .map_err(invalid_at!())?;
            self.response = Some(PendingResponse {
                operation,
                aborted,
                request,
                peer: Some(current),
                operation_control: false,
                operation_disclosure: None,
                git_receipt_disclosure,
                remaining,
            });
            advanced = true;
        }
        Ok(advanced)
    }
}

fn current_proof(
    cached: Option<peer::VerifiedCurrentPeer>,
    auth: &HostAuth<'_, dyn SecretStorage + '_>,
    runtime: RuntimeWithOperation<'_, '_>,
    eligibility: &PeerEligibility,
    source: &lomi_host_store::AcknowledgedWorkspaceGrant,
    cutoff: Instant,
) -> peer::ResultPeer<peer::VerifiedCurrentPeer> {
    if let Some(proof) = cached {
        let evidence = runtime.remote_worker_evidence(auth, eligibility)?;
        let now = Instant::now();
        if proof.current(&evidence)
            && now
                .checked_add(PEER_REFRESH_MARGIN)
                .is_some_and(|refresh_by| refresh_by < proof.fresh_until())
        {
            return Ok(proof);
        }
    }
    peer::Worker::default().read_current_pairing_bounded(
        auth,
        runtime,
        eligibility,
        source.clone(),
        cutoff,
    )
}

fn terminal_renew_cached_proof(
    cached: Option<peer::VerifiedCurrentPeer>,
    runtime: RuntimeWithOperation<'_, '_>,
    cutoff: Instant,
    evidence: &super::RemoteWorkerEvidence<'_, '_, '_, '_>,
) -> Option<peer::VerifiedCurrentPeer> {
    let proof = cached?;
    let deadline = runtime.operation.deadline();
    (proof.current(evidence)
        && proof.io_deadline(evidence).is_some_and(|proof_deadline| {
            terminal_renew_cached_proof_covers(Instant::now(), deadline, cutoff, proof_deadline)
        }))
    .then_some(proof)
}

fn terminal_renew_cached_proof_covers(
    now: Instant,
    operation_deadline: Instant,
    peer_cutoff: Instant,
    proof_deadline: Instant,
) -> bool {
    now < operation_deadline
        && peer_cutoff >= operation_deadline
        && proof_deadline >= operation_deadline
}

fn terminal_call(call: &RpcCall) -> bool {
    matches!(
        call,
        RpcCall::TerminalAttach(_)
            | RpcCall::TerminalSnapshot(_)
            | RpcCall::TerminalAck(_)
            | RpcCall::TerminalClaim(_)
            | RpcCall::TerminalRenew(_)
            | RpcCall::TerminalRelease(_)
            | RpcCall::TerminalInput(_)
            | RpcCall::TerminalResize(_)
    )
}

fn operation_control_call(call: &RpcCall) -> bool {
    matches!(
        call,
        RpcCall::OperationStatus(_) | RpcCall::OperationCancel(_)
    )
}

fn active_started_git_operation_control_call(
    call: &RpcCall,
    active: &super::shared_owner::StartedGitContinuation,
) -> bool {
    let (workspace, operation_id) = match call {
        RpcCall::OperationStatus(params) => (params.context.workspace_id, params.operation_id),
        RpcCall::OperationCancel(params) => (params.context.workspace_id, params.operation_id),
        _ => return false,
    };
    workspace == active.context_workspace() && operation_id == active.operation_id()
}

fn terminal_target(call: &RpcCall) -> Option<&lomi_remote_protocol::TerminalContext> {
    match call {
        RpcCall::TerminalAttach(params) | RpcCall::TerminalSnapshot(params) => {
            Some(&params.terminal)
        }
        RpcCall::TerminalAck(params) => Some(&params.terminal),
        RpcCall::TerminalClaim(params) => Some(&params.terminal),
        RpcCall::TerminalRenew(params) | RpcCall::TerminalRelease(params) => Some(&params.terminal),
        RpcCall::TerminalInput(params) => Some(&params.terminal),
        RpcCall::TerminalResize(params) => Some(&params.terminal),
        _ => None,
    }
}

fn frame_count(byte_length: usize) -> usize {
    byte_length.div_ceil(MAX_FRAGMENT_PAYLOAD_LEN)
}

fn prioritized_staged_remaining(
    response_remaining: Option<usize>,
    stream_remaining: Option<usize>,
    has_active_git_writer: bool,
) -> Option<usize> {
    if has_active_git_writer {
        return None;
    }
    response_remaining
        .filter(|remaining| *remaining > 0)
        .or_else(|| stream_remaining.filter(|remaining| *remaining > 0))
}

fn git_mutation_call(call: &RpcCall) -> bool {
    matches!(
        call,
        RpcCall::GitStage(_)
            | RpcCall::GitUnstage(_)
            | RpcCall::GitCommit(_)
            | RpcCall::GitFetch(_)
            | RpcCall::GitPull(_)
            | RpcCall::GitPush(_)
    )
}

fn remote_git_owner_error(error: super::super::shared_owner::RemoteRenameError) -> peer::PeerError {
    match error {
        super::super::shared_owner::RemoteRenameError::Owner(error) => peer::owner_error(error),
        super::super::shared_owner::RemoteRenameError::Gate(_)
        | super::super::shared_owner::RemoteRenameError::Closed => peer::PeerError::Invalid,
    }
}

fn unsupported() -> lomi_remote_protocol::RemoteError {
    lomi_remote_protocol::RemoteError::new(
        lomi_remote_protocol::ErrorCode::UnsupportedCapability,
        false,
        lomi_remote_protocol::Effect::None,
        lomi_remote_protocol::ErrorDetails::empty(),
        None,
    )
    .expect("static unsupported method")
}

fn operation_not_found() -> lomi_remote_protocol::RemoteError {
    lomi_remote_protocol::RemoteError::new(
        lomi_remote_protocol::ErrorCode::OperationNotFound,
        false,
        lomi_remote_protocol::Effect::None,
        lomi_remote_protocol::ErrorDetails::empty(),
        None,
    )
    .expect("static operation-not-found error")
}

fn host_busy_error() -> lomi_remote_protocol::RemoteError {
    lomi_remote_protocol::RemoteError::new(
        lomi_remote_protocol::ErrorCode::HostBusy,
        true,
        lomi_remote_protocol::Effect::None,
        lomi_remote_protocol::ErrorDetails::empty(),
        None,
    )
    .expect("static busy refusal")
}
impl Drop for Connection<'_> {
    fn drop(&mut self) {
        self.socket.close();
        if let Crypto::Established(crypto) = &mut self.crypto {
            crypto.dispose();
        }
        self.crypto = Crypto::Vacant;
        self.encoder.dispose();
        self.assembler.abort();
        self.response = None;
        self.stream = None;
        // No owner/actor/Store guard survives any driver turn. Disconnect retires
        // this principal's attachments/leases and leaves the host PTY alive.
        if let Some(mut terminal) = self.terminal.take() {
            terminal.disconnect();
        }
    }
}

fn peer_refresh_deadline_for(
    refreshable: bool,
    peer_cutoff: Instant,
    now: Instant,
) -> Option<Instant> {
    if !refreshable || peer_cutoff <= now {
        return None;
    }
    (peer_cutoff.saturating_duration_since(now) <= PEER_REFRESH_MARGIN).then_some(peer_cutoff)
}

fn peer_cutoff_expired(peer_cutoff: Instant, now: Instant) -> bool {
    now >= peer_cutoff
}

fn peer_cutoff_requires_discard(
    pending_setup: bool,
    has_eligibility: bool,
    peer_cutoff: Instant,
    now: Instant,
) -> bool {
    peer_cutoff_expired(peer_cutoff, now) && (pending_setup || !has_eligibility)
}

#[cfg(test)]
mod operation_unit_retention_tests {
    use super::*;

    #[test]
    fn pending_stream_and_partial_input_keep_their_original_unit() {
        let now = Instant::now();
        let expired_deadline = now - Duration::from_millis(1);

        // PendingStream includes its delivery/cursor and original operation.
        assert!(connection_retains_worker_unit(
            [false, true, false, false, false, false, false, false, false],
            true,
            expired_deadline,
            now,
        ));
        // The inbound assembler keeps an incomplete logical message and its
        // first-fragment deadline on the same unit.
        assert!(connection_retains_worker_unit(
            [false, false, false, false, false, false, false, true, false],
            true,
            expired_deadline,
            now,
        ));
    }

    #[test]
    fn terminal_emission_yields_only_inside_existing_unit_headroom() {
        let now = Instant::now();
        let headroom =
            Duration::from_millis(lomi_remote_protocol::message_framing::ASSEMBLY_TIMEOUT_MS)
                + PEER_REFRESH_MARGIN;

        assert!(connection_retains_worker_unit(
            [false; 9],
            true,
            now + headroom + Duration::from_millis(1),
            now,
        ));
        assert!(!connection_retains_worker_unit(
            [false; 9],
            true,
            now + headroom,
            now,
        ));
        assert!(!connection_retains_worker_unit(
            [false; 9],
            true,
            now + headroom - Duration::from_millis(1),
            now,
        ));
    }

    #[test]
    fn peer_refresh_remains_bound_even_when_terminal_output_is_ready() {
        let now = Instant::now();

        assert!(connection_retains_worker_unit(
            [false, false, false, false, false, false, false, false, true],
            true,
            now + Duration::from_secs(60),
            now,
        ));
    }

    #[test]
    fn only_a_live_settled_connection_can_be_suspended() {
        assert!(may_suspend_at_message_boundary(true, true, false));
        assert!(!may_suspend_at_message_boundary(false, true, false));
        assert!(!may_suspend_at_message_boundary(true, false, false));
        assert!(!may_suspend_at_message_boundary(true, true, true));
    }
}

fn staged_message_is_live(
    now: Instant,
    peer_cutoff: Instant,
    suspended: bool,
    remaining: usize,
    aborted: bool,
    cancelled: bool,
    operation_deadline: Instant,
) -> bool {
    !suspended
        && now < peer_cutoff
        && remaining > 0
        && !aborted
        && !cancelled
        && now < operation_deadline
}

fn handoff_peer_refresh_deadline(
    handoff: &channel::AdmittedChannelHandoff,
    ticket_expires_at: Option<Instant>,
    now: Instant,
) -> Option<Instant> {
    let mut cutoff = handoff.observation().fresh_until().min(handoff.deadline());
    if let Some(ticket_expires_at) = ticket_expires_at {
        cutoff = cutoff.min(ticket_expires_at);
    }
    peer_refresh_deadline_for(true, cutoff, now)
}

#[cfg(test)]
mod peer_refresh_tests {
    use super::*;

    #[test]
    fn settlement_uses_the_retention_observation_at_the_refresh_boundary() {
        let scheduling_time = Instant::now();
        let cutoff = scheduling_time + PEER_REFRESH_MARGIN + Duration::from_millis(1);
        let maintenance_deadline = scheduling_time + Duration::from_secs(60);
        let retained_at = |now| {
            connection_retains_worker_unit(
                [peer_refresh_deadline_for(true, cutoff, now).is_some()],
                false,
                maintenance_deadline,
                now,
            )
        };

        let retained = retained_at(scheduling_time);
        assert!(!retained);
        assert!(may_suspend_at_message_boundary(
            true,
            cutoff > scheduling_time,
            retained
        ));
        let later = scheduling_time + Duration::from_millis(1);
        assert!(retained_at(later));
        assert!(!may_suspend_at_message_boundary(
            true,
            cutoff > later,
            retained_at(later)
        ));
    }

    #[test]
    fn peer_refresh_deadline_is_bounded_to_live_margin_and_skips_vacant() {
        let now = Instant::now();
        let cutoff = now + PEER_REFRESH_MARGIN;

        assert_eq!(peer_refresh_deadline_for(true, cutoff, now), Some(cutoff));
        assert_eq!(
            peer_refresh_deadline_for(true, cutoff + Duration::from_nanos(1), now),
            None
        );
        assert_eq!(peer_refresh_deadline_for(false, cutoff, now), None);
        assert_eq!(peer_refresh_deadline_for(true, now, now), None);
    }

    #[test]
    fn paused_connection_cleanup_uses_original_peer_cutoff() {
        let now = Instant::now();
        let original_cutoff = now + Duration::from_secs(1);

        assert!(!peer_cutoff_requires_discard(
            false,
            false,
            original_cutoff,
            now
        ));
        assert!(peer_cutoff_requires_discard(
            false,
            false,
            original_cutoff,
            original_cutoff
        ));
        assert!(peer_cutoff_requires_discard(
            false,
            false,
            original_cutoff,
            original_cutoff + Duration::from_nanos(1),
        ));
        assert!(peer_cutoff_requires_discard(
            true,
            true,
            original_cutoff,
            original_cutoff
        ));
        assert!(!peer_cutoff_requires_discard(
            false,
            true,
            original_cutoff,
            original_cutoff
        ));
        assert!(!peer_cutoff_requires_discard(
            false,
            false,
            now + Duration::from_secs(1),
            now
        ));
        assert_eq!(
            peer_refresh_deadline_for(true, original_cutoff, original_cutoff),
            None
        );
    }
}

#[cfg(test)]
mod staged_output_tests {
    use super::*;

    #[test]
    fn staged_remaining_follows_response_then_stream_and_excludes_git_writer() {
        assert_eq!(
            prioritized_staged_remaining(Some(3), Some(5), false),
            Some(3)
        );
        assert_eq!(
            prioritized_staged_remaining(Some(0), Some(5), false),
            Some(5)
        );
        assert_eq!(prioritized_staged_remaining(None, Some(5), false), Some(5));
        assert_eq!(prioritized_staged_remaining(Some(3), Some(5), true), None);
        assert_eq!(prioritized_staged_remaining(Some(0), Some(0), false), None);
    }

    #[test]
    fn staged_output_priority_tracks_only_live_queued_message_fragments() {
        let now = Instant::now();
        let peer_cutoff = now + Duration::from_secs(5);
        let operation_deadline = now + Duration::from_secs(10);

        assert!(staged_message_is_live(
            now,
            peer_cutoff,
            false,
            2,
            false,
            false,
            operation_deadline,
        ));
        // After the last fragment, a producer may still have another event
        // ready, but there is no queued message to hold the idle reservation.
        assert!(!staged_message_is_live(
            now,
            peer_cutoff,
            false,
            0,
            false,
            false,
            operation_deadline,
        ));
        assert!(!staged_message_is_live(
            now,
            peer_cutoff,
            false,
            2,
            true,
            false,
            operation_deadline,
        ));
        assert!(!staged_message_is_live(
            now,
            peer_cutoff,
            false,
            2,
            false,
            true,
            operation_deadline,
        ));
        assert!(!staged_message_is_live(
            peer_cutoff,
            peer_cutoff,
            false,
            2,
            false,
            false,
            operation_deadline,
        ));
        assert!(!staged_message_is_live(
            now,
            peer_cutoff,
            false,
            2,
            false,
            false,
            now,
        ));
        assert!(!staged_message_is_live(
            now,
            peer_cutoff,
            true,
            2,
            false,
            false,
            operation_deadline,
        ));
    }
}

#[cfg(test)]
mod stream_operation_transfer_tests {
    use super::*;

    #[test]
    fn normal_terminal_burst_starts_at_first_send_after_staging_delay_and_never_resets() {
        let staged_at = Instant::now();
        let first_send = staged_at + Duration::from_millis(800);
        let mut pending_first_send = true;
        let mut burst_started = None;

        // Queueing/proof work can exceed one old quantum without consuming
        // the send-time budget for a normal terminal burst.
        start_terminal_burst_at_first_send(&mut pending_first_send, &mut burst_started, first_send);
        assert!(!pending_first_send);
        assert_eq!(burst_started, Some(first_send));

        let next_frame_send = first_send + Duration::from_millis(200);
        start_terminal_burst_at_first_send(
            &mut pending_first_send,
            &mut burst_started,
            next_frame_send,
        );
        assert_eq!(burst_started, Some(first_send));

        let headroom =
            Duration::from_millis(lomi_remote_protocol::message_framing::ASSEMBLY_TIMEOUT_MS)
                .saturating_add(PEER_REFRESH_MARGIN);
        let operation_deadline = first_send + headroom + Duration::from_secs(2);
        let proof_fresh_until = first_send + PEER_REFRESH_MARGIN + Duration::from_secs(2);
        assert!(terminal_burst_can_continue(
            burst_started,
            first_send + Duration::from_millis(499),
            proof_fresh_until,
            operation_deadline,
            true,
            true,
            true,
        ));
        assert!(!terminal_burst_can_continue(
            burst_started,
            first_send + registry::STAGED_MESSAGE_BATCH_QUANTUM,
            proof_fresh_until,
            operation_deadline,
            true,
            true,
            true,
        ));

        // First-send eligibility is explicit; Started-Git streams keep their
        // existing no-burst behavior.
        let mut ineligible = false;
        let mut no_burst = None;
        start_terminal_burst_at_first_send(&mut ineligible, &mut no_burst, first_send);
        assert_eq!(no_burst, None);
    }

    #[test]
    fn terminal_burst_requires_first_send_quantum_proof_and_worker_headroom() {
        let now = Instant::now();
        let started = now - Duration::from_millis(499);
        let headroom =
            Duration::from_millis(lomi_remote_protocol::message_framing::ASSEMBLY_TIMEOUT_MS)
                .saturating_add(PEER_REFRESH_MARGIN);
        let operation_deadline = now + headroom + Duration::from_nanos(1);
        let proof_fresh_until = now + PEER_REFRESH_MARGIN + Duration::from_nanos(1);

        let can_continue =
            |origin, at, fresh_until, deadline, operation_live, proof_current, pending| {
                terminal_burst_can_continue(
                    origin,
                    at,
                    fresh_until,
                    deadline,
                    operation_live,
                    proof_current,
                    pending,
                )
            };

        assert!(can_continue(
            Some(started),
            now,
            proof_fresh_until,
            operation_deadline,
            true,
            true,
            true,
        ));
        assert!(!can_continue(
            None,
            now,
            proof_fresh_until,
            operation_deadline,
            true,
            true,
            true,
        ));
        assert!(!can_continue(
            Some(now - registry::STAGED_MESSAGE_BATCH_QUANTUM),
            now,
            proof_fresh_until,
            operation_deadline,
            true,
            true,
            true,
        ));
        assert!(!can_continue(
            Some(now + Duration::from_nanos(1)),
            now,
            proof_fresh_until,
            operation_deadline,
            true,
            true,
            true,
        ));
        assert!(!can_continue(
            Some(started),
            now,
            now + PEER_REFRESH_MARGIN,
            operation_deadline,
            true,
            true,
            true,
        ));
        assert!(!can_continue(
            Some(started),
            now,
            proof_fresh_until,
            now + headroom,
            true,
            true,
            true,
        ));
        assert!(!can_continue(
            Some(started),
            now,
            proof_fresh_until,
            operation_deadline,
            false,
            true,
            true,
        ));
        assert!(!can_continue(
            Some(started),
            now,
            proof_fresh_until,
            operation_deadline,
            true,
            false,
            true,
        ));
        assert!(!can_continue(
            Some(started),
            now,
            proof_fresh_until,
            operation_deadline,
            true,
            true,
            false,
        ));
    }

    #[test]
    fn stream_transfer_preserves_operation_and_moves_its_proof_once() {
        let cancelled = AtomicBool::new(false);
        let original_deadline = Instant::now() + Duration::from_secs(20);
        let replacement_deadline = original_deadline + Duration::from_secs(5);
        let mut maintenance = super::super::OwnerOperation::new(original_deadline, &cancelled);
        let proof_identity = maintenance.retained_identity();
        let mut maintenance_aborted = std::cell::Cell::new(true);
        let mut peer = Some(proof_identity.clone());

        let (stream_operation, stream_aborted, stream_peer) = transfer_maintenance_to_stream(
            &mut maintenance,
            &mut maintenance_aborted,
            &mut peer,
            super::super::OwnerOperation::new(replacement_deadline, &cancelled),
        );

        assert!(stream_operation.is_same_admission(&proof_identity));
        assert_eq!(stream_operation.deadline(), original_deadline);
        assert!(stream_aborted.get());
        assert!(
            stream_peer
                .as_ref()
                .is_some_and(|proof| stream_operation.is_same_admission(proof))
        );
        assert!(peer.is_none());

        let replacement_identity = maintenance.retained_identity();
        assert!(!maintenance.is_same_admission(&proof_identity));
        assert_eq!(maintenance.deadline(), replacement_deadline);
        assert!(!maintenance_aborted.get());
        assert!(maintenance.check().is_ok());

        let (_next_stream_operation, _next_stream_aborted, next_stream_peer) =
            transfer_maintenance_to_stream(
                &mut maintenance,
                &mut maintenance_aborted,
                &mut peer,
                super::super::OwnerOperation::new(replacement_deadline, &cancelled),
            );
        assert!(next_stream_peer.is_none());
        assert!(!maintenance.is_same_admission(&replacement_identity));
    }

    #[test]
    fn normal_terminal_stream_restores_exact_admission_without_rebasing() {
        let cancelled = AtomicBool::new(false);
        let original_deadline = Instant::now() + Duration::from_secs(20);
        let replacement_deadline = original_deadline + Duration::from_secs(5);
        let mut maintenance = super::super::OwnerOperation::new(original_deadline, &cancelled);
        let original_identity = maintenance.retained_identity();
        let mut maintenance_aborted = std::cell::Cell::new(false);
        let mut peer = Some(original_identity.clone());
        let (stream_operation, stream_aborted, _) = transfer_maintenance_to_stream(
            &mut maintenance,
            &mut maintenance_aborted,
            &mut peer,
            super::super::OwnerOperation::new(replacement_deadline, &cancelled),
        );
        let replacement_identity = maintenance.retained_identity();

        restore_terminal_stream_operation(
            &mut maintenance,
            &mut maintenance_aborted,
            stream_operation,
            stream_aborted,
        );

        assert!(maintenance.is_same_admission(&original_identity));
        assert_eq!(maintenance.deadline(), original_deadline);
        assert!(!maintenance.is_same_admission(&replacement_identity));
        assert!(!maintenance_aborted.get());

        let successor_unit = super::super::OwnerOperation::new(
            original_deadline + Duration::from_secs(1),
            &cancelled,
        );
        assert!(!successor_unit.is_same_admission(&original_identity));
        cancelled.store(true, Ordering::Release);
        assert!(maintenance.check().is_err());
    }

    #[test]
    fn transferred_stream_operation_keeps_expiry_and_sticky_cancellation() {
        let cancelled = AtomicBool::new(false);
        let expired_deadline = Instant::now() - Duration::from_secs(1);
        let mut maintenance = super::super::OwnerOperation::new(expired_deadline, &cancelled);
        let mut maintenance_aborted = std::cell::Cell::new(false);
        let mut peer: Option<()> = Some(());
        let (expired_stream, _, _) = transfer_maintenance_to_stream(
            &mut maintenance,
            &mut maintenance_aborted,
            &mut peer,
            super::super::OwnerOperation::new(Instant::now() + Duration::from_secs(20), &cancelled),
        );
        assert!(expired_stream.check().is_err());

        let cancelled = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut maintenance = super::super::OwnerOperation::new(deadline, &cancelled);
        let mut maintenance_aborted = std::cell::Cell::new(false);
        let mut peer: Option<()> = Some(());
        let (cancelled_stream, _, _) = transfer_maintenance_to_stream(
            &mut maintenance,
            &mut maintenance_aborted,
            &mut peer,
            super::super::OwnerOperation::new(deadline, &cancelled),
        );
        cancelled.store(true, Ordering::Release);
        assert!(cancelled_stream.check().is_err());
        cancelled.store(false, Ordering::Release);
        assert!(cancelled_stream.check().is_err());
    }
}

#[cfg(test)]
mod terminal_renew_fast_path_tests {
    use super::*;
    use lomi_remote_protocol::{
        ApplicationMajor, TimeoutMs,
        message_framing::{MessageEncoder, MessageKind},
        rpc::{RequestKind, RpcResponse, RpcResult, TerminalLeaseParams},
        streams::TerminalStreamFrame,
    };

    #[test]
    fn renewal_moves_the_same_admission_and_sticky_abort_while_only_shortening_deadline() {
        let cancelled = AtomicBool::new(false);
        let now = Instant::now();
        let original_deadline = now + Duration::from_secs(10);
        let mut maintenance = super::super::OwnerOperation::new(original_deadline, &cancelled);
        let original_identity = maintenance.retained_identity();
        let mut maintenance_aborted = std::cell::Cell::new(true);
        let mut peer = Some(original_identity.clone());
        let (mut request, aborted, request_peer) = transfer_maintenance_to_stream(
            &mut maintenance,
            &mut maintenance_aborted,
            &mut peer,
            super::super::OwnerOperation::new(now + Duration::from_secs(30), &cancelled),
        );

        request.cap_deadline(now + Duration::from_secs(3));
        assert!(request.is_same_admission(&original_identity));
        assert_eq!(request.deadline(), now + Duration::from_secs(3));
        assert!(aborted.get());
        assert!(
            request_peer
                .as_ref()
                .is_some_and(|proof| request.is_same_admission(proof))
        );
        assert!(peer.is_none());

        request.cap_deadline(now + Duration::from_secs(20));
        assert_eq!(request.deadline(), now + Duration::from_secs(3));
        cancelled.store(true, Ordering::Release);
        assert!(request.check().is_err());
    }

    #[test]
    fn cached_renewal_proof_skips_prefetch_margin_only_when_all_real_bounds_cover() {
        let now = Instant::now();
        let deadline = now + Duration::from_millis(1_500);
        let covered_until = now + Duration::from_millis(2_000);

        assert!(terminal_renew_cached_proof_covers(
            now,
            deadline,
            covered_until,
            covered_until,
        ));
        assert!(!terminal_renew_cached_proof_covers(
            now,
            deadline,
            deadline - Duration::from_nanos(1),
            covered_until,
        ));
        assert!(!terminal_renew_cached_proof_covers(
            now,
            deadline,
            covered_until,
            deadline - Duration::from_nanos(1),
        ));
        assert!(!terminal_renew_cached_proof_covers(
            deadline,
            deadline,
            covered_until,
            covered_until,
        ));
    }

    fn encrypted_request(
        encoder: &mut MessageEncoder,
        channel: &mut lomi_remote_crypto::Channel,
        context: &lomi_remote_crypto::ChannelContextV3,
        request: &RpcRequest,
    ) -> Vec<u8> {
        encoder
            .begin(
                MessageKind::RpcRequest,
                serde_json::to_vec(request).unwrap(),
            )
            .unwrap();
        let frame = encoder.next_frame().unwrap().unwrap();
        channel.seal_binary(context.channel_id, &frame).unwrap()
    }

    fn decode_encrypted_response(
        channel: &mut lomi_remote_crypto::Channel,
        context: &lomi_remote_crypto::ChannelContextV3,
        frame: &[u8],
        assembler: &mut MessageAssembler,
        origin: Instant,
    ) -> RpcResponse {
        let plain = channel.open_binary(context.channel_id, frame).unwrap();
        let elapsed_ms = u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        let message = assembler.push(&plain, elapsed_ms).unwrap().unwrap();
        assert_eq!(message.kind, MessageKind::RpcResponse);
        lomi_remote_protocol::rpc::decode_response(&message.bytes).unwrap()
    }

    fn established_terminal_connection<'a>(
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: Runtime<'a>,
        eligibility: &PeerEligibility,
        fixture: &super::super::channel::tests::TerminalFixture,
        seed_test_lease: bool,
    ) -> (
        Connection<'a>,
        lomi_remote_crypto::Channel,
        lomi_remote_protocol::TerminalContext,
        Option<lomi_remote_protocol::rpc::TerminalLeaseResult>,
        Option<lomi_terminal::Attachment>,
    ) {
        let cancelled = runtime.operation.cancellation_latch();
        let maintenance =
            super::super::OwnerOperation::new(runtime.operation.deadline(), cancelled);
        let maintenance_aborted = std::cell::Cell::new(false);
        let admission_runtime = RuntimeWithOperation {
            operation: &maintenance,
            aborted: &maintenance_aborted,
            ..runtime
        };
        let (established, consumer) = super::super::channel::tests::establish_terminal_connection(
            auth,
            admission_runtime,
            eligibility,
            fixture,
        );
        let mut remote_terminal = RemoteTerminalState::new(
            std::sync::Arc::downgrade(&fixture.coordinator),
            &established,
        )
        .unwrap();
        let mut terminal = fixture.terminal.clone();
        terminal.workspace = fixture.workspace.clone();
        let (initial, attachment_guard) = if seed_test_lease {
            let principal = remote_terminal.principal_for_test();
            let attachment = fixture
                .coordinator
                .terminals
                .attach(terminal.session_id, terminal.session_epoch, principal)
                .unwrap();
            attachment
                .acknowledge(principal, attachment.snapshot.sequence.0)
                .unwrap();
            let lease = fixture
                .coordinator
                .terminals
                .claim(terminal.session_id, terminal.session_epoch, principal)
                .unwrap();
            let initial = remote_terminal
                .seed_test_lease(&established, terminal.clone(), lease)
                .unwrap();
            // Attachment drop removes the test subscription and revokes its
            // associated lease; keep it alive through the renewal callback.
            (Some(initial), Some(attachment))
        } else {
            (None, None)
        };

        let connection = Connection {
            coordinator: std::sync::Arc::downgrade(&fixture.coordinator),
            terminal: Some(remote_terminal),
            watch: None,
            watch_generation: 0,
            workspace_stream: None,
            workspace_stream_call: None,
            next_stream_class: 0,
            stream: None,
            watch_call: None,
            started_git_outputs: VecDeque::new(),
            git_output_reservation: 0,
            socket: IngressSocket::memory([]),
            maintenance,
            suspended: false,
            maintenance_aborted,
            peer: None,
            source: fixture.source.clone(),
            workspace: fixture.workspace.clone(),
            crypto: Crypto::Established(established),
            assembler: MessageAssembler::new(),
            encoder: MessageEncoder::new(),
            origin: Instant::now(),
            peer_cutoff: eligibility.heartbeat.request_started
                + Duration::from_millis(eligibility.heartbeat.freshness_ms),
            applied_observation: Instant::now(),
            started_git_peer: None,
            response: None,
            git_read: None,
            git_mutation: None,
        };
        (connection, consumer, terminal, initial, attachment_guard)
    }

    fn with_established_terminal_renew<'a>(
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: Runtime<'a>,
        eligibility: &PeerEligibility,
        fixture: &super::super::channel::tests::TerminalFixture,
        test: impl FnOnce(
            &mut Connection<'a>,
            &mut lomi_remote_crypto::Channel,
            &lomi_remote_protocol::TerminalContext,
            &lomi_remote_protocol::rpc::TerminalLeaseResult,
        ),
    ) {
        let (mut connection, mut consumer, terminal, initial, _attachment_guard) =
            established_terminal_connection(auth, runtime, eligibility, fixture, true);
        let initial = initial.expect("renew test setup seeds a current control lease");
        let request = RpcRequest {
            v: ApplicationMajor::try_from(2).unwrap(),
            r#type: RequestKind::Request,
            request_id: "renew-fast-path".to_owned().try_into().unwrap(),
            timeout_ms: TimeoutMs::new(1200).unwrap(),
            call: RpcCall::TerminalRenew(TerminalLeaseParams {
                terminal: terminal.clone(),
                lease: initial.lease.clone(),
            }),
        };
        let mut request_encoder = MessageEncoder::new();
        let encrypted = encrypted_request(
            &mut request_encoder,
            &mut consumer,
            &fixture.context,
            &request,
        );
        let IngressSocket::Memory(socket) = &mut connection.socket else {
            unreachable!("renew tests use their in-memory relay boundary");
        };
        socket.incoming.push_back(encrypted);
        test(&mut connection, &mut consumer, &terminal, &initial);
    }

    fn with_established_terminal_subscription<'a>(
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: Runtime<'a>,
        eligibility: &PeerEligibility,
        fixture: &super::super::channel::tests::TerminalFixture,
        test: impl FnOnce(
            &mut Connection<'a>,
            &mut lomi_remote_crypto::Channel,
            &lomi_remote_protocol::TerminalContext,
            &lomi_remote_protocol::streams::TerminalSnapshotMetadata,
            &mut MessageEncoder,
            &mut MessageAssembler,
        ),
    ) {
        let (mut connection, mut consumer, terminal, _, _attachment_guard) =
            established_terminal_connection(auth, runtime, eligibility, fixture, false);
        let attach_request = RpcRequest {
            v: ApplicationMajor::try_from(2).unwrap(),
            r#type: RequestKind::Request,
            request_id: "terminal-control-setup".to_owned().try_into().unwrap(),
            timeout_ms: TimeoutMs::new(10_000).unwrap(),
            call: RpcCall::TerminalAttach(TerminalReadParams {
                terminal: terminal.clone(),
            }),
        };
        let mut request_encoder = MessageEncoder::new();
        let encrypted = encrypted_request(
            &mut request_encoder,
            &mut consumer,
            &fixture.context,
            &attach_request,
        );
        let IngressSocket::Memory(socket) = &mut connection.socket else {
            unreachable!("terminal control tests use their in-memory relay boundary");
        };
        socket.incoming.push_back(encrypted);

        let mut metadata = None;
        let mut snapshot_complete = false;
        let mut sent_index = 0;
        let mut assembler = MessageAssembler::new();
        super::super::peer::with_test_pairing_get(fixture.source.response.clone(), |_get_count| {
            // One turn sends one physical fragment. The 540 KiB terminal
            // fixture needs 34 snapshot chunks with four fragments each,
            // plus the attach response; 64 turns stopped near chunk 15.
            for _ in 0..256 {
                let outcome = connection.turn(
                    auth,
                    runtime,
                    eligibility,
                    Some(runtime.operation.cancellation_latch()),
                );
                assert!(outcome.is_ok(), "terminal attach setup failed: {outcome:?}");
                let IngressSocket::Memory(socket) = &connection.socket else {
                    unreachable!("terminal control tests use their in-memory relay boundary");
                };
                while sent_index < socket.sent.len() {
                    let ciphertext = &socket.sent[sent_index];
                    sent_index += 1;
                    let plaintext = consumer
                        .open_binary(fixture.context.channel_id, ciphertext)
                        .unwrap();
                    let elapsed_ms =
                        u64::try_from(connection.origin.elapsed().as_millis()).unwrap_or(u64::MAX);
                    let Some(message) = assembler.push(&plaintext, elapsed_ms).unwrap() else {
                        continue;
                    };
                    match message.kind {
                        MessageKind::RpcResponse => {
                            let response =
                                lomi_remote_protocol::rpc::decode_response(&message.bytes).unwrap();
                            let RpcResponse::Result {
                                request_id,
                                result: RpcResult::TerminalAttach(result),
                                ..
                            } = response
                            else {
                                panic!("terminal.attach response expected: {response:?}");
                            };
                            assert_eq!(String::from(request_id), "terminal-control-setup");
                            assert!(metadata.replace(result).is_none());
                        }
                        MessageKind::TerminalFrame => {
                            let frame: TerminalStreamFrame =
                                serde_json::from_slice(&message.bytes).unwrap();
                            if let TerminalStreamFrame::SnapshotComplete(complete) = frame {
                                let metadata = metadata
                                    .as_ref()
                                    .expect("attach metadata precedes snapshot completion");
                                assert_eq!(complete.terminal, metadata.terminal);
                                assert_eq!(complete.subscription_id, metadata.subscription_id);
                                assert_eq!(complete.through_seq, metadata.through_seq);
                                snapshot_complete = true;
                            }
                        }
                        kind => panic!("unexpected setup message kind: {kind:?}"),
                    }
                }
                if snapshot_complete {
                    break;
                }
            }
        });
        let metadata = metadata.expect("encrypted terminal.attach metadata was sent");
        assert!(
            snapshot_complete,
            "initial terminal snapshot did not commit"
        );
        assert!(connection.response.is_none());
        assert!(connection.stream.is_none());
        test(
            &mut connection,
            &mut consumer,
            &terminal,
            &metadata,
            &mut request_encoder,
            &mut assembler,
        );
    }

    #[derive(Clone, Copy, Debug)]
    enum TerminalControlKind {
        Ack,
        Claim,
    }

    impl TerminalControlKind {
        fn request_id(self) -> &'static str {
            match self {
                Self::Ack => "terminal-ack-fast-path",
                Self::Claim => "terminal-claim-fast-path",
            }
        }

        fn request(
            self,
            terminal: &lomi_remote_protocol::TerminalContext,
            metadata: &lomi_remote_protocol::streams::TerminalSnapshotMetadata,
        ) -> RpcRequest {
            let call = match self {
                Self::Ack => RpcCall::TerminalAck(TerminalAckParams {
                    terminal: terminal.clone(),
                    subscription_id: metadata.subscription_id.clone(),
                    through_seq: metadata.through_seq,
                }),
                Self::Claim => RpcCall::TerminalClaim(TerminalClaimParams {
                    terminal: terminal.clone(),
                    subscription_id: metadata.subscription_id.clone(),
                    rendered_through_seq: metadata.through_seq,
                }),
            };
            RpcRequest {
                v: ApplicationMajor::try_from(2).unwrap(),
                r#type: RequestKind::Request,
                request_id: self.request_id().to_owned().try_into().unwrap(),
                timeout_ms: TimeoutMs::new(5000).unwrap(),
                call,
            }
        }
    }

    fn queue_request(
        connection: &mut Connection<'_>,
        consumer: &mut lomi_remote_crypto::Channel,
        encoder: &mut MessageEncoder,
        channel_context: &lomi_remote_crypto::ChannelContextV3,
        request: &RpcRequest,
    ) {
        let encrypted = encrypted_request(encoder, consumer, channel_context, request);
        let IngressSocket::Memory(socket) = &mut connection.socket else {
            unreachable!("terminal control tests use their in-memory relay boundary");
        };
        socket.incoming.push_back(encrypted);
    }

    fn terminal_request_response_one_turn<'a>(
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: Runtime<'a>,
        eligibility: &PeerEligibility,
        fixture: &super::super::channel::tests::TerminalFixture,
        connection: &mut Connection<'a>,
        consumer: &mut lomi_remote_crypto::Channel,
        request_encoder: &mut MessageEncoder,
        response_assembler: &mut MessageAssembler,
        request: &RpcRequest,
    ) -> RpcResponse {
        connection.peer = None;
        queue_request(
            connection,
            consumer,
            request_encoder,
            &fixture.context,
            request,
        );
        let sent_before = connection.socket.sent().len();
        super::super::peer::with_test_pairing_get(fixture.source.response.clone(), |get_count| {
            let outcome = connection.turn(
                auth,
                runtime,
                eligibility,
                Some(runtime.operation.cancellation_latch()),
            );
            assert!(
                matches!(&outcome, Ok(true)),
                "terminal request did not finish in its current turn: {outcome:?}"
            );
            assert_eq!(
                get_count.get(),
                2,
                "maintenance and fresh request pairing reads are required"
            );
            assert_eq!(connection.socket.sent().len(), sent_before + 1);
            assert!(connection.response.is_none());
        });
        let IngressSocket::Memory(socket) = &connection.socket else {
            unreachable!("terminal control tests use their in-memory relay boundary");
        };
        decode_encrypted_response(
            consumer,
            &fixture.context,
            &socket.sent[sent_before],
            response_assembler,
            connection.origin,
        )
    }

    fn claim_terminal_control_lease<'a>(
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: Runtime<'a>,
        eligibility: &PeerEligibility,
        fixture: &super::super::channel::tests::TerminalFixture,
        connection: &mut Connection<'a>,
        consumer: &mut lomi_remote_crypto::Channel,
        terminal: &lomi_remote_protocol::TerminalContext,
        metadata: &lomi_remote_protocol::streams::TerminalSnapshotMetadata,
        request_encoder: &mut MessageEncoder,
        response_assembler: &mut MessageAssembler,
    ) -> lomi_remote_protocol::rpc::TerminalLeaseResult {
        let request = TerminalControlKind::Claim.request(terminal, metadata);
        let response = terminal_request_response_one_turn(
            auth,
            runtime,
            eligibility,
            fixture,
            connection,
            consumer,
            request_encoder,
            response_assembler,
            &request,
        );
        let RpcResponse::Result {
            request_id,
            result: RpcResult::TerminalClaim(lease),
            ..
        } = response
        else {
            panic!("real terminal.claim result expected: {response:?}");
        };
        assert_eq!(
            String::from(request_id),
            TerminalControlKind::Claim.request_id()
        );
        assert_eq!(lease.terminal, *terminal);
        lease
    }

    #[derive(Clone, Copy, Debug)]
    enum TerminalDataKind {
        Input,
        Resize,
    }

    impl TerminalDataKind {
        fn request_id(self) -> &'static str {
            match self {
                Self::Input => "terminal-input-fast-path",
                Self::Resize => "terminal-resize-fast-path",
            }
        }

        fn request(
            self,
            terminal: &lomi_remote_protocol::TerminalContext,
            lease: &lomi_remote_protocol::rpc::TerminalLeaseResult,
        ) -> RpcRequest {
            let call = match self {
                Self::Input => RpcCall::TerminalInput(TerminalInputParams {
                    terminal: terminal.clone(),
                    lease: lease.lease.clone(),
                    input_id: lease.next_input_id,
                    input_seq: lease.next_input_seq,
                    // A printable byte only; this never submits Enter or a command.
                    bytes: BoundedList(vec![b'x']),
                }),
                Self::Resize => RpcCall::TerminalResize(TerminalResizeParams {
                    terminal: terminal.clone(),
                    lease: lease.lease.clone(),
                    resize_seq: lease.next_resize_seq,
                    columns: TerminalDimension(82),
                    rows: TerminalDimension(25),
                }),
            };
            RpcRequest {
                v: ApplicationMajor::try_from(2).unwrap(),
                r#type: RequestKind::Request,
                request_id: self.request_id().to_owned().try_into().unwrap(),
                timeout_ms: TimeoutMs::new(5000).unwrap(),
                call,
            }
        }
    }

    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore = "requires Linux native PTY backend")]
    fn established_encrypted_renew_reuses_current_proof_and_sends_in_same_turn() {
        super::super::channel::tests::with_terminal_fixture(
            |auth, _config, runtime, eligibility, _owner, api| {
                let fixture = api.terminal.as_ref().unwrap();
                with_established_terminal_renew(
                    auth,
                    runtime,
                    eligibility,
                    fixture,
                    |connection, consumer, terminal, initial| {
                        super::super::peer::with_test_pairing_get(
                            fixture.source.response.clone(),
                            |get_count| {
                                let started = Instant::now();
                                let outcome = connection.turn(
                                    auth,
                                    runtime,
                                    eligibility,
                                    Some(runtime.operation.cancellation_latch()),
                                );
                                assert!(
                                    matches!(&outcome, Ok(true)),
                                    "Connection::turn must admit the real terminal renewal"
                                );
                                assert_eq!(
                                    get_count.get(),
                                    1,
                                    "one current GET, no renew duplicate"
                                );
                                assert_eq!(connection.socket.sent().len(), 1);
                                assert!(started.elapsed() < Duration::from_millis(1500));
                                let sent = connection.socket.sent();
                                let mut response_assembler = MessageAssembler::new();
                                let response = decode_encrypted_response(
                                    consumer,
                                    &fixture.context,
                                    &sent[0],
                                    &mut response_assembler,
                                    connection.origin,
                                );
                                let RpcResponse::Result {
                                    request_id,
                                    result: RpcResult::TerminalRenew(renewed),
                                    ..
                                } = response
                                else {
                                    panic!("successful terminal.renew response expected");
                                };
                                assert_eq!(String::from(request_id), "renew-fast-path");
                                assert_eq!(renewed.terminal, *terminal);
                                assert_eq!(renewed.lease.token, initial.lease.token);
                                assert_eq!(renewed.lease.version.0, initial.lease.version.0);
                                assert_eq!(renewed.next_input_id.0, initial.next_input_id.0);
                                assert_eq!(renewed.next_input_seq.0.0, initial.next_input_seq.0.0);
                                assert_eq!(
                                    renewed.next_resize_seq.0.0,
                                    initial.next_resize_seq.0.0
                                );
                                assert_eq!(renewed.expires_in_ms.get(), 5000);
                            },
                        );
                    },
                );
            },
        );
    }

    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore = "requires Linux native PTY backend")]
    fn established_encrypted_ack_and_claim_flush_after_committed_snapshot() {
        super::super::channel::tests::with_terminal_fixture(
            |auth, _config, runtime, eligibility, _owner, api| {
                let fixture = api.terminal.as_ref().unwrap();
                for kind in [TerminalControlKind::Ack, TerminalControlKind::Claim] {
                    with_established_terminal_subscription(
                        auth,
                        runtime,
                        eligibility,
                        fixture,
                        |connection,
                         consumer,
                         terminal,
                         metadata,
                         request_encoder,
                         response_assembler| {
                            // These operations must take a fresh request admission and
                            // pairing read; they cannot borrow the maintenance proof.
                            connection.peer = None;
                            let request = kind.request(terminal, metadata);
                            queue_request(
                                connection,
                                consumer,
                                request_encoder,
                                &fixture.context,
                                &request,
                            );
                            let sent_before = connection.socket.sent().len();
                            super::super::peer::with_test_pairing_get(
                                fixture.source.response.clone(),
                                |get_count| {
                                    let outcome = connection.turn(
                                        auth,
                                        runtime,
                                        eligibility,
                                        Some(runtime.operation.cancellation_latch()),
                                    );
                                    assert!(
                                        matches!(&outcome, Ok(true)),
                                        "terminal control request did not finish: {outcome:?}"
                                    );
                                    assert_eq!(
                                        get_count.get(),
                                        2,
                                        "maintenance and fresh request pairing reads are required"
                                    );
                                    assert_eq!(connection.socket.sent().len(), sent_before + 1);
                                    assert!(connection.response.is_none());
                                    let response = decode_encrypted_response(
                                        consumer,
                                        &fixture.context,
                                        &connection.socket.sent()[sent_before],
                                        response_assembler,
                                        connection.origin,
                                    );
                                    let RpcResponse::Result {
                                        request_id, result, ..
                                    } = response
                                    else {
                                        panic!("terminal control success expected: {response:?}");
                                    };
                                    assert_eq!(String::from(request_id), kind.request_id());
                                    match (kind, result) {
                                        (TerminalControlKind::Ack, RpcResult::TerminalAck(ack)) => {
                                            assert_eq!(
                                                ack.subscription_id,
                                                metadata.subscription_id
                                            );
                                            assert_eq!(ack.through_seq, metadata.through_seq);
                                        }
                                        (
                                            TerminalControlKind::Claim,
                                            RpcResult::TerminalClaim(lease),
                                        ) => {
                                            assert_eq!(lease.terminal, *terminal);
                                            assert_eq!(lease.expires_in_ms.get(), 5000);
                                        }
                                        (_, unexpected) => {
                                            panic!(
                                                "unexpected terminal control result: {unexpected:?}"
                                            )
                                        }
                                    }
                                },
                            );
                        },
                    );
                }
            },
        );
    }

    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore = "requires Linux native PTY backend")]
    fn ack_and_claim_send_watch_cancellation_and_ambiguous_write_are_not_replayed() {
        super::super::channel::tests::with_terminal_fixture(
            |auth, _config, runtime, eligibility, _owner, api| {
                let fixture = api.terminal.as_ref().unwrap();
                for kind in [TerminalControlKind::Ack, TerminalControlKind::Claim] {
                    for fail_after_write in [false, true] {
                        with_established_terminal_subscription(
                            auth,
                            runtime,
                            eligibility,
                            fixture,
                            |connection,
                             consumer,
                             terminal,
                             metadata,
                             request_encoder,
                             _response_assembler| {
                                connection.peer = None;
                                let request = kind.request(terminal, metadata);
                                queue_request(
                                    connection,
                                    consumer,
                                    request_encoder,
                                    &fixture.context,
                                    &request,
                                );
                                let sent_before = connection.socket.sent().len();
                                match &mut connection.socket {
                                    IngressSocket::Memory(socket) if fail_after_write => {
                                        socket.fail_after_write = true;
                                    }
                                    IngressSocket::Memory(socket) => {
                                        socket.cancel_before_send = Some(api.cancelled.clone());
                                    }
                                    IngressSocket::Relay(_) => unreachable!(
                                        "terminal control tests use the in-memory relay boundary"
                                    ),
                                }
                                super::super::peer::with_test_pairing_get(
                                    fixture.source.response.clone(),
                                    |get_count| {
                                        let outcome = connection.turn(
                                            auth,
                                            runtime,
                                            eligibility,
                                            Some(runtime.operation.cancellation_latch()),
                                        );
                                        assert!(
                                            outcome.is_err(),
                                            "physical send fault unexpectedly succeeded: {outcome:?}"
                                        );
                                        assert_eq!(get_count.get(), 2);
                                        let IngressSocket::Memory(socket) = &connection.socket
                                        else {
                                            unreachable!("terminal control tests use memory socket")
                                        };
                                        assert!(socket.closed);
                                        let expected_writes =
                                            sent_before + if fail_after_write { 1 } else { 0 };
                                        assert_eq!(socket.sent.len(), expected_writes);
                                        assert!(connection.response.is_none());

                                        if !fail_after_write {
                                            api.cancelled.store(false, Ordering::Release);
                                        }

                                        // A subsequent turn cannot replay either a
                                        // suppressed result or an ambiguous write.
                                        assert!(
                                            connection
                                                .turn(
                                                    auth,
                                                    runtime,
                                                    eligibility,
                                                    Some(runtime.operation.cancellation_latch()),
                                                )
                                                .is_err()
                                        );
                                        let IngressSocket::Memory(socket) = &connection.socket
                                        else {
                                            unreachable!("terminal control tests use memory socket")
                                        };
                                        assert_eq!(socket.sent.len(), expected_writes);
                                        assert!(connection.response.is_none());
                                    },
                                );
                            },
                        );
                    }
                }
            },
        );
    }

    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore = "requires Linux native PTY backend")]
    fn stale_ack_and_mismatched_claim_authority_are_refused_in_same_turn() {
        super::super::channel::tests::with_terminal_fixture(
            |auth, _config, runtime, eligibility, _owner, api| {
                let fixture = api.terminal.as_ref().unwrap();
                for kind in [TerminalControlKind::Ack, TerminalControlKind::Claim] {
                    with_established_terminal_subscription(
                        auth,
                        runtime,
                        eligibility,
                        fixture,
                        |connection,
                         consumer,
                         terminal,
                         metadata,
                         request_encoder,
                         response_assembler| {
                            connection.peer = None;
                            let mut request = kind.request(terminal, metadata);
                            match &mut request.call {
                                RpcCall::TerminalAck(params) => {
                                    params.through_seq = lomi_remote_protocol::streams::TerminalSeq(
                                        DecimalU64(metadata.through_seq.0.0.saturating_add(1)),
                                    );
                                }
                                RpcCall::TerminalClaim(params) => {
                                    params.subscription_id =
                                        "other-subscription".to_owned().try_into().unwrap();
                                }
                                _ => unreachable!("helper builds only ACK or Claim"),
                            }
                            queue_request(
                                connection,
                                consumer,
                                request_encoder,
                                &fixture.context,
                                &request,
                            );
                            let sent_before = connection.socket.sent().len();
                            super::super::peer::with_test_pairing_get(
                                fixture.source.response.clone(),
                                |get_count| {
                                    let outcome = connection.turn(
                                        auth,
                                        runtime,
                                        eligibility,
                                        Some(runtime.operation.cancellation_latch()),
                                    );
                                    assert!(matches!(&outcome, Ok(true)));
                                    assert_eq!(get_count.get(), 2);
                                    assert_eq!(connection.socket.sent().len(), sent_before + 1);
                                    assert!(connection.response.is_none());
                                    let response = decode_encrypted_response(
                                        consumer,
                                        &fixture.context,
                                        &connection.socket.sent()[sent_before],
                                        response_assembler,
                                        connection.origin,
                                    );
                                    let RpcResponse::Error {
                                        request_id, error, ..
                                    } = response
                                    else {
                                        panic!("stale authority must be refused: {response:?}");
                                    };
                                    assert_eq!(String::from(request_id), kind.request_id());
                                    assert_eq!(
                                        error.code(),
                                        lomi_remote_protocol::ErrorCode::ResyncRequired
                                    );
                                },
                            );
                        },
                    );
                }
            },
        );
    }

    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore = "requires Linux native PTY backend")]
    fn established_encrypted_input_and_resize_flush_after_real_claim() {
        super::super::channel::tests::with_terminal_fixture(
            |auth, _config, runtime, eligibility, _owner, api| {
                let fixture = api.terminal.as_ref().unwrap();
                with_established_terminal_subscription(
                    auth,
                    runtime,
                    eligibility,
                    fixture,
                    |connection,
                     consumer,
                     terminal,
                     metadata,
                     request_encoder,
                     response_assembler| {
                        let lease = claim_terminal_control_lease(
                            auth,
                            runtime,
                            eligibility,
                            fixture,
                            connection,
                            consumer,
                            terminal,
                            metadata,
                            request_encoder,
                            response_assembler,
                        );
                        assert_eq!(lease.expires_in_ms.get(), 5000);
                        assert!(connection.stream.is_none());

                        let input_request = TerminalDataKind::Input.request(terminal, &lease);
                        let input_response = terminal_request_response_one_turn(
                            auth,
                            runtime,
                            eligibility,
                            fixture,
                            connection,
                            consumer,
                            request_encoder,
                            response_assembler,
                            &input_request,
                        );
                        let RpcResponse::Result {
                            request_id,
                            result: RpcResult::TerminalInput(receipt),
                            ..
                        } = input_response
                        else {
                            panic!("terminal.input receipt expected: {input_response:?}");
                        };
                        assert_eq!(
                            String::from(request_id),
                            TerminalDataKind::Input.request_id()
                        );
                        let submitted = lomi_remote_protocol::InputBytes::new(1).unwrap();
                        receipt
                            .validate_binding(
                                terminal.session_id,
                                terminal.session_epoch,
                                lease.next_input_id,
                                lease.next_input_seq.0,
                                submitted,
                            )
                            .unwrap();
                        assert_eq!(receipt.accepted_bytes(), submitted);
                        assert!(connection.response.is_none());
                        assert!(connection.stream.is_none());

                        // The same claimed lease binding remains valid for the
                        // following resize on this already attached connection.
                        let resize_request = TerminalDataKind::Resize.request(terminal, &lease);
                        let resize_response = terminal_request_response_one_turn(
                            auth,
                            runtime,
                            eligibility,
                            fixture,
                            connection,
                            consumer,
                            request_encoder,
                            response_assembler,
                            &resize_request,
                        );
                        let RpcResponse::Result {
                            request_id,
                            result: RpcResult::TerminalResize(resize),
                            ..
                        } = resize_response
                        else {
                            panic!("terminal.resize receipt expected: {resize_response:?}");
                        };
                        assert_eq!(
                            String::from(request_id),
                            TerminalDataKind::Resize.request_id()
                        );
                        assert_eq!(resize.terminal, *terminal);
                        assert_eq!(resize.resize_seq, lease.next_resize_seq);
                        assert_eq!(resize.columns, TerminalDimension(82));
                        assert_eq!(resize.rows, TerminalDimension(25));
                        assert!(connection.response.is_none());
                        assert!(connection.stream.is_none());
                    },
                );
            },
        );
    }

    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore = "requires Linux native PTY backend")]
    fn stale_terminal_input_and_resize_sequences_are_refused_in_one_turn() {
        super::super::channel::tests::with_terminal_fixture(
            |auth, _config, runtime, eligibility, _owner, api| {
                let fixture = api.terminal.as_ref().unwrap();
                with_established_terminal_subscription(
                    auth,
                    runtime,
                    eligibility,
                    fixture,
                    |connection,
                     consumer,
                     terminal,
                     metadata,
                     request_encoder,
                     response_assembler| {
                        let lease = claim_terminal_control_lease(
                            auth,
                            runtime,
                            eligibility,
                            fixture,
                            connection,
                            consumer,
                            terminal,
                            metadata,
                            request_encoder,
                            response_assembler,
                        );
                        let input_request = RpcRequest {
                            v: ApplicationMajor::try_from(2).unwrap(),
                            r#type: RequestKind::Request,
                            request_id: "terminal-input-stale-sequence"
                                .to_owned()
                                .try_into()
                                .unwrap(),
                            timeout_ms: TimeoutMs::new(5000).unwrap(),
                            call: RpcCall::TerminalInput(TerminalInputParams {
                                terminal: terminal.clone(),
                                lease: lease.lease.clone(),
                                input_id: lease.next_input_id,
                                input_seq: lomi_remote_protocol::streams::InputSeq(DecimalU64(
                                    lease.next_input_seq.0.0.saturating_add(1),
                                )),
                                bytes: BoundedList(vec![b'x']),
                            }),
                        };
                        let input_response = terminal_request_response_one_turn(
                            auth,
                            runtime,
                            eligibility,
                            fixture,
                            connection,
                            consumer,
                            request_encoder,
                            response_assembler,
                            &input_request,
                        );
                        let RpcResponse::Error { error, .. } = input_response else {
                            panic!("stale terminal.input must be rejected: {input_response:?}");
                        };
                        assert_eq!(
                            error.code(),
                            lomi_remote_protocol::ErrorCode::IdempotencyConflict
                        );

                        let resize_request = RpcRequest {
                            v: ApplicationMajor::try_from(2).unwrap(),
                            r#type: RequestKind::Request,
                            request_id: "terminal-resize-stale-sequence"
                                .to_owned()
                                .try_into()
                                .unwrap(),
                            timeout_ms: TimeoutMs::new(5000).unwrap(),
                            call: RpcCall::TerminalResize(TerminalResizeParams {
                                terminal: terminal.clone(),
                                lease: lease.lease.clone(),
                                resize_seq: lomi_remote_protocol::streams::ResizeSeq(DecimalU64(
                                    lease.next_resize_seq.0.0.saturating_add(1),
                                )),
                                columns: TerminalDimension(82),
                                rows: TerminalDimension(25),
                            }),
                        };
                        let resize_response = terminal_request_response_one_turn(
                            auth,
                            runtime,
                            eligibility,
                            fixture,
                            connection,
                            consumer,
                            request_encoder,
                            response_assembler,
                            &resize_request,
                        );
                        let RpcResponse::Error { error, .. } = resize_response else {
                            panic!("stale terminal.resize must be rejected: {resize_response:?}");
                        };
                        assert_eq!(
                            error.code(),
                            lomi_remote_protocol::ErrorCode::IdempotencyConflict
                        );
                        assert!(connection.response.is_none());
                        assert!(connection.stream.is_none());
                    },
                );
            },
        );
    }

    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore = "requires Linux native PTY backend")]
    fn input_and_resize_send_failures_are_never_replayed() {
        super::super::channel::tests::with_terminal_fixture(
            |auth, _config, runtime, eligibility, _owner, api| {
                let fixture = api.terminal.as_ref().unwrap();
                for kind in [TerminalDataKind::Input, TerminalDataKind::Resize] {
                    for fail_after_write in [false, true] {
                        with_established_terminal_subscription(
                            auth,
                            runtime,
                            eligibility,
                            fixture,
                            |connection,
                             consumer,
                             terminal,
                             metadata,
                             request_encoder,
                             response_assembler| {
                                let lease = claim_terminal_control_lease(
                                    auth,
                                    runtime,
                                    eligibility,
                                    fixture,
                                    connection,
                                    consumer,
                                    terminal,
                                    metadata,
                                    request_encoder,
                                    response_assembler,
                                );
                                let request = kind.request(terminal, &lease);
                                connection.peer = None;
                                queue_request(
                                    connection,
                                    consumer,
                                    request_encoder,
                                    &fixture.context,
                                    &request,
                                );
                                let sent_before = connection.socket.sent().len();
                                match &mut connection.socket {
                                    IngressSocket::Memory(socket) if fail_after_write => {
                                        socket.fail_after_write = true;
                                    }
                                    IngressSocket::Memory(socket) => {
                                        socket.cancel_before_send = Some(api.cancelled.clone());
                                    }
                                    IngressSocket::Relay(_) => unreachable!(
                                        "terminal control tests use their in-memory relay boundary"
                                    ),
                                }
                                super::super::peer::with_test_pairing_get(
                                    fixture.source.response.clone(),
                                    |get_count| {
                                        let outcome = connection.turn(
                                            auth,
                                            runtime,
                                            eligibility,
                                            Some(runtime.operation.cancellation_latch()),
                                        );
                                        assert!(outcome.is_err());
                                        assert_eq!(get_count.get(), 2);
                                        let IngressSocket::Memory(socket) = &connection.socket
                                        else {
                                            unreachable!("terminal data tests use memory socket")
                                        };
                                        assert!(socket.closed);
                                        let expected_writes =
                                            sent_before + if fail_after_write { 1 } else { 0 };
                                        assert_eq!(socket.sent.len(), expected_writes);
                                        assert!(connection.response.is_none());

                                        if !fail_after_write {
                                            api.cancelled.store(false, Ordering::Release);
                                        }

                                        // A cancelled pre-send or ambiguous post-write
                                        // outcome cannot be replayed on this channel.
                                        assert!(
                                            connection
                                                .turn(
                                                    auth,
                                                    runtime,
                                                    eligibility,
                                                    Some(runtime.operation.cancellation_latch()),
                                                )
                                                .is_err()
                                        );
                                        let IngressSocket::Memory(socket) = &connection.socket
                                        else {
                                            unreachable!("terminal data tests use memory socket")
                                        };
                                        assert_eq!(socket.sent.len(), expected_writes);
                                        assert!(connection.response.is_none());
                                    },
                                );
                            },
                        );
                    }
                }
            },
        );
    }

    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore = "requires Linux native PTY backend")]
    fn cancellation_at_physical_send_watch_suppresses_renew_response() {
        super::super::channel::tests::with_terminal_fixture(
            |auth, _config, runtime, eligibility, _owner, api| {
                let fixture = api.terminal.as_ref().unwrap();
                with_established_terminal_renew(
                    auth,
                    runtime,
                    eligibility,
                    fixture,
                    |connection, _consumer, _terminal, _initial| {
                        match &mut connection.socket {
                            IngressSocket::Memory(socket) => {
                                socket.cancel_before_send = Some(api.cancelled.clone());
                            }
                            IngressSocket::Relay(_) => {
                                unreachable!("renew tests use their in-memory relay boundary");
                            }
                        }
                        super::super::peer::with_test_pairing_get(
                            fixture.source.response.clone(),
                            |get_count| {
                                let outcome = connection.turn(
                                    auth,
                                    runtime,
                                    eligibility,
                                    Some(runtime.operation.cancellation_latch()),
                                );
                                assert!(outcome.is_err(), "unexpected turn outcome: {outcome:?}");
                                assert_eq!(get_count.get(), 1);
                                let IngressSocket::Memory(socket) = &connection.socket else {
                                    unreachable!("renew tests use their in-memory relay boundary");
                                };
                                assert!(socket.closed, "send watch not reached: {outcome:?}");
                                assert!(socket.sent.is_empty());
                                assert!(connection.response.is_none());
                            },
                        );
                    },
                );
            },
        );
    }

    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore = "requires Linux native PTY backend")]
    fn failed_physical_renew_send_closes_connection_without_replay() {
        super::super::channel::tests::with_terminal_fixture(
            |auth, _config, runtime, eligibility, _owner, api| {
                let fixture = api.terminal.as_ref().unwrap();
                with_established_terminal_renew(
                    auth,
                    runtime,
                    eligibility,
                    fixture,
                    |connection, _consumer, _terminal, _initial| {
                        match &mut connection.socket {
                            IngressSocket::Memory(socket) => socket.fail_after_write = true,
                            IngressSocket::Relay(_) => {
                                unreachable!("renew tests use their in-memory relay boundary");
                            }
                        }
                        super::super::peer::with_test_pairing_get(
                            fixture.source.response.clone(),
                            |get_count| {
                                let outcome = connection.turn(
                                    auth,
                                    runtime,
                                    eligibility,
                                    Some(runtime.operation.cancellation_latch()),
                                );
                                assert!(outcome.is_err(), "unexpected turn outcome: {outcome:?}");
                                assert_eq!(get_count.get(), 1);
                                let IngressSocket::Memory(socket) = &connection.socket else {
                                    unreachable!("renew tests use their in-memory relay boundary");
                                };
                                assert!(socket.closed, "send not reached: {outcome:?}");
                                assert_eq!(socket.sent.len(), 1);
                                assert!(connection.response.is_none());

                                // The physical outcome was ambiguous after one frame
                                // write; a closed connection cannot replay that result.
                                assert!(
                                    connection
                                        .turn(
                                            auth,
                                            runtime,
                                            eligibility,
                                            Some(runtime.operation.cancellation_latch()),
                                        )
                                        .is_err()
                                );
                                let IngressSocket::Memory(socket) = &connection.socket else {
                                    unreachable!("renew tests use their in-memory relay boundary");
                                };
                                assert_eq!(socket.sent.len(), 1);
                                assert!(connection.response.is_none());
                            },
                        );
                    },
                );
            },
        );
    }
}

#[cfg(test)]
mod ticket_bounds_tests {
    use super::*;

    fn channel_id(byte: u8) -> ChannelId {
        ChannelId::from_bytes([byte; 16]).expect("valid channel id")
    }

    fn ticket(value: String) -> RelayTicket {
        RelayTicket::try_from(value).expect("valid relay ticket encoding")
    }

    #[test]
    fn ticket_cache_bounds_keep_original_ticket_and_handoff_expiry() {
        let now = Instant::now();
        let request_started = now - Duration::from_millis(100);
        let ticket_deadline = request_started + Duration::from_millis(5000);
        let handoff_deadline = ticket_deadline + Duration::from_secs(1);
        let id = channel_id(1);
        let relay_ticket = ticket("A".repeat(43));

        assert!(ticket_bounds_current_at(
            now,
            request_started,
            5000,
            ticket_deadline,
            handoff_deadline,
            id,
            id,
            &relay_ticket,
        ));
        assert!(!ticket_bounds_current_at(
            ticket_deadline,
            request_started,
            5000,
            ticket_deadline,
            handoff_deadline,
            id,
            id,
            &relay_ticket,
        ));
        assert!(!ticket_bounds_current_at(
            now,
            request_started,
            5000,
            ticket_deadline - Duration::from_millis(1),
            handoff_deadline,
            id,
            id,
            &relay_ticket,
        ));
        assert!(!ticket_bounds_current_at(
            now,
            request_started,
            5000,
            ticket_deadline,
            handoff_deadline,
            id,
            channel_id(2),
            &relay_ticket,
        ));
        assert!(!ticket_bounds_current_at(
            now,
            request_started,
            5000,
            ticket_deadline,
            handoff_deadline,
            id,
            id,
            &ticket("A".repeat(42)),
        ));
        assert!(!ticket_bounds_current_at(
            now,
            request_started,
            5001,
            ticket_deadline,
            handoff_deadline,
            id,
            id,
            &relay_ticket,
        ));

        let short_handoff_deadline = now + Duration::from_millis(250);
        assert!(ticket_bounds_current_at(
            now,
            request_started,
            5000,
            short_handoff_deadline,
            short_handoff_deadline,
            id,
            id,
            &relay_ticket,
        ));
        assert!(!ticket_bounds_current_at(
            short_handoff_deadline,
            request_started,
            5000,
            short_handoff_deadline,
            short_handoff_deadline,
            id,
            id,
            &relay_ticket,
        ));
    }
}
