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
use lomi_host_http::{BudgetStop, RelayConnection, RelayTransport};
#[cfg(any(not(test), all(test, feature = "cloud-fixture")))]
use lomi_host_http::{DataTransport, RemoteApiOrigin};
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

#[path = "remote_ingress_registry.rs"]
mod registry;
pub(super) use registry::Registry;

/// Keep the actor's ordinary idle wait unless a successful ingress stage left
/// output that can be sent without waiting for another peer frame.
pub(super) const fn actor_wait_duration(immediate_output: bool) -> Duration {
    if immediate_output {
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

// Test-only originating failure metadata. Never format an error or payload.
#[cfg(test)]
pub(super) type IngressOrigin = (&'static str, Option<&'static str>, &'static str, u32, u32);
#[cfg(test)]
pub(super) type IngressFailure = (
    &'static str,
    &'static str,
    Option<IngressOrigin>,
    u64,
    &'static str,
    bool,
    bool,
);
#[cfg(test)]
pub(super) type IngressFailureSnapshot = (Option<IngressFailure>, u64, u64);
#[cfg(all(test, feature = "cloud-fixture"))]
const INGRESS_DIAGNOSTIC_PREFIX: &[u8] = b"LOMI_INGRESS_DIAGNOSTIC=";
#[cfg(all(test, feature = "cloud-fixture"))]
const INGRESS_DIAGNOSTIC_MAX_BYTES: usize = 2048;
#[cfg(all(test, feature = "cloud-fixture"))]
const INGRESS_DIAGNOSTIC_MAX_EVENTS: usize = 64;
#[cfg(all(test, feature = "cloud-fixture"))]
static INGRESS_DIAGNOSTIC_EVENTS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
std::thread_local! {
    static INGRESS_ORIGIN: std::cell::Cell<Option<IngressOrigin>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
pub(in super::super) fn record_origin_for_test(
    error_type: &'static str,
    variant: Option<&'static str>,
    file: &'static str,
    line: u32,
    column: u32,
) {
    INGRESS_ORIGIN.with(|origin| {
        if origin.get().is_none() {
            origin.set(Some((error_type, variant, file, line, column)));
        }
    });
}
#[cfg(all(test, feature = "cloud-fixture"))]
fn diagnostic_phase_for_fixture(phase: &'static str) -> &'static str {
    match phase {
        "connect" => "CONNECT",
        "ticket-request" => "TICKET_REQUEST",
        "discard" => "DISCARD",
        "connection-turn/vacant" => "CONNECTION_TURN_VACANT",
        "connection-turn/read-first" => "CONNECTION_TURN_READ_FIRST",
        "connection-turn/write-second" => "CONNECTION_TURN_WRITE_SECOND",
        "connection-turn/read-third" => "CONNECTION_TURN_READ_THIRD",
        "connection-turn/established" => "CONNECTION_TURN_ESTABLISHED",
        _ => "OTHER",
    }
}
#[cfg(all(test, feature = "cloud-fixture"))]
fn diagnostic_error_for_fixture(error: &'static str) -> &'static str {
    match error {
        "None" => "NONE",
        "Invalid" => "INVALID",
        "Fatal::Auth" => "FATAL_AUTH",
        "Fatal::Http" => "FATAL_HTTP",
        "Fatal::Rejected" => "FATAL_REJECTED",
        "Fatal::Stale" => "FATAL_STALE",
        _ => "OTHER",
    }
}
#[cfg(all(test, feature = "cloud-fixture"))]
fn diagnostic_origin_for_fixture(file: &'static str) -> &'static str {
    if file.ends_with("/remote_ingress.rs") || file == "remote_ingress.rs" {
        "REMOTE_INGRESS"
    } else if file.ends_with("/remote_connection.rs") || file == "remote_connection.rs" {
        "REMOTE_CONNECTION"
    } else if file.contains("/remote_terminal") || file == "remote_terminal.rs" {
        "REMOTE_TERMINAL"
    } else if file.ends_with("/remote_files_watch.rs") || file == "remote_files_watch.rs" {
        "REMOTE_FILES_WATCH"
    } else if file.ends_with("/shared_owner.rs") || file == "shared_owner.rs" {
        "SHARED_OWNER"
    } else if file.ends_with("/owner_domain.rs") || file == "owner_domain.rs" {
        "OWNER_DOMAIN"
    } else {
        "OTHER"
    }
}
#[cfg(all(test, feature = "cloud-fixture"))]
fn diagnostic_call_for_fixture(call: &'static str) -> &'static str {
    match call {
        "none" => "NONE",
        "workspace.get" => "WORKSPACE_GET",
        "workspace.capabilities" => "WORKSPACE_CAPABILITIES",
        "terminal.rename" => "TERMINAL_RENAME",
        "terminal.move" => "TERMINAL_MOVE",
        "terminal.create" => "TERMINAL_CREATE",
        "terminal.split" => "TERMINAL_SPLIT",
        "terminal.close" => "TERMINAL_CLOSE",
        "terminal.restart" => "TERMINAL_RESTART",
        "terminal.attach" => "TERMINAL_ATTACH",
        "terminal.snapshot" => "TERMINAL_SNAPSHOT",
        "terminal.ack" => "TERMINAL_ACK",
        "terminal.claim" => "TERMINAL_CLAIM",
        "terminal.renew" => "TERMINAL_RENEW",
        "terminal.release" => "TERMINAL_RELEASE",
        "terminal.input" => "TERMINAL_INPUT",
        "terminal.resize" => "TERMINAL_RESIZE",
        _ => "OTHER",
    }
}
#[cfg(all(test, feature = "cloud-fixture"))]
fn emit_ingress_diagnostic_for_fixture(failure: IngressFailure, elapsed_ms: u64) {
    use std::io::Write as _;
    use std::sync::atomic::Ordering as AtomicOrdering;

    if INGRESS_DIAGNOSTIC_EVENTS
        .fetch_update(AtomicOrdering::Relaxed, AtomicOrdering::Relaxed, |events| {
            (events < INGRESS_DIAGNOSTIC_MAX_EVENTS).then_some(events + 1)
        })
        .is_err()
    {
        return;
    }
    let (phase, error, origin, request_count, call, pending_response, pending_stream) = failure;
    let (origin_category, line, column) = match origin {
        Some((_, _, file, line, column)) => (
            diagnostic_origin_for_fixture(file),
            line.min(100_000),
            column.min(100_000),
        ),
        None => ("OTHER", 0, 0),
    };
    let record = serde_json::json!({
        "formatVersion": 1,
        "phase": diagnostic_phase_for_fixture(phase),
        "error": diagnostic_error_for_fixture(error),
        "origin": origin_category,
        "line": line,
        "column": column,
        "requestCount": request_count.min(1_000_000),
        "call": diagnostic_call_for_fixture(call),
        "elapsedMs": elapsed_ms.min(600_000),
        "pendingResponse": pending_response,
        "pendingStream": pending_stream,
    });
    let Ok(payload) = serde_json::to_vec(&record) else {
        return;
    };
    if INGRESS_DIAGNOSTIC_PREFIX.len() + payload.len() + 1 > INGRESS_DIAGNOSTIC_MAX_BYTES {
        return;
    }
    let mut line = Vec::with_capacity(INGRESS_DIAGNOSTIC_PREFIX.len() + payload.len() + 1);
    line.extend_from_slice(INGRESS_DIAGNOSTIC_PREFIX);
    line.extend_from_slice(&payload);
    line.push(b'\n');
    let _ = std::io::stderr().lock().write_all(&line);
}
// Non-test expansions are the exact preexisting mapper function items.
#[cfg(not(test))]
macro_rules! invalid_at {
    () => {
        invalid
    };
}
#[cfg(test)]
macro_rules! invalid_at {
    () => {
        |error| {
            record_origin_for_test(
                std::any::type_name_of_val(&error),
                None,
                file!(),
                line!(),
                column!(),
            );
            invalid(error)
        }
    };
}
#[cfg(not(test))]
macro_rules! owner_error_at {
    () => {
        peer::owner_error
    };
}
#[cfg(test)]
macro_rules! owner_error_at {
    () => {
        |error| {
            let variant = match &error {
                super::super::shared_owner::Error::Store(_) => "Store",
                super::super::shared_owner::Error::UncertainStore(_) => "UncertainStore",
                super::super::shared_owner::Error::Domain(_) => "Domain",
            };
            record_origin_for_test(
                std::any::type_name_of_val(&error),
                Some(variant),
                file!(),
                line!(),
                column!(),
            );
            peer::owner_error(error)
        }
    };
}
// Non-test boundary macros expand to the exact original expression.
#[cfg(not(test))]
macro_rules! peer_boundary_at {
    ($label:literal, $result:expr) => {
        $result
    };
}
#[cfg(test)]
macro_rules! peer_boundary_at {
    ($label:literal, $result:expr) => {
        $result.inspect_err(|error| {
            record_origin_for_test(
                $label,
                Some(peer_error_variant_for_test(error)),
                file!(),
                line!(),
                column!(),
            );
        })
    };
}
#[cfg(not(test))]
macro_rules! invalid_none_at {
    ($label:literal, $option:expr) => {
        $option.ok_or(peer::PeerError::Invalid)
    };
}
#[cfg(test)]
macro_rules! invalid_none_at {
    ($label:literal, $option:expr) => {
        $option.ok_or_else(|| {
            record_origin_for_test($label, Some("None"), file!(), line!(), column!());
            peer::PeerError::Invalid
        })
    };
}
#[cfg(test)]
fn peer_error_variant_for_test(error: &peer::PeerError) -> &'static str {
    match error {
        peer::PeerError::Invalid => "Invalid",
        peer::PeerError::Fatal(super::StepError::Auth(_)) => "Fatal::Auth",
        peer::PeerError::Fatal(super::StepError::Http(_)) => "Fatal::Http",
        peer::PeerError::Fatal(super::StepError::ExpiredEnrollment) => "Fatal::Auth",
        peer::PeerError::Fatal(super::StepError::ExpiredRotation) => "Fatal::Auth",
        peer::PeerError::Fatal(super::StepError::Rejected) => "Fatal::Rejected",
        peer::PeerError::Fatal(super::StepError::Stale) => "Fatal::Stale",
    }
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
impl TicketedAdmission {
    fn current(
        &self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'_, '_>,
        eligibility: &PeerEligibility,
    ) -> bool {
        let now = Instant::now();
        let bounded = (1..=5000).contains(&self.expires_in_ms)
            && self.request_started <= now
            && now < self.expires_at
            && self
                .request_started
                .checked_add(Duration::from_millis(self.expires_in_ms))
                .is_some_and(|expiry| self.expires_at == expiry.min(self.handoff.deadline()))
            && self.channel_id == self.handoff.channel_id()
            && ticket_grammar(&self.ticket);
        if !bounded {
            return false;
        }
        // Cache polling rechecks the named current ACK/source/local join. No
        // owner/Store/provider borrow or effect continuation crosses iterations.
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
#[cfg(test)]
pub(super) type TicketTestHook =
    Box<dyn FnOnce(ChannelId, &ChannelTicketParams, &super::OwnerOperation<'_>, &WatchCheck<'_>)>;
#[cfg(test)]
struct TicketScript {
    response: Result<ChannelTicketResult, lomi_host_http::Error>,
    hook: Option<TicketTestHook>,
    calls: std::rc::Rc<std::cell::Cell<usize>>,
    // Attenuation-only future receipt fault: never changes original budgets.
    minimum_elapsed: Duration,
}
#[cfg(all(test, feature = "cloud-fixture"))]
#[derive(Clone)]
struct CloudFixtureTransportRoots {
    remote_api: Vec<u8>,
    relay: Vec<u8>,
}
#[cfg(all(test, feature = "cloud-fixture"))]
const CLOUD_FIXTURE_ROOT_DER_MAX_BYTES: usize = 16 * 1024;
#[derive(Default)]
pub(super) struct Driver<'cancel> {
    coordinator: Weak<Coordinator>,
    cancelled: Option<&'cancel AtomicBool>,
    defer_network: bool,
    connection: Option<Connection<'cancel>>,
    candidate: Option<channel::AdmittedChannelHandoff>,
    ticketed: Option<TicketedAdmission>,
    #[cfg(test)]
    script: Option<TicketScript>,
    #[cfg(test)]
    relay_script: Option<RelayTransport>,
    #[cfg(all(test, feature = "cloud-fixture"))]
    cloud_fixture_transport_roots: Option<CloudFixtureTransportRoots>,
    #[cfg(all(test, feature = "cloud-fixture"))]
    cloud_fixture_ticket_error: Option<lomi_host_http::Error>,
    // Static diagnostic only; retained across discard so failure remains visible.
    #[cfg(test)]
    channel_step_observation: (&'static str, Option<&'static str>),
    #[cfg(test)]
    failure_observation: Option<IngressFailure>,
    #[cfg(test)]
    diagnostic_connects: u64,
    #[cfg(test)]
    diagnostic_turns: u64,
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
    #[cfg(test)]
    sent_fragments: usize,
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
    remaining: usize,
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
    socket: RelayConnection,
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
    #[cfg(test)]
    diagnostic_requests: u64,
    #[cfg(test)]
    diagnostic_call: &'static str,
    response: Option<PendingResponse<'cancel>>,
    git_read: Option<PendingGitRead<'cancel>>,
    git_mutation: Option<PendingGitMutation<'cancel>>,
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

    #[cfg(test)]
    pub(super) fn new(cancelled: &'cancel AtomicBool) -> Self {
        Self::with_coordinator(cancelled, Weak::new())
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
        self.candidate.is_some()
            || self.ticketed.is_some()
            || self
                .connection
                .as_ref()
                .is_some_and(Connection::has_retained_operation)
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
    #[cfg(test)]
    pub(super) fn pending_git_cancellation_for_test(&self) -> Option<lomi_git::CancellationToken> {
        self.connection
            .as_ref()?
            .git_read
            .as_ref()
            .map(|read| read.read.cancellation_for_test())
    }
    #[cfg(test)]
    pub(super) fn sent_git_diff_fragments_for_test(&self) -> usize {
        self.connection
            .as_ref()
            .and_then(|c| c.response.as_ref())
            .filter(|response| matches!(&response.request.call, RpcCall::GitDiff(_)))
            .map_or(0, |response| response.sent_fragments)
    }
    pub(super) fn peer_refresh_deadline(&self, now: Instant) -> Option<Instant> {
        self.connection
            .as_ref()
            .and_then(|connection| connection.peer_refresh_deadline(now))
    }
    pub(super) fn has_immediate_output(&self) -> bool {
        self.connection
            .as_ref()
            .is_some_and(|connection| connection.has_immediate_output())
    }
    /// Empty means no candidate, ticket, or live transport. A live transport
    /// can outlast its maintenance operation and must remain in the registry.
    pub(super) fn is_empty(&self) -> bool {
        self.candidate.is_none() && self.ticketed.is_none() && self.connection.is_none()
    }
    pub(super) fn discard(&mut self) {
        #[cfg(all(test, feature = "cloud-fixture"))]
        if let Some(connection) = self.connection.as_ref() {
            emit_ingress_diagnostic_for_fixture(
                (
                    "discard",
                    "None",
                    None,
                    connection.diagnostic_requests,
                    connection.diagnostic_call,
                    connection.response.is_some(),
                    connection.stream.is_some(),
                ),
                connection
                    .origin
                    .elapsed()
                    .as_millis()
                    .min(u64::MAX as u128) as u64,
            );
        }
        self.candidate = None;
        self.ticketed = None;
        self.connection = None;
        #[cfg(test)]
        {
            self.script = None;
            self.relay_script = None;
        }
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
    #[cfg(test)]
    pub(super) fn channel_step_observation_for_test(&self) -> (&'static str, Option<&'static str>) {
        self.channel_step_observation
    }
    #[cfg(all(test, feature = "cloud-fixture"))]
    pub(super) fn cloud_fixture_ticket_error_for_test(&self) -> Option<lomi_host_http::Error> {
        self.cloud_fixture_ticket_error
    }
    #[cfg(test)]
    pub(super) fn after_channel_step(
        &mut self,
        worker: &mut channel::Worker,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
        eligibility: &PeerEligibility,
    ) -> bool {
        self.after_channel_handoff(worker.take_admitted(), auth, runtime, eligibility)
    }
    #[cfg(test)]
    pub(super) fn after_channel_handoff(
        &mut self,
        handoff: Option<channel::AdmittedChannelHandoff>,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        runtime: RuntimeWithOperation<'cancel, '_>,
        eligibility: &PeerEligibility,
    ) -> bool {
        #[cfg(test)]
        {
            self.channel_step_observation = ("take-admitted", None);
        }
        if let Some(handoff) = handoff {
            #[cfg(test)]
            {
                self.channel_step_observation.0 = "accept-handoff";
            }
            let _accepted = self.accept(handoff, auth, runtime, eligibility);
            #[cfg(test)]
            if !_accepted {
                self.channel_step_observation.1 = Some("not-accepted");
            }
        }
        let _current = self.poll(auth, runtime, Some(eligibility));
        #[cfg(test)]
        if !_current && self.channel_step_observation.1.is_none() {
            self.channel_step_observation = ("poll-handoff", Some("not-current"));
        }
        // At most one network stage in this scheduler pass. Resource-local
        // failures (including 401) never become host credential rejection.
        self.request_ticket_stage(auth, runtime, eligibility)
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
        #[cfg(test)]
        INGRESS_ORIGIN.with(|origin| origin.set(None));
        #[cfg(all(test, feature = "cloud-fixture"))]
        let request_started = Instant::now();
        if let Err(_error) = self.request_ticket(auth, runtime, eligibility) {
            #[cfg(test)]
            {
                self.channel_step_observation.1 = Some(peer_error_variant_for_test(&_error));
            }
            #[cfg(all(test, feature = "cloud-fixture"))]
            emit_ingress_diagnostic_for_fixture(
                (
                    "ticket-request",
                    peer_error_variant_for_test(&_error),
                    INGRESS_ORIGIN.with(|origin| origin.get()),
                    1,
                    "none",
                    false,
                    false,
                ),
                request_started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            );
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
                (None, Some(ticketed)) => ticketed.current(auth, runtime, eligibility),
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
            #[cfg(test)]
            {
                INGRESS_ORIGIN.with(|origin| origin.set(None));
                self.diagnostic_turns += 1;
            }
            match self.connection_turn(auth, runtime, eligibility) {
                Ok(advanced) => return advanced,
                Err(_) => {
                    self.discard();
                    return false;
                }
            }
        }
        if self.ticketed.is_some() {
            #[cfg(test)]
            {
                INGRESS_ORIGIN.with(|origin| origin.set(None));
                self.diagnostic_connects += 1;
            }
            #[cfg(all(test, feature = "cloud-fixture"))]
            let connect_started = self
                .ticketed
                .as_ref()
                .map(|ticketed| ticketed.request_started)
                .unwrap_or_else(Instant::now);
            let result = eligibility
                .ok_or(peer::PeerError::Invalid)
                .and_then(|e| self.connect(auth, runtime, e));
            #[cfg(test)]
            if let Err(error) = &result {
                self.failure_observation = Some((
                    "connect",
                    peer_error_variant_for_test(error),
                    INGRESS_ORIGIN.with(|origin| origin.get()),
                    0,
                    "none",
                    false,
                    false,
                ));
                #[cfg(all(test, feature = "cloud-fixture"))]
                emit_ingress_diagnostic_for_fixture(
                    (
                        "connect",
                        peer_error_variant_for_test(error),
                        INGRESS_ORIGIN.with(|origin| origin.get()),
                        0,
                        "none",
                        false,
                        false,
                    ),
                    connect_started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                );
            }
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
        #[cfg(test)]
        {
            self.channel_step_observation.0 = "take-candidate";
        }
        let handoff = self.candidate.take().ok_or(peer::PeerError::Invalid)?;
        #[cfg(test)]
        {
            self.channel_step_observation.0 = "check-initial-handoff";
        }
        handoff.check_current(auth, runtime, eligibility)?;
        #[cfg(not(test))]
        let transport = DataTransport::new(
            RemoteApiOrigin::new(
                auth.trusted_configuration(),
                eligibility.binding.scope.remote_api_origin.clone(),
            )
            .map_err(|_| peer::PeerError::Invalid)?,
        )
        .map_err(|_| peer::PeerError::Invalid)?;
        #[cfg(test)]
        {
            self.channel_step_observation.0 = "provider-before-ticket";
        }
        let provider = peer::ProviderCapture::read(auth, runtime, eligibility)?;
        #[cfg(test)]
        {
            self.channel_step_observation.0 = "capture-ticket-effect";
        }
        let mut effect = peer::owner_turn(runtime, || {
            runtime.owner.capture_channel_ticket(
                runtime.operation,
                eligibility,
                &handoff,
                runtime.base,
                runtime.anchor,
            )
        })?;
        #[cfg(test)]
        {
            self.channel_step_observation.0 = "validate-ticket-effect";
        }
        peer::owner_turn(runtime, || effect.try_validate(&provider))?;
        let now = runtime
            .base
            .saturating_add(runtime.anchor.elapsed().as_secs());
        #[cfg(test)]
        {
            self.channel_step_observation.0 = "access-credential";
        }
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
        #[cfg(test)]
        {
            self.channel_step_observation.0 = "check-before-ticket";
        }
        handoff.check_current(auth, runtime, eligibility)?;
        #[cfg(test)]
        {
            self.channel_step_observation.0 = "boundary-before-ticket";
        }
        effect
            .check_boundary(&provider)
            .map_err(owner_error_at!())?;
        #[cfg(not(test))]
        let budget = transport.with_budget(handoff.deadline(), watch);
        #[cfg(test)]
        {
            self.channel_step_observation.0 = "ticket-http-response";
        }
        let request_started = Instant::now();
        #[cfg(not(test))]
        let response = budget.channel_ticket(handoff.channel_id(), &params, &access);
        #[cfg(test)]
        let (response, minimum_elapsed) = self.channel_ticket_for_test(
            auth,
            eligibility,
            &handoff,
            &params,
            operation,
            watch,
            &access,
        );
        let response = response.map_err(|_| peer::PeerError::Invalid)?;
        #[cfg(test)]
        {
            self.channel_step_observation.0 = "provider-after-ticket";
        }
        let provider = peer::ProviderCapture::read(auth, runtime, eligibility)?;
        #[cfg(test)]
        {
            self.channel_step_observation.0 = "validate-after-ticket";
        }
        peer::owner_turn(runtime, || effect.try_validate(&provider))?;
        #[cfg(test)]
        {
            self.channel_step_observation.0 = "boundary-after-ticket";
        }
        effect
            .check_boundary(&provider)
            .map_err(owner_error_at!())?;
        #[cfg(test)]
        {
            self.channel_step_observation.0 = "check-after-ticket";
        }
        handoff.check_current(auth, runtime, eligibility)?;
        #[cfg(test)]
        {
            self.channel_step_observation.0 = "validate-ticket-receipt";
        }
        let received_at = Instant::now();
        #[cfg(test)]
        let received_at = received_at.max(
            request_started
                .checked_add(minimum_elapsed)
                .ok_or(peer::PeerError::Invalid)?,
        );
        let expires_in_ms = response.expires_in_ms.0;
        let expires_at = request_started
            .checked_add(Duration::from_millis(expires_in_ms))
            .ok_or(peer::PeerError::Invalid)?
            .min(handoff.deadline());
        if response.channel_id != handoff.channel_id()
            || !(1..=5000).contains(&expires_in_ms)
            || !ticket_grammar(&response.ticket)
            || received_at >= expires_at
        {
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
        #[cfg(test)]
        {
            self.channel_step_observation = ("ticket-retained", None);
        }
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
            let turn = runtime
                .owner
                .try_remote_workspace_turn(&evidence, &current, &workspace)
                .map_err(owner_error_at!())?;
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
        #[cfg(not(test))]
        let relay = RelayTransport::new(endpoint).map_err(|_| peer::PeerError::Invalid)?;
        #[cfg(test)]
        let relay = {
            #[cfg(feature = "cloud-fixture")]
            if let Some(roots) = self.cloud_fixture_transport_roots.as_ref() {
                RelayTransport::with_test_root(endpoint, roots.relay.clone())
                    .map_err(|_| peer::PeerError::Invalid)?
            } else {
                let _ = endpoint;
                // Default test mode stays closed and scripted. No ambient roots
                // or real account relay are selected when a script is absent.
                self.relay_script.take().ok_or(peer::PeerError::Invalid)?
            }
            #[cfg(not(feature = "cloud-fixture"))]
            {
                let _ = endpoint;
                self.relay_script.take().ok_or(peer::PeerError::Invalid)?
            }
        };
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
            socket,
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
            #[cfg(test)]
            diagnostic_requests: 0,
            #[cfg(test)]
            diagnostic_call: "none",
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
        #[cfg(test)]
        let phase = match &c.crypto {
            Crypto::Vacant => "connection-turn/vacant",
            Crypto::ReadFirst(_) => "connection-turn/read-first",
            Crypto::WriteSecond(_) => "connection-turn/write-second",
            Crypto::ReadThird(_) => "connection-turn/read-third",
            Crypto::Established(_) => "connection-turn/established",
        };
        #[cfg(test)]
        let pending_at_turn_entry = (c.response.is_some(), c.stream.is_some());
        let result = c.turn(auth, runtime, eligibility, self.cancelled);
        #[cfg(test)]
        if let Err(error) = &result {
            self.failure_observation = Some((
                phase,
                peer_error_variant_for_test(error),
                INGRESS_ORIGIN.with(|origin| origin.get()),
                c.diagnostic_requests,
                c.diagnostic_call,
                pending_at_turn_entry.0,
                pending_at_turn_entry.1,
            ));
            #[cfg(all(test, feature = "cloud-fixture"))]
            emit_ingress_diagnostic_for_fixture(
                (
                    phase,
                    peer_error_variant_for_test(error),
                    INGRESS_ORIGIN.with(|origin| origin.get()),
                    c.diagnostic_requests,
                    c.diagnostic_call,
                    pending_at_turn_entry.0,
                    pending_at_turn_entry.1,
                ),
                c.origin.elapsed().as_millis().min(u64::MAX as u128) as u64,
            );
        }
        if result.is_ok() {
            self.connection = Some(c);
        }
        result
    }
    #[cfg(test)]
    pub(super) fn failure_observation_for_test(&self) -> IngressFailureSnapshot {
        (
            self.failure_observation,
            self.diagnostic_connects,
            self.diagnostic_turns,
        )
    }
    #[cfg(test)]
    pub(super) fn diagnostic_request_for_test(&self) -> (u64, &'static str) {
        self.connection
            .as_ref()
            .map(|connection| (connection.diagnostic_requests, connection.diagnostic_call))
            .unwrap_or((0, "none"))
    }
    #[cfg(test)]
    pub(super) fn diagnostic_response_pending_for_test(&self) -> bool {
        self.connection
            .as_ref()
            .is_some_and(|connection| connection.response.is_some())
    }
    #[cfg(test)]
    pub(super) fn diagnostic_stream_pending_for_test(&self) -> bool {
        self.connection
            .as_ref()
            .is_some_and(|connection| connection.stream.is_some())
    }
    #[cfg(test)]
    pub(super) fn script_relay_for_test(&mut self, relay: RelayTransport) {
        #[cfg(feature = "cloud-fixture")]
        assert!(self.cloud_fixture_transport_roots.is_none());
        assert!(self.relay_script.is_none());
        self.relay_script = Some(relay);
    }
    /// Opt in to the actual HTTP ticket and configured WSS endpoint only for
    /// private Cloud integration fixtures. Ordinary unit tests remain scripted.
    #[cfg(all(test, feature = "cloud-fixture"))]
    pub(super) fn use_cloud_fixture_transport_for_test(
        &mut self,
        remote_api_root_der: Vec<u8>,
        relay_root_der: Vec<u8>,
    ) -> Result<(), &'static str> {
        if self.cloud_fixture_transport_roots.is_some()
            || self.script.is_some()
            || self.relay_script.is_some()
            || self.candidate.is_some()
            || self.ticketed.is_some()
            || self.connection.is_some()
        {
            return Err("cloud fixture transport must be selected before ingress work");
        }
        if remote_api_root_der.is_empty()
            || remote_api_root_der.len() > CLOUD_FIXTURE_ROOT_DER_MAX_BYTES
            || relay_root_der.is_empty()
            || relay_root_der.len() > CLOUD_FIXTURE_ROOT_DER_MAX_BYTES
        {
            return Err("cloud fixture TLS root is outside its byte bound");
        }
        self.cloud_fixture_transport_roots = Some(CloudFixtureTransportRoots {
            remote_api: remote_api_root_der,
            relay: relay_root_der,
        });
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn connected_for_test(&self) -> bool {
        self.connection.is_some()
    }
    #[cfg(test)]
    pub(super) fn settle_maintenance_for_test(&mut self) {
        self.connection
            .as_ref()
            .expect("live fixture connection")
            .maintenance
            .expire_for_test();
    }
    #[cfg(test)]
    pub(super) fn set_peer_cutoff_for_test(&mut self, cutoff: Instant) {
        let connection = self.connection.as_mut().expect("live fixture connection");
        assert!(cutoff < connection.peer_cutoff, "test only shortens cutoff");
        connection.peer_cutoff = cutoff;
        connection.peer = None;
        if let Some(response) = connection.response.as_mut() {
            response.peer = None;
        }
        if let Some(stream) = connection.stream.as_mut() {
            stream.peer = None;
        }
    }
    #[cfg(test)]
    fn scripted_ticket(
        &mut self,
        handoff: &channel::AdmittedChannelHandoff,
        params: &ChannelTicketParams,
        operation: &super::OwnerOperation<'_>,
        watch: &WatchCheck<'_>,
        _access: &lomi_remote_protocol::HostAccessCredential,
    ) -> (Result<ChannelTicketResult, lomi_host_http::Error>, Duration) {
        // Closed test seam: no fallback to account/network IO when unscripted.
        let Some(script) = self.script.take() else {
            return (Err(lomi_host_http::Error::Network), Duration::ZERO);
        };
        script.calls.set(script.calls.get() + 1);
        if watch().is_err() {
            return (
                Err(lomi_host_http::Error::Cancelled),
                script.minimum_elapsed,
            );
        }
        if let Some(hook) = script.hook {
            hook(handoff.channel_id(), params, operation, watch);
        }
        if watch().is_err() {
            return (
                Err(lomi_host_http::Error::Cancelled),
                script.minimum_elapsed,
            );
        }
        (script.response, script.minimum_elapsed)
    }
    #[cfg(test)]
    fn channel_ticket_for_test(
        &mut self,
        auth: &HostAuth<'_, dyn SecretStorage + '_>,
        eligibility: &PeerEligibility,
        handoff: &channel::AdmittedChannelHandoff,
        params: &ChannelTicketParams,
        operation: &super::OwnerOperation<'_>,
        watch: &WatchCheck<'_>,
        access: &lomi_remote_protocol::HostAccessCredential,
    ) -> (Result<ChannelTicketResult, lomi_host_http::Error>, Duration) {
        #[cfg(not(feature = "cloud-fixture"))]
        let _ = (auth, eligibility);
        #[cfg(feature = "cloud-fixture")]
        if let Some(roots) = self.cloud_fixture_transport_roots.as_ref() {
            let response = (|| {
                let origin = RemoteApiOrigin::new(
                    auth.trusted_configuration(),
                    eligibility.binding.scope.remote_api_origin.clone(),
                )?;
                let transport = DataTransport::with_test_root(origin, roots.remote_api.clone())?;
                let budget = transport.with_budget(handoff.deadline(), watch);
                budget.channel_ticket(handoff.channel_id(), params, access)
            })();
            self.cloud_fixture_ticket_error = response.as_ref().err().copied();
            // An opted-in real transport never falls back to the ticket script,
            // including invalid TLS roots, HTTP failures and lost responses.
            return (response, Duration::ZERO);
        }
        self.scripted_ticket(handoff, params, operation, watch, access)
    }
    #[cfg(test)]
    pub(super) fn script_ticket_for_test(
        &mut self,
        response: Result<ChannelTicketResult, lomi_host_http::Error>,
        hook: Option<TicketTestHook>,
        minimum_elapsed: Duration,
    ) -> std::rc::Rc<std::cell::Cell<usize>> {
        #[cfg(feature = "cloud-fixture")]
        assert!(self.cloud_fixture_transport_roots.is_none());
        assert!(self.script.is_none());
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        self.script = Some(TicketScript {
            response,
            hook,
            calls: calls.clone(),
            minimum_elapsed,
        });
        calls
    }
    #[cfg(test)]
    pub(super) fn ticket_timing_for_test(&self) -> Option<(Instant, Instant, u64)> {
        self.ticketed.as_ref().map(|cached| {
            (
                cached.request_started,
                cached.expires_at,
                cached.expires_in_ms,
            )
        })
    }
}

#[cfg_attr(test, track_caller)]
fn invalid<E>(_: E) -> peer::PeerError {
    #[cfg(test)]
    {
        let caller = std::panic::Location::caller();
        record_origin_for_test(
            std::any::type_name::<E>(),
            None,
            caller.file(),
            caller.line(),
            caller.column(),
        );
    }
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
    /// A live socket is a resource, not an unfinished owner operation. Keep the
    /// worker unit only for the handshake or an RPC/stream operation whose
    /// original deadline and continuation are still retained here. A partial
    /// inbound message is not dispatched yet; `turn` enforces its assembler's
    /// fixed origin-based timeout before accepting more input.
    fn has_retained_operation(&self) -> bool {
        self.response.is_some()
            || self.stream.is_some()
            || !self.started_git_outputs.is_empty()
            || self.git_output_reservation != 0
            || self.git_read.is_some()
            || self.git_mutation.is_some()
            || !matches!(&self.crypto, Crypto::Established(_))
            || self.peer_refresh_deadline(Instant::now()).is_some()
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
                #[cfg(test)]
                sent_fragments: 0,
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
            #[cfg(test)]
            sent_fragments: 0,
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
            #[cfg(test)]
            sent_fragments: 0,
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
        #[cfg(test)]
        {
            response.sent_fragments = response.sent_fragments.saturating_add(1);
        }
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
        #[cfg(test)]
        {
            response.sent_fragments = response.sent_fragments.saturating_add(1);
        }
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

    /// Retain the current worker unit only while an established connection is
    /// inside the pre-expiry refresh window. The existing cutoff remains
    /// absolute; failure to refresh before it expires still closes the channel.
    fn peer_refresh_deadline(&self, now: Instant) -> Option<Instant> {
        if !matches!(&self.crypto, Crypto::Established(_)) || self.peer_cutoff <= now {
            return None;
        }
        (self.peer_cutoff.saturating_duration_since(now) <= PEER_REFRESH_MARGIN)
            .then_some(self.peer_cutoff)
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
                let turn = runtime
                    .owner
                    .try_remote_workspace_turn(&evidence, &current, &pending.context)
                    .map_err(owner_error_at!())?;
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
                            #[cfg(test)]
                            sent_fragments: 0,
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
                        #[cfg(test)]
                        sent_fragments: 0,
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
                    let turn = runtime
                        .owner
                        .try_remote_workspace_turn(&evidence, current_peer, &pending.context)
                        .map_err(owner_error_at!())?;
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
                            #[cfg(test)]
                            sent_fragments: 0,
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
                    let turn = runtime
                        .owner
                        .try_remote_workspace_turn(&evidence, current_peer, &pending.context)
                        .map_err(owner_error_at!())?;
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
                            #[cfg(test)]
                            sent_fragments: 0,
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
                let turn = runtime
                    .owner
                    .try_remote_workspace_turn(&evidence, &current, &self.workspace)
                    .map_err(owner_error_at!())?;
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
                            #[cfg(test)]
                            sent_fragments: 0,
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
            let current = peer_boundary_at!(
                "response.current-proof",
                current_proof(
                    response.peer.take(),
                    auth,
                    request_runtime,
                    eligibility,
                    &self.source,
                    self.peer_cutoff,
                )
            )?;
            let evidence = peer_boundary_at!(
                "response.evidence",
                request_runtime.remote_worker_evidence(auth, eligibility)
            )?;
            let frame = {
                let turn = runtime
                    .owner
                    .try_remote_workspace_turn(&evidence, &current, &self.workspace)
                    .map_err(owner_error_at!())?;
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
            let send_deadline =
                invalid_none_at!("response.io-deadline", current.io_deadline(&evidence))?;
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
                #[cfg(test)]
                {
                    response.sent_fragments += 1;
                }
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
            let current = peer_boundary_at!(
                "stream.current-proof",
                current_proof(
                    stream.peer.take(),
                    auth,
                    stream_runtime,
                    eligibility,
                    &self.source,
                    self.peer_cutoff,
                )
            )?;
            let evidence = peer_boundary_at!(
                "stream.evidence",
                stream_runtime.remote_worker_evidence(auth, eligibility)
            )?;
            let Crypto::Established(crypto) = &mut self.crypto else {
                return Err(peer::PeerError::Invalid);
            };
            {
                let turn = runtime
                    .owner
                    .try_remote_workspace_turn(&evidence, &current, &self.workspace)
                    .map_err(owner_error_at!())?;
                if current.observed_at() > self.applied_observation {
                    turn.refresh_peer(crypto).map_err(invalid_at!())?;
                    self.applied_observation = current.observed_at();
                }
                if let Some(request) = stream.authorization_call.as_ref() {
                    turn.check_response(crypto, request)
                        .map_err(invalid_at!())?;
                }
            }
            if let Some(delivery) = &stream.delivery {
                self.terminal
                    .as_mut()
                    .ok_or(peer::PeerError::Invalid)?
                    .check_fragment(delivery, crypto, &evidence, &current)
                    .map_err(invalid_at!())?;
            }
            let ciphertext = {
                let turn = runtime
                    .owner
                    .try_remote_workspace_turn(&evidence, &current, &self.workspace)
                    .map_err(owner_error_at!())?;
                let frame = self
                    .encoder
                    .next_frame()
                    .map_err(invalid_at!())?
                    .ok_or(peer::PeerError::Invalid)?;
                turn.seal_frame(crypto, &frame).map_err(invalid_at!())?
            };
            let deadline = invalid_none_at!("stream.io-deadline", current.io_deadline(&evidence))?;
            self.peer_cutoff = current.fresh_until();
            drop(evidence);
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
            self.socket
                .send_binary(&ciphertext, deadline, &check)
                .map_err(invalid_at!())?;
            stream.remaining = stream
                .remaining
                .checked_sub(1)
                .ok_or(peer::PeerError::Invalid)?;
            if stream.remaining == 0 {
                if let Some(delivery) = stream.delivery {
                    self.terminal
                        .as_mut()
                        .ok_or(peer::PeerError::Invalid)?
                        .complete_delivery(crypto, delivery)
                        .map_err(invalid_at!())?;
                }
                self.peer = None;
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
        let runtime = Runtime {
            operation: &self.maintenance,
            aborted: &self.maintenance_aborted,
            ..runtime
        };
        let current = current_proof(
            self.peer.take(),
            auth,
            runtime,
            eligibility,
            &self.source,
            self.peer_cutoff,
        )?;
        self.assembler
            .expire(u64::try_from(self.origin.elapsed().as_millis()).map_err(invalid_at!())?)
            .map_err(invalid_at!())?;
        let evidence = runtime.remote_worker_evidence(auth, eligibility)?;
        let io_deadline = current
            .io_deadline(&evidence)
            .ok_or(peer::PeerError::Invalid)?;
        let operation = runtime.operation;
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
        let stage = std::mem::replace(&mut self.crypto, Crypto::Vacant);
        let mut request = None;
        let mut advanced = false;
        match stage {
            Crypto::WriteSecond(mut pending) => {
                let bytes = {
                    let turn = runtime
                        .owner
                        .try_remote_workspace_turn(&evidence, &current, &self.workspace)
                        .map_err(owner_error_at!())?;
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
                        let turn = runtime
                            .owner
                            .try_remote_workspace_turn(&evidence, &current, &self.workspace)
                            .map_err(owner_error_at!())?;
                        if current.observed_at() > self.applied_observation {
                            turn.refresh_peer(&mut crypto).map_err(invalid_at!())?;
                            self.applied_observation = current.observed_at();
                        }
                        self.crypto = Crypto::Established(crypto);
                    }
                    (stage, Poll::Pending) => self.crypto = stage,
                    (Crypto::ReadFirst(mut pending), Poll::Ready(bytes)) => {
                        let turn = runtime
                            .owner
                            .try_remote_workspace_turn(&evidence, &current, &self.workspace)
                            .map_err(owner_error_at!())?;
                        turn.handshake_read(&mut pending, &bytes)
                            .map_err(invalid_at!())?;
                        self.crypto = Crypto::WriteSecond(pending);
                        advanced = true;
                    }
                    (Crypto::ReadThird(mut pending), Poll::Ready(bytes)) => {
                        let turn = runtime
                            .owner
                            .try_remote_workspace_turn(&evidence, &current, &self.workspace)
                            .map_err(owner_error_at!())?;
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
                            let turn = runtime
                                .owner
                                .try_remote_workspace_turn(&evidence, &current, &self.workspace)
                                .map_err(owner_error_at!())?;
                            if current.observed_at() > self.applied_observation {
                                turn.refresh_peer(&mut crypto).map_err(invalid_at!())?;
                                self.applied_observation = current.observed_at();
                            }
                            turn.open_frame(&mut crypto, &bytes)
                                .map_err(invalid_at!())?
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
            let evidence = runtime.remote_worker_evidence(auth, eligibility)?;
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
                            let turn = runtime
                                .owner
                                .try_remote_workspace_turn(&evidence, current, &self.workspace)
                                .map_err(owner_error_at!())?;
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
                let operation = super::OwnerOperation::new(
                    worker_deadline,
                    cancelled.ok_or(peer::PeerError::Invalid)?,
                );
                let aborted = std::cell::Cell::new(false);
                // Serialization follows dropping actor/Domain/Core turns.
                // The first physical fragment obtains fresh authority under
                // this new logical stream operation, then retains it.
                let remaining = bytes
                    .len()
                    .div_ceil(lomi_remote_protocol::message_framing::MAX_FRAGMENT_PAYLOAD_LEN);
                self.encoder.begin(kind, bytes).map_err(invalid_at!())?;
                self.stream = Some(PendingStream {
                    operation,
                    aborted,
                    peer: None,
                    kind,
                    authorization_call: match kind {
                        MessageKind::WorkspaceFrame => self.workspace_stream_call.clone(),
                        MessageKind::FileWatchFrame => self.watch_call.clone(),
                        MessageKind::TerminalFrame => None,
                        _ => return Err(peer::PeerError::Invalid),
                    },
                    delivery,
                    remaining,
                });
                self.peer = None;
                advanced = true;
            }
        }
        if let Some((request, received)) = request {
            #[cfg(test)]
            {
                self.diagnostic_requests += 1;
                self.diagnostic_call = match &request.call {
                    RpcCall::WorkspaceGet(_) => "workspace.get",
                    RpcCall::WorkspaceCapabilities(_) => "workspace.capabilities",
                    RpcCall::TerminalRename(_) => "terminal.rename",
                    RpcCall::TerminalMove(_) => "terminal.move",
                    RpcCall::TerminalCreate(_) => "terminal.create",
                    RpcCall::TerminalSplit(_) => "terminal.split",
                    RpcCall::TerminalClose(_) => "terminal.close",
                    RpcCall::TerminalRestart(_) => "terminal.restart",
                    RpcCall::TerminalAttach(_) => "terminal.attach",
                    RpcCall::TerminalSnapshot(_) => "terminal.snapshot",
                    RpcCall::TerminalAck(_) => "terminal.ack",
                    RpcCall::TerminalClaim(_) => "terminal.claim",
                    RpcCall::TerminalRenew(_) => "terminal.renew",
                    RpcCall::TerminalRelease(_) => "terminal.release",
                    RpcCall::TerminalInput(_) => "terminal.input",
                    RpcCall::TerminalResize(_) => "terminal.resize",
                    _ => "other",
                };
            }
            // A request uses a different admission. Do not later try to refresh
            // the channel from an older maintenance observation.
            self.peer = None;
            let deadline = received
                .checked_add(Duration::from_millis(request.timeout_ms.get()))
                .ok_or(peer::PeerError::Invalid)?
                .min(worker_deadline);
            let operation =
                super::OwnerOperation::new(deadline, cancelled.ok_or(peer::PeerError::Invalid)?);
            let aborted = std::cell::Cell::new(false);
            let request_runtime = Runtime {
                operation: &operation,
                aborted: &aborted,
                ..runtime
            };
            let current = peer_boundary_at!(
                "request.current-get",
                peer::Worker::default().read_current_pairing_bounded(
                    auth,
                    request_runtime,
                    eligibility,
                    self.source.clone(),
                    self.peer_cutoff,
                )
            )?;
            let evidence = peer_boundary_at!(
                "request.evidence",
                request_runtime.remote_worker_evidence(auth, eligibility)
            )?;
            let Crypto::Established(crypto) = &mut self.crypto else {
                return Err(peer::PeerError::Invalid);
            };
            let (queued, workspace_result, workspace_subscription, workspace_capabilities) = {
                let turn = runtime
                    .owner
                    .try_remote_workspace_turn(&evidence, &current, &self.workspace)
                    .map_err(owner_error_at!())?;
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
                    let turn = runtime
                        .owner
                        .try_remote_workspace_turn(&evidence, &current, &self.workspace)
                        .map_err(owner_error_at!())?;
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
                let response_current = peer_boundary_at!(
                    "operation.response-current-get",
                    peer::Worker::default().read_current_pairing_bounded(
                        auth,
                        request_runtime,
                        eligibility,
                        self.source.clone(),
                        self.peer_cutoff,
                    )
                )?;
                let response_evidence = peer_boundary_at!(
                    "operation.response-evidence",
                    request_runtime.remote_worker_evidence(auth, eligibility)
                )?;
                {
                    let turn = runtime
                        .owner
                        .try_remote_workspace_turn(
                            &response_evidence,
                            &response_current,
                            &self.workspace,
                        )
                        .map_err(owner_error_at!())?;
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
                    #[cfg(test)]
                    sent_fragments: 0,
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
                            .send(crypto, &mut self.socket)
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
                let turn = runtime
                    .owner
                    .try_remote_workspace_turn(&evidence, &current, &self.workspace)
                    .map_err(owner_error_at!())?;
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
                let turn = runtime
                    .owner
                    .try_remote_workspace_turn(&evidence, &current, &self.workspace)
                    .map_err(owner_error_at!())?;
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
                let turn = runtime
                    .owner
                    .try_remote_workspace_turn(&evidence, &current, &self.workspace)
                    .map_err(owner_error_at!())?;
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
                        #[cfg(test)]
                        {
                            let category = match error.code() {
                                lomi_remote_protocol::ErrorCode::ScopeDenied => {
                                    "terminal.fatal/ScopeDenied"
                                }
                                lomi_remote_protocol::ErrorCode::ServiceUnavailable => {
                                    "terminal.fatal/ServiceUnavailable"
                                }
                                lomi_remote_protocol::ErrorCode::OutcomeUnknown => {
                                    "terminal.fatal/OutcomeUnknown"
                                }
                                _ => "terminal.fatal/OtherErrorCode",
                            };
                            let effect = match error.effect() {
                                lomi_remote_protocol::Effect::None => "None",
                                lomi_remote_protocol::Effect::Committed => "Committed",
                                lomi_remote_protocol::Effect::Partial => "Partial",
                                lomi_remote_protocol::Effect::Unknown => "Unknown",
                            };
                            record_origin_for_test(
                                category,
                                Some(effect),
                                file!(),
                                line!(),
                                column!(),
                            );
                        }
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
            drop(evidence);
            let bytes = serde_json::to_vec(&response).map_err(invalid_at!())?;
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
                #[cfg(test)]
                sent_fragments: 0,
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

#[cfg(test)]
mod rollover_repro_tests {
    use super::*;

    #[test]
    fn pending_stream_evidence_keeps_its_original_worker_unit_deadline() {
        peer::tests::fixture(|f, auth| {
            let outer = f.runtime();
            let stream = PendingStream {
                operation: super::super::OwnerOperation::new(
                    outer.operation.deadline(),
                    &f.stopping,
                ),
                aborted: std::cell::Cell::new(false),
                peer: None,
                kind: MessageKind::WorkspaceFrame,
                authorization_call: None,
                delivery: None,
                remaining: 1,
            };
            assert_eq!(
                stream.operation.deadline(),
                outer.operation.deadline(),
                "stream operation is bounded by the worker unit that created it"
            );

            let stream_runtime = Runtime {
                operation: &stream.operation,
                aborted: &stream.aborted,
                ..outer
            };
            let evidence = stream_runtime
                .remote_worker_evidence(auth, &f.eligibility)
                .unwrap_or_else(|_| panic!("actual worker evidence"));
            assert!(evidence.current());

            // Model the worker-unit boundary after ProviderCapture succeeds
            // but before RemoteWorkerEvidence performs its final current check.
            stream.operation.expire_for_test();
            assert!(
                !evidence.current(),
                "a boundary between provider capture and current() rejects the evidence"
            );
            drop(evidence);
            assert!(matches!(
                stream_runtime.remote_worker_evidence(auth, &f.eligibility),
                Err(peer::PeerError::Fatal(super::super::StepError::Stale))
            ));

            // The actor can admit a later unit, but that does not renew the
            // original stream operation or make its next fragment current.
            let mut units = super::super::WorkerOperationUnits::new(outer.operation, outer.aborted);
            units.admit_after_settlement(&f.stopping);
            let resumed = Runtime {
                operation: units.operation(),
                aborted: units.aborted(),
                ..outer
            };
            assert!(
                resumed.remote_worker_evidence(auth, &f.eligibility).is_ok(),
                "a later worker unit can obtain fresh evidence"
            );
            assert!(stream.operation.check().is_err());
        });
    }
}
