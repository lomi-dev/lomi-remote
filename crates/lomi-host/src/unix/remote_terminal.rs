//! Typed remote execution for existing host-owned terminals only.
//! Future ingress declares this module and owns network/framing. No transport,
//! local RPC dispatch, Store guard, or strong Coordinator reference is retained.
use super::{Coordinator, auth, rpc};
use auth::{
    RemoteWorkerEvidence,
    peer::VerifiedCurrentPeer,
    remote_connection::{GateError, QueuedRequest, RemoteConnectionState},
};
use lomi_remote_protocol::{rpc::*, streams::*, *};
use lomi_terminal::{Attachment, AuthenticatedConnection, ControlLease, TerminalEvent};
use std::{
    collections::{HashMap, VecDeque},
    sync::Weak,
};
use uuid::Uuid;

const LIMIT: usize = 32;
const ASSEMBLY_BYTES: usize = 8 * 1024 * 1024;
const CHUNK: usize = 16384;
struct Subscription {
    terminal: TerminalContext,
    attachment: Attachment,
    emission: Option<Emission>,
    sent_through: Option<u64>,
}
struct Emission {
    bytes: Vec<u8>,
    position: usize,
    previous: Option<u64>,
    through: u64,
    offset: u64,
    metadata: bool,
    working_directory: Option<WorkingDirectory>,
}
struct PendingDelivery {
    id: Uuid,
    subscription: String,
    through: Option<u64>,
    retire: bool,
}
/// A logical message, not a ciphertext or permission to disclose later.
/// The one connection MessageEncoder serializes frame(); call check_fragment
/// again before EVERY encrypted fragment and complete_delivery only after the
/// final fragment has physically completed. Failure requires disconnect.
pub(super) struct RemoteTerminalStreamFrame {
    frame: TerminalStreamFrame,
    terminal: TerminalContext,
    delivery: Uuid,
}
impl RemoteTerminalStreamFrame {
    pub(super) fn frame(&self) -> &TerminalStreamFrame {
        &self.frame
    }

    pub(super) fn terminal_context(&self) -> &TerminalContext {
        &self.terminal
    }
}
pub(super) struct RemoteTerminalState {
    coordinator: Weak<Coordinator>,
    principal: AuthenticatedConnection,
    channel: Uuid,
    subscriptions: HashMap<String, Subscription>,
    leases: HashMap<String, (TerminalContext, ControlLease)>,
    schedule: VecDeque<String>,
    pending: Option<PendingDelivery>,
    disconnected: bool,
}
fn fault(code: ErrorCode) -> RemoteError {
    RemoteError::new(code, false, Effect::None, ErrorDetails::empty(), None).expect("static error")
}
fn gate(_: GateError) -> RemoteError {
    fault(ErrorCode::ScopeDenied)
}

fn owner(_: super::shared_owner::Error) -> RemoteError {
    fault(ErrorCode::ServiceUnavailable)
}

fn terminal(error: lomi_terminal::Error) -> RemoteError {
    if error == lomi_terminal::Error::OutcomeUnknown {
        return RemoteError::new(
            ErrorCode::OutcomeUnknown,
            false,
            Effect::Unknown,
            ErrorDetails::empty(),
            None,
        )
        .expect("uncertain input");
    }
    fault(match error {
        lomi_terminal::Error::StaleEpoch => ErrorCode::StaleEpoch,
        lomi_terminal::Error::SessionMissing | lomi_terminal::Error::SessionExited => {
            ErrorCode::SessionExited
        }
        lomi_terminal::Error::ControlRequired | lomi_terminal::Error::LeaseExpired => {
            ErrorCode::ControlRequired
        }
        lomi_terminal::Error::RenderAckRequired => ErrorCode::ResyncRequired,
        lomi_terminal::Error::SequenceConflict => ErrorCode::IdempotencyConflict,
        lomi_terminal::Error::InvalidArgument => ErrorCode::InvalidArgument,
        lomi_terminal::Error::ResourceExhausted => ErrorCode::ResourceExhausted,
        lomi_terminal::Error::FenceRejected => ErrorCode::ScopeDenied,
        _ => ErrorCode::ServiceUnavailable,
    })
}
fn target(call: &RpcCall) -> Option<&TerminalContext> {
    match call {
        RpcCall::TerminalAttach(p) | RpcCall::TerminalSnapshot(p) => Some(&p.terminal),
        RpcCall::TerminalAck(p) => Some(&p.terminal),
        RpcCall::TerminalClaim(p) => Some(&p.terminal),
        RpcCall::TerminalRenew(p) | RpcCall::TerminalRelease(p) => Some(&p.terminal),
        RpcCall::TerminalInput(p) => Some(&p.terminal),
        RpcCall::TerminalResize(p) => Some(&p.terminal),
        _ => None,
    }
}
fn lease_result(context: TerminalContext, lease: &ControlLease) -> TerminalLeaseResult {
    TerminalLeaseResult {
        terminal: context,
        lease: lease.wire_binding(),
        expires_in_ms: TimeoutMs::new(5000).expect("TerminalService lease TTL"),
        next_input_id: DecimalU64(lease.next_input_id),
        next_input_seq: InputSeq(DecimalU64(lease.next_input_seq)),
        next_resize_seq: ResizeSeq(DecimalU64(lease.next_resize_seq)),
    }
}
impl RemoteTerminalState {
    /// Reports retained snapshot/delta bytes without advancing a subscription
    /// or consuming a queued terminal event.
    pub(super) fn has_immediate_output(&self) -> bool {
        !self.disconnected && self.subscriptions.values().any(|s| s.emission.is_some())
    }

    /// Only a completed Noise connection supplies the consumer principal. A new
    /// AuthenticatedConnection generates a fresh UUID even for the same actor.
    pub(super) fn new(
        coordinator: Weak<Coordinator>,
        connection: &RemoteConnectionState,
    ) -> Result<Self, RemoteError> {
        if !connection.supports_active_rpc_purpose() {
            return Err(fault(ErrorCode::ScopeDenied));
        }
        Ok(Self {
            channel: connection.connection_identity(),
            coordinator,
            principal: AuthenticatedConnection::new(connection.consumer_actor()),
            subscriptions: HashMap::new(),
            leases: HashMap::new(),
            schedule: VecDeque::new(),
            pending: None,
            disconnected: false,
        })
    }
    fn lease(
        &self,
        context: &TerminalContext,
        binding: &LeaseBinding,
    ) -> Result<ControlLease, RemoteError> {
        self.leases
            .get(&String::from(binding.token.clone()))
            .filter(|(target, lease)| target == context && lease.version == binding.version.0)
            .map(|(_, lease)| lease.clone())
            .ok_or_else(|| fault(ErrorCode::ControlRequired))
    }
    fn ready(&self, connection: &RemoteConnectionState) -> Result<(), RemoteError> {
        if self.disconnected
            || self.channel != connection.connection_identity()
            || self.principal.actor() != connection.consumer_actor()
        {
            return Err(fault(ErrorCode::ScopeDenied));
        }
        if self.pending.is_some() {
            return Err(fault(ErrorCode::ResourceExhausted));
        }
        Ok(())
    }
    /// Owner evidence uses the same original logical operation as queued. Only
    /// the explicit eight terminal methods below can execute; no lifecycle path.
    pub(super) fn execute(
        &mut self,
        connection: &mut RemoteConnectionState,
        worker: &RemoteWorkerEvidence<'_, '_, '_, '_>,
        peer: &VerifiedCurrentPeer,
        original: &RpcRequest,
        queued: &QueuedRequest,
    ) -> Result<RpcResult, RemoteError> {
        self.ready(connection)?;
        let context = target(&original.call)
            .ok_or_else(|| fault(ErrorCode::UnsupportedCapability))?
            .clone();
        let coordinator = self
            .coordinator
            .upgrade()
            .ok_or_else(|| fault(ErrorCode::ServiceUnavailable))?;
        if !std::ptr::eq(coordinator.owner.as_ref(), worker.owner()) {
            return Err(fault(ErrorCode::ScopeDenied));
        }
        let operation = worker.operation();
        let actor = coordinator
            .workspace_lock(context.workspace.workspace_id)
            .map_err(|_| fault(ErrorCode::ServiceUnavailable))?;
        // All waiting is actor -> Domain -> Store; no Store is retained by turn.
        let result = (|| -> Result<Execution, RemoteError> {
            let _actor = rpc::actor_lock(&actor, operation)?;
            let mut turn = rpc::owner_call(operation, || {
                coordinator
                    .owner
                    .try_remote_terminal_turn(worker, peer, &context)
            })
            .map_err(owner)?;
            self.execute_authorized(
                connection,
                original,
                queued,
                context.clone(),
                &coordinator,
                &mut turn,
            )
        })();
        self.finish_execution(connection, result)
    }

    /// The StartedGit path keeps the same terminal call set and checked Core
    /// callbacks while using only an established-channel pairing observation.
    pub(super) fn execute_started_git(
        &mut self,
        connection: &mut RemoteConnectionState,
        operation: &super::owner_domain::Operation<'_>,
        active: &super::shared_owner::StartedGitContinuation,
        peer: &auth::peer::StartedGitPeerObservation,
        latches: super::owner_domain::StartedGitTerminalLatches<'_>,
        original: &RpcRequest,
        queued: &QueuedRequest,
    ) -> Result<RpcResult, RemoteError> {
        self.ready(connection)?;
        let context = target(&original.call)
            .ok_or_else(|| fault(ErrorCode::UnsupportedCapability))?
            .clone();
        let coordinator = self
            .coordinator
            .upgrade()
            .ok_or_else(|| fault(ErrorCode::ServiceUnavailable))?;
        let actor = coordinator
            .workspace_lock(context.workspace.workspace_id)
            .map_err(|_| fault(ErrorCode::ServiceUnavailable))?;
        let result = (|| -> Result<Execution, RemoteError> {
            let _actor = rpc::actor_lock(&actor, operation)?;
            let mut turn = rpc::owner_call(operation, || {
                coordinator.owner.try_started_git_terminal_turn(
                    operation, active, peer, latches, connection, &context,
                )
            })
            .map_err(owner)?;
            self.execute_authorized(
                connection,
                original,
                queued,
                context.clone(),
                &coordinator,
                &mut turn,
            )
        })();
        self.finish_execution(connection, result)
    }

    fn execute_authorized<T: TerminalTurnCallbacks>(
        &mut self,
        connection: &mut RemoteConnectionState,
        original: &RpcRequest,
        queued: &QueuedRequest,
        context: TerminalContext,
        coordinator: &Coordinator,
        turn: &mut T,
    ) -> Result<Execution, RemoteError> {
        let request = turn.terminal_after_wait(connection, queued).map_err(gate)?;
        if &request != original {
            return Err(fault(ErrorCode::InvalidArgument));
        }
        // Every cached target belongs to this workspace-purpose connection.
        // Pruning only retires expired/dead credentials under its actor turn.
        self.leases.retain(|_, (target, lease)| {
            coordinator.terminals.lease_is_current(
                target.session_id,
                target.session_epoch,
                &self.principal,
                lease,
            )
        });
        // Checked APIs invoke these predicates under Core/retirement locks.
        // They read only the retained owner turn or its lock-free IO watch.
        match &request.call {
            RpcCall::TerminalAttach(_) | RpcCall::TerminalSnapshot(_) => {
                if self.subscriptions.len() >= LIMIT {
                    return Err(fault(ErrorCode::ResourceExhausted));
                }
                let mut current = || turn.check_terminal_request(connection, &request).is_ok();
                let attachment = coordinator
                    .terminals
                    .attach_checked(
                        context.session_id,
                        context.session_epoch,
                        &self.principal,
                        &mut current,
                    )
                    .map_err(terminal)?;
                Ok(Execution::Attachment(
                    context,
                    Box::new(attachment),
                    matches!(&request.call, RpcCall::TerminalAttach(_)),
                ))
            }
            RpcCall::TerminalAck(params) => {
                let mut current = || turn.check_terminal_request(connection, &request).is_ok();
                self.ack(
                    &params.terminal,
                    &params.subscription_id,
                    params.through_seq.0.0,
                    &mut current,
                )?;
                Ok(Execution::Result(RpcResult::TerminalAck(
                    TerminalAckResult {
                        subscription_id: params.subscription_id.clone(),
                        through_seq: params.through_seq,
                    },
                )))
            }
            RpcCall::TerminalClaim(params) => {
                let mut current = || turn.check_terminal_request(connection, &request).is_ok();
                self.ack(
                    &params.terminal,
                    &params.subscription_id,
                    params.rendered_through_seq.0.0,
                    &mut current,
                )?;
                if self
                    .leases
                    .values()
                    .filter(|(target, _)| target.session_id != context.session_id)
                    .count()
                    >= LIMIT
                {
                    return Err(fault(ErrorCode::ResourceExhausted));
                }
                let lease = coordinator
                    .terminals
                    .claim_checked(
                        context.session_id,
                        context.session_epoch,
                        &self.principal,
                        &mut current,
                    )
                    .map_err(terminal)?;
                self.leases
                    .retain(|_, (target, _)| target.session_id != context.session_id);
                let result = lease_result(context.clone(), &lease);
                self.leases
                    .insert(lease.wire_token(), (context.clone(), lease));
                Ok(Execution::Result(RpcResult::TerminalClaim(result)))
            }
            RpcCall::TerminalRenew(params) => {
                let lease = self.lease(&context, &params.lease)?;
                let mut current = || turn.check_terminal_request(connection, &request).is_ok();
                let renewed = coordinator
                    .terminals
                    .renew_checked(
                        context.session_id,
                        context.session_epoch,
                        &self.principal,
                        &lease,
                        &mut current,
                    )
                    .map_err(terminal)?;
                let result = lease_result(context.clone(), &renewed);
                self.leases
                    .insert(renewed.wire_token(), (context.clone(), renewed));
                Ok(Execution::Result(RpcResult::TerminalRenew(result)))
            }
            RpcCall::TerminalRelease(params) => {
                let lease = self.lease(&context, &params.lease)?;
                let mut current = || turn.check_terminal_request(connection, &request).is_ok();
                coordinator
                    .terminals
                    .release_checked(
                        context.session_id,
                        context.session_epoch,
                        &self.principal,
                        &lease,
                        &mut current,
                    )
                    .map_err(terminal)?;
                self.leases.remove(&lease.wire_token());
                Ok(Execution::Result(RpcResult::TerminalRelease(
                    TerminalReleaseResult {
                        terminal: context,
                        released: true,
                    },
                )))
            }
            RpcCall::TerminalInput(params) => {
                let lease = self.lease(&context, &params.lease)?;
                turn.before_terminal_io(connection, &request)
                    .map_err(gate)?;
                let mut current = || turn.check_terminal_request(connection, &request).is_ok();
                let receipt = coordinator
                    .terminals
                    .input(
                        context.session_id,
                        context.session_epoch,
                        &self.principal,
                        &lease,
                        params.input_id.0,
                        params.input_seq.0.0,
                        &params.bytes.0,
                        &mut current,
                    )
                    .map_err(terminal)?;
                Ok(Execution::Result(RpcResult::TerminalInput(
                    InputReceipt::new(
                        context.session_id,
                        context.session_epoch,
                        params.input_id,
                        params.input_seq.0,
                        InputBytes::new(receipt.submitted_bytes as u64)
                            .map_err(|_| fault(ErrorCode::InvalidArgument))?,
                        InputBytes::new(receipt.accepted_bytes as u64)
                            .map_err(|_| fault(ErrorCode::InvalidArgument))?,
                    )
                    .map_err(|_| fault(ErrorCode::ServiceUnavailable))?,
                )))
            }
            RpcCall::TerminalResize(params) => {
                let lease = self.lease(&context, &params.lease)?;
                turn.before_terminal_io(connection, &request)
                    .map_err(gate)?;
                let mut current = || turn.check_terminal_request(connection, &request).is_ok();
                coordinator
                    .terminals
                    .resize(
                        context.session_id,
                        context.session_epoch,
                        &self.principal,
                        &lease,
                        params.resize_seq.0.0,
                        params.rows.0 as u16,
                        params.columns.0 as u16,
                        &mut current,
                    )
                    .map_err(terminal)?;
                Ok(Execution::Result(RpcResult::TerminalResize(
                    TerminalResizeResult {
                        terminal: context,
                        resize_seq: params.resize_seq,
                        columns: params.columns,
                        rows: params.rows,
                    },
                )))
            }
            _ => Err(fault(ErrorCode::UnsupportedCapability)),
        }
    }

    fn finish_execution(
        &mut self,
        connection: &mut RemoteConnectionState,
        result: Result<Execution, RemoteError>,
    ) -> Result<RpcResult, RemoteError> {
        // Both Domain and actor have dropped before snapshot serialization.
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                if error.code() == ErrorCode::OutcomeUnknown {
                    connection.dispose();
                    self.disconnect();
                }
                return Err(error);
            }
        };
        match result {
            Execution::Result(result) => Ok(result),
            Execution::Attachment(context, attachment, attach) => {
                let metadata = self.register(context, *attachment)?;
                Ok(if attach {
                    RpcResult::TerminalAttach(metadata)
                } else {
                    RpcResult::TerminalSnapshot(metadata)
                })
            }
        }
    }
    fn ack(
        &self,
        context: &TerminalContext,
        id: &SubscriptionId,
        through: u64,
        current: &mut impl FnMut() -> bool,
    ) -> Result<(), RemoteError> {
        let subscription = self
            .subscriptions
            .get(&String::from(id.clone()))
            .filter(|s| &s.terminal == context)
            .ok_or_else(|| fault(ErrorCode::ResyncRequired))?;
        if subscription.sent_through.is_none_or(|sent| through > sent) {
            return Err(fault(ErrorCode::ResyncRequired));
        }
        subscription
            .attachment
            .acknowledge_checked(&self.principal, through, current)
            .map_err(terminal)
    }
    fn register(
        &mut self,
        context: TerminalContext,
        attachment: Attachment,
    ) -> Result<TerminalSnapshotMetadata, RemoteError> {
        let bytes = serde_json::to_vec(&attachment.snapshot)
            .map_err(|_| fault(ErrorCode::ServiceUnavailable))?;
        let working_directory = attachment.working_directory.clone();
        let pending: usize = self
            .subscriptions
            .values()
            .filter_map(|s| s.emission.as_ref())
            .map(|e| {
                e.bytes.len().saturating_add(
                    e.working_directory
                        .as_ref()
                        .map_or(0, |path| path.as_str().len()),
                )
            })
            .sum();
        let assembly_bytes = bytes.len().saturating_add(
            working_directory
                .as_ref()
                .map_or(0, |path| path.as_str().len()),
        );
        if bytes.is_empty() || assembly_bytes > ASSEMBLY_BYTES.saturating_sub(pending) {
            return Err(fault(ErrorCode::ResourceExhausted));
        }
        let id = Uuid::new_v4().to_string();
        let subscription_id = id
            .clone()
            .try_into()
            .map_err(|_| fault(ErrorCode::ServiceUnavailable))?;
        let snapshot = &attachment.snapshot;
        let result = TerminalSnapshotMetadata {
            terminal: context.clone(),
            subscription_id,
            through_seq: TerminalSeq(snapshot.sequence),
            output_offset: snapshot.output_offset,
            columns: TerminalDimension(snapshot.cols as u32),
            rows: TerminalDimension(snapshot.rows as u32),
            chunk_count: ChunkCount(bytes.len().div_ceil(CHUNK) as u32),
            total_bytes: DecimalU64(bytes.len() as u64),
            working_directory: working_directory.clone().into(),
        };
        let emission = Emission {
            bytes,
            position: 0,
            previous: None,
            through: snapshot.sequence.0,
            offset: snapshot.output_offset.0,
            metadata: false,
            working_directory: None,
        };
        self.subscriptions.insert(
            id.clone(),
            Subscription {
                terminal: context,
                attachment,
                emission: Some(emission),
                sent_through: None,
            },
        );
        self.schedule.push_back(id);
        Ok(result)
    }
    /// Upgrade only for this boundary. TerminalService is never allowed to own
    /// this state or Coordinator, and host PTYs survive its disconnect/drop.
    pub(super) fn disconnect(&mut self) {
        if let Some(coordinator) = self.coordinator.upgrade() {
            coordinator.terminals.disconnect(&self.principal);
        }
        self.subscriptions.clear();
        self.leases.clear();
        self.schedule.clear();
        self.pending = None;
        self.disconnected = true;
    }
}
enum Execution {
    Attachment(TerminalContext, Box<Attachment>, bool),
    Result(RpcResult),
}
trait TerminalTurnCallbacks {
    fn terminal_after_wait(
        &mut self,
        connection: &mut RemoteConnectionState,
        queued: &QueuedRequest,
    ) -> Result<RpcRequest, GateError>;
    fn check_terminal_request(
        &mut self,
        connection: &mut RemoteConnectionState,
        original: &RpcRequest,
    ) -> Result<(), GateError>;
    fn before_terminal_io(
        &mut self,
        _connection: &mut RemoteConnectionState,
        _original: &RpcRequest,
    ) -> Result<(), GateError> {
        Ok(())
    }
}
impl TerminalTurnCallbacks for super::shared_owner::RemoteTerminalTurn<'_, '_, '_, '_, '_, '_> {
    fn terminal_after_wait(
        &mut self,
        connection: &mut RemoteConnectionState,
        queued: &QueuedRequest,
    ) -> Result<RpcRequest, GateError> {
        super::shared_owner::RemoteTerminalTurn::terminal_after_wait(self, connection, queued)
    }
    fn check_terminal_request(
        &mut self,
        connection: &mut RemoteConnectionState,
        original: &RpcRequest,
    ) -> Result<(), GateError> {
        super::shared_owner::RemoteTerminalTurn::check_terminal_request(self, connection, original)
    }
}
impl TerminalTurnCallbacks for super::shared_owner::StartedGitTerminalTurn<'_, '_, '_, '_, '_> {
    fn terminal_after_wait(
        &mut self,
        connection: &mut RemoteConnectionState,
        queued: &QueuedRequest,
    ) -> Result<RpcRequest, GateError> {
        super::shared_owner::StartedGitTerminalTurn::terminal_after_wait(self, connection, queued)
    }
    fn check_terminal_request(
        &mut self,
        connection: &mut RemoteConnectionState,
        original: &RpcRequest,
    ) -> Result<(), GateError> {
        super::shared_owner::StartedGitTerminalTurn::check_terminal_request(
            self, connection, original,
        )
    }
    fn before_terminal_io(
        &mut self,
        connection: &mut RemoteConnectionState,
        original: &RpcRequest,
    ) -> Result<(), GateError> {
        let watch = self.into_io_watch();
        watch.check_terminal_request(connection, original)
    }
}
impl Drop for RemoteTerminalState {
    fn drop(&mut self) {
        self.disconnect();
    }
}

impl RemoteTerminalState {
    fn check_target(
        &self,
        connection: &mut RemoteConnectionState,
        worker: &RemoteWorkerEvidence<'_, '_, '_, '_>,
        peer: &VerifiedCurrentPeer,
        context: &TerminalContext,
    ) -> Result<(), RemoteError> {
        if self.disconnected || self.channel != connection.connection_identity() {
            return Err(fault(ErrorCode::ScopeDenied));
        }
        let coordinator = self
            .coordinator
            .upgrade()
            .ok_or_else(|| fault(ErrorCode::ServiceUnavailable))?;
        if !std::ptr::eq(coordinator.owner.as_ref(), worker.owner()) {
            return Err(fault(ErrorCode::ScopeDenied));
        }
        let actor = coordinator
            .workspace_lock(context.workspace.workspace_id)
            .map_err(|_| fault(ErrorCode::ServiceUnavailable))?;
        let _actor = rpc::actor_lock(&actor, worker.operation())?;
        let turn = rpc::owner_call(worker.operation(), || {
            coordinator
                .owner
                .try_remote_terminal_turn(worker, peer, context)
        })
        .map_err(owner)?;
        turn.check_terminal_stream(connection).map_err(gate)
    }
    fn check_target_started_git(
        &self,
        connection: &mut RemoteConnectionState,
        operation: &super::owner_domain::Operation<'_>,
        active: &super::shared_owner::StartedGitContinuation,
        peer: &auth::peer::StartedGitPeerObservation,
        latches: super::owner_domain::StartedGitTerminalLatches<'_>,
        context: &TerminalContext,
    ) -> Result<(), RemoteError> {
        if self.disconnected || self.channel != connection.connection_identity() {
            return Err(fault(ErrorCode::ScopeDenied));
        }
        let coordinator = self
            .coordinator
            .upgrade()
            .ok_or_else(|| fault(ErrorCode::ServiceUnavailable))?;
        let actor = coordinator
            .workspace_lock(context.workspace.workspace_id)
            .map_err(|_| fault(ErrorCode::ServiceUnavailable))?;
        let _actor = rpc::actor_lock(&actor, operation)?;
        let turn = rpc::owner_call(operation, || {
            coordinator.owner.try_started_git_terminal_turn(
                operation, active, peer, latches, connection, context,
            )
        })
        .map_err(owner)?;
        turn.check_terminal_stream(connection).map_err(gate)
    }
    /// At most one logical frame may be outstanding. Snapshot/delta assembly
    /// bytes share the same aggregate limit across all subscriptions.
    pub(super) fn next_frame(
        &mut self,
        connection: &mut RemoteConnectionState,
        worker: &RemoteWorkerEvidence<'_, '_, '_, '_>,
        peer: &VerifiedCurrentPeer,
    ) -> Result<Option<RemoteTerminalStreamFrame>, RemoteError> {
        self.next_frame_checked(connection, |state, connection, context| {
            state.check_target(connection, worker, peer, context)
        })
    }

    pub(super) fn next_frame_started_git(
        &mut self,
        connection: &mut RemoteConnectionState,
        operation: &super::owner_domain::Operation<'_>,
        active: &super::shared_owner::StartedGitContinuation,
        peer: &auth::peer::StartedGitPeerObservation,
        latches: super::owner_domain::StartedGitTerminalLatches<'_>,
    ) -> Result<Option<RemoteTerminalStreamFrame>, RemoteError> {
        self.next_frame_checked(connection, |state, connection, context| {
            state.check_target_started_git(connection, operation, active, peer, latches, context)
        })
    }

    fn next_frame_checked(
        &mut self,
        connection: &mut RemoteConnectionState,
        mut check_target: impl FnMut(
            &Self,
            &mut RemoteConnectionState,
            &TerminalContext,
        ) -> Result<(), RemoteError>,
    ) -> Result<Option<RemoteTerminalStreamFrame>, RemoteError> {
        self.ready(connection)?;
        let assembling = self.subscriptions.values().any(|s| s.emission.is_some());
        for _ in 0..self.schedule.len() {
            let Some(key) = self.schedule.pop_front() else {
                break;
            };
            let Some(sub) = self.subscriptions.get(&key) else {
                continue;
            };
            self.schedule.push_back(key.clone());
            if assembling && sub.emission.is_none() {
                continue;
            }
            let context = sub.terminal.clone();
            check_target(self, connection, &context)?;
            if sub.emission.is_some() {
                return self.emit(&key).map(Some);
            }
            // Queue polling does not acquire Core. Current owner proof was just
            // checked; disclosure is rechecked after serialization per fragment.
            let queued = sub.attachment.try_next_with_metadata();
            let Some(queued) = queued else {
                continue;
            };
            let subscription_id: SubscriptionId = key
                .clone()
                .try_into()
                .map_err(|_| fault(ErrorCode::ServiceUnavailable))?;
            match &*queued.event {
                TerminalEvent::State(delta) => {
                    // No Domain/actor/Store guard remains during serialization.
                    let bytes = serde_json::to_vec(&**delta)
                        .map_err(|_| fault(ErrorCode::ServiceUnavailable))?;
                    let working_directory = queued.working_directory.clone();
                    let pending: usize = self
                        .subscriptions
                        .values()
                        .filter_map(|s| s.emission.as_ref())
                        .map(|e| {
                            e.bytes.len().saturating_add(
                                e.working_directory
                                    .as_ref()
                                    .map_or(0, |path| path.as_str().len()),
                            )
                        })
                        .sum();
                    let assembly_bytes = bytes.len().saturating_add(
                        working_directory
                            .as_ref()
                            .map_or(0, |path| path.as_str().len()),
                    );
                    if bytes.is_empty() || assembly_bytes > ASSEMBLY_BYTES.saturating_sub(pending) {
                        let frame = TerminalStreamFrame::ResyncRequired(TerminalResync {
                            terminal: context.clone(),
                            subscription_id,
                            reason: ResyncReason::SubscriberOverflow,
                        });
                        return Ok(Some(self.prepare(&key, context, frame, None, true)));
                    }
                    self.subscriptions
                        .get_mut(&key)
                        .expect("retained subscription")
                        .emission = Some(Emission {
                        bytes,
                        position: 0,
                        previous: Some(delta.previous_sequence().0),
                        through: delta.sequence().0,
                        offset: delta.output_offset().0,
                        metadata: true,
                        working_directory,
                    });
                    return self.emit(&key).map(Some);
                }
                TerminalEvent::ControlChanged {
                    sequence,
                    version,
                    controlled,
                } => {
                    let frame = TerminalStreamFrame::Delta(TerminalDelta {
                        terminal: context.clone(),
                        subscription_id,
                        seq: TerminalSeq(DecimalU64(*sequence)),
                        change: TerminalChange::ControlChanged(TerminalControlChanged {
                            terminal: context.clone(),
                            lease_version: DecimalU64(*version),
                            controlled: *controlled,
                        }),
                    });
                    return Ok(Some(self.prepare(
                        &key,
                        context,
                        frame,
                        Some(*sequence),
                        false,
                    )));
                }
                TerminalEvent::Exited { sequence } => {
                    let frame = TerminalStreamFrame::Delta(TerminalDelta {
                        terminal: context.clone(),
                        subscription_id,
                        seq: TerminalSeq(DecimalU64(*sequence)),
                        change: TerminalChange::Exit(TerminalExit { exit_code: None }),
                    });
                    return Ok(Some(self.prepare(
                        &key,
                        context,
                        frame,
                        Some(*sequence),
                        true,
                    )));
                }
                TerminalEvent::ResyncRequired => {
                    let frame = TerminalStreamFrame::ResyncRequired(TerminalResync {
                        terminal: context.clone(),
                        subscription_id,
                        reason: ResyncReason::SubscriberOverflow,
                    });
                    return Ok(Some(self.prepare(&key, context, frame, None, true)));
                }
            }
        }
        Ok(None)
    }
    fn prepare(
        &mut self,
        key: &str,
        context: TerminalContext,
        frame: TerminalStreamFrame,
        through: Option<u64>,
        retire: bool,
    ) -> RemoteTerminalStreamFrame {
        let delivery = Uuid::new_v4();
        self.pending = Some(PendingDelivery {
            id: delivery,
            subscription: key.to_owned(),
            through,
            retire,
        });
        RemoteTerminalStreamFrame {
            frame,
            terminal: context,
            delivery,
        }
    }
    fn emit(&mut self, key: &str) -> Result<RemoteTerminalStreamFrame, RemoteError> {
        let subscription = self
            .subscriptions
            .get_mut(key)
            .ok_or_else(|| fault(ErrorCode::ResyncRequired))?;
        let emission = subscription
            .emission
            .as_mut()
            .ok_or_else(|| fault(ErrorCode::ResyncRequired))?;
        let terminal = subscription.terminal.clone();
        let subscription_id: SubscriptionId = key
            .to_owned()
            .try_into()
            .map_err(|_| fault(ErrorCode::ServiceUnavailable))?;
        let (frame, through) = if emission.metadata {
            emission.metadata = false;
            (
                TerminalStreamFrame::DeltaMetadata(TerminalDeltaMetadata {
                    terminal: terminal.clone(),
                    subscription_id,
                    previous_seq: TerminalSeq(DecimalU64(
                        emission
                            .previous
                            .ok_or_else(|| fault(ErrorCode::ServiceUnavailable))?,
                    )),
                    through_seq: TerminalSeq(DecimalU64(emission.through)),
                    chunk_count: ChunkCount(emission.bytes.len().div_ceil(CHUNK) as u32),
                    total_bytes: DecimalU64(emission.bytes.len() as u64),
                    working_directory: emission.working_directory.clone().into(),
                }),
                None,
            )
        } else if emission.position < emission.bytes.len() {
            let index = ChunkIndex((emission.position / CHUNK) as u32);
            let end = (emission.position + CHUNK).min(emission.bytes.len());
            let bytes = BoundedList(emission.bytes[emission.position..end].to_vec());
            emission.position = end;
            let frame = if emission.previous.is_some() {
                TerminalStreamFrame::DeltaChunk(TerminalDeltaChunk {
                    terminal: terminal.clone(),
                    subscription_id,
                    index,
                    bytes,
                })
            } else {
                TerminalStreamFrame::SnapshotChunk(TerminalSnapshotChunk {
                    terminal: terminal.clone(),
                    subscription_id,
                    index,
                    bytes,
                })
            };
            (frame, None)
        } else {
            let through = emission.through;
            let frame = if emission.previous.is_some() {
                TerminalStreamFrame::DeltaComplete(TerminalDeltaComplete {
                    terminal: terminal.clone(),
                    subscription_id,
                    through_seq: TerminalSeq(DecimalU64(through)),
                })
            } else {
                TerminalStreamFrame::SnapshotComplete(TerminalSnapshotComplete {
                    terminal: terminal.clone(),
                    subscription_id,
                    through_seq: TerminalSeq(DecimalU64(through)),
                    output_offset: DecimalU64(emission.offset),
                })
            };
            (frame, Some(through))
        };
        Ok(self.prepare(key, terminal, frame, through, false))
    }
    pub(super) fn check_fragment(
        &mut self,
        frame: &RemoteTerminalStreamFrame,
        connection: &mut RemoteConnectionState,
        worker: &RemoteWorkerEvidence<'_, '_, '_, '_>,
        peer: &VerifiedCurrentPeer,
    ) -> Result<(), RemoteError> {
        let result = if !self.pending.as_ref().is_some_and(|p| {
            p.id == frame.delivery
                && self
                    .subscriptions
                    .get(&p.subscription)
                    .is_some_and(|s| s.terminal == frame.terminal)
        }) {
            Err(fault(ErrorCode::ScopeDenied))
        } else {
            self.check_target(connection, worker, peer, &frame.terminal)
        };
        if result.is_err() {
            connection.dispose();
            self.disconnect();
        }
        result
    }
    pub(super) fn check_fragment_started_git(
        &mut self,
        frame: &RemoteTerminalStreamFrame,
        connection: &mut RemoteConnectionState,
        operation: &super::owner_domain::Operation<'_>,
        active: &super::shared_owner::StartedGitContinuation,
        peer: &auth::peer::StartedGitPeerObservation,
        latches: super::owner_domain::StartedGitTerminalLatches<'_>,
    ) -> Result<(), RemoteError> {
        let result = if !self.pending.as_ref().is_some_and(|p| {
            p.id == frame.delivery
                && self
                    .subscriptions
                    .get(&p.subscription)
                    .is_some_and(|s| s.terminal == frame.terminal)
        }) {
            Err(fault(ErrorCode::ScopeDenied))
        } else {
            self.check_target_started_git(
                connection,
                operation,
                active,
                peer,
                latches,
                &frame.terminal,
            )
        };
        if result.is_err() {
            connection.dispose();
            self.disconnect();
        }
        result
    }
    /// A delivery ACK is transport-owned, never a message from the peer. This
    /// method consumes the unforgeable outstanding frame after its final send.
    pub(super) fn complete_delivery(
        &mut self,
        connection: &RemoteConnectionState,
        frame: RemoteTerminalStreamFrame,
    ) -> Result<(), RemoteError> {
        if self.disconnected || self.channel != connection.connection_identity() {
            return Err(fault(ErrorCode::ScopeDenied));
        }
        self.commit_delivery(frame)
    }
    fn commit_delivery(&mut self, frame: RemoteTerminalStreamFrame) -> Result<(), RemoteError> {
        if !self
            .pending
            .as_ref()
            .is_some_and(|p| p.id == frame.delivery)
        {
            return Err(fault(ErrorCode::ScopeDenied));
        }
        let pending = self.pending.take().expect("matched delivery");
        if let Some(through) = pending.through {
            let subscription = self
                .subscriptions
                .get_mut(&pending.subscription)
                .ok_or_else(|| fault(ErrorCode::ResyncRequired))?;
            subscription.sent_through = Some(through);
            subscription.emission = None;
        }
        if pending.retire {
            self.subscriptions.remove(&pending.subscription);
            self.schedule.retain(|key| key != &pending.subscription);
            self.leases
                .retain(|_, (context, _)| context != &frame.terminal);
        }
        Ok(())
    }
}
