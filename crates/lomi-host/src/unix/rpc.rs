//! Local authenticated-owner RPC execution. Domain serialization spans intent,
//! OS effect and finalization; no SQLite transaction spans a PTY syscall.
use super::{
    Coordinator,
    owner_domain::{self as domain, Operation},
    shared_owner::Error as OwnerError,
};
use lomi_host_store::{
    DefaultShellProfile, HostStore, OperationBinding, ProjectRecord, StoreError, parameter_hash,
};
use lomi_remote_protocol::{ipc::*, rpc::*, streams::*, *};
use lomi_terminal::{
    Attachment, AuthenticatedConnection, ControlLease, SpawnProfile, TerminalEvent,
};
use std::{
    collections::{HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::{Arc, atomic::Ordering},
};
use std::{
    sync::{Mutex, MutexGuard, TryLockError},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

const SUBSCRIPTIONS: usize = 32;
const ASSEMBLY_BYTES: usize = 8 * 1024 * 1024;
struct Subscription {
    terminal: TerminalContext,
    attachment: Attachment,
    stream: Option<Emission>,
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
pub(super) struct ConnectionState {
    coordinator: Arc<Coordinator>,
    connection: AuthenticatedConnection,
    streams: super::local_streams::Streams,
    stream_turn: bool,
    subscriptions: HashMap<String, Subscription>,
    leases: HashMap<String, (TerminalContext, ControlLease)>,
    schedule: VecDeque<String>,
}

fn fault(code: ErrorCode) -> RemoteError {
    RemoteError::new(code, false, Effect::None, ErrorDetails::empty(), None)
        .expect("static safe error")
}
/// A failure that happened strictly BEFORE anything was journaled or executed
/// and that discloses nothing beyond the workspace view the consumer can already
/// read. Only these codes may be answered with an ordinary error response; every
/// other failure keeps the closed withhold-and-dispose behavior.
pub(super) fn pre_effect_rejection(error: RemoteError) -> Option<RemoteError> {
    (error.effect() == Effect::None
        && matches!(
            error.code(),
            ErrorCode::StaleEpoch
                | ErrorCode::RevisionConflict
                | ErrorCode::ResourceNotFound
                | ErrorCode::InvalidArgument
                | ErrorCode::SessionExited
                | ErrorCode::UnsupportedCapability
                | ErrorCode::HostBusy
                | ErrorCode::ResourceExhausted
        ))
    .then_some(error)
}
/// Ordinary-response form of a Store refusal that happened before any journal
/// write; closed (withhold) when the code is not a safe pre-effect refusal.
pub(super) fn stored_rejection(
    error: StoreError,
) -> Result<RemoteError, super::shared_owner::RemoteRenameError> {
    pre_effect_rejection(stored(error)).ok_or(super::shared_owner::RemoteRenameError::Closed)
}
pub(super) fn revision_conflict(
    expected: lomi_remote_protocol::DecimalU64,
    actual: lomi_remote_protocol::DecimalU64,
) -> RemoteError {
    RemoteError::new(
        ErrorCode::RevisionConflict,
        false,
        Effect::None,
        ErrorDetails::Revision(RevisionErrorDetails {
            expected_revision: expected,
            actual_revision: actual,
        }),
        None,
    )
    .expect("static safe error")
}
pub(super) fn stored(error: StoreError) -> RemoteError {
    fault(match error {
        StoreError::NotFound => ErrorCode::ResourceNotFound,
        StoreError::RevisionConflict | StoreError::Fenced => ErrorCode::StaleEpoch,
        StoreError::NativeWriterBusy => return native_writer_busy(),
        StoreError::IdempotencyConflict => ErrorCode::IdempotencyConflict,
        StoreError::ResourceExhausted => ErrorCode::ResourceExhausted,
        StoreError::Invalid => ErrorCode::InvalidArgument,
        _ => ErrorCode::ServiceUnavailable,
    })
}
fn native_writer_busy() -> RemoteError {
    RemoteError::new(
        ErrorCode::HostBusy,
        true,
        Effect::None,
        ErrorDetails::empty(),
        None,
    )
    .expect("typed native-writer busy refusal")
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
        .expect("ephemeral uncertain effect");
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
        _ => ErrorCode::ServiceUnavailable,
    })
}
fn before_deadline(operation: &Operation<'_>) -> Result<(), RemoteError> {
    operation
        .check()
        .map_err(|error| owner_fault(OwnerError::Domain(error)))
}
fn owner_fault(error: OwnerError) -> RemoteError {
    match error {
        OwnerError::Store(error) => stored(error),
        OwnerError::Domain(domain::Error::Deadline) => fault(ErrorCode::DeadlineExceeded),
        _ => fault(ErrorCode::ServiceUnavailable),
    }
}
/// The closure calls only a named typed API. It never receives a Store/Domain
/// guard. Every attempt has returned and dropped both guards before waiting.
pub(super) fn owner_call<T>(
    operation: &Operation<'_>,
    mut attempt: impl FnMut() -> Result<T, OwnerError>,
) -> Result<T, OwnerError> {
    loop {
        operation.check().map_err(OwnerError::Domain)?;
        match attempt() {
            Err(OwnerError::Domain(domain::Error::Busy))
            | Err(OwnerError::Store(StoreError::Busy)) => {
                operation.check().map_err(OwnerError::Domain)?;
                thread::park_timeout(
                    operation
                        .deadline()
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(1)),
                );
            }
            result => return result,
        }
    }
}
// Core-held effect callbacks consult only this original operation's atomic
// cancellation latch and clock, never Store, Domain or a provider.
fn terminal_effect_current(operation: &Operation<'_>) -> bool {
    operation.check().is_ok()
}
pub(super) fn actor_lock<'a>(
    owner: &'a Mutex<()>,
    operation: &Operation<'_>,
) -> Result<MutexGuard<'a, ()>, RemoteError> {
    loop {
        before_deadline(operation)?;
        match owner.try_lock() {
            Ok(guard) => {
                before_deadline(operation)?;
                return Ok(guard);
            }
            Err(TryLockError::Poisoned(_)) => return Err(fault(ErrorCode::ServiceUnavailable)),
            Err(TryLockError::WouldBlock) => thread::park_timeout(
                operation
                    .deadline()
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(1)),
            ),
        }
    }
}
fn local_rights() -> CapabilitySet {
    vec![
        Capability::WorkspaceRead,
        Capability::TerminalObserve,
        Capability::TerminalControl,
        Capability::TerminalManage,
        Capability::FilesRead,
        Capability::FilesWrite,
        Capability::GitRead,
        Capability::GitWrite,
        Capability::GitNetwork,
    ]
    .try_into()
    .expect("closed local terminal rights")
}
fn fresh<T: TryFrom<String>>() -> T
where
    T::Error: std::fmt::Debug,
{
    Uuid::new_v4()
        .to_string()
        .try_into()
        .expect("generated canonical UUID")
}
fn stream_frame(frame: TerminalStreamFrame) -> LocalStreamEvent {
    LocalStreamEvent::Terminal(frame)
}
impl ConnectionState {
    pub(super) fn new(
        coordinator: Arc<Coordinator>,
        operation: &Operation<'_>,
    ) -> Result<Self, LocalError> {
        let actor = ConsumerAuthorizationId::from_bytes(
            owner_call(operation, || coordinator.owner.identity(operation))
                .map_err(super::owner_error)?
                .host_id
                .to_bytes(),
        )
        .map_err(|_| LocalError::Unavailable)?;
        Ok(Self {
            coordinator,
            connection: AuthenticatedConnection::new(actor),
            streams: super::local_streams::Streams::default(),
            stream_turn: false,
            subscriptions: HashMap::new(),
            leases: HashMap::new(),
            schedule: VecDeque::new(),
        })
    }
    fn prune_leases(&mut self) {
        self.leases.retain(|_, (context, lease)| {
            self.coordinator.terminals.lease_is_current(
                context.session_id,
                context.session_epoch,
                &self.connection,
                lease,
            )
        });
    }
    pub(super) fn next_event(&mut self, operation: &Operation<'_>) -> Option<LocalStreamEvent> {
        operation.check().ok()?;
        self.prune_leases();
        let active = if self.subscriptions.is_empty() {
            Ok(None)
        } else {
            self.coordinator.started_git_terminal_continuation()
        };
        self.stream_turn = !self.stream_turn;
        if self.stream_turn
            && let Some(event) = self.streams.next(&self.coordinator, operation)
        {
            return Some(event);
        }
        match active {
            Ok(Some(active)) => self.next_terminal_event(operation, Some(&active)),
            Ok(None) => self.next_terminal_event(operation, None),
            Err(_) => None,
        }
        .or_else(|| self.streams.next(&self.coordinator, operation))
    }
    pub(super) fn acknowledge_stream(
        &mut self,
        ack: LocalStreamAck,
    ) -> Result<LocalResult, LocalError> {
        self.streams.acknowledge(ack)
    }
    fn next_terminal_event(
        &mut self,
        operation: &Operation<'_>,
        active: Option<&super::shared_owner::StartedGitContinuation>,
    ) -> Option<LocalStreamEvent> {
        // Rotation persists across calls. Active assemblies share one aggregate
        // 8 MiB budget; finish those before allocating the next serialized delta.
        let assembling = self.subscriptions.values().any(|s| s.stream.is_some());
        for _ in 0..self.schedule.len() {
            let key = self.schedule.pop_front()?;
            let Some(subscription) = self.subscriptions.get(&key) else {
                continue;
            };
            let terminal = subscription.terminal.clone();
            let has_emission = subscription.stream.is_some();
            self.schedule.push_back(key.clone());
            if assembling && !has_emission {
                continue;
            }
            if let Some(active) = active {
                let coordinator = self.coordinator.clone();
                let current = match with_started_git_terminal_current(
                    &coordinator,
                    operation,
                    active,
                    &terminal,
                    |current| Ok(current()),
                ) {
                    Ok(current) => current,
                    Err(_) => continue,
                };
                if !current {
                    continue;
                }
            }
            let subscription = self.subscriptions.get_mut(&key)?;
            let subscription_id: SubscriptionId = key.clone().try_into().ok()?;
            if let Some(emission) = &mut subscription.stream {
                let terminal = subscription.terminal.clone();
                if emission.metadata {
                    emission.metadata = false;
                    return Some(stream_frame(TerminalStreamFrame::DeltaMetadata(
                        TerminalDeltaMetadata {
                            terminal,
                            subscription_id,
                            previous_seq: TerminalSeq(DecimalU64(emission.previous?)),
                            through_seq: TerminalSeq(DecimalU64(emission.through)),
                            chunk_count: ChunkCount((emission.bytes.len().div_ceil(16384)) as u32),
                            total_bytes: DecimalU64(emission.bytes.len() as u64),
                            working_directory: emission.working_directory.clone().into(),
                        },
                    )));
                }
                if emission.position < emission.bytes.len() {
                    let index = emission.position / 16384;
                    let end = (emission.position + 16384).min(emission.bytes.len());
                    let bytes = BoundedList(emission.bytes[emission.position..end].to_vec());
                    emission.position = end;
                    return Some(stream_frame(if emission.previous.is_some() {
                        TerminalStreamFrame::DeltaChunk(TerminalDeltaChunk {
                            terminal,
                            subscription_id,
                            index: ChunkIndex(index as u32),
                            bytes,
                        })
                    } else {
                        TerminalStreamFrame::SnapshotChunk(TerminalSnapshotChunk {
                            terminal,
                            subscription_id,
                            index: ChunkIndex(index as u32),
                            bytes,
                        })
                    }));
                }
                let complete = if emission.previous.is_some() {
                    TerminalStreamFrame::DeltaComplete(TerminalDeltaComplete {
                        terminal,
                        subscription_id,
                        through_seq: TerminalSeq(DecimalU64(emission.through)),
                    })
                } else {
                    TerminalStreamFrame::SnapshotComplete(TerminalSnapshotComplete {
                        terminal,
                        subscription_id,
                        through_seq: TerminalSeq(DecimalU64(emission.through)),
                        output_offset: DecimalU64(emission.offset),
                    })
                };
                subscription.sent_through = Some(emission.through);
                subscription.stream = None;
                return Some(stream_frame(complete));
            }
            if let Some(queued) = subscription.attachment.try_next_with_metadata() {
                match &*queued.event {
                    TerminalEvent::State(delta) => {
                        let working_directory = queued.working_directory.clone();
                        if let Ok(bytes) = serde_json::to_vec(&**delta)
                            && !bytes.is_empty()
                            && bytes.len().saturating_add(
                                working_directory
                                    .as_ref()
                                    .map_or(0, |path| path.as_str().len()),
                            ) <= ASSEMBLY_BYTES
                        {
                            subscription.stream = Some(Emission {
                                bytes,
                                position: 0,
                                previous: Some(delta.previous_sequence().0),
                                through: delta.sequence().0,
                                offset: delta.output_offset().0,
                                metadata: true,
                                working_directory,
                            });
                            return self.next_event(operation);
                        }
                        let terminal = subscription.terminal.clone();
                        self.subscriptions.remove(&key);
                        return Some(stream_frame(TerminalStreamFrame::ResyncRequired(
                            TerminalResync {
                                terminal,
                                subscription_id,
                                reason: ResyncReason::SnapshotInvalid,
                            },
                        )));
                    }
                    TerminalEvent::ControlChanged {
                        sequence,
                        version,
                        controlled,
                    } => {
                        subscription.sent_through = Some(*sequence);
                        return Some(stream_frame(TerminalStreamFrame::Delta(TerminalDelta {
                            terminal: subscription.terminal.clone(),
                            subscription_id,
                            seq: TerminalSeq(DecimalU64(*sequence)),
                            change: TerminalChange::ControlChanged(TerminalControlChanged {
                                terminal: subscription.terminal.clone(),
                                lease_version: DecimalU64(*version),
                                controlled: *controlled,
                            }),
                        })));
                    }
                    TerminalEvent::Exited { sequence } => {
                        let terminal = subscription.terminal.clone();
                        let frame = stream_frame(TerminalStreamFrame::Delta(TerminalDelta {
                            terminal: terminal.clone(),
                            subscription_id,
                            seq: TerminalSeq(DecimalU64(*sequence)),
                            change: TerminalChange::Exit(TerminalExit { exit_code: None }),
                        }));
                        self.subscriptions.remove(&key);
                        self.schedule.retain(|id| id != &key);
                        self.leases.retain(|_, (context, _)| context != &terminal);
                        return Some(frame);
                    }
                    TerminalEvent::ResyncRequired => {
                        let terminal = subscription.terminal.clone();
                        self.subscriptions.remove(&key);
                        return Some(stream_frame(TerminalStreamFrame::ResyncRequired(
                            TerminalResync {
                                terminal,
                                subscription_id,
                                reason: ResyncReason::SubscriberOverflow,
                            },
                        )));
                    }
                }
            }
        }
        None
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
    fn attach(
        &mut self,
        context: TerminalContext,
        operation: &Operation<'_>,
    ) -> Result<TerminalSnapshotMetadata, RemoteError> {
        if self.subscriptions.len() >= SUBSCRIPTIONS {
            return Err(fault(ErrorCode::ResourceExhausted));
        }
        check_terminal(&self.coordinator, &context, operation)?;
        let attachment = self
            .coordinator
            .terminals
            .attach(context.session_id, context.session_epoch, &self.connection)
            .map_err(terminal)?;
        self.register_attachment(context, attachment)
    }
    fn attach_started_git(
        &mut self,
        context: TerminalContext,
        operation: &Operation<'_>,
        active: &super::shared_owner::StartedGitContinuation,
    ) -> Result<TerminalSnapshotMetadata, RemoteError> {
        if self.subscriptions.len() >= SUBSCRIPTIONS {
            return Err(fault(ErrorCode::ResourceExhausted));
        }
        let coordinator = self.coordinator.clone();
        let connection = self.connection.clone();
        let attachment = with_started_git_terminal_current(
            &coordinator,
            operation,
            active,
            &context,
            |current| {
                coordinator
                    .terminals
                    .attach_checked(
                        context.session_id,
                        context.session_epoch,
                        &connection,
                        current,
                    )
                    .map_err(terminal)
            },
        )?;
        self.register_attachment(context, attachment)
    }
    fn register_attachment(
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
            .filter_map(|s| s.stream.as_ref())
            .map(|s| {
                s.bytes.len().saturating_add(
                    s.working_directory
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
            chunk_count: ChunkCount(bytes.len().div_ceil(16384) as u32),
            total_bytes: DecimalU64(bytes.len() as u64),
            working_directory: working_directory.clone().into(),
        };
        self.schedule.push_back(id.clone());
        self.subscriptions.insert(
            id,
            Subscription {
                terminal: context,
                stream: Some(Emission {
                    bytes,
                    position: 0,
                    previous: None,
                    through: snapshot.sequence.0,
                    offset: snapshot.output_offset.0,
                    metadata: false,
                    working_directory: None,
                }),
                attachment,
                sent_through: None,
            },
        );
        Ok(result)
    }
}
impl Drop for ConnectionState {
    fn drop(&mut self) {
        self.coordinator.terminals.disconnect(&self.connection);
        self.leases.clear();
        self.subscriptions.clear();
    }
}
fn project(
    coordinator: &Coordinator,
    context: &WorkspaceContext,
    operation: &Operation<'_>,
) -> Result<ProjectRecord, RemoteError> {
    let project = owner_call(operation, || {
        coordinator.owner.workspace(operation, context.workspace_id)
    })
    .map_err(owner_fault)?;
    if &project.state.context != context {
        return Err(fault(ErrorCode::StaleEpoch));
    }
    Ok(project)
}
fn pane(layout: &TerminalLayout, id: PaneId) -> Option<&TerminalPane> {
    match layout {
        TerminalLayout::Pane { pane } if pane.pane_id == id => Some(pane),
        TerminalLayout::Split { first, second, .. } => pane(first, id).or_else(|| pane(second, id)),
        _ => None,
    }
}
fn pane_mut(layout: &mut TerminalLayout, id: PaneId) -> Option<&mut TerminalPane> {
    match layout {
        TerminalLayout::Pane { pane } if pane.pane_id == id => Some(pane),
        TerminalLayout::Split { first, second, .. } => {
            pane_mut(first, id).or_else(|| pane_mut(second, id))
        }
        _ => None,
    }
}
fn find_pane(state: &WorkspaceState, id: PaneId) -> Option<&TerminalPane> {
    state.tabs.0.iter().find_map(|tab| pane(&tab.layout, id))
}
fn check_terminal(
    coordinator: &Coordinator,
    context: &TerminalContext,
    operation: &Operation<'_>,
) -> Result<(), RemoteError> {
    let project = project(coordinator, &context.workspace, operation)?;
    if find_pane(&project.state, context.pane_id).and_then(|p| p.session.as_ref()) != Some(context)
    {
        return Err(fault(ErrorCode::StaleEpoch));
    }
    Ok(())
}

/// Run one local terminal operation under the exact StartedGit owner snapshot.
/// The terminal Core callback only samples the retained Domain guard and local
/// descriptor; the Store handle is dropped before this function reaches Core.
fn with_started_git_terminal_current<T>(
    coordinator: &Coordinator,
    operation: &Operation<'_>,
    active: &super::shared_owner::StartedGitContinuation,
    context: &TerminalContext,
    effect: impl FnOnce(&mut dyn FnMut() -> bool) -> Result<T, RemoteError>,
) -> Result<T, RemoteError> {
    let actor = coordinator
        .workspace_lock(context.workspace.workspace_id)
        .map_err(|_| fault(ErrorCode::ServiceUnavailable))?;
    let _actor = actor_lock(&actor, operation)?;
    let turn = owner_call(operation, || {
        coordinator
            .owner
            .try_started_git_local_terminal_turn(operation, active, context)
    })
    .map_err(owner_fault)?;
    let mut current = || turn.terminal_current();
    effect(&mut current)
}

/// Convert the retained owner turn to its lock free watch before a PTY call.
/// The workspace actor remains serialized, while no Domain/Store guard crosses
/// a blocking terminal input or resize syscall.
fn with_started_git_terminal_io_current<T>(
    coordinator: &Coordinator,
    operation: &Operation<'_>,
    active: &super::shared_owner::StartedGitContinuation,
    context: &TerminalContext,
    effect: impl FnOnce(&mut dyn FnMut() -> bool) -> Result<T, RemoteError>,
) -> Result<T, RemoteError> {
    let actor = coordinator
        .workspace_lock(context.workspace.workspace_id)
        .map_err(|_| fault(ErrorCode::ServiceUnavailable))?;
    let _actor = actor_lock(&actor, operation)?;
    let turn = owner_call(operation, || {
        coordinator
            .owner
            .try_started_git_local_terminal_turn(operation, active, context)
    })
    .map_err(owner_fault)?;
    let watch = turn.into_io_watch();
    let mut current = || watch.terminal_current();
    effect(&mut current)
}

fn is_terminal_call(call: &RpcCall) -> bool {
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

/// Owner-loop observation, independent of connection/view activity. Never hold
/// a store/model lock while waiting for a workspace actor or doing OS cleanup.
pub(super) fn reconcile_terminal_lifecycle(
    coordinator: &Coordinator,
    operation: &Operation<'_>,
) -> Result<(), LocalError> {
    let exits = coordinator
        .terminals
        .exited_sessions()
        .map_err(|_| LocalError::Unavailable)?;
    if exits.is_empty() {
        return Ok(());
    }
    let projects = owner_call(operation, || coordinator.owner.workspaces(operation))
        .map_err(super::owner_error)?;
    for exit in exits {
        let terminal = projects.iter().find_map(|project| {
            fn find(
                layout: &TerminalLayout,
                id: TerminalSessionId,
                epoch: SessionEpoch,
            ) -> Option<TerminalContext> {
                match layout {
                    TerminalLayout::Pane { pane } => pane
                        .session
                        .as_ref()
                        .filter(|s| s.session_id == id && s.session_epoch == epoch)
                        .cloned(),
                    TerminalLayout::Split { first, second, .. } => {
                        find(first, id, epoch).or_else(|| find(second, id, epoch))
                    }
                }
            }
            project
                .state
                .tabs
                .0
                .iter()
                .find_map(|tab| find(&tab.layout, exit.session_id, exit.session_epoch))
        });
        let Some(terminal) = terminal else { continue };
        let owner = coordinator.workspace_lock(terminal.workspace.workspace_id)?;
        let _guard = match owner.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => continue,
            Err(TryLockError::Poisoned(_)) => return Err(LocalError::Unavailable),
        };
        if ensure_workspace_settled(coordinator, terminal.workspace.workspace_id).is_err() {
            continue;
        }
        let mut turn = owner_call(operation, || {
            coordinator.owner.begin_terminal_exit(operation, &terminal)
        })
        .map_err(super::owner_error)?;
        owner_call(operation, || turn.try_commit()).map_err(super::owner_error)?;
        if coordinator
            .terminals
            .at_capacity()
            .map_err(|_| LocalError::Unavailable)?
        {
            let mut persisted = Ok(false);
            coordinator
                .terminals
                .retire_exited(exit.session_id, exit.session_epoch, || {
                    persisted = owner_call(operation, || {
                        coordinator
                            .owner
                            .begin_terminal_retired(operation, &terminal)
                    })
                    .and_then(|mut turn| owner_call(operation, || turn.try_commit()))
                    .map_err(super::owner_error);
                    matches!(persisted, Ok(true))
                })
                .map_err(|_| LocalError::Unavailable)?;
            persisted?;
        }
    }
    Ok(())
}

pub(super) fn dispatch(
    coordinator: &Coordinator,
    connection: &mut ConnectionState,
    request: RpcRequest,
    operation: &Operation<'_>,
) -> RpcResponse {
    let operation_id = request.call.operation_binding().map(|b| b.operation_id);
    let request_id = request.request_id;
    match execute(coordinator, connection, request.call, operation) {
        Ok(result) => RpcResponse::Result {
            v: ApplicationMajor,
            request_id,
            result,
        },
        Err(error) => RpcResponse::Error {
            v: ApplicationMajor,
            request_id,
            operation_id: if error.effect() != Effect::None {
                operation_id
            } else {
                None
            },
            error,
        },
    }
}
fn lease_result(context: TerminalContext, lease: &ControlLease) -> TerminalLeaseResult {
    TerminalLeaseResult {
        terminal: context,
        lease: lease.wire_binding(),
        expires_in_ms: TimeoutMs::new(5000).expect("fixed lease TTL"),
        next_input_id: DecimalU64(lease.next_input_id),
        next_input_seq: InputSeq(DecimalU64(lease.next_input_seq)),
        next_resize_seq: ResizeSeq(DecimalU64(lease.next_resize_seq)),
    }
}
fn execute(
    coordinator: &Coordinator,
    connection: &mut ConnectionState,
    call: RpcCall,
    operation: &Operation<'_>,
) -> Result<RpcResult, RemoteError> {
    before_deadline(operation)?;
    connection.prune_leases();
    if coordinator.stopping.load(Ordering::Acquire) {
        return Err(fault(ErrorCode::ServiceUnavailable));
    }
    if is_terminal_call(&call)
        && let Some(active) = coordinator
            .started_git_terminal_continuation()
            .map_err(|_| fault(ErrorCode::ServiceUnavailable))?
    {
        return execute_started_git_terminal(coordinator, connection, call, operation, &active);
    }
    match call {
        RpcCall::WorkspaceGet(params) => Ok(RpcResult::WorkspaceGet(
            project(coordinator, &params.context, operation)?.state,
        )),
        RpcCall::WorkspaceSubscribe(params) => {
            connection
                .streams
                .subscribe_workspace(coordinator, &params, operation)
        }
        RpcCall::WorkspaceCapabilities(params) => {
            project(coordinator, &params.context, operation)?;
            let profiles = owner_call(operation, || {
                coordinator
                    .owner
                    .shell_profiles(operation, params.context.workspace_id)
            })
            .map_err(owner_fault)?;
            Ok(RpcResult::WorkspaceCapabilities(
                WorkspaceCapabilitiesResult {
                    capabilities: local_rights(),
                    profiles: BoundedList(profiles),
                },
            ))
        }
        call @ (RpcCall::FilesList(_)
        | RpcCall::FilesStat(_)
        | RpcCall::FilesRead(_)
        | RpcCall::FilesSearchNames(_)) => {
            let context = match &call {
                RpcCall::FilesList(p) => &p.context,
                RpcCall::FilesStat(p) => &p.context,
                RpcCall::FilesRead(p) => &p.context,
                RpcCall::FilesSearchNames(p) => &p.context,
                _ => unreachable!("closed file read branch"),
            };
            let project = project(coordinator, context, operation)?;
            let files = coordinator.files.get(
                context.workspace_id,
                context.workspace_epoch,
                &project.local_root,
            )?;
            let result = super::remote_files::execute_read(&files, &call)?;
            before_deadline(operation)?;
            Ok(result)
        }
        RpcCall::FilesWatch(params) => {
            connection
                .streams
                .watch_files(coordinator, &params, operation)
        }
        call @ (RpcCall::GitRepositories(_)
        | RpcCall::GitStatus(_)
        | RpcCall::GitDiff(_)
        | RpcCall::GitLog(_)
        | RpcCall::GitShow(_)) => {
            let context = match &call {
                RpcCall::GitRepositories(p) => &p.context,
                RpcCall::GitStatus(p) => &p.context,
                RpcCall::GitDiff(p) => &p.context,
                RpcCall::GitLog(p) => &p.context,
                RpcCall::GitShow(p) => &p.context,
                _ => unreachable!("closed Git read branch"),
            };
            let project = project(coordinator, context, operation)?;
            coordinator
                .git_reads
                .read_local(context.clone(), project.local_root, call, operation)
        }
        RpcCall::TerminalAttach(params) => connection
            .attach(params.terminal, operation)
            .map(RpcResult::TerminalAttach),
        RpcCall::TerminalSnapshot(params) => connection
            .attach(params.terminal, operation)
            .map(RpcResult::TerminalSnapshot),
        RpcCall::TerminalAck(params) => {
            check_terminal(coordinator, &params.terminal, operation)?;
            let sub = connection
                .subscriptions
                .get(&String::from(params.subscription_id.clone()))
                .filter(|s| s.terminal == params.terminal)
                .ok_or_else(|| fault(ErrorCode::ResyncRequired))?;
            if sub
                .sent_through
                .is_none_or(|sent| params.through_seq.0.0 > sent)
            {
                return Err(fault(ErrorCode::ResyncRequired));
            }
            sub.attachment
                .acknowledge(&connection.connection, params.through_seq.0.0)
                .map_err(terminal)?;
            Ok(RpcResult::TerminalAck(TerminalAckResult {
                subscription_id: params.subscription_id,
                through_seq: params.through_seq,
            }))
        }
        RpcCall::TerminalClaim(params) => {
            check_terminal(coordinator, &params.terminal, operation)?;
            let sub = connection
                .subscriptions
                .get(&String::from(params.subscription_id))
                .filter(|s| s.terminal == params.terminal)
                .ok_or_else(|| fault(ErrorCode::ResyncRequired))?;
            if sub
                .sent_through
                .is_none_or(|sent| params.rendered_through_seq.0.0 > sent)
            {
                return Err(fault(ErrorCode::ResyncRequired));
            }
            sub.attachment
                .acknowledge(&connection.connection, params.rendered_through_seq.0.0)
                .map_err(terminal)?;
            // A failed claim must preserve an existing usable credential.
            // Only a successful replacement may retire the old cache entry.
            if connection
                .leases
                .values()
                .filter(|(target, _)| target.session_id != params.terminal.session_id)
                .count()
                >= SUBSCRIPTIONS
            {
                return Err(fault(ErrorCode::ResourceExhausted));
            }
            let lease = coordinator
                .terminals
                .claim(
                    params.terminal.session_id,
                    params.terminal.session_epoch,
                    &connection.connection,
                )
                .map_err(terminal)?;
            connection
                .leases
                .retain(|_, (target, _)| target.session_id != params.terminal.session_id);
            let result = lease_result(params.terminal.clone(), &lease);
            connection
                .leases
                .insert(lease.wire_token(), (params.terminal, lease));
            Ok(RpcResult::TerminalClaim(result))
        }
        RpcCall::TerminalRenew(params) => {
            check_terminal(coordinator, &params.terminal, operation)?;
            let lease = connection.lease(&params.terminal, &params.lease)?;
            let renewed = coordinator
                .terminals
                .renew(
                    params.terminal.session_id,
                    params.terminal.session_epoch,
                    &connection.connection,
                    &lease,
                )
                .map_err(terminal)?;
            let result = lease_result(params.terminal.clone(), &renewed);
            connection
                .leases
                .insert(renewed.wire_token(), (params.terminal, renewed));
            Ok(RpcResult::TerminalRenew(result))
        }
        RpcCall::TerminalRelease(params) => {
            check_terminal(coordinator, &params.terminal, operation)?;
            let lease = connection.lease(&params.terminal, &params.lease)?;
            coordinator
                .terminals
                .release(
                    params.terminal.session_id,
                    params.terminal.session_epoch,
                    &connection.connection,
                    &lease,
                )
                .map_err(terminal)?;
            connection.leases.remove(&lease.wire_token());
            Ok(RpcResult::TerminalRelease(TerminalReleaseResult {
                terminal: params.terminal,
                released: true,
            }))
        }
        RpcCall::TerminalInput(params) => {
            // Pin the local workspace layout before the fresh Store check.
            // Never acquire Store from the final Core-held physical-effect gate.
            let owner = coordinator
                .workspace_lock(params.terminal.workspace.workspace_id)
                .map_err(|_| fault(ErrorCode::ServiceUnavailable))?;
            let _actor = actor_lock(&owner, operation)?;
            check_terminal(coordinator, &params.terminal, operation)?;
            let lease = connection.lease(&params.terminal, &params.lease)?;
            let context = params.terminal.clone();
            before_deadline(operation)?;
            let receipt = coordinator
                .terminals
                .input(
                    context.session_id,
                    context.session_epoch,
                    &connection.connection,
                    &lease,
                    params.input_id.0,
                    params.input_seq.0.0,
                    &params.bytes.0,
                    || terminal_effect_current(operation),
                )
                .map_err(|error| {
                    if error == lomi_terminal::Error::SequenceConflict && operation.check().is_err()
                    {
                        fault(ErrorCode::DeadlineExceeded)
                    } else {
                        terminal(error)
                    }
                })?;
            if receipt.accepted_bytes == 0 && operation.check().is_err() {
                return Err(fault(ErrorCode::DeadlineExceeded));
            }
            Ok(RpcResult::TerminalInput(
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
            ))
        }
        RpcCall::TerminalResize(params) => {
            // Pin the local workspace layout before the fresh Store check.
            // Never acquire Store from the final Core-held physical-effect gate.
            let owner = coordinator
                .workspace_lock(params.terminal.workspace.workspace_id)
                .map_err(|_| fault(ErrorCode::ServiceUnavailable))?;
            let _actor = actor_lock(&owner, operation)?;
            check_terminal(coordinator, &params.terminal, operation)?;
            let lease = connection.lease(&params.terminal, &params.lease)?;
            let context = params.terminal.clone();
            before_deadline(operation)?;
            coordinator
                .terminals
                .resize(
                    context.session_id,
                    context.session_epoch,
                    &connection.connection,
                    &lease,
                    params.resize_seq.0.0,
                    params.rows.0 as u16,
                    params.columns.0 as u16,
                    || terminal_effect_current(operation),
                )
                .map_err(|error| {
                    if error == lomi_terminal::Error::SequenceConflict && operation.check().is_err()
                    {
                        fault(ErrorCode::DeadlineExceeded)
                    } else {
                        terminal(error)
                    }
                })?;
            Ok(RpcResult::TerminalResize(TerminalResizeResult {
                terminal: context,
                resize_seq: params.resize_seq,
                columns: params.columns,
                rows: params.rows,
            }))
        }
        RpcCall::OperationStatus(params) => {
            project(coordinator, &params.context, operation)?;
            owner_call(operation, || {
                coordinator.owner.lookup_operation(
                    operation,
                    connection.connection.actor(),
                    params.context.workspace_id,
                    params.operation_id,
                    &local_rights(),
                )
            })
            .map_err(owner_fault)?
            .map(RpcResult::OperationStatus)
            .ok_or_else(|| fault(ErrorCode::OperationNotFound))
        }
        RpcCall::OperationCancel(params) => {
            let owner = coordinator
                .workspace_lock(params.context.workspace_id)
                .map_err(|_| fault(ErrorCode::ServiceUnavailable))?;
            let _guard = actor_lock(&owner, operation)?;
            project(coordinator, &params.context, operation)?;
            let rights = local_rights();
            let mut turn = owner_call(operation, || {
                coordinator.owner.begin_cancel_operation(
                    operation,
                    connection.connection.actor(),
                    params.context.workspace_id,
                    params.operation_id,
                    &rights,
                )
            })
            .map_err(owner_fault)?;
            owner_call(operation, || turn.try_commit())
                .map_err(owner_fault)?
                .map(RpcResult::OperationCancel)
                .ok_or_else(|| fault(ErrorCode::OperationNotFound))
        }
        call if matches!(
            call,
            RpcCall::TerminalCreate(_)
                | RpcCall::TerminalSplit(_)
                | RpcCall::TerminalRename(_)
                | RpcCall::TerminalMove(_)
                | RpcCall::TerminalClose(_)
                | RpcCall::TerminalRestart(_)
        ) =>
        {
            mutate(coordinator, connection, call, operation)
        }
        call if matches!(
            call,
            RpcCall::FilesCreate(_)
                | RpcCall::FilesMkdir(_)
                | RpcCall::FilesRename(_)
                | RpcCall::FilesRemove(_)
        ) =>
        {
            mutate_files(coordinator, connection, call, operation)
        }
        call if matches!(
            call,
            RpcCall::GitStage(_)
                | RpcCall::GitUnstage(_)
                | RpcCall::GitCommit(_)
                | RpcCall::GitFetch(_)
                | RpcCall::GitPull(_)
                | RpcCall::GitPush(_)
        ) =>
        {
            mutate_git(coordinator, connection, call, operation)
        }
        _ => Err(fault(ErrorCode::UnsupportedCapability)),
    }
}

fn execute_started_git_terminal(
    coordinator: &Coordinator,
    connection: &mut ConnectionState,
    call: RpcCall,
    operation: &Operation<'_>,
    active: &super::shared_owner::StartedGitContinuation,
) -> Result<RpcResult, RemoteError> {
    match call {
        RpcCall::TerminalAttach(params) => connection
            .attach_started_git(params.terminal, operation, active)
            .map(RpcResult::TerminalAttach),
        RpcCall::TerminalSnapshot(params) => connection
            .attach_started_git(params.terminal, operation, active)
            .map(RpcResult::TerminalSnapshot),
        RpcCall::TerminalAck(params) => {
            let context = params.terminal.clone();
            with_started_git_terminal_current(coordinator, operation, active, &context, |current| {
                let sub = connection
                    .subscriptions
                    .get(&String::from(params.subscription_id.clone()))
                    .filter(|sub| sub.terminal == context)
                    .ok_or_else(|| fault(ErrorCode::ResyncRequired))?;
                if sub
                    .sent_through
                    .is_none_or(|sent| params.through_seq.0.0 > sent)
                {
                    return Err(fault(ErrorCode::ResyncRequired));
                }
                sub.attachment
                    .acknowledge_checked(
                        &connection.connection,
                        params.through_seq.0.0,
                        &mut *current,
                    )
                    .map_err(terminal)?;
                Ok(RpcResult::TerminalAck(TerminalAckResult {
                    subscription_id: params.subscription_id,
                    through_seq: params.through_seq,
                }))
            })
        }
        RpcCall::TerminalClaim(params) => {
            let context = params.terminal.clone();
            with_started_git_terminal_current(coordinator, operation, active, &context, |current| {
                let sub = connection
                    .subscriptions
                    .get(&String::from(params.subscription_id.clone()))
                    .filter(|sub| sub.terminal == context)
                    .ok_or_else(|| fault(ErrorCode::ResyncRequired))?;
                if sub
                    .sent_through
                    .is_none_or(|sent| params.rendered_through_seq.0.0 > sent)
                {
                    return Err(fault(ErrorCode::ResyncRequired));
                }
                sub.attachment
                    .acknowledge_checked(
                        &connection.connection,
                        params.rendered_through_seq.0.0,
                        &mut *current,
                    )
                    .map_err(terminal)?;
                if connection
                    .leases
                    .values()
                    .filter(|(target, _)| target.session_id != context.session_id)
                    .count()
                    >= SUBSCRIPTIONS
                {
                    return Err(fault(ErrorCode::ResourceExhausted));
                }
                let lease = coordinator
                    .terminals
                    .claim_checked(
                        context.session_id,
                        context.session_epoch,
                        &connection.connection,
                        &mut *current,
                    )
                    .map_err(terminal)?;
                connection
                    .leases
                    .retain(|_, (target, _)| target.session_id != context.session_id);
                let result = lease_result(context.clone(), &lease);
                connection
                    .leases
                    .insert(lease.wire_token(), (context.clone(), lease));
                Ok(RpcResult::TerminalClaim(result))
            })
        }
        RpcCall::TerminalRenew(params) => {
            let context = params.terminal.clone();
            with_started_git_terminal_current(coordinator, operation, active, &context, |current| {
                let lease = connection.lease(&context, &params.lease)?;
                let renewed = coordinator
                    .terminals
                    .renew_checked(
                        context.session_id,
                        context.session_epoch,
                        &connection.connection,
                        &lease,
                        current,
                    )
                    .map_err(terminal)?;
                let result = lease_result(context.clone(), &renewed);
                connection
                    .leases
                    .insert(renewed.wire_token(), (context.clone(), renewed));
                Ok(RpcResult::TerminalRenew(result))
            })
        }
        RpcCall::TerminalRelease(params) => {
            let context = params.terminal.clone();
            with_started_git_terminal_current(coordinator, operation, active, &context, |current| {
                let lease = connection.lease(&context, &params.lease)?;
                coordinator
                    .terminals
                    .release_checked(
                        context.session_id,
                        context.session_epoch,
                        &connection.connection,
                        &lease,
                        current,
                    )
                    .map_err(terminal)?;
                connection.leases.remove(&lease.wire_token());
                Ok(RpcResult::TerminalRelease(TerminalReleaseResult {
                    terminal: context.clone(),
                    released: true,
                }))
            })
        }
        RpcCall::TerminalInput(params) => {
            let context = params.terminal.clone();
            with_started_git_terminal_io_current(
                coordinator,
                operation,
                active,
                &context,
                |current| {
                    let lease = connection.lease(&context, &params.lease)?;
                    before_deadline(operation)?;
                    let receipt = coordinator
                        .terminals
                        .input(
                            context.session_id,
                            context.session_epoch,
                            &connection.connection,
                            &lease,
                            params.input_id.0,
                            params.input_seq.0.0,
                            &params.bytes.0,
                            || current(),
                        )
                        .map_err(|error| {
                            if error == lomi_terminal::Error::SequenceConflict
                                && operation.check().is_err()
                            {
                                fault(ErrorCode::DeadlineExceeded)
                            } else {
                                terminal(error)
                            }
                        })?;
                    if receipt.accepted_bytes == 0 && operation.check().is_err() {
                        return Err(fault(ErrorCode::DeadlineExceeded));
                    }
                    Ok(RpcResult::TerminalInput(
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
                    ))
                },
            )
        }
        RpcCall::TerminalResize(params) => {
            let context = params.terminal.clone();
            with_started_git_terminal_io_current(
                coordinator,
                operation,
                active,
                &context,
                |current| {
                    let lease = connection.lease(&context, &params.lease)?;
                    before_deadline(operation)?;
                    coordinator
                        .terminals
                        .resize(
                            context.session_id,
                            context.session_epoch,
                            &connection.connection,
                            &lease,
                            params.resize_seq.0.0,
                            params.rows.0 as u16,
                            params.columns.0 as u16,
                            || current(),
                        )
                        .map_err(|error| {
                            if error == lomi_terminal::Error::SequenceConflict
                                && operation.check().is_err()
                            {
                                fault(ErrorCode::DeadlineExceeded)
                            } else {
                                terminal(error)
                            }
                        })?;
                    Ok(RpcResult::TerminalResize(TerminalResizeResult {
                        terminal: context.clone(),
                        resize_seq: params.resize_seq,
                        columns: params.columns,
                        rows: params.rows,
                    }))
                },
            )
        }
        _ => Err(fault(ErrorCode::UnsupportedCapability)),
    }
}
fn mutation(call: &RpcCall) -> &MutationContext {
    match call {
        RpcCall::TerminalCreate(p) => &p.mutation,
        RpcCall::TerminalSplit(p) => &p.mutation,
        RpcCall::TerminalRename(p) => &p.mutation,
        RpcCall::TerminalMove(p) => &p.mutation,
        RpcCall::TerminalClose(p) => &p.mutation,
        RpcCall::TerminalRestart(p) => &p.mutation,
        _ => unreachable!("terminal mutation only"),
    }
}

fn file_mutation_context(call: &RpcCall) -> Option<&FileMutationContext> {
    match call {
        RpcCall::FilesCreate(p) | RpcCall::FilesMkdir(p) => Some(&p.mutation),
        RpcCall::FilesRename(p) => Some(&p.mutation),
        RpcCall::FilesRemove(p) => Some(&p.mutation),
        _ => None,
    }
}

fn file_receipt_result(method: Method, receipt: OperationReceipt) -> RpcResult {
    match method {
        Method::FilesCreate => RpcResult::FilesCreate(receipt),
        Method::FilesMkdir => RpcResult::FilesMkdir(receipt),
        Method::FilesRename => RpcResult::FilesRename(receipt),
        Method::FilesRemove => RpcResult::FilesRemove(receipt),
        _ => unreachable!("closed Explorer mutation method"),
    }
}

fn mutate_files(
    coordinator: &Coordinator,
    connection: &ConnectionState,
    call: RpcCall,
    operation: &Operation<'_>,
) -> Result<RpcResult, RemoteError> {
    let mutation = file_mutation_context(&call).ok_or_else(|| fault(ErrorCode::InvalidArgument))?;
    let method = call.method();
    let context = &mutation.context;
    let workspace = context.workspace_id;
    let initial = project(coordinator, context, operation)?;
    let initial_plan = super::shared_owner::RemoteFilePlan {
        call: call.clone(),
        workspace_id: workspace,
        epoch: context.workspace_epoch,
        root: initial.local_root,
    };
    let guarded_ids =
        super::remote_file_namespace::mutation_lock_ids(coordinator, operation, &initial_plan)?;
    let actors = guarded_ids
        .iter()
        .map(|id| {
            coordinator
                .workspace_lock(*id)
                .map_err(|_| fault(ErrorCode::ServiceUnavailable))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut guards = Vec::with_capacity(actors.len());
    for actor in &actors {
        guards.push(actor_lock(actor, operation)?);
    }
    for id in &guarded_ids {
        ensure_workspace_settled(coordinator, *id)?;
    }
    let project = project(coordinator, context, operation)?;
    // Pin and validate the host-resolved root before journal admission. The
    // same cached FileRoot is used by the shared local/remote syscall path.
    coordinator
        .files
        .get_engine(workspace, context.workspace_epoch, &project.local_root)
        .map_err(super::remote_files::map_error)?;
    let rights = match method.rights() {
        MethodRights::Static(rights) => rights
            .to_vec()
            .try_into()
            .map_err(|_| fault(ErrorCode::ScopeDenied))?,
        _ => return Err(fault(ErrorCode::UnsupportedCapability)),
    };
    let binding = OperationBinding {
        rights: StoredOperationRights::new(
            mutation.operation_id,
            connection.connection.actor(),
            workspace,
            method,
            rights,
            false,
        )
        .map_err(|_| fault(ErrorCode::ScopeDenied))?,
        parameter_hash: parameter_hash(&call).map_err(stored)?,
    };
    let slot = CompletionSlot::reserve(coordinator, operation, workspace)?;
    let mut admission_turn = owner_call(operation, || {
        coordinator
            .owner
            .begin_admit_external(operation, &binding, project.state.domain_revision)
    })
    .map_err(owner_fault)?;
    let admitted = owner_call(operation, || admission_turn.try_commit());
    drop(admission_turn);
    let admission = match admitted {
        Ok(admission) => admission,
        Err(error) => {
            slot.defer(DeferredCompletion::Cancel { binding });
            return Err(owner_fault(error));
        }
    };
    if !admission.newly_admitted {
        return Ok(file_receipt_result(method, admission.receipt));
    }
    let (started, retained_permit) = match owner_call(operation, || {
        coordinator.owner.begin_start_external(operation, &binding)
    }) {
        Ok(mut start_turn) => {
            let started = owner_call(operation, || start_turn.try_commit());
            let retained = if started.is_err() {
                start_turn.take_started_permit()
            } else {
                None
            };
            drop(start_turn);
            (started, retained)
        }
        Err(error) => (Err(error), None),
    };
    let permit = match started {
        Ok(permit) => permit,
        Err(error) => {
            if let Some(permit) = retained_permit {
                slot.defer(DeferredCompletion::Complete {
                    binding,
                    permit,
                    state: OperationState::Failed,
                    effect: Effect::None,
                    result: None,
                    projection: None,
                });
            } else {
                slot.defer(DeferredCompletion::Cancel { binding });
            }
            return Err(owner_fault(error));
        }
    };
    let plan = super::shared_owner::RemoteFilePlan {
        call: call.clone(),
        workspace_id: workspace,
        epoch: context.workspace_epoch,
        root: project.local_root,
    };
    let mut namespace = None;
    let execution = (|| {
        use super::remote_file_namespace::FileNamespaceSelection;
        use lomi_files::desktop::DesktopFileErrorCode;
        let mut selection = FileNamespaceSelection::capture(&coordinator.files, &plan)?;
        if let Some(effect) = selection.effect.clone() {
            let namespace_plan = owner_call(operation, || {
                coordinator
                    .owner
                    .remote_namespace_plan(operation, &permit, effect.clone())
            })
            .map_err(owner_fault)?;
            if !namespace_plan
                .guarded_workspace_ids()
                .iter()
                .all(|id| guarded_ids.contains(id))
            {
                return Err(fault(ErrorCode::FileChanged));
            }
            selection = selection.with_guarded_ids(namespace_plan.guarded_workspace_ids())?;
            let projects = owner_call(operation, || coordinator.owner.workspaces(operation))
                .map_err(owner_fault)?;
            let roots = namespace_plan
                .guarded_workspace_ids()
                .iter()
                .map(|id| {
                    projects
                        .iter()
                        .find(|project| project.state.context.workspace_id == *id)
                        .map(|project| (*id, project.local_root.clone()))
                        .ok_or_else(|| fault(ErrorCode::FileChanged))
                })
                .collect::<Result<Vec<_>, _>>()?;
            namespace = Some(
                super::remote_namespace_effect::RemoteNamespaceEffect::capture(
                    namespace_plan,
                    &selection,
                    &roots,
                    &mut || operation.check().map_err(|_| DesktopFileErrorCode::Revoked),
                )
                .map_err(|_| fault(ErrorCode::FileChanged))?,
            );
            let captured = namespace
                .as_ref()
                .ok_or_else(|| fault(ErrorCode::ServiceUnavailable))?;
            let physical = captured.prepared_proof();
            let mut preparation = owner_call(operation, || {
                coordinator.owner.begin_remote_namespace_prepare(
                    operation,
                    &permit,
                    &captured.plan,
                    &physical,
                )
            })
            .map_err(owner_fault)?;
            owner_call(operation, || preparation.try_commit()).map_err(owner_fault)?;
        }
        let gate = owner_call(operation, || {
            coordinator.owner.external_effect_gate(operation, &permit)
        })
        .map_err(owner_fault)?;
        Ok(super::remote_terminal_lifecycle::perform_file_plan(
            coordinator,
            &plan,
            selection.expected_source.as_ref(),
            |phase| {
                if operation.check().is_err() || !gate.current() {
                    return false;
                }
                if phase == lomi_files::LocalNativeFileCheckPhase::BeforeEffect
                    && let Some(namespace) = namespace.as_ref()
                    && namespace
                        .verify_before_effect(&mut || {
                            if operation.check().is_ok() && gate.current() {
                                Ok(())
                            } else {
                                Err(DesktopFileErrorCode::Revoked)
                            }
                        })
                        .is_err()
                {
                    return false;
                }
                operation.check().is_ok() && gate.current()
            },
        ))
    })();
    let (outcome, file_error, preparation_error) = match execution {
        Ok((outcome, error)) => (outcome, error, None),
        Err(error) => (
            super::remote_terminal_lifecycle::no_effect_failure(),
            None,
            Some(error),
        ),
    };
    if let Some(namespace) = namespace {
        let record = DeferredCompletion::Namespace {
            binding,
            permit,
            outcome: outcome.clone(),
            namespace,
        };
        let receipt = match commit_record(coordinator, operation, &record) {
            Ok(Some(receipt)) => receipt,
            failed => {
                let error = match (&record, failed) {
                    (_, Err(error)) if outcome.effect == Effect::None => owner_fault(error),
                    (DeferredCompletion::Namespace { binding, .. }, _) => unknown(binding),
                    _ => fault(ErrorCode::ServiceUnavailable),
                };
                slot.defer(record);
                return Err(error);
            }
        };
        if let Some(error) = preparation_error {
            return Err(error);
        }
        if outcome.effect == Effect::None
            && let Some(error) = file_error
        {
            return Err(super::remote_files::map_error(error));
        }
        if outcome.effect == Effect::Unknown {
            return Err(RemoteError::new(
                ErrorCode::OutcomeUnknown,
                false,
                Effect::Unknown,
                ErrorDetails::empty(),
                None,
            )
            .expect("static uncertain namespace effect"));
        }
        return Ok(file_receipt_result(method, receipt));
    }
    if let Some(error) = preparation_error {
        finish_external(
            &slot,
            operation,
            binding,
            permit,
            outcome.state,
            outcome.effect,
            None,
            None,
            false,
        )?;
        return Err(error);
    }
    if let Some(error) = file_error {
        if outcome.effect == Effect::None {
            let _ = finish_external(
                &slot,
                operation,
                binding,
                permit,
                outcome.state,
                outcome.effect,
                outcome.result,
                outcome.projection,
                false,
            )?;
            return Err(super::remote_files::map_error(error));
        }
    }
    let physical_effect = outcome.effect != Effect::None;
    let state = outcome.state;
    let effect = outcome.effect;
    let result = outcome.result;
    let projection = outcome.projection;
    let receipt = finish_external(
        &slot,
        operation,
        binding,
        permit,
        state,
        effect,
        result,
        projection,
        physical_effect,
    )?;
    if effect == Effect::Unknown {
        return Err(RemoteError::new(
            ErrorCode::OutcomeUnknown,
            false,
            Effect::Unknown,
            ErrorDetails::empty(),
            None,
        )
        .expect("static uncertain Explorer mutation"));
    }
    Ok(file_receipt_result(method, receipt))
}

fn local_external_current(
    coordinator: &Coordinator,
    operation: &Operation<'_>,
    permit: &lomi_host_store::ExternalPermit,
) -> bool {
    operation.check().is_ok()
        && owner_call(operation, || {
            coordinator.owner.check_external_fence(operation, permit)
        })
        .is_ok()
}
fn receipt_result(method: Method, receipt: OperationReceipt) -> RpcResult {
    match method {
        Method::TerminalCreate => RpcResult::TerminalCreate(receipt),
        Method::TerminalSplit => RpcResult::TerminalSplit(receipt),
        Method::TerminalRename => RpcResult::TerminalRename(receipt),
        Method::TerminalMove => RpcResult::TerminalMove(receipt),
        Method::TerminalClose => RpcResult::TerminalClose(receipt),
        Method::TerminalRestart => RpcResult::TerminalRestart(receipt),
        _ => unreachable!("terminal mutation only"),
    }
}

pub(super) fn git_receipt_result(method: Method, receipt: OperationReceipt) -> RpcResult {
    match method {
        Method::GitStage => RpcResult::GitStage(receipt),
        Method::GitUnstage => RpcResult::GitUnstage(receipt),
        Method::GitCommit => RpcResult::GitCommit(receipt),
        Method::GitFetch => RpcResult::GitFetch(receipt),
        Method::GitPull => RpcResult::GitPull(receipt),
        Method::GitPush => RpcResult::GitPush(receipt),
        _ => unreachable!("closed Git mutation method"),
    }
}
pub(super) struct Plan {
    pub(super) state: WorkspaceState,
    pub(super) stop: Option<TerminalContext>,
    pub(super) spawn: Option<(TerminalContext, HostProfileId)>,
    pub(super) result: OperationResult,
}
fn context(project: &ProjectRecord, pane_id: PaneId) -> TerminalContext {
    TerminalContext {
        workspace: project.state.context.clone(),
        pane_id,
        session_id: fresh(),
        session_epoch: fresh(),
        profile: TerminalProfile::ExperimentalRustGridV1,
    }
}
fn replace_node(
    layout: &mut TerminalLayout,
    id: PaneId,
    replace: &mut impl FnMut(TerminalLayout) -> TerminalLayout,
) -> bool {
    match layout {
        TerminalLayout::Pane { pane } if pane.pane_id == id => {
            *layout = replace(layout.clone());
            true
        }
        TerminalLayout::Split { first, second, .. } => {
            replace_node(first, id, replace) || replace_node(second, id, replace)
        }
        _ => false,
    }
}
fn remove_pane(
    layout: TerminalLayout,
    id: PaneId,
) -> (Option<TerminalLayout>, Option<TerminalPane>) {
    match layout {
        TerminalLayout::Pane { pane } if pane.pane_id == id => (None, Some(pane)),
        TerminalLayout::Split {
            axis,
            first,
            second,
        } => {
            let (first, removed) = remove_pane(*first, id);
            if let Some(removed) = removed {
                return (
                    match first {
                        Some(first) => Some(TerminalLayout::Split {
                            axis,
                            first: Box::new(first),
                            second,
                        }),
                        None => Some(*second),
                    },
                    Some(removed),
                );
            }
            let (second, removed) = remove_pane(*second, id);
            (
                match second {
                    Some(second) => Some(TerminalLayout::Split {
                        axis,
                        first: Box::new(first.expect("no removal in first")),
                        second: Box::new(second),
                    }),
                    None => first,
                },
                removed,
            )
        }
        other => (Some(other), None),
    }
}
fn plan(call: &RpcCall, project: &ProjectRecord) -> Result<Plan, RemoteError> {
    let mut next = project.state.clone();
    next.domain_revision = DecimalU64(
        next.domain_revision
            .0
            .checked_add(1)
            .ok_or_else(|| fault(ErrorCode::ResourceExhausted))?,
    );
    let mut stop = None;
    let mut spawn = None;
    match call {
        RpcCall::TerminalCreate(params) => {
            let target = context(project, fresh());
            next.tabs.0.push(TerminalTab {
                tab_id: fresh(),
                name: params.tab_name.clone(),
                layout: TerminalLayout::Pane {
                    pane: TerminalPane {
                        pane_id: target.pane_id,
                        session: Some(target.clone()),
                        state: PaneState::Running,
                    },
                },
            });
            spawn = Some((target, params.profile_id.clone()));
        }
        RpcCall::TerminalSplit(params) => {
            let target = context(project, fresh());
            let tab = next
                .tabs
                .0
                .iter_mut()
                .find(|t| t.tab_id == params.tab_id)
                .ok_or_else(|| fault(ErrorCode::ResourceNotFound))?;
            if !replace_node(&mut tab.layout, params.pane_id, &mut |old| {
                TerminalLayout::Split {
                    axis: params.axis,
                    first: Box::new(old),
                    second: Box::new(TerminalLayout::Pane {
                        pane: TerminalPane {
                            pane_id: target.pane_id,
                            session: Some(target.clone()),
                            state: PaneState::Running,
                        },
                    }),
                }
            }) {
                return Err(fault(ErrorCode::ResourceNotFound));
            }
            spawn = Some((target, params.profile_id.clone()));
        }
        RpcCall::TerminalRename(params) => {
            next.tabs
                .0
                .iter_mut()
                .find(|t| t.tab_id == params.tab_id)
                .ok_or_else(|| fault(ErrorCode::ResourceNotFound))?
                .name = params.name.clone();
        }
        RpcCall::TerminalMove(params) => {
            next = lomi_host_store::plan_terminal_move(
                &next,
                &lomi_host_store::TerminalMoveLayout::from(params),
            )
            .map_err(|error| {
                fault(match error {
                    lomi_host_store::TerminalMoveError::InvalidArgument => {
                        ErrorCode::InvalidArgument
                    }
                    lomi_host_store::TerminalMoveError::NotFound => ErrorCode::ResourceNotFound,
                    lomi_host_store::TerminalMoveError::ResourceExhausted => {
                        ErrorCode::ResourceExhausted
                    }
                })
            })?;
        }
        RpcCall::TerminalClose(params) => {
            let current = find_pane(&next, params.pane_id)
                .ok_or_else(|| fault(ErrorCode::ResourceNotFound))?;
            if current.session != params.expected_session {
                return Err(fault(ErrorCode::StaleEpoch));
            }
            stop = current.session.clone();
            let index = next
                .tabs
                .0
                .iter()
                .position(|t| pane(&t.layout, params.pane_id).is_some())
                .ok_or_else(|| fault(ErrorCode::ResourceNotFound))?;
            let (layout, _) = remove_pane(next.tabs.0[index].layout.clone(), params.pane_id);
            if let Some(layout) = layout {
                next.tabs.0[index].layout = layout;
            } else {
                next.tabs.0.remove(index);
            }
        }
        RpcCall::TerminalRestart(params) => {
            let current = next
                .tabs
                .0
                .iter_mut()
                .find_map(|tab| pane_mut(&mut tab.layout, params.pane_id))
                .ok_or_else(|| fault(ErrorCode::ResourceNotFound))?;
            if current.session != params.expected_session {
                return Err(fault(ErrorCode::StaleEpoch));
            }
            stop = current.session.clone();
            let target = context(project, params.pane_id);
            current.session = Some(target.clone());
            current.state = PaneState::Running;
            spawn = Some((target, params.profile_id.clone()));
        }
        _ => return Err(fault(ErrorCode::UnsupportedCapability)),
    }
    if next.tabs.0.len() > 32 || next.validate().is_err() {
        return Err(fault(ErrorCode::ResourceExhausted));
    }
    let result = if let Some((target, _)) = &spawn {
        OperationResult::Terminal {
            domain_revision: next.domain_revision,
            pane_id: target.pane_id,
            session_id: target.session_id,
            session_epoch: target.session_epoch,
        }
    } else {
        OperationResult::Domain {
            domain_revision: next.domain_revision,
        }
    };
    Ok(Plan {
        state: next,
        stop,
        spawn,
        result,
    })
}
/// Plan a remote lifecycle call against the LOCAL project record. The only
/// translation is the verified remote workspace context on `expected_session`
/// to the stored local one; everything else (ids, epochs, profile) must match
/// the stored descriptor exactly, so a stale or foreign session stays stale.
pub(super) fn plan_remote(
    call: &RpcCall,
    project: &ProjectRecord,
    remote: &lomi_remote_protocol::WorkspaceContext,
) -> Result<Plan, RemoteError> {
    fn localize(
        expected: &mut Option<TerminalContext>,
        project: &ProjectRecord,
        remote: &lomi_remote_protocol::WorkspaceContext,
    ) -> Result<(), RemoteError> {
        if let Some(target) = expected {
            if target.workspace != *remote {
                return Err(fault(ErrorCode::StaleEpoch));
            }
            target.workspace = project.state.context.clone();
        }
        Ok(())
    }
    let mut local = call.clone();
    match &mut local {
        RpcCall::TerminalCreate(_) | RpcCall::TerminalSplit(_) => {}
        RpcCall::TerminalClose(params) => localize(&mut params.expected_session, project, remote)?,
        RpcCall::TerminalRestart(params) => {
            localize(&mut params.expected_session, project, remote)?
        }
        _ => return Err(fault(ErrorCode::UnsupportedCapability)),
    }
    plan(&local, project)
}
fn validate_shell(profile: &DefaultShellProfile) -> Result<(), RemoteError> {
    let path = &profile.executable;
    let metadata = path
        .metadata()
        .map_err(|_| fault(ErrorCode::InvalidArgument))?;
    if !path.is_absolute() || !metadata.is_file() {
        return Err(fault(ErrorCode::InvalidArgument));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(fault(ErrorCode::InvalidArgument));
        }
    }
    Ok(())
}
pub(super) fn initialize_default_shell(store: &mut HostStore) -> Result<(), RemoteError> {
    if store.default_shell().map_err(stored)?.is_some() {
        return Ok(());
    }
    #[cfg(unix)]
    let shell = std::env::var_os("SHELL")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && p.is_file())
        .unwrap_or_else(|| "/bin/sh".into());
    #[cfg(windows)]
    let shell = std::env::var_os("COMSPEC")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && p.is_file())
        .or_else(|| {
            std::env::var_os("SystemRoot").map(|root| PathBuf::from(root).join("System32/cmd.exe"))
        })
        .filter(|p| p.is_absolute() && p.is_file())
        .ok_or_else(|| fault(ErrorCode::InvalidArgument))?;
    let profile = DefaultShellProfile {
        executable: shell,
        args: vec![],
    };
    validate_shell(&profile)?;
    store.initialize_default_shell(profile).map_err(stored)?;
    Ok(())
}
fn profile(
    coordinator: &Coordinator,
    project: &ProjectRecord,
    connection: &ConnectionState,
    operation: &Operation<'_>,
    profile_id: &HostProfileId,
) -> Result<SpawnProfile, RemoteError> {
    let _ = connection;
    if profile_id.as_str() != "default" {
        let (configured, cwd_override) = owner_call(operation, || {
            coordinator.owner.shell_profile_with_cwd_override(
                operation,
                project.state.context.workspace_id,
                profile_id,
            )
        })
        .map_err(owner_fault)?
        .ok_or_else(|| fault(ErrorCode::InvalidArgument))?;
        return match cwd_override {
            Some(cwd_override) => {
                configured_spawn_profile_with_cwd_override(&configured, project, &cwd_override)
            }
            None => configured_spawn_profile(&configured, project),
        };
    }
    let shell = owner_call(operation, || coordinator.owner.default_shell(operation))
        .map_err(owner_fault)?
        .ok_or_else(|| fault(ErrorCode::InvalidArgument))?;
    spawn_profile(&shell, project)
}

pub(super) fn validate_registered_shell_profile(
    configured: &lomi_remote_protocol::ipc::LocalShellProfileRegister,
) -> Result<(), RemoteError> {
    validate_registered_shell_profile_fields(configured, true)
}

fn validate_registered_shell_profile_fields(
    configured: &lomi_remote_protocol::ipc::LocalShellProfileRegister,
    require_cwd_exists: bool,
) -> Result<(), RemoteError> {
    if configured
        .derived_profile_id()
        .map_err(|_| fault(ErrorCode::InvalidArgument))?
        != configured.profile_id
        || !std::path::Path::new(configured.cwd.as_str()).is_absolute()
        || (require_cwd_exists && !std::path::Path::new(configured.cwd.as_str()).is_dir())
    {
        return Err(fault(ErrorCode::InvalidArgument));
    }
    validate_shell(&DefaultShellProfile {
        executable: configured.executable.as_str().into(),
        args: configured
            .args
            .0
            .iter()
            .cloned()
            .map(String::from)
            .collect(),
    })
    .and_then(|_| {
        configured
            .integration
            .as_ref()
            .map_or(Ok(()), |integration| {
                integration
                    .validate_launch(&configured.executable, &configured.args)
                    .map_err(|_| fault(ErrorCode::InvalidArgument))
            })
    })?;
    Ok(())
}

/// Validate a registered profile for an owner-controlled registration or
/// same-ID retry. New definitions must use an existing directory under the
/// current workspace root. Existing immutable definitions may retain their
/// historical external CWD, while a namespace override is resolved only
/// beneath the current workspace root.
pub(super) fn validate_shell_profile_registration(
    configured: &lomi_remote_protocol::ipc::LocalShellProfileRegister,
    project: &ProjectRecord,
    existing_definition: bool,
    cwd_override: Option<&Path>,
) -> Result<PathBuf, RemoteError> {
    if configured.workspace_id != project.state.context.workspace_id
        || (cwd_override.is_some() && !existing_definition)
    {
        return Err(fault(ErrorCode::InvalidArgument));
    }
    validate_registered_shell_profile_fields(configured, false)?;
    match cwd_override {
        Some(suffix) => resolve_workspace_cwd(project, suffix, true),
        None if existing_definition => {
            validate_registered_shell_profile(configured)?;
            Ok(PathBuf::from(configured.cwd.as_str()))
        }
        None => resolve_workspace_cwd(project, Path::new(configured.cwd.as_str()), false),
    }
}

fn resolve_workspace_cwd(
    project: &ProjectRecord,
    path_or_suffix: &Path,
    is_suffix: bool,
) -> Result<PathBuf, RemoteError> {
    let candidate = if is_suffix {
        if path_or_suffix.is_absolute()
            || path_or_suffix.as_os_str().len() > 4096
            || path_or_suffix
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(fault(ErrorCode::InvalidArgument));
        }
        project.local_root.join(path_or_suffix)
    } else {
        path_or_suffix.to_path_buf()
    };
    if !candidate.is_absolute() || candidate.as_os_str().len() > 4096 {
        return Err(fault(ErrorCode::InvalidArgument));
    }

    let root_pin = lomi_files::desktop::DesktopDirectoryPin::open(&project.local_root)
        .map_err(|_| fault(ErrorCode::InvalidArgument))?;
    let cwd_pin = lomi_files::desktop::DesktopDirectoryPin::open(&candidate)
        .map_err(|_| fault(ErrorCode::InvalidArgument))?;
    let canonical_root = std::fs::canonicalize(&project.local_root)
        .map_err(|_| fault(ErrorCode::InvalidArgument))?;
    let canonical_cwd =
        std::fs::canonicalize(&candidate).map_err(|_| fault(ErrorCode::InvalidArgument))?;
    if !canonical_cwd.starts_with(&canonical_root) {
        return Err(fault(ErrorCode::InvalidArgument));
    }
    let canonical_pin = lomi_files::desktop::DesktopDirectoryPin::open(&canonical_cwd)
        .map_err(|_| fault(ErrorCode::InvalidArgument))?;
    if canonical_pin.witness() != cwd_pin.witness() {
        return Err(fault(ErrorCode::InvalidArgument));
    }
    root_pin
        .verify_named()
        .map_err(|_| fault(ErrorCode::InvalidArgument))?;
    cwd_pin
        .verify_named()
        .map_err(|_| fault(ErrorCode::InvalidArgument))?;
    canonical_pin
        .verify_named()
        .map_err(|_| fault(ErrorCode::InvalidArgument))?;
    Ok(canonical_cwd)
}

pub(super) fn configured_spawn_profile(
    configured: &lomi_remote_protocol::ipc::LocalShellProfileRegister,
    project: &ProjectRecord,
) -> Result<SpawnProfile, RemoteError> {
    validate_registered_shell_profile(configured)?;
    if configured.workspace_id != project.state.context.workspace_id {
        return Err(fault(ErrorCode::InvalidArgument));
    }
    let mut profile = spawn_profile(
        &DefaultShellProfile {
            executable: configured.executable.as_str().into(),
            args: configured
                .args
                .0
                .iter()
                .cloned()
                .map(String::from)
                .collect(),
        },
        project,
    )?;
    profile.cwd = configured.cwd.as_str().into();
    for entry in &configured.environment.0 {
        profile
            .environment
            .retain(|(key, _)| key != entry.name.as_str());
        profile
            .environment
            .push((entry.name.as_str().to_owned(), entry.value.clone().into()));
    }
    profile.shell_integration = configured.integration.clone();
    Ok(profile)
}

pub(super) fn configured_spawn_profile_with_cwd_override(
    configured: &lomi_remote_protocol::ipc::LocalShellProfileRegister,
    project: &ProjectRecord,
    cwd_override: &Path,
) -> Result<SpawnProfile, RemoteError> {
    let cwd = validate_shell_profile_registration(configured, project, true, Some(cwd_override))?;
    let mut profile = spawn_profile(
        &DefaultShellProfile {
            executable: configured.executable.as_str().into(),
            args: configured
                .args
                .0
                .iter()
                .cloned()
                .map(String::from)
                .collect(),
        },
        project,
    )?;
    profile.cwd = cwd;
    for entry in &configured.environment.0 {
        profile
            .environment
            .retain(|(key, _)| key != entry.name.as_str());
        profile
            .environment
            .push((entry.name.as_str().to_owned(), entry.value.clone().into()));
    }
    profile.shell_integration = configured.integration.clone();
    Ok(profile)
}
/// Trusted host-side profile only: shell from the Store, root as cwd, a fixed
/// environment allow-list. Nothing in a request can influence any field.
pub(super) fn spawn_profile(
    shell: &DefaultShellProfile,
    project: &ProjectRecord,
) -> Result<SpawnProfile, RemoteError> {
    validate_shell(shell)?;
    let mut environment = Vec::new();
    #[cfg(unix)]
    let inherited = &["PATH", "HOME", "LANG", "TERM"][..];
    #[cfg(windows)]
    let inherited = &[
        "PATH",
        "PATHEXT",
        "SystemRoot",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
        "TERM",
    ][..];
    for name in inherited {
        if let Ok(value) = std::env::var(name) {
            environment.push(((*name).to_owned(), value));
        }
    }
    if !environment.iter().any(|(key, _)| key == "TERM") {
        environment.push(("TERM".into(), "xterm-256color".into()));
    }
    #[cfg(windows)]
    let home = environment
        .iter()
        .find(|(key, _)| key == "USERPROFILE")
        .map(|(_, value)| PathBuf::from(value));
    #[cfg(unix)]
    let home = environment
        .iter()
        .find(|(key, _)| key == "HOME")
        .map(|(_, value)| PathBuf::from(value));
    let original_zdotdir =
        std::env::var_os("ZDOTDIR").and_then(|value| value.into_string().ok().map(PathBuf::from));
    let shell_integration = home.and_then(|home| {
        lomi_terminal::shell::native_integration(
            &shell.executable,
            &shell.args,
            &home,
            original_zdotdir.as_deref(),
        )
    });
    Ok(SpawnProfile {
        executable: shell.executable.clone(),
        args: shell.args.clone(),
        cwd: project.local_root.clone(),
        environment,
        shell_integration,
        rows: 24,
        cols: 80,
        history: 128,
    })
}
fn unknown(binding: &OperationBinding) -> RemoteError {
    RemoteError::new(
        ErrorCode::OutcomeUnknown,
        false,
        Effect::Unknown,
        ErrorDetails::empty(),
        Some(OperationLookup {
            workspace_id: binding.rights.workspace(),
            operation_id: binding.rights.operation_id(),
        }),
    )
    .expect("bound unknown effect")
}
pub(super) fn stopped_after_restart(old: &WorkspaceState, plan: &Plan) -> Option<WorkspaceState> {
    plan.spawn.as_ref()?;
    let stopped = plan.stop.as_ref()?;
    let mut state = old.clone();
    state.domain_revision = plan.state.domain_revision;
    for tab in &mut state.tabs.0 {
        if let Some(pane) = pane_mut(&mut tab.layout, stopped.pane_id) {
            pane.session = None;
            pane.state = PaneState::Stopped;
        }
    }
    Some(state)
}
/// Capacity is reserved before journal admission and before any physical effect.
/// Slots own move-only permits across expired requests; no callback, allocation,
/// Store/Domain guard or PTY execution occurs while this bookkeeping lock is held.
const COMPLETION_SLOTS: usize = 128;
pub(super) struct CompletionQueue {
    slots: Vec<CompletionSlotState>,
}
#[expect(
    clippy::large_enum_variant,
    reason = "128 preallocated slots retain actual permits inline without allocation after effects"
)]
enum CompletionSlotState {
    Free,
    Reserved(WorkspaceId),
    NamespaceReserved {
        workspace: WorkspaceId,
        guarded_workspace_ids: std::sync::Arc<[WorkspaceId]>,
    },
    Deferred(DeferredCompletion),
}
impl CompletionQueue {
    pub(super) fn new() -> Self {
        Self {
            slots: (0..COMPLETION_SLOTS)
                .map(|_| CompletionSlotState::Free)
                .collect(),
        }
    }
}
#[expect(
    clippy::large_enum_variant,
    reason = "retain actual linear permit and observed projection inline without allocation after effects"
)]
pub(super) enum DeferredCompletion {
    Cancel {
        binding: OperationBinding,
    },
    Complete {
        binding: OperationBinding,
        permit: lomi_host_store::ExternalPermit,
        state: OperationState,
        effect: Effect,
        result: Option<OperationResult>,
        projection: Option<WorkspaceState>,
    },
    Namespace {
        binding: OperationBinding,
        permit: lomi_host_store::ExternalPermit,
        outcome: super::shared_owner::RemoteEffectOutcome,
        namespace: Box<super::remote_namespace_effect::RemoteNamespaceEffect>,
    },
}
pub(super) struct CompletionSlot<'a> {
    coordinator: CompletionCoordinator<'a>,
    index: usize,
}
enum CompletionCoordinator<'a> {
    Borrowed(&'a Coordinator),
    Owned(std::sync::Arc<Coordinator>),
}
impl CompletionCoordinator<'_> {
    fn queue(&self) -> &Mutex<CompletionQueue> {
        match self {
            Self::Borrowed(coordinator) => &coordinator.deferred_completions,
            Self::Owned(coordinator) => &coordinator.deferred_completions,
        }
    }
    fn coordinator(&self) -> &Coordinator {
        match self {
            Self::Borrowed(coordinator) => coordinator,
            Self::Owned(coordinator) => coordinator,
        }
    }
}
impl<'a> CompletionSlot<'a> {
    pub(super) fn reserve(
        coordinator: &'a Coordinator,
        operation: &Operation<'_>,
        workspace: WorkspaceId,
    ) -> Result<Self, RemoteError> {
        before_deadline(operation)?;
        // Poison here protects only slot accounting; recover all actual owned
        // records. It never recovers Store/Domain state or grants authority.
        let mut queue = coordinator
            .deferred_completions
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let index = queue
            .slots
            .iter()
            .position(|slot| matches!(slot, CompletionSlotState::Free))
            .ok_or_else(|| fault(ErrorCode::ResourceExhausted))?;
        queue.slots[index] = CompletionSlotState::Reserved(workspace);
        Ok(Self {
            coordinator: CompletionCoordinator::Borrowed(coordinator),
            index,
        })
    }
    /// Cross-turn reservation for an encrypted remote mutation. It owns the
    /// coordinator Arc so a failed durable completion can retain its actual
    /// permit without a self-reference into the connection state.
    pub(super) fn reserve_owned(
        coordinator: std::sync::Arc<Coordinator>,
        operation: &Operation<'_>,
        workspace: WorkspaceId,
    ) -> Result<CompletionSlot<'static>, RemoteError> {
        before_deadline(operation)?;
        let mut queue = coordinator
            .deferred_completions
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let index = queue
            .slots
            .iter()
            .position(|slot| matches!(slot, CompletionSlotState::Free))
            .ok_or_else(|| fault(ErrorCode::ResourceExhausted))?;
        queue.slots[index] = CompletionSlotState::Reserved(workspace);
        drop(queue);
        Ok(CompletionSlot {
            coordinator: CompletionCoordinator::Owned(coordinator),
            index,
        })
    }
    pub(super) fn defer(&self, record: DeferredCompletion) {
        let mut queue = self
            .coordinator
            .queue()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        queue.slots[self.index] = CompletionSlotState::Deferred(record);
    }
}
impl Drop for CompletionSlot<'_> {
    fn drop(&mut self) {
        let mut queue = self
            .coordinator
            .queue()
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if matches!(
            queue.slots[self.index],
            CompletionSlotState::Reserved(_) | CompletionSlotState::NamespaceReserved { .. }
        ) {
            queue.slots[self.index] = CompletionSlotState::Free;
        }
    }
}
pub(super) fn ensure_workspace_settled(
    coordinator: &Coordinator,
    workspace: WorkspaceId,
) -> Result<(), RemoteError> {
    ensure_workspace_queue_settled(&coordinator.deferred_completions, workspace)
}

pub(super) fn ensure_workspace_queue_settled(
    queue: &Mutex<CompletionQueue>,
    workspace: WorkspaceId,
) -> Result<(), RemoteError> {
    let queue = queue.lock().unwrap_or_else(|p| p.into_inner());
    if queue.slots.iter().any(|slot| match slot {
        CompletionSlotState::Deferred(DeferredCompletion::Cancel { binding })
        | CompletionSlotState::Deferred(DeferredCompletion::Complete { binding, .. }) => {
            binding.rights.workspace() == workspace
        }
        CompletionSlotState::Deferred(DeferredCompletion::Namespace {
            binding, namespace, ..
        }) => {
            binding.rights.workspace() == workspace
                || namespace.plan.guarded_workspace_ids().contains(&workspace)
        }
        CompletionSlotState::Reserved(id) => *id == workspace,
        CompletionSlotState::NamespaceReserved {
            workspace: origin,
            guarded_workspace_ids,
        } => *origin == workspace || guarded_workspace_ids.contains(&workspace),
        _ => false,
    }) {
        return Err(fault(ErrorCode::ServiceUnavailable));
    }
    Ok(())
}
fn commit_record(
    coordinator: &Coordinator,
    operation: &Operation<'_>,
    record: &DeferredCompletion,
) -> Result<Option<OperationReceipt>, OwnerError> {
    match record {
        DeferredCompletion::Namespace {
            permit,
            outcome,
            namespace,
            ..
        } => {
            let evidence = namespace
                .completion_proof(outcome, &mut || {
                    operation
                        .check()
                        .map_err(|_| lomi_files::desktop::DesktopFileErrorCode::Revoked)
                })
                .map_err(|_| OwnerError::Store(StoreError::Fenced))?;
            let mut turn = owner_call(operation, || {
                coordinator.owner.begin_remote_namespace_complete(
                    operation,
                    permit,
                    outcome.state,
                    outcome.effect,
                    outcome.result.clone(),
                    &evidence,
                )
            })?;
            owner_call(operation, || turn.try_commit()).map(Some)
        }
        DeferredCompletion::Cancel { binding } => {
            let rights = local_rights();
            let mut turn = owner_call(operation, || {
                coordinator.owner.begin_cancel_operation(
                    operation,
                    binding.rights.actor(),
                    binding.rights.workspace(),
                    binding.rights.operation_id(),
                    &rights,
                )
            })?;
            owner_call(operation, || turn.try_commit()).and_then(|receipt| {
                if receipt
                    .as_ref()
                    .is_some_and(|receipt| !receipt.state().is_final())
                {
                    Err(OwnerError::Store(StoreError::AlreadyStarted))
                } else {
                    Ok(receipt)
                }
            })
        }
        DeferredCompletion::Complete {
            binding,
            permit,
            state,
            effect,
            result,
            projection,
        } => {
            let mut turn = owner_call(operation, || {
                coordinator.owner.begin_complete_external(
                    operation,
                    permit,
                    *state,
                    *effect,
                    result.clone(),
                    projection.clone(),
                )
            })?;
            match owner_call(operation, || turn.try_commit()) {
                Ok(receipt) => Ok(Some(receipt)),
                // An uncertain commit may already have stored its final receipt.
                // Recognize that exact binding; never repeat the physical effect.
                Err(OwnerError::Store(StoreError::AlreadyStarted)) => owner_call(operation, || {
                    coordinator.owner.lookup_operation(
                        operation,
                        binding.rights.actor(),
                        binding.rights.workspace(),
                        binding.rights.operation_id(),
                        &local_rights(),
                    )
                })
                .and_then(|receipt| match receipt {
                    Some(receipt) if receipt.state().is_final() => Ok(Some(receipt)),
                    _ => Err(OwnerError::Store(StoreError::AlreadyStarted)),
                }),
                Err(error) => Err(error),
            }
        }
    }
}
pub(super) fn reconcile_deferred_completions(
    coordinator: &Coordinator,
    operation: &Operation<'_>,
) -> Result<(), LocalError> {
    for index in 0..COMPLETION_SLOTS {
        operation.check().map_err(|_| LocalError::Unavailable)?;
        let record = {
            let mut queue = coordinator
                .deferred_completions
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if !matches!(queue.slots[index], CompletionSlotState::Deferred(_)) {
                continue;
            }
            let workspace = match &queue.slots[index] {
                CompletionSlotState::Deferred(DeferredCompletion::Cancel { binding })
                | CompletionSlotState::Deferred(DeferredCompletion::Complete { binding, .. })
                | CompletionSlotState::Deferred(DeferredCompletion::Namespace {
                    binding, ..
                }) => binding.rights.workspace(),
                _ => unreachable!(),
            };
            let reserved = match &queue.slots[index] {
                CompletionSlotState::Deferred(DeferredCompletion::Namespace {
                    namespace, ..
                }) => CompletionSlotState::NamespaceReserved {
                    workspace,
                    guarded_workspace_ids: namespace.guarded_workspace_ids.clone(),
                },
                _ => CompletionSlotState::Reserved(workspace),
            };
            match std::mem::replace(&mut queue.slots[index], reserved) {
                CompletionSlotState::Deferred(record) => record,
                _ => unreachable!(),
            }
        };
        let slot = CompletionSlot {
            coordinator: CompletionCoordinator::Borrowed(coordinator),
            index,
        };
        let workspace = match &record {
            DeferredCompletion::Cancel { binding }
            | DeferredCompletion::Complete { binding, .. }
            | DeferredCompletion::Namespace { binding, .. } => binding.rights.workspace(),
        };
        let mut ids = match &record {
            DeferredCompletion::Namespace { namespace, .. } => {
                namespace.plan.guarded_workspace_ids().to_vec()
            }
            _ => Vec::new(),
        };
        ids.push(workspace);
        ids.sort();
        ids.dedup();
        let actors = match ids
            .iter()
            .map(|id| coordinator.workspace_lock(*id))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(actors) => actors,
            Err(error) => {
                slot.defer(record);
                return Err(error);
            }
        };
        let mut guards = Vec::with_capacity(actors.len());
        for actor in &actors {
            match actor_lock(actor, operation) {
                Ok(guard) => guards.push(guard),
                Err(_) => {
                    slot.defer(record);
                    return Err(LocalError::Unavailable);
                }
            }
        }
        if commit_record(coordinator, operation, &record).is_err() {
            slot.defer(record);
            return Err(LocalError::Unavailable);
        }
    }
    Ok(())
}
#[expect(
    clippy::too_many_arguments,
    reason = "explicit linear permit, operation and observed effect fields preserve completion ownership"
)]
fn finish_external(
    slot: &CompletionSlot<'_>,
    operation: &Operation<'_>,
    binding: OperationBinding,
    permit: lomi_host_store::ExternalPermit,
    state: OperationState,
    effect: Effect,
    result: Option<OperationResult>,
    projection: Option<WorkspaceState>,
    physical_effect_observed: bool,
) -> Result<OperationReceipt, RemoteError> {
    let mut record = DeferredCompletion::Complete {
        binding,
        permit,
        state,
        effect,
        result,
        projection,
    };
    match commit_record(slot.coordinator.coordinator(), operation, &record) {
        Ok(Some(receipt)) => Ok(receipt),
        failed => {
            let error = match (&record, failed) {
                (_, Err(error)) if effect == Effect::None => owner_fault(error),
                (DeferredCompletion::Complete { binding, .. }, _) => unknown(binding),
                _ => unreachable!(),
            };
            // A domain-only mutation has no physical effect to preserve. If
            // its request cannot commit, reconcile failure rather than apply
            // that mutation later under a maintenance budget. Already-final
            // uncertain commits are recognized by lookup in commit_record.
            if !physical_effect_observed
                && state == OperationState::Succeeded
                && let DeferredCompletion::Complete {
                    state,
                    effect,
                    result,
                    projection,
                    ..
                } = &mut record
            {
                *state = OperationState::Failed;
                *effect = Effect::None;
                *result = None;
                *projection = None;
            }
            slot.defer(record);
            Err(error)
        }
    }
}
fn mutate(
    coordinator: &Coordinator,
    connection: &ConnectionState,
    call: RpcCall,
    operation: &Operation<'_>,
) -> Result<RpcResult, RemoteError> {
    reconcile_terminal_lifecycle(coordinator, operation)
        .map_err(|_| fault(ErrorCode::ServiceUnavailable))?;
    let params = mutation(&call);
    let method = call.method();
    let owner = coordinator
        .workspace_lock(params.context.workspace_id)
        .map_err(|_| fault(ErrorCode::ServiceUnavailable))?;
    let _actor = actor_lock(&owner, operation)?;
    ensure_workspace_settled(coordinator, params.context.workspace_id)?;
    let project = project(coordinator, &params.context, operation)?;
    let rights = match method.rights() {
        MethodRights::Static(rights) => rights.to_vec(),
        _ => return Err(fault(ErrorCode::UnsupportedCapability)),
    };
    let binding = OperationBinding {
        rights: StoredOperationRights::new(
            params.operation_id,
            connection.connection.actor(),
            params.context.workspace_id,
            method,
            rights
                .try_into()
                .map_err(|_| fault(ErrorCode::ScopeDenied))?,
            false,
        )
        .map_err(|_| fault(ErrorCode::ScopeDenied))?,
        parameter_hash: parameter_hash(&call).map_err(stored)?,
    };
    let slot = CompletionSlot::reserve(coordinator, operation, params.context.workspace_id)?;
    let mut admission_turn = owner_call(operation, || {
        coordinator
            .owner
            .begin_admit_external(operation, &binding, params.expected_revision)
    })
    .map_err(owner_fault)?;
    let admitted = owner_call(operation, || admission_turn.try_commit());
    drop(admission_turn);
    let admission = match admitted {
        Ok(admission) => admission,
        Err(error) => {
            let remote = if matches!(error, OwnerError::Store(StoreError::RevisionConflict)) {
                RemoteError::new(
                    ErrorCode::RevisionConflict,
                    false,
                    Effect::None,
                    ErrorDetails::Revision(RevisionErrorDetails {
                        expected_revision: params.expected_revision,
                        actual_revision: project.state.domain_revision,
                    }),
                    None,
                )
                .expect("revision details")
            } else {
                owner_fault(error)
            };
            slot.defer(DeferredCompletion::Cancel { binding });
            return Err(remote);
        }
    };
    if !admission.newly_admitted {
        return Ok(receipt_result(method, admission.receipt));
    }
    let (started, retained_permit) = match owner_call(operation, || {
        coordinator.owner.begin_start_external(operation, &binding)
    }) {
        Ok(mut start_turn) => {
            let started = owner_call(operation, || start_turn.try_commit());
            // Keep the actual permit on post-start failure, exclusively for
            // persistence/quarantine. Return only owned results from this scope
            // so the start-turn temporary drops before binding can move.
            let retained_permit = if started.is_err() {
                start_turn.take_started_permit()
            } else {
                None
            };
            drop(start_turn);
            (started, retained_permit)
        }
        Err(error) => (Err(error), None),
    };
    let permit = match started {
        Ok(permit) => permit,
        Err(error) => {
            if let Some(permit) = retained_permit {
                slot.defer(DeferredCompletion::Complete {
                    binding,
                    permit,
                    state: OperationState::Failed,
                    effect: Effect::None,
                    result: None,
                    projection: None,
                });
            } else {
                slot.defer(DeferredCompletion::Cancel { binding });
            }
            return Err(owner_fault(error));
        }
    };
    let plan = match plan(&call, &project) {
        Ok(plan) => plan,
        Err(error) => {
            finish_external(
                &slot,
                operation,
                binding,
                permit,
                OperationState::Failed,
                Effect::None,
                None,
                None,
                false,
            )?;
            return Err(error);
        }
    };
    let profile = if let Some((_, profile_id)) = &plan.spawn {
        match profile(coordinator, &project, connection, operation, profile_id) {
            Ok(profile) => Some(profile),
            Err(error) => {
                finish_external(
                    &slot,
                    operation,
                    binding,
                    permit,
                    OperationState::Failed,
                    Effect::None,
                    None,
                    None,
                    false,
                )?;
                return Err(error);
            }
        }
    } else {
        None
    };
    if let Err(error) = owner_call(operation, || {
        coordinator.owner.check_external_fence(operation, &permit)
    }) {
        finish_external(
            &slot,
            operation,
            binding,
            permit,
            OperationState::Failed,
            Effect::None,
            None,
            None,
            false,
        )?;
        return Err(owner_fault(error));
    }
    if let Err(error) = before_deadline(operation) {
        finish_external(
            &slot,
            operation,
            binding,
            permit,
            OperationState::Failed,
            Effect::None,
            None,
            None,
            false,
        )?;
        return Err(error);
    }
    if let Some(target) = &plan.stop {
        if let Err(error) = coordinator
            .terminals
            .stop_checked(target.session_id, || terminal_effect_current(operation))
        {
            let (state, effect) = if error == lomi_terminal::Error::FenceRejected {
                (OperationState::Failed, Effect::None)
            } else {
                (OperationState::OutcomeUnknown, Effect::Unknown)
            };
            let unknown_error = unknown(&binding);
            finish_external(
                &slot, operation, binding, permit, state, effect, None, None, false,
            )?;
            return if effect == Effect::None {
                Err(fault(if operation.check().is_err() {
                    ErrorCode::DeadlineExceeded
                } else {
                    ErrorCode::ServiceUnavailable
                }))
            } else {
                Err(unknown_error)
            };
        }
    }
    if let Some((target, _)) = &plan.spawn {
        if owner_call(operation, || {
            coordinator.owner.check_external_fence(operation, &permit)
        })
        .is_err()
        {
            let effect = if plan.stop.is_some() {
                Effect::Unknown
            } else {
                Effect::None
            };
            let state = if effect == Effect::Unknown {
                OperationState::OutcomeUnknown
            } else {
                OperationState::Failed
            };
            finish_external(
                &slot,
                operation,
                binding,
                permit,
                state,
                effect,
                None,
                stopped_after_restart(&project.state, &plan),
                true,
            )?;
            return Err(fault(ErrorCode::ServiceUnavailable));
        }

        let check = || Ok(());
        let spawn_result = coordinator.terminals.spawn_with_checks_until(
            target.session_id,
            target.session_epoch,
            profile.as_ref().expect("spawn profile"),
            operation.deadline(),
            || terminal_effect_current(operation),
            check,
        );
        if let Err(spawn_error) = spawn_result {
            let (state, effect) = if plan.stop.is_some()
                || spawn_error == lomi_terminal::Error::SpawnOutcomeUnknown
            {
                (OperationState::OutcomeUnknown, Effect::Unknown)
            } else {
                (OperationState::Failed, Effect::None)
            };
            let receipt = finish_external(
                &slot,
                operation,
                binding,
                permit,
                state,
                effect,
                None,
                stopped_after_restart(&project.state, &plan),
                true,
            )?;
            if effect == Effect::None && operation.check().is_err() {
                return Err(fault(ErrorCode::DeadlineExceeded));
            }
            return Ok(receipt_result(method, receipt));
        }
    }
    let physical_effect_observed = plan.stop.is_some() || plan.spawn.is_some();
    finish_external(
        &slot,
        operation,
        binding,
        permit,
        OperationState::Succeeded,
        Effect::Committed,
        Some(plan.result),
        Some(plan.state),
        physical_effect_observed,
    )
    .map(|receipt| receipt_result(method, receipt))
}

fn git_mutation_context(call: &RpcCall) -> Option<(OperationId, &WorkspaceContext, RepositoryId)> {
    match call {
        RpcCall::GitStage(p) => Some((
            p.mutation.operation_id,
            &p.mutation.context,
            p.repository_id,
        )),
        RpcCall::GitUnstage(p) => Some((
            p.mutation.operation_id,
            &p.mutation.context,
            p.repository_id,
        )),
        RpcCall::GitCommit(p) => Some((
            p.mutation.operation_id,
            &p.mutation.context,
            p.repository_id,
        )),
        RpcCall::GitFetch(p) | RpcCall::GitPush(p) => Some((
            p.mutation.operation_id,
            &p.mutation.context,
            p.repository_id,
        )),
        RpcCall::GitPull(p) => Some((
            p.mutation.operation_id,
            &p.mutation.context,
            p.repository_id,
        )),
        _ => None,
    }
}

/// Local IPC Git mutations use the same prepared engine and operation journal
/// as remote Git, but run on the dedicated bounded local connection thread.
fn mutate_git(
    coordinator: &Coordinator,
    connection: &ConnectionState,
    call: RpcCall,
    operation: &Operation<'_>,
) -> Result<RpcResult, RemoteError> {
    let (operation_id, context, _repository_id) =
        git_mutation_context(&call).ok_or_else(|| fault(ErrorCode::InvalidArgument))?;
    let method = call.method();
    let workspace = context.workspace_id;
    let actor = coordinator
        .workspace_lock(workspace)
        .map_err(|_| fault(ErrorCode::ServiceUnavailable))?;
    let _actor = actor_lock(&actor, operation)?;
    ensure_workspace_settled(coordinator, workspace)?;
    let project = project(coordinator, context, operation)?;
    // Capture public provider selection before durable Start. A failed read
    // must not abandon a Running receipt with no retained completion owner.
    let credential_configuration = if matches!(
        &call,
        RpcCall::GitFetch(_) | RpcCall::GitPull(_) | RpcCall::GitPush(_)
    ) {
        owner_call(operation, || coordinator.owner.auth_selection(operation))
            .map_err(owner_fault)?
            .configuration
    } else {
        None
    };
    let rights = match method.rights() {
        MethodRights::Static(rights) => rights
            .to_vec()
            .try_into()
            .map_err(|_| fault(ErrorCode::ScopeDenied))?,
        _ => return Err(fault(ErrorCode::UnsupportedCapability)),
    };
    let binding = OperationBinding {
        rights: StoredOperationRights::new(
            operation_id,
            connection.connection.actor(),
            workspace,
            method,
            rights,
            false,
        )
        .map_err(|_| fault(ErrorCode::ScopeDenied))?,
        parameter_hash: parameter_hash(&call).map_err(stored)?,
    };
    let slot = CompletionSlot::reserve(coordinator, operation, workspace)?;
    let mut admission_turn = owner_call(operation, || {
        coordinator
            .owner
            .begin_admit_external(operation, &binding, project.state.domain_revision)
    })
    .map_err(owner_fault)?;
    let admitted = owner_call(operation, || admission_turn.try_commit());
    drop(admission_turn);
    let admission = match admitted {
        Ok(admission) => admission,
        Err(error) => {
            slot.defer(DeferredCompletion::Cancel { binding });
            return Err(owner_fault(error));
        }
    };
    if !admission.newly_admitted {
        return Ok(git_receipt_result(method, admission.receipt));
    }
    let (started, retained_permit) = match owner_call(operation, || {
        coordinator.owner.begin_start_external(operation, &binding)
    }) {
        Ok(mut start) => {
            let started = owner_call(operation, || start.try_commit());
            let retained = if started.is_err() {
                start.take_started_permit()
            } else {
                None
            };
            drop(start);
            (started, retained)
        }
        Err(error) => (Err(error), None),
    };
    let permit = match started {
        Ok(permit) => permit,
        Err(error) => {
            if let Some(permit) = retained_permit {
                slot.defer(DeferredCompletion::Complete {
                    binding,
                    permit,
                    state: OperationState::Failed,
                    effect: Effect::None,
                    result: None,
                    projection: None,
                });
            } else {
                slot.defer(DeferredCompletion::Cancel { binding });
            }
            return Err(owner_fault(error));
        }
    };

    let mut job = match coordinator.git_mutations.start(
        context.clone(),
        project.local_root,
        call,
        operation.deadline(),
    ) {
        Ok(job) => job,
        Err(error) => {
            let _ = finish_external(
                &slot,
                operation,
                binding,
                permit,
                OperationState::Failed,
                Effect::None,
                None,
                None,
                false,
            )?;
            return Err(error);
        }
    };
    let cancellation = job.cancellation();
    let control =
        lomi_git::RequestControl::with_deadline(cancellation.clone(), operation.deadline());
    let prepared = loop {
        if operation.check().is_err() {
            cancellation.cancel();
            let _ = finish_external(
                &slot,
                operation,
                binding,
                permit,
                OperationState::Failed,
                Effect::None,
                None,
                None,
                false,
            )?;
            return Err(fault(ErrorCode::DeadlineExceeded));
        }
        match job.poll() {
            std::task::Poll::Ready(result) => break result,
            std::task::Poll::Pending => thread::park_timeout(Duration::from_millis(1)),
        }
    };
    drop(job);
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            let _ = finish_external(
                &slot,
                operation,
                binding,
                permit,
                OperationState::Failed,
                Effect::None,
                None,
                None,
                false,
            )?;
            return Err(error);
        }
    };

    let execution = match prepared {
        super::remote_git_mutations::PreparedGitOperation::Publish(mutation) => mutation
            .publish_for_receipt_guarded(&control, || {
                local_external_current(coordinator, operation, &permit)
            })
            .map_err(GitDispatchFailure::from_service)
            .map(|token| {
                (
                    OperationState::Succeeded,
                    Effect::Committed,
                    Some(OperationResult::Git {
                        repo_state_token: token,
                    }),
                    true,
                )
            }),
        network => {
            let credentials = super::remote_git_mutations::credentials_provider(
                coordinator.profile.clone(),
                credential_configuration,
            );
            network
                .dispatch_network(&control, credentials.as_ref(), || {
                    if local_external_current(coordinator, operation, &permit) {
                        Ok(())
                    } else {
                        Err(lomi_git::GitServiceError::Cancelled)
                    }
                })
                .map_err(GitDispatchFailure::from_service)
                .and_then(|network| match network {
                    super::remote_git_mutations::NetworkResult::Publication(publication) => {
                        publication
                            .publish_for_receipt_guarded(&control, || {
                                local_external_current(coordinator, operation, &permit)
                            })
                            .map(|token| {
                                (
                                    OperationState::Succeeded,
                                    Effect::Committed,
                                    Some(OperationResult::Git {
                                        repo_state_token: token,
                                    }),
                                    true,
                                )
                            })
                            .map_err(GitDispatchFailure::from_service)
                    }
                    super::remote_git_mutations::NetworkResult::Push {
                        outcome,
                        repo_state_token,
                    } => match outcome {
                        lomi_git::GitPushOutcome::Committed => Ok((
                            OperationState::Succeeded,
                            Effect::Committed,
                            Some(OperationResult::Git { repo_state_token }),
                            true,
                        )),
                        lomi_git::GitPushOutcome::PossibleRemoteEffect => {
                            Ok((OperationState::OutcomeUnknown, Effect::Unknown, None, true))
                        }
                        lomi_git::GitPushOutcome::NoEffect => Err(GitDispatchFailure::NoEffect(
                            lomi_git::GitServiceError::NetworkFailed,
                        )),
                        lomi_git::GitPushOutcome::Rejected => Err(GitDispatchFailure::NoEffect(
                            lomi_git::GitServiceError::PushRejected,
                        )),
                        lomi_git::GitPushOutcome::FailedNoEffect(error) => {
                            Err(GitDispatchFailure::NoEffect(error))
                        }
                    },
                })
        }
    };
    let (state, effect, result, physical_effect) = match execution {
        Ok(outcome) => outcome,
        Err(GitDispatchFailure::NoEffect(error)) => {
            let _ = finish_external(
                &slot,
                operation,
                binding,
                permit,
                OperationState::Failed,
                Effect::None,
                None,
                None,
                false,
            )?;
            return Err(super::remote_git_mutations::map_error(error));
        }
        Err(GitDispatchFailure::Unknown) => {
            (OperationState::OutcomeUnknown, Effect::Unknown, None, true)
        }
    };
    let receipt = finish_external(
        &slot,
        operation,
        binding,
        permit,
        state,
        effect,
        result,
        None,
        physical_effect,
    )?;
    Ok(git_receipt_result(method, receipt))
}

enum GitDispatchFailure {
    NoEffect(lomi_git::GitServiceError),
    Unknown,
}
impl GitDispatchFailure {
    fn from_service(error: lomi_git::GitServiceError) -> Self {
        if matches!(
            error,
            lomi_git::GitServiceError::MutationOutcomeUnknown
                | lomi_git::GitServiceError::NetworkOutcomeUnknown
        ) {
            Self::Unknown
        } else {
            Self::NoEffect(error)
        }
    }
}
