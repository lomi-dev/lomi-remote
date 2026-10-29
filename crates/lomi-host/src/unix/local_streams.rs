//! Local views consume the same workspace and watch frames as remote clients.
//! Snapshot buffers and unacknowledged events have fixed bounds. Owner revision
//! hints avoid reading SQLite while a workspace is idle; every changed view is
//! still read through the owner, never authorized by the hint itself.
use super::{Coordinator, owner_domain::Operation, remote_files_watch::RemoteWatch};
use lomi_remote_protocol::{ipc::*, rpc::*, streams::*, *};
use std::{collections::VecDeque, time::Instant};

const MAX_SNAPSHOT: usize = 8 * 1024 * 1024;
const MAX_PENDING: usize = 8;

fn fault(code: ErrorCode) -> RemoteError {
    RemoteError::new(code, false, Effect::None, ErrorDetails::empty(), None)
        .expect("closed local stream error")
}

fn current(
    coordinator: &Coordinator,
    context: &WorkspaceContext,
    operation: &Operation<'_>,
) -> Result<WorkspaceState, RemoteError> {
    let project = super::rpc::owner_call(operation, || {
        coordinator.owner.workspace(operation, context.workspace_id)
    })
    .map_err(|_| fault(ErrorCode::ServiceUnavailable))?;
    if &project.state.context != context {
        return Err(fault(ErrorCode::StaleEpoch));
    }
    Ok(project.state)
}

fn cursor(state: &WorkspaceState) -> Result<EventCursor, RemoteError> {
    format!(
        "{}-{}",
        String::from(state.context.workspace_epoch),
        state.domain_revision.0
    )
    .try_into()
    .map_err(|_| fault(ErrorCode::ResourceExhausted))
}

pub(super) struct Workspace {
    context: WorkspaceContext,
    id: SubscriptionId,
    bytes: Option<Vec<u8>>,
    position: usize,
    revision: DecimalU64,
    hint: u64,
    sequence: u64,
    pending: VecDeque<(u64, EventCursor)>,
    last_ack: Option<(u64, EventCursor)>,
    snapshot_cursor: EventCursor,
    finished: bool,
}

impl Workspace {
    fn open(
        coordinator: &Coordinator,
        params: &WorkspaceSubscribeParams,
        operation: &Operation<'_>,
    ) -> Result<(Self, WorkspaceSnapshotMetadata), RemoteError> {
        let hint = coordinator.owner.projection_hint().unwrap_or(0);
        let state = current(coordinator, &params.context, operation)?;
        operation
            .check()
            .map_err(|_| fault(ErrorCode::DeadlineExceeded))?;
        Self::open_projected(state, hint)
    }

    /// The remote caller must supply its freshly authorized, projected state.
    /// Local roots/private views must never be passed to a remote subscriber.
    pub(super) fn open_projected(
        state: WorkspaceState,
        hint: u64,
    ) -> Result<(Self, WorkspaceSnapshotMetadata), RemoteError> {
        let bytes = serde_json::to_vec(&state).map_err(|_| fault(ErrorCode::ResourceExhausted))?;
        if bytes.is_empty() || bytes.len() > MAX_SNAPSHOT {
            return Err(fault(ErrorCode::ResourceExhausted));
        }
        let id: SubscriptionId = format!("workspace-{}", uuid::Uuid::new_v4())
            .try_into()
            .map_err(|_| fault(ErrorCode::ResourceExhausted))?;
        let cursor = cursor(&state)?;
        let metadata = WorkspaceSnapshotMetadata {
            context: state.context.clone(),
            domain_revision: state.domain_revision,
            subscription_id: id.clone(),
            through_seq: WorkspaceEventSeq(DecimalU64(0)),
            cursor: cursor.clone(),
            chunk_count: ChunkCount(bytes.len().div_ceil(16384) as u32),
            total_bytes: DecimalU64(bytes.len() as u64),
        };
        Ok((
            Self {
                context: state.context.clone(),
                id,
                bytes: Some(bytes),
                position: 0,
                revision: state.domain_revision,
                hint,
                sequence: 0,
                pending: VecDeque::new(),
                last_ack: None,
                snapshot_cursor: cursor,
                finished: false,
            },
            metadata,
        ))
    }

    fn resync(&mut self, reason: ResyncReason) -> WorkspaceStreamFrame {
        self.finished = true;
        self.bytes = None;
        self.pending.clear();
        WorkspaceStreamFrame::ResyncRequired(WorkspaceResync {
            context: self.context.clone(),
            subscription_id: self.id.clone(),
            reason,
        })
    }

    fn next_snapshot(&mut self) -> Option<WorkspaceStreamFrame> {
        if self.finished {
            return None;
        }
        if let Some(bytes) = &self.bytes {
            if self.position < bytes.len() {
                let index = self.position / 16384;
                let end = (self.position + 16384).min(bytes.len());
                let chunk = bytes[self.position..end].to_vec();
                self.position = end;
                return Some(WorkspaceStreamFrame::SnapshotChunk(
                    WorkspaceSnapshotChunk {
                        subscription_id: self.id.clone(),
                        index: ChunkIndex(index as u32),
                        bytes: BoundedList(chunk),
                    },
                ));
            }
            self.bytes = None;
            self.pending.push_back((0, self.snapshot_cursor.clone()));
            return Some(WorkspaceStreamFrame::SnapshotComplete(
                WorkspaceSnapshotComplete {
                    subscription_id: self.id.clone(),
                    through_seq: WorkspaceEventSeq(DecimalU64(0)),
                    cursor: self.snapshot_cursor.clone(),
                },
            ));
        }
        None
    }

    fn next(
        &mut self,
        coordinator: &Coordinator,
        operation: &Operation<'_>,
    ) -> Option<WorkspaceStreamFrame> {
        if self.finished || operation.check().is_err() {
            return None;
        }
        if let Some(frame) = self.next_snapshot() {
            return Some(frame);
        }
        if self.pending.len() >= MAX_PENDING {
            return None;
        }
        let hint = coordinator.owner.projection_hint()?;
        if hint == self.hint {
            return None;
        }
        // This connection owns no authority derived from the revision hint.
        // Busy leaves the old hint so the view is retried after the writer.
        let project = match coordinator
            .owner
            .workspace(operation, self.context.workspace_id)
        {
            Ok(value) => value,
            Err(super::shared_owner::Error::Domain(super::owner_domain::Error::Busy))
            | Err(super::shared_owner::Error::Store(lomi_host_store::StoreError::Busy)) => {
                return None;
            }
            Err(_) => return Some(self.resync(ResyncReason::WorkspaceEpochChanged)),
        };
        self.hint = hint;
        self.next_projected(project.state)
    }

    /// Fresh proof/disclosure gates remain the remote caller's responsibility,
    /// including for each encoded fragment of a snapshot or event.
    pub(super) fn next_projected(&mut self, state: WorkspaceState) -> Option<WorkspaceStreamFrame> {
        if self.finished {
            return None;
        }
        if state.context != self.context {
            return Some(self.resync(ResyncReason::WorkspaceEpochChanged));
        }
        if let Some(frame) = self.next_snapshot() {
            return Some(frame);
        }
        if self.pending.len() >= MAX_PENDING || state.domain_revision == self.revision {
            return None;
        }
        let Some(next) = self.sequence.checked_add(1) else {
            return Some(self.resync(ResyncReason::SubscriberOverflow));
        };
        let cursor = match cursor(&state) {
            Ok(value) => value,
            Err(_) => return Some(self.resync(ResyncReason::SubscriberOverflow)),
        };
        let event = WorkspaceEvent {
            context: self.context.clone(),
            subscription_id: self.id.clone(),
            event_seq: WorkspaceEventSeq(DecimalU64(next)),
            cursor: cursor.clone(),
            data: WorkspaceEventData::WorkspaceChanged(WorkspaceChanged {
                domain_revision: state.domain_revision,
                operation_id: None,
                state,
            }),
        };
        if serde_json::to_vec(&event).map_or(true, |bytes| bytes.len() > LOCAL_IPC_FRAME_BYTES / 2)
        {
            return Some(self.resync(ResyncReason::SubscriberOverflow));
        }
        self.sequence = next;
        if let WorkspaceEventData::WorkspaceChanged(value) = &event.data {
            self.revision = value.domain_revision;
        }
        self.pending.push_back((next, cursor));
        Some(WorkspaceStreamFrame::Event(event))
    }

    pub(super) fn ack(&mut self, ack: &WorkspaceStreamAck) -> bool {
        if self.finished || ack.context != self.context || ack.subscription_id != self.id {
            return false;
        }
        let target = (ack.through_seq.0.0, ack.cursor.clone());
        if self.last_ack.as_ref() == Some(&target) {
            return true;
        }
        if !self.pending.iter().any(|value| value == &target) {
            return false;
        }
        while self
            .pending
            .front()
            .is_some_and(|(sequence, _)| *sequence <= target.0)
        {
            self.pending.pop_front();
        }
        self.last_ack = Some(target);
        true
    }
}

struct Watch {
    inner: RemoteWatch,
    context: WorkspaceContext,
    id: SubscriptionId,
    hint: u64,
}

#[derive(Default)]
pub(super) struct Streams {
    workspace: Option<Workspace>,
    watch: Option<Watch>,
    watch_generation: u64,
    watch_turn: bool,
}

impl Streams {
    pub(super) fn subscribe_workspace(
        &mut self,
        coordinator: &Coordinator,
        params: &WorkspaceSubscribeParams,
        operation: &Operation<'_>,
    ) -> Result<RpcResult, RemoteError> {
        self.workspace = None;
        let (stream, metadata) = Workspace::open(coordinator, params, operation)?;
        self.workspace = Some(stream);
        Ok(RpcResult::WorkspaceSubscribe(metadata))
    }

    pub(super) fn watch_files(
        &mut self,
        coordinator: &Coordinator,
        params: &FilesWatchParams,
        operation: &Operation<'_>,
    ) -> Result<RpcResult, RemoteError> {
        self.watch = None;
        let hint = coordinator.owner.projection_hint().unwrap_or(0);
        let project = super::rpc::owner_call(operation, || {
            coordinator
                .owner
                .workspace(operation, params.context.workspace_id)
        })
        .map_err(|_| fault(ErrorCode::ServiceUnavailable))?;
        if project.state.context != params.context {
            return Err(fault(ErrorCode::StaleEpoch));
        }
        self.watch_generation = self
            .watch_generation
            .checked_add(1)
            .ok_or_else(|| fault(ErrorCode::ResourceExhausted))?;
        let files = coordinator.files.get(
            params.context.workspace_id,
            params.context.workspace_epoch,
            &project.local_root,
        )?;
        let (inner, result) =
            RemoteWatch::open(files, params, self.watch_generation, Instant::now())?;
        operation
            .check()
            .map_err(|_| fault(ErrorCode::DeadlineExceeded))?;
        self.watch = Some(Watch {
            inner,
            context: params.context.clone(),
            id: result.subscription_id.clone(),
            hint,
        });
        Ok(RpcResult::FilesWatch(result))
    }

    pub(super) fn acknowledge(&mut self, ack: LocalStreamAck) -> Result<LocalResult, LocalError> {
        let (accepted, id) = match ack {
            LocalStreamAck::Workspace(value) => (
                self.workspace
                    .as_mut()
                    .is_some_and(|stream| stream.ack(&value)),
                value.subscription_id,
            ),
            LocalStreamAck::Files(value) => (
                self.watch
                    .as_mut()
                    .is_some_and(|watch| watch.inner.ack(&value)),
                value.subscription_id,
            ),
        };
        if !accepted {
            return Err(LocalError::Conflict);
        }
        Ok(LocalResult::StreamAcknowledged(id))
    }

    fn next_watch(
        &mut self,
        coordinator: &Coordinator,
        operation: &Operation<'_>,
    ) -> Option<LocalStreamEvent> {
        let watch = self.watch.as_mut()?;
        if let Some(hint) = coordinator.owner.projection_hint() {
            if hint != watch.hint {
                match coordinator
                    .owner
                    .workspace(operation, watch.context.workspace_id)
                {
                    Ok(project) if project.state.context == watch.context => watch.hint = hint,
                    Err(super::shared_owner::Error::Domain(super::owner_domain::Error::Busy))
                    | Err(super::shared_owner::Error::Store(lomi_host_store::StoreError::Busy)) => {
                        return None;
                    }
                    _ => {
                        let frame = FileWatchFrame::ResyncRequired(WorkspaceResync {
                            context: watch.context.clone(),
                            subscription_id: watch.id.clone(),
                            reason: ResyncReason::WorkspaceEpochChanged,
                        });
                        self.watch = None;
                        return Some(LocalStreamEvent::Files(frame));
                    }
                }
            }
        }
        watch
            .inner
            .poll(Instant::now())
            .map(LocalStreamEvent::Files)
    }

    pub(super) fn next(
        &mut self,
        coordinator: &Coordinator,
        operation: &Operation<'_>,
    ) -> Option<LocalStreamEvent> {
        if operation.check().is_err() {
            return None;
        }
        self.watch_turn = !self.watch_turn;
        if self.watch_turn {
            if let Some(event) = self.next_watch(coordinator, operation) {
                return Some(event);
            }
        }
        if let Some(event) = self
            .workspace
            .as_mut()
            .and_then(|stream| stream.next(coordinator, operation))
        {
            return Some(LocalStreamEvent::Workspace(event));
        }
        if !self.watch_turn {
            return self.next_watch(coordinator, operation);
        }
        None
    }
}
