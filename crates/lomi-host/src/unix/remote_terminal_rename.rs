//! Fixed remote terminal.rename / terminal.move journal kernel and delivery.
//! Production move ingress activation is a separate integration boundary.
//! Never call local RPC mutation/dispatch or reuse a receipt for another message.
use super::{
    Coordinator,
    auth::{
        RemoteWorkerEvidence,
        peer::VerifiedCurrentPeer,
        remote_connection::{QueuedRequest, RemoteConnectionState, SealedRemoteRenameReceipt},
    },
    rpc,
    shared_owner::{
        RemoteRenameBegin, RemoteRenameError, RemoteRenameIoWatch, RemoteRenameReceipt,
    },
};
use lomi_remote_protocol::{
    OperationReceipt,
    message_framing::{MAX_FRAGMENT_PAYLOAD_LEN, MessageEncoder, MessageKind},
    rpc::*,
};
use std::{
    sync::Weak,
    time::{Duration, Instant},
};

/// Closed operation view. Every production view borrows the exact queued call;
/// wire mutation context/hash are never translated into local authority.
pub(super) enum RemoteTerminalEdit<'a> {
    Rename(&'a TerminalRenameParams),
    Move(&'a TerminalMoveParams),
    // OS-effect lifecycle operations. They never use the single-transaction
    // rename/move commit; see `remote_terminal_lifecycle`.
    Create(&'a TerminalCreateParams),
    Split(&'a TerminalSplitParams),
    Close(&'a TerminalCloseParams),
    Restart(&'a TerminalRestartParams),
}
impl<'a> RemoteTerminalEdit<'a> {
    pub(super) fn from_call(call: &'a RpcCall) -> Result<Self, RemoteRenameError> {
        match call {
            RpcCall::TerminalRename(params) => Ok(Self::Rename(params)),
            RpcCall::TerminalMove(params) => Ok(Self::Move(params)),
            RpcCall::TerminalCreate(params) => Ok(Self::Create(params)),
            RpcCall::TerminalSplit(params) => Ok(Self::Split(params)),
            RpcCall::TerminalClose(params) => Ok(Self::Close(params)),
            RpcCall::TerminalRestart(params) => Ok(Self::Restart(params)),
            _ => Err(RemoteRenameError::Closed),
        }
    }
    /// True for operations that start/stop a PTY and so need the two-turn
    /// effect lifecycle instead of one atomic Store transaction.
    pub(super) fn is_effect(&self) -> bool {
        matches!(
            self,
            Self::Create(_) | Self::Split(_) | Self::Close(_) | Self::Restart(_)
        )
    }
    pub(super) fn mutation(&self) -> &lomi_remote_protocol::MutationContext {
        match self {
            Self::Rename(params) => &params.mutation,
            Self::Move(params) => &params.mutation,
            Self::Create(params) => &params.mutation,
            Self::Split(params) => &params.mutation,
            Self::Close(params) => &params.mutation,
            Self::Restart(params) => &params.mutation,
        }
    }
    pub(super) fn method(&self) -> lomi_remote_protocol::Method {
        match self {
            Self::Rename(_) => lomi_remote_protocol::Method::TerminalRename,
            Self::Move(_) => lomi_remote_protocol::Method::TerminalMove,
            Self::Create(_) => lomi_remote_protocol::Method::TerminalCreate,
            Self::Split(_) => lomi_remote_protocol::Method::TerminalSplit,
            Self::Close(_) => lomi_remote_protocol::Method::TerminalClose,
            Self::Restart(_) => lomi_remote_protocol::Method::TerminalRestart,
        }
    }
    /// Postview expectation uses verified LOCAL prestate and preserves its
    /// context and every descriptor; only this edit and one revision may differ.
    /// Effect operations derive their expectation from the sealed plan instead.
    pub(super) fn expected_state(
        &self,
        before: &WorkspaceState,
    ) -> Result<WorkspaceState, RemoteRenameError> {
        let mut expected = match self {
            Self::Rename(params) => {
                let mut expected = before.clone();
                expected
                    .tabs
                    .0
                    .iter_mut()
                    .find(|tab| tab.tab_id == params.tab_id)
                    .ok_or(RemoteRenameError::Closed)?
                    .name = params.name.clone();
                expected
            }
            Self::Move(params) => lomi_host_store::plan_terminal_move(
                before,
                &lomi_host_store::TerminalMoveLayout::from(*params),
            )
            .map_err(|_| RemoteRenameError::Closed)?,
            Self::Create(_) | Self::Split(_) | Self::Close(_) | Self::Restart(_) => {
                return Err(RemoteRenameError::Closed);
            }
        };
        expected.domain_revision.0 = expected
            .domain_revision
            .0
            .checked_add(1)
            .ok_or(RemoteRenameError::Closed)?;
        Ok(expected)
    }
}

pub(super) enum RemoteRenameOutcome<'d, 'o, 'e, 'w, 'p, 's> {
    /// Must use ordinary current response/IO checks, no publication exception.
    Duplicate(OperationReceipt),
    Committed(Box<RemoteRenameReceipt<'d, 'o, 'e, 'w, 'p, 's>>),
    /// Rejected before any journal write or effect. Answered with an ordinary
    /// error response on the still-usable connection (no receipt exists).
    Rejected(lomi_remote_protocol::RemoteError),
}
fn file_mutation_workspace(call: &RpcCall) -> Option<lomi_remote_protocol::WorkspaceId> {
    match call {
        RpcCall::FilesCreate(p) | RpcCall::FilesMkdir(p) => Some(p.mutation.context.workspace_id),
        RpcCall::FilesRename(p) => Some(p.mutation.context.workspace_id),
        RpcCall::FilesRemove(p) => Some(p.mutation.context.workspace_id),
        _ => None,
    }
}
pub(super) fn execute<'d, 'o, 'e, 'w, 'p, 's>(
    coordinator: &Weak<Coordinator>,
    connection: &mut RemoteConnectionState,
    worker: &'e RemoteWorkerEvidence<'w, 'p, 's, 'o>,
    peer: &'e VerifiedCurrentPeer,
    owner: &'d super::shared_owner::SharedOwner,
    original: &RpcRequest,
    queued: &QueuedRequest,
) -> Result<RemoteRenameOutcome<'d, 'o, 'e, 'w, 'p, 's>, RemoteRenameError> {
    let result = (|| {
        let coordinator = coordinator.upgrade().ok_or(RemoteRenameError::Closed)?;
        if let Some(workspace) = file_mutation_workspace(&original.call) {
            // Explorer mutations share the effect kernel but never touch
            // terminal sessions, so there is nothing to reconcile first.
            if !std::ptr::eq(coordinator.owner.as_ref(), owner)
                || !std::ptr::eq(owner, worker.owner())
            {
                return Err(RemoteRenameError::Closed);
            }
            let project = rpc::owner_call(worker.operation(), || {
                owner.workspace(worker.operation(), workspace)
            })
            .map_err(RemoteRenameError::Owner)?;
            let plan = super::shared_owner::RemoteFilePlan {
                call: original.call.clone(),
                workspace_id: workspace,
                epoch: project.state.context.workspace_epoch,
                root: project.local_root,
            };
            let ids = super::remote_file_namespace::mutation_lock_ids(
                &coordinator,
                worker.operation(),
                &plan,
            )
            .map_err(|_| RemoteRenameError::Closed)?;
            let actors = ids
                .iter()
                .map(|id| {
                    coordinator
                        .workspace_lock(*id)
                        .map_err(|_| RemoteRenameError::Closed)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut guards = Vec::with_capacity(actors.len());
            for actor in &actors {
                guards.push(
                    rpc::actor_lock(actor, worker.operation())
                        .map_err(|_| RemoteRenameError::Closed)?,
                );
            }
            for id in &ids {
                rpc::ensure_workspace_settled(&coordinator, *id)
                    .map_err(|_| RemoteRenameError::Closed)?;
            }
            return super::remote_terminal_lifecycle::run(
                &coordinator,
                connection,
                worker,
                peer,
                owner,
                original,
                queued,
                Some(&ids),
            );
        }
        let edit = RemoteTerminalEdit::from_call(&original.call)?;
        if edit.is_effect() {
            // Exited sessions are recorded under their own writers BEFORE this
            // operation takes the workspace actor, exactly like local mutate.
            rpc::reconcile_terminal_lifecycle(&coordinator, worker.operation())
                .map_err(|_| RemoteRenameError::Closed)?;
        }
        if !std::ptr::eq(coordinator.owner.as_ref(), owner) || !std::ptr::eq(owner, worker.owner())
        {
            return Err(RemoteRenameError::Closed);
        }
        let actor = coordinator
            .workspace_lock(edit.mutation().context.workspace_id)
            .map_err(|_| RemoteRenameError::Closed)?;
        let _actor =
            rpc::actor_lock(&actor, worker.operation()).map_err(|_| RemoteRenameError::Closed)?;
        // Initial admission errors close/withhold. An opaque queue ticket is not
        // re-admitted after before_remote_rename has consumed it.
        let begin = match edit {
            RemoteTerminalEdit::Rename(_) => {
                owner.begin_remote_terminal_rename(worker, peer, connection, original, queued)
            }
            RemoteTerminalEdit::Move(_) => {
                owner.begin_remote_terminal_move(worker, peer, connection, original, queued)
            }
            RemoteTerminalEdit::Create(_)
            | RemoteTerminalEdit::Split(_)
            | RemoteTerminalEdit::Close(_)
            | RemoteTerminalEdit::Restart(_) => {
                return super::remote_terminal_lifecycle::run(
                    &coordinator,
                    connection,
                    worker,
                    peer,
                    owner,
                    original,
                    queued,
                    None,
                );
            }
        }?;
        match begin {
            RemoteRenameBegin::Duplicate(receipt) => Ok(RemoteRenameOutcome::Duplicate(receipt)),
            RemoteRenameBegin::Rejected(error) => Ok(RemoteRenameOutcome::Rejected(error)),
            RemoteRenameBegin::Write(mut write) => loop {
                if !worker.current() {
                    return Err(RemoteRenameError::Closed);
                }
                match write.try_commit() {
                    Err(RemoteRenameError::Owner(super::shared_owner::Error::Domain(
                        super::owner_domain::Error::Busy,
                    )))
                    | Err(RemoteRenameError::Owner(super::shared_owner::Error::Store(
                        lomi_host_store::StoreError::Busy,
                    ))) => {
                        worker
                            .operation()
                            .check()
                            .map_err(|_| RemoteRenameError::Closed)?;
                        std::thread::park_timeout(
                            worker
                                .operation()
                                .deadline()
                                .saturating_duration_since(Instant::now())
                                .min(Duration::from_millis(1)),
                        );
                    }
                    Ok(receipt) => break Ok(RemoteRenameOutcome::Committed(Box::new(receipt))),
                    Err(error) => {
                        break match write.take_rejection() {
                            Some(rejection) => Ok(RemoteRenameOutcome::Rejected(rejection)),
                            None => Err(error),
                        };
                    }
                }
            },
        }
    })();
    // Actor/Domain/Store turns have dropped, including every error/uncertain path.
    if result.is_err() {
        connection.dispose();
    }
    result
}

/// Move-only entire original RpcResponse (including RequestId) + one encoder
/// fragment. Private fields prevent arbitrary plaintext/publication exceptions.
pub(super) struct RemoteRenameResponseFrame<'d, 'o, 'e, 'w, 'p, 's> {
    receipt: RemoteRenameReceipt<'d, 'o, 'e, 'w, 'p, 's>,
    bytes: Vec<u8>,
}
fn encode_receipt_response(
    response: &RpcResponse,
    encoder: &mut MessageEncoder,
) -> Result<Vec<u8>, RemoteRenameError> {
    let (receipt, method) = match response {
        RpcResponse::Result {
            result: RpcResult::TerminalRename(receipt),
            ..
        } => (receipt, lomi_remote_protocol::Method::TerminalRename),
        RpcResponse::Result {
            result: RpcResult::TerminalMove(receipt),
            ..
        } => (receipt, lomi_remote_protocol::Method::TerminalMove),
        RpcResponse::Result {
            result: RpcResult::TerminalCreate(receipt),
            ..
        } => (receipt, lomi_remote_protocol::Method::TerminalCreate),
        RpcResponse::Result {
            result: RpcResult::TerminalSplit(receipt),
            ..
        } => (receipt, lomi_remote_protocol::Method::TerminalSplit),
        RpcResponse::Result {
            result: RpcResult::TerminalClose(receipt),
            ..
        } => (receipt, lomi_remote_protocol::Method::TerminalClose),
        RpcResponse::Result {
            result: RpcResult::TerminalRestart(receipt),
            ..
        } => (receipt, lomi_remote_protocol::Method::TerminalRestart),
        RpcResponse::Result {
            result: RpcResult::FilesCreate(receipt),
            ..
        } => (receipt, lomi_remote_protocol::Method::FilesCreate),
        RpcResponse::Result {
            result: RpcResult::FilesMkdir(receipt),
            ..
        } => (receipt, lomi_remote_protocol::Method::FilesMkdir),
        RpcResponse::Result {
            result: RpcResult::FilesRename(receipt),
            ..
        } => (receipt, lomi_remote_protocol::Method::FilesRename),
        RpcResponse::Result {
            result: RpcResult::FilesRemove(receipt),
            ..
        } => (receipt, lomi_remote_protocol::Method::FilesRemove),
        // A durable known-no-effect file refusal: only an effect-less error
        // for a file method with the operation id of its own receipt.
        RpcResponse::Error {
            error,
            operation_id: Some(_),
            ..
        } if error.effect() == lomi_remote_protocol::Effect::None => {
            return encode_frame(response, encoder);
        }
        _ => return Err(RemoteRenameError::Closed),
    };
    if receipt.state() != lomi_remote_protocol::OperationState::Succeeded
        || receipt.effect() != lomi_remote_protocol::Effect::Committed
        || receipt.stored_rights().original_method() != method
    {
        return Err(RemoteRenameError::Closed);
    }
    encode_frame(response, encoder)
}
fn encode_frame(
    response: &RpcResponse,
    encoder: &mut MessageEncoder,
) -> Result<Vec<u8>, RemoteRenameError> {
    let bytes = serde_json::to_vec(response).map_err(|_| RemoteRenameError::Closed)?;
    if bytes.is_empty() || bytes.len() > MAX_FRAGMENT_PAYLOAD_LEN {
        return Err(RemoteRenameError::Closed);
    }
    encoder
        .begin(MessageKind::RpcResponse, bytes)
        .map_err(|_| RemoteRenameError::Closed)?;
    let bytes = encoder
        .next_frame()
        .map_err(|_| RemoteRenameError::Closed)?
        .ok_or(RemoteRenameError::Closed)?;
    if encoder
        .next_frame()
        .map_err(|_| RemoteRenameError::Closed)?
        .is_some()
    {
        return Err(RemoteRenameError::Closed);
    }
    Ok(bytes)
}
impl<'d, 'o, 'e, 'w, 'p, 's> RemoteRenameResponseFrame<'d, 'o, 'e, 'w, 'p, 's> {
    pub(super) fn encode(
        receipt: RemoteRenameReceipt<'d, 'o, 'e, 'w, 'p, 's>,
        encoder: &mut MessageEncoder,
    ) -> Result<Self, RemoteRenameError> {
        // All owner/actor locks were dropped by execute before serialization.
        // The response and RequestId come only from the sealed original request.
        let bytes = encode_receipt_response(&receipt.response(), encoder)?;
        Ok(Self { receipt, bytes })
    }
    pub(super) fn receipt(&self) -> &RemoteRenameReceipt<'d, 'o, 'e, 'w, 'p, 's> {
        &self.receipt
    }
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// The only sealing boundary consumes this actual frame. Ciphertext and
    /// the one-send capability are constructed privately by the connection.
    pub(super) fn seal(
        self,
        connection: &mut RemoteConnectionState,
    ) -> Result<SealedRemoteRenameReceipt<'d, 'o, 'e, 'w, 'p, 's>, RemoteRenameError> {
        connection.seal_remote_rename_receipt(self)
    }
    /// Ownership-only join: consuming the frame cannot export ciphertext or
    /// retain a second response capable of sealing with this receipt stamp.
    pub(super) fn consume_into_io_watch(self) -> RemoteRenameIoWatch<'d, 'o, 'e, 'w, 'p, 's> {
        self.receipt.into_io_watch()
    }
}
