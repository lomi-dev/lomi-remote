use super::{Error, RemoteWorkspaceTurn, SharedOwner, StoreError};
use crate::unix::auth::{RemoteWorkerEvidence, peer::VerifiedCurrentPeer};
use lomi_remote_protocol::{
    CapabilitySet, ConsumerAuthorizationId, Method, OperationId, OperationReceipt,
    StoredOperationRights, WorkspaceContext,
    rpc::{RpcCall, RpcRequest, RpcResponse, RpcResult},
};
use std::time::Instant;

/// Store-derived authority for disclosing one exact durable operation receipt.
/// Construction stays private to this module; RPC data cannot mint this proof.
#[derive(Clone)]
pub(in crate::unix) struct RemoteOperationAuthorization {
    request: RpcRequest,
    rights: StoredOperationRights,
    capabilities: CapabilitySet,
    context: WorkspaceContext,
    connection: uuid::Uuid,
    sequence: u64,
    deadline: Instant,
}

impl RemoteOperationAuthorization {
    fn from_started_git_receipt(
        receipt: &OperationReceipt,
        request: &RpcRequest,
        actor: ConsumerAuthorizationId,
        capabilities: &CapabilitySet,
        connection: uuid::Uuid,
        deadline: Instant,
    ) -> Option<Self> {
        let (method, context, operation_id) = operation_request(&request.call)?;
        if !matches!(method, Method::OperationStatus | Method::OperationCancel) {
            return None;
        }
        let rights = receipt.stored_rights();
        if receipt.operation_id() != operation_id
            || rights.operation_id() != operation_id
            || rights.actor() != actor
            || rights.workspace() != context.workspace_id
            || receipt
                .authorize_disclosure(capabilities, actor, context.workspace_id)
                .is_err()
            || Instant::now() >= deadline
        {
            return None;
        }
        Some(Self {
            request: request.clone(),
            rights,
            capabilities: capabilities.clone(),
            context: context.clone(),
            connection,
            // This proof has no queued Store ticket. Response gates omit the
            // queue sequence and retain only the request, channel and deadline.
            sequence: 0,
            deadline,
        })
    }

    fn from_receipt(
        receipt: &OperationReceipt,
        request: &RpcRequest,
        actor: ConsumerAuthorizationId,
        capabilities: &CapabilitySet,
        connection: &super::super::auth::remote_connection::RemoteConnectionState,
        queued: &super::super::auth::remote_connection::QueuedRequest,
    ) -> Option<Self> {
        let (method, context, operation_id) = operation_request(&request.call)?;
        let rights = receipt.stored_rights();
        if receipt.operation_id() != operation_id
            || rights.operation_id() != operation_id
            || rights.actor() != actor
            || rights.workspace() != context.workspace_id
            || capabilities
                .authorize_operation(
                    method,
                    operation_id,
                    actor,
                    context.workspace_id,
                    Some(&rights),
                )
                .is_err()
            || queued.connection_identity() != connection.connection_identity()
            || Instant::now() >= queued.deadline()
        {
            return None;
        }
        Some(Self {
            request: request.clone(),
            rights,
            capabilities: capabilities.clone(),
            context: context.clone(),
            connection: connection.connection_identity(),
            sequence: queued.sequence(),
            deadline: queued.deadline(),
        })
    }

    fn from_committed_receipt(receipt: &OperationReceipt, previous: &Self) -> Option<Self> {
        let (method, context, operation_id) = operation_request(&previous.request.call)?;
        let rights = receipt.stored_rights();
        if receipt.operation_id() != operation_id
            || context != &previous.context
            || !same_stored_rights(&rights, &previous.rights)
            || previous
                .capabilities
                .authorize_operation(
                    method,
                    operation_id,
                    rights.actor(),
                    context.workspace_id,
                    Some(&rights),
                )
                .is_err()
        {
            return None;
        }
        Some(Self {
            request: previous.request.clone(),
            rights,
            capabilities: previous.capabilities.clone(),
            context: previous.context.clone(),
            connection: previous.connection,
            sequence: previous.sequence,
            deadline: previous.deadline,
        })
    }

    /// Used only by the narrow operation-control gates in RemoteConnection.
    /// `sequence` is supplied after wait and omitted for already-retained
    /// response fragments; the proof always retains and checks its original
    /// connection, request, and deadline.
    pub(in crate::unix) fn allows(
        &self,
        request: &RpcRequest,
        context: &WorkspaceContext,
        actor: ConsumerAuthorizationId,
        capabilities: &CapabilitySet,
        connection: uuid::Uuid,
        sequence: Option<u64>,
    ) -> bool {
        let Some((method, request_context, operation_id)) = operation_request(&request.call) else {
            return false;
        };
        request == &self.request
            && method == self.request.call.method()
            && context == &self.context
            && request_context == &self.context
            && actor == self.rights.actor()
            && operation_id == self.rights.operation_id()
            && request_context.workspace_id == self.rights.workspace()
            && connection == self.connection
            && sequence.is_none_or(|sequence| sequence == self.sequence)
            && Instant::now() < self.deadline
            && capabilities
                .authorize_operation(
                    method,
                    operation_id,
                    actor,
                    request_context.workspace_id,
                    Some(&self.rights),
                )
                .is_ok()
    }

    fn matches_request(
        &self,
        request: &RpcRequest,
        connection: uuid::Uuid,
        sequence: Option<u64>,
    ) -> bool {
        request == &self.request
            && connection == self.connection
            && sequence.is_none_or(|sequence| sequence == self.sequence)
            && Instant::now() < self.deadline
    }
}

/// An exact Store lookup or committed cancellation result, paired with the
/// immutable row rights used by channel and response gates.
pub(in crate::unix) struct RemoteOperationDisclosure {
    receipt: OperationReceipt,
    authorization: RemoteOperationAuthorization,
}

impl RemoteOperationDisclosure {
    pub(in crate::unix) fn from_started_git_receipt(
        receipt: OperationReceipt,
        request: &RpcRequest,
        actor: ConsumerAuthorizationId,
        capabilities: &CapabilitySet,
        connection: uuid::Uuid,
        deadline: Instant,
    ) -> Option<Self> {
        let authorization = RemoteOperationAuthorization::from_started_git_receipt(
            &receipt,
            request,
            actor,
            capabilities,
            connection,
            deadline,
        )?;
        Some(Self {
            receipt,
            authorization,
        })
    }

    pub(in crate::unix) fn authorization(&self) -> &RemoteOperationAuthorization {
        &self.authorization
    }

    pub(in crate::unix) fn response(
        &self,
        request: &RpcRequest,
    ) -> Result<RpcResponse, super::super::auth::remote_connection::GateError> {
        if !self.authorization.matches_request(
            request,
            self.authorization.connection,
            Some(self.authorization.sequence),
        ) {
            return Err(super::super::auth::remote_connection::GateError::Denied);
        }
        let result = match request.call.method() {
            Method::OperationStatus => RpcResult::OperationStatus(self.receipt.clone()),
            Method::OperationCancel => RpcResult::OperationCancel(self.receipt.clone()),
            _ => return Err(super::super::auth::remote_connection::GateError::Denied),
        };
        Ok(RpcResponse::Result {
            v: request.v,
            request_id: request.request_id.clone(),
            result,
        })
    }
}

/// Proof that the exact operation-control request passed its post-wait gate.
/// Cancellation requires this value, so a Store write cannot precede that gate.
pub(in crate::unix) struct RemoteOperationReady {
    request: RpcRequest,
    authorization: Option<RemoteOperationAuthorization>,
    connection: uuid::Uuid,
    sequence: u64,
    deadline: Instant,
}

impl RemoteOperationReady {
    pub(in crate::unix) fn request(&self) -> &RpcRequest {
        &self.request
    }

    pub(in crate::unix) fn authorization(&self) -> Option<&RemoteOperationAuthorization> {
        self.authorization.as_ref()
    }

    fn matches(
        &self,
        request: &RpcRequest,
        connection: &super::super::auth::remote_connection::RemoteConnectionState,
        queued: &super::super::auth::remote_connection::QueuedRequest,
    ) -> bool {
        request == &self.request
            && connection.connection_identity() == self.connection
            && queued.connection_identity() == self.connection
            && queued.sequence() == self.sequence
            && queued.deadline() == self.deadline
            && Instant::now() < self.deadline
            && self.authorization.as_ref().is_some_and(|authorization| {
                authorization.matches_request(request, self.connection, Some(self.sequence))
            })
    }
}

/// A single owner turn may retry only contention before the cancellation Store
/// call. Once the named Store API has been called, its result is terminal.
pub(in crate::unix) enum RemoteOperationCancelProgress {
    Retry,
    Finished(Option<RemoteOperationDisclosure>),
}

/// Retains one actual Shared cancellation writer across pre-Store contention.
/// The peer continuation and owner ticket were registered while the exact
/// current RemoteWorkspaceTurn guard was still held.
pub(in crate::unix) struct RemoteOperationCancelTurn<'d, 'o, 'e, 'w, 'p, 's> {
    owner: &'d SharedOwner,
    worker: &'e RemoteWorkerEvidence<'w, 'p, 's, 'o>,
    pending: Option<super::domain::RemoteOperationCancelWrite<'d, 'o>>,
    before: super::PeerJournalRows,
    authorization: RemoteOperationAuthorization,
    request: RpcRequest,
    closed: bool,
}

impl RemoteOperationCancelTurn<'_, '_, '_, '_, '_, '_> {
    pub(in crate::unix) fn try_finish(&mut self) -> Result<RemoteOperationCancelProgress, Error> {
        if self.closed {
            return Err(Error::Domain(super::domain::Error::Stale));
        }
        if !self.authorization.matches_request(
            &self.request,
            self.authorization.connection,
            Some(self.authorization.sequence),
        ) || self.worker.operation().check().is_err()
            || !self.worker.current()
        {
            return self.abandon_before_store(Error::Domain(super::domain::Error::Stale));
        }
        let attempt = {
            let pending = self
                .pending
                .as_mut()
                .ok_or(Error::Domain(super::domain::Error::Stale))?;
            attempt_remote_operation_cancel(
                self.owner,
                self.worker,
                pending,
                &self.before,
                &self.authorization,
            )
        };
        match attempt {
            RemoteOperationCancelAttempt::Retry => Ok(RemoteOperationCancelProgress::Retry),
            RemoteOperationCancelAttempt::BeforeStore(error) => self.abandon_before_store(error),
            RemoteOperationCancelAttempt::KnownNoEffect(error) => {
                self.finish_writer()?;
                Err(Error::Store(error))
            }
            RemoteOperationCancelAttempt::Receipt(receipt) => {
                self.finish_writer()?;
                let Some(receipt) = receipt else {
                    return Ok(RemoteOperationCancelProgress::Finished(None));
                };
                let Some(authorization) = RemoteOperationAuthorization::from_committed_receipt(
                    &receipt,
                    &self.authorization,
                ) else {
                    return Err(Error::Domain(super::domain::Error::Stale));
                };
                Ok(RemoteOperationCancelProgress::Finished(Some(
                    RemoteOperationDisclosure {
                        receipt,
                        authorization,
                    },
                )))
            }
            RemoteOperationCancelAttempt::Uncertain(error) => {
                self.closed = true;
                drop(self.pending.take());
                Err(error)
            }
        }
    }

    fn finish_writer(&mut self) -> Result<(), Error> {
        self.closed = true;
        let pending = self
            .pending
            .take()
            .ok_or(Error::Domain(super::domain::Error::Stale))?;
        pending.finish().map_err(Error::Domain)
    }

    fn abandon_before_store<T>(&mut self, error: Error) -> Result<T, Error> {
        self.closed = true;
        if let Some(pending) = self.pending.take() {
            if pending.phase() == super::domain::RemoteOperationCancelPhase::StoreNotCalled {
                pending.abandon().map_err(Error::Domain)?;
            } else {
                // An unexpected post-call phase must keep the normal fail-closed
                // PendingWriter drop behavior; never pretend it was abandoned.
                drop(pending);
            }
        }
        Err(error)
    }
}

enum RemoteOperationCancelAttempt {
    Retry,
    BeforeStore(Error),
    KnownNoEffect(StoreError),
    Receipt(Option<OperationReceipt>),
    Uncertain(Error),
}

fn attempt_remote_operation_cancel<'d, 'o, 'w, 'p, 's>(
    owner: &SharedOwner,
    worker: &RemoteWorkerEvidence<'w, 'p, 's, 'o>,
    pending: &mut super::domain::RemoteOperationCancelWrite<'d, 'o>,
    before: &super::PeerJournalRows,
    authorization: &RemoteOperationAuthorization,
) -> RemoteOperationCancelAttempt {
    let mut guard = match pending.try_enter() {
        Ok(guard) => guard,
        Err(super::domain::Error::Busy) => return RemoteOperationCancelAttempt::Retry,
        Err(error) => {
            return RemoteOperationCancelAttempt::BeforeStore(Error::Domain(error));
        }
    };
    let mut store = match owner.try_store() {
        Ok(store) => store,
        Err(Error::Domain(super::domain::Error::Busy) | Error::Store(StoreError::Busy)) => {
            return RemoteOperationCancelAttempt::Retry;
        }
        Err(error) => return RemoteOperationCancelAttempt::BeforeStore(error),
    };
    if let Err(error) = guard.check_current() {
        return RemoteOperationCancelAttempt::BeforeStore(Error::Domain(error));
    }
    let current = match super::PeerJournalRows::read(
        &store,
        worker.eligibility(),
        authorization.rights.workspace(),
    ) {
        Ok(rows) => rows,
        Err(StoreError::Busy) => return RemoteOperationCancelAttempt::Retry,
        Err(error) => {
            owner.domain.cloud_uncertain();
            return RemoteOperationCancelAttempt::BeforeStore(Error::UncertainStore(error));
        }
    };
    if !before.current(&current)
        || current.host_pending.is_some()
        || !current.outbox.is_empty()
        || !worker.current()
    {
        return RemoteOperationCancelAttempt::BeforeStore(Error::Domain(
            super::domain::Error::Stale,
        ));
    }
    if let Err(error) = super::rename_public_current(&store, &current) {
        if matches!(error, Error::UncertainStore(StoreError::Busy)) {
            return RemoteOperationCancelAttempt::Retry;
        }
        return RemoteOperationCancelAttempt::BeforeStore(error);
    }
    if let Err(error) = guard.check_current() {
        return RemoteOperationCancelAttempt::BeforeStore(Error::Domain(error));
    }
    if worker.operation().check().is_err()
        || Instant::now() >= authorization.deadline
        || !worker.current()
    {
        return RemoteOperationCancelAttempt::BeforeStore(Error::Domain(
            super::domain::Error::Deadline,
        ));
    }

    match guard.commit_cancel(
        &mut store,
        &authorization.rights,
        &authorization.capabilities,
    ) {
        Ok(receipt) => RemoteOperationCancelAttempt::Receipt(receipt),
        Err(super::domain::StepError::Source(error)) => match guard.phase() {
            super::domain::RemoteOperationCancelPhase::KnownNoEffect
            | super::domain::RemoteOperationCancelPhase::Committed => {
                RemoteOperationCancelAttempt::KnownNoEffect(error)
            }
            super::domain::RemoteOperationCancelPhase::StoreNotCalled
                if error == StoreError::Busy =>
            {
                RemoteOperationCancelAttempt::Retry
            }
            super::domain::RemoteOperationCancelPhase::StoreNotCalled => {
                RemoteOperationCancelAttempt::BeforeStore(Error::Store(error))
            }
            super::domain::RemoteOperationCancelPhase::Uncertain => {
                RemoteOperationCancelAttempt::Uncertain(Error::UncertainStore(error))
            }
        },
        Err(super::domain::StepError::Domain(error)) => {
            if guard.phase() == super::domain::RemoteOperationCancelPhase::StoreNotCalled {
                RemoteOperationCancelAttempt::BeforeStore(Error::Domain(error))
            } else {
                RemoteOperationCancelAttempt::Uncertain(Error::Domain(error))
            }
        }
    }
}

impl Drop for RemoteOperationCancelTurn<'_, '_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take()
            && pending.phase() == super::domain::RemoteOperationCancelPhase::StoreNotCalled
        {
            let _ = pending.abandon();
        }
    }
}

fn operation_request(call: &RpcCall) -> Option<(Method, &WorkspaceContext, OperationId)> {
    match call {
        RpcCall::OperationStatus(params) => Some((
            Method::OperationStatus,
            &params.context,
            params.operation_id,
        )),
        RpcCall::OperationCancel(params) => Some((
            Method::OperationCancel,
            &params.context,
            params.operation_id,
        )),
        _ => None,
    }
}

fn request_authority(
    worker: &RemoteWorkerEvidence<'_, '_, '_, '_>,
    peer: &VerifiedCurrentPeer,
    request: &RpcRequest,
) -> Result<
    (
        Method,
        WorkspaceContext,
        OperationId,
        ConsumerAuthorizationId,
        CapabilitySet,
    ),
    Error,
> {
    let (method, context, operation_id) =
        operation_request(&request.call).ok_or(Error::Domain(super::domain::Error::Stale))?;
    if !peer.current(worker) {
        return Err(Error::Domain(super::domain::Error::Stale));
    }
    let grant = peer.grant();
    let actor = ConsumerAuthorizationId::from_bytes(grant.consumer_authorization_id)
        .map_err(|_| Error::Domain(super::domain::Error::Stale))?;
    Ok((
        method,
        context.clone(),
        operation_id,
        actor,
        grant.capabilities.clone(),
    ))
}

impl SharedOwner {
    /// Read the exact operation receipt using the current peer's actor and
    /// capabilities. Missing, foreign, and under-authorized rows stay hidden.
    pub(in crate::unix) fn lookup_remote_operation(
        &self,
        worker: &RemoteWorkerEvidence<'_, '_, '_, '_>,
        peer: &VerifiedCurrentPeer,
        connection: &super::super::auth::remote_connection::RemoteConnectionState,
        request: &RpcRequest,
        queued: &super::super::auth::remote_connection::QueuedRequest,
    ) -> Result<Option<RemoteOperationDisclosure>, Error> {
        if !std::ptr::eq(self, worker.owner())
            || worker.operation().check().is_err()
            || queued.connection_identity() != connection.connection_identity()
            || Instant::now() >= queued.deadline()
        {
            return Err(Error::Domain(super::domain::Error::Stale));
        }
        let (method, context, operation_id, actor, capabilities) =
            request_authority(worker, peer, request)?;
        let workspace_turn = self.try_remote_workspace_turn(worker, peer, &context)?;
        if workspace_turn.check().is_err() {
            return Err(Error::Domain(super::domain::Error::Stale));
        }
        drop(workspace_turn);

        let Some(receipt) = self.lookup_operation(
            worker.operation(),
            actor,
            context.workspace_id,
            operation_id,
            &capabilities,
        )?
        else {
            return Ok(None);
        };
        if !peer.current(worker) || worker.operation().check().is_err() {
            return Err(Error::Domain(super::domain::Error::Stale));
        }
        let Some(authorization) = RemoteOperationAuthorization::from_receipt(
            &receipt,
            request,
            actor,
            &capabilities,
            connection,
            queued,
        ) else {
            return Ok(None);
        };
        if authorization.request.call.method() != method {
            return Err(Error::Domain(super::domain::Error::Stale));
        }
        Ok(Some(RemoteOperationDisclosure {
            receipt,
            authorization,
        }))
    }

    /// Register the one exact Shared cancellation writer while the fresh
    /// RemoteWorkspaceTurn guard and snapshot are still held. The returned
    /// turn retains that same writer across pre-Store contention.
    pub(in crate::unix) fn begin_remote_operation_cancel<'d, 'o, 'e, 'w, 'p, 's>(
        &'d self,
        worker: &'e RemoteWorkerEvidence<'w, 'p, 's, 'o>,
        peer: &'e VerifiedCurrentPeer,
        connection: &super::super::auth::remote_connection::RemoteConnectionState,
        request: &RpcRequest,
        queued: &super::super::auth::remote_connection::QueuedRequest,
        ready: &RemoteOperationReady,
    ) -> Result<RemoteOperationCancelTurn<'d, 'o, 'e, 'w, 'p, 's>, Error>
    where
        'd: 'o,
    {
        if !std::ptr::eq(self, worker.owner())
            || !ready.matches(request, connection, queued)
            || queued.connection_identity() != connection.connection_identity()
            || worker.operation().check().is_err()
        {
            return Err(Error::Domain(super::domain::Error::Stale));
        }
        let (method, context, _operation_id, actor, capabilities) =
            request_authority(worker, peer, request)?;
        let absolute_expiry = peer
            .io_deadline(worker)
            .ok_or(Error::Domain(super::domain::Error::Stale))?
            .min(ready.deadline);
        let authorization = ready
            .authorization()
            .cloned()
            .ok_or(Error::Domain(super::domain::Error::Stale))?;
        if method != Method::OperationCancel
            || !authorization.allows(
                request,
                &context,
                actor,
                &capabilities,
                connection.connection_identity(),
                Some(queued.sequence()),
            )
        {
            return Err(Error::Domain(super::domain::Error::Stale));
        }
        if Instant::now() >= ready.deadline {
            return Err(Error::Domain(super::domain::Error::Stale));
        }
        let workspace_turn = self.try_remote_workspace_turn(worker, peer, &context)?;
        if workspace_turn.check().is_err() {
            return Err(Error::Domain(super::domain::Error::Stale));
        }
        let before = workspace_turn.rows.clone();
        if workspace_turn.check().is_err() {
            return Err(Error::Domain(super::domain::Error::Stale));
        }
        if Instant::now() >= absolute_expiry {
            return Err(Error::Domain(super::domain::Error::Deadline));
        }
        let pending = workspace_turn
            .guard
            .begin_remote_operation_cancel(
                workspace_turn.snapshot,
                peer.continuation(),
                absolute_expiry,
            )
            .map_err(Error::Domain)?;
        Ok(RemoteOperationCancelTurn {
            owner: self,
            worker,
            pending: Some(pending),
            before,
            authorization,
            request: request.clone(),
            closed: false,
        })
    }
}

fn same_stored_rights(a: &StoredOperationRights, b: &StoredOperationRights) -> bool {
    a.operation_id() == b.operation_id()
        && a.actor() == b.actor()
        && a.workspace() == b.workspace()
        && a.original_method() == b.original_method()
        && a.actual_rights() == b.actual_rights()
        && a.repository_execution() == b.repository_execution()
}

impl RemoteWorkspaceTurn<'_, '_, '_, '_, '_, '_> {
    pub(in crate::unix) fn before_operation_queue(
        &self,
        connection: &mut super::super::auth::remote_connection::RemoteConnectionState,
        request: &RpcRequest,
    ) -> Result<
        super::super::auth::remote_connection::QueuedRequest,
        super::super::auth::remote_connection::GateError,
    > {
        self.check_connection(connection)?;
        connection.before_operation_queue(
            request,
            self.worker.operation(),
            &self.facts(),
            &mut || self.now(),
        )
    }

    pub(in crate::unix) fn after_operation_wait(
        &self,
        connection: &mut super::super::auth::remote_connection::RemoteConnectionState,
        queued: &super::super::auth::remote_connection::QueuedRequest,
        authorization: Option<&RemoteOperationAuthorization>,
    ) -> Result<RemoteOperationReady, super::super::auth::remote_connection::GateError> {
        self.check_connection(connection)?;
        let request = connection.after_operation_wait(
            queued,
            self.worker.operation(),
            authorization,
            &self.facts(),
            &mut || self.now(),
        )?;
        if authorization.is_some_and(|authorization| {
            !authorization.matches_request(
                &request,
                connection.connection_identity(),
                Some(queued.sequence()),
            )
        }) {
            connection.dispose();
            return Err(super::super::auth::remote_connection::GateError::Disposed);
        }
        Ok(RemoteOperationReady {
            request,
            authorization: authorization.cloned(),
            connection: connection.connection_identity(),
            sequence: queued.sequence(),
            deadline: queued.deadline(),
        })
    }

    pub(in crate::unix) fn cached_operation_response(
        &self,
        connection: &mut super::super::auth::remote_connection::RemoteConnectionState,
        request: &RpcRequest,
        authorization: Option<&RemoteOperationAuthorization>,
    ) -> Result<(), super::super::auth::remote_connection::GateError> {
        self.check_connection(connection)?;
        connection
            .cached_operation_response(request, authorization, &self.facts(), &mut || self.now())
    }
}
