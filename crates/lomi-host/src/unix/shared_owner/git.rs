use super::*;
use lomi_host_store::{ExternalPermit, OperationBinding, StoreError};
use lomi_remote_protocol::{
    CapabilitySet, Effect, Method, MethodRights, OperationId, OperationReceipt, OperationResult,
    OperationState, RepoStateToken, StoredOperationRights, WorkspaceContext,
    ipc::LocalAuthConfiguration,
    rpc::{RpcCall, RpcRequest},
};
use std::{sync::atomic::AtomicBool, time::Instant};

/// Exact rights for disclosing one already-committed Git receipt. This is
/// minted only from a validated one-shot receipt witness or an exact Store
/// lookup under a consumed request ticket, then retained with response bytes.
pub(in crate::unix) struct GitReceiptDisclosure {
    request: RpcRequest,
    context: WorkspaceContext,
    rights: StoredOperationRights,
    connection: uuid::Uuid,
    deadline: std::time::Instant,
}

impl GitReceiptDisclosure {
    fn from_validated_receipt(
        receipt: &OperationReceipt,
        request: &RpcRequest,
        binding: &OperationBinding,
        context: &WorkspaceContext,
        connection: uuid::Uuid,
        deadline: std::time::Instant,
        capabilities: &CapabilitySet,
    ) -> Option<Self> {
        let (operation_id, request_context) = git_mutation_binding(&request.call)?;
        let rights = receipt.stored_rights();
        if request.call.validate().is_err()
            || request_context != context
            || operation_id != rights.operation_id()
            || receipt.operation_id() != operation_id
            || rights.actor() != binding.rights.actor()
            || rights.workspace() != context.workspace_id
            || rights.original_method() != request.call.method()
            || !super::rename_rights_match(&rights, &binding.rights)
            || Instant::now() >= deadline
            || !matches!(rights.original_method().rights(), MethodRights::Static(required)
                if required.iter().all(|right| rights.actual_rights().contains(*right)))
            || capabilities
                .authorize(
                    request.call.method().as_str(),
                    rights.repository_execution(),
                )
                .is_err()
            || Vec::<lomi_remote_protocol::Capability>::from(rights.actual_rights().clone())
                .iter()
                .any(|right| !capabilities.contains(*right))
        {
            return None;
        }
        // Keep the closed method set explicit. The call parser above yields a
        // method only through the signed durable Git mutation variants.
        if !matches!(
            request.call.method(),
            Method::GitStage
                | Method::GitUnstage
                | Method::GitCommit
                | Method::GitFetch
                | Method::GitPush
                | Method::GitPull
        ) {
            return None;
        }
        Some(Self {
            request: request.clone(),
            context: context.clone(),
            rights,
            connection,
            deadline,
        })
    }

    pub(in crate::unix) fn context(&self) -> &WorkspaceContext {
        &self.context
    }

    pub(in crate::unix) fn allows(
        &self,
        request: &RpcRequest,
        actor: lomi_remote_protocol::ConsumerAuthorizationId,
        capabilities: &CapabilitySet,
        connection: uuid::Uuid,
    ) -> bool {
        let Some((operation_id, context)) = git_mutation_binding(&request.call) else {
            return false;
        };
        if Instant::now() >= self.deadline
            || request != &self.request
            || request.call.validate().is_err()
            || context != &self.context
            || operation_id != self.rights.operation_id()
            || actor != self.rights.actor()
            || context.workspace_id != self.rights.workspace()
            || request.call.method() != self.rights.original_method()
            || connection != self.connection
            || !matches!(self.rights.original_method().rights(), MethodRights::Static(required)
                if required.iter().all(|right| self.rights.actual_rights().contains(*right)))
            || capabilities
                .authorize(
                    self.rights.original_method().as_str(),
                    self.rights.repository_execution(),
                )
                .is_err()
        {
            return false;
        }
        Vec::<lomi_remote_protocol::Capability>::from(self.rights.actual_rights().clone())
            .iter()
            .all(|right| capabilities.contains(*right))
    }
}

pub(in crate::unix) enum RemoteGitMutationBegin {
    Duplicate(OperationReceipt, GitReceiptDisclosure),
    Started {
        lease: domain::RemoteGitWriterLease,
        continuation: StartedGitContinuation,
        permit: ExternalPermit,
        binding: OperationBinding,
        credential_configuration: Option<LocalAuthConfiguration>,
    },
}

/// Opaque, request-scoped authority for control-plane maintenance of one
/// durable Started Git operation. It cannot create a peer/data-plane permit.
#[derive(Clone)]
pub(in crate::unix) struct StartedGitContinuation {
    control: domain::RemoteGitWriterControl,
    binding: OperationBinding,
    connection: uuid::Uuid,
    context: WorkspaceContext,
    runtime: lomi_host_store::CloudRuntimeState,
    identity: lomi_host_auth::PublicHostIdentity,
    credential_deadlines: lomi_host_auth::CredentialDeadlines,
    store_identity: Identity,
    credential_configuration: LocalAuthConfiguration,
    source: lomi_host_store::AcknowledgedWorkspaceGrant,
    grant: lomi_remote_crypto::GrantV3,
    authority: lomi_remote_crypto::CurrentAuthorityV3,
    capabilities: lomi_remote_protocol::CapabilitySet,
    origin: lomi_host_auth::peer_policy::RemoteOrigin,
    heartbeat: std::sync::Arc<std::sync::Mutex<super::super::auth::cloud::HeartbeatObservation>>,
    acknowledged: lomi_host_store::HostAcknowledgedPublication,
    initial_rows: super::PeerJournalRows,
    wall_origin: std::time::Duration,
    monotonic_origin: std::time::Instant,
}

pub(in crate::unix) struct RemoteGitStartedReceipt<'e, 'op> {
    owner: &'e SharedOwner,
    operation: &'e domain::Operation<'op>,
    continuation: StartedGitContinuation,
    watcher: domain::RemoteGitWriterReceiptWatcher,
    post: super::PeerJournalRows,
    request: RpcRequest,
    binding: OperationBinding,
    receipt: OperationReceipt,
    connection: uuid::Uuid,
    context: WorkspaceContext,
}

pub(in crate::unix) struct RemoteGitStartedReceiptTurn<'d, 'op, 'r, 'e> {
    guard: domain::OwnerGuard<'d, 'op>,
    snapshot: domain::Snapshot<'d, 'op>,
    receipt: &'r RemoteGitStartedReceipt<'e, 'op>,
    heartbeat: super::super::auth::cloud::HeartbeatObservation,
    floor: u64,
    local: lomi_host_auth::peer_policy::LocalWorkspace,
    running: Vec<lomi_remote_protocol::TerminalContext>,
    gate_denied: &'d AtomicBool,
    paused: &'d AtomicBool,
    stopping: &'d AtomicBool,
}

pub(in crate::unix) struct RemoteGitStartedReceiptIoWatch<'d, 'op> {
    watcher: domain::RemoteGitWriterReceiptWatcher,
    operation: &'d domain::Operation<'op>,
    gate_denied: &'d AtomicBool,
    paused: &'d AtomicBool,
    stopping: &'d AtomicBool,
    public_pending: &'d AtomicBool,
}
impl StartedGitContinuation {
    pub(in crate::unix) fn owner_control(&self) -> domain::RemoteGitWriterControl {
        self.control.clone()
    }
    pub(in crate::unix) fn same_writer(&self, other: &Self) -> bool {
        self.control.same_writer(&other.control)
    }
    pub(in crate::unix) fn terminal_peer_observation(
        &self,
        operation: &domain::Operation<'_>,
        target: &super::super::auth::peer::StartedGitPairingTarget,
    ) -> Option<super::super::auth::peer::StartedGitPeerObservation> {
        if !self.is_current(operation)
            || target.connection != self.connection
            || target.context.grant != self.grant
            || target.authority != self.authority
            || target.origin != self.origin
            || target.scope != self.runtime.scope
        {
            return None;
        }
        let fresh_until = self.peer_deadline();
        (std::time::Instant::now() < fresh_until).then(|| {
            super::super::auth::peer::StartedGitPeerObservation {
                active: self.clone(),
                target: target.clone(),
                source: self.source.clone(),
                fresh_until,
            }
        })
    }
    pub(in crate::unix) fn is_current(&self, operation: &domain::Operation<'_>) -> bool {
        self.control.matches_operation(operation) && self.control.current()
    }
    pub(in crate::unix) fn belongs_to(&self, domain: &domain::OwnerDomain) -> bool {
        self.control.belongs_to(domain)
    }
    pub(in crate::unix) fn matches_request(
        &self,
        operation: &domain::Operation<'_>,
        connection: uuid::Uuid,
        request: &RpcRequest,
    ) -> bool {
        if !self.is_current(operation) || self.connection != connection {
            return false;
        }
        git_mutation_binding(&request.call).is_some_and(|(operation_id, context)| {
            context == &self.context
                && operation_id == self.binding.rights.operation_id()
                && request.call.method() == self.binding.rights.original_method()
                && lomi_host_store::parameter_hash(&request.call)
                    .is_ok_and(|hash| hash == self.binding.parameter_hash)
        })
    }
    pub(in crate::unix) fn runtime(&self) -> &lomi_host_store::CloudRuntimeState {
        &self.runtime
    }
    pub(in crate::unix) fn identity(&self) -> &lomi_host_auth::PublicHostIdentity {
        &self.identity
    }
    pub(in crate::unix) fn credential_deadlines(&self) -> lomi_host_auth::CredentialDeadlines {
        self.credential_deadlines
    }
    pub(in crate::unix) fn store_identity(&self) -> &Identity {
        &self.store_identity
    }
    pub(in crate::unix) fn credential_configuration(&self) -> &LocalAuthConfiguration {
        &self.credential_configuration
    }
    pub(in crate::unix) fn connection(&self) -> uuid::Uuid {
        self.connection
    }
    pub(in crate::unix) fn context_workspace(&self) -> WorkspaceId {
        self.context.workspace_id
    }
    pub(in crate::unix) fn operation_id(&self) -> lomi_remote_protocol::OperationId {
        self.binding.rights.operation_id()
    }
    pub(in crate::unix) fn stored_rights(&self) -> &lomi_remote_protocol::StoredOperationRights {
        &self.binding.rights
    }
    pub(in crate::unix) fn source(&self) -> &lomi_host_store::AcknowledgedWorkspaceGrant {
        &self.source
    }
    pub(in crate::unix) fn grant(&self) -> &lomi_remote_crypto::GrantV3 {
        &self.grant
    }
    pub(in crate::unix) fn capabilities(&self) -> &lomi_remote_protocol::CapabilitySet {
        &self.capabilities
    }
    pub(in crate::unix) fn origin(&self) -> &lomi_host_auth::peer_policy::RemoteOrigin {
        &self.origin
    }
    pub(in crate::unix) fn heartbeat(
        &self,
    ) -> Option<super::super::auth::cloud::HeartbeatObservation> {
        self.heartbeat
            .lock()
            .ok()
            .map(|heartbeat| heartbeat.clone())
    }
    pub(in crate::unix) fn acknowledged(&self) -> &lomi_host_store::HostAcknowledgedPublication {
        &self.acknowledged
    }
    fn initial_rows(&self) -> &super::PeerJournalRows {
        &self.initial_rows
    }
    pub(in crate::unix) fn trusted_now(
        &self,
    ) -> Option<super::super::auth::remote_connection::TrustedNow> {
        let monotonic = std::time::Instant::now();
        let elapsed = monotonic.checked_duration_since(self.monotonic_origin)?;
        Some(super::super::auth::remote_connection::TrustedNow {
            wall: self.wall_origin.checked_add(elapsed)?,
            monotonic,
        })
    }
    pub(in crate::unix) fn heartbeat_deadline(&self) -> std::time::Instant {
        self.control.heartbeat_deadline()
    }
    pub(in crate::unix) fn peer_deadline(&self) -> std::time::Instant {
        self.control.peer_deadline()
    }
    pub(in crate::unix) fn renew_peer_observation(
        &self,
        operation: &domain::Operation<'_>,
        request_started: std::time::Instant,
        peer_expiry: std::time::Instant,
    ) -> Result<(), domain::Error> {
        self.control
            .renew_peer_observation(operation, request_started, peer_expiry)
    }
    pub(in crate::unix) fn authority(&self) -> &lomi_remote_crypto::CurrentAuthorityV3 {
        &self.authority
    }
    pub(in crate::unix) fn hard_deadline(&self) -> std::time::Instant {
        self.control.hard_deadline()
    }
    pub(in crate::unix) fn renew_heartbeat(
        &self,
        operation: &domain::Operation<'_>,
        observation: super::super::auth::cloud::HeartbeatObservation,
    ) -> Result<(), domain::Error> {
        if observation.scope != self.runtime.scope
            || observation.runtime != self.runtime.server_runtime
            || !(1..=30_000).contains(&observation.lease_ms)
            || !(1..=5_000).contains(&observation.freshness_ms)
            || observation.freshness_ms > observation.lease_ms
        {
            return Err(domain::Error::Denied);
        }
        self.control.renew_heartbeat(
            operation,
            observation.request_started,
            observation.lease_ms,
            observation.freshness_ms,
        )?;
        let mut current = self.heartbeat.lock().map_err(|_| domain::Error::Poisoned)?;
        if observation.request_started <= current.request_started {
            return Err(domain::Error::Stale);
        }
        *current = observation;
        Ok(())
    }
    pub(in crate::unix) fn invalidate(&self) {
        self.control.invalidate();
    }
}

pub(in crate::unix) enum RemoteGitMutationPreflight {
    /// No journal binding exists yet. The queued request remains available to
    /// be consumed by the atomic begin immediately before journal admission.
    New(super::FilesTarget),
    /// An exact replay already has a durable receipt. Its one-shot ticket was
    /// consumed under fresh owner evidence before returning this value.
    Duplicate(OperationReceipt, GitReceiptDisclosure),
    /// The operation ID exists with a different binding. Its ticket was
    /// consumed before returning the ordinary idempotency conflict.
    Conflict,
}

/// A single, exact Git operation receipt immediately after its committed
/// Store transaction. It is an output capability only; it cannot authorize a
/// subsequent RPC or mutation.
pub(in crate::unix) struct RemoteGitReceipt<'e, 'w, 'p, 's, 'o> {
    owner: &'e SharedOwner,
    worker: &'e super::super::auth::RemoteWorkerEvidence<'w, 'p, 's, 'o>,
    peer: super::super::auth::peer::VerifiedCurrentPeer,
    watcher: domain::RemoteGitWriterReceiptWatcher,
    post: PeerJournalRows,
    local: lomi_host_auth::peer_policy::LocalWorkspace,
    running: Vec<TerminalContext>,
    context: WorkspaceContext,
    binding: OperationBinding,
    request: RpcRequest,
    receipt: OperationReceipt,
    connection: uuid::Uuid,
}

pub(in crate::unix) struct RemoteGitReceiptTurn<'d, 'o, 'r, 'e, 'w, 'p, 's, 'op> {
    guard: domain::OwnerGuard<'d, 'o>,
    snapshot: domain::Snapshot<'d, 'o>,
    receipt: &'r RemoteGitReceipt<'e, 'w, 'p, 's, 'op>,
    floor: u64,
}

pub(in crate::unix) struct RemoteGitReceiptIoWatch<'e, 'w, 'p, 's, 'o> {
    atoms: RemoteGitReceiptIoAtoms<'o>,
    worker: &'e super::super::auth::RemoteWorkerEvidence<'w, 'p, 's, 'o>,
}

pub(in crate::unix) struct RemoteGitReceiptIoAtoms<'o> {
    watcher: domain::RemoteGitWriterReceiptWatcher,
    gate: &'o std::sync::atomic::AtomicBool,
    paused: &'o std::sync::atomic::AtomicBool,
    stopping: &'o std::sync::atomic::AtomicBool,
    public_pending: &'o std::sync::atomic::AtomicBool,
}

impl SharedOwner {
    /// Check the durable binding before Git prepares a private mutation
    /// snapshot. This prevents a successful replay from being rejected by a
    /// state-dependent prepare, and rejects changed parameters before doing
    /// expensive work. New bindings keep the one-shot ticket unconsumed; the
    /// journal begin repeats these lookups atomically after preparation.
    pub(in crate::unix) fn preflight_remote_git_mutation<'e, 'w, 'p, 's, 'o>(
        &self,
        worker: &'e super::super::auth::RemoteWorkerEvidence<'w, 'p, 's, 'o>,
        peer: &'e super::super::auth::peer::VerifiedCurrentPeer,
        connection: &mut super::super::auth::remote_connection::RemoteConnectionState,
        original: &RpcRequest,
        queued: &super::super::auth::remote_connection::QueuedRequest,
    ) -> Result<RemoteGitMutationPreflight, super::RemoteRenameError> {
        let (operation_id, context) =
            git_mutation_binding(&original.call).ok_or(super::RemoteRenameError::Closed)?;
        if !std::ptr::eq(worker.owner(), self) || !peer.current(worker) {
            return Err(super::RemoteRenameError::Closed);
        }
        let turn = self.try_remote_workspace_turn(worker, peer, context)?;
        turn.check()?;
        let target = turn.git_mutation_peek_after_wait(connection, queued)?;
        if target.workspace_id != context.workspace_id {
            return Err(super::RemoteRenameError::Closed);
        }
        let binding = git_operation_binding(connection, original, operation_id)?;
        let store = self.try_store()?;
        turn.guard
            .validate_current(&turn.snapshot)
            .map_err(|error| super::RemoteRenameError::Owner(Error::Domain(error)))?;
        let exact = store
            .lookup(&binding, &peer.grant().capabilities)
            .map_err(|error| super::RemoteRenameError::Owner(Error::Store(error)))?;
        let existing = if exact.is_none() {
            store
                .lookup_operation(
                    binding.rights.actor(),
                    binding.rights.workspace(),
                    binding.rights.operation_id(),
                    &peer.grant().capabilities,
                )
                .map_err(|error| super::RemoteRenameError::Owner(Error::Store(error)))?
        } else {
            None
        };
        drop(store);
        turn.check()?;

        if exact.is_none() && existing.is_none() {
            return Ok(RemoteGitMutationPreflight::New(target));
        }

        // Duplicate/conflict responses consume the same ticket once under a
        // fresh owner turn, while no external mutation work has started.
        let (consumed, consumed_target, hard_expiry, _) =
            turn.git_mutation_after_wait(connection, queued)?;
        if &consumed != original
            || consumed_target.workspace_id != target.workspace_id
            || consumed_target.epoch != target.epoch
            || consumed_target.root != target.root
        {
            return Err(super::RemoteRenameError::Closed);
        }
        if let Some(receipt) = exact {
            let disclosure = GitReceiptDisclosure::from_validated_receipt(
                &receipt,
                original,
                &binding,
                context,
                connection.connection_identity(),
                worker.operation().deadline().min(hard_expiry),
                &peer.grant().capabilities,
            )
            .ok_or(super::RemoteRenameError::Closed)?;
            Ok(RemoteGitMutationPreflight::Duplicate(receipt, disclosure))
        } else {
            Ok(RemoteGitMutationPreflight::Conflict)
        }
    }

    /// Consume the exact queued Git mutation ticket and atomically persist its
    /// durable Started receipt before any remote dispatch or local publication.
    /// The shared writer lease is detached from actor borrows and retained by
    /// the caller across bounded worker turns.
    pub(in crate::unix) fn begin_remote_git_mutation<'e, 'w, 'p, 's, 'o>(
        &self,
        worker: &'e super::super::auth::RemoteWorkerEvidence<'w, 'p, 's, 'o>,
        peer: &'e super::super::auth::peer::VerifiedCurrentPeer,
        connection: &mut super::super::auth::remote_connection::RemoteConnectionState,
        original: &RpcRequest,
        queued: &super::super::auth::remote_connection::QueuedRequest,
        cancellation: &AtomicBool,
        completion: &super::super::rpc::CompletionSlot<'static>,
        expected_root: &std::path::Path,
    ) -> Result<RemoteGitMutationBegin, super::RemoteRenameError> {
        let (operation_id, context) =
            git_mutation_binding(&original.call).ok_or(super::RemoteRenameError::Closed)?;
        if !std::ptr::eq(worker.owner(), self) || !peer.current(worker) {
            return Err(super::RemoteRenameError::Closed);
        }
        let turn = self.try_remote_workspace_turn(worker, peer, context)?;
        turn.check()?;
        let (request, target, hard_expiry, heartbeat_expiry) =
            turn.git_mutation_after_wait(connection, queued)?;
        if &request != original
            || target.workspace_id != context.workspace_id
            || target.root != expected_root
        {
            return Err(super::RemoteRenameError::Closed);
        }
        let binding = git_operation_binding(connection, &request, operation_id)?;
        let store = self.try_store()?;
        let credential_configuration = store
            .auth_configuration()
            .map_err(|error| super::RemoteRenameError::Owner(Error::Store(error)))?;
        let store_identity = store.identity().clone();
        turn.guard
            .validate_current(&turn.snapshot)
            .map_err(|error| super::RemoteRenameError::Owner(Error::Domain(error)))?;
        let exact = store
            .lookup(&binding, &peer.grant().capabilities)
            .map_err(|error| super::RemoteRenameError::Owner(Error::Store(error)))?;
        let existing = store
            .lookup_operation(
                binding.rights.actor(),
                binding.rights.workspace(),
                binding.rights.operation_id(),
                &peer.grant().capabilities,
            )
            .map_err(|error| super::RemoteRenameError::Owner(Error::Store(error)))?;
        if let Some(receipt) = exact {
            turn.check()?;
            let disclosure = GitReceiptDisclosure::from_validated_receipt(
                &receipt,
                &request,
                &binding,
                context,
                connection.connection_identity(),
                worker.operation().deadline().min(hard_expiry),
                &peer.grant().capabilities,
            )
            .ok_or(super::RemoteRenameError::Closed)?;
            return Ok(RemoteGitMutationBegin::Duplicate(receipt, disclosure));
        }
        if existing.is_some() {
            return Err(super::RemoteRenameError::Owner(Error::Store(
                StoreError::IdempotencyConflict,
            )));
        }
        let expected_revision = turn.state.domain_revision;
        let before = turn.rows.clone();
        drop(store);
        turn.check()?;
        let mut lease = turn
            .guard
            .begin_remote_git_writer(
                turn.snapshot,
                peer.continuation(),
                hard_expiry,
                heartbeat_expiry,
                peer.fresh_until(),
                cancellation,
                self.domain.clone(),
            )
            .map_err(|error| super::RemoteRenameError::Owner(Error::Domain(error)))?;
        if !std::ptr::eq(worker.operation().cancellation_latch(), cancellation) {
            completion.defer(super::super::rpc::DeferredCompletion::Cancel { binding });
            return Err(super::RemoteRenameError::Closed);
        }
        let mut permit = None;
        let start = (|| {
            let mut guard = lease
                .try_enter(worker.operation())
                .map_err(|error| super::RemoteRenameError::Owner(Error::Domain(error)))?;
            let mut store = self.try_store()?;
            super::rename_public_current(&store, &before)
                .map_err(super::RemoteRenameError::Owner)?;
            guard
                .start_external(&mut store, &binding, expected_revision, &mut permit)
                .map_err(|error| match error {
                    StepError::Domain(error) => {
                        super::RemoteRenameError::Owner(Error::Domain(error))
                    }
                    StepError::Source(error) => {
                        super::RemoteRenameError::Owner(Error::Store(error))
                    }
                })?;
            let post =
                PeerJournalRows::read(&store, worker.eligibility(), binding.rights.workspace())
                    .map_err(|error| {
                        super::RemoteRenameError::Owner(Error::UncertainStore(error))
                    })?;
            drop(guard);
            if !before.current(&post) || !worker.current() || !lease.current() {
                self.domain.fail_remote();
                return Err(super::RemoteRenameError::Closed);
            }
            super::rename_public_current(&store, &post).map_err(super::RemoteRenameError::Owner)?;
            Ok(())
        })();
        if let Err(error) = start {
            if let Some(permit) = permit.take() {
                completion.defer(super::super::rpc::DeferredCompletion::Complete {
                    binding,
                    permit,
                    state: OperationState::OutcomeUnknown,
                    effect: Effect::Unknown,
                    result: None,
                    projection: None,
                });
            } else {
                completion.defer(super::super::rpc::DeferredCompletion::Cancel { binding });
            }
            return Err(error);
        }
        let permit = permit.ok_or(super::RemoteRenameError::Closed)?;
        let control = lease.control();
        let eligibility = worker.eligibility();
        let trusted_now = worker.now().ok_or(super::RemoteRenameError::Closed)?;
        let credential_configuration = credential_configuration
            .clone()
            .ok_or(super::RemoteRenameError::Closed)?;
        if eligibility.binding.scope.host_id != eligibility.identity.host_id
            || eligibility.binding.server_runtime.host_access_epoch.0
                != eligibility.identity.access_epoch
            || !control.matches_operation(worker.operation())
            || !control.current()
        {
            return Err(super::RemoteRenameError::Closed);
        }
        let continuation = StartedGitContinuation {
            control,
            binding: binding.clone(),
            connection: connection.connection_identity(),
            context: context.clone(),
            runtime: eligibility.binding.clone(),
            identity: eligibility.identity.clone(),
            credential_deadlines: worker.provider().captured_deadlines(),
            store_identity,
            credential_configuration: credential_configuration.clone(),
            source: peer.source().clone(),
            grant: peer.grant().clone(),
            authority: peer.current_authority().clone(),
            capabilities: peer.grant().capabilities.clone(),
            origin: worker.origin().clone(),
            heartbeat: std::sync::Arc::new(std::sync::Mutex::new(eligibility.heartbeat.clone())),
            acknowledged: eligibility.publication.clone(),
            initial_rows: before.clone(),
            wall_origin: trusted_now.wall,
            monotonic_origin: trusted_now.monotonic,
        };
        Ok(RemoteGitMutationBegin::Started {
            lease,
            continuation,
            permit,
            binding,
            credential_configuration: Some(credential_configuration),
        })
    }

    /// Persist a final Git operation receipt under the same retained owner
    /// lease. Fresh owner evidence is supplied by the caller on this actor turn;
    /// no borrowed authority or actor lock crosses a worker phase.
    pub(in crate::unix) fn complete_remote_git_mutation<'e, 'w, 'p, 's, 'o>(
        &'e self,
        worker: &'e super::super::auth::RemoteWorkerEvidence<'w, 'p, 's, 'o>,
        peer: super::super::auth::peer::VerifiedCurrentPeer,
        connection: uuid::Uuid,
        context: &WorkspaceContext,
        request: RpcRequest,
        mut lease: domain::RemoteGitWriterLease,
        permit: &ExternalPermit,
        binding: &OperationBinding,
        state: OperationState,
        effect: Effect,
        repo_state: Option<RepoStateToken>,
    ) -> Result<RemoteGitReceipt<'e, 'w, 'p, 's, 'o>, super::RemoteRenameError> {
        if !std::ptr::eq(worker.owner(), self) || !worker.current() || !lease.current() {
            return Err(super::RemoteRenameError::Closed);
        }
        let (operation_id, request_context) =
            git_mutation_binding(&request.call).ok_or(super::RemoteRenameError::Closed)?;
        if context.workspace_id != binding.rights.workspace()
            || request_context != context
            || operation_id != binding.rights.operation_id()
            || request.call.method() != binding.rights.original_method()
            || lomi_host_store::parameter_hash(&request.call)
                .map_err(|error| super::RemoteRenameError::Owner(Error::Store(error)))?
                != binding.parameter_hash
            || !matches!(
                (state, effect, repo_state.as_ref()),
                (OperationState::Succeeded, Effect::Committed, Some(_))
                    | (OperationState::Failed, Effect::None, None)
                    | (OperationState::OutcomeUnknown, Effect::Unknown, None)
            )
        {
            return Err(super::RemoteRenameError::Closed);
        }
        let mut guard = lease
            .try_enter(worker.operation())
            .map_err(|error| super::RemoteRenameError::Owner(Error::Domain(error)))?;
        let mut store = self.try_store()?;
        store
            .check_external_fence(permit)
            .map_err(|error| super::RemoteRenameError::Owner(Error::Store(error)))?;
        let current = PeerJournalRows::read(&store, worker.eligibility(), context.workspace_id)
            .map_err(|error| super::RemoteRenameError::Owner(Error::UncertainStore(error)))?;
        if current.host_pending.is_some() || !current.outbox.is_empty() {
            return Err(super::RemoteRenameError::Closed);
        }
        super::rename_public_current(&store, &current).map_err(super::RemoteRenameError::Owner)?;
        if !current
            .pairing_acknowledged
            .iter()
            .any(|grant| grant == peer.source())
        {
            return Err(super::RemoteRenameError::Closed);
        }
        let result = repo_state.map(|repo_state_token| OperationResult::Git { repo_state_token });
        let receipt = guard
            .complete_external(&mut store, permit, state, effect, result.clone())
            .map_err(|error| match error {
                StepError::Domain(error) => super::RemoteRenameError::Owner(Error::Domain(error)),
                StepError::Source(error) => {
                    super::RemoteRenameError::Owner(Error::UncertainStore(error))
                }
            })?;
        let post = PeerJournalRows::read(&store, worker.eligibility(), context.workspace_id)
            .map_err(|error| {
                self.domain.cloud_uncertain();
                super::RemoteRenameError::Owner(Error::UncertainStore(error))
            })?;
        if !super::rename_rights_match(&receipt.stored_rights(), &binding.rights)
            || receipt.state() != state
            || receipt.effect() != effect
            || receipt.result() != result.as_ref()
            || post.host_pending.is_some()
            || !post.outbox.is_empty()
            || !current.current(&post)
            || !post
                .pairing_acknowledged
                .iter()
                .any(|grant| grant == peer.source())
            || !worker.current()
        {
            self.domain.fail_remote();
            return Err(super::RemoteRenameError::Closed);
        }
        super::rename_public_current(&store, &post).map_err(super::RemoteRenameError::Owner)?;
        let (_, local, running) = super::derive_remote_view(
            &post,
            worker.eligibility(),
            &peer,
            context.workspace_id,
            context,
        )
        .map_err(super::RemoteRenameError::Owner)?;
        drop(guard);
        let watcher = lease
            .finish_receipt()
            .map_err(|error| super::RemoteRenameError::Owner(Error::Domain(error)))?;
        drop(store);
        Ok(RemoteGitReceipt {
            owner: self,
            worker,
            peer,
            watcher,
            post,
            local,
            running,
            context: context.clone(),
            binding: binding.clone(),
            request,
            receipt,
            connection,
        })
    }

    /// Complete the exact Started Git operation using its nonrenewable
    /// control-plane token. No fresh peer/data-plane eligibility is created.
    #[expect(
        clippy::too_many_arguments,
        reason = "all one-shot Git completion bindings stay explicit"
    )]
    pub(in crate::unix) fn complete_remote_git_mutation_started<'e, 'op>(
        &'e self,
        operation: &'e domain::Operation<'op>,
        continuation: StartedGitContinuation,
        mut lease: domain::RemoteGitWriterLease,
        permit: &ExternalPermit,
        binding: &OperationBinding,
        request: RpcRequest,
        state: OperationState,
        effect: Effect,
        repo_state: Option<RepoStateToken>,
        connection: uuid::Uuid,
    ) -> Result<RemoteGitStartedReceipt<'e, 'op>, super::RemoteRenameError> {
        if !continuation.matches_request(operation, connection, &request)
            || !lease.current()
            || continuation.binding.rights.operation_id() != binding.rights.operation_id()
            || continuation.binding.rights.actor() != binding.rights.actor()
            || continuation.binding.rights.workspace() != binding.rights.workspace()
            || continuation.binding.rights.original_method() != binding.rights.original_method()
            || continuation.binding.rights.actual_rights() != binding.rights.actual_rights()
            || continuation.binding.rights.repository_execution()
                != binding.rights.repository_execution()
            || continuation.binding.parameter_hash != binding.parameter_hash
        {
            return Err(super::RemoteRenameError::Closed);
        }
        let (operation_id, request_context) =
            git_mutation_binding(&request.call).ok_or(super::RemoteRenameError::Closed)?;
        let context = request_context.clone();
        if context != continuation.context
            || context.workspace_id != binding.rights.workspace()
            || operation_id != binding.rights.operation_id()
            || request.call.method() != binding.rights.original_method()
            || lomi_host_store::parameter_hash(&request.call)
                .map_err(|error| super::RemoteRenameError::Owner(Error::Store(error)))?
                != binding.parameter_hash
            || !matches!(
                (state, effect, repo_state.as_ref()),
                (OperationState::Succeeded, Effect::Committed, Some(_))
                    | (OperationState::Failed, Effect::None, None)
                    | (OperationState::OutcomeUnknown, Effect::Unknown, None)
            )
        {
            return Err(super::RemoteRenameError::Closed);
        }
        let mut guard = lease
            .try_enter(operation)
            .map_err(|error| super::RemoteRenameError::Owner(Error::Domain(error)))?;
        let mut store = self.try_store()?;
        store
            .check_external_fence(permit)
            .map_err(|error| super::RemoteRenameError::Owner(Error::Store(error)))?;
        let current = super::PeerJournalRows::read_binding(
            &store,
            continuation.runtime(),
            context.workspace_id,
        )
        .map_err(|error| super::RemoteRenameError::Owner(Error::UncertainStore(error)))?;
        if !continuation.initial_rows().current(&current)
            || current.host_pending.is_some()
            || !current.outbox.is_empty()
            || !current
                .pairing_acknowledged
                .iter()
                .any(|grant| grant == continuation.source())
        {
            return Err(super::RemoteRenameError::Closed);
        }
        super::rename_public_current(&store, &current).map_err(super::RemoteRenameError::Owner)?;
        let result = repo_state.map(|repo_state_token| OperationResult::Git { repo_state_token });
        let receipt = guard
            .complete_external(&mut store, permit, state, effect, result.clone())
            .map_err(|error| match error {
                StepError::Domain(error) => super::RemoteRenameError::Owner(Error::Domain(error)),
                StepError::Source(error) => {
                    super::RemoteRenameError::Owner(Error::UncertainStore(error))
                }
            })?;
        let post = super::PeerJournalRows::read_binding(
            &store,
            continuation.runtime(),
            context.workspace_id,
        )
        .map_err(|error| {
            self.domain.cloud_uncertain();
            super::RemoteRenameError::Owner(Error::UncertainStore(error))
        })?;
        if !rename_rights_match(&receipt.stored_rights(), &binding.rights)
            || receipt.state() != state
            || receipt.effect() != effect
            || receipt.result() != result.as_ref()
            || !current.current(&post)
            || post.host_pending.is_some()
            || !post.outbox.is_empty()
            || !post
                .pairing_acknowledged
                .iter()
                .any(|grant| grant == continuation.source())
        {
            self.domain.fail_remote();
            return Err(super::RemoteRenameError::Closed);
        }
        super::rename_public_current(&store, &post).map_err(super::RemoteRenameError::Owner)?;
        super::derive_remote_view_from_grant(
            &post,
            continuation.runtime(),
            continuation.grant(),
            continuation.source(),
            context.workspace_id,
            &context,
        )
        .map_err(super::RemoteRenameError::Owner)?;
        drop(guard);
        let watcher = lease
            .finish_receipt()
            .map_err(|error| super::RemoteRenameError::Owner(Error::Domain(error)))?;
        drop(store);
        Ok(RemoteGitStartedReceipt {
            owner: self,
            operation,
            continuation,
            watcher,
            post,
            request,
            binding: binding.clone(),
            receipt,
            connection,
            context,
        })
    }
}

impl<'e, 'w, 'p, 's, 'o> RemoteGitReceipt<'e, 'w, 'p, 's, 'o> {
    pub(in crate::unix) fn response(&self) -> lomi_remote_protocol::rpc::RpcResponse {
        lomi_remote_protocol::rpc::RpcResponse::Result {
            v: self.request.v,
            request_id: self.request.request_id.clone(),
            result: super::super::rpc::git_receipt_result(
                self.request.call.method(),
                self.receipt.clone(),
            ),
        }
    }

    /// Consume the one-shot committed-receipt witness after validating its
    /// exact Store row. The returned immutable response and exact stored-rights
    /// proof are later checked by the ordinary fresh channel gate, so they can
    /// wait behind an already-started logical frame without retaining guards.
    pub(in crate::unix) fn into_queued_response(
        self,
        request_deadline: std::time::Instant,
    ) -> Result<(RpcRequest, Vec<u8>, GitReceiptDisclosure), super::RemoteRenameError> {
        let turn = self.capture()?;
        if !turn.current_for(self.connection) || !turn.matches(&self) {
            return Err(super::RemoteRenameError::Closed);
        }
        drop(turn);
        let request = self.request.clone();
        let disclosure = GitReceiptDisclosure::from_validated_receipt(
            &self.receipt,
            &request,
            &self.binding,
            &self.context,
            self.connection,
            request_deadline,
            &self.peer.grant().capabilities,
        )
        .ok_or(super::RemoteRenameError::Closed)?;
        let bytes =
            serde_json::to_vec(&self.response()).map_err(|_| super::RemoteRenameError::Closed)?;
        if bytes.is_empty()
            || bytes.len() > lomi_remote_protocol::message_framing::MAX_FRAGMENT_PAYLOAD_LEN
        {
            return Err(super::RemoteRenameError::Closed);
        }
        Ok((request, bytes, disclosure))
    }

    pub(in crate::unix) fn capture<'r>(
        &'r self,
    ) -> Result<RemoteGitReceiptTurn<'r, 'r, 'r, 'e, 'w, 'p, 's, 'o>, super::RemoteRenameError>
    {
        let (operation_id, context) =
            git_mutation_binding(&self.request.call).ok_or(super::RemoteRenameError::Closed)?;
        if context != &self.context
            || operation_id != self.binding.rights.operation_id()
            || self.binding.rights.original_method() != self.request.call.method()
            || lomi_host_store::parameter_hash(&self.request.call)
                .map_err(|error| super::RemoteRenameError::Owner(Error::Store(error)))?
                != self.binding.parameter_hash
            || !rename_rights_match(&self.receipt.stored_rights(), &self.binding.rights)
        {
            return Err(super::RemoteRenameError::Closed);
        }
        let expected_result = match (self.receipt.state(), self.receipt.effect()) {
            (OperationState::Succeeded, Effect::Committed) => self.receipt.result().cloned(),
            (OperationState::Failed, Effect::None) => None,
            (OperationState::OutcomeUnknown, Effect::Unknown) => None,
            _ => return Err(super::RemoteRenameError::Closed),
        };
        if self.receipt.result() != expected_result.as_ref()
            || (self.receipt.state() == OperationState::Succeeded
                && !matches!(expected_result, Some(OperationResult::Git { .. })))
        {
            return Err(super::RemoteRenameError::Closed);
        }

        let guard = self
            .owner
            .domain
            .try_read(self.worker.operation())
            .map_err(|error| super::RemoteRenameError::Owner(Error::Domain(error)))?;
        let store = self.owner.try_store()?;
        let floor = self
            .watcher
            .validate(&guard, &store)
            .map_err(peer_store_step)?;
        let current =
            PeerJournalRows::read(&store, self.worker.eligibility(), self.context.workspace_id)
                .map_err(|error| super::RemoteRenameError::Owner(Error::UncertainStore(error)))?;
        let exact = store
            .lookup(&self.binding, &self.peer.grant().capabilities)
            .map_err(|error| super::RemoteRenameError::Owner(Error::UncertainStore(error)))?;
        if !self.post.current(&current)
            || !self.worker.current()
            || !self.watcher.check().is_ok()
            || !current
                .pairing_acknowledged
                .iter()
                .any(|grant| grant == self.peer.source())
            || current.host_pending.is_some()
            || !current.outbox.is_empty()
            || exact.as_ref() != Some(&self.receipt)
        {
            return Err(super::RemoteRenameError::Closed);
        }
        rename_public_current(&store, &current).map_err(super::RemoteRenameError::Owner)?;
        let snapshot = guard
            .capture_remote(|| StoreView::read(&store))
            .map_err(|error| super::RemoteRenameError::Owner(Error::from(error)))?;
        guard
            .validate_current(&snapshot)
            .map_err(|error| super::RemoteRenameError::Owner(Error::Domain(error)))?;
        drop(store);
        Ok(RemoteGitReceiptTurn {
            guard,
            snapshot,
            receipt: self,
            floor,
        })
    }

    pub(in crate::unix) fn into_io_watch(self) -> RemoteGitReceiptIoWatch<'e, 'w, 'p, 's, 'o> {
        RemoteGitReceiptIoWatch {
            atoms: RemoteGitReceiptIoAtoms {
                watcher: self.watcher,
                gate: self.worker.gate_denied(),
                paused: self.worker.paused(),
                stopping: self.worker.stopping(),
                public_pending: self.worker.public_setup_pending(),
            },
            worker: self.worker,
        }
    }
}

impl<'e: 'op, 'op> RemoteGitStartedReceipt<'e, 'op> {
    pub(in crate::unix) fn response(&self) -> lomi_remote_protocol::rpc::RpcResponse {
        lomi_remote_protocol::rpc::RpcResponse::Result {
            v: self.request.v,
            request_id: self.request.request_id.clone(),
            result: super::super::rpc::git_receipt_result(
                self.request.call.method(),
                self.receipt.clone(),
            ),
        }
    }

    /// Consume the one-shot Started-receipt witness after exact Store and
    /// writer validation. Delivery is reauthorized by the normal fresh peer
    /// gate after the response enters the bounded FIFO.
    pub(in crate::unix) fn into_queued_response(
        self,
        gate_denied: &AtomicBool,
        paused: &AtomicBool,
        stopping: &AtomicBool,
        public_pending: &AtomicBool,
        request_deadline: std::time::Instant,
    ) -> Result<(RpcRequest, Vec<u8>, GitReceiptDisclosure), super::RemoteRenameError> {
        use std::sync::atomic::Ordering::Acquire;
        if public_pending.load(Acquire) {
            return Err(super::RemoteRenameError::Closed);
        }
        let turn = self.capture(gate_denied, paused, stopping)?;
        if !turn.current_for(self.connection)
            || !turn.matches(&self)
            || public_pending.load(Acquire)
        {
            return Err(super::RemoteRenameError::Closed);
        }
        drop(turn);
        let request = self.request.clone();
        let disclosure = GitReceiptDisclosure::from_validated_receipt(
            &self.receipt,
            &request,
            &self.binding,
            &self.context,
            self.connection,
            request_deadline,
            self.continuation.capabilities(),
        )
        .ok_or(super::RemoteRenameError::Closed)?;
        let bytes =
            serde_json::to_vec(&self.response()).map_err(|_| super::RemoteRenameError::Closed)?;
        if bytes.is_empty()
            || bytes.len() > lomi_remote_protocol::message_framing::MAX_FRAGMENT_PAYLOAD_LEN
        {
            return Err(super::RemoteRenameError::Closed);
        }
        Ok((request, bytes, disclosure))
    }

    pub(in crate::unix) fn capture<'d, 'r>(
        &'r self,
        gate_denied: &'d AtomicBool,
        paused: &'d AtomicBool,
        stopping: &'d AtomicBool,
    ) -> Result<RemoteGitStartedReceiptTurn<'d, 'op, 'r, 'e>, super::RemoteRenameError>
    where
        'e: 'd,
    {
        self.operation
            .check()
            .map_err(|error| super::RemoteRenameError::Owner(Error::Domain(error)))?;
        let (operation_id, context) =
            git_mutation_binding(&self.request.call).ok_or(super::RemoteRenameError::Closed)?;
        if context != &self.context
            || context.workspace_id != self.binding.rights.workspace()
            || operation_id != self.binding.rights.operation_id()
            || self.request.call.method() != self.binding.rights.original_method()
            || lomi_host_store::parameter_hash(&self.request.call)
                .map_err(|error| super::RemoteRenameError::Owner(Error::Store(error)))?
                != self.binding.parameter_hash
            || !rename_rights_match(&self.receipt.stored_rights(), &self.binding.rights)
        {
            return Err(super::RemoteRenameError::Closed);
        }
        match (self.receipt.state(), self.receipt.effect()) {
            (OperationState::Succeeded, Effect::Committed)
                if matches!(self.receipt.result(), Some(OperationResult::Git { .. })) => {}
            (OperationState::Failed, Effect::None) if self.receipt.result().is_none() => {}
            (OperationState::OutcomeUnknown, Effect::Unknown)
                if self.receipt.result().is_none() => {}
            _ => return Err(super::RemoteRenameError::Closed),
        }

        let guard = self
            .owner
            .domain
            .try_read(self.operation)
            .map_err(|error| super::RemoteRenameError::Owner(Error::Domain(error)))?;
        let store = self.owner.try_store()?;
        let floor = self
            .watcher
            .validate(&guard, &store)
            .map_err(peer_store_step)?;
        if store.identity() != &self.continuation.store_identity
            || !matches!(
                store.auth_configuration(),
                Ok(Some(ref configuration))
                    if configuration == &self.continuation.credential_configuration
            )
        {
            return Err(super::RemoteRenameError::Closed);
        }
        let current = PeerJournalRows::read_binding(
            &store,
            &self.continuation.runtime,
            self.context.workspace_id,
        )
        .map_err(|error| super::RemoteRenameError::Owner(Error::UncertainStore(error)))?;
        let exact = store
            .lookup(&self.binding, &self.continuation.capabilities)
            .map_err(|error| super::RemoteRenameError::Owner(Error::UncertainStore(error)))?;
        if !self.post.current(&current)
            || self.watcher.check().is_err()
            || current.authorization.generation
                != self.continuation.runtime.scope.authorization_generation
            || current.authorization.locked
            || current.authorization.pending_cloud_revoke
            || current.verified != Some(current.authorization.generation)
            || current.configuration.as_ref() != Some(&self.continuation.credential_configuration)
            || current.binding.as_ref() != Some(&self.continuation.runtime)
            || current.publication.as_ref() != Some(&self.continuation.acknowledged)
            || current.host_pending.is_some()
            || !current.outbox.is_empty()
            || exact.as_ref() != Some(&self.receipt)
            || !current
                .pairing_acknowledged
                .iter()
                .any(|grant| grant == &self.continuation.source)
        {
            return Err(super::RemoteRenameError::Closed);
        }
        rename_public_current(&store, &current).map_err(super::RemoteRenameError::Owner)?;
        let (_, local, running) = derive_remote_view_from_grant(
            &current,
            &self.continuation.runtime,
            &self.continuation.grant,
            &self.continuation.source,
            self.context.workspace_id,
            &self.context,
        )
        .map_err(super::RemoteRenameError::Owner)?;
        let snapshot =
            guard
                .capture_remote(|| StoreView::read(&store))
                .map_err(|error| match error {
                    StepError::Domain(error) => {
                        super::RemoteRenameError::Owner(Error::Domain(error))
                    }
                    StepError::Source(error) => {
                        super::RemoteRenameError::Owner(Error::UncertainStore(error))
                    }
                })?;
        guard
            .validate_current(&snapshot)
            .map_err(|error| super::RemoteRenameError::Owner(Error::Domain(error)))?;
        let heartbeat = self
            .continuation
            .heartbeat()
            .ok_or(super::RemoteRenameError::Closed)?;
        drop(store);
        Ok(RemoteGitStartedReceiptTurn {
            guard,
            snapshot,
            receipt: self,
            heartbeat,
            floor,
            gate_denied,
            paused,
            stopping,
            local,
            running,
        })
    }

    pub(in crate::unix) fn into_io_watch<'d>(
        self,
        gate_denied: &'d AtomicBool,
        paused: &'d AtomicBool,
        stopping: &'d AtomicBool,
        public_pending: &'d AtomicBool,
    ) -> RemoteGitStartedReceiptIoWatch<'d, 'op>
    where
        'e: 'd,
    {
        RemoteGitStartedReceiptIoWatch {
            watcher: self.watcher,
            operation: self.operation,
            gate_denied,
            paused,
            stopping,
            public_pending,
        }
    }
}

impl RemoteGitStartedReceiptIoWatch<'_, '_> {
    pub(in crate::unix) fn check(
        &self,
    ) -> Result<(), super::super::auth::remote_connection::GateError> {
        use std::sync::atomic::Ordering::Acquire;
        let map = |_| super::super::auth::remote_connection::GateError::Disposed;
        self.operation.check().map_err(map)?;
        self.watcher.check().map_err(map)?;
        if self.gate_denied.load(Acquire)
            || self.paused.load(Acquire)
            || self.stopping.load(Acquire)
            || self.public_pending.load(Acquire)
        {
            return Err(super::super::auth::remote_connection::GateError::Disposed);
        }
        self.operation.check().map_err(map)?;
        self.watcher.check().map_err(map)
    }
    pub(in crate::unix) fn deadline(&self) -> std::time::Instant {
        self.watcher.deadline()
    }
}

impl RemoteGitStartedReceiptTurn<'_, '_, '_, '_> {
    pub(in crate::unix) fn current_for(&self, connection: uuid::Uuid) -> bool {
        self.receipt.connection == connection
            && self.receipt.operation.check().is_ok()
            && self.guard.validate_current(&self.snapshot).is_ok()
            && self.receipt.watcher.check().is_ok()
            && self
                .receipt
                .continuation
                .trusted_now()
                .is_some_and(|now| now.wall.as_secs() >= self.floor)
    }

    pub(in crate::unix) fn matches(&self, receipt: &RemoteGitStartedReceipt<'_, '_>) -> bool {
        std::ptr::eq(
            self.receipt as *const _ as *const (),
            receipt as *const _ as *const (),
        )
    }

    pub(in crate::unix) fn sample(&self) -> super::super::auth::remote_connection::TrustedNow {
        self.receipt
            .continuation
            .trusted_now()
            .filter(|_| self.current_for(self.receipt.connection))
            .unwrap_or(super::super::auth::remote_connection::TrustedNow {
                wall: std::time::Duration::ZERO,
                monotonic: std::time::Instant::now(),
            })
    }

    pub(in crate::unix) fn facts(&self) -> super::super::auth::remote_connection::OwnerFacts<'_> {
        let continuation = &self.receipt.continuation;
        super::super::auth::remote_connection::OwnerFacts {
            protected_host: &continuation.identity,
            origin: &continuation.origin,
            scope: &continuation.runtime.scope,
            runtime: &continuation.runtime.server_runtime,
            heartbeat: &self.heartbeat,
            acknowledged: &continuation.acknowledged,
            local: &self.local,
            running: &self.running,
            auth_ready: true,
            access_expires_at: continuation.credential_deadlines.access_expires_at,
            refresh_at: continuation.credential_deadlines.refresh_at,
            authorization_locked: self.receipt.post.authorization.locked,
            pending_login: false,
            pending_logout: false,
            pending_revoke: self.receipt.post.authorization.pending_cloud_revoke,
            pending_publication: false,
            peer_revoked: false,
            gate_denied: self.gate_denied,
            paused: self.paused,
            stopping: self.stopping,
            cancelled: self.receipt.operation.cancellation_latch(),
        }
    }
}

impl RemoteGitReceiptIoWatch<'_, '_, '_, '_, '_> {
    pub(in crate::unix) fn check(
        &self,
    ) -> Result<(), super::super::auth::remote_connection::GateError> {
        if self.atoms.check().is_err() || !self.worker.current() || self.atoms.check().is_err() {
            return Err(super::super::auth::remote_connection::GateError::Disposed);
        }
        Ok(())
    }

    pub(in crate::unix) fn atoms(&self) -> &RemoteGitReceiptIoAtoms<'_> {
        &self.atoms
    }
}

impl RemoteGitReceiptIoAtoms<'_> {
    pub(in crate::unix) fn deadline(&self) -> std::time::Instant {
        self.watcher.deadline()
    }

    pub(in crate::unix) fn check(&self) -> Result<(), lomi_host_http::BudgetStop> {
        let map = |error| {
            if matches!(error, domain::Error::Deadline) {
                lomi_host_http::BudgetStop::Deadline
            } else {
                lomi_host_http::BudgetStop::Cancelled
            }
        };
        self.watcher.check().map_err(map)?;
        use std::sync::atomic::Ordering::Acquire;
        if self.gate.load(Acquire)
            || self.paused.load(Acquire)
            || self.stopping.load(Acquire)
            || self.public_pending.load(Acquire)
        {
            return Err(lomi_host_http::BudgetStop::Cancelled);
        }
        self.watcher.check().map_err(map)
    }
}

impl RemoteGitReceiptTurn<'_, '_, '_, '_, '_, '_, '_, '_> {
    pub(in crate::unix) fn current_for(&self, connection: uuid::Uuid) -> bool {
        self.receipt.connection == connection
            && self.guard.validate_current(&self.snapshot).is_ok()
            && self.receipt.watcher.check().is_ok()
            && self.receipt.worker.current()
            && self
                .receipt
                .worker
                .now()
                .is_some_and(|now| now.wall.as_secs() >= self.floor)
    }

    pub(in crate::unix) fn matches(&self, receipt: &RemoteGitReceipt<'_, '_, '_, '_, '_>) -> bool {
        std::ptr::eq(
            self.receipt as *const _ as *const (),
            receipt as *const _ as *const (),
        )
    }

    pub(in crate::unix) fn sample(&self) -> super::super::auth::remote_connection::TrustedNow {
        self.receipt
            .worker
            .now()
            .filter(|_| self.current_for(self.receipt.connection))
            .unwrap_or(super::super::auth::remote_connection::TrustedNow {
                wall: std::time::Duration::ZERO,
                monotonic: std::time::Instant::now(),
            })
    }

    pub(in crate::unix) fn facts(&self) -> super::super::auth::remote_connection::OwnerFacts<'_> {
        let receipt = self.receipt;
        let eligibility = receipt.worker.eligibility();
        let deadlines = receipt.worker.provider().captured_deadlines();
        super::super::auth::remote_connection::OwnerFacts {
            protected_host: &eligibility.identity,
            origin: receipt.worker.origin(),
            scope: &eligibility.binding.scope,
            runtime: &eligibility.binding.server_runtime,
            heartbeat: &eligibility.heartbeat,
            acknowledged: &eligibility.publication,
            local: &receipt.local,
            running: &receipt.running,
            auth_ready: true,
            access_expires_at: deadlines.access_expires_at,
            refresh_at: deadlines.refresh_at,
            authorization_locked: receipt.post.authorization.locked,
            pending_login: false,
            pending_logout: false,
            pending_revoke: receipt.post.authorization.pending_cloud_revoke,
            pending_publication: false,
            peer_revoked: false,
            gate_denied: receipt.worker.gate_denied(),
            paused: receipt.worker.paused(),
            stopping: receipt.worker.stopping(),
            cancelled: receipt.worker.operation().cancellation_latch(),
        }
    }
}

fn git_operation_binding(
    connection: &super::super::auth::remote_connection::RemoteConnectionState,
    request: &RpcRequest,
    operation_id: OperationId,
) -> Result<OperationBinding, super::RemoteRenameError> {
    let method = request.call.method();
    let rights = match method.rights() {
        lomi_remote_protocol::MethodRights::Static(rights) => rights
            .to_vec()
            .try_into()
            .map_err(|_| super::RemoteRenameError::Closed)?,
        _ => return Err(super::RemoteRenameError::Closed),
    };
    let (_, context) =
        git_mutation_binding(&request.call).ok_or(super::RemoteRenameError::Closed)?;
    Ok(OperationBinding {
        rights: StoredOperationRights::new(
            operation_id,
            connection.consumer_actor(),
            context.workspace_id,
            method,
            rights,
            false,
        )
        .map_err(|_| super::RemoteRenameError::Closed)?,
        parameter_hash: lomi_host_store::parameter_hash(&request.call)
            .map_err(|error| super::RemoteRenameError::Owner(Error::Store(error)))?,
    })
}

fn git_mutation_binding(call: &RpcCall) -> Option<(OperationId, &WorkspaceContext)> {
    match call {
        RpcCall::GitStage(p) => Some((p.mutation.operation_id, &p.mutation.context)),
        RpcCall::GitUnstage(p) => Some((p.mutation.operation_id, &p.mutation.context)),
        RpcCall::GitCommit(p) => Some((p.mutation.operation_id, &p.mutation.context)),
        RpcCall::GitFetch(p) | RpcCall::GitPush(p) => {
            Some((p.mutation.operation_id, &p.mutation.context))
        }
        RpcCall::GitPull(p) => Some((p.mutation.operation_id, &p.mutation.context)),
        _ => None,
    }
}
