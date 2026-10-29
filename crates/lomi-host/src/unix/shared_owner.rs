//! Inactive ownership foundation. No production writer or Ready proof is wired.
//!
//! One Arc owns both synchronization domains. Only this module sees Store's
//! mutex; callers receive owned records or an operation-bound pending write.
use super::owner_domain::{
    self as domain, Intent, Operation, OwnerDomain, PendingWriter, StepError, StoreFailure,
    StoreView, WriterClass,
};
use lomi_host_store::{
    Admission, AuthorizationFenceReason, ExternalPermit, Identity, LoginIntent, OperationBinding,
};
use lomi_host_store::{
    AuthorizationState, HostStore, ProjectRecord, StoreError, ValidatedProjectRoot,
    prepare_project_root,
};
use lomi_remote_protocol::ipc::LocalAuthConfiguration;
use lomi_remote_protocol::ipc::LocalStartMode;
use lomi_remote_protocol::ipc::{
    LocalPublicationState, LocalSharing, LocalWorkspaceConsentAuthorized,
    LocalWorkspacePublication, LocalWorkspaceRename,
};
use lomi_remote_protocol::{
    Capability, CapabilitySet, ConsumerAuthorizationId, DecimalU64, Effect, OperationId,
    OperationReceipt, OperationResult, OperationState, TerminalContext, WorkspaceContext,
    WorkspaceId,
    rpc::{HostProfile, WorkspaceState},
};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};

#[path = "shared_owner/git.rs"]
mod git;
#[path = "shared_owner/host_metadata.rs"]
pub(super) mod host_metadata;
#[path = "shared_owner/operations.rs"]
mod operations;
#[path = "shared_owner/workspace_removal.rs"]
mod workspace_removal;
pub(super) use git::{
    GitReceiptDisclosure, RemoteGitMutationBegin, RemoteGitMutationPreflight, RemoteGitReceipt,
    RemoteGitReceiptIoWatch, RemoteGitReceiptTurn, RemoteGitStartedReceipt,
    RemoteGitStartedReceiptIoWatch, RemoteGitStartedReceiptTurn, StartedGitContinuation,
};
pub(super) use host_metadata::suggested_host_display_name;
pub(super) use operations::{
    RemoteOperationAuthorization, RemoteOperationCancelProgress, RemoteOperationDisclosure,
};
pub(super) use workspace_removal::{
    WorkspaceRemovalBeginFailure, WorkspaceRemovalBeginWrite, WorkspaceRemovalCheckpointWrite,
    WorkspaceRemovalCompletion, WorkspaceRemovalFinalizeWrite, WorkspaceRemovalUncertainWrite,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Error {
    Domain(domain::Error),
    Store(StoreError),
    UncertainStore(StoreError),
}
impl From<StepError<StoreError>> for Error {
    fn from(error: StepError<StoreError>) -> Self {
        match error {
            StepError::Domain(error) => Self::Domain(error),
            StepError::Source(error) => Self::Store(error),
        }
    }
}

/// Owned local data only. These snapshots cannot establish Domain Ready.
#[derive(Debug, Clone, Copy)]
pub(super) struct AuthStatusSnapshot {
    pub(super) authorization: AuthorizationState,
    pub(super) intent: Option<LoginIntent>,
    pub(super) deferred_intent: Option<LoginIntent>,
}
#[derive(Debug, Clone)]
pub(super) struct AuthSelectionSnapshot {
    pub(super) identity: Identity,
    pub(super) configuration: Option<LocalAuthConfiguration>,
    pub(super) verified_generation: Option<u64>,
}
#[derive(Debug, Clone, Copy)]
pub(super) struct AuthHistorySnapshot {
    pub(super) authorization: AuthorizationState,
    pub(super) cloud_may_exist: Option<bool>,
}

pub(super) struct SharedOwner {
    domain: Arc<OwnerDomain>,
    store: Mutex<HostStore>,
}

impl SharedOwner {
    /// Called after exclusive startup, before handing this one Arc to workers.
    /// Durable verified state never initializes volatile Domain Ready.
    pub(super) fn new(mut store: HostStore) -> Result<Arc<Self>, StoreError> {
        let default_host_name =
            host_metadata::suggested_host_display_name(Some(store.identity().host_id));
        store.initialize_host_display_name(default_host_name)?;
        let generation = store.authorization_state()?.generation;
        Ok(Arc::new(Self {
            domain: Arc::new(OwnerDomain::new(generation)),
            store: Mutex::new(store),
        }))
    }

    #[cfg(test)]
    pub(super) fn probe_both_locks_for_test(&self, operation: &Operation<'_>) -> Result<(), Error> {
        let _domain = self.domain.try_read(operation).map_err(Error::Domain)?;
        let _store = self.try_store()?;
        Ok(())
    }

    // These two helpers are private implementation details, never a public
    // callback/guard escape. Every caller enters Domain before trying Store.
    fn try_store(&self) -> Result<MutexGuard<'_, HostStore>, Error> {
        match self.store.try_lock() {
            Ok(store) => Ok(store),
            Err(TryLockError::WouldBlock) => Err(Error::Domain(domain::Error::Busy)),
            Err(TryLockError::Poisoned(_)) => Err(Error::Domain(domain::Error::Poisoned)),
        }
    }

    fn read<T>(
        &self,
        operation: &Operation<'_>,
        read: impl FnOnce(&HostStore) -> Result<T, StoreError>,
    ) -> Result<T, Error> {
        let guard = self.domain.try_read(operation).map_err(Error::Domain)?;
        let store = match self.try_store() {
            Ok(store) => store,
            Err(Error::Domain(domain::Error::Poisoned)) => {
                // Use the existing fail-closed read path; do not recover a
                // poisoned Store or expose its guard to the caller.
                let _ = guard.capture_local(|| Err::<(), _>(StoreError::Storage));
                return Err(Error::Domain(domain::Error::Poisoned));
            }
            Err(error) => return Err(error),
        };
        let mut result = None;
        let snapshot = guard.capture_local(|| {
            let value = read(&store);
            if let Err(error) = &value
                && !expected_workspace_rejection(*error)
            {
                return Err(*error);
            }
            result = Some(value);
            Ok(())
        })?;
        guard.validate(snapshot).map_err(Error::Domain)?;
        result
            .expect("successful capture runs read")
            .map_err(Error::Store)
    }

    pub(super) fn workspaces(
        &self,
        operation: &Operation<'_>,
    ) -> Result<Vec<ProjectRecord>, Error> {
        self.read(operation, HostStore::list_projects)
    }

    pub(super) fn workspace(
        &self,
        operation: &Operation<'_>,
        id: WorkspaceId,
    ) -> Result<ProjectRecord, Error> {
        self.read(operation, |store| store.workspace(id))
    }

    pub(super) fn shell_profiles(
        &self,
        operation: &Operation<'_>,
        id: WorkspaceId,
    ) -> Result<Vec<HostProfile>, Error> {
        self.read(operation, |store| store.shell_profiles(id))
    }

    /// Local publication diagnosis is a read-only observation. It deliberately
    /// does not capture remote authority or infer acknowledgement from consent.
    pub(super) fn workspace_publication(
        &self,
        operation: &Operation<'_>,
        id: WorkspaceId,
    ) -> Result<LocalWorkspacePublication, Error> {
        self.read(operation, |store| workspace_publication(store, id))
    }

    /// Local status remains available when remote authority has failed closed.
    pub(super) fn authorization_state(
        &self,
        operation: &Operation<'_>,
    ) -> Result<AuthorizationState, Error> {
        self.read(operation, HostStore::authorization_state)
    }

    /// Identity alone is sufficient for future external provider/keychain
    /// configuration checks. Perform filesystem/provider I/O after this returns.
    pub(super) fn identity(&self, operation: &Operation<'_>) -> Result<Identity, Error> {
        self.read(operation, |store| Ok(store.identity().clone()))
    }

    pub(super) fn auth_status(
        &self,
        operation: &Operation<'_>,
    ) -> Result<AuthStatusSnapshot, Error> {
        self.read(operation, |store| {
            Ok(AuthStatusSnapshot {
                authorization: store.authorization_state()?,
                intent: store.login_intent()?,
                deferred_intent: store.deferred_login_intent()?,
            })
        })
    }

    /// Read local auth state while the exact Started Git writer owns the
    /// Shared pending barrier. This is observation only: the token is checked
    /// both before and after Store IO and never validates remote eligibility.
    pub(super) fn auth_status_started_git(
        &self,
        operation: &Operation<'_>,
        continuation: &StartedGitContinuation,
    ) -> Result<AuthStatusSnapshot, Error> {
        operation.check().map_err(Error::Domain)?;
        if !continuation.belongs_to(&self.domain) || !continuation.is_current(operation) {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let store = self.try_store()?;
        let snapshot = AuthStatusSnapshot {
            authorization: store.authorization_state().map_err(Error::Store)?,
            intent: store.login_intent().map_err(Error::Store)?,
            deferred_intent: store.deferred_login_intent().map_err(Error::Store)?,
        };
        operation.check().map_err(Error::Domain)?;
        if !continuation.is_current(operation) {
            return Err(Error::Domain(domain::Error::Stale));
        }
        Ok(snapshot)
    }

    pub(super) fn auth_selection_started_git(
        &self,
        operation: &Operation<'_>,
        continuation: &StartedGitContinuation,
    ) -> Result<AuthSelectionSnapshot, Error> {
        operation.check().map_err(Error::Domain)?;
        if !continuation.belongs_to(&self.domain) || !continuation.is_current(operation) {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let store = self.try_store()?;
        let snapshot = AuthSelectionSnapshot {
            identity: store.identity().clone(),
            configuration: store.auth_configuration().map_err(Error::Store)?,
            verified_generation: store
                .verified_authorization_generation()
                .map_err(Error::Store)?,
        };
        operation.check().map_err(Error::Domain)?;
        if !continuation.is_current(operation) {
            return Err(Error::Domain(domain::Error::Stale));
        }
        Ok(snapshot)
    }

    pub(super) fn auth_selection(
        &self,
        operation: &Operation<'_>,
    ) -> Result<AuthSelectionSnapshot, Error> {
        self.read(operation, |store| {
            Ok(AuthSelectionSnapshot {
                identity: store.identity().clone(),
                configuration: store.auth_configuration()?,
                verified_generation: store.verified_authorization_generation()?,
            })
        })
    }

    pub(super) fn auth_history(
        &self,
        operation: &Operation<'_>,
    ) -> Result<AuthHistorySnapshot, Error> {
        self.read(operation, |store| {
            Ok(AuthHistorySnapshot {
                authorization: store.authorization_state()?,
                cloud_may_exist: store.cloud_authorization_may_exist()?,
            })
        })
    }

    /// A fresh Domain gate as well as the current durable authorization view.
    /// No Store row, cached bool or returned DTO can mint Ready through this API.
    pub(super) fn remote_authorization(
        &self,
        operation: &Operation<'_>,
    ) -> Result<AuthorizationState, Error> {
        let guard = self.domain.try_read(operation).map_err(Error::Domain)?;
        let store = match self.try_store() {
            Ok(store) => store,
            Err(Error::Domain(domain::Error::Poisoned)) => {
                let _ = guard.capture_local(|| Err::<(), _>(StoreError::Storage));
                return Err(Error::Domain(domain::Error::Poisoned));
            }
            Err(error) => return Err(error),
        };
        let mut state = None;
        let snapshot = guard.capture_remote(|| {
            state = Some(store.authorization_state()?);
            StoreView::read(&store)
        })?;
        guard.validate(snapshot).map_err(Error::Domain)?;
        Ok(state.expect("successful capture reads authorization"))
    }

    pub(super) fn begin_share<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        id: WorkspaceId,
        expected_fence: u64,
    ) -> Result<WorkspaceWrite<'d, 'o>, Error> {
        self.begin_workspace_write(operation, WorkspaceChange::Share(id, expected_fence))
    }

    pub(super) fn begin_share_if_authorized<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        authorization: LocalWorkspaceConsentAuthorized,
        expected_fence: u64,
    ) -> Result<WorkspaceWrite<'d, 'o>, Error> {
        self.begin_workspace_write(
            operation,
            WorkspaceChange::ShareAuthorized(authorization, expected_fence),
        )
    }

    pub(super) fn begin_unshare<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        id: WorkspaceId,
    ) -> Result<WorkspaceWrite<'d, 'o>, Error> {
        self.begin_workspace_write(operation, WorkspaceChange::Unshare(id))
    }

    pub(super) fn begin_unshare_if_authorized<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        authorization: LocalWorkspaceConsentAuthorized,
    ) -> Result<WorkspaceWrite<'d, 'o>, Error> {
        self.begin_workspace_write(operation, WorkspaceChange::UnshareAuthorized(authorization))
    }

    pub(super) fn begin_rename_project<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        rename: LocalWorkspaceRename,
    ) -> Result<WorkspaceRenameWrite<'d, 'o>, Error> {
        self.begin_store_turn(
            operation,
            move |store| {
                store.rename_project(rename.workspace_id, &rename.expected_name, &rename.name)
            },
            expected_workspace_rejection,
        )
        .map(WorkspaceRenameWrite)
    }

    pub(super) fn begin_remove_workspace<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        id: WorkspaceId,
    ) -> Result<WorkspaceWrite<'d, 'o>, Error> {
        self.begin_workspace_write(operation, WorkspaceChange::Remove(id))
    }

    fn begin_workspace_write<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        change: WorkspaceChange,
    ) -> Result<WorkspaceWrite<'d, 'o>, Error> {
        // Workspace consent is a shared local fact, not a global auth fence.
        // In particular unshare must not strand unrelated login generations.
        let pending = self
            .domain
            .announce(operation, WriterClass::Shared, Intent::Mutation)
            .map_err(Error::Domain)?;
        Ok(WorkspaceWrite {
            owner: self,
            pending: Some(pending),
            change,
        })
    }
}

#[derive(Clone)]
enum WorkspaceChange {
    Share(WorkspaceId, u64),
    ShareAuthorized(LocalWorkspaceConsentAuthorized, u64),
    Unshare(WorkspaceId),
    UnshareAuthorized(LocalWorkspaceConsentAuthorized),
    Remove(WorkspaceId),
}

/// This classification is limited to the three transactional methods above.
/// Their ordinary conflicts/capacity rejection roll back before commit. It is
/// not a global policy for auth, provider publication, schema or backup errors.
fn expected_workspace_rejection(error: StoreError) -> bool {
    matches!(
        error,
        StoreError::Busy
            | StoreError::Invalid
            | StoreError::NotFound
            | StoreError::RevisionConflict
            | StoreError::IdempotencyConflict
            | StoreError::ResourceExhausted
            | StoreError::NativeWriterBusy
            | StoreError::Fenced
            | StoreError::AlreadyStarted
    )
}

fn workspace_publication(
    store: &HostStore,
    workspace_id: WorkspaceId,
) -> Result<LocalWorkspacePublication, StoreError> {
    let project = store.workspace_publication_record(workspace_id)?;
    let authorization = store.authorization_state()?;
    let identity = store.identity().host_id;
    let mut publication = LocalPublicationState::Unknown;

    let pending_host = store.pending_host_publication()?.is_some();
    let pending_workspace = !store.pending_publications()?.is_empty();
    if pending_host || pending_workspace {
        publication = LocalPublicationState::Pending;
    } else if !authorization.locked
        && !authorization.pending_cloud_revoke
        && store.verified_authorization_generation()? == Some(authorization.generation)
        && let Some(origin) = store
            .auth_configuration()?
            .and_then(|configuration| configuration.remote_api_origin)
    {
        let scope =
            match store.cloud_runtime_scope(authorization.generation, origin.as_str().to_owned()) {
                Ok(scope) => Some(scope),
                Err(StoreError::Busy | StoreError::Fenced | StoreError::Invalid) => None,
                Err(error) => return Err(error),
            };
        if let Some(scope) = scope {
            let state = match store.cloud_runtime_reconciliation_state(&scope) {
                Ok(state) => state,
                Err(StoreError::Busy | StoreError::Fenced | StoreError::RevisionConflict) => None,
                Err(error) => return Err(error),
            };
            if let Some(state) = state.filter(|state| state.scope == scope) {
                let acknowledged = match store.acknowledged_host_publication(&state) {
                    Ok(acknowledged) => acknowledged,
                    Err(StoreError::Busy | StoreError::Fenced | StoreError::RevisionConflict) => {
                        None
                    }
                    Err(error) => return Err(error),
                };
                if let Some(acknowledged) = acknowledged.filter(|ack| ack.state == state) {
                    let current = match current_publication_workspaces(store) {
                        Ok(current) => current,
                        Err(
                            StoreError::Busy
                            | StoreError::Fenced
                            | StoreError::NativeWriterBusy
                            | StoreError::RevisionConflict,
                        ) => None,
                        Err(error) => return Err(error),
                    };
                    if current.is_some_and(|current| current == acknowledged.workspaces) {
                        publication = LocalPublicationState::Acknowledged;
                    }
                }
            }
        }
    }

    Ok(LocalWorkspacePublication {
        host_id: identity,
        workspace_id,
        auth_generation: DecimalU64(authorization.generation),
        consent: if project.consent {
            LocalSharing::Enabled
        } else {
            LocalSharing::Disabled
        },
        publication,
    })
}

/// Build the current exact whole-host membership without invoking a provider.
/// An inconsistent projection is not evidence of acknowledgement.
fn current_publication_workspaces(
    store: &HostStore,
) -> Result<Option<lomi_remote_protocol::http::PublicationWorkspaces>, StoreError> {
    use lomi_remote_protocol::http::{
        PublicationTerminals, PublicationWorkspaces, PublishedTerminal, PublishedWorkspace,
    };
    use lomi_remote_protocol::rpc::{PaneState, TerminalLayout};

    let mut workspaces = Vec::new();
    for project in store
        .list_projects()?
        .into_iter()
        .filter(|project| project.consent)
    {
        let descriptors = store.terminal_descriptors(project.state.context.workspace_id)?;
        let running_descriptors = descriptors
            .iter()
            .filter(|descriptor| descriptor.status == lomi_host_store::TerminalStatus::Running)
            .count();
        let mut layouts = project
            .state
            .tabs
            .0
            .iter()
            .map(|tab| &tab.layout)
            .collect::<Vec<_>>();
        let mut terminals = Vec::new();
        while let Some(layout) = layouts.pop() {
            match layout {
                TerminalLayout::Split { first, second, .. } => {
                    layouts.push(first);
                    layouts.push(second);
                }
                TerminalLayout::Pane { pane } if pane.state == PaneState::Running => {
                    let Some(session) = pane.session.as_ref() else {
                        return Ok(None);
                    };
                    if session.workspace != project.state.context
                        || session.pane_id != pane.pane_id
                        || descriptors
                            .iter()
                            .filter(|descriptor| {
                                descriptor.pane_id == pane.pane_id
                                    && descriptor.status == lomi_host_store::TerminalStatus::Running
                            })
                            .count()
                            != 1
                    {
                        return Ok(None);
                    }
                    terminals.push(PublishedTerminal {
                        pane_id: pane.pane_id,
                        session_id: session.session_id,
                        session_epoch: session.session_epoch,
                    });
                }
                TerminalLayout::Pane { .. } => {}
            }
        }
        if terminals.len() != running_descriptors {
            return Ok(None);
        }
        terminals.sort_by_key(|terminal| terminal.pane_id);
        let terminals = match PublicationTerminals::try_from(terminals) {
            Ok(terminals) => terminals,
            Err(_) => return Ok(None),
        };
        workspaces.push(PublishedWorkspace {
            workspace_id: project.state.context.workspace_id,
            workspace_epoch: project.state.context.workspace_epoch,
            terminals,
        });
    }
    Ok(PublicationWorkspaces::try_from(workspaces).ok())
}

#[must_use]
pub(super) struct WorkspaceWrite<'d, 'o> {
    owner: &'d SharedOwner,
    pending: Option<PendingWriter<'d, 'o>>,
    change: WorkspaceChange,
}

impl WorkspaceWrite<'_, '_> {
    /// Busy retains the SAME announcement, Operation and absolute deadline.
    /// All other results consume the turn. No replacement context is accepted.
    pub(super) fn try_commit(&mut self) -> Result<u64, Error> {
        let result = self.try_phase();
        if matches!(
            result,
            Err(Error::Domain(domain::Error::Busy)) | Err(Error::Store(StoreError::Busy))
        ) {
            return result;
        }
        if let Some(pending) = self.pending.take() {
            match result {
                Ok(value) => {
                    pending.finish().map_err(Error::Domain)?;
                    return Ok(value);
                }
                Err(_) => {
                    // Expected source rejection is a completed turn. An
                    // uncertain error already made finish fail closed. Preserve
                    // the original source error rather than hide it with Drop.
                    let _ = pending.finish();
                }
            }
        }
        result
    }

    fn try_phase(&mut self) -> Result<u64, Error> {
        let pending = self
            .pending
            .as_mut()
            .ok_or(Error::Domain(domain::Error::Stale))?;
        let mut guard = pending.try_enter().map_err(Error::Domain)?;
        let mut store = self.owner.try_store()?;
        let change = self.change.clone();
        guard
            .commit_classified(|| {
                let result = match change {
                    WorkspaceChange::Share(id, fence) => store.share(id, fence),
                    WorkspaceChange::ShareAuthorized(authorization, fence) => {
                        store.share_if_authorized(&authorization, fence)
                    }
                    WorkspaceChange::Unshare(id) => store.unshare(id),
                    WorkspaceChange::UnshareAuthorized(authorization) => {
                        store.unshare_if_authorized(&authorization)
                    }
                    WorkspaceChange::Remove(id) => store.remove_project(id),
                };
                if let Err(error) = result
                    && !expected_workspace_rejection(error)
                {
                    return Err(StoreFailure::Uncertain(Error::UncertainStore(error)));
                }
                // Read this view even after a definite rejected transaction. Failure
                // to establish the post-state is uncertain and closes remote access.
                let view = StoreView::read(&store)
                    .map_err(|error| StoreFailure::Uncertain(Error::UncertainStore(error)))?;
                match result {
                    Ok(value) => Ok((value, view)),
                    Err(error) if expected_workspace_rejection(error) => {
                        Err(StoreFailure::Expected(Error::Store(error), view))
                    }
                    Err(error) => Err(StoreFailure::Uncertain(Error::UncertainStore(error))),
                }
            })
            .map_err(|error| match error {
                StepError::Domain(error) => Error::Domain(error),
                StepError::Source(error) => error,
            })
    }
}

// Only named constructors below can put a Store action in this private turn.
// No caller-supplied closure, Store reference or guard crosses the API boundary.
type StoreAction<'d, T> = Box<dyn FnMut(&mut HostStore) -> Result<T, StoreError> + 'd>;

struct StoreTurn<'d, 'o, T> {
    owner: &'d SharedOwner,
    pending: Option<PendingWriter<'d, 'o>>,
    action: StoreAction<'d, T>,
    expected: fn(StoreError) -> bool,
}
impl<T> StoreTurn<'_, '_, T> {
    fn try_commit(&mut self) -> Result<T, Error> {
        let result = self.try_phase();
        if matches!(
            result,
            Err(Error::Domain(domain::Error::Busy)) | Err(Error::Store(StoreError::Busy))
        ) {
            return result;
        }
        match (self.pending.take(), result) {
            (Some(pending), Ok(value)) => {
                pending.finish().map_err(Error::Domain)?;
                Ok(value)
            }
            (Some(pending), Err(error)) => {
                let _ = pending.finish();
                Err(error)
            }
            (None, result) => result,
        }
    }
    fn try_phase(&mut self) -> Result<T, Error> {
        let pending = self
            .pending
            .as_mut()
            .ok_or(Error::Domain(domain::Error::Stale))?;
        let mut guard = pending.try_enter().map_err(Error::Domain)?;
        let mut store = self.owner.try_store()?;
        let action = &mut self.action;
        let expected = self.expected;
        guard
            .commit_classified(|| {
                let result = action(&mut store);
                if let Err(error) = &result
                    && !expected(*error)
                {
                    return Err(StoreFailure::Uncertain(Error::UncertainStore(*error)));
                }
                let view = StoreView::read(&store)
                    .map_err(|error| StoreFailure::Uncertain(Error::UncertainStore(error)))?;
                match result {
                    Ok(value) => Ok((value, view)),
                    Err(error) => Err(StoreFailure::Expected(Error::Store(error), view)),
                }
            })
            .map_err(|error| match error {
                StepError::Domain(error) => Error::Domain(error),
                StepError::Source(error) => error,
            })
    }
}

// A named wrapper exposes only try_commit; the generic Store turn stays private.
macro_rules! named_turn {
    ($name:ident, $result:ty) => {
        #[must_use]
        pub(super) struct $name<'d, 'o>(StoreTurn<'d, 'o, $result>);
        impl $name<'_, '_> {
            pub(super) fn try_commit(&mut self) -> Result<$result, Error> {
                self.0.try_commit()
            }
        }
    };
}
named_turn!(LoginBeginWrite, LoginIntent);
named_turn!(AuthorizationClockWrite, u64);
named_turn!(CloudPossibleWrite, ());
named_turn!(AuthorizationSuspendWrite, AuthorizationState);
named_turn!(LocalLogoutWrite, AuthorizationState);
named_turn!(CloudRevokeAckWrite, AuthorizationState);
named_turn!(LocalLogoutAckWrite, AuthorizationState);
named_turn!(AuthorizationSealWrite, ());
named_turn!(CleanShutdownWrite, ());
named_turn!(AddProjectWrite, ProjectRecord);
named_turn!(WorkspaceRenameWrite, ProjectRecord);
named_turn!(ShellProfileWrite, ());
named_turn!(SetupStartModeWrite, ());
named_turn!(HostNameWrite, lomi_remote_protocol::ipc::LocalHostName);
named_turn!(ExternalAdmissionWrite, Admission);
/// Retains the actual accepted -> running result before fallible postchecks.
/// A saved permit after error is reconciliation data, never permission to run
/// an OS effect under the failed original Operation.
#[must_use]
pub(super) struct ExternalStartWrite<'d, 'o> {
    owner: &'d SharedOwner,
    operation: &'o Operation<'o>,
    binding: &'d OperationBinding,
    pending: Option<PendingWriter<'d, 'o>>,
    started: Option<ExternalPermit>,
    terminal: Option<Error>,
    #[cfg(test)]
    fault: Option<ExternalStartFault>,
    #[cfg(test)]
    starts: usize,
}
#[cfg(test)]
#[derive(Clone, Copy)]
enum ExternalStartFault {
    PostView(StoreError),
    PostActionDeadline,
    FinishDeadline,
}
impl ExternalStartWrite<'_, '_> {
    pub(super) fn try_commit(&mut self) -> Result<ExternalPermit, Error> {
        if let Some(error) = self.terminal {
            return Err(error);
        }
        let result = self.try_phase();
        if self.started.is_none()
            && let Err(
                error @ (Error::Domain(domain::Error::Busy) | Error::Store(StoreError::Busy)),
            ) = result
        {
            return Err(error);
        }
        if let Err(error) = result {
            // A post-success Busy cannot replay the start or masquerade as a
            // phase still waiting to execute. Keep its actual permit for take.
            let error = if self.started.is_some()
                && matches!(
                    error,
                    Error::Domain(domain::Error::Busy) | Error::Store(StoreError::Busy)
                ) {
                Error::UncertainStore(StoreError::Busy)
            } else {
                error
            };
            self.terminal = Some(error);
            if self.started.is_none()
                && let Some(pending) = self.pending.take()
            {
                let _ = pending.finish();
            }
            return Err(error);
        }
        #[cfg(test)]
        if matches!(self.fault, Some(ExternalStartFault::FinishDeadline)) {
            self.fault = None;
            self.operation.expire_for_test();
        }
        if let Some(pending) = self.pending.take()
            && let Err(error) = pending.finish()
        {
            let error = Error::Domain(error);
            self.terminal = Some(error);
            return Err(error);
        }
        self.started
            .take()
            .ok_or(Error::Domain(domain::Error::Stale))
    }
    /// Error-only, move-once handoff to a slot reserved BEFORE admission/start.
    /// This does not check/renew authority and must not authorize an OS effect.
    pub(super) fn take_started_permit(&mut self) -> Option<ExternalPermit> {
        self.terminal?;
        let permit = self.started.take()?;
        if let Some(pending) = self.pending.take() {
            let _ = pending.finish();
        }
        Some(permit)
    }
    fn try_phase(&mut self) -> Result<(), Error> {
        if self.started.is_some() {
            return Err(Error::Domain(domain::Error::Stale));
        }
        self.operation.check().map_err(Error::Domain)?;
        let pending = self
            .pending
            .as_mut()
            .ok_or(Error::Domain(domain::Error::Stale))?;
        let mut guard = pending.try_enter().map_err(Error::Domain)?;
        let mut store = self.owner.try_store()?;
        let started = &mut self.started;
        let binding = self.binding;
        #[cfg(test)]
        let operation = self.operation;
        #[cfg(test)]
        let fault = self.fault;
        #[cfg(test)]
        if !matches!(fault, Some(ExternalStartFault::FinishDeadline)) {
            self.fault = None;
        }
        #[cfg(test)]
        let starts = &mut self.starts;
        guard
            .commit_classified(|| {
                #[cfg(test)]
                {
                    *starts += 1;
                }
                let result = store.start_external(binding);
                // Move the real permit into the retained turn BEFORE any operation,
                // view, Domain observation, or finish check can fail.
                let result = match result {
                    Ok(permit) => {
                        *started = Some(permit);
                        Ok(())
                    }
                    Err(error) => Err(error),
                };
                #[cfg(test)]
                if started.is_some() {
                    match fault {
                        Some(ExternalStartFault::PostView(error)) => {
                            return Err(StoreFailure::Uncertain(Error::UncertainStore(error)));
                        }
                        Some(ExternalStartFault::PostActionDeadline) => operation.expire_for_test(),
                        _ => {}
                    }
                }
                if let Err(error) = &result
                    && !expected_start(*error)
                {
                    return Err(StoreFailure::Uncertain(Error::UncertainStore(*error)));
                }
                let view = StoreView::read(&store)
                    .map_err(|error| StoreFailure::Uncertain(Error::UncertainStore(error)))?;
                match result {
                    Ok(()) => Ok(((), view)),
                    Err(error) => Err(StoreFailure::Expected(Error::Store(error), view)),
                }
            })
            .map_err(|error| match error {
                StepError::Domain(error) => Error::Domain(error),
                StepError::Source(error) => error,
            })
    }
}

named_turn!(ExternalCompletionWrite, OperationReceipt);
named_turn!(RemoteNamespacePreparationWrite, ());
named_turn!(CancellationWrite, Option<OperationReceipt>);
named_turn!(TerminalTransitionWrite, bool);

/// Generation-conditional fence. Only this named turn can arm a rejection
/// after checking Store under the same uninterrupted Domain -> Store locks.
#[must_use]
pub(super) struct AuthorityRejectionWrite<'d, 'o> {
    owner: &'d SharedOwner,
    pending: Option<PendingWriter<'d, 'o>>,
    expected_generation: u64,
}
impl AuthorityRejectionWrite<'_, '_> {
    pub(super) fn try_commit(&mut self) -> Result<AuthorizationState, Error> {
        let result = self.try_phase();
        if matches!(
            result,
            Err(Error::Domain(domain::Error::Busy)) | Err(Error::Store(StoreError::Busy))
        ) {
            return result;
        }
        match (self.pending.take(), result) {
            (Some(pending), Ok(value)) => {
                pending.finish().map_err(Error::Domain)?;
                Ok(value)
            }
            (Some(pending), Err(error)) => {
                let _ = pending.finish();
                Err(error)
            }
            (None, result) => result,
        }
    }

    fn try_phase(&mut self) -> Result<AuthorizationState, Error> {
        let pending = self
            .pending
            .as_mut()
            .ok_or(Error::Domain(domain::Error::Stale))?;
        let mut guard = pending.try_enter().map_err(Error::Domain)?;
        let mut store = self.owner.try_store()?;
        let checked = match store.authorization_state() {
            Ok(state) if state.generation == self.expected_generation => {
                guard
                    .arm_authority_rejection(self.expected_generation)
                    .map_err(Error::Domain)?;
                Ok(())
            }
            Ok(_) => Err(StoreError::Fenced),
            Err(error) => Err(error),
        };
        guard
            .commit_classified(|| {
                let result = checked.and_then(|()| {
                    store.fence_authorization(AuthorizationFenceReason::AuthorityRejected)
                });
                if let Err(error) = result
                    && !expected_authority_rejection(error)
                {
                    return Err(StoreFailure::Uncertain(Error::UncertainStore(error)));
                }
                // Busy may have sealed Store; capture/observe its actual locked
                // post-state before preserving the source error and pending token.
                let view = StoreView::read(&store)
                    .map_err(|error| StoreFailure::Uncertain(Error::UncertainStore(error)))?;
                match result {
                    Ok(value) => Ok((value, view)),
                    Err(error) => Err(StoreFailure::Expected(Error::Store(error), view)),
                }
            })
            .map_err(|error| match error {
                StepError::Domain(error) => Error::Domain(error),
                StepError::Source(error) => error,
            })
    }
}

/// Credential-specific generation/configuration fence. The exact selected
/// configuration and captured generation are checked under Domain -> Store
/// before the rejection is armed, then the Store records its deferred intent
/// marker in the same classified write.
#[must_use]
pub(super) struct CredentialRejectionWrite<'d, 'o> {
    owner: &'d SharedOwner,
    pending: Option<PendingWriter<'d, 'o>>,
    expected_generation: u64,
    expected_configuration: LocalAuthConfiguration,
}
impl CredentialRejectionWrite<'_, '_> {
    pub(super) fn try_commit(&mut self) -> Result<AuthorizationState, Error> {
        let result = self.try_phase();
        if matches!(
            result,
            Err(Error::Domain(domain::Error::Busy)) | Err(Error::Store(StoreError::Busy))
        ) {
            return result;
        }
        match (self.pending.take(), result) {
            (Some(pending), Ok(value)) => {
                pending.finish().map_err(Error::Domain)?;
                Ok(value)
            }
            (Some(pending), Err(error)) => {
                let _ = pending.finish();
                Err(error)
            }
            (None, result) => result,
        }
    }

    fn try_phase(&mut self) -> Result<AuthorizationState, Error> {
        let pending = self
            .pending
            .as_mut()
            .ok_or(Error::Domain(domain::Error::Stale))?;
        let mut guard = pending.try_enter().map_err(Error::Domain)?;
        let mut store = self.owner.try_store()?;
        let checked = match store.authorization_state() {
            Ok(state) if state.generation == self.expected_generation => {
                match store.auth_configuration() {
                    Ok(Some(configuration)) if configuration == self.expected_configuration => {
                        guard
                            .arm_authority_rejection(self.expected_generation)
                            .map_err(Error::Domain)?;
                        Ok(())
                    }
                    Ok(_) => Err(StoreError::Fenced),
                    Err(error) => Err(error),
                }
            }
            Ok(_) => Err(StoreError::Fenced),
            Err(error) => Err(error),
        };
        guard
            .commit_classified(|| {
                let result = checked.and_then(|()| {
                    store.fence_rejected_credentials(
                        self.expected_generation,
                        &self.expected_configuration,
                    )
                });
                if let Err(error) = result
                    && !expected_authority_rejection(error)
                {
                    return Err(StoreFailure::Uncertain(Error::UncertainStore(error)));
                }
                let view = StoreView::read(&store)
                    .map_err(|error| StoreFailure::Uncertain(Error::UncertainStore(error)))?;
                match result {
                    Ok(value) => Ok((value, view)),
                    Err(error) => Err(StoreFailure::Expected(Error::Store(error), view)),
                }
            })
            .map_err(|error| match error {
                StepError::Domain(error) => Error::Domain(error),
                StepError::Source(error) => error,
            })
    }
}

// These lists describe definite transaction rollbacks for each concrete method.
// Unexpected Invalid/capacity errors from terminal-transition/cancel internals
// are not generalized into harmless rejections.
// Only known pre-commit project capacity/validation failures are definite.
fn expected_add_project(error: StoreError) -> bool {
    matches!(
        error,
        StoreError::Busy
            | StoreError::Invalid
            | StoreError::IdempotencyConflict
            | StoreError::ResourceExhausted
    )
}
fn expected_admission(error: StoreError) -> bool {
    matches!(
        error,
        StoreError::Busy
            | StoreError::Invalid
            | StoreError::NotFound
            | StoreError::RevisionConflict
            | StoreError::IdempotencyConflict
            | StoreError::ResourceExhausted
    )
}
fn expected_start(error: StoreError) -> bool {
    matches!(
        error,
        StoreError::Busy
            | StoreError::NotFound
            | StoreError::AlreadyStarted
            | StoreError::Fenced
            | StoreError::NativeWriterBusy
            | StoreError::RevisionConflict
            | StoreError::IdempotencyConflict
    )
}
fn expected_completion(error: StoreError) -> bool {
    matches!(
        error,
        StoreError::Busy
            | StoreError::Invalid
            | StoreError::NotFound
            | StoreError::AlreadyStarted
            | StoreError::ResourceExhausted
            | StoreError::IdempotencyConflict
    )
}
fn expected_cancellation(error: StoreError) -> bool {
    matches!(error, StoreError::Busy | StoreError::Fenced)
}
fn expected_terminal_transition(error: StoreError) -> bool {
    error == StoreError::Busy
}

fn expected_login_begin(error: StoreError) -> bool {
    matches!(
        error,
        StoreError::Busy | StoreError::Invalid | StoreError::Fenced
    )
}
fn expected_auth_generation(error: StoreError) -> bool {
    matches!(error, StoreError::Busy | StoreError::Fenced)
}
fn expected_auth_fence(error: StoreError) -> bool {
    matches!(error, StoreError::Busy | StoreError::ResourceExhausted)
}
fn expected_authority_rejection(error: StoreError) -> bool {
    expected_auth_fence(error) || error == StoreError::Fenced
}
fn expected_auth_clock(error: StoreError) -> bool {
    error == StoreError::Busy
}
fn expected_seal(_error: StoreError) -> bool {
    false
}
fn never_expected_store_error(_error: StoreError) -> bool {
    false
}

impl SharedOwner {
    fn begin_store_turn<'d, 'o, T>(
        &'d self,
        operation: &'o Operation<'o>,
        action: impl FnMut(&mut HostStore) -> Result<T, StoreError> + 'd,
        expected: fn(StoreError) -> bool,
    ) -> Result<StoreTurn<'d, 'o, T>, Error> {
        self.begin_classified_store_turn(
            operation,
            WriterClass::Shared,
            Intent::Mutation,
            action,
            expected,
        )
    }

    // Private classes/intents are selected only by named constructors, never by
    // a caller-supplied callback or returned Store/Domain guard.
    fn begin_classified_store_turn<'d, 'o, T>(
        &'d self,
        operation: &'o Operation<'o>,
        class: WriterClass,
        intent: Intent,
        action: impl FnMut(&mut HostStore) -> Result<T, StoreError> + 'd,
        expected: fn(StoreError) -> bool,
    ) -> Result<StoreTurn<'d, 'o, T>, Error> {
        let pending = self
            .domain
            .announce(operation, class, intent)
            .map_err(Error::Domain)?;
        Ok(StoreTurn {
            owner: self,
            pending: Some(pending),
            action: Box::new(action),
            expected,
        })
    }

    // All adapters below are NON-READY primitives. Acknowledgements require a
    // future worker to join the exact pending generation with actual provider
    // results; these APIs do not verify a remote acknowledgement's authority.
    pub(super) fn begin_login<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        operation_id: OperationId,
        expected_configuration: LocalAuthConfiguration,
        expected_generation: u64,
    ) -> Result<LoginBeginWrite<'d, 'o>, Error> {
        self.begin_classified_store_turn(
            operation,
            WriterClass::Remote,
            Intent::Mutation,
            move |store| {
                if store.authorization_state()?.generation != expected_generation
                    || store.auth_configuration()?.as_ref() != Some(&expected_configuration)
                {
                    return Err(StoreError::Fenced);
                }
                store.begin_login(operation_id)
            },
            expected_login_begin,
        )
        .map(LoginBeginWrite)
    }

    /// This standalone clock turn cannot follow a provider response inside a
    /// future verification flow: it would stale that verification scope. Such
    /// a concrete verify turn must persist the post-response clock with its
    /// original scope. No verification/Ready transition is implemented here.
    pub(super) fn begin_observe_authorization_clock<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        now: u64,
    ) -> Result<AuthorizationClockWrite<'d, 'o>, Error> {
        self.begin_classified_store_turn(
            operation,
            WriterClass::Remote,
            Intent::Mutation,
            move |store| store.observe_authorization_clock(now),
            expected_auth_clock,
        )
        .map(AuthorizationClockWrite)
    }

    pub(super) fn begin_mark_cloud_authorization_possible<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        generation: u64,
    ) -> Result<CloudPossibleWrite<'d, 'o>, Error> {
        self.begin_classified_store_turn(
            operation,
            WriterClass::Remote,
            Intent::Mutation,
            move |store| store.mark_cloud_authorization_possible(generation),
            expected_auth_generation,
        )
        .map(CloudPossibleWrite)
    }

    pub(super) fn begin_suspend_authorization<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        generation: u64,
    ) -> Result<AuthorizationSuspendWrite<'d, 'o>, Error> {
        // Suspension permits a fresh same-generation scope; it is not a fence.
        self.begin_classified_store_turn(
            operation,
            WriterClass::Remote,
            Intent::Mutation,
            move |store| store.suspend_authorization(generation),
            expected_auth_generation,
        )
        .map(AuthorizationSuspendWrite)
    }

    pub(super) fn begin_local_logout<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
    ) -> Result<LocalLogoutWrite<'d, 'o>, Error> {
        self.begin_classified_store_turn(
            operation,
            WriterClass::Shared,
            Intent::FenceRemote,
            |store| store.fence_authorization(AuthorizationFenceReason::LocalLogout),
            expected_auth_fence,
        )
        .map(LocalLogoutWrite)
    }

    pub(super) fn begin_authority_rejection<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        expected_generation: u64,
    ) -> Result<AuthorityRejectionWrite<'d, 'o>, Error> {
        // A delayed rejection must not fence the currently active generation.
        // Shared pending blocks new remote effects before the exact locked check.
        let pending = self
            .domain
            .announce(operation, WriterClass::Shared, Intent::Mutation)
            .map_err(Error::Domain)?;
        Ok(AuthorityRejectionWrite {
            owner: self,
            pending: Some(pending),
            expected_generation,
        })
    }

    pub(super) fn begin_credential_rejection<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        expected_generation: u64,
        expected_configuration: LocalAuthConfiguration,
    ) -> Result<CredentialRejectionWrite<'d, 'o>, Error> {
        let pending = self
            .domain
            .announce(operation, WriterClass::Shared, Intent::Mutation)
            .map_err(Error::Domain)?;
        Ok(CredentialRejectionWrite {
            owner: self,
            pending: Some(pending),
            expected_generation,
            expected_configuration,
        })
    }

    pub(super) fn begin_acknowledge_authorization_revoke<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        generation: u64,
    ) -> Result<CloudRevokeAckWrite<'d, 'o>, Error> {
        self.begin_classified_store_turn(
            operation,
            WriterClass::Remote,
            Intent::Mutation,
            move |store| store.acknowledge_authorization_revoke(generation),
            expected_auth_generation,
        )
        .map(CloudRevokeAckWrite)
    }

    pub(super) fn begin_acknowledge_local_authorization_logout<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        generation: u64,
    ) -> Result<LocalLogoutAckWrite<'d, 'o>, Error> {
        self.begin_classified_store_turn(
            operation,
            WriterClass::Remote,
            Intent::Mutation,
            move |store| store.acknowledge_local_authorization_logout(generation),
            expected_auth_generation,
        )
        .map(LocalLogoutAckWrite)
    }

    pub(super) fn begin_seal_authorization<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
    ) -> Result<AuthorizationSealWrite<'d, 'o>, Error> {
        self.begin_classified_store_turn(
            operation,
            WriterClass::Remote,
            Intent::Mutation,
            |store| {
                store.seal_authorization();
                Ok(())
            },
            expected_seal,
        )
        .map(AuthorizationSealWrite)
    }

    pub(super) fn begin_record_clean_shutdown<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
    ) -> Result<CleanShutdownWrite<'d, 'o>, Error> {
        self.begin_classified_store_turn(
            operation,
            WriterClass::Shared,
            Intent::Mutation,
            HostStore::record_clean_shutdown,
            expected_terminal_transition,
        )
        .map(CleanShutdownWrite)
    }

    pub(super) fn begin_save_local_start_mode<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        mode: LocalStartMode,
    ) -> Result<SetupStartModeWrite<'d, 'o>, Error> {
        self.begin_store_turn(
            operation,
            move |store| store.save_local_start_mode(mode),
            never_expected_store_error,
        )
        .map(SetupStartModeWrite)
    }

    /// Prepare the root with neither Domain nor Store held, then announce the
    /// SQL-only turn. Busy retries retain this turn's original Operation/token.
    pub(super) fn begin_add_project<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        root: &std::path::Path,
        name: lomi_remote_protocol::rpc::DisplayText,
    ) -> Result<AddProjectWrite<'d, 'o>, Error> {
        operation.check().map_err(Error::Domain)?;
        let prepared = prepare_project_root(root);
        self.begin_prepared_project(operation, prepared, name)
    }

    fn begin_prepared_project<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        prepared: Result<ValidatedProjectRoot, StoreError>,
        name: lomi_remote_protocol::rpc::DisplayText,
    ) -> Result<AddProjectWrite<'d, 'o>, Error> {
        // Check even on preparation failure: blocking filesystem work does not
        // create a replacement deadline or mask observed cancellation/expiry.
        operation.check().map_err(Error::Domain)?;
        let prepared = prepared.map_err(Error::Store)?;
        self.begin_store_turn(
            operation,
            move |store| store.insert_prepared_project(&prepared, name.clone()),
            expected_add_project,
        )
        .map(AddProjectWrite)
    }

    pub(super) fn begin_import_workspace<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        root: &std::path::Path,
        name: lomi_remote_protocol::rpc::DisplayText,
        workspace_id: WorkspaceId,
    ) -> Result<AddProjectWrite<'d, 'o>, Error> {
        operation.check().map_err(Error::Domain)?;
        let prepared = prepare_project_root(root);
        operation.check().map_err(Error::Domain)?;
        let prepared = prepared.map_err(Error::Store)?;
        self.begin_store_turn(
            operation,
            move |store| store.import_prepared_workspace(&prepared, name.clone(), workspace_id),
            expected_add_project,
        )
        .map(AddProjectWrite)
    }

    pub(super) fn begin_register_shell_profile<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        profile: lomi_remote_protocol::ipc::LocalShellProfileRegister,
    ) -> Result<ShellProfileWrite<'d, 'o>, Error> {
        self.begin_store_turn(
            operation,
            move |store| store.register_shell_profile(profile.clone()),
            expected_admission,
        )
        .map(ShellProfileWrite)
    }

    /// Native bookkeeping uses Store serialization directly. It must not issue
    /// a Domain authority ticket when registration/check/denial is metadata-only;
    /// the durable SQLite writer barrier arbitrates native-vs-remote effects.
    fn native_store<T>(
        &self,
        operation: &Operation<'_>,
        action: impl FnOnce(&mut HostStore) -> Result<T, StoreError>,
    ) -> Result<T, Error> {
        operation.check().map_err(Error::Domain)?;
        let mut store = self.try_store()?;
        operation.check().map_err(Error::Domain)?;
        action(&mut store).map_err(Error::Store)
    }

    pub(super) fn native_intent(
        &self,
        operation: &Operation<'_>,
        request: lomi_remote_protocol::ipc::NativeIntentRequest,
        connection: lomi_remote_protocol::ipc::IpcNonce,
    ) -> Result<lomi_remote_protocol::ipc::NativeIntentId, Error> {
        self.native_store(operation, |store| {
            store.register_native_intent(&request, connection)
        })
    }

    pub(super) fn native_acknowledge(
        &self,
        operation: &Operation<'_>,
        intent_id: lomi_remote_protocol::ipc::NativeIntentId,
    ) -> Result<(), Error> {
        self.native_store(operation, |store| {
            store.acknowledge_native_intent(intent_id)
        })
    }

    pub(super) fn native_bind_preflight(
        &self,
        operation: &Operation<'_>,
        intent_id: lomi_remote_protocol::ipc::NativeIntentId,
        connection: lomi_remote_protocol::ipc::IpcNonce,
        store_root: &str,
        parent_operation_id: &str,
    ) -> Result<Option<lomi_remote_protocol::ipc::NativeLease>, Error> {
        self.native_store(operation, |store| {
            store.native_bind_preflight(intent_id, connection, store_root, parent_operation_id)
        })
    }

    pub(super) fn reject_unbound_native_intent(
        &self,
        operation: &Operation<'_>,
        intent_id: lomi_remote_protocol::ipc::NativeIntentId,
        connection: lomi_remote_protocol::ipc::IpcNonce,
    ) -> Result<(), Error> {
        self.native_store(operation, |store| {
            store.reject_unbound_native_intent(intent_id, connection)
        })
    }

    pub(super) fn native_bind_registered(
        &self,
        operation: &Operation<'_>,
        intent_id: lomi_remote_protocol::ipc::NativeIntentId,
        connection: lomi_remote_protocol::ipc::IpcNonce,
        store_root: &str,
        parent_operation_id: &str,
        binding_json: &str,
        runtime_descriptor_json: &str,
    ) -> Result<lomi_remote_protocol::ipc::NativeLease, Error> {
        self.native_store(operation, |store| {
            store.bind_registered_native_intent(
                intent_id,
                connection,
                store_root,
                parent_operation_id,
                binding_json,
                runtime_descriptor_json,
            )
        })
    }

    pub(super) fn native_quarantine_for_verification(
        &self,
        operation: &Operation<'_>,
        intent_id: lomi_remote_protocol::ipc::NativeIntentId,
    ) -> Result<
        (
            lomi_remote_protocol::ipc::NativeLease,
            Option<lomi_host_store::NativeEvidenceBinding>,
        ),
        Error,
    > {
        self.native_store(operation, |store| {
            store.quarantine_native_intent_for_verification(intent_id)
        })
    }

    pub(super) fn native_finish_verified(
        &self,
        operation: &Operation<'_>,
        intent_id: lomi_remote_protocol::ipc::NativeIntentId,
        binding_sha256: &str,
    ) -> Result<lomi_remote_protocol::ipc::NativeLease, Error> {
        self.native_store(operation, |store| {
            store.finish_native_intent_if_binding_matches(intent_id, binding_sha256)
        })
    }

    pub(super) fn native_acquire(
        &self,
        operation: &Operation<'_>,
        intent_id: lomi_remote_protocol::ipc::NativeIntentId,
        connection: lomi_remote_protocol::ipc::IpcNonce,
    ) -> Result<lomi_remote_protocol::ipc::NativeLease, Error> {
        self.native_store(operation, |store| {
            store.acquire_native_intent(intent_id, connection)
        })
    }

    pub(super) fn native_check(
        &self,
        operation: &Operation<'_>,
        intent_id: lomi_remote_protocol::ipc::NativeIntentId,
        connection: lomi_remote_protocol::ipc::IpcNonce,
    ) -> Result<lomi_remote_protocol::ipc::NativeLease, Error> {
        self.native_store(operation, |store| {
            store.check_native_intent(intent_id, connection)
        })
    }

    pub(super) fn native_renew(
        &self,
        operation: &Operation<'_>,
        intent_id: lomi_remote_protocol::ipc::NativeIntentId,
        connection: lomi_remote_protocol::ipc::IpcNonce,
    ) -> Result<lomi_remote_protocol::ipc::NativeLease, Error> {
        self.native_store(operation, |store| {
            store.renew_native_intent(intent_id, connection)
        })
    }

    pub(super) fn native_request_finish(
        &self,
        operation: &Operation<'_>,
        intent_id: lomi_remote_protocol::ipc::NativeIntentId,
    ) -> Result<lomi_remote_protocol::ipc::NativeLease, Error> {
        self.native_store(operation, |store| {
            store.request_finish_native_intent(intent_id)
        })
    }

    pub(super) fn native_reconcile(
        &self,
        operation: &Operation<'_>,
        intent_id: lomi_remote_protocol::ipc::NativeIntentId,
    ) -> Result<lomi_remote_protocol::ipc::NativeLease, Error> {
        self.native_store(operation, |store| store.reconcile_native_intent(intent_id))
    }

    pub(super) fn native_connection_lost(
        &self,
        operation: &Operation<'_>,
        connection: lomi_remote_protocol::ipc::IpcNonce,
    ) -> Result<(), Error> {
        self.native_store(operation, |store| {
            store.quarantine_native_connection(connection)
        })
    }

    pub(super) fn native_editor_stage(
        &self,
        operation: &Operation<'_>,
        operation_id: lomi_remote_protocol::ipc::NativeIntentId,
        byte_length: u64,
        content_sha256: &str,
    ) -> Result<lomi_host_store::NativeEditorStageRegistration, Error> {
        self.native_store(operation, |store| {
            store.register_native_editor_stage(operation_id, byte_length, content_sha256)
        })
    }

    pub(super) fn native_editor_expire_stages(
        &self,
    ) -> Result<Vec<lomi_remote_protocol::ipc::NativeIntentId>, Error> {
        let mut store = self.try_store()?;
        store.expire_native_editor_stages().map_err(Error::Store)
    }

    pub(super) fn native_editor_ack_stage_cleanup(
        &self,
        operation_ids: &[lomi_remote_protocol::ipc::NativeIntentId],
    ) -> Result<(), Error> {
        let mut store = self.try_store()?;
        store
            .acknowledge_native_editor_stage_cleanup(operation_ids)
            .map_err(Error::Store)
    }

    pub(super) fn native_editor_begin(
        &self,
        operation: &Operation<'_>,
        operation_id: lomi_remote_protocol::ipc::NativeIntentId,
        byte_length: u64,
        content_sha256: &str,
        request_hash: &str,
        connection: lomi_remote_protocol::ipc::IpcNonce,
        workspace_guard: Option<&lomi_host_store::WorkspaceEffectGuard>,
    ) -> Result<lomi_host_store::NativeEditorBegin, Error> {
        self.native_store(operation, |store| match workspace_guard {
            Some(guard) => store.begin_native_editor_job_for_workspace(
                guard,
                operation_id,
                byte_length,
                content_sha256,
                request_hash,
                connection,
            ),
            None => store.begin_native_editor_job(
                operation_id,
                byte_length,
                content_sha256,
                request_hash,
                connection,
            ),
        })
    }

    pub(super) fn native_editor_retry(
        &self,
        operation: &Operation<'_>,
        operation_id: lomi_remote_protocol::ipc::NativeIntentId,
        byte_length: u64,
        content_sha256: &str,
        request_hash: &str,
    ) -> Result<Option<lomi_host_store::NativeEditorJobRecord>, Error> {
        self.native_store(operation, |store| {
            store.native_editor_job_retry(operation_id, byte_length, content_sha256, request_hash)
        })
    }

    pub(super) fn native_editor_status(
        &self,
        operation: &Operation<'_>,
        operation_id: lomi_remote_protocol::ipc::NativeIntentId,
    ) -> Result<lomi_host_store::NativeEditorJobRecord, Error> {
        self.native_store(operation, |store| store.native_editor_job(operation_id))
    }

    pub(super) fn native_editor_disposition_read(
        &self,
        operation: &Operation<'_>,
        operation_id: lomi_remote_protocol::ipc::NativeIntentId,
    ) -> Result<lomi_remote_protocol::ipc::NativeEditorDisposition, Error> {
        self.read(operation, |store| {
            store.native_editor_disposition_read(operation_id)
        })
    }

    pub(super) fn workspace_bindings_read(
        &self,
        operation: &Operation<'_>,
        import_ids: &[WorkspaceId],
    ) -> Result<lomi_remote_protocol::ipc::WorkspaceBindingsSnapshot, Error> {
        self.read(operation, |store| store.workspace_bindings_read(import_ids))
    }

    pub(super) fn native_editor_acknowledge(
        &self,
        operation: &Operation<'_>,
        operation_id: lomi_remote_protocol::ipc::NativeIntentId,
    ) -> Result<(), Error> {
        self.native_store(operation, |store| {
            store.acknowledge_native_editor_job(operation_id)
        })
    }

    /// Completion has already joined the actual no-exec worker. It uses only
    /// the Store mutex and remains retryable on a contended Store without
    /// issuing a Domain authority mutation or holding any lock across I/O.
    pub(super) fn native_editor_complete(
        &self,
        operation_id: lomi_remote_protocol::ipc::NativeIntentId,
        state: lomi_host_store::NativeEditorJobState,
        proof: lomi_host_store::NativeEditorCompletionProof,
        result_json: Option<String>,
    ) -> Result<(), Error> {
        let mut store = self.try_store()?;
        store
            .complete_native_editor_job(operation_id, state, proof, result_json)
            .map_err(Error::Store)
    }

    pub(super) fn native_namespace_plan(
        &self,
        operation: &Operation<'_>,
        operation_id: lomi_remote_protocol::ipc::NativeIntentId,
        effect: lomi_host_store::DesktopNamespaceEffect,
    ) -> Result<lomi_host_store::DesktopNamespacePlan, Error> {
        self.native_store(operation, |store| {
            store.plan_desktop_namespace(operation_id, effect)
        })
    }

    pub(super) fn remote_namespace_guarded_workspaces(
        &self,
        operation: &Operation<'_>,
        effect: &lomi_host_store::DesktopNamespaceEffect,
    ) -> Result<Vec<WorkspaceId>, Error> {
        self.read(operation, |store| {
            store.desktop_namespace_guarded_workspaces(effect)
        })
    }

    pub(super) fn remote_namespace_plan(
        &self,
        operation: &Operation<'_>,
        permit: &ExternalPermit,
        effect: lomi_host_store::DesktopNamespaceEffect,
    ) -> Result<lomi_host_store::RemoteDesktopNamespacePlan, Error> {
        self.read(operation, |store| {
            store.plan_desktop_namespace_remote(permit, effect)
        })
    }

    pub(super) fn begin_remote_namespace_prepare<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        permit: &'d ExternalPermit,
        plan: &'d lomi_host_store::RemoteDesktopNamespacePlan,
        proof: &'d lomi_host_store::DesktopNamespacePhysicalProof,
    ) -> Result<RemoteNamespacePreparationWrite<'d, 'o>, Error> {
        self.begin_store_turn(
            operation,
            move |store| {
                store
                    .prepare_desktop_namespace_remote(permit, plan, proof)
                    .map(|_| ())
            },
            expected_completion,
        )
        .map(RemoteNamespacePreparationWrite)
    }

    pub(super) fn begin_remote_namespace_complete<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        permit: &'d ExternalPermit,
        state: OperationState,
        effect: Effect,
        result: Option<OperationResult>,
        evidence: &'d lomi_host_store::DesktopNamespaceAppliedProof,
    ) -> Result<ExternalCompletionWrite<'d, 'o>, Error> {
        self.begin_store_turn(
            operation,
            move |store| {
                match store.complete_remote_namespace(
                    permit,
                    state,
                    effect,
                    result.clone(),
                    evidence,
                ) {
                    // Preparation may have failed before its transaction existed.
                    // Generic completion itself refuses any prepared namespace row.
                    Err(StoreError::NotFound)
                        if state == OperationState::Failed && effect == Effect::None =>
                    {
                        store.complete_external(permit, state, effect, result.clone(), None)
                    }
                    result => result,
                }
            },
            expected_completion,
        )
        .map(ExternalCompletionWrite)
    }

    pub(super) fn native_namespace_prepare(
        &self,
        operation: &Operation<'_>,
        plan: &lomi_host_store::DesktopNamespacePlan,
        physical: &lomi_host_store::DesktopNamespacePhysicalProof,
    ) -> Result<lomi_host_store::DesktopNamespaceIntentRecord, Error> {
        self.native_store(operation, |store| {
            store.prepare_desktop_namespace(plan, physical)
        })
    }

    /// Called only after joining the same no-exec worker that minted the
    /// evidence. Like ordinary completion, Store contention is retryable after
    /// the request expires; no filesystem effect is repeated on this path.
    pub(super) fn native_namespace_complete(
        &self,
        operation_id: lomi_remote_protocol::ipc::NativeIntentId,
        state: lomi_host_store::NativeEditorJobState,
        proof: lomi_host_store::NativeEditorCompletionProof,
        result_json: Option<String>,
        evidence: &lomi_host_store::DesktopNamespaceAppliedProof,
    ) -> Result<(), Error> {
        let mut store = self.try_store()?;
        store
            .complete_native_editor_namespace(operation_id, state, proof, result_json, evidence)
            .map_err(Error::Store)
    }

    pub(super) fn native_namespace_intent(
        &self,
        operation_id: lomi_remote_protocol::ipc::NativeIntentId,
    ) -> Result<Option<lomi_host_store::DesktopNamespaceIntentRecord>, Error> {
        match self.try_store()?.desktop_namespace_intent(operation_id) {
            Ok(record) => Ok(Some(record)),
            Err(StoreError::NotFound) => Ok(None),
            Err(error) => Err(Error::Store(error)),
        }
    }

    pub(super) fn native_namespace_quarantine_joined(
        &self,
        operation_id: lomi_remote_protocol::ipc::NativeIntentId,
    ) -> Result<(), Error> {
        self.try_store()?
            .quarantine_native_editor_namespace_after_join(
                operation_id,
                lomi_host_store::NativeEditorCompletionProof::Joined,
            )
            .map_err(Error::Store)
    }

    pub(super) fn native_namespace_recovery_records(
        &self,
    ) -> Result<Vec<lomi_host_store::DesktopNamespaceIntentRecord>, Error> {
        self.try_store()?
            .desktop_namespace_intents_requiring_recovery()
            .map_err(Error::Store)
    }

    pub(super) fn native_namespace_recover(
        &self,
        evidence: &lomi_host_store::DesktopNamespaceRecoveryEvidence,
    ) -> Result<(), Error> {
        self.try_store()?
            .recover_desktop_namespace_intent(evidence)
            .map_err(Error::Store)
    }

    pub(super) fn remote_namespace_recovery_records(
        &self,
    ) -> Result<Vec<lomi_host_store::RemoteDesktopNamespaceIntentRecord>, Error> {
        self.try_store()?
            .remote_desktop_namespace_intents_requiring_recovery()
            .map_err(Error::Store)
    }

    pub(super) fn remote_namespace_recover(
        &self,
        evidence: &lomi_host_store::RemoteDesktopNamespaceRecoveryEvidence,
    ) -> Result<(), Error> {
        self.try_store()?
            .recover_remote_desktop_namespace_intent(evidence)
            .map_err(Error::Store)
    }

    pub(super) fn native_git_begin(
        &self,
        operation: &Operation<'_>,
        workspace_guard: &lomi_host_store::WorkspaceEffectGuard,
        operation_id: lomi_remote_protocol::ipc::NativeIntentId,
        request_hash: &str,
        connection: lomi_remote_protocol::ipc::IpcNonce,
    ) -> Result<lomi_host_store::NativeGitBegin, Error> {
        self.native_store(operation, |store| {
            store.begin_native_git_job_for_workspace(
                workspace_guard,
                operation_id,
                request_hash,
                connection,
            )
        })
    }

    pub(super) fn native_git_retry(
        &self,
        operation: &Operation<'_>,
        operation_id: lomi_remote_protocol::ipc::NativeIntentId,
        request_hash: &str,
    ) -> Result<Option<lomi_host_store::NativeGitJobRecord>, Error> {
        self.native_store(operation, |store| {
            store.native_git_job_retry(operation_id, request_hash)
        })
    }

    pub(super) fn native_git_prepared(
        &self,
        operation: &Operation<'_>,
        operation_id: lomi_remote_protocol::ipc::NativeIntentId,
        request_hash: &str,
        plan_hash: &str,
        preview_json: &str,
    ) -> Result<lomi_host_store::NativeGitJobRecord, Error> {
        self.native_store(operation, |store| {
            store.record_native_git_prepared(
                operation_id,
                request_hash,
                plan_hash,
                Some(preview_json),
            )
        })
    }

    pub(super) fn native_git_bind_custody(
        &self,
        operation: &Operation<'_>,
        operation_id: lomi_remote_protocol::ipc::NativeIntentId,
        request_hash: &str,
        plan_hash: &str,
        custody_binding_json: &str,
    ) -> Result<String, Error> {
        self.native_store(operation, |store| {
            store.bind_native_git_custody(
                operation_id,
                request_hash,
                plan_hash,
                custody_binding_json,
            )
        })
    }

    pub(super) fn native_git_begin_execution(
        &self,
        operation: &Operation<'_>,
        operation_id: lomi_remote_protocol::ipc::NativeIntentId,
        request_hash: &str,
        plan_hash: &str,
        custody_binding_sha256: &str,
    ) -> Result<lomi_host_store::NativeGitExecution, Error> {
        self.native_store(operation, |store| {
            store.begin_native_git_execution(
                operation_id,
                request_hash,
                plan_hash,
                custody_binding_sha256,
            )
        })
    }

    pub(super) fn native_git_status(
        &self,
        operation: &Operation<'_>,
        operation_id: lomi_remote_protocol::ipc::NativeIntentId,
    ) -> Result<lomi_host_store::NativeGitJobRecord, Error> {
        self.native_store(operation, |store| store.native_git_job(operation_id))
    }

    pub(super) fn native_git_status_recovery(
        &self,
        operation_id: lomi_remote_protocol::ipc::NativeIntentId,
    ) -> Result<lomi_host_store::NativeGitJobRecord, Error> {
        let mut store = self.try_store()?;
        store.native_git_job(operation_id).map_err(Error::Store)
    }

    pub(super) fn native_git_acknowledge(
        &self,
        operation: &Operation<'_>,
        operation_id: lomi_remote_protocol::ipc::NativeIntentId,
    ) -> Result<(), Error> {
        self.native_store(operation, |store| {
            store.acknowledge_native_git_job(operation_id)
        })
    }

    pub(super) fn native_git_fail_not_started(
        &self,
        proof: lomi_host_store::NativeGitNotStartedProof,
        result_json: Option<String>,
    ) -> Result<(), Error> {
        let mut store = self.try_store()?;
        store
            .fail_native_git_not_started(proof, result_json)
            .map_err(Error::Store)
    }

    pub(super) fn native_git_mark_outcome_unknown(
        &self,
        operation_id: lomi_remote_protocol::ipc::NativeIntentId,
    ) -> Result<lomi_host_store::NativeGitJobRecord, Error> {
        let mut store = self.try_store()?;
        store
            .mark_native_git_outcome_unknown(operation_id)
            .map_err(Error::Store)
    }

    pub(super) fn native_git_complete(
        &self,
        proof: lomi_host_store::NativeGitCustodyCompletion,
        state: lomi_host_store::NativeGitJobState,
        result_json: Option<String>,
    ) -> Result<(), Error> {
        let mut store = self.try_store()?;
        store
            .complete_native_git_job(proof, state, result_json)
            .map_err(Error::Store)
    }

    /// Startup recovery query. Returned rows have no terminal completion proof;
    /// callers must verify any custody provider without holding Store locks.
    pub(super) fn native_git_jobs_requiring_custody(
        &self,
    ) -> Result<Vec<lomi_host_store::NativeGitJobRecord>, Error> {
        let mut store = self.try_store()?;
        store
            .native_git_jobs_requiring_custody()
            .map_err(Error::Store)
    }

    pub(super) fn begin_admit_external<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        binding: &'d OperationBinding,
        expected_revision: DecimalU64,
    ) -> Result<ExternalAdmissionWrite<'d, 'o>, Error> {
        self.begin_store_turn(
            operation,
            move |store| store.admit_external(binding, expected_revision),
            expected_admission,
        )
        .map(ExternalAdmissionWrite)
    }
    pub(super) fn begin_start_external<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        binding: &'d OperationBinding,
    ) -> Result<ExternalStartWrite<'d, 'o>, Error> {
        let pending = self
            .domain
            .announce(operation, WriterClass::Shared, Intent::Mutation)
            .map_err(Error::Domain)?;
        Ok(ExternalStartWrite {
            owner: self,
            operation,
            binding,
            pending: Some(pending),
            started: None,
            terminal: None,
            #[cfg(test)]
            fault: None,
            #[cfg(test)]
            starts: 0,
        })
    }
    /// Only persist the observed effect/result. Never run or stop a PTY here.
    /// Callers must use the original operation, and reconcile separately if it
    /// has expired; this API cannot silently grant a fresh completion budget.
    pub(super) fn begin_complete_external<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        permit: &'d ExternalPermit,
        state: OperationState,
        effect: Effect,
        result: Option<OperationResult>,
        projection: Option<WorkspaceState>,
    ) -> Result<ExternalCompletionWrite<'d, 'o>, Error> {
        self.begin_store_turn(
            operation,
            move |store| {
                store.complete_external(permit, state, effect, result.clone(), projection.clone())
            },
            expected_completion,
        )
        .map(ExternalCompletionWrite)
    }
    pub(super) fn begin_cancel_operation<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        actor: ConsumerAuthorizationId,
        workspace: WorkspaceId,
        id: OperationId,
        current: &'d CapabilitySet,
    ) -> Result<CancellationWrite<'d, 'o>, Error> {
        self.begin_store_turn(
            operation,
            move |store| store.cancel_operation(actor, workspace, id, current),
            expected_cancellation,
        )
        .map(CancellationWrite)
    }
    pub(super) fn lookup_operation(
        &self,
        operation: &Operation<'_>,
        actor: ConsumerAuthorizationId,
        workspace: WorkspaceId,
        id: OperationId,
        current: &CapabilitySet,
    ) -> Result<Option<OperationReceipt>, Error> {
        self.read(operation, |store| {
            store.lookup_operation(actor, workspace, id, current)
        })
    }
    pub(super) fn check_external_fence(
        &self,
        operation: &Operation<'_>,
        permit: &ExternalPermit,
    ) -> Result<(), Error> {
        self.read(operation, |store| store.check_external_fence(permit))
    }
    pub(super) fn external_effect_gate<'a>(
        &'a self,
        operation: &Operation<'_>,
        permit: &ExternalPermit,
    ) -> Result<domain::LocalExternalEffectGate<'a>, Error> {
        let gate = self.domain.observe_local_external_effect();
        self.check_external_fence(operation, permit)?;
        if !gate.current() {
            return Err(Error::Domain(domain::Error::Busy));
        }
        Ok(gate)
    }
    pub(super) fn begin_terminal_exit<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        terminal: &'d TerminalContext,
    ) -> Result<TerminalTransitionWrite<'d, 'o>, Error> {
        self.begin_store_turn(
            operation,
            move |store| store.record_terminal_exit(terminal),
            expected_terminal_transition,
        )
        .map(TerminalTransitionWrite)
    }
    /// The terminal service must first reserve retirement and drop its Core/map
    /// locks. This short Store turn may run in its persistence callback only.
    pub(super) fn begin_terminal_retired<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        terminal: &'d TerminalContext,
    ) -> Result<TerminalTransitionWrite<'d, 'o>, Error> {
        self.begin_store_turn(
            operation,
            move |store| store.record_terminal_retired(terminal),
            expected_terminal_transition,
        )
        .map(TerminalTransitionWrite)
    }
}

// Public configuration is a multi-phase local writer. This turn owns one
// announcement for the original Operation; every method releases Domain/Store
// before returning an owned record to the file-only coordinator.
use super::public_configuration::{self as public, PublicAuthFence};
use lomi_host_store::{PublicDocument, PublicPreparation};

impl SharedOwner {
    pub(super) fn local_start_mode(
        &self,
        operation: &Operation<'_>,
    ) -> Result<LocalStartMode, Error> {
        self.read(operation, HostStore::local_start_mode)
    }

    pub(super) fn begin_public_configuration<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        authentication: lomi_remote_protocol::ipc::LocalAuthConfiguration,
    ) -> Result<public::OwnerConfiguration<'d, 'o>, Error> {
        let pending = self
            .domain
            .announce(operation, WriterClass::Shared, Intent::Mutation)
            .map_err(Error::Domain)?;
        Ok(public::OwnerConfiguration::new(
            PublicConfigurationWrite {
                owner: self,
                pending: Some(pending),
            },
            authentication,
        ))
    }
}

// Internal backend, never a compatibility mutex/guard or public callback API.
// The public coordinator exposes only its fixed configure operation.
pub(super) struct PublicConfigurationWrite<'d, 'o> {
    owner: &'d SharedOwner,
    pending: Option<PendingWriter<'d, 'o>>,
}
#[derive(Clone, Copy)]
enum PublicMethod {
    Snapshot,
    Current,
    Prepare,
    Finish,
}
impl PublicMethod {
    fn definite(self, error: &public::Error) -> bool {
        match error {
            public::Error::Conflict => true,
            public::Error::Store(StoreError::Busy) => true,
            public::Error::Store(StoreError::Fenced) => matches!(
                self,
                Self::Snapshot | Self::Current | Self::Prepare | Self::Finish
            ),
            // Only public_prepare's binding/transition rejection is a definite
            // conflict. An unexpected Invalid/Storage is never retried.
            public::Error::Store(StoreError::IdempotencyConflict) => matches!(self, Self::Prepare),
            _ => false,
        }
    }
}
impl PublicConfigurationWrite<'_, '_> {
    pub(super) fn check_operation(&mut self) -> Result<(), public::Error> {
        self.pending
            .as_mut()
            .ok_or(public::Error::Owner(Error::Domain(domain::Error::Stale)))?
            .check_operation()
            .map_err(|error| public::Error::Owner(Error::Domain(error)))
    }
    // Private helper used exclusively by the concrete methods below.
    fn phase<T>(
        &mut self,
        method: PublicMethod,
        action: impl FnOnce(&mut HostStore) -> Result<T, public::Error>,
    ) -> Result<T, public::Error> {
        let pending = self
            .pending
            .as_mut()
            .ok_or(public::Error::Owner(Error::Domain(domain::Error::Stale)))?;
        let mut guard = pending
            .try_enter()
            .map_err(|e| public::Error::Owner(Error::Domain(e)))?;
        let mut store = self.owner.try_store().map_err(public::Error::Owner)?;
        guard
            .commit_classified(|| {
                let result = action(&mut store);
                if let Err(error) = &result
                    && !method.definite(error)
                {
                    store.public_block();
                    return Err(StoreFailure::Uncertain(match error {
                        public::Error::Store(e) => public::Error::Owner(Error::UncertainStore(*e)),
                        public::Error::Owner(Error::UncertainStore(e)) => {
                            public::Error::Owner(Error::UncertainStore(*e))
                        }
                        _ => public::Error::Storage,
                    }));
                }
                // A post-state read failure is uncertain even if the transaction
                // initially reported Busy or a definite binding conflict.
                let view = StoreView::read(&store).map_err(|e| {
                    store.public_block();
                    StoreFailure::Uncertain(public::Error::Owner(Error::UncertainStore(e)))
                })?;
                match result {
                    Ok(value) => Ok((value, view)),
                    Err(public::Error::Store(StoreError::Busy)) => Err(StoreFailure::Expected(
                        public::Error::Owner(Error::Store(StoreError::Busy)),
                        view,
                    )),
                    Err(error) => Err(StoreFailure::Expected(error, view)),
                }
            })
            .map_err(|error| match error {
                StepError::Domain(error) => public::Error::Owner(Error::Domain(error)),
                StepError::Source(error) => error,
            })
    }
    pub(super) fn snapshot(&mut self) -> Result<(PublicDocument, PublicAuthFence), public::Error> {
        self.phase(PublicMethod::Snapshot, |store| {
            Ok((store.public_current()?, PublicAuthFence::read(store)?))
        })
    }
    pub(super) fn current(
        &mut self,
        current: &PublicDocument,
        scope: PublicAuthFence,
    ) -> Result<(), public::Error> {
        self.phase(PublicMethod::Current, |store| {
            if PublicAuthFence::read(store)? != scope || store.public_current()? != *current {
                store.public_block();
                return Err(public::Error::Conflict);
            }
            Ok(())
        })
    }
    pub(super) fn prepare(
        &mut self,
        current: &PublicDocument,
        scope: PublicAuthFence,
        desired: &PublicDocument,
    ) -> Result<(PublicPreparation, PublicAuthFence), public::Error> {
        self.phase(PublicMethod::Prepare, |store| {
            if PublicAuthFence::read(store)? != scope || store.public_current()? != *current {
                store.public_block();
                return Err(public::Error::Conflict);
            }
            let intent = match store.public_prepare(Some(current), desired) {
                Ok(intent) => intent,
                Err(StoreError::Busy) => {
                    // Busy may originate at commit, after readiness was cleared.
                    // Retry only if the exact old ready state is still provable.
                    if store.public_current().ok().as_ref() == Some(current)
                        && PublicAuthFence::read(store).ok() == Some(scope)
                    {
                        return Err(public::Error::Store(StoreError::Busy));
                    }
                    return Err(public::Error::Owner(Error::UncertainStore(
                        StoreError::Busy,
                    )));
                }
                Err(error) => return Err(public::Error::Store(error)),
            };
            // If this post-commit read fails (even Busy), do not retry prepare.
            // Preserve the durable intent for explicit exclusive recovery.
            let scope = PublicAuthFence::read(store).map_err(|e| match e {
                public::Error::Store(e) => public::Error::Owner(Error::UncertainStore(e)),
                _ => public::Error::Storage,
            })?;
            Ok((intent, scope))
        })
    }
    pub(super) fn finish(
        &mut self,
        intent: &PublicPreparation,
        scope: PublicAuthFence,
        published: &PublicDocument,
    ) -> Result<(), public::Error> {
        self.phase(PublicMethod::Finish, |store| {
            let state = store
                .public_configuration_state()?
                .ok_or(public::Error::Conflict)?;
            if PublicAuthFence::read(store)? != scope
                || state.current.as_ref() != intent.expected.as_ref()
                || state.prepared.as_ref() != Some(intent)
            {
                store.public_block();
                return Err(public::Error::Conflict);
            }
            match store.public_finish(intent.operation_id, published) {
                Ok(()) => Ok(()),
                Err(StoreError::Busy) => {
                    // public_finish clears volatile readiness before its tx.
                    // Only an exact durable old intent and auth fence establish
                    // that this Busy did not commit; otherwise recovery is explicit.
                    match (
                        store.public_configuration_state(),
                        PublicAuthFence::read(store),
                    ) {
                        (Ok(Some(state)), Ok(actual))
                            if actual == scope
                                && state.current.as_ref() == intent.expected.as_ref()
                                && state.prepared.as_ref() == Some(intent) =>
                        {
                            Err(public::Error::Store(StoreError::Busy))
                        }
                        _ => Err(public::Error::Owner(Error::UncertainStore(
                            StoreError::Busy,
                        ))),
                    }
                }
                Err(error) => Err(public::Error::Store(error)),
            }
        })
    }
    pub(super) fn block(&mut self) {
        // Failure-only cleanup must still attenuate after the original request
        // expired/cancelled. This never prepares, publishes, finishes or retries.
        let _ = self
            .owner
            .domain
            .try_block_public_configuration(&self.owner.store);
    }
    #[cfg(test)]
    pub(super) fn public_state_for_test(
        &self,
    ) -> (Option<lomi_host_store::PublicConfigurationState>, bool) {
        let store = self.owner.store.try_lock().unwrap();
        (
            store.public_configuration_state().unwrap(),
            store.public_configuration_ready().unwrap(),
        )
    }
    pub(super) fn complete(&mut self) -> Result<(), Error> {
        self.pending
            .take()
            .ok_or(Error::Domain(domain::Error::Stale))?
            .finish()
            .map_err(Error::Domain)
    }
    pub(super) fn abandon(&mut self) {
        // Drop fail-closes Domain even if the nonblocking Store cleanup was Busy.
        self.pending.take();
    }
}

// BEGIN PASSIVE CLOUD OWNER PRIMITIVES (inactive; compose this block only)
#[cfg(test)]
use lomi_host_store::Publication;
use lomi_host_store::{
    CloudRuntimeScope, CloudRuntimeState, HostAcknowledgedPublication, HostPublicationIntent,
};
use lomi_remote_protocol::HostId;
#[cfg(test)]
use lomi_remote_protocol::RuntimeId;

/// Owned local evidence only, never an HTTP admission, canonical origin proof,
/// current worker gate, lease, heartbeat, response proof or Domain Ready proof.
#[derive(Debug, Clone)]
#[cfg(test)]
pub(super) struct CloudScopeSnapshot {
    pub(super) authorization: AuthorizationState,
    pub(super) verified_generation: Option<u64>,
    pub(super) configuration: Option<LocalAuthConfiguration>,
    pub(super) scope: CloudRuntimeScope,
}
/// A coherent local join, not authority to adopt/install/ACK a runtime after GET.
#[derive(Debug, Clone)]
#[cfg(test)]
pub(super) struct CloudReconciliationSnapshot {
    pub(super) scope: CloudRuntimeScope,
    pub(super) configuration: Option<LocalAuthConfiguration>,
    pub(super) previous: Option<CloudRuntimeState>,
    pub(super) pending: Option<HostPublicationIntent>,
}
/// Historical membership and current outbox evidence, never PeerEligibility.
#[derive(Debug, Clone)]
#[cfg(test)]
pub(super) struct CloudOnlineSnapshot {
    pub(super) scope: CloudRuntimeScope,
    pub(super) binding: CloudRuntimeState,
    pub(super) acknowledged: Option<HostAcknowledgedPublication>,
    pub(super) pending: Option<HostPublicationIntent>,
    pub(super) outbox: Vec<Publication>,
}
/// Logout recovery evidence, deliberately separate from normal remote admission.
#[derive(Debug, Clone)]
#[cfg(test)]
pub(super) struct CloudLogoutSnapshot {
    pub(super) authorization: AuthorizationState,
    pub(super) configuration: Option<LocalAuthConfiguration>,
    pub(super) host_id: HostId,
    pub(super) owner_runtime_id: RuntimeId,
}

#[cfg(test)]
impl SharedOwner {
    pub(super) fn cloud_scope_snapshot(
        &self,
        operation: &Operation<'_>,
        generation: u64,
        origin: String,
    ) -> Result<CloudScopeSnapshot, Error> {
        self.read(operation, |store| {
            Ok(CloudScopeSnapshot {
                authorization: store.authorization_state()?,
                verified_generation: store.verified_authorization_generation()?,
                configuration: store.auth_configuration()?,
                scope: store.cloud_runtime_scope(generation, origin)?,
            })
        })
    }
    pub(super) fn cloud_reconciliation_snapshot(
        &self,
        operation: &Operation<'_>,
        scope: &CloudRuntimeScope,
    ) -> Result<CloudReconciliationSnapshot, Error> {
        self.read(operation, |store| {
            Ok(CloudReconciliationSnapshot {
                scope: scope.clone(),
                configuration: store.auth_configuration()?,
                previous: store.cloud_runtime_reconciliation_state(scope)?,
                pending: store.pending_host_publication()?,
            })
        })
    }
    pub(super) fn cloud_online_snapshot(
        &self,
        operation: &Operation<'_>,
        scope: &CloudRuntimeScope,
    ) -> Result<CloudOnlineSnapshot, Error> {
        self.read(operation, |store| {
            let binding = store
                .cloud_runtime_state(scope)?
                .ok_or(StoreError::Fenced)?;
            Ok(CloudOnlineSnapshot {
                scope: scope.clone(),
                acknowledged: store.acknowledged_host_publication(&binding)?,
                binding,
                pending: store.pending_host_publication()?,
                outbox: store.pending_publications()?,
            })
        })
    }
    pub(super) fn cloud_logout_snapshot(
        &self,
        operation: &Operation<'_>,
    ) -> Result<CloudLogoutSnapshot, Error> {
        self.read(operation, |store| {
            Ok(CloudLogoutSnapshot {
                authorization: store.authorization_state()?,
                configuration: store.auth_configuration()?,
                host_id: store.identity().host_id,
                owner_runtime_id: store.runtime_id(),
            })
        })
    }
    // Owned arguments remain exact across Busy. This is only an independent
    // primitive: it does NOT revalidate config/worker gates/provider provenance.
    pub(super) fn begin_invalidate_cloud_runtime<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        scope: CloudRuntimeScope,
        previous: CloudRuntimeState,
        pending_intent: Option<HostPublicationIntent>,
    ) -> Result<CloudInvalidationWrite<'d, 'o>, Error> {
        let pending = self
            .domain
            .announce(operation, WriterClass::Remote, Intent::Mutation)
            .map_err(Error::Domain)?;
        Ok(CloudInvalidationWrite(CloudPublicationTurn {
            owner: self,
            pending: Some(pending),
            expected: expected_cloud_invalidation,
            action: Box::new(move |store| {
                store.invalidate_cloud_runtime(&scope, &previous, pending_intent.as_ref())
            }),
        }))
    }
    pub(super) fn begin_prepare_host_publication<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        binding: CloudRuntimeState,
    ) -> Result<HostPublicationPrepareWrite<'d, 'o>, Error> {
        let pending = self
            .domain
            .announce(operation, WriterClass::Remote, Intent::Mutation)
            .map_err(Error::Domain)?;
        Ok(HostPublicationPrepareWrite(CloudPublicationTurn {
            owner: self,
            pending: Some(pending),
            expected: expected_cloud_preparation,
            action: Box::new(move |store| store.prepare_host_publication(&binding)),
        }))
    }
}

#[cfg(test)]
fn expected_cloud_invalidation(error: StoreError) -> bool {
    matches!(
        error,
        StoreError::Busy | StoreError::Fenced | StoreError::RevisionConflict
    )
}
#[cfg(test)]
fn expected_cloud_preparation(error: StoreError) -> bool {
    matches!(
        error,
        StoreError::Busy
            | StoreError::Fenced
            | StoreError::RevisionConflict
            | StoreError::ResourceExhausted
    )
}
// Invalid is deliberately absent: input shape and internal validation failures
// share that error in Store. No sound caller-only Invalid classification exists.
fn classify_cloud_outcome<T>(
    result: Result<T, StoreError>,
    postview: Result<StoreView, StoreError>,
    expected: fn(StoreError) -> bool,
) -> Result<(T, StoreView), StoreFailure<Error>> {
    let view = match postview {
        Ok(view) => view,
        Err(view_error) => {
            // The post-view failure is terminal, including Busy. If the action
            // also failed, preserve its ORIGINAL error instead of masking it.
            // No second view read or publication retry is attempted.
            return Err(StoreFailure::Uncertain(Error::UncertainStore(
                result.err().unwrap_or(view_error),
            )));
        }
    };
    match result {
        Ok(value) => Ok((value, view)),
        Err(error) if expected(error) => Err(StoreFailure::Expected(Error::Store(error), view)),
        Err(error) => Err(StoreFailure::UncertainObserved(
            Error::UncertainStore(error),
            view,
        )),
    }
}
// Separate from the unchanged generic StoreTurn: cloud methods always read the
// actual post-error view, even for unexpected failures which might have sealed
// authorization while validating the transaction guard.
#[cfg(test)]
struct CloudPublicationTurn<'d, 'o, T> {
    owner: &'d SharedOwner,
    pending: Option<PendingWriter<'d, 'o>>,
    action: StoreAction<'d, T>,
    expected: fn(StoreError) -> bool,
}
#[cfg(test)]
impl<T> CloudPublicationTurn<'_, '_, T> {
    fn try_commit(&mut self) -> Result<T, Error> {
        let result = self.try_phase();
        if matches!(
            result,
            Err(Error::Domain(domain::Error::Busy)) | Err(Error::Store(StoreError::Busy))
        ) {
            return result;
        }
        match (self.pending.take(), result) {
            (Some(pending), Ok(value)) => {
                pending.finish().map_err(Error::Domain)?;
                Ok(value)
            }
            (Some(pending), Err(error)) => {
                let _ = pending.finish();
                Err(error)
            }
            (None, result) => result,
        }
    }
    fn try_phase(&mut self) -> Result<T, Error> {
        let pending = self
            .pending
            .as_mut()
            .ok_or(Error::Domain(domain::Error::Stale))?;
        let mut guard = pending.try_enter().map_err(Error::Domain)?;
        let mut store = self.owner.try_store()?;
        let action = &mut self.action;
        let expected = self.expected;
        guard
            .commit_classified(|| {
                let result = action(&mut store);
                let postview = StoreView::read(&store);
                classify_cloud_outcome(result, postview, expected)
            })
            .map_err(|error| match error {
                StepError::Domain(error) => Error::Domain(error),
                StepError::Source(error) => error,
            })
    }
}
#[must_use]
#[cfg(test)]
pub(super) struct CloudInvalidationWrite<'d, 'o>(CloudPublicationTurn<'d, 'o, ()>);
#[cfg(test)]
impl CloudInvalidationWrite<'_, '_> {
    pub(super) fn try_commit(&mut self) -> Result<(), Error> {
        self.0.try_commit()
    }
}
#[must_use]
#[cfg(test)]
pub(super) struct HostPublicationPrepareWrite<'d, 'o>(
    CloudPublicationTurn<'d, 'o, HostPublicationIntent>,
);
#[cfg(test)]
impl HostPublicationPrepareWrite<'_, '_> {
    pub(super) fn try_commit(&mut self) -> Result<HostPublicationIntent, Error> {
        self.0.try_commit()
    }
}
// END PASSIVE CLOUD OWNER PRIMITIVES

// BEGIN ORIGINAL OPERATION CONFIGURED HTTP BINDING
// A borrowed view only: no replacement Operation, deadline, latch or authority.
// HTTP's scoped watcher invokes only this SAME sticky Operation::check().
struct OriginalOperationHttpBudget<'o, 'c> {
    operation: &'o Operation<'c>,
}
impl OriginalOperationHttpBudget<'_, '_> {
    fn deadline(&self) -> std::time::Instant {
        self.operation.deadline()
    }
    fn check(&self) -> Result<(), lomi_host_http::BudgetStop> {
        self.operation.check().map_err(|error| match error {
            domain::Error::Deadline => lomi_host_http::BudgetStop::Deadline,
            domain::Error::Cancelled => lomi_host_http::BudgetStop::Cancelled,
            // Operation::check currently returns only these two errors. A future
            // additional terminal outcome must never reopen HTTP admission.
            _ => lomi_host_http::BudgetStop::Cancelled,
        })
    }
}
fn configured_worker_ready_send(
    transport: &lomi_host_http::Transport,
    request: &WorkerReadyRequest,
    operation: &Operation<'_>,
) -> Result<WorkerReadyResponse, lomi_host_http::Error> {
    let budget = OriginalOperationHttpBudget { operation };
    let check = || budget.check();
    let transport = transport.with_budget(budget.deadline(), &check);
    match request {
        WorkerReadyRequest::Register(access, request) => transport
            .register(request, access)
            .map(WorkerReadyResponse::Register),
        WorkerReadyRequest::Rotate(request) => {
            transport.refresh(request).map(WorkerReadyResponse::Rotate)
        }
    }
}
fn configured_cloud_get_send(
    transport: &lomi_host_http::DataTransport,
    request: &CloudGetRequest,
    operation: &Operation<'_>,
) -> Result<lomi_remote_protocol::HostRuntimeGetResult, lomi_host_http::Error> {
    let budget = OriginalOperationHttpBudget { operation };
    let check = || budget.check();
    transport
        .with_budget(budget.deadline(), &check)
        .runtime_get(request.host, &request.access)
}
// END ORIGINAL OPERATION CONFIGURED HTTP BINDING

// BEGIN INACTIVE SOLE-WORKER READY HANDOFF
// No production worker invokes this factory/turn. Future activation replaces
// its existing Transport construction and retains its already-held PublicSetup
// read guard; it NEVER opens/reloads/replaces a provider or HostAuth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WorkerReadyError {
    Domain(domain::Error),
    Store(StoreError),
    Provider(lomi_host_auth::Error),
    Http(lomi_host_http::Error),
    Stale,
}
impl From<Error> for WorkerReadyError {
    fn from(error: Error) -> Self {
        match error {
            Error::Domain(error) => Self::Domain(error),
            Error::Store(error) | Error::UncertainStore(error) => Self::Store(error),
        }
    }
}
impl From<StepError<StoreError>> for WorkerReadyError {
    fn from(error: StepError<StoreError>) -> Self {
        match error {
            StepError::Domain(error) => Self::Domain(error),
            StepError::Source(error) => Self::Store(error),
        }
    }
}
impl From<StoreError> for WorkerReadyError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum WorkerReadyPhase {
    Prepare,
    Send,
    Clock,
    Accept,
    Publish,
    Published,
    Terminal,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum WorkerReadyCompletion {
    Login(LoginIntent),
    Resume(u64),
}
struct WorkerReadyCapture {
    identity: Identity,
    selected: LocalAuthConfiguration,
    public_state: lomi_host_store::PublicConfigurationState,
    public: PublicDocument,
    public_ready: bool,
    authorization: AuthorizationState,
    verified: Option<u64>,
    completion: WorkerReadyCompletion,
}
enum WorkerReadyRequest {
    Register(
        lomi_remote_protocol::HostAccessCredential,
        lomi_remote_protocol::HostRegisterParams,
    ),
    Rotate(lomi_remote_protocol::HostAuthorizationRefreshParams),
}
enum WorkerReadyResponse {
    Register(lomi_remote_protocol::HostRegisterResult),
    Rotate(lomi_remote_protocol::HostAuthorizationResult),
}
enum WorkerReadyHttp {
    Configured(lomi_host_http::Transport),
    #[cfg(test)]
    Scripted(WorkerReadyScript),
}
pub(super) struct ConfiguredWorkerAttempt<
    'w,
    'p,
    'i,
    S: lomi_platform::secrets::SecretStorage + ?Sized,
> {
    auth: &'w mut lomi_host_auth::HostAuth<'p, S>,
    trusted: lomi_host_auth::Config,
    http: WorkerReadyHttp,
    #[cfg(test)]
    auth_api: Option<&'w dyn super::auth::AuthTransport>,
    // Borrow the PublicSetup-local capability for the entire attempt and turn.
    // Its private constructor binds the exact setup to the actual read lease.
    _public_io: &'i super::public_configuration::WorkerPublicIo<'i>,
    setup: &'i super::public_configuration::PublicSetup,
    gate: &'i std::sync::atomic::AtomicBool,
    paused: &'i std::sync::atomic::AtomicBool,
    base: u64,
    anchor: std::time::Instant,
    #[cfg(test)]
    projected_for_test: Option<u64>,
    #[cfg(test)]
    after_final_store_time_for_test: Option<u64>,
}
impl<'w, 'p, 'i, S: lomi_platform::secrets::SecretStorage + ?Sized>
    ConfiguredWorkerAttempt<'w, 'p, 'i, S>
{
    /// Outside Domain/Store, under the sole worker's existing IO exclusion.
    /// No independently supplied Config/Transport, and no provider construction.
    pub(super) fn from_existing_worker(
        auth: &'w mut lomi_host_auth::HostAuth<'p, S>,
        public_io: &'i super::public_configuration::WorkerPublicIo<'i>,
        gate: &'i std::sync::atomic::AtomicBool,
        paused: &'i std::sync::atomic::AtomicBool,
        base: u64,
        anchor: std::time::Instant,
    ) -> Result<Self, WorkerReadyError> {
        let setup = public_io.setup();
        if paused.load(std::sync::atomic::Ordering::Acquire)
            || setup.pending.load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(WorkerReadyError::Stale);
        }
        let trusted = auth.trusted_configuration().clone();
        let transport = lomi_host_http::Transport::new(&trusted).map_err(WorkerReadyError::Http)?;
        if paused.load(std::sync::atomic::Ordering::Acquire)
            || setup.pending.load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(WorkerReadyError::Stale);
        }
        Ok(Self {
            auth,
            trusted,
            http: WorkerReadyHttp::Configured(transport),
            #[cfg(test)]
            auth_api: None,
            _public_io: public_io,
            setup,
            gate,
            paused,
            base,
            anchor,
            #[cfg(test)]
            projected_for_test: None,
            #[cfg(test)]
            after_final_store_time_for_test: None,
        })
    }
    fn projected_time(&self) -> Result<u64, WorkerReadyError> {
        #[cfg(test)]
        if let Some(now) = self.projected_for_test {
            return Ok(now);
        }
        self.base
            .checked_add(self.anchor.elapsed().as_secs())
            .ok_or(WorkerReadyError::Domain(domain::Error::Exhausted))
    }
    /// Original Operation is admitted once externally, never reconstructed here.
    pub(super) fn begin_ready<'t, 'd, 'o>(
        &'t mut self,
        owner: &'d SharedOwner,
        operation: &'o Operation<'o>,
    ) -> Result<SoleWorkerReadyTurn<'t, 'd, 'o, 'w, 'p, 'i, S>, WorkerReadyError> {
        self.gate.store(true, std::sync::atomic::Ordering::Release);
        let writer = owner
            .domain
            .announce_worker_verification(operation)
            .map_err(WorkerReadyError::Domain)?;
        Ok(SoleWorkerReadyTurn {
            attempt: self,
            owner,
            operation,
            writer: Some(writer),
            scope: None,
            capture: None,
            request: None,
            response: None,
            deadlines: None,
            phase: WorkerReadyPhase::Prepare,
            terminal: None,
            clock_floor: None,
            provider_accept_started: false,
            cancel_noticed: false,
        })
    }
}
/// Linear private state: response and provider acceptance survive mutex Busy.
/// No Store/Domain guard, callback proof, bool proof, or Ready capability escapes.
pub(super) struct SoleWorkerReadyTurn<
    't,
    'd,
    'o,
    'w,
    'p,
    'i,
    S: lomi_platform::secrets::SecretStorage + ?Sized,
> {
    attempt: &'t mut ConfiguredWorkerAttempt<'w, 'p, 'i, S>,
    owner: &'d SharedOwner,
    operation: &'o Operation<'o>,
    writer: Option<PendingWriter<'d, 'o>>,
    scope: Option<super::owner_domain::VerificationScope<'d, 'o>>,
    capture: Option<WorkerReadyCapture>,
    request: Option<WorkerReadyRequest>,
    response: Option<WorkerReadyResponse>,
    deadlines: Option<lomi_host_auth::CredentialDeadlines>,
    phase: WorkerReadyPhase,
    terminal: Option<WorkerReadyError>,
    clock_floor: Option<u64>,
    provider_accept_started: bool,
    cancel_noticed: bool,
}
impl<S: lomi_platform::secrets::SecretStorage + ?Sized>
    SoleWorkerReadyTurn<'_, '_, '_, '_, '_, '_, S>
{
    #[cfg(all(unix, test, feature = "cloud-fixture"))]
    pub(super) fn diagnostic_stage(&self) -> super::auth::AuthReadyStage {
        match self.phase {
            WorkerReadyPhase::Prepare => super::auth::AuthReadyStage::Prepare,
            WorkerReadyPhase::Send => super::auth::AuthReadyStage::Send,
            WorkerReadyPhase::Clock => super::auth::AuthReadyStage::Clock,
            WorkerReadyPhase::Accept => super::auth::AuthReadyStage::Accept,
            WorkerReadyPhase::Publish => super::auth::AuthReadyStage::Publish,
            WorkerReadyPhase::Published => super::auth::AuthReadyStage::Done,
            WorkerReadyPhase::Terminal => super::auth::AuthReadyStage::Abort,
        }
    }
    /// Attenuation only. The actual wrapper uses this when its runtime aborts,
    /// then drives this SAME turn through typed cleanup instead of dropping it.
    /// No operation/deadline/scope/provider/response is admitted or renewed.
    pub(super) fn notice_cancel(&mut self) {
        self.cancel_noticed = true;
        self.attempt
            .gate
            .store(true, std::sync::atomic::Ordering::Release);
    }
    /// Read-only cleanup diagnostic, never an admission or retry capability.
    /// Ordinary mutex Busy has no terminal error and therefore returns None.
    pub(super) fn pending_abort_error(&self) -> Option<WorkerReadyError> {
        if self.writer.is_some() && !self.provider_accept_started {
            self.terminal
        } else {
            None
        }
    }
    fn check_boundary(&mut self) -> Result<(), WorkerReadyError> {
        if self.cancel_noticed {
            return Err(WorkerReadyError::Domain(domain::Error::Cancelled));
        }
        let writer = self.writer.as_mut().ok_or(WorkerReadyError::Stale)?;
        if self.provider_accept_started {
            writer.check_operation()
        } else {
            writer.check_worker_verification_operation()
        }
        .map_err(WorkerReadyError::Domain)?;
        if self
            .attempt
            .paused
            .load(std::sync::atomic::Ordering::Acquire)
            || self
                .attempt
                .setup
                .pending
                .load(std::sync::atomic::Ordering::Acquire)
            || !self.attempt.gate.load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(WorkerReadyError::Stale);
        }
        Ok(())
    }
    /// Return true only to report completion, never as a proof constructor.
    /// Exactly one stage runs per call. Domain mutex/Store mutex Busy retain the
    /// SAME stage, response, scope, original ticket and Operation. SQL Busy is
    /// Store(Busy), hence terminal; it never takes this retry branch.
    pub(super) fn try_step(&mut self) -> Result<bool, WorkerReadyError> {
        if let Some(error) = self.terminal {
            return self.finish_terminal(error);
        }
        if self.phase == WorkerReadyPhase::Published {
            return Err(WorkerReadyError::Stale);
        }
        let result = self.check_boundary().and_then(|()| self.step());
        match result {
            Err(WorkerReadyError::Domain(domain::Error::Busy)) => {
                Err(WorkerReadyError::Domain(domain::Error::Busy))
            }
            Err(error) => {
                self.attempt
                    .gate
                    .store(true, std::sync::atomic::Ordering::Release);
                self.terminal = Some(error);
                self.phase = WorkerReadyPhase::Terminal;
                self.finish_terminal(error)
            }
            Ok(complete) => Ok(complete),
        }
    }
    fn finish_terminal(&mut self, error: WorkerReadyError) -> Result<bool, WorkerReadyError> {
        let retryable = !self.provider_accept_started
            && matches!(
                error,
                WorkerReadyError::Stale
                    | WorkerReadyError::Domain(
                        domain::Error::Stale | domain::Error::Cancelled | domain::Error::Deadline
                    )
                    | WorkerReadyError::Http(
                        lomi_host_http::Error::Network
                            | lomi_host_http::Error::Timeout
                            | lomi_host_http::Error::Cancelled
                            | lomi_host_http::Error::ResolverUnavailable
                    )
            );
        if retryable
            && let Some(writer) = self.writer.as_mut()
            && let Err(domain::Error::Busy) = writer.try_abandon_worker_verification()
        {
            return Err(WorkerReadyError::Domain(domain::Error::Busy));
        }
        // No reset of failed_remote: unrelated uncertainty is never recoverable.
        // Any unaccepted provider/Store error or accepted response retains the
        // original conservative Drop fence. Only a successful abort disarms it.
        drop(self.writer.take());
        self.scope = None;
        self.response = None;
        Err(error)
    }
    fn step(&mut self) -> Result<bool, WorkerReadyError> {
        match self.phase {
            WorkerReadyPhase::Prepare => self.prepare(),
            WorkerReadyPhase::Send => self.send_once(),
            WorkerReadyPhase::Clock => self.checkpoint_clock(),
            WorkerReadyPhase::Accept => self.accept_once(),
            WorkerReadyPhase::Publish => self.publish(),
            WorkerReadyPhase::Published | WorkerReadyPhase::Terminal => {
                Err(WorkerReadyError::Stale)
            }
        }
    }
    /// Pure reads/validation only: auth::configuration contains keychain FS
    /// checks and MUST NOT be called here while Domain/Store are held.
    fn capture(
        store: &HostStore,
        trusted: &lomi_host_auth::Config,
    ) -> Result<WorkerReadyCapture, WorkerReadyError> {
        let identity = store.identity().clone();
        let selected = store.auth_configuration()?.ok_or(WorkerReadyError::Stale)?;
        selected.validate().map_err(|_| WorkerReadyError::Stale)?;
        let actual = lomi_host_auth::Config::new(
            identity.host_id,
            identity.profile_id,
            selected.origin.as_str().to_owned(),
            selected
                .client_id
                .as_str()
                .to_owned()
                .try_into()
                .map_err(|_| WorkerReadyError::Stale)?,
        )
        .map_err(WorkerReadyError::Provider)?;
        if &actual != trusted {
            return Err(WorkerReadyError::Stale);
        }
        if let Some(origin) = &selected.remote_api_origin {
            lomi_host_http::RemoteApiOrigin::new(&actual, origin.as_str().to_owned())
                .map_err(WorkerReadyError::Http)?;
        }
        let public_ready = store.public_configuration_ready()?;
        let public_state = store
            .public_configuration_state()?
            .ok_or(WorkerReadyError::Stale)?;
        let public = store.public_current()?;
        if !public_ready
            || public_state.prepared.is_some()
            || public_state.current.as_ref() != Some(&public)
            || public.configuration()?.authentication.as_ref() != Some(&selected)
        {
            return Err(WorkerReadyError::Stale);
        }
        let authorization = store.authorization_state()?;
        let verified = store.verified_authorization_generation()?;
        if authorization.pending_cloud_revoke {
            return Err(WorkerReadyError::Stale);
        }
        let completion = match store.login_intent()? {
            Some(intent) if intent.generation == authorization.generation => {
                WorkerReadyCompletion::Login(intent)
            }
            None if verified == Some(authorization.generation) => {
                WorkerReadyCompletion::Resume(authorization.generation)
            }
            _ => return Err(WorkerReadyError::Stale),
        };
        Ok(WorkerReadyCapture {
            identity,
            selected,
            public_state,
            public,
            public_ready,
            authorization,
            verified,
            completion,
        })
    }
    fn same_capture(a: &WorkerReadyCapture, b: &WorkerReadyCapture) -> bool {
        a.identity == b.identity
            && a.selected == b.selected
            && a.public_state == b.public_state
            && a.public == b.public
            && a.public_ready == b.public_ready
            && a.authorization.generation == b.authorization.generation
            && a.authorization.locked == b.authorization.locked
            && a.authorization.pending_cloud_revoke == b.authorization.pending_cloud_revoke
            && a.verified == b.verified
            && a.completion == b.completion
        // clock_floor is intentionally monotonic, not frozen across checkpoints.
    }
    fn prepare(&mut self) -> Result<bool, WorkerReadyError> {
        let now = self.attempt.projected_time()?;
        let capture;
        {
            let mut guard = self
                .writer
                .as_mut()
                .ok_or(WorkerReadyError::Stale)?
                .try_enter_worker_verification()
                .map_err(WorkerReadyError::Domain)?;
            let store = self.owner.try_store().map_err(WorkerReadyError::from)?;
            capture = Self::capture(&store, &self.attempt.trusted)?;
            if now < capture.authorization.clock_floor {
                return Err(WorkerReadyError::Provider(
                    lomi_host_auth::Error::ClockRollback,
                ));
            }
            // The ONLY scope capture in this handoff, before provider/HTTP IO.
            self.scope = Some(
                guard
                    .prepare_worker_verification(capture.authorization.generation, &store)
                    .map_err(WorkerReadyError::from)?,
            );
        }
        self.check_boundary()?;
        let request = match self.attempt.auth.status() {
            lomi_host_auth::Status::Unconfirmed
                if matches!(capture.completion, WorkerReadyCompletion::Login(_)) =>
            {
                let (access, request) = self
                    .attempt
                    .auth
                    .registration_request(now)
                    .map_err(WorkerReadyError::Provider)?;
                WorkerReadyRequest::Register(access, request)
            }
            lomi_host_auth::Status::Ready => {
                // Cached Ready is never accepted as proof. Persist a fresh
                // rotation intent outside both locks and send its exact request.
                self.attempt
                    .auth
                    .prepare_rotation(now)
                    .map_err(WorkerReadyError::Provider)?;
                WorkerReadyRequest::Rotate(
                    self.attempt
                        .auth
                        .rotation_request(now)
                        .map_err(WorkerReadyError::Provider)?,
                )
            }
            lomi_host_auth::Status::Rotating => WorkerReadyRequest::Rotate(
                self.attempt
                    .auth
                    .rotation_request(now)
                    .map_err(WorkerReadyError::Provider)?,
            ),
            _ => return Err(WorkerReadyError::Stale),
        };
        self.check_boundary()?;
        self.capture = Some(capture);
        self.request = Some(request);
        self.phase = WorkerReadyPhase::Send;
        Ok(false)
    }
    fn send_once(&mut self) -> Result<bool, WorkerReadyError> {
        self.check_boundary()?;
        let request = self.request.as_ref().ok_or(WorkerReadyError::Stale)?;
        #[cfg(test)]
        let response = if let Some(api) = self.attempt.auth_api {
            self.operation.check().map_err(WorkerReadyError::Domain)?;
            match request {
                WorkerReadyRequest::Register(access, request) => api
                    .register(request, access)
                    .map(WorkerReadyResponse::Register),
                WorkerReadyRequest::Rotate(request) => {
                    api.refresh(request).map(WorkerReadyResponse::Rotate)
                }
            }
            .map_err(WorkerReadyError::Http)?
        } else {
            match &mut self.attempt.http {
                WorkerReadyHttp::Configured(transport) => {
                    configured_worker_ready_send(transport, request, self.operation)
                        .map_err(WorkerReadyError::Http)
                }
                #[cfg(test)]
                WorkerReadyHttp::Scripted(script) => {
                    script.send(request, self.owner, self.operation)
                }
            }?
        };
        #[cfg(not(test))]
        let response = match &mut self.attempt.http {
            WorkerReadyHttp::Configured(transport) => {
                configured_worker_ready_send(transport, request, self.operation)
                    .map_err(WorkerReadyError::Http)
            }
            #[cfg(test)]
            WorkerReadyHttp::Scripted(script) => script.send(request, self.owner, self.operation),
        }?;
        // Never resend after this point, even if the next mutex acquisition Busy.
        self.response = Some(response);
        self.phase = WorkerReadyPhase::Clock;
        self.check_boundary()?;
        Ok(false)
    }
    fn checkpoint_clock(&mut self) -> Result<bool, WorkerReadyError> {
        let now = self.attempt.projected_time()?;
        let mut guard = self
            .writer
            .as_mut()
            .ok_or(WorkerReadyError::Stale)?
            .try_enter_worker_verification()
            .map_err(WorkerReadyError::Domain)?;
        let mut store = self.owner.try_store().map_err(WorkerReadyError::from)?;
        let actual = Self::capture(&store, &self.attempt.trusted)?;
        if !Self::same_capture(
            self.capture.as_ref().ok_or(WorkerReadyError::Stale)?,
            &actual,
        ) {
            return Err(WorkerReadyError::Stale);
        }
        #[cfg(test)]
        if let WorkerReadyHttp::Scripted(script) = &mut self.attempt.http
            && let Some(error) = script.clock_failure.take()
        {
            // Synthetic concrete-clock failure seam, NOT an actual SQL fault.
            // Production always executes the fixed Domain checkpoint below.
            store.seal_authorization();
            return Err(WorkerReadyError::Store(error));
        }
        let floor = guard
            .checkpoint_worker_verification_clock(
                self.scope.as_ref().ok_or(WorkerReadyError::Stale)?,
                &mut store,
                now,
            )
            .map_err(WorkerReadyError::from)?;
        self.clock_floor = Some(floor);
        self.phase = WorkerReadyPhase::Accept;
        Ok(false)
    }
    fn accept_once(&mut self) -> Result<bool, WorkerReadyError> {
        self.check_boundary()?;
        // Accept is a distinct scheduler boundary. Refresh the durable clock
        // using the SAME original scope before taking the retained response.
        // Mutex Busy here retains Accept/response/provider state exactly.
        let floor = {
            let now = self.attempt.projected_time()?;
            let mut guard = self
                .writer
                .as_mut()
                .ok_or(WorkerReadyError::Stale)?
                .try_enter_worker_verification()
                .map_err(WorkerReadyError::Domain)?;
            let mut store = self.owner.try_store().map_err(WorkerReadyError::from)?;
            let actual = Self::capture(&store, &self.attempt.trusted)?;
            if !Self::same_capture(
                self.capture.as_ref().ok_or(WorkerReadyError::Stale)?,
                &actual,
            ) {
                return Err(WorkerReadyError::Stale);
            }
            #[cfg(test)]
            if let WorkerReadyHttp::Scripted(script) = &mut self.attempt.http
                && let Some(error) = script.clock_failure.take()
            {
                // Synthetic actual-clock self-seal seam, not an induced SQL fault.
                store.seal_authorization();
                return Err(WorkerReadyError::Store(error));
            }
            guard
                .checkpoint_worker_verification_clock(
                    self.scope.as_ref().ok_or(WorkerReadyError::Stale)?,
                    &mut store,
                    now,
                )
                .map_err(WorkerReadyError::from)?
        };
        self.clock_floor = Some(floor);
        self.check_boundary()?;
        // Store work itself may block. Sample again after releasing BOTH locks,
        // immediately before validating/mutating the same borrowed provider.
        let floor = self.attempt.projected_time()?.max(floor);
        let response = self.response.take().ok_or(WorkerReadyError::Stale)?;
        // Same exclusively borrowed HostAuth/provider, with neither mutex held.
        // Preserve this provider error before boundary/cleanup errors can occur.
        match response {
            WorkerReadyResponse::Register(response) => {
                // confirm_registration itself has no now parameter. Recheck
                // freshness AND exact original request at the persisted floor.
                let (access, request) = self.attempt.auth.registration_request(floor)
                    .map_err(WorkerReadyError::Provider)?;
                if !matches!(self.request.as_ref(), Some(WorkerReadyRequest::Register(original_access, original_request))
                    if original_access == &access && original_request == &request) { return Err(WorkerReadyError::Stale); }
                self.provider_accept_started = true;
                self.attempt.auth.confirm_registration(response)
            }
            WorkerReadyResponse::Rotate(response) => {
                let request = self.attempt.auth.rotation_request(floor).map_err(WorkerReadyError::Provider)?;
                if !matches!(self.request.as_ref(), Some(WorkerReadyRequest::Rotate(original))
                    if original == &request) { return Err(WorkerReadyError::Stale); }
                self.provider_accept_started = true;
                self.attempt.auth.accept_rotation(response, floor)
            }
        }.map_err(WorkerReadyError::Provider)?;
        self.check_boundary()?;
        if self.attempt.auth.status() != lomi_host_auth::Status::Ready {
            return Err(WorkerReadyError::Stale);
        }
        self.deadlines = Some(
            self.attempt
                .auth
                .credential_deadlines()
                .map_err(WorkerReadyError::Provider)?,
        );
        self.phase = WorkerReadyPhase::Publish;
        Ok(false)
    }
    fn publish(&mut self) -> Result<bool, WorkerReadyError> {
        let now = self.attempt.projected_time()?;
        let capture = self.capture.as_ref().ok_or(WorkerReadyError::Stale)?;
        let deadlines = self.deadlines.ok_or(WorkerReadyError::Stale)?;
        {
            let mut guard = self
                .writer
                .as_mut()
                .ok_or(WorkerReadyError::Stale)?
                .try_enter()
                .map_err(WorkerReadyError::Domain)?;
            let mut store = self.owner.try_store().map_err(WorkerReadyError::from)?;
            let actual = Self::capture(&store, &self.attempt.trusted)?;
            if !Self::same_capture(capture, &actual) {
                return Err(WorkerReadyError::Stale);
            }
            // Final trusted clock remains clock-only on the SAME original scope.
            let floor = guard
                .checkpoint_verification_clock(
                    self.scope.as_ref().ok_or(WorkerReadyError::Stale)?,
                    &mut store,
                    now,
                )
                .map_err(WorkerReadyError::from)?;
            if floor >= deadlines.access_expires_at {
                return Err(WorkerReadyError::Provider(lomi_host_auth::Error::Expired));
            }
            self.operation.check().map_err(WorkerReadyError::Domain)?;
            if self
                .attempt
                .paused
                .load(std::sync::atomic::Ordering::Acquire)
                || self
                    .attempt
                    .setup
                    .pending
                    .load(std::sync::atomic::Ordering::Acquire)
            {
                return Err(WorkerReadyError::Stale);
            }
            let scope = self.scope.take().ok_or(WorkerReadyError::Stale)?;
            guard
                .commit_verified(scope, || {
                    match capture.completion {
                        WorkerReadyCompletion::Login(intent) => store.complete_login(intent)?,
                        WorkerReadyCompletion::Resume(generation) => {
                            store.enable_authorization(generation)?
                        }
                    };
                    Ok::<_, StoreError>(((), StoreView::read(&store)?))
                })
                .map_err(WorkerReadyError::from)?;
            #[cfg(test)]
            if let Some(now) = self.attempt.after_final_store_time_for_test.take() {
                // Deterministic time crossing at the final blocking Store boundary.
                self.attempt.projected_for_test = Some(now);
            }
            // complete/enable and its final post-view can block across expiry.
            // Check after ALL that work, while the original writer is retained.
            // No successful-path Store reacquisition/blocking work follows this.
            let completed_at = self.attempt.projected_time()?.max(floor);
            if completed_at >= deadlines.access_expires_at {
                // Infallible volatile Store attenuation; writer-drop below also
                // denies Domain remotely. Preserve Expired, never open the gate.
                store.seal_authorization();
                return Err(WorkerReadyError::Provider(lomi_host_auth::Error::Expired));
            }
        }
        self.check_boundary()?;
        self.writer
            .take()
            .ok_or(WorkerReadyError::Stale)?
            .finish()
            .map_err(WorkerReadyError::Domain)?;
        // Volatile gate opens only after successful final Domain Ready AND finish.
        self.attempt
            .gate
            .store(false, std::sync::atomic::Ordering::Release);
        self.phase = WorkerReadyPhase::Published;
        Ok(true)
    }
}
impl<S: lomi_platform::secrets::SecretStorage + ?Sized> Drop
    for SoleWorkerReadyTurn<'_, '_, '_, '_, '_, '_, S>
{
    fn drop(&mut self) {
        if self.phase != WorkerReadyPhase::Published {
            self.attempt
                .gate
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }
}
// END INACTIVE SOLE-WORKER READY HANDOFF

#[cfg(test)]
struct WorkerReadyScript {
    send_failure: Option<lomi_host_http::Error>,
    sends: std::rc::Rc<std::cell::Cell<usize>>,
    exact_request: std::rc::Rc<std::cell::RefCell<Option<String>>>,
    clock_failure: Option<StoreError>,
}
#[cfg(test)]
impl WorkerReadyScript {
    fn send(
        &mut self,
        request: &WorkerReadyRequest,
        owner: &SharedOwner,
        operation: &Operation<'_>,
    ) -> Result<WorkerReadyResponse, WorkerReadyError> {
        // Rendezvous proves neither actual mutex is retained at HTTP boundary.
        assert!(owner.domain.try_read(operation).is_ok());
        assert!(owner.store.try_lock().is_ok());
        self.sends.set(self.sends.get() + 1);
        assert_eq!(
            self.sends.get(),
            1,
            "the same response must never be replayed"
        );
        if let Some(error) = self.send_failure.take() {
            *self.exact_request.borrow_mut() = Some(match request {
                WorkerReadyRequest::Register(_, request) => serde_json::to_string(request).unwrap(),
                WorkerReadyRequest::Rotate(request) => serde_json::to_string(request).unwrap(),
            });
            return Err(WorkerReadyError::Http(error));
        }
        match request {
            WorkerReadyRequest::Register(_, request) => {
                *self.exact_request.borrow_mut() = Some(serde_json::to_string(request).unwrap());
                Ok(WorkerReadyResponse::Register(
                    lomi_remote_protocol::HostRegisterResult {
                        host_id: request.host_id,
                        host_access_epoch: DecimalU64(12),
                    },
                ))
            }
            WorkerReadyRequest::Rotate(request) => {
                *self.exact_request.borrow_mut() = Some(serde_json::to_string(request).unwrap());
                // A restart creates a new scripted HTTP client, so a fixed
                // synthetic credential would repeat the previous response
                // and correctly fail HostAuth's rotation replay checks. Bind
                // these test-only credentials to the fresh rotation ID.
                let rotation = request
                    .rotation_id
                    .to_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                Ok(WorkerReadyResponse::Rotate(
                    lomi_remote_protocol::HostAuthorizationResult {
                        account_id: lomi_remote_protocol::AccountId::from_bytes([4; 16]).unwrap(),
                        host_id: request.host_id,
                        host_authorization_id:
                            lomi_remote_protocol::HostAuthorizationId::from_bytes([8; 16]).unwrap(),
                        access: format!("synthetic_access_{rotation}").try_into().unwrap(),
                        refresh: format!("synthetic_refresh_{rotation}").try_into().unwrap(),
                        rotation_id: request.rotation_id,
                        expires_in_seconds: DecimalU64(300),
                    },
                ))
            }
        }
    }
}
// BEGIN INACTIVE COHERENT CLOUD GET (direct PUT/ACK deliberately excluded)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CloudGetError {
    Domain(domain::Error),
    Store(StoreError),
    UncertainStore(StoreError),
    Provider(lomi_host_auth::Error),
    Http(lomi_host_http::Error),
    Stale,
}
impl CloudGetError {
    pub(super) fn is_uncertain(self) -> bool {
        matches!(
            self,
            Self::UncertainStore(_)
                | Self::Domain(domain::Error::Poisoned)
                | Self::Provider(
                    lomi_host_auth::Error::Storage(_)
                        | lomi_host_auth::Error::Sealed
                        | lomi_host_auth::Error::ClockRollback
                )
        )
    }
}
impl From<Error> for CloudGetError {
    fn from(error: Error) -> Self {
        match error {
            Error::Domain(error) => Self::Domain(error),
            Error::Store(error) => Self::Store(error),
            Error::UncertainStore(error) => Self::UncertainStore(error),
        }
    }
}
impl From<StepError<StoreError>> for CloudGetError {
    fn from(error: StepError<StoreError>) -> Self {
        match error {
            StepError::Domain(error) => Self::Domain(error),
            StepError::Source(error) => Self::UncertainStore(error),
        }
    }
}
impl From<StepError<CloudGetError>> for CloudGetError {
    fn from(error: StepError<CloudGetError>) -> Self {
        match error {
            StepError::Domain(error) => Self::Domain(error),
            StepError::Source(error) => error,
        }
    }
}
impl From<StoreError> for CloudGetError {
    fn from(error: StoreError) -> Self {
        Self::UncertainStore(error)
    }
}
#[derive(Clone, Copy)]
pub(super) enum CloudGetStoreAction {
    Invalidate,
    RecoveredAck,
    Install,
}
impl CloudGetStoreAction {
    /// INDIVIDUAL audited classifications, not a global Store-error whitelist.
    /// Busy loses call-site provenance (including COMMIT): conservatively uncertain.
    pub(super) fn expected(self, error: StoreError) -> bool {
        match self {
            Self::Invalidate => matches!(error, StoreError::Fenced | StoreError::RevisionConflict),
            Self::RecoveredAck => {
                matches!(error, StoreError::Fenced | StoreError::RevisionConflict)
            }
            Self::Install => matches!(error, StoreError::Fenced | StoreError::RevisionConflict),
        }
    }
}
#[derive(Clone, PartialEq, Eq)]
struct CloudGetTuple {
    trusted: lomi_host_auth::Config,
    identity: Identity,
    configuration: LocalAuthConfiguration,
    public_state: lomi_host_store::PublicConfigurationState,
    public_document: PublicDocument,
    public_ready: bool,
    generation: u64,
    verified: Option<u64>,
    scope: CloudRuntimeScope,
    previous: Option<CloudRuntimeState>,
    pending: Option<HostPublicationIntent>,
    epoch: DecimalU64,
    deadlines: lomi_host_auth::CredentialDeadlines,
}
impl CloudGetTuple {
    fn read(
        store: &HostStore,
        trusted: &lomi_host_auth::Config,
        epoch: DecimalU64,
        deadlines: lomi_host_auth::CredentialDeadlines,
    ) -> Result<Self, CloudGetError> {
        let identity = store.identity().clone();
        let configuration = store.auth_configuration()?.ok_or(CloudGetError::Stale)?;
        configuration.validate().map_err(|_| CloudGetError::Stale)?;
        let derived = lomi_host_auth::Config::new(
            identity.host_id,
            identity.profile_id,
            configuration.origin.as_str().to_owned(),
            configuration
                .client_id
                .as_str()
                .to_owned()
                .try_into()
                .map_err(|_| CloudGetError::Stale)?,
        )
        .map_err(CloudGetError::Provider)?;
        if &derived != trusted {
            return Err(CloudGetError::Stale);
        }
        let pin = configuration
            .remote_api_origin
            .as_ref()
            .ok_or(CloudGetError::Stale)?
            .as_str()
            .to_owned();
        lomi_host_http::RemoteApiOrigin::new(trusted, pin.clone()).map_err(CloudGetError::Http)?;
        let public_state = store
            .public_configuration_state()?
            .ok_or(CloudGetError::Stale)?;
        let public_document = store.public_current()?;
        let public_ready = store.public_configuration_ready()?;
        if !public_ready
            || public_state.prepared.is_some()
            || public_state.current.as_ref() != Some(&public_document)
            || public_document.configuration()?.authentication.as_ref() != Some(&configuration)
        {
            return Err(CloudGetError::Stale);
        }
        let authorization = store.authorization_state()?;
        let verified = store.verified_authorization_generation()?;
        if authorization.locked
            || authorization.pending_cloud_revoke
            || verified != Some(authorization.generation)
        {
            return Err(CloudGetError::Stale);
        }
        let scope = store.cloud_runtime_scope(authorization.generation, pin)?;
        Ok(Self {
            trusted: trusted.clone(),
            identity,
            configuration,
            public_state,
            public_document,
            public_ready,
            generation: authorization.generation,
            verified,
            previous: store.cloud_runtime_reconciliation_state(&scope)?,
            pending: store.pending_host_publication()?,
            scope,
            epoch,
            deadlines,
        })
    }
    fn revalidate(
        &self,
        store: &HostStore,
        #[cfg(test)] fault: Option<CloudGetTupleFault>,
    ) -> Result<(), CloudGetError> {
        let current = Self::read(store, &self.trusted, self.epoch, self.deadlines)?;
        #[cfg(test)]
        let current = {
            let mut value = current;
            if let Some(fault) = fault {
                fault.apply(&mut value);
            }
            value
        };
        if current != *self {
            return Err(CloudGetError::Stale);
        }
        Ok(())
    }
}
/// Private flow-control result only; never peer/heartbeat eligibility or a permit.
pub(super) enum CloudGetDecision {
    Blocked,
    Claim(DecimalU64),
    Online {
        binding: Option<CloudRuntimeState>,
        lease_until: Option<std::time::Instant>,
    },
}
struct CloudGetLatches<'a> {
    gate: &'a std::sync::atomic::AtomicBool,
    paused: &'a std::sync::atomic::AtomicBool,
    stopping: &'a std::sync::atomic::AtomicBool,
    pending: &'a std::sync::atomic::AtomicBool,
}
/// Opaque fixed plan. Fields/constructor remain PRIVATE to this module; no
/// public response/boolean/callback proof constructor. Only the retained actual
/// configured GET and same HostAuth acceptance path below can assemble it.
pub(super) struct CloudGetPlan<'a> {
    latches: CloudGetLatches<'a>,
    tuple: CloudGetTuple,
    snapshot: lomi_remote_protocol::HostRuntimeGetResult,
    provider_invalid: bool,
    started: std::time::Instant,
    base: u64,
    anchor: std::time::Instant,
    #[cfg(test)]
    projected: Option<u64>,
    #[cfg(test)]
    post_store_time: Option<u64>,
    #[cfg(test)]
    handoff_race: bool,
    #[cfg(test)]
    fault: Option<CloudGetTupleFault>,
}
impl CloudGetPlan<'_> {
    pub(super) fn revalidate(&self, store: &HostStore) -> Result<(), CloudGetError> {
        self.check_latches()?;
        self.tuple.revalidate(
            store,
            #[cfg(test)]
            self.fault,
        )
    }
    pub(super) fn projected_time(&self) -> Result<u64, CloudGetError> {
        #[cfg(test)]
        if let Some(now) = self.projected {
            return Ok(now);
        }
        self.base
            .checked_add(self.anchor.elapsed().as_secs())
            .ok_or(CloudGetError::Domain(domain::Error::Exhausted))
    }
    fn check_latches(&self) -> Result<(), CloudGetError> {
        if self.latches.gate.load(std::sync::atomic::Ordering::Acquire)
            || self
                .latches
                .paused
                .load(std::sync::atomic::Ordering::Acquire)
            || self
                .latches
                .stopping
                .load(std::sync::atomic::Ordering::Acquire)
            || self
                .latches
                .pending
                .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(CloudGetError::Stale);
        }
        Ok(())
    }
    pub(super) fn check_current(&self, floor: u64) -> Result<(), CloudGetError> {
        self.check_latches()?;
        let now = self.projected_time()?.max(floor);
        if now >= self.tuple.deadlines.access_expires_at {
            return Err(CloudGetError::Provider(lomi_host_auth::Error::Expired));
        }
        Ok(())
    }
    pub(super) fn check_fresh(&self, floor: u64) -> Result<(), CloudGetError> {
        self.check_current(floor)?;
        #[cfg(test)]
        if self
            .post_store_time
            .is_some_and(|now| now >= self.tuple.deadlines.access_expires_at)
        {
            return Err(CloudGetError::Provider(lomi_host_auth::Error::Expired));
        }
        Ok(())
    }
    pub(super) fn scope(&self) -> &CloudRuntimeScope {
        &self.tuple.scope
    }
    pub(super) fn previous(&self) -> Option<&CloudRuntimeState> {
        self.tuple.previous.as_ref()
    }
    pub(super) fn pending(&self) -> Option<&HostPublicationIntent> {
        self.tuple.pending.as_ref()
    }
    pub(super) fn snapshot(&self) -> &lomi_remote_protocol::HostRuntimeGetResult {
        &self.snapshot
    }
    pub(super) fn provider_invalid(&self) -> bool {
        self.provider_invalid
    }
    pub(super) fn request_started(&self) -> std::time::Instant {
        self.started
    }
}
enum CloudGetHttp {
    Configured(lomi_host_http::DataTransport),
    #[cfg(test)]
    Scripted(CloudGetScript),
}
pub(super) struct ConfiguredCloudAttempt<
    'w,
    'p,
    'i,
    S: lomi_platform::secrets::SecretStorage + ?Sized,
> {
    auth: &'w mut lomi_host_auth::HostAuth<'p, S>,
    trusted: lomi_host_auth::Config,
    // Interface-only dependency on the separately authored WorkerPublicIo lease.
    // Future composition supplies that exact source; no lease duplication here.
    io: &'i super::public_configuration::WorkerPublicIo<'i>,
    gate: &'i std::sync::atomic::AtomicBool,
    paused: &'i std::sync::atomic::AtomicBool,
    stopping: &'i std::sync::atomic::AtomicBool,
    base: u64,
    anchor: std::time::Instant,
    http: Option<CloudGetHttp>,
    started_once: bool,
    #[cfg(test)]
    api: Option<&'w dyn super::auth::CloudDataApi>,
    #[cfg(test)]
    projected: Option<u64>,
    #[cfg(test)]
    before_provider_fault: Option<CloudGetTupleFault>,
    #[cfg(test)]
    after_provider_fault: Option<CloudGetTupleFault>,
    #[cfg(test)]
    post_store_time: Option<u64>,
    #[cfg(test)]
    handoff_race: bool,
    #[cfg(test)]
    clock_failure: Option<StoreError>,
    #[cfg(test)]
    post_provider_clock_failure: Option<StoreError>,
}
impl<'w, 'p, 'i, S: lomi_platform::secrets::SecretStorage + ?Sized>
    ConfiguredCloudAttempt<'w, 'p, 'i, S>
{
    pub(super) fn from_existing_worker(
        auth: &'w mut lomi_host_auth::HostAuth<'p, S>,
        io: &'i super::public_configuration::WorkerPublicIo<'i>,
        gate: &'i std::sync::atomic::AtomicBool,
        paused: &'i std::sync::atomic::AtomicBool,
        stopping: &'i std::sync::atomic::AtomicBool,
        base: u64,
        anchor: std::time::Instant,
    ) -> Self {
        let trusted = auth.trusted_configuration().clone();
        Self {
            auth,
            trusted,
            io,
            gate,
            paused,
            stopping,
            base,
            anchor,
            http: None,
            started_once: false,
            #[cfg(test)]
            api: None,
            #[cfg(test)]
            projected: None,
            #[cfg(test)]
            before_provider_fault: None,
            #[cfg(test)]
            after_provider_fault: None,
            #[cfg(test)]
            post_store_time: None,
            #[cfg(test)]
            clock_failure: None,
            #[cfg(test)]
            handoff_race: false,
            #[cfg(test)]
            post_provider_clock_failure: None,
        }
    }
    fn projected_time(&self) -> Result<u64, CloudGetError> {
        #[cfg(test)]
        if let Some(now) = self.projected {
            return Ok(now);
        }
        self.base
            .checked_add(self.anchor.elapsed().as_secs())
            .ok_or(CloudGetError::Domain(domain::Error::Exhausted))
    }
    pub(super) fn begin_get<'t, 'd, 'o>(
        &'t mut self,
        owner: &'d SharedOwner,
        operation: &'o Operation<'o>,
    ) -> Result<CoherentCloudGet<'t, 'd, 'o, 'w, 'p, 'i, S>, CloudGetError> {
        if self.started_once {
            return Err(CloudGetError::Stale);
        }
        operation.check().map_err(CloudGetError::Domain)?;
        self.started_once = true;
        Ok(CoherentCloudGet {
            attempt: self,
            owner,
            operation,
            scope: None,
            tuple: None,
            request: None,
            response: None,
            started: None,
            floor: None,
            provider_invalid: false,
            phase: CloudGetPhase::Prepare,
            decision: None,
            claim: None,
            terminal: None,
        })
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum CloudGetPhase {
    Prepare,
    Send,
    Clock,
    Accept,
    Reconcile,
    Complete,
    Terminal,
}
struct CloudGetRequest {
    host: HostId,
    access: lomi_remote_protocol::HostAccessCredential,
    epoch: DecimalU64,
}
pub(super) struct CoherentCloudGet<
    't,
    'd,
    'o,
    'w,
    'p,
    'i,
    S: lomi_platform::secrets::SecretStorage + ?Sized,
> {
    attempt: &'t mut ConfiguredCloudAttempt<'w, 'p, 'i, S>,
    owner: &'d SharedOwner,
    operation: &'o Operation<'o>,
    scope: Option<super::owner_domain::CloudReadScope<'d, 'o>>,
    tuple: Option<CloudGetTuple>,
    request: Option<CloudGetRequest>,
    response: Option<Result<lomi_remote_protocol::HostRuntimeGetResult, lomi_host_http::Error>>,
    started: Option<std::time::Instant>,
    floor: Option<u64>,
    provider_invalid: bool,
    phase: CloudGetPhase,
    decision: Option<CloudGetDecision>,
    claim: Option<CloudClaimAdmission>,
    terminal: Option<CloudGetError>,
}
impl<S: lomi_platform::secrets::SecretStorage + ?Sized>
    CoherentCloudGet<'_, '_, '_, '_, '_, '_, S>
{
    pub(super) fn take_decision(&mut self) -> Option<CloudGetDecision> {
        self.decision.take()
    }
    pub(super) fn take_claim_admission(&mut self) -> Option<CloudClaimAdmission> {
        self.claim.take()
    }
    fn boundary(&mut self) -> Result<(), CloudGetError> {
        self.operation.check().map_err(CloudGetError::Domain)?;
        if self.attempt.gate.load(std::sync::atomic::Ordering::Acquire)
            || self
                .attempt
                .paused
                .load(std::sync::atomic::Ordering::Acquire)
            || self
                .attempt
                .stopping
                .load(std::sync::atomic::Ordering::Acquire)
            || self
                .attempt
                .io
                .setup()
                .pending
                .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(CloudGetError::Stale);
        }
        Ok(())
    }
    /// Progress only: no lease/Ready/eligibility proof escapes this API.
    pub(super) fn try_step(&mut self) -> Result<bool, CloudGetError> {
        if let Some(error) = self.terminal {
            return Err(error);
        }
        if self.phase == CloudGetPhase::Complete {
            return Err(CloudGetError::Stale);
        }
        let result = self.boundary().and_then(|()| match self.phase {
            CloudGetPhase::Prepare => self.prepare(),
            CloudGetPhase::Send => self.send_once(),
            CloudGetPhase::Clock => {
                self.clock(false)?;
                self.phase = CloudGetPhase::Accept;
                Ok(false)
            }
            CloudGetPhase::Accept => self.accept_once(),
            CloudGetPhase::Reconcile => self.reconcile(),
            CloudGetPhase::Complete | CloudGetPhase::Terminal => Err(CloudGetError::Stale),
        });
        if matches!(result, Err(CloudGetError::Domain(domain::Error::Busy))) {
            return result;
        }
        if let Err(error) = result {
            // Read scope disposal is nonminting and has no writer Drop effect.
            // Actual SQL/provider uncertainty is explicit; ordinary network,
            // cancellation or deadline failure leaves independent work possible.
            if error.is_uncertain() {
                self.owner.domain.cloud_uncertain();
            }
            self.terminal = Some(error);
            self.phase = CloudGetPhase::Terminal;
        }
        result
    }
    fn prepare(&mut self) -> Result<bool, CloudGetError> {
        let now = self.attempt.projected_time()?;
        if self.attempt.auth.status() != lomi_host_auth::Status::Ready {
            return Err(CloudGetError::Stale);
        }
        let epoch = self
            .attempt
            .auth
            .verified_host_access_epoch()
            .map_err(CloudGetError::Provider)?;
        let deadlines = self
            .attempt
            .auth
            .credential_deadlines()
            .map_err(CloudGetError::Provider)?;
        if now >= deadlines.refresh_at {
            return Err(CloudGetError::Provider(lomi_host_auth::Error::Expired));
        }
        let access = self
            .attempt
            .auth
            .access_credential(now)
            .map_err(CloudGetError::Provider)?;
        let tuple;
        {
            let mut guard = self
                .owner
                .domain
                .try_read(self.operation)
                .map_err(CloudGetError::Domain)?;
            let mut store = self.owner.try_store().map_err(CloudGetError::from)?;
            tuple = CloudGetTuple::read(&store, &self.attempt.trusted, epoch, deadlines)?;
            let scope = guard
                .prepare_cloud_read(&store)
                .map_err(CloudGetError::from)?;
            self.floor = Some(
                guard
                    .checkpoint_cloud_read_clock(&scope, &mut store, now)
                    .map_err(CloudGetError::from)?,
            );
            self.scope = Some(scope);
        }
        self.boundary()?;
        // Transport construction may access TLS configuration: outside locks,
        // under the existing sole worker's exact typed PublicSetup IO lease.
        if self.attempt.http.is_none() {
            let origin = lomi_host_http::RemoteApiOrigin::new(
                &self.attempt.trusted,
                tuple.scope.remote_api_origin.clone(),
            )
            .map_err(CloudGetError::Http)?;
            self.attempt.http = Some(CloudGetHttp::Configured(
                self.attempt
                    .io
                    .data_transport(origin)
                    .map_err(CloudGetError::Http)?,
            ));
        }
        self.boundary()?;
        self.request = Some(CloudGetRequest {
            host: tuple.scope.host_id,
            access,
            epoch,
        });
        self.tuple = Some(tuple);
        self.phase = CloudGetPhase::Send;
        Ok(false)
    }
    fn clock(&mut self, after_provider: bool) -> Result<(), CloudGetError> {
        let now = self.attempt.projected_time()?;
        let mut guard = self
            .owner
            .domain
            .try_read(self.operation)
            .map_err(CloudGetError::Domain)?;
        let mut store = self.owner.try_store().map_err(CloudGetError::from)?;
        self.tuple
            .as_ref()
            .ok_or(CloudGetError::Stale)?
            .revalidate(
                &store,
                #[cfg(test)]
                if after_provider {
                    self.attempt.after_provider_fault
                } else {
                    self.attempt.before_provider_fault
                },
            )?;
        let _ = after_provider;
        #[cfg(test)]
        if let Some(error) = if after_provider {
            self.attempt.post_provider_clock_failure.take()
        } else {
            self.attempt.clock_failure.take()
        } {
            // Synthetic self-seal boundary, not actual SQLite fault induction.
            store.seal_authorization();
            return Err(CloudGetError::UncertainStore(error));
        }
        self.floor = Some(
            guard
                .checkpoint_cloud_read_clock(
                    self.scope.as_ref().ok_or(CloudGetError::Stale)?,
                    &mut store,
                    now,
                )
                .map_err(CloudGetError::from)?,
        );
        Ok(())
    }
    fn send_once(&mut self) -> Result<bool, CloudGetError> {
        self.clock(false)?;
        self.boundary()?;
        let now = self
            .attempt
            .projected_time()?
            .max(self.floor.ok_or(CloudGetError::Stale)?);
        let request = self.request.as_ref().ok_or(CloudGetError::Stale)?;
        if self
            .attempt
            .auth
            .verified_host_access_epoch()
            .map_err(CloudGetError::Provider)?
            != request.epoch
            || self
                .attempt
                .auth
                .access_credential(now)
                .map_err(CloudGetError::Provider)?
                != request.access
            || now
                >= self
                    .tuple
                    .as_ref()
                    .ok_or(CloudGetError::Stale)?
                    .deadlines
                    .refresh_at
        {
            return Err(CloudGetError::Stale);
        }
        self.started = Some(std::time::Instant::now());
        #[cfg(test)]
        if let Some(api) = self.attempt.api {
            self.response = Some(api.get(request.host, &request.access));
        } else {
            self.response = Some(
                match self.attempt.http.as_mut().ok_or(CloudGetError::Stale)? {
                    CloudGetHttp::Configured(transport) => {
                        configured_cloud_get_send(transport, request, self.operation)
                    }
                    #[cfg(test)]
                    CloudGetHttp::Scripted(script) => {
                        script.get(request, self.owner, self.operation)
                    }
                },
            );
        }
        #[cfg(not(test))]
        {
            self.response = Some(
                match self.attempt.http.as_mut().ok_or(CloudGetError::Stale)? {
                    CloudGetHttp::Configured(transport) => {
                        configured_cloud_get_send(transport, request, self.operation)
                    }
                    #[cfg(test)]
                    CloudGetHttp::Scripted(script) => {
                        script.get(request, self.owner, self.operation)
                    }
                },
            );
        }
        self.phase = CloudGetPhase::Clock;
        if let Some(Err(error)) = self.response.as_ref() {
            return Err(CloudGetError::Http(*error));
        }
        self.boundary()?;
        Ok(false)
    }
    fn accept_once(&mut self) -> Result<bool, CloudGetError> {
        self.clock(false)?;
        self.boundary()?;
        let now = self
            .attempt
            .projected_time()?
            .max(self.floor.ok_or(CloudGetError::Stale)?);
        let request = self.request.as_ref().ok_or(CloudGetError::Stale)?;
        if self
            .attempt
            .auth
            .verified_host_access_epoch()
            .map_err(CloudGetError::Provider)?
            != request.epoch
        {
            return Err(CloudGetError::Stale);
        }
        self.attempt
            .auth
            .access_credential(now)
            .map_err(CloudGetError::Provider)?;
        let snapshot = self
            .response
            .as_ref()
            .ok_or(CloudGetError::Stale)?
            .as_ref()
            .map_err(|error| CloudGetError::Http(*error))?;
        // No Domain/Store guard at this provider boundary. Non-InvalidResponse
        // MUST return BEFORE any post-provider clock, domain or tuple check.
        match self
            .attempt
            .auth
            .accept_runtime_observation(request.epoch, snapshot.clone(), now)
        {
            Err(error) if error != lomi_host_auth::Error::InvalidResponse => {
                return Err(CloudGetError::Provider(error));
            }
            Err(_) => self.provider_invalid = true,
            Ok(()) => self.provider_invalid = false,
        }
        self.phase = CloudGetPhase::Reconcile;
        Ok(false)
    }
    fn reconcile(&mut self) -> Result<bool, CloudGetError> {
        self.clock(true)?;
        self.boundary()?;
        let now = self
            .attempt
            .projected_time()?
            .max(self.floor.ok_or(CloudGetError::Stale)?);
        let snapshot = self
            .response
            .as_ref()
            .ok_or(CloudGetError::Stale)?
            .as_ref()
            .map_err(|error| CloudGetError::Http(*error))?
            .clone();
        if !self.provider_invalid {
            self.attempt
                .auth
                .access_credential(now)
                .map_err(CloudGetError::Provider)?;
            if self
                .attempt
                .auth
                .verified_host_access_epoch()
                .map_err(CloudGetError::Provider)?
                != snapshot.host_access_epoch
            {
                return Err(CloudGetError::Stale);
            }
        }
        self.boundary()?;
        let plan = CloudGetPlan {
            latches: CloudGetLatches {
                gate: self.attempt.gate,
                paused: self.attempt.paused,
                stopping: self.attempt.stopping,
                pending: &self.attempt.io.setup().pending,
            },
            tuple: self.tuple.as_ref().ok_or(CloudGetError::Stale)?.clone(),
            snapshot: snapshot.clone(),
            provider_invalid: self.provider_invalid,
            started: self.started.ok_or(CloudGetError::Stale)?,
            base: self.attempt.base,
            anchor: self.attempt.anchor,
            #[cfg(test)]
            projected: self.attempt.projected,
            #[cfg(test)]
            post_store_time: self.attempt.post_store_time,
            #[cfg(test)]
            handoff_race: self.attempt.handoff_race,
            #[cfg(test)]
            fault: self.attempt.after_provider_fault,
        };
        let settlement = self
            .owner
            .domain
            .try_commit_cloud_get(
                self.scope.as_ref().ok_or(CloudGetError::Stale)?,
                &self.owner.store,
                plan,
            )
            .map_err(CloudGetError::from)?;
        self.claim = settlement.claim.map(|continuation| CloudClaimAdmission {
            continuation,
            tuple: self.tuple.as_ref().expect("captured GET tuple").clone(),
            expected_generation: snapshot.runtime_generation,
            accepted_epoch: snapshot.host_access_epoch,
            producer: ClaimProducer {
                provider: self.attempt.auth as *const _ as usize,
                io: self.attempt.io as *const _ as usize,
                gate: self.attempt.gate as *const _ as usize,
                paused: self.attempt.paused as *const _ as usize,
                stopping: self.attempt.stopping as *const _ as usize,
            },
            consumed: false,
        });
        let decision = settlement.decision;
        self.scope = None;
        let blocked = matches!(decision, CloudGetDecision::Blocked);
        self.decision = Some(decision);
        self.phase = CloudGetPhase::Complete;
        if blocked {
            return Err(CloudGetError::Http(lomi_host_http::Error::InvalidResponse));
        }
        Ok(true)
    }
}
// END INACTIVE COHERENT CLOUD GET

#[cfg(test)]
#[derive(Clone, Copy)]
enum CloudGetTupleFault {
    Configuration,
    PublicDocument,
    PublicReadiness,
    Scope,
    Previous,
    Pending,
    Generation,
    Epoch,
    Identity,
    Deadline,
}
#[cfg(test)]
impl CloudGetTupleFault {
    fn apply(self, current: &mut CloudGetTuple) {
        match self {
            Self::Configuration => {
                current.configuration.client_id = "changed-client".to_owned().try_into().unwrap()
            }
            Self::PublicDocument => {
                let mut value = current.public_document.configuration().unwrap();
                value.revision += 1;
                current.public_document = PublicDocument::encode(&value).unwrap();
            }
            Self::PublicReadiness => current.public_ready = !current.public_ready,
            Self::Scope => current.scope.owner_generation += 1,
            Self::Previous => {
                current
                    .previous
                    .as_mut()
                    .unwrap()
                    .acknowledged_publication_seq
                    .0 += 1
            }
            Self::Pending => current.pending.as_mut().unwrap().token.push('x'),
            Self::Generation => current.generation += 1,
            Self::Epoch => current.epoch.0 += 1,
            Self::Identity => {
                current.identity.profile_id =
                    lomi_remote_protocol::ipc::IpcProfileId::from_bytes([44; 16]).unwrap()
            }
            Self::Deadline => current.deadlines.access_expires_at += 1,
        }
    }
}
#[cfg(test)]
struct CloudGetScript {
    reply: Option<Result<lomi_remote_protocol::HostRuntimeGetResult, lomi_host_http::Error>>,
    sends: std::rc::Rc<std::cell::Cell<usize>>,
    expected_host: HostId,
    expected_access: lomi_remote_protocol::HostAccessCredential,
    mutation: u8,
}
#[cfg(test)]
impl CloudGetScript {
    fn get(
        &mut self,
        request: &CloudGetRequest,
        owner: &SharedOwner,
        operation: &Operation<'_>,
    ) -> Result<lomi_remote_protocol::HostRuntimeGetResult, lomi_host_http::Error> {
        assert!(owner.domain.try_read(operation).is_ok());
        assert!(owner.store.try_lock().is_ok());
        assert_eq!(request.host, self.expected_host);
        assert_eq!(request.access, self.expected_access);
        self.sends.set(self.sends.get() + 1);
        assert_eq!(self.sends.get(), 1);
        match self.mutation {
            1 => {
                owner
                    .begin_local_logout(operation)
                    .unwrap()
                    .try_commit()
                    .unwrap();
            }
            2 => {
                owner.store.lock().unwrap().public_block();
            }
            3 => operation.expire_for_test(),
            _ => {}
        }
        self.reply
            .take()
            .expect("one retained actual scripted response")
    }
}
#[cfg(test)]
impl CloudGetPlan<'static> {
    pub(super) fn synthetic_for_domain_test(
        store: &HostStore,
        post_store_time: Option<u64>,
    ) -> Self {
        let selected = store.auth_configuration().unwrap().unwrap();
        let identity = store.identity();
        let trusted = lomi_host_auth::Config::new(
            identity.host_id,
            identity.profile_id,
            selected.origin.as_str().to_owned(),
            selected.client_id.as_str().to_owned().try_into().unwrap(),
        )
        .unwrap();
        let tuple = CloudGetTuple::read(
            store,
            &trusted,
            DecimalU64(12),
            lomi_host_auth::CredentialDeadlines {
                access_expires_at: 1302,
                refresh_at: 1242,
                rotation_expires_at: None,
            },
        )
        .unwrap();
        let snapshot = lomi_remote_protocol::HostRuntimeGetResult {
            host_id: identity.host_id,
            host_access_epoch: DecimalU64(12),
            runtime_generation: DecimalU64(0),
            runtime: None,
            publication_seq: DecimalU64(0),
            lease_ms: DecimalU64(0),
            freshness_ms: DecimalU64(0),
        };
        static FALSE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        Self {
            latches: CloudGetLatches {
                gate: &FALSE,
                paused: &FALSE,
                stopping: &FALSE,
                pending: &FALSE,
            },
            tuple,
            snapshot,
            provider_invalid: false,
            started: std::time::Instant::now(),
            base: 1004,
            anchor: std::time::Instant::now(),
            projected: Some(1004),
            post_store_time,
            handoff_race: false,
            fault: None,
        }
    }
}

#[cfg(test)]
impl CloudGetPlan<'_> {
    pub(super) fn handoff_race_for_test(&self) -> bool {
        self.handoff_race
    }
}
// BEGIN INACTIVE NORMAL CONFIGURED PUBLICATION
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PublicationError {
    Domain(domain::Error),
    Store(StoreError),
    UncertainStore(StoreError),
    Auth(lomi_host_auth::Error),
    Http(lomi_host_http::Error),
    Stale,
}
impl PublicationError {
    pub(super) fn uncertain(self) -> bool {
        matches!(
            self,
            Self::UncertainStore(_)
                | Self::Domain(domain::Error::Poisoned)
                | Self::Auth(
                    lomi_host_auth::Error::Storage(_)
                        | lomi_host_auth::Error::Sealed
                        | lomi_host_auth::Error::ClockRollback
                )
        )
    }
}
impl From<Error> for PublicationError {
    fn from(error: Error) -> Self {
        match error {
            Error::Domain(error) => Self::Domain(error),
            Error::Store(error) | Error::UncertainStore(error) => Self::UncertainStore(error),
        }
    }
}
impl From<StepError<StoreError>> for PublicationError {
    fn from(error: StepError<StoreError>) -> Self {
        match error {
            StepError::Domain(error) => Self::Domain(error),
            StepError::Source(error) => Self::UncertainStore(error),
        }
    }
}
impl From<StepError<PublicationError>> for PublicationError {
    fn from(error: StepError<PublicationError>) -> Self {
        match error {
            StepError::Domain(error) => Self::Domain(error),
            StepError::Source(error) => error,
        }
    }
}
impl From<StoreError> for PublicationError {
    fn from(error: StoreError) -> Self {
        Self::UncertainStore(error)
    }
}
impl From<super::auth::NormalPublicationOriginError> for PublicationError {
    fn from(error: super::auth::NormalPublicationOriginError) -> Self {
        match error {
            super::auth::NormalPublicationOriginError::Auth(error) => Self::Auth(error),
            super::auth::NormalPublicationOriginError::Http(error) => Self::Http(error),
            super::auth::NormalPublicationOriginError::Stopped(error) => Self::Domain(error),
            super::auth::NormalPublicationOriginError::Stale => Self::Stale,
        }
    }
}
fn publication_get_error(error: CloudGetError) -> PublicationError {
    match error {
        CloudGetError::Domain(error) => PublicationError::Domain(error),
        CloudGetError::Store(error) => PublicationError::Store(error),
        CloudGetError::UncertainStore(error) => PublicationError::UncertainStore(error),
        CloudGetError::Provider(error) => PublicationError::Auth(error),
        CloudGetError::Http(error) => PublicationError::Http(error),
        CloudGetError::Stale => PublicationError::Stale,
    }
}
#[derive(Clone)]
struct PublicationTuple {
    cloud: CloudGetTuple,
    binding: CloudRuntimeState,
    acknowledged: Option<HostAcknowledgedPublication>,
    outbox: Vec<lomi_host_store::Publication>,
}
impl PublicationTuple {
    fn read(
        store: &HostStore,
        trusted: &lomi_host_auth::Config,
        epoch: DecimalU64,
        deadlines: lomi_host_auth::CredentialDeadlines,
    ) -> Result<Self, PublicationError> {
        let cloud =
            CloudGetTuple::read(store, trusted, epoch, deadlines).map_err(publication_get_error)?;
        let binding = store
            .cloud_runtime_state(&cloud.scope)?
            .ok_or(PublicationError::Stale)?;
        if cloud.previous.as_ref() != Some(&binding)
            || binding.server_runtime.host_access_epoch != epoch
        {
            return Err(PublicationError::Stale);
        }
        Ok(Self {
            acknowledged: store.acknowledged_host_publication(&binding)?,
            outbox: store.pending_publications()?,
            cloud,
            binding,
        })
    }
    fn revalidate(
        &self,
        store: &HostStore,
        prepared: Option<&HostPublicationIntent>,
    ) -> Result<(), PublicationError> {
        let current = Self::read(
            store,
            &self.cloud.trusted,
            self.cloud.epoch,
            self.cloud.deadlines,
        )?;
        let mut expected_cloud = self.cloud.clone();
        if let Some(intent) = prepared {
            expected_cloud.pending = Some(intent.clone());
        }
        if current.cloud != expected_cloud
            || current.binding != self.binding
            || current.acknowledged != self.acknowledged
        {
            return Err(PublicationError::Stale);
        }
        if prepared.is_none() {
            if current.outbox != self.outbox {
                return Err(PublicationError::Stale);
            }
        } else {
            // Outbox is frozen request data, not renewed authority. Superseding
            // rows may remain; ACK only clears the exact original intent tokens.
            for old in &self.outbox {
                let now = current
                    .outbox
                    .iter()
                    .find(|row| row.workspace_id == old.workspace_id)
                    .ok_or(PublicationError::Stale)?;
                if now != old
                    && (now.fence < old.fence
                        || now.domain_revision.0 < old.domain_revision.0
                        || (now.fence == old.fence && now.domain_revision == old.domain_revision))
                {
                    return Err(PublicationError::Stale);
                }
            }
        }
        Ok(())
    }
}
/// Opaque fixed plan; only the retained actual-worker/configured-turn code here
/// constructs it. No caller response/boolean/callback authority constructor.
pub(super) struct PublicationPlan<'a, 'w, 'o> {
    tuple: PublicationTuple,
    observation: &'a super::auth::NormalPublicationObservation<'w, 'o>,
    latches: CloudGetLatches<'a>,
    base: u64,
    anchor: std::time::Instant,
    #[cfg(test)]
    projected: Option<u64>,
    #[cfg(test)]
    post_store_time: Option<u64>,
}
impl PublicationPlan<'_, '_, '_> {
    pub(super) fn binding(&self) -> &CloudRuntimeState {
        &self.tuple.binding
    }
    pub(super) fn revalidate(
        &self,
        store: &HostStore,
        prepared: Option<&HostPublicationIntent>,
    ) -> Result<(), PublicationError> {
        self.check_latches()?;
        self.tuple.revalidate(store, prepared)
    }
    fn check_latches(&self) -> Result<(), PublicationError> {
        if self.latches.gate.load(std::sync::atomic::Ordering::Acquire)
            || self
                .latches
                .paused
                .load(std::sync::atomic::Ordering::Acquire)
            || self
                .latches
                .stopping
                .load(std::sync::atomic::Ordering::Acquire)
            || self
                .latches
                .pending
                .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(PublicationError::Stale);
        }
        Ok(())
    }
    pub(super) fn check_current(&self, floor: u64) -> Result<(), PublicationError> {
        self.check_latches()?;
        #[cfg(test)]
        let projected = self.projected.unwrap_or(
            self.base
                .checked_add(self.anchor.elapsed().as_secs())
                .ok_or(PublicationError::Domain(domain::Error::Exhausted))?,
        );
        #[cfg(not(test))]
        let projected = self
            .base
            .checked_add(self.anchor.elapsed().as_secs())
            .ok_or(PublicationError::Domain(domain::Error::Exhausted))?;
        let now = projected.max(floor);
        if now >= self.tuple.cloud.deadlines.access_expires_at {
            return Err(PublicationError::Auth(lomi_host_auth::Error::Expired));
        }
        self.observation
            .check_local(now)
            .map_err(PublicationError::from)?;
        Ok(())
    }
    pub(super) fn check_operation(
        &self,
        operation: &Operation<'_>,
    ) -> Result<(), PublicationError> {
        if !std::ptr::eq(operation, self.observation.operation()) {
            return Err(PublicationError::Stale);
        }
        Ok(())
    }
    pub(super) fn check_fresh(&self, floor: u64) -> Result<(), PublicationError> {
        self.check_current(floor)?;
        #[cfg(test)]
        if self
            .post_store_time
            .is_some_and(|after| after >= self.tuple.cloud.deadlines.access_expires_at)
        {
            return Err(PublicationError::Auth(lomi_host_auth::Error::Expired));
        }
        Ok(())
    }
}
/// Contains only the exact retained intent and actual configured PUT response.
/// Fields and constructor remain private to this module.
pub(super) struct ConfiguredPublicationResponse {
    intent: HostPublicationIntent,
    response: lomi_remote_protocol::http::PublicationResult,
    _request_started: std::time::Instant,
}
impl ConfiguredPublicationResponse {
    pub(super) fn validate(&self, intent: &HostPublicationIntent) -> Result<(), PublicationError> {
        if &self.intent != intent
            || self.response.runtime != intent.params.runtime
            || self.response.publication_seq != intent.params.publication_seq
        {
            return Err(PublicationError::Http(
                lomi_host_http::Error::InvalidResponse,
            ));
        }
        Ok(())
    }
    pub(super) fn result(&self) -> &lomi_remote_protocol::http::PublicationResult {
        &self.response
    }
}
/// Only a retained actual observation can select this transport attenuation.
/// The watcher owns no Worker/provider/scope; it checks just the SAME original
/// Operation and a copied absolute deadline. Fields/constructor stay private.
struct PublicationHttpBudget<'o, 'c> {
    operation: &'o Operation<'c>,
    deadline: std::time::Instant,
}
impl<'o, 'c> PublicationHttpBudget<'o, 'c> {
    fn from_observation(
        observation: &super::auth::NormalPublicationObservation<'_, '_>,
        operation: &'o Operation<'c>,
        now: u64,
    ) -> Result<Self, PublicationError> {
        if !std::ptr::eq(observation.operation(), operation) {
            return Err(PublicationError::Stale);
        }
        let deadline = observation
            .publication_http_deadline(now)
            .map_err(PublicationError::from)?;
        Ok(Self {
            operation,
            deadline,
        })
    }
    fn check_at(&self, now: std::time::Instant) -> Result<(), lomi_host_http::BudgetStop> {
        OriginalOperationHttpBudget {
            operation: self.operation,
        }
        .check()?;
        if now >= self.deadline {
            return Err(lomi_host_http::BudgetStop::Deadline);
        }
        Ok(())
    }
    fn check(&self) -> Result<(), lomi_host_http::BudgetStop> {
        self.check_at(std::time::Instant::now())
    }
}
fn configured_publication_send(
    transport: &lomi_host_http::DataTransport,
    intent: &HostPublicationIntent,
    access: &lomi_remote_protocol::HostAccessCredential,
    operation: &Operation<'_>,
    observation: &super::auth::NormalPublicationObservation<'_, '_>,
    now: u64,
) -> Result<lomi_remote_protocol::http::PublicationResult, PublicationError> {
    let budget = PublicationHttpBudget::from_observation(observation, operation, now)?;
    let check = || budget.check();
    transport
        .with_budget(budget.deadline, &check)
        .publication(intent.scope.host_id, &intent.params, access)
        .map_err(PublicationError::Http)
}
enum PublicationHttp {
    Configured(lomi_host_http::DataTransport),
    #[cfg(test)]
    Scripted(PublicationScript),
}
/// Only successful actual configured heartbeat installation and original
/// Domain settlement construct this receipt. It owns no guard or provider.
/// The scheduler retains the same provider and PublicIo lease externally.
pub(super) struct OwnedConfiguredHeartbeat {
    admission: RetainedHeartbeatAdmission,
    observation: super::auth::OwnedNormalPublicationObservation,
}
struct RetainedHeartbeatAdmission {
    domain: domain::OwnedHeartbeatPublication,
    tuple: PublicationTuple,
    access: lomi_remote_protocol::HostAccessCredential,
    io_identity: super::public_configuration::WorkerPublicIoIdentity,
    base: u64,
    anchor: std::time::Instant,
    floor: u64,
}
pub(super) struct ConfiguredNormalPublication<
    'w,
    'p,
    'o,
    'i,
    S: lomi_platform::secrets::SecretStorage + ?Sized,
> {
    auth: &'w mut lomi_host_auth::HostAuth<'p, S>,
    driver: Option<super::auth::NormalPublicationDriver<'w>>,
    retained: Option<RetainedHeartbeatAdmission>,
    observation: Option<super::auth::NormalPublicationObservation<'w, 'o>>,
    operation: &'o Operation<'o>,
    io: &'i super::public_configuration::WorkerPublicIo<'i>,
    gate: &'i std::sync::atomic::AtomicBool,
    paused: &'i std::sync::atomic::AtomicBool,
    stopping: &'i std::sync::atomic::AtomicBool,
    base: u64,
    anchor: std::time::Instant,
    started: bool,
    heartbeat_started: bool,
    http: Option<PublicationHttp>,
    #[cfg(test)]
    api: Option<&'w dyn super::auth::CloudDataApi>,
    #[cfg(test)]
    projected: Option<u64>,
    #[cfg(test)]
    post_store_time: Option<u64>,
}
impl<'w, 'p, 'o, 'i, S: lomi_platform::secrets::SecretStorage + ?Sized>
    ConfiguredNormalPublication<'w, 'p, 'o, 'i, S>
{
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep the original worker, operation, IO lease and latches explicit"
    )]
    pub(super) fn from_existing_worker(
        auth: &'w mut lomi_host_auth::HostAuth<'p, S>,
        driver: super::auth::NormalPublicationDriver<'w>,
        operation: &'o Operation<'o>,
        io: &'i super::public_configuration::WorkerPublicIo<'i>,
        gate: &'i std::sync::atomic::AtomicBool,
        paused: &'i std::sync::atomic::AtomicBool,
        stopping: &'i std::sync::atomic::AtomicBool,
        base: u64,
        anchor: std::time::Instant,
    ) -> Self {
        Self {
            auth,
            driver: Some(driver),
            retained: None,
            observation: None,
            operation,
            io,
            gate,
            paused,
            stopping,
            base,
            anchor,
            started: false,
            heartbeat_started: false,
            http: None,
            #[cfg(test)]
            api: None,
            #[cfg(test)]
            projected: None,
            #[cfg(test)]
            post_store_time: None,
        }
    }
    pub(super) fn retain_configured_heartbeat(
        mut self,
    ) -> Result<OwnedConfiguredHeartbeat, PublicationError> {
        self.boundary()?;
        let admission = self.retained.take().ok_or(PublicationError::Stale)?;
        let observation = self
            .observation
            .take()
            .ok_or(PublicationError::Stale)?
            .retain_owned(self.now()?)
            .map_err(PublicationError::from)?;
        Ok(OwnedConfiguredHeartbeat {
            admission,
            observation,
        })
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "keep the original provider, Worker, operation, IO lease, latches and owned receipt explicit"
    )]
    pub(super) fn from_retained_heartbeat(
        auth: &'w mut lomi_host_auth::HostAuth<'p, S>,
        driver: super::auth::NormalPublicationDriver<'w>,
        operation: &'o Operation<'o>,
        io: &'i super::public_configuration::WorkerPublicIo<'i>,
        gate: &'i std::sync::atomic::AtomicBool,
        paused: &'i std::sync::atomic::AtomicBool,
        stopping: &'i std::sync::atomic::AtomicBool,
        receipt: OwnedConfiguredHeartbeat,
    ) -> Result<Self, PublicationError> {
        if !io.is_same_lease(&receipt.admission.io_identity) {
            return Err(PublicationError::Stale);
        }
        let OwnedConfiguredHeartbeat {
            admission,
            observation,
        } = receipt;
        let base = admission.base;
        let anchor = admission.anchor;
        let now = base
            .checked_add(anchor.elapsed().as_secs())
            .ok_or(PublicationError::Stale)?
            .max(admission.floor);
        let observation = driver
            .resume_owned(observation, operation, now)
            .map_err(PublicationError::from)?;
        observation
            .validate_provider(auth, now)
            .map_err(PublicationError::from)?;
        let attempt = Self {
            auth,
            driver: None,
            retained: Some(admission),
            observation: Some(observation),
            operation,
            io,
            gate,
            paused,
            stopping,
            base,
            anchor,
            started: false,
            heartbeat_started: true,
            http: None,
            #[cfg(test)]
            api: None,
            #[cfg(test)]
            projected: None,
            #[cfg(test)]
            post_store_time: None,
        };
        attempt.boundary()?;
        Ok(attempt)
    }
    /// Legacy test-only denied entry: caller binding data cannot mint origin.
    #[cfg(test)]
    pub(super) fn observe_configured_heartbeat(
        &mut self,
        _binding: &CloudRuntimeState,
    ) -> Result<(), PublicationError> {
        self.boundary()?;
        Err(PublicationError::Stale)
    }
    pub(super) fn begin_configured_heartbeat<'t, 'd>(
        &'t mut self,
        owner: &'d SharedOwner,
    ) -> Result<ConfiguredHeartbeatTurn<'t, 'd, 'w, 'p, 'o, 'i, S>, PublicationError> {
        self.driver
            .as_mut()
            .ok_or(PublicationError::Stale)?
            .invalidate_heartbeat();
        self.boundary()?;
        if self.started || self.heartbeat_started || self.observation.is_some() {
            return Err(PublicationError::Stale);
        }
        self.heartbeat_started = true;
        Ok(ConfiguredHeartbeatTurn {
            attempt: self,
            owner,
            scope: None,
            tuple: None,
            captured_access: None,
            floor: 0,
            phase: ConfiguredHeartbeatPhase::Capture,
            terminal: None,
            #[cfg(test)]
            final_send_fault: None,
        })
    }
    fn now(&self) -> Result<u64, PublicationError> {
        #[cfg(test)]
        if let Some(now) = self.projected {
            return Ok(now);
        }
        self.base
            .checked_add(self.anchor.elapsed().as_secs())
            .ok_or(PublicationError::Domain(domain::Error::Exhausted))
    }
    fn boundary(&self) -> Result<(), PublicationError> {
        self.operation.check().map_err(PublicationError::Domain)?;
        if self.gate.load(std::sync::atomic::Ordering::Acquire)
            || self.paused.load(std::sync::atomic::Ordering::Acquire)
            || self.stopping.load(std::sync::atomic::Ordering::Acquire)
            || self
                .io
                .setup()
                .pending
                .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(PublicationError::Stale);
        }
        Ok(())
    }
    pub(super) fn begin<'t, 'd>(
        &'t mut self,
        owner: &'d SharedOwner,
    ) -> Result<NormalPublicationTurn<'t, 'd, 'w, 'p, 'o, 'i, S>, PublicationError> {
        if self.started {
            return Err(PublicationError::Stale);
        }
        self.boundary()?;
        let now = self.now()?;
        self.observation
            .as_mut()
            .ok_or(PublicationError::Stale)?
            .arm_get(now)
            .map_err(PublicationError::from)?;
        self.started = true;
        Ok(NormalPublicationTurn {
            attempt: self,
            owner,
            continuation: None,
            tuple: None,
            access: None,
            intent: None,
            response: None,
            floor: 0,
            phase: NormalPublicationPhase::Capture,
            terminal: None,
        })
    }
}
/// Fixed read-only configured heartbeat, retaining the exclusive provider and
/// actual Worker borrow in `attempt` across every Busy retry. No authority
/// DTO, injected DataApi, new writer, VerificationScope or Ready is produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfiguredHeartbeatPhase {
    Capture,
    PrepareProvider,
    FinalSendAdmission,
    SendOnce,
    ValidateProvider,
    PostClock,
    InstallObservation,
    Complete,
    Terminal,
}
pub(super) struct ConfiguredHeartbeatTurn<
    't,
    'd,
    'w,
    'p,
    'o,
    'i,
    S: lomi_platform::secrets::SecretStorage + ?Sized,
> {
    attempt: &'t mut ConfiguredNormalPublication<'w, 'p, 'o, 'i, S>,
    owner: &'d SharedOwner,
    scope: Option<domain::CloudReadScope<'d, 'o>>,
    tuple: Option<PublicationTuple>,
    captured_access: Option<lomi_remote_protocol::HostAccessCredential>,
    floor: u64,
    phase: ConfiguredHeartbeatPhase,
    terminal: Option<PublicationError>,
    #[cfg(test)]
    final_send_fault: Option<CloudGetTupleFault>,
}
impl<S: lomi_platform::secrets::SecretStorage + ?Sized>
    ConfiguredHeartbeatTurn<'_, '_, '_, '_, '_, '_, S>
{
    pub(super) fn try_step(&mut self) -> Result<bool, PublicationError> {
        if let Some(error) = self.terminal {
            return Err(error);
        }
        if self.phase == ConfiguredHeartbeatPhase::Complete {
            return Err(PublicationError::Stale);
        }
        let result = match self.phase {
            ConfiguredHeartbeatPhase::Capture => self.capture(),
            ConfiguredHeartbeatPhase::PrepareProvider => self.prepare_provider(),
            ConfiguredHeartbeatPhase::FinalSendAdmission => self.final_send_admission(),
            ConfiguredHeartbeatPhase::ValidateProvider => self.validate_provider(),
            ConfiguredHeartbeatPhase::PostClock => self.post_clock(),
            ConfiguredHeartbeatPhase::InstallObservation => self.install(),
            _ => Err(PublicationError::Stale),
        };
        if matches!(result, Err(PublicationError::Domain(domain::Error::Busy))) {
            return result;
        }
        if let Err(error) = result {
            if error.uncertain() {
                self.owner.domain.cloud_uncertain();
            }
            if let Some(driver) = self.attempt.driver.as_mut() {
                driver.invalidate_heartbeat();
            }
            self.attempt.observation.take();
            self.terminal = Some(error);
            self.phase = ConfiguredHeartbeatPhase::Terminal;
        }
        result
    }
    fn current(&self) -> Result<u64, PublicationError> {
        self.attempt.boundary()?;
        let now = self.attempt.now()?.max(self.floor);
        if let Some(tuple) = &self.tuple {
            if now >= tuple.cloud.deadlines.access_expires_at {
                return Err(PublicationError::Auth(lomi_host_auth::Error::Expired));
            }
            if now >= tuple.cloud.deadlines.refresh_at {
                return Err(PublicationError::Stale);
            }
        }
        Ok(now)
    }
    fn capture(&mut self) -> Result<bool, PublicationError> {
        let now = self.current()?;
        // All provider calls precede acquisition of either mutex.
        let trusted = self.attempt.auth.trusted_configuration().clone();
        let epoch = self
            .attempt
            .auth
            .verified_host_access_epoch()
            .map_err(PublicationError::Auth)?;
        let deadlines = self
            .attempt
            .auth
            .credential_deadlines()
            .map_err(PublicationError::Auth)?;
        let access = self
            .attempt
            .auth
            .access_credential(now)
            .map_err(PublicationError::Auth)?;
        {
            let mut guard = self
                .owner
                .domain
                .try_read(self.attempt.operation)
                .map_err(PublicationError::Domain)?;
            let mut store = self.owner.try_store().map_err(PublicationError::from)?;
            let tuple = PublicationTuple::read(&store, &trusted, epoch, deadlines)?;
            let scope = guard
                .prepare_cloud_read(&store)
                .map_err(PublicationError::from)?;
            self.floor = guard
                .checkpoint_cloud_read_clock(&scope, &mut store, now)
                .map_err(PublicationError::from)?;
            self.tuple = Some(tuple);
            self.scope = Some(scope);
            self.captured_access = Some(access);
        }
        self.phase = ConfiguredHeartbeatPhase::PrepareProvider;
        Ok(false)
    }
    fn prepare_provider(&mut self) -> Result<bool, PublicationError> {
        let now = self.current()?;
        let tuple = self.tuple.as_ref().ok_or(PublicationError::Stale)?;
        self.captured_provider(now)?;
        self.attempt
            .driver
            .as_mut()
            .ok_or(PublicationError::Stale)?
            .prepare_configured_heartbeat(self.attempt.auth, self.attempt.io, &tuple.binding, now)
            .map_err(PublicationError::from)?;
        self.phase = ConfiguredHeartbeatPhase::FinalSendAdmission;
        Ok(false)
    }
    fn check_original(&mut self) -> Result<(), PublicationError> {
        {
            let guard = self
                .owner
                .domain
                .try_read(self.attempt.operation)
                .map_err(PublicationError::Domain)?;
            let store = self.owner.try_store().map_err(PublicationError::from)?;
            self.tuple
                .as_ref()
                .ok_or(PublicationError::Stale)?
                .revalidate(&store, None)?;
            self.floor = self.floor.max(
                guard
                    .check_cloud_read_send(
                        self.scope.as_ref().ok_or(PublicationError::Stale)?,
                        &store,
                    )
                    .map_err(PublicationError::from)?,
            );
        }
        self.current()?;
        Ok(())
    }
    fn final_send_admission(&mut self) -> Result<bool, PublicationError> {
        // Fault the reread proof rather than rewriting its captured provider
        // epoch/deadlines: those inputs are intentionally supplied by the owner.
        #[cfg(test)]
        if let Some(fault) = self.final_send_fault {
            let _guard = self
                .owner
                .domain
                .try_read(self.attempt.operation)
                .map_err(PublicationError::Domain)?;
            let store = self.owner.try_store().map_err(PublicationError::from)?;
            self.tuple
                .as_ref()
                .ok_or(PublicationError::Stale)?
                .cloud
                .revalidate(&store, Some(fault))
                .map_err(publication_get_error)?;
        }
        // A previous Busy retains provider material, original scope and phase.
        // The final mutex pair drops before pure checks and SAME-operation TLS.
        self.check_original()?;
        self.phase = ConfiguredHeartbeatPhase::SendOnce;
        let now = self.current()?;
        self.attempt
            .driver
            .as_mut()
            .ok_or(PublicationError::Stale)?
            .send_configured_heartbeat(self.attempt.operation, now)
            .map_err(PublicationError::from)?;
        // No fallible work or yield between retaining response and next phase.
        self.phase = ConfiguredHeartbeatPhase::ValidateProvider;
        Ok(false)
    }
    fn captured_provider(&self, now: u64) -> Result<(), PublicationError> {
        let cloud = &self.tuple.as_ref().ok_or(PublicationError::Stale)?.cloud;
        if &cloud.trusted != self.attempt.auth.trusted_configuration()
            || self
                .attempt
                .auth
                .verified_host_access_epoch()
                .map_err(PublicationError::Auth)?
                != cloud.epoch
            || self
                .attempt
                .auth
                .credential_deadlines()
                .map_err(PublicationError::Auth)?
                != cloud.deadlines
            || Some(
                self.attempt
                    .auth
                    .access_credential(now)
                    .map_err(PublicationError::Auth)?,
            ) != self.captured_access
        {
            return Err(PublicationError::Stale);
        }
        Ok(())
    }
    fn provider(&self) -> Result<(), PublicationError> {
        // Provider failure is primary before cancellation/fence/clock checks.
        let now = self.attempt.now()?.max(self.floor);
        self.attempt
            .driver
            .as_ref()
            .ok_or(PublicationError::Stale)?
            .validate_configured_heartbeat(self.attempt.auth, now)
            .map_err(PublicationError::from)?;
        self.captured_provider(now)
    }
    fn validate_provider(&mut self) -> Result<bool, PublicationError> {
        self.provider()?;
        self.phase = ConfiguredHeartbeatPhase::PostClock;
        Ok(false)
    }
    fn post_clock(&mut self) -> Result<bool, PublicationError> {
        self.provider()?;
        let now = self.current()?;
        {
            let mut guard = self
                .owner
                .domain
                .try_read(self.attempt.operation)
                .map_err(PublicationError::Domain)?;
            let mut store = self.owner.try_store().map_err(PublicationError::from)?;
            self.tuple
                .as_ref()
                .ok_or(PublicationError::Stale)?
                .revalidate(&store, None)?;
            self.floor = self.floor.max(
                guard
                    .checkpoint_cloud_read_clock(
                        self.scope.as_ref().ok_or(PublicationError::Stale)?,
                        &mut store,
                        now,
                    )
                    .map_err(PublicationError::from)?,
            );
        }
        self.phase = ConfiguredHeartbeatPhase::InstallObservation;
        Ok(false)
    }
    fn install(&mut self) -> Result<bool, PublicationError> {
        self.provider()?;
        self.check_original()?;
        let (domain, floor) = {
            let guard = self
                .owner
                .domain
                .try_read(self.attempt.operation)
                .map_err(PublicationError::Domain)?;
            let store = self.owner.try_store().map_err(PublicationError::from)?;
            self.tuple
                .as_ref()
                .ok_or(PublicationError::Stale)?
                .revalidate(&store, None)?;
            guard
                .retain_heartbeat_publication(
                    self.scope.take().ok_or(PublicationError::Stale)?,
                    &store,
                )
                .map_err(PublicationError::from)?
        };
        self.floor = self.floor.max(floor);
        let now = self.current()?;
        let driver = self.attempt.driver.take().ok_or(PublicationError::Stale)?;
        self.attempt.observation = Some(
            driver
                .install_configured_heartbeat(self.attempt.operation, now)
                .map_err(PublicationError::from)?,
        );
        self.attempt.retained = Some(RetainedHeartbeatAdmission {
            domain,
            tuple: self.tuple.take().ok_or(PublicationError::Stale)?,
            access: self.captured_access.take().ok_or(PublicationError::Stale)?,
            io_identity: self.attempt.io.retained_identity(),
            base: self.attempt.base,
            anchor: self.attempt.anchor,
            floor: self.floor,
        });
        self.phase = ConfiguredHeartbeatPhase::Complete;
        Ok(true)
    }
}
impl<S: lomi_platform::secrets::SecretStorage + ?Sized> Drop
    for ConfiguredHeartbeatTurn<'_, '_, '_, '_, '_, '_, S>
{
    fn drop(&mut self) {
        if self.phase != ConfiguredHeartbeatPhase::Complete {
            if let Some(driver) = self.attempt.driver.as_mut() {
                driver.invalidate_heartbeat();
            }
            self.attempt.observation.take();
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum NormalPublicationPhase {
    Capture,
    Prepare,
    Send,
    AfterPut,
    Ack,
    Complete,
    Terminal,
}
pub(super) struct NormalPublicationTurn<
    't,
    'd,
    'w,
    'p,
    'o,
    'i,
    S: lomi_platform::secrets::SecretStorage + ?Sized,
> {
    attempt: &'t mut ConfiguredNormalPublication<'w, 'p, 'o, 'i, S>,
    owner: &'d SharedOwner,
    continuation: Option<super::owner_domain::PublicationContinuation<'d, 'o>>,
    tuple: Option<PublicationTuple>,
    access: Option<lomi_remote_protocol::HostAccessCredential>,
    intent: Option<HostPublicationIntent>,
    response: Option<ConfiguredPublicationResponse>,
    floor: u64,
    phase: NormalPublicationPhase,
    terminal: Option<PublicationError>,
}
impl<S: lomi_platform::secrets::SecretStorage + ?Sized>
    NormalPublicationTurn<'_, '_, '_, '_, '_, '_, S>
{
    pub(super) fn try_step(&mut self) -> Result<bool, PublicationError> {
        if let Some(error) = self.terminal {
            return Err(error);
        }
        if self.phase == NormalPublicationPhase::Complete {
            return Err(PublicationError::Stale);
        }
        // Post-response provider failure precedes subsequent local/budget errors.
        let admission = if matches!(
            self.phase,
            NormalPublicationPhase::AfterPut | NormalPublicationPhase::Ack
        ) {
            Ok(())
        } else {
            self.attempt.boundary()
        };
        let result = admission.and_then(|()| match self.phase {
            NormalPublicationPhase::Capture => self.capture(),
            NormalPublicationPhase::Prepare => self.prepare(),
            NormalPublicationPhase::Send => self.send_once(),
            NormalPublicationPhase::AfterPut => self.after_put(),
            NormalPublicationPhase::Ack => self.ack(),
            _ => Err(PublicationError::Stale),
        });
        if matches!(result, Err(PublicationError::Domain(domain::Error::Busy))) {
            return result;
        }
        if let Err(error) = result {
            if error.uncertain() {
                self.owner.domain.cloud_uncertain();
            }
            self.attempt.observation.take(); // Drop irrevocably leaves Worker.Get.
            self.terminal = Some(error);
            self.phase = NormalPublicationPhase::Terminal;
        }
        result
    }
    fn capture(&mut self) -> Result<bool, PublicationError> {
        let now = self.attempt.now()?;
        self.attempt
            .observation
            .as_ref()
            .ok_or(PublicationError::Stale)?
            .validate_provider(self.attempt.auth, now)
            .map_err(PublicationError::from)?;
        let retained = self
            .attempt
            .retained
            .as_ref()
            .ok_or(PublicationError::Stale)?;
        // Provider checks use the original tuple and access, never a new epoch.
        if self.attempt.auth.trusted_configuration() != &retained.tuple.cloud.trusted
            || self
                .attempt
                .auth
                .verified_host_access_epoch()
                .map_err(PublicationError::Auth)?
                != retained.tuple.cloud.epoch
            || self
                .attempt
                .auth
                .credential_deadlines()
                .map_err(PublicationError::Auth)?
                != retained.tuple.cloud.deadlines
            || self
                .attempt
                .auth
                .access_credential(now)
                .map_err(PublicationError::Auth)?
                != retained.access
        {
            return Err(PublicationError::Stale);
        }
        let continuation = retained
            .domain
            .reborrow(&self.owner.domain, self.attempt.operation)
            .map_err(PublicationError::Domain)?;
        {
            let guard = self
                .owner
                .domain
                .try_read(self.attempt.operation)
                .map_err(PublicationError::Domain)?;
            let store = self.owner.try_store().map_err(PublicationError::from)?;
            retained.tuple.revalidate(&store, None)?;
            self.floor = retained.floor.max(
                guard
                    .check_publication_send(&continuation, &store)
                    .map_err(PublicationError::from)?,
            );
        }
        self.attempt.boundary()?;
        if self.attempt.http.is_none() {
            let origin = lomi_host_http::RemoteApiOrigin::new(
                &retained.tuple.cloud.trusted,
                retained.tuple.cloud.scope.remote_api_origin.clone(),
            )
            .map_err(PublicationError::Http)?;
            self.attempt.http = Some(PublicationHttp::Configured(
                self.attempt
                    .io
                    .data_transport(origin)
                    .map_err(PublicationError::Http)?,
            ));
        }
        self.tuple = Some(retained.tuple.clone());
        self.access = Some(retained.access.clone());
        self.continuation = Some(continuation);
        self.phase = NormalPublicationPhase::Prepare;
        Ok(false)
    }
    fn clock(&mut self) -> Result<(), PublicationError> {
        let now = self.attempt.now()?;
        let mut guard = self
            .owner
            .domain
            .try_read(self.attempt.operation)
            .map_err(PublicationError::Domain)?;
        let mut store = self.owner.try_store().map_err(|error| match error {
            Error::Domain(error) => PublicationError::Domain(error),
            Error::Store(error) | Error::UncertainStore(error) => {
                PublicationError::UncertainStore(error)
            }
        })?;
        self.tuple
            .as_ref()
            .ok_or(PublicationError::Stale)?
            .revalidate(&store, self.intent.as_ref())?;
        self.floor = guard
            .checkpoint_publication_clock(
                self.continuation.as_ref().ok_or(PublicationError::Stale)?,
                &mut store,
                now,
            )
            .map_err(PublicationError::from)?;
        Ok(())
    }
    fn provider(&self) -> Result<(), PublicationError> {
        let now = self.attempt.now()?.max(self.floor);
        self.attempt
            .observation
            .as_ref()
            .ok_or(PublicationError::Stale)?
            .validate_provider(self.attempt.auth, now)
            .map_err(PublicationError::from)?;
        if self
            .attempt
            .auth
            .access_credential(now)
            .map_err(PublicationError::Auth)?
            != *self.access.as_ref().ok_or(PublicationError::Stale)?
        {
            return Err(PublicationError::Stale);
        }
        self.attempt.boundary()
    }
    fn prepare(&mut self) -> Result<bool, PublicationError> {
        self.clock()?;
        self.provider()?;
        let plan = PublicationPlan {
            tuple: self.tuple.as_ref().ok_or(PublicationError::Stale)?.clone(),
            observation: self
                .attempt
                .observation
                .as_ref()
                .ok_or(PublicationError::Stale)?,
            latches: CloudGetLatches {
                gate: self.attempt.gate,
                paused: self.attempt.paused,
                stopping: self.attempt.stopping,
                pending: &self.attempt.io.setup().pending,
            },
            base: self.attempt.base,
            anchor: self.attempt.anchor,
            #[cfg(test)]
            projected: self.attempt.projected,
            #[cfg(test)]
            post_store_time: None,
        };
        let intent = self
            .owner
            .domain
            .try_prepare_publication(
                self.continuation.as_mut().ok_or(PublicationError::Stale)?,
                &self.owner.store,
                plan,
            )
            .map_err(PublicationError::from)?;
        self.intent = Some(intent);
        self.phase = NormalPublicationPhase::Send;
        Ok(false)
    }
    /// Full original authority and exact tuple admission AFTER the last provider
    /// call. Both guards drop before pure freshness and the actual PUT. There is
    /// no provider/HTTP/FS/Core call in or after this checkpoint before transport.
    fn final_send_admission(&mut self) -> Result<(), PublicationError> {
        {
            let guard = self
                .owner
                .domain
                .try_read(self.attempt.operation)
                .map_err(PublicationError::Domain)?;
            let store = self.owner.try_store().map_err(|error| match error {
                Error::Domain(error) => PublicationError::Domain(error),
                Error::Store(error) | Error::UncertainStore(error) => {
                    PublicationError::UncertainStore(error)
                }
            })?;
            self.tuple
                .as_ref()
                .ok_or(PublicationError::Stale)?
                .revalidate(&store, self.intent.as_ref())?;
            self.floor = self.floor.max(
                guard
                    .check_publication_send(
                        self.continuation.as_ref().ok_or(PublicationError::Stale)?,
                        &store,
                    )
                    .map_err(PublicationError::from)?,
            );
        }
        // Pure only, after the last blocking Store work. This checks the same
        // sticky operation, current projected trusted time/access deadline,
        // original heartbeat anchors and latches without refreshing authority.
        let plan = PublicationPlan {
            tuple: self.tuple.as_ref().ok_or(PublicationError::Stale)?.clone(),
            observation: self
                .attempt
                .observation
                .as_ref()
                .ok_or(PublicationError::Stale)?,
            latches: CloudGetLatches {
                gate: self.attempt.gate,
                paused: self.attempt.paused,
                stopping: self.attempt.stopping,
                pending: &self.attempt.io.setup().pending,
            },
            base: self.attempt.base,
            anchor: self.attempt.anchor,
            #[cfg(test)]
            projected: self.attempt.projected,
            #[cfg(test)]
            post_store_time: None,
        };
        plan.check_current(self.floor)
    }
    fn send_once(&mut self) -> Result<bool, PublicationError> {
        self.clock()?;
        self.provider()?;
        #[cfg(test)]
        let _final_send_boundary =
            publication_final_send_boundary(self.owner, self.attempt.operation);
        self.final_send_admission()?;
        let intent = self.intent.as_ref().ok_or(PublicationError::Stale)?;
        let access = self.access.as_ref().ok_or(PublicationError::Stale)?;
        let observation = self
            .attempt
            .observation
            .as_ref()
            .ok_or(PublicationError::Stale)?;
        let now = self.attempt.now()?.max(self.floor);
        let request_started = std::time::Instant::now();
        #[cfg(test)]
        let response = if let Some(api) = self.attempt.api {
            let budget =
                PublicationHttpBudget::from_observation(observation, self.attempt.operation, now)?;
            budget.check().map_err(|_| PublicationError::Stale)?;
            api.publish(intent.scope.host_id, &intent.params, access)
                .map_err(PublicationError::Http)?
        } else {
            match self.attempt.http.as_mut().ok_or(PublicationError::Stale)? {
                PublicationHttp::Configured(transport) => configured_publication_send(
                    transport,
                    intent,
                    access,
                    self.attempt.operation,
                    observation,
                    now,
                ),
                #[cfg(test)]
                PublicationHttp::Scripted(script) => {
                    let budget = PublicationHttpBudget::from_observation(
                        observation,
                        self.attempt.operation,
                        now,
                    )?;
                    script
                        .put(self.owner, self.attempt.operation, intent, access, &budget)
                        .map_err(PublicationError::Http)
                }
            }?
        };
        #[cfg(not(test))]
        let response = match self.attempt.http.as_mut().ok_or(PublicationError::Stale)? {
            PublicationHttp::Configured(transport) => configured_publication_send(
                transport,
                intent,
                access,
                self.attempt.operation,
                observation,
                now,
            ),
            #[cfg(test)]
            PublicationHttp::Scripted(script) => {
                let budget = PublicationHttpBudget::from_observation(
                    observation,
                    self.attempt.operation,
                    now,
                )?;
                script
                    .put(self.owner, self.attempt.operation, intent, access, &budget)
                    .map_err(PublicationError::Http)
            }
        }?;
        self.response = Some(ConfiguredPublicationResponse {
            intent: intent.clone(),
            response,
            _request_started: request_started,
        });
        self.phase = NormalPublicationPhase::AfterPut;
        Ok(false)
    }
    fn after_put(&mut self) -> Result<bool, PublicationError> {
        // Preserve a provider failure before post-response clock/local failures.
        self.provider()?;
        self.clock()?;
        self.provider()?;
        self.response
            .as_ref()
            .ok_or(PublicationError::Stale)?
            .validate(self.intent.as_ref().ok_or(PublicationError::Stale)?)?;
        self.phase = NormalPublicationPhase::Ack;
        Ok(false)
    }
    fn ack(&mut self) -> Result<bool, PublicationError> {
        self.provider()?;
        self.clock()?;
        self.provider()?;
        let plan = PublicationPlan {
            tuple: self.tuple.as_ref().ok_or(PublicationError::Stale)?.clone(),
            observation: self
                .attempt
                .observation
                .as_ref()
                .ok_or(PublicationError::Stale)?,
            latches: CloudGetLatches {
                gate: self.attempt.gate,
                paused: self.attempt.paused,
                stopping: self.attempt.stopping,
                pending: &self.attempt.io.setup().pending,
            },
            base: self.attempt.base,
            anchor: self.attempt.anchor,
            #[cfg(test)]
            projected: self.attempt.projected,
            #[cfg(test)]
            post_store_time: self.attempt.post_store_time,
        };
        self.owner
            .domain
            .try_ack_publication(
                self.continuation.as_mut().ok_or(PublicationError::Stale)?,
                &self.owner.store,
                plan,
                self.response.as_ref().ok_or(PublicationError::Stale)?,
            )
            .map_err(PublicationError::from)?;
        self.attempt
            .observation
            .take()
            .ok_or(PublicationError::Stale)?
            .complete_ack(self.attempt.now()?.max(self.floor))
            .map_err(PublicationError::from)?;
        self.phase = NormalPublicationPhase::Complete;
        Ok(true)
    }
}
// END INACTIVE NORMAL CONFIGURED PUBLICATION

// Deterministic cfg(test)-only boundary immediately after successful provider
// validation. These are real existing Domain writers/guards, not DTO proof.
#[cfg(test)]
thread_local! { static PUBLICATION_FINAL_SEND_BOUNDARY: std::cell::Cell<u8> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
pub(super) fn set_publication_final_send_boundary_for_test(boundary: u8) {
    PUBLICATION_FINAL_SEND_BOUNDARY.with(|slot| slot.set(boundary));
}
#[cfg(test)]
struct PublicationFinalSendHold<'d, 'o> {
    _writer: Option<PendingWriter<'d, 'o>>,
    _domain: Option<domain::OwnerGuard<'d, 'o>>,
    _store: Option<MutexGuard<'d, HostStore>>,
}
#[cfg(test)]
fn publication_final_send_boundary<'d, 'o>(
    owner: &'d SharedOwner,
    operation: &'o Operation<'o>,
) -> PublicationFinalSendHold<'d, 'o> {
    let boundary = PUBLICATION_FINAL_SEND_BOUNDARY.with(|slot| slot.replace(0));
    let mut held = PublicationFinalSendHold {
        _writer: None,
        _domain: None,
        _store: None,
    };
    match boundary {
        1 => {
            held._writer = Some(
                owner
                    .domain
                    .announce(operation, WriterClass::Remote, Intent::Mutation)
                    .unwrap(),
            );
        }
        2 => {
            let mut writer = owner
                .domain
                .announce(operation, WriterClass::Remote, Intent::Mutation)
                .unwrap();
            let mut guard = writer.try_enter().unwrap();
            let store = owner.store.lock().unwrap();
            guard
                .commit(|| Ok::<_, StoreError>(((), StoreView::read(&store)?)))
                .unwrap();
            drop(store);
            drop(guard);
            writer.finish().unwrap();
        }
        3 => {
            held._domain = Some(owner.domain.try_read(operation).unwrap());
        }
        4 => {
            held._store = Some(owner.store.lock().unwrap());
        }
        _ => (),
    }
    held
}

#[cfg(test)]
struct PublicationScript {
    reply: Option<Result<lomi_remote_protocol::http::PublicationResult, lomi_host_http::Error>>,
    sends: std::rc::Rc<std::cell::Cell<usize>>,
    expected_access: lomi_remote_protocol::HostAccessCredential,
    mutation: u8,
    selected_deadline: Option<std::time::Instant>,
    timeout_boundary: u8,
}
#[cfg(test)]
impl PublicationScript {
    fn put(
        &mut self,
        owner: &SharedOwner,
        operation: &Operation<'_>,
        intent: &HostPublicationIntent,
        access: &lomi_remote_protocol::HostAccessCredential,
        budget: &PublicationHttpBudget<'_, '_>,
    ) -> Result<lomi_remote_protocol::http::PublicationResult, lomi_host_http::Error> {
        assert!(std::ptr::eq(operation, budget.operation));
        self.selected_deadline = Some(budget.deadline);
        assert!(owner.domain.try_read(operation).is_ok());
        assert!(owner.store.try_lock().is_ok());
        assert_eq!(access, &self.expected_access);
        self.sends.set(self.sends.get() + 1);
        assert_eq!(self.sends.get(), 1);
        // Three synthetic transport interruption sites: write, wait and read.
        // They call the SAME pure budget check at its copied deadline; no real
        // socket/TLS scheduling or watcher timing is claimed by this seam.
        if (1..=3).contains(&self.timeout_boundary) {
            return Err(match budget.check_at(budget.deadline) {
                Err(lomi_host_http::BudgetStop::Cancelled) => lomi_host_http::Error::Cancelled,
                Err(lomi_host_http::BudgetStop::Deadline) => lomi_host_http::Error::Timeout,
                Ok(()) => panic!("expired heartbeat transport budget admitted IO"),
            });
        }
        match self.mutation {
            1 => owner.store.lock().unwrap().public_block(),
            2 => {
                owner
                    .begin_local_logout(operation)
                    .unwrap()
                    .try_commit()
                    .unwrap();
            }
            3 => {
                let workspace = intent.workspace_publications.first().unwrap().workspace_id;
                owner.store.lock().unwrap().unshare(workspace).unwrap();
            }
            4 => {
                let mut writer = owner
                    .domain
                    .announce(operation, WriterClass::Remote, Intent::Mutation)
                    .unwrap();
                let mut guard = writer.try_enter().unwrap();
                let store = owner.store.lock().unwrap();
                guard
                    .commit(|| Ok::<_, StoreError>(((), StoreView::read(&store)?)))
                    .unwrap();
                drop(store);
                drop(guard);
                writer.finish().unwrap();
            }
            5 => {
                let mut store = owner.store.lock().unwrap();
                let current = store.public_current().unwrap();
                let mut selected = current.configuration().unwrap();
                selected.revision += 1;
                // A configured remote origin is immutable. Adding the absent
                // relay pin is a valid configuration change that still fences
                // the captured publication tuple.
                selected.authentication.as_mut().unwrap().relay_endpoint = Some(
                    "wss://relay.example/v2/relay"
                        .to_owned()
                        .try_into()
                        .unwrap(),
                );
                let document = PublicDocument::encode(&selected).unwrap();
                let operation = store.public_prepare(Some(&current), &document).unwrap();
                store
                    .public_finish(operation.operation_id, &document)
                    .unwrap();
            }
            _ => (),
        }
        self.reply
            .take()
            .expect("the actual scripted PUT result is retained once")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lomi_host_store::Limits;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
    use std::time::{Duration, Instant};

    fn fixture() -> (tempfile::TempDir, Arc<SharedOwner>, WorkspaceId) {
        let directory = tempfile::tempdir().unwrap();
        let mut store =
            HostStore::open(&directory.path().join("host.sqlite"), Limits::default()).unwrap();
        let project = store
            .add_project(directory.path(), "Test".to_owned().try_into().unwrap())
            .unwrap();
        let id = project.state.context.workspace_id;
        (directory, SharedOwner::new(store).unwrap(), id)
    }

    fn end() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[test]
    fn cloned_arc_shares_domain_and_store_identity() {
        let (_directory, owner, id) = fixture();
        let clone = Arc::clone(&owner);
        assert!(Arc::ptr_eq(&owner, &clone));
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let held = owner.domain.try_read(&operation).unwrap();
        assert!(matches!(
            clone.workspace(&operation, id),
            Err(Error::Domain(domain::Error::Busy))
        ));
        drop(held);
        let held = owner.store.lock().unwrap();
        assert!(matches!(
            clone.workspace(&operation, id),
            Err(Error::Domain(domain::Error::Busy))
        ));
        drop(held);
        assert_eq!(clone.workspace(&operation, id).unwrap().fence, 0);
    }

    #[test]
    fn held_domain_and_store_busy_never_invoke_read_callback() {
        let (_directory, owner, _id) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let calls = AtomicUsize::new(0);
        let held = owner.domain.try_read(&operation).unwrap();
        let read = || {
            owner.read(&operation, |_| {
                calls.fetch_add(1, SeqCst);
                Ok(())
            })
        };
        assert_eq!(read(), Err(Error::Domain(domain::Error::Busy)));
        drop(held);
        let held = owner.store.lock().unwrap();
        assert_eq!(read(), Err(Error::Domain(domain::Error::Busy)));
        drop(held);
        assert_eq!(calls.load(SeqCst), 0);
        assert_eq!(read(), Ok(()));
        assert_eq!(calls.load(SeqCst), 1);
    }

    #[test]
    fn named_write_retries_same_pending_turn_after_domain_and_store_busy() {
        let (_directory, owner, id) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let held = owner.domain.try_read(&operation).unwrap();
        let mut write = owner.begin_share(&operation, id, 0).unwrap();
        assert_eq!(write.try_commit(), Err(Error::Domain(domain::Error::Busy)));
        drop(held);
        let held = owner.store.lock().unwrap();
        assert_eq!(write.try_commit(), Err(Error::Domain(domain::Error::Busy)));
        assert_eq!(held.workspace(id).unwrap().fence, 0);
        drop(held);
        assert_eq!(write.try_commit(), Ok(1));
        assert_eq!(write.try_commit(), Err(Error::Domain(domain::Error::Stale)));
        assert_eq!(owner.workspace(&operation, id).unwrap().fence, 1);
    }

    #[test]
    fn cancelled_busy_write_never_publishes_after_latch_reset() {
        let (_directory, owner, id) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let held = owner.store.lock().unwrap();
        let mut write = owner.begin_share(&operation, id, 0).unwrap();
        assert_eq!(write.try_commit(), Err(Error::Domain(domain::Error::Busy)));
        cancel.store(true, SeqCst);
        assert_eq!(
            write.try_commit(),
            Err(Error::Domain(domain::Error::Cancelled))
        );
        cancel.store(false, SeqCst);
        drop(held);
        assert_eq!(write.try_commit(), Err(Error::Domain(domain::Error::Stale)));
        let fresh = Operation::new(end(), &cancel);
        assert!(!owner.workspace(&fresh, id).unwrap().consent);
    }

    #[test]
    fn original_deadline_expires_while_busy_without_replacement_budget() {
        let (_directory, owner, id) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let held = owner.store.lock().unwrap();
        let mut write = owner.begin_share(&operation, id, 0).unwrap();
        assert_eq!(write.try_commit(), Err(Error::Domain(domain::Error::Busy)));
        // The existing cfg(test) clock seam expires this ORIGINAL Operation.
        // The pending write cannot accept a fresh Operation on retry.
        operation.expire_for_test();
        assert_eq!(
            write.try_commit(),
            Err(Error::Domain(domain::Error::Deadline))
        );
        drop(held);
        let fresh = Operation::new(end(), &cancel);
        assert_eq!(owner.workspace(&fresh, id).unwrap().fence, 0);
    }

    #[test]
    fn expired_and_cancelled_reads_never_invoke_callback() {
        let (_directory, owner, _id) = fixture();
        let cancel = AtomicBool::new(true);
        let cancelled = Operation::new(end(), &cancel);
        let expired_cancel = AtomicBool::new(false);
        let expired = Operation::new(Instant::now(), &expired_cancel);
        let calls = AtomicUsize::new(0);
        for (operation, expected) in [
            (&cancelled, domain::Error::Cancelled),
            (&expired, domain::Error::Deadline),
        ] {
            assert_eq!(
                owner.read(operation, |_| {
                    calls.fetch_add(1, SeqCst);
                    Ok(())
                }),
                Err(Error::Domain(expected))
            );
        }
        assert_eq!(calls.load(SeqCst), 0);
    }

    #[test]
    fn returned_records_release_both_locks_before_external_work() {
        let (_directory, owner, id) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let records = owner.workspaces(&operation).unwrap();
        let state = owner.authorization_state(&operation).unwrap();
        assert_eq!(records[0].state.context.workspace_id, id);
        assert!(state.locked);
        let _domain = owner.domain.try_read(&operation).unwrap();
        let _store = owner.store.try_lock().unwrap();
        // Records/state remain usable while an unrelated phase owns both locks.
        assert_eq!(records[0].fence, 0);
        assert!(state.locked);
    }

    #[test]
    fn definite_fence_conflict_allows_next_named_write_and_owned_reads() {
        let (_directory, owner, id) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        assert_eq!(
            owner.begin_share(&operation, id, 1).unwrap().try_commit(),
            Err(Error::Store(StoreError::Fenced))
        );
        assert_eq!(
            owner.begin_share(&operation, id, 0).unwrap().try_commit(),
            Ok(1)
        );
        assert_eq!(
            owner.begin_unshare(&operation, id).unwrap().try_commit(),
            Ok(2)
        );
        assert!(!owner.workspace(&operation, id).unwrap().consent);
        assert_eq!(
            owner
                .begin_remove_workspace(&operation, id)
                .unwrap()
                .try_commit(),
            Ok(3)
        );
        assert!(owner.workspaces(&operation).unwrap().is_empty());
    }

    #[test]
    fn durable_verified_state_and_local_dto_cannot_open_remote_domain() {
        let directory = tempfile::tempdir().unwrap();
        let mut store =
            HostStore::open(&directory.path().join("host.sqlite"), Limits::default()).unwrap();
        store.enable_authorization(0).unwrap();
        let owner = SharedOwner::new(store).unwrap();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let local = owner.authorization_state(&operation).unwrap();
        assert!(!local.locked);
        assert_eq!(
            owner.remote_authorization(&operation).unwrap_err(),
            Error::Domain(domain::Error::Denied)
        );
        assert!(owner.workspaces(&operation).unwrap().is_empty());
    }

    #[test]
    fn unfinished_remote_failure_keeps_named_local_reads_and_writes_available() {
        let (_directory, owner, id) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        drop(owner.begin_share(&operation, id, 0).unwrap());
        assert_eq!(
            owner.remote_authorization(&operation).unwrap_err(),
            Error::Domain(domain::Error::Denied)
        );
        assert_eq!(
            owner.begin_share(&operation, id, 0).unwrap().try_commit(),
            Ok(1)
        );
        assert!(owner.workspace(&operation, id).unwrap().consent);
        assert_eq!(owner.workspaces(&operation).unwrap().len(), 1);
    }

    fn binding(workspace: WorkspaceId, byte: u8) -> OperationBinding {
        use lomi_remote_protocol::{Method, StoredOperationRights};
        OperationBinding {
            rights: StoredOperationRights::new(
                OperationId::from_bytes([byte; 16]).unwrap(),
                ConsumerAuthorizationId::from_bytes([2; 16]).unwrap(),
                workspace,
                Method::TerminalCreate,
                CapabilitySet::control_with_workspace_tools(),
                false,
            )
            .unwrap(),
            parameter_hash: lomi_host_store::parameter_hash(&(workspace, byte)).unwrap(),
        }
    }
    fn rights() -> CapabilitySet {
        CapabilitySet::control_with_workspace_tools()
    }

    #[test]
    fn journal_running_cancel_and_completion_preserve_exact_receipt() {
        let (_directory, owner, id) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let binding = binding(id, 10);
        let admission = owner
            .begin_admit_external(&operation, &binding, DecimalU64(0))
            .unwrap()
            .try_commit()
            .unwrap();
        assert!(admission.newly_admitted);
        let replay = owner
            .begin_admit_external(&operation, &binding, DecimalU64(0))
            .unwrap()
            .try_commit()
            .unwrap();
        assert!(!replay.newly_admitted);
        let permit = owner
            .begin_start_external(&operation, &binding)
            .unwrap()
            .try_commit()
            .unwrap();
        assert!(matches!(
            owner
                .begin_start_external(&operation, &binding)
                .unwrap()
                .try_commit(),
            Err(Error::Store(StoreError::AlreadyStarted))
        ));
        owner.check_external_fence(&operation, &permit).unwrap();
        let rights = rights();
        let foreign = ConsumerAuthorizationId::from_bytes([99; 16]).unwrap();
        assert!(
            owner
                .lookup_operation(
                    &operation,
                    foreign,
                    id,
                    binding.rights.operation_id(),
                    &rights
                )
                .unwrap()
                .is_none()
        );
        assert!(
            owner
                .begin_cancel_operation(
                    &operation,
                    foreign,
                    id,
                    binding.rights.operation_id(),
                    &rights
                )
                .unwrap()
                .try_commit()
                .unwrap()
                .is_none()
        );
        let cancelled = owner
            .begin_cancel_operation(
                &operation,
                binding.rights.actor(),
                id,
                binding.rights.operation_id(),
                &rights,
            )
            .unwrap()
            .try_commit()
            .unwrap()
            .unwrap();
        assert_eq!(cancelled.state(), OperationState::Running);
        assert!(cancelled.cancel_requested());
        let completed = owner
            .begin_complete_external(
                &operation,
                &permit,
                OperationState::Failed,
                Effect::None,
                None,
                None,
            )
            .unwrap()
            .try_commit()
            .unwrap();
        assert_eq!(completed.state(), OperationState::Failed);
        assert!(completed.cancel_requested());
        let looked_up = owner
            .lookup_operation(
                &operation,
                binding.rights.actor(),
                id,
                binding.rights.operation_id(),
                &rights,
            )
            .unwrap()
            .unwrap();
        assert_eq!(looked_up, completed);
        assert!(matches!(
            owner
                .begin_complete_external(
                    &operation,
                    &permit,
                    OperationState::Failed,
                    Effect::None,
                    None,
                    None
                )
                .unwrap()
                .try_commit(),
            Err(Error::Store(StoreError::AlreadyStarted))
        ));
        let _domain = owner.domain.try_read(&operation).unwrap();
        let _store = owner.store.try_lock().unwrap();
    }

    #[test]
    fn accepted_cancellation_never_returns_a_start_permit() {
        let (_directory, owner, id) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let binding = binding(id, 11);
        owner
            .begin_admit_external(&operation, &binding, DecimalU64(0))
            .unwrap()
            .try_commit()
            .unwrap();
        let rights = rights();
        let receipt = owner
            .begin_cancel_operation(
                &operation,
                binding.rights.actor(),
                id,
                binding.rights.operation_id(),
                &rights,
            )
            .unwrap()
            .try_commit()
            .unwrap()
            .unwrap();
        assert_eq!(receipt.state(), OperationState::Cancelled);
        assert!(matches!(
            owner
                .begin_start_external(&operation, &binding)
                .unwrap()
                .try_commit(),
            Err(Error::Store(StoreError::AlreadyStarted))
        ));
    }

    #[test]
    fn admission_busy_retries_original_turn_without_duplicate_journal() {
        let (_directory, owner, id) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let binding = binding(id, 12);
        let held = owner.domain.try_read(&operation).unwrap();
        let mut turn = owner
            .begin_admit_external(&operation, &binding, DecimalU64(0))
            .unwrap();
        assert!(matches!(
            turn.try_commit(),
            Err(Error::Domain(domain::Error::Busy))
        ));
        drop(held);
        let held = owner.store.lock().unwrap();
        assert!(matches!(
            turn.try_commit(),
            Err(Error::Domain(domain::Error::Busy))
        ));
        assert!(
            held.lookup_operation(
                binding.rights.actor(),
                id,
                binding.rights.operation_id(),
                &rights()
            )
            .unwrap()
            .is_none()
        );
        drop(held);
        assert!(turn.try_commit().unwrap().newly_admitted);
        assert!(matches!(
            turn.try_commit(),
            Err(Error::Domain(domain::Error::Stale))
        ));
        assert_eq!(
            owner
                .lookup_operation(
                    &operation,
                    binding.rights.actor(),
                    id,
                    binding.rights.operation_id(),
                    &rights()
                )
                .unwrap()
                .unwrap()
                .state(),
            OperationState::Accepted
        );
    }

    #[test]
    fn external_start_retains_actual_permit_through_postview_and_domain_failures() {
        for fault in [
            ExternalStartFault::PostView(StoreError::Storage),
            ExternalStartFault::PostView(StoreError::Busy),
            ExternalStartFault::PostActionDeadline,
            ExternalStartFault::FinishDeadline,
        ] {
            let (_directory, owner, id) = fixture();
            let cancel = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancel);
            let binding = binding(id, 91);
            owner
                .begin_admit_external(&operation, &binding, DecimalU64(0))
                .unwrap()
                .try_commit()
                .unwrap();
            let before = owner
                .store
                .lock()
                .unwrap()
                .events_after(0)
                .unwrap()
                .events
                .len();
            let mut start = owner.begin_start_external(&operation, &binding).unwrap();
            start.fault = Some(fault);
            assert!(start.take_started_permit().is_none());
            let expected = match fault {
                ExternalStartFault::PostView(error) => Error::UncertainStore(error),
                ExternalStartFault::PostActionDeadline => Error::Domain(domain::Error::Deadline),
                ExternalStartFault::FinishDeadline => Error::Domain(domain::Error::Unfinished),
            };
            assert_eq!(start.try_commit().unwrap_err(), expected);
            assert!(start.started.is_some());
            assert_eq!(start.starts, 1);
            assert!(std::ptr::eq(start.operation, &operation));
            let state = super::super::owner_domain::cloud_no_effect_state_for_test(&owner.domain);
            assert!(state.2); // Uncertain/failed finalization cannot restore Ready.
            if !matches!(fault, ExternalStartFault::FinishDeadline) {
                assert!(start.pending.is_some());
                assert_eq!(state.0, 1);
            }
            assert_eq!(start.try_commit().unwrap_err(), expected);
            let permit = start
                .take_started_permit()
                .expect("actual committed Running permit retained");
            assert!(start.take_started_permit().is_none());
            assert!(start.pending.is_none());
            assert_eq!(start.try_commit().unwrap_err(), expected);
            assert_eq!(start.starts, 1);
            let state = super::super::owner_domain::cloud_no_effect_state_for_test(&owner.domain);
            assert_eq!(state.0, 0);
            assert!(state.2);
            // The retained object is the real original Runtime/fence permit:
            // Store recognizes it, and only one actual start event was added.
            let store = owner.store.lock().unwrap();
            store.check_external_fence(&permit).unwrap();
            assert_eq!(store.events_after(0).unwrap().events.len(), before + 1);
            let receipt = store
                .lookup_operation(
                    binding.rights.actor(),
                    id,
                    binding.rights.operation_id(),
                    &rights(),
                )
                .unwrap()
                .unwrap();
            assert_eq!(receipt.state(), OperationState::Running);
            drop(store);
            if matches!(
                fault,
                ExternalStartFault::PostActionDeadline | ExternalStartFault::FinishDeadline
            ) {
                assert_eq!(
                    owner.check_external_fence(&operation, &permit),
                    Err(Error::Domain(domain::Error::Deadline))
                );
            }
            // No physical-effect callback is invoked: an Err branch hands the
            // actual object to reconciliation, never to the successful branch.
        }
    }

    #[test]
    fn external_start_busy_keeps_original_writer_and_executes_once() {
        let (_directory, owner, id) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let binding = binding(id, 92);
        owner
            .begin_admit_external(&operation, &binding, DecimalU64(0))
            .unwrap()
            .try_commit()
            .unwrap();
        let mut start = owner.begin_start_external(&operation, &binding).unwrap();
        let pending = start.pending.as_ref().unwrap() as *const _;
        {
            let held = owner.domain.try_read(&operation).unwrap();
            assert_eq!(
                start.try_commit().unwrap_err(),
                Error::Domain(domain::Error::Busy)
            );
            drop(held);
        }
        {
            let held = owner.store.lock().unwrap();
            assert_eq!(
                start.try_commit().unwrap_err(),
                Error::Domain(domain::Error::Busy)
            );
            drop(held);
        }
        assert!(std::ptr::eq(start.operation, &operation));
        assert_eq!(start.pending.as_ref().unwrap() as *const _, pending);
        assert_eq!(start.starts, 0);
        assert!(start.take_started_permit().is_none());
        let permit = start.try_commit().unwrap();
        assert_eq!(start.starts, 1);
        assert!(start.take_started_permit().is_none());
        assert_eq!(
            start.try_commit().unwrap_err(),
            Error::Domain(domain::Error::Stale)
        );
        assert_eq!(start.starts, 1);
        owner.check_external_fence(&operation, &permit).unwrap();
    }

    #[test]
    fn expiry_between_admission_and_start_preserves_accepted_intent() {
        let (_directory, owner, id) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let binding = binding(id, 13);
        owner
            .begin_admit_external(&operation, &binding, DecimalU64(0))
            .unwrap()
            .try_commit()
            .unwrap();
        let held = owner.store.lock().unwrap();
        let mut start = owner.begin_start_external(&operation, &binding).unwrap();
        assert!(matches!(
            start.try_commit(),
            Err(Error::Domain(domain::Error::Busy))
        ));
        operation.expire_for_test();
        assert!(matches!(
            start.try_commit(),
            Err(Error::Domain(domain::Error::Deadline))
        ));
        drop(held);
        let fresh = Operation::new(end(), &cancel);
        let receipt = owner
            .lookup_operation(
                &fresh,
                binding.rights.actor(),
                id,
                binding.rights.operation_id(),
                &rights(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(receipt.state(), OperationState::Accepted);
    }

    #[test]
    fn definite_revision_rejection_allows_corrected_named_admission() {
        let (_directory, owner, id) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let binding = binding(id, 14);
        assert!(matches!(
            owner
                .begin_admit_external(&operation, &binding, DecimalU64(1))
                .unwrap()
                .try_commit(),
            Err(Error::Store(StoreError::RevisionConflict))
        ));
        assert!(
            owner
                .begin_admit_external(&operation, &binding, DecimalU64(0))
                .unwrap()
                .try_commit()
                .unwrap()
                .newly_admitted
        );
    }

    #[test]
    fn completion_expiry_preserves_running_intent_without_new_budget() {
        let (_directory, owner, id) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let binding = binding(id, 15);
        owner
            .begin_admit_external(&operation, &binding, DecimalU64(0))
            .unwrap()
            .try_commit()
            .unwrap();
        let permit = owner
            .begin_start_external(&operation, &binding)
            .unwrap()
            .try_commit()
            .unwrap();
        owner
            .begin_unshare(&operation, id)
            .unwrap()
            .try_commit()
            .unwrap();
        assert_eq!(
            owner.check_external_fence(&operation, &permit),
            Err(Error::Store(StoreError::Fenced))
        );
        let held = owner.store.lock().unwrap();
        let mut completion = owner
            .begin_complete_external(
                &operation,
                &permit,
                OperationState::OutcomeUnknown,
                Effect::Unknown,
                None,
                None,
            )
            .unwrap();
        assert!(matches!(
            completion.try_commit(),
            Err(Error::Domain(domain::Error::Busy))
        ));
        operation.expire_for_test();
        assert!(matches!(
            completion.try_commit(),
            Err(Error::Domain(domain::Error::Deadline))
        ));
        drop(held);
        let fresh = Operation::new(end(), &cancel);
        let receipt = owner
            .lookup_operation(
                &fresh,
                binding.rights.actor(),
                id,
                binding.rights.operation_id(),
                &rights(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(receipt.state(), OperationState::Running);
        assert_eq!(receipt.effect(), Effect::None);
    }

    #[test]
    fn exact_terminal_exit_and_retirement_use_journal_projection_without_pty() {
        use lomi_remote_protocol::{
            PaneId, SessionEpoch, TabId, TerminalProfile, TerminalSessionId,
            rpc::{BoundedList, PaneState, TerminalLayout, TerminalPane, TerminalTab},
        };
        let (_directory, owner, id) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let binding = binding(id, 16);
        let mut state = owner.workspace(&operation, id).unwrap().state;
        owner
            .begin_admit_external(&operation, &binding, state.domain_revision)
            .unwrap()
            .try_commit()
            .unwrap();
        let permit = owner
            .begin_start_external(&operation, &binding)
            .unwrap()
            .try_commit()
            .unwrap();
        let terminal = TerminalContext {
            workspace: state.context.clone(),
            pane_id: PaneId::from_bytes([3; 16]).unwrap(),
            session_id: TerminalSessionId::from_bytes([4; 16]).unwrap(),
            session_epoch: SessionEpoch::from_bytes([5; 16]).unwrap(),
            profile: TerminalProfile::ExperimentalRustGridV1,
        };
        state.domain_revision = DecimalU64(1);
        state.tabs = BoundedList(vec![TerminalTab {
            tab_id: TabId::from_bytes([6; 16]).unwrap(),
            name: "Test".to_owned().try_into().unwrap(),
            layout: TerminalLayout::Pane {
                pane: TerminalPane {
                    pane_id: terminal.pane_id,
                    session: Some(terminal.clone()),
                    state: PaneState::Running,
                },
            },
        }]);
        owner
            .begin_complete_external(
                &operation,
                &permit,
                OperationState::Succeeded,
                Effect::Committed,
                Some(OperationResult::Terminal {
                    domain_revision: state.domain_revision,
                    pane_id: terminal.pane_id,
                    session_id: terminal.session_id,
                    session_epoch: terminal.session_epoch,
                }),
                Some(state),
            )
            .unwrap()
            .try_commit()
            .unwrap();
        assert!(
            !owner
                .begin_terminal_retired(&operation, &terminal)
                .unwrap()
                .try_commit()
                .unwrap()
        );
        assert!(
            owner
                .begin_terminal_exit(&operation, &terminal)
                .unwrap()
                .try_commit()
                .unwrap()
        );
        assert!(
            !owner
                .begin_terminal_exit(&operation, &terminal)
                .unwrap()
                .try_commit()
                .unwrap()
        );
        let mut foreign = terminal.clone();
        foreign.session_epoch = SessionEpoch::from_bytes([9; 16]).unwrap();
        assert!(
            !owner
                .begin_terminal_retired(&operation, &foreign)
                .unwrap()
                .try_commit()
                .unwrap()
        );
        assert!(
            owner
                .begin_terminal_retired(&operation, &terminal)
                .unwrap()
                .try_commit()
                .unwrap()
        );
        assert!(
            !owner
                .begin_terminal_retired(&operation, &terminal)
                .unwrap()
                .try_commit()
                .unwrap()
        );
        let workspace = owner.workspace(&operation, id).unwrap();
        assert_eq!(workspace.state.domain_revision, DecimalU64(3));
        let TerminalLayout::Pane { pane } = &workspace.state.tabs.0[0].layout else {
            panic!("pane")
        };
        assert_eq!(pane.state, PaneState::Stopped);
        assert!(pane.session.is_none());
        let _domain = owner.domain.try_read(&operation).unwrap();
        let _store = owner.store.try_lock().unwrap();
    }
    #[test]
    fn add_preparation_needs_neither_domain_nor_store_lock() {
        let (directory, owner, _id) = fixture();
        let added_root = directory.path().join("added-project");
        std::fs::create_dir(&added_root).unwrap();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let domain = owner.domain.try_read(&operation).unwrap();
        let store = owner.store.lock().unwrap();
        let mut turn = owner
            .begin_add_project(
                &operation,
                &added_root,
                "Added".to_owned().try_into().unwrap(),
            )
            .unwrap();
        assert!(matches!(
            turn.try_commit(),
            Err(Error::Domain(domain::Error::Busy))
        ));
        drop(domain);
        assert!(matches!(
            turn.try_commit(),
            Err(Error::Domain(domain::Error::Busy))
        ));
        assert_eq!(store.list_projects().unwrap().len(), 1);
        drop(store);
        let record = turn.try_commit().unwrap();
        assert_eq!(record.local_root, added_root.canonicalize().unwrap());
        assert!(matches!(
            turn.try_commit(),
            Err(Error::Domain(domain::Error::Stale))
        ));
        assert_eq!(owner.workspaces(&operation).unwrap().len(), 2);
    }

    #[test]
    fn add_busy_expiry_uses_original_operation_and_creates_no_row() {
        let (directory, owner, _id) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let store = owner.store.lock().unwrap();
        let mut turn = owner
            .begin_add_project(
                &operation,
                directory.path(),
                "Added".to_owned().try_into().unwrap(),
            )
            .unwrap();
        assert!(matches!(
            turn.try_commit(),
            Err(Error::Domain(domain::Error::Busy))
        ));
        operation.expire_for_test();
        assert!(matches!(
            turn.try_commit(),
            Err(Error::Domain(domain::Error::Deadline))
        ));
        assert!(matches!(
            turn.try_commit(),
            Err(Error::Domain(domain::Error::Stale))
        ));
        drop(store);
        let fresh = Operation::new(end(), &cancel);
        assert_eq!(owner.workspaces(&fresh).unwrap().len(), 1);
    }

    #[test]
    fn add_busy_cancellation_stays_terminal_after_latch_reset() {
        let (directory, owner, _id) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let store = owner.store.lock().unwrap();
        let mut turn = owner
            .begin_add_project(
                &operation,
                directory.path(),
                "Added".to_owned().try_into().unwrap(),
            )
            .unwrap();
        assert!(matches!(
            turn.try_commit(),
            Err(Error::Domain(domain::Error::Busy))
        ));
        cancel.store(true, SeqCst);
        assert!(matches!(
            turn.try_commit(),
            Err(Error::Domain(domain::Error::Cancelled))
        ));
        cancel.store(false, SeqCst);
        drop(store);
        assert!(matches!(
            turn.try_commit(),
            Err(Error::Domain(domain::Error::Stale))
        ));
        let fresh = Operation::new(end(), &cancel);
        assert_eq!(owner.workspaces(&fresh).unwrap().len(), 1);
    }

    #[test]
    fn add_expired_before_preparation_and_invalid_root_create_no_row() {
        let (directory, owner, _id) = fixture();
        let cancel = AtomicBool::new(false);
        let expired = Operation::new(Instant::now(), &cancel);
        let missing = directory.path().join("missing");
        assert!(matches!(
            owner.begin_add_project(&expired, &missing, "Added".to_owned().try_into().unwrap()),
            Err(Error::Domain(domain::Error::Deadline))
        ));
        let fresh = Operation::new(end(), &cancel);
        assert!(matches!(
            owner.begin_add_project(&fresh, &missing, "Added".to_owned().try_into().unwrap()),
            Err(Error::Store(StoreError::Invalid))
        ));
        assert_eq!(owner.workspaces(&fresh).unwrap().len(), 1);
    }

    #[test]
    fn add_commit_uses_prepared_root_without_new_filesystem_work() {
        let (directory, owner, _id) = fixture();
        let root = directory.path().join("prepared");
        std::fs::create_dir(&root).unwrap();
        let expected = root.canonicalize().unwrap();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let mut turn = owner
            .begin_add_project(&operation, &root, "Added".to_owned().try_into().unwrap())
            .unwrap();
        std::fs::remove_dir(&root).unwrap();
        assert_eq!(turn.try_commit().unwrap().local_root, expected);
        assert_eq!(owner.workspaces(&operation).unwrap().len(), 2);
        assert!(matches!(
            owner.remote_authorization(&operation),
            Err(Error::Domain(domain::Error::Denied))
        ));
    }

    #[test]
    fn add_expiry_after_preparation_denies_both_valid_and_invalid_results() {
        let (directory, owner, _id) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let prepared = prepare_project_root(directory.path());
        assert!(prepared.is_ok());
        // Expire deterministically between filesystem preparation and its
        // checked handoff, without a sleep, helper thread or filesystem hook.
        operation.expire_for_test();
        assert!(matches!(
            owner.begin_prepared_project(
                &operation,
                prepared,
                "Added".to_owned().try_into().unwrap()
            ),
            Err(Error::Domain(domain::Error::Deadline))
        ));
        assert!(matches!(
            owner.begin_prepared_project(
                &operation,
                Err(StoreError::Invalid),
                "Added".to_owned().try_into().unwrap()
            ),
            Err(Error::Domain(domain::Error::Deadline))
        ));
        let fresh = Operation::new(end(), &cancel);
        assert_eq!(owner.workspaces(&fresh).unwrap().len(), 1);
    }

    fn auth_config() -> LocalAuthConfiguration {
        LocalAuthConfiguration {
            version: 1,
            origin: "https://identity.example".to_owned().try_into().unwrap(),
            remote_api_origin: None,
            relay_endpoint: None,
            client_id: "lomi-remote-host".to_owned().try_into().unwrap(),
            provider: crate::testsupport::provider(),
            keychain_path: None,
            protected_file_acknowledgement: crate::testsupport::file_acknowledgement(),
        }
    }
    fn configured_auth_fixture() -> (tempfile::TempDir, Arc<SharedOwner>, LocalAuthConfiguration) {
        let (directory, owner, _id) = fixture();
        let config = auth_config();
        // Legacy configuration is used only to seed existing Store test data.
        // This proposal exposes no owner adapter for configuring authentication.
        owner.store.lock().unwrap().configure_auth(&config).unwrap();
        (directory, owner, config)
    }
    fn assert_auth_closed(owner: &SharedOwner, operation: &Operation<'_>) {
        assert!(matches!(
            owner.remote_authorization(operation),
            Err(Error::Domain(domain::Error::Denied))
        ));
    }

    #[test]
    fn auth_snapshots_are_owned_and_release_both_locks() {
        let (_directory, owner, config) = configured_auth_fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let seeded_cloud_history = owner.auth_history(&operation).unwrap().cloud_may_exist;
        assert_eq!(seeded_cloud_history, Some(false));
        let identity = owner.identity(&operation).unwrap();
        let status = owner.auth_status(&operation).unwrap();
        let selection = owner.auth_selection(&operation).unwrap();
        let history = owner.auth_history(&operation).unwrap();
        let domain = owner.domain.try_read(&operation).unwrap();
        let store = owner.store.try_lock().unwrap();
        assert_eq!(identity.host_id, selection.identity.host_id);
        assert_eq!(identity.profile_id, selection.identity.profile_id);
        assert_eq!(identity.host_id, store.identity().host_id);
        assert_eq!(selection.configuration, Some(config));
        assert_eq!(selection.verified_generation, None);
        assert_eq!(status.authorization, history.authorization);
        assert_eq!(status.intent, None);
        assert_eq!(history.cloud_may_exist, seeded_cloud_history);
        drop(store);
        drop(domain);
        assert_auth_closed(&owner, &operation);
    }

    #[test]
    fn auth_snapshot_busy_deadline_and_cancellation_do_not_escape_guards() {
        let (_directory, owner, _id) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let held = owner.store.lock().unwrap();
        assert!(matches!(
            owner.identity(&operation),
            Err(Error::Domain(domain::Error::Busy))
        ));
        assert!(matches!(
            owner.auth_status(&operation),
            Err(Error::Domain(domain::Error::Busy))
        ));
        assert!(matches!(
            owner.auth_selection(&operation),
            Err(Error::Domain(domain::Error::Busy))
        ));
        assert!(matches!(
            owner.auth_history(&operation),
            Err(Error::Domain(domain::Error::Busy))
        ));
        drop(held);
        operation.expire_for_test();
        assert!(matches!(
            owner.auth_status(&operation),
            Err(Error::Domain(domain::Error::Deadline))
        ));
        cancel.store(true, SeqCst);
        let cancelled = Operation::new(end(), &cancel);
        assert!(matches!(
            owner.auth_history(&cancelled),
            Err(Error::Domain(domain::Error::Cancelled))
        ));
    }

    #[test]
    fn login_rechecks_exact_configuration_at_commit_without_intent_on_denial() {
        let (_directory, owner, config) = configured_auth_fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let generation = owner
            .auth_status(&operation)
            .unwrap()
            .authorization
            .generation;
        let mut turn = owner
            .begin_login(
                &operation,
                OperationId::from_bytes([70; 16]).unwrap(),
                config.clone(),
                generation,
            )
            .unwrap();
        let mut changed = config;
        changed.remote_api_origin = Some("https://remote.example".to_owned().try_into().unwrap());
        owner
            .store
            .lock()
            .unwrap()
            .configure_auth(&changed)
            .unwrap();
        assert_eq!(turn.try_commit(), Err(Error::Store(StoreError::Fenced)));
        assert_eq!(owner.auth_status(&operation).unwrap().intent, None);
        assert_auth_closed(&owner, &operation);
    }

    #[test]
    fn login_rechecks_generation_and_retries_one_turn_after_both_busy_locks() {
        let (_directory, owner, config) = configured_auth_fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let generation = owner
            .auth_status(&operation)
            .unwrap()
            .authorization
            .generation;
        let held = owner.domain.try_read(&operation).unwrap();
        let operation_id = OperationId::from_bytes([71; 16]).unwrap();
        let mut turn = owner
            .begin_login(&operation, operation_id, config.clone(), generation)
            .unwrap();
        assert_eq!(turn.try_commit(), Err(Error::Domain(domain::Error::Busy)));
        drop(held);
        let held = owner.store.lock().unwrap();
        assert_eq!(turn.try_commit(), Err(Error::Domain(domain::Error::Busy)));
        assert_eq!(held.login_intent().unwrap(), None);
        drop(held);
        let intent = turn.try_commit().unwrap();
        assert_eq!(intent.operation_id, operation_id);
        assert_eq!(turn.try_commit(), Err(Error::Domain(domain::Error::Stale)));
        owner
            .begin_local_logout(&operation)
            .unwrap()
            .try_commit()
            .unwrap();
        assert_eq!(
            owner
                .begin_login(&operation, operation_id, config, generation)
                .unwrap()
                .try_commit(),
            Err(Error::Store(StoreError::Fenced))
        );
        assert_eq!(owner.auth_status(&operation).unwrap().intent, None);
        assert_auth_closed(&owner, &operation);
    }

    #[test]
    fn auth_busy_expiry_and_cancel_preserve_original_operation() {
        let (_directory, owner, _config) = configured_auth_fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let seeded_cloud_history = owner.auth_history(&operation).unwrap().cloud_may_exist;
        assert_eq!(seeded_cloud_history, Some(false));
        let generation = owner
            .auth_status(&operation)
            .unwrap()
            .authorization
            .generation;
        let held = owner.store.lock().unwrap();
        let mut turn = owner
            .begin_mark_cloud_authorization_possible(&operation, generation)
            .unwrap();
        assert_eq!(turn.try_commit(), Err(Error::Domain(domain::Error::Busy)));
        operation.expire_for_test();
        assert_eq!(
            turn.try_commit(),
            Err(Error::Domain(domain::Error::Deadline))
        );
        assert_eq!(turn.try_commit(), Err(Error::Domain(domain::Error::Stale)));
        drop(held);
        let fresh = Operation::new(end(), &cancel);
        assert_eq!(
            owner.auth_history(&fresh).unwrap().cloud_may_exist,
            seeded_cloud_history
        );
        let held = owner.store.lock().unwrap();
        let mut turn = owner
            .begin_observe_authorization_clock(&fresh, 500)
            .unwrap();
        assert_eq!(turn.try_commit(), Err(Error::Domain(domain::Error::Busy)));
        cancel.store(true, SeqCst);
        assert_eq!(
            turn.try_commit(),
            Err(Error::Domain(domain::Error::Cancelled))
        );
        cancel.store(false, SeqCst);
        drop(held);
        assert_eq!(turn.try_commit(), Err(Error::Domain(domain::Error::Stale)));
        let final_operation = Operation::new(end(), &cancel);
        assert_eq!(
            owner
                .auth_history(&final_operation)
                .unwrap()
                .cloud_may_exist,
            seeded_cloud_history
        );
        assert_auth_closed(&owner, &final_operation);
        assert_eq!(
            owner
                .auth_status(&final_operation)
                .unwrap()
                .authorization
                .clock_floor,
            0
        );
    }

    #[test]
    fn suspend_fenced_source_observes_self_sealed_post_state_and_preserves_generation() {
        let (_directory, owner, _config) = configured_auth_fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let generation = owner
            .auth_status(&operation)
            .unwrap()
            .authorization
            .generation;
        assert_eq!(
            owner
                .begin_suspend_authorization(&operation, generation + 1)
                .unwrap()
                .try_commit(),
            Err(Error::Store(StoreError::Fenced))
        );
        let status = owner.auth_status(&operation).unwrap();
        assert!(status.authorization.locked);
        assert_eq!(status.authorization.generation, generation);
        let suspended = owner
            .begin_suspend_authorization(&operation, generation)
            .unwrap()
            .try_commit()
            .unwrap();
        assert_eq!(suspended.generation, generation);
        assert!(suspended.locked);
        assert_auth_closed(&owner, &operation);
    }

    #[test]
    fn all_named_auth_primitives_leave_remote_closed() {
        let (_directory, owner, config) = configured_auth_fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let generation = owner
            .auth_status(&operation)
            .unwrap()
            .authorization
            .generation;
        owner
            .begin_login(
                &operation,
                OperationId::from_bytes([72; 16]).unwrap(),
                config,
                generation,
            )
            .unwrap()
            .try_commit()
            .unwrap();
        assert_auth_closed(&owner, &operation);
        assert_eq!(
            owner
                .begin_observe_authorization_clock(&operation, 99)
                .unwrap()
                .try_commit(),
            Ok(99)
        );
        assert_eq!(
            owner
                .begin_observe_authorization_clock(&operation, 1)
                .unwrap()
                .try_commit(),
            Ok(99)
        );
        assert_auth_closed(&owner, &operation);
        owner
            .begin_mark_cloud_authorization_possible(&operation, generation)
            .unwrap()
            .try_commit()
            .unwrap();
        assert_eq!(
            owner.auth_history(&operation).unwrap().cloud_may_exist,
            Some(true)
        );
        assert_auth_closed(&owner, &operation);
        owner
            .begin_suspend_authorization(&operation, generation)
            .unwrap()
            .try_commit()
            .unwrap();
        assert_auth_closed(&owner, &operation);
        let logout = owner
            .begin_local_logout(&operation)
            .unwrap()
            .try_commit()
            .unwrap();
        assert_eq!(logout.generation, generation + 1);
        assert!(logout.pending_cloud_revoke);
        assert_auth_closed(&owner, &operation);
        assert_eq!(
            owner
                .begin_acknowledge_local_authorization_logout(&operation, logout.generation)
                .unwrap()
                .try_commit(),
            Err(Error::Store(StoreError::Fenced))
        );
        owner
            .begin_acknowledge_authorization_revoke(&operation, logout.generation)
            .unwrap()
            .try_commit()
            .unwrap();
        assert_eq!(
            owner.auth_history(&operation).unwrap().cloud_may_exist,
            Some(false)
        );
        assert_auth_closed(&owner, &operation);
        let logout = owner
            .begin_local_logout(&operation)
            .unwrap()
            .try_commit()
            .unwrap();
        owner
            .begin_acknowledge_local_authorization_logout(&operation, logout.generation)
            .unwrap()
            .try_commit()
            .unwrap();
        assert!(
            !owner
                .auth_status(&operation)
                .unwrap()
                .authorization
                .pending_cloud_revoke
        );
        assert_auth_closed(&owner, &operation);
        let rejected = owner
            .begin_authority_rejection(&operation, logout.generation)
            .unwrap()
            .try_commit()
            .unwrap();
        assert_eq!(rejected.generation, logout.generation + 1);
        assert_auth_closed(&owner, &operation);
        owner
            .begin_seal_authorization(&operation)
            .unwrap()
            .try_commit()
            .unwrap();
        assert_auth_closed(&owner, &operation);
        owner
            .begin_record_clean_shutdown(&operation)
            .unwrap()
            .try_commit()
            .unwrap();
        assert_auth_closed(&owner, &operation);
    }

    #[test]
    fn stale_authority_rejection_does_not_advance_generation_again() {
        let (_directory, owner, _config) = configured_auth_fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let generation = owner
            .auth_status(&operation)
            .unwrap()
            .authorization
            .generation;
        let logout = owner
            .begin_local_logout(&operation)
            .unwrap()
            .try_commit()
            .unwrap();
        assert_eq!(
            owner
                .begin_authority_rejection(&operation, generation)
                .unwrap()
                .try_commit(),
            Err(Error::Store(StoreError::Fenced))
        );
        assert_eq!(
            owner
                .auth_status(&operation)
                .unwrap()
                .authorization
                .generation,
            logout.generation
        );
        assert_auth_closed(&owner, &operation);
    }

    #[test]
    fn stale_rejection_after_new_generation_keeps_current_scope_eligible() {
        let (_directory, owner, _config) = configured_auth_fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let old = owner
            .auth_status(&operation)
            .unwrap()
            .authorization
            .generation;
        let held = owner.store.lock().unwrap();
        let mut delayed = owner.begin_authority_rejection(&operation, old).unwrap();
        assert_eq!(
            delayed.try_commit(),
            Err(Error::Domain(domain::Error::Busy))
        );
        drop(held);
        let current = owner
            .begin_local_logout(&operation)
            .unwrap()
            .try_commit()
            .unwrap();
        owner
            .begin_acknowledge_authorization_revoke(&operation, current.generation)
            .unwrap()
            .try_commit()
            .unwrap();
        assert_eq!(delayed.try_commit(), Err(Error::Store(StoreError::Fenced)));
        assert_eq!(
            delayed.try_commit(),
            Err(Error::Domain(domain::Error::Stale))
        );
        assert_eq!(
            owner
                .auth_status(&operation)
                .unwrap()
                .authorization
                .generation,
            current.generation
        );
        // Synthetic mechanical eligibility only: no provider response is used,
        // no scope is committed, and this does not establish remote Ready.
        let mut verification = owner
            .domain
            .announce(&operation, WriterClass::Remote, Intent::VerifyRemote)
            .unwrap();
        let mut guard = verification.try_enter().unwrap();
        let store = owner.store.lock().unwrap();
        assert!(
            guard
                .prepare_verification(current.generation, || StoreView::read(&store))
                .is_ok()
        );
    }

    #[test]
    fn matching_rejection_is_a_real_generation_fence() {
        let (_directory, owner, _config) = configured_auth_fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let old = owner
            .auth_status(&operation)
            .unwrap()
            .authorization
            .generation;
        let rejected = owner
            .begin_authority_rejection(&operation, old)
            .unwrap()
            .try_commit()
            .unwrap();
        assert_eq!(rejected.generation, old + 1);
        assert!(rejected.locked);
        assert!(!rejected.pending_cloud_revoke);
        // Attempt only a mechanical old-generation scope, not provider proof.
        let mut verification = owner
            .domain
            .announce(&operation, WriterClass::Remote, Intent::VerifyRemote)
            .unwrap();
        let mut guard = verification.try_enter().unwrap();
        let store = owner.store.lock().unwrap();
        assert!(matches!(
            guard.prepare_verification(old, || StoreView::read(&store)),
            Err(StepError::Domain(domain::Error::Stale))
        ));
    }

    #[test]
    fn credential_rejection_atomically_defers_active_login_until_typed_ack() {
        let (_directory, owner, config) = configured_auth_fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let generation = owner
            .auth_status(&operation)
            .unwrap()
            .authorization
            .generation;
        let operation_id = OperationId::from_bytes([91; 16]).unwrap();
        let active = owner
            .begin_login(&operation, operation_id, config.clone(), generation)
            .unwrap()
            .try_commit()
            .unwrap();

        let rejected = owner
            .begin_credential_rejection(&operation, generation, config.clone())
            .unwrap()
            .try_commit()
            .unwrap();
        assert_eq!(rejected.generation, generation + 1);
        assert!(rejected.locked && rejected.pending_cloud_revoke);
        let status = owner.auth_status(&operation).unwrap();
        assert_eq!(status.intent, None);
        assert_eq!(
            status.deferred_intent,
            Some(LoginIntent {
                operation_id: active.operation_id,
                generation: rejected.generation,
            })
        );
        assert_eq!(
            owner
                .begin_login(
                    &operation,
                    OperationId::from_bytes([92; 16]).unwrap(),
                    config,
                    rejected.generation,
                )
                .unwrap()
                .try_commit(),
            Ok(status.deferred_intent.unwrap())
        );

        let acknowledged = owner
            .begin_acknowledge_authorization_revoke(&operation, rejected.generation)
            .unwrap()
            .try_commit()
            .unwrap();
        let promoted = owner.auth_status(&operation).unwrap();
        assert_eq!(acknowledged.generation, rejected.generation);
        assert!(acknowledged.locked && !acknowledged.pending_cloud_revoke);
        assert_eq!(promoted.intent, status.deferred_intent);
        assert_eq!(promoted.deferred_intent, None);
        assert_auth_closed(&owner, &operation);
    }

    #[test]
    fn passive_credential_rejection_defers_only_after_explicit_login() {
        let (_directory, owner, config) = configured_auth_fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let generation = owner
            .auth_status(&operation)
            .unwrap()
            .authorization
            .generation;
        let rejected = owner
            .begin_credential_rejection(&operation, generation, config.clone())
            .unwrap()
            .try_commit()
            .unwrap();
        assert_eq!(rejected.generation, generation + 1);
        assert!(rejected.locked && !rejected.pending_cloud_revoke);
        let status = owner.auth_status(&operation).unwrap();
        assert_eq!(status.intent, None);
        assert_eq!(status.deferred_intent, None);

        let requested = owner
            .begin_login(
                &operation,
                OperationId::from_bytes([93; 16]).unwrap(),
                config.clone(),
                rejected.generation,
            )
            .unwrap()
            .try_commit()
            .unwrap();
        let pending = owner.auth_status(&operation).unwrap();
        assert!(
            owner
                .authorization_state(&operation)
                .unwrap()
                .pending_cloud_revoke
        );
        assert_eq!(pending.intent, None);
        assert_eq!(pending.deferred_intent, Some(requested));
        assert_eq!(
            owner
                .begin_login(
                    &operation,
                    OperationId::from_bytes([94; 16]).unwrap(),
                    config,
                    rejected.generation,
                )
                .unwrap()
                .try_commit(),
            Ok(requested)
        );
        assert_eq!(
            owner
                .begin_acknowledge_local_authorization_logout(&operation, rejected.generation)
                .unwrap()
                .try_commit(),
            Err(Error::Store(StoreError::Fenced))
        );
        let acknowledged = owner
            .begin_acknowledge_authorization_revoke(&operation, rejected.generation)
            .unwrap()
            .try_commit()
            .unwrap();
        let promoted = owner.auth_status(&operation).unwrap();
        assert!(!acknowledged.pending_cloud_revoke && acknowledged.locked);
        assert_eq!(promoted.intent, Some(requested));
        assert_eq!(promoted.deferred_intent, None);
        assert_auth_closed(&owner, &operation);
    }

    #[test]
    fn cancelled_credential_rejection_does_not_mutate_store() {
        let (_directory, owner, config) = configured_auth_fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let before = owner.auth_status(&operation).unwrap();
        let mut write = owner
            .begin_credential_rejection(&operation, before.authorization.generation, config)
            .unwrap();

        cancel.store(true, SeqCst);
        assert_eq!(
            write.try_commit(),
            Err(Error::Domain(domain::Error::Cancelled))
        );
        cancel.store(false, SeqCst);

        let fresh = Operation::new(end(), &cancel);
        let after = owner.auth_status(&fresh).unwrap();
        assert_eq!(after.authorization, before.authorization);
        assert_eq!(after.intent, before.intent);
        assert_eq!(after.deferred_intent, before.deferred_intent);
        assert_eq!(
            owner.remote_authorization(&fresh),
            Err(Error::Domain(domain::Error::Denied))
        );
    }

    #[test]
    fn credential_rejection_rechecks_generation_and_exact_configuration_before_arm() {
        let (_directory, owner, config) = configured_auth_fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let generation = owner
            .auth_status(&operation)
            .unwrap()
            .authorization
            .generation;
        let mut changed = config.clone();
        changed.remote_api_origin =
            Some("https://new-remote.example".to_owned().try_into().unwrap());
        owner
            .store
            .lock()
            .unwrap()
            .configure_auth(&changed)
            .unwrap();
        assert_eq!(
            owner
                .begin_credential_rejection(&operation, generation, config.clone())
                .unwrap()
                .try_commit(),
            Err(Error::Store(StoreError::Fenced))
        );
        let current_generation = owner
            .auth_status(&operation)
            .unwrap()
            .authorization
            .generation;
        assert_eq!(current_generation, generation);
        assert_eq!(
            owner
                .begin_credential_rejection(&operation, generation + 1, changed.clone())
                .unwrap()
                .try_commit(),
            Err(Error::Store(StoreError::Fenced))
        );
        let current = owner.auth_status(&operation).unwrap().authorization;
        assert_eq!(current.generation, generation);
        assert!(!current.pending_cloud_revoke);

        let mut verification = owner
            .domain
            .announce(&operation, WriterClass::Remote, Intent::VerifyRemote)
            .unwrap();
        let mut guard = verification.try_enter().unwrap();
        let store = owner.store.lock().unwrap();
        assert!(
            guard
                .prepare_verification(generation, || StoreView::read(&store))
                .is_ok()
        );
    }

    // Authored/unrun. Real HostAuth transitions; scripted HTTP is cfg(test) only.
    #[derive(Default)]
    struct ReadyTestCounts {
        loads: std::cell::Cell<usize>,
        statuses: std::cell::Cell<usize>,
        writes: std::cell::Cell<usize>,
    }
    struct ReadyTestStorage {
        bytes: Option<Vec<u8>>,
        counts: std::rc::Rc<ReadyTestCounts>,
        effect: std::rc::Rc<std::cell::Cell<u8>>,
        owner: Arc<SharedOwner>,
    }
    impl lomi_platform::secrets::SecretStorage for ReadyTestStorage {
        fn status(&self) -> lomi_platform::secrets::ProviderStatus {
            self.counts.statuses.set(self.counts.statuses.get() + 1);
            lomi_platform::secrets::ProviderStatus {
                kind: Some(crate::testsupport::provider_kind()),
                state: lomi_platform::secrets::StorageState::Available,
            }
        }
        fn load(
            &self,
        ) -> Result<Option<lomi_platform::secrets::SecretBundle>, lomi_platform::secrets::Error>
        {
            self.counts.loads.set(self.counts.loads.get() + 1);
            self.bytes
                .clone()
                .map(lomi_platform::secrets::SecretBundle::new)
                .transpose()
        }
        fn replace(
            &mut self,
            bundle: &lomi_platform::secrets::SecretBundle,
        ) -> Result<(), lomi_platform::secrets::Error> {
            let cancelled = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancelled);
            // Actual provider replacement rendezvous: BOTH locks are available.
            assert!(self.owner.domain.try_read(&operation).is_ok());
            assert!(self.owner.store.try_lock().is_ok());
            self.counts.writes.set(self.counts.writes.get() + 1);
            let effect = self.effect.replace(0);
            if effect == 1 || effect == 2 {
                self.owner
                    .begin_local_logout(&operation)
                    .unwrap()
                    .try_commit()
                    .unwrap();
            }
            if effect == 2 {
                return Err(lomi_platform::secrets::Error::CommitUncertain);
            }
            self.bytes = Some(bundle.expose().to_vec());
            Ok(())
        }
    }
    fn ready_test_fixture() -> (
        tempfile::TempDir,
        Arc<SharedOwner>,
        super::super::public_configuration::PublicSetup,
        lomi_host_auth::Config,
    ) {
        #[cfg(unix)]
        let root = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        #[cfg(windows)]
        let root = tempfile::Builder::new()
            .prefix("lomi-worker-native-")
            .tempdir_in(std::env::var_os("USERPROFILE").unwrap())
            .unwrap();
        #[cfg(unix)]
        let profile = root.path().canonicalize().unwrap();
        #[cfg(windows)]
        let profile = root.path().canonicalize().unwrap().join("profile");
        let lock = super::super::platform::OwnerLock::acquire(&profile).unwrap();
        let mut store =
            HostStore::open(&lock.prepare_database().unwrap(), Limits::default()).unwrap();
        let selected = auth_config();
        store.configure_auth(&selected).unwrap();
        let document = PublicDocument::encode(&lomi_platform::public_config::Configuration {
            version: 1,
            revision: 1,
            authentication: Some(selected.clone()),
        })
        .unwrap();
        let prepared = store.public_prepare(None, &document).unwrap();
        // Synthetic Store publication only; no public-file durability claim.
        store
            .public_finish(prepared.operation_id, &document)
            .unwrap();
        store
            .begin_login(OperationId::from_bytes([9; 16]).unwrap())
            .unwrap();
        let identity = store.identity().clone();
        let trusted = lomi_host_auth::Config::new(
            identity.host_id,
            identity.profile_id,
            selected.origin.as_str().to_owned(),
            selected.client_id.as_str().to_owned().try_into().unwrap(),
        )
        .unwrap();
        let endpoint = Arc::new(
            super::super::platform::OwnerEndpoint::bind(
                lock,
                super::super::platform::LocalDiscovery {
                    version: lomi_remote_protocol::LocalIpcVersion::CURRENT,
                    profile_id: identity.profile_id,
                    host_id: identity.host_id,
                    runtime_id: store.runtime_id(),
                    build_id: "source-fixture".to_owned(),
                },
            )
            .unwrap(),
        );
        (
            root,
            SharedOwner::new(store).unwrap(),
            super::super::public_configuration::PublicSetup::new(endpoint),
            trusted,
        )
    }
    fn ready_test_initialize(
        auth: &mut lomi_host_auth::HostAuth<'_, ReadyTestStorage>,
        host: lomi_remote_protocol::HostId,
    ) {
        let config = auth.trusted_configuration().clone();
        auth.initialize().unwrap();
        let initial = auth.init_request().unwrap();
        let committed = lomi_remote_crypto::verify_host_key_initiation(&initial).unwrap();
        let pin = committed.descriptor.commitment().unwrap();
        auth.accept_initiation(
            lomi_remote_protocol::EnrollmentInitiateResult {
                enrollment_id: lomi_remote_protocol::EnrollmentId::from_bytes([3; 16]).unwrap(),
                device_code: "synthetic_device".to_owned().try_into().unwrap(),
                user_code: "SYNTHETIC-CODE".to_owned().try_into().unwrap(),
                expires_in_seconds: DecimalU64(600),
                poll_interval_seconds: DecimalU64(5),
            },
            1000,
        )
        .unwrap();
        let challenge = lomi_remote_crypto::prepare_host_enrollment_challenge(
            &committed,
            &pin,
            [4; 16],
            &lomi_remote_crypto::HostEnrollmentChallengeContext {
                enrollment_id: [3; 16],
                bootstrap_session_id: [5; 16],
                operation_id: [6; 16],
                nonce: [7; 32],
                audience: config.exchange_audience(),
                expires_at: DecimalU64(1500),
            },
        )
        .unwrap();
        let encoded: String = challenge
            .canonical()
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        auth.accept_tls_approval(
            config.origin(),
            lomi_remote_protocol::HostEnrollmentTokenContext {
                account_id: lomi_remote_protocol::AccountId::from_bytes([4; 16]).unwrap(),
                challenge: encoded.try_into().unwrap(),
            },
            "synthetic_bootstrap".to_owned().try_into().unwrap(),
            1001,
        )
        .unwrap();
        auth.prepare_exchange(1002).unwrap();
        let operation = auth.exchange_request(1002).unwrap().operation_id;
        auth.accept_exchange(
            lomi_remote_protocol::HostAuthorizationResult {
                account_id: lomi_remote_protocol::AccountId::from_bytes([4; 16]).unwrap(),
                host_id: host,
                host_authorization_id: lomi_remote_protocol::HostAuthorizationId::from_bytes(
                    [8; 16],
                )
                .unwrap(),
                access: "synthetic_access".to_owned().try_into().unwrap(),
                refresh: "synthetic_refresh".to_owned().try_into().unwrap(),
                rotation_id: operation,
                expires_in_seconds: DecimalU64(300),
            },
            1003,
        )
        .unwrap();
    }
    fn with_ready_test(
        resume: bool,
        run: impl FnOnce(
            &Arc<SharedOwner>,
            &mut lomi_host_auth::HostAuth<'_, ReadyTestStorage>,
            &super::super::public_configuration::PublicSetup,
            &super::super::public_configuration::WorkerPublicIo<'_>,
            &AtomicBool,
            &AtomicBool,
            std::rc::Rc<ReadyTestCounts>,
            std::rc::Rc<std::cell::Cell<u8>>,
        ),
    ) {
        let (_root, owner, setup, trusted) = ready_test_fixture();
        let counts = std::rc::Rc::new(ReadyTestCounts::default());
        let effect = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut storage = ReadyTestStorage {
            bytes: None,
            counts: counts.clone(),
            effect: effect.clone(),
            owner: owner.clone(),
        };
        let gate = AtomicBool::new(true);
        let paused = AtomicBool::new(false);
        // Same exclusion order as actual worker: IO guard before provider open.
        let public_io = setup.enter_owned(&paused).unwrap().unwrap();
        let mut auth = lomi_host_auth::HostAuth::open(&mut storage, trusted, 1000).unwrap();
        let host = owner.store.lock().unwrap().identity().host_id;
        ready_test_initialize(&mut auth, host);
        if resume {
            auth.confirm_registration(lomi_remote_protocol::HostRegisterResult {
                host_id: host,
                host_access_epoch: DecimalU64(12),
            })
            .unwrap();
            let mut store = owner.store.lock().unwrap();
            let intent = store.login_intent().unwrap().unwrap();
            store.complete_login(intent).unwrap();
            let generation = store.authorization_state().unwrap().generation;
            store.suspend_authorization(generation).unwrap();
        }
        run(
            &owner, &mut auth, &setup, &public_io, &gate, &paused, counts, effect,
        );
    }
    type ReadyScriptedAttempt<'w, 'p, 'i> = (
        ConfiguredWorkerAttempt<'w, 'p, 'i, ReadyTestStorage>,
        std::rc::Rc<std::cell::Cell<usize>>,
        std::rc::Rc<std::cell::RefCell<Option<String>>>,
    );
    fn ready_scripted_attempt<'w, 'p, 'i>(
        auth: &'w mut lomi_host_auth::HostAuth<'p, ReadyTestStorage>,
        setup: &'i super::super::public_configuration::PublicSetup,
        public_io: &'i super::super::public_configuration::WorkerPublicIo<'i>,
        gate: &'i AtomicBool,
        paused: &'i AtomicBool,
    ) -> ReadyScriptedAttempt<'w, 'p, 'i> {
        // Preserve existing test bodies while binding their test-only adapter
        // to the same private capability as the real inactive factory.
        assert!(std::ptr::eq(setup, public_io.setup()));
        let setup = public_io.setup();
        let sends = std::rc::Rc::new(std::cell::Cell::new(0));
        let exact_request = std::rc::Rc::new(std::cell::RefCell::new(None));
        let trusted = auth.trusted_configuration().clone();
        (
            ConfiguredWorkerAttempt {
                auth,
                trusted,
                auth_api: None,
                http: WorkerReadyHttp::Scripted(WorkerReadyScript {
                    send_failure: None,
                    sends: sends.clone(),
                    exact_request: exact_request.clone(),
                    clock_failure: None,
                }),
                _public_io: public_io,
                setup,
                gate,
                paused,
                base: 1004,
                anchor: Instant::now(),
                projected_for_test: Some(1004),
                after_final_store_time_for_test: None,
            },
            sends,
            exact_request,
        )
    }
    fn ready_to_phase<S: lomi_platform::secrets::SecretStorage + ?Sized>(
        turn: &mut SoleWorkerReadyTurn<'_, '_, '_, '_, '_, '_, S>,
        phase: WorkerReadyPhase,
    ) {
        for _ in 0..5 {
            if turn.phase == phase {
                return;
            }
            assert_eq!(turn.try_step(), Ok(false));
        }
        panic!("phase was not reached");
    }
    #[test]
    fn worker_public_io_owns_actual_read_lease_until_capability_drop() {
        let (_root, _owner, setup, _trusted) = ready_test_fixture();
        let paused = AtomicBool::new(true);
        let public_io = setup.enter_owned(&paused).unwrap().unwrap();
        assert!(std::ptr::eq(public_io.setup(), &setup));
        assert!(!paused.load(SeqCst));
        assert!(setup.io.try_write().is_err());
        drop(public_io);
        // No retained/nested acquisition remains after the sole lease drops.
        assert!(setup.io.try_write().is_ok());
    }
    #[test]
    fn worker_public_io_pending_pauses_and_refuses_owned_lease() {
        let (_root, _owner, setup, _trusted) = ready_test_fixture();
        let paused = AtomicBool::new(false);
        setup.pending.store(true, SeqCst);
        assert!(setup.enter_owned(&paused).unwrap().is_none());
        assert!(paused.load(SeqCst));
        assert!(setup.io.try_write().is_ok());
    }
    #[test]
    fn worker_public_io_pending_refusal_does_not_open_provider() {
        let (_root, owner, setup, trusted) = ready_test_fixture();
        let counts = std::rc::Rc::new(ReadyTestCounts::default());
        let effect = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut storage = ReadyTestStorage {
            bytes: None,
            counts: counts.clone(),
            effect,
            owner,
        };
        let paused = AtomicBool::new(false);
        setup.pending.store(true, SeqCst);
        if let Some(_public_io) = setup.enter_owned(&paused).unwrap() {
            let _auth = lomi_host_auth::HostAuth::open(&mut storage, trusted, 1000).unwrap();
            panic!("pending configure admitted a provider open");
        }
        assert!(paused.load(SeqCst));
        assert_eq!(counts.loads.get(), 0);
        assert_eq!(counts.statuses.get(), 0);
        assert_eq!(counts.writes.get(), 0);
    }
    #[test]
    fn ready_factory_derives_exact_setup_only_from_owned_public_io() {
        with_ready_test(
            false,
            |_owner, auth, setup, io, gate, paused, _counts, _| {
                let (_other_root, _other_owner, other_setup, _trusted) = ready_test_fixture();
                let attempt = ConfiguredWorkerAttempt::from_existing_worker(
                    auth,
                    io,
                    gate,
                    paused,
                    1004,
                    Instant::now(),
                )
                .unwrap();
                assert!(std::ptr::eq(attempt.setup, setup));
                assert!(std::ptr::eq(attempt._public_io, io));
                assert!(!std::ptr::eq(attempt.setup, &other_setup));
                assert!(setup.io.try_write().is_err());
                assert!(other_setup.io.try_write().is_ok());
            },
        );
    }
    #[test]
    fn ready_factory_rejects_pending_or_paused_without_touching_existing_provider() {
        for pending in [true, false] {
            with_ready_test(false, |_owner, auth, setup, io, gate, paused, counts, _| {
                let before = (
                    counts.loads.get(),
                    counts.statuses.get(),
                    counts.writes.get(),
                );
                let address = auth as *mut _;
                setup.pending.store(pending, SeqCst);
                paused.store(!pending, SeqCst);
                assert!(matches!(
                    ConfiguredWorkerAttempt::from_existing_worker(
                        auth,
                        io,
                        gate,
                        paused,
                        1004,
                        Instant::now()
                    ),
                    Err(WorkerReadyError::Stale)
                ));
                assert_eq!(auth as *mut _, address);
                assert_eq!(
                    (
                        counts.loads.get(),
                        counts.statuses.get(),
                        counts.writes.get()
                    ),
                    before
                );
                assert!(setup.io.try_write().is_err());
                assert!(gate.load(SeqCst));
            });
        }
    }
    #[test]
    fn ready_attempt_and_turn_keep_borrow_of_same_owned_public_io() {
        with_ready_test(false, |owner, auth, setup, io, gate, paused, _counts, _| {
            let cancelled = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancelled);
            let (mut attempt, sends, _) = ready_scripted_attempt(auth, setup, io, gate, paused);
            assert!(setup.io.try_write().is_err());
            assert!(std::ptr::eq(attempt._public_io, io));
            let mut turn = attempt.begin_ready(owner, &operation).unwrap();
            assert_eq!(turn.try_step(), Ok(false));
            assert!(std::ptr::eq(turn.attempt._public_io, io));
            assert!(setup.io.try_write().is_err());
            drop(turn);
            drop(attempt);
            // The caller still owns the actual read lease after the borrows end.
            assert!(setup.io.try_write().is_err());
            assert_eq!(sends.get(), 0);
        });
    }
    #[test]
    fn sole_worker_registration_uses_same_provider_borrow_exact_request_and_one_scope() {
        with_ready_test(false, |owner, auth, setup, io, gate, paused, counts, _| {
            let address = auth as *mut _;
            let loads = counts.loads.get();
            let statuses = counts.statuses.get();
            let writes = counts.writes.get();
            let cancel = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancel);
            let (mut attempt, sends, request) =
                ready_scripted_attempt(auth, setup, io, gate, paused);
            assert_eq!(attempt.auth as *mut _, address);
            let expected =
                serde_json::to_string(&attempt.auth.registration_request(1004).unwrap().1).unwrap();
            let mut turn = attempt.begin_ready(owner, &operation).unwrap();
            assert_eq!(turn.try_step(), Ok(false));
            let scope_address = turn.scope.as_ref().unwrap() as *const _;
            let writer_address = turn.writer.as_ref().unwrap() as *const _;
            ready_to_phase(&mut turn, WorkerReadyPhase::Publish);
            assert_eq!(scope_address, turn.scope.as_ref().unwrap() as *const _);
            assert_eq!(writer_address, turn.writer.as_ref().unwrap() as *const _);
            assert_eq!(turn.try_step(), Ok(true));
            assert_eq!(turn.try_step(), Err(WorkerReadyError::Stale));
            assert_eq!(sends.get(), 1);
            assert_eq!(request.borrow().as_ref(), Some(&expected));
            assert_eq!(counts.loads.get(), loads);
            assert_eq!(counts.statuses.get(), statuses);
            assert_eq!(counts.writes.get(), writes + 1);
            assert!(!gate.load(SeqCst));
            assert!(owner.remote_authorization(&operation).is_ok());
            assert!(
                owner
                    .store
                    .lock()
                    .unwrap()
                    .login_intent()
                    .unwrap()
                    .is_none()
            );
        });
    }
    #[test]
    fn sole_worker_cached_ready_requires_fresh_exact_rotation_before_resume() {
        with_ready_test(true, |owner, auth, setup, io, gate, paused, counts, _| {
            let writes = counts.writes.get();
            let cancel = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancel);
            let generation = owner
                .store
                .lock()
                .unwrap()
                .authorization_state()
                .unwrap()
                .generation;
            let (mut attempt, sends, request) =
                ready_scripted_attempt(auth, setup, io, gate, paused);
            let mut turn = attempt.begin_ready(owner, &operation).unwrap();
            assert_eq!(turn.try_step(), Ok(false));
            assert_eq!(turn.attempt.auth.status(), lomi_host_auth::Status::Rotating);
            assert!(owner.remote_authorization(&operation).is_err());
            assert!(gate.load(SeqCst));
            let expected = match turn.request.as_ref().unwrap() {
                WorkerReadyRequest::Rotate(request) => serde_json::to_string(request).unwrap(),
                _ => panic!("cached state did not produce a rotation request"),
            };
            ready_to_phase(&mut turn, WorkerReadyPhase::Publish);
            assert_eq!(turn.try_step(), Ok(true));
            assert_eq!(request.borrow().as_ref(), Some(&expected));
            assert_eq!(sends.get(), 1);
            assert_eq!(counts.writes.get(), writes + 2);
            assert_eq!(
                owner.remote_authorization(&operation).unwrap().generation,
                generation
            );
        });
    }
    #[test]
    fn sole_worker_network_failure_then_success_uses_same_owner_and_exact_registration_or_rotation()
    {
        for resume in [false, true] {
            with_ready_test(resume, |owner, auth, setup, io, gate, paused, counts, _| {
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends, request) =
                    ready_scripted_attempt(auth, setup, io, gate, paused);
                if let WorkerReadyHttp::Scripted(script) = &mut attempt.http {
                    script.send_failure = Some(lomi_host_http::Error::Network);
                }
                let mut turn = attempt.begin_ready(owner, &operation).unwrap();
                ready_to_phase(&mut turn, WorkerReadyPhase::Send);
                let writes = counts.writes.get();
                let error = WorkerReadyError::Http(lomi_host_http::Error::Network);
                assert_eq!(turn.try_step(), Err(error));
                assert_eq!(turn.try_step(), Err(error));
                assert_eq!(sends.get(), 1);
                assert_eq!(counts.writes.get(), writes);
                assert!(turn.writer.is_none());
                assert!(gate.load(SeqCst));
                assert!(owner.remote_authorization(&operation).is_err());
                let original_request = request.borrow().clone();
                drop(turn);
                drop(attempt);
                assert_eq!(
                    auth.status(),
                    if resume {
                        lomi_host_auth::Status::Rotating
                    } else {
                        lomi_host_auth::Status::Unconfirmed
                    }
                );
                let retry = Operation::new(end(), &cancel);
                let (mut attempt, sends, request) =
                    ready_scripted_attempt(auth, setup, io, gate, paused);
                let mut turn = attempt.begin_ready(owner, &retry).unwrap();
                ready_to_phase(&mut turn, WorkerReadyPhase::Publish);
                assert_eq!(turn.try_step(), Ok(true));
                assert_eq!(*request.borrow(), original_request);
                assert_eq!(sends.get(), 1);
                assert_eq!(counts.writes.get(), writes + 1);
                assert!(!gate.load(SeqCst));
                assert!(owner.remote_authorization(&retry).is_ok());
            });
        }
    }
    #[test]
    fn sole_worker_competing_local_writer_stales_only_attempt_then_same_owner_reverifies() {
        with_ready_test(true, |owner, auth, setup, io, gate, paused, counts, _| {
            let cancel = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancel);
            let (mut attempt, sends, request) =
                ready_scripted_attempt(auth, setup, io, gate, paused);
            let mut turn = attempt.begin_ready(owner, &operation).unwrap();
            ready_to_phase(&mut turn, WorkerReadyPhase::Clock);
            let writes = counts.writes.get();
            let original_request = request.borrow().clone();
            let mut local = owner
                .domain
                .announce(&operation, WriterClass::Shared, Intent::Mutation)
                .unwrap();
            local
                .try_enter()
                .unwrap()
                .commit(|| {
                    Ok::<_, StoreError>(((), StoreView::read(&owner.store.lock().unwrap())?))
                })
                .unwrap();
            local.finish().unwrap();
            assert_eq!(
                turn.try_step(),
                Err(WorkerReadyError::Domain(domain::Error::Stale))
            );
            assert_eq!(sends.get(), 1);
            assert_eq!(counts.writes.get(), writes);
            assert!(gate.load(SeqCst));
            assert!(owner.remote_authorization(&operation).is_err());
            drop(turn);
            drop(attempt);
            let retry = Operation::new(end(), &cancel);
            let (mut attempt, sends, request) =
                ready_scripted_attempt(auth, setup, io, gate, paused);
            let mut turn = attempt.begin_ready(owner, &retry).unwrap();
            ready_to_phase(&mut turn, WorkerReadyPhase::Publish);
            assert_eq!(turn.try_step(), Ok(true));
            assert_eq!(sends.get(), 1);
            assert_eq!(*request.borrow(), original_request);
            assert_eq!(counts.writes.get(), writes + 1);
            assert!(owner.remote_authorization(&retry).is_ok());
        });
    }
    #[test]
    fn sole_worker_notice_cancel_is_sticky_attenuation_and_cannot_resume_same_turn() {
        with_ready_test(false, |owner, auth, setup, io, gate, paused, counts, _| {
            let cancel = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancel);
            let (mut attempt, sends, _) = ready_scripted_attempt(auth, setup, io, gate, paused);
            let mut turn = attempt.begin_ready(owner, &operation).unwrap();
            ready_to_phase(&mut turn, WorkerReadyPhase::Clock);
            let writes = counts.writes.get();
            turn.notice_cancel();
            assert_eq!(
                turn.try_step(),
                Err(WorkerReadyError::Domain(domain::Error::Cancelled))
            );
            turn.notice_cancel();
            assert_eq!(
                turn.try_step(),
                Err(WorkerReadyError::Domain(domain::Error::Cancelled))
            );
            assert!(turn.writer.is_none());
            assert!(gate.load(SeqCst));
            assert_eq!(sends.get(), 1);
            assert_eq!(counts.writes.get(), writes);
            assert!(operation.check().is_ok());
            assert!(owner.remote_authorization(&operation).is_err());
        });
    }
    #[test]
    fn sole_worker_preaccept_abort_busy_retains_writer_and_primary_error_until_cleanup() {
        with_ready_test(false, |owner, auth, setup, io, gate, paused, counts, _| {
            let cancel = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancel);
            let (mut attempt, sends, _) = ready_scripted_attempt(auth, setup, io, gate, paused);
            let mut turn = attempt.begin_ready(owner, &operation).unwrap();
            ready_to_phase(&mut turn, WorkerReadyPhase::Clock);
            let writes = counts.writes.get();
            let writer = turn.writer.as_ref().unwrap() as *const _;
            assert_eq!(turn.pending_abort_error(), None);
            paused.store(true, SeqCst);
            let held = owner.domain.try_read(&operation).unwrap();
            assert_eq!(
                turn.try_step(),
                Err(WorkerReadyError::Domain(domain::Error::Busy))
            );
            assert_eq!(turn.writer.as_ref().unwrap() as *const _, writer);
            assert_eq!(turn.pending_abort_error(), Some(WorkerReadyError::Stale));
            assert_eq!(
                turn.try_step(),
                Err(WorkerReadyError::Domain(domain::Error::Busy))
            );
            drop(held);
            assert_eq!(turn.try_step(), Err(WorkerReadyError::Stale));
            assert!(turn.writer.is_none());
            assert_eq!(turn.pending_abort_error(), None);
            assert_eq!(sends.get(), 1);
            assert_eq!(counts.writes.get(), writes);
        });
    }
    #[test]
    fn sole_worker_mutex_busy_retains_response_and_never_repeats_http_or_provider() {
        for store_busy in [true, false] {
            with_ready_test(false, |owner, auth, setup, io, gate, paused, counts, _| {
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends, _) = ready_scripted_attempt(auth, setup, io, gate, paused);
                let mut turn = attempt.begin_ready(owner, &operation).unwrap();
                for target in [
                    WorkerReadyPhase::Prepare,
                    WorkerReadyPhase::Clock,
                    WorkerReadyPhase::Publish,
                ] {
                    ready_to_phase(&mut turn, target);
                    let before = counts.writes.get();
                    let sends_before = sends.get();
                    if store_busy {
                        let held = owner.store.lock().unwrap();
                        assert_eq!(
                            turn.try_step(),
                            Err(WorkerReadyError::Domain(domain::Error::Busy))
                        );
                        drop(held);
                    } else {
                        let held = owner.domain.try_read(&operation).unwrap();
                        assert_eq!(
                            turn.try_step(),
                            Err(WorkerReadyError::Domain(domain::Error::Busy))
                        );
                        drop(held);
                    }
                    assert!(turn.phase == target);
                    assert_eq!(counts.writes.get(), before);
                    assert_eq!(sends.get(), sends_before);
                    assert!(turn.writer.is_some());
                }
                assert_eq!(turn.try_step(), Ok(true));
                assert_eq!(sends.get(), 1);
            });
        }
    }
    #[test]
    fn sole_worker_clock_failure_selfseal_is_terminal_before_provider_acceptance() {
        for error in [StoreError::Busy, StoreError::Storage] {
            with_ready_test(false, |owner, auth, setup, io, gate, paused, counts, _| {
                let writes = counts.writes.get();
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends, _) = ready_scripted_attempt(auth, setup, io, gate, paused);
                if let WorkerReadyHttp::Scripted(script) = &mut attempt.http {
                    script.clock_failure = Some(error);
                }
                let mut turn = attempt.begin_ready(owner, &operation).unwrap();
                ready_to_phase(&mut turn, WorkerReadyPhase::Clock);
                assert_eq!(turn.try_step(), Err(WorkerReadyError::Store(error)));
                assert_eq!(turn.try_step(), Err(WorkerReadyError::Store(error)));
                assert_eq!(sends.get(), 1);
                assert_eq!(counts.writes.get(), writes);
                assert!(
                    owner
                        .store
                        .lock()
                        .unwrap()
                        .authorization_state()
                        .unwrap()
                        .locked
                );
                assert!(owner.remote_authorization(&operation).is_err());
                assert!(gate.load(SeqCst));
            });
        }
    }
    #[test]
    fn sole_worker_original_cancel_deadline_and_pause_reject_every_boundary() {
        for target in [
            WorkerReadyPhase::Prepare,
            WorkerReadyPhase::Send,
            WorkerReadyPhase::Clock,
            WorkerReadyPhase::Accept,
            WorkerReadyPhase::Publish,
        ] {
            for boundary in 0..5 {
                with_ready_test(false, |owner, auth, setup, io, gate, paused, _, _| {
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let (mut attempt, sends, _) =
                        ready_scripted_attempt(auth, setup, io, gate, paused);
                    let mut turn = attempt.begin_ready(owner, &operation).unwrap();
                    ready_to_phase(&mut turn, target);
                    let before = sends.get();
                    let expected = match boundary {
                        0 => {
                            cancel.store(true, SeqCst);
                            WorkerReadyError::Domain(domain::Error::Cancelled)
                        }
                        1 => {
                            operation.expire_for_test();
                            WorkerReadyError::Domain(domain::Error::Deadline)
                        }
                        2 => {
                            paused.store(true, SeqCst);
                            WorkerReadyError::Stale
                        }
                        3 => {
                            setup.pending.store(true, SeqCst);
                            WorkerReadyError::Stale
                        }
                        _ => {
                            gate.store(false, SeqCst);
                            WorkerReadyError::Stale
                        }
                    };
                    assert_eq!(turn.try_step(), Err(expected));
                    assert_eq!(sends.get(), before);
                    assert!(gate.load(SeqCst));
                    assert!(
                        owner
                            .remote_authorization(&Operation::new(end(), &AtomicBool::new(false)))
                            .is_err()
                    );
                });
            }
        }
    }
    #[test]
    fn sole_worker_logout_config_public_fence_and_new_writer_reject_after_response() {
        for boundary in 0..4 {
            with_ready_test(false, |owner, auth, setup, io, gate, paused, _, _| {
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends, _) = ready_scripted_attempt(auth, setup, io, gate, paused);
                let mut turn = attempt.begin_ready(owner, &operation).unwrap();
                ready_to_phase(&mut turn, WorkerReadyPhase::Clock);
                match boundary {
                    0 => {
                        owner
                            .begin_local_logout(&operation)
                            .unwrap()
                            .try_commit()
                            .unwrap();
                    }
                    1 => {
                        let mut store = owner.store.lock().unwrap();
                        let current = store.public_current().unwrap();
                        let mut configuration = current.configuration().unwrap();
                        configuration.revision += 1;
                        configuration
                            .authentication
                            .as_mut()
                            .unwrap()
                            .remote_api_origin =
                            Some("https://remote.example".to_owned().try_into().unwrap());
                        let desired = PublicDocument::encode(&configuration).unwrap();
                        // Authored synthetic first-fill/public publication race;
                        // legacy configure_auth correctly rejects migrated state.
                        let intent = store.public_prepare(Some(&current), &desired).unwrap();
                        store.public_finish(intent.operation_id, &desired).unwrap();
                    }
                    2 => {
                        owner.store.lock().unwrap().public_block();
                    }
                    _ => {
                        let mut writer = owner
                            .domain
                            .announce(&operation, WriterClass::Shared, Intent::Mutation)
                            .unwrap();
                        writer
                            .try_enter()
                            .unwrap()
                            .commit(|| {
                                Ok::<_, StoreError>((
                                    (),
                                    StoreView::read(&owner.store.lock().unwrap())?,
                                ))
                            })
                            .unwrap();
                        writer.finish().unwrap();
                    }
                }
                assert!(turn.try_step().is_err());
                assert_eq!(sends.get(), 1);
                assert!(gate.load(SeqCst));
                assert!(owner.remote_authorization(&operation).is_err());
            });
        }
    }
    #[test]
    fn sole_worker_provider_accepted_then_stale_publication_never_mints_ready() {
        with_ready_test(false, |owner, auth, setup, io, gate, paused, counts, _| {
            let cancel = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancel);
            let (mut attempt, sends, _) = ready_scripted_attempt(auth, setup, io, gate, paused);
            let mut turn = attempt.begin_ready(owner, &operation).unwrap();
            ready_to_phase(&mut turn, WorkerReadyPhase::Publish);
            let writes = counts.writes.get();
            assert_eq!(turn.attempt.auth.status(), lomi_host_auth::Status::Ready);
            owner
                .begin_local_logout(&operation)
                .unwrap()
                .try_commit()
                .unwrap();
            assert!(turn.try_step().is_err());
            assert_eq!(counts.writes.get(), writes);
            assert_eq!(sends.get(), 1);
            assert!(gate.load(SeqCst));
            assert!(owner.remote_authorization(&operation).is_err());
        });
    }
    #[test]
    fn sole_worker_provider_error_wins_over_logout_cleanup_and_boundary_failure() {
        with_ready_test(false, |owner, auth, setup, io, gate, paused, _, effect| {
            let cancel = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancel);
            let (mut attempt, sends, _) = ready_scripted_attempt(auth, setup, io, gate, paused);
            let mut turn = attempt.begin_ready(owner, &operation).unwrap();
            ready_to_phase(&mut turn, WorkerReadyPhase::Accept);
            effect.set(2); // actual provider replace triggers logout, then fails
            let expected = WorkerReadyError::Provider(lomi_host_auth::Error::Storage(
                lomi_platform::secrets::Error::CommitUncertain,
            ));
            assert_eq!(turn.try_step(), Err(expected));
            assert_eq!(turn.try_step(), Err(expected));
            assert_eq!(sends.get(), 1);
            assert!(gate.load(SeqCst));
            assert!(owner.remote_authorization(&operation).is_err());
        });
    }
    #[test]
    fn sole_worker_logout_during_actual_provider_acceptance_rejects_final_publish() {
        with_ready_test(false, |owner, auth, setup, io, gate, paused, _, effect| {
            let cancel = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancel);
            let (mut attempt, sends, _) = ready_scripted_attempt(auth, setup, io, gate, paused);
            let mut turn = attempt.begin_ready(owner, &operation).unwrap();
            ready_to_phase(&mut turn, WorkerReadyPhase::Accept);
            effect.set(1);
            assert_eq!(turn.try_step(), Ok(false));
            assert_eq!(turn.attempt.auth.status(), lomi_host_auth::Status::Ready);
            assert!(turn.try_step().is_err());
            assert_eq!(sends.get(), 1);
            assert!(gate.load(SeqCst));
            assert!(owner.remote_authorization(&operation).is_err());
        });
    }
    #[test]
    fn sole_worker_final_clock_expiry_rejects_without_reaccepting_provider() {
        with_ready_test(false, |owner, auth, setup, io, gate, paused, counts, _| {
            let cancel = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancel);
            let (mut attempt, sends, _) = ready_scripted_attempt(auth, setup, io, gate, paused);
            let mut turn = attempt.begin_ready(owner, &operation).unwrap();
            ready_to_phase(&mut turn, WorkerReadyPhase::Publish);
            let writes = counts.writes.get();
            turn.attempt.projected_for_test = Some(turn.deadlines.unwrap().access_expires_at);
            assert_eq!(
                turn.try_step(),
                Err(WorkerReadyError::Provider(lomi_host_auth::Error::Expired))
            );
            assert_eq!(counts.writes.get(), writes);
            assert_eq!(sends.get(), 1);
            assert!(gate.load(SeqCst));
            assert!(owner.remote_authorization(&operation).is_err());
        });
    }

    #[test]
    fn sole_worker_postresponse_floor_expiry_prevents_provider_registration_commit() {
        with_ready_test(false, |owner, auth, setup, io, gate, paused, counts, _| {
            let writes = counts.writes.get();
            let cancel = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancel);
            let (mut attempt, sends, _) = ready_scripted_attempt(auth, setup, io, gate, paused);
            let mut turn = attempt.begin_ready(owner, &operation).unwrap();
            ready_to_phase(&mut turn, WorkerReadyPhase::Clock);
            // Original exchange prepared at1002 grants at most300 seconds.
            turn.attempt.projected_for_test = Some(1302);
            assert_eq!(turn.try_step(), Ok(false));
            assert_eq!(
                turn.try_step(),
                Err(WorkerReadyError::Provider(lomi_host_auth::Error::Expired))
            );
            assert_eq!(counts.writes.get(), writes);
            assert_eq!(sends.get(), 1);
            assert!(gate.load(SeqCst));
            assert!(owner.remote_authorization(&operation).is_err());
        });
    }

    // Authored/unrun successor tests: explicit time changes, no sleeps/network.
    #[test]
    fn sole_worker_registration_expiring_between_clock_and_accept_never_writes_provider() {
        with_ready_test(false, |owner, auth, setup, io, gate, paused, counts, _| {
            let cancel = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancel);
            let (mut attempt, sends, _) = ready_scripted_attempt(auth, setup, io, gate, paused);
            let mut turn = attempt.begin_ready(owner, &operation).unwrap();
            ready_to_phase(&mut turn, WorkerReadyPhase::Accept);
            let before = counts.writes.get();
            assert_eq!(turn.clock_floor, Some(1004));
            assert!(operation.check().is_ok());
            // Exchange prepared at1002; its 300-second grant expires at1302.
            turn.attempt.projected_for_test = Some(1302);
            let expected = WorkerReadyError::Provider(lomi_host_auth::Error::Expired);
            assert_eq!(turn.try_step(), Err(expected));
            assert_eq!(turn.try_step(), Err(expected));
            assert_eq!(counts.writes.get(), before);
            assert_eq!(sends.get(), 1);
            assert_eq!(
                owner
                    .store
                    .lock()
                    .unwrap()
                    .authorization_state()
                    .unwrap()
                    .clock_floor,
                1302
            );
            assert_eq!(
                turn.attempt.auth.status(),
                lomi_host_auth::Status::Unconfirmed
            );
            assert!(gate.load(SeqCst));
            assert!(owner.remote_authorization(&operation).is_err());
        });
    }
    #[test]
    fn sole_worker_rotation_expiring_between_clock_and_accept_never_writes_provider() {
        with_ready_test(true, |owner, auth, setup, io, gate, paused, counts, _| {
            let cancel = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancel);
            let (mut attempt, sends, _) = ready_scripted_attempt(auth, setup, io, gate, paused);
            let mut turn = attempt.begin_ready(owner, &operation).unwrap();
            ready_to_phase(&mut turn, WorkerReadyPhase::Accept);
            let before = counts.writes.get();
            let deadline = turn
                .attempt
                .auth
                .credential_deadlines()
                .unwrap()
                .rotation_expires_at
                .unwrap();
            assert_eq!(turn.clock_floor, Some(1004));
            assert!(operation.check().is_ok());
            turn.attempt.projected_for_test = Some(deadline);
            let expected = WorkerReadyError::Provider(lomi_host_auth::Error::Expired);
            assert_eq!(turn.try_step(), Err(expected));
            assert_eq!(turn.try_step(), Err(expected));
            assert_eq!(counts.writes.get(), before);
            assert_eq!(sends.get(), 1);
            assert_eq!(
                owner
                    .store
                    .lock()
                    .unwrap()
                    .authorization_state()
                    .unwrap()
                    .clock_floor,
                deadline
            );
            assert_eq!(turn.attempt.auth.status(), lomi_host_auth::Status::Rotating);
            assert!(gate.load(SeqCst));
            assert!(owner.remote_authorization(&operation).is_err());
        });
    }
    #[test]
    fn sole_worker_accept_mutex_busy_retains_original_scope_response_and_provider_turn() {
        for store_busy in [true, false] {
            with_ready_test(false, |owner, auth, setup, io, gate, paused, counts, _| {
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends, _) = ready_scripted_attempt(auth, setup, io, gate, paused);
                let mut turn = attempt.begin_ready(owner, &operation).unwrap();
                ready_to_phase(&mut turn, WorkerReadyPhase::Accept);
                let scope = turn.scope.as_ref().unwrap() as *const _;
                let writer = turn.writer.as_ref().unwrap() as *const _;
                let response = turn.response.as_ref().unwrap() as *const _;
                let before = counts.writes.get();
                if store_busy {
                    let held = owner.store.lock().unwrap();
                    assert_eq!(
                        turn.try_step(),
                        Err(WorkerReadyError::Domain(domain::Error::Busy))
                    );
                    drop(held);
                } else {
                    let held = owner.domain.try_read(&operation).unwrap();
                    assert_eq!(
                        turn.try_step(),
                        Err(WorkerReadyError::Domain(domain::Error::Busy))
                    );
                    drop(held);
                }
                assert!(turn.phase == WorkerReadyPhase::Accept);
                assert_eq!(scope, turn.scope.as_ref().unwrap() as *const _);
                assert_eq!(writer, turn.writer.as_ref().unwrap() as *const _);
                assert_eq!(response, turn.response.as_ref().unwrap() as *const _);
                assert_eq!(turn.clock_floor, Some(1004));
                assert_eq!(counts.writes.get(), before);
                assert_eq!(sends.get(), 1);
                assert!(gate.load(SeqCst));
                assert_eq!(turn.try_step(), Ok(false));
                assert_eq!(counts.writes.get(), before + 1);
                assert_eq!(turn.try_step(), Ok(true));
                assert_eq!(counts.writes.get(), before + 1);
                assert_eq!(sends.get(), 1);
            });
        }
    }
    #[test]
    fn sole_worker_accept_clock_sql_failure_is_terminal_without_provider_or_http_replay() {
        for error in [StoreError::Busy, StoreError::Storage] {
            with_ready_test(false, |owner, auth, setup, io, gate, paused, counts, _| {
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends, _) = ready_scripted_attempt(auth, setup, io, gate, paused);
                let mut turn = attempt.begin_ready(owner, &operation).unwrap();
                ready_to_phase(&mut turn, WorkerReadyPhase::Accept);
                let before = counts.writes.get();
                // Existing cfg(test)-only self-seal seam; not actual SQL fault injection.
                if let WorkerReadyHttp::Scripted(script) = &mut turn.attempt.http {
                    script.clock_failure = Some(error);
                }
                assert_eq!(turn.try_step(), Err(WorkerReadyError::Store(error)));
                assert_eq!(turn.try_step(), Err(WorkerReadyError::Store(error)));
                assert_eq!(counts.writes.get(), before);
                assert_eq!(sends.get(), 1);
                assert!(turn.writer.is_none());
                assert!(
                    owner
                        .store
                        .lock()
                        .unwrap()
                        .authorization_state()
                        .unwrap()
                        .locked
                );
                assert!(gate.load(SeqCst));
                assert!(owner.remote_authorization(&operation).is_err());
            });
        }
    }
    #[test]
    fn sole_worker_postcommit_access_expiry_seals_without_opening_gate_or_reaccepting_provider() {
        for resume in [false, true] {
            with_ready_test(resume, |owner, auth, setup, io, gate, paused, counts, _| {
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends, _) = ready_scripted_attempt(auth, setup, io, gate, paused);
                let mut turn = attempt.begin_ready(owner, &operation).unwrap();
                ready_to_phase(&mut turn, WorkerReadyPhase::Publish);
                let deadline = turn.deadlines.unwrap().access_expires_at;
                let before = counts.writes.get();
                let generation = owner
                    .store
                    .lock()
                    .unwrap()
                    .authorization_state()
                    .unwrap()
                    .generation;
                assert_eq!(turn.attempt.projected_for_test, Some(1004));
                turn.attempt.after_final_store_time_for_test = Some(deadline);
                let expected = WorkerReadyError::Provider(lomi_host_auth::Error::Expired);
                assert_eq!(turn.try_step(), Err(expected));
                assert_eq!(turn.try_step(), Err(expected));
                assert_eq!(counts.writes.get(), before);
                assert_eq!(sends.get(), 1);
                assert!(turn.writer.is_none());
                assert_eq!(turn.attempt.auth.status(), lomi_host_auth::Status::Ready);
                let store = owner.store.lock().unwrap();
                // Completion actually happened: the final Store view was read,
                // but subsequent expiry kept the runtime authorization sealed.
                assert_eq!(
                    store.verified_authorization_generation().unwrap(),
                    Some(generation)
                );
                assert!(store.login_intent().unwrap().is_none());
                assert!(store.authorization_state().unwrap().locked);
                drop(store);
                assert!(gate.load(SeqCst));
                assert!(owner.remote_authorization(&operation).is_err());
            });
        }
    }

    // Authored/unrun. TLS is scripted; HostAuth transitions and Store effects are real.
    fn with_cloud_get_test(
        run: impl FnOnce(
            &Arc<SharedOwner>,
            &mut lomi_host_auth::HostAuth<'_, ReadyTestStorage>,
            &super::super::public_configuration::WorkerPublicIo<'_>,
            &AtomicBool,
            &AtomicBool,
            &AtomicBool,
            std::rc::Rc<ReadyTestCounts>,
            std::rc::Rc<std::cell::Cell<u8>>,
            CloudRuntimeState,
            HostPublicationIntent,
            WorkspaceId,
        ),
    ) {
        let (root, owner, setup, trusted) = ready_test_fixture();
        {
            let mut store = owner.store.lock().unwrap();
            let current = store.public_current().unwrap();
            let mut configuration = current.configuration().unwrap();
            configuration.revision += 1;
            configuration
                .authentication
                .as_mut()
                .unwrap()
                .remote_api_origin = Some("https://remote.example".to_owned().try_into().unwrap());
            let desired = PublicDocument::encode(&configuration).unwrap();
            let intent = store.public_prepare(Some(&current), &desired).unwrap();
            store.public_finish(intent.operation_id, &desired).unwrap();
        }
        let gate = AtomicBool::new(false);
        let paused = AtomicBool::new(false);
        let stopping = AtomicBool::new(false);
        let io = setup.enter_owned(&paused).unwrap().unwrap();
        let counts = std::rc::Rc::new(ReadyTestCounts::default());
        let effect = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut storage = ReadyTestStorage {
            bytes: None,
            counts: counts.clone(),
            effect: effect.clone(),
            owner: owner.clone(),
        };
        // ONE existing provider borrow throughout bootstrap and the tested GET.
        let mut auth = lomi_host_auth::HostAuth::open(&mut storage, trusted, 1000).unwrap();
        let host = owner.store.lock().unwrap().identity().host_id;
        ready_test_initialize(&mut auth, host);
        auth.confirm_registration(lomi_remote_protocol::HostRegisterResult {
            host_id: host,
            host_access_epoch: DecimalU64(12),
        })
        .unwrap();
        let cancel = AtomicBool::new(false);
        let bootstrap = Operation::new(end(), &cancel);
        let mut verification = owner
            .domain
            .announce(&bootstrap, WriterClass::Remote, Intent::VerifyRemote)
            .unwrap();
        {
            let mut guard = verification.try_enter().unwrap();
            let mut store = owner.store.lock().unwrap();
            let intent = store.login_intent().unwrap().unwrap();
            let scope = guard
                .prepare_verification(intent.generation, || StoreView::read(&store))
                .unwrap();
            guard
                .commit_verified(scope, || {
                    store.complete_login(intent)?;
                    Ok::<_, StoreError>(((), StoreView::read(&store)?))
                })
                .unwrap();
        }
        verification.finish().unwrap();
        let (binding, intent, workspace) = {
            let mut store = owner.store.lock().unwrap();
            let generation = store.authorization_state().unwrap().generation;
            let workspace = store
                .add_project(root.path(), "Cloud fixture".to_owned().try_into().unwrap())
                .unwrap()
                .state
                .context
                .workspace_id;
            store.share(workspace, generation).unwrap();
            let scope = store
                .cloud_runtime_scope(generation, "https://remote.example".to_owned())
                .unwrap();
            let runtime = lomi_remote_protocol::RuntimeBinding {
                runtime_id: scope.owner_runtime_id,
                runtime_generation: DecimalU64(18),
                host_access_epoch: DecimalU64(12),
            };
            let binding = store
                .compare_and_set_cloud_runtime(&scope, None, runtime, DecimalU64(0))
                .unwrap();
            let intent = store.prepare_host_publication(&binding).unwrap();
            (binding, intent, workspace)
        };
        run(
            &owner, &mut auth, &io, &gate, &paused, &stopping, counts, effect, binding, intent,
            workspace,
        );
    }
    fn cloud_snapshot(
        binding: &CloudRuntimeState,
        sequence: u64,
        epoch: u64,
    ) -> lomi_remote_protocol::HostRuntimeGetResult {
        let mut runtime = binding.server_runtime.clone();
        runtime.host_access_epoch = DecimalU64(epoch);
        if epoch != binding.server_runtime.host_access_epoch.0 {
            runtime.runtime_generation.0 += 1;
        }
        lomi_remote_protocol::HostRuntimeGetResult {
            host_id: binding.scope.host_id,
            host_access_epoch: DecimalU64(epoch),
            runtime_generation: runtime.runtime_generation,
            runtime: Some(runtime),
            publication_seq: DecimalU64(sequence),
            lease_ms: DecimalU64(30_000),
            freshness_ms: DecimalU64(5_000),
        }
    }
    fn scripted_cloud<'w, 'p, 'i>(
        auth: &'w mut lomi_host_auth::HostAuth<'p, ReadyTestStorage>,
        io: &'i super::super::public_configuration::WorkerPublicIo<'i>,
        gate: &'i AtomicBool,
        paused: &'i AtomicBool,
        stopping: &'i AtomicBool,
        snapshot: lomi_remote_protocol::HostRuntimeGetResult,
    ) -> (
        ConfiguredCloudAttempt<'w, 'p, 'i, ReadyTestStorage>,
        std::rc::Rc<std::cell::Cell<usize>>,
    ) {
        let access = auth.access_credential(1004).unwrap();
        let sends = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut attempt = ConfiguredCloudAttempt::from_existing_worker(
            auth,
            io,
            gate,
            paused,
            stopping,
            1004,
            Instant::now(),
        );
        attempt.projected = Some(1004);
        attempt.http = Some(CloudGetHttp::Scripted(CloudGetScript {
            expected_host: snapshot.host_id,
            expected_access: access,
            reply: Some(Ok(snapshot)),
            sends: sends.clone(),
            mutation: 0,
        }));
        (attempt, sends)
    }
    fn cloud_to<S: lomi_platform::secrets::SecretStorage + ?Sized>(
        turn: &mut CoherentCloudGet<'_, '_, '_, '_, '_, '_, S>,
        phase: CloudGetPhase,
    ) {
        for _ in 0..5 {
            if turn.phase == phase {
                return;
            }
            assert_eq!(turn.try_step(), Ok(false));
        }
        panic!("GET phase not reached");
    }
    #[test]
    fn coherent_get_read_scope_preserves_existing_ready_without_writer_or_provider_reopen() {
        with_cloud_get_test(
            |owner, auth, io, gate, paused, stopping, counts, _, binding, _, _| {
                let address = auth as *mut _;
                let loads = counts.loads.get();
                let writes = counts.writes.get();
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                assert!(owner.remote_authorization(&operation).is_ok());
                let (mut attempt, sends) = scripted_cloud(
                    auth,
                    io,
                    gate,
                    paused,
                    stopping,
                    cloud_snapshot(&binding, 1, 12),
                );
                assert_eq!(attempt.auth as *mut _, address);
                let mut turn = attempt.begin_get(owner, &operation).unwrap();
                // No pending writer exists during HTTP/provider read stages.
                assert!(owner.remote_authorization(&operation).is_ok());
                cloud_to(&mut turn, CloudGetPhase::Reconcile);
                assert_eq!(turn.try_step(), Ok(true));
                assert_eq!(turn.try_step(), Err(CloudGetError::Stale));
                assert_eq!(sends.get(), 1);
                assert_eq!(counts.loads.get(), loads);
                assert_eq!(counts.writes.get(), writes);
                assert!(!gate.load(SeqCst));
                assert!(owner.remote_authorization(&operation).is_ok());
                assert!(
                    owner
                        .store
                        .lock()
                        .unwrap()
                        .pending_host_publication()
                        .unwrap()
                        .is_none()
                );
            },
        );
    }
    #[test]
    fn coherent_get_rejects_each_original_tuple_member_changed_after_http_or_provider() {
        for after_provider in [false, true] {
            for fault in [
                CloudGetTupleFault::Configuration,
                CloudGetTupleFault::PublicDocument,
                CloudGetTupleFault::PublicReadiness,
                CloudGetTupleFault::Scope,
                CloudGetTupleFault::Previous,
                CloudGetTupleFault::Pending,
                CloudGetTupleFault::Generation,
                CloudGetTupleFault::Epoch,
                CloudGetTupleFault::Identity,
                CloudGetTupleFault::Deadline,
            ] {
                with_cloud_get_test(
                    |owner, auth, io, gate, paused, stopping, counts, _, binding, intent, _| {
                        let cancel = AtomicBool::new(false);
                        let operation = Operation::new(end(), &cancel);
                        let (mut attempt, sends) = scripted_cloud(
                            auth,
                            io,
                            gate,
                            paused,
                            stopping,
                            cloud_snapshot(&binding, 0, 13),
                        );
                        let mut turn = attempt.begin_get(owner, &operation).unwrap();
                        cloud_to(
                            &mut turn,
                            if after_provider {
                                CloudGetPhase::Reconcile
                            } else {
                                CloudGetPhase::Clock
                            },
                        );
                        let original = turn.tuple.as_ref().unwrap().clone();
                        let before = counts.writes.get();
                        // Honest cfg(test) readback-projection mutation: real Store
                        // reads occur first, then exactly ONE member is changed.
                        // Original tuple is never replaced; no actual SQL corruption claimed.
                        if after_provider {
                            turn.attempt.after_provider_fault = Some(fault);
                        } else {
                            turn.attempt.before_provider_fault = Some(fault);
                        }
                        assert_eq!(turn.try_step(), Err(CloudGetError::Stale));
                        assert_eq!(turn.try_step(), Err(CloudGetError::Stale));
                        assert!(turn.tuple.as_ref().unwrap() == &original);
                        assert_eq!(counts.writes.get(), before);
                        assert_eq!(sends.get(), 1);
                        let store = owner.store.lock().unwrap();
                        assert_eq!(store.pending_host_publication().unwrap(), Some(intent));
                        assert_eq!(
                            store
                                .cloud_runtime_reconciliation_state(&binding.scope)
                                .unwrap(),
                            Some(binding)
                        );
                        drop(store);
                        if after_provider {
                            assert_eq!(
                                turn.attempt.auth.verified_host_access_epoch().unwrap(),
                                DecimalU64(13)
                            );
                        }
                    },
                );
            }
        }
    }
    #[test]
    fn coherent_get_real_logout_or_public_fence_during_http_rejects_before_provider() {
        for mutation in [1, 2] {
            with_cloud_get_test(
                |owner, auth, io, gate, paused, stopping, counts, _, binding, _, _| {
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let before = counts.writes.get();
                    let (mut attempt, sends) = scripted_cloud(
                        auth,
                        io,
                        gate,
                        paused,
                        stopping,
                        cloud_snapshot(&binding, 0, 13),
                    );
                    if let Some(CloudGetHttp::Scripted(script)) = &mut attempt.http {
                        script.mutation = mutation;
                    }
                    let mut turn = attempt.begin_get(owner, &operation).unwrap();
                    cloud_to(&mut turn, CloudGetPhase::Clock);
                    assert!(turn.try_step().is_err());
                    assert_eq!(counts.writes.get(), before);
                    assert_eq!(sends.get(), 1);
                    assert!(owner.remote_authorization(&operation).is_err());
                    assert!(!gate.load(SeqCst));
                },
            );
        }
    }
    #[test]
    fn coherent_get_mutex_busy_retains_original_tuple_scope_response_and_provider_phase() {
        for store_busy in [true, false] {
            with_cloud_get_test(
                |owner, auth, io, gate, paused, stopping, counts, _, binding, _, _| {
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let (mut attempt, sends) = scripted_cloud(
                        auth,
                        io,
                        gate,
                        paused,
                        stopping,
                        cloud_snapshot(&binding, 0, 13),
                    );
                    let mut turn = attempt.begin_get(owner, &operation).unwrap();
                    for target in [
                        CloudGetPhase::Prepare,
                        CloudGetPhase::Send,
                        CloudGetPhase::Clock,
                        CloudGetPhase::Accept,
                        CloudGetPhase::Reconcile,
                    ] {
                        cloud_to(&mut turn, target);
                        let before = counts.writes.get();
                        let sent = sends.get();
                        let scope = turn.scope.as_ref().map(|x| x as *const _);
                        let response = turn.response.as_ref().map(|x| x as *const _);
                        if store_busy {
                            let held = owner.store.lock().unwrap();
                            assert_eq!(
                                turn.try_step(),
                                Err(CloudGetError::Domain(domain::Error::Busy))
                            );
                            drop(held);
                        } else {
                            let held = owner.domain.try_read(&operation).unwrap();
                            assert_eq!(
                                turn.try_step(),
                                Err(CloudGetError::Domain(domain::Error::Busy))
                            );
                            drop(held);
                        }
                        assert!(turn.phase == target);
                        assert_eq!(scope, turn.scope.as_ref().map(|x| x as *const _));
                        assert_eq!(response, turn.response.as_ref().map(|x| x as *const _));
                        assert_eq!(counts.writes.get(), before);
                        assert_eq!(sends.get(), sent);
                    }
                    assert_eq!(turn.try_step(), Ok(true));
                    assert_eq!(sends.get(), 1);
                    assert!(!gate.load(SeqCst));
                },
            );
        }
    }
    #[test]
    fn coherent_get_original_operation_and_live_latches_stop_every_stage_without_replay() {
        for target in [
            CloudGetPhase::Prepare,
            CloudGetPhase::Send,
            CloudGetPhase::Clock,
            CloudGetPhase::Accept,
            CloudGetPhase::Reconcile,
        ] {
            for boundary in 0..6 {
                with_cloud_get_test(
                    |owner, auth, io, gate, paused, stopping, counts, _, binding, _, _| {
                        let cancel = AtomicBool::new(false);
                        let operation = Operation::new(end(), &cancel);
                        let (mut attempt, sends) = scripted_cloud(
                            auth,
                            io,
                            gate,
                            paused,
                            stopping,
                            cloud_snapshot(&binding, 0, 13),
                        );
                        let mut turn = attempt.begin_get(owner, &operation).unwrap();
                        cloud_to(&mut turn, target);
                        let before = counts.writes.get();
                        let sent = sends.get();
                        match boundary {
                            0 => cancel.store(true, SeqCst),
                            1 => operation.expire_for_test(),
                            2 => paused.store(true, SeqCst),
                            3 => stopping.store(true, SeqCst),
                            4 => gate.store(true, SeqCst),
                            _ => io.setup().pending.store(true, SeqCst),
                        }
                        assert!(turn.try_step().is_err());
                        assert_eq!(counts.writes.get(), before);
                        assert_eq!(sends.get(), sent);
                        assert_eq!(gate.load(SeqCst), boundary == 4);
                    },
                );
            }
        }
    }
    #[test]
    fn coherent_get_noninvalid_provider_error_wins_before_postprovider_clock_and_domain_errors() {
        with_cloud_get_test(
            |owner, auth, io, gate, paused, stopping, _, effect, binding, _, _| {
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends) = scripted_cloud(
                    auth,
                    io,
                    gate,
                    paused,
                    stopping,
                    cloud_snapshot(&binding, 0, 13),
                );
                let mut turn = attempt.begin_get(owner, &operation).unwrap();
                cloud_to(&mut turn, CloudGetPhase::Accept);
                // Existing actual provider spy logs out then returns CommitUncertain.
                effect.set(2);
                turn.attempt.post_provider_clock_failure = Some(StoreError::Busy);
                turn.attempt.after_provider_fault = Some(CloudGetTupleFault::Configuration);
                let expected = CloudGetError::Provider(lomi_host_auth::Error::Storage(
                    lomi_platform::secrets::Error::CommitUncertain,
                ));
                assert_eq!(turn.try_step(), Err(expected));
                assert_eq!(turn.try_step(), Err(expected));
                assert_eq!(sends.get(), 1);
                assert!(turn.decision.is_none());
                assert!(owner.remote_authorization(&operation).is_err());
                assert_eq!(
                    turn.attempt.post_provider_clock_failure,
                    Some(StoreError::Busy)
                );
            },
        );
    }
    #[test]
    fn coherent_get_invalid_response_blocks_only_after_atomic_original_tuple_revalidation() {
        for stale in [false, true] {
            with_cloud_get_test(
                |owner, auth, io, gate, paused, stopping, _, _, binding, intent, _| {
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let mut snapshot = cloud_snapshot(&binding, 0, 12);
                    snapshot.host_access_epoch = DecimalU64(11);
                    let (mut attempt, sends) =
                        scripted_cloud(auth, io, gate, paused, stopping, snapshot);
                    let mut turn = attempt.begin_get(owner, &operation).unwrap();
                    cloud_to(&mut turn, CloudGetPhase::Reconcile);
                    if stale {
                        owner.store.lock().unwrap().public_block();
                    }
                    let result = turn.try_step();
                    if stale {
                        assert!(
                            result
                                != Err(CloudGetError::Http(lomi_host_http::Error::InvalidResponse))
                        );
                        assert!(turn.decision.is_none());
                    } else {
                        assert_eq!(
                            result,
                            Err(CloudGetError::Http(lomi_host_http::Error::InvalidResponse))
                        );
                        assert!(matches!(turn.decision, Some(CloudGetDecision::Blocked)));
                    }
                    assert_eq!(sends.get(), 1);
                    assert_eq!(
                        owner
                            .store
                            .lock()
                            .unwrap()
                            .pending_host_publication()
                            .unwrap(),
                        Some(intent)
                    );
                },
            );
        }
    }
    #[test]
    fn coherent_get_lost_put_recovers_only_exact_intended_sequence_and_blocks_advanced_sequence() {
        for sequence in [0, 1, 2] {
            with_cloud_get_test(
                |owner, auth, io, gate, paused, stopping, _, _, binding, intent, _| {
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let (mut attempt, sends) = scripted_cloud(
                        auth,
                        io,
                        gate,
                        paused,
                        stopping,
                        cloud_snapshot(&binding, sequence, 12),
                    );
                    let mut turn = attempt.begin_get(owner, &operation).unwrap();
                    cloud_to(&mut turn, CloudGetPhase::Reconcile);
                    if sequence == 1 {
                        assert_eq!(turn.try_step(), Ok(true));
                        assert!(
                            owner
                                .store
                                .lock()
                                .unwrap()
                                .pending_host_publication()
                                .unwrap()
                                .is_none()
                        );
                    } else if sequence == 0 {
                        assert_eq!(turn.try_step(), Ok(true));
                        assert_eq!(
                            owner
                                .store
                                .lock()
                                .unwrap()
                                .pending_host_publication()
                                .unwrap(),
                            Some(intent)
                        );
                    } else {
                        assert_eq!(
                            turn.try_step(),
                            Err(CloudGetError::Http(lomi_host_http::Error::InvalidResponse))
                        );
                        assert_eq!(
                            owner
                                .store
                                .lock()
                                .unwrap()
                                .pending_host_publication()
                                .unwrap(),
                            Some(intent)
                        );
                    }
                    assert_eq!(sends.get(), 1);
                },
            );
        }
    }
    #[test]
    fn coherent_get_invalidation_zero_cas_or_claim_preserves_outbox_and_old_branch_order() {
        for branch in 0..4 {
            with_cloud_get_test(
                |owner, auth, io, gate, paused, stopping, _, _, binding, _, _| {
                    let before = owner.store.lock().unwrap().pending_publications().unwrap();
                    let mut snapshot =
                        cloud_snapshot(&binding, if branch == 1 { 5 } else { 0 }, 13);
                    if branch == 2 {
                        snapshot.runtime.as_mut().unwrap().runtime_id =
                            lomi_remote_protocol::RuntimeId::from_bytes([77; 16]).unwrap();
                    }
                    if branch == 3 {
                        snapshot.runtime = None;
                        snapshot.lease_ms = DecimalU64(0);
                        snapshot.freshness_ms = DecimalU64(0);
                    }
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let (mut attempt, sends) =
                        scripted_cloud(auth, io, gate, paused, stopping, snapshot);
                    let mut turn = attempt.begin_get(owner, &operation).unwrap();
                    cloud_to(&mut turn, CloudGetPhase::Reconcile);
                    let result = turn.try_step();
                    if branch == 1 {
                        assert_eq!(
                            result,
                            Err(CloudGetError::Http(lomi_host_http::Error::InvalidResponse))
                        );
                    } else {
                        assert_eq!(result, Ok(true));
                    }
                    let store = owner.store.lock().unwrap();
                    assert_eq!(store.pending_publications().unwrap(), before);
                    assert!(store.pending_host_publication().unwrap().is_none());
                    if branch == 0 {
                        assert!(matches!(
                            turn.decision,
                            Some(CloudGetDecision::Online { .. })
                        ));
                        assert!(store.cloud_runtime_state(&binding.scope).unwrap().is_some());
                    } else if branch >= 2 {
                        assert!(matches!(turn.decision, Some(CloudGetDecision::Claim(_))));
                    }
                    assert_eq!(sends.get(), 1);
                },
            );
        }
    }
    #[test]
    fn coherent_get_recovered_ack_preserves_later_outbox_tokens() {
        with_cloud_get_test(
            |owner, auth, io, gate, paused, stopping, _, _, binding, _, workspace| {
                // Later pending work exists BEFORE the GET scope is admitted, while
                // its immutable original publication intent still names old tokens.
                owner.store.lock().unwrap().unshare(workspace).unwrap();
                let later = owner.store.lock().unwrap().pending_publications().unwrap();
                assert!(!later.is_empty());
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, _) = scripted_cloud(
                    auth,
                    io,
                    gate,
                    paused,
                    stopping,
                    cloud_snapshot(&binding, 1, 12),
                );
                let mut turn = attempt.begin_get(owner, &operation).unwrap();
                cloud_to(&mut turn, CloudGetPhase::Reconcile);
                assert_eq!(turn.try_step(), Ok(true));
                assert_eq!(
                    owner.store.lock().unwrap().pending_publications().unwrap(),
                    later
                );
            },
        );
    }
    #[test]
    fn coherent_get_expiry_after_final_store_work_seals_before_writer_release_without_replay() {
        with_cloud_get_test(
            |owner, auth, io, gate, paused, stopping, counts, _, binding, _, _| {
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends) = scripted_cloud(
                    auth,
                    io,
                    gate,
                    paused,
                    stopping,
                    cloud_snapshot(&binding, 1, 12),
                );
                let mut turn = attempt.begin_get(owner, &operation).unwrap();
                cloud_to(&mut turn, CloudGetPhase::Reconcile);
                let before = counts.writes.get();
                turn.attempt.post_store_time = Some(1302);
                let expected = CloudGetError::Provider(lomi_host_auth::Error::Expired);
                assert_eq!(turn.try_step(), Err(expected));
                assert_eq!(turn.try_step(), Err(expected));
                assert_eq!(counts.writes.get(), before);
                assert_eq!(sends.get(), 1);
                assert!(!gate.load(SeqCst));
                assert!(
                    owner
                        .store
                        .lock()
                        .unwrap()
                        .pending_host_publication()
                        .unwrap()
                        .is_none()
                );
                assert!(
                    owner
                        .store
                        .lock()
                        .unwrap()
                        .authorization_state()
                        .unwrap()
                        .locked
                );
                assert!(owner.remote_authorization(&operation).is_err());
            },
        );
    }
    #[test]
    fn coherent_get_clock_failure_is_terminal_selfsealed_without_http_or_provider_replay() {
        with_cloud_get_test(
            |owner, auth, io, gate, paused, stopping, counts, _, binding, _, _| {
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends) = scripted_cloud(
                    auth,
                    io,
                    gate,
                    paused,
                    stopping,
                    cloud_snapshot(&binding, 1, 12),
                );
                let mut turn = attempt.begin_get(owner, &operation).unwrap();
                cloud_to(&mut turn, CloudGetPhase::Clock);
                let before = counts.writes.get();
                turn.attempt.clock_failure = Some(StoreError::Busy);
                assert_eq!(
                    turn.try_step(),
                    Err(CloudGetError::UncertainStore(StoreError::Busy))
                );
                assert_eq!(
                    turn.try_step(),
                    Err(CloudGetError::UncertainStore(StoreError::Busy))
                );
                assert_eq!(sends.get(), 1);
                assert_eq!(counts.writes.get(), before);
                assert!(
                    owner
                        .store
                        .lock()
                        .unwrap()
                        .authorization_state()
                        .unwrap()
                        .locked
                );
            },
        );
    }

    #[test]
    fn coherent_get_successful_provider_epoch_commit_survives_later_logout_without_local_runtime_effect()
     {
        with_cloud_get_test(
            |owner, auth, io, gate, paused, stopping, _, effect, binding, intent, _| {
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends) = scripted_cloud(
                    auth,
                    io,
                    gate,
                    paused,
                    stopping,
                    cloud_snapshot(&binding, 0, 13),
                );
                let mut turn = attempt.begin_get(owner, &operation).unwrap();
                cloud_to(&mut turn, CloudGetPhase::Accept);
                effect.set(1); // actual provider replace logs out, then commits successfully
                assert_eq!(turn.try_step(), Ok(false));
                assert_eq!(
                    turn.attempt.auth.verified_host_access_epoch().unwrap(),
                    DecimalU64(13)
                );
                assert!(turn.try_step().is_err());
                assert!(turn.decision.is_none());
                assert_eq!(
                    owner
                        .store
                        .lock()
                        .unwrap()
                        .pending_host_publication()
                        .unwrap(),
                    Some(intent)
                );
                assert_eq!(sends.get(), 1);
                assert!(owner.remote_authorization(&operation).is_err());
            },
        );
    }

    #[test]
    fn coherent_get_exact_sequence_with_different_runtime_never_recovers_publication_ack() {
        with_cloud_get_test(
            |owner, auth, io, gate, paused, stopping, _, _, binding, _, _| {
                let before = owner.store.lock().unwrap().pending_publications().unwrap();
                let mut snapshot = cloud_snapshot(&binding, 1, 12);
                snapshot.runtime_generation.0 += 1;
                snapshot.runtime.as_mut().unwrap().runtime_generation = snapshot.runtime_generation;
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends) =
                    scripted_cloud(auth, io, gate, paused, stopping, snapshot);
                let mut turn = attempt.begin_get(owner, &operation).unwrap();
                cloud_to(&mut turn, CloudGetPhase::Reconcile);
                assert_eq!(
                    turn.try_step(),
                    Err(CloudGetError::Http(lomi_host_http::Error::InvalidResponse))
                );
                let store = owner.store.lock().unwrap();
                assert!(
                    store
                        .cloud_runtime_reconciliation_state(&binding.scope)
                        .unwrap()
                        .is_none()
                );
                assert_eq!(store.pending_publications().unwrap(), before);
                assert_eq!(sends.get(), 1);
            },
        );
    }

    #[test]
    fn coherent_get_http_failure_or_expired_cancelled_read_allows_independent_fresh_get() {
        for failure in 0..4 {
            with_cloud_get_test(
                |owner, auth, io, gate, paused, stopping, counts, _, binding, intent, _| {
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let baseline = counts.writes.get();
                    {
                        let (mut attempt, sends) = scripted_cloud(
                            auth,
                            io,
                            gate,
                            paused,
                            stopping,
                            cloud_snapshot(&binding, 0, 12),
                        );
                        if let Some(CloudGetHttp::Scripted(script)) = attempt.http.as_mut() {
                            if failure < 2 {
                                script.reply = Some(Err(if failure == 0 {
                                    lomi_host_http::Error::Network
                                } else {
                                    lomi_host_http::Error::Timeout
                                }));
                            }
                            if failure == 1 {
                                script.mutation = 3;
                            }
                        }
                        let mut turn = attempt.begin_get(owner, &operation).unwrap();
                        if failure < 2 {
                            assert_eq!(turn.try_step(), Ok(false));
                            let error = CloudGetError::Http(if failure == 0 {
                                lomi_host_http::Error::Network
                            } else {
                                lomi_host_http::Error::Timeout
                            });
                            assert_eq!(turn.try_step(), Err(error));
                            assert_eq!(turn.try_step(), Err(error));
                        } else {
                            cloud_to(&mut turn, CloudGetPhase::Clock);
                            if failure == 2 {
                                cancel.store(true, SeqCst);
                            } else {
                                operation.expire_for_test();
                            }
                            let error = CloudGetError::Domain(if failure == 2 {
                                domain::Error::Cancelled
                            } else {
                                domain::Error::Deadline
                            });
                            assert_eq!(turn.try_step(), Err(error));
                            assert_eq!(turn.try_step(), Err(error));
                        }
                        assert_eq!(sends.get(), 1);
                        assert_eq!(counts.writes.get(), baseline);
                    }
                    let fresh_cancel = AtomicBool::new(false);
                    let fresh = Operation::new(end(), &fresh_cancel);
                    assert!(owner.remote_authorization(&fresh).is_ok());
                    assert_eq!(
                        owner
                            .store
                            .lock()
                            .unwrap()
                            .pending_host_publication()
                            .unwrap(),
                        Some(intent)
                    );
                    let (mut attempt, sends) = scripted_cloud(
                        auth,
                        io,
                        gate,
                        paused,
                        stopping,
                        cloud_snapshot(&binding, 0, 12),
                    );
                    let mut turn = attempt.begin_get(owner, &fresh).unwrap();
                    cloud_to(&mut turn, CloudGetPhase::Reconcile);
                    assert_eq!(turn.try_step(), Ok(true));
                    assert_eq!(sends.get(), 1);
                    assert_eq!(counts.writes.get(), baseline);
                },
            );
        }
    }
    #[test]
    fn coherent_get_competing_handoff_announcement_releases_only_local_no_effect_ticket() {
        with_cloud_get_test(
            |owner, auth, io, gate, paused, stopping, counts, _, binding, intent, _| {
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let baseline = counts.writes.get();
                {
                    let (mut attempt, sends) = scripted_cloud(
                        auth,
                        io,
                        gate,
                        paused,
                        stopping,
                        cloud_snapshot(&binding, 0, 12),
                    );
                    attempt.handoff_race = true;
                    let mut turn = attempt.begin_get(owner, &operation).unwrap();
                    cloud_to(&mut turn, CloudGetPhase::Reconcile);
                    assert_eq!(
                        turn.try_step(),
                        Err(CloudGetError::Domain(domain::Error::Stale))
                    );
                    assert_eq!(sends.get(), 1);
                    assert_eq!(counts.writes.get(), baseline);
                }
                let fresh_cancel = AtomicBool::new(false);
                let fresh = Operation::new(end(), &fresh_cancel);
                assert!(owner.remote_authorization(&fresh).is_ok());
                assert_eq!(
                    owner
                        .store
                        .lock()
                        .unwrap()
                        .pending_host_publication()
                        .unwrap(),
                    Some(intent)
                );
            },
        );
    }
    // Authored/unrun; actual HostAuth/Store transitions, scripted TLS only.
    fn cloud_no_effect_finalization_case(fault: u8) {
        with_cloud_get_test(
            |owner, auth, io, gate, paused, stopping, counts, _, binding, intent, _| {
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let expected = if fault == 1 {
                    domain::Error::Cancelled
                } else {
                    domain::Error::Deadline
                };
                let baseline = counts.writes.get();
                let ready_before =
                    super::super::owner_domain::cloud_no_effect_state_for_test(&owner.domain);
                assert_eq!(ready_before.0, 0);
                assert!(ready_before.1.is_some());
                assert!(!ready_before.2);
                {
                    // expected old sequence leaves the original pending PUT intact;
                    // GET reconciliation completes with no authoritative Store call.
                    let (mut attempt, sends) = scripted_cloud(
                        auth,
                        io,
                        gate,
                        paused,
                        stopping,
                        cloud_snapshot(&binding, 0, 12),
                    );
                    let mut turn = attempt.begin_get(owner, &operation).unwrap();
                    cloud_to(&mut turn, CloudGetPhase::Reconcile);
                    super::super::owner_domain::CLOUD_NO_EFFECT_FINALIZE
                        .with(|value| value.set(fault));
                    assert_eq!(turn.try_step(), Ok(true));
                    assert_eq!(operation.check(), Err(expected));
                    assert!(matches!(
                        turn.decision.as_ref(),
                        Some(CloudGetDecision::Online { .. })
                    ));
                    assert_eq!(sends.get(), 1);
                    assert_eq!(counts.writes.get(), baseline);
                    assert_eq!(turn.try_step(), Err(CloudGetError::Stale));
                }
                let fresh_cancel = AtomicBool::new(false);
                let fresh = Operation::new(end(), &fresh_cancel);
                assert_eq!(
                    super::super::owner_domain::cloud_no_effect_state_for_test(&owner.domain),
                    ready_before
                );
                // Remote admission checks pending==0 AND the unchanged actual Ready.
                assert!(owner.remote_authorization(&fresh).is_ok());
                assert!(!gate.load(SeqCst));
                {
                    let store = owner.store.lock().unwrap();
                    assert_eq!(
                        store.pending_host_publication().unwrap(),
                        Some(intent.clone())
                    );
                    assert_eq!(
                        store
                            .cloud_runtime_reconciliation_state(&binding.scope)
                            .unwrap(),
                        Some(binding.clone())
                    );
                }
                let (mut attempt, sends) = scripted_cloud(
                    auth,
                    io,
                    gate,
                    paused,
                    stopping,
                    cloud_snapshot(&binding, 0, 12),
                );
                let mut turn = attempt.begin_get(owner, &fresh).unwrap();
                cloud_to(&mut turn, CloudGetPhase::Reconcile);
                assert_eq!(turn.try_step(), Ok(true));
                assert_eq!(sends.get(), 1);
                assert_eq!(counts.writes.get(), baseline);
                assert_eq!(
                    owner
                        .store
                        .lock()
                        .unwrap()
                        .pending_host_publication()
                        .unwrap(),
                    Some(intent)
                );
            },
        );
    }
    #[test]
    fn coherent_get_cancel_after_last_no_effect_check_releases_ticket_and_admits_fresh_get() {
        cloud_no_effect_finalization_case(1);
    }
    #[test]
    fn coherent_get_original_deadline_after_last_no_effect_check_releases_ticket_and_admits_fresh_get()
     {
        cloud_no_effect_finalization_case(2);
    }

    // Authored/unrun: these use the actual configured Transport budget facade.
    // An original stop must reject before resolver/socket work or auth acceptance.
    #[test]
    fn configured_ready_registration_stopped_original_budget_skips_http_and_acceptance() {
        for cancelled in [false, true] {
            with_ready_test(
                false,
                |_owner, auth, _setup, io, gate, paused, counts, _| {
                    let cancel = AtomicBool::new(cancelled);
                    let operation =
                        Operation::new(if cancelled { end() } else { Instant::now() }, &cancel);
                    let attempt = ConfiguredWorkerAttempt::from_existing_worker(
                        auth,
                        io,
                        gate,
                        paused,
                        1004,
                        Instant::now(),
                    )
                    .unwrap();
                    let (access, request) = attempt.auth.registration_request(1004).unwrap();
                    let request = WorkerReadyRequest::Register(access, request);
                    let before = (
                        counts.loads.get(),
                        counts.statuses.get(),
                        counts.writes.get(),
                    );
                    let result = match &attempt.http {
                        WorkerReadyHttp::Configured(transport) => {
                            configured_worker_ready_send(transport, &request, &operation)
                        }
                        _ => panic!("must exercise actual configured transport"),
                    };
                    let expected = if cancelled {
                        lomi_host_http::Error::Cancelled
                    } else {
                        lomi_host_http::Error::Timeout
                    };
                    assert!(matches!(result, Err(error) if error == expected));
                    assert_eq!(
                        (
                            counts.loads.get(),
                            counts.statuses.get(),
                            counts.writes.get()
                        ),
                        before
                    );
                    assert_eq!(attempt.auth.status(), lomi_host_auth::Status::Unconfirmed);
                },
            );
        }
    }
    #[test]
    fn configured_ready_refresh_stopped_original_budget_preserves_persisted_rotation() {
        for cancelled in [false, true] {
            with_ready_test(true, |_owner, auth, _setup, io, gate, paused, counts, _| {
                auth.prepare_rotation(1004).unwrap();
                let request = WorkerReadyRequest::Rotate(auth.rotation_request(1004).unwrap());
                let cancel = AtomicBool::new(cancelled);
                let operation =
                    Operation::new(if cancelled { end() } else { Instant::now() }, &cancel);
                let attempt = ConfiguredWorkerAttempt::from_existing_worker(
                    auth,
                    io,
                    gate,
                    paused,
                    1004,
                    Instant::now(),
                )
                .unwrap();
                let before = (
                    counts.loads.get(),
                    counts.statuses.get(),
                    counts.writes.get(),
                );
                let exact =
                    serde_json::to_string(&attempt.auth.rotation_request(1004).unwrap()).unwrap();
                let result = match &attempt.http {
                    WorkerReadyHttp::Configured(transport) => {
                        configured_worker_ready_send(transport, &request, &operation)
                    }
                    _ => panic!("must exercise actual configured transport"),
                };
                let expected = if cancelled {
                    lomi_host_http::Error::Cancelled
                } else {
                    lomi_host_http::Error::Timeout
                };
                assert!(matches!(result, Err(error) if error == expected));
                assert_eq!(
                    (
                        counts.loads.get(),
                        counts.statuses.get(),
                        counts.writes.get()
                    ),
                    before
                );
                assert_eq!(attempt.auth.status(), lomi_host_auth::Status::Rotating);
                assert_eq!(
                    serde_json::to_string(&attempt.auth.rotation_request(1004).unwrap()).unwrap(),
                    exact
                );
            });
        }
    }
    #[test]
    fn configured_cloud_get_stopped_same_original_budget_never_accepts_provider_response() {
        for cancelled in [false, true] {
            with_cloud_get_test(
                |owner, auth, io, gate, paused, stopping, counts, _, _binding, _, _| {
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let mut attempt = ConfiguredCloudAttempt::from_existing_worker(
                        auth,
                        io,
                        gate,
                        paused,
                        stopping,
                        1004,
                        Instant::now(),
                    );
                    attempt.projected = Some(1004);
                    let mut turn = attempt.begin_get(owner, &operation).unwrap();
                    assert_eq!(turn.try_step(), Ok(false)); // actual prepare constructs DataTransport under exact IO lease
                    let before = (
                        counts.loads.get(),
                        counts.statuses.get(),
                        counts.writes.get(),
                    );
                    if cancelled {
                        cancel.store(true, SeqCst);
                    } else {
                        operation.expire_for_test();
                    }
                    let result = match turn.attempt.http.as_ref().unwrap() {
                        CloudGetHttp::Configured(transport) => configured_cloud_get_send(
                            transport,
                            turn.request.as_ref().unwrap(),
                            turn.operation,
                        ),
                        _ => panic!("must exercise actual configured transport"),
                    };
                    let expected = if cancelled {
                        lomi_host_http::Error::Cancelled
                    } else {
                        lomi_host_http::Error::Timeout
                    };
                    assert!(matches!(result, Err(error) if error == expected));
                    assert!(turn.response.is_none());
                    assert!(turn.phase == CloudGetPhase::Send);
                    assert_eq!(
                        (
                            counts.loads.get(),
                            counts.statuses.get(),
                            counts.writes.get()
                        ),
                        before
                    );
                },
            );
        }
    }
    #[test]
    fn configured_near_expired_original_deadline_is_not_renewed_at_request_boundary() {
        with_ready_test(
            false,
            |_owner, auth, _setup, io, gate, paused, counts, _| {
                let cancel = AtomicBool::new(false);
                let admitted_deadline = Instant::now() + Duration::from_millis(20);
                let operation = Operation::new(admitted_deadline, &cancel);
                let budget = OriginalOperationHttpBudget {
                    operation: &operation,
                };
                assert_eq!(budget.deadline(), admitted_deadline);
                let attempt = ConfiguredWorkerAttempt::from_existing_worker(
                    auth,
                    io,
                    gate,
                    paused,
                    1004,
                    Instant::now(),
                )
                .unwrap();
                let (access, request) = attempt.auth.registration_request(1004).unwrap();
                let request = WorkerReadyRequest::Register(access, request);
                let before = counts.writes.get();
                std::thread::sleep(Duration::from_millis(25));
                let transport = match &attempt.http {
                    WorkerReadyHttp::Configured(transport) => transport,
                    _ => panic!("configured"),
                };
                assert!(matches!(
                    configured_worker_ready_send(transport, &request, &operation),
                    Err(lomi_host_http::Error::Timeout)
                ));
                assert_eq!(budget.deadline(), admitted_deadline);
                assert_eq!(counts.writes.get(), before);
            },
        );
    }
    #[test]
    fn configured_http_callback_observes_same_sticky_operation_after_external_reset() {
        with_ready_test(
            false,
            |_owner, auth, _setup, io, gate, paused, counts, _| {
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let budget = OriginalOperationHttpBudget {
                    operation: &operation,
                };
                let check = || budget.check();
                fn require_sync<T: Sync>(_: &T) {}
                require_sync(&check);
                assert!(std::ptr::eq(budget.operation, &operation));
                assert_eq!(check(), Ok(()));
                cancel.store(true, SeqCst);
                std::thread::scope(|scope| {
                    assert_eq!(
                        scope.spawn(check).join().unwrap(),
                        Err(lomi_host_http::BudgetStop::Cancelled)
                    );
                });
                cancel.store(false, SeqCst);
                assert_eq!(check(), Err(lomi_host_http::BudgetStop::Cancelled));
                assert_eq!(operation.check(), Err(domain::Error::Cancelled));
                let attempt = ConfiguredWorkerAttempt::from_existing_worker(
                    auth,
                    io,
                    gate,
                    paused,
                    1004,
                    Instant::now(),
                )
                .unwrap();
                let (access, request) = attempt.auth.registration_request(1004).unwrap();
                let before = counts.writes.get();
                let transport = match &attempt.http {
                    WorkerReadyHttp::Configured(transport) => transport,
                    _ => panic!("configured"),
                };
                assert!(matches!(
                    configured_worker_ready_send(
                        transport,
                        &WorkerReadyRequest::Register(access, request),
                        &operation
                    ),
                    Err(lomi_host_http::Error::Cancelled)
                ));
                assert_eq!(counts.writes.get(), before);
            },
        );
    }

    // Authored/unrun. Real Store/HostAuth transitions; synthetic provenance and
    // scripted PUT are cfg(test) mechanics, never configured TLS qualification.
    fn with_normal_publication_test(
        expected_get: bool,
        run: impl FnOnce(
            &Arc<SharedOwner>,
            &mut lomi_host_auth::HostAuth<'_, ReadyTestStorage>,
            super::super::auth::NormalPublicationDriver<'_>,
            &super::super::public_configuration::WorkerPublicIo<'_>,
            &AtomicBool,
            &AtomicBool,
            &AtomicBool,
            std::rc::Rc<ReadyTestCounts>,
            std::rc::Rc<std::cell::Cell<u8>>,
            CloudRuntimeState,
            HostPublicationIntent,
            WorkspaceId,
        ),
    ) {
        with_cloud_get_test(
            |owner,
             auth,
             io,
             gate,
             paused,
             stopping,
             counts,
             effect,
             binding,
             intent,
             workspace| {
                let get = super::super::auth::with_normal_publication_test_worker(|driver| {
                    run(
                        owner, auth, driver, io, gate, paused, stopping, counts, effect, binding,
                        intent, workspace,
                    )
                });
                assert_eq!(get, expected_get);
            },
        );
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Exercise all original publication authority inputs explicitly"
    )]
    fn scripted_normal_publication<'w, 'p, 'o, 'i>(
        owner: &SharedOwner,
        auth: &'w mut lomi_host_auth::HostAuth<'p, ReadyTestStorage>,
        driver: super::super::auth::NormalPublicationDriver<'w>,
        operation: &'o Operation<'o>,
        io: &'i super::super::public_configuration::WorkerPublicIo<'i>,
        gate: &'i AtomicBool,
        paused: &'i AtomicBool,
        stopping: &'i AtomicBool,
        binding: &CloudRuntimeState,
        reply: Option<Result<lomi_remote_protocol::http::PublicationResult, lomi_host_http::Error>>,
    ) -> (
        ConfiguredNormalPublication<'w, 'p, 'o, 'i, ReadyTestStorage>,
        std::rc::Rc<std::cell::Cell<usize>>,
    ) {
        let access = auth.access_credential(1004).unwrap();
        let sends = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut attempt = ConfiguredNormalPublication::from_existing_worker(
            auth,
            driver,
            operation,
            io,
            gate,
            paused,
            stopping,
            1004,
            Instant::now(),
        );
        attempt.projected = Some(1004);
        let heartbeat_sends = std::rc::Rc::new(std::cell::Cell::new(0));
        attempt.driver.as_mut().unwrap().script_heartbeat_test(
            binding,
            Ok(heartbeat_reply(binding)),
            heartbeat_sends.clone(),
            Duration::ZERO,
        );
        {
            let mut heartbeat = attempt.begin_configured_heartbeat(owner).unwrap();
            while !heartbeat.try_step().unwrap() {}
        }
        assert_eq!(heartbeat_sends.get(), 1);
        let response = lomi_remote_protocol::http::PublicationResult {
            runtime: binding.server_runtime.clone(),
            publication_seq: DecimalU64(binding.acknowledged_publication_seq.0 + 1),
        };
        attempt.http = Some(PublicationHttp::Scripted(PublicationScript {
            reply: Some(reply.unwrap_or(Ok(response))),
            sends: sends.clone(),
            expected_access: access,
            mutation: 0,
            selected_deadline: None,
            timeout_boundary: 0,
        }));
        (attempt, sends)
    }
    fn normal_to<S: lomi_platform::secrets::SecretStorage + ?Sized>(
        turn: &mut NormalPublicationTurn<'_, '_, '_, '_, '_, '_, S>,
        phase: NormalPublicationPhase,
    ) {
        for _ in 0..6 {
            if turn.phase == phase {
                return;
            }
            assert_eq!(turn.try_step(), Ok(false));
        }
        panic!("normal publication phase not reached");
    }
    // Authored/unrun. The script uses the actual fixed budget selection and
    // models IO interruption sites; no real socket/TLS timing is exercised.
    #[test]
    fn normal_publication_http_selects_original_heartbeat_or_earlier_operation_deadline() {
        for operation_first in [false, true] {
            with_normal_publication_test(
                false,
                |owner, auth, driver, io, gate, paused, stopping, _, _, binding, _, _| {
                    let cancel = AtomicBool::new(false);
                    let original_deadline = Instant::now()
                        .checked_add(Duration::from_secs(if operation_first { 2 } else { 60 }))
                        .unwrap();
                    let operation = Operation::new(original_deadline, &cancel);
                    let (mut attempt, sends) = scripted_normal_publication(
                        owner, auth, driver, &operation, io, gate, paused, stopping, &binding, None,
                    );
                    let anchors = attempt
                        .observation
                        .as_ref()
                        .unwrap()
                        .publication_anchors_test();
                    let expected = original_deadline
                        .min(
                            anchors
                                .0
                                .checked_add(Duration::from_millis(anchors.1))
                                .unwrap(),
                        )
                        .min(
                            anchors
                                .0
                                .checked_add(Duration::from_millis(anchors.2))
                                .unwrap(),
                        );
                    if operation_first {
                        assert_eq!(expected, original_deadline);
                    } else {
                        assert!(expected < original_deadline);
                    }
                    let mut turn = attempt.begin(owner).unwrap();
                    normal_to(&mut turn, NormalPublicationPhase::AfterPut);
                    match turn.attempt.http.as_ref().unwrap() {
                        PublicationHttp::Scripted(script) => {
                            assert_eq!(script.selected_deadline, Some(expected))
                        }
                        _ => panic!("script"),
                    }
                    assert_eq!(turn.attempt.operation.deadline(), original_deadline);
                    assert_eq!(
                        turn.attempt
                            .observation
                            .as_ref()
                            .unwrap()
                            .publication_anchors_test(),
                        anchors
                    );
                    normal_to(&mut turn, NormalPublicationPhase::Ack);
                    assert_eq!(turn.try_step(), Ok(true));
                    assert_eq!(sends.get(), 1);
                },
            );
        }
    }
    #[test]
    fn normal_publication_http_watcher_keeps_original_sticky_cancel_and_only_copied_deadline() {
        with_normal_publication_test(
            true,
            |owner, auth, driver, io, gate, paused, stopping, _, _, binding, _, _| {
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (attempt, sends) = scripted_normal_publication(
                    owner, auth, driver, &operation, io, gate, paused, stopping, &binding, None,
                );
                let observation = attempt.observation.as_ref().unwrap();
                let budget =
                    PublicationHttpBudget::from_observation(observation, &operation, 1004).unwrap();
                assert!(std::ptr::eq(budget.operation, &operation));
                let check = || budget.check();
                fn require_sync<T: Sync>(_: &T) {}
                require_sync(&check);
                assert_eq!(check(), Ok(()));
                assert_eq!(
                    budget.check_at(budget.deadline),
                    Err(lomi_host_http::BudgetStop::Deadline)
                );
                cancel.store(true, SeqCst);
                assert_eq!(check(), Err(lomi_host_http::BudgetStop::Cancelled));
                cancel.store(false, SeqCst);
                assert_eq!(
                    budget.check_at(budget.deadline),
                    Err(lomi_host_http::BudgetStop::Cancelled)
                );
                assert_eq!(operation.check(), Err(domain::Error::Cancelled));
                assert_eq!(sends.get(), 0);
            },
        );
    }
    #[test]
    fn normal_publication_http_missing_changed_or_expired_observation_anchors_deny_before_transport()
     {
        for fault in 0..4 {
            with_normal_publication_test(
                true,
                |owner, auth, driver, io, gate, paused, stopping, _, _, binding, _, _| {
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let (mut attempt, sends) = scripted_normal_publication(
                        owner, auth, driver, &operation, io, gate, paused, stopping, &binding, None,
                    );
                    let observation = attempt.observation.as_mut().unwrap();
                    let original = observation.publication_anchors_test();
                    if fault < 3 {
                        observation.invalidate_publication_anchor_test(fault);
                    } else {
                        observation.advance_publication_clock_test(
                            original
                                .0
                                .checked_add(Duration::from_millis(original.1))
                                .unwrap(),
                        );
                    }
                    assert!(matches!(
                        PublicationHttpBudget::from_observation(observation, &operation, 1004),
                        Err(PublicationError::Stale)
                    ));
                    assert_eq!(observation.publication_anchors_test(), original);
                    assert_eq!(sends.get(), 0);
                },
            );
        }
    }
    #[test]
    fn normal_publication_http_synthetic_expiry_at_write_wait_read_preserves_intent_and_never_replays()
     {
        for boundary in 1..=3 {
            with_normal_publication_test(
                true,
                |owner, auth, driver, io, gate, paused, stopping, counts, _, binding, intent, _| {
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let writes = counts.writes.get();
                    let (mut attempt, sends) = scripted_normal_publication(
                        owner, auth, driver, &operation, io, gate, paused, stopping, &binding, None,
                    );
                    if let Some(PublicationHttp::Scripted(script)) = attempt.http.as_mut() {
                        script.timeout_boundary = boundary;
                    }
                    let mut turn = attempt.begin(owner).unwrap();
                    normal_to(&mut turn, NormalPublicationPhase::Send);
                    let retained_intent = turn.intent.as_ref().unwrap().clone();
                    assert_eq!(retained_intent, intent);
                    assert_eq!(
                        turn.try_step(),
                        Err(PublicationError::Http(lomi_host_http::Error::Timeout))
                    );
                    assert_eq!(
                        turn.try_step(),
                        Err(PublicationError::Http(lomi_host_http::Error::Timeout))
                    );
                    assert_eq!(turn.intent.as_ref(), Some(&retained_intent));
                    assert!(turn.response.is_none());
                    assert_eq!(sends.get(), 1);
                    let store = owner.store.lock().unwrap();
                    assert_eq!(
                        store.pending_host_publication().unwrap(),
                        Some(retained_intent)
                    );
                    assert!(
                        store
                            .acknowledged_host_publication(&binding)
                            .unwrap()
                            .is_none()
                    );
                    assert_eq!(counts.writes.get(), writes);
                },
            );
        }
    }
    #[test]
    fn normal_publication_http_postresponse_busy_then_heartbeat_expiry_cannot_ack_or_replay() {
        for phase in [
            NormalPublicationPhase::AfterPut,
            NormalPublicationPhase::Ack,
        ] {
            for store_busy in [false, true] {
                with_normal_publication_test(
                    true,
                    |owner, auth, driver, io, gate, paused, stopping, _, _, binding, _, _| {
                        let cancel = AtomicBool::new(false);
                        let operation = Operation::new(end(), &cancel);
                        let (mut attempt, sends) = scripted_normal_publication(
                            owner, auth, driver, &operation, io, gate, paused, stopping, &binding,
                            None,
                        );
                        let anchors = attempt
                            .observation
                            .as_ref()
                            .unwrap()
                            .publication_anchors_test();
                        let mut turn = attempt.begin(owner).unwrap();
                        normal_to(&mut turn, phase);
                        let intent = turn.intent.as_ref().unwrap().clone();
                        let response = turn.response.as_ref().unwrap() as *const _;
                        if store_busy {
                            let held = owner.store.lock().unwrap();
                            assert_eq!(
                                turn.try_step(),
                                Err(PublicationError::Domain(domain::Error::Busy))
                            );
                            drop(held);
                        } else {
                            let held = owner.domain.try_read(&operation).unwrap();
                            assert_eq!(
                                turn.try_step(),
                                Err(PublicationError::Domain(domain::Error::Busy))
                            );
                            drop(held);
                        }
                        assert!(turn.phase == phase);
                        assert_eq!(turn.response.as_ref().unwrap() as *const _, response);
                        turn.attempt
                            .observation
                            .as_mut()
                            .unwrap()
                            .advance_publication_clock_test(
                                anchors
                                    .0
                                    .checked_add(Duration::from_millis(anchors.1))
                                    .unwrap(),
                            );
                        assert_eq!(turn.try_step(), Err(PublicationError::Stale));
                        assert_eq!(turn.try_step(), Err(PublicationError::Stale));
                        assert_eq!(turn.intent.as_ref(), Some(&intent));
                        assert_eq!(turn.response.as_ref().unwrap() as *const _, response);
                        assert_eq!(sends.get(), 1);
                        let store = owner.store.lock().unwrap();
                        assert_eq!(store.pending_host_publication().unwrap(), Some(intent));
                        assert!(
                            store
                                .acknowledged_host_publication(&binding)
                                .unwrap()
                                .is_none()
                        );
                    },
                );
            }
        }
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Exercise all original heartbeat authority inputs explicitly"
    )]
    fn scripted_heartbeat<'w, 'p, 'o, 'i>(
        auth: &'w mut lomi_host_auth::HostAuth<'p, ReadyTestStorage>,
        mut driver: super::super::auth::NormalPublicationDriver<'w>,
        operation: &'o Operation<'o>,
        io: &'i super::super::public_configuration::WorkerPublicIo<'i>,
        gate: &'i AtomicBool,
        paused: &'i AtomicBool,
        stopping: &'i AtomicBool,
        binding: &CloudRuntimeState,
        reply: Result<lomi_remote_protocol::http::HeartbeatResult, lomi_host_http::Error>,
        elapsed: Duration,
    ) -> (
        ConfiguredNormalPublication<'w, 'p, 'o, 'i, ReadyTestStorage>,
        std::rc::Rc<std::cell::Cell<usize>>,
    ) {
        let sends = std::rc::Rc::new(std::cell::Cell::new(0));
        driver.script_heartbeat_test(binding, reply, sends.clone(), elapsed);
        let mut attempt = ConfiguredNormalPublication::from_existing_worker(
            auth,
            driver,
            operation,
            io,
            gate,
            paused,
            stopping,
            1004,
            Instant::now(),
        );
        attempt.projected = Some(1004);
        (attempt, sends)
    }
    fn heartbeat_reply(binding: &CloudRuntimeState) -> lomi_remote_protocol::http::HeartbeatResult {
        lomi_remote_protocol::http::HeartbeatResult {
            runtime: binding.server_runtime.clone(),
            lease_ms: DecimalU64(30_000),
            freshness_ms: DecimalU64(5_000),
        }
    }
    fn heartbeat_to<S: lomi_platform::secrets::SecretStorage + ?Sized>(
        turn: &mut ConfiguredHeartbeatTurn<'_, '_, '_, '_, '_, '_, S>,
        phase: ConfiguredHeartbeatPhase,
    ) {
        for _ in 0..8 {
            if turn.phase == phase {
                return;
            }
            assert_eq!(turn.try_step(), Ok(false));
        }
        panic!("heartbeat phase not reached");
    }
    #[test]
    fn configured_heartbeat_installs_only_after_postclock_and_hands_same_observation_to_publication()
     {
        with_normal_publication_test(
            false,
            |owner, auth, driver, io, gate, paused, stopping, counts, _, binding, _, _| {
                let provider = auth as *mut _ as usize;
                let writes = counts.writes.get();
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let ready =
                    super::super::owner_domain::cloud_no_effect_state_for_test(&owner.domain);
                let (mut attempt, sends) = scripted_heartbeat(
                    auth,
                    driver,
                    &operation,
                    io,
                    gate,
                    paused,
                    stopping,
                    &binding,
                    Ok(heartbeat_reply(&binding)),
                    Duration::ZERO,
                );
                let mut turn = attempt.begin_configured_heartbeat(owner).unwrap();
                heartbeat_to(&mut turn, ConfiguredHeartbeatPhase::InstallObservation);
                assert!(turn.attempt.observation.is_none());
                assert_eq!(sends.get(), 1);
                assert_eq!(turn.try_step(), Ok(true));
                assert_eq!(turn.attempt.auth as *mut _ as usize, provider);
                let accepted = turn.attempt.observation.as_ref().unwrap() as *const _;
                assert_eq!(turn.try_step(), Err(PublicationError::Stale));
                assert_eq!(turn.phase, ConfiguredHeartbeatPhase::Complete);
                assert!(turn.terminal.is_none());
                assert_eq!(
                    turn.attempt.observation.as_ref().unwrap() as *const _,
                    accepted
                );
                assert_eq!(counts.writes.get(), writes);
                assert_eq!(
                    super::super::owner_domain::cloud_no_effect_state_for_test(&owner.domain),
                    ready
                );
                let observation = turn.attempt.observation.as_ref().unwrap();
                assert!(std::ptr::eq(observation.operation(), &operation));
                assert_eq!(observation.binding(), &binding);
                drop(turn);
                let put_sends = std::rc::Rc::new(std::cell::Cell::new(0));
                let access = attempt.auth.access_credential(1004).unwrap();
                attempt.http = Some(PublicationHttp::Scripted(PublicationScript {
                    reply: Some(Ok(lomi_remote_protocol::http::PublicationResult {
                        runtime: binding.server_runtime.clone(),
                        publication_seq: DecimalU64(binding.acknowledged_publication_seq.0 + 1),
                    })),
                    sends: put_sends.clone(),
                    expected_access: access,
                    mutation: 0,
                    selected_deadline: None,
                    timeout_boundary: 0,
                }));
                let mut publication = attempt.begin(owner).unwrap();
                assert!(std::ptr::eq(publication.attempt.operation, &operation));
                assert_eq!(
                    publication.attempt.observation.as_ref().unwrap() as *const _,
                    accepted
                );
                assert_eq!(publication.attempt.auth as *mut _ as usize, provider);
                {
                    let held = owner.store.lock().unwrap();
                    assert_eq!(
                        publication.try_step(),
                        Err(PublicationError::Domain(domain::Error::Busy))
                    );
                    assert_eq!(
                        publication.attempt.observation.as_ref().unwrap() as *const _,
                        accepted
                    );
                    assert!(std::ptr::eq(publication.attempt.operation, &operation));
                    assert_eq!(publication.attempt.auth as *mut _ as usize, provider);
                    assert_eq!(put_sends.get(), 0);
                    assert_eq!(sends.get(), 1);
                    drop(held);
                }
                normal_to(&mut publication, NormalPublicationPhase::Ack);
                assert_eq!(
                    publication.attempt.observation.as_ref().unwrap() as *const _,
                    accepted
                );
                assert!(std::ptr::eq(
                    publication
                        .attempt
                        .observation
                        .as_ref()
                        .unwrap()
                        .operation(),
                    &operation
                ));
                assert_eq!(publication.try_step(), Ok(true));
                assert_eq!(publication.try_step(), Err(PublicationError::Stale));
                assert_eq!(publication.attempt.auth as *mut _ as usize, provider);
                assert_eq!(put_sends.get(), 1);
                assert_eq!(sends.get(), 1);
            },
        );
    }
    #[test]
    fn configured_heartbeat_full_original_tuple_and_ready_denial_prevent_tls() {
        for fault in [
            CloudGetTupleFault::Configuration,
            CloudGetTupleFault::PublicDocument,
            CloudGetTupleFault::PublicReadiness,
            CloudGetTupleFault::Scope,
            CloudGetTupleFault::Previous,
            CloudGetTupleFault::Pending,
            CloudGetTupleFault::Generation,
            CloudGetTupleFault::Epoch,
            CloudGetTupleFault::Identity,
            CloudGetTupleFault::Deadline,
        ] {
            with_normal_publication_test(
                true,
                |owner, auth, driver, io, gate, paused, stopping, _, _, binding, _, _| {
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let (mut attempt, sends) = scripted_heartbeat(
                        auth,
                        driver,
                        &operation,
                        io,
                        gate,
                        paused,
                        stopping,
                        &binding,
                        Ok(heartbeat_reply(&binding)),
                        Duration::ZERO,
                    );
                    let mut turn = attempt.begin_configured_heartbeat(owner).unwrap();
                    heartbeat_to(&mut turn, ConfiguredHeartbeatPhase::FinalSendAdmission);
                    turn.final_send_fault = Some(fault);
                    assert!(turn.try_step().is_err());
                    assert_eq!(sends.get(), 0);
                    assert!(turn.attempt.observation.is_none());
                },
            );
        }
        with_normal_publication_test(
            true,
            |owner, auth, driver, io, gate, paused, stopping, _, _, binding, _, _| {
                owner.domain.cloud_uncertain();
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends) = scripted_heartbeat(
                    auth,
                    driver,
                    &operation,
                    io,
                    gate,
                    paused,
                    stopping,
                    &binding,
                    Ok(heartbeat_reply(&binding)),
                    Duration::ZERO,
                );
                let mut turn = attempt.begin_configured_heartbeat(owner).unwrap();
                assert!(turn.try_step().is_err());
                assert_eq!(sends.get(), 0);
            },
        );
    }
    #[test]
    fn configured_heartbeat_writer_announced_after_provider_prevents_tls() {
        with_normal_publication_test(
            true,
            |owner, auth, driver, io, gate, paused, stopping, _, _, binding, _, _| {
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends) = scripted_heartbeat(
                    auth,
                    driver,
                    &operation,
                    io,
                    gate,
                    paused,
                    stopping,
                    &binding,
                    Ok(heartbeat_reply(&binding)),
                    Duration::ZERO,
                );
                let mut turn = attempt.begin_configured_heartbeat(owner).unwrap();
                heartbeat_to(&mut turn, ConfiguredHeartbeatPhase::FinalSendAdmission);
                let _writer = owner
                    .domain
                    .announce(&operation, WriterClass::Remote, Intent::Mutation)
                    .unwrap();
                assert_eq!(
                    turn.try_step(),
                    Err(PublicationError::Domain(domain::Error::Stale))
                );
                assert_eq!(sends.get(), 0);
            },
        );
    }
    #[test]
    fn configured_heartbeat_busy_retains_original_scope_operation_response_and_sends_once() {
        for phase in [
            ConfiguredHeartbeatPhase::Capture,
            ConfiguredHeartbeatPhase::FinalSendAdmission,
            ConfiguredHeartbeatPhase::PostClock,
            ConfiguredHeartbeatPhase::InstallObservation,
        ] {
            for store_busy in [false, true] {
                with_normal_publication_test(
                    true,
                    |owner, auth, driver, io, gate, paused, stopping, _, _, binding, _, _| {
                        let cancel = AtomicBool::new(false);
                        let operation = Operation::new(end(), &cancel);
                        let (mut attempt, sends) = scripted_heartbeat(
                            auth,
                            driver,
                            &operation,
                            io,
                            gate,
                            paused,
                            stopping,
                            &binding,
                            Ok(heartbeat_reply(&binding)),
                            Duration::ZERO,
                        );
                        let mut turn = attempt.begin_configured_heartbeat(owner).unwrap();
                        heartbeat_to(&mut turn, phase);
                        let scope = turn.scope.as_ref().map(|scope| scope as *const _);
                        let retained = turn
                            .attempt
                            .driver
                            .as_ref()
                            .unwrap()
                            .retained_heartbeat_test();
                        let before = sends.get();
                        if store_busy {
                            let held = owner.store.lock().unwrap();
                            assert_eq!(
                                turn.try_step(),
                                Err(PublicationError::Domain(domain::Error::Busy))
                            );
                            drop(held);
                        } else {
                            let held = owner.domain.try_read(&operation).unwrap();
                            assert_eq!(
                                turn.try_step(),
                                Err(PublicationError::Domain(domain::Error::Busy))
                            );
                            drop(held);
                        }
                        assert_eq!(turn.phase, phase);
                        assert!(turn.terminal.is_none());
                        assert_eq!(sends.get(), before);
                        assert_eq!(turn.scope.as_ref().map(|scope| scope as *const _), scope);
                        assert!(std::ptr::eq(turn.attempt.operation, &operation));
                        assert_eq!(
                            turn.attempt
                                .driver
                                .as_ref()
                                .unwrap()
                                .retained_heartbeat_test(),
                            retained
                        );
                        heartbeat_to(&mut turn, ConfiguredHeartbeatPhase::InstallObservation);
                        assert_eq!(turn.try_step(), Ok(true));
                        assert_eq!(sends.get(), 1);
                    },
                );
            }
        }
    }
    #[test]
    fn configured_heartbeat_original_cancel_deadline_and_latches_stop_every_phase_without_replay() {
        for phase in [
            ConfiguredHeartbeatPhase::Capture,
            ConfiguredHeartbeatPhase::PrepareProvider,
            ConfiguredHeartbeatPhase::FinalSendAdmission,
            ConfiguredHeartbeatPhase::ValidateProvider,
            ConfiguredHeartbeatPhase::PostClock,
            ConfiguredHeartbeatPhase::InstallObservation,
        ] {
            for stop in 0..6 {
                with_normal_publication_test(
                    true,
                    |owner, auth, driver, io, gate, paused, stopping, _, _, binding, _, _| {
                        let cancel = AtomicBool::new(false);
                        let operation = Operation::new(end(), &cancel);
                        let (mut attempt, sends) = scripted_heartbeat(
                            auth,
                            driver,
                            &operation,
                            io,
                            gate,
                            paused,
                            stopping,
                            &binding,
                            Ok(heartbeat_reply(&binding)),
                            Duration::ZERO,
                        );
                        let mut turn = attempt.begin_configured_heartbeat(owner).unwrap();
                        heartbeat_to(&mut turn, phase);
                        let before = sends.get();
                        match stop {
                            0 => cancel.store(true, SeqCst),
                            1 => operation.expire_for_test(),
                            2 => gate.store(true, SeqCst),
                            3 => paused.store(true, SeqCst),
                            4 => stopping.store(true, SeqCst),
                            _ => io.setup().pending.store(true, SeqCst),
                        }
                        // ValidateProvider saves provider outcome first; the next fixed
                        // stage checks original sticky operation/latches before effects.
                        if phase == ConfiguredHeartbeatPhase::ValidateProvider {
                            assert_eq!(turn.try_step(), Ok(false));
                        }
                        assert!(turn.try_step().is_err());
                        assert!(turn.try_step().is_err());
                        assert_eq!(sends.get(), before);
                        assert!(turn.attempt.observation.is_none());
                    },
                );
            }
        }
    }
    #[test]
    fn configured_heartbeat_provider_seal_is_primary_before_clock_fence_or_cancel() {
        for phase in [
            ConfiguredHeartbeatPhase::ValidateProvider,
            ConfiguredHeartbeatPhase::PostClock,
            ConfiguredHeartbeatPhase::InstallObservation,
        ] {
            with_normal_publication_test(
                true,
                |owner, auth, driver, io, gate, paused, stopping, _, effect, binding, _, _| {
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let (mut attempt, sends) = scripted_heartbeat(
                        auth,
                        driver,
                        &operation,
                        io,
                        gate,
                        paused,
                        stopping,
                        &binding,
                        Ok(heartbeat_reply(&binding)),
                        Duration::ZERO,
                    );
                    let mut turn = attempt.begin_configured_heartbeat(owner).unwrap();
                    heartbeat_to(&mut turn, phase);
                    effect.set(2);
                    assert_eq!(
                        turn.attempt.auth.prepare_rotation(1004),
                        Err(lomi_host_auth::Error::Storage(
                            lomi_platform::secrets::Error::CommitUncertain
                        ))
                    );
                    cancel.store(true, SeqCst);
                    owner.domain.cloud_uncertain();
                    assert_eq!(
                        turn.try_step(),
                        Err(PublicationError::Auth(lomi_host_auth::Error::Sealed))
                    );
                    assert_eq!(sends.get(), 1);
                },
            );
        }
    }
    #[test]
    fn configured_heartbeat_provider_pointer_identity_epoch_deadlines_access_and_config_are_exact()
    {
        for fault in 0..6 {
            with_normal_publication_test(
                true,
                |owner, auth, driver, io, gate, paused, stopping, _, _, binding, _, _| {
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let (mut attempt, sends) = scripted_heartbeat(
                        auth,
                        driver,
                        &operation,
                        io,
                        gate,
                        paused,
                        stopping,
                        &binding,
                        Ok(heartbeat_reply(&binding)),
                        Duration::ZERO,
                    );
                    let mut turn = attempt.begin_configured_heartbeat(owner).unwrap();
                    heartbeat_to(&mut turn, ConfiguredHeartbeatPhase::ValidateProvider);
                    if fault < 5 {
                        turn.attempt
                            .driver
                            .as_mut()
                            .unwrap()
                            .corrupt_heartbeat_provider_test(fault);
                    } else {
                        let cloud = &mut turn.tuple.as_mut().unwrap().cloud;
                        cloud.trusted = lomi_host_auth::Config::new(
                            cloud.identity.host_id,
                            cloud.identity.profile_id,
                            cloud.configuration.origin.as_str().to_owned(),
                            "different-client".to_owned().try_into().unwrap(),
                        )
                        .unwrap();
                    }
                    assert_eq!(turn.try_step(), Err(PublicationError::Stale));
                    assert_eq!(sends.get(), 1);
                    assert!(turn.attempt.observation.is_none());
                },
            );
        }
    }
    #[test]
    fn configured_heartbeat_drop_after_response_does_not_install_or_restart_old_resource() {
        with_normal_publication_test(
            true,
            |owner, auth, driver, io, gate, paused, stopping, _, _, binding, _, _| {
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends) = scripted_heartbeat(
                    auth,
                    driver,
                    &operation,
                    io,
                    gate,
                    paused,
                    stopping,
                    &binding,
                    Ok(heartbeat_reply(&binding)),
                    Duration::ZERO,
                );
                let mut turn = attempt.begin_configured_heartbeat(owner).unwrap();
                heartbeat_to(&mut turn, ConfiguredHeartbeatPhase::ValidateProvider);
                drop(turn);
                assert!(attempt.observation.is_none());
                assert!(attempt.begin_configured_heartbeat(owner).is_err());
                assert_eq!(sends.get(), 1);
                assert_eq!(
                    owner
                        .store
                        .lock()
                        .unwrap()
                        .cloud_runtime_state(&binding.scope)
                        .unwrap(),
                    Some(binding)
                );
            },
        );
    }
    #[test]
    fn configured_heartbeat_malformed_and_delayed_responses_never_install_or_replay() {
        for fault in 0..9 {
            with_normal_publication_test(
                true,
                |owner, auth, driver, io, gate, paused, stopping, _, _, binding, _, _| {
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let mut reply = heartbeat_reply(&binding);
                    match fault {
                        0 => reply.runtime.runtime_generation.0 += 1,
                        1 => reply.runtime.host_access_epoch.0 += 1,
                        2 => reply.lease_ms.0 = 0,
                        3 => reply.lease_ms.0 = 30_001,
                        4 => reply.freshness_ms.0 = 0,
                        5 => reply.freshness_ms.0 = 5_001,
                        6 => reply.lease_ms.0 = 1,
                        _ => (),
                    }
                    let elapsed = if fault >= 7 {
                        Duration::from_secs(if fault == 7 { 6 } else { 31 })
                    } else {
                        Duration::ZERO
                    };
                    let (mut attempt, sends) = scripted_heartbeat(
                        auth,
                        driver,
                        &operation,
                        io,
                        gate,
                        paused,
                        stopping,
                        &binding,
                        Ok(reply),
                        elapsed,
                    );
                    let mut turn = attempt.begin_configured_heartbeat(owner).unwrap();
                    heartbeat_to(&mut turn, ConfiguredHeartbeatPhase::InstallObservation);
                    let expected = if fault < 7 {
                        PublicationError::Http(lomi_host_http::Error::InvalidResponse)
                    } else {
                        PublicationError::Stale
                    };
                    assert_eq!(turn.try_step(), Err(expected));
                    assert_eq!(turn.try_step(), Err(expected));
                    assert_eq!(sends.get(), 1);
                    assert!(turn.attempt.observation.is_none());
                },
            );
        }
    }
    #[test]
    fn configured_heartbeat_missing_or_already_expired_original_lease_prevents_tls() {
        for missing in [true, false] {
            with_normal_publication_test(
                true,
                |owner, auth, driver, io, gate, paused, stopping, _, _, binding, _, _| {
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let (mut attempt, sends) = scripted_heartbeat(
                        auth,
                        driver,
                        &operation,
                        io,
                        gate,
                        paused,
                        stopping,
                        &binding,
                        Ok(heartbeat_reply(&binding)),
                        Duration::ZERO,
                    );
                    let lease = if missing {
                        None
                    } else {
                        Instant::now().checked_sub(Duration::from_secs(1))
                    };
                    attempt
                        .driver
                        .as_mut()
                        .unwrap()
                        .set_original_heartbeat_lease_test(lease);
                    let mut turn = attempt.begin_configured_heartbeat(owner).unwrap();
                    heartbeat_to(&mut turn, ConfiguredHeartbeatPhase::PrepareProvider);
                    assert_eq!(turn.try_step(), Err(PublicationError::Stale));
                    assert_eq!(sends.get(), 0);
                    assert!(turn.attempt.observation.is_none());
                },
            );
        }
    }
    #[test]
    fn configured_heartbeat_original_lease_expiry_during_busy_keeps_same_anchor_and_prevents_tls() {
        for store_busy in [false, true] {
            with_normal_publication_test(
                true,
                |owner, auth, driver, io, gate, paused, stopping, _, _, binding, _, _| {
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let (mut attempt, sends) = scripted_heartbeat(
                        auth,
                        driver,
                        &operation,
                        io,
                        gate,
                        paused,
                        stopping,
                        &binding,
                        Ok(heartbeat_reply(&binding)),
                        Duration::ZERO,
                    );
                    let lease = attempt
                        .driver
                        .as_ref()
                        .unwrap()
                        .original_heartbeat_lease_test()
                        .unwrap();
                    let mut turn = attempt.begin_configured_heartbeat(owner).unwrap();
                    heartbeat_to(&mut turn, ConfiguredHeartbeatPhase::FinalSendAdmission);
                    if store_busy {
                        let held = owner.store.lock().unwrap();
                        assert_eq!(
                            turn.try_step(),
                            Err(PublicationError::Domain(domain::Error::Busy))
                        );
                        drop(held);
                    } else {
                        let held = owner.domain.try_read(&operation).unwrap();
                        assert_eq!(
                            turn.try_step(),
                            Err(PublicationError::Domain(domain::Error::Busy))
                        );
                        drop(held);
                    }
                    turn.attempt
                        .driver
                        .as_mut()
                        .unwrap()
                        .advance_heartbeat_lease_clock_test(lease);
                    assert_eq!(
                        turn.attempt
                            .driver
                            .as_ref()
                            .unwrap()
                            .original_heartbeat_lease_test(),
                        Some(lease)
                    );
                    assert_eq!(turn.try_step(), Err(PublicationError::Stale));
                    assert_eq!(sends.get(), 0);
                    assert!(turn.attempt.observation.is_none());
                },
            );
        }
    }
    #[test]
    fn configured_heartbeat_expired_or_changed_lease_at_final_send_boundary_prevents_tls() {
        for changed in [false, true] {
            with_normal_publication_test(
                true,
                |owner, auth, driver, io, gate, paused, stopping, _, _, binding, _, _| {
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let (mut attempt, sends) = scripted_heartbeat(
                        auth,
                        driver,
                        &operation,
                        io,
                        gate,
                        paused,
                        stopping,
                        &binding,
                        Ok(heartbeat_reply(&binding)),
                        Duration::ZERO,
                    );
                    let mut turn = attempt.begin_configured_heartbeat(owner).unwrap();
                    heartbeat_to(&mut turn, ConfiguredHeartbeatPhase::FinalSendAdmission);
                    let driver = turn.attempt.driver.as_mut().unwrap();
                    let original = driver.original_heartbeat_lease_test().unwrap();
                    if changed {
                        driver.change_current_heartbeat_lease_test();
                    } else {
                        driver.advance_heartbeat_lease_clock_test(original);
                    }
                    assert_eq!(driver.original_heartbeat_lease_test(), Some(original));
                    assert_eq!(turn.try_step(), Err(PublicationError::Stale));
                    assert_eq!(sends.get(), 0);
                    assert!(turn.attempt.observation.is_none());
                },
            );
        }
    }
    #[test]
    fn configured_heartbeat_transport_error_is_terminal_and_drop_cannot_restart_request() {
        with_normal_publication_test(
            true,
            |owner, auth, driver, io, gate, paused, stopping, _, _, binding, _, _| {
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends) = scripted_heartbeat(
                    auth,
                    driver,
                    &operation,
                    io,
                    gate,
                    paused,
                    stopping,
                    &binding,
                    Err(lomi_host_http::Error::Network),
                    Duration::ZERO,
                );
                let mut turn = attempt.begin_configured_heartbeat(owner).unwrap();
                heartbeat_to(&mut turn, ConfiguredHeartbeatPhase::FinalSendAdmission);
                assert_eq!(
                    turn.try_step(),
                    Err(PublicationError::Http(lomi_host_http::Error::Network))
                );
                assert_eq!(
                    turn.try_step(),
                    Err(PublicationError::Http(lomi_host_http::Error::Network))
                );
                drop(turn);
                assert!(attempt.begin_configured_heartbeat(owner).is_err());
                assert_eq!(sends.get(), 1);
            },
        );
    }
    #[test]
    fn configured_heartbeat_advanced_store_clock_cannot_refresh_expired_provider() {
        with_normal_publication_test(
            true,
            |owner, auth, driver, io, gate, paused, stopping, _, _, binding, _, _| {
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends) = scripted_heartbeat(
                    auth,
                    driver,
                    &operation,
                    io,
                    gate,
                    paused,
                    stopping,
                    &binding,
                    Ok(heartbeat_reply(&binding)),
                    Duration::ZERO,
                );
                let mut turn = attempt.begin_configured_heartbeat(owner).unwrap();
                heartbeat_to(&mut turn, ConfiguredHeartbeatPhase::PostClock);
                owner
                    .store
                    .lock()
                    .unwrap()
                    .observe_authorization_clock(u64::MAX)
                    .unwrap();
                assert_eq!(turn.try_step(), Ok(false));
                assert!(turn.try_step().is_err());
                assert_eq!(sends.get(), 1);
                assert!(turn.attempt.observation.is_none());
            },
        );
    }
    #[test]
    fn normal_publication_retains_original_scope_provider_intent_and_only_known_advance_through_ack()
     {
        with_normal_publication_test(
            false,
            |owner, auth, driver, io, gate, paused, stopping, counts, _, binding, intent, _| {
                let provider = auth as *mut _ as usize;
                let before = (counts.loads.get(), counts.writes.get());
                let ready =
                    super::super::owner_domain::cloud_no_effect_state_for_test(&owner.domain);
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends) = scripted_normal_publication(
                    owner, auth, driver, &operation, io, gate, paused, stopping, &binding, None,
                );
                assert_eq!(attempt.auth as *mut _ as usize, provider);
                let mut turn = attempt.begin(owner).unwrap();
                normal_to(&mut turn, NormalPublicationPhase::Prepare);
                let original = turn.continuation.as_ref().unwrap().original_for_test();
                assert_eq!(turn.try_step(), Ok(false));
                assert_eq!(turn.intent.as_ref(), Some(&intent));
                assert_eq!(
                    turn.continuation.as_ref().unwrap().original_for_test(),
                    original
                );
                normal_to(&mut turn, NormalPublicationPhase::Ack);
                assert_eq!(turn.try_step(), Ok(true));
                assert_eq!(
                    turn.continuation.as_ref().unwrap().original_for_test(),
                    original
                );
                assert_eq!(sends.get(), 1);
                assert_eq!((counts.loads.get(), counts.writes.get()), before);
                assert_eq!(
                    super::super::owner_domain::cloud_no_effect_state_for_test(&owner.domain),
                    ready
                );
                assert!(
                    owner
                        .store
                        .lock()
                        .unwrap()
                        .pending_host_publication()
                        .unwrap()
                        .is_none()
                );
            },
        );
    }
    #[test]
    fn normal_publication_freezes_new_real_store_intent_and_membership_once() {
        with_normal_publication_test(
            false,
            |owner, auth, driver, io, gate, paused, stopping, _, _, binding, old, workspace| {
                let binding = {
                    let mut store = owner.store.lock().unwrap();
                    store
                        .acknowledge_host_publication(
                            &old,
                            &lomi_remote_protocol::http::PublicationResult {
                                runtime: old.params.runtime.clone(),
                                publication_seq: old.params.publication_seq,
                            },
                        )
                        .unwrap();
                    store.unshare(workspace).unwrap();
                    store.cloud_runtime_state(&binding.scope).unwrap().unwrap()
                };
                let outbox = owner.store.lock().unwrap().pending_publications().unwrap();
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends) = scripted_normal_publication(
                    owner, auth, driver, &operation, io, gate, paused, stopping, &binding, None,
                );
                let mut turn = attempt.begin(owner).unwrap();
                normal_to(&mut turn, NormalPublicationPhase::Send);
                let frozen = turn.intent.clone().unwrap();
                assert_ne!(frozen.token, old.token);
                assert_eq!(frozen.workspace_publications, outbox);
                assert_eq!(
                    frozen.params.expected_publication_seq,
                    binding.acknowledged_publication_seq
                );
                assert_eq!(
                    frozen.params.publication_seq.0,
                    binding.acknowledged_publication_seq.0 + 1
                );
                normal_to(&mut turn, NormalPublicationPhase::Ack);
                assert_eq!(turn.try_step(), Ok(true));
                assert_eq!(sends.get(), 1);
            },
        );
    }
    #[test]
    fn normal_publication_mutex_busy_retains_phase_response_scope_and_never_replays_put() {
        for store_busy in [false, true] {
            with_normal_publication_test(
                false,
                |owner, auth, driver, io, gate, paused, stopping, counts, _, binding, _, _| {
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let (mut attempt, sends) = scripted_normal_publication(
                        owner, auth, driver, &operation, io, gate, paused, stopping, &binding, None,
                    );
                    let mut turn = attempt.begin(owner).unwrap();
                    for phase in [
                        NormalPublicationPhase::Capture,
                        NormalPublicationPhase::Prepare,
                        NormalPublicationPhase::Send,
                        NormalPublicationPhase::AfterPut,
                        NormalPublicationPhase::Ack,
                    ] {
                        normal_to(&mut turn, phase);
                        let response = turn.response.as_ref().map(|value| value as *const _);
                        let scope = turn
                            .continuation
                            .as_ref()
                            .map(|value| value.original_for_test());
                        let sent = sends.get();
                        let writes = counts.writes.get();
                        if store_busy {
                            let held = owner.store.lock().unwrap();
                            assert_eq!(
                                turn.try_step(),
                                Err(PublicationError::Domain(domain::Error::Busy))
                            );
                            drop(held);
                        } else {
                            let held = owner.domain.try_read(&operation).unwrap();
                            assert_eq!(
                                turn.try_step(),
                                Err(PublicationError::Domain(domain::Error::Busy))
                            );
                            drop(held);
                        }
                        assert!(turn.phase == phase);
                        assert_eq!(
                            turn.response.as_ref().map(|value| value as *const _),
                            response
                        );
                        assert_eq!(
                            turn.continuation
                                .as_ref()
                                .map(|value| value.original_for_test()),
                            scope
                        );
                        assert_eq!(sends.get(), sent);
                        assert_eq!(counts.writes.get(), writes);
                    }
                    assert_eq!(turn.try_step(), Ok(true));
                    assert_eq!(sends.get(), 1);
                },
            );
        }
    }
    #[test]
    fn normal_publication_uncertain_put_retains_exact_intent_and_requires_get_without_blind_retry()
    {
        for error in [
            lomi_host_http::Error::Network,
            lomi_host_http::Error::Timeout,
        ] {
            with_normal_publication_test(
                true,
                |owner, auth, driver, io, gate, paused, stopping, _, _, binding, intent, _| {
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let (mut attempt, sends) = scripted_normal_publication(
                        owner,
                        auth,
                        driver,
                        &operation,
                        io,
                        gate,
                        paused,
                        stopping,
                        &binding,
                        Some(Err(error)),
                    );
                    {
                        let mut turn = attempt.begin(owner).unwrap();
                        normal_to(&mut turn, NormalPublicationPhase::Send);
                        assert_eq!(turn.try_step(), Err(PublicationError::Http(error)));
                        assert_eq!(turn.try_step(), Err(PublicationError::Http(error)));
                    }
                    assert!(attempt.begin(owner).is_err());
                    assert_eq!(sends.get(), 1);
                    assert_eq!(
                        owner
                            .store
                            .lock()
                            .unwrap()
                            .pending_host_publication()
                            .unwrap(),
                        Some(intent)
                    );
                    let fresh_cancel = AtomicBool::new(false);
                    let fresh = Operation::new(end(), &fresh_cancel);
                    assert!(owner.remote_authorization(&fresh).is_ok());
                },
            );
        }
    }
    #[test]
    fn normal_publication_response_runtime_sequence_and_original_intent_association_are_exact() {
        for fault in 0..3 {
            with_normal_publication_test(
                true,
                |owner, auth, driver, io, gate, paused, stopping, _, _, binding, intent, _| {
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let (mut attempt, sends) = scripted_normal_publication(
                        owner, auth, driver, &operation, io, gate, paused, stopping, &binding, None,
                    );
                    let mut turn = attempt.begin(owner).unwrap();
                    normal_to(&mut turn, NormalPublicationPhase::AfterPut);
                    let response = turn.response.as_mut().unwrap();
                    match fault {
                        0 => response.response.runtime.runtime_generation.0 += 1,
                        1 => response.response.publication_seq.0 += 1,
                        _ => response.intent.token.push('x'),
                    }
                    assert_eq!(
                        turn.try_step(),
                        Err(PublicationError::Http(
                            lomi_host_http::Error::InvalidResponse
                        ))
                    );
                    assert_eq!(sends.get(), 1);
                    assert_eq!(
                        owner
                            .store
                            .lock()
                            .unwrap()
                            .pending_host_publication()
                            .unwrap(),
                        Some(intent)
                    );
                },
            );
        }
    }
    #[test]
    fn normal_publication_configuration_fence_logout_and_new_writer_during_put_suppress_ack() {
        for mutation in [1, 2, 4, 5] {
            with_normal_publication_test(
                true,
                |owner, auth, driver, io, gate, paused, stopping, counts, _, binding, intent, _| {
                    let writes = counts.writes.get();
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let (mut attempt, sends) = scripted_normal_publication(
                        owner, auth, driver, &operation, io, gate, paused, stopping, &binding, None,
                    );
                    if let Some(PublicationHttp::Scripted(script)) = attempt.http.as_mut() {
                        script.mutation = mutation;
                    }
                    let mut turn = attempt.begin(owner).unwrap();
                    normal_to(&mut turn, NormalPublicationPhase::AfterPut);
                    assert!(turn.try_step().is_err());
                    assert_eq!(sends.get(), 1);
                    assert_eq!(counts.writes.get(), writes);
                    assert_eq!(
                        owner
                            .store
                            .lock()
                            .unwrap()
                            .pending_host_publication()
                            .unwrap(),
                        Some(intent)
                    );
                },
            );
        }
    }
    #[test]
    fn normal_publication_ack_preserves_superseding_real_store_outbox_token() {
        with_normal_publication_test(
            false,
            |owner, auth, driver, io, gate, paused, stopping, _, _, binding, intent, workspace| {
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends) = scripted_normal_publication(
                    owner, auth, driver, &operation, io, gate, paused, stopping, &binding, None,
                );
                if let Some(PublicationHttp::Scripted(script)) = attempt.http.as_mut() {
                    script.mutation = 3;
                }
                let mut turn = attempt.begin(owner).unwrap();
                normal_to(&mut turn, NormalPublicationPhase::Ack);
                let later = owner.store.lock().unwrap().pending_publications().unwrap();
                assert!(
                    later
                        .iter()
                        .any(|row| row.workspace_id == workspace && !row.enabled)
                );
                assert_ne!(later, intent.workspace_publications);
                assert_eq!(turn.try_step(), Ok(true));
                assert_eq!(sends.get(), 1);
                let store = owner.store.lock().unwrap();
                assert_eq!(store.pending_publications().unwrap(), later);
                assert!(store.pending_host_publication().unwrap().is_none());
            },
        );
    }
    #[test]
    fn normal_publication_preprepare_outbox_change_rejects_before_intent_method_or_http() {
        with_normal_publication_test(
            true,
            |owner, auth, driver, io, gate, paused, stopping, _, _, binding, intent, workspace| {
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends) = scripted_normal_publication(
                    owner, auth, driver, &operation, io, gate, paused, stopping, &binding, None,
                );
                let mut turn = attempt.begin(owner).unwrap();
                normal_to(&mut turn, NormalPublicationPhase::Prepare);
                owner.store.lock().unwrap().unshare(workspace).unwrap();
                assert_eq!(turn.try_step(), Err(PublicationError::Stale));
                assert_eq!(sends.get(), 0);
                assert_eq!(
                    owner
                        .store
                        .lock()
                        .unwrap()
                        .pending_host_publication()
                        .unwrap(),
                    Some(intent)
                );
            },
        );
    }
    #[test]
    fn normal_publication_original_cancel_deadline_and_latches_stop_every_phase_without_replay() {
        for phase in [
            NormalPublicationPhase::Capture,
            NormalPublicationPhase::Prepare,
            NormalPublicationPhase::Send,
            NormalPublicationPhase::AfterPut,
            NormalPublicationPhase::Ack,
        ] {
            for stop in 0..6 {
                with_normal_publication_test(
                    true,
                    |owner, auth, driver, io, gate, paused, stopping, counts, _, binding, _, _| {
                        let cancel = AtomicBool::new(false);
                        let operation = Operation::new(end(), &cancel);
                        let (mut attempt, sends) = scripted_normal_publication(
                            owner, auth, driver, &operation, io, gate, paused, stopping, &binding,
                            None,
                        );
                        let mut turn = attempt.begin(owner).unwrap();
                        normal_to(&mut turn, phase);
                        let sent = sends.get();
                        let writes = counts.writes.get();
                        match stop {
                            0 => cancel.store(true, SeqCst),
                            1 => operation.expire_for_test(),
                            2 => gate.store(true, SeqCst),
                            3 => paused.store(true, SeqCst),
                            4 => stopping.store(true, SeqCst),
                            _ => io.setup().pending.store(true, SeqCst),
                        }
                        assert!(turn.try_step().is_err());
                        assert_eq!(sends.get(), sent);
                        assert_eq!(counts.writes.get(), writes);
                    },
                );
            }
        }
    }
    #[test]
    fn normal_publication_post_ack_store_expiry_is_terminal_and_never_reaccepts_or_replays() {
        with_normal_publication_test(
            true,
            |owner, auth, driver, io, gate, paused, stopping, counts, _, binding, _, _| {
                let writes = counts.writes.get();
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends) = scripted_normal_publication(
                    owner, auth, driver, &operation, io, gate, paused, stopping, &binding, None,
                );
                attempt.post_store_time = Some(1302);
                let mut turn = attempt.begin(owner).unwrap();
                normal_to(&mut turn, NormalPublicationPhase::Ack);
                let expected = PublicationError::Auth(lomi_host_auth::Error::Expired);
                assert_eq!(turn.try_step(), Err(expected));
                assert_eq!(turn.try_step(), Err(expected));
                assert!(
                    owner
                        .store
                        .lock()
                        .unwrap()
                        .pending_host_publication()
                        .unwrap()
                        .is_none()
                );
                assert_eq!(sends.get(), 1);
                assert_eq!(counts.writes.get(), writes);
                let fresh_cancel = AtomicBool::new(false);
                let fresh = Operation::new(end(), &fresh_cancel);
                assert!(owner.remote_authorization(&fresh).is_err());
            },
        );
    }
    #[test]
    fn normal_publication_provider_seal_error_precedes_postput_clock_and_fence_error() {
        with_normal_publication_test(
            true,
            |owner, auth, driver, io, gate, paused, stopping, _, effect, binding, _, _| {
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends) = scripted_normal_publication(
                    owner, auth, driver, &operation, io, gate, paused, stopping, &binding, None,
                );
                let mut turn = attempt.begin(owner).unwrap();
                normal_to(&mut turn, NormalPublicationPhase::AfterPut);
                effect.set(2);
                assert_eq!(
                    turn.attempt.auth.prepare_rotation(1004),
                    Err(lomi_host_auth::Error::Storage(
                        lomi_platform::secrets::Error::CommitUncertain
                    ))
                );
                assert_eq!(
                    turn.try_step(),
                    Err(PublicationError::Auth(lomi_host_auth::Error::Sealed))
                );
                assert_eq!(sends.get(), 1);
            },
        );
    }
    #[test]
    fn normal_publication_each_named_action_has_individual_expected_and_uncertain_error_policy() {
        for action in [1u8, 2] {
            for error in [
                StoreError::Fenced,
                StoreError::RevisionConflict,
                StoreError::ResourceExhausted,
                StoreError::Invalid,
                StoreError::Storage,
                StoreError::Busy,
            ] {
                with_normal_publication_test(
                    true,
                    |owner, auth, driver, io, gate, paused, stopping, _, _, binding, intent, _| {
                        let cancel = AtomicBool::new(false);
                        let operation = Operation::new(end(), &cancel);
                        let (mut attempt, sends) = scripted_normal_publication(
                            owner, auth, driver, &operation, io, gate, paused, stopping, &binding,
                            None,
                        );
                        let mut turn = attempt.begin(owner).unwrap();
                        normal_to(
                            &mut turn,
                            if action == 1 {
                                NormalPublicationPhase::Prepare
                            } else {
                                NormalPublicationPhase::Ack
                            },
                        );
                        super::super::owner_domain::PUBLICATION_ACTION_ERROR
                            .with(|slot| slot.set(Some((action, error))));
                        let expected =
                            matches!(error, StoreError::Fenced | StoreError::RevisionConflict)
                                || (action == 1 && error == StoreError::ResourceExhausted);
                        assert_eq!(
                            turn.try_step(),
                            Err(if expected {
                                PublicationError::Store(error)
                            } else {
                                PublicationError::UncertainStore(error)
                            })
                        );
                        assert_eq!(sends.get(), if action == 2 { 1 } else { 0 });
                        assert_eq!(
                            owner
                                .store
                                .lock()
                                .unwrap()
                                .pending_host_publication()
                                .unwrap(),
                            Some(intent)
                        );
                        let fresh_cancel = AtomicBool::new(false);
                        let fresh = Operation::new(end(), &fresh_cancel);
                        assert_eq!(owner.remote_authorization(&fresh).is_ok(), expected);
                    },
                );
            }
        }
    }
    #[test]
    fn normal_publication_primary_action_error_wins_postview_failure_and_freshness_failure() {
        for post_read in [false, true] {
            with_normal_publication_test(
                true,
                |owner, auth, driver, io, gate, paused, stopping, _, _, binding, _, _| {
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let (mut attempt, _) = scripted_normal_publication(
                        owner, auth, driver, &operation, io, gate, paused, stopping, &binding, None,
                    );
                    attempt.post_store_time = Some(1302);
                    let mut turn = attempt.begin(owner).unwrap();
                    normal_to(&mut turn, NormalPublicationPhase::Ack);
                    super::super::owner_domain::PUBLICATION_ACTION_ERROR
                        .with(|slot| slot.set(Some((2, StoreError::Fenced))));
                    if post_read {
                        super::super::owner_domain::PUBLICATION_POST_ERROR
                            .with(|slot| slot.set(Some(2)));
                    }
                    let result = turn.try_step();
                    assert!(matches!(
                        result,
                        Err(PublicationError::Store(StoreError::Fenced)
                            | PublicationError::UncertainStore(StoreError::Fenced))
                    ));
                },
            );
        }
    }
    #[test]
    fn normal_publication_successful_action_with_postview_failure_never_returns_success() {
        for action in [1u8, 2] {
            with_normal_publication_test(
                true,
                |owner, auth, driver, io, gate, paused, stopping, _, _, binding, _, _| {
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let (mut attempt, sends) = scripted_normal_publication(
                        owner, auth, driver, &operation, io, gate, paused, stopping, &binding, None,
                    );
                    let mut turn = attempt.begin(owner).unwrap();
                    normal_to(
                        &mut turn,
                        if action == 1 {
                            NormalPublicationPhase::Prepare
                        } else {
                            NormalPublicationPhase::Ack
                        },
                    );
                    super::super::owner_domain::PUBLICATION_POST_ERROR
                        .with(|slot| slot.set(Some(action)));
                    assert_eq!(
                        turn.try_step(),
                        Err(PublicationError::UncertainStore(StoreError::Storage))
                    );
                    assert_eq!(sends.get(), if action == 2 { 1 } else { 0 });
                    let fresh_cancel = AtomicBool::new(false);
                    let fresh = Operation::new(end(), &fresh_cancel);
                    assert!(owner.remote_authorization(&fresh).is_err());
                },
            );
        }
    }
    #[test]
    fn normal_publication_ready_provider_and_scripted_origin_cannot_remint_missing_domain_ready() {
        with_normal_publication_test(
            true,
            |owner, auth, driver, io, gate, paused, stopping, counts, _, binding, intent, _| {
                let before = counts.writes.get();
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends) = scripted_normal_publication(
                    owner, auth, driver, &operation, io, gate, paused, stopping, &binding, None,
                );
                owner.domain.cloud_uncertain();
                assert_eq!(attempt.auth.status(), lomi_host_auth::Status::Ready);
                let mut turn = attempt.begin(owner).unwrap();
                assert!(turn.try_step().is_err());
                assert_eq!(sends.get(), 0);
                assert_eq!(counts.writes.get(), before);
                assert_eq!(
                    owner
                        .store
                        .lock()
                        .unwrap()
                        .pending_host_publication()
                        .unwrap(),
                    Some(intent)
                );
            },
        );
    }

    #[test]
    fn normal_publication_actual_prepare_sequence_exhaustion_is_no_effect_and_keeps_ready() {
        with_normal_publication_test(
            true,
            |owner, auth, driver, io, gate, paused, stopping, _, _, binding, intent, _| {
                let binding = {
                    let mut store = owner.store.lock().unwrap();
                    store
                        .invalidate_cloud_runtime(&binding.scope, &binding, Some(&intent))
                        .unwrap();
                    store
                        .compare_and_set_cloud_runtime(
                            &binding.scope,
                            None,
                            binding.server_runtime.clone(),
                            DecimalU64(i64::MAX as u64),
                        )
                        .unwrap()
                };
                let outbox = owner.store.lock().unwrap().pending_publications().unwrap();
                let cancel = AtomicBool::new(false);
                let operation = Operation::new(end(), &cancel);
                let (mut attempt, sends) = scripted_normal_publication(
                    owner, auth, driver, &operation, io, gate, paused, stopping, &binding, None,
                );
                let mut turn = attempt.begin(owner).unwrap();
                normal_to(&mut turn, NormalPublicationPhase::Prepare);
                assert_eq!(
                    turn.try_step(),
                    Err(PublicationError::Store(StoreError::ResourceExhausted))
                );
                assert_eq!(sends.get(), 0);
                let store = owner.store.lock().unwrap();
                assert_eq!(store.pending_publications().unwrap(), outbox);
                assert!(store.pending_host_publication().unwrap().is_none());
                drop(store);
                let fresh_cancel = AtomicBool::new(false);
                let fresh = Operation::new(end(), &fresh_cancel);
                assert!(owner.remote_authorization(&fresh).is_ok());
            },
        );
    }
    #[test]
    fn normal_publication_stopped_original_operation_cannot_create_configured_heartbeat_origin() {
        with_normal_publication_test(
            false,
            |_, auth, driver, io, gate, paused, stopping, counts, _, binding, _, _| {
                let before = (counts.loads.get(), counts.writes.get());
                let cancel = AtomicBool::new(true);
                let operation = Operation::new(end(), &cancel);
                let mut attempt = ConfiguredNormalPublication::from_existing_worker(
                    auth,
                    driver,
                    &operation,
                    io,
                    gate,
                    paused,
                    stopping,
                    1004,
                    Instant::now(),
                );
                assert_eq!(
                    attempt.observe_configured_heartbeat(&binding),
                    Err(PublicationError::Domain(domain::Error::Cancelled))
                );
                assert!(attempt.observation.is_none());
                assert!(attempt.http.is_none());
                assert_eq!((counts.loads.get(), counts.writes.get()), before);
            },
        );
    }

    #[test]
    fn normal_publication_writer_after_provider_before_final_send_admission_prevents_put() {
        for boundary in [1, 2] {
            with_normal_publication_test(
                true,
                |owner, auth, driver, io, gate, paused, stopping, counts, _, binding, intent, _| {
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let (mut attempt, sends) = scripted_normal_publication(
                        owner, auth, driver, &operation, io, gate, paused, stopping, &binding, None,
                    );
                    let mut turn = attempt.begin(owner).unwrap();
                    normal_to(&mut turn, NormalPublicationPhase::Send);
                    let original = turn.continuation.as_ref().unwrap().original_for_test();
                    let writes = counts.writes.get();
                    PUBLICATION_FINAL_SEND_BOUNDARY.with(|slot| slot.set(boundary));
                    assert_eq!(
                        turn.try_step(),
                        Err(PublicationError::Domain(domain::Error::Stale))
                    );
                    assert_eq!(
                        turn.continuation.as_ref().unwrap().original_for_test(),
                        original
                    );
                    assert_eq!(sends.get(), 0);
                    assert_eq!(counts.writes.get(), writes);
                    assert!(turn.response.is_none());
                    assert_eq!(
                        owner
                            .store
                            .lock()
                            .unwrap()
                            .pending_host_publication()
                            .unwrap(),
                        Some(intent)
                    );
                    assert_eq!(
                        turn.try_step(),
                        Err(PublicationError::Domain(domain::Error::Stale))
                    );
                    assert_eq!(sends.get(), 0);
                },
            );
        }
    }
    #[test]
    fn normal_publication_final_send_mutex_busy_retains_original_phase_intent_and_sends_once() {
        for boundary in [3, 4] {
            with_normal_publication_test(
                false,
                |owner, auth, driver, io, gate, paused, stopping, counts, _, binding, intent, _| {
                    let cancel = AtomicBool::new(false);
                    let operation = Operation::new(end(), &cancel);
                    let (mut attempt, sends) = scripted_normal_publication(
                        owner, auth, driver, &operation, io, gate, paused, stopping, &binding, None,
                    );
                    let mut turn = attempt.begin(owner).unwrap();
                    normal_to(&mut turn, NormalPublicationPhase::Send);
                    let original = turn.continuation.as_ref().unwrap().original_for_test();
                    let writes = counts.writes.get();
                    PUBLICATION_FINAL_SEND_BOUNDARY.with(|slot| slot.set(boundary));
                    assert_eq!(
                        turn.try_step(),
                        Err(PublicationError::Domain(domain::Error::Busy))
                    );
                    assert!(turn.phase == NormalPublicationPhase::Send);
                    assert!(turn.terminal.is_none());
                    assert!(turn.response.is_none());
                    assert_eq!(
                        turn.continuation.as_ref().unwrap().original_for_test(),
                        original
                    );
                    assert_eq!(turn.intent.as_ref(), Some(&intent));
                    assert_eq!(sends.get(), 0);
                    assert_eq!(counts.writes.get(), writes);
                    assert_eq!(
                        owner
                            .store
                            .lock()
                            .unwrap()
                            .pending_host_publication()
                            .unwrap(),
                        Some(intent)
                    );
                    normal_to(&mut turn, NormalPublicationPhase::Ack);
                    assert_eq!(turn.try_step(), Ok(true));
                    assert_eq!(sends.get(), 1);
                    assert_eq!(counts.writes.get(), writes);
                },
            );
        }
    }
}

#[cfg(test)]
mod public_owner_tests {
    use super::*;
    use lomi_host_store::Limits;
    use lomi_platform::public_config::Configuration;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    fn fixture() -> (tempfile::TempDir, Arc<SharedOwner>) {
        let root = tempfile::tempdir().unwrap();
        let mut store =
            HostStore::open(&root.path().join("host.sqlite"), Limits::default()).unwrap();
        let document = PublicDocument::encode(&Configuration {
            version: 1,
            revision: 1,
            authentication: None,
        })
        .unwrap();
        let intent = store.public_prepare(None, &document).unwrap();
        // Pure synthetic Store fixture, never a claim of file durability.
        store.public_finish(intent.operation_id, &document).unwrap();
        (root, SharedOwner::new(store).unwrap())
    }
    fn turn<'d, 'o>(
        owner: &'d SharedOwner,
        operation: &'o Operation<'o>,
    ) -> PublicConfigurationWrite<'d, 'o> {
        PublicConfigurationWrite {
            owner,
            pending: Some(
                owner
                    .domain
                    .announce(operation, WriterClass::Shared, Intent::Mutation)
                    .unwrap(),
            ),
        }
    }
    #[test]
    fn public_busy_preserves_original_announcement_and_owned_snapshot() {
        let (_root, owner) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(Instant::now() + Duration::from_secs(5), &cancel);
        let mut turn = turn(&owner, &operation);
        let held = owner.domain.try_read(&operation).unwrap();
        assert!(matches!(
            turn.snapshot(),
            Err(public::Error::Owner(Error::Domain(domain::Error::Busy)))
        ));
        drop(held);
        let (current, scope) = turn.snapshot().unwrap();
        let held = owner.store.lock().unwrap();
        assert!(matches!(
            turn.current(&current, scope),
            Err(public::Error::Owner(Error::Domain(domain::Error::Busy)))
        ));
        assert!(turn.pending.is_some());
        drop(held);
        turn.current(&current, scope).unwrap();
        turn.complete().unwrap();
        assert!(matches!(
            turn.snapshot(),
            Err(public::Error::Owner(Error::Domain(domain::Error::Stale)))
        ));
    }
    #[test]
    fn public_busy_expiry_cannot_accept_a_fresh_operation() {
        let (_root, owner) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(Instant::now() + Duration::from_secs(5), &cancel);
        let mut turn = turn(&owner, &operation);
        let held = owner.store.lock().unwrap();
        assert!(matches!(
            turn.snapshot(),
            Err(public::Error::Owner(Error::Domain(domain::Error::Busy)))
        ));
        operation.expire_for_test();
        assert!(matches!(
            turn.snapshot(),
            Err(public::Error::Owner(Error::Domain(domain::Error::Deadline)))
        ));
        drop(held);
        turn.abandon();
        assert!(matches!(
            turn.snapshot(),
            Err(public::Error::Owner(Error::Domain(domain::Error::Stale)))
        ));
    }
    #[test]
    fn public_same_generation_auth_change_rejects_exact_old_scope() {
        let (_root, owner) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(Instant::now() + Duration::from_secs(5), &cancel);
        let mut turn = turn(&owner, &operation);
        let (current, scope) = turn.snapshot().unwrap();
        {
            let mut store = owner.store.lock().unwrap();
            let generation = store.authorization_state().unwrap().generation;
            store.enable_authorization(generation).unwrap();
        }
        assert!(matches!(
            turn.current(&current, scope),
            Err(public::Error::Conflict)
        ));
        assert!(
            !owner
                .store
                .lock()
                .unwrap()
                .public_configuration_ready()
                .unwrap()
        );
        turn.abandon();
    }
    #[test]
    fn public_uncertain_post_state_never_becomes_retryable_busy() {
        assert!(PublicMethod::Prepare.definite(&public::Error::Store(StoreError::Busy)));
        assert!(
            !PublicMethod::Prepare.definite(&public::Error::Owner(Error::UncertainStore(
                StoreError::Busy
            )))
        );
        assert!(
            PublicMethod::Prepare.definite(&public::Error::Store(StoreError::IdempotencyConflict))
        );
        assert!(
            !PublicMethod::Finish.definite(&public::Error::Store(StoreError::IdempotencyConflict))
        );
    }
    #[test]
    fn public_prepared_cas_rejects_different_intent_without_losing_durable_recovery() {
        let (_root, owner) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(Instant::now() + Duration::from_secs(5), &cancel);
        let mut turn = turn(&owner, &operation);
        let (current, scope) = turn.snapshot().unwrap();
        let desired = PublicDocument::encode(&Configuration {
            version: 1,
            revision: 2,
            authentication: None,
        })
        .unwrap();
        let (intent, scope) = turn.prepare(&current, scope, &desired).unwrap();
        let mut wrong = intent.clone();
        wrong.operation_id = OperationId::from_bytes([99; 16]).unwrap();
        assert!(matches!(
            turn.finish(&wrong, scope, &desired),
            Err(public::Error::Conflict)
        ));
        turn.abandon();
        let store = owner.store.lock().unwrap();
        let state = store.public_configuration_state().unwrap().unwrap();
        assert!(state.prepared.as_ref() == Some(&intent));
        assert!(state.current.as_ref() == Some(&current));
        assert!(!store.public_configuration_ready().unwrap());
    }
}

#[cfg(test)]
mod cloud_owner_tests {
    use super::*;
    use lomi_host_store::Limits;
    use lomi_remote_protocol::http::RuntimeBinding;
    use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
    use std::time::{Duration, Instant};

    fn fixture() -> (
        tempfile::TempDir,
        Arc<SharedOwner>,
        CloudRuntimeState,
        WorkspaceId,
        LocalAuthConfiguration,
    ) {
        let root = tempfile::tempdir().unwrap();
        let mut store =
            HostStore::open(&root.path().join("host.sqlite"), Limits::default()).unwrap();
        let configuration = LocalAuthConfiguration {
            version: 1,
            origin: "https://identity.example".to_owned().try_into().unwrap(),
            remote_api_origin: Some("https://remote.example".to_owned().try_into().unwrap()),
            relay_endpoint: None,
            client_id: "cloud-fixture".to_owned().try_into().unwrap(),
            provider: crate::testsupport::provider(),
            keychain_path: None,
            protected_file_acknowledgement: crate::testsupport::file_acknowledgement(),
        };
        store.configure_auth(&configuration).unwrap();
        store.enable_authorization(0).unwrap();
        let project = store
            .add_project(root.path(), "Test".to_owned().try_into().unwrap())
            .unwrap();
        let id = project.state.context.workspace_id;
        store.share(id, 0).unwrap();
        let scope = store
            .cloud_runtime_scope(0, "https://remote.example".into())
            .unwrap();
        // Existing public Store APIs seed synthetic PRE-OWNER evidence only.
        // This is not a new owner CAS/claim/response-proof capability.
        let binding = store
            .compare_and_set_cloud_runtime(
                &scope,
                None,
                RuntimeBinding {
                    runtime_id: store.runtime_id(),
                    runtime_generation: DecimalU64(18),
                    host_access_epoch: DecimalU64(13),
                },
                DecimalU64(0),
            )
            .unwrap();
        (
            root,
            SharedOwner::new(store).unwrap(),
            binding,
            id,
            configuration,
        )
    }
    fn end() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[test]
    fn cloud_snapshots_are_owned_local_captures_and_release_both_locks() {
        let (_root, owner, binding, _id, configuration) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let scope = owner
            .cloud_scope_snapshot(&operation, 0, "https://remote.example".into())
            .unwrap();
        let reconciliation = owner
            .cloud_reconciliation_snapshot(&operation, &binding.scope)
            .unwrap();
        let online = owner
            .cloud_online_snapshot(&operation, &binding.scope)
            .unwrap();
        let logout = owner.cloud_logout_snapshot(&operation).unwrap();
        let _domain = owner.domain.try_read(&operation).unwrap();
        let _store = owner.store.try_lock().unwrap();
        assert_eq!(scope.authorization.generation, 0);
        assert_eq!(scope.verified_generation, Some(0));
        assert_eq!(scope.configuration, Some(configuration.clone()));
        assert_eq!(scope.scope, binding.scope);
        assert_eq!(reconciliation.previous.as_ref(), Some(&binding));
        assert_eq!(reconciliation.scope, binding.scope);
        assert_eq!(reconciliation.configuration, Some(configuration.clone()));
        assert!(reconciliation.pending.is_none());
        assert_eq!(online.scope, binding.scope);
        assert_eq!(online.binding, binding);
        assert!(online.acknowledged.is_none() && online.pending.is_none());
        assert_eq!(online.outbox.len(), 1);
        assert_eq!(logout.configuration, Some(configuration));
        assert_eq!(logout.host_id, binding.scope.host_id);
        assert_eq!(logout.owner_runtime_id, binding.scope.owner_runtime_id);
    }
    #[test]
    fn cloud_snapshots_do_not_open_remote_and_logout_keeps_distinct_authorization() {
        let (_root, owner, binding, _id, _configuration) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        owner
            .cloud_scope_snapshot(&operation, 0, "https://remote.example".into())
            .unwrap();
        assert!(matches!(
            owner.remote_authorization(&operation),
            Err(Error::Domain(domain::Error::Denied))
        ));
        let fenced = owner
            .begin_local_logout(&operation)
            .unwrap()
            .try_commit()
            .unwrap();
        let logout = owner.cloud_logout_snapshot(&operation).unwrap();
        assert_eq!(logout.authorization.generation, fenced.generation);
        assert!(logout.authorization.locked && logout.authorization.pending_cloud_revoke);
        assert!(
            owner
                .cloud_scope_snapshot(&operation, 0, "https://remote.example".into())
                .is_err()
        );
        assert_eq!(logout.host_id, binding.scope.host_id);
        assert!(owner.remote_authorization(&operation).is_err());
    }
    #[test]
    fn cloud_preparation_joins_exact_binding_intent_and_outbox_without_acknowledging() {
        let (_root, owner, binding, _id, _configuration) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let intent = owner
            .begin_prepare_host_publication(&operation, binding.clone())
            .unwrap()
            .try_commit()
            .unwrap();
        let online = owner
            .cloud_online_snapshot(&operation, &binding.scope)
            .unwrap();
        let reconciliation = owner
            .cloud_reconciliation_snapshot(&operation, &binding.scope)
            .unwrap();
        assert_eq!(online.binding, binding);
        assert_eq!(online.pending.as_ref(), Some(&intent));
        assert_eq!(online.outbox, intent.workspace_publications);
        assert!(online.acknowledged.is_none());
        assert_eq!(reconciliation.previous.as_ref(), Some(&binding));
        assert_eq!(reconciliation.pending.as_ref(), Some(&intent));
        assert_eq!(owner.authorization_state(&operation).unwrap().generation, 0);
        assert!(owner.remote_authorization(&operation).is_err());
    }
    #[test]
    fn cloud_exact_binding_and_pending_mismatches_never_delete_outbox_or_newer_intent() {
        let (_root, owner, binding, _id, _configuration) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let intent = owner
            .begin_prepare_host_publication(&operation, binding.clone())
            .unwrap()
            .try_commit()
            .unwrap();
        let mut wrong_binding = binding.clone();
        wrong_binding.acknowledged_publication_seq = DecimalU64(1);
        assert!(matches!(
            owner
                .begin_prepare_host_publication(&operation, wrong_binding.clone())
                .unwrap()
                .try_commit(),
            Err(Error::Store(StoreError::RevisionConflict))
        ));
        assert!(matches!(
            owner
                .begin_invalidate_cloud_runtime(
                    &operation,
                    binding.scope.clone(),
                    wrong_binding,
                    Some(intent.clone())
                )
                .unwrap()
                .try_commit(),
            Err(Error::Store(StoreError::RevisionConflict))
        ));
        let mut wrong_intent = intent.clone();
        wrong_intent.token = "different-token".into();
        assert!(matches!(
            owner
                .begin_invalidate_cloud_runtime(
                    &operation,
                    binding.scope.clone(),
                    binding.clone(),
                    Some(wrong_intent)
                )
                .unwrap()
                .try_commit(),
            Err(Error::Store(StoreError::RevisionConflict))
        ));
        let online = owner
            .cloud_online_snapshot(&operation, &binding.scope)
            .unwrap();
        assert_eq!(online.pending.as_ref(), Some(&intent));
        assert_eq!(online.outbox, intent.workspace_publications);
    }
    #[test]
    fn cloud_replay_and_exact_invalidation_preserve_newer_workspace_token() {
        let (_root, owner, binding, id, _configuration) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let intent = owner
            .begin_prepare_host_publication(&operation, binding.clone())
            .unwrap()
            .try_commit()
            .unwrap();
        owner
            .begin_unshare(&operation, id)
            .unwrap()
            .try_commit()
            .unwrap();
        let newer = owner
            .cloud_online_snapshot(&operation, &binding.scope)
            .unwrap()
            .outbox;
        assert_ne!(newer[0].token, intent.workspace_publications[0].token);
        let replay = owner
            .begin_prepare_host_publication(&operation, binding.clone())
            .unwrap()
            .try_commit()
            .unwrap();
        assert_eq!(replay, intent);
        owner
            .begin_invalidate_cloud_runtime(
                &operation,
                binding.scope.clone(),
                binding.clone(),
                Some(intent),
            )
            .unwrap()
            .try_commit()
            .unwrap();
        let reconciliation = owner
            .cloud_reconciliation_snapshot(&operation, &binding.scope)
            .unwrap();
        assert!(reconciliation.previous.is_none() && reconciliation.pending.is_none());
        assert_eq!(
            owner.store.lock().unwrap().pending_publications().unwrap(),
            newer
        );
        assert_eq!(owner.authorization_state(&operation).unwrap().generation, 0);
        assert!(owner.remote_authorization(&operation).is_err());
    }
    #[test]
    fn cloud_busy_keeps_same_pending_then_commits_original_binding_once() {
        let (_root, owner, binding, _id, _configuration) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let mut turn = owner
            .begin_prepare_host_publication(&operation, binding.clone())
            .unwrap();
        let pending = turn.0.pending.as_ref().unwrap() as *const _;
        let held = owner.domain.try_read(&operation).unwrap();
        assert!(matches!(
            turn.try_commit(),
            Err(Error::Domain(domain::Error::Busy))
        ));
        assert_eq!(turn.0.pending.as_ref().unwrap() as *const _, pending);
        drop(held);
        let held = owner.store.lock().unwrap();
        assert!(matches!(
            turn.try_commit(),
            Err(Error::Domain(domain::Error::Busy))
        ));
        assert!(held.pending_host_publication().unwrap().is_none());
        assert_eq!(turn.0.pending.as_ref().unwrap() as *const _, pending);
        drop(held);
        let intent = turn.try_commit().unwrap();
        assert_eq!(intent.scope, binding.scope);
        assert!(matches!(
            turn.try_commit(),
            Err(Error::Domain(domain::Error::Stale))
        ));
    }
    #[test]
    fn cloud_busy_deadline_or_cancellation_never_gets_a_replacement_budget() {
        for cancellation in [false, true] {
            let (_root, owner, binding, _id, _configuration) = fixture();
            let cancel = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancel);
            let mut turn = owner
                .begin_prepare_host_publication(&operation, binding.clone())
                .unwrap();
            let held = owner.store.lock().unwrap();
            assert!(matches!(
                turn.try_commit(),
                Err(Error::Domain(domain::Error::Busy))
            ));
            if cancellation {
                cancel.store(true, SeqCst);
            } else {
                operation.expire_for_test();
            }
            if cancellation {
                assert!(matches!(
                    turn.try_commit(),
                    Err(Error::Domain(domain::Error::Cancelled))
                ));
            } else {
                assert!(matches!(
                    turn.try_commit(),
                    Err(Error::Domain(domain::Error::Deadline))
                ));
            }
            cancel.store(false, SeqCst);
            drop(held);
            assert!(matches!(
                turn.try_commit(),
                Err(Error::Domain(domain::Error::Stale))
            ));
            assert!(
                owner
                    .store
                    .lock()
                    .unwrap()
                    .pending_host_publication()
                    .unwrap()
                    .is_none()
            );
        }
    }
    #[test]
    fn cloud_error_classification_preserves_action_priority_and_never_retries_uncertain_busy() {
        assert!(expected_cloud_invalidation(StoreError::Busy));
        assert!(!expected_cloud_invalidation(StoreError::ResourceExhausted));
        assert!(expected_cloud_preparation(StoreError::ResourceExhausted));
        for error in [StoreError::Invalid, StoreError::Storage] {
            assert!(!expected_cloud_invalidation(error) && !expected_cloud_preparation(error));
        }
        for action_error in [
            StoreError::Busy,
            StoreError::Fenced,
            StoreError::Invalid,
            StoreError::Storage,
        ] {
            let result = classify_cloud_outcome::<()>(
                Err(action_error),
                Err(StoreError::Storage),
                expected_cloud_preparation,
            );
            assert!(
                matches!(result, Err(StoreFailure::Uncertain(Error::UncertainStore(error))) if error == action_error)
            );
        }
    }
    #[test]
    fn cloud_configuration_failure_does_not_prevent_independent_local_logout() {
        let root = tempfile::tempdir().unwrap();
        let mut store =
            HostStore::open(&root.path().join("host.sqlite"), Limits::default()).unwrap();
        let document =
            lomi_host_store::PublicDocument::encode(&lomi_platform::public_config::Configuration {
                version: 1,
                revision: 1,
                authentication: None,
            })
            .unwrap();
        let intent = store.public_prepare(None, &document).unwrap();
        store.public_finish(intent.operation_id, &document).unwrap();
        store.public_block(); // public API creates unavailable configuration evidence
        let owner = SharedOwner::new(store).unwrap();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        assert!(matches!(
            owner.cloud_logout_snapshot(&operation),
            Err(Error::Store(StoreError::Fenced))
        ));
        assert!(owner.auth_status(&operation).is_ok());
        let fence = owner
            .begin_local_logout(&operation)
            .unwrap()
            .try_commit()
            .unwrap();
        let authorization = owner.authorization_state(&operation).unwrap();
        assert_eq!(authorization.generation, fence.generation);
        assert!(authorization.locked && authorization.pending_cloud_revoke);
        assert!(owner.remote_authorization(&operation).is_err());
    }
}
// BEGIN PASSIVE_PEER_CHANNEL_LOCAL_EVIDENCE_V1
// Inactive LOCAL observations only: no Ready, eligibility, sign/send, ACK or
// retirement permit. Never reuse a GET CloudMutationScope for these records.
// Future concrete original-operation turns must bind configuration, runtime,
// ACK/outbox, HostAuth and heartbeat, then revalidate after signing/provider I/O.
// This block does not close the peer/channel coherence authority gap.
use lomi_host_store::{
    AcknowledgedChannelAdmission, AcknowledgedWorkspaceGrant, ChannelAdmissionIntent,
    PairingDecisionIntent, TerminalDescriptor,
};
#[cfg(test)]
use lomi_remote_protocol::GrantId;

#[derive(Debug, Clone)]
pub(super) struct LocalPeerWorkspaceEvidence {
    pub(super) workspace: ProjectRecord,
    pub(super) descriptors: Vec<TerminalDescriptor>,
}
#[derive(Debug, Clone)]
#[cfg(test)]
pub(super) struct LocalChannelSourceEvidence {
    // Exact acknowledged source record, including original intent token.
    pub(super) source: AcknowledgedWorkspaceGrant,
    pub(super) local: LocalPeerWorkspaceEvidence,
}
// Private stage-specific classification: journal NotFound/Invalid/Busy is never
// an expected workspace rejection. Synthetic tests inject errors through this
// same private seam; they do not claim to induce real SQL corruption.
#[cfg(test)]
enum LocalEvidenceFailure {
    Missing(StoreError),
    Uncertain(StoreError),
}
#[cfg(test)]
fn local_workspace_evidence(
    store: &HostStore,
    id: WorkspaceId,
) -> Result<LocalPeerWorkspaceEvidence, LocalEvidenceFailure> {
    let workspace = store.workspace(id).map_err(|error| {
        if error == StoreError::NotFound {
            LocalEvidenceFailure::Missing(error)
        } else {
            LocalEvidenceFailure::Uncertain(error)
        }
    })?;
    let descriptors = store
        .terminal_descriptors(id)
        .map_err(LocalEvidenceFailure::Uncertain)?;
    // Store journals have their own record/byte budgets. Bound this DTO's
    // descriptor vector too; exceeding the passive observation budget is uncertain.
    if descriptors.len() > 4096 {
        return Err(LocalEvidenceFailure::Uncertain(
            StoreError::ResourceExhausted,
        ));
    }
    Ok(LocalPeerWorkspaceEvidence {
        workspace,
        descriptors,
    })
}
#[cfg(test)]
impl SharedOwner {
    // Private only: callers cannot supply Store callbacks or escape raw guards.
    fn read_local_peer_evidence<T>(
        &self,
        operation: &Operation<'_>,
        read: impl FnOnce(&HostStore) -> Result<T, LocalEvidenceFailure>,
    ) -> Result<T, Error> {
        let guard = self.domain.try_read(operation).map_err(Error::Domain)?;
        let store = match self.try_store() {
            Ok(store) => store,
            Err(Error::Domain(domain::Error::Poisoned)) => {
                let _ = guard.capture_local(|| Err::<(), _>(StoreError::Storage));
                return Err(Error::Domain(domain::Error::Poisoned));
            }
            Err(error) => return Err(error),
        };
        let mut result = None;
        let snapshot = guard
            .capture_local(|| {
                result = Some(match read(&store) {
                    Ok(value) => Ok(value),
                    Err(LocalEvidenceFailure::Missing(error)) => Err(error),
                    Err(LocalEvidenceFailure::Uncertain(error)) => return Err(error),
                });
                Ok(())
            })
            .map_err(|error| match error {
                StepError::Domain(error) => Error::Domain(error),
                StepError::Source(error) => Error::UncertainStore(error),
            })?;
        guard.validate(snapshot).map_err(Error::Domain)?;
        result
            .expect("capture executed local evidence read")
            .map_err(Error::Store)
    }
    pub(super) fn local_pending_pairing_decisions(
        &self,
        operation: &Operation<'_>,
    ) -> Result<Vec<PairingDecisionIntent>, Error> {
        self.read_local_peer_evidence(operation, |store| {
            store
                .pending_pairing_decisions()
                .map_err(LocalEvidenceFailure::Uncertain)
        })
    }
    pub(super) fn local_acknowledged_workspace_grants(
        &self,
        operation: &Operation<'_>,
    ) -> Result<Vec<AcknowledgedWorkspaceGrant>, Error> {
        self.read_local_peer_evidence(operation, |store| {
            store
                .acknowledged_workspace_grants()
                .map_err(LocalEvidenceFailure::Uncertain)
        })
    }
    pub(super) fn local_pending_channel_admissions(
        &self,
        operation: &Operation<'_>,
    ) -> Result<Vec<ChannelAdmissionIntent>, Error> {
        self.read_local_peer_evidence(operation, |store| {
            store
                .pending_channel_admissions()
                .map_err(LocalEvidenceFailure::Uncertain)
        })
    }
    pub(super) fn local_acknowledged_channel_admissions(
        &self,
        operation: &Operation<'_>,
    ) -> Result<Vec<AcknowledgedChannelAdmission>, Error> {
        self.read_local_peer_evidence(operation, |store| {
            store
                .acknowledged_channel_admissions()
                .map_err(LocalEvidenceFailure::Uncertain)
        })
    }
    pub(super) fn local_peer_workspace_evidence(
        &self,
        operation: &Operation<'_>,
        id: WorkspaceId,
    ) -> Result<LocalPeerWorkspaceEvidence, Error> {
        self.read_local_peer_evidence(operation, |store| local_workspace_evidence(store, id))
    }
    pub(super) fn local_channel_source_evidence(
        &self,
        operation: &Operation<'_>,
        id: GrantId,
    ) -> Result<LocalChannelSourceEvidence, Error> {
        self.read_local_peer_evidence(operation, |store| {
            let source = store
                .acknowledged_workspace_grants()
                .map_err(LocalEvidenceFailure::Uncertain)?
                .into_iter()
                .find(|grant| grant.intent.preparation.grant_id == id)
                .ok_or(LocalEvidenceFailure::Missing(StoreError::NotFound))?;
            let local =
                local_workspace_evidence(store, source.intent.preparation.scope.workspace_id)?;
            Ok(LocalChannelSourceEvidence { source, local })
        })
    }
}

#[cfg(test)]
mod passive_peer_channel_local_evidence_tests {
    use super::*;
    use lomi_host_store::*;
    use lomi_remote_protocol::{http::*, rpc::*, *};
    use std::cell::Cell;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
    use std::time::{Duration, Instant};
    // Synthetic public wire fixtures; no cryptographic authority is claimed.
    fn id(n: usize) -> [u8; 16] {
        (n as u128 + 1).to_be_bytes()
    }
    fn install(store: &mut HostStore) -> CloudRuntimeState {
        store.enable_authorization(0).unwrap();
        let scope = store
            .cloud_runtime_scope(0, "https://remote.example".into())
            .unwrap();
        if let Some(old) = store.cloud_runtime_reconciliation_state(&scope).unwrap() {
            store.invalidate_cloud_runtime(&scope, &old, None).unwrap();
        }
        store
            .compare_and_set_cloud_runtime(
                &scope,
                None,
                RuntimeBinding {
                    runtime_id: scope.owner_runtime_id,
                    runtime_generation: DecimalU64(41),
                    host_access_epoch: DecimalU64(3),
                },
                DecimalU64(0),
            )
            .unwrap()
    }
    fn workspace(store: &mut HostStore, root: &Path) -> WorkspaceId {
        let project = store
            .add_project(root, "private-project-title".to_owned().try_into().unwrap())
            .unwrap();
        store.share(project.state.context.workspace_id, 0).unwrap();
        project.state.context.workspace_id
    }
    fn proof_identity(cbor: &str) -> EnrollmentProof {
        EnrollmentProof {
            canonical_cbor: cbor.to_owned().try_into().unwrap(),
            signature: "11".repeat(64).try_into().unwrap(),
        }
    }
    fn preparation(
        store: &HostStore,
        state: &CloudRuntimeState,
        workspace: WorkspaceId,
        n: usize,
        approve: bool,
    ) -> PairingDecisionPreparation {
        let local = store.workspace(workspace).unwrap();
        let identities = PeerIdentities {
            host: proof_identity("01"),
            consumer: proof_identity("02"),
            host_fingerprint: "12".repeat(32).try_into().unwrap(),
            consumer_fingerprint: "13".repeat(32).try_into().unwrap(),
        };
        let authority = CurrentAuthorityBinding {
            host_authorization_id: HostAuthorizationId::from_bytes(id(4)).unwrap(),
            consumer_authorization_id: ConsumerAuthorizationId::from_bytes(id(5)).unwrap(),
            account_session_id: "synthetic-session-id".to_owned().try_into().unwrap(),
            access_epoch: state.server_runtime.host_access_epoch,
            grant_revision: DecimalU64(1),
            workspace_epoch: local.state.context.workspace_epoch,
            runtime_id: state.server_runtime.runtime_id,
            runtime_generation: state.server_runtime.runtime_generation,
            terminal_membership: None,
        };
        PairingDecisionPreparation {
            scope: CloudPairingScope {
                runtime_scope: state.scope.clone(),
                runtime: state.server_runtime.clone(),
                workspace_id: workspace,
                workspace_epoch: local.state.context.workspace_epoch,
                workspace_fence: local.fence,
            },
            pairing_id: PairingId::from_bytes(id(n)).unwrap(),
            grant_id: GrantId::from_bytes(id(n + 1000)).unwrap(),
            account_id: AccountId::from_bytes(id(1)).unwrap(),
            window_identity_id: WindowIdentityId::from_bytes(id(2)).unwrap(),
            proposal: PairingProposal {
                maximum_grant: "03".to_owned().try_into().unwrap(),
                identities,
                authority,
            },
            original_expires_at: 1100,
            params: if approve {
                PairingDecisionParams::Approve {
                    grant: SignedGrantWire {
                        canonical_cbor: "04".to_owned().try_into().unwrap(),
                        signature: "22".repeat(64).try_into().unwrap(),
                    },
                    runtime: state.server_runtime.clone(),
                }
            } else {
                PairingDecisionParams::Deny {
                    runtime: state.server_runtime.clone(),
                }
            },
        }
    }
    fn response(intent: &PairingDecisionIntent) -> PairingResult {
        let p = &intent.preparation;
        match &p.params {
            PairingDecisionParams::Approve { grant, .. } => PairingResult::Approved {
                pairing_id: p.pairing_id,
                proposal: p.proposal.clone(),
                grant: grant.clone(),
                identities: p.proposal.identities.clone(),
                authority: p.proposal.authority.clone(),
            },
            PairingDecisionParams::Deny { .. } => PairingResult::Denied {
                pairing_id: p.pairing_id,
            },
        }
    }
    fn running_terminal(
        store: &mut HostStore,
        workspace: WorkspaceId,
        seed: u8,
    ) -> TerminalContext {
        let binding = OperationBinding {
            rights: StoredOperationRights::new(
                OperationId::from_bytes([seed; 16]).unwrap(),
                ConsumerAuthorizationId::from_bytes([seed; 16]).unwrap(),
                workspace,
                Method::TerminalCreate,
                CapabilitySet::control_with_workspace_tools(),
                false,
            )
            .unwrap(),
            parameter_hash: parameter_hash(&(Method::TerminalCreate, workspace)).unwrap(),
        };
        let mut state = store.workspace(workspace).unwrap().state;
        store
            .admit_external(&binding, state.domain_revision)
            .unwrap();
        let permit = store.start_external(&binding).unwrap();
        state.domain_revision = DecimalU64(state.domain_revision.0 + 1);
        let terminal = TerminalContext {
            workspace: state.context.clone(),
            pane_id: PaneId::from_bytes([seed; 16]).unwrap(),
            session_id: TerminalSessionId::from_bytes([seed; 16]).unwrap(),
            session_epoch: SessionEpoch::from_bytes([seed; 16]).unwrap(),
            profile: TerminalProfile::ExperimentalRustGridV1,
        };
        let layout = TerminalLayout::Pane {
            pane: TerminalPane {
                pane_id: terminal.pane_id,
                session: Some(terminal.clone()),
                state: PaneState::Running,
            },
        };
        state.tabs.0.push(TerminalTab {
            tab_id: TabId::from_bytes([seed; 16]).unwrap(),
            name: "private-terminal-title".to_owned().try_into().unwrap(),
            layout,
        });
        store
            .complete_external(
                &permit,
                OperationState::Succeeded,
                Effect::Committed,
                Some(OperationResult::Terminal {
                    domain_revision: state.domain_revision,
                    pane_id: terminal.pane_id,
                    session_id: terminal.session_id,
                    session_epoch: terminal.session_epoch,
                }),
                Some(state),
            )
            .unwrap();
        terminal
    }
    fn publish(store: &mut HostStore, state: &CloudRuntimeState) -> CloudRuntimeState {
        let intent = store.prepare_host_publication(state).unwrap();
        store
            .acknowledge_host_publication(
                &intent,
                &PublicationResult {
                    runtime: intent.params.runtime.clone(),
                    publication_seq: intent.params.publication_seq,
                },
            )
            .unwrap()
    }
    fn grant(
        store: &mut HostStore,
        state: &CloudRuntimeState,
        workspace: WorkspaceId,
    ) -> AcknowledgedWorkspaceGrant {
        let intent = store
            .prepare_pairing_decision(preparation(store, state, workspace, 10, true), 1000)
            .unwrap();
        store
            .acknowledge_pairing_decision(&intent, &response(&intent), 1000)
            .unwrap()
            .unwrap()
    }
    fn fixture() -> (
        tempfile::TempDir,
        Arc<SharedOwner>,
        AcknowledgedWorkspaceGrant,
        TerminalContext,
    ) {
        let root = tempfile::tempdir().unwrap();
        let mut store =
            HostStore::open(&root.path().join("host.sqlite"), Limits::default()).unwrap();
        let binding = install(&mut store);
        let id = workspace(&mut store, root.path());
        let terminal = running_terminal(&mut store, id, 42);
        let binding = publish(&mut store, &binding);
        let source = grant(&mut store, &binding, id);
        (root, SharedOwner::new(store).unwrap(), source, terminal)
    }
    fn end() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }
    // Observe whether fail_remote rejected before StoreView construction. This
    // synthetic probe never establishes Ready or claims an actual SQL fault.
    fn remote_capture_reaches_read(owner: &SharedOwner, operation: &Operation<'_>) -> bool {
        let reached = Cell::new(false);
        let guard = owner.domain.try_read(operation).unwrap();
        let _ = guard.capture_remote(|| {
            reached.set(true);
            Err::<StoreView, _>(StoreError::Storage)
        });
        reached.get()
    }
    #[test]
    fn exact_source_token_workspace_and_descriptors_are_owned_in_one_capture() {
        let (_root, owner, source, terminal) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let evidence = owner
            .local_channel_source_evidence(&operation, source.intent.preparation.grant_id)
            .unwrap();
        assert_eq!(evidence.source, source);
        assert_eq!(evidence.source.intent.token, source.intent.token);
        assert_eq!(evidence.local.workspace.state.context, terminal.workspace);
        assert_eq!(evidence.local.descriptors.len(), 1);
        assert_eq!(evidence.local.descriptors[0].pane_id, terminal.pane_id);
        assert!(matches!(
            evidence.local.descriptors[0].status,
            TerminalStatus::Running
        ));
        let original_fence = evidence.local.workspace.fence;
        owner
            .begin_unshare(&operation, terminal.workspace.workspace_id)
            .unwrap()
            .try_commit()
            .unwrap();
        assert_eq!(evidence.local.workspace.fence, original_fence);
        assert_ne!(
            owner
                .local_peer_workspace_evidence(&operation, terminal.workspace.workspace_id)
                .unwrap()
                .workspace
                .fence,
            original_fence
        );
        assert_eq!(evidence.source, source); // returned DTO outlives both guards
        assert!(owner.store.try_lock().is_ok());
    }
    #[test]
    fn all_local_observations_survive_remote_failure_without_opening_remote() {
        let (_root, owner, source, terminal) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        assert!(remote_capture_reaches_read(&owner, &operation)); // deliberately seals remote
        assert!(!remote_capture_reaches_read(&owner, &operation));
        assert!(
            owner
                .local_pending_pairing_decisions(&operation)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            owner
                .local_acknowledged_workspace_grants(&operation)
                .unwrap(),
            vec![source.clone()]
        );
        assert!(
            owner
                .local_pending_channel_admissions(&operation)
                .unwrap()
                .is_empty()
        );
        assert!(
            owner
                .local_acknowledged_channel_admissions(&operation)
                .unwrap()
                .is_empty()
        );
        owner
            .local_peer_workspace_evidence(&operation, terminal.workspace.workspace_id)
            .unwrap();
        owner
            .local_channel_source_evidence(&operation, source.intent.preparation.grant_id)
            .unwrap();
        assert!(!remote_capture_reaches_read(&owner, &operation));
    }
    #[test]
    fn busy_retry_keeps_original_cancellation_and_deadline_and_releases_domain() {
        for cancellation in [true, false] {
            let (_root, owner, source, _terminal) = fixture();
            let cancel = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancel);
            let held = owner.store.lock().unwrap();
            assert!(matches!(
                owner.local_channel_source_evidence(&operation, source.intent.preparation.grant_id),
                Err(Error::Domain(domain::Error::Busy))
            ));
            assert!(owner.domain.try_read(&operation).is_ok()); // Busy leaked no Domain guard
            if cancellation {
                cancel.store(true, SeqCst);
            } else {
                operation.expire_for_test();
            }
            drop(held);
            let result =
                owner.local_channel_source_evidence(&operation, source.intent.preparation.grant_id);
            if cancellation {
                assert!(matches!(
                    result,
                    Err(Error::Domain(domain::Error::Cancelled))
                ));
            } else {
                assert!(matches!(
                    result,
                    Err(Error::Domain(domain::Error::Deadline))
                ));
            }
            assert!(owner.store.try_lock().is_ok());
        }
    }
    #[test]
    fn domain_busy_does_not_touch_store_or_escape_guards() {
        let (_root, owner, _source, _terminal) = fixture();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        let held = owner.domain.try_read(&operation).unwrap();
        assert!(matches!(
            owner.local_pending_pairing_decisions(&operation),
            Err(Error::Domain(domain::Error::Busy))
        ));
        assert!(owner.store.try_lock().is_ok());
        drop(held);
        assert!(owner.local_pending_pairing_decisions(&operation).is_ok());
    }
    #[test]
    fn absent_workspace_or_source_preserves_not_found_without_sealing_remote() {
        for source_missing in [true, false] {
            let (_root, owner, _source, _terminal) = fixture();
            let cancel = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancel);
            let result = if source_missing {
                owner
                    .local_channel_source_evidence(
                        &operation,
                        GrantId::from_bytes([98; 16]).unwrap(),
                    )
                    .map(|_| ())
            } else {
                owner
                    .local_peer_workspace_evidence(
                        &operation,
                        WorkspaceId::from_bytes([98; 16]).unwrap(),
                    )
                    .map(|_| ())
            };
            assert!(matches!(result, Err(Error::Store(StoreError::NotFound))));
            assert!(remote_capture_reaches_read(&owner, &operation));
        }
    }
    #[test]
    fn uncertain_journal_errors_keep_actual_error_and_fail_remote_closed() {
        // Honest private injection seam: SQL decode/connection faults are not
        // induced here. Each error must bypass the workspace rejection policy.
        for error in [
            StoreError::Invalid,
            StoreError::Storage,
            StoreError::NotFound,
            StoreError::Busy,
            StoreError::ResourceExhausted,
        ] {
            let (_root, owner, _source, terminal) = fixture();
            let cancel = AtomicBool::new(false);
            let operation = Operation::new(end(), &cancel);
            let result = owner.read_local_peer_evidence::<()>(&operation, |_store| {
                Err(LocalEvidenceFailure::Uncertain(error))
            });
            assert!(matches!(result, Err(Error::UncertainStore(actual)) if actual == error));
            assert!(!remote_capture_reaches_read(&owner, &operation));
            assert!(
                owner
                    .local_peer_workspace_evidence(&operation, terminal.workspace.workspace_id)
                    .is_ok()
            );
            assert!(owner.store.try_lock().is_ok());
        }
    }
    fn channel(
        source: &AcknowledgedWorkspaceGrant,
        n: usize,
        terminal: Option<&TerminalContext>,
    ) -> ChannelAdmissionPreparation {
        let original = &source.intent.preparation;
        let PairingResult::Approved {
            grant,
            identities,
            authority,
            ..
        } = &source.response
        else {
            unreachable!()
        };
        let mut authority = authority.clone();
        let target = match terminal {
            Some(t) => {
                authority.terminal_membership = Some(ChannelTerminalMembership {
                    pane_id: t.pane_id,
                    session_id: t.session_id,
                    session_epoch: t.session_epoch,
                    terminal_profile: t.profile.clone(),
                });
                ChannelTarget::Terminal {
                    workspace_id: original.scope.workspace_id,
                    workspace_epoch: original.scope.workspace_epoch,
                    pane_id: t.pane_id,
                    session_id: t.session_id,
                    session_epoch: t.session_epoch,
                }
            }
            None => ChannelTarget::Workspace {
                workspace_id: original.scope.workspace_id,
                workspace_epoch: original.scope.workspace_epoch,
            },
        };
        ChannelAdmissionPreparation {
            scope: original.scope.clone(),
            channel_id: ChannelId::from_bytes(id(n)).unwrap(),
            source_grant_id: original.grant_id,
            source_grant_token: source.intent.token.clone(),
            target,
            inputs: ChannelAdmissionInputs {
                expected_context: "05".to_owned().try_into().unwrap(),
                expected_context_json: serde_json::Map::new(),
                grant: grant.clone(),
                identities: identities.clone(),
                authority,
            },
            issued_at: 1000,
            expires_at: 1020,
            params: ChannelAdmissionParams {
                runtime: original.scope.runtime.clone(),
                admission: SignedChannelAdmissionWire {
                    canonical_cbor: "06".to_owned().try_into().unwrap(),
                    signature: "33".repeat(64).try_into().unwrap(),
                },
            },
        }
    }
    fn admitted(intent: &ChannelAdmissionIntent) -> ChannelResult {
        ChannelResult::Admitted {
            channel_id: intent.preparation.channel_id,
            inputs: intent.preparation.inputs.clone(),
            admission: intent.preparation.params.admission.clone(),
        }
    }
    #[test]
    fn nonempty_owned_journal_lists_keep_exact_pending_and_acknowledged_records() {
        let root = tempfile::tempdir().unwrap();
        let mut store =
            HostStore::open(&root.path().join("host.sqlite"), Limits::default()).unwrap();
        let binding = install(&mut store);
        let id = workspace(&mut store, root.path());
        let source = grant(&mut store, &binding, id);
        let binding = publish(&mut store, &binding);
        let pending_pair = store
            .prepare_pairing_decision(preparation(&store, &binding, id, 50, false), 1000)
            .unwrap();
        let pending_channel = store
            .prepare_channel_admission(channel(&source, 60, None), 1000)
            .unwrap();
        let ack_intent = store
            .prepare_channel_admission(channel(&source, 61, None), 1000)
            .unwrap();
        let ack_channel = store
            .acknowledge_channel_admission(&ack_intent, &admitted(&ack_intent), 1000)
            .unwrap();
        let owner = SharedOwner::new(store).unwrap();
        let cancel = AtomicBool::new(false);
        let operation = Operation::new(end(), &cancel);
        assert_eq!(
            owner.local_pending_pairing_decisions(&operation).unwrap(),
            vec![pending_pair]
        );
        assert_eq!(
            owner
                .local_acknowledged_workspace_grants(&operation)
                .unwrap(),
            vec![source]
        );
        assert_eq!(
            owner.local_pending_channel_admissions(&operation).unwrap(),
            vec![pending_channel]
        );
        assert_eq!(
            owner
                .local_acknowledged_channel_admissions(&operation)
                .unwrap(),
            vec![ack_channel]
        );
        assert!(owner.domain.try_read(&operation).is_ok());
        assert!(owner.store.try_lock().is_ok());
    }
}
// END PASSIVE_PEER_CHANNEL_LOCAL_EVIDENCE_V1

// Fixed Cloud action snapshots. Returned records are observations, not permits.
#[cfg(any(unix, windows))]
pub(super) struct CloudWorkerSnapshot {
    pub(super) scope: CloudRuntimeScope,
    pub(super) binding: Option<CloudRuntimeState>,
    pub(super) acknowledged: Option<lomi_host_store::HostAcknowledgedPublication>,
    pub(super) needs_publication: bool,
}

/// Negative-only observation used to decide whether existing remote transports
/// must close. `Clear` never grants peer eligibility; every request still uses
/// the ordinary captured Cloud snapshot and Domain gates.
#[cfg(any(unix, windows))]
pub(super) enum CloudPublicationFenceObservation {
    Clear,
    CloseIngress,
    Defer,
}

#[cfg(any(unix, windows))]
impl SharedOwner {
    pub(super) fn cloud_worker_snapshot(
        &self,
        operation: &Operation<'_>,
        generation: u64,
    ) -> Result<Option<CloudWorkerSnapshot>, Error> {
        let guard = self.domain.try_read(operation).map_err(Error::Domain)?;
        let store = self.try_store()?;
        let mut result = None;
        let snapshot = guard.capture_remote(|| {
            let authorization = store.authorization_state()?;
            if authorization.generation != generation {
                return Err(StoreError::Fenced);
            }
            result = Some(
                match store
                    .auth_configuration()?
                    .and_then(|c| c.remote_api_origin)
                {
                    None => None,
                    Some(pin) => {
                        let scope =
                            store.cloud_runtime_scope(generation, pin.as_str().to_owned())?;
                        let binding = store
                            .cloud_runtime_reconciliation_state(&scope)?
                            .filter(|binding| binding.scope == scope);
                        let acknowledged = binding
                            .as_ref()
                            .map(|binding| store.acknowledged_host_publication(binding))
                            .transpose()?
                            .flatten();
                        let needs_publication = binding
                            .as_ref()
                            .is_none_or(|binding| binding.acknowledged_publication_seq.0 == 0)
                            || acknowledged.is_none()
                            || store.pending_host_publication()?.is_some()
                            || !store.pending_publications()?.is_empty();
                        Some(CloudWorkerSnapshot {
                            scope,
                            binding,
                            acknowledged,
                            needs_publication,
                        })
                    }
                },
            );
            StoreView::read(&store)
        })?;
        guard.validate(snapshot).map_err(Error::Domain)?;
        Ok(result.expect("successful capture produces owned snapshot"))
    }

    /// Observe only durable facts that can require closing ingress. This path
    /// intentionally takes no Domain read guard: an active Shared writer must
    /// not make the authorization worker seal itself while advancing that
    /// writer's final receipt. A clear result is not a permit and cannot mint,
    /// renew, or cache Cloud eligibility.
    pub(super) fn cloud_publication_fence_observation(
        &self,
        operation: &Operation<'_>,
        generation: u64,
        expected_scope: Option<&lomi_host_store::CloudRuntimeScope>,
    ) -> Result<CloudPublicationFenceObservation, Error> {
        operation.check().map_err(Error::Domain)?;
        let store = match self.try_store() {
            Ok(store) => store,
            Err(Error::Domain(domain::Error::Busy)) => {
                operation.check().map_err(Error::Domain)?;
                return Ok(CloudPublicationFenceObservation::Defer);
            }
            Err(error) => return Err(error),
        };

        let authorization = match store.authorization_state() {
            Ok(authorization) => authorization,
            Err(StoreError::Busy) => {
                operation.check().map_err(Error::Domain)?;
                return Ok(CloudPublicationFenceObservation::Defer);
            }
            Err(error) => return Err(Error::UncertainStore(error)),
        };
        if authorization.generation != generation
            || authorization.locked
            || authorization.pending_cloud_revoke
        {
            operation.check().map_err(Error::Domain)?;
            return Ok(CloudPublicationFenceObservation::CloseIngress);
        }

        let configuration = match store.auth_configuration() {
            Ok(configuration) => configuration,
            Err(StoreError::Busy) => {
                operation.check().map_err(Error::Domain)?;
                return Ok(CloudPublicationFenceObservation::Defer);
            }
            Err(error) => return Err(Error::UncertainStore(error)),
        };
        let Some(remote_api_origin) = configuration.and_then(|c| c.remote_api_origin) else {
            operation.check().map_err(Error::Domain)?;
            return Ok(CloudPublicationFenceObservation::CloseIngress);
        };
        let scope =
            match store.cloud_runtime_scope(generation, remote_api_origin.as_str().to_owned()) {
                Ok(scope) => scope,
                Err(StoreError::Busy) => {
                    operation.check().map_err(Error::Domain)?;
                    return Ok(CloudPublicationFenceObservation::Defer);
                }
                Err(StoreError::Fenced | StoreError::RevisionConflict) => {
                    operation.check().map_err(Error::Domain)?;
                    return Ok(CloudPublicationFenceObservation::CloseIngress);
                }
                Err(error) => return Err(Error::UncertainStore(error)),
            };
        if expected_scope.is_some_and(|expected| expected != &scope) {
            operation.check().map_err(Error::Domain)?;
            return Ok(CloudPublicationFenceObservation::CloseIngress);
        }
        let binding = match store.cloud_runtime_reconciliation_state(&scope) {
            Ok(Some(binding)) if binding.scope == scope => binding,
            Err(StoreError::Busy) => {
                operation.check().map_err(Error::Domain)?;
                return Ok(CloudPublicationFenceObservation::Defer);
            }
            Ok(_) | Err(StoreError::Fenced | StoreError::RevisionConflict) => {
                operation.check().map_err(Error::Domain)?;
                return Ok(CloudPublicationFenceObservation::CloseIngress);
            }
            Err(error) => return Err(Error::UncertainStore(error)),
        };
        let acknowledged = match store.acknowledged_host_publication(&binding) {
            Ok(acknowledged) => acknowledged,
            Err(StoreError::Busy) => {
                operation.check().map_err(Error::Domain)?;
                return Ok(CloudPublicationFenceObservation::Defer);
            }
            Err(StoreError::Fenced | StoreError::RevisionConflict) => {
                operation.check().map_err(Error::Domain)?;
                return Ok(CloudPublicationFenceObservation::CloseIngress);
            }
            Err(error) => return Err(Error::UncertainStore(error)),
        };
        let pending_host_publication = match store.pending_host_publication() {
            Ok(pending) => pending,
            Err(StoreError::Busy) => {
                operation.check().map_err(Error::Domain)?;
                return Ok(CloudPublicationFenceObservation::Defer);
            }
            Err(error) => return Err(Error::UncertainStore(error)),
        };
        let pending_publications = match store.pending_publications() {
            Ok(pending) => pending,
            Err(StoreError::Busy) => {
                operation.check().map_err(Error::Domain)?;
                return Ok(CloudPublicationFenceObservation::Defer);
            }
            Err(error) => return Err(Error::UncertainStore(error)),
        };
        let needs_publication = binding.acknowledged_publication_seq.0 == 0
            || acknowledged.is_none()
            || acknowledged
                .as_ref()
                .is_some_and(|publication| publication.state != binding)
            || pending_host_publication.is_some()
            || !pending_publications.is_empty();
        operation.check().map_err(Error::Domain)?;
        Ok(if needs_publication {
            CloudPublicationFenceObservation::CloseIngress
        } else {
            CloudPublicationFenceObservation::Clear
        })
    }

    /// Same negative-only publication observation, bound to the exact active
    /// Git lease. It cannot turn a clear result into Cloud or peer authority.
    pub(super) fn cloud_publication_fence_observation_started_git(
        &self,
        operation: &Operation<'_>,
        continuation: &StartedGitContinuation,
        generation: u64,
        expected_scope: Option<&lomi_host_store::CloudRuntimeScope>,
    ) -> Result<CloudPublicationFenceObservation, Error> {
        if !continuation.belongs_to(&self.domain) || !continuation.is_current(operation) {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let observation =
            self.cloud_publication_fence_observation(operation, generation, expected_scope)?;
        if !continuation.is_current(operation) {
            return Ok(CloudPublicationFenceObservation::CloseIngress);
        }
        Ok(observation)
    }

    /// Recheck only the locally acknowledged source grant for an already
    /// Started Git operation. This is a negative observation during the
    /// retained writer barrier; it cannot admit another peer effect.
    pub(super) fn started_git_pairing_source_current(
        &self,
        operation: &Operation<'_>,
        continuation: &StartedGitContinuation,
    ) -> Result<Option<bool>, Error> {
        if !continuation.belongs_to(&self.domain) || !continuation.is_current(operation) {
            return Ok(Some(false));
        }
        let store = match self.try_store() {
            Ok(store) => store,
            Err(Error::Domain(domain::Error::Busy)) => return Ok(None),
            Err(error) => return Err(error),
        };
        let rows = match PeerJournalRows::read_binding(
            &store,
            continuation.runtime(),
            continuation.context_workspace(),
        ) {
            Ok(rows) => rows,
            Err(StoreError::Busy) => return Ok(None),
            Err(error) => return Err(Error::UncertainStore(error)),
        };
        let current = rows.binding.as_ref() == Some(continuation.runtime())
            && rows.publication.as_ref() == Some(continuation.acknowledged())
            && approved_pairing_read_local(continuation.source(), &rows).is_ok();
        operation.check().map_err(Error::Domain)?;
        Ok(Some(current && continuation.is_current(operation)))
    }

    pub(super) fn started_git_pairing_source_for_target(
        &self,
        operation: &Operation<'_>,
        continuation: &StartedGitContinuation,
        target: &super::auth::peer::StartedGitPairingTarget,
    ) -> Result<lomi_host_store::AcknowledgedWorkspaceGrant, Error> {
        if !continuation.belongs_to(&self.domain)
            || !continuation.is_current(operation)
            || target.scope != continuation.runtime().scope
            || target.context.grant.consumer_id != target.consumer_window_id
            || target.context.grant.consumer_authorization_id
                != target.authority.consumer_authorization_id
        {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let workspace = WorkspaceId::from_bytes(target.context.grant.workspace_id)
            .map_err(|_| Error::Domain(domain::Error::Stale))?;
        let store = self.try_store()?;
        let rows = PeerJournalRows::read_binding(&store, continuation.runtime(), workspace)
            .map_err(Error::Store)?;
        if rows.binding.as_ref() != Some(continuation.runtime())
            || rows.publication.as_ref() != Some(continuation.acknowledged())
        {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let mut matches = rows.pairing_acknowledged.iter().filter(|source| {
            let preparation = &source.intent.preparation;
            let original_grant = match &preparation.params {
                lomi_remote_protocol::http::PairingDecisionParams::Approve { grant, .. } => grant,
                _ => return false,
            };
            preparation.scope.runtime_scope == target.scope
                && preparation.scope.runtime == continuation.runtime().server_runtime
                && preparation.scope.workspace_id == workspace
                && preparation.window_identity_id.to_bytes() == target.consumer_window_id
                && preparation.proposal.identities.consumer == target.consumer_identity
                && preparation.grant_id.to_bytes() == target.context.grant.grant_id
                && lomi_remote_crypto::SignedGrantV3::from_wire(original_grant)
                    .is_ok_and(|grant| grant == target.signed_grant)
                && matches!(
                    &source.response,
                    lomi_remote_protocol::http::PairingResult::Approved {
                        pairing_id, grant, identities, ..
                    } if *pairing_id == preparation.pairing_id
                        && grant == original_grant
                        && identities == &preparation.proposal.identities
                )
        });
        let source = matches.next().ok_or(Error::Domain(domain::Error::Stale))?;
        if matches.next().is_some() {
            return Err(Error::Domain(domain::Error::Stale));
        }
        approved_pairing_read_local(source, &rows)
            .map_err(|_| Error::Domain(domain::Error::Stale))?;
        operation.check().map_err(Error::Domain)?;
        if !continuation.is_current(operation) {
            return Err(Error::Domain(domain::Error::Stale));
        }
        Ok(source.clone())
    }
}

#[cfg(any(unix, windows))]
struct ClaimProducer {
    provider: usize,
    io: usize,
    gate: usize,
    paused: usize,
    stopping: usize,
}
/// Constructed ONLY from the retained actual configured GET's accepted response
/// and the Domain's original no-effect settlement. No public constructor.
#[cfg(any(unix, windows))]
pub(super) struct CloudClaimAdmission {
    continuation: domain::ClaimContinuation,
    tuple: CloudGetTuple,
    expected_generation: DecimalU64,
    accepted_epoch: DecimalU64,
    producer: ClaimProducer,
    consumed: bool,
}
#[cfg(any(unix, windows))]
struct CloudActionClock<'i> {
    io: &'i super::public_configuration::WorkerPublicIo<'i>,
    gate: &'i std::sync::atomic::AtomicBool,
    paused: &'i std::sync::atomic::AtomicBool,
    stopping: &'i std::sync::atomic::AtomicBool,
    base: u64,
    anchor: std::time::Instant,
}
#[cfg(any(unix, windows))]
impl CloudActionClock<'_> {
    fn check(&self, operation: &Operation<'_>, recovery: bool) -> Result<(), CloudGetError> {
        use std::sync::atomic::Ordering::Acquire;
        operation.check().map_err(CloudGetError::Domain)?;
        if self.stopping.load(Acquire)
            || self.paused.load(Acquire)
            || self.io.setup().pending.load(Acquire)
            || self.gate.load(Acquire) != recovery
        {
            return Err(CloudGetError::Stale);
        }
        Ok(())
    }
    fn now(&self) -> Result<u64, CloudGetError> {
        self.base
            .checked_add(self.anchor.elapsed().as_secs())
            .ok_or(CloudGetError::Domain(domain::Error::Exhausted))
    }
}
#[cfg(any(unix, windows))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum CloudClaimPhase {
    Prepare,
    Send,
    Clock,
    Complete,
    Terminal,
}
#[cfg(any(unix, windows))]
pub(super) struct CoherentCloudClaim<
    't,
    'd,
    'o,
    'w,
    'p,
    'i,
    S: lomi_platform::secrets::SecretStorage + ?Sized,
> {
    admission: &'t mut CloudClaimAdmission,
    owner: &'d SharedOwner,
    operation: &'o Operation<'o>,
    auth: &'w mut lomi_host_auth::HostAuth<'p, S>,
    clock: CloudActionClock<'i>,
    request: Option<lomi_remote_protocol::http::RuntimeClaimParams>,
    access: Option<lomi_remote_protocol::HostAccessCredential>,
    http: Option<lomi_host_http::DataTransport>,
    response: Option<Result<lomi_remote_protocol::http::RuntimeClaimResult, lomi_host_http::Error>>,
    phase: CloudClaimPhase,
    terminal: Option<CloudGetError>,
    #[cfg(test)]
    api: Option<&'w dyn super::auth::CloudDataApi>,
}
#[cfg(any(unix, windows))]
impl CloudClaimAdmission {
    pub(super) fn expected_generation(&self) -> DecimalU64 {
        self.expected_generation
    }
    pub(super) fn was_sent(&self) -> bool {
        self.consumed
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "retain original operation, actual provider and exact IO/latch identities"
    )]
    pub(super) fn begin<
        't,
        'd,
        'o,
        'w,
        'p,
        'i,
        S: lomi_platform::secrets::SecretStorage + ?Sized,
    >(
        &'t mut self,
        owner: &'d SharedOwner,
        operation: &'o Operation<'o>,
        auth: &'w mut lomi_host_auth::HostAuth<'p, S>,
        io: &'i super::public_configuration::WorkerPublicIo<'i>,
        gate: &'i std::sync::atomic::AtomicBool,
        paused: &'i std::sync::atomic::AtomicBool,
        stopping: &'i std::sync::atomic::AtomicBool,
        base: u64,
        anchor: std::time::Instant,
    ) -> Result<CoherentCloudClaim<'t, 'd, 'o, 'w, 'p, 'i, S>, CloudGetError> {
        if self.continuation.get_started() > std::time::Instant::now() {
            return Err(CloudGetError::Stale);
        }
        if self.consumed
            || self.producer.provider != auth as *const _ as usize
            || self.producer.io != io as *const _ as usize
            || self.producer.gate != gate as *const _ as usize
            || self.producer.paused != paused as *const _ as usize
            || self.producer.stopping != stopping as *const _ as usize
        {
            return Err(CloudGetError::Stale);
        }
        Ok(CoherentCloudClaim {
            admission: self,
            owner,
            operation,
            auth,
            clock: CloudActionClock {
                io,
                gate,
                paused,
                stopping,
                base,
                anchor,
            },
            request: None,
            access: None,
            http: None,
            response: None,
            phase: CloudClaimPhase::Prepare,
            terminal: None,
            #[cfg(test)]
            api: None,
        })
    }
}
#[cfg(any(unix, windows))]
impl<S: lomi_platform::secrets::SecretStorage + ?Sized>
    CoherentCloudClaim<'_, '_, '_, '_, '_, '_, S>
{
    fn checkpoint(&mut self) -> Result<u64, CloudGetError> {
        self.clock.check(self.operation, false)?;
        let now = self.clock.now()?;
        let mut guard = self
            .owner
            .domain
            .try_read(self.operation)
            .map_err(CloudGetError::Domain)?;
        let mut store = self.owner.try_store().map_err(CloudGetError::from)?;
        self.admission.tuple.revalidate(
            &store,
            #[cfg(test)]
            None,
        )?;
        guard
            .checkpoint_claim_clock(&self.admission.continuation, &mut store, now)
            .map_err(CloudGetError::from)
    }
    fn provider(
        &self,
        now: u64,
    ) -> Result<lomi_remote_protocol::HostAccessCredential, CloudGetError> {
        if self.auth.status() != lomi_host_auth::Status::Ready
            || self.auth.trusted_configuration() != &self.admission.tuple.trusted
            || self
                .auth
                .credential_deadlines()
                .map_err(CloudGetError::Provider)?
                != self.admission.tuple.deadlines
            || self
                .auth
                .verified_host_access_epoch()
                .map_err(CloudGetError::Provider)?
                != self.admission.accepted_epoch
            || now >= self.admission.tuple.deadlines.refresh_at
        {
            return Err(CloudGetError::Stale);
        }
        self.auth
            .access_credential(now)
            .map_err(CloudGetError::Provider)
    }
    pub(super) fn try_step(&mut self) -> Result<bool, CloudGetError> {
        if let Some(error) = self.terminal {
            return Err(error);
        }
        if self.phase == CloudClaimPhase::Complete {
            return Err(CloudGetError::Stale);
        }
        let result = self
            .clock
            .check(self.operation, false)
            .and_then(|()| match self.phase {
                CloudClaimPhase::Prepare => {
                    let floor = self.checkpoint()?;
                    self.access = Some(self.provider(self.clock.now()?.max(floor))?);
                    self.request = Some(lomi_remote_protocol::http::RuntimeClaimParams {
                        runtime_id: self.admission.tuple.scope.owner_runtime_id,
                        expected_generation: self.admission.expected_generation,
                    });
                    let origin = lomi_host_http::RemoteApiOrigin::new(
                        &self.admission.tuple.trusted,
                        self.admission.tuple.scope.remote_api_origin.clone(),
                    )
                    .map_err(CloudGetError::Http)?;
                    self.http = Some(
                        self.clock
                            .io
                            .data_transport(origin)
                            .map_err(CloudGetError::Http)?,
                    );
                    self.phase = CloudClaimPhase::Send;
                    Ok(false)
                }
                CloudClaimPhase::Send => {
                    let floor = self.checkpoint()?;
                    // Actual same provider work completes BEFORE the last fixed
                    // Domain/Store tuple check. No callback or lock spans HTTP.
                    let access = self.provider(self.clock.now()?.max(floor))?;
                    if self.access.as_ref() != Some(&access) {
                        return Err(CloudGetError::Stale);
                    }
                    {
                        let guard = self
                            .owner
                            .domain
                            .try_read(self.operation)
                            .map_err(CloudGetError::Domain)?;
                        let store = self.owner.try_store().map_err(CloudGetError::from)?;
                        self.admission.tuple.revalidate(
                            &store,
                            #[cfg(test)]
                            None,
                        )?;
                        guard
                            .check_claim_send(&self.admission.continuation, &store)
                            .map_err(CloudGetError::from)?;
                    }
                    // Last pure original-operation/latch/time check, after all
                    // provider/Store work, immediately before the actual send.
                    if self.clock.now()? >= self.admission.tuple.deadlines.refresh_at {
                        return Err(CloudGetError::Stale);
                    }
                    self.clock.check(self.operation, false)?;
                    self.admission.consumed = true;
                    let request = self.request.as_ref().ok_or(CloudGetError::Stale)?;
                    let host = self.admission.tuple.scope.host_id;
                    #[cfg(test)]
                    let response = if let Some(api) = self.api {
                        api.claim(host, request, &access)
                    } else {
                        configured_cloud_claim_send(
                            self.http.as_ref().ok_or(CloudGetError::Stale)?,
                            host,
                            request,
                            &access,
                            self.operation,
                        )
                    };
                    #[cfg(not(test))]
                    let response = configured_cloud_claim_send(
                        self.http.as_ref().ok_or(CloudGetError::Stale)?,
                        host,
                        request,
                        &access,
                        self.operation,
                    );
                    self.response = Some(response);
                    self.phase = CloudClaimPhase::Clock;
                    Ok(false)
                }
                CloudClaimPhase::Clock => {
                    let floor = self.checkpoint()?;
                    let access = self.provider(self.clock.now()?.max(floor))?;
                    if self.access.as_ref() != Some(&access) {
                        return Err(CloudGetError::Stale);
                    }
                    self.clock.check(self.operation, false)?;
                    // Even a valid Claim response grants NOTHING. The caller's
                    // pre-armed Get action reconciles success AND unknown outcomes.
                    self.response
                        .as_ref()
                        .ok_or(CloudGetError::Stale)?
                        .as_ref()
                        .map_err(|error| CloudGetError::Http(*error))?;
                    self.phase = CloudClaimPhase::Complete;
                    Ok(true)
                }
                CloudClaimPhase::Complete | CloudClaimPhase::Terminal => Err(CloudGetError::Stale),
            });
        if matches!(result, Err(CloudGetError::Domain(domain::Error::Busy))) {
            return result;
        }
        if let Err(error) = result {
            if error.is_uncertain() {
                self.owner.domain.cloud_uncertain();
            }
            self.terminal = Some(error);
            self.phase = CloudClaimPhase::Terminal;
        }
        result
    }
}
#[cfg(any(unix, windows))]
fn configured_cloud_claim_send(
    transport: &lomi_host_http::DataTransport,
    host: HostId,
    request: &lomi_remote_protocol::http::RuntimeClaimParams,
    access: &lomi_remote_protocol::HostAccessCredential,
    operation: &Operation<'_>,
) -> Result<lomi_remote_protocol::http::RuntimeClaimResult, lomi_host_http::Error> {
    let budget = OriginalOperationHttpBudget { operation };
    let check = || budget.check();
    transport
        .with_budget(budget.deadline(), &check)
        .runtime_claim(host, request, access)
}

#[cfg(any(unix, windows))]
#[derive(Clone, PartialEq, Eq)]
struct LogoutEpochTuple {
    trusted: lomi_host_auth::Config,
    identity: Identity,
    runtime: lomi_remote_protocol::RuntimeId,
    configuration: LocalAuthConfiguration,
    public_state: lomi_host_store::PublicConfigurationState,
    public_document: PublicDocument,
    generation: u64,
    verified: Option<u64>,
    cloud_may_exist: Option<bool>,
    pending: Option<HostPublicationIntent>,
    epoch: DecimalU64,
    deadlines: lomi_host_auth::CredentialDeadlines,
}
#[cfg(any(unix, windows))]
impl LogoutEpochTuple {
    fn read(
        store: &HostStore,
        trusted: &lomi_host_auth::Config,
        epoch: DecimalU64,
        deadlines: lomi_host_auth::CredentialDeadlines,
    ) -> Result<Self, CloudGetError> {
        let identity = store.identity().clone();
        let configuration = store.auth_configuration()?.ok_or(CloudGetError::Stale)?;
        configuration.validate().map_err(|_| CloudGetError::Stale)?;
        let derived = lomi_host_auth::Config::new(
            identity.host_id,
            identity.profile_id,
            configuration.origin.as_str().to_owned(),
            configuration
                .client_id
                .as_str()
                .to_owned()
                .try_into()
                .map_err(|_| CloudGetError::Stale)?,
        )
        .map_err(CloudGetError::Provider)?;
        if &derived != trusted {
            return Err(CloudGetError::Stale);
        }
        let public_state = store
            .public_configuration_state()?
            .ok_or(CloudGetError::Stale)?;
        let public_document = store.public_current()?;
        if !store.public_configuration_ready()?
            || public_state.prepared.is_some()
            || public_state.current.as_ref() != Some(&public_document)
            || public_document.configuration()?.authentication.as_ref() != Some(&configuration)
        {
            return Err(CloudGetError::Stale);
        }
        let state = store.authorization_state()?;
        if !state.locked || !state.pending_cloud_revoke {
            return Err(CloudGetError::Stale);
        }
        Ok(Self {
            trusted: trusted.clone(),
            identity,
            runtime: store.runtime_id(),
            configuration,
            public_state,
            public_document,
            generation: state.generation,
            verified: store.verified_authorization_generation()?,
            cloud_may_exist: store.cloud_authorization_may_exist()?,
            pending: store.pending_host_publication()?,
            epoch,
            deadlines,
        })
    }
    fn revalidate(&self, store: &HostStore) -> Result<(), CloudGetError> {
        if Self::read(store, &self.trusted, self.epoch, self.deadlines)? != *self {
            return Err(CloudGetError::Stale);
        }
        Ok(())
    }
}
#[cfg(any(unix, windows))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum LogoutEpochPhase {
    Prepare,
    Send,
    Clock,
    Accept,
    Final,
    Complete,
    Terminal,
}
#[cfg(any(unix, windows))]
pub(super) struct CoherentLogoutEpoch<
    'd,
    'o,
    'w,
    'p,
    'i,
    S: lomi_platform::secrets::SecretStorage + ?Sized,
> {
    owner: &'d SharedOwner,
    operation: &'o Operation<'o>,
    auth: &'w mut lomi_host_auth::HostAuth<'p, S>,
    clock: CloudActionClock<'i>,
    generation: u64,
    scope: Option<domain::LogoutRecoveryScope<'d, 'o>>,
    tuple: Option<LogoutEpochTuple>,
    access: Option<lomi_remote_protocol::HostAccessCredential>,
    http: Option<lomi_host_http::DataTransport>,
    response: Option<Result<lomi_remote_protocol::HostRuntimeGetResult, lomi_host_http::Error>>,
    provider_invalid: bool,
    accepted_epoch: Option<DecimalU64>,
    phase: LogoutEpochPhase,
    terminal: Option<CloudGetError>,
    allow_identity_revoke: bool,
    #[cfg(test)]
    api: Option<&'w dyn super::auth::CloudDataApi>,
}
#[cfg(any(unix, windows))]
impl SharedOwner {
    #[expect(
        clippy::too_many_arguments,
        reason = "recovery binds the original operation, actual provider, IO exclusion and closed gate"
    )]
    pub(super) fn begin_logout_epoch<
        'd,
        'o,
        'w,
        'p,
        'i,
        S: lomi_platform::secrets::SecretStorage + ?Sized,
    >(
        &'d self,
        operation: &'o Operation<'o>,
        auth: &'w mut lomi_host_auth::HostAuth<'p, S>,
        io: &'i super::public_configuration::WorkerPublicIo<'i>,
        gate: &'i std::sync::atomic::AtomicBool,
        paused: &'i std::sync::atomic::AtomicBool,
        stopping: &'i std::sync::atomic::AtomicBool,
        base: u64,
        anchor: std::time::Instant,
        generation: u64,
    ) -> CoherentLogoutEpoch<'d, 'o, 'w, 'p, 'i, S> {
        CoherentLogoutEpoch {
            owner: self,
            operation,
            auth,
            clock: CloudActionClock {
                io,
                gate,
                paused,
                stopping,
                base,
                anchor,
            },
            generation,
            scope: None,
            tuple: None,
            access: None,
            http: None,
            response: None,
            provider_invalid: false,
            accepted_epoch: None,
            phase: LogoutEpochPhase::Prepare,
            terminal: None,
            allow_identity_revoke: false,
            #[cfg(test)]
            api: None,
        }
    }
}
#[cfg(any(unix, windows))]
impl<S: lomi_platform::secrets::SecretStorage + ?Sized> CoherentLogoutEpoch<'_, '_, '_, '_, '_, S> {
    pub(super) fn allows_identity_revoke(&self) -> bool {
        self.allow_identity_revoke
    }
    fn checkpoint(&mut self) -> Result<u64, CloudGetError> {
        self.clock.check(self.operation, true)?;
        let now = self.clock.now()?;
        let mut guard = self
            .owner
            .domain
            .try_read(self.operation)
            .map_err(CloudGetError::Domain)?;
        let mut store = self.owner.try_store().map_err(CloudGetError::from)?;
        self.tuple
            .as_ref()
            .ok_or(CloudGetError::Stale)?
            .revalidate(&store)?;
        guard
            .checkpoint_logout_recovery_clock(
                self.scope.as_ref().ok_or(CloudGetError::Stale)?,
                &mut store,
                now,
            )
            .map_err(CloudGetError::from)
    }
    fn provider(
        &self,
        now: u64,
        epoch: DecimalU64,
    ) -> Result<lomi_remote_protocol::HostAccessCredential, CloudGetError> {
        let tuple = self.tuple.as_ref().ok_or(CloudGetError::Stale)?;
        if self.auth.status() != lomi_host_auth::Status::Ready
            || self.auth.trusted_configuration() != &tuple.trusted
            || self
                .auth
                .credential_deadlines()
                .map_err(CloudGetError::Provider)?
                != tuple.deadlines
            || self
                .auth
                .verified_host_access_epoch()
                .map_err(CloudGetError::Provider)?
                != epoch
        {
            return Err(CloudGetError::Stale);
        }
        self.auth
            .access_credential(now)
            .map_err(CloudGetError::Provider)
    }
    pub(super) fn try_step(&mut self) -> Result<bool, CloudGetError> {
        if let Some(error) = self.terminal {
            return Err(error);
        }
        if self.phase == LogoutEpochPhase::Complete {
            return Err(CloudGetError::Stale);
        }
        let result = self
            .clock
            .check(self.operation, true)
            .and_then(|()| match self.phase {
                LogoutEpochPhase::Prepare => {
                    if self.auth.status() != lomi_host_auth::Status::Ready {
                        return Err(CloudGetError::Stale);
                    }
                    let trusted = self.auth.trusted_configuration().clone();
                    let epoch = self
                        .auth
                        .verified_host_access_epoch()
                        .map_err(CloudGetError::Provider)?;
                    let deadlines = self
                        .auth
                        .credential_deadlines()
                        .map_err(CloudGetError::Provider)?;
                    self.access = Some(
                        self.auth
                            .access_credential(self.clock.now()?)
                            .map_err(CloudGetError::Provider)?,
                    );
                    let tuple;
                    {
                        let mut guard = self
                            .owner
                            .domain
                            .try_read(self.operation)
                            .map_err(CloudGetError::Domain)?;
                        let mut store = self.owner.try_store().map_err(CloudGetError::from)?;
                        tuple = LogoutEpochTuple::read(&store, &trusted, epoch, deadlines)?;
                        if tuple.generation != self.generation {
                            return Err(CloudGetError::Stale);
                        }
                        let scope = guard
                            .prepare_logout_recovery(&store)
                            .map_err(CloudGetError::from)?;
                        guard
                            .checkpoint_logout_recovery_clock(&scope, &mut store, self.clock.now()?)
                            .map_err(CloudGetError::from)?;
                        self.scope = Some(scope);
                    }
                    let pin = tuple
                        .configuration
                        .remote_api_origin
                        .as_ref()
                        .ok_or(CloudGetError::Stale)?
                        .as_str()
                        .to_owned();
                    let origin = lomi_host_http::RemoteApiOrigin::new(&trusted, pin)
                        .map_err(CloudGetError::Http)?;
                    self.http = Some(
                        self.clock
                            .io
                            .data_transport(origin)
                            .map_err(CloudGetError::Http)?,
                    );
                    self.tuple = Some(tuple);
                    self.phase = LogoutEpochPhase::Send;
                    Ok(false)
                }
                LogoutEpochPhase::Send => {
                    let floor = self.checkpoint()?;
                    let epoch = self.tuple.as_ref().ok_or(CloudGetError::Stale)?.epoch;
                    let access = self.provider(self.clock.now()?.max(floor), epoch)?;
                    if self.access.as_ref() != Some(&access) {
                        return Err(CloudGetError::Stale);
                    }
                    {
                        let guard = self
                            .owner
                            .domain
                            .try_read(self.operation)
                            .map_err(CloudGetError::Domain)?;
                        let store = self.owner.try_store().map_err(CloudGetError::from)?;
                        self.tuple
                            .as_ref()
                            .ok_or(CloudGetError::Stale)?
                            .revalidate(&store)?;
                        guard
                            .check_logout_recovery_send(
                                self.scope.as_ref().ok_or(CloudGetError::Stale)?,
                                &store,
                            )
                            .map_err(CloudGetError::from)?;
                    }
                    let tuple = self.tuple.as_ref().ok_or(CloudGetError::Stale)?;
                    if self.clock.now()? >= tuple.deadlines.access_expires_at {
                        return Err(CloudGetError::Provider(lomi_host_auth::Error::Expired));
                    }
                    self.clock.check(self.operation, true)?;
                    #[cfg(test)]
                    let response = if let Some(api) = self.api {
                        api.get(tuple.identity.host_id, &access)
                    } else {
                        configured_logout_epoch_send(
                            self.http.as_ref().ok_or(CloudGetError::Stale)?,
                            tuple.identity.host_id,
                            &access,
                            self.operation,
                        )
                    };
                    #[cfg(not(test))]
                    let response = configured_logout_epoch_send(
                        self.http.as_ref().ok_or(CloudGetError::Stale)?,
                        tuple.identity.host_id,
                        &access,
                        self.operation,
                    );
                    self.response = Some(response);
                    self.phase = LogoutEpochPhase::Clock;
                    Ok(false)
                }
                LogoutEpochPhase::Clock => {
                    let floor = self.checkpoint()?;
                    let epoch = self.tuple.as_ref().ok_or(CloudGetError::Stale)?.epoch;
                    self.provider(self.clock.now()?.max(floor), epoch)?;
                    self.clock.check(self.operation, true)?;
                    if let Some(Err(error)) = self.response.as_ref() {
                        self.allow_identity_revoke = true;
                        return Err(CloudGetError::Http(*error));
                    }
                    self.phase = LogoutEpochPhase::Accept;
                    Ok(false)
                }
                LogoutEpochPhase::Accept => {
                    let floor = self.checkpoint()?;
                    let epoch = self.tuple.as_ref().ok_or(CloudGetError::Stale)?.epoch;
                    self.provider(self.clock.now()?.max(floor), epoch)?;
                    self.clock.check(self.operation, true)?;
                    let snapshot = self
                        .response
                        .as_ref()
                        .ok_or(CloudGetError::Stale)?
                        .as_ref()
                        .map_err(|error| CloudGetError::Http(*error))?
                        .clone();
                    self.accepted_epoch = Some(snapshot.host_access_epoch);
                    // Provider uncertainty precedes ANY post-provider clock/fence
                    // error. A successful epoch commit cannot restore remote Ready.
                    match self.auth.accept_runtime_observation(
                        epoch,
                        snapshot,
                        self.clock.now()?.max(floor),
                    ) {
                        Err(error) if error != lomi_host_auth::Error::InvalidResponse => {
                            return Err(CloudGetError::Provider(error));
                        }
                        Err(_) => self.provider_invalid = true,
                        Ok(()) => self.provider_invalid = false,
                    }
                    self.phase = LogoutEpochPhase::Final;
                    Ok(false)
                }
                LogoutEpochPhase::Final => {
                    let floor = self.checkpoint()?;
                    if !self.provider_invalid {
                        self.provider(
                            self.clock.now()?.max(floor),
                            self.accepted_epoch.ok_or(CloudGetError::Stale)?,
                        )?;
                    }
                    self.clock.check(self.operation, true)?;
                    self.allow_identity_revoke = true;
                    if self.provider_invalid {
                        return Err(CloudGetError::Http(lomi_host_http::Error::InvalidResponse));
                    }
                    self.phase = LogoutEpochPhase::Complete;
                    Ok(true)
                }
                LogoutEpochPhase::Complete | LogoutEpochPhase::Terminal => {
                    Err(CloudGetError::Stale)
                }
            });
        if matches!(result, Err(CloudGetError::Domain(domain::Error::Busy))) {
            return result;
        }
        if let Err(error) = result {
            if error.is_uncertain() {
                self.owner.domain.cloud_uncertain();
            }
            self.terminal = Some(error);
            self.phase = LogoutEpochPhase::Terminal;
        }
        result
    }
}
#[cfg(any(unix, windows))]
fn configured_logout_epoch_send(
    transport: &lomi_host_http::DataTransport,
    host: HostId,
    access: &lomi_remote_protocol::HostAccessCredential,
    operation: &Operation<'_>,
) -> Result<lomi_remote_protocol::HostRuntimeGetResult, lomi_host_http::Error> {
    let budget = OriginalOperationHttpBudget { operation };
    let check = || budget.check();
    transport
        .with_budget(budget.deadline(), &check)
        .runtime_get(host, access)
}

#[cfg(test)]
impl<'w, S: lomi_platform::secrets::SecretStorage + ?Sized>
    CoherentCloudClaim<'_, '_, '_, 'w, '_, '_, S>
{
    pub(super) fn install_cloud_api_for_test(&mut self, api: &'w dyn super::auth::CloudDataApi) {
        assert!(self.phase == CloudClaimPhase::Prepare);
        self.api = Some(api);
    }
}
#[cfg(test)]
impl<'w, S: lomi_platform::secrets::SecretStorage + ?Sized>
    CoherentLogoutEpoch<'_, '_, 'w, '_, '_, S>
{
    pub(super) fn install_cloud_api_for_test(&mut self, api: &'w dyn super::auth::CloudDataApi) {
        assert!(self.phase == LogoutEpochPhase::Prepare);
        self.api = Some(api);
    }
}
#[cfg(any(unix, windows))]
impl<S: lomi_platform::secrets::SecretStorage + ?Sized>
    ConfiguredNormalPublication<'_, '_, '_, '_, S>
{
    pub(super) fn finish_heartbeat_only(&mut self) -> Result<(), PublicationError> {
        self.boundary()?;
        let now = self.now()?;
        let observation = self.observation.take().ok_or(PublicationError::Stale)?;
        observation
            .validate_provider(self.auth, now)
            .map_err(PublicationError::from)?;
        self.boundary()?;
        observation
            .complete_heartbeat_only(now)
            .map_err(PublicationError::from)
    }
}

#[cfg(test)]
pub(super) struct CloudTestRecords {
    pub(super) pending: Option<HostPublicationIntent>,
    pub(super) outbox: Vec<lomi_host_store::Publication>,
    pub(super) binding: Option<CloudRuntimeState>,
    pub(super) acknowledged: Option<lomi_host_store::HostAcknowledgedPublication>,
}
#[cfg(test)]
impl SharedOwner {
    pub(super) fn cloud_records_for_test(
        &self,
        operation: &Operation<'_>,
        scope: Option<&CloudRuntimeScope>,
    ) -> Result<CloudTestRecords, Error> {
        self.read(operation, |store| {
            let binding = scope
                .map(|scope| store.cloud_runtime_reconciliation_state(scope))
                .transpose()?
                .flatten();
            let acknowledged = binding
                .as_ref()
                .filter(|binding| Some(&binding.scope) == scope)
                .map(|binding| store.acknowledged_host_publication(binding))
                .transpose()?
                .flatten();
            Ok(CloudTestRecords {
                pending: store.pending_host_publication()?,
                outbox: store.pending_publications()?,
                binding,
                acknowledged,
            })
        })
    }
}

#[cfg(test)]
impl<'w, S: lomi_platform::secrets::SecretStorage + ?Sized> ConfiguredWorkerAttempt<'w, '_, '_, S> {
    pub(super) fn install_auth_api_for_test(&mut self, api: &'w dyn super::auth::AuthTransport) {
        assert!(matches!(&self.http, WorkerReadyHttp::Configured(_)));
        self.auth_api = Some(api);
    }
}
#[cfg(test)]
impl<'w, S: lomi_platform::secrets::SecretStorage + ?Sized> ConfiguredCloudAttempt<'w, '_, '_, S> {
    pub(super) fn install_cloud_api_for_test(&mut self, api: &'w dyn super::auth::CloudDataApi) {
        assert!(!self.started_once);
        self.api = Some(api);
    }
}
#[cfg(test)]
impl<'w, S: lomi_platform::secrets::SecretStorage + ?Sized>
    ConfiguredNormalPublication<'w, '_, '_, '_, S>
{
    pub(super) fn install_cloud_api_for_test(&mut self, api: &'w dyn super::auth::CloudDataApi) {
        if let Some(installed) = self.api {
            // A retained heartbeat-to-PUT turn may reinstall only the exact
            // same trait object. Never replace transport after any send.
            assert!(std::ptr::eq(installed, api));
            return;
        }
        assert!(!self.started);
        assert!(
            !self.heartbeat_started
                || (self.driver.is_none() && self.observation.is_some() && self.retained.is_some())
        );
        self.api = Some(api);
    }
}

// Integrate into unix/shared_owner.rs only as part of Root's whole-graph switch.
// Both use the existing LOCAL read path (including remote FailClosed/no Ready).
impl SharedOwner {
    pub(super) fn local_status(
        &self,
        operation: &Operation<'_>,
    ) -> Result<lomi_remote_protocol::ipc::LocalStatus, Error> {
        self.read(operation, |store| {
            use lomi_remote_protocol::ipc::{LocalSharing, LocalStatus};
            Ok(LocalStatus {
                host_name: store.host_display_name()?.ok_or(StoreError::Storage)?,
                host_id: store.identity().host_id,
                runtime_id: store.runtime_id(),
                sharing: if store.list_projects()?.iter().any(|project| project.consent) {
                    LocalSharing::Enabled
                } else {
                    LocalSharing::Disabled
                },
            })
        })
    }

    pub(super) fn default_shell(
        &self,
        operation: &Operation<'_>,
    ) -> Result<Option<lomi_host_store::DefaultShellProfile>, Error> {
        self.read(operation, HostStore::default_shell)
    }

    pub(super) fn projection_hint(&self) -> Option<u64> {
        self.domain.projection_hint()
    }

    pub(super) fn maintenance_status(
        &self,
        operation: &Operation<'_>,
    ) -> Result<lomi_remote_protocol::ipc::LocalMaintenanceStatus, Error> {
        self.read(operation, HostStore::maintenance_status)
    }

    pub(super) fn shell_profile(
        &self,
        operation: &Operation<'_>,
        workspace_id: WorkspaceId,
        profile_id: &lomi_remote_protocol::rpc::HostProfileId,
    ) -> Result<Option<lomi_remote_protocol::ipc::LocalShellProfileRegister>, Error> {
        self.read(operation, |store| {
            store.shell_profile(workspace_id, profile_id)
        })
    }

    pub(super) fn shell_profile_with_cwd_override(
        &self,
        operation: &Operation<'_>,
        workspace_id: WorkspaceId,
        profile_id: &lomi_remote_protocol::rpc::HostProfileId,
    ) -> Result<
        Option<(
            lomi_remote_protocol::ipc::LocalShellProfileRegister,
            Option<std::path::PathBuf>,
        )>,
        Error,
    > {
        self.read(operation, |store| {
            store.shell_profile_with_cwd_override(workspace_id, profile_id)
        })
    }
}

// Test-only synchronization seam for the existing lock-order regressions.
// Exposes neither a Store/Mutex guard nor a caller-supplied callback. Production
// code never parks while holding either guard. The typed rendezvous deliberately
// holds both guards so the test can prove Core effect gates remain independent.
#[cfg(test)]
impl SharedOwner {
    pub(super) fn hold_store_for_test(
        &self,
        operation: &Operation<'_>,
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) -> Result<(), Error> {
        let _domain = self.domain.try_read(operation).map_err(Error::Domain)?;
        let _store = self.try_store()?;
        entered
            .send(())
            .map_err(|_| Error::Domain(domain::Error::Stale))?;
        release
            .recv_timeout(
                operation
                    .deadline()
                    .saturating_duration_since(std::time::Instant::now()),
            )
            .map_err(|_| Error::Domain(domain::Error::Deadline))?;
        Ok(())
    }
}

// Root integration addition to shared_owner.rs, test-only. The caller MUST
// first call the actual ConfiguredWorkerAttempt::from_existing_worker factory.
// No Store callbacks, authority constructors, or external Ready boolean.
#[cfg(test)]
impl<S: lomi_platform::secrets::SecretStorage + ?Sized> ConfiguredWorkerAttempt<'_, '_, '_, S> {
    pub(super) fn install_ready_http_script_for_test(
        &mut self,
        sends: std::rc::Rc<std::cell::Cell<usize>>,
        exact_request: std::rc::Rc<std::cell::RefCell<Option<String>>>,
        projected_now: u64,
    ) {
        assert!(matches!(&self.http, WorkerReadyHttp::Configured(_)));
        assert_eq!(sends.get(), 0);
        assert!(exact_request.borrow().is_none());
        assert!(projected_now >= self.base);
        // Deterministic projection uses the existing cfg(test) clock seam;
        // production clock projection and provider lifetime are unchanged.
        self.projected_for_test = Some(projected_now);
        self.http = WorkerReadyHttp::Scripted(WorkerReadyScript {
            send_failure: None,
            sends,
            exact_request,
            clock_failure: None,
        });
    }
}
#[cfg(test)]
impl<S: lomi_platform::secrets::SecretStorage + ?Sized>
    SoleWorkerReadyTurn<'_, '_, '_, '_, '_, '_, S>
{
    pub(super) fn advance_retained_response_time_for_test(
        &mut self,
        now: u64,
    ) -> Result<(), WorkerReadyError> {
        self.check_boundary()?;
        if self.phase != WorkerReadyPhase::Clock
            || !matches!(
                self.response.as_ref(),
                Some(WorkerReadyResponse::Register(_))
            )
            || !matches!(&self.attempt.http, WorkerReadyHttp::Scripted(_))
        {
            return Err(WorkerReadyError::Stale);
        }
        if now < self.attempt.projected_time()? {
            return Err(WorkerReadyError::Provider(
                lomi_host_auth::Error::ClockRollback,
            ));
        }
        // Only time changes; the original response/request/scope/Operation and
        // borrowed HostAuth/provider/IO lease remain retained by the same turn.
        self.attempt.projected_for_test = Some(now);
        Ok(())
    }
}

// Private cfg(test) access for existing synthetic mutation/race fixtures only.
// It cannot be compiled into production or mint Ready. Tests obtain this view
// from the same owner used by Runtime and construct real Ready separately.
#[cfg(test)]
pub(super) struct PeerStoreForTest {
    owner: Arc<SharedOwner>,
}
#[cfg(test)]
impl PeerStoreForTest {
    pub(super) fn lock(&self) -> std::sync::LockResult<std::sync::MutexGuard<'_, HostStore>> {
        self.owner.store.lock()
    }
    pub(super) fn try_lock(
        &self,
    ) -> std::sync::TryLockResult<std::sync::MutexGuard<'_, HostStore>> {
        self.owner.store.try_lock()
    }
    pub(super) fn observe_clock_for_test(
        &self,
        operation: &Operation<'_>,
        now: u64,
    ) -> Result<u64, Error> {
        let mut guard = self
            .owner
            .domain
            .try_read(operation)
            .map_err(Error::Domain)?;
        let mut store = self.owner.try_store()?;
        let continuation = guard
            .prepare_peer_continuation(&store)
            .map_err(peer_store_step)?;
        guard
            .checkpoint_peer_clock(&continuation, &mut store, now)
            .map_err(peer_store_step)
    }
}
#[cfg(test)]
impl SharedOwner {
    pub(super) fn peer_store_for_test(self: &Arc<Self>) -> Arc<PeerStoreForTest> {
        Arc::new(PeerStoreForTest {
            owner: self.clone(),
        })
    }
}

#[cfg(test)]
impl SharedOwner {
    pub(super) fn peer_continuation_for_test(
        &self,
        operation: &Operation<'_>,
    ) -> Result<Arc<domain::PeerContinuation>, Error> {
        let guard = self.domain.try_read(operation).map_err(Error::Domain)?;
        let store = self.try_store()?;
        guard
            .prepare_peer_continuation(&store)
            .map_err(peer_store_step)
    }
}

// Concrete typed Peer/Channel journal turns. Effect continuation lives in the
// adjacent dedicated effect fragment; journal observations alone never send.
// All provider/policy/signature work is outside these Domain -> Store turns.

#[derive(Clone)]
struct PeerJournalRows {
    authorization: AuthorizationState,
    verified: Option<u64>,
    configuration: Option<LocalAuthConfiguration>,
    binding: Option<CloudRuntimeState>,
    publication: Option<HostAcknowledgedPublication>,
    host_pending: Option<HostPublicationIntent>,
    outbox: Vec<lomi_host_store::Publication>,
    local: Option<ProjectRecord>,
    terminals: Vec<(
        lomi_remote_protocol::PaneId,
        lomi_host_store::TerminalStatus,
    )>,
    // Full signed proposals/grants/contexts, tokens, epochs and replay tuples.
    pairing_pending: Vec<PairingDecisionIntent>,
    pairing_acknowledged: Vec<AcknowledgedWorkspaceGrant>,
    channel_pending: Vec<ChannelAdmissionIntent>,
    channel_acknowledged: Vec<AcknowledgedChannelAdmission>,
}
impl PeerJournalRows {
    fn read(
        store: &HostStore,
        eligibility: &super::auth::cloud::PeerEligibility,
        workspace: WorkspaceId,
    ) -> Result<Self, StoreError> {
        Self::read_binding(store, &eligibility.binding, workspace)
    }
    fn read_binding(
        store: &HostStore,
        binding: &CloudRuntimeState,
        workspace: WorkspaceId,
    ) -> Result<Self, StoreError> {
        let scope = &binding.scope;
        let state = store.authorization_state()?;
        if state.generation != scope.authorization_generation
            || state.locked
            || state.pending_cloud_revoke
            || store.verified_authorization_generation()? != Some(scope.authorization_generation)
            || store.cloud_runtime_scope(
                scope.authorization_generation,
                scope.remote_api_origin.clone(),
            )? != *scope
        {
            return Err(StoreError::Fenced);
        }
        let terminals = store
            .terminal_descriptors(workspace)?
            .into_iter()
            .map(|d| (d.pane_id, d.status))
            .collect();
        Ok(Self {
            authorization: store.authorization_state()?,
            verified: store.verified_authorization_generation()?,
            configuration: store.auth_configuration()?,
            binding: store.cloud_runtime_state(&binding.scope)?,
            publication: store.acknowledged_host_publication(binding)?,
            host_pending: store.pending_host_publication()?,
            outbox: store.pending_publications()?,
            local: match store.workspace(workspace) {
                Ok(local) => Some(local),
                Err(StoreError::NotFound) => None,
                Err(error) => return Err(error),
            },
            terminals,
            pairing_pending: store.pending_pairing_decisions()?,
            pairing_acknowledged: store.acknowledged_workspace_grants()?,
            channel_pending: store.pending_channel_admissions()?,
            channel_acknowledged: store.acknowledged_channel_admissions()?,
        })
    }
    fn current(&self, other: &Self) -> bool {
        self.authorization == other.authorization
            && self.verified == other.verified
            && self.configuration == other.configuration
            && self.binding == other.binding
            && self.publication == other.publication
            && self.host_pending == other.host_pending
            && self.outbox == other.outbox
            && match (&self.local, &other.local) {
                (Some(left), Some(right)) => {
                    left.local_root == right.local_root
                        && left.state == right.state
                        && left.consent == right.consent
                        && left.fence == right.fence
                }
                (None, None) => true,
                _ => false,
            }
            && self.terminals == other.terminals
            && self.pairing_pending == other.pairing_pending
            && self.pairing_acknowledged == other.pairing_acknowledged
            && self.channel_pending == other.channel_pending
            && self.channel_acknowledged == other.channel_acknowledged
    }
}
/// No Clone or authority constructor. Every mutation consumes one exact capture
/// and carries its original owner/Operation into the retained pending writer.
pub(super) struct PeerJournalCapture<'d, 'o> {
    owner: &'d SharedOwner,
    operation: &'o Operation<'o>,
    eligibility: &'d super::auth::cloud::PeerEligibility,
    provider: &'d super::auth::peer::ProviderCapture,
    observation: Option<&'d super::auth::peer::Observation>,
    workspace: WorkspaceId,
    rows: PeerJournalRows,
    continuation: Arc<domain::PeerContinuation>,
    base: u64,
    anchor: std::time::Instant,
}
impl SharedOwner {
    #[expect(
        clippy::too_many_arguments,
        reason = "keep the original operation, eligibility, provider, IO lease, latches and clock anchors explicit"
    )]
    pub(super) fn capture_peer_journal<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        eligibility: &'d super::auth::cloud::PeerEligibility,
        provider: &'d super::auth::peer::ProviderCapture,
        observation: Option<&'d super::auth::peer::Observation>,
        workspace: WorkspaceId,
        base: u64,
        anchor: std::time::Instant,
    ) -> Result<PeerJournalCapture<'d, 'o>, Error> {
        let guard = self.domain.try_read(operation).map_err(Error::Domain)?;
        let store = self.try_store()?;
        let continuation = match observation {
            Some(observation) => observation.continuation.clone(),
            None => guard
                .prepare_peer_continuation(&store)
                .map_err(peer_store_step)?,
        };
        guard
            .check_peer_effect(&continuation, &store)
            .map_err(peer_store_step)?;
        let mut rows = None;
        let snapshot = guard
            .capture_remote(|| {
                rows = Some(PeerJournalRows::read(&store, eligibility, workspace)?);
                StoreView::read(&store)
            })
            .map_err(|e| match e {
                StepError::Domain(e) => Error::Domain(e),
                StepError::Source(e) => Error::UncertainStore(e),
            })?;
        guard.validate(snapshot).map_err(Error::Domain)?;
        let capture = PeerJournalCapture {
            owner: self,
            operation,
            eligibility,
            provider,
            observation,
            workspace,
            rows: rows.expect("capture ran"),
            continuation,
            base,
            anchor,
        };
        capture.check_current()?;
        if capture.rows.binding.as_ref() != Some(&eligibility.binding)
            || capture.rows.publication.as_ref() != Some(&eligibility.publication)
            || capture.rows.host_pending.is_some()
            || !capture.rows.outbox.is_empty()
        {
            return Err(Error::Domain(domain::Error::Stale));
        }
        Ok(capture)
    }
}
impl PeerJournalCapture<'_, '_> {
    fn matches_scope(&self, scope: &lomi_host_store::CloudPairingScope) -> bool {
        scope.runtime_scope == self.eligibility.binding.scope
            && scope.runtime == self.eligibility.binding.server_runtime
            && scope.workspace_id == self.workspace
            && self.rows.local.as_ref().is_some_and(|local| {
                scope.workspace_epoch == local.state.context.workspace_epoch
                    && scope.workspace_fence == local.fence
            })
    }
    fn check_current(&self) -> Result<(), Error> {
        self.operation.check().map_err(Error::Domain)?;
        let now = self.base.saturating_add(self.anchor.elapsed().as_secs());
        if !self.provider.valid_for_owner(now, self.eligibility) {
            return Err(Error::Domain(domain::Error::Stale));
        }
        if self
            .observation
            .is_some_and(|o| !o.current(self.eligibility))
        {
            return Err(Error::Domain(domain::Error::Stale));
        }
        Ok(())
    }
}
enum PeerJournalAction {
    PairingPrepare(lomi_host_store::PairingDecisionPreparation),
    PairingSend(PairingDecisionIntent),
    PairingRetire(PairingDecisionIntent),
    PairingAckRetire(AcknowledgedWorkspaceGrant),
    ChannelPrepare(lomi_host_store::ChannelAdmissionPreparation),
    ChannelSend(ChannelAdmissionIntent),
    ChannelRetire(ChannelAdmissionIntent),
    ChannelAckRetire(AcknowledgedChannelAdmission),
    PairingAck(
        PairingDecisionIntent,
        lomi_remote_protocol::http::PairingResult,
    ),
    ChannelAck(
        ChannelAdmissionIntent,
        lomi_remote_protocol::http::ChannelResult,
    ),
}
enum PeerJournalResult {
    Pairing(PairingDecisionIntent),
    Channel(ChannelAdmissionIntent),
    Unit,
}
impl PeerJournalAction {
    fn apply(&self, store: &mut HostStore, now: u64) -> Result<PeerJournalResult, StoreError> {
        match self {
            Self::PairingPrepare(request) => store
                .prepare_pairing_decision(request.clone(), now)
                .map(PeerJournalResult::Pairing),
            Self::ChannelPrepare(request) => store
                .prepare_channel_admission(request.clone(), now)
                .map(PeerJournalResult::Channel),
            Self::PairingSend(intent) => store
                .pairing_decision_for_send(intent, now)
                .map(|_| PeerJournalResult::Unit),
            Self::ChannelSend(intent) => store
                .channel_admission_for_send(intent, now)
                .map(|_| PeerJournalResult::Unit),
            Self::PairingRetire(intent) => store
                .retire_pairing_decision(intent)
                .map(|_| PeerJournalResult::Unit),
            Self::ChannelRetire(intent) => store
                .retire_channel_admission(intent)
                .map(|_| PeerJournalResult::Unit),
            Self::PairingAckRetire(ack) => store
                .retire_acknowledged_workspace_grant(ack)
                .map(|_| PeerJournalResult::Unit),
            Self::ChannelAckRetire(ack) => store
                .retire_acknowledged_channel_admission(ack)
                .map(|_| PeerJournalResult::Unit),
            Self::PairingAck(intent, response) => store
                .acknowledge_pairing_decision(intent, response, now)
                .map(|_| PeerJournalResult::Unit),
            Self::ChannelAck(intent, response) => store
                .acknowledge_channel_admission(intent, response, now)
                .map(|_| PeerJournalResult::Unit),
        }
    }
}
struct PeerJournalTurn<'d, 'o> {
    capture: PeerJournalCapture<'d, 'o>,
    pending: Option<PendingWriter<'d, 'o>>,
    action: PeerJournalAction,
}
impl PeerJournalTurn<'_, '_> {
    fn try_commit(&mut self) -> Result<PeerJournalResult, Error> {
        let result = self.try_phase();
        if matches!(result, Err(Error::UncertainStore(_))) {
            self.capture.owner.domain.cloud_uncertain();
        }
        // Busy is only retryable before a classified mutation outcome; the same
        // action, capture, PendingWriter and absolute Operation remain retained.
        if matches!(
            result,
            Err(Error::Domain(domain::Error::Busy)) | Err(Error::Store(StoreError::Busy))
        ) {
            return result;
        }
        if let Some(pending) = self.pending.take() {
            match result {
                Ok(value) => {
                    pending.finish().map_err(Error::Domain)?;
                    return Ok(value);
                }
                Err(error) => {
                    let _ = pending.finish();
                    return Err(error);
                }
            }
        }
        result
    }
    fn try_phase(&mut self) -> Result<PeerJournalResult, Error> {
        self.capture.check_current()?;
        let pending = self
            .pending
            .as_mut()
            .ok_or(Error::Domain(domain::Error::Stale))?;
        let mut guard = pending.try_enter().map_err(Error::Domain)?;
        let mut store = self.capture.owner.try_store()?;
        guard
            .check_peer_journal(&self.capture.continuation)
            .map_err(Error::Domain)?;
        let current =
            PeerJournalRows::read(&store, self.capture.eligibility, self.capture.workspace)
                .map_err(Error::UncertainStore)?;
        if !self.capture.rows.current(&current) {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let capture = &self.capture;
        let action = &mut self.action;
        let result = guard
            .commit_classified(|| {
                // Clock persistence belongs to this classified transaction too.
                let result = (|| {
                    let now = store.observe_authorization_clock(
                        capture
                            .base
                            .saturating_add(capture.anchor.elapsed().as_secs()),
                    )?;
                    if !capture.provider.valid_for_owner(now, capture.eligibility) {
                        return Err(StoreError::Fenced);
                    }
                    capture.check_current().map_err(|_| StoreError::Fenced)?;
                    action.apply(&mut store, now)
                })();
                classify_cloud_outcome(result, StoreView::read(&store), peer_journal_expected)
            })
            .map_err(|e| match e {
                StepError::Domain(e) => Error::Domain(e),
                StepError::Source(e) => e,
            });
        if !matches!(
            result,
            Err(Error::UncertainStore(_)) | Err(Error::Domain(_))
        ) {
            guard
                .settle_peer_journal(&self.capture.continuation)
                .map_err(Error::Domain)?;
        }
        result
    }
}
fn peer_journal_expected(error: StoreError) -> bool {
    matches!(
        error,
        StoreError::Fenced
            | StoreError::RevisionConflict
            | StoreError::IdempotencyConflict
            | StoreError::ResourceExhausted
            | StoreError::NotFound
    )
}
macro_rules! peer_journal_turn {
    ($name:ident, $result:ty, $variant:ident) => {
        #[must_use]
        pub(super) struct $name<'d, 'o>(PeerJournalTurn<'d, 'o>);
        impl $name<'_, '_> {
            pub(super) fn try_commit(&mut self) -> Result<$result, Error> {
                match self.0.try_commit()? {
                    PeerJournalResult::$variant(value) => Ok(value),
                    _ => unreachable!("sealed journal action/result"),
                }
            }
        }
    };
    ($name:ident) => {
        #[must_use]
        pub(super) struct $name<'d, 'o>(PeerJournalTurn<'d, 'o>);
        impl $name<'_, '_> {
            pub(super) fn try_commit(&mut self) -> Result<(), Error> {
                match self.0.try_commit()? {
                    PeerJournalResult::Unit => Ok(()),
                    _ => unreachable!("sealed journal action/result"),
                }
            }
        }
    };
}
peer_journal_turn!(PairingPrepareWrite, PairingDecisionIntent, Pairing);
peer_journal_turn!(ChannelPrepareWrite, ChannelAdmissionIntent, Channel);
peer_journal_turn!(PairingSendCheckWrite);
peer_journal_turn!(PairingRetireWrite);
peer_journal_turn!(PairingAckRetireWrite);
peer_journal_turn!(PairingAckWrite);
peer_journal_turn!(ChannelSendCheckWrite);
peer_journal_turn!(ChannelRetireWrite);
peer_journal_turn!(ChannelAckRetireWrite);
peer_journal_turn!(ChannelAckWrite);
impl<'d, 'o> PeerJournalCapture<'d, 'o> {
    pub(super) fn begin_prepare_pairing_decision(
        self,
        request: lomi_host_store::PairingDecisionPreparation,
    ) -> Result<PairingPrepareWrite<'d, 'o>, Error> {
        if !self.matches_scope(&request.scope) {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let pending = self
            .owner
            .domain
            .announce(self.operation, WriterClass::Remote, Intent::Mutation)
            .map_err(Error::Domain)?;
        Ok(PairingPrepareWrite(PeerJournalTurn {
            capture: self,
            pending: Some(pending),
            action: PeerJournalAction::PairingPrepare(request),
        }))
    }
    pub(super) fn begin_check_pairing_decision_send(
        self,
        intent: PairingDecisionIntent,
    ) -> Result<PairingSendCheckWrite<'d, 'o>, Error> {
        if !self.matches_scope(&intent.preparation.scope) {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let pending = self
            .owner
            .domain
            .announce(self.operation, WriterClass::Remote, Intent::Mutation)
            .map_err(Error::Domain)?;
        Ok(PairingSendCheckWrite(PeerJournalTurn {
            capture: self,
            pending: Some(pending),
            action: PeerJournalAction::PairingSend(intent),
        }))
    }
    pub(super) fn begin_retire_pairing_decision(
        self,
        intent: PairingDecisionIntent,
    ) -> Result<PairingRetireWrite<'d, 'o>, Error> {
        let pending = self
            .owner
            .domain
            .announce(self.operation, WriterClass::Remote, Intent::Mutation)
            .map_err(Error::Domain)?;
        Ok(PairingRetireWrite(PeerJournalTurn {
            capture: self,
            pending: Some(pending),
            action: PeerJournalAction::PairingRetire(intent),
        }))
    }
    pub(super) fn begin_retire_acknowledged_workspace_grant(
        self,
        ack: AcknowledgedWorkspaceGrant,
    ) -> Result<PairingAckRetireWrite<'d, 'o>, Error> {
        let pending = self
            .owner
            .domain
            .announce(self.operation, WriterClass::Remote, Intent::Mutation)
            .map_err(Error::Domain)?;
        Ok(PairingAckRetireWrite(PeerJournalTurn {
            capture: self,
            pending: Some(pending),
            action: PeerJournalAction::PairingAckRetire(ack),
        }))
    }
    pub(super) fn begin_prepare_channel_admission(
        self,
        request: lomi_host_store::ChannelAdmissionPreparation,
    ) -> Result<ChannelPrepareWrite<'d, 'o>, Error> {
        if !self.matches_scope(&request.scope) {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let pending = self
            .owner
            .domain
            .announce(self.operation, WriterClass::Remote, Intent::Mutation)
            .map_err(Error::Domain)?;
        Ok(ChannelPrepareWrite(PeerJournalTurn {
            capture: self,
            pending: Some(pending),
            action: PeerJournalAction::ChannelPrepare(request),
        }))
    }
    pub(super) fn begin_check_channel_admission_send(
        self,
        intent: ChannelAdmissionIntent,
    ) -> Result<ChannelSendCheckWrite<'d, 'o>, Error> {
        if !self.matches_scope(&intent.preparation.scope) {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let pending = self
            .owner
            .domain
            .announce(self.operation, WriterClass::Remote, Intent::Mutation)
            .map_err(Error::Domain)?;
        Ok(ChannelSendCheckWrite(PeerJournalTurn {
            capture: self,
            pending: Some(pending),
            action: PeerJournalAction::ChannelSend(intent),
        }))
    }
    pub(super) fn begin_retire_channel_admission(
        self,
        intent: ChannelAdmissionIntent,
    ) -> Result<ChannelRetireWrite<'d, 'o>, Error> {
        let pending = self
            .owner
            .domain
            .announce(self.operation, WriterClass::Remote, Intent::Mutation)
            .map_err(Error::Domain)?;
        Ok(ChannelRetireWrite(PeerJournalTurn {
            capture: self,
            pending: Some(pending),
            action: PeerJournalAction::ChannelRetire(intent),
        }))
    }
    pub(super) fn begin_retire_acknowledged_channel_admission(
        self,
        ack: AcknowledgedChannelAdmission,
    ) -> Result<ChannelAckRetireWrite<'d, 'o>, Error> {
        let pending = self
            .owner
            .domain
            .announce(self.operation, WriterClass::Remote, Intent::Mutation)
            .map_err(Error::Domain)?;
        Ok(ChannelAckRetireWrite(PeerJournalTurn {
            capture: self,
            pending: Some(pending),
            action: PeerJournalAction::ChannelAckRetire(ack),
        }))
    }
    pub(super) fn begin_acknowledge_pairing(
        self,
        intent: PairingDecisionIntent,
        response: lomi_remote_protocol::http::PairingResult,
    ) -> Result<PairingAckWrite<'d, 'o>, Error> {
        if !self.matches_scope(&intent.preparation.scope) {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let pending = self
            .owner
            .domain
            .announce(self.operation, WriterClass::Remote, Intent::Mutation)
            .map_err(Error::Domain)?;
        Ok(PairingAckWrite(PeerJournalTurn {
            capture: self,
            pending: Some(pending),
            action: PeerJournalAction::PairingAck(intent, response),
        }))
    }
    pub(super) fn begin_acknowledge_channel(
        self,
        intent: ChannelAdmissionIntent,
        response: lomi_remote_protocol::http::ChannelResult,
    ) -> Result<ChannelAckWrite<'d, 'o>, Error> {
        if !self.matches_scope(&intent.preparation.scope) {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let pending = self
            .owner
            .domain
            .announce(self.operation, WriterClass::Remote, Intent::Mutation)
            .map_err(Error::Domain)?;
        Ok(ChannelAckWrite(PeerJournalTurn {
            capture: self,
            pending: Some(pending),
            action: PeerJournalAction::ChannelAck(intent, response),
        }))
    }
}

fn peer_store_step(error: domain::StepError<StoreError>) -> Error {
    match error {
        domain::StepError::Domain(error) => Error::Domain(error),
        domain::StepError::Source(error) => Error::UncertainStore(error),
    }
}
#[derive(Clone, PartialEq)]
struct PeerRemoteRows {
    configuration: Option<LocalAuthConfiguration>,
    binding: Option<CloudRuntimeState>,
    publication: Option<HostAcknowledgedPublication>,
    host_pending: Option<HostPublicationIntent>,
    outbox: Vec<lomi_host_store::Publication>,
    pairings: Vec<PairingDecisionIntent>,
    grants: Vec<AcknowledgedWorkspaceGrant>,
    channels: Vec<ChannelAdmissionIntent>,
    admissions: Vec<AcknowledgedChannelAdmission>,
}
impl PeerRemoteRows {
    fn read(store: &HostStore) -> Result<Self, StoreError> {
        let configuration = store.auth_configuration()?;
        let state = store.authorization_state()?;
        let origin = configuration
            .as_ref()
            .and_then(|config| config.remote_api_origin.as_ref())
            .ok_or(StoreError::Fenced)?
            .as_str()
            .to_owned();
        let scope = store.cloud_runtime_scope(state.generation, origin)?;
        let binding = store.cloud_runtime_state(&scope)?;
        let publication = match &binding {
            Some(binding) => store.acknowledged_host_publication(binding)?,
            None => None,
        };
        Ok(Self {
            configuration,
            binding,
            publication,
            host_pending: store.pending_host_publication()?,
            outbox: store.pending_publications()?,
            pairings: store.pending_pairing_decisions()?,
            grants: store.acknowledged_workspace_grants()?,
            channels: store.pending_channel_admissions()?,
            admissions: store.acknowledged_channel_admissions()?,
        })
    }
    fn eligible(&self, eligibility: &super::auth::cloud::PeerEligibility) -> Result<(), Error> {
        let now = std::time::Instant::now();
        if self.binding.as_ref() != Some(&eligibility.binding)
            || self.publication.as_ref() != Some(&eligibility.publication)
            || self.host_pending.is_some()
            || !self.outbox.is_empty()
            || eligibility.heartbeat.scope != eligibility.binding.scope
            || eligibility.heartbeat.runtime != eligibility.binding.server_runtime
            || now
                >= eligibility.heartbeat.request_started
                    + std::time::Duration::from_millis(eligibility.heartbeat.freshness_ms)
            || now
                >= eligibility.heartbeat.request_started
                    + std::time::Duration::from_millis(eligibility.heartbeat.lease_ms)
        {
            return Err(Error::Domain(domain::Error::Stale));
        }
        Ok(())
    }
}
impl SharedOwner {
    fn read_peer<T>(
        &self,
        operation: &Operation<'_>,
        eligibility: &super::auth::cloud::PeerEligibility,
        read: impl FnOnce(&HostStore, PeerRemoteRows) -> Result<T, StoreError>,
    ) -> Result<T, Error> {
        let guard = self.domain.try_read(operation).map_err(Error::Domain)?;
        let store = self.try_store()?;
        let cap = guard
            .prepare_peer_continuation(&store)
            .map_err(peer_store_step)?;
        let rows = PeerRemoteRows::read(&store).map_err(|error| {
            self.domain.cloud_uncertain();
            Error::UncertainStore(error)
        })?;
        rows.eligible(eligibility)?;
        let result = read(&store, rows).map_err(|error| match error {
            StoreError::NotFound | StoreError::Fenced => Error::Store(error),
            _ => {
                self.domain.cloud_uncertain();
                Error::UncertainStore(error)
            }
        })?;
        guard
            .check_peer_effect(&cap, &store)
            .map_err(peer_store_step)?;
        Ok(result)
    }
    pub(super) fn peer_original_boundary(
        &self,
        operation: &Operation<'_>,
        continuation: &domain::PeerContinuation,
    ) -> Result<(), Error> {
        continuation
            .check_effect_boundary(&self.domain, operation)
            .map_err(Error::Domain)
    }
    pub(super) fn peer_time(
        &self,
        operation: &Operation<'_>,
        eligibility: &super::auth::cloud::PeerEligibility,
        base: u64,
        anchor: std::time::Instant,
    ) -> Result<u64, Error> {
        self.read_peer(operation, eligibility, |store, _| {
            let now = base.saturating_add(anchor.elapsed().as_secs());
            if now < store.authorization_state()?.clock_floor {
                return Err(StoreError::Fenced);
            }
            Ok(now)
        })
    }
    pub(super) fn validate_peer_eligibility(
        &self,
        operation: &Operation<'_>,
        eligibility: &super::auth::cloud::PeerEligibility,
    ) -> Result<(), Error> {
        self.read_peer(operation, eligibility, |_, _| Ok(()))
    }
    pub(super) fn peer_pending_pairings(
        &self,
        operation: &Operation<'_>,
        eligibility: &super::auth::cloud::PeerEligibility,
    ) -> Result<Vec<PairingDecisionIntent>, Error> {
        self.read_peer(operation, eligibility, |_, rows| Ok(rows.pairings))
    }
    pub(super) fn peer_workspace_grants(
        &self,
        operation: &Operation<'_>,
        eligibility: &super::auth::cloud::PeerEligibility,
    ) -> Result<Vec<AcknowledgedWorkspaceGrant>, Error> {
        self.read_peer(operation, eligibility, |_, rows| Ok(rows.grants))
    }
    pub(super) fn peer_pending_channels(
        &self,
        operation: &Operation<'_>,
        eligibility: &super::auth::cloud::PeerEligibility,
    ) -> Result<Vec<ChannelAdmissionIntent>, Error> {
        self.read_peer(operation, eligibility, |_, rows| Ok(rows.channels))
    }
    pub(super) fn peer_channel_acks(
        &self,
        operation: &Operation<'_>,
        eligibility: &super::auth::cloud::PeerEligibility,
    ) -> Result<Vec<AcknowledgedChannelAdmission>, Error> {
        self.read_peer(operation, eligibility, |_, rows| Ok(rows.admissions))
    }
    pub(super) fn peer_workspace(
        &self,
        operation: &Operation<'_>,
        eligibility: &super::auth::cloud::PeerEligibility,
        id: WorkspaceId,
    ) -> Result<LocalPeerWorkspaceEvidence, Error> {
        self.read_peer(operation, eligibility, |store, _| {
            Ok(LocalPeerWorkspaceEvidence {
                workspace: store.workspace(id)?,
                descriptors: store.terminal_descriptors(id)?,
            })
        })
    }
}
// Full exact request payload retained; no transport callback or raw Store escape.
pub(super) enum PeerEffect {
    PairingPending(lomi_remote_protocol::HostId),
    PairingGet(lomi_remote_protocol::PairingId),
    /// Exact acknowledged record selects only a fresh current pairing GET.
    ApprovedPairingGet(Box<AcknowledgedWorkspaceGrant>),
    PairingSend(PairingDecisionIntent),
    ChannelPending(lomi_remote_protocol::HostId),
    ChannelGet(lomi_remote_protocol::ChannelId),
    ChannelSend(ChannelAdmissionIntent),
    ChannelTicket(Box<super::auth::channel::ChannelTicketBinding>),
}
impl PeerEffect {
    fn check_time(&self, rows: &PeerRemoteRows, now: u64) -> Result<(), Error> {
        let current = match self {
            Self::PairingSend(intent) => now < intent.preparation.original_expires_at,
            Self::ApprovedPairingGet(source) => now < source.intent.preparation.original_expires_at,
            Self::ChannelTicket(binding) => {
                std::time::Instant::now() < binding.deadline()
                    && now < binding.acknowledgement().intent.preparation.expires_at
                    && now < binding.source().intent.preparation.original_expires_at
            }
            Self::ChannelSend(intent) => {
                now < intent.preparation.expires_at
                    && rows.grants.iter().any(|grant| {
                        grant.intent.token == intent.preparation.source_grant_token
                            && now < grant.intent.preparation.original_expires_at
                    })
            }
            _ => true,
        };
        if !current {
            return Err(Error::Domain(domain::Error::Stale));
        }
        Ok(())
    }
    fn workspace(&self) -> Option<WorkspaceId> {
        match self {
            Self::PairingSend(intent) => Some(intent.preparation.scope.workspace_id),
            Self::ApprovedPairingGet(source) => Some(source.intent.preparation.scope.workspace_id),
            Self::ChannelSend(intent) => Some(intent.preparation.scope.workspace_id),
            Self::ChannelTicket(binding) => Some(binding.scope().workspace_id),
            _ => None,
        }
    }
    fn validate(
        &self,
        rows: &PeerRemoteRows,
        eligibility: &super::auth::cloud::PeerEligibility,
    ) -> Result<(), Error> {
        let valid = match self {
            Self::PairingPending(host) | Self::ChannelPending(host) => *host == eligibility.identity.host_id,
            Self::PairingGet(id) => rows.pairings.iter().any(|intent| intent.preparation.pairing_id == *id),
            Self::ApprovedPairingGet(source) => rows.grants.contains(source.as_ref())
                && source.intent.preparation.scope.runtime_scope == eligibility.binding.scope
                && source.intent.preparation.scope.runtime == eligibility.binding.server_runtime
                && matches!(&source.response, lomi_remote_protocol::http::PairingResult::Approved { pairing_id, grant, identities, .. }
                    if *pairing_id == source.intent.preparation.pairing_id
                        && identities == &source.intent.preparation.proposal.identities
                        && matches!(&source.intent.preparation.params, lomi_remote_protocol::http::PairingDecisionParams::Approve { grant: original, .. } if grant == original)),
            Self::ChannelGet(id) => rows.channels.iter().any(|intent| intent.preparation.channel_id == *id),
            Self::ChannelTicket(binding) => rows.admissions.contains(binding.acknowledgement())
                && rows.grants.contains(binding.source())
                && &binding.acknowledgement().intent.preparation.scope == binding.scope()
                && &binding.source().intent.preparation.scope == binding.scope()
                && binding.acknowledgement().intent.preparation.source_grant_token == binding.source().intent.token
                && binding.acknowledgement().intent.preparation.source_grant_id == binding.source().intent.preparation.grant_id
                && binding.scope().runtime_scope == eligibility.binding.scope
                && binding.scope().runtime == eligibility.binding.server_runtime,

            Self::PairingSend(intent) => rows.pairings.contains(intent)
                && intent.preparation.scope.runtime_scope == eligibility.binding.scope
                && intent.preparation.scope.runtime == eligibility.binding.server_runtime,
            Self::ChannelSend(intent) => rows.channels.contains(intent)
                && intent.preparation.scope.runtime_scope == eligibility.binding.scope
                && intent.preparation.scope.runtime == eligibility.binding.server_runtime
                && rows.grants.iter().any(|grant| grant.intent.token == intent.preparation.source_grant_token
                    && grant.intent.preparation.grant_id == intent.preparation.source_grant_id
                    && matches!(&grant.response, lomi_remote_protocol::http::PairingResult::Approved { grant, identities, .. }
                        if grant == &intent.preparation.inputs.grant && identities == &intent.preparation.inputs.identities)),
        };
        if !valid {
            return Err(Error::Domain(domain::Error::Stale));
        }
        Ok(())
    }
}
pub(super) struct PeerEffectContinuation<'d, 'o, 'e> {
    owner: &'d SharedOwner,
    operation: &'o Operation<'o>,
    continuation: Arc<domain::PeerContinuation>,
    eligibility: &'e super::auth::cloud::PeerEligibility,
    observation: Option<&'e super::auth::peer::Observation>,
    action: PeerEffect,
    rows: PeerRemoteRows,
    local: Option<PeerJournalRows>,
    base: u64,
    anchor: std::time::Instant,
}
impl SharedOwner {
    pub(super) fn capture_channel_ticket<'d, 'o, 'e>(
        &'d self,
        operation: &'o Operation<'o>,
        eligibility: &'e super::auth::cloud::PeerEligibility,
        handoff: &'e super::auth::channel::AdmittedChannelHandoff,
        base: u64,
        anchor: std::time::Instant,
    ) -> Result<PeerEffectContinuation<'d, 'o, 'e>, Error> {
        let binding = handoff
            .ticket_binding(operation, eligibility)
            .ok_or(Error::Domain(domain::Error::Stale))?;
        self.capture_peer_effect(
            operation,
            eligibility,
            PeerEffect::ChannelTicket(Box::new(binding)),
            Some(handoff.observation()),
            base,
            anchor,
        )
    }
    pub(super) fn capture_peer_effect<'d, 'o, 'e>(
        &'d self,
        operation: &'o Operation<'o>,
        eligibility: &'e super::auth::cloud::PeerEligibility,
        action: PeerEffect,
        observation: Option<&'e super::auth::peer::Observation>,
        base: u64,
        anchor: std::time::Instant,
    ) -> Result<PeerEffectContinuation<'d, 'o, 'e>, Error> {
        let guard = self.domain.try_read(operation).map_err(Error::Domain)?;
        let store = self.try_store()?;
        let continuation = match observation {
            Some(observation) => observation.continuation.clone(),
            None => guard
                .prepare_peer_continuation(&store)
                .map_err(peer_store_step)?,
        };
        guard
            .check_peer_effect(&continuation, &store)
            .map_err(peer_store_step)?;
        let rows = PeerRemoteRows::read(&store).map_err(|error| {
            self.domain.cloud_uncertain();
            Error::UncertainStore(error)
        })?;
        rows.eligible(eligibility)?;
        action.validate(&rows, eligibility)?;
        let local = action
            .workspace()
            .map(|workspace| PeerJournalRows::read(&store, eligibility, workspace))
            .transpose()
            .map_err(|error| {
                self.domain.cloud_uncertain();
                Error::UncertainStore(error)
            })?;
        if let PeerEffect::ApprovedPairingGet(source) = &action {
            approved_pairing_read_local(
                source,
                local.as_ref().ok_or(Error::Domain(domain::Error::Stale))?,
            )?;
        }
        if let PeerEffect::ChannelTicket(binding) = &action {
            self.channel_ticket_local(
                binding,
                local.as_ref().ok_or(Error::Domain(domain::Error::Stale))?,
                &store,
            )?;
        }
        Ok(PeerEffectContinuation {
            owner: self,
            operation,
            continuation,
            eligibility,
            observation,
            action,
            rows,
            local,
            base,
            anchor,
        })
    }
}
impl PeerEffectContinuation<'_, '_, '_> {
    pub(super) fn continuation(&self) -> Arc<domain::PeerContinuation> {
        self.continuation.clone()
    }

    pub(super) fn check_boundary(
        &self,
        provider: &super::auth::peer::ProviderCapture,
    ) -> Result<(), Error> {
        self.continuation
            .check_effect_boundary(&self.owner.domain, self.operation)
            .map_err(Error::Domain)?;
        self.rows.eligible(self.eligibility)?;
        self.action.check_time(
            &self.rows,
            self.base.saturating_add(self.anchor.elapsed().as_secs()),
        )?;
        if !provider.valid_for_owner(
            self.base.saturating_add(self.anchor.elapsed().as_secs()),
            self.eligibility,
        ) {
            return Err(Error::Domain(domain::Error::Stale));
        }
        if self
            .observation
            .is_some_and(|observation| !observation.current(self.eligibility))
        {
            return Err(Error::Domain(domain::Error::Stale));
        }
        Ok(())
    }
    pub(super) fn try_validate(
        &mut self,
        provider: &super::auth::peer::ProviderCapture,
    ) -> Result<(), Error> {
        self.check_boundary(provider)?;
        let mut guard = self
            .owner
            .domain
            .try_read(self.operation)
            .map_err(Error::Domain)?;
        let mut store = self.owner.try_store()?;
        let floor = guard
            .check_peer_effect(&self.continuation, &store)
            .map_err(peer_store_step)?;
        let rows = PeerRemoteRows::read(&store).map_err(|error| {
            self.owner.domain.cloud_uncertain();
            Error::UncertainStore(error)
        })?;
        if rows != self.rows {
            return Err(Error::Domain(domain::Error::Stale));
        }
        self.action.validate(&rows, self.eligibility)?;
        if let Some(local) = &self.local {
            let current = PeerJournalRows::read(
                &store,
                self.eligibility,
                self.action.workspace().expect("captured workspace"),
            )
            .map_err(|error| {
                self.owner.domain.cloud_uncertain();
                Error::UncertainStore(error)
            })?;
            if !local.current(&current) {
                return Err(Error::Domain(domain::Error::Stale));
            }
            if let PeerEffect::ChannelTicket(binding) = &self.action {
                self.owner.channel_ticket_local(binding, &current, &store)?;
            }
            if let PeerEffect::ApprovedPairingGet(source) = &self.action {
                approved_pairing_read_local(source, &current)?;
            }
        }
        if !provider.valid_for_owner(
            floor.max(self.base.saturating_add(self.anchor.elapsed().as_secs())),
            self.eligibility,
        ) {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let checkpoint_floor = guard
            .checkpoint_peer_clock(
                &self.continuation,
                &mut store,
                self.base.saturating_add(self.anchor.elapsed().as_secs()),
            )
            .map_err(peer_store_step)?;
        // Account only for this successful checkpoint while the same guards
        // still exclude writers. Never refresh other authorization/local rows
        // or adopt any unrelated Store change as a new effect baseline.
        if let Some(local) = &mut self.local {
            local.authorization.clock_floor = checkpoint_floor;
        }
        self.check_boundary(provider)
    }
}

// Retained terminal owner capture. Acquire the workspace actor
// BEFORE this Domain turn. Drop the turn before network/output backpressure.
// No public snapshot, caller booleans, ACK grant or generic callback mints it.
pub(super) struct RemoteTerminalTurn<'d, 'o, 'e, 'w, 'p, 's> {
    guard: domain::OwnerGuard<'d, 'o>,
    snapshot: domain::Snapshot<'d, 'o>,
    worker: &'e super::auth::RemoteWorkerEvidence<'w, 'p, 's, 'o>,
    peer: &'e super::auth::peer::VerifiedCurrentPeer,
    rows: PeerJournalRows,
    local: lomi_host_auth::peer_policy::LocalWorkspace,
    running: Vec<TerminalContext>,
    target: TerminalContext,
    raw_target: TerminalContext,
    clock_floor: u64,
}
/// Established terminal read/continuation checked against one current pairing
/// GET while a single Started Git writer owns the global mutation barrier.
/// This is a read-only owner frame; it cannot admit another writer or channel.
pub(super) struct StartedGitTerminalTurn<'d, 'o, 'a, 'p, 'l> {
    guard: Option<domain::StartedGitOwnerGuard<'d, 'o>>,
    operation: &'o Operation<'o>,
    active: &'a StartedGitContinuation,
    peer: &'p super::auth::peer::StartedGitPeerObservation,
    latches: domain::StartedGitTerminalLatches<'l>,
    control: domain::RemoteGitWriterControl,
    authority_revision: u64,
    request_deadline: Option<std::time::Instant>,
    io_snapshot_valid: bool,
    view: StoreView,
    rows: PeerJournalRows,
    heartbeat: super::auth::cloud::HeartbeatObservation,
    local: lomi_host_auth::peer_policy::LocalWorkspace,
    running: Vec<TerminalContext>,
    target: TerminalContext,
    clock_floor: u64,
}
/// Terminal Core watch returned after the owner turn releases its
/// Domain guard. Keeping the captured turn alive preserves exact peer, writer,
/// operation and descriptor identity without holding model locks over PTY IO.
pub(super) struct StartedGitTerminalIoWatch<'t, 'd, 'o, 'a, 'p, 'l> {
    turn: &'t StartedGitTerminalTurn<'d, 'o, 'a, 'p, 'l>,
}
/// Channel-level Started Git proof used only to authenticate bounded framing
/// before an RPC target can be decoded. It grants no method or terminal rights.
pub(super) struct StartedGitTerminalChannelTurn<'d, 'o, 'a, 'p, 'l> {
    owner: &'d SharedOwner,
    guard: Option<domain::StartedGitOwnerGuard<'d, 'o>>,
    operation: &'o Operation<'o>,
    active: &'a StartedGitContinuation,
    peer: &'p super::auth::peer::StartedGitPeerObservation,
    latches: domain::StartedGitTerminalLatches<'l>,
    control: domain::RemoteGitWriterControl,
    authority_revision: u64,
    io_snapshot_valid: bool,
    view: StoreView,
    rows: PeerJournalRows,
    heartbeat: super::auth::cloud::HeartbeatObservation,
    local: lomi_host_auth::peer_policy::LocalWorkspace,
    running: Vec<TerminalContext>,
    clock_floor: u64,
    request_deadline: Option<std::time::Instant>,
}
pub(super) struct StartedGitTerminalChannelIoWatch<'t, 'd, 'o, 'a, 'p, 'l> {
    turn: &'t StartedGitTerminalChannelTurn<'d, 'o, 'a, 'p, 'l>,
}
/// Local IPC counterpart to the cloud-authenticated Started Git turn. It uses
/// the exact active writer core only as a read-only serialization token; local
/// terminal access does not inherit Cloud grants or pairings.
pub(super) struct StartedGitLocalTerminalTurn<'d, 'o> {
    guard: domain::StartedGitOwnerGuard<'d, 'o>,
    operation: &'o Operation<'o>,
    control: domain::RemoteGitWriterControl,
    authority_revision: u64,
    project: ProjectRecord,
    descriptors: Vec<lomi_host_store::TerminalDescriptor>,
    target: TerminalContext,
}
/// Lock-free fence for the narrow local PTY input/resize calls made during a
/// Started Git writer. The captured owner turn is consumed before this watch is
/// returned, so no Store or Domain guard crosses terminal Core/syscall work.
pub(super) struct StartedGitLocalTerminalIoWatch<'o> {
    operation: &'o Operation<'o>,
    control: domain::RemoteGitWriterControl,
    authority_revision: u64,
    project: ProjectRecord,
    descriptors: Vec<lomi_host_store::TerminalDescriptor>,
    target: TerminalContext,
}
impl SharedOwner {
    /// Capture a fresh owner snapshot for established-channel framing while a
    /// Started Git writer owns the mutation barrier. This authorizes no RPC;
    /// a decoded request must immediately pass the target-specific terminal
    /// turn before it can be queued or executed.
    pub(super) fn try_started_git_terminal_channel_turn<'d, 'o, 'a, 'p, 'l>(
        &'d self,
        operation: &'o Operation<'o>,
        active: &'a StartedGitContinuation,
        peer: &'p super::auth::peer::StartedGitPeerObservation,
        latches: domain::StartedGitTerminalLatches<'l>,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
    ) -> Result<StartedGitTerminalChannelTurn<'d, 'o, 'a, 'p, 'l>, Error> {
        if !active.belongs_to(&self.domain)
            || !active.is_current(operation)
            || !peer.current_for(active, operation, peer.target().connection)
            || !connection.matches_started_git_peer(active, operation, peer)
            || !latches.current()
        {
            connection.dispose();
            return Err(Error::Domain(domain::Error::Stale));
        }
        let grant = &peer.target().signed_grant.grant;
        match (
            peer.target().context.purpose,
            peer.target().context.terminal.as_ref(),
        ) {
            (lomi_remote_crypto::ChannelPurposeV3::Workspace, None)
                if peer.target().authority.terminal_membership.is_none() => {}
            (lomi_remote_crypto::ChannelPurposeV3::Terminal, Some(target))
                if peer.target().authority.terminal_membership.as_ref() == Some(target) => {}
            _ => return Err(Error::Domain(domain::Error::Stale)),
        }

        let control = active.owner_control();
        let guard = self
            .domain
            .try_started_git_read(operation, &control)
            .map_err(Error::Domain)?;
        let authority_revision = control.authority_revision();
        let store = self.try_store()?;
        let workspace = WorkspaceId::from_bytes(grant.workspace_id)
            .map_err(|_| Error::Domain(domain::Error::Stale))?;
        let (captured, view) = guard
            .capture(|| {
                let rows = PeerJournalRows::read_binding(&store, active.runtime(), workspace)?;
                let login = store.login_intent()?;
                let identity = store.identity().clone();
                let public_ready = store.public_configuration_ready()?;
                let public = if public_ready {
                    Some(store.public_current()?)
                } else {
                    None
                };
                let public_state = store.public_configuration_state()?;
                let selected = rows.configuration.as_ref();
                let public_matches = selected.is_some_and(|selected| {
                    public.as_ref().is_some_and(|public| {
                        public.configuration().is_ok_and(|configuration| {
                            configuration.authentication.as_ref() == Some(selected)
                        })
                    }) && public_state.as_ref().is_some_and(|state| {
                        state.prepared.is_none()
                            && public
                                .as_ref()
                                .is_some_and(|public| state.current.as_ref() == Some(public))
                    })
                });
                let trusted_matches = selected.is_some_and(|selected| {
                    let Ok(client_id) = selected.client_id.as_str().to_owned().try_into() else {
                        return false;
                    };
                    lomi_host_auth::Config::new(
                        identity.host_id,
                        identity.profile_id,
                        selected.origin.as_str().to_owned(),
                        client_id,
                    )
                    .is_ok()
                        && identity.host_id == active.identity().host_id
                        && selected == active.credential_configuration()
                });
                let configuration_matches = trusted_matches
                    && public_matches
                    && selected.is_some_and(|selected| {
                        selected
                            .remote_api_origin
                            .as_ref()
                            .is_some_and(|origin| origin.as_str() == active.origin().as_str())
                    });
                let view = StoreView::read(&store)?;
                Ok((
                    (rows, identity, login.is_none(), configuration_matches),
                    view,
                ))
            })
            .map_err(|error| match error {
                StepError::Domain(error) => Error::Domain(error),
                StepError::Source(error) => Error::UncertainStore(error),
            })?;
        let (rows, identity, no_login, configuration_matches) = captured;
        if identity != *active.store_identity()
            || identity.host_id != active.identity().host_id
            || rows.authorization.generation != active.runtime().scope.authorization_generation
            || rows.binding.as_ref() != Some(active.runtime())
            || rows.publication.as_ref() != Some(active.acknowledged())
            || rows.host_pending.is_some()
            || !rows.outbox.is_empty()
            || !rows.pairing_acknowledged.contains(peer.source())
            || !no_login
            || !configuration_matches
        {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let heartbeat = active
            .heartbeat()
            .ok_or(Error::Domain(domain::Error::Stale))?;
        if heartbeat.scope != active.runtime().scope
            || heartbeat.runtime != active.runtime().server_runtime
        {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let workspace_context = WorkspaceContext {
            workspace_id: workspace,
            workspace_epoch: lomi_remote_protocol::WorkspaceEpoch::from_bytes(
                grant.workspace_epoch,
            )
            .map_err(|_| Error::Domain(domain::Error::Stale))?,
            runtime_id: active.runtime().server_runtime.runtime_id,
            runtime_generation: active.runtime().server_runtime.runtime_generation,
            host_access_epoch: active.runtime().server_runtime.host_access_epoch,
            grant_revision: DecimalU64(grant.grant_revision),
        };
        let (remote_workspace, local, running) = derive_remote_view_from_grant(
            &rows,
            active.runtime(),
            grant,
            peer.source(),
            workspace,
            &workspace_context,
        )?;
        if remote_workspace != workspace_context {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let now = active
            .trusted_now()
            .ok_or(Error::Domain(domain::Error::Stale))?;
        let clock_floor = rows.authorization.clock_floor;
        if now.wall.as_secs() < clock_floor
            || now.monotonic >= peer.fresh_until()
            || !latches.current()
        {
            return Err(Error::Domain(domain::Error::Stale));
        }
        guard.validate_view(view).map_err(Error::Domain)?;
        drop(store);
        let turn = StartedGitTerminalChannelTurn {
            owner: self,
            guard: Some(guard),
            operation,
            active,
            peer,
            latches,
            control,
            authority_revision,
            io_snapshot_valid: true,
            view,
            rows,
            heartbeat,
            local,
            running,
            clock_floor,
            request_deadline: None,
        };
        if !turn.current() {
            connection.dispose();
            return Err(Error::Domain(domain::Error::Stale));
        }
        Ok(turn)
    }

    /// Caller must already own workspace actor serialization. Domain is retained
    /// across terminal retirement/Core waits; Store is explicitly dropped here.
    pub(super) fn try_remote_terminal_turn<'d, 'o, 'e, 'w, 'p, 's>(
        &'d self,
        worker: &'e super::auth::RemoteWorkerEvidence<'w, 'p, 's, 'o>,
        peer: &'e super::auth::peer::VerifiedCurrentPeer,
        target: &TerminalContext,
    ) -> Result<RemoteTerminalTurn<'d, 'o, 'e, 'w, 'p, 's>, Error> {
        if !std::ptr::eq(self, worker.owner()) || !peer.current(worker) {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let guard = self
            .domain
            .try_read(worker.operation())
            .map_err(Error::Domain)?;
        let store = self.try_store()?;
        let floor = guard
            .check_peer_effect(peer.continuation(), &store)
            .map_err(peer_store_step)?;
        let workspace = target.workspace.workspace_id;
        let mut rows = None;
        let mut login = None;
        let snapshot = guard
            .capture_remote(|| {
                rows = Some(PeerJournalRows::read(
                    &store,
                    worker.eligibility(),
                    workspace,
                )?);
                login = store.login_intent()?;
                StoreView::read(&store)
            })
            .map_err(|error| match error {
                StepError::Domain(error) => Error::Domain(error),
                StepError::Source(error) => Error::UncertainStore(error),
            })?;
        let rows = rows.expect("named capture ran");
        let eligibility = worker.eligibility();
        let selected = rows
            .configuration
            .as_ref()
            .ok_or(Error::Domain(domain::Error::Stale))?;
        let trusted = lomi_host_auth::Config::new(
            store.identity().host_id,
            store.identity().profile_id,
            selected.origin.as_str().to_owned(),
            selected
                .client_id
                .as_str()
                .to_owned()
                .try_into()
                .map_err(|_| Error::Domain(domain::Error::Stale))?,
        )
        .map_err(|_| Error::Domain(domain::Error::Stale))?;
        let public = store.public_current().map_err(Error::UncertainStore)?;
        let public_state = store
            .public_configuration_state()
            .map_err(Error::UncertainStore)?;
        if &trusted != worker.trusted()
            || selected
                .remote_api_origin
                .as_ref()
                .map(|origin| origin.as_str())
                != Some(worker.origin().as_str())
            || !store
                .public_configuration_ready()
                .map_err(Error::UncertainStore)?
            || public
                .configuration()
                .map_err(Error::UncertainStore)?
                .authentication
                .as_ref()
                != Some(selected)
            || !public_state.as_ref().is_some_and(|state| {
                state.prepared.is_none() && state.current.as_ref() == Some(&public)
            })
            || login.is_some()
            || rows.binding.as_ref() != Some(&eligibility.binding)
            || rows.publication.as_ref() != Some(&eligibility.publication)
            || rows.host_pending.is_some()
            || !rows.outbox.is_empty()
            || !rows.pairing_acknowledged.contains(peer.source())
        {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let project = rows
            .local
            .as_ref()
            .ok_or(Error::Domain(domain::Error::Stale))?;
        let source = &peer.source().intent.preparation;
        let grant = peer.grant();
        if !project.consent
            || project.fence != source.scope.workspace_fence
            || project.state.context.workspace_id != source.scope.workspace_id
            || project.state.context.workspace_epoch != source.scope.workspace_epoch
            || project.state.context.runtime_id != eligibility.binding.scope.owner_runtime_id
            || project.state.context.runtime_generation.0
                != eligibility.binding.scope.owner_generation
            || grant.workspace_id != workspace.to_bytes()
            || grant.workspace_epoch != project.state.context.workspace_epoch.to_bytes()
        {
            return Err(Error::Domain(domain::Error::Stale));
        }
        project
            .state
            .validate()
            .map_err(|_| Error::Domain(domain::Error::Stale))?;
        let mut layouts: Vec<_> = project.state.tabs.0.iter().map(|tab| &tab.layout).collect();
        // Store contexts carry OWNER runtime/gen, while remote requests carry
        // the verified server tuple. Derive only that tuple after the raw join.
        if grant.runtime_id != eligibility.binding.server_runtime.runtime_id.to_bytes()
            || grant.runtime_generation != eligibility.binding.server_runtime.runtime_generation.0
            || grant.access_epoch != eligibility.binding.server_runtime.host_access_epoch.0
        {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let remote_workspace = lomi_remote_protocol::WorkspaceContext {
            workspace_id: project.state.context.workspace_id,
            workspace_epoch: project.state.context.workspace_epoch,
            runtime_id: eligibility.binding.server_runtime.runtime_id,
            runtime_generation: eligibility.binding.server_runtime.runtime_generation,
            host_access_epoch: eligibility.binding.server_runtime.host_access_epoch,
            grant_revision: DecimalU64(grant.grant_revision),
        };
        let mut raw_target = None;
        let mut running = Vec::new();
        let mut published = Vec::new();
        let mut seen = std::collections::HashSet::new();
        while let Some(layout) = layouts.pop() {
            match layout {
                lomi_remote_protocol::rpc::TerminalLayout::Split { first, second, .. } => {
                    layouts.push(first);
                    layouts.push(second);
                }
                lomi_remote_protocol::rpc::TerminalLayout::Pane { pane }
                    if pane.state == lomi_remote_protocol::rpc::PaneState::Running =>
                {
                    let terminal = pane
                        .session
                        .as_ref()
                        .ok_or(Error::Domain(domain::Error::Stale))?;
                    if terminal.workspace != project.state.context
                        || terminal.pane_id != pane.pane_id
                        || !seen.insert(pane.pane_id)
                        || rows
                            .terminals
                            .iter()
                            .filter(|(id, status)| {
                                *id == pane.pane_id
                                    && *status == lomi_host_store::TerminalStatus::Running
                            })
                            .count()
                            != 1
                    {
                        return Err(Error::Domain(domain::Error::Stale));
                    }
                    published.push(lomi_remote_protocol::http::PublishedTerminal {
                        pane_id: terminal.pane_id,
                        session_id: terminal.session_id,
                        session_epoch: terminal.session_epoch,
                    });
                    let mut remote = terminal.clone();
                    remote.workspace = remote_workspace.clone();
                    if &remote == target {
                        raw_target = Some(terminal.clone());
                    }
                    running.push(remote);
                }
                lomi_remote_protocol::rpc::TerminalLayout::Pane { .. } => (),
            }
        }
        if !running.contains(target)
            || rows.terminals.iter().any(|(id, status)| {
                *status == lomi_host_store::TerminalStatus::Running && !seen.contains(id)
            })
        {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let local = lomi_host_auth::peer_policy::LocalWorkspace {
            workspace_id: workspace,
            workspace_epoch: project.state.context.workspace_epoch,
            fence: project.fence,
            consent: project.consent,
            running_terminals: published
                .try_into()
                .map_err(|_| Error::Domain(domain::Error::Stale))?,
            capability_ceiling: None,
        };
        guard.validate_current(&snapshot).map_err(Error::Domain)?;
        drop(store); // Intentional: no Store/provider/Domain acquisition under Core.
        let turn = RemoteTerminalTurn {
            guard,
            snapshot,
            worker,
            peer,
            rows,
            local,
            running,
            target: target.clone(),
            raw_target: raw_target.ok_or(Error::Domain(domain::Error::Stale))?,
            clock_floor: floor,
        };
        if !turn.terminal_current() {
            return Err(Error::Domain(domain::Error::Stale));
        }
        Ok(turn)
    }

    /// Caller already owns the workspace actor and has performed a fresh GET
    /// for this exact established channel. Store and owner observations are
    /// captured under the retained Started writer, then Store is dropped before
    /// any terminal Core or transport work.
    pub(super) fn try_started_git_terminal_turn<'d, 'o, 'a, 'p, 'l>(
        &'d self,
        operation: &'o Operation<'o>,
        active: &'a StartedGitContinuation,
        peer: &'p super::auth::peer::StartedGitPeerObservation,
        latches: domain::StartedGitTerminalLatches<'l>,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        target: &TerminalContext,
    ) -> Result<StartedGitTerminalTurn<'d, 'o, 'a, 'p, 'l>, Error> {
        if !active.belongs_to(&self.domain)
            || !active.is_current(operation)
            || !peer.current_for(active, operation, peer.target().connection)
            || !connection.matches_started_git_peer(active, operation, peer)
            || !latches.current()
        {
            connection.dispose();
            return Err(Error::Domain(domain::Error::Stale));
        }

        let target_context = peer.target().context.clone();
        let target_channel_matches =
            match (target_context.purpose, target_context.terminal.as_ref()) {
                (lomi_remote_crypto::ChannelPurposeV3::Workspace, None) => {
                    peer.target().authority.terminal_membership.is_none()
                }
                (lomi_remote_crypto::ChannelPurposeV3::Terminal, Some(channel_target)) => {
                    let profile = match &target.profile {
                        lomi_remote_protocol::TerminalProfile::ExperimentalRustGridV1 => {
                            "lomi-rust-grid-v1-experimental"
                        }
                    };
                    channel_target.pane_id == target.pane_id.to_bytes()
                        && channel_target.session_id == target.session_id.to_bytes()
                        && channel_target.session_epoch == target.session_epoch.to_bytes()
                        && channel_target.terminal_profile == profile
                        && peer.target().authority.terminal_membership.as_ref()
                            == Some(channel_target)
                }
                _ => false,
            };
        if !target_channel_matches {
            connection.dispose();
            return Err(Error::Domain(domain::Error::Stale));
        }

        let control = active.owner_control();
        let guard = self
            .domain
            .try_started_git_read(operation, &control)
            .map_err(Error::Domain)?;
        let authority_revision = control.authority_revision();
        let store = self.try_store()?;
        let workspace = target.workspace.workspace_id;
        let (captured, view) = guard
            .capture(|| {
                let rows = PeerJournalRows::read_binding(&store, active.runtime(), workspace)?;
                let login = store.login_intent()?;
                let identity = store.identity().clone();
                let public_ready = store.public_configuration_ready()?;
                let public = if public_ready {
                    Some(store.public_current()?)
                } else {
                    None
                };
                let public_state = store.public_configuration_state()?;
                let selected = rows.configuration.as_ref();
                let public_matches = selected.is_some_and(|selected| {
                    public.as_ref().is_some_and(|public| {
                        public.configuration().is_ok_and(|configuration| {
                            configuration.authentication.as_ref() == Some(selected)
                        })
                    }) && public_state.as_ref().is_some_and(|state| {
                        state.prepared.is_none()
                            && public
                                .as_ref()
                                .is_some_and(|public| state.current.as_ref() == Some(public))
                    })
                });
                let trusted_matches = selected.is_some_and(|selected| {
                    let Ok(client_id) = selected.client_id.as_str().to_owned().try_into() else {
                        return false;
                    };
                    lomi_host_auth::Config::new(
                        identity.host_id,
                        identity.profile_id,
                        selected.origin.as_str().to_owned(),
                        client_id,
                    )
                    .is_ok()
                        && identity.host_id == active.identity().host_id
                        && selected == active.credential_configuration()
                });
                let configuration_matches = trusted_matches
                    && public_matches
                    && selected.is_some_and(|selected| {
                        selected
                            .remote_api_origin
                            .as_ref()
                            .is_some_and(|origin| origin.as_str() == active.origin().as_str())
                    });
                let view = StoreView::read(&store)?;
                Ok((
                    (rows, identity, login.is_none(), configuration_matches),
                    view,
                ))
            })
            .map_err(|error| match error {
                StepError::Domain(error) => Error::Domain(error),
                StepError::Source(error) => Error::UncertainStore(error),
            })?;
        let (rows, identity, no_login, configuration_matches) = captured;
        if identity != *active.store_identity()
            || identity.host_id != active.identity().host_id
            || rows.authorization.generation != active.runtime().scope.authorization_generation
            || rows.binding.as_ref() != Some(active.runtime())
            || rows.publication.as_ref() != Some(active.acknowledged())
            || rows.host_pending.is_some()
            || !rows.outbox.is_empty()
            || !rows.pairing_acknowledged.contains(peer.source())
            || !no_login
            || !configuration_matches
        {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let heartbeat = active
            .heartbeat()
            .ok_or(Error::Domain(domain::Error::Stale))?;
        if heartbeat.scope != active.runtime().scope
            || heartbeat.runtime != active.runtime().server_runtime
            || identity != *active.store_identity()
        {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let (remote_workspace, local, running) = derive_remote_view_from_grant(
            &rows,
            active.runtime(),
            &peer.target().signed_grant.grant,
            peer.source(),
            workspace,
            &target.workspace,
        )?;
        if remote_workspace != target.workspace || !running.contains(target) {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let now = active
            .trusted_now()
            .ok_or(Error::Domain(domain::Error::Stale))?;
        let clock_floor = rows.authorization.clock_floor;
        if now.wall.as_secs() < clock_floor
            || now.monotonic >= peer.fresh_until()
            || !latches.current()
        {
            return Err(Error::Domain(domain::Error::Stale));
        }
        guard.validate_view(view).map_err(Error::Domain)?;
        drop(store);
        let turn = StartedGitTerminalTurn {
            guard: Some(guard),
            operation,
            active,
            peer,
            latches,
            control,
            authority_revision,
            request_deadline: None,
            io_snapshot_valid: true,
            view,
            rows,
            heartbeat,
            local,
            running,
            target: target.clone(),
            clock_floor,
        };
        if !turn.terminal_current() {
            connection.dispose();
            return Err(Error::Domain(domain::Error::Stale));
        }
        Ok(turn)
    }

    /// Capture one exact locally owned running terminal while a Started Git
    /// writer holds the mutation barrier. The request operation is independent
    /// and retains its own original local IPC deadline/cancellation latch.
    pub(super) fn try_started_git_local_terminal_turn<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        active: &StartedGitContinuation,
        target: &TerminalContext,
    ) -> Result<StartedGitLocalTerminalTurn<'d, 'o>, Error> {
        if !active.belongs_to(&self.domain) {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let control = active.owner_control();
        let guard = self
            .domain
            .try_started_git_local_read(operation, &control)
            .map_err(Error::Domain)?;
        let authority_revision = control.authority_revision();
        let store = self.try_store()?;
        let (identity, project, descriptors) = guard
            .capture_local(|| {
                Ok::<_, StoreError>((
                    store.identity().clone(),
                    store.workspace(target.workspace.workspace_id)?,
                    store.terminal_descriptors(target.workspace.workspace_id)?,
                ))
            })
            .map_err(|error| match error {
                StepError::Domain(error) => Error::Domain(error),
                StepError::Source(error) => Error::UncertainStore(error),
            })?;
        if identity != *active.store_identity()
            || project.state.context != target.workspace
            || project.state.validate().is_err()
            || !project_contains_terminal(&project, target)
            || descriptors
                .iter()
                .filter(|descriptor| {
                    descriptor.pane_id == target.pane_id
                        && descriptor.status == lomi_host_store::TerminalStatus::Running
                })
                .count()
                != 1
        {
            return Err(Error::Domain(domain::Error::Stale));
        }
        drop(store);
        let turn = StartedGitLocalTerminalTurn {
            guard,
            operation,
            control,
            authority_revision,
            project,
            descriptors,
            target: target.clone(),
        };
        if !turn.terminal_current() {
            return Err(Error::Domain(domain::Error::Stale));
        }
        Ok(turn)
    }
}
impl RemoteTerminalTurn<'_, '_, '_, '_, '_, '_> {
    /// Nonblocking final Core predicate: only held Domain checks, already-owned
    /// typed facts, actual atomics and the original trusted clock/Operation.
    pub(super) fn terminal_current(&self) -> bool {
        self.guard.validate_current(&self.snapshot).is_ok()
            && self.raw_target.pane_id == self.target.pane_id
            && self.raw_target.session_id == self.target.session_id
            && self.raw_target.session_epoch == self.target.session_epoch
            && self.raw_target.profile == self.target.profile
            && self.peer.current(self.worker)
            && self
                .worker
                .now()
                .is_some_and(|now| now.wall.as_secs() >= self.clock_floor)
    }
    fn now(&self) -> super::auth::remote_connection::TrustedNow {
        self.worker
            .now()
            .filter(|_| self.terminal_current())
            .unwrap_or(super::auth::remote_connection::TrustedNow {
                wall: std::time::Duration::ZERO,
                monotonic: std::time::Instant::now(),
            })
    }
    fn facts(&self) -> super::auth::remote_connection::OwnerFacts<'_> {
        let eligibility = self.worker.eligibility();
        let deadlines = self.worker.provider().captured_deadlines();
        super::auth::remote_connection::OwnerFacts {
            protected_host: &eligibility.identity,
            origin: self.worker.origin(),
            scope: &eligibility.binding.scope,
            runtime: &eligibility.binding.server_runtime,
            heartbeat: &eligibility.heartbeat,
            acknowledged: &eligibility.publication,
            local: &self.local,
            running: &self.running,
            // Derived from actual borrowed Ready HostAuth and named Store capture.
            auth_ready: true,
            access_expires_at: deadlines.access_expires_at,
            refresh_at: deadlines.refresh_at,
            authorization_locked: self.rows.authorization.locked,
            pending_login: false,
            // Logout is generation/lock/revoke plus actual worker/setup latches;
            // there is no invented durable pending_logout cell.
            pending_logout: false,
            pending_revoke: self.rows.authorization.pending_cloud_revoke,
            pending_publication: self.rows.host_pending.is_some() || !self.rows.outbox.is_empty(),
            peer_revoked: false,
            gate_denied: self.worker.gate_denied(),
            paused: self.worker.paused(),
            stopping: self.worker.stopping(),
            cancelled: self.worker.operation().cancellation_latch(),
        }
    }
    pub(super) fn check_terminal_stream(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
    ) -> Result<(), super::auth::remote_connection::GateError> {
        if !self.terminal_current() {
            connection.dispose();
            return Err(super::auth::remote_connection::GateError::Disposed);
        }
        connection.terminal_stream(&self.target, &self.facts(), &mut || self.now())
    }
    pub(super) fn check_terminal_request(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        original: &lomi_remote_protocol::rpc::RpcRequest,
    ) -> Result<(), super::auth::remote_connection::GateError> {
        use lomi_remote_protocol::rpc::RpcCall;
        let target = match &original.call {
            RpcCall::TerminalAttach(params) | RpcCall::TerminalSnapshot(params) => &params.terminal,
            RpcCall::TerminalAck(params) => &params.terminal,
            RpcCall::TerminalClaim(params) => &params.terminal,
            RpcCall::TerminalRenew(params) | RpcCall::TerminalRelease(params) => &params.terminal,
            RpcCall::TerminalInput(params) => &params.terminal,
            RpcCall::TerminalResize(params) => &params.terminal,
            _ => return Err(super::auth::remote_connection::GateError::Denied),
        };
        if target != &self.target {
            return Err(super::auth::remote_connection::GateError::Denied);
        }
        if !self.terminal_current() {
            connection.dispose();
            return Err(super::auth::remote_connection::GateError::Disposed);
        }
        connection.cached_response(original, &self.facts(), &mut || self.now())
    }
    pub(super) fn terminal_after_wait(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        queued: &super::auth::remote_connection::QueuedRequest,
    ) -> Result<lomi_remote_protocol::rpc::RpcRequest, super::auth::remote_connection::GateError>
    {
        if !self.terminal_current() {
            connection.dispose();
            return Err(super::auth::remote_connection::GateError::Disposed);
        }
        let original =
            connection.after_wait(queued, self.worker.operation(), &self.facts(), &mut || {
                self.now()
            })?;
        self.check_terminal_request(connection, &original)?;
        Ok(original)
    }
}

impl StartedGitTerminalTurn<'_, '_, '_, '_, '_> {
    fn current(&self) -> bool {
        self.latches.current()
            && self.owner_current()
            && self.active.is_current(self.operation)
            && self
                .peer
                .current_for(self.active, self.operation, self.peer.target().connection)
            && self
                .active
                .trusted_now()
                .is_some_and(|now| now.wall.as_secs() >= self.clock_floor)
            && self.running.contains(&self.target)
            && self
                .request_deadline
                .is_none_or(|deadline| std::time::Instant::now() < deadline)
    }

    fn owner_current(&self) -> bool {
        match &self.guard {
            Some(guard) => guard.validate_view(self.view).is_ok(),
            None => self.control.current_at_revision(self.authority_revision),
        }
    }

    /// Drop the retained Domain read guard before terminal PTY input/resize.
    /// The returned watch keeps the exact captured owner/peer/descriptor tuple
    /// and checks the real writer-control atomics plus original operation.
    pub(super) fn into_io_watch(&mut self) -> StartedGitTerminalIoWatch<'_, '_, '_, '_, '_, '_> {
        if let Some(guard) = self.guard.take() {
            let valid = guard.validate_view(self.view).is_ok();
            drop(guard);
            if !valid {
                self.io_snapshot_valid = false;
            }
        }
        StartedGitTerminalIoWatch { turn: self }
    }

    fn now(&self) -> super::auth::remote_connection::TrustedNow {
        self.active
            .trusted_now()
            .filter(|_| self.current())
            .unwrap_or(super::auth::remote_connection::TrustedNow {
                wall: std::time::Duration::ZERO,
                monotonic: std::time::Instant::now(),
            })
    }

    fn facts(&self) -> super::auth::remote_connection::OwnerFacts<'_> {
        let deadlines = self.active.credential_deadlines();
        super::auth::remote_connection::OwnerFacts {
            protected_host: self.active.identity(),
            origin: self.active.origin(),
            scope: &self.active.runtime().scope,
            runtime: &self.active.runtime().server_runtime,
            heartbeat: &self.heartbeat,
            acknowledged: self.active.acknowledged(),
            local: &self.local,
            running: &self.running,
            auth_ready: true,
            access_expires_at: deadlines.access_expires_at,
            refresh_at: deadlines.refresh_at,
            authorization_locked: self.rows.authorization.locked,
            pending_login: false,
            pending_logout: false,
            pending_revoke: self.rows.authorization.pending_cloud_revoke,
            pending_publication: self.rows.host_pending.is_some() || !self.rows.outbox.is_empty(),
            peer_revoked: false,
            gate_denied: self.latches.gate_denied(),
            paused: self.latches.paused(),
            stopping: self.latches.stopping(),
            cancelled: self.operation.cancellation_latch(),
        }
    }

    pub(super) fn terminal_current(&self) -> bool {
        self.current()
    }

    pub(super) fn before_queue(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        request: &lomi_remote_protocol::rpc::RpcRequest,
        request_deadline: std::time::Instant,
    ) -> Result<
        super::auth::remote_connection::QueuedRequest,
        super::auth::remote_connection::GateError,
    > {
        use lomi_remote_protocol::rpc::RpcCall;
        let requested = match &request.call {
            RpcCall::TerminalAttach(params) | RpcCall::TerminalSnapshot(params) => &params.terminal,
            RpcCall::TerminalAck(params) => &params.terminal,
            RpcCall::TerminalClaim(params) => &params.terminal,
            RpcCall::TerminalRenew(params) | RpcCall::TerminalRelease(params) => &params.terminal,
            RpcCall::TerminalInput(params) => &params.terminal,
            RpcCall::TerminalResize(params) => &params.terminal,
            _ => return Err(super::auth::remote_connection::GateError::Denied),
        };
        if requested != &self.target {
            return Err(super::auth::remote_connection::GateError::Denied);
        }
        if !self.current() {
            connection.dispose();
            return Err(super::auth::remote_connection::GateError::Disposed);
        }
        connection.before_queue_started_git_terminal(
            request,
            request_deadline,
            self.operation,
            &self.facts(),
            &mut || self.now(),
            self.active,
            self.peer,
        )
    }

    pub(super) fn check_terminal_stream(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
    ) -> Result<(), super::auth::remote_connection::GateError> {
        if !self.current() {
            connection.dispose();
            return Err(super::auth::remote_connection::GateError::Disposed);
        }
        connection.terminal_stream_started_git(
            &self.target,
            self.operation,
            &self.facts(),
            &mut || self.now(),
            self.active,
            self.peer,
        )
    }

    pub(super) fn check_terminal_request(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        original: &lomi_remote_protocol::rpc::RpcRequest,
    ) -> Result<(), super::auth::remote_connection::GateError> {
        use lomi_remote_protocol::rpc::RpcCall;
        let requested = match &original.call {
            RpcCall::TerminalAttach(params) | RpcCall::TerminalSnapshot(params) => &params.terminal,
            RpcCall::TerminalAck(params) => &params.terminal,
            RpcCall::TerminalClaim(params) => &params.terminal,
            RpcCall::TerminalRenew(params) | RpcCall::TerminalRelease(params) => &params.terminal,
            RpcCall::TerminalInput(params) => &params.terminal,
            RpcCall::TerminalResize(params) => &params.terminal,
            _ => return Err(super::auth::remote_connection::GateError::Denied),
        };
        if requested != &self.target {
            return Err(super::auth::remote_connection::GateError::Denied);
        }
        if !self.current() {
            connection.dispose();
            return Err(super::auth::remote_connection::GateError::Disposed);
        }
        connection.cached_response_started_git_terminal(
            original,
            self.operation,
            &self.facts(),
            &mut || self.now(),
            self.active,
            self.peer,
        )
    }

    pub(super) fn terminal_after_wait(
        &mut self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        queued: &super::auth::remote_connection::QueuedRequest,
    ) -> Result<lomi_remote_protocol::rpc::RpcRequest, super::auth::remote_connection::GateError>
    {
        if !self.current() {
            connection.dispose();
            return Err(super::auth::remote_connection::GateError::Disposed);
        }
        let original = connection.after_wait_started_git_terminal(
            queued,
            self.operation,
            &self.facts(),
            &mut || self.now(),
            self.active,
            self.peer,
        )?;
        self.request_deadline = Some(queued.deadline());
        self.check_terminal_request(connection, &original)?;
        Ok(original)
    }
}

impl StartedGitTerminalIoWatch<'_, '_, '_, '_, '_, '_> {
    pub(super) fn terminal_current(&self) -> bool {
        self.turn.guard.is_none() && self.turn.io_snapshot_valid && self.turn.current()
    }

    pub(super) fn check_terminal_request(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        original: &lomi_remote_protocol::rpc::RpcRequest,
    ) -> Result<(), super::auth::remote_connection::GateError> {
        if !self.terminal_current() {
            connection.dispose();
            return Err(super::auth::remote_connection::GateError::Disposed);
        }
        self.turn.check_terminal_request(connection, original)
    }
}

impl StartedGitTerminalChannelTurn<'_, '_, '_, '_, '_> {
    fn current(&self) -> bool {
        self.request_deadline
            .map_or(true, |deadline| std::time::Instant::now() < deadline)
            && self.latches.current()
            && match &self.guard {
                Some(guard) => guard.validate_view(self.view).is_ok(),
                None => self.control.current_at_revision(self.authority_revision),
            }
            && self.active.is_current(self.operation)
            && self
                .peer
                .current_for(self.active, self.operation, self.peer.target().connection)
            && self
                .active
                .trusted_now()
                .is_some_and(|now| now.wall.as_secs() >= self.clock_floor)
    }

    fn facts(&self) -> super::auth::remote_connection::OwnerFacts<'_> {
        let deadlines = self.active.credential_deadlines();
        super::auth::remote_connection::OwnerFacts {
            protected_host: self.active.identity(),
            origin: self.active.origin(),
            scope: &self.active.runtime().scope,
            runtime: &self.active.runtime().server_runtime,
            heartbeat: &self.heartbeat,
            acknowledged: self.active.acknowledged(),
            local: &self.local,
            running: &self.running,
            auth_ready: true,
            access_expires_at: deadlines.access_expires_at,
            refresh_at: deadlines.refresh_at,
            authorization_locked: self.rows.authorization.locked,
            pending_login: false,
            pending_logout: false,
            pending_revoke: self.rows.authorization.pending_cloud_revoke,
            pending_publication: self.rows.host_pending.is_some() || !self.rows.outbox.is_empty(),
            peer_revoked: false,
            gate_denied: self.latches.gate_denied(),
            paused: self.latches.paused(),
            stopping: self.latches.stopping(),
            cancelled: self.operation.cancellation_latch(),
        }
    }

    fn now(&self) -> super::auth::remote_connection::TrustedNow {
        self.active
            .trusted_now()
            .filter(|_| self.current())
            .unwrap_or(super::auth::remote_connection::TrustedNow {
                wall: std::time::Duration::ZERO,
                monotonic: std::time::Instant::now(),
            })
    }

    pub(super) fn cached_response(
        &mut self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        request: &lomi_remote_protocol::rpc::RpcRequest,
        request_deadline: std::time::Instant,
    ) -> Result<(), super::auth::remote_connection::GateError> {
        self.request_deadline = Some(request_deadline);
        if !self.current() {
            connection.dispose();
            return Err(super::auth::remote_connection::GateError::Disposed);
        }
        connection.cached_response_started_git_terminal(
            request,
            self.operation,
            &self.facts(),
            &mut || self.now(),
            self.active,
            self.peer,
        )
    }

    pub(super) fn cached_operation_response(
        &mut self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        request: &lomi_remote_protocol::rpc::RpcRequest,
        request_deadline: std::time::Instant,
        authorization: Option<&super::remote_operations::RemoteOperationAuthorization>,
    ) -> Result<(), super::auth::remote_connection::GateError> {
        self.request_deadline = Some(request_deadline);
        if !self.current() {
            connection.dispose();
            return Err(super::auth::remote_connection::GateError::Disposed);
        }
        connection.cached_operation_response_started_git_terminal(
            request,
            self.operation,
            authorization,
            &self.facts(),
            &mut || self.now(),
            self.active,
            self.peer,
        )
    }

    pub(super) fn cached_git_receipt_response(
        &mut self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        request: &lomi_remote_protocol::rpc::RpcRequest,
        request_deadline: std::time::Instant,
        disclosure: &GitReceiptDisclosure,
    ) -> Result<(), super::auth::remote_connection::GateError> {
        self.request_deadline = Some(request_deadline);
        if !self.current() {
            connection.dispose();
            return Err(super::auth::remote_connection::GateError::Disposed);
        }
        connection.cached_git_receipt_response_started_git_terminal(
            request,
            self.operation,
            disclosure,
            &self.facts(),
            &mut || self.now(),
            self.active,
            self.peer,
        )
    }

    /// Read or cancel only the exact Git operation protected by this live
    /// Started writer. Cancellation records durable intent; it never releases
    /// the writer or claims that the executor has stopped.
    pub(super) fn operation_control(
        &mut self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        request: &lomi_remote_protocol::rpc::RpcRequest,
        actor: ConsumerAuthorizationId,
        request_deadline: std::time::Instant,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<Option<(OperationReceipt, bool)>, Error> {
        use lomi_remote_protocol::rpc::RpcCall;

        self.request_deadline = Some(request_deadline);
        let (context, operation_id, cancel) = match &request.call {
            RpcCall::OperationStatus(params) => (&params.context, params.operation_id, false),
            RpcCall::OperationCancel(params) => (&params.context, params.operation_id, true),
            _ => return Err(Error::Domain(domain::Error::Stale)),
        };
        let grant = &self.peer.target().signed_grant.grant;
        let workspace_context = WorkspaceContext {
            workspace_id: WorkspaceId::from_bytes(grant.workspace_id)
                .map_err(|_| Error::Domain(domain::Error::Stale))?,
            workspace_epoch: lomi_remote_protocol::WorkspaceEpoch::from_bytes(
                grant.workspace_epoch,
            )
            .map_err(|_| Error::Domain(domain::Error::Stale))?,
            runtime_id: self.active.runtime().scope.owner_runtime_id,
            runtime_generation: DecimalU64(self.active.runtime().scope.owner_generation),
            host_access_epoch: self.active.runtime().server_runtime.host_access_epoch,
            grant_revision: DecimalU64(grant.grant_revision),
        };
        let workspace = workspace_context.workspace_id;
        if std::time::Instant::now() >= request_deadline
            || cancelled.load(std::sync::atomic::Ordering::Acquire)
            || self.peer.target().context.purpose != lomi_remote_crypto::ChannelPurposeV3::Workspace
            || context != &workspace_context
            || self.local.workspace_id != workspace_context.workspace_id
            || self.local.workspace_epoch != workspace_context.workspace_epoch
            || operation_id != self.active.operation_id()
            || workspace != self.active.context_workspace()
            || !self.current()
            || !connection.matches_started_git_peer(self.active, self.operation, self.peer)
        {
            connection.dispose();
            return Err(Error::Domain(domain::Error::Stale));
        }
        let Some(guard) = self.guard.as_ref() else {
            connection.dispose();
            return Err(Error::Domain(domain::Error::Stale));
        };
        guard.validate_view(self.view).map_err(Error::Domain)?;
        let mut store = self.owner.try_store()?;
        let before = PeerJournalRows::read_binding(&store, self.active.runtime(), workspace)
            .map_err(Error::UncertainStore)?;
        if !before.current(&self.rows) {
            connection.dispose();
            return Err(Error::Domain(domain::Error::Stale));
        }
        let capabilities = &self.peer.target().signed_grant.grant.capabilities;
        let receipt = if cancel {
            store
                .cancel_operation(actor, workspace, operation_id, capabilities)
                .map_err(Error::Store)?
        } else {
            store
                .lookup_operation(actor, workspace, operation_id, capabilities)
                .map_err(Error::UncertainStore)?
        };
        let Some(receipt) = receipt else {
            return Ok(None);
        };
        let rights = receipt.stored_rights();
        let active_rights = self.active.stored_rights();
        if receipt.operation_id() != self.active.operation_id()
            || rights.operation_id() != active_rights.operation_id()
            || rights.actor() != active_rights.actor()
            || rights.workspace() != active_rights.workspace()
            || rights.original_method() != active_rights.original_method()
            || rights.actual_rights() != active_rights.actual_rights()
            || rights.repository_execution() != active_rights.repository_execution()
            || receipt
                .authorize_disclosure(capabilities, actor, workspace)
                .is_err()
        {
            connection.dispose();
            return Err(Error::Domain(domain::Error::Stale));
        }
        let after = PeerJournalRows::read_binding(&store, self.active.runtime(), workspace)
            .map_err(Error::UncertainStore)?;
        if !after.current(&before)
            || cancelled.load(std::sync::atomic::Ordering::Acquire)
            || !self.current()
            || guard.validate_view(self.view).is_err()
            || !connection.matches_started_git_peer(self.active, self.operation, self.peer)
        {
            connection.dispose();
            return Err(Error::Domain(domain::Error::Stale));
        }
        let signal_executor =
            cancel && receipt.state() == OperationState::Running && receipt.cancel_requested();
        Ok(Some((receipt, signal_executor)))
    }

    pub(super) fn into_io_watch(
        &mut self,
    ) -> StartedGitTerminalChannelIoWatch<'_, '_, '_, '_, '_, '_> {
        if let Some(guard) = self.guard.take() {
            self.io_snapshot_valid = guard.validate_view(self.view).is_ok();
            drop(guard);
        }
        StartedGitTerminalChannelIoWatch { turn: self }
    }

    pub(super) fn open_frame(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        frame: &[u8],
    ) -> Result<impl AsRef<[u8]> + use<>, super::auth::remote_connection::GateError> {
        if !self.current() {
            connection.dispose();
            return Err(super::auth::remote_connection::GateError::Disposed);
        }
        connection.open_frame_started_git_terminal(
            frame,
            self.operation,
            &self.facts(),
            &mut || self.now(),
            self.active,
            self.peer,
        )
    }

    pub(super) fn seal_frame(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        frame: &[u8],
    ) -> Result<Vec<u8>, super::auth::remote_connection::GateError> {
        if !self.current() {
            connection.dispose();
            return Err(super::auth::remote_connection::GateError::Disposed);
        }
        connection.seal_frame_started_git_terminal(
            frame,
            self.operation,
            &self.facts(),
            &mut || self.now(),
            self.active,
            self.peer,
        )
    }
}

impl StartedGitTerminalChannelIoWatch<'_, '_, '_, '_, '_, '_> {
    pub(super) fn current(&self) -> bool {
        self.turn.guard.is_none() && self.turn.io_snapshot_valid && self.turn.current()
    }

    pub(super) fn open_frame(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        frame: &[u8],
    ) -> Result<impl AsRef<[u8]> + use<>, super::auth::remote_connection::GateError> {
        if !self.current() {
            connection.dispose();
            return Err(super::auth::remote_connection::GateError::Disposed);
        }
        self.turn.open_frame(connection, frame)
    }

    pub(super) fn seal_frame(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        frame: &[u8],
    ) -> Result<Vec<u8>, super::auth::remote_connection::GateError> {
        if !self.current() {
            connection.dispose();
            return Err(super::auth::remote_connection::GateError::Disposed);
        }
        self.turn.seal_frame(connection, frame)
    }
}

impl<'d, 'o> StartedGitLocalTerminalTurn<'d, 'o> {
    pub(super) fn into_io_watch(self) -> StartedGitLocalTerminalIoWatch<'o> {
        let Self {
            guard,
            operation,
            control,
            authority_revision,
            project,
            descriptors,
            target,
        } = self;
        drop(guard);
        StartedGitLocalTerminalIoWatch {
            operation,
            control,
            authority_revision,
            project,
            descriptors,
            target,
        }
    }

    pub(super) fn terminal_current(&self) -> bool {
        self.guard.validate_current().is_ok()
            && self.project.state.context == self.target.workspace
            && project_contains_terminal(&self.project, &self.target)
            && self
                .descriptors
                .iter()
                .filter(|descriptor| {
                    descriptor.pane_id == self.target.pane_id
                        && descriptor.status == lomi_host_store::TerminalStatus::Running
                })
                .count()
                == 1
    }
}

impl StartedGitLocalTerminalIoWatch<'_> {
    pub(super) fn terminal_current(&self) -> bool {
        self.operation.check().is_ok()
            && self.control.current_at_revision(self.authority_revision)
            && self.project.state.context == self.target.workspace
            && project_contains_terminal(&self.project, &self.target)
            && self
                .descriptors
                .iter()
                .filter(|descriptor| {
                    descriptor.pane_id == self.target.pane_id
                        && descriptor.status == lomi_host_store::TerminalStatus::Running
                })
                .count()
                == 1
    }
}

fn project_contains_terminal(project: &ProjectRecord, target: &TerminalContext) -> bool {
    fn in_layout(
        layout: &lomi_remote_protocol::rpc::TerminalLayout,
        target: &TerminalContext,
    ) -> bool {
        use lomi_remote_protocol::rpc::{PaneState, TerminalLayout};
        match layout {
            TerminalLayout::Pane { pane } => {
                pane.pane_id == target.pane_id
                    && pane.state == PaneState::Running
                    && pane.session.as_ref() == Some(target)
            }
            TerminalLayout::Split { first, second, .. } => {
                in_layout(first, target) || in_layout(second, target)
            }
        }
    }
    project.state.context == target.workspace
        && project
            .state
            .tabs
            .0
            .iter()
            .any(|tab| in_layout(&tab.layout, target))
}

fn approved_pairing_read_local(
    source: &AcknowledgedWorkspaceGrant,
    rows: &PeerJournalRows,
) -> Result<(), Error> {
    let scope = &source.intent.preparation.scope;
    let local = rows
        .local
        .as_ref()
        .ok_or(Error::Domain(domain::Error::Stale))?;
    if !local.consent
        || local.fence != scope.workspace_fence
        || local.state.context.workspace_id != scope.workspace_id
        || local.state.context.workspace_epoch != scope.workspace_epoch
        || local.state.context.runtime_id != scope.runtime_scope.owner_runtime_id
        || local.state.context.runtime_generation.0 != scope.runtime_scope.owner_generation
        || !rows.binding.as_ref().is_some_and(|binding| {
            binding.scope == scope.runtime_scope && binding.server_runtime == scope.runtime
        })
        || rows.host_pending.is_some()
        || !rows.outbox.is_empty()
        || !rows.pairing_acknowledged.contains(source)
    {
        return Err(Error::Domain(domain::Error::Stale));
    }
    Ok(())
}

// Production ticket authorization: exact current local facts, including an
// empty workspace. This is independent of the test-only fresh-pairing helper.
impl SharedOwner {
    fn channel_ticket_local(
        &self,
        binding: &super::auth::channel::ChannelTicketBinding,
        rows: &PeerJournalRows,
        store: &HostStore,
    ) -> Result<(), Error> {
        let stale = || Error::Domain(domain::Error::Stale);
        let uncertain = |error| {
            self.domain.cloud_uncertain();
            Error::UncertainStore(error)
        };
        let scope = binding.scope();
        let local = rows.local.as_ref().ok_or_else(stale)?;
        let selected = rows.configuration.as_ref().ok_or_else(stale)?;
        let trusted = lomi_host_auth::Config::new(
            store.identity().host_id,
            store.identity().profile_id,
            selected.origin.as_str().to_owned(),
            selected
                .client_id
                .as_str()
                .to_owned()
                .try_into()
                .map_err(|_| stale())?,
        )
        .map_err(|_| stale())?;
        let public = store.public_current().map_err(uncertain)?;
        let public_state = store.public_configuration_state().map_err(uncertain)?;
        if &trusted != binding.trusted()
            || selected
                .remote_api_origin
                .as_ref()
                .map(|origin| origin.as_str())
                != Some(scope.runtime_scope.remote_api_origin.as_str())
            || !store.public_configuration_ready().map_err(uncertain)?
            || public
                .configuration()
                .map_err(uncertain)?
                .authentication
                .as_ref()
                != Some(selected)
            || !public_state.as_ref().is_some_and(|state| {
                state.prepared.is_none() && state.current.as_ref() == Some(&public)
            })
            || store.login_intent().map_err(uncertain)?.is_some()
            || !local.consent
            || local.fence != scope.workspace_fence
            || local.state.context.workspace_id != scope.workspace_id
            || local.state.context.workspace_epoch != scope.workspace_epoch
            || local.state.context.runtime_id != scope.runtime_scope.owner_runtime_id
            || local.state.context.runtime_generation.0 != scope.runtime_scope.owner_generation
            || !rows.binding.as_ref().is_some_and(|current| {
                current.scope == scope.runtime_scope && current.server_runtime == scope.runtime
            })
            || rows.host_pending.is_some()
            || !rows.outbox.is_empty()
            || !rows.pairing_acknowledged.contains(binding.source())
            || !rows
                .channel_acknowledged
                .contains(binding.acknowledgement())
        {
            return Err(stale());
        }
        if let lomi_remote_protocol::http::ChannelTarget::Terminal {
            pane_id,
            session_id,
            session_epoch,
            ..
        } = &binding.acknowledgement().intent.preparation.target
        {
            let membership = binding
                .acknowledgement()
                .intent
                .preparation
                .inputs
                .authority
                .terminal_membership
                .as_ref()
                .ok_or_else(stale)?;
            if !rows.terminals.iter().any(|(pane, status)| {
                pane == pane_id && *status == lomi_host_store::TerminalStatus::Running
            }) {
                return Err(stale());
            }
            let mut layouts: Vec<_> = local.state.tabs.0.iter().map(|tab| &tab.layout).collect();
            let mut found = false;
            while let Some(layout) = layouts.pop() {
                match layout {
                    lomi_remote_protocol::rpc::TerminalLayout::Split { first, second, .. } => {
                        layouts.push(first);
                        layouts.push(second);
                    }
                    lomi_remote_protocol::rpc::TerminalLayout::Pane { pane } => {
                        found |= pane.pane_id == *pane_id
                            && pane.state == lomi_remote_protocol::rpc::PaneState::Running
                            && pane.session.as_ref().is_some_and(|session| {
                                session.session_id == *session_id
                                    && session.session_epoch == *session_epoch
                                    && session.workspace == local.state.context
                                    && session.profile == membership.terminal_profile
                            });
                    }
                }
            }
            if !found {
                return Err(stale());
            }
        }
        Ok(())
    }
}

// Workspace ingress facade. Only this named owner capture constructs production
// facts. The turn holds Domain and its snapshot; Store is dropped before crypto
// or workspace projection can leave this boundary. Drop before network waits.
/// Host-resolved Explorer root of one workspace (never client supplied).
pub(super) struct FilesTarget {
    pub(super) workspace_id: lomi_remote_protocol::WorkspaceId,
    pub(super) epoch: lomi_remote_protocol::WorkspaceEpoch,
    pub(super) root: std::path::PathBuf,
}
pub(super) struct RemoteWorkspaceTurn<'d, 'o, 'e, 'w, 'p, 's> {
    guard: domain::OwnerGuard<'d, 'o>,
    snapshot: domain::Snapshot<'d, 'o>,
    worker: &'e super::auth::RemoteWorkerEvidence<'w, 'p, 's, 'o>,
    peer: &'e super::auth::peer::VerifiedCurrentPeer,
    rows: PeerJournalRows,
    local: lomi_host_auth::peer_policy::LocalWorkspace,
    running: Vec<TerminalContext>,
    workspace: lomi_remote_protocol::WorkspaceContext,
    state: WorkspaceState,
    profiles: Vec<HostProfile>,
    relay_endpoint: Option<lomi_remote_protocol::ipc::LocalRelayEndpoint>,
    clock_floor: u64,
}
impl SharedOwner {
    /// Domain -> Store captures one coherent read-only workspace snapshot.
    /// No terminal actor is needed; Store is explicitly dropped here.
    pub(super) fn try_remote_workspace_turn<'d, 'o, 'e, 'w, 'p, 's>(
        &'d self,
        worker: &'e super::auth::RemoteWorkerEvidence<'w, 'p, 's, 'o>,
        peer: &'e super::auth::peer::VerifiedCurrentPeer,
        context: &lomi_remote_protocol::WorkspaceContext,
    ) -> Result<RemoteWorkspaceTurn<'d, 'o, 'e, 'w, 'p, 's>, Error> {
        if !std::ptr::eq(self, worker.owner()) || !peer.current(worker) {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let guard = self
            .domain
            .try_read(worker.operation())
            .map_err(Error::Domain)?;
        let store = self.try_store()?;
        let floor = guard
            .check_peer_effect(peer.continuation(), &store)
            .map_err(peer_store_step)?;
        let workspace = context.workspace_id;
        let mut rows = None;
        let mut login = None;
        let mut profiles = None;
        let snapshot = guard
            .capture_remote(|| {
                rows = Some(PeerJournalRows::read(
                    &store,
                    worker.eligibility(),
                    workspace,
                )?);
                login = store.login_intent()?;
                profiles = Some(store.shell_profiles(workspace)?);
                StoreView::read(&store)
            })
            .map_err(|error| match error {
                StepError::Domain(error) => Error::Domain(error),
                StepError::Source(error) => Error::UncertainStore(error),
            })?;
        let rows = rows.expect("named capture ran");
        let profiles = profiles.expect("named capture ran");
        let eligibility = worker.eligibility();
        let selected = rows
            .configuration
            .as_ref()
            .ok_or(Error::Domain(domain::Error::Stale))?;
        let trusted = lomi_host_auth::Config::new(
            store.identity().host_id,
            store.identity().profile_id,
            selected.origin.as_str().to_owned(),
            selected
                .client_id
                .as_str()
                .to_owned()
                .try_into()
                .map_err(|_| Error::Domain(domain::Error::Stale))?,
        )
        .map_err(|_| Error::Domain(domain::Error::Stale))?;
        let public = store.public_current().map_err(Error::UncertainStore)?;
        let public_state = store
            .public_configuration_state()
            .map_err(Error::UncertainStore)?;
        if &trusted != worker.trusted()
            || selected
                .remote_api_origin
                .as_ref()
                .map(|origin| origin.as_str())
                != Some(worker.origin().as_str())
            || !store
                .public_configuration_ready()
                .map_err(Error::UncertainStore)?
            || public
                .configuration()
                .map_err(Error::UncertainStore)?
                .authentication
                .as_ref()
                != Some(selected)
            || !public_state.as_ref().is_some_and(|state| {
                state.prepared.is_none() && state.current.as_ref() == Some(&public)
            })
            || login.is_some()
            || rows.binding.as_ref() != Some(&eligibility.binding)
            || rows.publication.as_ref() != Some(&eligibility.publication)
            || rows.host_pending.is_some()
            || !rows.outbox.is_empty()
            || !rows.pairing_acknowledged.contains(peer.source())
        {
            return Err(Error::Domain(domain::Error::Stale));
        }
        let (remote_workspace, local, running) =
            derive_remote_view(&rows, eligibility, peer, workspace, context)?;
        let project = rows
            .local
            .as_ref()
            .ok_or(Error::Domain(domain::Error::Stale))?;
        let state = project_remote_workspace(&project.state, &remote_workspace)?;
        let relay_endpoint = selected.relay_endpoint.clone();
        guard.validate_current(&snapshot).map_err(Error::Domain)?;
        drop(store); // Intentional: no Store/provider/Domain acquisition under Core.
        let turn = RemoteWorkspaceTurn {
            guard,
            snapshot,
            worker,
            peer,
            rows,
            local,
            running,
            workspace: remote_workspace,
            state,
            profiles,
            relay_endpoint,
            clock_floor: floor,
        };
        if !turn.current() {
            return Err(Error::Domain(domain::Error::Stale));
        }
        Ok(turn)
    }
}
/// Single derivation of the workspace-facing view from one coherent set of
/// journal rows. Used before a request and again after an effect completes, so
/// both sides apply identical ready/grant/terminal consistency checks.
fn derive_remote_view(
    rows: &PeerJournalRows,
    eligibility: &super::auth::cloud::PeerEligibility,
    peer: &super::auth::peer::VerifiedCurrentPeer,
    workspace: WorkspaceId,
    context: &lomi_remote_protocol::WorkspaceContext,
) -> Result<
    (
        lomi_remote_protocol::WorkspaceContext,
        lomi_host_auth::peer_policy::LocalWorkspace,
        Vec<TerminalContext>,
    ),
    Error,
> {
    derive_remote_view_from_grant(
        rows,
        &eligibility.binding,
        peer.grant(),
        peer.source(),
        workspace,
        context,
    )
}

fn derive_remote_view_from_grant(
    rows: &PeerJournalRows,
    binding: &CloudRuntimeState,
    grant: &lomi_remote_crypto::GrantV3,
    source: &AcknowledgedWorkspaceGrant,
    workspace: WorkspaceId,
    context: &lomi_remote_protocol::WorkspaceContext,
) -> Result<
    (
        lomi_remote_protocol::WorkspaceContext,
        lomi_host_auth::peer_policy::LocalWorkspace,
        Vec<TerminalContext>,
    ),
    Error,
> {
    let project = rows
        .local
        .as_ref()
        .ok_or(Error::Domain(domain::Error::Stale))?;
    let source = &source.intent.preparation;
    if !project.consent
        || project.fence != source.scope.workspace_fence
        || project.state.context.workspace_id != source.scope.workspace_id
        || project.state.context.workspace_epoch != source.scope.workspace_epoch
        || project.state.context.runtime_id != binding.scope.owner_runtime_id
        || project.state.context.runtime_generation.0 != binding.scope.owner_generation
        || grant.workspace_id != workspace.to_bytes()
        || grant.workspace_epoch != project.state.context.workspace_epoch.to_bytes()
    {
        return Err(Error::Domain(domain::Error::Stale));
    }
    let mut layouts: Vec<_> = project.state.tabs.0.iter().map(|tab| &tab.layout).collect();
    // Store contexts carry OWNER runtime/gen, while remote requests carry
    // the verified server tuple. Derive only that tuple after the raw join.
    if grant.runtime_id != binding.server_runtime.runtime_id.to_bytes()
        || grant.runtime_generation != binding.server_runtime.runtime_generation.0
        || grant.access_epoch != binding.server_runtime.host_access_epoch.0
    {
        return Err(Error::Domain(domain::Error::Stale));
    }
    let remote_workspace = lomi_remote_protocol::WorkspaceContext {
        workspace_id: project.state.context.workspace_id,
        workspace_epoch: project.state.context.workspace_epoch,
        runtime_id: binding.server_runtime.runtime_id,
        runtime_generation: binding.server_runtime.runtime_generation,
        host_access_epoch: binding.server_runtime.host_access_epoch,
        grant_revision: DecimalU64(grant.grant_revision),
    };
    let mut running = Vec::new();
    let mut published = Vec::new();
    let mut seen = std::collections::HashSet::new();
    while let Some(layout) = layouts.pop() {
        match layout {
            lomi_remote_protocol::rpc::TerminalLayout::Split { first, second, .. } => {
                layouts.push(first);
                layouts.push(second);
            }
            lomi_remote_protocol::rpc::TerminalLayout::Pane { pane }
                if pane.state == lomi_remote_protocol::rpc::PaneState::Running =>
            {
                let terminal = pane
                    .session
                    .as_ref()
                    .ok_or(Error::Domain(domain::Error::Stale))?;
                if terminal.workspace != project.state.context
                    || terminal.pane_id != pane.pane_id
                    || !seen.insert(pane.pane_id)
                    || rows
                        .terminals
                        .iter()
                        .filter(|(id, status)| {
                            *id == pane.pane_id
                                && *status == lomi_host_store::TerminalStatus::Running
                        })
                        .count()
                        != 1
                {
                    return Err(Error::Domain(domain::Error::Stale));
                }
                published.push(lomi_remote_protocol::http::PublishedTerminal {
                    pane_id: terminal.pane_id,
                    session_id: terminal.session_id,
                    session_epoch: terminal.session_epoch,
                });
                let mut remote = terminal.clone();
                remote.workspace = remote_workspace.clone();
                running.push(remote);
            }
            lomi_remote_protocol::rpc::TerminalLayout::Pane { .. } => (),
        }
    }
    if &remote_workspace != context
        || rows.terminals.iter().any(|(id, status)| {
            *status == lomi_host_store::TerminalStatus::Running && !seen.contains(id)
        })
    {
        return Err(Error::Domain(domain::Error::Stale));
    }
    let local = lomi_host_auth::peer_policy::LocalWorkspace {
        workspace_id: workspace,
        workspace_epoch: project.state.context.workspace_epoch,
        fence: project.fence,
        consent: project.consent,
        running_terminals: published
            .try_into()
            .map_err(|_| Error::Domain(domain::Error::Stale))?,
        capability_ceiling: None,
    };
    Ok((remote_workspace, local, running))
}
impl RemoteWorkspaceTurn<'_, '_, '_, '_, '_, '_> {
    fn current(&self) -> bool {
        self.guard.validate_current(&self.snapshot).is_ok()
            && self.peer.current(self.worker)
            && self
                .worker
                .now()
                .is_some_and(|now| now.wall.as_secs() >= self.clock_floor)
    }
    fn check(&self) -> Result<(), super::auth::remote_connection::GateError> {
        if self.current() {
            Ok(())
        } else {
            Err(super::auth::remote_connection::GateError::Disposed)
        }
    }
    fn check_connection(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
    ) -> Result<(), super::auth::remote_connection::GateError> {
        if let Err(error) = self.check() {
            #[cfg(test)]
            super::auth::remote_connection::record_shared_owner_origin_for_test(
                file!(),
                line!(),
                column!(),
            );
            connection.dispose();
            return Err(error);
        }
        Ok(())
    }
    fn now(&self) -> super::auth::remote_connection::TrustedNow {
        self.worker.now().filter(|_| self.current()).unwrap_or(
            super::auth::remote_connection::TrustedNow {
                wall: std::time::Duration::ZERO,
                monotonic: std::time::Instant::now(),
            },
        )
    }
    fn facts(&self) -> super::auth::remote_connection::OwnerFacts<'_> {
        let eligibility = self.worker.eligibility();
        let deadlines = self.worker.provider().captured_deadlines();
        super::auth::remote_connection::OwnerFacts {
            protected_host: &eligibility.identity,
            origin: self.worker.origin(),
            scope: &eligibility.binding.scope,
            runtime: &eligibility.binding.server_runtime,
            heartbeat: &eligibility.heartbeat,
            acknowledged: &eligibility.publication,
            local: &self.local,
            running: &self.running,
            // Derived from actual borrowed Ready HostAuth and named Store capture.
            auth_ready: true,
            access_expires_at: deadlines.access_expires_at,
            refresh_at: deadlines.refresh_at,
            authorization_locked: self.rows.authorization.locked,
            pending_login: false,
            // Logout is generation/lock/revoke plus actual worker/setup latches;
            // there is no invented durable pending_logout cell.
            pending_logout: false,
            pending_revoke: self.rows.authorization.pending_cloud_revoke,
            pending_publication: self.rows.host_pending.is_some() || !self.rows.outbox.is_empty(),
            peer_revoked: false,
            gate_denied: self.worker.gate_denied(),
            paused: self.worker.paused(),
            stopping: self.worker.stopping(),
            cancelled: self.worker.operation().cancellation_latch(),
        }
    }

    pub(super) fn relay_endpoint(
        &self,
    ) -> Result<
        lomi_remote_protocol::ipc::LocalRelayEndpoint,
        super::auth::remote_connection::GateError,
    > {
        self.check()?;
        self.relay_endpoint
            .clone()
            .ok_or(super::auth::remote_connection::GateError::Denied)
    }
    pub(super) fn begin_connection(
        &self,
        canonical: &[u8],
        signed: &lomi_remote_crypto::SignedGrantV3,
        admission: &lomi_remote_crypto::SignedChannelAdmissionV3,
    ) -> Result<
        super::auth::remote_connection::PendingRemoteConnection,
        super::auth::remote_connection::GateError,
    > {
        self.check()?;
        super::auth::remote_connection::PendingRemoteConnection::begin(
            self.worker.auth(),
            super::auth::remote_connection::AdmissionInputs {
                canonical_context: canonical,
                signed_grant: signed,
                admission,
                peer: self.peer.read(),
            },
            &self.facts(),
            &mut || self.now(),
        )
    }
    pub(super) fn handshake_read(
        &self,
        pending: &mut super::auth::remote_connection::PendingRemoteConnection,
        bytes: &[u8],
    ) -> Result<(), super::auth::remote_connection::GateError> {
        if let Err(error) = self.check() {
            pending.dispose();
            return Err(error);
        }
        pending.read(bytes, &self.facts(), &mut || self.now())
    }
    pub(super) fn handshake_write(
        &self,
        pending: &mut super::auth::remote_connection::PendingRemoteConnection,
    ) -> Result<Vec<u8>, super::auth::remote_connection::GateError> {
        if let Err(error) = self.check() {
            pending.dispose();
            return Err(error);
        }
        pending.write(&self.facts(), &mut || self.now())
    }
    pub(super) fn finish_connection(
        &self,
        mut pending: super::auth::remote_connection::PendingRemoteConnection,
    ) -> Result<
        super::auth::remote_connection::RemoteConnectionState,
        super::auth::remote_connection::GateError,
    > {
        if let Err(error) = self.check() {
            pending.dispose();
            return Err(error);
        }
        pending.finish(&self.facts(), &mut || self.now())
    }
    pub(super) fn refresh_peer(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
    ) -> Result<(), super::auth::remote_connection::GateError> {
        self.check_connection(connection)?;
        connection.refresh_peer(self.peer.read(), &self.facts(), &mut || self.now())
    }
    pub(super) fn open_frame(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        bytes: &[u8],
    ) -> Result<impl AsRef<[u8]> + use<>, super::auth::remote_connection::GateError> {
        self.check_connection(connection)?;
        connection.open_frame(bytes, &self.facts(), &mut || self.now())
    }
    pub(super) fn seal_frame(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        bytes: &[u8],
    ) -> Result<Vec<u8>, super::auth::remote_connection::GateError> {
        self.check_connection(connection)?;
        connection.seal_frame(bytes, &self.facts(), &mut || self.now())
    }
    pub(super) fn before_queue(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        request: &lomi_remote_protocol::rpc::RpcRequest,
    ) -> Result<
        super::auth::remote_connection::QueuedRequest,
        super::auth::remote_connection::GateError,
    > {
        self.check_connection(connection)?;
        connection.before_queue(request, self.worker.operation(), &self.facts(), &mut || {
            self.now()
        })
    }

    pub(super) fn workspace_get_after_wait(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        queued: &super::auth::remote_connection::QueuedRequest,
    ) -> Result<WorkspaceState, super::auth::remote_connection::GateError> {
        self.check_connection(connection)?;
        let request =
            connection.after_wait(queued, self.worker.operation(), &self.facts(), &mut || {
                self.now()
            })?;
        if !matches!(&request.call, lomi_remote_protocol::rpc::RpcCall::WorkspaceGet(params) if params.context == self.workspace)
        {
            return Err(super::auth::remote_connection::GateError::Denied);
        }
        self.check_connection(connection)?;
        Ok(self.state.clone())
    }
    pub(super) fn workspace_subscribe_after_wait(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        queued: &super::auth::remote_connection::QueuedRequest,
    ) -> Result<WorkspaceState, super::auth::remote_connection::GateError> {
        self.check_connection(connection)?;
        let request =
            connection.after_wait(queued, self.worker.operation(), &self.facts(), &mut || {
                self.now()
            })?;
        if !matches!(
            &request.call,
            lomi_remote_protocol::rpc::RpcCall::WorkspaceSubscribe(params)
                if params.context == self.workspace
        ) {
            return Err(super::auth::remote_connection::GateError::Denied);
        }
        self.check_connection(connection)?;
        Ok(self.state.clone())
    }
    /// Return only the current peer's projected workspace state for an active
    /// stream frame. The revision hint is never authorization or data itself.
    pub(super) fn workspace_stream_state(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
    ) -> Result<WorkspaceState, super::auth::remote_connection::GateError> {
        self.check_connection(connection)?;
        Ok(self.state.clone())
    }
    pub(super) fn workspace_capabilities_after_wait(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        queued: &super::auth::remote_connection::QueuedRequest,
    ) -> Result<
        lomi_remote_protocol::rpc::WorkspaceCapabilitiesResult,
        super::auth::remote_connection::GateError,
    > {
        self.check_connection(connection)?;
        let granted = connection.workspace_capabilities_after_wait(
            queued,
            self.worker.operation(),
            &self.workspace,
            &self.facts(),
            &mut || self.now(),
        )?;
        // Advertise only implemented services, intersected with this grant.
        // Git mutations use the journaled, revocation-gated execution path.
        const IMPLEMENTED: [Capability; 9] = [
            Capability::WorkspaceRead,
            Capability::TerminalObserve,
            Capability::TerminalControl,
            Capability::TerminalManage,
            Capability::FilesRead,
            Capability::FilesWrite,
            Capability::GitRead,
            Capability::GitWrite,
            Capability::GitNetwork,
        ];
        let capabilities = CapabilitySet::try_from(
            IMPLEMENTED
                .into_iter()
                .filter(|capability| granted.contains(*capability))
                .collect::<Vec<_>>(),
        )
        .map_err(|_| super::auth::remote_connection::GateError::Disposed)?;
        let profiles = if capabilities.contains(Capability::TerminalManage) {
            self.profiles.clone()
        } else {
            Vec::new()
        };
        self.check_connection(connection)?;
        Ok(lomi_remote_protocol::rpc::WorkspaceCapabilitiesResult {
            capabilities,
            profiles: lomi_remote_protocol::rpc::BoundedList(profiles),
        })
    }
    pub(super) fn finish_unsupported_after_wait(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        queued: &super::auth::remote_connection::QueuedRequest,
    ) -> Result<(), super::auth::remote_connection::GateError> {
        self.check_connection(connection)?;
        connection.after_wait(queued, self.worker.operation(), &self.facts(), &mut || {
            self.now()
        })?;
        self.check_connection(connection)
    }
    /// Consumes the queued read-only Explorer request after the same live gates
    /// as `workspace.get` and returns the host-resolved root (never client
    /// input). Every owner turn is dropped by the caller before any file IO.
    pub(super) fn files_after_wait(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        queued: &super::auth::remote_connection::QueuedRequest,
    ) -> Result<
        (lomi_remote_protocol::rpc::RpcRequest, FilesTarget),
        super::auth::remote_connection::GateError,
    > {
        use lomi_remote_protocol::rpc::RpcCall;
        self.check_connection(connection)?;
        let request =
            connection.after_wait(queued, self.worker.operation(), &self.facts(), &mut || {
                self.now()
            })?;
        let context = match &request.call {
            RpcCall::FilesList(p) => &p.context,
            RpcCall::FilesStat(p) => &p.context,
            RpcCall::FilesRead(p) => &p.context,
            RpcCall::FilesSearchNames(p) => &p.context,
            RpcCall::FilesWatch(p) => &p.context,
            _ => return Err(super::auth::remote_connection::GateError::Denied),
        };
        if context != &self.workspace {
            return Err(super::auth::remote_connection::GateError::Denied);
        }
        let local = self
            .rows
            .local
            .as_ref()
            .ok_or(super::auth::remote_connection::GateError::Denied)?;
        let target = FilesTarget {
            workspace_id: local.state.context.workspace_id,
            epoch: local.state.context.workspace_epoch,
            root: local.local_root.clone(),
        };
        self.check_connection(connection)?;
        Ok((request, target))
    }
    /// Consume a Git read using the same current owner/peer gates as Explorer.
    /// The host-selected root leaves this turn only as an internal target;
    /// background computation cannot retain an owner or authorization guard.
    pub(super) fn git_read_after_wait(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        queued: &super::auth::remote_connection::QueuedRequest,
    ) -> Result<FilesTarget, super::auth::remote_connection::GateError> {
        use lomi_remote_protocol::rpc::RpcCall;
        self.check_connection(connection)?;
        let request =
            connection.after_wait(queued, self.worker.operation(), &self.facts(), &mut || {
                self.now()
            })?;
        let context = match &request.call {
            RpcCall::GitRepositories(p) => &p.context,
            RpcCall::GitStatus(p) => &p.context,
            RpcCall::GitDiff(p) => &p.context,
            RpcCall::GitLog(p) => &p.context,
            RpcCall::GitShow(p) => &p.context,
            _ => return Err(super::auth::remote_connection::GateError::Denied),
        };
        if context != &self.workspace {
            return Err(super::auth::remote_connection::GateError::Denied);
        }
        let local = self
            .rows
            .local
            .as_ref()
            .ok_or(super::auth::remote_connection::GateError::Denied)?;
        let target = FilesTarget {
            workspace_id: local.state.context.workspace_id,
            epoch: local.state.context.workspace_epoch,
            root: local.local_root.clone(),
        };
        self.check_connection(connection)?;
        Ok(target)
    }
    /// Non-consuming Git mutation admission check used only while the bounded
    /// private snapshot job runs. The exact queued ticket is consumed later,
    /// under a fresh owner turn, immediately before the durable journal start.
    pub(super) fn git_mutation_peek_after_wait(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        queued: &super::auth::remote_connection::QueuedRequest,
    ) -> Result<FilesTarget, super::auth::remote_connection::GateError> {
        use lomi_remote_protocol::rpc::RpcCall;
        self.check_connection(connection)?;
        let request = connection.peek_after_wait(
            queued,
            self.worker.operation(),
            &self.facts(),
            &mut || self.now(),
        )?;
        let context = match &request.call {
            RpcCall::GitStage(p) => &p.mutation.context,
            RpcCall::GitUnstage(p) => &p.mutation.context,
            RpcCall::GitCommit(p) => &p.mutation.context,
            RpcCall::GitFetch(p) | RpcCall::GitPush(p) => &p.mutation.context,
            RpcCall::GitPull(p) => &p.mutation.context,
            _ => return Err(super::auth::remote_connection::GateError::Denied),
        };
        if context != &self.workspace {
            return Err(super::auth::remote_connection::GateError::Denied);
        }
        let local = self
            .rows
            .local
            .as_ref()
            .ok_or(super::auth::remote_connection::GateError::Denied)?;
        let target = FilesTarget {
            workspace_id: local.state.context.workspace_id,
            epoch: local.state.context.workspace_epoch,
            root: local.local_root.clone(),
        };
        self.check_connection(connection)?;
        Ok(target)
    }
    /// Consume the same queued Git mutation ticket after private preparation.
    /// The caller follows this with durable admission/start while the exact
    /// current owner/evidence turn is still held.
    pub(super) fn git_mutation_after_wait(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        queued: &super::auth::remote_connection::QueuedRequest,
    ) -> Result<
        (
            lomi_remote_protocol::rpc::RpcRequest,
            FilesTarget,
            std::time::Instant,
            std::time::Instant,
        ),
        super::auth::remote_connection::GateError,
    > {
        use lomi_remote_protocol::rpc::RpcCall;
        self.check_connection(connection)?;
        let (request, hard_expiry, heartbeat_expiry) = connection.before_remote_git_mutation(
            queued,
            self.worker.operation(),
            &self.facts(),
            &mut || self.now(),
        )?;
        let context = match &request.call {
            RpcCall::GitStage(p) => &p.mutation.context,
            RpcCall::GitUnstage(p) => &p.mutation.context,
            RpcCall::GitCommit(p) => &p.mutation.context,
            RpcCall::GitFetch(p) | RpcCall::GitPush(p) => &p.mutation.context,
            RpcCall::GitPull(p) => &p.mutation.context,
            _ => return Err(super::auth::remote_connection::GateError::Denied),
        };
        if context != &self.workspace {
            return Err(super::auth::remote_connection::GateError::Denied);
        }
        let local = self
            .rows
            .local
            .as_ref()
            .ok_or(super::auth::remote_connection::GateError::Denied)?;
        let target = FilesTarget {
            workspace_id: local.state.context.workspace_id,
            epoch: local.state.context.workspace_epoch,
            root: local.local_root.clone(),
        };
        self.check_connection(connection)?;
        Ok((request, target, hard_expiry, heartbeat_expiry))
    }
    pub(super) fn check_response(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        request: &lomi_remote_protocol::rpc::RpcRequest,
    ) -> Result<(), super::auth::remote_connection::GateError> {
        self.check_connection(connection)?;
        connection.cached_response(request, &self.facts(), &mut || self.now())
    }

    pub(super) fn cached_git_receipt_response(
        &self,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        request: &lomi_remote_protocol::rpc::RpcRequest,
        disclosure: &GitReceiptDisclosure,
    ) -> Result<(), super::auth::remote_connection::GateError> {
        self.check_connection(connection)?;
        connection
            .cached_git_receipt_response(request, disclosure, &self.facts(), &mut || self.now())
    }
}

// Project only the public protocol DTO. ProjectRecord (and local_root) never
// enters the response. Rebind every session, including non-running sessions.
fn project_remote_workspace(
    state: &WorkspaceState,
    context: &lomi_remote_protocol::WorkspaceContext,
) -> Result<WorkspaceState, Error> {
    state
        .validate()
        .map_err(|_| Error::Domain(domain::Error::Stale))?;
    if state.context.workspace_id != context.workspace_id
        || state.context.workspace_epoch != context.workspace_epoch
    {
        return Err(Error::Domain(domain::Error::Stale));
    }
    let mut projected = state.clone();
    projected.context = context.clone();
    let mut layouts: Vec<_> = projected
        .tabs
        .0
        .iter_mut()
        .map(|tab| &mut tab.layout)
        .collect();
    while let Some(layout) = layouts.pop() {
        match layout {
            lomi_remote_protocol::rpc::TerminalLayout::Split { first, second, .. } => {
                layouts.push(first);
                layouts.push(second);
            }
            lomi_remote_protocol::rpc::TerminalLayout::Pane { pane } => {
                if let Some(session) = &mut pane.session {
                    session.workspace = context.clone();
                }
            }
        }
    }
    projected
        .validate()
        .map_err(|_| Error::Domain(domain::Error::Stale))?;
    Ok(projected)
}

#[cfg(test)]
#[path = "remote_workspace_projection_tests.rs"]
mod remote_workspace_projection_tests;

// Closed Rename/Move mutation and receipt boundary. No generic outbox/peer exception.
#[derive(Clone, Copy, Debug)]
pub(super) enum RemoteRenameError {
    Owner(Error),
    Gate(super::auth::remote_connection::GateError),
    Closed,
}
impl From<Error> for RemoteRenameError {
    fn from(value: Error) -> Self {
        Self::Owner(value)
    }
}
impl From<super::auth::remote_connection::GateError> for RemoteRenameError {
    fn from(value: super::auth::remote_connection::GateError) -> Self {
        Self::Gate(value)
    }
}
pub(super) enum RemoteRenameBegin<'d, 'o, 'e, 'w, 'p, 's> {
    Duplicate(OperationReceipt),
    /// Refused before any announcement, journal write or effect.
    Rejected(lomi_remote_protocol::RemoteError),
    Write(Box<RemoteTerminalRenameWrite<'d, 'o, 'e, 'w, 'p, 's>>),
}
pub(super) struct RemoteTerminalRenameWrite<'d, 'o, 'e, 'w, 'p, 's> {
    owner: &'d SharedOwner,
    worker: &'e super::auth::RemoteWorkerEvidence<'w, 'p, 's, 'o>,
    pending: Option<domain::RemoteRenameWrite<'d, 'o>>,
    before: PeerJournalRows,
    local: lomi_host_auth::peer_policy::LocalWorkspace,
    running: Vec<TerminalContext>,
    request: lomi_remote_protocol::rpc::RpcRequest,
    binding: OperationBinding,
    connection: uuid::Uuid,
    closed: bool,
    /// Set only when the Store refused with a known no-effect error.
    rejection: Option<lomi_remote_protocol::RemoteError>,
}
pub(super) struct RemoteRenameReceipt<'d, 'o, 'e, 'w, 'p, 's> {
    owner: &'d SharedOwner,
    worker: &'e super::auth::RemoteWorkerEvidence<'w, 'p, 's, 'o>,
    watcher: domain::RemoteRenameReceiptWatcher<'d, 'o>,
    post: PeerJournalRows,
    local: lomi_host_auth::peer_policy::LocalWorkspace,
    running: Vec<TerminalContext>,
    request: lomi_remote_protocol::rpc::RpcRequest,
    receipt: OperationReceipt,
    connection: uuid::Uuid,
    /// File operations only: a durable known-no-effect receipt is answered with
    /// this error through the same sealed delivery (the journal write that
    /// recorded it invalidated the ordinary response proof).
    refusal: Option<lomi_remote_protocol::RemoteError>,
}
pub(super) struct RemoteRenameReceiptTurn<'d, 'o, 'r, 'e, 'w, 'p, 's> {
    guard: domain::OwnerGuard<'d, 'o>,
    snapshot: domain::Snapshot<'d, 'o>,
    receipt: &'r RemoteRenameReceipt<'d, 'o, 'e, 'w, 'p, 's>,
    floor: u64,
}
pub(super) struct RemoteRenameIoWatch<'d, 'o, 'e, 'w, 'p, 's> {
    atoms: RemoteRenameIoAtoms<'d, 'o>,
    worker: &'e super::auth::RemoteWorkerEvidence<'w, 'p, 's, 'o>,
}
pub(super) struct RemoteRenameIoAtoms<'d, 'o> {
    watcher: domain::RemoteRenameReceiptWatcher<'d, 'o>,
    gate: &'o std::sync::atomic::AtomicBool,
    paused: &'o std::sync::atomic::AtomicBool,
    stopping: &'o std::sync::atomic::AtomicBool,
    public_pending: &'o std::sync::atomic::AtomicBool,
}
fn rename_rights_match(
    a: &lomi_remote_protocol::StoredOperationRights,
    b: &lomi_remote_protocol::StoredOperationRights,
) -> bool {
    a.operation_id() == b.operation_id()
        && a.actor() == b.actor()
        && a.workspace() == b.workspace()
        && a.original_method() == b.original_method()
        && a.actual_rights() == b.actual_rights()
        && a.repository_execution() == b.repository_execution()
}
fn rename_public_current(store: &HostStore, rows: &PeerJournalRows) -> Result<(), Error> {
    let public = store.public_current().map_err(Error::UncertainStore)?;
    let state = store
        .public_configuration_state()
        .map_err(Error::UncertainStore)?;
    if !store
        .public_configuration_ready()
        .map_err(Error::UncertainStore)?
        || public
            .configuration()
            .map_err(Error::UncertainStore)?
            .authentication
            .as_ref()
            != rows.configuration.as_ref()
        || !state
            .as_ref()
            .is_some_and(|s| s.prepared.is_none() && s.current.as_ref() == Some(&public))
        || store
            .login_intent()
            .map_err(Error::UncertainStore)?
            .is_some()
    {
        return Err(Error::Domain(domain::Error::Stale));
    }
    Ok(())
}
impl SharedOwner {
    /// Caller holds workspace actor. Reads/duplicate disclosure happen before
    /// actual Shared registration; no reader is retained beneath the writer.
    pub(super) fn begin_remote_terminal_rename<'d, 'o, 'e, 'w, 'p, 's>(
        &'d self,
        worker: &'e super::auth::RemoteWorkerEvidence<'w, 'p, 's, 'o>,
        peer: &'e super::auth::peer::VerifiedCurrentPeer,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        original: &lomi_remote_protocol::rpc::RpcRequest,
        queued: &super::auth::remote_connection::QueuedRequest,
    ) -> Result<RemoteRenameBegin<'d, 'o, 'e, 'w, 'p, 's>, RemoteRenameError> {
        if !matches!(
            original.call,
            lomi_remote_protocol::rpc::RpcCall::TerminalRename(_)
        ) {
            return Err(RemoteRenameError::Closed);
        }
        self.begin_remote_terminal_edit(worker, peer, connection, original, queued)
    }
    /// Caller holds workspace actor. Reads/duplicate disclosure happen before
    /// actual Shared registration; no reader is retained beneath the writer.
    pub(super) fn begin_remote_terminal_move<'d, 'o, 'e, 'w, 'p, 's>(
        &'d self,
        worker: &'e super::auth::RemoteWorkerEvidence<'w, 'p, 's, 'o>,
        peer: &'e super::auth::peer::VerifiedCurrentPeer,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        original: &lomi_remote_protocol::rpc::RpcRequest,
        queued: &super::auth::remote_connection::QueuedRequest,
    ) -> Result<RemoteRenameBegin<'d, 'o, 'e, 'w, 'p, 's>, RemoteRenameError> {
        if !matches!(
            original.call,
            lomi_remote_protocol::rpc::RpcCall::TerminalMove(_)
        ) {
            return Err(RemoteRenameError::Closed);
        }
        self.begin_remote_terminal_edit(worker, peer, connection, original, queued)
    }
    /// Caller holds workspace actor. Reads/duplicate disclosure happen before
    /// actual Shared registration; no reader is retained beneath the writer.
    fn begin_remote_terminal_edit<'d, 'o, 'e, 'w, 'p, 's>(
        &'d self,
        worker: &'e super::auth::RemoteWorkerEvidence<'w, 'p, 's, 'o>,
        peer: &'e super::auth::peer::VerifiedCurrentPeer,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        original: &lomi_remote_protocol::rpc::RpcRequest,
        queued: &super::auth::remote_connection::QueuedRequest,
    ) -> Result<RemoteRenameBegin<'d, 'o, 'e, 'w, 'p, 's>, RemoteRenameError> {
        use super::remote_terminal_rename::RemoteTerminalEdit;
        let edit = RemoteTerminalEdit::from_call(&original.call)?;
        let mutation = edit.mutation();
        let turn = self.try_remote_workspace_turn(worker, peer, &mutation.context)?;
        turn.check()?;
        let (request, expiry) = connection.before_remote_rename(
            queued,
            worker.operation(),
            &turn.facts(),
            &mut || turn.now(),
        )?;
        if &request != original {
            return Err(RemoteRenameError::Closed);
        }
        let rights = match edit.method().rights() {
            lomi_remote_protocol::MethodRights::Static(value) => value
                .to_vec()
                .try_into()
                .map_err(|_| RemoteRenameError::Closed)?,
            _ => return Err(RemoteRenameError::Closed),
        };
        let binding = OperationBinding {
            rights: lomi_remote_protocol::StoredOperationRights::new(
                mutation.operation_id,
                connection.consumer_actor(),
                mutation.context.workspace_id,
                edit.method(),
                rights,
                false,
            )
            .map_err(|_| RemoteRenameError::Closed)?,
            parameter_hash: lomi_host_store::parameter_hash(&request.call)
                .map_err(|e| RemoteRenameError::Owner(Error::Store(e)))?,
        };
        let store = self.try_store()?;
        turn.guard
            .validate_current(&turn.snapshot)
            .map_err(|e| RemoteRenameError::Owner(Error::Domain(e)))?;
        let exact = store
            .lookup(&binding, &peer.grant().capabilities)
            .map_err(|e| RemoteRenameError::Owner(Error::Store(e)))?;
        let existing = store
            .lookup_operation(
                binding.rights.actor(),
                binding.rights.workspace(),
                binding.rights.operation_id(),
                &peer.grant().capabilities,
            )
            .map_err(|e| RemoteRenameError::Owner(Error::Store(e)))?;
        // Preserve generic lookup privacy: absence alone never proves no conflict.
        if let Some(receipt) = exact {
            turn.check()?;
            return Ok(RemoteRenameBegin::Duplicate(receipt));
        }
        if existing.is_some() {
            return Err(RemoteRenameError::Owner(Error::Store(
                StoreError::IdempotencyConflict,
            )));
        }
        // Duplicate lookup precedes all layout membership/CAS checks. Move's
        // complete membership and pure layout validation run at Store commit.
        if let RemoteTerminalEdit::Rename(params) = &edit
            && !turn
                .state
                .tabs
                .0
                .iter()
                .any(|tab| tab.tab_id == params.tab_id)
        {
            // Nothing is announced, journaled or executed; authority must still
            // be current before this error oracle is answered.
            drop(store);
            turn.check()?;
            return Ok(RemoteRenameBegin::Rejected(super::rpc::stored_rejection(
                StoreError::NotFound,
            )?));
        }
        drop(store);
        turn.check()?;
        let pending = turn
            .guard
            .begin_remote_rename(turn.snapshot, peer.continuation(), expiry.deadline())
            .map_err(|e| RemoteRenameError::Owner(Error::Domain(e)))?;
        Ok(RemoteRenameBegin::Write(Box::new(
            RemoteTerminalRenameWrite {
                owner: self,
                worker,
                pending: Some(pending),
                before: turn.rows,
                local: turn.local,
                running: turn.running,
                request,
                binding,
                connection: connection.connection_identity(),
                closed: false,
                rejection: None,
            },
        )))
    }
}
impl<'d, 'o, 'e, 'w, 'p, 's> RemoteTerminalRenameWrite<'d, 'o, 'e, 'w, 'p, 's> {
    pub(super) fn try_commit(
        &mut self,
    ) -> Result<RemoteRenameReceipt<'d, 'o, 'e, 'w, 'p, 's>, RemoteRenameError> {
        if self.closed {
            return Err(RemoteRenameError::Closed);
        }
        let result = self.try_phase();
        let busy = matches!(
            result,
            Err(RemoteRenameError::Owner(Error::Domain(domain::Error::Busy)))
                | Err(RemoteRenameError::Owner(Error::Store(StoreError::Busy)))
        );
        if busy
            && self
                .pending
                .as_ref()
                .is_some_and(|p| p.phase() == domain::RemoteRenamePhase::StoreNotCalled)
        {
            return Err(match result {
                Err(error) => error,
                Ok(_) => unreachable!(),
            });
        }
        let result = if busy {
            Err(RemoteRenameError::Owner(Error::UncertainStore(
                StoreError::Busy,
            )))
        } else {
            result
        };
        if matches!(
            result,
            Err(RemoteRenameError::Owner(Error::UncertainStore(_)))
        ) {
            self.owner.domain.cloud_uncertain();
        }
        self.closed = true;
        match result {
            Ok((admission, post)) => {
                let pending = self.pending.take().ok_or(RemoteRenameError::Closed)?;
                let stamp = pending
                    .finish()
                    .map_err(|e| RemoteRenameError::Owner(Error::Domain(e)))?;
                Ok(RemoteRenameReceipt {
                    owner: self.owner,
                    worker: self.worker,
                    watcher: stamp.into_io_watcher(),
                    post,
                    local: self.local.clone(),
                    running: self.running.clone(),
                    request: self.request.clone(),
                    receipt: admission.receipt,
                    connection: self.connection,
                    refusal: None,
                })
            }
            Err(error) => {
                if let Some(pending) = self.pending.take()
                    && matches!(
                        pending.phase(),
                        domain::RemoteRenamePhase::StoreNotCalled
                            | domain::RemoteRenamePhase::KnownNoEffect
                    )
                {
                    // A stale CAS, missing target or invalid layout is a known
                    // no-effect Store refusal: nothing was journaled or run.
                    if pending.phase() == domain::RemoteRenamePhase::KnownNoEffect
                        && let RemoteRenameError::Owner(Error::Store(refused)) = &error
                    {
                        self.rejection = self.refusal_for(refused);
                    }
                    let _ = pending.abandon();
                }
                // Committed/Uncertain Drop fences and preserves durable receipt.
                Err(error)
            }
        }
    }
    /// Ordinary-response form of a known no-effect Store refusal, or None when
    /// the failure must keep the closed withhold-and-dispose behavior.
    fn refusal_for(&self, error: &StoreError) -> Option<lomi_remote_protocol::RemoteError> {
        let stale = match (error, &self.request.call) {
            (
                StoreError::RevisionConflict,
                lomi_remote_protocol::rpc::RpcCall::TerminalRename(p),
            ) => Some(p.mutation.expected_revision),
            (StoreError::RevisionConflict, lomi_remote_protocol::rpc::RpcCall::TerminalMove(p)) => {
                Some(p.mutation.expected_revision)
            }
            _ => None,
        };
        let refusal = match stale {
            Some(expected) => super::rpc::revision_conflict(
                expected,
                self.before.local.as_ref()?.state.domain_revision,
            ),
            None => super::rpc::stored(*error),
        };
        super::rpc::pre_effect_rejection(refusal)
    }
    /// Known no-effect refusal recorded by the failed `try_commit`, if any.
    pub(super) fn take_rejection(&mut self) -> Option<lomi_remote_protocol::RemoteError> {
        self.rejection.take()
    }
    fn try_phase(&mut self) -> Result<(Admission, PeerJournalRows), RemoteRenameError> {
        let pending = self.pending.as_mut().ok_or(RemoteRenameError::Closed)?;
        let mut guard = pending
            .try_enter()
            .map_err(|e| RemoteRenameError::Owner(Error::Domain(e)))?;
        let mut store = self.owner.try_store()?;
        guard
            .check_current()
            .map_err(|e| RemoteRenameError::Owner(Error::Domain(e)))?;
        let current = PeerJournalRows::read(
            &store,
            self.worker.eligibility(),
            self.binding.rights.workspace(),
        )
        .map_err(|e| RemoteRenameError::Owner(Error::UncertainStore(e)))?;
        if !self.before.current(&current) || !self.worker.current() {
            return Err(RemoteRenameError::Closed);
        }
        rename_public_current(&store, &current)?;
        guard
            .check_current()
            .map_err(|e| RemoteRenameError::Owner(Error::Domain(e)))?;
        if !self.worker.current() {
            return Err(RemoteRenameError::Closed);
        }
        use super::remote_terminal_rename::RemoteTerminalEdit;
        let edit = RemoteTerminalEdit::from_call(&self.request.call)?;
        let move_events = if matches!(&edit, RemoteTerminalEdit::Move(_)) {
            Some(
                store
                    .events_after(0)
                    .map_err(|e| RemoteRenameError::Owner(Error::UncertainStore(e)))?,
            )
        } else {
            None
        };
        let admission = match &edit {
            RemoteTerminalEdit::Rename(_) => {
                guard.commit(&mut store, &self.binding, &self.request.call)
            }
            RemoteTerminalEdit::Move(_) => {
                guard.commit_move(&mut store, &self.binding, &self.request.call)
            }
            // Effect operations never take the single-transaction commit.
            RemoteTerminalEdit::Create(_)
            | RemoteTerminalEdit::Split(_)
            | RemoteTerminalEdit::Close(_)
            | RemoteTerminalEdit::Restart(_) => return Err(RemoteRenameError::Closed),
        }
        .map_err(|error| match error {
            StepError::Domain(error) => RemoteRenameError::Owner(Error::Domain(error)),
            StepError::Source(error) => RemoteRenameError::Owner(Error::Store(error)),
        })?;
        let post = PeerJournalRows::read(
            &store,
            self.worker.eligibility(),
            self.binding.rights.workspace(),
        )
        .map_err(|e| {
            self.owner.domain.cloud_uncertain();
            RemoteRenameError::Owner(Error::UncertainStore(e))
        })?;
        let mut expected = self.before.clone();
        let local = expected.local.as_mut().ok_or(RemoteRenameError::Closed)?;
        local.state = edit.expected_state(&local.state)?;
        if !admission.newly_admitted
            || admission.receipt.state() != OperationState::Succeeded
            || admission.receipt.effect() != Effect::Committed
            || !rename_rights_match(&admission.receipt.stored_rights(), &self.binding.rights)
            || post.outbox.len() != 1
            || !self.before.outbox.is_empty()
            || !post.outbox.iter().all(|p| {
                p.workspace_id == self.binding.rights.workspace()
                    && p.fence == local.fence
                    && p.enabled == local.consent
                    && p.domain_revision == local.state.domain_revision
                    && !p.token.is_empty()
            })
        {
            self.owner.domain.cloud_uncertain();
            return Err(RemoteRenameError::Closed);
        }
        if let Some(before_events) = move_events {
            let expected_receipt = OperationReceipt::new(
                &self.binding.rights,
                self.binding.parameter_hash.clone(),
                OperationState::Succeeded,
                false,
                Effect::Committed,
                Some(lomi_remote_protocol::OperationResult::Domain {
                    domain_revision: local.state.domain_revision,
                }),
            )
            .map_err(|_| RemoteRenameError::Closed)?;
            let after_events = store.events_after(0).map_err(|e| {
                self.owner.domain.cloud_uncertain();
                RemoteRenameError::Owner(Error::UncertainStore(e))
            })?;
            let exact_receipt = store
                .lookup(&self.binding, self.binding.rights.actual_rights())
                .map_err(|e| {
                    self.owner.domain.cloud_uncertain();
                    RemoteRenameError::Owner(Error::UncertainStore(e))
                })?;
            let prefix_exact =
                before_events
                    .events
                    .iter()
                    .zip(&after_events.events)
                    .all(|(a, b)| {
                        a.sequence == b.sequence
                            && a.workspace_id == b.workspace_id
                            && a.operation_id == b.operation_id
                            && a.domain_revision == b.domain_revision
                    });
            let new_event = after_events.events.last();
            if admission.receipt != expected_receipt
                || exact_receipt.as_ref() != Some(&expected_receipt)
                || before_events.low_watermark != after_events.low_watermark
                || after_events.events.len() != before_events.events.len() + 1
                || !prefix_exact
                || !new_event.is_some_and(|event| {
                    event.sequence
                        > before_events
                            .events
                            .last()
                            .map_or(before_events.low_watermark, |e| e.sequence)
                        && event.workspace_id == self.binding.rights.workspace()
                        && event.operation_id == Some(self.binding.rights.operation_id())
                        && event.domain_revision == local.state.domain_revision
                })
            {
                self.owner.domain.cloud_uncertain();
                return Err(RemoteRenameError::Closed);
            }
        }
        expected.outbox = post.outbox.clone();
        if !expected.current(&post) || !self.worker.current() {
            self.owner.domain.cloud_uncertain();
            return Err(RemoteRenameError::Closed);
        }
        rename_public_current(&store, &post)?;
        Ok((admission, post))
    }
}
impl<'d, 'o, 'e, 'w, 'p, 's> RemoteRenameReceipt<'d, 'o, 'e, 'w, 'p, 's> {
    pub(super) fn response(&self) -> lomi_remote_protocol::rpc::RpcResponse {
        if let Some(error) = &self.refusal {
            return lomi_remote_protocol::rpc::RpcResponse::Error {
                v: self.request.v,
                request_id: self.request.request_id.clone(),
                operation_id: Some(self.receipt.operation_id()),
                error: error.clone(),
            };
        }
        lomi_remote_protocol::rpc::RpcResponse::Result {
            v: self.request.v,
            request_id: self.request.request_id.clone(),
            result: match &self.request.call {
                lomi_remote_protocol::rpc::RpcCall::TerminalRename(_) => {
                    lomi_remote_protocol::rpc::RpcResult::TerminalRename(self.receipt.clone())
                }
                lomi_remote_protocol::rpc::RpcCall::TerminalMove(_) => {
                    lomi_remote_protocol::rpc::RpcResult::TerminalMove(self.receipt.clone())
                }
                lomi_remote_protocol::rpc::RpcCall::TerminalCreate(_) => {
                    lomi_remote_protocol::rpc::RpcResult::TerminalCreate(self.receipt.clone())
                }
                lomi_remote_protocol::rpc::RpcCall::TerminalSplit(_) => {
                    lomi_remote_protocol::rpc::RpcResult::TerminalSplit(self.receipt.clone())
                }
                lomi_remote_protocol::rpc::RpcCall::TerminalClose(_) => {
                    lomi_remote_protocol::rpc::RpcResult::TerminalClose(self.receipt.clone())
                }
                lomi_remote_protocol::rpc::RpcCall::TerminalRestart(_) => {
                    lomi_remote_protocol::rpc::RpcResult::TerminalRestart(self.receipt.clone())
                }
                lomi_remote_protocol::rpc::RpcCall::FilesCreate(_) => {
                    lomi_remote_protocol::rpc::RpcResult::FilesCreate(self.receipt.clone())
                }
                lomi_remote_protocol::rpc::RpcCall::FilesMkdir(_) => {
                    lomi_remote_protocol::rpc::RpcResult::FilesMkdir(self.receipt.clone())
                }
                lomi_remote_protocol::rpc::RpcCall::FilesRename(_) => {
                    lomi_remote_protocol::rpc::RpcResult::FilesRename(self.receipt.clone())
                }
                lomi_remote_protocol::rpc::RpcCall::FilesRemove(_) => {
                    lomi_remote_protocol::rpc::RpcResult::FilesRemove(self.receipt.clone())
                }
                _ => unreachable!("receipt constructed only by the closed edit boundary"),
            },
        }
    }
    pub(super) fn capture<'r>(
        &'r self,
    ) -> Result<RemoteRenameReceiptTurn<'d, 'o, 'r, 'e, 'w, 'p, 's>, RemoteRenameError> {
        let (method, operation_id) = match &self.request.call {
            lomi_remote_protocol::rpc::RpcCall::FilesCreate(p)
            | lomi_remote_protocol::rpc::RpcCall::FilesMkdir(p) => {
                (self.request.call.method(), p.mutation.operation_id)
            }
            lomi_remote_protocol::rpc::RpcCall::FilesRename(p) => {
                (self.request.call.method(), p.mutation.operation_id)
            }
            lomi_remote_protocol::rpc::RpcCall::FilesRemove(p) => {
                (self.request.call.method(), p.mutation.operation_id)
            }
            call => {
                let edit = super::remote_terminal_rename::RemoteTerminalEdit::from_call(call)?;
                (edit.method(), edit.mutation().operation_id)
            }
        };
        if self.receipt.stored_rights().original_method() != method
            || self.receipt.stored_rights().operation_id() != operation_id
        {
            return Err(RemoteRenameError::Closed);
        }
        let guard = self
            .owner
            .domain
            .try_read(self.worker.operation())
            .map_err(|e| RemoteRenameError::Owner(Error::Domain(e)))?;
        let store = self.owner.try_store()?;
        let floor = self
            .watcher
            .validate(&guard, &store)
            .map_err(peer_store_step)?;
        let current =
            PeerJournalRows::read(&store, self.worker.eligibility(), self.local.workspace_id)
                .map_err(|e| RemoteRenameError::Owner(Error::UncertainStore(e)))?;
        if !self.post.current(&current) || !self.worker.current() {
            return Err(RemoteRenameError::Closed);
        }
        rename_public_current(&store, &current)?;
        let snapshot = guard
            .capture_remote(|| StoreView::read(&store))
            .map_err(|e| RemoteRenameError::Owner(Error::from(e)))?;
        guard
            .validate_current(&snapshot)
            .map_err(|e| RemoteRenameError::Owner(Error::Domain(e)))?;
        drop(store);
        Ok(RemoteRenameReceiptTurn {
            guard,
            snapshot,
            receipt: self,
            floor,
        })
    }
    pub(super) fn into_io_watch(self) -> RemoteRenameIoWatch<'d, 'o, 'e, 'w, 'p, 's> {
        RemoteRenameIoWatch {
            atoms: RemoteRenameIoAtoms {
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
impl RemoteRenameIoWatch<'_, '_, '_, '_, '_, '_> {
    /// Actual socket boundary. No Domain/Store/provider IO is permitted here.
    pub(super) fn check(&self) -> Result<(), super::auth::remote_connection::GateError> {
        if self.atoms.check().is_err() || !self.worker.current() || self.atoms.check().is_err() {
            return Err(super::auth::remote_connection::GateError::Disposed);
        }
        Ok(())
    }
    pub(super) fn atoms(&self) -> &RemoteRenameIoAtoms<'_, '_> {
        &self.atoms
    }
}
impl RemoteRenameIoAtoms<'_, '_> {
    pub(super) fn deadline(&self) -> std::time::Instant {
        self.watcher.deadline()
    }
    pub(super) fn check(&self) -> Result<(), lomi_host_http::BudgetStop> {
        use std::sync::atomic::Ordering::Acquire;
        let map = |error| {
            if matches!(error, domain::Error::Deadline) {
                lomi_host_http::BudgetStop::Deadline
            } else {
                lomi_host_http::BudgetStop::Cancelled
            }
        };
        self.watcher.check().map_err(map)?;
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
impl RemoteRenameReceiptTurn<'_, '_, '_, '_, '_, '_, '_> {
    pub(super) fn current_for(&self, connection: uuid::Uuid) -> bool {
        self.receipt.connection == connection
            && self.guard.validate_current(&self.snapshot).is_ok()
            && self.receipt.watcher.check().is_ok()
            && self.receipt.worker.current()
            && self
                .receipt
                .worker
                .now()
                .is_some_and(|n| n.wall.as_secs() >= self.floor)
    }
    pub(super) fn matches(&self, receipt: &RemoteRenameReceipt<'_, '_, '_, '_, '_, '_>) -> bool {
        std::ptr::eq(
            self.receipt as *const _ as *const (),
            receipt as *const _ as *const (),
        )
    }
    pub(super) fn sample(&self) -> super::auth::remote_connection::TrustedNow {
        self.receipt
            .worker
            .now()
            .filter(|_| self.current_for(self.receipt.connection))
            .unwrap_or(super::auth::remote_connection::TrustedNow {
                wall: std::time::Duration::ZERO,
                monotonic: std::time::Instant::now(),
            })
    }
    pub(super) fn facts(&self) -> super::auth::remote_connection::OwnerFacts<'_> {
        let r = self.receipt;
        let e = r.worker.eligibility();
        let d = r.worker.provider().captured_deadlines();
        super::auth::remote_connection::OwnerFacts {
            protected_host: &e.identity,
            origin: r.worker.origin(),
            scope: &e.binding.scope,
            runtime: &e.binding.server_runtime,
            heartbeat: &e.heartbeat,
            acknowledged: &e.publication,
            local: &r.local,
            running: &r.running,
            auth_ready: true,
            access_expires_at: d.access_expires_at,
            refresh_at: d.refresh_at,
            authorization_locked: r.post.authorization.locked,
            pending_login: false,
            pending_logout: false,
            pending_revoke: r.post.authorization.pending_cloud_revoke,
            pending_publication: r.post.host_pending.is_some() || !r.post.outbox.is_empty(),
            peer_revoked: false,
            gate_denied: r.worker.gate_denied(),
            paused: r.worker.paused(),
            stopping: r.worker.stopping(),
            cancelled: r.worker.operation().cancellation_latch(),
        }
    }
}

impl Drop for RemoteTerminalRenameWrite<'_, '_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take()
            && matches!(
                pending.phase(),
                domain::RemoteRenamePhase::StoreNotCalled
                    | domain::RemoteRenamePhase::KnownNoEffect
            )
        {
            let _ = pending.abandon();
        }
        // Actual Committed/Uncertain unfinished ownership retains existing
        // conservative fail-closed Drop behavior; never invent completion.
    }
}

// Closed OS-effect lifecycle boundary (terminal.create/split/close/restart).
// One retained Shared announcement spans start -> physical effect -> completion.
// Between the two Store turns Domain/Store are released and the effect is gated
// only by the lock-free `effect_current` predicate. No local dispatch, no generic
// outbox/peer exception, and no automatic replay of an uncertain effect.

/// Everything the effect needs, computed from verified rows BEFORE the writer is
/// registered. Request fields never reach a shell path, argv, cwd or env.
pub(super) struct RemoteLifecyclePlan {
    pub(super) before: WorkspaceState,
    pub(super) plan: super::rpc::Plan,
    pub(super) profile: Option<lomi_terminal::SpawnProfile>,
}
/// Final durable outcome to persist for the retained permit.
#[derive(Clone)]
pub(super) struct RemoteEffectOutcome {
    pub(super) state: OperationState,
    pub(super) effect: lomi_remote_protocol::Effect,
    pub(super) result: Option<OperationResult>,
    pub(super) projection: Option<WorkspaceState>,
}
pub(super) enum RemoteEffectBegin<'d, 'o, 'e, 'w, 'p, 's> {
    Duplicate(OperationReceipt),
    /// Planning failed before anything was journaled or executed. Every turn is
    /// already dropped; the caller answers with an ordinary error response.
    Rejected(lomi_remote_protocol::RemoteError),
    Write(Box<RemoteTerminalEffectWrite<'d, 'o, 'e, 'w, 'p, 's>>),
}
pub(super) enum RemoteEffectCompletion<'d, 'o, 'e, 'w, 'p, 's> {
    /// Succeeded/Committed: eligible for the sealed own-publication delivery.
    Delivered(Box<RemoteRenameReceipt<'d, 'o, 'e, 'w, 'p, 's>>),
    /// Durable final receipt that is not a committed success. Nothing is sent
    /// on this connection; a reconnect retrieves it by exact duplicate lookup.
    Settled,
}
/// Host-resolved file mutation: the exact request plus the pinned root inputs.
#[derive(Clone)]
pub(super) struct RemoteFilePlan {
    pub(super) call: lomi_remote_protocol::rpc::RpcCall,
    pub(super) workspace_id: lomi_remote_protocol::WorkspaceId,
    pub(super) epoch: lomi_remote_protocol::WorkspaceEpoch,
    pub(super) root: std::path::PathBuf,
}
pub(super) struct RemoteTerminalEffectWrite<'d, 'o, 'e, 'w, 'p, 's> {
    owner: &'d SharedOwner,
    worker: &'e super::auth::RemoteWorkerEvidence<'w, 'p, 's, 'o>,
    peer: &'e super::auth::peer::VerifiedCurrentPeer,
    pending: Option<domain::RemoteRenameWrite<'d, 'o>>,
    before: PeerJournalRows,
    request: lomi_remote_protocol::rpc::RpcRequest,
    binding: OperationBinding,
    connection: uuid::Uuid,
    workspace: lomi_remote_protocol::WorkspaceContext,
    /// `None` for file operations (their preconditions are file revisions).
    expected_revision: Option<lomi_remote_protocol::DecimalU64>,
    plan: RemoteLifecyclePlan,
    file: Option<RemoteFilePlan>,
    namespace: Option<lomi_host_store::RemoteDesktopNamespacePlan>,
    namespace_projects: Vec<ProjectRecord>,
    refusal: Option<lomi_remote_protocol::RemoteError>,
    permit: Option<ExternalPermit>,
    started: bool,
    closed: bool,
}

impl SharedOwner {
    /// Caller holds the workspace actor. Reads and duplicate disclosure happen
    /// before actual Shared registration; no reader is retained beneath the writer.
    pub(super) fn begin_remote_terminal_lifecycle<'d, 'o, 'e, 'w, 'p, 's>(
        &'d self,
        worker: &'e super::auth::RemoteWorkerEvidence<'w, 'p, 's, 'o>,
        peer: &'e super::auth::peer::VerifiedCurrentPeer,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        original: &lomi_remote_protocol::rpc::RpcRequest,
        queued: &super::auth::remote_connection::QueuedRequest,
    ) -> Result<RemoteEffectBegin<'d, 'o, 'e, 'w, 'p, 's>, RemoteRenameError> {
        use super::remote_terminal_rename::RemoteTerminalEdit;
        let edit = RemoteTerminalEdit::from_call(&original.call)?;
        if !edit.is_effect() {
            return Err(RemoteRenameError::Closed);
        }
        let mutation = edit.mutation();
        let turn = self.try_remote_workspace_turn(worker, peer, &mutation.context)?;
        turn.check()?;
        let (request, expiry) = connection.before_remote_rename(
            queued,
            worker.operation(),
            &turn.facts(),
            &mut || turn.now(),
        )?;
        if &request != original {
            return Err(RemoteRenameError::Closed);
        }
        let rights = match edit.method().rights() {
            lomi_remote_protocol::MethodRights::Static(value) => value
                .to_vec()
                .try_into()
                .map_err(|_| RemoteRenameError::Closed)?,
            _ => return Err(RemoteRenameError::Closed),
        };
        let binding = OperationBinding {
            rights: lomi_remote_protocol::StoredOperationRights::new(
                mutation.operation_id,
                connection.consumer_actor(),
                mutation.context.workspace_id,
                edit.method(),
                rights,
                false,
            )
            .map_err(|_| RemoteRenameError::Closed)?,
            parameter_hash: lomi_host_store::parameter_hash(&request.call)
                .map_err(|e| RemoteRenameError::Owner(Error::Store(e)))?,
        };
        let store = self.try_store()?;
        turn.guard
            .validate_current(&turn.snapshot)
            .map_err(|e| RemoteRenameError::Owner(Error::Domain(e)))?;
        let exact = store
            .lookup(&binding, &peer.grant().capabilities)
            .map_err(|e| RemoteRenameError::Owner(Error::Store(e)))?;
        let existing = store
            .lookup_operation(
                binding.rights.actor(),
                binding.rights.workspace(),
                binding.rights.operation_id(),
                &peer.grant().capabilities,
            )
            .map_err(|e| RemoteRenameError::Owner(Error::Store(e)))?;
        // Preserve generic lookup privacy: absence alone never proves no conflict.
        if let Some(receipt) = exact {
            turn.check()?;
            return Ok(RemoteEffectBegin::Duplicate(receipt));
        }
        if existing.is_some() {
            return Err(RemoteRenameError::Owner(Error::Store(
                StoreError::IdempotencyConflict,
            )));
        }
        // Plan against the verified LOCAL record only after duplicate lookup. A
        // plan error is a closed withhold: nothing was journaled or executed.
        let project = turn.rows.local.as_ref().ok_or(RemoteRenameError::Closed)?;
        let before = project.state.clone();
        let plan = match super::rpc::plan_remote(&request.call, project, &turn.workspace) {
            Ok(plan) => plan,
            Err(error) => {
                let Some(rejection) = super::rpc::pre_effect_rejection(error) else {
                    return Err(RemoteRenameError::Closed);
                };
                // Authority must still be current before an error oracle is
                // answered; nothing is announced, journaled or executed.
                drop(store);
                turn.check()?;
                return Ok(RemoteEffectBegin::Rejected(rejection));
            }
        };
        enum SpawnProfileSource {
            Default(lomi_host_store::DefaultShellProfile),
            Registered(
                lomi_remote_protocol::ipc::LocalShellProfileRegister,
                Option<std::path::PathBuf>,
            ),
        }
        let profile_source = if let Some((_, profile_id)) = &plan.spawn {
            if profile_id.as_str() == "default" {
                Some(SpawnProfileSource::Default(
                    store
                        .default_shell()
                        .map_err(|e| RemoteRenameError::Owner(Error::Store(e)))?
                        .ok_or(RemoteRenameError::Closed)?,
                ))
            } else {
                let (configured, cwd_override) = store
                    .shell_profile_with_cwd_override(project.state.context.workspace_id, profile_id)
                    .map_err(|e| RemoteRenameError::Owner(Error::Store(e)))?
                    .ok_or(RemoteRenameError::Closed)?;
                Some(SpawnProfileSource::Registered(configured, cwd_override))
            }
        } else {
            None
        };
        drop(store);
        let profile = profile_source
            .map(|source| match source {
                SpawnProfileSource::Default(shell) => super::rpc::spawn_profile(&shell, project),
                SpawnProfileSource::Registered(configured, Some(cwd_override)) => {
                    super::rpc::configured_spawn_profile_with_cwd_override(
                        &configured,
                        project,
                        &cwd_override,
                    )
                }
                SpawnProfileSource::Registered(configured, None) => {
                    super::rpc::configured_spawn_profile(&configured, project)
                }
            })
            .transpose()
            .map_err(|_| RemoteRenameError::Closed)?;
        turn.check()?;
        let pending = turn
            .guard
            .begin_remote_rename(turn.snapshot, peer.continuation(), expiry.deadline())
            .map_err(|e| RemoteRenameError::Owner(Error::Domain(e)))?;
        Ok(RemoteEffectBegin::Write(Box::new(
            RemoteTerminalEffectWrite {
                owner: self,
                worker,
                peer,
                pending: Some(pending),
                before: turn.rows,
                request,
                binding,
                connection: connection.connection_identity(),
                workspace: turn.workspace,
                expected_revision: Some(mutation.expected_revision),
                file: None,
                namespace: None,
                namespace_projects: Vec::new(),
                refusal: None,
                plan: RemoteLifecyclePlan {
                    before,
                    plan,
                    profile,
                },
                permit: None,
                started: false,
                closed: false,
            },
        )))
    }
}

impl SharedOwner {
    /// File create/mkdir/rename/remove. Same closed boundary as terminal
    /// lifecycle: duplicate lookup first, one retained Shared announcement,
    /// atomic admit+start. Preconditions are file revisions checked by the
    /// engine at the effect, never the workspace domain revision.
    pub(super) fn begin_remote_file_mutation<'d, 'o, 'e, 'w, 'p, 's>(
        &'d self,
        worker: &'e super::auth::RemoteWorkerEvidence<'w, 'p, 's, 'o>,
        peer: &'e super::auth::peer::VerifiedCurrentPeer,
        connection: &mut super::auth::remote_connection::RemoteConnectionState,
        original: &lomi_remote_protocol::rpc::RpcRequest,
        queued: &super::auth::remote_connection::QueuedRequest,
    ) -> Result<RemoteEffectBegin<'d, 'o, 'e, 'w, 'p, 's>, RemoteRenameError> {
        use lomi_remote_protocol::rpc::RpcCall;
        let (operation_id, context) = match &original.call {
            RpcCall::FilesCreate(p) | RpcCall::FilesMkdir(p) => {
                (p.mutation.operation_id, &p.mutation.context)
            }
            RpcCall::FilesRename(p) => (p.mutation.operation_id, &p.mutation.context),
            RpcCall::FilesRemove(p) => (p.mutation.operation_id, &p.mutation.context),
            _ => return Err(RemoteRenameError::Closed),
        };
        let method = original.call.method();
        let turn = self.try_remote_workspace_turn(worker, peer, context)?;
        turn.check()?;
        let (request, expiry) = connection.before_remote_rename(
            queued,
            worker.operation(),
            &turn.facts(),
            &mut || turn.now(),
        )?;
        if &request != original {
            return Err(RemoteRenameError::Closed);
        }
        let rights = match method.rights() {
            lomi_remote_protocol::MethodRights::Static(value) => value
                .to_vec()
                .try_into()
                .map_err(|_| RemoteRenameError::Closed)?,
            _ => return Err(RemoteRenameError::Closed),
        };
        let binding = OperationBinding {
            rights: lomi_remote_protocol::StoredOperationRights::new(
                operation_id,
                connection.consumer_actor(),
                context.workspace_id,
                method,
                rights,
                false,
            )
            .map_err(|_| RemoteRenameError::Closed)?,
            parameter_hash: lomi_host_store::parameter_hash(&request.call)
                .map_err(|e| RemoteRenameError::Owner(Error::Store(e)))?,
        };
        let store = self.try_store()?;
        turn.guard
            .validate_current(&turn.snapshot)
            .map_err(|e| RemoteRenameError::Owner(Error::Domain(e)))?;
        let exact = store
            .lookup(&binding, &peer.grant().capabilities)
            .map_err(|e| RemoteRenameError::Owner(Error::Store(e)))?;
        let existing = store
            .lookup_operation(
                binding.rights.actor(),
                binding.rights.workspace(),
                binding.rights.operation_id(),
                &peer.grant().capabilities,
            )
            .map_err(|e| RemoteRenameError::Owner(Error::Store(e)))?;
        if let Some(receipt) = exact {
            turn.check()?;
            return Ok(RemoteEffectBegin::Duplicate(receipt));
        }
        if existing.is_some() {
            return Err(RemoteRenameError::Owner(Error::Store(
                StoreError::IdempotencyConflict,
            )));
        }
        let project = turn.rows.local.as_ref().ok_or(RemoteRenameError::Closed)?;
        let before = project.state.clone();
        let file = RemoteFilePlan {
            call: request.call.clone(),
            workspace_id: project.state.context.workspace_id,
            epoch: project.state.context.workspace_epoch,
            root: project.local_root.clone(),
        };
        drop(store);
        turn.check()?;
        let pending = turn
            .guard
            .begin_remote_rename(turn.snapshot, peer.continuation(), expiry.deadline())
            .map_err(|e| RemoteRenameError::Owner(Error::Domain(e)))?;
        Ok(RemoteEffectBegin::Write(Box::new(
            RemoteTerminalEffectWrite {
                owner: self,
                worker,
                peer,
                pending: Some(pending),
                before: turn.rows,
                request,
                binding,
                connection: connection.connection_identity(),
                workspace: turn.workspace,
                expected_revision: None,
                file: Some(file),
                namespace: None,
                namespace_projects: Vec::new(),
                refusal: None,
                plan: RemoteLifecyclePlan {
                    plan: super::rpc::Plan {
                        state: before.clone(),
                        stop: None,
                        spawn: None,
                        result: lomi_remote_protocol::OperationResult::Domain {
                            domain_revision: before.domain_revision,
                        },
                    },
                    before,
                    profile: None,
                },
                permit: None,
                started: false,
                closed: false,
            },
        )))
    }
}

impl<'d, 'o, 'e, 'w, 'p, 's> RemoteTerminalEffectWrite<'d, 'o, 'e, 'w, 'p, 's> {
    pub(super) fn plan(&self) -> &RemoteLifecyclePlan {
        &self.plan
    }
    pub(super) fn file_plan(&self) -> Option<&RemoteFilePlan> {
        self.file.as_ref()
    }
    pub(super) fn file_namespace_plan(
        &mut self,
        effect: lomi_host_store::DesktopNamespaceEffect,
    ) -> Result<
        (
            lomi_host_store::RemoteDesktopNamespacePlan,
            Vec<(WorkspaceId, std::path::PathBuf)>,
        ),
        RemoteRenameError,
    > {
        let pending = self.pending.as_mut().ok_or(RemoteRenameError::Closed)?;
        let guard = pending
            .try_enter()
            .map_err(|e| RemoteRenameError::Owner(Error::Domain(e)))?;
        let store = self.owner.try_store()?;
        let plan = guard
            .effect_namespace_plan(
                &store,
                self.permit.as_ref().ok_or(RemoteRenameError::Closed)?,
                effect,
            )
            .map_err(|e| RemoteRenameError::Owner(e.into()))?;
        let projects = store
            .list_projects()
            .map_err(|e| RemoteRenameError::Owner(Error::Store(e)))?;
        let roots = plan
            .guarded_workspace_ids()
            .iter()
            .map(|id| {
                projects
                    .iter()
                    .find(|project| project.state.context.workspace_id == *id)
                    .map(|project| (*id, project.local_root.clone()))
                    .ok_or(RemoteRenameError::Closed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if !self.worker.current() {
            return Err(RemoteRenameError::Closed);
        }
        self.namespace_projects = projects
            .into_iter()
            .filter(|project| {
                plan.workspaces()
                    .iter()
                    .any(|workspace| workspace.workspace_id == project.state.context.workspace_id)
            })
            .collect();
        Ok((plan, roots))
    }
    pub(super) fn prepare_file_namespace(
        &mut self,
        plan: &lomi_host_store::RemoteDesktopNamespacePlan,
        proof: &lomi_host_store::DesktopNamespacePhysicalProof,
    ) -> Result<(), RemoteRenameError> {
        // Retain the exact plan even if the preparation's ACK is lost. Recovery
        // can only persist a physically proven result; it cannot repeat effects.
        self.namespace = Some(plan.clone());
        let pending = self.pending.as_mut().ok_or(RemoteRenameError::Closed)?;
        let mut guard = pending
            .try_enter()
            .map_err(|e| RemoteRenameError::Owner(Error::Domain(e)))?;
        let mut store = self.owner.try_store()?;
        let current = PeerJournalRows::read(
            &store,
            self.worker.eligibility(),
            self.binding.rights.workspace(),
        )
        .map_err(|e| RemoteRenameError::Owner(Error::UncertainStore(e)))?;
        if !self.before.current(&current) || !self.worker.current() {
            return Err(RemoteRenameError::Closed);
        }
        guard
            .prepare_effect_namespace(
                &mut store,
                self.permit.as_ref().ok_or(RemoteRenameError::Closed)?,
                plan,
                proof,
            )
            .map_err(|e| RemoteRenameError::Owner(e.into()))
    }
    /// File operations: the host-mapped refusal to deliver with a Failed/None
    /// receipt. Never set for terminal operations.
    pub(super) fn set_refusal(&mut self, error: lomi_remote_protocol::RemoteError) {
        self.refusal = Some(error);
    }
    pub(super) fn binding(&self) -> &OperationBinding {
        &self.binding
    }
    /// Move-once handoff of the real permit, for persistence-only reconciliation
    /// after a failed start/completion. It never authorizes an OS effect.
    pub(super) fn take_permit(&mut self) -> Option<ExternalPermit> {
        self.permit.take()
    }
    /// Lock-free. True only while the sole announcement still owns the Started
    /// operation and the remote worker/channel remain current.
    pub(super) fn effect_current(&self) -> bool {
        self.started
            && !self.closed
            && self.worker.current()
            && self.pending.as_ref().is_some_and(|p| p.effect_current())
            && self.worker.current()
    }
    fn is_busy(result: &Result<(), RemoteRenameError>) -> bool {
        matches!(
            result,
            Err(RemoteRenameError::Owner(Error::Domain(domain::Error::Busy)))
                | Err(RemoteRenameError::Owner(Error::Store(StoreError::Busy)))
        )
    }
    /// Admit + start in one Store transaction. Busy before the Store call is
    /// retryable (same announcement); every other failure closes this write.
    pub(super) fn try_start(&mut self) -> Result<(), RemoteRenameError> {
        if self.closed || self.started {
            return Err(RemoteRenameError::Closed);
        }
        let result = self.start_phase();
        let busy = Self::is_busy(&result);
        if busy
            && self
                .pending
                .as_ref()
                .is_some_and(|p| p.phase() == domain::RemoteRenamePhase::StoreNotCalled)
        {
            return result;
        }
        let result = if busy {
            Err(RemoteRenameError::Owner(Error::UncertainStore(
                StoreError::Busy,
            )))
        } else {
            result
        };
        if matches!(
            result,
            Err(RemoteRenameError::Owner(Error::UncertainStore(_)))
        ) {
            self.owner.domain.cloud_uncertain();
        }
        match result {
            Ok(()) => {
                self.started = true;
                Ok(())
            }
            Err(error) => {
                self.closed = true;
                if let Some(pending) = self.pending.take()
                    && matches!(
                        pending.phase(),
                        domain::RemoteRenamePhase::StoreNotCalled
                            | domain::RemoteRenamePhase::KnownNoEffect
                    )
                {
                    let _ = pending.abandon();
                }
                Err(error)
            }
        }
    }
    fn start_phase(&mut self) -> Result<(), RemoteRenameError> {
        let pending = self.pending.as_mut().ok_or(RemoteRenameError::Closed)?;
        let mut guard = pending
            .try_enter()
            .map_err(|e| RemoteRenameError::Owner(Error::Domain(e)))?;
        let mut store = self.owner.try_store()?;
        guard
            .check_current()
            .map_err(|e| RemoteRenameError::Owner(Error::Domain(e)))?;
        let current = PeerJournalRows::read(
            &store,
            self.worker.eligibility(),
            self.binding.rights.workspace(),
        )
        .map_err(|e| RemoteRenameError::Owner(Error::UncertainStore(e)))?;
        if !self.before.current(&current) || !self.worker.current() {
            return Err(RemoteRenameError::Closed);
        }
        rename_public_current(&store, &current)?;
        guard
            .check_current()
            .map_err(|e| RemoteRenameError::Owner(Error::Domain(e)))?;
        if !self.worker.current() {
            return Err(RemoteRenameError::Closed);
        }
        let admission = guard
            .start_effect(
                &mut store,
                &self.binding,
                self.expected_revision,
                &mut self.permit,
            )
            .map_err(|error| match error {
                StepError::Domain(error) => RemoteRenameError::Owner(Error::Domain(error)),
                StepError::Source(error) => RemoteRenameError::Owner(Error::Store(error)),
            })?;
        let post = PeerJournalRows::read(
            &store,
            self.worker.eligibility(),
            self.binding.rights.workspace(),
        )
        .map_err(|e| {
            self.owner.domain.cloud_uncertain();
            RemoteRenameError::Owner(Error::UncertainStore(e))
        })?;
        // Start only journals Running + events: every observed row is unchanged.
        if !admission.newly_admitted
            || admission.receipt.state() != OperationState::Running
            || admission.receipt.effect() != lomi_remote_protocol::Effect::None
            || !rename_rights_match(&admission.receipt.stored_rights(), &self.binding.rights)
            || !self.before.current(&post)
            || !self.worker.current()
        {
            self.owner.domain.cloud_uncertain();
            return Err(RemoteRenameError::Closed);
        }
        rename_public_current(&store, &post)?;
        Ok(())
    }

    /// Persist the observed outcome for the retained permit and settle the
    /// announcement. Busy before the Store call is retryable.
    pub(super) fn try_complete(
        &mut self,
        outcome: &RemoteEffectOutcome,
        namespace_evidence: Option<&lomi_host_store::DesktopNamespaceAppliedProof>,
    ) -> Result<RemoteEffectCompletion<'d, 'o, 'e, 'w, 'p, 's>, RemoteRenameError> {
        if self.closed || !self.started {
            return Err(RemoteRenameError::Closed);
        }
        let result = self.complete_phase(outcome, namespace_evidence);
        let busy = matches!(
            result,
            Err(RemoteRenameError::Owner(Error::Domain(domain::Error::Busy)))
                | Err(RemoteRenameError::Owner(Error::Store(StoreError::Busy)))
        );
        if busy
            && self
                .pending
                .as_ref()
                .is_some_and(|p| p.phase() == domain::RemoteRenamePhase::Started)
        {
            return Err(match result {
                Err(error) => error,
                Ok(_) => unreachable!(),
            });
        }
        let result = if busy {
            Err(RemoteRenameError::Owner(Error::UncertainStore(
                StoreError::Busy,
            )))
        } else {
            result
        };
        if matches!(
            result,
            Err(RemoteRenameError::Owner(Error::UncertainStore(_)))
        ) {
            self.owner.domain.cloud_uncertain();
        }
        self.closed = true;
        match result {
            Ok((receipt, post)) => {
                let pending = self.pending.take().ok_or(RemoteRenameError::Closed)?;
                let stamp = pending
                    .finish()
                    .map_err(|e| RemoteRenameError::Owner(Error::Domain(e)))?;
                let refusal = if outcome.state == OperationState::Failed
                    && outcome.effect == lomi_remote_protocol::Effect::None
                {
                    self.refusal.take()
                } else {
                    None
                };
                let delivered = refusal.is_some()
                    || (outcome.state == OperationState::Succeeded
                        && outcome.effect == lomi_remote_protocol::Effect::Committed);
                if !delivered || post.outbox != self.before.outbox && self.namespace.is_some() {
                    return Ok(RemoteEffectCompletion::Settled);
                }
                // Same derivation as a fresh request, now from POST rows: this
                // re-proves grant/ready/terminal consistency of the new world.
                let (_, local, running) = derive_remote_view(
                    &post,
                    self.worker.eligibility(),
                    self.peer,
                    self.binding.rights.workspace(),
                    &self.workspace,
                )
                .map_err(RemoteRenameError::Owner)?;
                Ok(RemoteEffectCompletion::Delivered(Box::new(
                    RemoteRenameReceipt {
                        owner: self.owner,
                        worker: self.worker,
                        watcher: stamp.into_io_watcher(),
                        post,
                        local,
                        running,
                        request: self.request.clone(),
                        receipt,
                        connection: self.connection,
                        refusal,
                    },
                )))
            }
            // Started/Uncertain unfinished ownership keeps the conservative
            // fail-closed Drop; the permit stays with the caller for recovery.
            Err(error) => Err(error),
        }
    }
    fn complete_phase(
        &mut self,
        outcome: &RemoteEffectOutcome,
        namespace_evidence: Option<&lomi_host_store::DesktopNamespaceAppliedProof>,
    ) -> Result<(OperationReceipt, PeerJournalRows), RemoteRenameError> {
        let permit = self.permit.as_ref().ok_or(RemoteRenameError::Closed)?;
        let pending = self.pending.as_mut().ok_or(RemoteRenameError::Closed)?;
        let mut guard = pending
            .try_enter()
            .map_err(|e| RemoteRenameError::Owner(Error::Domain(e)))?;
        let mut store = self.owner.try_store()?;
        let current = PeerJournalRows::read(
            &store,
            self.worker.eligibility(),
            self.binding.rights.workspace(),
        )
        .map_err(|e| RemoteRenameError::Owner(Error::UncertainStore(e)))?;
        if !self.before.current(&current) || !self.worker.current() {
            return Err(RemoteRenameError::Closed);
        }
        rename_public_current(&store, &current)?;
        if !self.worker.current() {
            return Err(RemoteRenameError::Closed);
        }
        #[cfg(test)]
        if super::remote_terminal_lifecycle::fault::take_completion_failure(
            self.binding.rights.operation_id().to_bytes(),
        ) {
            return Err(RemoteRenameError::Owner(Error::Store(StoreError::Storage)));
        }
        let receipt = match (&self.namespace, namespace_evidence) {
            (Some(_), Some(evidence)) => guard.complete_namespace_effect(
                &mut store,
                permit,
                outcome.state,
                outcome.effect,
                outcome.result.clone(),
                evidence,
            ),
            (Some(_), None) | (None, Some(_)) => return Err(RemoteRenameError::Closed),
            (None, None) => guard.complete_effect(
                &mut store,
                permit,
                outcome.state,
                outcome.effect,
                outcome.result.clone(),
                outcome.projection.clone(),
            ),
        }
        .map_err(|error| match error {
            StepError::Domain(error) => RemoteRenameError::Owner(Error::Domain(error)),
            StepError::Source(error) => RemoteRenameError::Owner(Error::Store(error)),
        })?;
        let post = PeerJournalRows::read(
            &store,
            self.worker.eligibility(),
            self.binding.rights.workspace(),
        )
        .map_err(|e| {
            self.owner.domain.cloud_uncertain();
            RemoteRenameError::Owner(Error::UncertainStore(e))
        })?;
        let mut expected = self.before.clone();
        let local = expected.local.as_mut().ok_or(RemoteRenameError::Closed)?;
        let delivered = outcome.state == OperationState::Succeeded
            && outcome.effect == lomi_remote_protocol::Effect::Committed;
        let post_local = post.local.as_ref().ok_or(RemoteRenameError::Closed)?;
        if self.file.is_some() {
            // FileRoot refuses mutation of its own root. Namespace effects may
            // retire registered child roots, but never alter the origin's
            // private layout, terminal descriptors, or sharing policy.
            if post.terminals != self.before.terminals || post_local.state != local.state {
                self.owner.domain.cloud_uncertain();
                return Err(RemoteRenameError::Closed);
            }
            let retired = self.namespace.as_ref().filter(|plan| {
                matches!(
                    plan.effect(),
                    lomi_host_store::DesktopNamespaceEffect::Remove { .. }
                ) && namespace_evidence.is_some_and(|evidence| {
                    evidence.observed() == lomi_host_store::DesktopNamespaceObservedEffect::Applied
                })
            });
            if let Some(plan) = retired {
                if !self.before.outbox.is_empty()
                    || post.outbox.len() != plan.workspaces().len()
                    || self.namespace_projects.len() != plan.workspaces().len()
                    || !post.outbox.iter().all(|publication| {
                        self.namespace_projects.iter().any(|project| {
                            publication.workspace_id == project.state.context.workspace_id
                                && project.fence.checked_add(1) == Some(publication.fence)
                                && publication.domain_revision == project.state.domain_revision
                                && !publication.enabled
                                && !publication.token.is_empty()
                        })
                    })
                {
                    self.owner.domain.cloud_uncertain();
                    return Err(RemoteRenameError::Closed);
                }
            } else if post.outbox != self.before.outbox {
                self.owner.domain.cloud_uncertain();
                return Err(RemoteRenameError::Closed);
            }
        } else if delivered {
            local.state = self.plan.plan.state.clone();
            // Running descriptors must be exactly the Running panes of the plan.
            let mut running: Vec<_> = self
                .plan
                .plan
                .state
                .tabs
                .0
                .iter()
                .flat_map(|tab| collect_running_panes(&tab.layout))
                .collect();
            let mut described: Vec<_> = post
                .terminals
                .iter()
                .filter(|(_, status)| *status == lomi_host_store::TerminalStatus::Running)
                .map(|(pane, _)| *pane)
                .collect();
            running.sort_by_key(|pane| pane.to_bytes());
            described.sort_by_key(|pane| pane.to_bytes());
            if running != described
                || post.outbox.len() != 1
                || !self.before.outbox.is_empty()
                || !post.outbox.iter().all(|p| {
                    p.workspace_id == self.binding.rights.workspace()
                        && p.fence == post_local.fence
                        && p.enabled == post_local.consent
                        && p.domain_revision == self.plan.plan.state.domain_revision
                        && !p.token.is_empty()
                })
            {
                self.owner.domain.cloud_uncertain();
                return Err(RemoteRenameError::Closed);
            }
        } else {
            // A final non-success never claims a committed effect and may only
            // change the exact stopped projection already validated by the Store.
            local.state = post_local.state.clone();
        }
        if receipt.state() != outcome.state
            || receipt.effect() != outcome.effect
            || !rename_rights_match(&receipt.stored_rights(), &self.binding.rights)
        {
            self.owner.domain.cloud_uncertain();
            return Err(RemoteRenameError::Closed);
        }
        expected.terminals = post.terminals.clone();
        expected.outbox = post.outbox.clone();
        if !expected.current(&post) || !self.worker.current() {
            self.owner.domain.cloud_uncertain();
            return Err(RemoteRenameError::Closed);
        }
        rename_public_current(&store, &post)?;
        Ok((receipt, post))
    }
}
impl Drop for RemoteTerminalEffectWrite<'_, '_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        // Never invent completion. Only a write that has not reached Store may
        // be abandoned; Started/Uncertain keep the fail-closed announcement Drop.
        if let Some(pending) = self.pending.take()
            && matches!(
                pending.phase(),
                domain::RemoteRenamePhase::StoreNotCalled
                    | domain::RemoteRenamePhase::KnownNoEffect
            )
        {
            let _ = pending.abandon();
        }
    }
}
fn collect_running_panes(
    layout: &lomi_remote_protocol::rpc::TerminalLayout,
) -> Vec<lomi_remote_protocol::PaneId> {
    match layout {
        lomi_remote_protocol::rpc::TerminalLayout::Pane { pane } => {
            if pane.state == lomi_remote_protocol::rpc::PaneState::Running {
                vec![pane.pane_id]
            } else {
                Vec::new()
            }
        }
        lomi_remote_protocol::rpc::TerminalLayout::Split { first, second, .. } => {
            let mut panes = collect_running_panes(first);
            panes.extend(collect_running_panes(second));
            panes
        }
    }
}
