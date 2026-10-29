use crate::HostError;
use lomi_host_store::{HostStore, Limits, ProjectRecord, StoreError};
#[cfg(unix)]
use lomi_platform::unix as platform;
#[cfg(windows)]
use lomi_platform::windows as platform;
use lomi_remote_protocol::{
    HostId, LocalIpcVersion, RequestId, WorkspaceId,
    ipc::*,
    rpc::{BoundedList, Confirmed, DisplayText},
};
use lomi_terminal::TerminalService;
use platform::{LocalClient, LocalDiscovery, OwnerEndpoint, OwnerLock};
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use std::process::{Command, Stdio};

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const CONNECTIONS: usize = 16;

#[cfg(target_os = "macos")]
fn admin_host_identity_pin(
    profile: &Path,
    executable: &Path,
    require_managed_pin: bool,
) -> Result<Option<lomi_host_store::Identity>, HostError> {
    use lomi_platform::service_macos::AdminHostIdentityLookup;

    match lomi_platform::service_macos::lookup_admin_host_identity_binding(profile, executable)
        .map_err(|_| HostError::IdentityMismatch)?
    {
        AdminHostIdentityLookup::NotManaged => Ok(None),
        AdminHostIdentityLookup::Missing if require_managed_pin => Err(HostError::IdentityMismatch),
        AdminHostIdentityLookup::Missing => Ok(None),
        AdminHostIdentityLookup::Present(binding) => Ok(Some(lomi_host_store::Identity {
            host_id: binding.host_id(),
            profile_id: binding.profile_id(),
        })),
    }
}

#[cfg(not(target_os = "macos"))]
fn admin_host_identity_pin(
    _profile: &Path,
    _executable: &Path,
    _require_managed_pin: bool,
) -> Result<Option<lomi_host_store::Identity>, HostError> {
    Ok(None)
}

mod auth;
mod desktop_namespace;
mod desktop_namespace_recovery;
mod local_streams;
mod namespace_runtime;
mod native_editor;
#[cfg(target_os = "macos")]
mod native_evidence;
mod native_git;
#[cfg(any(unix, windows))]
mod public_configuration;
mod remote_file_namespace;
mod remote_files;
mod remote_files_watch;
mod remote_git;
mod remote_git_mutations;
mod remote_namespace_effect;
mod remote_operations;
mod remote_terminal;
mod remote_terminal_lifecycle;
mod remote_terminal_rename;
mod rpc;
mod workspace_removal;
// Root integrates every writer before activating this common owner graph.
#[cfg(any(unix, windows))]
mod diagnostics;
#[cfg(any(unix, windows))]
mod ipc_admission;
mod operator;
mod owner_domain;
#[cfg(any(unix, windows))]
mod shared_owner;
pub(crate) fn suggested_host_display_name(
    host_id: Option<HostId>,
) -> lomi_remote_protocol::ipc::LocalHostName {
    shared_owner::suggested_host_display_name(host_id)
}
impl From<platform::Error> for HostError {
    fn from(value: platform::Error) -> Self {
        match value {
            platform::Error::Busy => Self::Busy,
            platform::Error::InvalidProfile
            | platform::Error::PermissionDenied
            | platform::Error::InvalidEndpoint => Self::InvalidProfile,
            _ => Self::Unavailable,
        }
    }
}
fn store_error(error: StoreError) -> LocalError {
    match error {
        StoreError::Invalid => LocalError::InvalidArgument,
        StoreError::NotFound => LocalError::InvalidArgument,
        StoreError::Busy
        | StoreError::RevisionConflict
        | StoreError::IdempotencyConflict
        | StoreError::Fenced
        | StoreError::NativeWriterBusy
        | StoreError::AlreadyStarted => LocalError::Conflict,
        _ => LocalError::Unavailable,
    }
}
fn owner_error(error: shared_owner::Error) -> LocalError {
    match error {
        shared_owner::Error::Store(error) => store_error(error),
        _ => LocalError::Unavailable,
    }
}
fn removal_status(
    workspace_id: WorkspaceId,
    outcome: Option<workspace_removal::WorkspaceRemovalOutcome>,
) -> lomi_remote_protocol::ipc::LocalWorkspaceRemovalStatus {
    use lomi_host_store::{WorkspaceRemovalSessionState, WorkspaceRemovalState};
    use lomi_remote_protocol::{
        DecimalU64,
        ipc::{LocalWorkspaceRemovalPhase as Phase, LocalWorkspaceRemovalStatus},
    };
    use workspace_removal::WorkspaceRemovalOutcome;
    let Some(outcome) = outcome else {
        return LocalWorkspaceRemovalStatus {
            workspace_id,
            attempt_id: None,
            phase: Phase::NotStarted,
            total_sessions: DecimalU64(0),
            confirmed_sessions: DecimalU64(0),
        };
    };
    let (record, uncertain) = match outcome {
        WorkspaceRemovalOutcome::Record(record) => (record, false),
        WorkspaceRemovalOutcome::Uncertain(record) => (record, true),
    };
    let phase = if uncertain {
        Phase::Uncertain
    } else {
        match record.state {
            WorkspaceRemovalState::Stopping => Phase::Stopping,
            WorkspaceRemovalState::Uncertain => Phase::Uncertain,
            WorkspaceRemovalState::Complete => Phase::Complete,
        }
    };
    LocalWorkspaceRemovalStatus {
        workspace_id: record.workspace_id,
        attempt_id: Some(record.attempt_id),
        phase,
        total_sessions: DecimalU64(record.sessions.len() as u64),
        confirmed_sessions: DecimalU64(
            record
                .sessions
                .iter()
                .filter(|session| session.state == WorkspaceRemovalSessionState::CleanupConfirmed)
                .count() as u64,
        ),
    }
}
fn summary(project: &ProjectRecord) -> Result<LocalWorkspaceSummary, LocalError> {
    Ok(LocalWorkspaceSummary {
        workspace_id: project.state.context.workspace_id,
        name: LocalProjectName::try_from(String::from(project.state.name.clone()))
            .map_err(|_| LocalError::Unavailable)?,
        sharing: if project.consent {
            LocalSharing::Enabled
        } else {
            LocalSharing::Disabled
        },
    })
}
struct Coordinator {
    profile: Option<PathBuf>,
    started: Instant,
    logs: diagnostics::DiagnosticLogRing,
    clients: Mutex<Option<operator::ClientObservation>>,
    diagnostic_auth: Mutex<Option<(LocalAuthPhase, LocalAuthStorage, LocalAuthNetwork)>>,
    started_git_terminal: Mutex<Option<shared_owner::StartedGitContinuation>>,
    owner: Arc<shared_owner::SharedOwner>,
    deferred_completions: Arc<Mutex<rpc::CompletionQueue>>,
    auth: Mutex<Option<auth::Handle>>,
    terminals: Arc<TerminalService>,
    stopping: Arc<AtomicBool>,
    workspace_locks:
        Arc<Mutex<std::collections::BTreeMap<WorkspaceId, std::sync::Weak<Mutex<()>>>>>,
    files: remote_files::Roots,
    git_reads: remote_git::Reads,
    git_mutations: remote_git_mutations::Mutations,
    native_editor: Mutex<Option<Arc<native_editor::NativeEditorHost>>>,
    native_git: Mutex<Option<Arc<native_git::NativeGitHost>>>,
    #[cfg(target_os = "macos")]
    native_evidence: Mutex<Option<Arc<native_evidence::NativeEvidenceHost>>>,
}
impl Coordinator {
    fn with_terminals(
        store: HostStore,
        stopping: Arc<AtomicBool>,
        terminals: TerminalService,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            profile: None,
            started: Instant::now(),
            logs: diagnostics::DiagnosticLogRing::default(),
            clients: Mutex::new(None),
            diagnostic_auth: Mutex::new(None),
            started_git_terminal: Mutex::new(None),
            owner: shared_owner::SharedOwner::new(store)?,
            deferred_completions: Arc::new(Mutex::new(rpc::CompletionQueue::new())),
            auth: Mutex::new(None),
            terminals: Arc::new(terminals),
            stopping,
            workspace_locks: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            files: remote_files::Roots::default(),
            git_reads: remote_git::Reads::default(),
            git_mutations: remote_git_mutations::Mutations::default(),
            native_editor: Mutex::new(None),
            native_git: Mutex::new(None),
            #[cfg(target_os = "macos")]
            native_evidence: Mutex::new(None),
        })
    }
    // This slot transports an opaque existing writer capability to local IPC;
    // it does not admit work. The terminal-only owner turn checks the actual
    // core and current descriptor on every callback, even for a retained clone.
    fn set_started_git_terminal_continuation(
        &self,
        active: Option<shared_owner::StartedGitContinuation>,
    ) -> Result<(), LocalError> {
        let mut slot = self
            .started_git_terminal
            .try_lock()
            .map_err(|_| LocalError::Unavailable)?;
        *slot = active;
        Ok(())
    }
    fn started_git_terminal_continuation(
        &self,
    ) -> Result<Option<shared_owner::StartedGitContinuation>, LocalError> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(LocalError::Unavailable);
        }
        self.started_git_terminal
            .try_lock()
            .map(|slot| slot.clone())
            .map_err(|_| LocalError::Unavailable)
    }
    fn workspace_lock(&self, id: WorkspaceId) -> Result<Arc<Mutex<()>>, LocalError> {
        namespace_runtime::workspace_lock(&self.workspace_locks, id)
    }
    fn native_editor(&self) -> Result<Arc<native_editor::NativeEditorHost>, LocalError> {
        self.native_editor
            .lock()
            .map_err(|_| LocalError::Unavailable)?
            .clone()
            .ok_or(LocalError::Unavailable)
    }
    fn native_git(&self) -> Result<Arc<native_git::NativeGitHost>, LocalError> {
        self.native_git
            .lock()
            .map_err(|_| LocalError::Unavailable)?
            .clone()
            .ok_or(LocalError::Unavailable)
    }
    #[cfg(target_os = "macos")]
    fn native_evidence(&self) -> Result<Arc<native_evidence::NativeEvidenceHost>, LocalError> {
        self.native_evidence
            .lock()
            .map_err(|_| LocalError::Unavailable)?
            .clone()
            .ok_or(LocalError::Unavailable)
    }

    fn dispatch_on_connection(
        &self,
        operation: &owner_domain::Operation<'_>,
        call: LocalCall,
        connection: IpcNonce,
        #[cfg(target_os = "macos")] accepted_stream: Option<&std::os::unix::net::UnixStream>,
    ) -> Result<LocalResult, LocalError> {
        self.dispatch_with_connection(
            operation,
            call,
            Some(connection),
            #[cfg(target_os = "macos")]
            accepted_stream,
        )
    }
    fn dispatch_with_connection(
        &self,
        operation: &owner_domain::Operation<'_>,
        call: LocalCall,
        connection: Option<IpcNonce>,
        #[cfg(target_os = "macos")] accepted_stream: Option<&std::os::unix::net::UnixStream>,
    ) -> Result<LocalResult, LocalError> {
        operation.check().map_err(|_| LocalError::Unavailable)?;
        if self.stopping.load(Ordering::Acquire) {
            return Err(LocalError::Unavailable);
        }
        if matches!(
            &call,
            LocalCall::AuthConfigure(_)
                | LocalCall::LoginStart(_)
                | LocalCall::LoginStatus {}
                | LocalCall::LoginPresentation {}
                | LocalCall::Logout(_)
        ) {
            let auth = self
                .auth
                .lock()
                .map_err(|_| LocalError::Unavailable)?
                .clone()
                .ok_or(LocalError::Unavailable)?;
            return auth.dispatch(operation, call);
        }
        if matches!(
            &call,
            LocalCall::WorkspaceInspect(_) | LocalCall::Workspaces {}
        ) {
            rpc::reconcile_terminal_lifecycle(self, operation)?;
        }
        let workspace_lock = match &call {
            LocalCall::Share(target)
            | LocalCall::Unshare(target)
            | LocalCall::WorkspaceRemove(target) => Some(self.workspace_lock(target.workspace_id)?),
            LocalCall::ShareAuthorized(target) | LocalCall::UnshareAuthorized(target) => {
                Some(self.workspace_lock(target.workspace_id)?)
            }
            LocalCall::WorkspaceRename(target) => Some(self.workspace_lock(target.workspace_id)?),
            LocalCall::WorkspaceRemovalStatus(target) => {
                Some(self.workspace_lock(target.workspace_id)?)
            }
            _ => None,
        };
        let _workspace_guard = workspace_lock
            .as_ref()
            .map(|lock| rpc::actor_lock(lock, operation).map_err(|_| LocalError::Unavailable))
            .transpose()?;
        if let LocalCall::Share(target)
        | LocalCall::Unshare(target)
        | LocalCall::WorkspaceRemove(target) = &call
        {
            rpc::ensure_workspace_settled(self, target.workspace_id)
                .map_err(|_| LocalError::Unavailable)?;
        }
        if let LocalCall::ShareAuthorized(target) | LocalCall::UnshareAuthorized(target) = &call {
            rpc::ensure_workspace_settled(self, target.workspace_id)
                .map_err(|_| LocalError::Unavailable)?;
        }
        if let LocalCall::WorkspaceRename(target) = &call {
            rpc::ensure_workspace_settled(self, target.workspace_id)
                .map_err(|_| LocalError::Unavailable)?;
        }
        match call {
            LocalCall::NativeFileStage(blob) => self.native_editor()?.stage(operation, blob),
            LocalCall::NativeEditorExecute(request) => {
                let connection = connection.ok_or(LocalError::Unavailable)?;
                self.native_editor()?
                    .execute(operation, connection, request)
            }
            LocalCall::NativeEditorExecuteGuarded(_) | LocalCall::NativeEffectDecision(_) => {
                Err(LocalError::InvalidArgument)
            }
            LocalCall::NativeEditorStatus(target) => {
                self.native_editor()?.status(operation, target)
            }
            LocalCall::NativeEditorDispositionRead(target) => {
                let value = rpc::owner_call(operation, || {
                    self.owner
                        .native_editor_disposition_read(operation, target.intent_id)
                })
                .map_err(owner_error)?;
                Ok(LocalResult::NativeEditorDisposition(value))
            }
            LocalCall::NativeEditorAcknowledge(target) => {
                self.native_editor()?.acknowledge(operation, target)
            }
            LocalCall::NativeGitPrepareGuarded(_) | LocalCall::NativeGitExecuteGuarded(_) => {
                Err(LocalError::InvalidArgument)
            }
            LocalCall::NativeGitStatus(target) => self.native_git()?.status(operation, target),
            LocalCall::NativeGitCancelPrepared(target) => {
                self.native_git()?.cancel_prepared(operation, target)
            }
            LocalCall::NativeGitAcknowledge(target) => {
                self.native_git()?.acknowledge(operation, target)
            }
            LocalCall::NativeAcknowledge(target) => {
                rpc::owner_call(operation, || {
                    self.owner.native_acknowledge(operation, target.intent_id)
                })
                .map_err(owner_error)?;
                Ok(LocalResult::NativeAcknowledged(target.intent_id))
            }
            LocalCall::NativeIntent(request) => {
                let connection = connection.ok_or(LocalError::Unavailable)?;
                let intent_id = rpc::owner_call(operation, || {
                    self.owner
                        .native_intent(operation, request.clone(), connection)
                })
                .map_err(owner_error)?;
                Ok(LocalResult::NativeIntent(intent_id))
            }
            LocalCall::NativeBindJob(request) => {
                let connection = connection.ok_or(LocalError::Unavailable)?;
                #[cfg(target_os = "macos")]
                {
                    let accepted_stream = accepted_stream.ok_or(LocalError::Unavailable)?;
                    self.native_evidence()?.bind_job(
                        operation,
                        connection,
                        accepted_stream,
                        request,
                    )
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = (connection, request);
                    Err(LocalError::Unavailable)
                }
            }
            LocalCall::NativeAcquire(target) => {
                let connection = connection.ok_or(LocalError::Unavailable)?;
                let lease = rpc::owner_call(operation, || {
                    self.owner
                        .native_acquire(operation, target.intent_id, connection)
                })
                .map_err(owner_error)?;
                Ok(LocalResult::NativeLease(lease))
            }
            LocalCall::NativeCheck(target) => {
                let connection = connection.ok_or(LocalError::Unavailable)?;
                let lease = rpc::owner_call(operation, || {
                    self.owner
                        .native_check(operation, target.intent_id, connection)
                })
                .map_err(owner_error)?;
                Ok(LocalResult::NativeLease(lease))
            }
            LocalCall::NativeRenew(target) => {
                let connection = connection.ok_or(LocalError::Unavailable)?;
                let lease = rpc::owner_call(operation, || {
                    self.owner
                        .native_renew(operation, target.intent_id, connection)
                })
                .map_err(owner_error)?;
                Ok(LocalResult::NativeLease(lease))
            }
            LocalCall::NativeRequestFinish(target) => {
                #[cfg(target_os = "macos")]
                {
                    return self
                        .native_evidence()?
                        .verify_finish(operation, target.intent_id);
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let lease = rpc::owner_call(operation, || {
                        self.owner
                            .native_request_finish(operation, target.intent_id)
                    })
                    .map_err(owner_error)?;
                    Ok(LocalResult::NativeLease(lease))
                }
            }
            LocalCall::NativeReconcile(target) => {
                #[cfg(target_os = "macos")]
                {
                    return self
                        .native_evidence()?
                        .verify_finish(operation, target.intent_id);
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let lease = rpc::owner_call(operation, || {
                        self.owner.native_reconcile(operation, target.intent_id)
                    })
                    .map_err(owner_error)?;
                    Ok(LocalResult::NativeLease(lease))
                }
            }
            LocalCall::Status {} => {
                rpc::owner_call(operation, || self.owner.local_status(operation))
                    .map(LocalResult::Status)
                    .map_err(owner_error)
            }
            LocalCall::HostNameSet(request) => {
                let mut write = rpc::owner_call(operation, || {
                    self.owner.begin_host_name_set(
                        operation,
                        request.expected_name.clone(),
                        request.name.clone(),
                    )
                })
                .map_err(owner_error)?;
                rpc::owner_call(operation, || write.try_commit())
                    .map(LocalResult::HostNameSet)
                    .map_err(owner_error)
            }
            LocalCall::SetupStartModeRead {} => {
                rpc::owner_call(operation, || self.owner.local_start_mode(operation))
                    .map(|start_mode| {
                        LocalResult::SetupStartMode(LocalStartModePreference { start_mode })
                    })
                    .map_err(owner_error)
            }
            LocalCall::SetupStartModeSave(preference) => {
                let mut write = rpc::owner_call(operation, || {
                    self.owner
                        .begin_save_local_start_mode(operation, preference.start_mode)
                })
                .map_err(owner_error)?;
                rpc::owner_call(operation, || write.try_commit()).map_err(owner_error)?;
                Ok(LocalResult::SetupStartMode(preference))
            }
            LocalCall::Doctor {} => self.doctor_legacy(operation).map(LocalResult::Doctor),
            LocalCall::DoctorReport {} => {
                self.doctor_report(operation).map(LocalResult::DoctorReport)
            }
            LocalCall::OperatorSnapshot {} => self
                .operator_snapshot(operation)
                .map(LocalResult::OperatorSnapshot),
            LocalCall::DiagnosticLogs(read) => {
                if read.limit == 0 || read.limit > 128 {
                    return Err(LocalError::InvalidArgument);
                }
                Ok(LocalResult::DiagnosticLogs(self.logs.snapshot(
                    read.after_sequence.map(|cursor| cursor.0),
                    usize::from(read.limit),
                )))
            }
            LocalCall::WorkspaceDetails(read) => self
                .workspace_details(operation, read.workspace_id)
                .map(LocalResult::WorkspaceDetails),
            LocalCall::WorkspacePublication(read) => rpc::owner_call(operation, || {
                self.owner
                    .workspace_publication(operation, read.workspace_id)
            })
            .map(LocalResult::WorkspacePublication)
            .map_err(owner_error),
            LocalCall::WorkspaceRename(rename) => {
                let mut turn = rpc::owner_call(operation, || {
                    self.owner.begin_rename_project(operation, rename.clone())
                })
                .map_err(owner_error)?;
                let project =
                    rpc::owner_call(operation, || turn.try_commit()).map_err(owner_error)?;
                Ok(LocalResult::Workspace(summary(&project)?))
            }
            LocalCall::MaintenancePrepare(_) => {
                let status =
                    rpc::owner_call(operation, || self.owner.maintenance_status(operation))
                        .map_err(owner_error)?;
                Ok(LocalResult::MaintenanceStatus(status))
            }
            LocalCall::Workspaces {} => Ok(LocalResult::Workspaces(BoundedList(
                rpc::owner_call(operation, || self.owner.workspaces(operation))
                    .map_err(owner_error)?
                    .iter()
                    .map(summary)
                    .collect::<Result<Vec<_>, _>>()?,
            ))),
            LocalCall::WorkspaceInspect(target) => Ok(LocalResult::WorkspaceState(Box::new(
                rpc::owner_call(operation, || {
                    self.owner.workspace(operation, target.workspace_id)
                })
                .map_err(owner_error)?
                .state,
            ))),
            LocalCall::Profiles {} => Ok(LocalResult::Profiles(BoundedList(vec![
                LocalProfileSummary {
                    profile_id: rpc::owner_call(operation, || self.owner.identity(operation))
                        .map_err(owner_error)?
                        .profile_id,
                    name: LocalProjectName::try_from("Default".to_owned())
                        .map_err(|_| LocalError::Unavailable)?,
                },
            ]))),
            LocalCall::WorkspaceAdd(parameters) => {
                let name = DisplayText::try_from(String::from(parameters.name))
                    .map_err(|_| LocalError::InvalidArgument)?;
                let mut turn = rpc::owner_call(operation, || {
                    self.owner.begin_add_project(
                        operation,
                        Path::new(parameters.root_path.as_str()),
                        name.clone(),
                    )
                })
                .map_err(owner_error)?;
                let project =
                    rpc::owner_call(operation, || turn.try_commit()).map_err(owner_error)?;
                Ok(LocalResult::Workspace(summary(&project)?))
            }
            LocalCall::WorkspaceImport(parameters) => {
                let name = DisplayText::try_from(String::from(parameters.name))
                    .map_err(|_| LocalError::InvalidArgument)?;
                let mut turn = rpc::owner_call(operation, || {
                    self.owner.begin_import_workspace(
                        operation,
                        Path::new(parameters.root_path.as_str()),
                        name.clone(),
                        parameters.workspace_id,
                    )
                })
                .map_err(owner_error)?;
                let project =
                    rpc::owner_call(operation, || turn.try_commit()).map_err(owner_error)?;
                Ok(LocalResult::WorkspaceImported(
                    LocalWorkspaceImportReceipt {
                        import_id: parameters.workspace_id,
                        workspace: summary(&project)?,
                    },
                ))
            }
            LocalCall::WorkspaceBindingsRead(request) => {
                let snapshot = rpc::owner_call(operation, || {
                    self.owner
                        .workspace_bindings_read(operation, &request.import_ids.0)
                })
                .map_err(owner_error)?;
                Ok(LocalResult::WorkspaceBindings(snapshot))
            }
            LocalCall::ShellProfileRegister(mut parameters) => {
                parameters
                    .environment
                    .0
                    .sort_by(|left, right| left.name.as_str().cmp(right.name.as_str()));
                let project = rpc::owner_call(operation, || {
                    self.owner.workspace(operation, parameters.workspace_id)
                })
                .map_err(owner_error)?;
                let existing = rpc::owner_call(operation, || {
                    self.owner.shell_profile_with_cwd_override(
                        operation,
                        parameters.workspace_id,
                        &parameters.profile_id,
                    )
                })
                .map_err(owner_error)?;
                if existing
                    .as_ref()
                    .is_some_and(|(original, _)| original != &parameters)
                {
                    return Err(LocalError::Conflict);
                }
                rpc::validate_shell_profile_registration(
                    &parameters,
                    &project,
                    existing.is_some(),
                    existing.as_ref().and_then(|(_, suffix)| suffix.as_deref()),
                )
                .map_err(|_| LocalError::InvalidArgument)?;
                let profile_id = parameters.profile_id.clone();
                let mut turn = rpc::owner_call(operation, || {
                    self.owner
                        .begin_register_shell_profile(operation, parameters.clone())
                })
                .map_err(owner_error)?;
                rpc::owner_call(operation, || turn.try_commit()).map_err(owner_error)?;
                Ok(LocalResult::ShellProfileRegistered { profile_id })
            }
            LocalCall::WorkspaceRemove(target) => {
                match workspace_removal::remove_workspace(self, operation, target.workspace_id) {
                    Ok(outcome) => {
                        let status = removal_status(target.workspace_id, Some(outcome));
                        if status.phase
                            == lomi_remote_protocol::ipc::LocalWorkspaceRemovalPhase::Complete
                        {
                            Ok(LocalResult::Removed(target.workspace_id))
                        } else {
                            Ok(LocalResult::WorkspaceRemovalStatus(status))
                        }
                    }
                    Err(LocalError::Unavailable) => {
                        // An uncertain begin must never be reported as a safe
                        // retry. Query this stable workspace ID without effects.
                        let mut status = removal_status(target.workspace_id, None);
                        status.phase =
                            lomi_remote_protocol::ipc::LocalWorkspaceRemovalPhase::Uncertain;
                        Ok(LocalResult::WorkspaceRemovalStatus(status))
                    }
                    Err(error) => Err(error),
                }
            }
            LocalCall::WorkspaceRemovalStatus(target) => {
                let outcome = workspace_removal::workspace_removal_status(
                    self,
                    operation,
                    target.workspace_id,
                )?;
                Ok(LocalResult::WorkspaceRemovalStatus(removal_status(
                    target.workspace_id,
                    outcome,
                )))
            }
            LocalCall::Share(target) => {
                let project = rpc::owner_call(operation, || {
                    self.owner.workspace(operation, target.workspace_id)
                })
                .map_err(owner_error)?;
                let mut turn = rpc::owner_call(operation, || {
                    self.owner
                        .begin_share(operation, target.workspace_id, project.fence)
                })
                .map_err(owner_error)?;
                rpc::owner_call(operation, || turn.try_commit()).map_err(owner_error)?;
                let project = rpc::owner_call(operation, || {
                    self.owner.workspace(operation, target.workspace_id)
                })
                .map_err(owner_error)?;
                Ok(LocalResult::Workspace(summary(&project)?))
            }
            LocalCall::ShareAuthorized(target) => {
                let handle = self
                    .auth
                    .lock()
                    .map_err(|_| LocalError::Unavailable)?
                    .clone()
                    .ok_or(LocalError::Unavailable)?;
                if !handle.is_authorized(operation) {
                    return Err(LocalError::PermissionDenied);
                }
                let project = rpc::owner_call(operation, || {
                    self.owner.workspace(operation, target.workspace_id)
                })
                .map_err(owner_error)?;
                let mut turn = rpc::owner_call(operation, || {
                    self.owner
                        .begin_share_if_authorized(operation, target.clone(), project.fence)
                })
                .map_err(owner_error)?;
                rpc::owner_call(operation, || turn.try_commit()).map_err(owner_error)?;
                let project = rpc::owner_call(operation, || {
                    self.owner.workspace(operation, target.workspace_id)
                })
                .map_err(owner_error)?;
                Ok(LocalResult::Workspace(summary(&project)?))
            }
            LocalCall::UnshareAuthorized(target) => {
                let mut turn = rpc::owner_call(operation, || {
                    self.owner
                        .begin_unshare_if_authorized(operation, target.clone())
                })
                .map_err(owner_error)?;
                rpc::owner_call(operation, || turn.try_commit()).map_err(owner_error)?;
                let project = rpc::owner_call(operation, || {
                    self.owner.workspace(operation, target.workspace_id)
                })
                .map_err(owner_error)?;
                Ok(LocalResult::Workspace(summary(&project)?))
            }
            LocalCall::Unshare(target) => {
                let mut turn = rpc::owner_call(operation, || {
                    self.owner.begin_unshare(operation, target.workspace_id)
                })
                .map_err(owner_error)?;
                rpc::owner_call(operation, || turn.try_commit()).map_err(owner_error)?;
                let project = rpc::owner_call(operation, || {
                    self.owner.workspace(operation, target.workspace_id)
                })
                .map_err(owner_error)?;
                Ok(LocalResult::Workspace(summary(&project)?))
            }
            LocalCall::DaemonStop(_) => {
                self.stopping.store(true, Ordering::Release);
                Ok(LocalResult::Stopping {})
            }
            // The service refuses commands until their actual executor is wired.
            // No unsupported method is reported as a completed operation.
            _ => Err(LocalError::Unavailable),
        }
    }
    fn native_connection_lost(&self, connection: IpcNonce) {
        let cancelled = AtomicBool::new(false);
        let operation =
            owner_domain::Operation::new(Instant::now() + platform::REQUEST_TIMEOUT, &cancelled);
        let _ = rpc::owner_call(&operation, || {
            self.owner.native_connection_lost(&operation, connection)
        });
    }
}

struct SignalGuards(Vec<signal_hook::SigId>);
impl Drop for SignalGuards {
    fn drop(&mut self) {
        for id in self.0.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}

/// Make unwind/error exits cancel IPC and no-exec workers before coordinator
/// references are released. NativeEditorHost itself retains OwnerEndpoint and
/// joins its effect thread before the profile lock can drop.
struct StopOnDrop(Arc<AtomicBool>);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn serve_guarded_editor_exchange(
    coordinator: &Coordinator,
    state: &mut rpc::ConnectionState,
    connection: &mut platform::LocalConnection,
    operation: &owner_domain::Operation<'_>,
    native_connection: IpcNonce,
    request_id: RequestId,
    execute: LocalNativeEditorExecute,
) -> Result<LocalResponse, ()> {
    let (initial, exchange) = match coordinator
        .native_editor()
        .and_then(|editor| editor.execute_guarded(operation, native_connection, execute))
    {
        Ok(value) => value,
        Err(error) => {
            return Ok(LocalResponse {
                version: connection.version(),
                request_id,
                result: Err(error),
            });
        }
    };
    let Some(exchange) = exchange else {
        return Ok(LocalResponse {
            version: connection.version(),
            request_id,
            result: Ok(initial),
        });
    };

    let version = connection.version();
    let mut completion_seen = false;
    loop {
        operation.check().map_err(|_| ())?;
        send_guarded_stream_events(coordinator, state, connection, operation)?;

        if let Some(challenge) = exchange.try_challenge() {
            let operation_id = challenge.operation_id;
            let nonce = challenge.challenge;
            connection.set_deadline(operation.deadline());
            connection
                .write(&LocalResponse {
                    version: version.clone(),
                    request_id: request_id.clone(),
                    result: Ok(LocalResult::NativeEffectChallenge(
                        LocalNativeEffectChallenge {
                            operation_id,
                            challenge: nonce,
                        },
                    )),
                })
                .map_err(|_| ())?;
            loop {
                operation.check().map_err(|_| ())?;
                send_guarded_stream_events(coordinator, state, connection, operation)?;
                connection.set_deadline(operation.deadline());
                if !connection
                    .wait_readable(Duration::from_millis(20))
                    .map_err(|_| ())?
                {
                    continue;
                }
                let decision_request = connection.read_request().map_err(|_| ())?;
                if decision_request.version != version || decision_request.request_id != request_id
                {
                    return Err(());
                }
                let decision = match decision_request.call {
                    LocalCall::NativeEffectDecision(decision)
                        if decision.operation_id == operation_id && decision.challenge == nonce =>
                    {
                        decision
                    }
                    _ => return Err(()),
                };
                native_editor::GuardedEditorExchange::respond(challenge, decision.allowed)
                    .map_err(|_| ())?;
                break;
            }
            continue;
        }

        if !completion_seen {
            completion_seen = exchange.wait_for_completion(Duration::from_millis(5));
        }
        if completion_seen {
            // `status` joins finished handles and persists completion before
            // reporting a terminal state. No owner or Store lock is held while
            // waiting for the client or the native effect worker.
            let editor = coordinator.native_editor().map_err(|_| ())?;
            let result = editor
                .status(
                    operation,
                    NativeIntentTarget {
                        intent_id: exchange.operation_id,
                    },
                )
                .map_err(|_| ())?;
            if matches!(
                &result,
                LocalResult::NativeEditor(value)
                    if value.state != LocalNativeEffectState::Running
            ) {
                return Ok(LocalResponse {
                    version,
                    request_id,
                    result: Ok(result),
                });
            }
            thread::sleep(Duration::from_millis(2));
        } else if connection
            .wait_readable(Duration::from_millis(1))
            .map_err(|_| ())?
        {
            // No decision is valid until its exact challenge has been sent.
            return Err(());
        }
    }
}

fn serve_guarded_native_git_exchange(
    coordinator: &Coordinator,
    state: &mut rpc::ConnectionState,
    connection: &mut platform::LocalConnection,
    operation: &owner_domain::Operation<'_>,
    native_connection: IpcNonce,
    request_id: RequestId,
    execute: LocalNativeGitExecute,
) -> Result<LocalResponse, ()> {
    let (initial, exchange) = match coordinator
        .native_git()
        .and_then(|git| git.execute_guarded(operation, native_connection, execute))
    {
        Ok(value) => value,
        Err(error) => {
            return Ok(LocalResponse {
                version: connection.version(),
                request_id,
                result: Err(error),
            });
        }
    };
    let Some(exchange) = exchange else {
        return Ok(LocalResponse {
            version: connection.version(),
            request_id,
            result: Ok(initial),
        });
    };
    let version = connection.version();
    let mut completion_seen = false;
    loop {
        operation.check().map_err(|_| ())?;
        send_guarded_stream_events(coordinator, state, connection, operation)?;
        if let Some(challenge) = exchange.try_challenge() {
            let operation_id = challenge.operation_id;
            let nonce = challenge.challenge;
            connection.set_deadline(operation.deadline());
            connection
                .write(&LocalResponse {
                    version: version.clone(),
                    request_id: request_id.clone(),
                    result: Ok(LocalResult::NativeEffectChallenge(
                        LocalNativeEffectChallenge {
                            operation_id,
                            challenge: nonce,
                        },
                    )),
                })
                .map_err(|_| ())?;
            loop {
                operation.check().map_err(|_| ())?;
                send_guarded_stream_events(coordinator, state, connection, operation)?;
                connection.set_deadline(operation.deadline());
                if !connection
                    .wait_readable(Duration::from_millis(20))
                    .map_err(|_| ())?
                {
                    continue;
                }
                let decision_request = connection.read_request().map_err(|_| ())?;
                if decision_request.version != version || decision_request.request_id != request_id
                {
                    return Err(());
                }
                let decision = match decision_request.call {
                    LocalCall::NativeEffectDecision(decision)
                        if decision.operation_id == operation_id && decision.challenge == nonce =>
                    {
                        decision
                    }
                    _ => return Err(()),
                };
                let allowed = decision.allowed
                    && (!challenge.before_execution
                        || coordinator.native_git().is_ok_and(|git| {
                            git.authorize_before_execution(operation, operation_id)
                                .is_ok()
                        }));
                native_git::GuardedNativeGitExchange::respond(challenge, allowed)
                    .map_err(|_| ())?;
                break;
            }
            continue;
        }
        if !completion_seen {
            completion_seen = exchange.wait_for_completion(Duration::from_millis(5));
        }
        if completion_seen {
            let result = coordinator
                .native_git()
                .and_then(|git| {
                    git.status(
                        operation,
                        NativeIntentTarget {
                            intent_id: exchange.operation_id,
                        },
                    )
                })
                .map_err(|_| ())?;
            if matches!(
                &result,
                LocalResult::NativeGit(value)
                    if matches!(value.state, LocalNativeGitState::Succeeded
                        | LocalNativeGitState::Failed | LocalNativeGitState::OutcomeUnknown)
            ) {
                return Ok(LocalResponse {
                    version,
                    request_id,
                    result: Ok(result),
                });
            }
            thread::sleep(Duration::from_millis(2));
        } else if connection
            .wait_readable(Duration::from_millis(1))
            .map_err(|_| ())?
        {
            return Err(());
        }
    }
}

fn send_guarded_stream_events(
    coordinator: &Coordinator,
    state: &mut rpc::ConnectionState,
    connection: &mut platform::LocalConnection,
    operation: &owner_domain::Operation<'_>,
) -> Result<(), ()> {
    for _ in 0..8 {
        let stream_operation = owner_domain::Operation::new(
            operation
                .deadline()
                .min(Instant::now() + Duration::from_secs(1)),
            &coordinator.stopping,
        );
        let Some(event) = state.next_event(&stream_operation) else {
            break;
        };
        connection.set_deadline(operation.deadline());
        connection.write(&event).map_err(|_| ())?;
    }
    Ok(())
}

pub fn run(profile: &Path) -> Result<(), HostError> {
    let expected_identity = initialize_profile(profile)?;
    run_bound_identity(profile, &expected_identity)
}

/// Run a managed Host from an existing initialized profile only.
pub fn run_existing(profile: &Path) -> Result<(), HostError> {
    run_with_ready_existing(profile, |_| Ok(()))
}

/// Start the Host only when its existing Store has the caller's pinned Host ID.
pub fn run_bound(profile: &Path, expected_host_id: HostId) -> Result<(), HostError> {
    run_with_managed_callbacks_bound(profile, Some(expected_host_id), |_| Ok(()), |_| Ok(()))
}

/// Run only the Store with both fields of its previously initialized identity.
pub fn run_bound_identity(
    profile: &Path,
    expected_identity: &lomi_host_store::Identity,
) -> Result<(), HostError> {
    run_with_managed_callbacks_using_auth_bound_mode(
        profile,
        |_| Ok(()),
        |_| Ok(()),
        auth::start,
        Some(expected_identity.host_id),
        Some(expected_identity.profile_id),
        true,
    )
}

pub(super) fn run_with_ready(
    profile: &Path,
    ready: impl FnOnce(lomi_remote_protocol::RuntimeId),
) -> Result<(), HostError> {
    run_with_fallible_ready(profile, |runtime| {
        ready(runtime);
        Ok(())
    })
}

pub(super) fn run_with_fallible_ready(
    profile: &Path,
    ready: impl FnOnce(lomi_remote_protocol::RuntimeId) -> Result<(), HostError>,
) -> Result<(), HostError> {
    run_with_managed_callbacks_using_auth(profile, ready, |_| Ok(()), auth::start)
}

/// Managed service readiness callback that never creates a profile, owner
/// lock, or database when any existing state is missing.
pub(super) fn run_with_ready_existing(
    profile: &Path,
    ready: impl FnOnce(lomi_remote_protocol::RuntimeId) -> Result<(), HostError>,
) -> Result<(), HostError> {
    run_with_managed_callbacks_using_auth_bound_mode(
        profile,
        ready,
        |_| Ok(()),
        auth::start,
        None,
        None,
        true,
    )
}

/// Managed start that requires both fields of a previously observed native
/// Host identity on the same SQLite connection before migration or recovery.
pub(super) fn run_with_ready_existing_identity(
    profile: &Path,
    expected_identity: &lomi_host_store::Identity,
    ready: impl FnOnce(lomi_remote_protocol::RuntimeId) -> Result<(), HostError>,
) -> Result<(), HostError> {
    run_with_managed_callbacks_using_auth_bound_mode(
        profile,
        ready,
        |_| Ok(()),
        auth::start,
        Some(expected_identity.host_id),
        Some(expected_identity.profile_id),
        true,
    )
}

#[cfg(windows)]
pub(super) fn run_with_managed_callbacks(
    profile: &Path,
    ready: impl FnOnce(lomi_remote_protocol::RuntimeId) -> Result<(), HostError>,
    finished: impl FnOnce(Result<(), HostError>) -> Result<(), HostError>,
) -> Result<(), HostError> {
    run_with_managed_callbacks_using_auth_bound_mode(
        profile,
        ready,
        finished,
        auth::start,
        None,
        None,
        cfg!(windows),
    )
}

fn require_host_account() -> Result<(), HostError> {
    #[cfg(any(unix, windows))]
    if lomi_platform::setup_context::current_account()
        .map_err(|_| HostError::NonRootAccountRequired)?
        .is_root()
    {
        return Err(HostError::NonRootAccountRequired);
    }
    #[cfg(target_os = "linux")]
    {
        let (mut real, mut effective, mut saved) = (0, 0, 0);
        // A permanently selected account must own the Host and every shell.
        // A temporary effective-UID drop with saved root credentials is not
        // the dedicated-account setup required by the product.
        if unsafe { libc::getresuid(&mut real, &mut effective, &mut saved) } != 0
            || real == 0
            || effective == 0
            || saved == 0
        {
            return Err(HostError::NonRootAccountRequired);
        }
    }
    Ok(())
}

const HOST_INITIALIZATION_RECEIPT_VERSION: u8 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
enum HostInitializationBinding {
    #[cfg(unix)]
    Unix {
        uid: u32,
        gid: u32,
        device: u64,
        inode: u64,
    },
    #[cfg(windows)]
    Windows {
        sid: String,
        volume: u64,
        file_index: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HostInitializationState {
    Creating,
    Complete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HostInitializationReceipt {
    version: u8,
    state: HostInitializationState,
    profile_path: String,
    owner: HostInitializationBinding,
    host_id: Option<String>,
    profile_id: Option<String>,
}

fn host_initialization_owner(lock: &OwnerLock) -> Result<HostInitializationBinding, HostError> {
    let account = lomi_platform::setup_context::current_account()
        .map_err(|_| HostError::NonRootAccountRequired)?
        .selected()
        .cloned()
        .ok_or(HostError::NonRootAccountRequired)?;
    let (first, second) = lock.profile_identity();
    #[cfg(unix)]
    {
        let account = account.unix().ok_or(HostError::NonRootAccountRequired)?;
        Ok(HostInitializationBinding::Unix {
            uid: account.uid(),
            gid: account.gid(),
            device: first,
            inode: second,
        })
    }
    #[cfg(windows)]
    {
        let account = account.windows().ok_or(HostError::NonRootAccountRequired)?;
        Ok(HostInitializationBinding::Windows {
            sid: account.sid().to_owned(),
            volume: first,
            file_index: second,
        })
    }
}

fn initialization_receipt(
    lock: &OwnerLock,
) -> Result<Option<HostInitializationReceipt>, HostError> {
    let Some(bytes) = lock
        .read_host_initialization_receipt()
        .map_err(map_initialization_platform_error)?
    else {
        return Ok(None);
    };
    let receipt: HostInitializationReceipt =
        serde_json::from_slice(&bytes).map_err(|_| HostError::InvalidProfile)?;
    if serde_json::to_vec(&receipt).map_err(|_| HostError::InvalidProfile)? != bytes
        || receipt.version != HOST_INITIALIZATION_RECEIPT_VERSION
        || receipt.profile_path
            != lock
                .profile()
                .path()
                .to_str()
                .ok_or(HostError::InvalidProfile)?
        || receipt.owner != host_initialization_owner(lock)?
    {
        return Err(HostError::InvalidProfile);
    }
    match receipt.state {
        HostInitializationState::Creating
            if receipt.host_id.is_none() && receipt.profile_id.is_none() => {}
        HostInitializationState::Complete => {
            parse_initialization_identity(&receipt)?;
        }
        _ => return Err(HostError::InvalidProfile),
    }
    Ok(Some(receipt))
}

fn parse_initialization_identity(
    receipt: &HostInitializationReceipt,
) -> Result<lomi_host_store::Identity, HostError> {
    let host_id = receipt
        .host_id
        .as_ref()
        .ok_or(HostError::InvalidProfile)?
        .clone()
        .try_into()
        .map_err(|_| HostError::InvalidProfile)?;
    let profile_id = receipt
        .profile_id
        .as_ref()
        .ok_or(HostError::InvalidProfile)?
        .clone()
        .try_into()
        .map_err(|_| HostError::InvalidProfile)?;
    Ok(lomi_host_store::Identity {
        host_id,
        profile_id,
    })
}

fn make_initialization_receipt(
    lock: &OwnerLock,
    state: HostInitializationState,
    identity: Option<&lomi_host_store::Identity>,
) -> Result<HostInitializationReceipt, HostError> {
    let receipt = HostInitializationReceipt {
        version: HOST_INITIALIZATION_RECEIPT_VERSION,
        state,
        profile_path: lock
            .profile()
            .path()
            .to_str()
            .ok_or(HostError::InvalidProfile)?
            .to_owned(),
        owner: host_initialization_owner(lock)?,
        host_id: identity.map(|value| String::from(value.host_id)),
        profile_id: identity.map(|value| String::from(value.profile_id)),
    };
    if state == HostInitializationState::Complete {
        parse_initialization_identity(&receipt)?;
    } else if identity.is_some() {
        return Err(HostError::InvalidProfile);
    }
    Ok(receipt)
}

fn write_initialization_receipt(
    lock: &OwnerLock,
    receipt: &HostInitializationReceipt,
) -> Result<(), HostError> {
    let bytes = serde_json::to_vec(receipt).map_err(|_| HostError::InvalidProfile)?;
    lock.replace_host_initialization_receipt(&bytes)
        .map_err(map_initialization_platform_error)
}

fn map_initialization_platform_error(error: platform::Error) -> HostError {
    match error {
        platform::Error::Busy => HostError::Busy,
        platform::Error::InvalidProfile | platform::Error::PermissionDenied => {
            HostError::InvalidProfile
        }
        _ => HostError::Storage,
    }
}

fn store_error_for_initialization(error: StoreError, pinned: bool) -> HostError {
    match error {
        StoreError::Busy => HostError::Busy,
        StoreError::Fenced if pinned => HostError::IdentityMismatch,
        StoreError::SchemaVersion | StoreError::Invalid => HostError::InvalidProfile,
        _ => HostError::Storage,
    }
}

fn merge_host_identity_pins(pins: &[Option<HostId>]) -> Result<Option<HostId>, HostError> {
    let mut found = None;
    for pin in pins.iter().flatten().copied() {
        if found.is_some_and(|existing| existing != pin) {
            return Err(HostError::IdentityMismatch);
        }
        found = Some(pin);
    }
    Ok(found)
}

fn initialization_host_id(
    receipt: Option<&HostInitializationReceipt>,
) -> Result<Option<HostId>, HostError> {
    match receipt {
        None => Ok(None),
        Some(receipt) if receipt.state == HostInitializationState::Creating => {
            Err(HostError::IdentityMismatch)
        }
        Some(receipt) => Ok(Some(parse_initialization_identity(receipt)?.host_id)),
    }
}

fn initialization_identity(
    receipt: Option<&HostInitializationReceipt>,
) -> Result<Option<lomi_host_store::Identity>, HostError> {
    match receipt {
        None => Ok(None),
        Some(receipt) if receipt.state == HostInitializationState::Creating => {
            Err(HostError::IdentityMismatch)
        }
        Some(receipt) => Ok(Some(parse_initialization_identity(receipt)?)),
    }
}

fn merge_profile_identity_pins(
    pins: &[Option<IpcProfileId>],
) -> Result<Option<IpcProfileId>, HostError> {
    let mut found = None;
    for pin in pins.iter().flatten().copied() {
        if found.is_some_and(|existing| existing != pin) {
            return Err(HostError::IdentityMismatch);
        }
        found = Some(pin);
    }
    Ok(found)
}

/// Create or validate the selected account's durable Host identity without
/// starting IPC, authentication workers, terminals, or a runtime loop.
///
/// A bounded owner-private Creating receipt is synced before creating a new
/// SQLite file. Retries recover WAL on the same SQLite connection and preserve
/// a committed identity. Complete receipts pin both HostId and profile ID;
/// setup-journal IDs only attenuate initialization and never mint identity.
pub fn initialize_profile(profile: &Path) -> Result<lomi_host_store::Identity, HostError> {
    require_host_account()?;
    let lock = OwnerLock::acquire(profile)?;
    // The root projection is optional only for this initializer: the first
    // signed admin install publishes it after the selected-account DB identity
    // is observed. If present, it is a mandatory conjunctive pin.
    let current_executable = std::env::current_exe().map_err(|_| HostError::Unavailable)?;
    let admin_identity = admin_host_identity_pin(profile, &current_executable, false)?;
    let journal_host_id =
        lomi_platform::setup_journal::read_expected_host_id(lock.profile().path())
            .map_err(|_| HostError::InvalidProfile)?;
    let expected_host_id = merge_host_identity_pins(&[
        journal_host_id,
        admin_identity.as_ref().map(|identity| identity.host_id),
    ])?;
    let expected_profile_id = admin_identity.as_ref().map(|identity| identity.profile_id);
    let database = lock.profile().path().join("host.sqlite3");
    let mut receipt = initialization_receipt(&lock)?;
    let has_database_set = lock
        .database_set_exists()
        .map_err(map_initialization_platform_error)?;

    if let Some(receipt) = receipt.as_ref() {
        if receipt.state == HostInitializationState::Complete {
            let pinned = parse_initialization_identity(receipt)?;
            if expected_host_id.is_some_and(|expected| expected != pinned.host_id) {
                return Err(HostError::IdentityMismatch);
            }
            if !has_database_set {
                return Err(HostError::IdentityMismatch);
            }
            let database = lock.validate_existing_database()?;
            let store =
                HostStore::open_existing_identity_bound(&database, Limits::default(), &pinned)
                    .map_err(|error| store_error_for_initialization(error, true))?;
            if store.identity() != &pinned
                || expected_profile_id.is_some_and(|expected| expected != pinned.profile_id)
            {
                return Err(HostError::IdentityMismatch);
            }
            return Ok(pinned);
        }
    }

    if !has_database_set {
        if expected_host_id.is_some() {
            return Err(HostError::IdentityMismatch);
        }
        if receipt.is_none() {
            // This is the only point allowed to create a Creating receipt:
            // under the same profile lock, all DB files and sidecars were
            // proved absent and no setup identity is pinned.
            let creating =
                make_initialization_receipt(&lock, HostInitializationState::Creating, None)?;
            write_initialization_receipt(&lock, &creating)?;
            receipt = Some(creating);
        }
        lock.prepare_database()
            .map_err(map_initialization_platform_error)?;
    } else {
        match std::fs::symlink_metadata(&database) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => return Err(HostError::InvalidProfile),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // A sidecar without its main database is never a fresh state.
                return Err(HostError::InvalidProfile);
            }
            Err(_) => return Err(HostError::Storage),
        }
        if receipt.is_none() {
            let metadata = std::fs::symlink_metadata(&database).map_err(|_| HostError::Storage)?;
            if metadata.len() == 0 {
                // Without a Creating receipt, a live empty/zero-schema file
                // could belong to another producer and is never adopted.
                return Err(HostError::InvalidProfile);
            }
        }
    }

    let database = if has_database_set {
        lock.validate_existing_database()
            .map_err(map_initialization_platform_error)?
    } else {
        database
    };
    let store = if has_database_set && let Some(admin_identity) = admin_identity.as_ref() {
        // The protected root projection pins both identity fields. For an
        // existing DB, enforce them on this SQLite connection before any
        // receipt-driven recovery, migration, or checkpoint can mutate it.
        HostStore::open_existing_identity_bound(&database, Limits::default(), admin_identity)
    } else if receipt.is_some() {
        HostStore::initialize_after_receipt(&database, Limits::default(), expected_host_id)
    } else {
        match expected_host_id {
            Some(expected) => {
                HostStore::open_existing_bound(&database, Limits::default(), expected)
            }
            None => HostStore::open_existing(&database, Limits::default()),
        }
    }
    .map_err(|error| store_error_for_initialization(error, expected_host_id.is_some()))?;
    if expected_host_id.is_some_and(|expected| expected != store.identity().host_id)
        || expected_profile_id.is_some_and(|expected| expected != store.identity().profile_id)
    {
        return Err(HostError::IdentityMismatch);
    }
    store
        .checkpoint_initialization()
        .map_err(|error| store_error_for_initialization(error, false))?;
    let identity = store.identity().clone();
    drop(store);
    lock.sync_database()
        .map_err(map_initialization_platform_error)?;
    let complete =
        make_initialization_receipt(&lock, HostInitializationState::Complete, Some(&identity))?;
    write_initialization_receipt(&lock, &complete)?;
    Ok(identity)
}

fn run_with_managed_callbacks_using_auth(
    profile: &Path,
    ready: impl FnOnce(lomi_remote_protocol::RuntimeId) -> Result<(), HostError>,
    finished: impl FnOnce(Result<(), HostError>) -> Result<(), HostError>,
    start_auth: impl FnOnce(
        Arc<OwnerEndpoint>,
        Arc<shared_owner::SharedOwner>,
        Arc<AtomicBool>,
        std::sync::Weak<Coordinator>,
    ) -> (auth::Handle, thread::JoinHandle<()>),
) -> Result<(), HostError> {
    run_with_managed_callbacks_using_auth_bound(profile, ready, finished, start_auth, None)
}

fn run_with_managed_callbacks_bound(
    profile: &Path,
    expected_host_id: Option<HostId>,
    ready: impl FnOnce(lomi_remote_protocol::RuntimeId) -> Result<(), HostError>,
    finished: impl FnOnce(Result<(), HostError>) -> Result<(), HostError>,
) -> Result<(), HostError> {
    run_with_managed_callbacks_using_auth_bound_mode(
        profile,
        ready,
        finished,
        auth::start,
        expected_host_id,
        None,
        true,
    )
}

fn run_with_managed_callbacks_using_auth_bound(
    profile: &Path,
    ready: impl FnOnce(lomi_remote_protocol::RuntimeId) -> Result<(), HostError>,
    finished: impl FnOnce(Result<(), HostError>) -> Result<(), HostError>,
    start_auth: impl FnOnce(
        Arc<OwnerEndpoint>,
        Arc<shared_owner::SharedOwner>,
        Arc<AtomicBool>,
        std::sync::Weak<Coordinator>,
    ) -> (auth::Handle, thread::JoinHandle<()>),
    expected_host_id: Option<HostId>,
) -> Result<(), HostError> {
    run_with_managed_callbacks_using_auth_bound_mode(
        profile,
        ready,
        finished,
        start_auth,
        expected_host_id,
        None,
        false,
    )
}

fn run_with_managed_callbacks_using_auth_bound_mode(
    profile: &Path,
    ready: impl FnOnce(lomi_remote_protocol::RuntimeId) -> Result<(), HostError>,
    finished: impl FnOnce(Result<(), HostError>) -> Result<(), HostError>,
    start_auth: impl FnOnce(
        Arc<OwnerEndpoint>,
        Arc<shared_owner::SharedOwner>,
        Arc<AtomicBool>,
        std::sync::Weak<Coordinator>,
    ) -> (auth::Handle, thread::JoinHandle<()>),
    expected_host_id: Option<HostId>,
    expected_profile_id: Option<IpcProfileId>,
    existing_profile: bool,
) -> Result<(), HostError> {
    require_host_account()?;
    lomi_platform::installation::check_current_executable().map_err(|_| HostError::Unavailable)?;
    #[cfg(unix)]
    lomi_platform::process::require_child_ownership().map_err(|_| HostError::Unavailable)?;
    #[cfg(windows)]
    crate::windows_launch::prepare_console_control().map_err(|_| HostError::Unavailable)?;
    let lock = if existing_profile {
        OwnerLock::acquire_existing(profile)?
    } else {
        OwnerLock::acquire(profile)?
    };
    let current_executable = std::env::current_exe().map_err(|_| HostError::Unavailable)?;
    let admin_identity = admin_host_identity_pin(profile, &current_executable, true)?;
    let durable_host_id =
        lomi_platform::setup_journal::read_expected_host_id(lock.profile().path())
            .map_err(|_| HostError::InvalidProfile)?;
    let receipt_identity = initialization_identity(initialization_receipt(&lock)?.as_ref())?;
    let expected_host_id = merge_host_identity_pins(&[
        expected_host_id,
        durable_host_id,
        admin_identity.as_ref().map(|value| value.host_id),
        receipt_identity.as_ref().map(|value| value.host_id),
    ])?;
    let expected_profile_id = merge_profile_identity_pins(&[
        expected_profile_id,
        admin_identity.as_ref().map(|value| value.profile_id),
        receipt_identity.as_ref().map(|value| value.profile_id),
    ])?;
    if expected_profile_id.is_some() && expected_host_id.is_none() {
        return Err(HostError::IdentityMismatch);
    }
    // Check again while holding the same lock used by installer activation.
    // A pre-lock observation cannot authorize startup after an interrupted
    // replacement that raced the process launch.
    lomi_platform::installation::check_current_executable().map_err(|_| HostError::Unavailable)?;
    if existing_profile || expected_host_id.is_some() {
        match std::fs::symlink_metadata(lock.profile().path().join("host.sqlite3")) {
            Ok(metadata) if metadata.file_type().is_file() && metadata.len() > 0 => {}
            _ => return Err(HostError::IdentityMismatch),
        }
    }
    let database = if existing_profile {
        lock.validate_existing_database()?
    } else {
        lock.prepare_database()?
    };
    let opened = if existing_profile && expected_host_id.is_none() && expected_profile_id.is_none()
    {
        HostStore::open_existing(&database, Limits::default())
    } else if let (Some(host_id), Some(profile_id)) = (expected_host_id, expected_profile_id) {
        HostStore::open_existing_identity_bound(
            &database,
            Limits::default(),
            &lomi_host_store::Identity {
                host_id,
                profile_id,
            },
        )
    } else {
        HostStore::open_bound(&database, Limits::default(), expected_host_id)
    };
    let mut store = opened.map_err(|e| {
        if e == StoreError::Busy {
            HostError::Busy
        } else if (expected_host_id.is_some() || existing_profile)
            && matches!(e, StoreError::Fenced | StoreError::SchemaVersion)
        {
            HostError::IdentityMismatch
        } else {
            HostError::Storage
        }
    })?;
    #[cfg(any(unix, windows))]
    {
        public_configuration::startup(&mut store, lock.profile())
            .map_err(|_| HostError::Storage)?;
        if let Some(configuration) = store.auth_configuration().map_err(|_| HostError::Storage)? {
            auth::configuration(store.identity(), &configuration)
                .map_err(|_| HostError::InvalidProfile)?;
        }
    }
    // Prepare the canonical shell assets under the actual locked Host profile,
    // independently of a Desktop installation or an attached renderer.
    lomi_terminal::shell::prepare(lock.profile().path()).map_err(|_| HostError::InvalidProfile)?;
    rpc::initialize_default_shell(&mut store).map_err(|_| HostError::InvalidProfile)?;
    store.seal_authorization(); // Restart always requires fresh server verification.
    let discovery = LocalDiscovery {
        version: LocalIpcVersion::CURRENT,
        profile_id: store.identity().profile_id,
        host_id: store.identity().host_id,
        runtime_id: store.runtime_id(),
        build_id: env!("CARGO_PKG_VERSION").to_owned(),
    };
    let endpoint = Arc::new(OwnerEndpoint::bind(lock, discovery)?);
    let stopping = Arc::new(AtomicBool::new(false));
    let _stop_on_drop = StopOnDrop(stopping.clone());
    let mut signal_guards = SignalGuards(Vec::new());
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_guards.0.push(
            signal_hook::flag::register(signal, stopping.clone())
                .map_err(|_| HostError::Unavailable)?,
        );
    }
    let executable = std::env::current_exe().map_err(|_| HostError::Unavailable)?;
    let mut coordinator = Coordinator::with_terminals(
        store,
        stopping.clone(),
        TerminalService::with_worker_in_profile(executable, profile.to_path_buf()),
    )
    .map_err(|_| HostError::Storage)?;
    coordinator.profile = Some(profile.to_path_buf());
    let native_editor = Arc::new(native_editor::NativeEditorHost::new(
        profile.to_path_buf(),
        coordinator.owner.clone(),
        endpoint.clone(),
        stopping.clone(),
        namespace_runtime::NativeNamespaceRuntime::new(&coordinator),
    ));
    native_editor.cleanup_expired_stages();
    let namespace_recovery =
        owner_domain::Operation::new(Instant::now() + platform::REQUEST_TIMEOUT, &stopping);
    // Unresolved physical/process observations retain quarantine; they must
    // not disable ordinary terminal startup or authorize any replay.
    let _ = native_editor.recover_pending_namespaces(&namespace_recovery);
    *coordinator
        .native_editor
        .lock()
        .map_err(|_| HostError::Unavailable)? = Some(native_editor);
    let native_git = Arc::new(native_git::NativeGitHost::new(
        profile.to_path_buf(),
        coordinator.owner.clone(),
        endpoint.clone(),
        stopping.clone(),
    ));
    // Recovery never authorizes a replay. An unavailable provider retains its
    // durable writer obligations without disabling ordinary terminal startup.
    native_git
        .recover_pending()
        .map_err(|_| HostError::Storage)?;
    *coordinator
        .native_git
        .lock()
        .map_err(|_| HostError::Unavailable)? = Some(native_git);
    #[cfg(target_os = "macos")]
    {
        *coordinator
            .native_evidence
            .lock()
            .map_err(|_| HostError::Unavailable)? =
            Some(Arc::new(native_evidence::NativeEvidenceHost::new(
                profile.to_path_buf(),
                coordinator.owner.clone(),
                endpoint.clone(),
                stopping.clone(),
            )));
    }
    let coordinator = Arc::new(coordinator);
    coordinator.files.protect_host(profile);
    coordinator
        .git_reads
        .protect_host(profile)
        .map_err(|_| HostError::Unavailable)?;
    coordinator
        .git_mutations
        .protect_host(profile)
        .map_err(|_| HostError::Unavailable)?;
    let (auth_handle, auth_worker) = start_auth(
        endpoint.clone(),
        coordinator.owner.clone(),
        stopping.clone(),
        Arc::downgrade(&coordinator),
    );
    *coordinator
        .auth
        .lock()
        .map_err(|_| HostError::Unavailable)? = Some(auth_handle);
    let mut failure = ready(endpoint.discovery().runtime_id).err();
    coordinator.logs.record(
        if failure.is_some() {
            DiagnosticSeverity::Error
        } else {
            DiagnosticSeverity::Info
        },
        DiagnosticComponent::Host,
        if failure.is_some() {
            DiagnosticCode::HostStartRejected
        } else {
            DiagnosticCode::HostStarted
        },
    );
    if failure.is_some() {
        stopping.store(true, Ordering::Release);
    }
    let mut workers: Vec<thread::JoinHandle<()>> = Vec::new();
    while !stopping.load(Ordering::Acquire) {
        let mut index = 0;
        while index < workers.len() {
            if workers[index].is_finished() {
                if workers.swap_remove(index).join().is_err() {
                    failure = Some(HostError::Cleanup);
                }
            } else {
                index += 1;
            }
        }
        let maintenance_cancelled = AtomicBool::new(false);
        let maintenance = owner_domain::Operation::new(
            Instant::now() + platform::REQUEST_TIMEOUT,
            &maintenance_cancelled,
        );
        // A deferred record continues to own its reserved slot/permit on any
        // retry failure. Keep local status available and retry persistence on
        // the next explicitly admitted maintenance pass.
        let _ = rpc::reconcile_deferred_completions(&coordinator, &maintenance);
        if let Ok(native_editor) = coordinator.native_editor() {
            native_editor.reap_finished();
            let _ = native_editor.recover_pending_namespaces(&maintenance);
            native_editor.cleanup_expired_stages_if_due();
        }
        if let Ok(native_git) = coordinator.native_git() {
            native_git.reap_finished();
        }
        if maintenance.check().is_ok()
            && rpc::reconcile_terminal_lifecycle(&coordinator, &maintenance).is_err()
        {
            failure = Some(HostError::Storage);
            break;
        }
        match endpoint.wait(Duration::from_millis(100)) {
            Ok(false) => continue,
            Err(_) => {
                failure = Some(HostError::Unavailable);
                break;
            }
            Ok(true) => {}
        }
        let stream = match endpoint.accept() {
            Ok(Some(stream)) => stream,
            Ok(None) => continue,
            Err(platform::Error::PermissionDenied) => continue,
            Err(_) => {
                failure = Some(HostError::Unavailable);
                break;
            }
        };
        if workers.len() >= CONNECTIONS {
            drop(stream);
            continue;
        }
        let endpoint = endpoint.clone();
        let coordinator = coordinator.clone();
        workers.push(thread::spawn(move || {
            #[cfg(target_os = "macos")]
            let accepted_peer_stream = stream.try_clone().ok();
            let Ok(mut connection) = endpoint.handshake(stream) else {
                return;
            };
            let connection_operation = owner_domain::Operation::new(
                Instant::now() + platform::REQUEST_TIMEOUT,
                &coordinator.stopping,
            );
            let Ok(mut state) =
                rpc::ConnectionState::new(coordinator.clone(), &connection_operation)
            else {
                return;
            };
            let Ok(native_connection) = IpcNonce::from_bytes(uuid::Uuid::new_v4().into_bytes())
            else {
                return;
            };
            'client: while !coordinator.stopping.load(Ordering::Acquire) {
                // Serialize a bounded number of small frames, then service
                // requests. PTY output/model updates use their independent pump.
                for _ in 0..8 {
                    if coordinator.stopping.load(Ordering::Acquire) {
                        break 'client;
                    }
                    let stream_operation = owner_domain::Operation::new(
                        Instant::now() + Duration::from_secs(1),
                        &coordinator.stopping,
                    );
                    let Some(event) = state.next_event(&stream_operation) else {
                        break;
                    };
                    connection.set_deadline(stream_operation.deadline());
                    if connection.write(&event).is_err() {
                        break 'client;
                    }
                }
                match connection.wait_readable(Duration::from_millis(20)) {
                    Ok(false) => continue,
                    Ok(true) => {}
                    Err(_) => break,
                }
                let Ok(admission) = ipc_admission::IpcAdmission::capture(
                    Duration::from_secs(120),
                    &coordinator.stopping,
                ) else {
                    break;
                };
                connection.set_deadline(admission.frame_deadline(platform::REQUEST_TIMEOUT));
                let Ok(request) = connection.read_request() else {
                    break;
                };
                let decoded_timeout = match &request.call {
                    LocalCall::NativeEditorExecuteGuarded(request) => match &request.effect {
                        LocalNativeEditorEffect::DesktopFiles { timeout_ms, .. } => {
                            Duration::from_millis(timeout_ms.get())
                        }
                        _ => platform::REQUEST_TIMEOUT,
                    },
                    LocalCall::Rpc(request) => Duration::from_millis(request.timeout_ms.get()),
                    LocalCall::NativeGitPrepareGuarded(request) => {
                        Duration::from_millis(request.timeout_ms.get())
                    }
                    LocalCall::NativeGitExecuteGuarded(request) => {
                        Duration::from_millis(request.timeout_ms.get())
                    }
                    _ => platform::REQUEST_TIMEOUT,
                };
                let Ok(operation) = admission.into_operation(decoded_timeout) else {
                    break;
                };
                connection.set_deadline(operation.deadline());
                let request_id = request.request_id;
                match request.call {
                    LocalCall::NativeGitPrepareGuarded(prepare) => {
                        let result = coordinator.native_git().and_then(|git| {
                            git.prepare_guarded(&operation, native_connection, prepare)
                        });
                        if result.is_err() {
                            coordinator.logs.record(
                                DiagnosticSeverity::Warning,
                                DiagnosticComponent::Ipc,
                                DiagnosticCode::IpcRequestRejected,
                            );
                        }
                        let response = LocalResponse {
                            version: connection.version(),
                            request_id,
                            result,
                        };
                        if connection.write(&response).is_err() {
                            break 'client;
                        }
                        continue 'client;
                    }
                    LocalCall::NativeGitExecuteGuarded(execute) => {
                        let Ok(response) = serve_guarded_native_git_exchange(
                            &coordinator,
                            &mut state,
                            &mut connection,
                            &operation,
                            native_connection,
                            request_id,
                            execute,
                        ) else {
                            break 'client;
                        };
                        if connection.write(&response).is_err() {
                            break 'client;
                        }
                        continue 'client;
                    }
                    LocalCall::NativeEditorExecuteGuarded(execute) => {
                        let Ok(response) = serve_guarded_editor_exchange(
                            &coordinator,
                            &mut state,
                            &mut connection,
                            &operation,
                            native_connection,
                            request_id,
                            execute,
                        ) else {
                            break 'client;
                        };
                        if connection.write(&response).is_err() {
                            break 'client;
                        }
                        continue 'client;
                    }
                    call => {
                        let result = match call {
                            LocalCall::StreamAck(ack) => state.acknowledge_stream(ack),
                            LocalCall::NativeEffectDecision(_) => Err(LocalError::InvalidArgument),
                            LocalCall::Rpc(request) => Ok(LocalResult::Rpc(Box::new(
                                rpc::dispatch(&coordinator, &mut state, *request, &operation),
                            ))),
                            #[cfg(target_os = "macos")]
                            call => coordinator.dispatch_on_connection(
                                &operation,
                                call,
                                native_connection,
                                accepted_peer_stream.as_ref(),
                            ),
                            #[cfg(not(target_os = "macos"))]
                            call => coordinator.dispatch_on_connection(
                                &operation,
                                call,
                                native_connection,
                            ),
                        };
                        if result.is_err() {
                            coordinator.logs.record(
                                DiagnosticSeverity::Warning,
                                DiagnosticComponent::Ipc,
                                DiagnosticCode::IpcRequestRejected,
                            );
                        }
                        let response = LocalResponse {
                            version: connection.version(),
                            request_id,
                            result,
                        };
                        if connection.write(&response).is_err() {
                            break;
                        }
                    }
                }
            }
            coordinator.native_connection_lost(native_connection);
        }));
    }
    stopping.store(true, Ordering::Release);
    // All IPC handlers have finite absolute deadlines. Stop execution before
    // releasing database and the owner endpoint, even after an accept failure.
    for worker in workers {
        if worker.join().is_err() {
            failure = Some(HostError::Cleanup);
        }
    }
    if auth_worker.join().is_err() {
        failure = Some(HostError::Cleanup);
    }
    if let Ok(native_editor) = coordinator.native_editor() {
        native_editor.shutdown_and_join();
    }
    if let Ok(native_git) = coordinator.native_git() {
        native_git.shutdown_and_join();
    }
    if coordinator.terminals.shutdown().is_err() {
        failure = Some(HostError::Cleanup);
    } else {
        let cleanup_cancelled = AtomicBool::new(false);
        let cleanup = owner_domain::Operation::new(
            Instant::now() + platform::REQUEST_TIMEOUT,
            &cleanup_cancelled,
        );
        if rpc::reconcile_deferred_completions(&coordinator, &cleanup).is_err() {
            failure = Some(HostError::Storage);
        } else {
            let committed = rpc::owner_call(&cleanup, || {
                coordinator.owner.begin_record_clean_shutdown(&cleanup)
            })
            .and_then(|mut turn| rpc::owner_call(&cleanup, || turn.try_commit()));
            if committed.is_err() {
                failure = Some(HostError::Storage);
            }
        }
    }
    drop(coordinator);
    if let Err(error) = finished(failure.map_or(Ok(()), Err))
        && failure.is_none()
    {
        failure = Some(error);
    }
    drop(endpoint);
    drop(signal_guards);
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Start the same executable without a controlling terminal. Readiness requires
/// the OS-authenticated IPC handshake; a PID file is never treated as authority.
pub fn start(executable: &Path, profile: &Path) -> Result<(), HostError> {
    // Preserve idempotent start for an already-running Host. If an owner is
    // currently initializing or starting, propagate Busy instead of racing a
    // second initializer. Only the absent/unavailable endpoint falls through
    // to the crash-safe initializer.
    match start_existing(executable, profile) {
        Ok(()) => return Ok(()),
        Err(HostError::Unavailable) => {}
        Err(error) => return Err(error),
    }
    let expected_identity = initialize_profile(profile)?;
    start_identity_bound(executable, profile, &expected_identity)
}

/// Start the Host from an already initialized native profile only.
///
/// This is for managed/manual dashboard actions that do not yet have a
/// separately pinned Host ID. The child must prove the existing database
/// identity before it can become ready.
pub fn start_existing(executable: &Path, profile: &Path) -> Result<(), HostError> {
    start_with_identity(executable, profile, None, None, true)
}

/// Start the Host only if its setup identity and authenticated IPC endpoint
/// match the caller's pinned Host ID.
pub fn start_bound(
    executable: &Path,
    profile: &Path,
    expected_host_id: HostId,
) -> Result<(), HostError> {
    start_with_identity(executable, profile, Some(expected_host_id), None, true)
}

/// Start only the Store with both fields of its previously initialized
/// identity. The ready endpoint must repeat both values before success.
pub fn start_identity_bound(
    executable: &Path,
    profile: &Path,
    expected_identity: &lomi_host_store::Identity,
) -> Result<(), HostError> {
    start_with_identity(
        executable,
        profile,
        Some(expected_identity.host_id),
        Some(expected_identity.profile_id),
        true,
    )
}

fn start_with_identity(
    executable: &Path,
    profile: &Path,
    expected_host_id: Option<HostId>,
    expected_profile_id: Option<IpcProfileId>,
    existing_profile: bool,
) -> Result<(), HostError> {
    require_host_account()?;
    let admin_identity = admin_host_identity_pin(profile, executable, true)?;
    let expected_host_id = merge_host_identity_pins(&[
        expected_host_id,
        admin_identity.as_ref().map(|identity| identity.host_id),
    ])?;
    let expected_profile_id = merge_profile_identity_pins(&[
        expected_profile_id,
        admin_identity.as_ref().map(|identity| identity.profile_id),
    ])?;
    if expected_profile_id.is_some() && expected_host_id.is_none() {
        return Err(HostError::IdentityMismatch);
    }
    #[cfg(unix)]
    lomi_platform::process::require_child_ownership().map_err(|_| HostError::Unavailable)?;
    if let Ok(client) = LocalClient::connect_with_timeout(profile, Duration::from_millis(200)) {
        if expected_host_id.is_some_and(|expected| client.discovery().host_id != expected) {
            return Err(HostError::IdentityMismatch);
        }
        if expected_profile_id.is_some_and(|expected| client.discovery().profile_id != expected) {
            return Err(HostError::IdentityMismatch);
        }
        return Ok(());
    }
    let expected_host_id = if existing_profile {
        // This is a read-only admission check. The child repeats it under its
        // own owner lock, so a profile removed after this check still fails
        // closed without being recreated.
        let lock = OwnerLock::acquire_existing(profile)?;
        lock.validate_existing_database()?;
        let durable_host_id =
            lomi_platform::setup_journal::read_expected_host_id(lock.profile().path())
                .map_err(|_| HostError::InvalidProfile)?;
        let receipt_identity = initialization_identity(initialization_receipt(&lock)?.as_ref())?;
        let expected = merge_host_identity_pins(&[
            expected_host_id,
            durable_host_id,
            receipt_identity.as_ref().map(|value| value.host_id),
        ])?;
        let expected_profile_id = merge_profile_identity_pins(&[
            expected_profile_id,
            receipt_identity.as_ref().map(|value| value.profile_id),
        ])?;
        drop(lock);
        if expected_profile_id.is_some() && expected.is_none() {
            return Err(HostError::IdentityMismatch);
        }
        (expected, expected_profile_id)
    } else {
        (expected_host_id, expected_profile_id)
    };
    let (expected_host_id, expected_profile_id) = expected_host_id;
    #[cfg(unix)]
    let mut child = {
        use std::os::unix::process::CommandExt;
        let mut command = Command::new(executable);
        command
            .arg("--profile-dir")
            .arg(profile)
            .args(["daemon", "run"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if existing_profile && expected_host_id.is_none() {
            command.arg("--existing-profile");
        }
        if let Some(expected_host_id) = expected_host_id {
            command
                .arg("--expected-host-id")
                .arg(String::from(expected_host_id));
        }
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        command.spawn().map_err(|_| HostError::Unavailable)?
    };
    #[cfg(windows)]
    let mut child = if existing_profile && expected_host_id.is_none() {
        crate::windows_launch::spawn_existing(executable, profile)
    } else {
        crate::windows_launch::spawn_bound(executable, profile, expected_host_id)
    }
    .map_err(|_| HostError::Unavailable)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(client) = LocalClient::connect_with_timeout(profile, Duration::from_millis(200)) {
            if expected_host_id.is_some_and(|expected| client.discovery().host_id != expected) {
                if child
                    .try_wait()
                    .map_err(|_| HostError::Unavailable)?
                    .is_none()
                {
                    child.kill().map_err(|_| HostError::Cleanup)?;
                    child.wait().map_err(|_| HostError::Cleanup)?;
                }
                return Err(HostError::IdentityMismatch);
            }
            if expected_profile_id.is_some_and(|expected| client.discovery().profile_id != expected)
            {
                if child
                    .try_wait()
                    .map_err(|_| HostError::Unavailable)?
                    .is_none()
                {
                    child.kill().map_err(|_| HostError::Cleanup)?;
                    child.wait().map_err(|_| HostError::Cleanup)?;
                }
                return Err(HostError::IdentityMismatch);
            }
            // Reap asynchronously when used from a long-lived local caller.
            thread::spawn(move || {
                let _ = child.wait();
            });
            return Ok(());
        }
        if child
            .try_wait()
            .map_err(|_| HostError::Unavailable)?
            .is_some()
        {
            return Err(HostError::Unavailable);
        }
        if Instant::now() >= deadline {
            #[cfg(unix)]
            lomi_platform::process::require_unreaped_child(&child)
                .map_err(|_| HostError::Cleanup)?;
            let _ = child.kill();
            let _ = child.wait();
            return Err(HostError::Unavailable);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

pub fn stop(profile: &Path) -> Result<(), HostError> {
    stop_with_expected_host_id(profile, None)
}

/// Stop only the Host whose authenticated IPC identity matches `expected_host_id`.
pub fn stop_bound(profile: &Path, expected_host_id: HostId) -> Result<(), HostError> {
    stop_with_expected_host_id(profile, Some(expected_host_id))
}

fn stop_with_expected_host_id(
    profile: &Path,
    expected_host_id: Option<HostId>,
) -> Result<(), HostError> {
    let mut client = LocalClient::connect(profile)?;
    if expected_host_id.is_some_and(|expected| client.discovery().host_id != expected) {
        return Err(HostError::IdentityMismatch);
    }
    let runtime = client.discovery().runtime_id;
    let response = client.request(LocalCall::DaemonStop(LocalOperatorIntent {
        operator_intent: Confirmed::Confirmed,
    }))?;
    if !matches!(response.result, Ok(LocalResult::Stopping {})) {
        return Err(HostError::Unavailable);
    }
    drop(client);
    let deadline = Instant::now() + Duration::from_secs(25);
    while profile.join("discovery.json").exists() {
        if let Ok(client) = LocalClient::connect_with_timeout(profile, Duration::from_millis(100)) {
            if expected_host_id.is_some_and(|expected| client.discovery().host_id != expected) {
                return Err(HostError::IdentityMismatch);
            }
            if client.discovery().runtime_id != runtime {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(HostError::Cleanup);
        }
        thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}
