//! Owner-local editor and desktop file effects executed by a bounded host thread.
//!
//! Staged bytes are read and verified before the durable job/fence transaction.
//! The worker receives only typed effect input and cannot spawn processes or
//! access IPC. Only this host's join path can complete the durable job and
//! release its native writer fence.

use super::{
    LocalError, LocalResult, desktop_namespace::PhysicalNamespacePins,
    namespace_runtime::NativeNamespaceRuntime, owner_domain::Operation, platform, rpc,
    shared_owner,
};
use lomi_files::LocalNativeFileCheckPhase;
use lomi_files::desktop::{DesktopFileErrorCode, DesktopMutationError, DesktopMutationRequest};
use lomi_host_store::{
    NativeEditorBegin, NativeEditorCompletionProof, NativeEditorJobRecord, NativeEditorJobState,
    StoreError, WorkspaceEffectGuard,
};
use lomi_native_files::{
    NativeFileCheckPhase, NativeFileError, NativeFileErrorKind, NativeFileLocation, NativeSaveFile,
    NativeSaveNew, NativeSaveNewChecked, NativeSaveRequest, NativeSaveResult,
};
use lomi_native_project_files::{
    NativeArtifactCreated, NativeProjectCheckPhase, NativeProjectDirectory, NativeProjectErrorCode,
    NativeProjectMutation, NativeProjectMutationError, NativeProjectMutationResult,
};
use lomi_remote_protocol::ipc::{
    self, LocalNativeEditorEffect, LocalNativeEditorExecute, LocalNativeEditorResult,
    LocalNativeEffectState, LocalNativeFileBlob, LocalNativeFileStage, LocalNativeResultJson,
    NativeIntentId,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const MAX_INPUT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_PROJECT_MUTATION_BYTES: usize = 1024 * 1024;
const MAX_DESKTOP_MUTATION_BYTES: usize = 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 4 * 1024 * 1024;
const READ_CHUNK_BYTES: usize = 64 * 1024;
const GUARDED_PROGRESS_AUTHORIZATION_INTERVAL: Duration = Duration::from_millis(50);
const GUARDED_PUBLICATION_APPROVAL_MAX_AGE: Duration = Duration::from_secs(1);
const NAMESPACE_RECOVERY_INTERVAL: Duration = Duration::from_secs(30);

type WorkerResult = Result<WorkerOutput, WorkerFailure>;

enum WorkerRequest {
    Editor(NativeSaveRequest),
    ProjectFiles {
        root: PathBuf,
    },
    DesktopFiles {
        root: PathBuf,
        profile: PathBuf,
    },
    ArtifactCreate {
        root: PathBuf,
        relative: String,
        expected_parent_revision: String,
    },
}

enum WorkerContent {
    Text(String),
    Raw(Vec<u8>),
}

#[derive(Clone, Copy)]
enum WorkerKind {
    Editor,
    ProjectFiles,
    DesktopFiles,
}

impl WorkerRequest {
    fn kind(&self) -> WorkerKind {
        match self {
            Self::Editor(_) => WorkerKind::Editor,
            Self::ProjectFiles { .. } | Self::ArtifactCreate { .. } => WorkerKind::ProjectFiles,
            Self::DesktopFiles { .. } => WorkerKind::DesktopFiles,
        }
    }

    fn takes_raw_content(&self) -> bool {
        matches!(self, Self::ArtifactCreate { .. })
    }

    fn requires_guarded_execution(&self) -> bool {
        matches!(
            self,
            Self::ProjectFiles { .. } | Self::DesktopFiles { .. } | Self::ArtifactCreate { .. }
        )
    }
}

enum WorkerOutput {
    Editor(NativeSaveResult),
    ProjectFiles(NativeProjectMutationResult),
    DesktopFiles(lomi_files::desktop::DesktopFileChange),
    ArtifactCreate(NativeArtifactCreated),
}

enum WorkerFailure {
    Editor(NativeFileError),
    ProjectFiles(NativeProjectMutationError),
    DesktopFiles(DesktopMutationError),
}

impl WorkerFailure {
    fn outcome_unknown(&self) -> bool {
        matches!(
            self,
            Self::Editor(NativeFileError {
                kind: NativeFileErrorKind::Uncertain,
                ..
            }) | Self::ProjectFiles(NativeProjectMutationError::Uncertain)
                | Self::DesktopFiles(DesktopMutationError::Uncertain)
        )
    }
}

struct RunningWorker {
    kind: WorkerKind,
    handle: JoinHandle<WorkerResult>,
    namespace: Arc<Mutex<Option<NativeNamespaceWork>>>,
}

/// Only the actual effect thread fills this record. The join path retains all
/// physical pins until the matching roots/receipt/fence transaction commits.
struct NativeNamespaceWork {
    _pins: PhysicalNamespacePins,
    evidence: Option<lomi_host_store::DesktopNamespaceAppliedProof>,
    expected_result_json: Option<String>,
}

pub(super) struct GuardedEffectChallenge {
    pub(super) operation_id: NativeIntentId,
    pub(super) challenge: ipc::IpcNonce,
    reply: SyncSender<ipc::LocalNativeEffectDecision>,
}

pub(super) struct GuardedEditorExchange {
    pub(super) operation_id: NativeIntentId,
    pub(super) challenges: Receiver<GuardedEffectChallenge>,
    completed: Receiver<()>,
    cancelled: Arc<AtomicBool>,
}

impl GuardedEditorExchange {
    pub(super) fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub(super) fn respond(challenge: GuardedEffectChallenge, allowed: bool) -> Result<(), ()> {
        challenge
            .reply
            .send(ipc::LocalNativeEffectDecision {
                operation_id: challenge.operation_id,
                challenge: challenge.challenge,
                allowed,
            })
            .map_err(|_| ())
    }

    pub(super) fn wait_for_completion(&self, timeout: Duration) -> bool {
        matches!(
            self.completed.recv_timeout(timeout),
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected)
        )
    }

    pub(super) fn try_challenge(&self) -> Option<GuardedEffectChallenge> {
        match self.challenges.try_recv() {
            Ok(challenge) => Some(challenge),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => None,
        }
    }
}

impl Drop for GuardedEditorExchange {
    fn drop(&mut self) {
        self.cancel();
    }
}

struct GuardedWorkerChannels {
    challenges: SyncSender<GuardedEffectChallenge>,
    completed: SyncSender<()>,
    cancelled: Arc<AtomicBool>,
}

struct PendingCompletion {
    operation_id: NativeIntentId,
    state: NativeEditorJobState,
    proof: NativeEditorCompletionProof,
    result_json: Option<String>,
    cleanup_stage: bool,
    namespace: Option<NativeNamespaceWork>,
}

pub(super) struct NativeEditorHost {
    profile: PathBuf,
    owner: Arc<shared_owner::SharedOwner>,
    namespace_runtime: NativeNamespaceRuntime,
    // Keeps OwnerEndpoint (and its profile OwnerLock) alive through Drop, which
    // joins every host effect thread before endpoint cleanup can run.
    _owner_endpoint: Arc<platform::OwnerEndpoint>,
    stopping: Arc<AtomicBool>,
    running: Mutex<BTreeMap<NativeIntentId, RunningWorker>>,
    pending: Mutex<Vec<PendingCompletion>>,
    cleanup_pending: Mutex<Vec<NativeIntentId>>,
    stage_cleanup: Mutex<()>,
    reaping: AtomicBool,
    last_stage_cleanup: Mutex<Instant>,
    next_namespace_recovery: Mutex<Option<Instant>>,
}

impl NativeEditorHost {
    pub(super) fn new(
        profile: PathBuf,
        owner: Arc<shared_owner::SharedOwner>,
        owner_endpoint: Arc<platform::OwnerEndpoint>,
        stopping: Arc<AtomicBool>,
        namespace_runtime: NativeNamespaceRuntime,
    ) -> Self {
        Self {
            profile,
            owner,
            namespace_runtime,
            _owner_endpoint: owner_endpoint,
            stopping,
            running: Mutex::new(BTreeMap::new()),
            pending: Mutex::new(Vec::new()),
            cleanup_pending: Mutex::new(Vec::new()),
            stage_cleanup: Mutex::new(()),
            reaping: AtomicBool::new(false),
            last_stage_cleanup: Mutex::new(Instant::now()),
            next_namespace_recovery: Mutex::new(None),
        }
    }

    /// Metadata-only recovery under the actual new profile owner. A fresh lock
    /// alone is not old-worker retirement: the prepared manifest must also
    /// prove, through an independent OS query, that its host process
    /// incarnation has stopped. No lost filesystem effect is executed again.
    pub(super) fn recover_pending_namespaces(
        &self,
        operation: &Operation<'_>,
    ) -> Result<(), LocalError> {
        operation.check().map_err(|_| LocalError::Unavailable)?;
        let pass_started = Instant::now();
        {
            let mut next = self
                .next_namespace_recovery
                .lock()
                .map_err(|_| LocalError::Unavailable)?;
            if next.is_some_and(|next| pass_started < next) {
                return Ok(());
            }
            *next = Some(pass_started + NAMESPACE_RECOVERY_INTERVAL);
        }
        // Unrecoverable names and unavailable OS witnesses must not turn the
        // idle owner's accept loop into continuous filesystem polling. The
        // admitted maintenance deadline bounds these read-only observations;
        // no original client deadline or effect authority is renewed.
        let records = self
            .owner
            .native_namespace_recovery_records()
            .map_err(super::owner_error)?;
        let discovery = self._owner_endpoint.discovery();
        for record in records {
            if operation.check().is_err() || self.stopping.load(Ordering::Acquire) {
                break;
            }
            if record.host_runtime_id == discovery.runtime_id {
                continue;
            }
            let Ok(witness) = super::desktop_namespace_recovery::prepared_host_process(&record)
            else {
                continue;
            };
            let Ok(retirement) = witness.verify_retired() else {
                // Live, inaccessible and ambiguous processes all retain both
                // fences. None may be replaced by a guessed PID absence.
                continue;
            };
            let retirement_json = retirement
                .canonical_json()
                .map_err(|_| LocalError::Unavailable)?;
            let retirement_sha256 = format!("{:x}", Sha256::digest(retirement_json.as_bytes()));
            // This endpoint is an owned native value, not a decoded client
            // receipt. It retains the kernel-acquired OwnerLock throughout
            // this call and throughout NativeEditorHost::Drop's worker join.
            let owner_receipt = serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "kind": "heldNativeOwnerEndpoint",
                "profilePath": self._owner_endpoint.profile().path(),
                "profileId": discovery.profile_id,
                "hostId": discovery.host_id,
                "runtimeId": discovery.runtime_id,
                "oldRuntimeId": record.host_runtime_id,
                "operationId": record.operation_id,
                "fenceId": record.fence_id,
                "planSha256": record.plan.plan_sha256(),
            }))
            .map_err(|_| LocalError::Unavailable)?;
            let owner_sha256 = format!("{:x}", Sha256::digest(&owner_receipt));
            let evidence = super::desktop_namespace_recovery::recover_native_namespace(
                &record,
                discovery.runtime_id,
                &owner_sha256,
                &retirement_sha256,
                &mut || {
                    operation
                        .check()
                        .map_err(|_| DesktopFileErrorCode::DeadlineExceeded)
                },
            );
            let Ok(evidence) = evidence else {
                // Missing birth witnesses or changed root bindings cannot
                // retire an unknown namespace. Keep status-only quarantine.
                continue;
            };
            self.owner
                .native_namespace_recover(&evidence)
                .map_err(super::owner_error)?;
        }

        let remote_records = self
            .owner
            .remote_namespace_recovery_records()
            .map_err(super::owner_error)?;
        for record in remote_records {
            if operation.check().is_err() || self.stopping.load(Ordering::Acquire) {
                break;
            }
            if record.host_runtime_id == discovery.runtime_id {
                continue;
            }
            let Ok(witness) =
                super::desktop_namespace_recovery::prepared_remote_host_process(&record)
            else {
                continue;
            };
            let Ok(retirement) = witness.verify_retired() else {
                // Live, inaccessible and ambiguous processes retain their
                // remote namespace quarantine.
                continue;
            };
            let retirement_json = retirement
                .canonical_json()
                .map_err(|_| LocalError::Unavailable)?;
            let retirement_sha256 = format!("{:x}", Sha256::digest(retirement_json.as_bytes()));
            // Bind this proof to the concrete endpoint/owner lock retained by
            // this host, and to the complete remote namespace identity. The
            // identity comes from the persisted typed record, not the client.
            let owner_receipt = serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "kind": "heldRemoteNamespaceOwnerEndpoint",
                "profilePath": self._owner_endpoint.profile().path(),
                "profileId": discovery.profile_id,
                "hostId": discovery.host_id,
                "runtimeId": discovery.runtime_id,
                "oldRuntimeId": record.host_runtime_id,
                "namespaceId": record.namespace_id,
                "actor": record.actor,
                "workspaceId": record.workspace_id,
                "operationId": record.operation_id,
                "method": record.method,
                "planSha256": record.plan.plan_sha256(),
            }))
            .map_err(|_| LocalError::Unavailable)?;
            let owner_sha256 = format!("{:x}", Sha256::digest(&owner_receipt));
            let evidence = super::desktop_namespace_recovery::recover_remote_namespace(
                &record,
                discovery.runtime_id,
                &owner_sha256,
                &retirement_sha256,
                &mut || {
                    operation
                        .check()
                        .map_err(|_| DesktopFileErrorCode::DeadlineExceeded)
                },
            );
            let Ok(evidence) = evidence else {
                // Changed or inconclusive filesystem evidence keeps the
                // remote intent quarantined. Remote removes are never
                // converted into native tombstones or replayed.
                continue;
            };
            self.owner
                .remote_namespace_recover(&evidence)
                .map_err(super::owner_error)?;
        }
        Ok(())
    }

    pub(super) fn stage(
        &self,
        operation: &Operation<'_>,
        blob: LocalNativeFileBlob,
    ) -> Result<LocalResult, LocalError> {
        operation.check().map_err(|_| LocalError::Unavailable)?;
        if blob.byte_length.0 > MAX_INPUT_BYTES {
            return Err(LocalError::InvalidArgument);
        }
        self.cleanup_expired_stage_rows();
        let digest = String::from(blob.content_sha256.clone());
        let stage_registration = match rpc::owner_call(operation, || {
            self.owner.native_editor_stage(
                operation,
                blob.operation_id,
                blob.byte_length.0,
                &digest,
            )
        }) {
            Err(shared_owner::Error::Store(StoreError::ResourceExhausted)) => {
                // A lease can expire between the cleanup pass and quota check.
                // Retry only after pruning, under the same Operation deadline.
                self.cleanup_expired_stage_rows();
                rpc::owner_call(operation, || {
                    self.owner.native_editor_stage(
                        operation,
                        blob.operation_id,
                        blob.byte_length.0,
                        &digest,
                    )
                })
            }
            result => result,
        }
        .map_err(super::owner_error)?;
        let path = if stage_registration.writable {
            let stage = platform::open_native_editor_stage(&self.profile, blob.operation_id, true)
                .map_err(|_| LocalError::Unavailable)?;
            let path = stage
                .path()
                .to_str()
                .ok_or(LocalError::Unavailable)?
                .to_owned();
            drop(stage);
            path
        } else {
            stage_path(&self.profile, blob.operation_id)
                .to_str()
                .ok_or(LocalError::Unavailable)?
                .to_owned()
        };
        let path = ipc::LocalRootPath::try_from(path).map_err(|_| LocalError::Unavailable)?;
        Ok(LocalResult::NativeFileStage(LocalNativeFileStage {
            operation_id: blob.operation_id,
            path,
        }))
    }

    pub(super) fn execute(
        &self,
        operation: &Operation<'_>,
        connection: ipc::IpcNonce,
        execute: LocalNativeEditorExecute,
    ) -> Result<LocalResult, LocalError> {
        self.execute_inner(operation, connection, execute, false, None)
            .map(|(result, _)| result)
    }

    pub(super) fn execute_guarded(
        &self,
        operation: &Operation<'_>,
        connection: ipc::IpcNonce,
        execute: LocalNativeEditorExecute,
    ) -> Result<(LocalResult, Option<GuardedEditorExchange>), LocalError> {
        let (challenge_sender, challenges) = mpsc::sync_channel(1);
        let (completed_sender, completed) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let (result, started) = self.execute_inner(
            operation,
            connection,
            execute,
            true,
            Some(GuardedWorkerChannels {
                challenges: challenge_sender,
                completed: completed_sender,
                cancelled: cancelled.clone(),
            }),
        )?;
        let exchange = started.then_some(GuardedEditorExchange {
            operation_id: match &result {
                LocalResult::NativeEditor(result) => result.operation_id,
                _ => return Err(LocalError::Unavailable),
            },
            challenges,
            completed,
            cancelled,
        });
        Ok((result, exchange))
    }

    fn execute_inner(
        &self,
        operation: &Operation<'_>,
        connection: ipc::IpcNonce,
        execute: LocalNativeEditorExecute,
        guarded: bool,
        worker_channels: Option<GuardedWorkerChannels>,
    ) -> Result<(LocalResult, bool), LocalError> {
        operation.check().map_err(|_| LocalError::Unavailable)?;
        let blob = execute.blob.clone();
        if blob.byte_length.0 > MAX_INPUT_BYTES {
            return Err(LocalError::InvalidArgument);
        }
        let request = native_request(&execute.effect, guarded, &self.profile);
        if request.requires_guarded_execution() && !guarded {
            return Err(LocalError::InvalidArgument);
        }
        let request_hash = request_hash(&execute, guarded)?;
        let digest = String::from(blob.content_sha256.clone());

        if let Some(existing) = rpc::owner_call(operation, || {
            self.owner.native_editor_retry(
                operation,
                blob.operation_id,
                blob.byte_length.0,
                &digest,
                &request_hash,
            )
        })
        .map_err(super::owner_error)?
        {
            self.reap_finished();
            return editor_result(existing).map(|result| (result, false));
        }

        let staged_bytes = match read_stage(&self.profile, operation, &blob) {
            Ok(content) => content,
            Err(error) => {
                if let Some(existing) = rpc::owner_call(operation, || {
                    self.owner.native_editor_retry(
                        operation,
                        blob.operation_id,
                        blob.byte_length.0,
                        &digest,
                        &request_hash,
                    )
                })
                .map_err(super::owner_error)?
                {
                    self.reap_finished();
                    return editor_result(existing).map(|result| (result, false));
                }
                if matches!(request.kind(), WorkerKind::DesktopFiles) {
                    let code = match error {
                        LocalError::InvalidArgument => DesktopFileErrorCode::Invalid,
                        LocalError::Conflict => DesktopFileErrorCode::Changed,
                        _ => return Err(error),
                    };
                    return desktop_prestart_failure(blob.operation_id, code)
                        .map(|result| (result, false));
                }
                return Err(error);
            }
        };
        let content = if request.takes_raw_content() {
            WorkerContent::Raw(staged_bytes)
        } else {
            WorkerContent::Text(
                String::from_utf8(staged_bytes).map_err(|_| LocalError::InvalidArgument)?,
            )
        };
        let mut workspace_effect_guard = None;
        if let (WorkerRequest::DesktopFiles { root, .. }, WorkerContent::Text(content)) =
            (&request, &content)
        {
            let desktop = (|| {
                if content.len() > MAX_DESKTOP_MUTATION_BYTES {
                    return Err(DesktopFileErrorCode::Limit);
                }
                let desktop: DesktopMutationRequest =
                    serde_json::from_str(content).map_err(|_| DesktopFileErrorCode::Invalid)?;
                lomi_files::desktop::validate_desktop_request(&desktop)?;
                if &desktop.root != root || desktop.operation_id != String::from(blob.operation_id)
                {
                    return Err(DesktopFileErrorCode::Invalid);
                }
                Ok(desktop)
            })();
            let desktop = match desktop {
                Ok(desktop) => desktop,
                Err(code) => {
                    return desktop_prestart_failure(blob.operation_id, code)
                        .map(|result| (result, false));
                }
            };
            if let Some(context) = desktop.operation.git_context() {
                let workspace = rpc::owner_call(operation, || {
                    self.owner.workspace(operation, context.workspace_id)
                })
                .map_err(super::owner_error)?;
                if &workspace.state.context != context || workspace.local_root != desktop.root {
                    // An identical request may have been admitted before the
                    // workspace changed. Recover its durable receipt before
                    // rejecting this connection's fresh admission.
                    if let Some(existing) = rpc::owner_call(operation, || {
                        self.owner.native_editor_retry(
                            operation,
                            blob.operation_id,
                            blob.byte_length.0,
                            &digest,
                            &request_hash,
                        )
                    })
                    .map_err(super::owner_error)?
                    {
                        self.reap_finished();
                        return editor_result(existing).map(|result| (result, false));
                    }
                    return desktop_prestart_failure(
                        blob.operation_id,
                        DesktopFileErrorCode::Changed,
                    )
                    .map(|result| (result, false));
                }
                workspace_effect_guard = Some(
                    WorkspaceEffectGuard::new(
                        context.workspace_id,
                        context.clone(),
                        workspace.local_root,
                        workspace.fence,
                    )
                    .map_err(|_| LocalError::InvalidArgument)?,
                );
            }
        }
        operation.check().map_err(|_| LocalError::Unavailable)?;
        let started = match rpc::owner_call(operation, || {
            self.owner.native_editor_begin(
                operation,
                blob.operation_id,
                blob.byte_length.0,
                &digest,
                &request_hash,
                connection,
                workspace_effect_guard.as_ref(),
            )
        }) {
            Ok(started) => started,
            Err(shared_owner::Error::Store(StoreError::NativeWriterBusy)) => {
                if matches!(request.kind(), WorkerKind::DesktopFiles) {
                    return desktop_prestart_failure(blob.operation_id, DesktopFileErrorCode::Io)
                        .map(|result| (result, false));
                }
                return prestart_failure(
                    blob.operation_id,
                    "Another local file or Git writer is active. Retry after it finishes.",
                )
                .map(|result| (result, false));
            }
            Err(shared_owner::Error::Store(StoreError::ResourceExhausted)) => {
                if matches!(request.kind(), WorkerKind::DesktopFiles) {
                    return desktop_prestart_failure(
                        blob.operation_id,
                        DesktopFileErrorCode::Limit,
                    )
                    .map(|result| (result, false));
                }
                return prestart_failure(
                    blob.operation_id,
                    "The host has reached its local editor receipt limit. Retry later.",
                )
                .map(|result| (result, false));
            }
            Err(error) => return Err(super::owner_error(error)),
        };
        match started {
            NativeEditorBegin::Existing(existing) => {
                self.reap_finished();
                editor_result(existing).map(|result| (result, false))
            }
            NativeEditorBegin::Started {
                operation_id,
                fence_id: _,
            } => {
                let deadline = operation.deadline();
                let stopping = self.stopping.clone();
                let sticky_cancelled = operation.sticky_cancellation();
                let worker_request = request;
                let worker_content = content;
                let (worker_challenges, worker_completed, worker_cancelled) = match worker_channels
                {
                    Some(channels) => (
                        Some(channels.challenges),
                        Some(channels.completed),
                        Some(channels.cancelled),
                    ),
                    None => (None, None, None),
                };
                let worker_kind = worker_request.kind();
                let namespace = Arc::new(Mutex::new(None));
                let worker_namespace = namespace.clone();
                let namespace_runtime = self.namespace_runtime.clone();
                let worker = thread::Builder::new()
                    .name("lomi-native-editor".into())
                    .spawn(move || {
                        let result = match (worker_challenges, worker_cancelled) {
                            (Some(challenges), Some(cancelled)) => run_guarded_worker(
                                worker_request,
                                &worker_content,
                                operation_id,
                                deadline,
                                &stopping,
                                &sticky_cancelled,
                                &cancelled,
                                &challenges,
                                &namespace_runtime,
                                &worker_namespace,
                            ),
                            _ => run_unguarded_worker(
                                worker_request,
                                &worker_content,
                                deadline,
                                &stopping,
                                &sticky_cancelled,
                            ),
                        };
                        if let Some(completed) = worker_completed {
                            let _ = completed.send(());
                        }
                        result
                    });
                let mut worker_started = false;
                match worker {
                    Ok(worker) => {
                        worker_started = true;
                        self.running
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .insert(
                                operation_id,
                                RunningWorker {
                                    kind: worker_kind,
                                    handle: worker,
                                    namespace,
                                },
                            );
                    }
                    Err(_) => {
                        let (state, result_json) = match worker_kind {
                            WorkerKind::Editor => (
                                NativeEditorJobState::Failed,
                                encode_error(NativeFileError::new(
                                    NativeFileErrorKind::Io,
                                    "The host could not start the local editor worker.",
                                ))
                                .ok(),
                            ),
                            WorkerKind::ProjectFiles => (
                                NativeEditorJobState::Failed,
                                encode_worker_failure(WorkerFailure::ProjectFiles(
                                    NativeProjectErrorCode::HostUnqualified.into(),
                                )),
                            ),
                            WorkerKind::DesktopFiles => (
                                NativeEditorJobState::Failed,
                                encode_worker_failure(WorkerFailure::DesktopFiles(
                                    DesktopFileErrorCode::Io.into(),
                                )),
                            ),
                        };
                        self.queue_completion(PendingCompletion {
                            operation_id,
                            state,
                            proof: NativeEditorCompletionProof::NotStarted,
                            result_json,
                            cleanup_stage: true,
                            namespace: None,
                        });
                    }
                }
                self.reap_finished();
                let record = rpc::owner_call(operation, || {
                    self.owner.native_editor_status(operation, operation_id)
                })
                .map_err(super::owner_error)?;
                editor_result(record).map(|result| (result, worker_started))
            }
        }
    }

    pub(super) fn status(
        &self,
        operation: &Operation<'_>,
        target: ipc::NativeIntentTarget,
    ) -> Result<LocalResult, LocalError> {
        operation.check().map_err(|_| LocalError::Unavailable)?;
        self.reap_finished();
        let record = rpc::owner_call(operation, || {
            self.owner.native_editor_status(operation, target.intent_id)
        })
        .map_err(super::owner_error)?;
        editor_result(record)
    }

    pub(super) fn acknowledge(
        &self,
        operation: &Operation<'_>,
        target: ipc::NativeIntentTarget,
    ) -> Result<LocalResult, LocalError> {
        operation.check().map_err(|_| LocalError::Unavailable)?;
        self.reap_finished();
        rpc::owner_call(operation, || {
            self.owner
                .native_editor_acknowledge(operation, target.intent_id)
        })
        .map_err(super::owner_error)?;
        Ok(LocalResult::NativeEditorAcknowledged(target.intent_id))
    }

    /// Startup sweep removes expired unconsumed inputs even when the client
    /// never submits another Stage request.
    pub(super) fn cleanup_expired_stages(&self) {
        self.cleanup_expired_stage_rows();
    }

    pub(super) fn cleanup_expired_stages_if_due(&self) {
        let should_run = {
            let mut previous = self
                .last_stage_cleanup
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let now = Instant::now();
            if now.saturating_duration_since(*previous).as_secs() >= 1 {
                *previous = now;
                true
            } else {
                false
            }
        };
        if should_run {
            self.cleanup_expired_stage_rows();
        }
    }

    fn cleanup_expired_stage_rows(&self) {
        let _serial = self
            .stage_cleanup
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Ok(operation_ids) = self.owner.native_editor_expire_stages() else {
            return;
        };
        let cleaned: Vec<_> = operation_ids
            .into_iter()
            .filter(|operation_id| remove_stage_file(&self.profile, *operation_id).is_ok())
            .collect();
        if !cleaned.is_empty() {
            let _ = self.owner.native_editor_ack_stage_cleanup(&cleaned);
        }
    }

    /// Keep the profile owner lock until every effect thread has crossed its
    /// engine completion boundary. Shutdown cancellation makes each pending
    /// engine callback deny visibility; a thread already publishing is joined
    /// before this host can release ownership.
    pub(super) fn shutdown_and_join(&self) {
        let workers = {
            let mut running = self
                .running
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(&mut *running)
        };
        for (operation_id, worker) in workers {
            let joined = worker.handle.join();
            let namespace = worker
                .namespace
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            self.queue_completion(completion_from_join(
                operation_id,
                worker.kind,
                joined,
                namespace,
            ));
        }
        self.reap_finished();
    }

    /// Called from the host's bounded maintenance loop. Completed workers are
    /// joined outside every coordinator/Store lock, then their journal update
    /// is retried until it commits or the process exits. A restart converts any
    /// still-Running row to OutcomeUnknown and keeps its quarantine fence.
    pub(super) fn reap_finished(&self) {
        if self
            .reaping
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let finished = {
            let mut running = self
                .running
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let ids: Vec<_> = running
                .iter()
                .filter_map(|(id, worker)| worker.handle.is_finished().then_some(*id))
                .collect();
            ids.into_iter()
                .filter_map(|id| running.remove(&id).map(|worker| (id, worker)))
                .collect::<Vec<_>>()
        };
        for (operation_id, worker) in finished {
            let joined = worker.handle.join();
            let namespace = worker
                .namespace
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            self.queue_completion(completion_from_join(
                operation_id,
                worker.kind,
                joined,
                namespace,
            ));
        }

        let pending = {
            let mut queue = self
                .pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(&mut *queue)
        };
        let mut retry = Vec::new();
        let mut cleanup = Vec::new();
        for completion in pending {
            let persisted = self.persist_completion(&completion);
            match persisted {
                Err(_) => retry.push(completion),
                Ok(quarantined) => {
                    if !quarantined
                        && completion.cleanup_stage
                        && remove_stage_file(&self.profile, completion.operation_id).is_err()
                    {
                        cleanup.push(completion.operation_id);
                    }
                }
            }
        }
        if !retry.is_empty() {
            self.pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .extend(retry);
        }
        let previously_pending = {
            let mut pending = self
                .cleanup_pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(&mut *pending)
        };
        cleanup.extend(previously_pending);
        let still_pending: Vec<_> = cleanup
            .into_iter()
            .filter(|operation_id| remove_stage_file(&self.profile, *operation_id).is_err())
            .collect();
        if !still_pending.is_empty() {
            self.cleanup_pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .extend(still_pending);
        }
        self.reaping.store(false, Ordering::Release);
    }

    fn persist_completion(
        &self,
        completion: &PendingCompletion,
    ) -> Result<bool, shared_owner::Error> {
        if self
            .owner
            .native_namespace_intent(completion.operation_id)?
            .is_some()
        {
            if let Some(evidence) = completion
                .namespace
                .as_ref()
                .and_then(|namespace| namespace.evidence.as_ref())
            {
                self.owner.native_namespace_complete(
                    completion.operation_id,
                    completion.state,
                    completion.proof,
                    completion.result_json.clone(),
                    evidence,
                )?;
                return Ok(false);
            }
            // Joining proves the worker stopped, not which physical namespace
            // survived. Report uncertainty and retain both durable fences.
            self.owner
                .native_namespace_quarantine_joined(completion.operation_id)?;
            return Ok(true);
        }
        self.owner.native_editor_complete(
            completion.operation_id,
            completion.state,
            completion.proof,
            completion.result_json.clone(),
        )?;
        Ok(false)
    }

    fn queue_completion(&self, completion: PendingCompletion) {
        self.pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(completion);
    }
}

impl Drop for NativeEditorHost {
    fn drop(&mut self) {
        // Covers error and unwind exits as well as the explicit normal shutdown
        // path. No JoinHandle may detach while this owner releases its lock.
        self.stopping.store(true, Ordering::Release);
        self.shutdown_and_join();
    }
}

fn completion_from_join(
    operation_id: NativeIntentId,
    kind: WorkerKind,
    joined: std::thread::Result<WorkerResult>,
    mut namespace: Option<NativeNamespaceWork>,
) -> PendingCompletion {
    let mut completion = match joined {
        Ok(Ok(result)) => match encode_success(result) {
            Ok(result_json) => PendingCompletion {
                operation_id,
                state: NativeEditorJobState::Succeeded,
                proof: NativeEditorCompletionProof::Joined,
                result_json: Some(result_json),
                cleanup_stage: true,
                namespace: None,
            },
            Err(failure) => PendingCompletion {
                operation_id,
                state: NativeEditorJobState::OutcomeUnknown,
                proof: NativeEditorCompletionProof::Joined,
                result_json: encode_worker_failure(failure),
                cleanup_stage: true,
                namespace: None,
            },
        },
        Ok(Err(failure)) => PendingCompletion {
            operation_id,
            state: if failure.outcome_unknown() {
                NativeEditorJobState::OutcomeUnknown
            } else {
                NativeEditorJobState::Failed
            },
            proof: NativeEditorCompletionProof::Joined,
            result_json: encode_worker_failure(failure),
            cleanup_stage: true,
            namespace: None,
        },
        Err(_) => {
            let (state, result_json) = match kind {
                WorkerKind::Editor => {
                    let error = NativeFileError::new(
                        NativeFileErrorKind::Uncertain,
                        "The host editor worker ended unexpectedly.",
                    );
                    (
                        NativeEditorJobState::OutcomeUnknown,
                        encode_error(error).ok(),
                    )
                }
                WorkerKind::ProjectFiles => (
                    NativeEditorJobState::OutcomeUnknown,
                    encode_worker_failure(WorkerFailure::ProjectFiles(
                        NativeProjectMutationError::Uncertain,
                    )),
                ),
                WorkerKind::DesktopFiles => (
                    NativeEditorJobState::OutcomeUnknown,
                    encode_worker_failure(WorkerFailure::DesktopFiles(
                        DesktopMutationError::Uncertain,
                    )),
                ),
            };
            PendingCompletion {
                operation_id,
                state,
                proof: NativeEditorCompletionProof::Joined,
                result_json,
                cleanup_stage: true,
                namespace: None,
            }
        }
    };
    if let Some(work) = namespace.as_mut()
        && (work.expected_result_json.is_none()
            || work.expected_result_json != completion.result_json)
    {
        // In particular a panic cannot reuse an evidence object constructed
        // for a different result. A joined uncertain Remove may instead retire
        // the requested registrations without claiming disk deletion; an
        // unprovable Move must retain quarantine.
        work.evidence = completion
            .result_json
            .as_deref()
            .filter(|_| completion.state == NativeEditorJobState::OutcomeUnknown)
            .and_then(|receipt| {
                work._pins
                    .retired_after_partial_remove_proof(receipt, &mut || Ok(()))
                    .ok()
            });
    }
    completion.namespace = namespace;
    completion
}

fn native_request(
    effect: &LocalNativeEditorEffect,
    guarded: bool,
    profile: &Path,
) -> WorkerRequest {
    match effect {
        LocalNativeEditorEffect::Save {
            root,
            relative,
            expected_revision,
        } => {
            let request = NativeSaveFile {
                root: String::from(root.clone()),
                relative: String::from(relative.clone()),
                expected_revision: String::from(expected_revision.clone()),
            };
            if guarded {
                WorkerRequest::Editor(NativeSaveRequest::FileNoFollow(request))
            } else {
                WorkerRequest::Editor(NativeSaveRequest::File(request))
            }
        }
        LocalNativeEditorEffect::SaveNew {
            absolute_path,
            open_files,
        } => WorkerRequest::Editor(NativeSaveRequest::New(NativeSaveNew {
            absolute_path: PathBuf::from(String::from(absolute_path.clone())),
            open_files: open_files
                .0
                .iter()
                .map(|file| NativeFileLocation {
                    root: String::from(file.root.clone()),
                    relative: String::from(file.relative.clone()),
                })
                .collect(),
        })),
        LocalNativeEditorEffect::SaveNewChecked {
            absolute_path,
            open_files,
            expected_revision,
        } => WorkerRequest::Editor(NativeSaveRequest::NewChecked(NativeSaveNewChecked {
            request: NativeSaveNew {
                absolute_path: PathBuf::from(String::from(absolute_path.clone())),
                open_files: open_files
                    .0
                    .iter()
                    .map(|file| NativeFileLocation {
                        root: String::from(file.root.clone()),
                        relative: String::from(file.relative.clone()),
                    })
                    .collect(),
            },
            expected_revision: expected_revision.clone().map(String::from),
        })),
        LocalNativeEditorEffect::ProjectFiles { root } => WorkerRequest::ProjectFiles {
            root: PathBuf::from(String::from(root.clone())),
        },
        LocalNativeEditorEffect::DesktopFiles { root, .. } => WorkerRequest::DesktopFiles {
            root: PathBuf::from(String::from(root.clone())),
            profile: profile.to_path_buf(),
        },
        LocalNativeEditorEffect::ArtifactCreate {
            root,
            relative,
            expected_parent_revision,
        } => WorkerRequest::ArtifactCreate {
            root: PathBuf::from(String::from(root.clone())),
            relative: String::from(relative.clone()),
            expected_parent_revision: String::from(expected_parent_revision.clone()),
        },
    }
}

fn request_hash(execute: &LocalNativeEditorExecute, guarded: bool) -> Result<String, LocalError> {
    let bytes = serde_json::to_vec(execute).map_err(|_| LocalError::InvalidArgument)?;
    let mut hash = Sha256::new();
    hash.update(if guarded {
        b"lomi-local-native-editor-guarded-v1\0".as_slice()
    } else {
        b"lomi-local-native-editor-v1\0".as_slice()
    });
    hash.update(bytes);
    Ok(format!("{:x}", hash.finalize()))
}

#[derive(Clone, Copy)]
enum GuardedAuthorizationFailure {
    Closing,
    Deadline,
    Exhausted,
    Denied,
    Unqualified,
}

fn guarded_worker_alive(
    deadline: Instant,
    stopping: &AtomicBool,
    sticky_cancelled: &AtomicBool,
    cancelled: &AtomicBool,
) -> Result<(), GuardedAuthorizationFailure> {
    if stopping.load(Ordering::Acquire) {
        return Err(GuardedAuthorizationFailure::Closing);
    }
    if sticky_cancelled.load(Ordering::SeqCst)
        || cancelled.load(Ordering::SeqCst)
        || Instant::now() >= deadline
    {
        return Err(GuardedAuthorizationFailure::Deadline);
    }
    Ok(())
}

fn guarded_authorize(
    operation_id: NativeIntentId,
    deadline: Instant,
    stopping: &AtomicBool,
    sticky_cancelled: &AtomicBool,
    cancelled: &AtomicBool,
    challenges: &SyncSender<GuardedEffectChallenge>,
    challenge_limit: usize,
    challenge_count: &mut usize,
) -> Result<Instant, GuardedAuthorizationFailure> {
    guarded_worker_alive(deadline, stopping, sticky_cancelled, cancelled)?;
    if *challenge_count >= challenge_limit {
        cancelled.store(true, Ordering::SeqCst);
        return Err(GuardedAuthorizationFailure::Exhausted);
    }
    *challenge_count += 1;
    let challenge = ipc::IpcNonce::from_bytes(uuid::Uuid::new_v4().into_bytes())
        .map_err(|_| GuardedAuthorizationFailure::Unqualified)?;
    let (reply, response) = mpsc::sync_channel(1);
    challenges
        .try_send(GuardedEffectChallenge {
            operation_id,
            challenge,
            reply,
        })
        .map_err(|_| {
            cancelled.store(true, Ordering::SeqCst);
            GuardedAuthorizationFailure::Denied
        })?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        cancelled.store(true, Ordering::SeqCst);
        return Err(GuardedAuthorizationFailure::Deadline);
    }
    let decision = match response.recv_timeout(remaining) {
        Ok(decision) => decision,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            cancelled.store(true, Ordering::SeqCst);
            return Err(GuardedAuthorizationFailure::Deadline);
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            cancelled.store(true, Ordering::SeqCst);
            return Err(GuardedAuthorizationFailure::Denied);
        }
    };
    guarded_worker_alive(deadline, stopping, sticky_cancelled, cancelled)?;
    if decision.operation_id != operation_id || decision.challenge != challenge || !decision.allowed
    {
        cancelled.store(true, Ordering::SeqCst);
        return Err(GuardedAuthorizationFailure::Denied);
    }
    Ok(Instant::now())
}

#[allow(clippy::too_many_arguments)]
fn guarded_file_worker_check(
    phase: NativeFileCheckPhase,
    operation_id: NativeIntentId,
    deadline: Instant,
    stopping: &AtomicBool,
    sticky_cancelled: &AtomicBool,
    cancelled: &AtomicBool,
    challenges: &SyncSender<GuardedEffectChallenge>,
    challenge_count: &mut usize,
    last_progress_authorized: &mut Option<Instant>,
    last_before_effect_authorized: &mut Option<Instant>,
) -> Result<(), NativeFileError> {
    let expired = || {
        NativeFileError::new(
            NativeFileErrorKind::Io,
            "The local editor operation expired before publication.",
        )
    };
    let denied = || {
        NativeFileError::new(
            NativeFileErrorKind::Io,
            "The local editor operation was not authorized before publication.",
        )
    };
    guarded_worker_alive(deadline, stopping, sticky_cancelled, cancelled).map_err(|_| expired())?;
    match phase {
        NativeFileCheckPhase::Validation => Ok(()),
        NativeFileCheckPhase::Publication => {
            if last_before_effect_authorized.is_some_and(|approved| {
                Instant::now().saturating_duration_since(approved)
                    <= GUARDED_PUBLICATION_APPROVAL_MAX_AGE
            }) {
                Ok(())
            } else {
                Err(expired())
            }
        }
        NativeFileCheckPhase::Progress
            if last_progress_authorized.is_some_and(|last| {
                Instant::now().saturating_duration_since(last)
                    < GUARDED_PROGRESS_AUTHORIZATION_INTERVAL
            }) =>
        {
            Ok(())
        }
        NativeFileCheckPhase::Progress | NativeFileCheckPhase::BeforeEffect => {
            let approved = guarded_authorize(
                operation_id,
                deadline,
                stopping,
                sticky_cancelled,
                cancelled,
                challenges,
                8192,
                challenge_count,
            )
            .map_err(|failure| match failure {
                GuardedAuthorizationFailure::Deadline | GuardedAuthorizationFailure::Closing => {
                    expired()
                }
                GuardedAuthorizationFailure::Denied
                | GuardedAuthorizationFailure::Exhausted
                | GuardedAuthorizationFailure::Unqualified => denied(),
            })?;
            match phase {
                NativeFileCheckPhase::Progress => *last_progress_authorized = Some(approved),
                NativeFileCheckPhase::BeforeEffect => {
                    *last_before_effect_authorized = Some(approved)
                }
                NativeFileCheckPhase::Validation | NativeFileCheckPhase::Publication => {
                    unreachable!("local-only native-file phases cannot request guarded IPC")
                }
            }
            Ok(())
        }
    }
}

fn run_guarded_worker(
    request: WorkerRequest,
    content: &WorkerContent,
    operation_id: NativeIntentId,
    deadline: Instant,
    stopping: &AtomicBool,
    sticky_cancelled: &AtomicBool,
    cancelled: &AtomicBool,
    challenges: &SyncSender<GuardedEffectChallenge>,
    namespace_runtime: &NativeNamespaceRuntime,
    namespace: &Mutex<Option<NativeNamespaceWork>>,
) -> WorkerResult {
    match request {
        WorkerRequest::Editor(request) => {
            let WorkerContent::Text(content) = content else {
                return Err(WorkerFailure::Editor(NativeFileError::new(
                    NativeFileErrorKind::Io,
                    "The local editor received invalid staged content.",
                )));
            };
            let mut challenge_count = 0;
            let mut last_progress_authorized = None;
            let mut last_before_effect_authorized = None;
            let mut check = |phase| {
                guarded_file_worker_check(
                    phase,
                    operation_id,
                    deadline,
                    stopping,
                    sticky_cancelled,
                    cancelled,
                    challenges,
                    &mut challenge_count,
                    &mut last_progress_authorized,
                    &mut last_before_effect_authorized,
                )
            };
            lomi_native_files::save_with_phase(request, content, &mut check)
                .map(WorkerOutput::Editor)
                .map_err(WorkerFailure::Editor)
        }
        WorkerRequest::ProjectFiles { root } => {
            let WorkerContent::Text(content) = content else {
                return Err(WorkerFailure::ProjectFiles(
                    NativeProjectErrorCode::ArtifactInvalid.into(),
                ));
            };
            let mut challenge_count = 0;
            let mut last_progress_authorized = None;
            let mut last_before_effect_authorized = None;
            run_project_mutation(root, content, |phase| {
                guarded_project_worker_check(
                    phase,
                    operation_id,
                    deadline,
                    stopping,
                    sticky_cancelled,
                    cancelled,
                    challenges,
                    &mut challenge_count,
                    &mut last_progress_authorized,
                    &mut last_before_effect_authorized,
                )
            })
        }
        WorkerRequest::DesktopFiles { root, profile } => {
            let WorkerContent::Text(content) = content else {
                return Err(WorkerFailure::DesktopFiles(
                    DesktopFileErrorCode::Invalid.into(),
                ));
            };
            let mut challenge_count = 0;
            let mut last_progress_authorized = None;
            let mut last_before_effect_authorized = None;
            run_desktop_mutation(
                root,
                profile,
                operation_id,
                content,
                deadline,
                namespace_runtime,
                namespace,
                cancelled,
                |phase| {
                    guarded_desktop_worker_check(
                        phase,
                        operation_id,
                        deadline,
                        stopping,
                        sticky_cancelled,
                        cancelled,
                        challenges,
                        &mut challenge_count,
                        &mut last_progress_authorized,
                        &mut last_before_effect_authorized,
                    )
                },
            )
        }
        WorkerRequest::ArtifactCreate {
            root,
            relative,
            expected_parent_revision,
        } => {
            let WorkerContent::Raw(content) = content else {
                return Err(WorkerFailure::ProjectFiles(
                    NativeProjectErrorCode::ArtifactInvalid.into(),
                ));
            };
            let mut challenge_count = 0;
            let mut last_progress_authorized = None;
            let mut last_before_effect_authorized = None;
            run_artifact_create(root, relative, expected_parent_revision, content, |phase| {
                guarded_project_worker_check(
                    phase,
                    operation_id,
                    deadline,
                    stopping,
                    sticky_cancelled,
                    cancelled,
                    challenges,
                    &mut challenge_count,
                    &mut last_progress_authorized,
                    &mut last_before_effect_authorized,
                )
            })
        }
    }
}

fn run_unguarded_worker(
    request: WorkerRequest,
    content: &WorkerContent,
    deadline: Instant,
    stopping: &AtomicBool,
    sticky_cancelled: &AtomicBool,
) -> WorkerResult {
    match request {
        WorkerRequest::Editor(request) => {
            let WorkerContent::Text(content) = content else {
                return Err(WorkerFailure::Editor(NativeFileError::new(
                    NativeFileErrorKind::Io,
                    "The local editor received invalid staged content.",
                )));
            };
            let mut check = |_phase: NativeFileCheckPhase| {
                if stopping.load(Ordering::Acquire)
                    || sticky_cancelled.load(Ordering::SeqCst)
                    || Instant::now() >= deadline
                {
                    Err(NativeFileError::new(
                        NativeFileErrorKind::Io,
                        "The local editor operation expired before publication.",
                    ))
                } else {
                    Ok(())
                }
            };
            lomi_native_files::save_with_phase(request, content, &mut check)
                .map(WorkerOutput::Editor)
                .map_err(WorkerFailure::Editor)
        }
        WorkerRequest::ProjectFiles { .. } => Err(WorkerFailure::ProjectFiles(
            NativeProjectErrorCode::HostUnqualified.into(),
        )),
        WorkerRequest::DesktopFiles { .. } => Err(WorkerFailure::DesktopFiles(
            DesktopFileErrorCode::Unsupported.into(),
        )),
        WorkerRequest::ArtifactCreate { .. } => Err(WorkerFailure::ProjectFiles(
            NativeProjectErrorCode::HostUnqualified.into(),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_desktop_mutation(
    root: PathBuf,
    profile: PathBuf,
    operation_id: NativeIntentId,
    content: &str,
    deadline: Instant,
    runtime: &NativeNamespaceRuntime,
    namespace: &Mutex<Option<NativeNamespaceWork>>,
    cancelled: &AtomicBool,
    mut check: impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> WorkerResult {
    if content.len() > MAX_DESKTOP_MUTATION_BYTES {
        return Err(WorkerFailure::DesktopFiles(
            DesktopFileErrorCode::Limit.into(),
        ));
    }
    let mut request = serde_json::from_str::<DesktopMutationRequest>(content)
        .map_err(|_| WorkerFailure::DesktopFiles(DesktopFileErrorCode::Invalid.into()))?;
    if request.operation_id != String::from(operation_id) || request.root != root {
        return Err(WorkerFailure::DesktopFiles(
            DesktopFileErrorCode::Invalid.into(),
        ));
    }
    if request.control_roots.len() >= lomi_files::desktop::MAX_DESKTOP_CONTROL_ROOTS {
        return Err(WorkerFailure::DesktopFiles(
            DesktopFileErrorCode::Limit.into(),
        ));
    }
    // The Host's own private profile is always protected, regardless of the
    // additional restriction roots selected by the desktop client.
    request.control_roots.push(profile);
    lomi_files::desktop::validate_desktop_request(&request)
        .map_err(|error| WorkerFailure::DesktopFiles(error.into()))?;
    let prospective = desktop_namespace_effect(&request);
    let source = prospective
        .as_ref()
        .map(|(path, _)| {
            check(LocalNativeFileCheckPhase::Progress)?;
            lomi_files::desktop::desktop_source_precondition(path)
        })
        .transpose()
        .map_err(|code| WorkerFailure::DesktopFiles(code.into()))?;
    if let (Some((_, effect)), Some(source)) = (prospective, source.as_ref())
        && source.kind == lomi_files::desktop::DesktopFileKind::Directory
    {
        let operation = Operation::new(deadline, cancelled);
        let mut result = None;
        runtime
            .with_native_plan(
                &operation,
                operation_id,
                effect.clone(),
                &mut check,
                |plan, roots, check| {
                    let pins =
                        PhysicalNamespacePins::capture_native(&plan, source, &roots, &mut || {
                            check(LocalNativeFileCheckPhase::Progress)
                        })?;
                    let mut slot = namespace
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    *slot = Some(NativeNamespaceWork {
                        _pins: pins,
                        evidence: None,
                        expected_result_json: None,
                    });
                    let work = slot.as_mut().expect("just captured namespace pins");
                    let mut prepared = false;
                    let mut publishing = false;
                    let mut outcome =
                        apply_desktop_request(&request, Some(source), deadline, |phase| {
                            check(phase)?;
                            if phase == LocalNativeFileCheckPhase::BeforeEffect && !prepared {
                                work._pins.verify_before_effect(&mut || {
                                    check(LocalNativeFileCheckPhase::Validation)
                                })?;
                                rpc::owner_call(&operation, || {
                                    runtime.owner.native_namespace_prepare(
                                        &operation,
                                        &plan,
                                        &work._pins.prepared_proof(),
                                    )
                                })
                                .map_err(|_| DesktopFileErrorCode::Changed)?;
                                prepared = true;
                            }
                            if phase == LocalNativeFileCheckPhase::Publication && !publishing {
                                // Check descendants only before the first
                                // effect. Recursive Delete subsequently
                                // removes its own captured descendant names.
                                work._pins.verify_before_effect(&mut || {
                                    check(LocalNativeFileCheckPhase::Validation)
                                })?;
                                // Pin verification may take time. Recheck the
                                // fast original-deadline/cancellation and
                                // approval-age gate after it, without IPC.
                                check(LocalNativeFileCheckPhase::Publication)?;
                                publishing = true;
                            }
                            Ok(())
                        });
                    // These are bounded read-only completion observations.
                    // They grant no effect authority and must still be able
                    // to settle an actual joined effect after cancellation.
                    let mut observation = || Ok(());
                    let receipt = encode_desktop_outcome(&outcome);
                    let evidence = match (&effect, &outcome) {
                        (lomi_host_store::DesktopNamespaceEffect::Move { .. }, Ok(_)) => {
                            work._pins.applied_move_proof(&mut observation)
                        }
                        (
                            lomi_host_store::DesktopNamespaceEffect::Move { .. },
                            Err(DesktopMutationError::Uncertain),
                        ) => work._pins.applied_move_proof(&mut observation),
                        (lomi_host_store::DesktopNamespaceEffect::Remove { .. }, Ok(change)) => {
                            receipt
                                .as_deref()
                                .ok_or(DesktopFileErrorCode::Limit)
                                .and_then(|receipt| {
                                    work._pins.applied_remove_proof(
                                        receipt,
                                        change.trash.as_ref(),
                                        &mut observation,
                                    )
                                })
                        }
                        (_, Err(DesktopMutationError::Before(_))) => {
                            work._pins.no_change_proof(&mut observation)
                        }
                        (
                            lomi_host_store::DesktopNamespaceEffect::Remove { .. },
                            Err(DesktopMutationError::Uncertain),
                        ) => receipt
                            .as_deref()
                            .ok_or(DesktopFileErrorCode::Limit)
                            .and_then(|receipt| {
                                work._pins
                                    .retired_after_partial_remove_proof(receipt, &mut observation)
                            }),
                    };
                    match evidence {
                        Ok(evidence) => work.evidence = Some(evidence),
                        Err(_) => {
                            // Never publish success without a matching
                            // namespace proof. Remove can conservatively
                            // retire requested bindings; an unprovable Move
                            // retains quarantine for status-only recovery.
                            outcome = Err(DesktopMutationError::Uncertain);
                            if matches!(
                                effect,
                                lomi_host_store::DesktopNamespaceEffect::Remove { .. }
                            ) && let Some(uncertain) = encode_desktop_outcome(&outcome)
                            {
                                work.evidence = work
                                    ._pins
                                    .retired_after_partial_remove_proof(
                                        &uncertain,
                                        &mut observation,
                                    )
                                    .ok();
                            }
                        }
                    }
                    work.expected_result_json = encode_desktop_outcome(&outcome);
                    result = Some(outcome);
                    Ok(())
                },
            )
            .map_err(|code| WorkerFailure::DesktopFiles(code.into()))?;
        return result
            .unwrap_or(Err(DesktopMutationError::Uncertain))
            .map(WorkerOutput::DesktopFiles)
            .map_err(WorkerFailure::DesktopFiles);
    }
    apply_desktop_request(&request, source.as_ref(), deadline, check)
        .map(WorkerOutput::DesktopFiles)
        .map_err(WorkerFailure::DesktopFiles)
}

fn encode_desktop_outcome(
    outcome: &Result<lomi_files::desktop::DesktopFileChange, DesktopMutationError>,
) -> Option<String> {
    match outcome {
        Ok(change) => encode_bounded_json(change).ok(),
        Err(error) => encode_bounded_json(error).ok(),
    }
}

fn apply_desktop_request(
    request: &DesktopMutationRequest,
    source: Option<&lomi_files::desktop::DesktopSourcePrecondition>,
    deadline: Instant,
    check: impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<lomi_files::desktop::DesktopFileChange, DesktopMutationError> {
    if request.operation.git_context().is_some() {
        return match source {
            Some(source) => lomi_git::GitService::apply_desktop_mutation_with_source(
                request, source, deadline, check,
            ),
            None => lomi_git::GitService::apply_desktop_mutation(request, deadline, check),
        };
    }
    match source {
        Some(source) => {
            lomi_files::desktop::apply_desktop_mutation_with_source(request, source, check)
        }
        None => lomi_files::desktop::apply_desktop_mutation(request, check),
    }
}

fn desktop_namespace_effect(
    request: &DesktopMutationRequest,
) -> Option<(PathBuf, lomi_host_store::DesktopNamespaceEffect)> {
    use lomi_files::desktop::DesktopFileOperation;
    use lomi_host_store::DesktopNamespaceEffect;
    let selected = request.root.join(&request.relative_path);
    let effect = match &request.operation {
        DesktopFileOperation::Rename { name } => DesktopNamespaceEffect::Move {
            old_path: selected.clone(),
            new_path: selected.parent()?.join(name),
        },
        DesktopFileOperation::Move {
            source_root,
            source,
        } => {
            let source = source_root.join(source);
            return Some((
                source.clone(),
                DesktopNamespaceEffect::Move {
                    new_path: selected.join(source.file_name()?),
                    old_path: source,
                },
            ));
        }
        DesktopFileOperation::Trash | DesktopFileOperation::Delete => {
            DesktopNamespaceEffect::Remove {
                old_path: selected.clone(),
            }
        }
        DesktopFileOperation::GitDiscard { expected, .. }
            if expected.index == '?'
                && expected.worktree == '?'
                && expected.original_path.is_none() =>
        {
            DesktopNamespaceEffect::Remove {
                old_path: selected.clone(),
            }
        }
        _ => return None,
    };
    Some((selected, effect))
}

#[allow(clippy::too_many_arguments)]
fn guarded_desktop_worker_check(
    phase: LocalNativeFileCheckPhase,
    operation_id: NativeIntentId,
    deadline: Instant,
    stopping: &AtomicBool,
    sticky_cancelled: &AtomicBool,
    cancelled: &AtomicBool,
    challenges: &SyncSender<GuardedEffectChallenge>,
    challenge_count: &mut usize,
    last_progress_authorized: &mut Option<Instant>,
    last_before_effect_authorized: &mut Option<Instant>,
) -> Result<(), DesktopFileErrorCode> {
    let map_failure = |failure| match failure {
        GuardedAuthorizationFailure::Closing | GuardedAuthorizationFailure::Denied => {
            DesktopFileErrorCode::Revoked
        }
        GuardedAuthorizationFailure::Deadline if sticky_cancelled.load(Ordering::SeqCst) => {
            DesktopFileErrorCode::Revoked
        }
        GuardedAuthorizationFailure::Deadline => DesktopFileErrorCode::DeadlineExceeded,
        GuardedAuthorizationFailure::Exhausted => DesktopFileErrorCode::Limit,
        GuardedAuthorizationFailure::Unqualified => DesktopFileErrorCode::Unsupported,
    };
    guarded_worker_alive(deadline, stopping, sticky_cancelled, cancelled).map_err(map_failure)?;
    match phase {
        LocalNativeFileCheckPhase::Validation => Ok(()),
        LocalNativeFileCheckPhase::Publication => {
            if last_before_effect_authorized.is_some_and(|approved| {
                Instant::now().saturating_duration_since(approved)
                    <= GUARDED_PUBLICATION_APPROVAL_MAX_AGE
            }) {
                Ok(())
            } else {
                Err(DesktopFileErrorCode::DeadlineExceeded)
            }
        }
        LocalNativeFileCheckPhase::Progress
            if last_progress_authorized.is_some_and(|last| {
                Instant::now().saturating_duration_since(last)
                    < GUARDED_PROGRESS_AUTHORIZATION_INTERVAL
            }) =>
        {
            Ok(())
        }
        LocalNativeFileCheckPhase::Progress | LocalNativeFileCheckPhase::BeforeEffect => {
            let approved = guarded_authorize(
                operation_id,
                deadline,
                stopping,
                sticky_cancelled,
                cancelled,
                challenges,
                ipc::DESKTOP_FILE_CHALLENGE_LIMIT,
                challenge_count,
            )
            .map_err(map_failure)?;
            match phase {
                LocalNativeFileCheckPhase::Progress => *last_progress_authorized = Some(approved),
                LocalNativeFileCheckPhase::BeforeEffect => {
                    *last_before_effect_authorized = Some(approved)
                }
                LocalNativeFileCheckPhase::Validation | LocalNativeFileCheckPhase::Publication => {
                    unreachable!("local desktop phases cannot request guarded IPC")
                }
            }
            Ok(())
        }
    }
}

fn run_project_mutation(
    root: PathBuf,
    content: &str,
    check: impl FnMut(NativeProjectCheckPhase) -> Result<(), NativeProjectErrorCode>,
) -> WorkerResult {
    if content.len() > MAX_PROJECT_MUTATION_BYTES {
        return Err(WorkerFailure::ProjectFiles(
            NativeProjectErrorCode::ArtifactTooLarge.into(),
        ));
    }
    let mutation = serde_json::from_str::<NativeProjectMutation>(content)
        .map_err(|_| WorkerFailure::ProjectFiles(NativeProjectErrorCode::ArtifactInvalid.into()))?;
    let directory = NativeProjectDirectory::open(&root)
        .map_err(|error| WorkerFailure::ProjectFiles(NativeProjectMutationError::Before(error)))?;
    directory
        .apply_with_phase(mutation, check)
        .map(WorkerOutput::ProjectFiles)
        .map_err(WorkerFailure::ProjectFiles)
}

fn run_artifact_create(
    root: PathBuf,
    relative: String,
    expected_parent_revision: String,
    bytes: &[u8],
    check: impl FnMut(NativeProjectCheckPhase) -> Result<(), NativeProjectErrorCode>,
) -> WorkerResult {
    if bytes.len() as u64 > MAX_ARTIFACT_BYTES {
        return Err(WorkerFailure::ProjectFiles(
            NativeProjectErrorCode::ArtifactTooLarge.into(),
        ));
    }
    let directory = NativeProjectDirectory::open(&root)
        .map_err(|error| WorkerFailure::ProjectFiles(NativeProjectMutationError::Before(error)))?;
    directory
        .create_artifact(&relative, &expected_parent_revision, bytes, check)
        .map(WorkerOutput::ArtifactCreate)
        .map_err(WorkerFailure::ProjectFiles)
}

#[allow(clippy::too_many_arguments)]
fn guarded_project_worker_check(
    phase: NativeProjectCheckPhase,
    operation_id: NativeIntentId,
    deadline: Instant,
    stopping: &AtomicBool,
    sticky_cancelled: &AtomicBool,
    cancelled: &AtomicBool,
    challenges: &SyncSender<GuardedEffectChallenge>,
    challenge_count: &mut usize,
    last_progress_authorized: &mut Option<Instant>,
    last_before_effect_authorized: &mut Option<Instant>,
) -> Result<(), NativeProjectErrorCode> {
    let map_failure = |failure| match failure {
        GuardedAuthorizationFailure::Closing => NativeProjectErrorCode::AppClosing,
        GuardedAuthorizationFailure::Deadline => NativeProjectErrorCode::DeadlineExceeded,
        GuardedAuthorizationFailure::Exhausted => NativeProjectErrorCode::ResourceExhausted,
        GuardedAuthorizationFailure::Denied => NativeProjectErrorCode::ScopeDenied,
        GuardedAuthorizationFailure::Unqualified => NativeProjectErrorCode::HostUnqualified,
    };
    guarded_worker_alive(deadline, stopping, sticky_cancelled, cancelled).map_err(map_failure)?;
    match phase {
        NativeProjectCheckPhase::Validation => Ok(()),
        NativeProjectCheckPhase::Publication => {
            if last_before_effect_authorized.is_some_and(|approved| {
                Instant::now().saturating_duration_since(approved)
                    <= GUARDED_PUBLICATION_APPROVAL_MAX_AGE
            }) {
                Ok(())
            } else {
                Err(NativeProjectErrorCode::DeadlineExceeded)
            }
        }
        NativeProjectCheckPhase::Progress
            if last_progress_authorized.is_some_and(|last| {
                Instant::now().saturating_duration_since(last)
                    < GUARDED_PROGRESS_AUTHORIZATION_INTERVAL
            }) =>
        {
            Ok(())
        }
        NativeProjectCheckPhase::Progress | NativeProjectCheckPhase::BeforeEffect => {
            let approved = guarded_authorize(
                operation_id,
                deadline,
                stopping,
                sticky_cancelled,
                cancelled,
                challenges,
                8192,
                challenge_count,
            )
            .map_err(map_failure)?;
            match phase {
                NativeProjectCheckPhase::Progress => {
                    *last_progress_authorized = Some(approved);
                }
                NativeProjectCheckPhase::BeforeEffect => {
                    *last_before_effect_authorized = Some(approved);
                }
                NativeProjectCheckPhase::Validation | NativeProjectCheckPhase::Publication => {
                    unreachable!("local-only project phases cannot request guarded IPC")
                }
            }
            Ok(())
        }
    }
}

fn read_stage(
    profile: &Path,
    operation: &Operation<'_>,
    blob: &LocalNativeFileBlob,
) -> Result<Vec<u8>, LocalError> {
    if blob.byte_length.0 > MAX_INPUT_BYTES {
        return Err(LocalError::InvalidArgument);
    }
    let stage = platform::open_native_editor_stage(profile, blob.operation_id, false)
        .map_err(|_| LocalError::InvalidArgument)?;
    let (path, mut file) = stage.into_parts();
    let expected_path = stage_path(profile, blob.operation_id);
    if path != expected_path {
        return Err(LocalError::PermissionDenied);
    }
    let metadata = file.metadata().map_err(|_| LocalError::Unavailable)?;
    if metadata.len() != blob.byte_length.0 {
        return Err(LocalError::Conflict);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| LocalError::Unavailable)?;
    let expected_len =
        usize::try_from(blob.byte_length.0).map_err(|_| LocalError::InvalidArgument)?;
    let mut bytes = Vec::with_capacity(expected_len);
    let mut buffer = [0u8; READ_CHUNK_BYTES];
    let mut hash = Sha256::new();
    loop {
        operation.check().map_err(|_| LocalError::Unavailable)?;
        let read = file
            .read(&mut buffer)
            .map_err(|_| LocalError::Unavailable)?;
        if read == 0 {
            break;
        }
        if bytes.len().saturating_add(read) > expected_len {
            return Err(LocalError::Conflict);
        }
        hash.update(&buffer[..read]);
        bytes.extend_from_slice(&buffer[..read]);
    }
    if bytes.len() != expected_len
        || format!("{:x}", hash.finalize()) != String::from(blob.content_sha256.clone())
    {
        return Err(LocalError::Conflict);
    }
    Ok(bytes)
}

fn stage_path(profile: &Path, operation_id: NativeIntentId) -> PathBuf {
    profile.join(format!(
        "native-editor-{}.stage",
        String::from(operation_id)
    ))
}

fn remove_stage_file(profile: &Path, operation_id: NativeIntentId) -> Result<(), LocalError> {
    match fs::remove_file(stage_path(profile, operation_id)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(LocalError::Unavailable),
    }
}

fn encode_success(value: WorkerOutput) -> Result<String, WorkerFailure> {
    match value {
        WorkerOutput::Editor(value) => encode_json(&value).map_err(WorkerFailure::Editor),
        WorkerOutput::ProjectFiles(value) => encode_bounded_json(&value)
            .map_err(|_| WorkerFailure::ProjectFiles(NativeProjectMutationError::Uncertain)),
        WorkerOutput::DesktopFiles(value) => encode_bounded_json(&value)
            .map_err(|_| WorkerFailure::DesktopFiles(DesktopMutationError::Uncertain)),
        WorkerOutput::ArtifactCreate(value) => encode_bounded_json(&value)
            .map_err(|_| WorkerFailure::ProjectFiles(NativeProjectMutationError::Uncertain)),
    }
}

fn encode_worker_failure(value: WorkerFailure) -> Option<String> {
    match value {
        WorkerFailure::Editor(error) => encode_error(error).ok(),
        WorkerFailure::ProjectFiles(error) => {
            let code = match error {
                NativeProjectMutationError::Before(code) => code,
                NativeProjectMutationError::Uncertain => NativeProjectErrorCode::OutcomeUnknown,
            };
            encode_bounded_json(&code).ok()
        }
        WorkerFailure::DesktopFiles(error) => encode_bounded_json(&error).ok(),
    }
}

fn encode_bounded_json(value: &impl Serialize) -> Result<String, ()> {
    let result = serde_json::to_string(value).map_err(|_| ())?;
    if result.len() > 131_072 {
        return Err(());
    }
    Ok(result)
}

fn encode_error(value: NativeFileError) -> Result<String, NativeFileError> {
    let mut value = value;
    if value.message.len() > 8_192 {
        let mut end = 8_192;
        while !value.message.is_char_boundary(end) {
            end -= 1;
        }
        value.message.truncate(end);
    }
    encode_json(&value)
}

fn encode_json(value: &impl Serialize) -> Result<String, NativeFileError> {
    let result = serde_json::to_string(value).map_err(|_| {
        NativeFileError::new(
            NativeFileErrorKind::Uncertain,
            "The host could not encode the editor result.",
        )
    })?;
    if result.len() > 131_072 {
        return Err(NativeFileError::new(
            NativeFileErrorKind::Uncertain,
            "The host editor result exceeded its response limit.",
        ));
    }
    Ok(result)
}

fn editor_result(record: NativeEditorJobRecord) -> Result<LocalResult, LocalError> {
    let state = match record.state {
        NativeEditorJobState::Running => LocalNativeEffectState::Running,
        NativeEditorJobState::Succeeded => LocalNativeEffectState::Succeeded,
        NativeEditorJobState::Failed => LocalNativeEffectState::Failed,
        NativeEditorJobState::OutcomeUnknown => LocalNativeEffectState::OutcomeUnknown,
    };
    let result_json = record
        .result_json
        .map(LocalNativeResultJson::try_from)
        .transpose()
        .map_err(|_| LocalError::Unavailable)?;
    Ok(LocalResult::NativeEditor(LocalNativeEditorResult {
        operation_id: record.operation_id,
        state,
        result_json,
    }))
}

fn prestart_failure(
    operation_id: NativeIntentId,
    message: &str,
) -> Result<LocalResult, LocalError> {
    let result_json = encode_error(NativeFileError::new(NativeFileErrorKind::Io, message)).ok();
    editor_result(NativeEditorJobRecord {
        operation_id,
        state: NativeEditorJobState::Failed,
        result_json,
    })
}

fn desktop_prestart_failure(
    operation_id: NativeIntentId,
    code: DesktopFileErrorCode,
) -> Result<LocalResult, LocalError> {
    // This explicit response is emitted only before durable job admission,
    // after exact retry lookup. It is not a joined-worker completion proof.
    let result_json = encode_bounded_json(&DesktopMutationError::Before(code)).ok();
    editor_result(NativeEditorJobRecord {
        operation_id,
        state: NativeEditorJobState::Failed,
        result_json,
    })
}
