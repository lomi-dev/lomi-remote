//! Owner-local native Git execution behind one plan-bound custody boundary.
//!
//! The Store journal and repository lease remain owned by this coordinator.
//! Worker output never proves that Git or a hook has stopped; only a verified
//! custody retirement receipt can complete a started operation.

use super::{LocalError, LocalResult, owner_domain::Operation, platform, rpc, shared_owner};
use lomi_host_store::{
    NativeGitCustodyCompletion, NativeGitJobCompletion, NativeGitJobRecord, NativeGitJobState,
    NativeGitNotStartedProof, WorkspaceEffectGuard,
};
use lomi_native_custody::{
    NativeGitPolicy, NativeIo, NativeSpec, Policy, PolicyMode, Purpose, Scope, ScopeBinding,
};
use lomi_native_git::{
    ErrorCode, NativeProjectDirectory, PreparedNativeGitPlan,
    git_execution::Environment,
    types::{NativeGitExecutionOutcome, NativeGitRequest},
};
use lomi_remote_protocol::ipc::{
    self, LocalNativeGitExecute, LocalNativeGitPrepare, LocalNativeGitResult, LocalNativeGitState,
    LocalNativeResultJson, NativeIntentId, NativeIntentTarget,
};
use lomi_remote_protocol::{HostKeyCommitmentHex, RuntimeId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::os::fd::AsRawFd;

const MAX_JOBS: usize = 128;
const MAX_WORKER_CHECKS: u64 = 65_536;
const MAX_WORKER_BUDGET: Duration = Duration::from_secs(120);
const PROGRESS_AUTHORIZATION_INTERVAL: Duration = Duration::from_millis(50);

type Challenges = SyncSender<GuardedNativeGitChallenge>;

struct GitResources {
    project: Arc<NativeProjectDirectory>,
    plan: Mutex<Option<PreparedNativeGitPlan>>,
    lease: Mutex<lomi_git::NativeRepositoryMutationLease>,
    temp_directory: PathBuf,
}

struct PreparedJob {
    record: NativeGitJobRecord,
    operation_id: NativeIntentId,
    workspace_id: lomi_remote_protocol::WorkspaceId,
    root: PathBuf,
    root_device: u64,
    root_inode: u64,
    control_roots: Vec<Arc<NativeProjectDirectory>>,
    request: NativeGitRequest,
    environment_pairs: Vec<(String, String)>,
    request_hash: String,
    plan_hash: String,
    fence_id: NativeIntentId,
    host_runtime_id: RuntimeId,
    deadline: Instant,
    dispatch_deadline: Mutex<Option<Instant>>,
    request_control: lomi_git::RequestControl,
    resources: Arc<GitResources>,
    custody_binding_sha256: Mutex<Option<String>>,
    dispatch_claimed: AtomicBool,
    started: AtomicBool,
    cancelled: AtomicBool,
    transition: Mutex<()>,
}

struct Running {
    cancelled: Arc<AtomicBool>,
    handle: JoinHandle<()>,
}

struct ShutdownRetirement {
    profile: PathBuf,
    owner: Arc<shared_owner::SharedOwner>,
    owner_endpoint: Arc<platform::OwnerEndpoint>,
    workers: Mutex<Vec<Running>>,
    previous_retry: Mutex<Option<JoinHandle<()>>>,
    pending: Arc<Mutex<Vec<PendingStoreUpdate>>>,
    unsettled: Arc<Mutex<BTreeMap<NativeIntentId, UnsettledBoundary>>>,
    prepared: Arc<Mutex<BTreeMap<NativeIntentId, Arc<PreparedJob>>>>,
}

fn retained_shutdown_holders() -> &'static Mutex<Vec<Arc<ShutdownRetirement>>> {
    static HOLDERS: OnceLock<Mutex<Vec<Arc<ShutdownRetirement>>>> = OnceLock::new();
    HOLDERS.get_or_init(|| Mutex::new(Vec::new()))
}

fn retained_retirement_threads() -> &'static Mutex<Vec<JoinHandle<()>>> {
    static THREADS: OnceLock<Mutex<Vec<JoinHandle<()>>>> = OnceLock::new();
    THREADS.get_or_init(|| Mutex::new(Vec::new()))
}

fn retain_retirement_thread(handle: JoinHandle<()>) {
    let mut threads = retained_retirement_threads()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut active = Vec::new();
    for finished in std::mem::take(&mut *threads) {
        if finished.is_finished() {
            let _ = finished.join();
        } else {
            active.push(finished);
        }
    }
    active.push(handle);
    *threads = active;
}

struct PendingStoreUpdate {
    job: Option<Arc<PreparedJob>>,
    update: StoreUpdate,
    cleanup_temp_directory: Option<PathBuf>,
}

enum StoreUpdate {
    Complete {
        proof: NativeGitCustodyCompletion,
        state: NativeGitJobState,
        result_json: Option<String>,
    },
    NotStarted {
        proof: NativeGitNotStartedProof,
        result_json: Option<String>,
    },
    FailPrepare {
        record: NativeGitJobRecord,
        expected_plan_hash: Option<String>,
        code: ErrorCode,
    },
}

struct UnsettledBoundary {
    job: Arc<PreparedJob>,
    boundary: Arc<Mutex<lomi_native_custody::Boundary>>,
    retry_ready: bool,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    stderr_drain: Option<StderrDrain>,
}

struct AtomicFlagReset(Arc<AtomicBool>);

impl Drop for AtomicFlagReset {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct BoundaryWatch {
    operation_id: NativeIntentId,
    boundary: Arc<Mutex<lomi_native_custody::Boundary>>,
    unsettled: Arc<Mutex<BTreeMap<NativeIntentId, UnsettledBoundary>>>,
    stop: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    watcher: Option<JoinHandle<()>>,
    settled: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct StderrDrain {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct StderrDrainGuard {
    operation_id: NativeIntentId,
    unsettled: Arc<Mutex<BTreeMap<NativeIntentId, UnsettledBoundary>>>,
    drain: Option<StderrDrain>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl StderrDrain {
    fn start(mut stderr: fs::File) -> Result<Self, ()> {
        use std::io::Read;

        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let handle = thread::Builder::new()
            .name("lomi-native-git-stderr-discard".to_owned())
            .spawn(move || {
                let mut buffer = [0u8; 4096];
                loop {
                    if thread_stop.load(Ordering::Acquire) {
                        break;
                    }
                    let mut descriptor = libc::pollfd {
                        fd: stderr.as_raw_fd(),
                        events: libc::POLLIN | libc::POLLHUP,
                        revents: 0,
                    };
                    let ready = unsafe { libc::poll(&mut descriptor, 1, 50) };
                    if ready < 0 {
                        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                        {
                            continue;
                        }
                        break;
                    }
                    if ready == 0 {
                        continue;
                    }
                    match stderr.read(&mut buffer) {
                        Ok(0) if thread_stop.load(Ordering::Acquire) => break,
                        Ok(0) => thread::sleep(Duration::from_millis(50)),
                        Ok(_) => {}
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                            ) => {}
                        Err(_) => break,
                    }
                }
            })
            .map_err(|_| ())?;
        Ok(Self {
            stop,
            handle: Some(handle),
        })
    }

    fn join(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for StderrDrain {
    fn drop(&mut self) {
        self.join();
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl StderrDrainGuard {
    fn new(
        operation_id: NativeIntentId,
        unsettled: Arc<Mutex<BTreeMap<NativeIntentId, UnsettledBoundary>>>,
        drain: StderrDrain,
    ) -> Self {
        Self {
            operation_id,
            unsettled,
            drain: Some(drain),
        }
    }

    fn join_after_verified_retirement(&mut self) {
        if let Some(mut drain) = self.drain.take() {
            drain.join();
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for StderrDrainGuard {
    fn drop(&mut self) {
        if let Some(drain) = self.drain.take()
            && let Some(item) = self
                .unsettled
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get_mut(&self.operation_id)
        {
            item.stderr_drain = Some(drain);
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl BoundaryWatch {
    fn start(
        operation_id: NativeIntentId,
        boundary: Arc<Mutex<lomi_native_custody::Boundary>>,
        unsettled: Arc<Mutex<BTreeMap<NativeIntentId, UnsettledBoundary>>>,
        cancelled: Arc<AtomicBool>,
        stopping: Arc<AtomicBool>,
        deadline: Instant,
    ) -> Result<Self, ()> {
        let stop = Arc::new(AtomicBool::new(false));
        let watcher_stop = stop.clone();
        let watcher_boundary = boundary.clone();
        let watcher_cancelled = cancelled.clone();
        let handle = thread::Builder::new()
            .name("lomi-native-git-retirement-watch".to_owned())
            .spawn(move || {
                loop {
                    if watcher_stop.load(Ordering::Acquire) {
                        break;
                    }
                    if watcher_cancelled.load(Ordering::SeqCst)
                        || stopping.load(Ordering::Acquire)
                        || Instant::now() >= deadline
                    {
                        if let Ok(boundary) = watcher_boundary.lock() {
                            let _ = boundary.signal(libc::SIGTERM);
                        }
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            })
            .map_err(|_| ())?;
        Ok(Self {
            operation_id,
            boundary,
            unsettled,
            stop,
            cancelled,
            watcher: Some(handle),
            settled: false,
        })
    }

    fn finish_watcher(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(watcher) = self.watcher.take() {
            let _ = watcher.join();
        }
    }

    fn mark_settled(&mut self) {
        self.finish_watcher();
        self.unsettled
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.operation_id);
        self.settled = true;
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for BoundaryWatch {
    fn drop(&mut self) {
        self.finish_watcher();
        if !self.settled {
            self.cancelled.store(true, Ordering::SeqCst);
            if let Ok(boundary) = self.boundary.lock() {
                let _ = boundary.signal(libc::SIGTERM);
            }
            if let Ok(mut unsettled) = self.unsettled.lock()
                && let Some(item) = unsettled.get_mut(&self.operation_id)
            {
                item.retry_ready = true;
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CustodyIntent {
    version: u8,
    scope: Scope,
    spec: NativeSpec,
}

pub(super) struct GuardedNativeGitChallenge {
    pub(super) operation_id: NativeIntentId,
    pub(super) challenge: ipc::IpcNonce,
    pub(super) before_execution: bool,
    sequence: u64,
    reply: SyncSender<crate::native_git_worker::HostReply>,
}

pub(super) struct GuardedNativeGitExchange {
    pub(super) operation_id: NativeIntentId,
    challenges: Receiver<GuardedNativeGitChallenge>,
    completed: Receiver<()>,
    cancelled: Arc<AtomicBool>,
}

impl GuardedNativeGitExchange {
    pub(super) fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub(super) fn respond(challenge: GuardedNativeGitChallenge, allowed: bool) -> Result<(), ()> {
        challenge
            .reply
            .send(crate::native_git_worker::HostReply::Decision {
                sequence: challenge.sequence,
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

    pub(super) fn try_challenge(&self) -> Option<GuardedNativeGitChallenge> {
        match self.challenges.try_recv() {
            Ok(challenge) => Some(challenge),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => None,
        }
    }
}

impl Drop for GuardedNativeGitExchange {
    fn drop(&mut self) {
        self.cancel();
    }
}

pub(super) struct NativeGitHost {
    profile: PathBuf,
    owner: Arc<shared_owner::SharedOwner>,
    _owner_endpoint: Arc<platform::OwnerEndpoint>,
    stopping: Arc<AtomicBool>,
    prepared: Arc<Mutex<BTreeMap<NativeIntentId, Arc<PreparedJob>>>>,
    running: Mutex<BTreeMap<NativeIntentId, Running>>,
    pending: Arc<Mutex<Vec<PendingStoreUpdate>>>,
    unsettled: Arc<Mutex<BTreeMap<NativeIntentId, UnsettledBoundary>>>,
    reaping: AtomicBool,
    last_prepared_sweep: Mutex<Instant>,
    last_recovery_sweep: Mutex<Instant>,
    retrying_unsettled: Arc<AtomicBool>,
    retirement_worker: Mutex<Option<JoinHandle<()>>>,
    shutdown_started: AtomicBool,
}

impl NativeGitHost {
    pub(super) fn new(
        profile: PathBuf,
        owner: Arc<shared_owner::SharedOwner>,
        owner_endpoint: Arc<platform::OwnerEndpoint>,
        stopping: Arc<AtomicBool>,
    ) -> Self {
        Self {
            profile,
            owner,
            _owner_endpoint: owner_endpoint,
            stopping,
            prepared: Arc::new(Mutex::new(BTreeMap::new())),
            running: Mutex::new(BTreeMap::new()),
            pending: Arc::new(Mutex::new(Vec::new())),
            unsettled: Arc::new(Mutex::new(BTreeMap::new())),
            reaping: AtomicBool::new(false),
            last_prepared_sweep: Mutex::new(Instant::now()),
            last_recovery_sweep: Mutex::new(Instant::now()),
            retrying_unsettled: Arc::new(AtomicBool::new(false)),
            retirement_worker: Mutex::new(None),
            shutdown_started: AtomicBool::new(false),
        }
    }

    pub(super) fn recover_pending(&self) -> Result<(), LocalError> {
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        {
            // Unsupported runtimes preserve the Store's durable fence. They do
            // not downgrade or clear an obligation they cannot independently
            // retire.
            return Ok(());
        }

        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            if !qualified_runtime() {
                return Ok(());
            }
            let records = self
                .owner
                .native_git_jobs_requiring_custody()
                .map_err(super::owner_error)?;
            for record in records {
                // One malformed or unavailable boundary keeps only its own
                // durable fence. It must not prevent ordinary Host startup.
                if self.recover_record(record.clone()).is_err()
                    && record.execution_started_at_ms.is_some()
                {
                    let _ = self
                        .owner
                        .native_git_mark_outcome_unknown(record.operation_id);
                }
            }
            Ok(())
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn recover_record(&self, record: NativeGitJobRecord) -> Result<(), LocalError> {
        recover_native_git_record(&self.profile, &self.owner, record)
    }

    pub(super) fn prepare_guarded(
        &self,
        operation: &Operation<'_>,
        connection: ipc::IpcNonce,
        prepare: LocalNativeGitPrepare,
    ) -> Result<LocalResult, LocalError> {
        operation.check().map_err(|_| LocalError::Unavailable)?;
        if self.stopping.load(Ordering::Acquire) || !qualified_runtime() {
            return Err(LocalError::Unavailable);
        }
        self.reap_finished();
        let input = prepare.input;
        let request_json = String::from(input.request_json.clone());
        let request: NativeGitRequest =
            serde_json::from_str(&request_json).map_err(|_| LocalError::InvalidArgument)?;
        PreparedNativeGitPlan::validate_request(&request)
            .map_err(|_| LocalError::InvalidArgument)?;
        let request_hash = hash_serialized(&input)?;

        if let Some(existing) = rpc::owner_call(operation, || {
            self.owner
                .native_git_retry(operation, prepare.operation_id, &request_hash)
        })
        .map_err(super::owner_error)?
        {
            return native_git_result(existing);
        }

        let workspace = rpc::owner_call(operation, || {
            self.owner.workspace(operation, input.workspace_id)
        })
        .map_err(super::owner_error)?;
        let requested_root = PathBuf::from(String::from(input.root));
        if requested_root != workspace.local_root {
            return Err(LocalError::InvalidArgument);
        }
        let workspace_effect_guard = WorkspaceEffectGuard::new(
            input.workspace_id,
            workspace.state.context.clone(),
            workspace.local_root.clone(),
            workspace.fence,
        )
        .map_err(|_| LocalError::InvalidArgument)?;
        let control_roots = validate_control_roots(&input.control_roots.0, &requested_root)?;
        let project = Arc::new(
            NativeProjectDirectory::open(&requested_root)
                .map_err(|_| LocalError::InvalidArgument)?,
        );
        if project.canonical_path() != requested_root {
            return Err(LocalError::InvalidArgument);
        }
        project.check().map_err(|_| LocalError::InvalidArgument)?;
        let root_directory = project
            .open_directory("")
            .map_err(|_| LocalError::InvalidArgument)?;
        let root_metadata = root_directory
            .metadata()
            .map_err(|_| LocalError::Unavailable)?;
        let root_device = root_metadata.dev();
        let root_inode = root_metadata.ino();
        for control_root in &control_roots {
            control_root
                .check()
                .map_err(|_| LocalError::InvalidArgument)?;
        }

        let cancellation = lomi_git::CancellationToken::new();
        let request_control =
            lomi_git::RequestControl::with_deadline(cancellation.clone(), operation.deadline());
        let service = Arc::new(
            lomi_git::GitService::open(
                &requested_root,
                &[self.profile.as_path()],
                workspace.state.context.clone(),
            )
            .map_err(|_| LocalError::InvalidArgument)?,
        );
        let repository_path = if request.repository_relative().is_empty() {
            requested_root.clone()
        } else {
            requested_root.join(request.repository_relative())
        };
        let repository_id = run_git_controlled(operation, cancellation.clone(), || {
            service.repository_id_for_path(&repository_path, &request_control)
        })
        .map_err(|_| LocalError::InvalidArgument)?;
        let lease = run_git_controlled(operation, cancellation.clone(), || {
            service.acquire_native_repository_lease(repository_id, &request_control)
        })
        .map_err(|_| LocalError::Conflict)?;
        lease
            .revalidate(&request_control)
            .map_err(|_| LocalError::Conflict)?;

        let started = match rpc::owner_call(operation, || {
            self.owner.native_git_begin(
                operation,
                &workspace_effect_guard,
                prepare.operation_id,
                &request_hash,
                connection,
            )
        }) {
            Ok(result) => result,
            Err(shared_owner::Error::Store(lomi_host_store::StoreError::NativeWriterBusy)) => {
                return Err(LocalError::Conflict);
            }
            Err(error) => return Err(super::owner_error(error)),
        };
        let record = match started {
            lomi_host_store::NativeGitBegin::Started(record) => record,
            lomi_host_store::NativeGitBegin::Existing(record) => return native_git_result(record),
        };

        let temp_directory = match create_native_temp_directory(prepare.operation_id) {
            Ok(path) => path,
            Err(_) => {
                self.fail_prepare(&record, None, None, ErrorCode::StorageUnavailable)?;
                return Err(LocalError::Unavailable);
            }
        };
        let captured = Environment::capture();
        let mut environment_pairs = match captured.to_unicode_pairs() {
            Ok(pairs) => pairs,
            Err(code) => {
                self.fail_prepare(&record, None, Some(&temp_directory), code)?;
                return Err(LocalError::Unavailable);
            }
        };
        environment_pairs.retain(|(key, _)| key != "TMPDIR");
        let Some(temp_directory_text) = temp_directory.to_str() else {
            self.fail_prepare(
                &record,
                None,
                Some(&temp_directory),
                ErrorCode::StorageUnavailable,
            )?;
            return Err(LocalError::Unavailable);
        };
        environment_pairs.push(("TMPDIR".to_owned(), temp_directory_text.to_owned()));
        environment_pairs.sort_by(|left, right| left.0.cmp(&right.0));
        let environment = match Environment::from_unicode_pairs(&environment_pairs) {
            Ok(environment) => environment,
            Err(code) => {
                self.fail_prepare(&record, None, Some(&temp_directory), code)?;
                return Err(LocalError::Unavailable);
            }
        };
        environment_pairs = match environment.to_unicode_pairs() {
            Ok(pairs) => pairs,
            Err(code) => {
                self.fail_prepare(&record, None, Some(&temp_directory), code)?;
                return Err(LocalError::Unavailable);
            }
        };

        let check = || operation.check().map_err(|_| ErrorCode::ControlRevoked);
        let plan = match PreparedNativeGitPlan::prepare_with_environment(
            project.clone(),
            request.clone(),
            environment.clone(),
            &check,
        ) {
            Ok(plan) => plan,
            Err(code) => {
                self.fail_prepare(&record, None, Some(&temp_directory), code)?;
                return Err(LocalError::InvalidArgument);
            }
        };
        let plan_hash = plan.revision().to_owned();
        let preview_json = match serde_json::to_string(plan.preview()) {
            Ok(preview) => preview,
            Err(_) => {
                self.fail_prepare(
                    &record,
                    Some(&plan_hash),
                    Some(&temp_directory),
                    ErrorCode::StorageUnavailable,
                )?;
                return Err(LocalError::Unavailable);
            }
        };
        let prepared_record = match rpc::owner_call(operation, || {
            self.owner.native_git_prepared(
                operation,
                prepare.operation_id,
                &request_hash,
                &plan_hash,
                &preview_json,
            )
        }) {
            Ok(record) => record,
            Err(error) => {
                self.fail_prepare(
                    &record,
                    Some(&plan_hash),
                    Some(&temp_directory),
                    ErrorCode::StorageUnavailable,
                )?;
                return Err(super::owner_error(error));
            }
        };

        let resources = Arc::new(GitResources {
            project,
            plan: Mutex::new(Some(plan)),
            lease: Mutex::new(lease),
            temp_directory,
        });
        let job = Arc::new(PreparedJob {
            record: prepared_record.clone(),
            operation_id: prepare.operation_id,
            workspace_id: input.workspace_id,
            root: requested_root,
            root_device,
            root_inode,
            control_roots,
            request,
            environment_pairs,
            request_hash,
            plan_hash,
            fence_id: prepared_record.fence_id,
            host_runtime_id: prepared_record.host_runtime_id,
            deadline: operation.deadline(),
            dispatch_deadline: Mutex::new(None),
            request_control,
            resources,
            custody_binding_sha256: Mutex::new(None),
            dispatch_claimed: AtomicBool::new(false),
            started: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            transition: Mutex::new(()),
        });
        let mut prepared = self
            .prepared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if prepared.len() >= MAX_JOBS || prepared.contains_key(&prepare.operation_id) {
            drop(prepared);
            self.fail_prepare(
                &prepared_record,
                Some(&job.plan_hash),
                Some(&job.resources.temp_directory),
                ErrorCode::ResourceExhausted,
            )?;
            return Err(LocalError::Unavailable);
        }
        prepared.insert(prepare.operation_id, job);
        native_git_result(prepared_record)
    }

    fn fail_prepare(
        &self,
        record: &NativeGitJobRecord,
        plan_hash: Option<&str>,
        cleanup_temp_directory: Option<&Path>,
        code: ErrorCode,
    ) -> Result<(), LocalError> {
        let update = StoreUpdate::FailPrepare {
            record: record.clone(),
            expected_plan_hash: plan_hash.map(str::to_owned),
            code,
        };
        if apply_prepare_failure(&self.owner, record, plan_hash, code).is_ok() {
            discard_pending_update(&self.pending, record.operation_id);
            if let Some(path) = cleanup_temp_directory {
                remove_native_temp_directory(path);
            }
        } else {
            queue_pending_update(
                &self.pending,
                None,
                update,
                cleanup_temp_directory.map(Path::to_path_buf),
            );
        }
        Ok(())
    }

    fn fail_execute_before_binding(
        &self,
        job: &Arc<PreparedJob>,
        code: ErrorCode,
    ) -> Result<(), LocalError> {
        let update = StoreUpdate::FailPrepare {
            record: job.record.clone(),
            expected_plan_hash: Some(job.plan_hash.clone()),
            code,
        };
        if apply_prepare_failure(&self.owner, &job.record, Some(&job.plan_hash), code).is_ok() {
            discard_pending_update(&self.pending, job.operation_id);
            self.prepared
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&job.operation_id);
            remove_native_temp_directory(&job.resources.temp_directory);
        } else {
            queue_pending_update(&self.pending, Some(job.clone()), update, None);
        }
        Ok(())
    }

    pub(super) fn execute_guarded(
        &self,
        operation: &Operation<'_>,
        _connection: ipc::IpcNonce,
        execute: LocalNativeGitExecute,
    ) -> Result<(LocalResult, Option<GuardedNativeGitExchange>), LocalError> {
        operation.check().map_err(|_| LocalError::Unavailable)?;
        if self.stopping.load(Ordering::Acquire) || !qualified_runtime() {
            return Err(LocalError::Unavailable);
        }
        self.reap_finished();
        let request_hash = String::from(execute.request_hash.clone());
        let plan_hash = String::from(execute.plan_hash.clone());
        let job = self
            .prepared
            .lock()
            .map_err(|_| LocalError::Unavailable)?
            .get(&execute.operation_id)
            .cloned();
        let Some(job) = job else {
            let record = rpc::owner_call(operation, || {
                self.owner
                    .native_git_status(operation, execute.operation_id)
            })
            .map_err(super::owner_error)?;
            return Ok((native_git_result(record)?, None));
        };
        if job.request_hash != request_hash || job.plan_hash != plan_hash {
            return Err(LocalError::InvalidArgument);
        }
        let transition = job.transition.lock().map_err(|_| LocalError::Unavailable)?;
        let record = rpc::owner_call(operation, || {
            self.owner
                .native_git_status(operation, execute.operation_id)
        })
        .map_err(super::owner_error)?;
        if record.state != NativeGitJobState::Prepared
            || record.plan_hash.as_deref() != Some(plan_hash.as_str())
            || record.custody_binding_json.is_some()
        {
            return Ok((native_git_result(record)?, None));
        }
        if job
            .dispatch_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok((native_git_result(record)?, None));
        }
        let execution_deadline = job.deadline.min(operation.deadline());
        *job.dispatch_deadline
            .lock()
            .map_err(|_| LocalError::Unavailable)? = Some(execution_deadline);
        let scope = match build_scope(&job) {
            Ok(scope) => scope,
            Err(error) => {
                self.fail_execute_before_binding(&job, ErrorCode::StorageUnavailable)?;
                return Err(error);
            }
        };
        let spec = match build_spec(&job, &self.profile) {
            Ok(spec) => spec,
            Err(error) => {
                self.fail_execute_before_binding(&job, ErrorCode::StorageUnavailable)?;
                return Err(error);
            }
        };
        let custody_intent = CustodyIntent {
            version: 1,
            scope,
            spec,
        };
        let custody_json = match serde_json::to_string(&custody_intent) {
            Ok(json) => json,
            Err(_) => {
                self.fail_execute_before_binding(&job, ErrorCode::StorageUnavailable)?;
                return Err(LocalError::Unavailable);
            }
        };
        if custody_json.len() > 131_072 {
            self.fail_execute_before_binding(&job, ErrorCode::ResourceExhausted)?;
            return Err(LocalError::Unavailable);
        }
        let binding_sha256 = rpc::owner_call(operation, || {
            self.owner.native_git_bind_custody(
                operation,
                job.operation_id,
                &job.request_hash,
                &job.plan_hash,
                &custody_json,
            )
        })
        .map_err(super::owner_error)?;
        *job.custody_binding_sha256
            .lock()
            .map_err(|_| LocalError::Unavailable)? = Some(binding_sha256.clone());

        let (challenge_tx, challenges) = mpsc::sync_channel(1);
        let (completed_tx, completed) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let runner_cancelled = cancelled.clone();
        let pending = self.pending.clone();
        let unsettled = self.unsettled.clone();
        let prepared = self.prepared.clone();
        let owner = self.owner.clone();
        let profile = self.profile.clone();
        let stopping = self.stopping.clone();
        let worker_job = job.clone();
        let worker_intent = custody_intent.clone();
        let mut running = self.running.lock().map_err(|_| LocalError::Unavailable)?;
        let worker_handle = match thread::Builder::new()
            .name("lomi-native-git-custody".to_owned())
            .spawn(move || {
                run_native_git(
                    worker_job,
                    worker_intent,
                    profile,
                    owner,
                    stopping,
                    runner_cancelled,
                    challenge_tx,
                    completed_tx,
                    pending,
                    unsettled,
                    prepared,
                );
            }) {
            Ok(handle) => handle,
            Err(_) => {
                let proof = NativeGitNotStartedProof::from_verified_no_execution(
                    job.operation_id,
                    job.fence_id,
                    &job.request_hash,
                    Some(&job.plan_hash),
                    job.host_runtime_id,
                    Some(&binding_sha256),
                )
                .map_err(|_| LocalError::Unavailable)?;
                let update = StoreUpdate::NotStarted {
                    proof: proof.clone(),
                    result_json: None,
                };
                if self.owner.native_git_fail_not_started(proof, None).is_ok() {
                    discard_pending_update(&self.pending, job.operation_id);
                    self.prepared
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .remove(&job.operation_id);
                    remove_native_temp_directory(&job.resources.temp_directory);
                } else {
                    queue_pending_update(&self.pending, Some(job.clone()), update, None);
                }
                return Err(LocalError::Unavailable);
            }
        };
        running.insert(
            job.operation_id,
            Running {
                cancelled: cancelled.clone(),
                handle: worker_handle,
            },
        );
        drop(running);
        drop(transition);
        let status = rpc::owner_call(operation, || {
            self.owner.native_git_status(operation, job.operation_id)
        })
        .map_err(super::owner_error)?;
        Ok((
            native_git_result(status)?,
            Some(GuardedNativeGitExchange {
                operation_id: job.operation_id,
                challenges,
                completed,
                cancelled,
            }),
        ))
    }

    pub(super) fn authorize_before_execution(
        &self,
        operation: &Operation<'_>,
        operation_id: NativeIntentId,
    ) -> Result<(), LocalError> {
        operation.check().map_err(|_| LocalError::Unavailable)?;
        if self.stopping.load(Ordering::Acquire) {
            return Err(LocalError::Unavailable);
        }
        let job = self
            .prepared
            .lock()
            .map_err(|_| LocalError::Unavailable)?
            .get(&operation_id)
            .cloned()
            .ok_or(LocalError::Conflict)?;
        let _transition = job.transition.lock().map_err(|_| LocalError::Unavailable)?;
        operation.check().map_err(|_| LocalError::Unavailable)?;
        let execution_deadline = job
            .dispatch_deadline
            .lock()
            .map_err(|_| LocalError::Unavailable)?
            .unwrap_or(job.deadline);
        if job.cancelled.load(Ordering::Acquire) || Instant::now() >= execution_deadline {
            return Err(LocalError::Unavailable);
        }
        self.revalidate_job(operation, &job)?;

        let already_started = job.started.load(Ordering::Acquire);
        let binding_sha256 = job
            .custody_binding_sha256
            .lock()
            .map_err(|_| LocalError::Unavailable)?
            .clone()
            .ok_or(LocalError::Conflict)?;
        if already_started {
            let status = rpc::owner_call(operation, || {
                self.owner.native_git_status(operation, operation_id)
            })
            .map_err(super::owner_error)?;
            if status.state == NativeGitJobState::Running
                && status.execution_started_at_ms.is_some()
                && status.custody_binding_sha256.as_deref() == Some(binding_sha256.as_str())
            {
                return Ok(());
            }
            return Err(LocalError::Conflict);
        }
        match rpc::owner_call(operation, || {
            self.owner.native_git_begin_execution(
                operation,
                operation_id,
                &job.request_hash,
                &job.plan_hash,
                &binding_sha256,
            )
        }) {
            Ok(lomi_host_store::NativeGitExecution::Started(record))
            | Ok(lomi_host_store::NativeGitExecution::Existing(record))
                if record.state == NativeGitJobState::Running
                    && record.execution_started_at_ms.is_some()
                    && record.custody_binding_sha256.as_deref()
                        == Some(binding_sha256.as_str()) =>
            {
                job.started.store(true, Ordering::Release);
                Ok(())
            }
            Ok(_) => Err(LocalError::Conflict),
            Err(error) => Err(super::owner_error(error)),
        }
    }

    fn revalidate_job(
        &self,
        operation: &Operation<'_>,
        job: &PreparedJob,
    ) -> Result<(), LocalError> {
        let project = rpc::owner_call(operation, || {
            self.owner.workspace(operation, job.workspace_id)
        })
        .map_err(super::owner_error)?;
        if project.local_root != job.root {
            return Err(LocalError::Conflict);
        }
        if job
            .resources
            .plan
            .lock()
            .map_err(|_| LocalError::Unavailable)?
            .as_ref()
            .is_none_or(|plan| plan.revision() != job.plan_hash)
        {
            return Err(LocalError::Conflict);
        }
        job.resources
            .project
            .check()
            .map_err(|_| LocalError::Conflict)?;
        for control_root in &job.control_roots {
            control_root.check().map_err(|_| LocalError::Conflict)?;
            if paths_overlap(control_root.canonical_path(), &job.root) {
                return Err(LocalError::Conflict);
            }
        }
        let directory = job
            .resources
            .project
            .open_directory("")
            .map_err(|_| LocalError::Conflict)?;
        let metadata = directory.metadata().map_err(|_| LocalError::Conflict)?;
        if metadata.dev() != job.root_device || metadata.ino() != job.root_inode {
            return Err(LocalError::Conflict);
        }
        job.resources
            .lease
            .lock()
            .map_err(|_| LocalError::Unavailable)?
            .revalidate(&job.request_control)
            .map_err(|_| LocalError::Conflict)
    }

    pub(super) fn status(
        &self,
        operation: &Operation<'_>,
        target: NativeIntentTarget,
    ) -> Result<LocalResult, LocalError> {
        operation.check().map_err(|_| LocalError::Unavailable)?;
        self.reap_finished();
        let record = rpc::owner_call(operation, || {
            self.owner.native_git_status(operation, target.intent_id)
        })
        .map_err(super::owner_error)?;
        native_git_result(record)
    }

    pub(super) fn cancel_prepared(
        &self,
        operation: &Operation<'_>,
        target: NativeIntentTarget,
    ) -> Result<LocalResult, LocalError> {
        operation.check().map_err(|_| LocalError::Unavailable)?;
        let job = self
            .prepared
            .lock()
            .map_err(|_| LocalError::Unavailable)?
            .get(&target.intent_id)
            .cloned();
        let _transition = job
            .as_ref()
            .map(|job| job.transition.lock().map_err(|_| LocalError::Unavailable))
            .transpose()?;
        let record = rpc::owner_call(operation, || {
            self.owner.native_git_status(operation, target.intent_id)
        })
        .map_err(super::owner_error)?;
        if !matches!(
            record.state,
            NativeGitJobState::Preparing | NativeGitJobState::Prepared
        ) || record.execution_started_at_ms.is_some()
            || record.custody_binding_json.is_some()
        {
            return Err(LocalError::Conflict);
        }
        let proof = NativeGitNotStartedProof::from_verified_no_execution(
            record.operation_id,
            record.fence_id,
            &record.request_hash,
            record.plan_hash.as_deref(),
            record.host_runtime_id,
            None,
        )
        .map_err(|_| LocalError::Unavailable)?;
        rpc::owner_call(operation, || {
            self.owner.native_git_fail_not_started(proof.clone(), None)
        })
        .map_err(super::owner_error)?;
        self.prepared
            .lock()
            .map_err(|_| LocalError::Unavailable)?
            .remove(&target.intent_id)
            .inspect(|job| remove_native_temp_directory(&job.resources.temp_directory));
        self.status(operation, target)
    }

    pub(super) fn acknowledge(
        &self,
        operation: &Operation<'_>,
        target: NativeIntentTarget,
    ) -> Result<LocalResult, LocalError> {
        operation.check().map_err(|_| LocalError::Unavailable)?;
        self.reap_finished();
        rpc::owner_call(operation, || {
            self.owner
                .native_git_acknowledge(operation, target.intent_id)
        })
        .map_err(super::owner_error)?;
        self.status(operation, target)
    }

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
                .filter_map(|id| running.remove(&id))
                .collect::<Vec<_>>()
        };
        for worker in finished {
            let _ = worker.handle.join();
        }
        retry_pending_store_updates(&self.owner, &self.pending, &self.prepared);
        self.reaping.store(false, Ordering::Release);
        self.sweep_expired_prepared();
        self.reap_unsettled_in_background();
    }

    fn sweep_expired_prepared(&self) {
        let now = Instant::now();
        {
            let mut last = self
                .last_prepared_sweep
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if now.saturating_duration_since(*last) < Duration::from_secs(1) {
                return;
            }
            *last = now;
        }

        let jobs = self
            .prepared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .filter(|job| now >= job.deadline)
            .cloned()
            .collect::<Vec<_>>();
        if jobs.is_empty() {
            return;
        }
        let Ok(records) = self.owner.native_git_jobs_requiring_custody() else {
            return;
        };

        for job in jobs {
            let Ok(_transition) = job.transition.try_lock() else {
                continue;
            };
            if Instant::now() < job.deadline
                || job.started.load(Ordering::Acquire)
                || job
                    .custody_binding_sha256
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .is_some()
            {
                continue;
            }
            let Some(record) = records.iter().find(|record| {
                record.operation_id == job.operation_id
                    && record.request_hash == job.request_hash
                    && record.plan_hash.as_deref() == Some(job.plan_hash.as_str())
            }) else {
                continue;
            };
            if record.state != NativeGitJobState::Prepared
                || record.execution_started_at_ms.is_some()
                || record.custody_binding_json.is_some()
                || record.custody_binding_sha256.is_some()
                || record.completion.is_some()
            {
                continue;
            }
            let Ok(proof) = NativeGitNotStartedProof::from_verified_no_execution(
                job.operation_id,
                job.fence_id,
                &job.request_hash,
                Some(&job.plan_hash),
                job.host_runtime_id,
                None,
            ) else {
                continue;
            };
            let result_json = serde_json::to_string(&ErrorCode::ControlRevoked).ok();
            let update = StoreUpdate::NotStarted {
                proof: proof.clone(),
                result_json: result_json.clone(),
            };
            match self.owner.native_git_fail_not_started(proof, result_json) {
                Ok(()) => {
                    discard_pending_update(&self.pending, job.operation_id);
                    self.prepared
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .remove(&job.operation_id);
                    remove_native_temp_directory(&job.resources.temp_directory);
                }
                Err(_) => queue_pending_update(&self.pending, Some(job.clone()), update, None),
            }
        }
    }

    fn reap_unsettled_in_background(&self) {
        let mut worker = self
            .retirement_worker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if worker.as_ref().is_some_and(JoinHandle::is_finished) {
            if let Some(finished) = worker.take() {
                drop(worker);
                let _ = finished.join();
                worker = self
                    .retirement_worker
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
        }
        if worker.is_some() {
            return;
        }
        let has_ready_boundary = self
            .unsettled
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .any(|item| item.retry_ready);
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let orphan_record = if has_ready_boundary {
            None
        } else {
            let now = Instant::now();
            let mut last = self
                .last_recovery_sweep
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if now.saturating_duration_since(*last) < Duration::from_secs(1) {
                None
            } else {
                *last = now;
                find_orphan_binding(&self.owner, &self.running, &self.unsettled, &self.prepared)
            }
        };
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        let orphan_record: Option<NativeGitJobRecord> = None;
        if (!has_ready_boundary && orphan_record.is_none())
            || self
                .retrying_unsettled
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return;
        }

        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            let owner = self.owner.clone();
            let owner_endpoint = self._owner_endpoint.clone();
            let unsettled = self.unsettled.clone();
            let pending = self.pending.clone();
            let prepared = self.prepared.clone();
            let profile = self.profile.clone();
            let orphan_record = orphan_record.clone();
            let resetting = self.retrying_unsettled.clone();
            match thread::Builder::new()
                .name("lomi-native-git-retirement-reaper".to_owned())
                .spawn(move || {
                    let _reset = AtomicFlagReset(resetting);
                    let _owner_endpoint = owner_endpoint;
                    if has_ready_boundary {
                        retry_one_unsettled_boundary(&owner, &unsettled, &pending, &prepared);
                    } else if let Some(record) = orphan_record {
                        retry_orphan_binding(&profile, &owner, record, &prepared, &pending);
                    }
                }) {
                Ok(handle) => *worker = Some(handle),
                Err(_) => self.retrying_unsettled.store(false, Ordering::Release),
            }
        }
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        self.retrying_unsettled.store(false, Ordering::Release);
    }

    pub(super) fn shutdown_and_join(&self) {
        if self
            .shutdown_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let workers = {
            let mut running = self
                .running
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(&mut *running)
        };
        for (_, worker) in &workers {
            worker.cancelled.store(true, Ordering::SeqCst);
        }
        let previous_retry = self
            .retirement_worker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        let has_pending = !self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty();
        let has_unsettled = !self
            .unsettled
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty();
        let has_prepared = !self
            .prepared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty();
        let has_durable_boundary = self
            .owner
            .native_git_jobs_requiring_custody()
            .map(|records| {
                records
                    .iter()
                    .any(|record| record.custody_binding_json.is_some())
            })
            .unwrap_or(true);
        if workers.is_empty()
            && previous_retry.is_none()
            && !has_pending
            && !has_unsettled
            && !has_prepared
            && !has_durable_boundary
        {
            self.reap_finished();
            return;
        }

        // Shutdown only signals on the owner loop. Keep the endpoint,
        // physical repository leases, runner handles, and durable update
        // retries in an owned retirement holder until every boundary has an
        // independently verified stop receipt.
        let holder = Arc::new(ShutdownRetirement {
            profile: self.profile.clone(),
            owner: self.owner.clone(),
            owner_endpoint: self._owner_endpoint.clone(),
            workers: Mutex::new(workers.into_values().collect()),
            previous_retry: Mutex::new(previous_retry),
            pending: self.pending.clone(),
            unsettled: self.unsettled.clone(),
            prepared: self.prepared.clone(),
        });
        let worker_holder = holder.clone();
        match thread::Builder::new()
            .name("lomi-native-git-shutdown-reaper".to_owned())
            .spawn(move || shutdown_retirement_loop(worker_holder))
        {
            Ok(handle) => retain_retirement_thread(handle),
            Err(_) => retained_shutdown_holders()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(holder),
        }
    }
}

fn shutdown_retirement_loop(holder: Arc<ShutdownRetirement>) {
    let _owner_endpoint = holder.owner_endpoint.clone();
    if let Some(previous_retry) = holder
        .previous_retry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
    {
        let _ = previous_retry.join();
    }
    let workers = std::mem::take(
        &mut *holder
            .workers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
    );
    for worker in workers {
        let _ = worker.handle.join();
    }

    loop {
        sweep_shutdown_prepared_jobs(&holder.owner, &holder.prepared, &holder.pending);
        retry_pending_store_updates(&holder.owner, &holder.pending, &holder.prepared);
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            retry_one_unsettled_boundary(
                &holder.owner,
                &holder.unsettled,
                &holder.pending,
                &holder.prepared,
            );
            let no_running = Mutex::new(BTreeMap::new());
            if let Some(record) = find_orphan_binding(
                &holder.owner,
                &no_running,
                &holder.unsettled,
                &holder.prepared,
            ) {
                retry_orphan_binding(
                    &holder.profile,
                    &holder.owner,
                    record,
                    &holder.prepared,
                    &holder.pending,
                );
            }
        }
        let has_unsettled = !holder
            .unsettled
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty();
        let has_pending = !holder
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty();
        let has_prepared = !holder
            .prepared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty();
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let has_durable_boundary = holder
            .owner
            .native_git_jobs_requiring_custody()
            .map(|records| {
                records
                    .iter()
                    .any(|record| record.custody_binding_json.is_some())
            })
            .unwrap_or(true);
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        let has_durable_boundary = false;
        if !has_unsettled && !has_pending && !has_prepared && !has_durable_boundary {
            return;
        }
        thread::sleep(Duration::from_secs(1));
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn recover_native_git_record(
    profile: &Path,
    owner: &shared_owner::SharedOwner,
    record: NativeGitJobRecord,
) -> Result<(), LocalError> {
    use lomi_native_custody::Boundary;

    let operation = operation_hex(record.operation_id);
    let Some(binding_json) = record.custody_binding_json.as_deref() else {
        if record.execution_started_at_ms.is_some() || record.state == NativeGitJobState::Running {
            return Err(LocalError::Unavailable);
        }
        let proof = NativeGitNotStartedProof::from_verified_no_execution(
            record.operation_id,
            record.fence_id,
            &record.request_hash,
            record.plan_hash.as_deref(),
            record.host_runtime_id,
            None,
        )
        .map_err(|_| LocalError::Unavailable)?;
        owner
            .native_git_fail_not_started(proof, None)
            .map_err(super::owner_error)?;
        return Ok(());
    };
    let binding: CustodyIntent =
        serde_json::from_str(binding_json).map_err(|_| LocalError::Unavailable)?;
    if binding.version != 1
        || binding.scope.operation_id != operation
        || binding.scope.purpose != Purpose::NativeGit
        || binding.spec.arguments != ["--internal-native-git-plan"]
        || !binding.spec.environment.is_empty()
        || binding.spec.cwd != binding.scope.project_root
        || binding.spec.policy.project_root != binding.scope.project_root
        || binding.scope.binding.as_ref().is_none_or(|scope_binding| {
            scope_binding.exact_operation.as_deref() != Some("git.execute")
                || scope_binding.request_hash.as_deref() != Some(record.request_hash.as_str())
                || scope_binding.plan_hash.as_deref() != record.plan_hash.as_deref()
                || scope_binding.fence.as_deref() != Some(String::from(record.fence_id).as_str())
                || scope_binding.host_runtime.as_deref()
                    != Some(String::from(record.host_runtime_id).as_str())
        })
    {
        return Err(LocalError::Unavailable);
    }
    let base = custody_base(profile);
    let path = base.join(&operation);
    if let Some(previous_receipt) =
        lomi_native_custody::retire_previous_boot(&path, &binding.scope, &binding.spec)
            .map_err(|_| LocalError::Unavailable)?
    {
        verify_previous_boot_receipt(&previous_receipt, &binding.scope)?;
        // The helper's release loads only trusted read-only preparation. The
        // parent may authorize a mutator only after Store records Running, so
        // release_attempted alone never means native Git execution started.
        if record.execution_started_at_ms.is_some() {
            let plan_hash = record.plan_hash.as_deref().ok_or(LocalError::Unavailable)?;
            let binding_hash = record
                .custody_binding_sha256
                .as_deref()
                .ok_or(LocalError::Unavailable)?;
            let proof = NativeGitCustodyCompletion::from_verified_custodian_binding(
                record.operation_id,
                record.fence_id,
                &record.request_hash,
                plan_hash,
                record.host_runtime_id,
                binding_hash,
            )
            .map_err(|_| LocalError::Unavailable)?;
            owner
                .native_git_complete(proof, NativeGitJobState::OutcomeUnknown, None)
                .map_err(super::owner_error)?;
        } else {
            let proof = NativeGitNotStartedProof::from_verified_no_execution(
                record.operation_id,
                record.fence_id,
                &record.request_hash,
                record.plan_hash.as_deref(),
                record.host_runtime_id,
                record.custody_binding_sha256.as_deref(),
            )
            .map_err(|_| LocalError::Unavailable)?;
            owner
                .native_git_fail_not_started(proof, None)
                .map_err(super::owner_error)?;
        }
        return Ok(());
    }

    let mut boundary = Boundary::restore(&path).map_err(|_| LocalError::Unavailable)?;
    let scope_matches = match (
        serde_json::to_vec(boundary.scope()),
        serde_json::to_vec(&binding.scope),
    ) {
        (Ok(actual), Ok(expected)) => actual == expected,
        _ => false,
    };
    if !scope_matches {
        return Err(LocalError::Unavailable);
    }
    boundary
        .verify_binding(&binding.scope, &binding.spec)
        .map_err(|_| LocalError::Unavailable)?;
    let member = boundary
        .member()
        .map_err(|_| LocalError::Unavailable)?
        .clone();
    let receipt = boundary.stop().map_err(|_| LocalError::Unavailable)?;
    verify_receipt(&receipt, &binding.scope, &member)?;

    if record.execution_started_at_ms.is_none() {
        let proof = NativeGitNotStartedProof::from_verified_no_execution(
            record.operation_id,
            record.fence_id,
            &record.request_hash,
            record.plan_hash.as_deref(),
            record.host_runtime_id,
            record.custody_binding_sha256.as_deref(),
        )
        .map_err(|_| LocalError::Unavailable)?;
        owner
            .native_git_fail_not_started(proof, None)
            .map_err(super::owner_error)?;
    } else {
        let plan_hash = record.plan_hash.as_deref().ok_or(LocalError::Unavailable)?;
        let binding_hash = record
            .custody_binding_sha256
            .as_deref()
            .ok_or(LocalError::Unavailable)?;
        let proof = NativeGitCustodyCompletion::from_verified_custodian_binding(
            record.operation_id,
            record.fence_id,
            &record.request_hash,
            plan_hash,
            record.host_runtime_id,
            binding_hash,
        )
        .map_err(|_| LocalError::Unavailable)?;
        owner
            .native_git_complete(proof, NativeGitJobState::OutcomeUnknown, None)
            .map_err(super::owner_error)?;
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn verify_previous_boot_receipt(
    receipt: &lomi_native_custody::PreviousBootReceipt,
    scope: &Scope,
) -> Result<(), LocalError> {
    let expected_job = format!(
        "gui/{}/dev.lomi.agent.host.{}",
        unsafe { libc::getuid() },
        scope.operation_id
    );
    if receipt.operation_id != scope.operation_id
        || receipt.old_boot.is_empty()
        || receipt.resource_coalition <= 1
        || receipt.sealed_job != expected_job
    {
        return Err(LocalError::Unavailable);
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn find_orphan_binding(
    owner: &shared_owner::SharedOwner,
    running: &Mutex<BTreeMap<NativeIntentId, Running>>,
    unsettled: &Mutex<BTreeMap<NativeIntentId, UnsettledBoundary>>,
    prepared: &Mutex<BTreeMap<NativeIntentId, Arc<PreparedJob>>>,
) -> Option<NativeGitJobRecord> {
    let records = owner.native_git_jobs_requiring_custody().ok()?;
    for record in records {
        if record.custody_binding_json.is_none()
            || running
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .contains_key(&record.operation_id)
            || unsettled
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .contains_key(&record.operation_id)
        {
            continue;
        }
        let job = prepared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&record.operation_id)
            .cloned();
        if let Some(job) = job {
            let Ok(_transition) = job.transition.try_lock() else {
                continue;
            };
            if running
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .contains_key(&record.operation_id)
                || unsettled
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .contains_key(&record.operation_id)
            {
                continue;
            }
        }
        return Some(record);
    }
    None
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn retry_orphan_binding(
    profile: &Path,
    owner: &shared_owner::SharedOwner,
    record: NativeGitJobRecord,
    prepared: &Mutex<BTreeMap<NativeIntentId, Arc<PreparedJob>>>,
    pending: &Mutex<Vec<PendingStoreUpdate>>,
) {
    let operation_id = record.operation_id;
    if recover_native_git_record(profile, owner, record.clone()).is_ok() {
        discard_pending_update(pending, operation_id);
        if let Some(job) = prepared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&operation_id)
        {
            remove_native_temp_directory(&job.resources.temp_directory);
        }
    } else if record.execution_started_at_ms.is_some() {
        let _ = owner.native_git_mark_outcome_unknown(operation_id);
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn retry_one_unsettled_boundary(
    owner: &shared_owner::SharedOwner,
    unsettled: &Mutex<BTreeMap<NativeIntentId, UnsettledBoundary>>,
    pending: &Mutex<Vec<PendingStoreUpdate>>,
    prepared: &Mutex<BTreeMap<NativeIntentId, Arc<PreparedJob>>>,
) {
    let candidate = unsettled
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .find(|(_, item)| item.retry_ready)
        .map(|(id, item)| (*id, item.job.clone(), item.boundary.clone()));
    let Some((operation_id, job, boundary)) = candidate else {
        return;
    };

    let (scope, member) = match boundary.lock() {
        Ok(boundary) => match boundary.member() {
            Ok(member) => (boundary.scope().clone(), member.clone()),
            Err(_) => return,
        },
        Err(_) => return,
    };
    let receipt = match boundary.lock() {
        Ok(mut boundary) => boundary.stop(),
        Err(_) => return,
    };
    let receipt = match receipt {
        Ok(receipt) => receipt,
        Err(_) => {
            if job.started.load(Ordering::Acquire) {
                let _ = owner.native_git_mark_outcome_unknown(job.operation_id);
            }
            return;
        }
    };
    if verify_receipt(&receipt, &scope, &member).is_err() {
        return;
    }

    let update = if job.started.load(Ordering::Acquire) {
        let binding_hash = job
            .custody_binding_sha256
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let Some(binding_hash) = binding_hash else {
            return;
        };
        let Ok(proof) = NativeGitCustodyCompletion::from_verified_custodian_binding(
            job.operation_id,
            job.fence_id,
            &job.request_hash,
            &job.plan_hash,
            job.host_runtime_id,
            &binding_hash,
        ) else {
            return;
        };
        StoreUpdate::Complete {
            proof,
            state: NativeGitJobState::OutcomeUnknown,
            result_json: None,
        }
    } else {
        let binding_hash = job
            .custody_binding_sha256
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let Ok(proof) = NativeGitNotStartedProof::from_verified_no_execution(
            job.operation_id,
            job.fence_id,
            &job.request_hash,
            Some(&job.plan_hash),
            job.host_runtime_id,
            binding_hash.as_deref(),
        ) else {
            return;
        };
        StoreUpdate::NotStarted {
            proof,
            result_json: None,
        }
    };

    // `apply_store_update` queues the exact proof on Store contention. Once
    // the independent retirement receipt exists, custody recovery itself is
    // complete even if durable Store completion needs another retry.
    let _ = apply_store_update(owner, job, update, pending, prepared);
    unsettled
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&operation_id);
}

fn qualified_runtime() -> bool {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        lomi_native_git::qualified() && lomi_native_custody::member(std::process::id()).is_ok()
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        false
    }
}

fn hash_serialized(value: &impl Serialize) -> Result<String, LocalError> {
    let bytes = serde_json::to_vec(value).map_err(|_| LocalError::InvalidArgument)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn operation_hex(operation_id: NativeIntentId) -> String {
    String::from(operation_id).replace('-', "")
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn validate_control_roots(
    roots: &[ipc::LocalRootPath],
    project_root: &Path,
) -> Result<Vec<Arc<NativeProjectDirectory>>, LocalError> {
    if roots.is_empty() || roots.len() > 8 {
        return Err(LocalError::InvalidArgument);
    }
    let mut validated = Vec::with_capacity(roots.len());
    let mut unique = std::collections::BTreeSet::new();
    for root in roots {
        let path = PathBuf::from(String::from(root.clone()));
        let directory =
            NativeProjectDirectory::open(&path).map_err(|_| LocalError::InvalidArgument)?;
        if !path.is_absolute()
            || directory.canonical_path() != path
            || path.canonicalize().ok().as_deref() != Some(path.as_path())
            || paths_overlap(&path, project_root)
        {
            return Err(LocalError::InvalidArgument);
        }
        directory.check().map_err(|_| LocalError::InvalidArgument)?;
        if unique.insert(path) {
            validated.push(Arc::new(directory));
        }
    }
    if validated.is_empty() {
        return Err(LocalError::InvalidArgument);
    }
    Ok(validated)
}

fn custody_base(profile: &Path) -> PathBuf {
    profile.join("custody")
}

fn build_scope(job: &PreparedJob) -> Result<Scope, LocalError> {
    let operation_id = operation_hex(job.operation_id);
    Ok(Scope {
        operation_id,
        parent_operation_id: None,
        physical_account_root: None,
        storage_root: None,
        account_id: String::new(),
        auth_revision: 0,
        task_id: None,
        attempt_id: None,
        generation: None,
        project_root: job.root.clone(),
        purpose: Purpose::NativeGit,
        binding: Some(ScopeBinding {
            exact_operation: Some("git.execute".to_owned()),
            request_hash: Some(job.request_hash.clone()),
            plan_hash: Some(job.plan_hash.clone()),
            fence: Some(String::from(job.fence_id)),
            host_runtime: Some(String::from(job.host_runtime_id)),
        }),
    })
}

fn build_policy(job: &PreparedJob, staged_worker: &Path) -> Result<Policy, LocalError> {
    let mut executable_roots = Vec::new();
    let mut runtime_roots = Vec::new();
    let mut runtime_reads = Vec::new();
    let mut blocked_reads = job
        .control_roots
        .iter()
        .map(|root| root.canonical_path().to_path_buf())
        .collect::<Vec<_>>();
    for (key, value) in &job.environment_pairs {
        if key == "PATH" {
            for entry in value.split(':').filter(|entry| !entry.is_empty()) {
                add_canonical_directory(&mut executable_roots, Path::new(entry));
            }
        } else if key == "GIT_EXEC_PATH" {
            add_canonical_directory(&mut executable_roots, Path::new(value));
        } else if matches!(key.as_str(), "GIT_CONFIG_GLOBAL" | "GIT_CONFIG_SYSTEM")
            && value != "/dev/null"
        {
            add_canonical_file(&mut runtime_reads, Path::new(value));
        } else if key == "GIT_SSH" {
            add_executable_parent(&mut executable_roots, Path::new(value));
        }
    }
    for path in [
        PathBuf::from("/etc/gitconfig"),
        PathBuf::from("/usr/local/etc/gitconfig"),
    ] {
        add_canonical_file(&mut runtime_reads, &path);
    }
    if let Some(home) = environment_value(&job.environment_pairs, "HOME") {
        add_canonical_directory(&mut runtime_roots, &Path::new(home).join(".ssh"));
        for path in [
            PathBuf::from(".gitconfig"),
            PathBuf::from(".config/git/config"),
        ] {
            add_canonical_file(&mut runtime_reads, &Path::new(home).join(path));
        }
    }
    add_canonical_directory(&mut runtime_roots, Path::new("/private/etc"));
    runtime_reads.push(staged_worker.to_path_buf());
    normalize_paths(&mut executable_roots);
    normalize_paths(&mut runtime_roots);
    normalize_paths(&mut runtime_reads);
    normalize_paths(&mut blocked_reads);
    if executable_roots.len() > 32
        || runtime_roots.len() > 32
        || runtime_reads.len() > 32
        || blocked_reads.len() > 8
    {
        return Err(LocalError::Unavailable);
    }
    let temp_root = job.resources.temp_directory.clone();
    if temp_root
        .canonicalize()
        .map_err(|_| LocalError::Unavailable)?
        != temp_root
        || !temp_root.is_dir()
    {
        return Err(LocalError::Unavailable);
    }
    let credential_socket = environment_value(&job.environment_pairs, "SSH_AUTH_SOCK")
        .map(PathBuf::from)
        .filter(|path| {
            fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket())
        });
    let network = matches!(
        job.request.operation(),
        lomi_native_git::types::NativeGitOperation::Fetch
            | lomi_native_git::types::NativeGitOperation::Push
            | lomi_native_git::types::NativeGitOperation::Pull
    );
    Ok(Policy {
        project_root: job.root.clone(),
        account_root: None,
        temp_root,
        mode: PolicyMode::NativeGit(NativeGitPolicy {
            executable_roots,
            runtime_read_roots: runtime_roots,
            repository_write_roots: Vec::new(),
            outbound_network: network,
            credential_socket,
        }),
        runtime_reads,
        protected_reads: Vec::new(),
        blocked_reads,
        runtime_read_roots: Vec::new(),
        codex_preferences: false,
        loopback_tcp_ports: Vec::new(),
        loopback_listener: false,
        unix_sockets: Vec::new(),
        allow_native_tools: false,
    })
}

fn environment_value<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find_map(|(name, value)| (name == key).then_some(value.as_str()))
}

fn add_canonical_directory(paths: &mut Vec<PathBuf>, path: &Path) {
    if let Ok(canonical) = path.canonicalize()
        && canonical.is_dir()
        && !paths.contains(&canonical)
    {
        paths.push(canonical);
    }
}

fn add_canonical_file(paths: &mut Vec<PathBuf>, path: &Path) {
    if let Ok(canonical) = path.canonicalize()
        && fs::metadata(&canonical).is_ok_and(|metadata| metadata.is_file())
        && !paths.contains(&canonical)
    {
        paths.push(canonical);
    }
}

fn add_executable_parent(paths: &mut Vec<PathBuf>, path: &Path) {
    if path.is_absolute() {
        if let Some(parent) = path.parent() {
            add_canonical_directory(paths, parent);
        }
    }
}

fn normalize_paths(paths: &mut Vec<PathBuf>) {
    paths.sort();
    paths.dedup();
}

fn native_git_result(record: NativeGitJobRecord) -> Result<LocalResult, LocalError> {
    let request_hash =
        HostKeyCommitmentHex::try_from(record.request_hash).map_err(|_| LocalError::Unavailable)?;
    let plan_hash = record
        .plan_hash
        .map(HostKeyCommitmentHex::try_from)
        .transpose()
        .map_err(|_| LocalError::Unavailable)?;
    let preview_json = record
        .preview_json
        .map(LocalNativeResultJson::try_from)
        .transpose()
        .map_err(|_| LocalError::Unavailable)?;
    let result_json = record
        .result_json
        .map(LocalNativeResultJson::try_from)
        .transpose()
        .map_err(|_| LocalError::Unavailable)?;
    Ok(LocalResult::NativeGit(LocalNativeGitResult {
        operation_id: record.operation_id,
        request_hash,
        state: match record.state {
            NativeGitJobState::Preparing => LocalNativeGitState::Preparing,
            NativeGitJobState::Prepared => LocalNativeGitState::Prepared,
            NativeGitJobState::Running => LocalNativeGitState::Running,
            NativeGitJobState::Succeeded => LocalNativeGitState::Succeeded,
            NativeGitJobState::Failed => LocalNativeGitState::Failed,
            NativeGitJobState::OutcomeUnknown => LocalNativeGitState::OutcomeUnknown,
        },
        plan_hash,
        preview_json,
        result_json,
        custody_settled: record.completion.is_some(),
    }))
}

fn run_git_controlled<T: Send + 'static>(
    operation: &Operation<'_>,
    cancellation: lomi_git::CancellationToken,
    run: impl FnOnce() -> Result<T, lomi_git::GitServiceError> + Send,
) -> Result<T, lomi_git::GitServiceError> {
    thread::scope(|scope| {
        let (sender, receiver) = mpsc::sync_channel(1);
        scope.spawn(move || {
            let _ = sender.send(run());
        });
        loop {
            match receiver.recv_timeout(Duration::from_millis(5)) {
                Ok(result) => return result,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if operation.check().is_err() {
                        cancellation.cancel();
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(lomi_git::GitServiceError::Cancelled);
                }
            }
        }
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(clippy::too_many_arguments)]
fn run_native_git(
    job: Arc<PreparedJob>,
    intent: CustodyIntent,
    profile: PathBuf,
    owner: Arc<shared_owner::SharedOwner>,
    stopping: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    challenges: Challenges,
    completed: SyncSender<()>,
    pending: Arc<Mutex<Vec<PendingStoreUpdate>>>,
    unsettled: Arc<Mutex<BTreeMap<NativeIntentId, UnsettledBoundary>>>,
    prepared: Arc<Mutex<BTreeMap<NativeIntentId, Arc<PreparedJob>>>>,
) {
    let run = run_native_git_inner(
        job.clone(),
        intent,
        &profile,
        &owner,
        stopping.clone(),
        cancelled.clone(),
        challenges,
        pending.clone(),
        unsettled.clone(),
        prepared,
    );
    if run.is_err() {
        // No result or process output is copied into the durable journal.
    }
    let _ = completed.send(());
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
#[allow(clippy::too_many_arguments)]
fn run_native_git(
    _job: Arc<PreparedJob>,
    _intent: CustodyIntent,
    _profile: PathBuf,
    _owner: Arc<shared_owner::SharedOwner>,
    _stopping: Arc<AtomicBool>,
    _cancelled: Arc<AtomicBool>,
    _challenges: Challenges,
    completed: SyncSender<()>,
    _pending: Arc<Mutex<Vec<PendingStoreUpdate>>>,
    _unsettled: Arc<Mutex<BTreeMap<NativeIntentId, UnsettledBoundary>>>,
    _prepared: Arc<Mutex<BTreeMap<NativeIntentId, Arc<PreparedJob>>>>,
) {
    let _ = completed.send(());
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(clippy::too_many_arguments)]
fn run_native_git_inner(
    job: Arc<PreparedJob>,
    intent: CustodyIntent,
    profile: &Path,
    owner: &shared_owner::SharedOwner,
    stopping: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    challenges: Challenges,
    pending: Arc<Mutex<Vec<PendingStoreUpdate>>>,
    unsettled: Arc<Mutex<BTreeMap<NativeIntentId, UnsettledBoundary>>>,
    prepared: Arc<Mutex<BTreeMap<NativeIntentId, Arc<PreparedJob>>>>,
) -> Result<(), ()> {
    use crate::native_git_worker::{HostReply, WorkerFrame, WorkerInput, read_frame, write_frame};
    use lomi_native_custody::Boundary;

    let scope = intent.scope.clone();
    let spec = intent.spec;
    let deadline = job
        .dispatch_deadline
        .lock()
        .map_err(|_| ())?
        .unwrap_or(job.deadline);
    let base = custody_base(profile);
    ensure_private_directory(&base).map_err(|_| ())?;
    let boundary = match Boundary::create(&base, scope.clone(), spec) {
        Ok(boundary) => boundary,
        Err(_) => {
            // Creation may have left a held, unreleased boundary. Leave both
            // the exact Store intent and its fencing lease for recovery.
            return Err(());
        }
    };
    let boundary = Arc::new(Mutex::new(boundary));
    unsettled
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(
            job.operation_id,
            UnsettledBoundary {
                job: job.clone(),
                boundary: boundary.clone(),
                retry_ready: false,
                stderr_drain: None,
            },
        );
    let mut watcher = match BoundaryWatch::start(
        job.operation_id,
        boundary.clone(),
        unsettled.clone(),
        cancelled.clone(),
        stopping.clone(),
        deadline,
    ) {
        Ok(watcher) => watcher,
        Err(()) => {
            if let Ok(boundary) = boundary.lock() {
                let _ = boundary.signal(libc::SIGTERM);
            }
            if let Some(item) = unsettled
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get_mut(&job.operation_id)
            {
                item.retry_ready = true;
            }
            return Err(());
        }
    };
    let member = boundary
        .lock()
        .map_err(|_| ())?
        .member()
        .map_err(|_| ())?
        .clone();
    let mut transport = {
        let mut boundary = boundary.lock().map_err(|_| ())?;
        boundary
            .retain_retirement_resource(job.resources.clone())
            .map_err(|_| ())?;
        boundary.take_transport().map_err(|_| ())?
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    let timeout_ms =
        u32::try_from(remaining.as_millis().min(MAX_WORKER_BUDGET.as_millis())).unwrap_or(u32::MAX);
    if timeout_ms == 0 {
        cancelled.store(true, Ordering::SeqCst);
    }
    let root = job.resources.project.canonical_path().to_path_buf();
    let input = WorkerInput {
        version: 1,
        operation_id: operation_hex(job.operation_id),
        fence_id: String::from(job.fence_id),
        request_hash: job.request_hash.clone(),
        plan_hash: job.plan_hash.clone(),
        host_runtime_id: String::from(job.host_runtime_id),
        root,
        root_device: job.root_device,
        root_inode: job.root_inode,
        controller: member.clone(),
        request: job.request.clone(),
        environment: job.environment_pairs.clone(),
        timeout_ms,
    };
    let stderr = std::mem::replace(
        &mut transport.stderr,
        fs::File::open("/dev/null").map_err(|_| ())?,
    );
    let mut stderr_drain = StderrDrainGuard::new(
        job.operation_id,
        unsettled.clone(),
        StderrDrain::start(stderr)?,
    );

    let released = boundary.lock().map_err(|_| ())?.release_with_gate(|_| {
        if stopping.load(Ordering::Acquire)
            || cancelled.load(Ordering::SeqCst)
            || Instant::now() >= deadline
        {
            return Err("Native Git operation was cancelled.".to_owned());
        }
        job.resources
            .project
            .check()
            .map_err(|_| "Native Git project root changed.".to_owned())?;
        job.resources
            .lease
            .lock()
            .map_err(|_| "Native Git repository lease is unavailable.".to_owned())?
            .revalidate(&job.request_control)
            .map_err(|_| "Native Git repository changed.".to_owned())
    });
    if released.is_err() {
        cancelled.store(true, Ordering::SeqCst);
    } else if write_frame(transport.stdin.as_raw_fd(), &input, deadline).is_err() {
        cancelled.store(true, Ordering::SeqCst);
    }

    let mut next_sequence = 1u64;
    let mut checks = 0u64;
    let mut last_progress_challenge = None;
    let mut worker_outcome: Option<NativeGitExecutionOutcome> = None;
    let mut worker_failed = false;
    let frame_result = loop {
        if stopping.load(Ordering::Acquire)
            || cancelled.load(Ordering::SeqCst)
            || Instant::now() >= deadline
        {
            cancelled.store(true, Ordering::SeqCst);
            break Err(());
        }
        match read_frame::<WorkerFrame>(transport.stdout.as_raw_fd(), deadline) {
            Ok(WorkerFrame::Check {
                sequence,
                before_execution,
            }) => {
                checks = checks.checked_add(1).ok_or(())?;
                if checks > MAX_WORKER_CHECKS || sequence != next_sequence {
                    cancelled.store(true, Ordering::SeqCst);
                    break Err(());
                }
                next_sequence = next_sequence.checked_add(1).ok_or(())?;
                if !before_execution
                    && last_progress_challenge.is_some_and(|last: Instant| {
                        Instant::now().saturating_duration_since(last)
                            < PROGRESS_AUTHORIZATION_INTERVAL
                    })
                {
                    write_frame(
                        transport.stdin.as_raw_fd(),
                        &HostReply::Decision {
                            sequence,
                            allowed: true,
                        },
                        deadline,
                    )
                    .map_err(|_| ())?;
                    continue;
                }
                if !before_execution {
                    last_progress_challenge = Some(Instant::now());
                }
                if operation_deadline_or_cancelled(&stopping, &cancelled, deadline) {
                    cancelled.store(true, Ordering::SeqCst);
                    break Err(());
                }
                let nonce =
                    ipc::IpcNonce::from_bytes(uuid::Uuid::new_v4().into_bytes()).map_err(|_| ())?;
                let (reply, decision) = mpsc::sync_channel(1);
                challenges
                    .send(GuardedNativeGitChallenge {
                        operation_id: job.operation_id,
                        challenge: nonce,
                        before_execution,
                        sequence,
                        reply,
                    })
                    .map_err(|_| ())?;
                let allowed = loop {
                    if operation_deadline_or_cancelled(&stopping, &cancelled, deadline) {
                        cancelled.store(true, Ordering::SeqCst);
                        break false;
                    }
                    match decision.recv_timeout(Duration::from_millis(10)) {
                        Ok(HostReply::Decision {
                            sequence: response_sequence,
                            allowed,
                        }) if response_sequence == sequence => {
                            if before_execution && allowed && !job.started.load(Ordering::Acquire) {
                                break false;
                            }
                            break allowed;
                        }
                        Ok(_) => break false,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break false,
                    }
                };
                if !allowed {
                    cancelled.store(true, Ordering::SeqCst);
                }
                write_frame(
                    transport.stdin.as_raw_fd(),
                    &HostReply::Decision { sequence, allowed },
                    deadline,
                )
                .map_err(|_| ())?;
                if !allowed {
                    break Err(());
                }
            }
            Ok(WorkerFrame::Complete { outcome }) => {
                worker_outcome = Some(outcome);
                break Ok(());
            }
            Ok(WorkerFrame::Failed { .. }) => {
                worker_failed = true;
                break Ok(());
            }
            Err(_) => break Err(()),
        }
    };
    if frame_result.is_err() {
        cancelled.store(true, Ordering::SeqCst);
    }
    let receipt = boundary.lock().map_err(|_| ())?.stop();
    watcher.finish_watcher();
    let receipt = match receipt {
        Ok(receipt) => receipt,
        Err(_) => {
            cancelled.store(true, Ordering::SeqCst);
            if let Ok(boundary) = boundary.lock() {
                let _ = boundary.signal(libc::SIGTERM);
            }
            let _ = owner.native_git_mark_outcome_unknown(job.operation_id);
            return Err(());
        }
    };
    verify_receipt(&receipt, &scope, &member).map_err(|_| ())?;
    stderr_drain.join_after_verified_retirement();
    watcher.mark_settled();

    let update = if job.started.load(Ordering::Acquire) {
        let (state, result_json) = match (worker_outcome, worker_failed, frame_result.is_ok()) {
            (Some(outcome), false, true) if outcome.plan_hash == job.plan_hash => {
                let state = if outcome.outcome_unknown {
                    NativeGitJobState::OutcomeUnknown
                } else {
                    NativeGitJobState::Succeeded
                };
                let result_json = serde_json::to_string(&outcome).ok();
                (state, result_json)
            }
            _ => (NativeGitJobState::OutcomeUnknown, None),
        };
        let binding_sha256 = job
            .custody_binding_sha256
            .lock()
            .map_err(|_| ())?
            .clone()
            .ok_or(())?;
        let proof = NativeGitCustodyCompletion::from_verified_custodian_binding(
            job.operation_id,
            job.fence_id,
            &job.request_hash,
            &job.plan_hash,
            job.host_runtime_id,
            &binding_sha256,
        )
        .map_err(|_| ())?;
        StoreUpdate::Complete {
            proof,
            state,
            result_json,
        }
    } else {
        let binding_sha256 = job.custody_binding_sha256.lock().map_err(|_| ())?.clone();
        let proof = NativeGitNotStartedProof::from_verified_no_execution(
            job.operation_id,
            job.fence_id,
            &job.request_hash,
            Some(&job.plan_hash),
            job.host_runtime_id,
            binding_sha256.as_deref(),
        )
        .map_err(|_| ())?;
        let result_json = worker_outcome
            .as_ref()
            .and_then(|outcome| serde_json::to_string(outcome).ok())
            .or_else(|| {
                worker_failed
                    .then(|| serde_json::to_string(&ErrorCode::ControlRevoked).ok())
                    .flatten()
            });
        StoreUpdate::NotStarted { proof, result_json }
    };
    if apply_store_update(owner, job.clone(), update, &pending, &prepared).is_err() {
        // Keep the job resources alive while the exact proof is retried.
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn build_spec(job: &PreparedJob, profile: &Path) -> Result<NativeSpec, LocalError> {
    let program =
        lomi_native_custody::staged_worker(profile).map_err(|_| LocalError::Unavailable)?;
    let mut policy = build_policy(job, &program)?;
    policy.blocked_reads.push(profile.to_path_buf());
    normalize_paths(&mut policy.blocked_reads);
    if policy.blocked_reads.len() > 9 {
        return Err(LocalError::Unavailable);
    }
    Ok(NativeSpec {
        program,
        arguments: vec!["--internal-native-git-plan".to_owned()],
        environment: Vec::new(),
        cwd: job.root.clone(),
        policy,
        io: NativeIo::Pipes,
    })
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn build_spec(_job: &PreparedJob, _profile: &Path) -> Result<NativeSpec, LocalError> {
    Err(LocalError::Unavailable)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn ensure_private_directory(path: &Path) -> Result<(), ()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| ())?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(()),
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || path.canonicalize().ok().as_deref() != Some(path)
    {
        return Err(());
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn create_native_temp_directory(operation_id: NativeIntentId) -> Result<PathBuf, ()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let base = PathBuf::from(format!("/private/tmp/lomi-native-git-{}", unsafe {
        libc::geteuid()
    }));
    ensure_private_directory(&base)?;
    let path = base.join(operation_hex(operation_id));
    fs::create_dir(&path).map_err(|_| ())?;
    let cleanup_empty_directory = || {
        if let Ok(metadata) = fs::symlink_metadata(&path)
            && metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == unsafe { libc::geteuid() }
            && path.canonicalize().ok().as_deref() == Some(path.as_path())
        {
            let _ = fs::remove_dir(&path);
        }
    };
    if fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).is_err() {
        cleanup_empty_directory();
        return Err(());
    }
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(_) => {
            cleanup_empty_directory();
            return Err(());
        }
    };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || path.canonicalize().ok().as_deref() != Some(path.as_path())
    {
        cleanup_empty_directory();
        return Err(());
    }
    Ok(path)
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn create_native_temp_directory(_operation_id: NativeIntentId) -> Result<PathBuf, ()> {
    Err(())
}

fn remove_native_temp_directory(path: &Path) {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(metadata) = fs::symlink_metadata(path)
            && metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && path.canonicalize().ok().as_deref() == Some(path)
        {
            let _ = fs::remove_dir_all(path);
        }
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn ensure_private_directory(_path: &Path) -> Result<(), ()> {
    Err(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn verify_receipt(
    receipt: &lomi_native_custody::RetiredReceipt,
    scope: &Scope,
    member: &lomi_native_custody::Member,
) -> Result<(), LocalError> {
    let expected_job = format!(
        "gui/{}/dev.lomi.agent.host.{}",
        unsafe { libc::getuid() },
        scope.operation_id
    );
    if receipt.operation_id != scope.operation_id
        || receipt.boot != member.identity.boot
        || receipt.resource_coalition != member.resource_coalition
        || receipt.sealed_job != expected_job
    {
        return Err(LocalError::Unavailable);
    }
    Ok(())
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn verify_receipt(
    _receipt: &lomi_native_custody::RetiredReceipt,
    _scope: &Scope,
    _member: &lomi_native_custody::Member,
) -> Result<(), LocalError> {
    Err(LocalError::Unavailable)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn operation_deadline_or_cancelled(
    stopping: &AtomicBool,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> bool {
    stopping.load(Ordering::Acquire)
        || cancelled.load(Ordering::SeqCst)
        || Instant::now() >= deadline
}

fn pending_update_operation_id(
    job: Option<&Arc<PreparedJob>>,
    update: &StoreUpdate,
) -> Option<NativeIntentId> {
    job.map(|job| job.operation_id).or_else(|| match update {
        StoreUpdate::FailPrepare { record, .. } => Some(record.operation_id),
        StoreUpdate::Complete { .. } | StoreUpdate::NotStarted { .. } => None,
    })
}

fn queue_pending_update(
    pending: &Mutex<Vec<PendingStoreUpdate>>,
    job: Option<Arc<PreparedJob>>,
    update: StoreUpdate,
    cleanup_temp_directory: Option<PathBuf>,
) {
    let id = pending_update_operation_id(job.as_ref(), &update);
    let mut pending = pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(id) = id
        && let Some(existing) = pending
            .iter_mut()
            .find(|item| pending_update_operation_id(item.job.as_ref(), &item.update) == Some(id))
    {
        if existing.job.is_none() {
            existing.job = job;
        }
        if existing.cleanup_temp_directory.is_none() {
            existing.cleanup_temp_directory = cleanup_temp_directory;
        }
        return;
    }
    pending.push(PendingStoreUpdate {
        job,
        update,
        cleanup_temp_directory,
    });
}

fn discard_pending_update(pending: &Mutex<Vec<PendingStoreUpdate>>, id: NativeIntentId) {
    pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .retain(|item| pending_update_operation_id(item.job.as_ref(), &item.update) != Some(id));
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn apply_store_update(
    owner: &shared_owner::SharedOwner,
    job: Arc<PreparedJob>,
    update: StoreUpdate,
    pending: &Mutex<Vec<PendingStoreUpdate>>,
    prepared: &Mutex<BTreeMap<NativeIntentId, Arc<PreparedJob>>>,
) -> Result<(), ()> {
    let result = match &update {
        StoreUpdate::Complete {
            proof,
            state,
            result_json,
        } => owner.native_git_complete(proof.clone(), *state, result_json.clone()),
        StoreUpdate::NotStarted { proof, result_json } => {
            owner.native_git_fail_not_started(proof.clone(), result_json.clone())
        }
        StoreUpdate::FailPrepare {
            record,
            expected_plan_hash,
            code,
        } => apply_prepare_failure(owner, record, expected_plan_hash.as_deref(), *code)
            .map_err(|_| shared_owner::Error::Store(lomi_host_store::StoreError::Fenced)),
    };
    if result.is_err() {
        queue_pending_update(pending, Some(job.clone()), update, None);
        return Err(());
    }
    discard_pending_update(pending, job.operation_id);
    prepared
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&job.operation_id);
    remove_native_temp_directory(&job.resources.temp_directory);
    Ok(())
}

fn retry_pending_store_updates(
    owner: &shared_owner::SharedOwner,
    pending: &Mutex<Vec<PendingStoreUpdate>>,
    prepared: &Mutex<BTreeMap<NativeIntentId, Arc<PreparedJob>>>,
) {
    let updates = std::mem::take(
        &mut *pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
    );
    let mut retry = Vec::new();
    for item in updates {
        let operation_id = pending_update_operation_id(item.job.as_ref(), &item.update);
        let result = match &item.update {
            StoreUpdate::Complete {
                proof,
                state,
                result_json,
            } => owner.native_git_complete(proof.clone(), *state, result_json.clone()),
            StoreUpdate::NotStarted { proof, result_json } => {
                owner.native_git_fail_not_started(proof.clone(), result_json.clone())
            }
            StoreUpdate::FailPrepare {
                record,
                expected_plan_hash,
                code,
            } => apply_prepare_failure(owner, record, expected_plan_hash.as_deref(), *code)
                .map_err(|_| shared_owner::Error::Store(lomi_host_store::StoreError::Fenced)),
        };
        if result.is_ok() {
            if let Some(operation_id) = operation_id {
                discard_pending_update(pending, operation_id);
            }
            if let Some(job) = item.job {
                prepared
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(&job.operation_id);
                remove_native_temp_directory(&job.resources.temp_directory);
            }
            if let Some(path) = item.cleanup_temp_directory {
                remove_native_temp_directory(&path);
            }
        } else {
            retry.push(item);
        }
    }
    for item in retry {
        queue_pending_update(pending, item.job, item.update, item.cleanup_temp_directory);
    }
}

fn apply_prepare_failure(
    owner: &shared_owner::SharedOwner,
    original: &NativeGitJobRecord,
    expected_plan_hash: Option<&str>,
    code: ErrorCode,
) -> Result<(), ()> {
    let current = owner
        .native_git_status_recovery(original.operation_id)
        .map_err(|_| ())?;
    if current.operation_id != original.operation_id
        || current.fence_id != original.fence_id
        || current.request_hash != original.request_hash
        || current.host_runtime_id != original.host_runtime_id
    {
        return Err(());
    }
    let result_json = serde_json::to_string(&code).map_err(|_| ())?;
    if current.state == NativeGitJobState::Failed
        && current.completion == Some(NativeGitJobCompletion::NotStarted)
        && current.result_json.as_deref() == Some(result_json.as_str())
    {
        return Ok(());
    }
    if !matches!(
        current.state,
        NativeGitJobState::Preparing | NativeGitJobState::Prepared
    ) || current.execution_started_at_ms.is_some()
        || current.custody_binding_json.is_some()
        || current.custody_binding_sha256.is_some()
        || current.completion.is_some()
        || current
            .plan_hash
            .as_deref()
            .is_some_and(|actual| Some(actual) != expected_plan_hash)
    {
        return Err(());
    }
    let proof = NativeGitNotStartedProof::from_verified_no_execution(
        current.operation_id,
        current.fence_id,
        &current.request_hash,
        current.plan_hash.as_deref(),
        current.host_runtime_id,
        None,
    )
    .map_err(|_| ())?;
    owner
        .native_git_fail_not_started(proof, Some(result_json))
        .map_err(|_| ())
}

fn sweep_shutdown_prepared_jobs(
    owner: &shared_owner::SharedOwner,
    prepared: &Mutex<BTreeMap<NativeIntentId, Arc<PreparedJob>>>,
    pending: &Mutex<Vec<PendingStoreUpdate>>,
) {
    let Ok(records) = owner.native_git_jobs_requiring_custody() else {
        return;
    };
    let jobs = prepared
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .values()
        .cloned()
        .collect::<Vec<_>>();
    for job in jobs {
        let Ok(_transition) = job.transition.try_lock() else {
            continue;
        };
        let Some(record) = records
            .iter()
            .find(|record| record.operation_id == job.operation_id)
        else {
            prepared
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&job.operation_id);
            remove_native_temp_directory(&job.resources.temp_directory);
            continue;
        };
        if record.state != NativeGitJobState::Prepared
            || record.execution_started_at_ms.is_some()
            || record.custody_binding_json.is_some()
            || record.custody_binding_sha256.is_some()
            || job.started.load(Ordering::Acquire)
            || job
                .custody_binding_sha256
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_some()
        {
            continue;
        }
        let Ok(proof) = NativeGitNotStartedProof::from_verified_no_execution(
            job.operation_id,
            job.fence_id,
            &job.request_hash,
            record.plan_hash.as_deref(),
            job.host_runtime_id,
            None,
        ) else {
            continue;
        };
        let result_json = serde_json::to_string(&ErrorCode::ControlRevoked).ok();
        match owner.native_git_fail_not_started(proof.clone(), result_json.clone()) {
            Ok(()) => {
                discard_pending_update(pending, job.operation_id);
                prepared
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(&job.operation_id);
                remove_native_temp_directory(&job.resources.temp_directory);
            }
            Err(_) => queue_pending_update(
                pending,
                Some(job.clone()),
                StoreUpdate::NotStarted { proof, result_json },
                None,
            ),
        }
    }
}

impl Drop for NativeGitHost {
    fn drop(&mut self) {
        self.shutdown_and_join();
    }
}
