//! Bounded preparation for journaled Git mutations.
//!
//! The worker performs only private-snapshot preparation. Admission, network
//! dispatch, publication, and result disclosure remain caller responsibilities
//! and must pass the existing operation/owner gates.

use lomi_git::{
    CancellationToken, GitCredentialProvider, GitPushOutcome, GitService, GitServiceError,
    PreparedGitFetch, PreparedGitMutation, PreparedGitPull, PreparedGitPullMutation,
    PreparedGitPush, PublishedGitMutation, RequestControl,
};
use lomi_remote_protocol::{
    Effect, ErrorCode, ErrorDetails, RemoteError, WorkspaceContext, WorkspaceId,
    ipc::LocalAuthConfiguration, rpc::RpcCall,
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    task::Poll,
    thread::{self, JoinHandle},
    time::Instant,
};

const MAX_WORKERS: usize = 2;
const MAX_ROOTS: usize = 200;

struct RootSlot {
    context: WorkspaceContext,
    path: PathBuf,
    service: Arc<GitService>,
}

#[derive(Default)]
struct Roots {
    slots: Mutex<BTreeMap<WorkspaceId, RootSlot>>,
    protected: Mutex<Vec<PathBuf>>,
}

impl Roots {
    fn get(&self, context: &WorkspaceContext, path: &Path) -> Result<Arc<GitService>, RemoteError> {
        let mut slots = self.slots.lock().map_err(|_| fault(ErrorCode::HostBusy))?;
        if let Some(slot) = slots.get(&context.workspace_id)
            && slot.context == *context
            && slot.path == path
        {
            return Ok(slot.service.clone());
        }
        if slots.len() >= MAX_ROOTS && !slots.contains_key(&context.workspace_id) {
            return Err(fault(ErrorCode::ResourceExhausted));
        }
        let protected = self
            .protected
            .lock()
            .map_err(|_| fault(ErrorCode::HostBusy))?;
        let paths: Vec<_> = protected.iter().map(PathBuf::as_path).collect();
        let service = Arc::new(GitService::open(path, &paths, context.clone()).map_err(map_error)?);
        slots.insert(
            context.workspace_id,
            RootSlot {
                context: context.clone(),
                path: path.to_owned(),
                service: service.clone(),
            },
        );
        Ok(service)
    }
}

struct Worker {
    cancellation: CancellationToken,
    handle: JoinHandle<()>,
}

/// One bounded mutation-preparation executor per host.
#[derive(Default)]
pub(super) struct Mutations {
    roots: Arc<Roots>,
    workers: Mutex<Vec<Worker>>,
}

/// Capture only the selected provider configuration on the owner thread. The
/// provider's actual secret-store access happens later inside the Git worker.
pub(super) fn credentials_provider(
    profile: Option<PathBuf>,
    configuration: Option<LocalAuthConfiguration>,
) -> Arc<dyn GitCredentialProvider> {
    match (profile, configuration) {
        (Some(profile), Some(configuration)) => {
            match crate::git_credentials::HostGitCredentials::new(profile, configuration) {
                Ok(provider) => Arc::new(provider),
                Err(_) => Arc::new(MissingCredentials),
            }
        }
        _ => Arc::new(MissingCredentials),
    }
}

impl Mutations {
    pub(super) fn protect_host(&self, path: &Path) -> Result<(), RemoteError> {
        self.roots
            .protected
            .lock()
            .map_err(|_| fault(ErrorCode::HostBusy))?
            .push(path.to_owned());
        Ok(())
    }

    /// Start private Git preparation outside the ingress/owner actor. The path
    /// comes from the host's workspace record, never from an RPC parameter.
    pub(super) fn start(
        &self,
        context: WorkspaceContext,
        path: PathBuf,
        call: RpcCall,
        deadline: Instant,
    ) -> Result<PrepareJob, RemoteError> {
        if mutation_context(&call) != Some(&context) {
            return Err(fault(ErrorCode::InvalidArgument));
        }
        if Instant::now() >= deadline {
            return Err(fault(ErrorCode::DeadlineExceeded));
        }
        let service = self.roots.get(&context, &path)?;
        self.spawn(deadline, move |control| prepare(&service, call, &control))
    }

    fn spawn(
        &self,
        deadline: Instant,
        run: impl FnOnce(RequestControl) -> Result<PreparedGitOperation, RemoteError> + Send + 'static,
    ) -> Result<PrepareJob, RemoteError> {
        let mut workers = self
            .workers
            .lock()
            .map_err(|_| fault(ErrorCode::HostBusy))?;
        let mut index = 0;
        while index < workers.len() {
            if workers[index].handle.is_finished() {
                let worker = workers.swap_remove(index);
                let _ = worker.handle.join();
            } else {
                index += 1;
            }
        }
        if workers.len() >= MAX_WORKERS {
            return Err(fault(ErrorCode::HostBusy));
        }
        let cancellation = CancellationToken::new();
        let control = RequestControl::with_deadline(cancellation.clone(), deadline);
        let (sender, receiver) = mpsc::sync_channel(1);
        let completed = Arc::new(AtomicBool::new(false));
        let worker_completed = completed.clone();
        let worker_cancelled = cancellation.clone();
        let handle = thread::Builder::new()
            .name("lomi-git-mutation-prepare".to_owned())
            .spawn(move || {
                let _completion = Completion(worker_completed);
                if worker_cancelled.is_cancelled() || Instant::now() >= deadline {
                    return;
                }
                let _ = sender.send(run(control));
            })
            .map_err(|_| fault(ErrorCode::HostBusy))?;
        workers.push(Worker {
            cancellation: cancellation.clone(),
            handle,
        });
        Ok(PrepareJob {
            cancellation,
            receiver,
            completed,
            transferred: false,
        })
    }

    fn spawn_step<T: Send + 'static>(
        &self,
        cancellation: CancellationToken,
        control: RequestControl,
        deadline: Instant,
        run: impl FnOnce(RequestControl) -> Result<T, GitServiceError> + Send + 'static,
    ) -> Result<StepJob<T>, RemoteError> {
        if cancellation.is_cancelled() || Instant::now() >= deadline {
            return Err(fault(ErrorCode::DeadlineExceeded));
        }
        let mut workers = self
            .workers
            .lock()
            .map_err(|_| fault(ErrorCode::HostBusy))?;
        let mut index = 0;
        while index < workers.len() {
            if workers[index].handle.is_finished() {
                let worker = workers.swap_remove(index);
                let _ = worker.handle.join();
            } else {
                index += 1;
            }
        }
        if workers.len() >= MAX_WORKERS {
            return Err(fault(ErrorCode::HostBusy));
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        let completed = Arc::new(AtomicBool::new(false));
        let worker_completed = completed.clone();
        let worker_cancelled = cancellation.clone();
        let control = control.clone();
        let handle = thread::Builder::new()
            .name("lomi-git-mutation-step".to_owned())
            .spawn(move || {
                let _completion = Completion(worker_completed);
                if worker_cancelled.is_cancelled() || Instant::now() >= deadline {
                    return;
                }
                let _ = sender.send(run(control));
            })
            .map_err(|_| fault(ErrorCode::HostBusy))?;
        workers.push(Worker {
            cancellation: cancellation.clone(),
            handle,
        });
        Ok(StepJob {
            cancellation,
            receiver,
            completed,
            transferred: false,
        })
    }

    pub(super) fn start_publish(
        &self,
        publication: PreparedGitPublication,
        cancellation: CancellationToken,
        control: RequestControl,
        deadline: Instant,
        gate: super::owner_domain::RemoteGitWriterGate,
    ) -> Result<StepJob<PublishedGitMutation>, RemoteError> {
        let phase_cancelled = cancellation.clone();
        self.spawn_step(cancellation, control, deadline, move |control| {
            publication.publish_guarded(&control, || {
                !phase_cancelled.is_cancelled() && gate.current()
            })
        })
    }

    pub(super) fn start_network(
        &self,
        operation: PreparedGitOperation,
        cancellation: CancellationToken,
        control: RequestControl,
        deadline: Instant,
        credentials: Arc<dyn GitCredentialProvider>,
        gate: super::owner_domain::RemoteGitWriterGate,
    ) -> Result<StepJob<NetworkResult>, RemoteError> {
        let phase_cancelled = cancellation.clone();
        self.spawn_step(cancellation, control, deadline, move |control| {
            operation.dispatch_network(&control, credentials.as_ref(), || {
                if !phase_cancelled.is_cancelled() && gate.current() {
                    Ok(())
                } else {
                    Err(GitServiceError::Cancelled)
                }
            })
        })
    }

    pub(super) fn start_capture(
        &self,
        published: PublishedGitMutation,
        cancellation: CancellationToken,
        control: RequestControl,
        deadline: Instant,
        gate: super::owner_domain::RemoteGitWriterGate,
    ) -> Result<StepJob<lomi_remote_protocol::RepoStateToken>, RemoteError> {
        let phase_cancelled = cancellation.clone();
        self.spawn_step(cancellation, control.clone(), deadline, move |control| {
            if phase_cancelled.is_cancelled() || !gate.current() {
                return Err(GitServiceError::MutationOutcomeUnknown);
            }
            let token = published.capture_state_token(&control)?;
            if phase_cancelled.is_cancelled() || !gate.current() {
                return Err(GitServiceError::MutationOutcomeUnknown);
            }
            Ok(token)
        })
    }
}

impl Drop for Mutations {
    fn drop(&mut self) {
        let workers = match self.workers.get_mut() {
            Ok(workers) => workers,
            Err(poisoned) => poisoned.into_inner(),
        };
        for worker in workers.iter() {
            worker.cancellation.cancel();
        }
        for worker in workers.drain(..) {
            let _ = worker.handle.join();
        }
    }
}

pub(super) struct PrepareJob {
    cancellation: CancellationToken,
    receiver: mpsc::Receiver<Result<PreparedGitOperation, RemoteError>>,
    completed: Arc<AtomicBool>,
    transferred: bool,
}

pub(super) struct StepJob<T> {
    cancellation: CancellationToken,
    receiver: mpsc::Receiver<Result<T, GitServiceError>>,
    completed: Arc<AtomicBool>,
    transferred: bool,
}

struct Completion(Arc<AtomicBool>);
impl Drop for Completion {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl PrepareJob {
    pub(super) fn is_ready(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }

    pub(super) fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub(super) fn poll(&mut self) -> Poll<Result<PreparedGitOperation, RemoteError>> {
        match self.receiver.try_recv() {
            Ok(result) => {
                if result.is_ok() {
                    // The prepared engine object retains this same original
                    // RequestControl; its caller now owns cancellation.
                    self.transferred = true;
                }
                Poll::Ready(result)
            }
            Err(mpsc::TryRecvError::Empty) => Poll::Pending,
            Err(mpsc::TryRecvError::Disconnected) => Poll::Ready(Err(fault(ErrorCode::HostBusy))),
        }
    }
}

impl Drop for PrepareJob {
    fn drop(&mut self) {
        if !self.transferred {
            self.cancellation.cancel();
        }
    }
}

impl<T> StepJob<T> {
    pub(super) fn is_ready(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }

    pub(super) fn poll(&mut self) -> Poll<Result<T, GitServiceError>> {
        match self.receiver.try_recv() {
            Ok(result) => {
                if result.is_ok() {
                    self.transferred = true;
                }
                Poll::Ready(result)
            }
            Err(mpsc::TryRecvError::Empty) => Poll::Pending,
            Err(mpsc::TryRecvError::Disconnected) => {
                Poll::Ready(Err(GitServiceError::ExecutorUnavailable))
            }
        }
    }
}

impl<T> Drop for StepJob<T> {
    fn drop(&mut self) {
        if !self.transferred {
            self.cancellation.cancel();
        }
    }
}

/// Opaque prepared operation. Network methods have not dispatched yet.
pub(super) enum PreparedGitOperation {
    Publish(PreparedGitMutation),
    Fetch(PreparedGitFetch),
    Pull(PreparedGitPull),
    Push(PreparedGitPush),
}

pub(super) enum PreparedGitPublication {
    IndexOrCommit(PreparedGitMutation),
    Pull(PreparedGitPullMutation),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum GitMutationEffect {
    Published,
    Push(GitPushOutcome),
}

impl PreparedGitOperation {
    /// Dispatch only after the caller has durably Started the operation. The
    /// callback is the final current-ticket gate immediately before network
    /// dispatch; no provider or native Git fallback is synthesized here.
    pub(super) fn dispatch_network(
        self,
        control: &RequestControl,
        credentials: &dyn GitCredentialProvider,
        start_network: impl FnOnce() -> Result<(), GitServiceError>,
    ) -> Result<NetworkResult, GitServiceError> {
        match self {
            Self::Fetch(fetch) => {
                fetch
                    .dispatch(control, credentials, start_network)
                    .map(|publication| {
                        NetworkResult::Publication(PreparedGitPublication::IndexOrCommit(
                            publication,
                        ))
                    })
            }
            Self::Pull(pull) => {
                pull.dispatch(control, credentials, start_network)
                    .map(|publication| {
                        NetworkResult::Publication(PreparedGitPublication::Pull(publication))
                    })
            }
            Self::Push(push) => push
                .dispatch_for_receipt(control, credentials, start_network)
                .map(|(outcome, repo_state_token)| NetworkResult::Push {
                    outcome,
                    repo_state_token,
                }),
            Self::Publish(_) => Err(GitServiceError::UnsupportedCapability),
        }
    }

    pub(super) fn publication(self) -> Result<PreparedGitPublication, GitServiceError> {
        match self {
            Self::Publish(mutation) => Ok(PreparedGitPublication::IndexOrCommit(mutation)),
            _ => Err(GitServiceError::UnsupportedCapability),
        }
    }
}

pub(super) enum NetworkResult {
    Publication(PreparedGitPublication),
    Push {
        outcome: GitPushOutcome,
        repo_state_token: lomi_remote_protocol::RepoStateToken,
    },
}

impl PreparedGitPublication {
    pub(super) fn publish_guarded(
        self,
        control: &RequestControl,
        current_gate: impl Fn() -> bool,
    ) -> Result<PublishedGitMutation, GitServiceError> {
        match self {
            Self::IndexOrCommit(mutation) => mutation.publish_guarded(control, current_gate),
            Self::Pull(pull) => pull.publish_guarded(control, current_gate),
        }
    }

    pub(super) fn publish_for_receipt_guarded(
        self,
        control: &RequestControl,
        current_gate: impl Fn() -> bool,
    ) -> Result<lomi_remote_protocol::RepoStateToken, GitServiceError> {
        match self {
            Self::IndexOrCommit(mutation) => {
                mutation.publish_for_receipt_guarded(control, current_gate)
            }
            Self::Pull(pull) => pull.publish_for_receipt_guarded(control, current_gate),
        }
    }
}

fn prepare(
    service: &GitService,
    call: RpcCall,
    control: &RequestControl,
) -> Result<PreparedGitOperation, RemoteError> {
    let prepared = match call {
        RpcCall::GitStage(params) => service
            .prepare_stage(params, control)
            .map(PreparedGitOperation::Publish),
        RpcCall::GitUnstage(params) => service
            .prepare_unstage(params, control)
            .map(PreparedGitOperation::Publish),
        RpcCall::GitCommit(params) => service
            .prepare_commit(params, control)
            .map(PreparedGitOperation::Publish),
        RpcCall::GitFetch(params) => service
            .prepare_fetch(params, control)
            .map(PreparedGitOperation::Fetch),
        RpcCall::GitPull(params) => service
            .prepare_pull(params, control)
            .map(PreparedGitOperation::Pull),
        RpcCall::GitPush(params) => service
            .prepare_push(params, control)
            .map(PreparedGitOperation::Push),
        _ => return Err(fault(ErrorCode::InvalidArgument)),
    };
    prepared.map_err(map_error)
}

fn mutation_context(call: &RpcCall) -> Option<&WorkspaceContext> {
    match call {
        RpcCall::GitStage(params) => Some(&params.mutation.context),
        RpcCall::GitUnstage(params) => Some(&params.mutation.context),
        RpcCall::GitCommit(params) => Some(&params.mutation.context),
        RpcCall::GitFetch(params) | RpcCall::GitPush(params) => Some(&params.mutation.context),
        RpcCall::GitPull(params) => Some(&params.mutation.context),
        _ => None,
    }
}

fn fault(code: ErrorCode) -> RemoteError {
    RemoteError::new(code, false, Effect::None, ErrorDetails::empty(), None)
        .expect("static Git mutation error")
}

pub(super) fn map_error(error: GitServiceError) -> RemoteError {
    fault(match error {
        GitServiceError::Cancelled => ErrorCode::ControlRevoked,
        GitServiceError::DeadlineExceeded => ErrorCode::DeadlineExceeded,
        GitServiceError::InvalidDeadline
        | GitServiceError::InvalidObjectId
        | GitServiceError::InvalidCursor => ErrorCode::InvalidArgument,
        GitServiceError::ContextMismatch => ErrorCode::StaleEpoch,
        GitServiceError::RepositoryNotFound | GitServiceError::DiscoveryFailed => {
            ErrorCode::ResourceNotFound
        }
        GitServiceError::RepositoryChanged | GitServiceError::StaleState => {
            ErrorCode::ResyncRequired
        }
        GitServiceError::MutationConflict => ErrorCode::ResyncRequired,
        GitServiceError::UnsafeRepository => ErrorCode::ProtectedPath,
        GitServiceError::ResourceLimit => ErrorCode::ResourceExhausted,
        GitServiceError::IdentityRequired => ErrorCode::GitIdentityRequired,
        GitServiceError::CredentialsRequired => ErrorCode::CredentialsRequired,
        GitServiceError::UnsupportedCapability => ErrorCode::UnsupportedCapability,
        GitServiceError::NetworkFailed => ErrorCode::ServiceUnavailable,
        GitServiceError::PushRejected => ErrorCode::ScopeDenied,
        GitServiceError::MutationFailed
        | GitServiceError::MutationOutcomeUnknown
        | GitServiceError::NetworkOutcomeUnknown
        | GitServiceError::ExecutorUnavailable
        | GitServiceError::ExecutorFailed => ErrorCode::HostBusy,
    })
}

// The credential provider is injected by host secret storage. Until configured,
// the safe behavior is to report CredentialsRequired without ambient fallback.
pub(super) struct MissingCredentials;
impl GitCredentialProvider for MissingCredentials {
    fn credentials(
        &self,
        _: &lomi_git::RemoteCredentialBinding,
    ) -> Option<lomi_git::GitCredentials> {
        None
    }
}
