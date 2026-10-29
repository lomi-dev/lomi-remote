//! Bounded Git reads outside the Cloud/ingress actor.
//!
//! Admission and disclosure remain the caller's responsibility. A job owns no
//! owner turn, authority proof, socket or credentials. Dropping its ticket
//! cancels computation; the executor retains and joins the worker instead of
//! detaching it. Completed data must still pass the ordinary response gate.
use lomi_git::{CancellationToken, GitService, GitServiceError, RequestControl};
use lomi_remote_protocol::{
    Effect, ErrorCode, ErrorDetails, RemoteError, WorkspaceContext, WorkspaceId,
    rpc::{RpcCall, RpcRequest, RpcResponse, RpcResult},
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

/// One executor per host, shared by every channel and workspace alias.
#[derive(Default)]
pub(super) struct Reads {
    roots: Arc<Roots>,
    workers: Mutex<Vec<Worker>>,
}

impl Reads {
    /// Called at host initialization, before any remote job can be submitted.
    pub(super) fn protect_host(&self, path: &Path) -> Result<(), RemoteError> {
        self.roots
            .protected
            .lock()
            .map_err(|_| fault(ErrorCode::HostBusy))?
            .push(path.to_owned());
        Ok(())
    }

    /// Call only after consuming the queued request under a current owner turn.
    /// `path` is the host's project root, never a path from an RPC parameter.
    pub(super) fn start(
        &self,
        context: WorkspaceContext,
        path: PathBuf,
        call: RpcCall,
        deadline: Instant,
    ) -> Result<Read, RemoteError> {
        if read_context(&call) != Some(&context) {
            return Err(fault(ErrorCode::InvalidArgument));
        }
        let roots = self.roots.clone();
        self.spawn(deadline, move |control| {
            let service = roots.get(&context, &path)?;
            execute(&service, call, &control)
        })
    }

    /// Local IPC runs on its own bounded connection thread. Reuse exactly the
    /// same root confinement and worker budget as remote reads; no owner lock
    /// is held while the WASI executor runs.
    pub(super) fn read_local(
        &self,
        context: WorkspaceContext,
        path: PathBuf,
        call: RpcCall,
        operation: &super::owner_domain::Operation<'_>,
    ) -> Result<RpcResult, RemoteError> {
        let mut read = self.start(context, path, call, operation.deadline())?;
        loop {
            operation
                .check()
                .map_err(|_| fault(ErrorCode::DeadlineExceeded))?;
            match read.poll() {
                Poll::Ready(result) => return result,
                Poll::Pending => thread::park_timeout(
                    operation
                        .deadline()
                        .saturating_duration_since(Instant::now())
                        .min(std::time::Duration::from_millis(1)),
                ),
            }
        }
    }

    fn spawn(
        &self,
        deadline: Instant,
        run: impl FnOnce(RequestControl) -> Result<RpcResult, RemoteError> + Send + 'static,
    ) -> Result<Read, RemoteError> {
        if Instant::now() >= deadline {
            return Err(fault(ErrorCode::DeadlineExceeded));
        }
        let mut workers = self
            .workers
            .lock()
            .map_err(|_| fault(ErrorCode::HostBusy))?;
        // Joining only known-finished workers cannot hold up Cloud/revoke work.
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
        let completion = Completion(completed.clone());
        let worker_cancelled = cancellation.clone();
        let handle = thread::Builder::new()
            .name("lomi-git-read".to_owned())
            .spawn(move || {
                let _completion = completion;
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
        Ok(Read {
            cancellation,
            receiver,
            completed,
        })
    }
}

impl Drop for Reads {
    fn drop(&mut self) {
        // Host shutdown retains custody even if the worker panicked or the
        // channel disappeared. There are at most MAX_WORKERS handles.
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

pub(super) struct Read {
    cancellation: CancellationToken,
    receiver: mpsc::Receiver<Result<RpcResult, RemoteError>>,
    completed: Arc<AtomicBool>,
}

struct Completion(Arc<AtomicBool>);
impl Drop for Completion {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl Read {
    pub(super) fn is_ready(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }
    /// Poll after checking the original operation and current authority. No
    /// result, including an error, is an authorization to send a response.
    pub(super) fn poll(&mut self) -> Poll<Result<RpcResult, RemoteError>> {
        match self.receiver.try_recv() {
            Ok(result) => Poll::Ready(result),
            Err(mpsc::TryRecvError::Empty) => Poll::Pending,
            Err(mpsc::TryRecvError::Disconnected) => Poll::Ready(Err(fault(ErrorCode::HostBusy))),
        }
    }
}

impl Drop for Read {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

fn read_context(call: &RpcCall) -> Option<&WorkspaceContext> {
    match call {
        RpcCall::GitRepositories(params) => Some(&params.context),
        RpcCall::GitStatus(params) => Some(&params.context),
        RpcCall::GitDiff(params) => Some(&params.context),
        RpcCall::GitLog(params) => Some(&params.context),
        RpcCall::GitShow(params) => Some(&params.context),
        _ => None,
    }
}

fn execute(
    service: &GitService,
    call: RpcCall,
    control: &RequestControl,
) -> Result<RpcResult, RemoteError> {
    match call {
        RpcCall::GitRepositories(params) => service
            .repositories(params, control)
            .map(RpcResult::GitRepositories),
        RpcCall::GitStatus(params) => service.status(params, control).map(RpcResult::GitStatus),
        RpcCall::GitDiff(params) => service.diff(params, control).map(RpcResult::GitDiff),
        RpcCall::GitLog(params) => service.log(params, control).map(RpcResult::GitLog),
        RpcCall::GitShow(params) => service.show(params, control).map(RpcResult::GitShow),
        _ => return Err(fault(ErrorCode::InvalidArgument)),
    }
    .map_err(map_error)
}

fn fault(code: ErrorCode) -> RemoteError {
    RemoteError::new(code, false, Effect::None, ErrorDetails::empty(), None)
        .expect("static Git error")
}

/// Keep the complete envelope within the logical-message budget. The worker's
/// independent stdout bound does not bound JSON escaping in the RPC envelope.
pub(super) fn encode_response(
    request: &RpcRequest,
    result: Result<RpcResult, RemoteError>,
) -> Result<Vec<u8>, serde_json::Error> {
    struct Output {
        bytes: Vec<u8>,
        exhausted: bool,
    }
    impl std::io::Write for Output {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len()
                > lomi_remote_protocol::message_framing::MAX_MESSAGE_LEN
                    .saturating_sub(self.bytes.len())
            {
                self.exhausted = true;
                return Err(std::io::Error::other("Git response exceeds framing limit"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let error_response = |error| RpcResponse::Error {
        v: request.v,
        request_id: request.request_id.clone(),
        operation_id: None,
        error,
    };
    let response = match result {
        Ok(result) => RpcResponse::Result {
            v: request.v,
            request_id: request.request_id.clone(),
            result,
        },
        Err(error) => error_response(error),
    };
    let mut output = Output {
        bytes: Vec::new(),
        exhausted: false,
    };
    match serde_json::to_writer(&mut output, &response) {
        // The encoder also bounds allocation capacity. Vec growth may reserve
        // more than the admitted bytes, especially for long unescaped strings.
        Ok(()) => Ok(output.bytes.into_boxed_slice().into_vec()),
        Err(_) if output.exhausted => {
            serde_json::to_vec(&error_response(fault(ErrorCode::ResourceExhausted)))
        }
        Err(error) => Err(error),
    }
}

fn map_error(error: GitServiceError) -> RemoteError {
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
        // This adapter admits only reads. Mutation uncertainty requires a
        // journaled operation binding in the separate publication path.
        GitServiceError::MutationOutcomeUnknown | GitServiceError::MutationFailed => {
            ErrorCode::HostBusy
        }
        GitServiceError::UnsafeRepository => ErrorCode::ProtectedPath,
        GitServiceError::ResourceLimit => ErrorCode::ResourceExhausted,
        GitServiceError::IdentityRequired => ErrorCode::GitIdentityRequired,
        GitServiceError::CredentialsRequired => ErrorCode::CredentialsRequired,
        GitServiceError::UnsupportedCapability => ErrorCode::UnsupportedCapability,
        GitServiceError::NetworkFailed => ErrorCode::ServiceUnavailable,
        GitServiceError::PushRejected => ErrorCode::ScopeDenied,
        GitServiceError::NetworkOutcomeUnknown => ErrorCode::HostBusy,
        GitServiceError::ExecutorUnavailable => ErrorCode::UnsupportedCapability,
        GitServiceError::ExecutorFailed => ErrorCode::HostBusy,
    })
}
