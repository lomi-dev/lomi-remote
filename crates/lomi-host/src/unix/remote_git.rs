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
    #[cfg(test)]
    pub(super) fn cancellation_for_test(&self) -> CancellationToken {
        self.cancellation.clone()
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_dropped_ticket_cancels_but_does_not_detach_or_free_a_live_worker_slot() {
        let reads = Reads::default();
        let deadline = Instant::now() + Duration::from_secs(5);
        let (released, wait) = mpsc::channel::<()>();
        let (started, ready) = mpsc::sync_channel(1);
        let mut first = reads
            .spawn(deadline, move |_| {
                started.send(()).unwrap();
                let _ = wait.recv_timeout(Duration::from_secs(3));
                Err(fault(ErrorCode::ResourceNotFound))
            })
            .unwrap();
        ready.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(first.poll().is_pending(), "the actor never waits for Git");
        let cancelled = first.cancellation.clone();
        drop(first);
        assert!(cancelled.is_cancelled());
        let (released_second, wait_second) = mpsc::channel::<()>();
        let second = reads
            .spawn(deadline, move |_| {
                let _ = wait_second.recv_timeout(Duration::from_secs(3));
                Err(fault(ErrorCode::ResourceNotFound))
            })
            .unwrap();
        assert_eq!(
            reads
                .spawn(deadline, |_| unreachable!())
                .err()
                .unwrap()
                .code(),
            ErrorCode::HostBusy
        );
        released.send(()).unwrap();
        released_second.send(()).unwrap();
        drop(second);
        drop(reads); // joins both owned workers, including the cancelled one
    }

    #[test]
    fn a_past_deadline_never_starts_work() {
        let reads = Reads::default();
        assert_eq!(
            reads
                .spawn(Instant::now(), |_| unreachable!())
                .err()
                .unwrap()
                .code(),
            ErrorCode::DeadlineExceeded
        );
        assert!(reads.workers.lock().unwrap().is_empty());
    }

    #[test]
    fn oversized_escaped_diff_becomes_a_bounded_error_without_discarding_the_channel() {
        use lomi_remote_protocol::{ApplicationMajor, DecimalU64, EntryId, rpc::*};
        let request = RpcRequest {
            v: ApplicationMajor, r#type: RequestKind::Request,
            request_id: "git-read-budget".to_owned().try_into().unwrap(),
            timeout_ms: 10_000u64.try_into().unwrap(),
            call: RpcCall::GitDiff(serde_json::from_value(serde_json::json!({
                "context": {"workspaceId": "01010101-0101-0101-0101-010101010101", "workspaceEpoch": "02020202-0202-0202-0202-020202020202", "runtimeId": "03030303-0303-0303-0303-030303030303", "runtimeGeneration": "1", "hostAccessEpoch": "1", "grantRevision": "1"},
                "repositoryId": "04040404-0404-0404-0404-040404040404", "stateToken": "snapshot", "view": "worktree", "entryId": null, "cursor": null, "limit": 5
            })).unwrap()),
        };
        let line = GitDiffLine {
            kind: DiffLineKind::Added,
            text: "\"".repeat(1024).try_into().unwrap(),
        };
        let file = GitDiffFile {
            entry_id: EntryId::from_bytes([5; 16]).unwrap(),
            display_name: "large.txt".to_owned().try_into().unwrap(),
            binary: false,
            hunks: BoundedList(vec![GitDiffHunk {
                old_start: DecimalU64(1),
                new_start: DecimalU64(1),
                lines: BoundedList(vec![line; 200]),
            }]),
            truncated: false,
        };
        let result = |files| {
            RpcResult::GitDiff(GitDiffResult {
                state_token: "snapshot".to_owned().try_into().unwrap(),
                files: BoundedList(files),
                next_cursor: None,
                truncated: false,
            })
        };
        let fits = encode_response(&request, Ok(result(vec![file.clone(); 2]))).unwrap();
        assert!(fits.len() < lomi_remote_protocol::message_framing::MAX_MESSAGE_LEN);
        assert!(matches!(
            lomi_remote_protocol::decode_response_for(&fits, &request).unwrap(),
            RpcResponse::Result { .. }
        ));
        let mut plain = file.clone();
        for hunk in &mut plain.hunks.0 {
            for line in &mut hunk.lines.0 {
                line.text = "a".repeat(1024).try_into().unwrap();
            }
        }
        let plain = encode_response(&request, Ok(result(vec![plain; 4]))).unwrap();
        assert!(plain.len() < lomi_remote_protocol::message_framing::MAX_MESSAGE_LEN);
        assert!(plain.capacity() <= lomi_remote_protocol::message_framing::MAX_MESSAGE_LEN);
        let oversized = encode_response(&request, Ok(result(vec![file; 5]))).unwrap();
        assert!(oversized.len() < 1024);
        let RpcResponse::Error { error, .. } =
            lomi_remote_protocol::decode_response_for(&oversized, &request).unwrap()
        else {
            panic!("bounded error");
        };
        assert_eq!(error.code(), ErrorCode::ResourceExhausted);
        assert_eq!(error.effect(), Effect::None);
        let mut encoder = lomi_remote_protocol::message_framing::MessageEncoder::new();
        encoder
            .begin(
                lomi_remote_protocol::message_framing::MessageKind::RpcResponse,
                oversized,
            )
            .unwrap();
        while encoder.next_frame().unwrap().is_some() {}
        encoder
            .begin(
                lomi_remote_protocol::message_framing::MessageKind::RpcResponse,
                fits,
            )
            .unwrap();
        while encoder.next_frame().unwrap().is_some() {}
        encoder
            .begin(
                lomi_remote_protocol::message_framing::MessageKind::RpcResponse,
                plain,
            )
            .unwrap();
    }

    #[test]
    fn repository_discovery_uses_the_host_root_and_rejects_a_cross_context_call() {
        use lomi_remote_protocol::{
            DecimalU64, RuntimeId, WorkspaceEpoch, rpc::WorkspaceReadParams,
        };
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join(".git")).unwrap();
        let context = WorkspaceContext {
            workspace_id: WorkspaceId::from_bytes([1; 16]).unwrap(),
            workspace_epoch: WorkspaceEpoch::from_bytes([2; 16]).unwrap(),
            runtime_id: RuntimeId::from_bytes([3; 16]).unwrap(),
            runtime_generation: DecimalU64(1),
            host_access_epoch: DecimalU64(1),
            grant_revision: DecimalU64(1),
        };
        let reads = Reads::default();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut other = context.clone();
        other.grant_revision = DecimalU64(2);
        let call = RpcCall::GitRepositories(WorkspaceReadParams { context: other });
        assert_eq!(
            reads
                .start(context.clone(), root.path().to_owned(), call, deadline)
                .err()
                .unwrap()
                .code(),
            ErrorCode::InvalidArgument
        );
        let mut read = reads
            .start(
                context.clone(),
                root.path().to_owned(),
                RpcCall::GitRepositories(WorkspaceReadParams { context }),
                deadline,
            )
            .unwrap();
        loop {
            if let Poll::Ready(result) = read.poll() {
                let RpcResult::GitRepositories(result) = result.unwrap() else {
                    panic!("repository result");
                };
                assert_eq!(result.repositories.0.len(), 1);
                break;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
    }
}
