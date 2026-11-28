//! The Host side of the device tunnel streams (plan-1.0 P3a.9): `rpc` on stream 0, `directory`,
//! `terminal`, `chat`, `files.watch` and `transfer`. Messages are today's frames (JSON), carried
//! as stream messages; the binary encodings are P4.
//!
//! Threads. The engine calls this service on the uplink thread, where nothing may block, so a
//! callback only hands bytes to the tunnel's workers and returns:
//! - `rpc` reads stream 0: it parses a request, takes a per-workspace permit (4 reads, 1
//!   mutation) and runs the call on its own short-lived thread, so a slow `git.fetch` delays no
//!   other call; answers go back through the `streams` worker;
//! - `streams` owns every other stream. It is one event loop that blocks until something
//!   happens: a job (open, message, credit, answer, transfer), a terminal or chat queue that got
//!   an event (their wake-ups), or the housekeeping tick.
//!
//! Wake-ups. Terminal attachments and chat subscriptions call a [`Wake`] when they queue an
//! event; credit (`on_writable`) and every request arrive as jobs. A wake is one coalesced job,
//! so an idle tunnel costs nothing. Every stream has its own [`Pipe`] (a bounded queue and a
//! bytes-in-flight budget) and a stream is only produced while its pipe has room, so a stream
//! whose device does not return credit stalls alone: the others keep flowing.
//!
//! Authorization is the one check from `tunnel_authz`, run for every rpc request, every stream
//! open and every control message, on a view (grant, shared workspaces) that is at most about a
//! second old or older only until the Host's projection revision moves. A stream whose
//! workspace is no longer shared with the device, or whose session ended, is reset.
//!
//! rpc. Files reads, chat and the stream messages run here; every other catalog method runs the
//! same code as local IPC (`rpc::dispatch`) on a per-request state whose actor is the device.
//! `files.read`, `git.diff` and `git.show` answer inline (one write on stream 0) when the JSON
//! is at most `TRANSFER_INLINE_MAX`; otherwise the Host opens a `transfer` stream (OPEN carries
//! the request id), answers with an `RpcTransferResponse` and sends the payload there in
//! `TRANSFER_CHUNK` messages followed by CLOSE.
//!
//! Flow control. The engine enforces the 64 KiB stream windows. This service keeps at most
//! `FLIGHT` bytes per stream between itself and the engine (`on_writable` reopens it); when the
//! device is slow the terminal's own attachment queue overflows and the existing overflow ->
//! `ResyncRequired` -> fresh snapshot rule applies.
//!
//! Shortcuts: the view, the directory and file watches are checked on a `HOUSEKEEPING` tick
//! (250 ms) while a stream or the directory is open, because the owner publishes no change
//! notification for them and the watch keeps its own 1 s fingerprint timer; the tick costs a
//! few atomic reads. The per-workspace limits are per tunnel, not per Host. A terminal's `OPEN`
//! size is applied with the first `claim` (resize needs the lease), and `afterSeq` resumes only
//! at the model's current sequence (the model keeps no delta history), otherwise a snapshot.
use super::{
    Coordinator,
    owner_domain::Operation,
    remote_chat::{self, ChatSub, Grant, Scope},
    remote_files,
    remote_files_watch::RemoteWatch,
    remote_terminal::{fault, lease_result, terminal as terminal_error},
    rpc::{ConnectionState, dispatch},
    tunnel_authz::{Denied, DeviceAccess, Granted, Target, authorize, call_workspace},
    tunnel_consent::{DeviceConsent, Mode},
};
use lomi_host_http::uplink::{
    self,
    tunnels::{AttestedDevice, CircuitId, Command, Config, Handle, Streams, TunnelService},
};
use lomi_host_store::ProjectRecord;
use lomi_remote_crypto::Identity;
use lomi_remote_protocol::{
    rpc::*,
    streams::*,
    tunnel::{
        ChatOpen, DirectoryChange, DirectoryChat, DirectoryChatState, DirectoryHost,
        DirectoryLayout, DirectoryMessage, DirectorySnapshot, DirectoryTab, DirectoryTerminal,
        DirectoryUpdate, DirectoryWorkspace, FilesWatchOpen, MAX_LOGICAL_MESSAGE, OpenParams,
        RpcEnvelope, RpcTransferResponse, TRANSFER_CHUNK, TRANSFER_INLINE_MAX, TRANSFER_MAX,
        TerminalOpen, TransferOpen, TransferTag,
    },
    *,
};
use lomi_terminal::{Attachment, AuthenticatedConnection, ControlLease, TerminalEvent};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{
        Arc, Mutex, OnceLock, PoisonError, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// The Host-opened directory stream: the engine opens it first, so it is always stream 2.
const DIRECTORY: u32 = 2;
/// Bytes handed to the engine for one stream and not yet sent.
const FLIGHT: usize = 128 * 1024;
const JOBS: usize = 256;
const CHUNK: usize = 16384;
const VIEW_TTL: Duration = Duration::from_secs(1);
const DIRECTORY_EVERY: Duration = Duration::from_secs(2);
/// How often an open tunnel looks at what has no wake-up: the view, the directory, file watches.
const HOUSEKEEPING: Duration = Duration::from_millis(250);
/// Retry delay while the engine's inbox is full.
const RETRY: Duration = Duration::from_millis(10);
/// Messages a stream's pipe holds before its source is left alone.
const PIPE: usize = 8;
/// Messages the device may make a pipe hold with replies before the stream is reset.
const PIPE_MAX: usize = 256;
const MAX_TERMINALS: usize = 32;
/// Parallel reads and repository/files/terminal mutations per workspace and tunnel (spec 10).
const MAX_READS: usize = 4;
const MAX_TRANSFERS: usize = 4;
/// Calls running at once for one tunnel, over all workspaces.
const MAX_CALLS: usize = 16;
/// Concurrent calls of one device over all its tunnels, and of the whole Host.
const MAX_CALLS_PER_DEVICE: usize = 32;
const MAX_CALLS_PER_HOST: usize = 64;
/// Open streams are reset when the view could not be read for this long.
const RECHECK_BLIND: Duration = Duration::from_secs(5);

/// RESET codes (the HTTP status of the matching error).
pub(super) const RESET_INVALID: u16 = 400;
pub(super) const RESET_REVOKED: u16 = 401;
pub(super) const RESET_SCOPE: u16 = 403;
pub(super) const RESET_UNSHARED: u16 = 404;
pub(super) const RESET_GONE: u16 = 410;
pub(super) const RESET_BUSY: u16 = 429;
pub(super) const RESET_UNSUPPORTED: u16 = 501;
pub(super) const RESET_UNAVAILABLE: u16 = 503;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn reset_code(denied: Denied) -> u16 {
    match denied {
        Denied::Revoked => RESET_REVOKED,
        Denied::WorkspaceUnshared => RESET_UNSHARED,
        _ => RESET_SCOPE,
    }
}
fn denied(d: Denied) -> RemoteError {
    fault(d.code())
}

/// What one tunnel knows about its device and the Host, shared by its two workers.
struct Ctx {
    coordinator: Weak<Coordinator>,
    handle: Handle,
    circuit: CircuitId,
    device: AttestedDevice,
    principal: AuthenticatedConnection,
    consent: Option<DeviceConsent>,
    view: Mutex<Option<Arc<View>>>,
    /// Into the `streams` worker. Every sender is a job source; the worker also stops on `closed`.
    jobs: SyncSender<Job>,
    /// Jobs that must not be lost (`Closed`, `Writable`, `Stop`, `Directory`): a short queue of
    /// its own, bounded by the number of streams, plus a wake-up into `jobs`.
    life: Mutex<VecDeque<Job>>,
    closed: AtomicBool,
    busy: Mutex<HashMap<WorkspaceId, Busy>>,
    transfers: AtomicUsize,
}
/// What one workspace has running for this tunnel.
#[derive(Default)]
struct Busy {
    reads: usize,
    mutation: bool,
}
/// A slot of the per-workspace limits, given back on drop.
struct Permit {
    ctx: Arc<Ctx>,
    workspace: WorkspaceId,
    mutation: bool,
}
/// Calls running on this Host, in total and per device (the per-tunnel limits alone let many
/// tunnels of one device multiply them).
static CALLS: Mutex<(usize, BTreeMap<[u8; 32], usize>)> = Mutex::new((0, BTreeMap::new()));
fn claim_call(device: &[u8; 32]) -> bool {
    let mut calls = CALLS.lock().unwrap_or_else(PoisonError::into_inner);
    let mine = calls.1.get(device).copied().unwrap_or(0);
    if calls.0 >= MAX_CALLS_PER_HOST || mine >= MAX_CALLS_PER_DEVICE {
        return false;
    }
    calls.0 += 1;
    calls.1.insert(*device, mine + 1);
    true
}
fn release_call(device: &[u8; 32]) {
    let mut calls = CALLS.lock().unwrap_or_else(PoisonError::into_inner);
    calls.0 = calls.0.saturating_sub(1);
    if let Some(n) = calls.1.get_mut(device) {
        *n -= 1;
        if *n == 0 {
            calls.1.remove(device);
        }
    }
}
impl Permit {
    fn take(ctx: &Arc<Ctx>, workspace: WorkspaceId, mutation: bool) -> Option<Self> {
        if !claim_call(&ctx.device.fingerprint) {
            return None;
        }
        let permit = Self::take_local(ctx, workspace, mutation);
        if permit.is_none() {
            release_call(&ctx.device.fingerprint);
        }
        permit
    }
    fn take_local(ctx: &Arc<Ctx>, workspace: WorkspaceId, mutation: bool) -> Option<Self> {
        let mut busy = ctx.busy.lock().unwrap_or_else(PoisonError::into_inner);
        let running: usize = busy
            .values()
            .map(|b| b.reads + usize::from(b.mutation))
            .sum();
        if running >= MAX_CALLS {
            return None;
        }
        let slot = busy.entry(workspace).or_default();
        if mutation && !slot.mutation {
            slot.mutation = true;
        } else if !mutation && slot.reads < MAX_READS {
            slot.reads += 1;
        } else {
            return None;
        }
        Some(Self {
            ctx: ctx.clone(),
            workspace,
            mutation,
        })
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        release_call(&self.ctx.device.fingerprint);
        let mut busy = self.ctx.busy.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(slot) = busy.get_mut(&self.workspace) {
            if self.mutation {
                slot.mutation = false;
            } else {
                slot.reads -= 1;
            }
            if slot.reads == 0 && !slot.mutation {
                busy.remove(&self.workspace);
            }
        }
    }
}
struct View {
    at: Instant,
    hint: Option<u64>,
    access: DeviceAccess,
    projects: Vec<ProjectRecord>,
    host_name: Option<String>,
}
impl View {
    fn project(&self, workspace: &WorkspaceId) -> Option<&ProjectRecord> {
        self.projects
            .iter()
            .find(|p| p.state.context.workspace_id == *workspace && p.consent)
    }
}
impl Ctx {
    fn coordinator(&self) -> Result<Arc<Coordinator>, RemoteError> {
        self.coordinator
            .upgrade()
            .ok_or_else(|| fault(ErrorCode::ServiceUnavailable))
    }
    /// The device's grant and the shared workspaces. Cached for `VIEW_TTL` and while the Host's
    /// projection revision stays the same; `fresh` always reads.
    fn view(&self, fresh: bool) -> Result<Arc<View>, RemoteError> {
        let coordinator = self.coordinator()?;
        let hint = coordinator.owner.projection_hint();
        // The lock is for the cache only: the read below can wait on a busy Host, and a second
        // caller must not queue behind it (at worst both read).
        {
            let cached = self.view.lock().unwrap_or_else(PoisonError::into_inner);
            if !fresh
                && let Some(v) = &*cached
                && v.at.elapsed() < VIEW_TTL
                && v.hint == hint
            {
                return Ok(v.clone());
            }
        }
        let cancelled = AtomicBool::new(false);
        let mut read = None;
        for _ in 0..50 {
            let operation = Operation::new(Instant::now() + Duration::from_secs(2), &cancelled);
            match coordinator
                .owner
                .tunnel_view(&operation, &self.device.fingerprint)
            {
                Ok(v) => {
                    read = Some(v);
                    break;
                }
                // The actor holds the owner for a moment; this is a worker thread, so wait.
                Err(super::shared_owner::Error::Domain(super::owner_domain::Error::Busy)) => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(_) => break,
            }
        }
        let view = read.ok_or_else(|| fault(ErrorCode::ServiceUnavailable))?;
        let grant = view.grant.ok_or_else(|| fault(ErrorCode::AuthRequired))?;
        let v = Arc::new(View {
            at: Instant::now(),
            hint,
            access: DeviceAccess::from_projects(grant, &view.projects),
            projects: view.projects,
            host_name: view.host_name,
        });
        *self.view.lock().unwrap_or_else(PoisonError::into_inner) = Some(v.clone());
        Ok(v)
    }
    /// `authorize`. When only the owner's code is missing, first re-read (it may just have been
    /// confirmed; `view` is then replaced), and if it still is, ask for it. The client gets
    /// SCOPE_DENIED either way; the device is told separately (`Control` frame) that the owner is
    /// asked, and shows its own copy of the code. The owner types that code on the Host.
    fn check(&self, view: &mut Arc<View>, target: &Target<'_>) -> Result<Granted, Denied> {
        let mut r = authorize(&view.access, target, now_ms());
        if r == Err(Denied::ControlNotConfirmed) {
            if let Ok(fresh) = self.view(true) {
                *view = fresh;
                r = authorize(&view.access, target, now_ms());
            }
            if r == Err(Denied::ControlNotConfirmed)
                && let Some(consent) = &self.consent
            {
                if let Ok(code) = consent.request_control(self.circuit)
                    && let Ok(code) = code.parse()
                {
                    let _ = self.handle.push(Command::ControlPending {
                        circuit: self.circuit,
                        code,
                    });
                }
            }
        }
        r
    }
    fn chat_grant(&self, view: &View, workspace: &WorkspaceId) -> Result<Grant, RemoteError> {
        Ok(Grant {
            capabilities: view
                .access
                .capabilities(workspace)
                .ok_or_else(|| fault(ErrorCode::WorkspaceUnshared))?,
            account: hex(&self.device.account_id),
            consumer: hex(&self.device.device_id),
            fingerprint: hex(&self.device.fingerprint),
            grant_id: hex(&self.device.fingerprint),
        })
    }
    /// Queues a job that cannot be dropped and wakes the `streams` worker (a full `jobs` channel
    /// means the worker is busy and will look at this queue anyway).
    fn lifecycle(&self, job: Job) {
        {
            let mut life = self.life.lock().unwrap_or_else(PoisonError::into_inner);
            // One `Writable` per stream is as good as many.
            let dup = matches!(&job, Job::Writable(s) if life.iter().any(|j| matches!(j, Job::Writable(t) if t == s)));
            if !dup {
                life.push_back(job);
            }
        }
        let _ = self.jobs.try_send(Job::Wake);
    }
    /// An answer for stream 0, paced by the `streams` worker like every other stream.
    fn reply(&self, data: Vec<u8>) {
        let _ = self.jobs.send(Job::Reply(data));
    }
    /// Opens a Host-owned `transfer` stream for `request` and returns its id.
    fn open_transfer(&self, request: &RequestId) -> Result<u32, RemoteError> {
        let (reply, answer) = sync_channel(1);
        let params = OpenParams::Transfer(TransferOpen {
            request_id: request.clone(),
        });
        self.handle
            .push(Command::OpenStream {
                circuit: self.circuit,
                params,
                reply,
            })
            .map_err(|_| fault(ErrorCode::HostBusy))?;
        match answer.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(id)) => Ok(id),
            _ => Err(fault(ErrorCode::HostBusy)),
        }
    }
}

fn response(
    id: &RequestId,
    operation: Option<OperationId>,
    r: Result<RpcResult, RemoteError>,
) -> RpcResponse {
    match r {
        Ok(result) => RpcResponse::Result {
            v: ApplicationMajor,
            request_id: id.clone(),
            result,
        },
        Err(error) => RpcResponse::Error {
            v: ApplicationMajor,
            request_id: id.clone(),
            operation_id: operation,
            error,
        },
    }
}
fn encode(response: &RpcResponse) -> Option<Vec<u8>> {
    serde_json::to_vec(response).ok()
}

fn is_chat(call: &RpcCall) -> bool {
    use RpcCall::*;
    matches!(
        call,
        ChatProviders(_)
            | ChatThreadsList(_)
            | ChatThreadGet(_)
            | ChatThreadCreate(_)
            | ChatThreadUpdate(_)
            | ChatThreadDelete(_)
            | ChatSend(_)
            | ChatStop(_)
    )
}
fn files_context(call: &RpcCall) -> Option<&WorkspaceContext> {
    Some(match call {
        RpcCall::FilesList(p) => &p.context,
        RpcCall::FilesStat(p) => &p.context,
        RpcCall::FilesRead(p) => &p.context,
        RpcCall::FilesSearchNames(p) => &p.context,
        _ => return None,
    })
}
/// Catalog methods that run through local IPC's executor (`rpc::dispatch`).
fn is_dispatched(call: &RpcCall) -> bool {
    use RpcCall::*;
    matches!(
        call,
        WorkspaceGet(_)
            | WorkspaceCapabilities(_)
            | OperationStatus(_)
            | OperationCancel(_)
            | GitRepositories(_)
            | GitStatus(_)
            | GitDiff(_)
            | GitLog(_)
            | GitShow(_)
    ) || is_mutation(call)
}
/// Calls that change something: at most one at a time per workspace and tunnel.
fn is_mutation(call: &RpcCall) -> bool {
    use RpcCall::*;
    matches!(
        call,
        GitStage(_)
            | GitUnstage(_)
            | GitCommit(_)
            | GitFetch(_)
            | GitPush(_)
            | GitPull(_)
            | FilesCreate(_)
            | FilesMkdir(_)
            | FilesRename(_)
            | FilesRemove(_)
            | TerminalCreate(_)
            | TerminalSplit(_)
            | TerminalRename(_)
            | TerminalMove(_)
            | TerminalClose(_)
            | TerminalRestart(_)
            | OperationCancel(_)
    )
}

// ---- stream 0 -------------------------------------------------------------------------------

/// Reads requests, takes a permit and hands each call to its own thread.
fn rpc_loop(ctx: Arc<Ctx>, jobs: Receiver<Vec<u8>>) {
    while let Ok(bytes) = jobs.recv() {
        // A request that does not parse has no id to answer; the device times it out.
        let Ok(envelope) = RpcEnvelope::decode(&bytes) else {
            continue;
        };
        let (id, operation) = (
            envelope.request_id.clone(),
            envelope.call.chat_operation_id(),
        );
        let busy = |ctx: &Ctx| {
            let r = response(&id, operation, Err(fault(ErrorCode::HostBusy)));
            if let Some(out) = encode(&r) {
                ctx.reply(out);
            }
        };
        let workspace = envelope
            .workspace_id
            .or_else(|| call_workspace(&envelope.call).copied());
        let Some(workspace) = workspace else {
            // Nothing to run: the answer is the error, and it needs no thread.
            serve(&ctx, &envelope);
            continue;
        };
        let Some(permit) = Permit::take(&ctx, workspace, is_mutation(&envelope.call)) else {
            busy(&ctx);
            continue;
        };
        let call_ctx = ctx.clone();
        let spawned = std::thread::Builder::new()
            .name("lomi-tunnel-call".into())
            .spawn(move || {
                let _permit = permit;
                serve(&call_ctx, &envelope);
            });
        if spawned.is_err() {
            busy(&ctx);
        }
    }
}

/// Runs one request and puts its answer (and a transfer, if any) on the wire.
fn serve(ctx: &Arc<Ctx>, envelope: &RpcEnvelope) {
    let answer = rpc(ctx, envelope);
    let workspace = envelope
        .workspace_id
        .or_else(|| call_workspace(&envelope.call).copied());
    let out = deliver(ctx, &envelope.request_id, workspace, answer)
        // The engine takes one message of 1 MiB at most and drops a larger one silently: answer
        // with an error instead of leaving the request hanging.
        .filter(|out| out.len() <= MAX_LOGICAL_MESSAGE)
        .or_else(|| {
            let id = &envelope.request_id;
            encode(&response(
                id,
                envelope.call.chat_operation_id(),
                Err(fault(ErrorCode::ResourceExhausted)),
            ))
        });
    if let Some(out) = out {
        ctx.reply(out);
    }
}

/// The bulk part of a result: what goes over a `transfer` stream instead of inline.
fn take_bulk(result: &mut RpcResult) -> Option<Vec<u8>> {
    let files = |files: &mut BoundedList<GitDiffFile, 200>| {
        serde_json::to_vec(&std::mem::take(&mut files.0)).ok()
    };
    match result {
        RpcResult::FilesRead(r) => Some(std::mem::take(&mut r.bytes.0)),
        RpcResult::GitDiff(r) => files(&mut r.files),
        RpcResult::GitShow(r) => files(&mut r.diff.files),
        _ => None,
    }
}

/// Stream 0 bytes for `answer`: the response itself, or, when a `files.read`, `git.diff` or
/// `git.show` result is larger than `TRANSFER_INLINE_MAX`, the metadata with a transfer stream
/// that the payload follows on.
fn deliver(
    ctx: &Arc<Ctx>,
    id: &RequestId,
    workspace: Option<WorkspaceId>,
    answer: RpcResponse,
) -> Option<Vec<u8>> {
    let RpcResponse::Result { result, .. } = &answer else {
        return encode(&answer);
    };
    // JSON writes a byte as at most four characters; do not serialize what cannot fit.
    let maybe_small = match result {
        RpcResult::FilesRead(r) => r.bytes.0.len() <= TRANSFER_INLINE_MAX / 4,
        RpcResult::GitDiff(_) | RpcResult::GitShow(_) => true,
        _ => return encode(&answer),
    };
    if maybe_small
        && let Some(bytes) = encode(&answer)
        && bytes.len() <= TRANSFER_INLINE_MAX
    {
        return Some(bytes);
    }
    let RpcResponse::Result { mut result, .. } = answer else {
        return None;
    };
    let failed = |code| {
        let r = response(id, None, Err(fault(code)));
        encode(&r)
    };
    let Some(payload) = take_bulk(&mut result) else {
        return failed(ErrorCode::ServiceUnavailable);
    };
    if payload.len() > TRANSFER_MAX {
        return failed(ErrorCode::ResourceExhausted);
    }
    if ctx.transfers.fetch_add(1, Ordering::AcqRel) >= MAX_TRANSFERS {
        ctx.transfers.fetch_sub(1, Ordering::AcqRel);
        return failed(ErrorCode::HostBusy);
    }
    let stream = match ctx.open_transfer(id) {
        Ok(stream) => stream,
        Err(_) => {
            ctx.transfers.fetch_sub(1, Ordering::AcqRel);
            return failed(ErrorCode::HostBusy);
        }
    };
    let head = RpcTransferResponse {
        r#type: TransferTag::Transfer,
        v: ApplicationMajor,
        request_id: id.clone(),
        transfer_stream: stream,
        transfer_bytes: DecimalU64(payload.len() as u64),
        result,
    };
    let job = Job::Transfer(stream, id.clone(), workspace, payload);
    if ctx.jobs.send(job).is_err() {
        ctx.transfers.fetch_sub(1, Ordering::AcqRel);
        return None;
    }
    serde_json::to_vec(&head).ok()
}

enum Outcome {
    Result(Result<RpcResult, RemoteError>),
    /// Already a response (with its own operation id), from the shared executor.
    Response(RpcResponse),
}

fn rpc(ctx: &Ctx, envelope: &RpcEnvelope) -> RpcResponse {
    let id = &envelope.request_id;
    match rpc_call(ctx, envelope) {
        Outcome::Response(r) => r,
        Outcome::Result(r) => response(id, envelope.call.chat_operation_id(), r),
    }
}

fn rpc_call(ctx: &Ctx, envelope: &RpcEnvelope) -> Outcome {
    let result = (|| {
        let call = &envelope.call;
        let workspace = envelope
            .workspace_id
            .or_else(|| call_workspace(call).copied())
            .ok_or_else(|| fault(ErrorCode::InvalidArgument))?;
        let mut view = ctx.view(false)?;
        let mut target = Target::rpc(&workspace, call).map_err(denied)?;
        let coordinator = ctx.coordinator()?;
        if let RpcCall::ChatSend(p) = call {
            // The thread's own mode decides the consent needed to send.
            let thread = coordinator
                .chat
                .local_threads(workspace)?
                .into_iter()
                .find(|t| t.thread_id == String::from(p.thread_id));
            if let Some(thread) = thread {
                target = target.with_chat_mode(remote_chat::to_thread(&thread)?.permissions);
            }
        }
        // No catalog method runs hooks here (the embedded Git engine has none), so none asks
        // for `with_repository_execution`; a method that does must add it to its target.
        ctx.check(&mut view, &target).map_err(denied)?;
        let project = view
            .project(&workspace)
            .ok_or_else(|| fault(ErrorCode::WorkspaceUnshared))?;
        let state = &project.state.context;
        if let Some(files) = files_context(call) {
            if files.workspace_epoch != state.workspace_epoch {
                return Err(fault(ErrorCode::StaleEpoch));
            }
            // The file engine cannot be interrupted: a call for a tunnel that is gone does not
            // start, and one that outlived its own deadline is answered as such.
            if ctx.closed.load(Ordering::Acquire) {
                return Err(fault(ErrorCode::ServiceUnavailable));
            }
            let started = Instant::now();
            let root =
                coordinator
                    .files
                    .get(workspace, state.workspace_epoch, &project.local_root)?;
            let read = remote_files::execute_read(&root, call);
            if started.elapsed() > Duration::from_millis(envelope.timeout_ms.get()) {
                return Err(fault(ErrorCode::DeadlineExceeded));
            }
            return read.map(Ok);
        }
        if is_chat(call) {
            let scope = Scope {
                workspace,
                root: project.local_root.clone(),
                level: project.chat_level,
                fence: project.fence,
            };
            let grant = ctx.chat_grant(&view, &workspace)?;
            let deadline = Instant::now() + Duration::from_millis(envelope.timeout_ms.get());
            return coordinator
                .chat
                .execute(call, &grant, &scope, deadline, &mut None)
                .map(Ok);
        }
        if is_dispatched(call) {
            let deadline = Instant::now() + Duration::from_millis(envelope.timeout_ms.get());
            // A closed tunnel cancels what its calls still run.
            let operation = Operation::new(deadline, &ctx.closed);
            // Stored operations are looked up with what this device may do here, not with the
            // owner's local rights.
            let rights = view
                .access
                .capabilities(&workspace)
                .ok_or_else(|| fault(ErrorCode::WorkspaceUnshared))?;
            let mut connection =
                ConnectionState::for_device(coordinator.clone(), ctx.principal.actor(), rights);
            let request = RpcRequest {
                v: ApplicationMajor,
                r#type: RequestKind::Request,
                request_id: envelope.request_id.clone(),
                timeout_ms: envelope.timeout_ms,
                call: call.clone(),
            };
            return Ok(Err(dispatch(
                &coordinator,
                &mut connection,
                request,
                &operation,
            )));
        }
        Err(fault(ErrorCode::UnsupportedCapability))
    })();
    match result {
        Ok(Ok(result)) => Outcome::Result(Ok(result)),
        Ok(Err(response)) => Outcome::Response(response),
        Err(error) => Outcome::Result(Err(error)),
    }
}

// ---- the other streams ----------------------------------------------------------------------

enum Job {
    Open(u32, OpenParams),
    Message(u32, Vec<u8>),
    Closed(u32),
    Writable(u32),
    /// The engine opened the directory stream: build and send the snapshot.
    Directory(u32),
    /// An answer for stream 0.
    Reply(Vec<u8>),
    /// The payload of a Host-opened transfer stream.
    Transfer(u32, RequestId, Option<WorkspaceId>, Vec<u8>),
    /// Something queued an event for a stream; nothing else to learn.
    Wake,
    /// The tunnel is gone.
    Stop,
}

/// Wakes the `streams` worker from another thread; one pending job at most.
struct Wake {
    pending: AtomicBool,
    jobs: SyncSender<Job>,
}
impl Wake {
    fn wake(&self) {
        if !self.pending.swap(true, Ordering::AcqRel) {
            let _ = self.jobs.try_send(Job::Wake);
        }
    }
}
type Waker = Arc<dyn Fn() + Send + Sync>;

/// What one stream has queued for the engine and how much of it the engine still holds.
#[derive(Default)]
struct Pipe {
    queue: VecDeque<Vec<u8>>,
    flight: usize,
    /// CLOSE once the queue is empty.
    closing: bool,
}
impl Pipe {
    fn room(&self) -> bool {
        self.queue.len() < PIPE && self.flight < FLIGHT
    }
}

struct Emission {
    bytes: Vec<u8>,
    position: usize,
    /// `None` for a snapshot.
    previous: Option<u64>,
    through: u64,
    offset: u64,
    header: bool,
    snapshot: Option<TerminalSnapshotMetadata>,
    working_directory: Option<WorkingDirectory>,
}
impl Emission {
    fn next(
        &mut self,
        terminal: &TerminalContext,
        id: &SubscriptionId,
    ) -> (TerminalStreamFrame, bool) {
        let (terminal, subscription_id) = (terminal.clone(), id.clone());
        if let Some(meta) = self.snapshot.take() {
            return (TerminalStreamFrame::SnapshotMetadata(meta), false);
        }
        if let (true, Some(previous)) = (std::mem::take(&mut self.header), self.previous) {
            return (
                TerminalStreamFrame::DeltaMetadata(TerminalDeltaMetadata {
                    terminal,
                    subscription_id,
                    previous_seq: TerminalSeq(DecimalU64(previous)),
                    through_seq: TerminalSeq(DecimalU64(self.through)),
                    chunk_count: ChunkCount(self.bytes.len().div_ceil(CHUNK) as u32),
                    total_bytes: DecimalU64(self.bytes.len() as u64),
                    working_directory: self.working_directory.clone().into(),
                }),
                false,
            );
        }
        if self.position < self.bytes.len() {
            let index = ChunkIndex((self.position / CHUNK) as u32);
            let end = (self.position + CHUNK).min(self.bytes.len());
            let bytes = BoundedList(self.bytes[self.position..end].to_vec());
            self.position = end;
            let frame = if self.previous.is_some() {
                TerminalStreamFrame::DeltaChunk(TerminalDeltaChunk {
                    terminal,
                    subscription_id,
                    index,
                    bytes,
                })
            } else {
                TerminalStreamFrame::SnapshotChunk(TerminalSnapshotChunk {
                    terminal,
                    subscription_id,
                    index,
                    bytes,
                })
            };
            return (frame, false);
        }
        let through_seq = TerminalSeq(DecimalU64(self.through));
        let frame = if self.previous.is_some() {
            TerminalStreamFrame::DeltaComplete(TerminalDeltaComplete {
                terminal,
                subscription_id,
                through_seq,
            })
        } else {
            TerminalStreamFrame::SnapshotComplete(TerminalSnapshotComplete {
                terminal,
                subscription_id,
                through_seq,
                output_offset: DecimalU64(self.offset),
            })
        };
        (frame, true)
    }
}

struct Term {
    open: OpenParams,
    terminal: TerminalContext,
    attachment: Attachment,
    wake: Waker,
    /// The size the device opened with, applied once with its first claim.
    size: Option<(u32, u32)>,
    id: SubscriptionId,
    emission: Option<Emission>,
    /// `None` until the snapshot has been handed over; control messages wait until then.
    sent_through: Option<u64>,
    lease: Option<ControlLease>,
    held: VecDeque<Vec<u8>>,
}
struct Chat {
    open: OpenParams,
    sub: ChatSub,
}
struct Watch {
    open: OpenParams,
    watch: RemoteWatch,
}

/// A payload on its way over a transfer stream.
struct Transfer {
    open: OpenParams,
    /// The workspace the payload came from; unsharing it ends the transfer.
    workspace: Option<WorkspaceId>,
    data: Vec<u8>,
    position: usize,
}

#[allow(clippy::large_enum_variant)] // shortcut: one Sub per stream, boxing buys nothing
enum Sub {
    Terminal(Box<Term>),
    Chat(Chat),
    Watch(Watch),
    Transfer(Transfer),
}
impl Sub {
    fn open(&self) -> &OpenParams {
        match self {
            Self::Terminal(t) => &t.open,
            Self::Chat(c) => &c.open,
            Self::Watch(w) => &w.open,
            Self::Transfer(t) => &t.open,
        }
    }
}

struct Dir {
    last: Vec<DirectoryWorkspace>,
    seq: u64,
    hint: Option<u64>,
    built: Instant,
}
struct Hub {
    ctx: Arc<Ctx>,
    subs: BTreeMap<u32, Sub>,
    pipes: HashMap<u32, Pipe>,
    /// Resets the engine's inbox has not taken yet.
    resets: VecDeque<(u32, u16)>,
    /// The engine's inbox was full: try again soon.
    blocked: bool,
    wake: Arc<Wake>,
    watches: u64,
    dir: Option<Dir>,
    checked: Option<Arc<View>>,
    /// Since when the view cannot be read while streams are open.
    blind: Option<Instant>,
    /// Streams closed with nothing of ours on them (a transfer may still be on its way).
    gone: VecDeque<u32>,
}

fn stream_loop(ctx: Arc<Ctx>, jobs: Receiver<Job>) {
    let wake = Arc::new(Wake {
        pending: AtomicBool::new(false),
        jobs: ctx.jobs.clone(),
    });
    let mut hub = Hub {
        ctx,
        subs: BTreeMap::new(),
        pipes: HashMap::new(),
        resets: VecDeque::new(),
        blocked: false,
        wake,
        watches: 0,
        dir: None,
        checked: None,
        blind: None,
        gone: VecDeque::new(),
    };
    loop {
        // Nothing to do until a job or a wake-up arrives, unless something needs a look.
        let first = match hub.timeout() {
            Some(wait) => jobs.recv_timeout(wait),
            None => jobs.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        // Taken before the channel is drained: whatever was queued here came after the `Open` it
        // belongs to, and that one is already in the channel.
        let life: Vec<Job> = hub
            .ctx
            .life
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain(..)
            .collect();
        match first {
            Ok(job) => hub.job(job),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        // From here an event queues a new wake-up job.
        hub.wake.pending.store(false, Ordering::Release);
        while let Ok(job) = jobs.try_recv() {
            hub.job(job);
        }
        for job in life {
            hub.job(job);
        }
        if hub.ctx.closed.load(Ordering::Acquire) {
            break;
        }
        hub.recheck();
        hub.directory();
        loop {
            let produced = hub.pump();
            hub.flush();
            if !produced {
                break;
            }
        }
    }
    // Host PTYs survive; only this device's attachments and leases go.
    if let Ok(coordinator) = hub.ctx.coordinator() {
        coordinator.terminals.disconnect(&hub.ctx.principal);
    }
}

impl Hub {
    /// How long the worker may sleep: forever, unless a stream, the directory or a queue needs
    /// a look (`HOUSEKEEPING` covers what has no wake-up).
    fn timeout(&self) -> Option<Duration> {
        if self.blocked {
            return Some(RETRY);
        }
        let queued = !self.resets.is_empty() || self.pipes.values().any(|p| !p.queue.is_empty());
        (!self.subs.is_empty() || self.dir.is_some() || queued).then_some(HOUSEKEEPING)
    }

    fn job(&mut self, job: Job) {
        match job {
            Job::Open(stream, params) => {
                if let Err(code) = self.open(stream, params) {
                    self.reset(stream, code);
                }
            }
            Job::Message(stream, data) => {
                if let Err(code) = self.message(stream, &data) {
                    self.fail(stream, code);
                }
            }
            Job::Closed(stream) => {
                if !self.subs.contains_key(&stream) {
                    if self.gone.len() == 256 {
                        self.gone.pop_front();
                    }
                    self.gone.push_back(stream);
                }
                self.finished(stream);
                self.subs.remove(&stream);
                self.pipes.remove(&stream);
            }
            Job::Writable(stream) => {
                if let Some(pipe) = self.pipes.get_mut(&stream) {
                    pipe.flight = 0;
                }
            }
            Job::Directory(stream) => self.snapshot(stream),
            Job::Reply(data) => self.push(0, data),
            Job::Transfer(stream, request_id, workspace, data) => {
                // The device closed the stream before the payload got here: nothing to send, and
                // the slot it took is free.
                if let Some(i) = self.gone.iter().position(|g| *g == stream) {
                    self.gone.remove(i);
                    self.ctx.transfers.fetch_sub(1, Ordering::AcqRel);
                    return;
                }
                let open = OpenParams::Transfer(TransferOpen { request_id });
                self.subs.insert(
                    stream,
                    Sub::Transfer(Transfer {
                        open,
                        workspace,
                        data,
                        position: 0,
                    }),
                );
            }
            Job::Wake => {}
            Job::Stop => self.ctx.closed.store(true, Ordering::Release),
        }
    }

    /// A stream with a transfer ended, one way or another.
    fn finished(&mut self, stream: u32) {
        if matches!(self.subs.get(&stream), Some(Sub::Transfer(_))) {
            self.ctx.transfers.fetch_sub(1, Ordering::AcqRel);
        }
    }

    fn push(&mut self, stream: u32, data: Vec<u8>) {
        self.pipes.entry(stream).or_default().queue.push_back(data);
    }
    /// Ends `stream` after what is queued for it.
    fn close(&mut self, stream: u32) {
        self.finished(stream);
        self.subs.remove(&stream);
        self.pipes.entry(stream).or_default().closing = true;
    }
    /// Resets at once; what was queued for the stream is dropped.
    fn reset(&mut self, stream: u32, code: u16) {
        self.finished(stream);
        self.subs.remove(&stream);
        self.pipes.remove(&stream);
        self.resets.push_back((stream, code));
    }
    fn fail(&mut self, stream: u32, code: u16) {
        self.reset(stream, code);
    }

    /// Hands queued output to the engine, stream by stream: one that has used its flight budget
    /// waits for credit, the others go on.
    fn flush(&mut self) {
        let handle = self.ctx.handle.clone();
        let circuit = self.ctx.circuit;
        self.blocked = false;
        while let Some(&(stream, code)) = self.resets.front() {
            let command = Command::ResetStream {
                circuit,
                stream,
                code,
            };
            if handle.push(command).is_err() {
                self.blocked = true;
                break;
            }
            self.resets.pop_front();
        }
        let streams: Vec<u32> = self.pipes.keys().copied().collect();
        for stream in streams {
            let Some(pipe) = self.pipes.get_mut(&stream) else {
                continue;
            };
            while let Some(front) = pipe.queue.front() {
                // A message bigger than the budget goes alone, when nothing of the stream is
                // left in the engine (its queue holds one logical message at most).
                let len = front.len();
                if pipe.flight != 0 && pipe.flight + len > FLIGHT {
                    break;
                }
                let data = pipe.queue.pop_front().unwrap_or_default();
                match handle.send(circuit, stream, data) {
                    Ok(()) => pipe.flight += len,
                    Err(Command::Send { data, .. }) => {
                        pipe.queue.push_front(data);
                        self.blocked = true;
                        break;
                    }
                    Err(_) => break,
                }
            }
            if pipe.closing && pipe.queue.is_empty() {
                if handle
                    .push(Command::CloseStream { circuit, stream })
                    .is_ok()
                {
                    self.pipes.remove(&stream);
                } else {
                    self.blocked = true;
                }
            }
        }
    }

    // -- open ----------------------------------------------------------------------------

    fn open(&mut self, stream: u32, params: OpenParams) -> Result<(), u16> {
        let view = self.ctx.view(false).map_err(|_| RESET_REVOKED)?;
        authorize(&view.access, &Target::open(&params), now_ms()).map_err(reset_code)?;
        let sub = match &params {
            OpenParams::Terminal(p) => self.open_terminal(&view, p, &params)?,
            OpenParams::Chat(p) => self.open_chat(&view, p, &params)?,
            OpenParams::FilesWatch(p) => self.open_watch(&view, p, &params)?,
            _ => return Err(RESET_UNSUPPORTED),
        };
        self.subs.insert(stream, sub);
        Ok(())
    }

    fn open_terminal(
        &mut self,
        view: &View,
        p: &TerminalOpen,
        open: &OpenParams,
    ) -> Result<Sub, u16> {
        if self
            .subs
            .values()
            .filter(|s| matches!(s, Sub::Terminal(_)))
            .count()
            >= MAX_TERMINALS
        {
            return Err(RESET_BUSY);
        }
        let project = view.project(&p.workspace_id).ok_or(RESET_UNSHARED)?;
        let terminal =
            find_session(&project.state, &p.pane_id, &p.session_epoch).ok_or(RESET_GONE)?;
        let coordinator = self.ctx.coordinator().map_err(|_| RESET_UNAVAILABLE)?;
        let wake = self.waker();
        let attachment = attach(&coordinator, &self.ctx.principal, &terminal, &wake)?;
        let mut term = Term {
            open: open.clone(),
            terminal,
            attachment,
            wake,
            size: Some((p.cols.0, p.rows.0)),
            id: SubscriptionId::try_from(format!("terminal-{}", uuid::Uuid::new_v4().simple()))
                .map_err(|_| RESET_UNAVAILABLE)?,
            emission: None,
            sent_through: None,
            lease: None,
            held: VecDeque::new(),
        };
        // The device is already current when it names the model's sequence: no snapshot, the
        // deltas follow. The model keeps no history, so any other `afterSeq` gets a snapshot.
        let current = term.attachment.snapshot.sequence.0;
        if p.after_seq == Some(current)
            && term
                .attachment
                .acknowledge_checked(&self.ctx.principal, current, || true)
                .is_ok()
        {
            term.sent_through = Some(current);
        } else {
            term.begin()?;
        }
        Ok(Sub::Terminal(Box::new(term)))
    }

    fn waker(&self) -> Waker {
        let wake = self.wake.clone();
        Arc::new(move || wake.wake())
    }

    fn open_chat(&mut self, view: &View, p: &ChatOpen, open: &OpenParams) -> Result<Sub, u16> {
        let project = view.project(&p.workspace_id).ok_or(RESET_UNSHARED)?;
        let coordinator = self.ctx.coordinator().map_err(|_| RESET_UNAVAILABLE)?;
        let call = RpcCall::ChatSubscribe(ChatSubscribeParams {
            thread_id: Some(p.thread_id),
            after: p.after.as_ref().map(|a| ChatStreamCursor {
                message_id: a.message_id,
                stream_seq: DecimalU64(a.stream_seq),
            }),
        });
        let scope = Scope {
            workspace: p.workspace_id,
            root: project.local_root.clone(),
            level: project.chat_level,
            fence: project.fence,
        };
        let grant = self
            .ctx
            .chat_grant(view, &p.workspace_id)
            .map_err(|_| RESET_SCOPE)?;
        let mut sub = None;
        coordinator
            .chat
            .execute(
                &call,
                &grant,
                &scope,
                Instant::now() + Duration::from_secs(10),
                &mut sub,
            )
            .map_err(|e| reset_for(e.code()))?;
        let sub: ChatSub = sub.ok_or(RESET_UNAVAILABLE)?;
        sub.set_waker(self.waker());
        Ok(Sub::Chat(Chat {
            open: open.clone(),
            sub,
        }))
    }

    fn open_watch(
        &mut self,
        view: &View,
        p: &FilesWatchOpen,
        open: &OpenParams,
    ) -> Result<Sub, u16> {
        let project = view.project(&p.workspace_id).ok_or(RESET_UNSHARED)?;
        let state = &project.state.context;
        let coordinator = self.ctx.coordinator().map_err(|_| RESET_UNAVAILABLE)?;
        let files = coordinator
            .files
            .get(p.workspace_id, state.workspace_epoch, &project.local_root)
            .map_err(|e| reset_for(e.code()))?;
        let params = FilesWatchParams {
            context: state.clone(),
            entry_id: EntryId::try_from(p.path.as_str().to_owned()).map_err(|_| RESET_INVALID)?,
            cursor: None,
        };
        self.watches += 1;
        let (watch, _) = RemoteWatch::open(files, &params, self.watches, Instant::now())
            .map_err(|e| reset_for(e.code()))?;
        Ok(Sub::Watch(Watch {
            open: open.clone(),
            watch,
        }))
    }

    // -- messages from the device ---------------------------------------------------------

    fn message(&mut self, stream: u32, data: &[u8]) -> Result<(), u16> {
        // A device that sends and never reads would grow the replies without bound.
        if self
            .pipes
            .get(&stream)
            .is_some_and(|p| p.queue.len() >= PIPE_MAX)
        {
            return Err(RESET_BUSY);
        }
        match self.subs.get_mut(&stream) {
            // Closed or refused earlier: nothing to do.
            None => Ok(()),
            Some(Sub::Chat(_) | Sub::Transfer(_)) => Err(RESET_INVALID),
            Some(Sub::Watch(w)) => match decode_watch_frame(data) {
                Ok(FileWatchFrame::Ack(ack)) if w.watch.ack(&ack) => Ok(()),
                _ => Err(RESET_INVALID),
            },
            Some(Sub::Terminal(t)) if t.sent_through.is_none() => {
                // `OPEN` and `claim` may arrive in one write: the claim waits for the snapshot.
                if t.held.len() >= 16 {
                    return Err(RESET_BUSY);
                }
                t.held.push_back(data.to_vec());
                Ok(())
            }
            Some(Sub::Terminal(_)) => {
                let reply = self.terminal_message(stream, data)?;
                self.push(stream, reply);
                Ok(())
            }
        }
    }

    /// One control message (ack, claim, renew, release, input, resize) and its reply.
    fn terminal_message(&mut self, stream: u32, data: &[u8]) -> Result<Vec<u8>, u16> {
        let envelope = RpcEnvelope::decode(data).map_err(|_| RESET_INVALID)?;
        let call = envelope.call;
        let context = match &call {
            RpcCall::TerminalAck(p) => &p.terminal,
            RpcCall::TerminalClaim(p) => &p.terminal,
            RpcCall::TerminalRenew(p) | RpcCall::TerminalRelease(p) => &p.terminal,
            RpcCall::TerminalInput(p) => &p.terminal,
            RpcCall::TerminalResize(p) => &p.terminal,
            _ => return Err(RESET_INVALID),
        }
        .clone();
        let Some(Sub::Terminal(term)) = self.subs.get_mut(&stream) else {
            return Err(RESET_GONE);
        };
        if context != term.terminal {
            return Err(RESET_INVALID);
        }
        let ctx = self.ctx.clone();
        let result = (|| {
            let mut view = ctx.view(false)?;
            let ws = term.terminal.workspace.workspace_id;
            ctx.check(&mut view, &Target::message(&ws, call.method()))
                .map_err(denied)?;
            term.control(&ctx, &call)
        })();
        encode(&response(
            &envelope.request_id,
            call.chat_operation_id(),
            result,
        ))
        .ok_or(RESET_UNAVAILABLE)
    }

    // -- output ---------------------------------------------------------------------------

    /// Produces output for every stream that has room; `true` when any was produced.
    fn pump(&mut self) -> bool {
        let mut produced = false;
        let streams: Vec<u32> = self.subs.keys().copied().collect();
        for stream in streams {
            if let Err(code) = self.release_held(stream) {
                self.fail(stream, code);
                continue;
            }
            for _ in 0..16 {
                if !self.pipes.get(&stream).is_none_or(Pipe::room) {
                    break;
                }
                match self.step(stream) {
                    Ok(true) => produced = true,
                    Ok(false) => break,
                    Err(code) => {
                        self.fail(stream, code);
                        break;
                    }
                }
            }
        }
        produced
    }

    fn release_held(&mut self, stream: u32) -> Result<(), u16> {
        loop {
            let data = match self.subs.get_mut(&stream) {
                Some(Sub::Terminal(t)) if t.sent_through.is_some() => t.held.pop_front(),
                _ => None,
            };
            let Some(data) = data else {
                return Ok(());
            };
            let reply = self.terminal_message(stream, &data)?;
            self.push(stream, reply);
        }
    }

    /// Produces at most one message for `stream`; `Ok(false)` when it has nothing now.
    fn step(&mut self, stream: u32) -> Result<bool, u16> {
        let ctx = self.ctx.clone();
        let Some(sub) = self.subs.get_mut(&stream) else {
            return Ok(false);
        };
        let json = |frame: Result<Vec<u8>, serde_json::Error>| frame.map_err(|_| RESET_UNAVAILABLE);
        let (bytes, finished) = match sub {
            Sub::Chat(c) => {
                let Some(frame) = c.sub.poll() else {
                    if c.sub.is_dead() {
                        self.close(stream);
                    }
                    return Ok(false);
                };
                (json(serde_json::to_vec(&frame))?, false)
            }
            Sub::Watch(w) => match w.watch.poll(Instant::now()) {
                Some(frame) => {
                    let end = matches!(frame, FileWatchFrame::ResyncRequired(_));
                    (json(serde_json::to_vec(&frame))?, end)
                }
                None => return Ok(false),
            },
            Sub::Terminal(t) => match t.next(&ctx)? {
                Some((frame, end)) => (json(serde_json::to_vec(&frame))?, end),
                None => return Ok(false),
            },
            Sub::Transfer(t) => {
                let end = (t.position + TRANSFER_CHUNK).min(t.data.len());
                let chunk = t.data[t.position..end].to_vec();
                t.position = end;
                (chunk, end == t.data.len())
            }
        };
        // An empty payload is no message: it is just the end.
        if !bytes.is_empty() {
            self.push(stream, bytes);
        }
        if finished {
            self.close(stream);
        }
        Ok(true)
    }

    // -- authorization over time ---------------------------------------------------------

    /// When the view moved, every open stream is authorized again; a workspace that is no
    /// longer shared, a revoked grant or an ended session resets the stream.
    fn recheck(&mut self) {
        if self.subs.is_empty() {
            return;
        }
        let view = match self.ctx.view(false) {
            Ok(v) => v,
            Err(e) if e.code() == ErrorCode::AuthRequired => {
                for stream in std::mem::take(&mut self.subs).into_keys() {
                    self.reset(stream, RESET_REVOKED);
                }
                return;
            }
            Err(_) => {
                // Busy for a moment is no reason to cut streams, but an unreadable Host is not
                // a licence to keep them: after RECHECK_BLIND without a view they go.
                let since = *self.blind.get_or_insert_with(Instant::now);
                if since.elapsed() >= RECHECK_BLIND {
                    for stream in std::mem::take(&mut self.subs).into_keys() {
                        self.reset(stream, RESET_UNAVAILABLE);
                    }
                }
                return;
            }
        };
        self.blind = None;
        if self.checked.as_ref().is_some_and(|c| Arc::ptr_eq(c, &view)) {
            return;
        }
        let mut gone = Vec::new();
        for (stream, sub) in &self.subs {
            let open = sub.open();
            let mut code = match sub {
                Sub::Transfer(Transfer {
                    workspace: Some(ws),
                    ..
                }) => authorize(
                    &view.access,
                    &Target::message(ws, Method::WorkspaceGet),
                    now_ms(),
                ),
                _ => authorize(&view.access, &Target::open(open), now_ms()),
            }
            .err()
            .map(reset_code);
            if let (None, OpenParams::Terminal(p)) = (code, open)
                && view
                    .project(&p.workspace_id)
                    .and_then(|pr| find_session(&pr.state, &p.pane_id, &p.session_epoch))
                    .is_none()
            {
                code = Some(RESET_GONE);
            }
            if let Some(code) = code {
                gone.push((*stream, code));
            }
        }
        for (stream, code) in gone {
            self.reset(stream, code);
        }
        self.checked = Some(view);
    }

    // -- directory ------------------------------------------------------------------------

    /// The first message of the Host-opened directory stream, built here and not on the uplink
    /// thread (the view read can block).
    fn snapshot(&mut self, stream: u32) {
        let (host, workspaces) = match self.ctx.view(true) {
            Ok(view) => (view.host_name.clone(), build_directory(&self.ctx, &view)),
            Err(_) => (None, Vec::new()),
        };
        self.dir = Some(Dir {
            last: workspaces.clone(),
            seq: 0,
            hint: None,
            built: Instant::now(),
        });
        self.push(stream, snapshot_bytes(host, workspaces, 0));
    }

    fn directory(&mut self) {
        let Some(dir) = &self.dir else {
            return;
        };
        // A device that does not read the directory gets the whole difference later.
        if self
            .pipes
            .get(&DIRECTORY)
            .is_some_and(|p| p.queue.len() >= PIPE)
        {
            return;
        }
        let hint = self
            .ctx
            .coordinator()
            .ok()
            .and_then(|c| c.owner.projection_hint());
        // Sessions of chat threads change without the Host's revision moving: rebuild now and then.
        if dir.built.elapsed() < DIRECTORY_EVERY && (hint.is_none() || hint == dir.hint) {
            return;
        }
        let Ok(view) = self.ctx.view(false) else {
            return;
        };
        let now = build_directory(&self.ctx, &view);
        let mut changes = Vec::new();
        let dir = self.dir.as_mut().expect("checked above");
        dir.built = Instant::now();
        dir.hint = hint;
        for ws in &now {
            if dir.last.iter().all(|old| old != ws) {
                dir.seq += 1;
                changes.push(DirectoryUpdate {
                    seq: dir.seq,
                    change: DirectoryChange::Workspace(ws.clone()),
                });
            }
        }
        for old in &dir.last {
            if now.iter().all(|ws| ws.id != old.id) {
                dir.seq += 1;
                changes.push(DirectoryUpdate {
                    seq: dir.seq,
                    change: DirectoryChange::Removed(old.id),
                });
            }
        }
        dir.last = now.clone();
        let encoded: Option<Vec<Vec<u8>>> = changes
            .into_iter()
            .map(|c| DirectoryMessage::Change(c).encode().ok())
            .collect();
        match encoded {
            Some(messages) => messages.into_iter().for_each(|m| self.push(DIRECTORY, m)),
            None => {
                // A change that does not encode must not leave the device behind: send the whole
                // state instead (its `seq` is past every change that was dropped).
                dir.seq += 1;
                let bytes = snapshot_bytes(view.host_name.clone(), now, dir.seq);
                self.push(DIRECTORY, bytes);
            }
        }
    }
}

fn snapshot_bytes(host: Option<String>, workspaces: Vec<DirectoryWorkspace>, seq: u64) -> Vec<u8> {
    let text = |s: String| {
        DisplayText::try_from(s)
            .unwrap_or_else(|_| DisplayText::try_from("Host".to_owned()).expect("static"))
    };
    DirectoryMessage::Snapshot(DirectorySnapshot {
        seq,
        host: DirectoryHost {
            name: text(host.unwrap_or_else(|| "Lomi Host".to_owned())),
            platform: text(std::env::consts::OS.to_owned()),
            version: text(env!("CARGO_PKG_VERSION").to_owned()),
        },
        workspaces,
    })
    .encode()
    .unwrap_or_default()
}

fn reset_for(code: ErrorCode) -> u16 {
    match code {
        ErrorCode::WorkspaceUnshared => RESET_UNSHARED,
        ErrorCode::ScopeDenied | ErrorCode::ControlRequired => RESET_SCOPE,
        ErrorCode::AuthRequired => RESET_REVOKED,
        ErrorCode::ResourceNotFound | ErrorCode::SessionExited | ErrorCode::StaleEpoch => {
            RESET_GONE
        }
        ErrorCode::InvalidArgument => RESET_INVALID,
        ErrorCode::ResourceExhausted | ErrorCode::HostBusy => RESET_BUSY,
        _ => RESET_UNAVAILABLE,
    }
}

/// The live session behind `pane` in the shared projection.
fn find_session(
    state: &WorkspaceState,
    pane: &PaneId,
    epoch: &SessionEpoch,
) -> Option<TerminalContext> {
    fn walk(layout: &TerminalLayout, f: &mut impl FnMut(&TerminalPane)) {
        match layout {
            TerminalLayout::Pane { pane } => f(pane),
            TerminalLayout::Split { first, second, .. } => {
                walk(first, f);
                walk(second, f);
            }
        }
    }
    let mut found = None;
    for tab in &state.tabs.0 {
        walk(&tab.layout, &mut |p| {
            if p.pane_id == *pane
                && let Some(session) = &p.session
                && session.session_epoch == *epoch
            {
                found = Some(session.clone());
            }
        });
    }
    found
}

fn attach(
    coordinator: &Coordinator,
    principal: &AuthenticatedConnection,
    terminal: &TerminalContext,
    wake: &Waker,
) -> Result<Attachment, u16> {
    let attachment = coordinator
        .terminals
        .attach_checked(
            terminal.session_id,
            terminal.session_epoch,
            principal,
            || true,
        )
        .map_err(|e| reset_for(terminal_error(e).code()))?;
    attachment.set_waker(wake.clone());
    Ok(attachment)
}

impl Term {
    /// Snapshot of the current attachment, sent as metadata, chunks and a completion.
    fn begin(&mut self) -> Result<(), u16> {
        let snapshot = &self.attachment.snapshot;
        let bytes = serde_json::to_vec(snapshot).map_err(|_| RESET_UNAVAILABLE)?;
        if bytes.is_empty() || bytes.len() > 8 * 1024 * 1024 {
            return Err(RESET_BUSY);
        }
        let wd = self.attachment.working_directory.clone();
        self.id = SubscriptionId::try_from(format!("terminal-{}", uuid::Uuid::new_v4().simple()))
            .map_err(|_| RESET_UNAVAILABLE)?;
        let meta = TerminalSnapshotMetadata {
            terminal: self.terminal.clone(),
            subscription_id: self.id.clone(),
            through_seq: TerminalSeq(snapshot.sequence),
            output_offset: snapshot.output_offset,
            columns: TerminalDimension(snapshot.cols as u32),
            rows: TerminalDimension(snapshot.rows as u32),
            chunk_count: ChunkCount(bytes.len().div_ceil(CHUNK) as u32),
            total_bytes: DecimalU64(bytes.len() as u64),
            working_directory: wd.into(),
        };
        self.sent_through = None;
        self.emission = Some(Emission {
            bytes,
            position: 0,
            previous: None,
            through: snapshot.sequence.0,
            offset: snapshot.output_offset.0,
            header: false,
            snapshot: Some(meta),
            working_directory: None,
        });
        Ok(())
    }

    /// The next frame: the rest of an emission first, then queued terminal events.
    fn next(&mut self, ctx: &Ctx) -> Result<Option<(TerminalStreamFrame, bool)>, u16> {
        if let Some(e) = &mut self.emission {
            let (frame, done) = e.next(&self.terminal, &self.id);
            if done {
                // Credit is the renderer's acknowledgement in a tunnel (spec 8): what the engine
                // has taken is acknowledged here, so a claim never waits for a separate ack.
                let through = e.through;
                let _ = self
                    .attachment
                    .acknowledge_checked(&ctx.principal, through, || true);
                self.sent_through = Some(through);
                self.emission = None;
            }
            return Ok(Some((frame, false)));
        }
        let Some(queued) = self.attachment.try_next_with_metadata() else {
            return Ok(None);
        };
        let (terminal, id) = (self.terminal.clone(), self.id.clone());
        let delta_frame = |change| {
            TerminalStreamFrame::Delta(TerminalDelta {
                terminal: terminal.clone(),
                subscription_id: id.clone(),
                seq: TerminalSeq(DecimalU64(0)),
                change,
            })
        };
        match &*queued.event {
            TerminalEvent::State(delta) => {
                let bytes = serde_json::to_vec(delta).map_err(|_| RESET_UNAVAILABLE)?;
                if bytes.is_empty() || bytes.len() > 8 * 1024 * 1024 {
                    return self.resync(ctx);
                }
                self.emission = Some(Emission {
                    bytes,
                    position: 0,
                    previous: Some(delta.previous_sequence().0),
                    through: delta.sequence().0,
                    offset: delta.output_offset().0,
                    header: true,
                    snapshot: None,
                    working_directory: queued.working_directory.clone(),
                });
                self.next(ctx)
            }
            TerminalEvent::ControlChanged {
                sequence,
                version,
                controlled,
            } => {
                let mut frame =
                    delta_frame(TerminalChange::ControlChanged(TerminalControlChanged {
                        terminal: self.terminal.clone(),
                        lease_version: DecimalU64(*version),
                        controlled: *controlled,
                    }));
                if let TerminalStreamFrame::Delta(d) = &mut frame {
                    d.seq = TerminalSeq(DecimalU64(*sequence));
                }
                let _ = self
                    .attachment
                    .acknowledge_checked(&ctx.principal, *sequence, || true);
                self.sent_through = Some(*sequence);
                Ok(Some((frame, false)))
            }
            TerminalEvent::Exited { sequence } => {
                let mut frame = delta_frame(TerminalChange::Exit(TerminalExit { exit_code: None }));
                if let TerminalStreamFrame::Delta(d) = &mut frame {
                    d.seq = TerminalSeq(DecimalU64(*sequence));
                }
                Ok(Some((frame, true)))
            }
            TerminalEvent::ResyncRequired => self.resync(ctx),
        }
    }

    /// Overflow: tell the device, then start again from a fresh snapshot on the same stream.
    fn resync(&mut self, ctx: &Ctx) -> Result<Option<(TerminalStreamFrame, bool)>, u16> {
        let frame = TerminalStreamFrame::ResyncRequired(TerminalResync {
            terminal: self.terminal.clone(),
            subscription_id: self.id.clone(),
            reason: ResyncReason::SubscriberOverflow,
        });
        let coordinator = ctx.coordinator().map_err(|_| RESET_UNAVAILABLE)?;
        self.attachment = attach(&coordinator, &ctx.principal, &self.terminal, &self.wake)?;
        self.begin()?;
        Ok(Some((frame, false)))
    }

    fn lease(&self, binding: &LeaseBinding) -> Result<ControlLease, RemoteError> {
        self.lease
            .clone()
            .filter(|l| {
                l.wire_token() == String::from(binding.token.clone())
                    && l.version == binding.version.0
            })
            .ok_or_else(|| fault(ErrorCode::ControlRequired))
    }

    fn ack(&self, ctx: &Ctx, id: &SubscriptionId, through: u64) -> Result<(), RemoteError> {
        if *id != self.id || self.sent_through.is_none_or(|sent| through > sent) {
            return Err(fault(ErrorCode::ResyncRequired));
        }
        self.attachment
            .acknowledge_checked(&ctx.principal, through, || true)
            .map_err(terminal_error)
    }

    fn control(&mut self, ctx: &Ctx, call: &RpcCall) -> Result<RpcResult, RemoteError> {
        let coordinator = ctx.coordinator()?;
        let terminals = &coordinator.terminals;
        let (session, epoch) = (self.terminal.session_id, self.terminal.session_epoch);
        let principal = &ctx.principal;
        Ok(match call {
            RpcCall::TerminalAck(p) => {
                self.ack(ctx, &p.subscription_id, p.through_seq.0.0)?;
                RpcResult::TerminalAck(TerminalAckResult {
                    subscription_id: p.subscription_id.clone(),
                    through_seq: p.through_seq,
                })
            }
            RpcCall::TerminalClaim(_) => {
                // `renderedThroughSeq` is not needed: the Host acknowledged what it sent.
                let mut lease = terminals
                    .claim_checked(session, epoch, principal, || true)
                    .map_err(terminal_error)?;
                // The size the device opened with, once: resizing needs the lease. A refusal
                // leaves the claim as it is.
                if let Some((cols, rows)) = self.size.take()
                    && let Ok(now) = terminals.snapshot(session, epoch)
                    && (now.cols as u32, now.rows as u32) != (cols, rows)
                    && terminals
                        .resize(
                            session,
                            epoch,
                            principal,
                            &lease,
                            lease.next_resize_seq,
                            rows as u16,
                            cols as u16,
                            || true,
                        )
                        .is_ok()
                    && let Ok(renewed) =
                        terminals.renew_checked(session, epoch, principal, &lease, || true)
                {
                    lease = renewed;
                }
                let result = lease_result(self.terminal.clone(), &lease);
                self.lease = Some(lease);
                RpcResult::TerminalClaim(result)
            }
            RpcCall::TerminalRenew(p) => {
                let lease = self.lease(&p.lease)?;
                let renewed = terminals
                    .renew_checked(session, epoch, principal, &lease, || true)
                    .map_err(terminal_error)?;
                let result = lease_result(self.terminal.clone(), &renewed);
                self.lease = Some(renewed);
                RpcResult::TerminalRenew(result)
            }
            RpcCall::TerminalRelease(p) => {
                let lease = self.lease(&p.lease)?;
                terminals
                    .release_checked(session, epoch, principal, &lease, || true)
                    .map_err(terminal_error)?;
                self.lease = None;
                RpcResult::TerminalRelease(TerminalReleaseResult {
                    terminal: self.terminal.clone(),
                    released: true,
                })
            }
            RpcCall::TerminalInput(p) => {
                let lease = self.lease(&p.lease)?;
                let receipt = terminals
                    .input(
                        session,
                        epoch,
                        principal,
                        &lease,
                        p.input_id.0,
                        p.input_seq.0.0,
                        &p.bytes.0,
                        || true,
                    )
                    .map_err(terminal_error)?;
                let bytes = |n: usize| {
                    InputBytes::new(n as u64).map_err(|_| fault(ErrorCode::InvalidArgument))
                };
                RpcResult::TerminalInput(
                    InputReceipt::new(
                        session,
                        epoch,
                        p.input_id,
                        p.input_seq.0,
                        bytes(receipt.submitted_bytes)?,
                        bytes(receipt.accepted_bytes)?,
                    )
                    .map_err(|_| fault(ErrorCode::ServiceUnavailable))?,
                )
            }
            RpcCall::TerminalResize(p) => {
                let lease = self.lease(&p.lease)?;
                terminals
                    .resize(
                        session,
                        epoch,
                        principal,
                        &lease,
                        p.resize_seq.0.0,
                        p.rows.0 as u16,
                        p.columns.0 as u16,
                        || true,
                    )
                    .map_err(terminal_error)?;
                RpcResult::TerminalResize(TerminalResizeResult {
                    terminal: self.terminal.clone(),
                    resize_seq: p.resize_seq,
                    columns: p.columns,
                    rows: p.rows,
                })
            }
            _ => return Err(fault(ErrorCode::UnsupportedCapability)),
        })
    }
}

fn build_directory(ctx: &Ctx, view: &View) -> Vec<DirectoryWorkspace> {
    fn layout(l: &TerminalLayout) -> DirectoryLayout {
        match l {
            TerminalLayout::Pane { pane } => DirectoryLayout::Pane(pane.pane_id),
            TerminalLayout::Split {
                axis,
                first,
                second,
            } => DirectoryLayout::Split {
                axis: *axis,
                first: Box::new(layout(first)),
                second: Box::new(layout(second)),
            },
        }
    }
    fn panes<'a>(l: &'a TerminalLayout, out: &mut Vec<&'a TerminalPane>) {
        match l {
            TerminalLayout::Pane { pane } => out.push(pane),
            TerminalLayout::Split { first, second, .. } => {
                panes(first, out);
                panes(second, out);
            }
        }
    }
    let coordinator = ctx.coordinator().ok();
    let mut out = Vec::new();
    for project in view.projects.iter().filter(|p| p.consent) {
        let state = &project.state;
        let id = state.context.workspace_id;
        let Some(capabilities) = view.access.capabilities(&id) else {
            continue;
        };
        let mut tabs = Vec::new();
        let mut terminals = Vec::new();
        for tab in &state.tabs.0 {
            tabs.push(DirectoryTab {
                tab_id: tab.tab_id,
                name: tab.name.clone(),
                layout: layout(&tab.layout),
            });
            let mut list = Vec::new();
            panes(&tab.layout, &mut list);
            for pane in list {
                terminals.push(DirectoryTerminal {
                    pane_id: pane.pane_id,
                    tab_id: tab.tab_id,
                    title: tab.name.clone(),
                    state: pane.state,
                    session_epoch: pane.session.as_ref().map(|s| s.session_epoch),
                });
            }
        }
        let chats = if capabilities.contains(Capability::ChatRead)
            && let Some(coordinator) = &coordinator
        {
            coordinator
                .chat
                .local_threads(id)
                .unwrap_or_default()
                .iter()
                .filter_map(|t| {
                    let thread = remote_chat::to_thread(t).ok()?;
                    Some(DirectoryChat {
                        thread_id: thread.thread_id,
                        title: thread.title,
                        provider: thread.provider_id,
                        model: thread.model,
                        mode: thread.permissions,
                        state: if t.streaming {
                            DirectoryChatState::Generating
                        } else {
                            DirectoryChatState::Idle
                        },
                        last_activity_at: t.updated_ms,
                    })
                })
                .collect()
        } else {
            Vec::new()
        };
        out.push(DirectoryWorkspace {
            id,
            epoch: state.context.workspace_epoch,
            name: state.name.clone(),
            capabilities,
            tabs,
            terminals,
            chats,
        });
    }
    out
}

// ---- the engine's view ----------------------------------------------------------------------

struct Tun {
    ctx: Arc<Ctx>,
    rpc: SyncSender<Vec<u8>>,
}
pub(super) struct HostService {
    coordinator: Weak<Coordinator>,
    handle: Arc<OnceLock<Handle>>,
    consent: Option<DeviceConsent>,
    tunnels: HashMap<CircuitId, Tun>,
    /// Tests: the stream whose credit never comes back (0: none).
    #[cfg(test)]
    stalled: Arc<std::sync::atomic::AtomicU32>,
}

impl HostService {
    fn tun(&self, s: &Streams<'_>) -> Option<&Tun> {
        self.tunnels.get(&s.circuit())
    }
}

impl TunnelService for HostService {
    fn on_tunnel_open(&mut self, s: &mut Streams<'_>, device: &AttestedDevice) {
        let Some(handle) = self.handle.get().cloned() else {
            return;
        };
        let Ok(actor) = ConsumerAuthorizationId::from_bytes(device.device_id) else {
            return;
        };
        let (rpc, rpc_rx) = sync_channel(JOBS);
        let (jobs, jobs_rx) = sync_channel(JOBS);
        let ctx = Arc::new(Ctx {
            coordinator: self.coordinator.clone(),
            handle,
            circuit: s.circuit(),
            device: device.clone(),
            principal: AuthenticatedConnection::new(actor),
            consent: self.consent.clone(),
            view: Mutex::new(None),
            jobs,
            life: Mutex::new(VecDeque::new()),
            closed: AtomicBool::new(false),
            busy: Mutex::new(HashMap::new()),
            transfers: AtomicUsize::new(0),
        });
        let spawn = |name: &str, f: Box<dyn FnOnce() + Send>| {
            std::thread::Builder::new()
                .name(name.into())
                .spawn(f)
                .is_ok()
        };
        let (a, b) = (ctx.clone(), ctx.clone());
        if spawn("lomi-tunnel-rpc", Box::new(move || rpc_loop(a, rpc_rx)))
            && spawn(
                "lomi-tunnel-streams",
                Box::new(move || stream_loop(b, jobs_rx)),
            )
        {
            self.tunnels.insert(s.circuit(), Tun { ctx, rpc });
        }
    }

    fn on_stream_open(
        &mut self,
        s: &mut Streams<'_>,
        stream: u32,
        params: &OpenParams,
    ) -> Result<(), u16> {
        let tun = self.tun(s).ok_or(RESET_UNAVAILABLE)?;
        match params {
            OpenParams::Terminal(_) | OpenParams::Chat(_) | OpenParams::FilesWatch(_) => tun
                .ctx
                .jobs
                .try_send(Job::Open(stream, params.clone()))
                .map_err(|_| RESET_BUSY),
            // A transfer is opened by the Host; the device never opens one.
            _ => Err(RESET_UNSUPPORTED),
        }
    }

    fn on_message(&mut self, s: &mut Streams<'_>, stream: u32, data: Vec<u8>) {
        let Some(tun) = self.tun(s) else {
            return;
        };
        let full = if stream == 0 {
            tun.rpc.try_send(data).is_err()
        } else if stream == DIRECTORY {
            false // the device has nothing to say here
        } else {
            tun.ctx.jobs.try_send(Job::Message(stream, data)).is_err()
        };
        if full {
            // The workers are far behind: a stream is reset, a stalled rpc closes the tunnel.
            if stream == 0 {
                let _ = tun.ctx.handle.push(Command::CloseTunnel {
                    circuit: s.circuit(),
                });
            } else {
                s.reset(stream, RESET_BUSY);
            }
        }
    }

    fn on_stream_close(&mut self, s: &mut Streams<'_>, stream: u32, _reset: Option<u16>) {
        if let Some(tun) = self.tun(s) {
            tun.ctx.lifecycle(Job::Closed(stream));
        }
    }

    fn on_writable(&mut self, s: &mut Streams<'_>, stream: u32) {
        #[cfg(test)]
        if self.stalled.load(Ordering::Acquire) == stream {
            return;
        }
        if let Some(tun) = self.tun(s) {
            tun.ctx.lifecycle(Job::Writable(stream));
        }
    }

    fn on_tunnel_close(&mut self, circuit: CircuitId, _reason: &str) {
        // Dropping `rpc` ends that worker; the streams worker is told to stop and then detaches
        // the device.
        if let Some(tun) = self.tunnels.remove(&circuit) {
            tun.ctx.closed.store(true, Ordering::Release);
            tun.ctx.lifecycle(Job::Stop);
        }
    }

    fn directory_opened(&mut self, s: &mut Streams<'_>, stream: u32) {
        if let Some(tun) = self.tun(s) {
            tun.ctx.lifecycle(Job::Directory(stream));
        }
    }
}

/// Installs the service on the uplink (a no-op unless the debug-only uplink switch is on).
/// Returns false while the Host identity is not ready yet, so the caller tries again later.
/// Until P3a.10 supplies the real policy every device is welcomed with `Read`.
pub(super) fn install(
    coordinator: &Weak<Coordinator>,
    identity: impl FnOnce() -> Option<(Identity, [u8; 16], [u8; 16])>,
) -> bool {
    if !uplink::enabled() {
        return true;
    }
    let Some(contract_hash) = uplink::contract_hash() else {
        return true;
    };
    let Some((identity, host_id, account)) = identity() else {
        return false;
    };
    let Some(owner) = coordinator.upgrade() else {
        return false;
    };
    // Default D5 variant 2 (`Auto`); the owner's saved choice wins.
    let store = owner.owner.store_handle();
    let mode = store
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .device_mode()
        .map_or(Mode::Auto, Mode::from);
    let consent = DeviceConsent::new(store, account, mode);
    *owner.consent.lock().unwrap_or_else(PoisonError::into_inner) = Some(consent.clone());
    let cell = Arc::new(OnceLock::new());
    let service = HostService {
        coordinator: coordinator.clone(),
        handle: cell.clone(),
        consent: Some(consent.clone()),
        tunnels: HashMap::new(),
        #[cfg(test)]
        stalled: Arc::default(),
    };
    let policy = consent.policy();
    let config = Config {
        identity,
        host_id,
        contract_hash,
    };
    // The roster first (it also replays a READY that came before), so no admission runs against a
    // consent that has not seen the device list.
    uplink::install_roster(consent.roster());
    if let Some(handle) = uplink::install_tunnels(config, policy, Box::new(service)) {
        consent.set_handle(handle.clone());
        let _ = cell.set(handle);
    }
    true
}

#[cfg(test)]
mod call_limits {
    use super::*;

    #[test]
    fn one_device_cannot_exceed_its_call_share_across_tunnels() {
        let key = [0xd1; 32];
        let claimed: Vec<bool> = (0..=MAX_CALLS_PER_DEVICE)
            .map(|_| claim_call(&key))
            .collect();
        assert!(claimed[..MAX_CALLS_PER_DEVICE].iter().all(|c| *c));
        assert!(!claimed[MAX_CALLS_PER_DEVICE], "the 33rd call is refused");
        release_call(&key);
        assert!(claim_call(&key));
        for _ in 0..MAX_CALLS_PER_DEVICE {
            release_call(&key);
        }
    }
}

#[cfg(test)]
#[path = "tunnel_service_tests.rs"]
mod tests;

#[cfg(test)]
pub(super) fn service_for_test(
    coordinator: Weak<Coordinator>,
    handle: Handle,
    consent: Option<DeviceConsent>,
    stalled: Arc<std::sync::atomic::AtomicU32>,
) -> Box<dyn TunnelService> {
    let cell = Arc::new(OnceLock::new());
    let _ = cell.set(handle);
    Box::new(HostService {
        coordinator,
        handle: cell,
        consent,
        tunnels: HashMap::new(),
        stalled,
    })
}
