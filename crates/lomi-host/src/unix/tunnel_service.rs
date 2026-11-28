//! The Host side of the device tunnel streams (plan-1.0 P3a.9): `rpc` on stream 0, `directory`,
//! `terminal`, `chat` and `files.watch`. Messages are today's frames (JSON), carried as stream
//! messages; the binary encodings are P4.
//!
//! Threads. The engine calls this service on the uplink thread, where nothing may block, so a
//! callback only hands bytes to two worker threads per tunnel and returns:
//! - `rpc` serves stream 0 one request at a time (files, chat; a slow call delays only later calls);
//! - `streams` owns every other stream: it opens them, polls terminal, chat and watch output,
//!   keeps the directory current and writes everything back through the engine [`Handle`].
//!
//! Authorization is the one check from `tunnel_authz`, run for every rpc request, every stream
//! open and every control message, on a view (grant, shared workspaces) that is at most about a
//! second old or older only until the Host's projection revision moves. A stream whose
//! workspace is no longer shared with the device, or whose session ended, is reset.
//!
//! Flow control. The engine enforces the 64 KiB stream windows. This service keeps at most
//! `FLIGHT` bytes per stream between itself and the engine (`on_writable` reopens it) and at most
//! `QUEUE` messages in its own queue; when the device is slow the terminal's own attachment queue
//! overflows and the existing overflow -> `ResyncRequired` -> fresh snapshot rule applies.
//!
//! Shortcuts: output is polled every 15 ms while a stream is open (the terminal queue has no
//! wake-up); `transfer`, git, workspace.* and terminal lifecycle calls are not served here yet;
//! terminal `OPEN` ignores `cols`/`rows`/`afterSeq` (always a full snapshot).
use super::{
    Coordinator,
    owner_domain::Operation,
    remote_chat::{self, ChatSub, Grant, Scope},
    remote_files,
    remote_files_watch::RemoteWatch,
    remote_terminal::{fault, lease_result, terminal as terminal_error},
    tunnel_authz::{Denied, DeviceAccess, Target, authorize, call_workspace},
};
use lomi_host_http::uplink::{
    self,
    tunnels::{
        AttestedDevice, AutoRead, CircuitId, Command, Config, Handle, Policy, Streams,
        TunnelService,
    },
};
use lomi_host_store::ProjectRecord;
use lomi_remote_crypto::Identity;
use lomi_remote_protocol::{
    rpc::*,
    streams::*,
    tunnel::{
        ChatOpen, DirectoryChange, DirectoryChat, DirectoryChatState, DirectoryHost,
        DirectoryLayout, DirectoryMessage, DirectorySnapshot, DirectoryTab, DirectoryTerminal,
        DirectoryUpdate, DirectoryWorkspace, FilesWatchOpen, OpenParams, RpcEnvelope, TerminalOpen,
    },
    *,
};
use lomi_terminal::{Attachment, AuthenticatedConnection, ControlLease, TerminalEvent};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{
        Arc, Mutex, OnceLock, PoisonError, Weak,
        atomic::AtomicBool,
        mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// The Host-opened directory stream: the engine opens it first, so it is always stream 2.
const DIRECTORY: u32 = 2;
/// Bytes handed to the engine for one stream and not yet sent.
const FLIGHT: usize = 128 * 1024;
const QUEUE: usize = 64;
const JOBS: usize = 256;
const CHUNK: usize = 16384;
const VIEW_TTL: Duration = Duration::from_secs(1);
const DIRECTORY_EVERY: Duration = Duration::from_secs(2);
const TICK: Duration = Duration::from_millis(15);
const IDLE_TICK: Duration = Duration::from_millis(500);
const MAX_TERMINALS: usize = 32;

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
    view: Mutex<Option<Arc<View>>>,
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
        let mut cached = self.view.lock().unwrap_or_else(PoisonError::into_inner);
        if !fresh
            && let Some(v) = &*cached
            && v.at.elapsed() < VIEW_TTL
            && v.hint == hint
        {
            return Ok(v.clone());
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
        *cached = Some(v.clone());
        Ok(v)
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
    /// Blocking send for the rpc worker.
    fn send(&self, stream: u32, mut data: Vec<u8>) {
        for _ in 0..200 {
            match self.handle.send(self.circuit, stream, data) {
                Ok(()) => return,
                Err(Command::Send { data: back, .. }) => data = back,
                Err(_) => return,
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn response(id: &RequestId, call: &RpcCall, r: Result<RpcResult, RemoteError>) -> Option<Vec<u8>> {
    let response = match r {
        Ok(result) => RpcResponse::Result {
            v: ApplicationMajor,
            request_id: id.clone(),
            result,
        },
        Err(error) => RpcResponse::Error {
            v: ApplicationMajor,
            request_id: id.clone(),
            operation_id: call.chat_operation_id(),
            error,
        },
    };
    serde_json::to_vec(&response).ok()
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

// ---- stream 0 -------------------------------------------------------------------------------

fn rpc_loop(ctx: Arc<Ctx>, jobs: Receiver<Vec<u8>>) {
    while let Ok(bytes) = jobs.recv() {
        // A request that does not parse has no id to answer; the device times it out.
        let Ok(envelope) = RpcEnvelope::decode(&bytes) else {
            continue;
        };
        let result = rpc(&ctx, &envelope);
        if let Some(out) = response(&envelope.request_id, &envelope.call, result) {
            ctx.send(0, out);
        }
    }
}

fn rpc(ctx: &Ctx, envelope: &RpcEnvelope) -> Result<RpcResult, RemoteError> {
    let call = &envelope.call;
    let workspace = envelope
        .workspace_id
        .or_else(|| call_workspace(call).copied())
        .ok_or_else(|| fault(ErrorCode::InvalidArgument))?;
    let view = ctx.view(false)?;
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
    authorize(&view.access, &target, now_ms()).map_err(denied)?;
    let project = view
        .project(&workspace)
        .ok_or_else(|| fault(ErrorCode::WorkspaceUnshared))?;
    let state = &project.state.context;
    if let Some(files) = files_context(call) {
        if files.workspace_epoch != state.workspace_epoch {
            return Err(fault(ErrorCode::StaleEpoch));
        }
        let root = coordinator
            .files
            .get(workspace, state.workspace_epoch, &project.local_root)?;
        return remote_files::execute_read(&root, call);
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
            .execute(call, &grant, &scope, deadline, &mut None);
    }
    Err(fault(ErrorCode::UnsupportedCapability))
}

// ---- the other streams ----------------------------------------------------------------------

enum Job {
    Open(u32, OpenParams),
    Message(u32, Vec<u8>),
    Closed(u32),
    Writable(u32),
    Baseline(Vec<DirectoryWorkspace>),
}
enum Out {
    Data(u32, Vec<u8>),
    Close(u32),
    Reset(u32, u16),
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

#[allow(clippy::large_enum_variant)] // shortcut: one Sub per stream, boxing buys nothing
enum Sub {
    Terminal(Box<Term>),
    Chat(Chat),
    Watch(Watch),
}
impl Sub {
    fn open(&self) -> &OpenParams {
        match self {
            Self::Terminal(t) => &t.open,
            Self::Chat(c) => &c.open,
            Self::Watch(w) => &w.open,
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
    out: VecDeque<Out>,
    flight: HashMap<u32, usize>,
    watches: u64,
    dir: Option<Dir>,
    checked: Option<Arc<View>>,
}

fn stream_loop(ctx: Arc<Ctx>, jobs: Receiver<Job>) {
    let mut hub = Hub {
        ctx,
        subs: BTreeMap::new(),
        out: VecDeque::new(),
        flight: HashMap::new(),
        watches: 0,
        dir: None,
        checked: None,
    };
    loop {
        let wait = if hub.subs.is_empty() && hub.out.is_empty() {
            IDLE_TICK
        } else {
            TICK
        };
        match jobs.recv_timeout(wait) {
            Ok(job) => hub.job(job),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        while let Ok(job) = jobs.try_recv() {
            hub.job(job);
        }
        hub.recheck();
        hub.directory();
        hub.pump();
        hub.flush();
    }
    // Host PTYs survive; only this device's attachments and leases go.
    if let Ok(coordinator) = hub.ctx.coordinator() {
        coordinator.terminals.disconnect(&hub.ctx.principal);
    }
}

impl Hub {
    fn job(&mut self, job: Job) {
        match job {
            Job::Open(stream, params) => {
                if let Err(code) = self.open(stream, params) {
                    self.out.push_back(Out::Reset(stream, code));
                }
            }
            Job::Message(stream, data) => {
                if let Err(code) = self.message(stream, &data) {
                    self.subs.remove(&stream);
                    self.out.push_back(Out::Reset(stream, code));
                }
            }
            Job::Closed(stream) => {
                self.subs.remove(&stream);
                self.flight.remove(&stream);
                self.out
                    .retain(|o| !matches!(o, Out::Data(s, _) if *s == stream));
            }
            Job::Writable(stream) => {
                self.flight.remove(&stream);
            }
            Job::Baseline(last) => {
                self.dir = Some(Dir {
                    last,
                    seq: 0,
                    hint: None,
                    built: Instant::now(),
                });
            }
        }
    }

    fn push(&mut self, stream: u32, data: Vec<u8>) {
        self.out.push_back(Out::Data(stream, data));
    }
    /// Hands queued output to the engine while the stream's flight budget allows.
    fn flush(&mut self) {
        let handle = &self.ctx.handle;
        let circuit = self.ctx.circuit;
        while let Some(front) = self.out.pop_front() {
            match front {
                Out::Data(stream, data) => {
                    let flying = self.flight.get(&stream).copied().unwrap_or(0);
                    if flying >= FLIGHT {
                        self.out.push_front(Out::Data(stream, data));
                        break;
                    }
                    let len = data.len();
                    match handle.send(circuit, stream, data) {
                        Ok(()) => *self.flight.entry(stream).or_default() += len,
                        Err(Command::Send { data, .. }) => {
                            self.out.push_front(Out::Data(stream, data));
                            break;
                        }
                        Err(_) => break,
                    }
                }
                Out::Close(stream) => {
                    let _ = handle.push(Command::CloseStream { circuit, stream });
                }
                Out::Reset(stream, code) => {
                    let _ = handle.push(Command::ResetStream {
                        circuit,
                        stream,
                        code,
                    });
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
        let attachment = attach(&coordinator, &self.ctx.principal, &terminal)?;
        let mut term = Term {
            open: open.clone(),
            terminal,
            attachment,
            id: SubscriptionId::try_from(format!("terminal-{}", uuid::Uuid::new_v4().simple()))
                .map_err(|_| RESET_UNAVAILABLE)?,
            emission: None,
            sent_through: None,
            lease: None,
            held: VecDeque::new(),
        };
        term.begin()?;
        Ok(Sub::Terminal(Box::new(term)))
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
        Ok(Sub::Chat(Chat {
            open: open.clone(),
            sub: sub.ok_or(RESET_UNAVAILABLE)?,
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
        match self.subs.get_mut(&stream) {
            // Closed or refused earlier: nothing to do.
            None => Ok(()),
            Some(Sub::Chat(_)) => Err(RESET_INVALID),
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
            let view = ctx.view(false)?;
            let ws = term.terminal.workspace.workspace_id;
            authorize(&view.access, &Target::message(&ws, call.method()), now_ms())
                .map_err(denied)?;
            term.control(&ctx, &call)
        })();
        response(&envelope.request_id, &call, result).ok_or(RESET_UNAVAILABLE)
    }

    // -- output ---------------------------------------------------------------------------

    fn pump(&mut self) {
        let streams: Vec<u32> = self.subs.keys().copied().collect();
        for stream in streams {
            if let Err(code) = self.release_held(stream) {
                self.subs.remove(&stream);
                self.out.push_back(Out::Reset(stream, code));
                continue;
            }
            for _ in 0..16 {
                if self.out.len() >= QUEUE
                    || self.flight.get(&stream).copied().unwrap_or(0) >= FLIGHT
                {
                    break;
                }
                match self.step(stream) {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(code) => {
                        self.subs.remove(&stream);
                        self.out.push_back(Out::Reset(stream, code));
                        break;
                    }
                }
            }
        }
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
        let (frame, finished) = match sub {
            Sub::Chat(c) => {
                let Some(frame) = c.sub.poll() else {
                    if c.sub.is_dead() {
                        self.subs.remove(&stream);
                        self.out.push_back(Out::Close(stream));
                    }
                    return Ok(false);
                };
                (serde_json::to_vec(&frame), false)
            }
            Sub::Watch(w) => match w.watch.poll(Instant::now()) {
                Some(frame) => {
                    let end = matches!(frame, FileWatchFrame::ResyncRequired(_));
                    (serde_json::to_vec(&frame), end)
                }
                None => return Ok(false),
            },
            Sub::Terminal(t) => match t.next(&ctx)? {
                Some((frame, end)) => (serde_json::to_vec(&frame), end),
                None => return Ok(false),
            },
        };
        let bytes = frame.map_err(|_| RESET_UNAVAILABLE)?;
        self.push(stream, bytes);
        if finished {
            self.subs.remove(&stream);
            self.out.push_back(Out::Close(stream));
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
                    self.out.push_back(Out::Reset(stream, RESET_REVOKED));
                }
                return;
            }
            Err(_) => return,
        };
        if self.checked.as_ref().is_some_and(|c| Arc::ptr_eq(c, &view)) {
            return;
        }
        let mut gone = Vec::new();
        for (stream, sub) in &self.subs {
            let open = sub.open();
            let mut code = authorize(&view.access, &Target::open(open), now_ms())
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
            self.subs.remove(&stream);
            self.out.push_back(Out::Reset(stream, code));
        }
        self.checked = Some(view);
    }

    // -- directory ------------------------------------------------------------------------

    fn directory(&mut self) {
        let Some(dir) = &self.dir else {
            return;
        };
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
        let mut messages = Vec::new();
        let dir = self.dir.as_mut().expect("checked above");
        dir.built = Instant::now();
        dir.hint = hint;
        for ws in &now {
            if dir.last.iter().all(|old| old != ws) {
                dir.seq += 1;
                messages.push(DirectoryUpdate {
                    seq: dir.seq,
                    change: DirectoryChange::Workspace(ws.clone()),
                });
            }
        }
        for old in &dir.last {
            if now.iter().all(|ws| ws.id != old.id) {
                dir.seq += 1;
                messages.push(DirectoryUpdate {
                    seq: dir.seq,
                    change: DirectoryChange::Removed(old.id),
                });
            }
        }
        dir.last = now;
        for change in messages {
            if let Ok(bytes) = DirectoryMessage::Change(change).encode() {
                self.push(DIRECTORY, bytes);
            }
        }
    }
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
) -> Result<Attachment, u16> {
    coordinator
        .terminals
        .attach_checked(
            terminal.session_id,
            terminal.session_epoch,
            principal,
            || true,
        )
        .map_err(|e| reset_for(terminal_error(e).code()))
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
        self.attachment = attach(&coordinator, &ctx.principal, &self.terminal)?;
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
                let lease = terminals
                    .claim_checked(session, epoch, principal, || true)
                    .map_err(terminal_error)?;
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
    jobs: SyncSender<Job>,
}
pub(super) struct HostService {
    coordinator: Weak<Coordinator>,
    handle: Arc<OnceLock<Handle>>,
    tunnels: HashMap<CircuitId, Tun>,
    /// The tunnel whose `directory()` call is next: the engine calls it right after opening.
    opening: Option<CircuitId>,
}

impl HostService {
    fn tun(&self, s: &Streams<'_>) -> Option<&Tun> {
        self.tunnels.get(&s.circuit())
    }
}

impl TunnelService for HostService {
    fn on_tunnel_open(&mut self, s: &mut Streams<'_>, device: &AttestedDevice) {
        self.opening = None;
        let Some(handle) = self.handle.get().cloned() else {
            return;
        };
        let Ok(actor) = ConsumerAuthorizationId::from_bytes(device.device_id) else {
            return;
        };
        let ctx = Arc::new(Ctx {
            coordinator: self.coordinator.clone(),
            handle,
            circuit: s.circuit(),
            device: device.clone(),
            principal: AuthenticatedConnection::new(actor),
            view: Mutex::new(None),
        });
        let (rpc, rpc_rx) = sync_channel(JOBS);
        let (jobs, jobs_rx) = sync_channel(JOBS);
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
            self.opening = Some(s.circuit());
            self.tunnels.insert(s.circuit(), Tun { ctx, rpc, jobs });
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
                .jobs
                .try_send(Job::Open(stream, params.clone()))
                .map_err(|_| RESET_BUSY),
            // shortcut: transfer streams arrive with the binary encodings (P4)
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
            tun.jobs.try_send(Job::Message(stream, data)).is_err()
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
            let _ = tun.jobs.try_send(Job::Closed(stream));
        }
    }

    fn on_writable(&mut self, s: &mut Streams<'_>, stream: u32) {
        if let Some(tun) = self.tun(s) {
            let _ = tun.jobs.try_send(Job::Writable(stream));
        }
    }

    fn on_tunnel_close(&mut self, circuit: CircuitId, _reason: &str) {
        // Dropping the senders ends both workers; the streams worker then detaches the device.
        self.tunnels.remove(&circuit);
    }

    fn directory(&mut self, _device: &AttestedDevice) -> Vec<u8> {
        let tun = self.opening.and_then(|c| self.tunnels.get(&c));
        let (host, workspaces) = match tun {
            Some(tun) => match tun.ctx.view(true) {
                Ok(view) => (view.host_name.clone(), build_directory(&tun.ctx, &view)),
                Err(_) => (None, Vec::new()),
            },
            None => (None, Vec::new()),
        };
        if let Some(tun) = tun {
            let _ = tun.jobs.try_send(Job::Baseline(workspaces.clone()));
        }
        let text = |s: String| {
            DisplayText::try_from(s)
                .unwrap_or_else(|_| DisplayText::try_from("Host".to_owned()).expect("static"))
        };
        DirectoryMessage::Snapshot(DirectorySnapshot {
            seq: 0,
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
}

/// Installs the service on the uplink (a no-op unless the debug-only uplink switch is on).
/// Returns false while the Host identity is not ready yet, so the caller tries again later.
/// Until P3a.10 supplies the real policy every device is welcomed with `Read`.
pub(super) fn install(
    coordinator: &Weak<Coordinator>,
    identity: impl FnOnce() -> Option<(Identity, [u8; 16])>,
) -> bool {
    if !uplink::enabled() {
        return true;
    }
    let Some(contract_hash) = uplink::contract_hash() else {
        return true;
    };
    let Some((identity, host_id)) = identity() else {
        return false;
    };
    let cell = Arc::new(OnceLock::new());
    let service = HostService {
        coordinator: coordinator.clone(),
        handle: cell.clone(),
        tunnels: HashMap::new(),
        opening: None,
    };
    let policy: Box<dyn Policy> = Box::new(AutoRead {
        host_access_epoch: 0,
        runtime_generation: 0,
    });
    let config = Config {
        identity,
        host_id,
        contract_hash,
    };
    if let Some(handle) = uplink::install_tunnels(config, policy, Box::new(service)) {
        let _ = cell.set(handle);
    }
    true
}

#[cfg(test)]
#[path = "tunnel_service_tests.rs"]
mod tests;

#[cfg(test)]
pub(super) fn service_for_test(
    coordinator: Weak<Coordinator>,
    handle: Handle,
) -> Box<dyn TunnelService> {
    let cell = Arc::new(OnceLock::new());
    let _ = cell.set(handle);
    Box::new(HostService {
        coordinator,
        handle: cell,
        tunnels: HashMap::new(),
        opening: None,
    })
}
