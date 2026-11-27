//! Chat AI workspace service. Execution (CLI processes, the thread store) lives on
//! the Host; remote clients only send intents and receive a stream. The engine runs
//! on its own thread with a Tokio runtime; ingress and local IPC (std threads)
//! talk to it through a job channel. Every operation is scoped to the channel's
//! grant workspace, and the working directory always comes from the Host store.
use lomi_chat::{
    cli,
    engine::{Engine, EventSink, Hooks},
    settings::{self, Permissions, Workspace},
    store::{self, MessageState, Role, ThreadKind, ThreadStreamEvent, ThreadSummary},
};
use lomi_remote_protocol::{
    CHAT_MESSAGE_CONTENT_BYTES, CHAT_STREAM_TEXT_BYTES, Capability, CapabilitySet, ChatEffort,
    ChatKind, ChatMessage, ChatMessageContent, ChatMessageId, ChatMessageState, ChatModel,
    ChatModelId, ChatName, ChatPermissions, ChatProvider, ChatProviderId, ChatRole,
    ChatSnapshotPart, ChatStopReason, ChatStreamFrame, ChatStreamText, ChatThread, ChatThreadId,
    ChatTitle, ChatWorkspaceMode, DecimalU64, Effect, ErrorCode, ErrorDetails, RemoteError,
    WorkspaceId,
    ipc::ChatLevel,
    message_framing::MAX_FRAGMENT_PAYLOAD_LEN,
    rpc::{BoundedList, DisplayText, RpcCall, RpcResult, SubscriptionId},
    streams::ResyncReason,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    io::Write,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};

const SEND_LIMIT: (usize, Duration) = (20, Duration::from_secs(60));
const CREATE_LIMIT: (usize, Duration) = (30, Duration::from_secs(3600));
const QUEUE_FRAMES: usize = 128;
const QUEUE_BYTES: usize = 1024 * 1024;
const AUDIT_MAX_LINES: usize = 10_000;
const AUDIT_MAX_AGE_MS: u64 = 30 * 24 * 3600 * 1000;
const PROVIDERS_TTL: Duration = Duration::from_secs(300);
const STOP_WAIT: Duration = Duration::from_secs(5);

/// Identity of the grant behind a request (limits and audit; never an authority).
#[derive(Clone, Debug)]
pub(super) struct Grant {
    pub capabilities: CapabilitySet,
    pub account: String,
    pub consumer: String,
    pub fingerprint: String,
    pub grant_id: String,
}
impl Grant {
    /// The local owner (CLI/IPC): all chat rights, recorded as `local`.
    fn local() -> Self {
        let caps = ChatLevel::Full.ceiling().expect("full level has a ceiling");
        Self {
            capabilities: caps,
            account: "local".into(),
            consumer: "local".into(),
            fingerprint: String::new(),
            grant_id: String::new(),
        }
    }
    fn has(&self, cap: Capability) -> bool {
        self.capabilities.contains(cap)
    }
}

/// Host-resolved scope of a request; nothing here comes from the client.
#[derive(Clone, Debug)]
pub(super) struct Scope {
    pub workspace: WorkspaceId,
    pub root: PathBuf,
    pub level: ChatLevel,
    /// Workspace fence this request was gated under.
    pub fence: u64,
}

// ---- authorization ------------------------------------------------------

fn permission_level(p: ChatPermissions) -> ChatLevel {
    match p {
        ChatPermissions::ReadOnly => ChatLevel::Send,
        ChatPermissions::Edit => ChatLevel::Edit,
        ChatPermissions::Full => ChatLevel::Full,
    }
}
fn permission_cap(p: ChatPermissions) -> Capability {
    match p {
        ChatPermissions::ReadOnly => Capability::ChatSend,
        ChatPermissions::Edit => Capability::ChatPermissionsEdit,
        ChatPermissions::Full => Capability::ChatPermissionsFull,
    }
}
/// A grant may create or send to a thread of mode `p` only when it carries that
/// mode's capability and the workspace's current level allows the mode.
fn permits(grant: &Grant, level: ChatLevel, p: ChatPermissions) -> bool {
    level >= permission_level(p) && grant.has(permission_cap(p))
}
fn thread_permission(p: Permissions) -> ChatPermissions {
    match p {
        Permissions::ReadOnly => ChatPermissions::ReadOnly,
        Permissions::Edit => ChatPermissions::Edit,
        Permissions::Full => ChatPermissions::Full,
    }
}
fn store_permission(p: ChatPermissions) -> Permissions {
    match p {
        ChatPermissions::ReadOnly => Permissions::ReadOnly,
        ChatPermissions::Edit => Permissions::Edit,
        ChatPermissions::Full => Permissions::Full,
    }
}
fn perm_text(p: ChatPermissions) -> &'static str {
    match p {
        ChatPermissions::ReadOnly => "read-only",
        ChatPermissions::Edit => "edit",
        ChatPermissions::Full => "full",
    }
}

// ---- errors ---------------------------------------------------------------

fn error(code: ErrorCode) -> RemoteError {
    revision_error(code, 0, 0)
}
/// `RevisionConflict` must carry revision details; the real numbers are filled in
/// by `run` once the thread's current revision is known.
fn revision_error(code: ErrorCode, expected: u64, actual: u64) -> RemoteError {
    let details = if code == ErrorCode::RevisionConflict {
        ErrorDetails::Revision(lomi_remote_protocol::RevisionErrorDetails {
            expected_revision: DecimalU64(expected),
            actual_revision: DecimalU64(actual),
        })
    } else {
        ErrorDetails::empty()
    };
    RemoteError::new(
        code,
        matches!(code, ErrorCode::ResourceExhausted),
        Effect::None,
        details,
        None,
    )
    .expect("static safe error")
}
fn unknown_outcome() -> RemoteError {
    RemoteError::new(
        ErrorCode::OutcomeUnknown,
        false,
        Effect::Unknown,
        ErrorDetails::empty(),
        None,
    )
    .expect("static safe error")
}
/// Maps store/engine failure text (never shown to the client) to a protocol code.
fn map_failure(message: &str) -> RemoteError {
    error(if message == store::GONE {
        ErrorCode::ResourceNotFound
    } else if message == store::REUSED {
        ErrorCode::IdempotencyConflict
    } else if message.contains("changed in another view") {
        ErrorCode::RevisionConflict
    } else if message.contains("already waiting")
        || message.contains("Wait for the response")
        || message.contains("Stop the response")
    {
        ErrorCode::ChatBusy
    } else if message.contains("Another Lomi instance") || message.contains("unavailable") {
        ErrorCode::ServiceUnavailable
    } else {
        ErrorCode::InvalidArgument
    })
}

// ---- DTO conversion -------------------------------------------------------

fn to_thread(t: &ThreadSummary) -> Result<ChatThread, RemoteError> {
    let bad = |_| error(ErrorCode::ServiceUnavailable);
    Ok(ChatThread {
        thread_id: ChatThreadId::try_from(t.thread_id.clone()).map_err(bad)?,
        kind: ChatKind::Cli,
        provider_id: ChatProviderId::try_from(t.instance_id.clone()).map_err(bad)?,
        model: ChatModelId::try_from(t.model.clone()).map_err(bad)?,
        title: ChatTitle::try_from(t.title.clone()).map_err(bad)?,
        effort: t
            .effort
            .clone()
            .map(ChatEffort::try_from)
            .transpose()
            .map_err(bad)?,
        permissions: thread_permission(t.permissions),
        workspace_mode: match t.workspace {
            Workspace::Project => ChatWorkspaceMode::Project,
            Workspace::Private => ChatWorkspaceMode::Private,
        },
        revision: DecimalU64(t.revision),
        created_ms: DecimalU64(t.created_ms),
        updated_ms: DecimalU64(t.updated_ms),
        streaming: t.streaming,
    })
}
fn message_state(s: MessageState) -> ChatMessageState {
    match s {
        MessageState::Committed => ChatMessageState::Committed,
        MessageState::Dispatching => ChatMessageState::Dispatching,
        MessageState::Streaming => ChatMessageState::Streaming,
        MessageState::Completed => ChatMessageState::Completed,
        MessageState::Stopped => ChatMessageState::Stopped,
        MessageState::Failed => ChatMessageState::Failed,
        MessageState::Interrupted => ChatMessageState::Interrupted,
    }
}
/// Longest prefix of `text` within `max` bytes that ends on a char boundary.
fn prefix(text: &str, max: usize) -> &str {
    let mut end = max.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}
/// Largest encoded size of one message DTO. A `message` frame and a one-message
/// `thread.get` page stay below the 1 MiB logical cap even after JSON escaping.
const MESSAGE_JSON_BUDGET: usize = 900 * 1024;
/// Largest encoded `thread.get` page (the response envelope adds well under 64 KiB).
const PAGE_JSON_BUDGET: usize = lomi_remote_protocol::message_framing::MAX_MESSAGE_LEN - 64 * 1024;

fn escaped_len(c: char) -> usize {
    match c {
        '"' | '\\' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => 2,
        c if (c as u32) < 0x20 || c as u32 == 0x7f => 6,
        c => c.len_utf8(),
    }
}
/// Longest prefix of `text` whose JSON-escaped form is at most `max` bytes.
fn fit_json(text: &str, max: usize) -> &str {
    let mut used = 0;
    for (i, c) in text.char_indices() {
        used += escaped_len(c);
        if used > max {
            return &text[..i];
        }
    }
    text
}
fn to_message(m: &store::ThreadMessage) -> Result<ChatMessage, RemoteError> {
    let bad = |_| error(ErrorCode::ServiceUnavailable);
    let build = |shown: &str, full: bool| -> Result<ChatMessage, RemoteError> {
        Ok(ChatMessage {
            message_id: ChatMessageId::try_from(m.message_id.clone()).map_err(bad)?,
            seq: DecimalU64(m.seq),
            role: match m.role {
                Role::User => ChatRole::User,
                Role::Assistant => ChatRole::Assistant,
            },
            content: ChatMessageContent::try_from(shown.to_string()).map_err(bad)?,
            truncated: !full,
            state: message_state(m.state),
            provider_id: ChatProviderId::try_from(m.instance_id.clone()).map_err(bad)?,
            model: ChatModelId::try_from(m.model.clone()).map_err(bad)?,
            stream_seq: DecimalU64(m.stream_seq),
            stop_reason: m
                .stop_reason
                .clone()
                .and_then(|r| ChatStopReason::try_from(r).ok()),
            error: m
                .error
                .as_deref()
                .and_then(|e| DisplayText::try_from(prefix(e, 4000).to_string()).ok()),
            created_ms: DecimalU64(m.created_ms),
        })
    };
    // Budget by the encoded size: quotes, newlines and control characters expand.
    let overhead = serde_json::to_vec(&build("", true)?).map_or(0, |v| v.len());
    let capped = prefix(&m.content, CHAT_MESSAGE_CONTENT_BYTES);
    let shown = fit_json(capped, MESSAGE_JSON_BUDGET.saturating_sub(overhead));
    build(shown, shown.len() == m.content.len())
}
/// Drops the oldest messages until the encoded page fits one logical message.
fn fit_page(messages: &mut Vec<ChatMessage>, thread_bytes: usize) -> bool {
    let size = |m: &ChatMessage| serde_json::to_vec(m).map_or(MESSAGE_JSON_BUDGET, |v| v.len() + 1);
    let mut total = thread_bytes + messages.iter().map(size).sum::<usize>();
    let mut trimmed = false;
    while messages.len() > 1 && total > PAGE_JSON_BUDGET {
        total -= size(&messages.remove(0));
        trimmed = true;
    }
    trimmed
}

/// Splits `text` into chunks that respect both the 12 KiB text cap and the plaintext
/// frame size once JSON-escaped (control characters expand up to six times).
fn split_text(text: &str) -> Vec<&str> {
    const ESCAPED_BUDGET: usize = MAX_FRAGMENT_PAYLOAD_LEN - 512;
    let mut out = Vec::new();
    let (mut start, mut raw, mut escaped) = (0, 0, 0);
    for (i, c) in text.char_indices() {
        let e = escaped_len(c);
        if raw + c.len_utf8() > CHAT_STREAM_TEXT_BYTES || escaped + e > ESCAPED_BUDGET {
            out.push(&text[start..i]);
            (start, raw, escaped) = (i, 0, 0);
        }
        raw += c.len_utf8();
        escaped += e;
    }
    if start < text.len() || out.is_empty() {
        out.push(&text[start..]);
    }
    out
}

// ---- stream router ----------------------------------------------------------

struct Snapshot {
    message_id: String,
    state: ChatMessageState,
    stream_seq: u64,
    parts: VecDeque<String>,
    part: u32,
}
impl Snapshot {
    fn new(message_id: String, state: ChatMessageState, stream_seq: u64, text: &str) -> Self {
        Self {
            message_id,
            state,
            stream_seq,
            parts: split_text(text).into_iter().map(str::to_owned).collect(),
            part: 0,
        }
    }
    fn next(&mut self) -> Option<ChatStreamFrame> {
        let text = self.parts.pop_front()?;
        let part = self.part;
        self.part += 1;
        Some(ChatStreamFrame::Snapshot {
            message_id: ChatMessageId::try_from(self.message_id.clone()).ok()?,
            state: self.state,
            stream_seq: DecimalU64(self.stream_seq),
            part: ChatSnapshotPart::try_from(part.min(170)).ok()?,
            last: self.parts.is_empty(),
            text: ChatStreamText::try_from(text).ok()?,
        })
    }
}

#[derive(Default)]
struct Queue {
    snapshot: Option<Snapshot>,
    frames: VecDeque<(ChatStreamFrame, usize)>,
    bytes: usize,
    /// Overflowed: the next poll yields `resync`, after which the sub is dead.
    resync: bool,
    dead: bool,
}
struct SubShared {
    workspace: String,
    thread: Option<String>,
    queue: Mutex<Queue>,
}
impl SubShared {
    fn push(&self, frame: ChatStreamFrame, size: usize) {
        let Ok(mut q) = self.queue.lock() else { return };
        if q.dead || q.resync {
            return;
        }
        if q.frames.len() >= QUEUE_FRAMES || q.bytes + size > QUEUE_BYTES {
            q.frames.clear();
            q.snapshot = None;
            q.bytes = 0;
            q.resync = true;
            return;
        }
        q.bytes += size;
        q.frames.push_back((frame, size));
    }
}

/// The connection's chat subscription (one slot per connection).
pub(super) struct ChatSub {
    shared: Arc<SubShared>,
}
impl ChatSub {
    /// Next frame in order: pending snapshot parts, then queued frames, then
    /// `resync` once after an overflow. None while idle.
    pub(super) fn poll(&self) -> Option<ChatStreamFrame> {
        let mut q = self.shared.queue.lock().ok()?;
        if q.dead {
            return None;
        }
        if q.resync {
            q.dead = true;
            return Some(ChatStreamFrame::Resync {
                reason: ResyncReason::SubscriberOverflow,
            });
        }
        if let Some(snapshot) = q.snapshot.as_mut() {
            if let Some(frame) = snapshot.next() {
                return Some(frame);
            }
            q.snapshot = None;
        }
        let (frame, size) = q.frames.pop_front()?;
        q.bytes -= size;
        Some(frame)
    }
    /// After an overflow the subscription is finished and the connection drops it.
    pub(super) fn is_dead(&self) -> bool {
        self.shared.queue.lock().map(|q| q.dead).unwrap_or(true)
    }
}

struct Active {
    thread: String,
    text: String,
    /// Host frame counter; equals the engine's `seq` unless a delta had to be split.
    seq: u64,
}
#[derive(Default)]
struct RouterState {
    subs: Vec<Weak<SubShared>>,
    active: HashMap<String, Active>,
    /// Recently finished message ids, so a late `begin` cannot leak an entry.
    done: VecDeque<String>,
    thread_workspace: HashMap<String, String>,
    /// (consumer id, grant id) behind each running generation, by thread.
    origins: HashMap<String, (String, String)>,
}
#[derive(Default)]
struct Router(Mutex<RouterState>);

fn frame_size(frame: &ChatStreamFrame) -> usize {
    256 + match frame {
        ChatStreamFrame::Delta { text, .. } => text.as_str().len(),
        ChatStreamFrame::Message { message } => message.content.as_str().len(),
        _ => 0,
    }
}

impl Router {
    fn lock(&self) -> std::sync::MutexGuard<'_, RouterState> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn deliver(
        state: &mut RouterState,
        workspace: &str,
        thread: Option<&str>,
        frame: ChatStreamFrame,
    ) {
        state.subs.retain(|w| w.strong_count() > 0);
        let size = frame_size(&frame);
        for sub in state.subs.iter().filter_map(Weak::upgrade) {
            let wanted = sub.workspace == workspace
                && thread.is_none_or(|t| sub.thread.as_deref() == Some(t));
            if wanted {
                sub.push(frame.clone(), size);
            }
        }
    }
    fn thread_changed(&self, t: &ThreadSummary) {
        let (Some(ws), Ok(thread)) = (t.workspace_id.clone(), to_thread(t)) else {
            return;
        };
        let mut s = self.lock();
        s.thread_workspace.insert(t.thread_id.clone(), ws.clone());
        Self::deliver(&mut s, &ws, None, ChatStreamFrame::Thread { thread });
    }
    fn thread_deleted(&self, workspace: Option<&str>, thread_id: &str) {
        let mut s = self.lock();
        let known = s.thread_workspace.remove(thread_id);
        let Some(ws) = workspace.map(str::to_owned).or(known) else {
            return;
        };
        s.active.retain(|_, a| a.thread != thread_id);
        if let Ok(id) = ChatThreadId::try_from(thread_id.to_owned()) {
            Self::deliver(
                &mut s,
                &ws,
                None,
                ChatStreamFrame::ThreadDeleted { thread_id: id },
            );
        }
    }
    fn set_origin(&self, thread: &str, grant: &Grant) {
        self.lock().origins.insert(
            thread.to_owned(),
            (grant.consumer.clone(), grant.grant_id.clone()),
        );
    }
    fn origin(&self, thread: &str) -> Option<(String, String)> {
        self.lock().origins.get(thread).cloned()
    }
    fn begin(&self, thread: &str, message_id: &str) {
        let mut s = self.lock();
        if !s.done.iter().any(|d| d == message_id) {
            s.active
                .entry(message_id.to_owned())
                .or_insert_with(|| Active {
                    thread: thread.to_owned(),
                    text: String::new(),
                    seq: 0,
                });
        }
    }
    fn delta(&self, workspace: &str, thread: &str, message_id: &str, text: &str) {
        let Ok(id) = ChatMessageId::try_from(message_id.to_owned()) else {
            return;
        };
        let mut s = self.lock();
        if s.done.iter().any(|d| d == message_id) {
            return;
        }
        let entry = s
            .active
            .entry(message_id.to_owned())
            .or_insert_with(|| Active {
                thread: thread.to_owned(),
                text: String::new(),
                seq: 0,
            });
        entry.text.push_str(text);
        let mut frames = Vec::new();
        for chunk in split_text(text).into_iter().filter(|c| !c.is_empty()) {
            entry.seq += 1;
            if let Ok(chunk) = ChatStreamText::try_from(chunk.to_owned()) {
                frames.push(ChatStreamFrame::Delta {
                    message_id: id,
                    seq: DecimalU64(entry.seq),
                    text: chunk,
                });
            }
        }
        for frame in frames {
            Self::deliver(&mut s, workspace, Some(thread), frame);
        }
    }
    fn finished(&self, workspace: &str, thread: &ThreadSummary, message: &store::ThreadMessage) {
        let mut s = self.lock();
        s.origins.remove(&thread.thread_id);
        s.active.remove(&message.message_id);
        s.done.push_back(message.message_id.clone());
        if s.done.len() > 64 {
            s.done.pop_front();
        }
        if let Ok(message) = to_message(message) {
            Self::deliver(
                &mut s,
                workspace,
                Some(&thread.thread_id),
                ChatStreamFrame::Message { message },
            );
        }
        drop(s);
        self.thread_changed(thread);
    }
    /// Registers a subscription and, atomically with it, captures the snapshot so no
    /// delta is lost or repeated: live text of an in-flight message, else
    /// `stored()` (called under the lock) for the latest assistant message.
    fn subscribe(
        &self,
        workspace: &str,
        thread: Option<&str>,
        stored: impl FnOnce() -> Option<Snapshot>,
    ) -> ChatSub {
        let mut s = self.lock();
        let snapshot = thread.and_then(|t| {
            s.active
                .iter()
                .find(|(_, a)| a.thread == t)
                .map(|(id, a)| {
                    Snapshot::new(id.clone(), ChatMessageState::Streaming, a.seq, &a.text)
                })
                .or_else(stored)
        });
        let shared = Arc::new(SubShared {
            workspace: workspace.to_owned(),
            thread: thread.map(str::to_owned),
            queue: Mutex::new(Queue {
                snapshot,
                ..Queue::default()
            }),
        });
        s.subs.retain(|w| w.strong_count() > 0);
        s.subs.push(Arc::downgrade(&shared));
        ChatSub { shared }
    }
}

struct HostSink {
    workspace: String,
    thread: String,
    router: Arc<Router>,
}
impl EventSink for HostSink {
    fn send(&self, event: ThreadStreamEvent) {
        match event {
            ThreadStreamEvent::Delta {
                message_id, text, ..
            } => self
                .router
                .delta(&self.workspace, &self.thread, &message_id, &text),
            ThreadStreamEvent::Final { thread, message } => {
                self.router.finished(&self.workspace, &thread, &message)
            }
            // The remote chat protocol carries text only; the final message keeps the activity.
            ThreadStreamEvent::Activity { .. } => {}
        }
    }
}

// ---- rate limits ----------------------------------------------------------------

#[derive(Default)]
struct Limits(HashMap<(&'static str, String), VecDeque<Instant>>);
impl Limits {
    /// Records one use; false when `max` uses already happened within `window`.
    fn allow(
        &mut self,
        kind: &'static str,
        consumer: &str,
        now: Instant,
        (max, window): (usize, Duration),
    ) -> bool {
        let uses = self.0.entry((kind, consumer.to_owned())).or_default();
        while uses
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= window)
        {
            uses.pop_front();
        }
        if uses.len() >= max {
            return false;
        }
        uses.push_back(now);
        true
    }
}

// ---- audit ----------------------------------------------------------------------

struct Audit {
    path: PathBuf,
    lines: Mutex<Option<(usize, u64)>>,
    /// Per consumer: window start, rows written, rows dropped in this window.
    denies: Mutex<HashMap<String, (Instant, u32, u32)>>,
}
const DENY_ROWS_PER_MINUTE: u32 = 60;
fn now_ms() -> u64 {
    store::now_ms()
}
impl Audit {
    fn new(dir: &std::path::Path) -> Self {
        Self {
            path: dir.join("audit.jsonl"),
            lines: Mutex::new(None),
            denies: Mutex::default(),
        }
    }
    /// One metadata line; prompt text is never passed in, only its size and hash.
    /// False when the row could not be written.
    fn record(&self, grant: &Grant, workspace: &str, rec: serde_json::Value) -> bool {
        let mut line = serde_json::json!({
            "time": now_ms(),
            "account": grant.account,
            "consumer": grant.consumer,
            "fingerprint": grant.fingerprint,
            "grant": grant.grant_id,
            "workspace": workspace,
        });
        if let (Some(base), Some(extra)) = (line.as_object_mut(), rec.as_object()) {
            base.extend(extra.clone());
        }
        let Ok(mut text) = serde_json::to_string(&line) else {
            return false;
        };
        text.push('\n');
        let Ok(mut state) = self.lines.lock() else {
            return false;
        };
        if store_reject_link(&self.path).is_err() {
            return false;
        }
        let (count, first) = state.get_or_insert_with(|| self.scan());
        let now = now_ms();
        if *count >= AUDIT_MAX_LINES
            || (*count > 0 && now.saturating_sub(*first) > AUDIT_MAX_AGE_MS)
        {
            // A failed rename keeps the counters so the next write retries it.
            if std::fs::rename(&self.path, self.path.with_extension("jsonl.1")).is_ok() {
                (*count, *first) = (0, now);
            }
        }
        if *count == 0 {
            *first = now;
        }
        let written = open_private(&self.path)
            .and_then(|mut f| f.write_all(text.as_bytes()))
            .is_ok();
        if written {
            *count += 1;
        }
        written
    }
    /// Deny rows are best effort and rate limited per consumer: at most
    /// `DENY_ROWS_PER_MINUTE` a minute, then one summary row with the dropped count.
    fn record_deny(&self, grant: &Grant, workspace: &str, rec: serde_json::Value) {
        let Ok(mut denies) = self.denies.lock() else {
            return;
        };
        let entry = denies
            .entry(grant.consumer.clone())
            .or_insert((Instant::now(), 0, 0));
        let mut summary = None;
        if entry.0.elapsed() >= Duration::from_secs(60) {
            summary = Some(entry.2).filter(|dropped| *dropped > 0);
            *entry = (Instant::now(), 0, 0);
        }
        let write = entry.1 < DENY_ROWS_PER_MINUTE;
        if write {
            entry.1 += 1;
        } else {
            entry.2 += 1;
        }
        drop(denies);
        if let Some(dropped) = summary {
            self.record(
                grant,
                workspace,
                serde_json::json!({"op": "deny", "summary": true, "dropped": dropped, "outcome": "coalesced"}),
            );
        }
        if write {
            self.record(grant, workspace, rec);
        }
    }
    /// (line count, time of the first line) of the current file.
    fn scan(&self) -> (usize, u64) {
        let text = std::fs::read_to_string(&self.path).unwrap_or_default();
        let first = text
            .lines()
            .next()
            .and_then(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .and_then(|v| v["time"].as_u64())
            .unwrap_or_else(now_ms);
        (text.lines().count(), first)
    }
    fn tail(&self, limit: usize) -> Vec<String> {
        let text = std::fs::read_to_string(&self.path).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(limit)..]
            .iter()
            .map(|l| (*l).to_owned())
            .collect()
    }
}
fn store_reject_link(path: &std::path::Path) -> Result<(), String> {
    lomi_chat::storage::reject_link(path)
}
fn open_private(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let file = options.open(path)?;
    // Windows has no mode bits; restrict the ACL to the current user instead.
    #[cfg(windows)]
    lomi_chat::storage::private(path, false).map_err(std::io::Error::other)?;
    Ok(file)
}
fn prompt_meta(text: &str) -> serde_json::Value {
    serde_json::json!({"promptBytes": text.len(), "promptSha256": format!("{:x}", Sha256::digest(text.as_bytes()))})
}

// ---- providers ---------------------------------------------------------------------

struct Providers {
    list: Vec<ChatProvider>,
    at: Option<Instant>,
}

// ---- service context ------------------------------------------------------------------

#[cfg(test)]
type TestHook = Arc<dyn Fn() + Send + Sync>;
/// Locates a CLI binary by id.
type Resolver = Arc<dyn Fn(&str) -> Option<PathBuf> + Send + Sync>;
type Job = Box<dyn FnOnce(Ctx) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

#[derive(Clone)]
struct Ctx {
    engine: Engine,
    router: Arc<Router>,
    audit: Arc<Audit>,
    limits: Arc<Mutex<Limits>>,
    providers: Arc<Mutex<Providers>>,
    resolve: Resolver,
    /// Probe CLIs for models and login status (off in tests).
    probe: bool,
    /// Level floor per workspace, set synchronously by `enforce` before any kill
    /// snapshot, so a send racing a disable or lowering cannot outlive it.
    floors: Arc<Mutex<HashMap<String, (ChatLevel, u64)>>>,
    /// Test override for the global authorization lock.
    #[cfg(test)]
    lock_override: Arc<std::sync::atomic::AtomicBool>,
    /// Serializes provider probes (single flight).
    refresh: Arc<tokio::sync::Mutex<()>>,
    refreshes: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(test)]
    after_send: Arc<Mutex<Option<TestHook>>>,
}

async fn blk<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, RemoteError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| error(ErrorCode::ServiceUnavailable))?
        .map_err(|m| map_failure(&m))
}

impl Ctx {
    /// Best-effort row (deny rows are rate limited).
    fn audit(&self, grant: &Grant, workspace: &str, rec: serde_json::Value) {
        if rec["op"] == "deny" {
            self.audit.record_deny(grant, workspace, rec);
        } else {
            self.audit.record(grant, workspace, rec);
        }
    }
    /// Fail-closed row for effects (create/send): without a record the op is refused.
    fn audit_strict(
        &self,
        grant: &Grant,
        workspace: &str,
        rec: serde_json::Value,
    ) -> Result<(), RemoteError> {
        if self.audit.record(grant, workspace, rec) {
            Ok(())
        } else {
            Err(error(ErrorCode::ServiceUnavailable))
        }
    }
    /// The workspace level after any revocation noted since the request was gated.
    /// A floor derived from an older fence than the request's is stale (the owner has
    /// changed the level since) and is ignored; a newer fence always applies.
    fn effective(&self, ws: &str, scope: &Scope) -> ChatLevel {
        let floor = self
            .floors
            .lock()
            .ok()
            .and_then(|f| f.get(ws).copied())
            .filter(|(_, fence)| *fence >= scope.fence)
            .map_or(ChatLevel::Full, |(level, _)| level);
        scope.level.min(floor)
    }
    /// Host authorization is locked or revoking (committed state, cleared on unlock).
    fn is_locked(&self) -> bool {
        #[cfg(test)]
        if self
            .lock_override
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return true;
        }
        self.probe && lomi_host_store::authorization_locked()
    }

    fn deny(&self, grant: &Grant, workspace: &str, op: &str, why: &str) -> RemoteError {
        self.audit(
            grant,
            workspace,
            serde_json::json!({"op": "deny", "denied": op, "outcome": why}),
        );
        error(ErrorCode::ScopeDenied)
    }
    fn limited(&self, grant: &Grant, kind: &'static str, rule: (usize, Duration)) -> bool {
        self.limits
            .lock()
            .map(|mut l| l.allow(kind, &grant.consumer, Instant::now(), rule))
            .unwrap_or(false)
    }

    /// Loads a thread and enforces workspace scoping: another workspace's thread
    /// looks exactly like a missing one.
    async fn scoped_thread(
        &self,
        ws: &str,
        id: &ChatThreadId,
    ) -> Result<ThreadSummary, RemoteError> {
        let (engine, id, ws) = (self.engine.clone(), String::from(*id), ws.to_owned());
        let thread = blk(move || engine.with(|i| i.store.thread(&id))).await?;
        if thread.workspace_id.as_deref() != Some(&ws) {
            return Err(error(ErrorCode::ResourceNotFound));
        }
        Ok(thread)
    }

    async fn refresh_providers(&self) {
        let began = Instant::now();
        let _flight = self.refresh.lock().await;
        // A probe that finished while this caller waited already answers it.
        if self
            .providers
            .lock()
            .is_ok_and(|p| p.at.is_some_and(|at| at >= began))
        {
            return;
        }
        self.refreshes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let ctx = self.clone();
        let Ok(settings) = blk({
            let engine = self.engine.clone();
            move || engine.with(|i| Ok(i.settings.cli_providers.clone()))
        })
        .await
        else {
            return;
        };
        let mut list = Vec::new();
        for p in settings.into_iter().filter(|p| p.enabled) {
            if (ctx.resolve)(&p.cli).is_none() {
                continue;
            }
            let (models, logged_in) = if ctx.probe {
                let models = cli::models(&p.cli, || None).await;
                (models, cli::status(&p.cli).await.signed_in)
            } else {
                (Vec::new(), None)
            };
            let mut efforts: Vec<String> = Vec::new();
            for e in models.iter().flat_map(|m| &m.efforts) {
                if !efforts.contains(e) {
                    efforts.push(e.clone());
                }
            }
            let provider = (|| -> Result<ChatProvider, &'static str> {
                Ok(ChatProvider {
                    provider_id: ChatProviderId::try_from(p.instance_id.clone())?,
                    kind: ChatKind::Cli,
                    name: ChatName::try_from(p.label.clone())?,
                    cli: Some(ChatName::try_from(p.cli.clone())?),
                    models: BoundedList(
                        models
                            .iter()
                            .filter_map(|m| {
                                Some(ChatModel {
                                    model_id: ChatModelId::try_from(m.id.clone()).ok()?,
                                    name: ChatName::try_from(m.label.clone()).ok()?,
                                })
                            })
                            .take(256)
                            .collect(),
                    ),
                    efforts: BoundedList(
                        efforts
                            .into_iter()
                            .filter_map(|e| ChatEffort::try_from(e).ok())
                            .take(16)
                            .collect(),
                    ),
                    logged_in,
                    // Kimi only has an agent-file restriction; the rest get hardened argv.
                    read_only_enforced: p.cli != "kimi",
                })
            })();
            if let Ok(provider) = provider {
                list.push(provider);
            }
        }
        if let Ok(mut cache) = ctx.providers.lock() {
            *cache = Providers {
                list,
                at: Some(Instant::now()),
            };
        }
    }
}

/// Handle to the running service.
struct Handle {
    ctx: Ctx,
    jobs: tokio::sync::mpsc::UnboundedSender<Job>,
    /// The service thread ended (panic or shutdown): the next call restarts it.
    dead: Arc<std::sync::atomic::AtomicBool>,
}
impl Handle {
    fn call<T, F, Fut>(&self, deadline: Instant, mutation: bool, f: F) -> Result<T, RemoteError>
    where
        T: Send + 'static,
        F: FnOnce(Ctx) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
    {
        let (tx, rx) = std::sync::mpsc::channel();
        let job: Job = Box::new(move |ctx| {
            Box::pin(async move {
                let _ = tx.send(f(ctx).await);
            })
        });
        self.jobs.send(job).map_err(|_| {
            self.dead.store(true, std::sync::atomic::Ordering::Release);
            error(ErrorCode::ServiceUnavailable)
        })?;
        rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| {
                if mutation {
                    unknown_outcome()
                } else {
                    error(ErrorCode::DeadlineExceeded)
                }
            })
    }
}

fn start(root: PathBuf, resolve: Resolver, probe: bool) -> Result<Arc<Handle>, RemoteError> {
    let router = Arc::new(Router::default());
    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let resolve_cli = resolve.clone();
    let engine = Engine::restricted(
        root,
        Hooks {
            // E1 has no API providers, so no key is ever read.
            api_key: Box::new(|_| Ok(None)),
            threads_changed: Box::new(move |_, id| {
                let _ = events_tx.send(id.to_owned());
            }),
            resolve_cli: Box::new(move |cli| resolve_cli(cli)),
        },
    );
    // Takes the data-root owner lock now and installs the detected CLI providers.
    let installed: Vec<String> = cli::CLIS
        .into_iter()
        .filter(|id| resolve(id).is_some())
        .map(str::to_owned)
        .collect();
    let dir = engine
        .with(|i| {
            let dir = i.dir.clone();
            settings::detect_cli_providers(&mut i.settings, &dir, &installed)?;
            Ok(dir)
        })
        .map_err(|m| map_failure(&m))?;
    let ctx = Ctx {
        engine,
        router,
        audit: Arc::new(Audit::new(&dir)),
        limits: Arc::default(),
        providers: Arc::new(Mutex::new(Providers {
            list: Vec::new(),
            at: None,
        })),
        resolve,
        probe,
        floors: Arc::default(),
        #[cfg(test)]
        lock_override: Arc::default(),
        refresh: Arc::default(),
        refreshes: Arc::default(),
        #[cfg(test)]
        after_send: Arc::default(),
    };
    let dead = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let thread_dead = dead.clone();
    let (jobs, mut rx) = tokio::sync::mpsc::unbounded_channel::<Job>();
    let thread_ctx = ctx.clone();
    std::thread::Builder::new()
        .name("lomi-chat".into())
        .spawn(move || {
            // A panic must not leave a permanently dead slot: it marks the handle dead
            // and the next call starts a fresh service.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                runtime.block_on(async move {
                    let ctx = thread_ctx;
                    let changes = ctx.clone();
                    tokio::spawn(async move {
                        while let Some(id) = events_rx.recv().await {
                            let (engine, router) = (changes.engine.clone(), changes.router.clone());
                            let _ = tokio::task::spawn_blocking(move || {
                                match engine.with(|i| i.store.thread(&id)) {
                                    Ok(thread) => router.thread_changed(&thread),
                                    Err(_) => router.thread_deleted(None, &id),
                                }
                            })
                            .await;
                        }
                    });
                    let first = ctx.clone();
                    tokio::spawn(async move { first.refresh_providers().await });
                    while let Some(job) = rx.recv().await {
                        tokio::spawn(job(ctx.clone()));
                    }
                    // The Host is gone: stop every CLI so nothing outlives it.
                    ctx.engine.kill_cli_groups();
                });
            }));
            thread_dead.store(true, std::sync::atomic::Ordering::Release);
        })
        .map_err(|_| error(ErrorCode::ServiceUnavailable))?;
    Ok(Arc::new(Handle { ctx, jobs, dead }))
}

// ---- public facade -----------------------------------------------------------------------

/// Applies revocations the Host store noted (any path that fenced, unshared,
/// removed or locked authorization) so generations never outlive access.
fn spawn_watchdog(handle: std::sync::Weak<Handle>) {
    let _ = std::thread::Builder::new()
        .name("lomi-chat-revoke".into())
        .spawn(move || {
            loop {
                std::thread::sleep(Duration::from_millis(500));
                let Some(h) = handle.upgrade() else { return };
                if h.dead.load(std::sync::atomic::Ordering::Acquire) {
                    return;
                }
                h.apply(lomi_host_store::take_chat_revocations());
            }
        });
}

/// Lazily started chat service of one Host profile.
#[derive(Default)]
pub(super) struct Chat {
    root: Option<PathBuf>,
    #[cfg(test)]
    resolve: Option<Resolver>,
    handle: Mutex<Option<Arc<Handle>>>,
}

impl Chat {
    /// `root` is `<profile>/chat`; nothing is created until the first chat call.
    pub(super) fn at(root: PathBuf) -> Self {
        Self {
            root: Some(root),
            ..Self::default()
        }
    }
    fn handle(&self) -> Result<Arc<Handle>, RemoteError> {
        let mut slot = self
            .handle
            .lock()
            .map_err(|_| error(ErrorCode::ServiceUnavailable))?;
        if let Some(h) = slot.as_ref() {
            if !h.dead.load(std::sync::atomic::Ordering::Acquire) {
                return Ok(h.clone());
            }
            // Dead service: release its CLIs and storage lock, then restart below.
            h.ctx.engine.kill_cli_groups();
            *slot = None;
        }
        let root = self
            .root
            .clone()
            .ok_or_else(|| error(ErrorCode::ServiceUnavailable))?;
        #[cfg(test)]
        let (resolve, probe): (Resolver, bool) = match &self.resolve {
            Some(r) => (r.clone(), false),
            None => (Arc::new(lomi_chat::cli_bin::resolve), true),
        };
        #[cfg(not(test))]
        let (resolve, probe): (Resolver, bool) = (Arc::new(lomi_chat::cli_bin::resolve), true);
        let handle = start(root, resolve, probe)?;
        if probe {
            // Revocations noted before the service existed concern nothing running.
            let _ = lomi_host_store::take_chat_revocations();
            spawn_watchdog(Arc::downgrade(&handle));
        }
        *slot = Some(handle.clone());
        Ok(handle)
    }
    /// The running service, without starting it (revocation hooks).
    fn running(&self) -> Option<Arc<Handle>> {
        self.handle.lock().ok()?.clone()
    }

    /// Runs one remote chat request. `sub` is the connection's single subscription slot.
    pub(super) fn execute(
        &self,
        call: &RpcCall,
        grant: &Grant,
        scope: &Scope,
        deadline: Instant,
        sub: &mut Option<ChatSub>,
    ) -> Result<RpcResult, RemoteError> {
        let ws = String::from(scope.workspace);
        let handle = self.handle()?;
        if scope.level == ChatLevel::Off {
            handle.ctx.audit(
                grant,
                &ws,
                serde_json::json!({"op": "deny", "outcome": "chat disabled"}),
            );
            return Err(error(ErrorCode::ScopeDenied));
        }
        let (g, s, call) = (grant.clone(), scope.clone(), call.clone());
        let mutation = lomi_remote_protocol::is_chat_mutation(call.method());
        let reply = handle.call(deadline, mutation, move |ctx| async move {
            run(&ctx, &g, &s, call).await
        })??;
        match reply {
            Reply::Result(r) => Ok(r),
            Reply::Subscribed(new, result) => {
                *sub = Some(new);
                Ok(result)
            }
        }
    }

    /// Stops generations of `workspace` whose mode exceeds `level` (`Off` stops all).
    pub(super) fn enforce_level(&self, workspace: WorkspaceId, level: ChatLevel, fence: u64) {
        if let Some(h) = self.running() {
            h.enforce(String::from(workspace), level, fence);
        }
    }
    /// Host logout/revoke: every generation stops.
    pub(super) fn kill_all(&self) {
        if let Some(h) = self.running() {
            h.kill(|_, _| true);
        }
    }
    /// Daemon shutdown: no CLI process group may outlive the Host.
    pub(super) fn shutdown(&self) {
        if let Some(h) = self.running() {
            h.ctx.engine.kill_cli_groups();
        }
    }
    /// Stops generations started by a revoked grant. The Host currently has no signal
    /// that distinguishes a revoked grant/consumer from a disconnect, so nothing calls
    /// this outside tests; it is ready for such a signal.
    #[allow(dead_code)]
    pub(super) fn revoke_origin(&self, consumer: Option<&str>, grant: Option<&str>) {
        if let Some(h) = self.running() {
            let (c, g) = (consumer.map(str::to_owned), grant.map(str::to_owned));
            h.kill(move |_, origin| {
                origin.is_some_and(|(oc, og)| {
                    c.as_deref().is_none_or(|c| c == oc) && g.as_deref().is_none_or(|g| g == og)
                })
            });
        }
    }

    pub(super) fn local_threads(
        &self,
        workspace: WorkspaceId,
    ) -> Result<Vec<ThreadSummary>, RemoteError> {
        let h = self.handle()?;
        let ws = String::from(workspace);
        h.call(
            Instant::now() + Duration::from_secs(10),
            false,
            move |ctx| async move {
                blk(move || ctx.engine.with(|i| i.store.list_workspace(&ws))).await
            },
        )?
    }
    pub(super) fn local_stop(&self, thread_id: &str) -> Result<ThreadSummary, RemoteError> {
        let h = self.handle()?;
        let id = thread_id.to_owned();
        h.call(
            Instant::now() + Duration::from_secs(15),
            false,
            move |ctx| async move {
                let thread = {
                    let (e, id) = (ctx.engine.clone(), id.clone());
                    blk(move || e.with(|i| i.store.thread(&id))).await?
                };
                ctx.audit(
                    &Grant::local(),
                    thread.workspace_id.as_deref().unwrap_or(""),
                    serde_json::json!({"op": "stop", "thread": id, "outcome": "ok"}),
                );
                stop_and_wait(&ctx, &id).await?;
                let e = ctx.engine.clone();
                blk(move || e.with(|i| i.store.thread(&id))).await
            },
        )?
    }
    pub(super) fn local_delete(&self, thread_id: &str) -> Result<(), RemoteError> {
        let h = self.handle()?;
        let id = thread_id.to_owned();
        h.call(
            Instant::now() + Duration::from_secs(30),
            true,
            move |ctx| async move {
                let thread = {
                    let (e, id) = (ctx.engine.clone(), id.clone());
                    blk(move || e.with(|i| i.store.thread(&id))).await?
                };
                let op = format!("local-{}", uuid::Uuid::new_v4());
                delete_thread(
                    &ctx,
                    &Grant::local(),
                    thread.workspace_id.as_deref().unwrap_or(""),
                    &thread,
                    &op,
                    None,
                )
                .await
            },
        )?
    }
    pub(super) fn audit_tail(&self, limit: usize) -> Result<Vec<String>, RemoteError> {
        let h = self.handle()?;
        Ok(h.ctx.audit.tail(limit))
    }
    /// Records an owner-side level change (`chat enable/disable/ceiling`).
    pub(super) fn audit_level(&self, workspace: WorkspaceId, level: ChatLevel) {
        if let Ok(h) = self.handle() {
            h.ctx.audit(
                &Grant::local(),
                &String::from(workspace),
                serde_json::json!({"op": "level", "outcome": level.as_str()}),
            );
        }
    }
}

impl Handle {
    /// Lowers the workspace floor right now, then stops generations above `level`.
    fn enforce(&self, workspace: String, level: ChatLevel, fence: u64) {
        if let Ok(mut floors) = self.ctx.floors.lock() {
            // Bound to the fence it was derived from; an older record never
            // overrides a newer one, equal fences keep the lower level.
            let entry = floors.entry(workspace.clone()).or_insert((level, fence));
            if fence > entry.1 {
                *entry = (level, fence);
            } else if fence == entry.1 {
                entry.0 = entry.0.min(level);
            }
        }
        self.kill(move |t, _| {
            t.workspace_id.as_deref() == Some(&workspace)
                && (level == ChatLevel::Off
                    || permission_level(thread_permission(t.permissions)) > level)
        });
    }
    fn apply(&self, revoked: lomi_host_store::ChatRevocations) {
        if revoked.all {
            self.kill(|_, _| true);
        }
        for (workspace, level, fence) in revoked.workspaces {
            self.enforce(String::from(workspace), level, fence);
        }
    }
    /// Stops every running generation matching `pred(thread, origin)`, in the background.
    fn kill(&self, pred: impl Fn(&ThreadSummary, Option<(&str, &str)>) -> bool + Send + 'static) {
        let _ = self.jobs.send(Box::new(move |ctx| {
            Box::pin(async move {
                let e = ctx.engine.clone();
                let Ok(running) = blk(move || e.with(|i| i.store.streaming_threads())).await else {
                    return;
                };
                let matching: Vec<_> = running
                    .into_iter()
                    .filter_map(|t| {
                        let origin = ctx.router.origin(&t.thread_id);
                        pred(&t, origin.as_ref().map(|(c, g)| (c.as_str(), g.as_str())))
                            .then_some((t, origin))
                    })
                    .collect();
                for (t, origin) in matching {
                    let (consumer, grant_id) = origin.unwrap_or_default();
                    ctx.audit(
                        &Grant::local(),
                        t.workspace_id.as_deref().unwrap_or(""),
                        serde_json::json!({"op": "kill", "thread": t.thread_id, "permissions": perm_text(thread_permission(t.permissions)), "originConsumer": consumer, "originGrant": grant_id, "outcome": "access revoked"}),
                    );
                    let _ = stop_and_wait(&ctx, &t.thread_id).await;
                }
            })
        }));
    }
}

enum Reply {
    Result(RpcResult),
    Subscribed(ChatSub, RpcResult),
}

async fn stop_and_wait(ctx: &Ctx, id: &str) -> Result<(), RemoteError> {
    let (engine, tid) = (ctx.engine.clone(), id.to_owned());
    blk(move || engine.stop(&tid)).await?;
    let start = Instant::now();
    while ctx.engine.is_active(id).unwrap_or(false) {
        if start.elapsed() > STOP_WAIT {
            return Err(error(ErrorCode::ChatBusy));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Ok(())
}

/// Deletes a thread (stopping it first). `expected` is checked before anything stops.
async fn delete_thread(
    ctx: &Ctx,
    grant: &Grant,
    ws: &str,
    thread: &ThreadSummary,
    operation: &str,
    expected: Option<u64>,
) -> Result<(), RemoteError> {
    let id = thread.thread_id.clone();
    let request = delete_request(&id, expected);
    let mut revision = expected.unwrap_or(thread.revision);
    if thread.streaming {
        if expected.is_some_and(|r| r != thread.revision) {
            return Err(error(ErrorCode::RevisionConflict));
        }
        stop_and_wait(ctx, &id).await?;
        // The stop committed the outcome and bumped the revision.
        let (engine, tid) = (ctx.engine.clone(), id.clone());
        revision = blk(move || engine.with(|i| i.store.thread(&tid)))
            .await
            .map_or(revision, |t| t.revision);
    }
    let (engine, tid, op) = (ctx.engine.clone(), id.clone(), operation.to_owned());
    let outcome = blk(move || {
        engine.with(|i| {
            i.store.delete_receipted(
                &op,
                &request,
                &store::ThreadDelete {
                    thread_id: tid,
                    expected_revision: revision,
                },
            )
        })
    })
    .await;
    let audit = |outcome: &str| {
        ctx.audit(
            grant,
            ws,
            serde_json::json!({"op": "delete", "thread": id, "provider": thread.instance_id, "permissions": perm_text(thread_permission(thread.permissions)), "outcome": outcome}),
        )
    };
    match outcome {
        Ok(()) => {
            audit("ok");
            ctx.router.thread_deleted(Some(ws), &id);
            Ok(())
        }
        Err(e) => {
            audit("error");
            Err(e)
        }
    }
}
fn delete_request(thread_id: &str, expected: Option<u64>) -> String {
    serde_json::json!({"delete": thread_id, "rev": expected}).to_string()
}

async fn run(ctx: &Ctx, grant: &Grant, scope: &Scope, call: RpcCall) -> Result<Reply, RemoteError> {
    let target = match &call {
        RpcCall::ChatSend(p) => Some((p.thread_id, p.expected_revision.0)),
        RpcCall::ChatThreadUpdate(p) => Some((p.thread_id, p.expected_revision.0)),
        RpcCall::ChatThreadDelete(p) => Some((p.thread_id, p.expected_revision.0)),
        _ => None,
    };
    let ws = String::from(scope.workspace);
    match (run_call(ctx, grant, scope, call).await, target) {
        (Err(e), Some((id, expected))) if e.code() == ErrorCode::RevisionConflict => {
            let actual = ctx.scoped_thread(&ws, &id).await.map_or(0, |t| t.revision);
            Err(revision_error(
                ErrorCode::RevisionConflict,
                expected,
                actual,
            ))
        }
        (result, _) => result,
    }
}

async fn run_call(
    ctx: &Ctx,
    grant: &Grant,
    scope: &Scope,
    call: RpcCall,
) -> Result<Reply, RemoteError> {
    let ws = String::from(scope.workspace);
    let level = ctx.effective(&ws, scope);
    if level == ChatLevel::Off || ctx.is_locked() {
        return Err(ctx.deny(grant, &ws, call.method().as_str(), "chat disabled"));
    }
    let ok = |r| Ok(Reply::Result(r));
    match call {
        RpcCall::ChatProviders(_) => {
            let stale = ctx
                .providers
                .lock()
                .map(|p| p.at.is_none_or(|t| t.elapsed() > PROVIDERS_TTL))
                .unwrap_or(true);
            if stale {
                ctx.refresh_providers().await;
            }
            let list = ctx
                .providers
                .lock()
                .map(|p| p.list.clone())
                .unwrap_or_default();
            ok(RpcResult::ChatProviders(
                lomi_remote_protocol::ChatProvidersResult {
                    providers: BoundedList(list),
                },
            ))
        }
        RpcCall::ChatThreadsList(p) => {
            let (e, w) = (ctx.engine.clone(), ws.clone());
            let all = blk(move || e.with(|i| i.store.list_workspace(&w))).await?;
            let offset = p
                .cursor
                .as_ref()
                .map(|c| c.as_str().parse::<usize>())
                .transpose()
                .map_err(|_| error(ErrorCode::InvalidArgument))?
                .unwrap_or(0);
            let limit = p.limit.0 as usize;
            let page: Vec<_> = all.iter().skip(offset).take(limit).collect();
            let next = (offset + page.len() < all.len()).then(|| (offset + page.len()).to_string());
            ok(RpcResult::ChatThreadsList(
                lomi_remote_protocol::ChatThreadsListResult {
                    threads: BoundedList(
                        page.into_iter().map(to_thread).collect::<Result<_, _>>()?,
                    ),
                    next_cursor: next
                        .and_then(|n| lomi_remote_protocol::ChatCursor::try_from(n).ok()),
                },
            ))
        }
        RpcCall::ChatThreadGet(p) => {
            let thread = ctx.scoped_thread(&ws, &p.thread_id).await?;
            let (e, id) = (ctx.engine.clone(), thread.thread_id.clone());
            let (before, limit) = (p.before_seq.map(|s| s.0), p.limit.0 as usize);
            let (messages, more) =
                blk(move || e.with(|i| i.store.messages_page(&id, before, limit))).await?;
            let mut out: Vec<ChatMessage> =
                messages.iter().map(to_message).collect::<Result<_, _>>()?;
            let thread_dto = to_thread(&thread)?;
            let trimmed = fit_page(
                &mut out,
                serde_json::to_vec(&thread_dto).map_or(0, |v| v.len()),
            );
            ok(RpcResult::ChatThreadGet(
                lomi_remote_protocol::ChatThreadGetResult {
                    thread: thread_dto,
                    messages: BoundedList(out),
                    has_more: more || trimmed,
                },
            ))
        }
        RpcCall::ChatSubscribe(p) => {
            let thread = match &p.thread_id {
                Some(id) => Some(ctx.scoped_thread(&ws, id).await?),
                None => None,
            };
            let (e, r, w) = (ctx.engine.clone(), ctx.router.clone(), ws.clone());
            let tid = thread.as_ref().map(|t| t.thread_id.clone());
            let sub = blk(move || {
                Ok(r.subscribe(&w, tid.as_deref(), || {
                    let id = tid.as_deref()?;
                    let m = e.with(|i| i.store.last_message(id)).ok()??;
                    (m.role == Role::Assistant).then(|| {
                        Snapshot::new(
                            m.message_id,
                            message_state(m.state),
                            m.stream_seq,
                            &m.content,
                        )
                    })
                }))
            })
            .await?;
            // `after` is advisory: the live text (or the stored latest message) is always
            // sent as a snapshot, which also covers a cursor that matches the live message.
            let result = RpcResult::ChatSubscribe(lomi_remote_protocol::ChatSubscribeResult {
                subscription_id: SubscriptionId::try_from(format!(
                    "chat-{}",
                    uuid::Uuid::new_v4().simple()
                ))
                .map_err(|_| error(ErrorCode::ServiceUnavailable))?,
            });
            Ok(Reply::Subscribed(sub, result))
        }
        RpcCall::ChatThreadCreate(p) => {
            let op = String::from(p.operation_id);
            let level_ok = permits(grant, level, p.permissions);
            if !level_ok {
                return Err(ctx.deny(grant, &ws, "create", "permission not granted"));
            }
            let provider = p.provider_id.as_str().to_owned();
            let known = ctx
                .providers
                .lock()
                .map(|c| {
                    c.list
                        .iter()
                        .find(|x| x.provider_id.as_str() == provider)
                        .cloned()
                })
                .unwrap_or(None);
            if ctx.providers.lock().map(|c| c.at.is_none()).unwrap_or(true) {
                ctx.refresh_providers().await;
            }
            let known = known.or_else(|| {
                ctx.providers.lock().ok().and_then(|c| {
                    c.list
                        .iter()
                        .find(|x| x.provider_id.as_str() == provider)
                        .cloned()
                })
            });
            let Some(known) = known else {
                return Err(error(ErrorCode::InvalidArgument));
            };
            if !known.models.0.is_empty() && !known.models.0.iter().any(|m| m.model_id == p.model) {
                return Err(error(ErrorCode::InvalidArgument));
            }
            let request = store::ThreadCreate {
                operation_id: op,
                project: scope.root.to_string_lossy().into_owned(),
                instance_id: provider.clone(),
                model: p.model.as_str().to_owned(),
                title: p
                    .title
                    .as_ref()
                    .map_or("New chat".to_owned(), |t| t.as_str().to_owned()),
                cwd: Some(scope.root.to_string_lossy().into_owned()),
                effort: p.effort.as_ref().map(|e| e.as_str().to_owned()),
                workspace_id: Some(ws.clone()),
                permissions: store_permission(p.permissions),
                workspace: match p.workspace_mode {
                    ChatWorkspaceMode::Project => Workspace::Project,
                    ChatWorkspaceMode::Private => Workspace::Private,
                },
            };
            // Intent row first: without an audit record the thread is not created.
            ctx.audit_strict(
                grant,
                &ws,
                serde_json::json!({"op": "create", "provider": provider, "model": request.model, "permissions": perm_text(p.permissions), "outcome": "intent"}),
            )?;
            let (e, req) = (ctx.engine.clone(), request.clone());
            let replay = blk(move || e.with(|i| i.store.create_replay(&req))).await?;
            let thread = match replay {
                Some(t) => t,
                None => {
                    if !ctx.limited(grant, "create", CREATE_LIMIT) {
                        ctx.audit(grant, &ws, serde_json::json!({"op": "deny", "denied": "create", "outcome": "rate limit"}));
                        return Err(error(ErrorCode::ResourceExhausted));
                    }
                    let (e, req) = (ctx.engine.clone(), request);
                    let title = store::valid_title(&req.title).map_err(|m| map_failure(&m))?;
                    blk(move || e.with(|i| i.store.create(&req, &title, ThreadKind::Cli))).await?
                }
            };
            ctx.audit(
                grant,
                &ws,
                serde_json::json!({"op": "create", "thread": thread.thread_id, "provider": provider, "model": thread.model, "effort": thread.effort, "permissions": perm_text(thread_permission(thread.permissions)), "outcome": "ok"}),
            );
            ctx.router.thread_changed(&thread);
            ok(RpcResult::ChatThreadCreate(
                lomi_remote_protocol::ChatThreadResult {
                    thread: to_thread(&thread)?,
                },
            ))
        }
        RpcCall::ChatThreadUpdate(p) => {
            let thread = ctx.scoped_thread(&ws, &p.thread_id).await?;
            if !permits(grant, level, thread_permission(thread.permissions)) {
                return Err(ctx.deny(grant, &ws, "update", "thread permission above grant"));
            }
            let op = String::from(p.operation_id);
            let request =
                serde_json::to_string(&p).map_err(|_| error(ErrorCode::InvalidArgument))?;
            let update = store::ThreadUpdate {
                thread_id: thread.thread_id.clone(),
                expected_revision: p.expected_revision.0,
                title: p.title.as_ref().map(|t| t.as_str().to_owned()),
                instance_id: None,
                model: p.model.as_ref().map(|m| m.as_str().to_owned()),
                effort: p
                    .effort
                    .as_ref()
                    .map(|e| e.as_ref().map(|e| e.as_str().to_owned())),
                permissions: None,
            };
            let e = ctx.engine.clone();
            let updated = blk(move || {
                e.with(|i| i.store.update_receipted(&op, &request, &update, |_| Ok(())))
            })
            .await?;
            ctx.audit(
                grant,
                &ws,
                serde_json::json!({"op": "update", "thread": updated.thread_id, "provider": updated.instance_id, "model": updated.model, "effort": updated.effort, "permissions": perm_text(thread_permission(updated.permissions)), "outcome": "ok"}),
            );
            ctx.router.thread_changed(&updated);
            ok(RpcResult::ChatThreadUpdate(
                lomi_remote_protocol::ChatThreadResult {
                    thread: to_thread(&updated)?,
                },
            ))
        }
        RpcCall::ChatThreadDelete(p) => {
            let op = String::from(p.operation_id);
            let id = String::from(p.thread_id);
            match ctx.scoped_thread(&ws, &p.thread_id).await {
                Ok(thread) => {
                    delete_thread(ctx, grant, &ws, &thread, &op, Some(p.expected_revision.0))
                        .await?
                }
                Err(missing) => {
                    // A retry finds the thread gone; the durable tombstone of this
                    // exact operation answers it, anything else stays not-found.
                    let request = delete_request(&id, Some(p.expected_revision.0));
                    let e = ctx.engine.clone();
                    // Only a stored tombstone of this exact operation answers a retry;
                    // this path never deletes (the thread may belong to another workspace).
                    let replayed = blk(move || e.with(|i| i.store.delete_replayed(&op, &request)))
                        .await
                        .map(|found| if found { Ok(()) } else { Err(()) })
                        .unwrap_or(Err(()));
                    if replayed.is_err() {
                        return Err(missing);
                    }
                }
            }
            ok(RpcResult::ChatThreadDelete(
                lomi_remote_protocol::ChatThreadDeleteResult {},
            ))
        }
        RpcCall::ChatSend(p) => {
            let thread = ctx.scoped_thread(&ws, &p.thread_id).await?;
            let perm = thread_permission(thread.permissions);
            if !permits(grant, level, perm) {
                return Err(ctx.deny(grant, &ws, "send", "thread permission above grant"));
            }
            if !ctx.limited(grant, "send", SEND_LIMIT) {
                ctx.audit(grant, &ws, serde_json::json!({"op": "deny", "denied": "send", "thread": thread.thread_id, "outcome": "rate limit"}));
                return Err(error(ErrorCode::ResourceExhausted));
            }
            let request = store::ThreadSend {
                operation_id: String::from(p.operation_id),
                thread_id: thread.thread_id.clone(),
                expected_revision: p.expected_revision.0,
                instance_id: thread.instance_id.clone(),
                model: thread.model.clone(),
                text: p.text.as_str().to_owned(),
                attachments: vec![],
            };
            let sink = Arc::new(HostSink {
                workspace: ws.clone(),
                thread: thread.thread_id.clone(),
                router: ctx.router.clone(),
            });
            let meta = |outcome: &str| {
                let mut v = serde_json::json!({"op": "send", "thread": thread.thread_id, "provider": thread.instance_id, "model": thread.model, "effort": thread.effort, "permissions": perm_text(perm), "outcome": outcome});
                v.as_object_mut()
                    .unwrap()
                    .extend(prompt_meta(p.text.as_str()).as_object().unwrap().clone());
                v
            };
            // Intent row before anything is spawned; a failed write refuses the send.
            ctx.audit_strict(grant, &ws, meta("intent"))?;
            let accepted = match ctx.engine.send(request, sink).await {
                Ok(a) => a,
                Err(m) => {
                    ctx.audit(grant, &ws, meta("error"));
                    return Err(map_failure(&m));
                }
            };
            ctx.audit(grant, &ws, meta("accepted"));
            if matches!(
                accepted.assistant.state,
                MessageState::Dispatching | MessageState::Streaming
            ) && ctx.engine.is_active(&thread.thread_id).unwrap_or(false)
            {
                ctx.router.set_origin(&thread.thread_id, grant);
                ctx.router
                    .begin(&thread.thread_id, &accepted.assistant.message_id);
            }
            #[cfg(test)]
            {
                let hook = ctx.after_send.lock().ok().and_then(|h| h.clone());
                if let Some(hook) = hook {
                    hook();
                }
            }
            // The send committed before a disable/lowering may have been noted: the
            // floor is set before any kill snapshot, so re-checking it closes the race.
            if ctx.is_locked() || !permits(grant, ctx.effective(&ws, scope), perm) {
                let _ = stop_and_wait(ctx, &thread.thread_id).await;
                ctx.audit(
                    grant,
                    &ws,
                    serde_json::json!({"op": "kill", "thread": thread.thread_id, "permissions": perm_text(perm), "originConsumer": grant.consumer, "originGrant": grant.grant_id, "outcome": "access revoked during send"}),
                );
                return Err(ctx.deny(grant, &ws, "send", "access revoked during send"));
            }
            ctx.router.thread_changed(&accepted.thread);
            ok(RpcResult::ChatSend(lomi_remote_protocol::ChatSendResult {
                thread: to_thread(&accepted.thread)?,
                user: to_message(&accepted.user)?,
                assistant: to_message(&accepted.assistant)?,
            }))
        }
        RpcCall::ChatStop(p) => {
            let thread = ctx.scoped_thread(&ws, &p.thread_id).await?;
            ctx.audit(
                grant,
                &ws,
                serde_json::json!({"op": "stop", "thread": thread.thread_id, "provider": thread.instance_id, "permissions": perm_text(thread_permission(thread.permissions)), "outcome": "ok"}),
            );
            stop_and_wait(ctx, &thread.thread_id).await?;
            let current = ctx.scoped_thread(&ws, &p.thread_id).await?;
            ok(RpcResult::ChatStop(
                lomi_remote_protocol::ChatThreadResult {
                    thread: to_thread(&current)?,
                },
            ))
        }
        _ => Err(error(ErrorCode::UnsupportedCapability)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lomi_remote_protocol::{ChatPermissions as P, decode_request, rpc::RpcResult as R};
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    const TEXT: &str = "SECRET-PROMPT-TEXT-123";

    struct Fx {
        dir: PathBuf,
        chat: Chat,
        scope: Scope,
        grant: Grant,
    }
    impl Drop for Fx {
        fn drop(&mut self) {
            if let Some(h) = self.chat.running() {
                h.ctx.engine.kill_cli_groups();
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn grant(level: ChatLevel) -> Grant {
        Grant {
            capabilities: level.ceiling().unwrap(),
            account: "acct".into(),
            consumer: "consumer-1".into(),
            fingerprint: "ff".repeat(32),
            grant_id: "grant-1".into(),
        }
    }
    fn fx(script: &str, level: ChatLevel) -> Fx {
        let dir = std::env::temp_dir().join(format!("lomi-chat-host-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::create_dir_all(dir.join("project")).unwrap();
        let dir = std::fs::canonicalize(dir).unwrap();
        let bin = dir.join("bin/claude");
        std::fs::write(&bin, format!("#!/bin/sh\n{script}")).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let resolve: Resolver = Arc::new(move |cli| (cli == "claude").then(|| bin.clone()));
        Fx {
            chat: Chat {
                root: Some(dir.join("chat")),
                resolve: Some(resolve),
                handle: Mutex::new(None),
            },
            scope: Scope {
                workspace: WorkspaceId::from_bytes([7; 16]).unwrap(),
                root: dir.join("project"),
                level,
                fence: 5,
            },
            grant: grant(level),
            dir,
        }
    }
    const HELLO: &str = r#"cat >/dev/null
printf '%s\n' '{"type":"stream_event","event":{"type":"content_block_delta","delta":{"type":"text_delta","text":"hello"}}}' '{"type":"result","result":"hello"}'"#;

    fn rpc(method: &str, params: serde_json::Value) -> RpcCall {
        let body = json!({"v":2,"type":"request","requestId":"r1","timeoutMs":1000,
            "call":{"method":method,"params":params}});
        decode_request(body.to_string().as_bytes()).unwrap().call
    }
    fn op() -> String {
        uuid::Uuid::new_v4().to_string()
    }
    impl Fx {
        fn run_as(
            &self,
            grant: &Grant,
            scope: &Scope,
            call: RpcCall,
            sub: &mut Option<ChatSub>,
        ) -> Result<RpcResult, RemoteError> {
            self.chat.execute(
                &call,
                grant,
                scope,
                Instant::now() + Duration::from_secs(20),
                sub,
            )
        }
        fn run(&self, call: RpcCall) -> Result<RpcResult, RemoteError> {
            self.run_as(&self.grant, &self.scope, call, &mut None)
        }
        fn create(&self, perms: &str) -> Result<ChatThread, RemoteError> {
            match self.run(rpc(
                "chat.thread.create",
                json!({"operationId":op(),"providerId":"claude","model":"m","effort":null,
                    "permissions":perms,"workspaceMode":"project","title":null}),
            ))? {
                R::ChatThreadCreate(r) => Ok(r.thread),
                other => panic!("{other:?}"),
            }
        }
        fn send_with(&self, t: &ChatThread, rev: u64, op_id: &str) -> Result<R, RemoteError> {
            self.run(rpc(
                "chat.send",
                json!({"operationId":op_id,"threadId":String::from(t.thread_id),
                    "expectedRevision":rev.to_string(),"text":TEXT}),
            ))
        }
        fn threads(&self) -> Vec<ThreadSummary> {
            self.chat.local_threads(self.scope.workspace).unwrap()
        }
        fn wait_idle(&self) {
            let start = Instant::now();
            while self.threads().iter().any(|t| t.streaming) {
                assert!(
                    start.elapsed() < Duration::from_secs(15),
                    "generation never ended"
                );
                std::thread::sleep(Duration::from_millis(30));
            }
        }
        fn audit(&self) -> String {
            std::fs::read_to_string(self.dir.join("chat/audit.jsonl")).unwrap_or_default()
        }
    }

    #[test]
    fn permission_matrix_grant_by_thread_mode_by_level() {
        let grant_with = |caps: &[Capability]| {
            let mut v = vec![Capability::WorkspaceRead];
            v.extend_from_slice(caps);
            Grant {
                capabilities: CapabilitySet::try_from(v).unwrap(),
                ..grant(ChatLevel::Send)
            }
        };
        let send = grant_with(&[Capability::ChatRead, Capability::ChatSend]);
        let edit = grant_with(&[
            Capability::ChatRead,
            Capability::ChatSend,
            Capability::ChatPermissionsEdit,
        ]);
        let full = grant(ChatLevel::Full);
        for (g, name, allowed) in [
            (&send, "send", [true, false, false]),
            (&edit, "edit", [true, true, false]),
            (&full, "full", [true, true, true]),
        ] {
            for (i, p) in [P::ReadOnly, P::Edit, P::Full].into_iter().enumerate() {
                assert_eq!(permits(g, ChatLevel::Full, p), allowed[i], "{name} {p:?}");
                // A lower workspace level caps even a full grant.
                for level in [ChatLevel::Send, ChatLevel::Edit] {
                    let expect = allowed[i] && level >= permission_level(p);
                    assert_eq!(permits(g, level, p), expect, "{name} {p:?} at {level:?}");
                }
            }
        }
    }

    #[test]
    fn denials_are_scope_denied_and_audited() {
        let fx = fx(HELLO, ChatLevel::Send);
        // Level send: edit threads cannot be created even with a full grant.
        let err = fx.create("edit").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ScopeDenied);
        let off = Scope {
            level: ChatLevel::Off,
            ..fx.scope.clone()
        };
        let err = fx
            .run_as(&fx.grant, &off, rpc("chat.providers", json!({})), &mut None)
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ScopeDenied);
        let audit = fx.audit();
        assert_eq!(audit.matches("\"op\":\"deny\"").count(), 2, "{audit}");
        assert!(fx.create("read-only").is_ok());
    }

    #[test]
    fn threads_are_scoped_to_the_grant_workspace() {
        let fx = fx(HELLO, ChatLevel::Full);
        let thread = fx.create("read-only").unwrap();
        let other = Scope {
            workspace: WorkspaceId::from_bytes([9; 16]).unwrap(),
            ..fx.scope.clone()
        };
        let id = String::from(thread.thread_id);
        for (method, params) in [
            ("chat.thread.get", json!({"threadId":id,"limit":10})),
            ("chat.stop", json!({"threadId":id})),
            ("chat.subscribe", json!({"threadId":id,"after":null})),
            (
                "chat.thread.delete",
                json!({"operationId":op(),"threadId":id,"expectedRevision":"1"}),
            ),
            (
                "chat.send",
                json!({"operationId":op(),"threadId":id,"expectedRevision":"1","text":"x"}),
            ),
            (
                "chat.thread.update",
                json!({"operationId":op(),"threadId":id,"expectedRevision":"1","title":"t"}),
            ),
        ] {
            let err = fx
                .run_as(&fx.grant, &other, rpc(method, params), &mut None)
                .unwrap_err();
            assert_eq!(err.code(), ErrorCode::ResourceNotFound, "{method}");
        }
        match fx
            .run_as(
                &fx.grant,
                &other,
                rpc("chat.threads.list", json!({"cursor":null,"limit":50})),
                &mut None,
            )
            .unwrap()
        {
            R::ChatThreadsList(l) => assert!(l.threads.0.is_empty()),
            other => panic!("{other:?}"),
        }
        // The thread lives in the grant workspace with the Host-resolved root as cwd.
        let stored = &fx.threads()[0];
        assert_eq!(
            stored.workspace_id.as_deref(),
            Some(String::from(fx.scope.workspace).as_str())
        );
        assert_eq!(stored.cwd.as_deref(), Some(fx.scope.root.to_str().unwrap()));
    }

    #[test]
    fn send_retry_after_revision_bump_returns_the_same_result() {
        let fx = fx(HELLO, ChatLevel::Full);
        let thread = fx.create("read-only").unwrap();
        let first_op = op();
        let first = fx.send_with(&thread, thread.revision.0, &first_op).unwrap();
        fx.wait_idle(); // the revision has moved on
        let again = fx.send_with(&thread, thread.revision.0, &first_op).unwrap();
        let (R::ChatSend(a), R::ChatSend(b)) = (first, again) else {
            panic!()
        };
        assert_eq!(a.user.message_id, b.user.message_id);
        assert_eq!(a.assistant.message_id, b.assistant.message_id);
        // A new operation with the stale revision is a conflict, and a reused id
        // with other parameters is an idempotency conflict.
        let err = fx.send_with(&thread, thread.revision.0, &op()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::RevisionConflict);
        let err = fx
            .run(rpc(
                "chat.send",
                json!({"operationId":first_op,"threadId":String::from(thread.thread_id),
                    "expectedRevision":thread.revision.0.to_string(),"text":"different"}),
            ))
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::IdempotencyConflict);
    }

    #[test]
    fn create_replays_by_operation_and_rejects_changed_parameters() {
        let fx = fx(HELLO, ChatLevel::Full);
        let id = op();
        let params = |perms: &str| {
            json!({"operationId":id,"providerId":"claude","model":"m","effort":null,
            "permissions":perms,"workspaceMode":"project","title":null})
        };
        let (R::ChatThreadCreate(a), R::ChatThreadCreate(b)) = (
            fx.run(rpc("chat.thread.create", params("read-only")))
                .unwrap(),
            fx.run(rpc("chat.thread.create", params("read-only")))
                .unwrap(),
        ) else {
            panic!()
        };
        assert_eq!(a.thread.thread_id, b.thread.thread_id);
        assert_eq!(fx.threads().len(), 1);
        let err = fx
            .run(rpc("chat.thread.create", params("edit")))
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::IdempotencyConflict);
    }

    #[test]
    fn delete_is_idempotent_and_update_replays() {
        let fx = fx(HELLO, ChatLevel::Full);
        let thread = fx.create("read-only").unwrap();
        let id = String::from(thread.thread_id);
        let update = json!({"operationId":op(),"threadId":id,"expectedRevision":thread.revision.0.to_string(),"title":"Renamed"});
        let (R::ChatThreadUpdate(a), R::ChatThreadUpdate(b)) = (
            fx.run(rpc("chat.thread.update", update.clone())).unwrap(),
            fx.run(rpc("chat.thread.update", update)).unwrap(),
        ) else {
            panic!()
        };
        assert_eq!(a.thread.revision, b.thread.revision);
        let delete = json!({"operationId":op(),"threadId":id,"expectedRevision":a.thread.revision.0.to_string()});
        fx.run(rpc("chat.thread.delete", delete.clone())).unwrap();
        fx.run(rpc("chat.thread.delete", delete)).unwrap(); // retry after the thread is gone
        assert!(fx.threads().is_empty());
        let other = json!({"operationId":op(),"threadId":id,"expectedRevision":"9"});
        assert_eq!(
            fx.run(rpc("chat.thread.delete", other)).unwrap_err().code(),
            ErrorCode::ResourceNotFound
        );
    }

    #[test]
    fn remote_sends_use_the_restricted_argv_and_audit_has_no_prompt_text() {
        let script = format!("printf '%s\\n' \"$@\" > '{}'\n{HELLO}", "$ARGV_OUT");
        let fx = fx("", ChatLevel::Full);
        let out = fx.dir.join("argv.txt");
        std::fs::write(
            fx.dir.join("bin/claude"),
            format!(
                "#!/bin/sh\n{}",
                script.replace("$ARGV_OUT", out.to_str().unwrap())
            ),
        )
        .unwrap();
        let thread = fx.create("read-only").unwrap();
        fx.send_with(&thread, thread.revision.0, &op()).unwrap();
        fx.wait_idle();
        let argv = std::fs::read_to_string(&out).unwrap();
        assert!(
            argv.contains("--restricted") && argv.contains("--strict-mcp-config"),
            "{argv}"
        );
        let audit = fx.audit();
        assert!(
            !audit.contains(TEXT),
            "prompt text leaked into the audit log"
        );
        assert!(
            audit.contains("promptSha256")
                && audit.contains(&format!("\"promptBytes\":{}", TEXT.len()))
        );
        let line: serde_json::Value =
            serde_json::from_str(audit.lines().find(|l| l.contains("\"send\"")).unwrap()).unwrap();
        for key in [
            "time",
            "account",
            "consumer",
            "fingerprint",
            "grant",
            "workspace",
            "thread",
            "provider",
            "model",
            "permissions",
            "outcome",
        ] {
            assert!(line.get(key).is_some(), "missing {key}");
        }
        let mode = std::fs::metadata(fx.dir.join("chat/audit.jsonl"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn disabling_or_lowering_kills_only_generations_above_the_level() {
        let fx = fx("cat >/dev/null\nsleep 60", ChatLevel::Full);
        let read_only = fx.create("read-only").unwrap();
        let full = fx.create("full").unwrap();
        fx.send_with(&read_only, read_only.revision.0, &op())
            .unwrap();
        fx.send_with(&full, full.revision.0, &op()).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert!(fx.threads().iter().all(|t| t.streaming));
        // Lowering to edit stops the full thread only.
        fx.chat
            .enforce_level(fx.scope.workspace, ChatLevel::Edit, 5);
        let start = Instant::now();
        while fx.threads().iter().filter(|t| t.streaming).count() != 1 {
            assert!(start.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(30));
        }
        let still = fx.threads().into_iter().find(|t| t.streaming).unwrap();
        assert_eq!(still.thread_id, String::from(read_only.thread_id));
        // Disabling stops everything of the workspace.
        fx.chat.enforce_level(fx.scope.workspace, ChatLevel::Off, 5);
        fx.wait_idle();
        let audit = fx.audit();
        assert_eq!(audit.matches("\"op\":\"kill\"").count(), 2, "{audit}");
    }

    #[test]
    fn rate_limits_per_consumer() {
        let mut limits = Limits::default();
        let t0 = Instant::now();
        for _ in 0..20 {
            assert!(limits.allow("send", "a", t0, SEND_LIMIT));
        }
        assert!(!limits.allow("send", "a", t0, SEND_LIMIT));
        assert!(
            limits.allow("send", "b", t0, SEND_LIMIT),
            "limits are per consumer"
        );
        assert!(limits.allow("send", "a", t0 + Duration::from_secs(61), SEND_LIMIT));
        for _ in 0..30 {
            assert!(limits.allow("create", "a", t0, CREATE_LIMIT));
        }
        assert!(!limits.allow("create", "a", t0 + Duration::from_secs(3599), CREATE_LIMIT));
        assert!(limits.allow("create", "a", t0 + Duration::from_secs(3601), CREATE_LIMIT));
    }

    #[test]
    fn send_rate_limit_is_enforced_end_to_end() {
        let fx = fx(HELLO, ChatLevel::Full);
        let thread = fx.create("read-only").unwrap();
        for _ in 0..20 {
            // Invalid revisions still count as attempts, which is the point of the limit.
            let _ = fx.send_with(&thread, 999, &op());
        }
        let err = fx.send_with(&thread, 999, &op()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ResourceExhausted);
    }

    #[test]
    fn subscribe_resumes_with_snapshot_then_deltas_then_message() {
        let script = r#"cat >/dev/null
printf '%s\n' '{"type":"stream_event","event":{"type":"content_block_delta","delta":{"type":"text_delta","text":"one "}}}'
sleep 2
printf '%s\n' '{"type":"stream_event","event":{"type":"content_block_delta","delta":{"type":"text_delta","text":"two"}}}' '{"type":"result","result":"one two"}'"#;
        let fx = fx(script, ChatLevel::Full);
        let thread = fx.create("read-only").unwrap();
        let mut events = None;
        fx.run_as(
            &fx.grant,
            &fx.scope,
            rpc("chat.subscribe", json!({"threadId":null,"after":null})),
            &mut events,
        )
        .unwrap();
        fx.send_with(&thread, thread.revision.0, &op()).unwrap();
        std::thread::sleep(Duration::from_millis(900));
        let mut sub = None;
        let id = String::from(thread.thread_id);
        let after = json!({"threadId":id,"after":{"messageId":"0".repeat(32),"streamSeq":"0"}});
        fx.run_as(&fx.grant, &fx.scope, rpc("chat.subscribe", after), &mut sub)
            .unwrap();
        let sub = sub.unwrap();
        let (mut frames, start) = (Vec::new(), Instant::now());
        while !frames
            .iter()
            .any(|f| matches!(f, ChatStreamFrame::Message { .. }))
        {
            assert!(start.elapsed() < Duration::from_secs(15), "{frames:?}");
            match sub.poll() {
                Some(f) => frames.push(f),
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        let ChatStreamFrame::Snapshot {
            text,
            stream_seq,
            last,
            ..
        } = &frames[0]
        else {
            panic!("snapshot first: {frames:?}")
        };
        assert!(*last && text.as_str() == "one ", "{frames:?}");
        let deltas: Vec<_> = frames
            .iter()
            .filter_map(|f| match f {
                ChatStreamFrame::Delta { seq, text, .. } => Some((seq.0, text.as_str().to_owned())),
                _ => None,
            })
            .collect();
        assert_eq!(deltas, vec![(stream_seq.0 + 1, "two".to_owned())]);
        let ChatStreamFrame::Message { message } = frames.last().unwrap() else {
            panic!()
        };
        assert_eq!(message.content.as_str(), "one two");
        // The thread-wide subscription saw thread frames only (no deltas).
        let mut thread_frames = 0;
        while let Some(f) = events.as_ref().unwrap().poll() {
            assert!(matches!(f, ChatStreamFrame::Thread { .. }), "{f:?}");
            thread_frames += 1;
        }
        assert!(thread_frames > 0);
    }

    #[test]
    fn subscribing_to_a_missing_or_deleted_thread_is_not_found() {
        let fx = fx(HELLO, ChatLevel::Full);
        let missing = fx.run(rpc(
            "chat.subscribe",
            json!({"threadId":"a".repeat(32),"after":null}),
        ));
        assert_eq!(missing.unwrap_err().code(), ErrorCode::ResourceNotFound);
        let thread = fx.create("read-only").unwrap();
        let id = String::from(thread.thread_id);
        fx.run(rpc("chat.thread.delete", json!({"operationId":op(),"threadId":id,"expectedRevision":thread.revision.0.to_string()}))).unwrap();
        let gone = fx.run(rpc("chat.subscribe", json!({"threadId":id,"after":null})));
        assert_eq!(gone.unwrap_err().code(), ErrorCode::ResourceNotFound);
    }

    #[test]
    fn slow_subscriber_overflows_into_resync_and_dies() {
        let router = Router::default();
        let id = "a".repeat(32);
        let sub = router.subscribe("ws", Some(&id), || None);
        for _ in 0..(QUEUE_FRAMES + 1) {
            router.delta("ws", &id, &"b".repeat(32), "x");
        }
        assert!(matches!(
            sub.poll(),
            Some(ChatStreamFrame::Resync {
                reason: ResyncReason::SubscriberOverflow
            })
        ));
        assert!(sub.poll().is_none() && sub.is_dead());
        // Byte budget: a few large deltas overflow before the frame budget does.
        let sub = router.subscribe("ws", Some(&id), || None);
        let big = "y".repeat(CHAT_STREAM_TEXT_BYTES);
        for _ in 0..100 {
            router.delta("ws", &id, &"b".repeat(32), &big);
        }
        assert!(matches!(sub.poll(), Some(ChatStreamFrame::Resync { .. })));
    }

    #[test]
    fn text_is_split_to_fit_frames_including_json_escaping() {
        use lomi_remote_protocol::decode_chat_frame;
        for text in [
            "é".repeat(20_000),
            "\u{1}".repeat(30_000),
            "a\n\"".repeat(15_000),
        ] {
            let parts = split_text(&text);
            assert_eq!(parts.concat(), text);
            for part in parts {
                let frame = ChatStreamFrame::Delta {
                    message_id: ChatMessageId::try_from("c".repeat(32)).unwrap(),
                    seq: DecimalU64(1),
                    text: ChatStreamText::try_from(part.to_owned()).unwrap(),
                };
                let bytes = serde_json::to_vec(&frame).unwrap();
                assert!(decode_chat_frame(&bytes).is_ok(), "{} bytes", bytes.len());
            }
        }
    }

    #[test]
    fn oversized_messages_are_truncated_on_a_char_boundary() {
        let m = store::ThreadMessage {
            message_id: "d".repeat(32),
            seq: 2,
            role: Role::Assistant,
            content: "é".repeat(CHAT_MESSAGE_CONTENT_BYTES),
            state: MessageState::Completed,
            instance_id: "claude".into(),
            model: "m".into(),
            stream_seq: 3,
            stop_reason: None,
            error: None,
            error_kind: None,
            retry_at_ms: None,
            created_ms: 1,
            attachments: vec![],
            activity: vec![],
            usage: None,
            changes: None,
        };
        let dto = to_message(&m).unwrap();
        assert!(dto.truncated && dto.content.as_str().len() <= CHAT_MESSAGE_CONTENT_BYTES);
        assert!(dto.content.as_str().chars().all(|c| c == 'é'));
        let small = store::ThreadMessage {
            content: "ok".into(),
            ..m
        };
        assert!(!to_message(&small).unwrap().truncated);
    }

    #[test]
    fn audit_rotates_by_line_count() {
        let dir = std::env::temp_dir().join(format!("lomi-audit-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let audit = Audit::new(&dir);
        *audit.lines.lock().unwrap() = Some((AUDIT_MAX_LINES, now_ms()));
        std::fs::write(dir.join("audit.jsonl"), "old\n").unwrap();
        audit.record(&Grant::local(), "ws", json!({"op":"create"}));
        assert!(dir.join("audit.jsonl.1").exists());
        assert_eq!(audit.tail(10).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn send_racing_a_lowering_is_stopped_after_commit() {
        let fx = fx("cat >/dev/null\nsleep 60", ChatLevel::Full);
        let thread = fx.create("full").unwrap();
        let h = fx.chat.handle().unwrap();
        // The lowering lands after the request was gated and committed, before any kill snapshot.
        let hook_chat = fx.chat.handle().unwrap();
        let ws = String::from(fx.scope.workspace);
        *h.ctx.after_send.lock().unwrap() = Some(Arc::new(move || {
            hook_chat.enforce(ws.clone(), ChatLevel::Edit, 5)
        }));
        let err = fx.send_with(&thread, thread.revision.0, &op()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ScopeDenied);
        fx.wait_idle();
        let audit = fx.audit();
        assert!(audit.contains("access revoked during send"), "{audit}");
        // The floor also refuses later requests that still carry a stale level.
        *h.ctx.after_send.lock().unwrap() = None;
        let err = fx.send_with(&thread, 1, &op()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ScopeDenied);
        // A read-only thread is still allowed at the lowered level.
        let ro = fx.create("read-only").unwrap();
        assert!(fx.send_with(&ro, ro.revision.0, &op()).is_ok());
        h.enforce(String::from(fx.scope.workspace), ChatLevel::Off, 5);
        assert_eq!(
            fx.create("read-only").unwrap_err().code(),
            ErrorCode::ScopeDenied
        );
    }

    #[test]
    fn revocation_signals_stop_generations_and_origin_is_recorded() {
        let fx = fx("cat >/dev/null\nsleep 60", ChatLevel::Full);
        let a = fx.create("read-only").unwrap();
        let b = fx.create("read-only").unwrap();
        let other = Grant {
            consumer: "consumer-2".into(),
            grant_id: "grant-2".into(),
            ..fx.grant.clone()
        };
        fx.send_with(&a, a.revision.0, &op()).unwrap();
        fx.run_as(&other, &fx.scope, rpc("chat.send", json!({"operationId":op(),"threadId":String::from(b.thread_id),"expectedRevision":b.revision.0.to_string(),"text":"x"})), &mut None).unwrap();
        let h = fx.chat.handle().unwrap();
        assert_eq!(
            h.ctx.router.origin(&String::from(a.thread_id)),
            Some(("consumer-1".into(), "grant-1".into()))
        );
        // A revoked grant stops only its own generations (a disconnect would not call this).
        fx.chat.revoke_origin(None, Some("grant-2"));
        let start = Instant::now();
        while fx.threads().iter().filter(|t| t.streaming).count() != 1 {
            assert!(start.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(30));
        }
        let audit = fx.audit();
        assert!(audit.contains("\"originGrant\":\"grant-2\""), "{audit}");
        // The store-noted "authorization lost" signal stops everything.
        h.apply(lomi_host_store::ChatRevocations {
            all: true,
            workspaces: vec![],
        });
        fx.wait_idle();
    }

    #[test]
    fn encoded_size_budgets_hold_for_hostile_content() {
        use lomi_remote_protocol::decode_chat_frame;
        let make = |content: String, seq: u64| store::ThreadMessage {
            message_id: format!("{seq:032x}"),
            seq,
            role: Role::Assistant,
            content,
            state: MessageState::Completed,
            instance_id: "claude".into(),
            model: "m".into(),
            stream_seq: 1,
            stop_reason: None,
            error: None,
            error_kind: None,
            retry_at_ms: None,
            created_ms: 1,
            attachments: vec![],
            activity: vec![],
            usage: None,
            changes: None,
        };
        for unit in ["\"", "\n", "\u{1}", "\\", "\u{7f}é"] {
            let m = make(unit.repeat(CHAT_MESSAGE_CONTENT_BYTES), 2);
            let dto = to_message(&m).unwrap();
            assert!(dto.truncated, "{unit:?}");
            let frame = ChatStreamFrame::Message {
                message: dto.clone(),
            };
            let bytes = serde_json::to_vec(&frame).unwrap();
            assert!(
                bytes.len() <= MESSAGE_JSON_BUDGET + 4096,
                "{unit:?} {}",
                bytes.len()
            );
            assert!(decode_chat_frame(&bytes).is_ok(), "{unit:?}");
            // A page of several such messages is trimmed to fit one logical message.
            let mut page: Vec<_> = (0..6)
                .map(|i| to_message(&make(unit.repeat(CHAT_MESSAGE_CONTENT_BYTES), i + 2)).unwrap())
                .collect();
            let trimmed = fit_page(&mut page, 600);
            assert!(trimmed && !page.is_empty());
            let total: usize = page
                .iter()
                .map(|m| serde_json::to_vec(m).unwrap().len())
                .sum();
            assert!(
                total + 600 < lomi_remote_protocol::message_framing::MAX_MESSAGE_LEN,
                "{unit:?} {total}"
            );
        }
    }

    #[test]
    fn deny_rows_are_coalesced_per_consumer() {
        let dir = std::env::temp_dir().join(format!("lomi-audit-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let audit = Audit::new(&dir);
        let g = grant(ChatLevel::Send);
        for _ in 0..100 {
            audit.record_deny(&g, "ws", json!({"op":"deny","outcome":"x"}));
        }
        assert_eq!(audit.tail(1000).len(), 60);
        // Another consumer has its own budget.
        let g2 = Grant {
            consumer: "c2".into(),
            ..g.clone()
        };
        audit.record_deny(&g2, "ws", json!({"op":"deny","outcome":"x"}));
        assert_eq!(audit.tail(1000).len(), 61);
        // The next window starts with one summary row carrying the dropped count.
        audit
            .denies
            .lock()
            .unwrap()
            .get_mut("consumer-1")
            .unwrap()
            .0 = Instant::now() - Duration::from_secs(61);
        audit.record_deny(&g, "ws", json!({"op":"deny","outcome":"y"}));
        let lines = audit.tail(1000);
        let summary: Vec<_> = lines
            .iter()
            .filter(|l| l.contains("\"summary\":true"))
            .collect();
        assert_eq!(summary.len(), 1);
        assert!(summary[0].contains("\"dropped\":40"), "{}", summary[0]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failing_audit_write_refuses_create_and_send() {
        let fx = fx(HELLO, ChatLevel::Full);
        let thread = fx.create("read-only").unwrap();
        // Make the audit file unwritable: a directory sits where the log must be.
        let path = fx.dir.join("chat/audit.jsonl");
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let err = fx.create("read-only").unwrap_err();
        assert_eq!(err.code(), ErrorCode::ServiceUnavailable);
        let err = fx.send_with(&thread, thread.revision.0, &op()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ServiceUnavailable);
        assert_eq!(fx.threads().len(), 1, "no thread was created");
        assert!(
            fx.threads().iter().all(|t| !t.streaming),
            "nothing was spawned"
        );
    }

    #[test]
    fn concurrent_provider_requests_share_one_probe() {
        let fx = fx(HELLO, ChatLevel::Full);
        let h = fx.chat.handle().unwrap();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    fx.run(rpc("chat.providers", json!({}))).unwrap();
                });
            }
        });
        let probes = h.ctx.refreshes.load(std::sync::atomic::Ordering::Relaxed);
        assert!(probes <= 2, "{probes} probes for 8 callers");
    }

    #[test]
    fn a_panicking_service_restarts_on_the_next_call() {
        let fx = fx(HELLO, ChatLevel::Full);
        let old = fx.chat.handle().unwrap();
        // A job that panics when invoked takes the runtime future down with it.
        old.jobs
            .send(Box::new(|_| panic!("simulated service panic")))
            .unwrap();
        let start = Instant::now();
        while !old.dead.load(std::sync::atomic::Ordering::Acquire) {
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(old);
        let thread = fx.create("read-only").unwrap();
        assert_eq!(fx.threads().len(), 1);
        assert_eq!(thread.permissions, P::ReadOnly);
    }

    #[test]
    fn a_delete_replay_never_touches_another_workspaces_thread() {
        let fx = fx(HELLO, ChatLevel::Full);
        let thread = fx.create("read-only").unwrap();
        let other = Scope {
            workspace: WorkspaceId::from_bytes([9; 16]).unwrap(),
            ..fx.scope.clone()
        };
        let id = String::from(thread.thread_id);
        let err = fx
            .run_as(
                &fx.grant,
                &other,
                rpc(
                    "chat.thread.delete",
                    json!({"operationId":op(),"threadId":id,"expectedRevision":"0"}),
                ),
                &mut None,
            )
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ResourceNotFound);
        assert_eq!(fx.threads().len(), 1, "the foreign delete deleted nothing");
    }

    #[test]
    fn floors_bound_to_an_older_fence_never_disable_chat() {
        let fx = fx(HELLO, ChatLevel::Full);
        let h = fx.chat.handle().unwrap();
        let ws = String::from(fx.scope.workspace);
        let thread = fx.create("full").unwrap();
        // Full -> Send -> Full: the Send record (fence 6) is drained after the raise (fence 7).
        h.enforce(ws.clone(), ChatLevel::Send, 6);
        let raised = Scope {
            fence: 7,
            ..fx.scope.clone()
        };
        assert_eq!(
            h.ctx.effective(&ws, &raised),
            ChatLevel::Full,
            "stale floor ignored"
        );
        let sent = fx.run_as(
            &fx.grant,
            &raised,
            rpc(
                "chat.send",
                json!({"operationId":op(),"threadId":String::from(thread.thread_id),
                "expectedRevision":thread.revision.0.to_string(),"text":"x"}),
            ),
            &mut None,
        );
        assert!(sent.is_ok(), "{sent:?}");
        // A request gated before the change (older fence) is still capped by it.
        let older = Scope {
            fence: 5,
            ..fx.scope.clone()
        };
        assert_eq!(h.ctx.effective(&ws, &older), ChatLevel::Send);
        // An older record never overrides a newer floor; equal fences keep the lower level.
        h.enforce(ws.clone(), ChatLevel::Full, 3);
        assert_eq!(h.ctx.effective(&ws, &older), ChatLevel::Send);
        h.enforce(ws.clone(), ChatLevel::Off, 6);
        assert_eq!(h.ctx.effective(&ws, &older), ChatLevel::Off);
        // The owner re-enabling at a newer fence restores access immediately.
        h.enforce(ws.clone(), ChatLevel::Full, 8);
        let newer = Scope {
            fence: 8,
            ..fx.scope.clone()
        };
        assert_eq!(h.ctx.effective(&ws, &newer), ChatLevel::Full);
    }

    #[test]
    fn a_send_committed_after_an_authorization_lock_is_stopped() {
        let fx = fx("cat >/dev/null\nsleep 60", ChatLevel::Full);
        let thread = fx.create("read-only").unwrap();
        let h = fx.chat.handle().unwrap();
        let flag = h.ctx.lock_override.clone();
        // The lock lands after the request was gated, before the post-send recheck.
        *h.ctx.after_send.lock().unwrap() = Some(Arc::new(move || {
            flag.store(true, std::sync::atomic::Ordering::Release)
        }));
        let err = fx.send_with(&thread, thread.revision.0, &op()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ScopeDenied);
        fx.wait_idle();
        // While locked every chat call is refused; clearing the lock restores service.
        assert_eq!(
            fx.create("read-only").unwrap_err().code(),
            ErrorCode::ScopeDenied
        );
        *h.ctx.after_send.lock().unwrap() = None;
        h.ctx
            .lock_override
            .store(false, std::sync::atomic::Ordering::Release);
        assert!(fx.create("read-only").is_ok());
    }

    #[test]
    fn a_failed_audit_rotation_keeps_the_counter_and_retries() {
        let dir = std::env::temp_dir().join(format!("lomi-audit-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let audit = Audit::new(&dir);
        // The rotation target is a non-empty directory, so the rename fails.
        std::fs::create_dir_all(dir.join("audit.jsonl.1/x")).unwrap();
        std::fs::write(dir.join("audit.jsonl"), "old\n").unwrap();
        *audit.lines.lock().unwrap() = Some((AUDIT_MAX_LINES, now_ms()));
        audit.record(&Grant::local(), "ws", json!({"op":"create"}));
        assert!(
            audit.lines.lock().unwrap().unwrap().0 > AUDIT_MAX_LINES,
            "counter kept for a retry"
        );
        std::fs::remove_dir_all(dir.join("audit.jsonl.1")).unwrap();
        audit.record(&Grant::local(), "ws", json!({"op":"create"}));
        assert!(dir.join("audit.jsonl.1").exists());
        assert_eq!(audit.lines.lock().unwrap().unwrap().0, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
