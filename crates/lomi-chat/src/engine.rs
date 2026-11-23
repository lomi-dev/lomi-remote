//! Chat send lifecycle without any UI framework: storage handle, the registry of
//! running generations, and the send pipeline (validate, commit the dispatch
//! intent, stream, commit the outcome). Hosts inject event delivery, change
//! notification, API key lookup and CLI resolution through [`Hooks`].
use crate::{
    attachments::{self, Attachment, Kind},
    cli, http,
    settings::{self, *},
    storage::{self, Owner},
    store::{self, *},
};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
    time::Instant,
};
use tokio::{io::AsyncReadExt, sync::Notify};
use zeroize::Zeroizing;

const FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(750);
const FLUSH_BYTES: usize = 16 * 1024;
/// Stored assistant output never exceeds what a later request could carry.
const CONTENT_CAP: usize = store::MAX_CONTEXT;
const NOTE_LIMIT: &str = "Response hit the output limit.";
const NOTE_SIZE: &str = "Response exceeded the size limit and was truncated.";

/// Receives the events of one send. Delivery failures are the sink's to ignore.
pub trait EventSink: Send + Sync {
    fn send(&self, event: ThreadStreamEvent);
}

type ApiKeyFn = dyn Fn(&str) -> Result<Option<Zeroizing<String>>, String> + Send + Sync;
type ChangedFn = dyn Fn(u64, &str) + Send + Sync;
type ResolveFn = dyn Fn(&str) -> Option<PathBuf> + Send + Sync;

/// Host-provided pieces; the engine never touches a keyring or a UI.
pub struct Hooks {
    /// Reads the stored API key of a provider instance.
    pub api_key: Box<ApiKeyFn>,
    /// A thread changed: new revision (0 when deleted) and thread id.
    pub threads_changed: Box<ChangedFn>,
    /// Locates an installed CLI binary by id.
    pub resolve_cli: Box<ResolveFn>,
}

/// Opened Chat storage, guarded by [`Engine::with`].
pub struct Inner {
    _owner: Owner,
    pub dir: PathBuf,
    pub settings: ChatSettings,
    pub store: Store,
    invalid: Option<String>,
}

struct Shared {
    root: PathBuf,
    /// Remote Host mode: read-only CLI sends get the hardened argv.
    restricted: bool,
    hooks: Hooks,
    inner: Mutex<Option<Inner>>,
    /// Stop tokens of running streams by thread. Never held across `.await`.
    active: Mutex<HashMap<String, Arc<Notify>>>,
    client: OnceLock<Result<reqwest::Client, String>>,
    /// Process-group ids of running CLIs, killed on app exit. Never held across `.await`.
    groups: Mutex<HashSet<u32>>,
}

/// Cheap to clone; clones share all state.
#[derive(Clone)]
pub struct Engine(Arc<Shared>);

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| "The chat worker failed.".to_string())?
}

pub fn valid_operation(op: &str) -> Result<(), String> {
    if op.len() > 120 {
        return Err("Invalid operation identity.".into());
    }
    if op.is_empty()
        || !op
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || matches!(v, b'-' | b'_' | b':'))
    {
        return Err("Invalid operation identity.".into());
    }
    Ok(())
}

impl Engine {
    /// `root` is the data directory (`ai-chat`); storage opens lazily on first use.
    pub fn new(root: PathBuf, hooks: Hooks) -> Self {
        Self::build(root, hooks, false)
    }

    /// Like [`Engine::new`], but read-only CLI sends use the restricted argv (remote Host).
    pub fn restricted(root: PathBuf, hooks: Hooks) -> Self {
        Self::build(root, hooks, true)
    }

    fn build(root: PathBuf, hooks: Hooks, restricted: bool) -> Self {
        Self(Arc::new(Shared {
            root,
            restricted,
            hooks,
            inner: Mutex::new(None),
            active: Mutex::new(HashMap::new()),
            client: OnceLock::new(),
            groups: Mutex::new(HashSet::new()),
        }))
    }

    /// Runs `f` against the opened storage. Blocking: call from `spawn_blocking`.
    pub fn with<T>(&self, f: impl FnOnce(&mut Inner) -> Result<T, String>) -> Result<T, String> {
        let mut guard = self
            .0
            .inner
            .lock()
            .map_err(|_| "Chat storage is unavailable.")?;
        if guard.is_none() {
            let owner = Owner::acquire(self.0.root.clone())?;
            let dir = owner.root.clone();
            let (settings, invalid) = match settings::load(&dir) {
                Loaded::Valid(s) => (s, None),
                Loaded::Invalid(message) => (ChatSettings::default(), Some(message)),
            };
            let store = Store::open(&dir)?;
            *guard = Some(Inner {
                _owner: owner,
                dir,
                settings,
                store,
                invalid,
            });
        }
        let inner = guard.as_mut().expect("initialized above");
        if let Some(message) = &inner.invalid {
            return Err(message.clone());
        }
        f(inner)
    }

    pub fn client(&self) -> Result<reqwest::Client, String> {
        self.0.client.get_or_init(http::client).clone()
    }

    fn active(&self) -> Result<MutexGuard<'_, HashMap<String, Arc<Notify>>>, String> {
        self.0
            .active
            .lock()
            .map_err(|_| "Chat state is unavailable.".into())
    }

    /// Whether a stream of `thread_id` is running.
    pub fn is_active(&self, thread_id: &str) -> Result<bool, String> {
        Ok(self.active()?.contains_key(thread_id))
    }

    /// Tracks a CLI process group until the guard drops.
    fn track_group(&self, pid: Option<u32>) -> GroupGuard {
        if let (Some(pid), Ok(mut g)) = (pid, self.0.groups.lock()) {
            g.insert(pid);
        }
        GroupGuard(self.clone(), pid)
    }

    /// Kills every running CLI group; the host is exiting and tasks will not be dropped.
    pub fn kill_cli_groups(&self) {
        if let Ok(mut g) = self.0.groups.lock() {
            for pid in g.drain() {
                cli::kill_group(Some(pid));
            }
        }
    }

    fn notify(&self, revision: u64, thread_id: &str) {
        (self.0.hooks.threads_changed)(revision, thread_id);
    }

    /// Stops a running stream, or marks leftover in-flight rows interrupted.
    /// Blocking: call from `spawn_blocking`.
    pub fn stop(&self, thread_id: &str) -> Result<(), String> {
        let changed = self.with(|i| {
            if let Some(token) = self.active()?.get(thread_id) {
                token.notify_one();
                return Ok(false);
            }
            i.store.interrupt_inflight(thread_id, true)
        })?;
        if changed {
            self.notify(0, thread_id);
        }
        Ok(())
    }

    /// Validates and commits a send; a new one then streams in the background into
    /// `sink`. Must run inside a Tokio runtime.
    pub async fn send(
        &self,
        request: ThreadSend,
        sink: Arc<dyn EventSink>,
    ) -> Result<ThreadSendAccepted, String> {
        let engine = self.clone();
        let (accepted, job) = blocking(move || {
            valid_operation(&request.operation_id)?;
            settings::valid_model_id(&request.model)?;
            engine.with(|i| engine.begin(i, &request))
        })
        .await?;
        if let Some(job) = job {
            self.notify(accepted.thread.revision, &accepted.thread.thread_id);
            tokio::spawn(run_stream(self.clone(), job, sink));
        }
        Ok(accepted)
    }

    fn begin(
        &self,
        i: &mut Inner,
        request: &ThreadSend,
    ) -> Result<(ThreadSendAccepted, Option<Job>), String> {
        let Inner {
            settings,
            store,
            dir,
            ..
        } = i;
        let mut provider = None;
        let begin =
            store.send_begin(request, settings.behavior.system_instructions.len(), |t| {
                provider = Some(match t.kind {
                    ThreadKind::Api => {
                        let p = settings
                            .api_providers
                            .iter()
                            .find(|p| p.instance_id == request.instance_id)
                            .ok_or("Unknown API provider.")?;
                        if !p.enabled {
                            return Err("This provider is disabled.".into());
                        }
                        if !p.api_key_set && p.kind != ApiKind::OpenaiCompatible {
                            return Err("This provider has no API key.".into());
                        }
                        Provider::Api(p.clone())
                    }
                    ThreadKind::Cli => {
                        let p = settings
                            .cli_providers
                            .iter()
                            .find(|p| p.instance_id == request.instance_id)
                            .filter(|p| p.instance_id == t.instance_id)
                            .ok_or("Unknown CLI provider.")?;
                        if !p.enabled {
                            return Err("This provider is disabled.".into());
                        }
                        cli::valid_model(&request.model)?;
                        cli::check_prompt(&p.cli, &request.text)?;
                        if t.cwd
                            .as_deref()
                            .is_some_and(|c| !std::path::Path::new(c).is_dir())
                        {
                            return Err("The project folder no longer exists.".into());
                        }
                        let bin = (self.0.hooks.resolve_cli)(&p.cli).ok_or(
                            "This CLI is not installed. Install it or remove the provider.",
                        )?;
                        Provider::Cli(p.cli.clone(), bin)
                    }
                });
                Ok(())
            })?;
        Ok(match begin {
            SendBegin::Replay(a) => (a, None),
            SendBegin::New(a, context) => {
                let target = match provider.expect("checked during begin") {
                    Provider::Api(provider) => Target::Api(ApiJob {
                        provider,
                        max_tokens: settings.behavior.max_output_tokens,
                        context,
                        attachments_dir: store.attachments_dir(),
                    }),
                    Provider::Cli(id, bin) => {
                        let session = store
                            .native_session(&a.thread.thread_id)?
                            .filter(|s| cli::valid_session(s));
                        let agent_file = if id == "kimi"
                            && session.is_none()
                            && a.thread.permissions == Permissions::ReadOnly
                        {
                            let path = dir.join("kimi-chat-agent.md");
                            storage::atomic(&path, cli::KIMI_AGENT.as_bytes())?;
                            Some(path.to_string_lossy().into_owned())
                        } else {
                            None
                        };
                        Target::Cli(cli_job(
                            &id,
                            bin,
                            &a,
                            &store.attachments_dir(),
                            session,
                            &settings.behavior.system_instructions,
                            agent_file.as_deref(),
                            self.0.restricted,
                        ))
                    }
                };
                // Registered under the storage lock so stop/delete never see a started send as stuck.
                let guard = ActiveGuard::new(self, a.thread.thread_id.clone())?;
                let job = Job {
                    thread_id: a.thread.thread_id.clone(),
                    message_id: a.assistant.message_id.clone(),
                    model: request.model.clone(),
                    system: settings.behavior.system_instructions.clone(),
                    target,
                    guard,
                };
                (a, Some(job))
            }
        })
    }
}

struct GroupGuard(Engine, Option<u32>);

impl Drop for GroupGuard {
    fn drop(&mut self) {
        if let (Some(pid), Ok(mut g)) = (self.1, self.0.0.groups.lock()) {
            g.remove(&pid);
        }
    }
}

/// Registers a running stream's stop token; dropping it (also on panic) removes the entry.
struct ActiveGuard {
    chat: Engine,
    thread_id: String,
    stop: Arc<Notify>,
}

impl ActiveGuard {
    fn new(chat: &Engine, thread_id: String) -> Result<Self, String> {
        let stop = Arc::new(Notify::new());
        chat.active()?.insert(thread_id.clone(), stop.clone());
        Ok(Self {
            chat: chat.clone(),
            thread_id,
            stop,
        })
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        if let Ok(mut active) = self.chat.active() {
            // A newer stream of the same thread may have replaced the entry.
            if active
                .get(&self.thread_id)
                .is_some_and(|s| Arc::ptr_eq(s, &self.stop))
            {
                active.remove(&self.thread_id);
            }
        }
    }
}

struct ApiJob {
    provider: ApiProvider,
    max_tokens: Option<u32>,
    context: Vec<Turn>,
    attachments_dir: std::path::PathBuf,
}

struct CliJob {
    cli: String,
    spec: cli::Spec,
    /// Session the CLI was resumed from, if any.
    session: Option<String>,
}

enum Target {
    Api(ApiJob),
    Cli(CliJob),
}

struct Job {
    thread_id: String,
    message_id: String,
    model: String,
    system: String,
    target: Target,
    guard: ActiveGuard,
}

/// Provider state a send needs, captured under the storage lock.
enum Provider {
    Api(ApiProvider),
    Cli(String, std::path::PathBuf),
}

#[allow(clippy::too_many_arguments)]
/// Builds the argv and working directory of a CLI send; a thread without a directory uses home.
fn cli_job(
    cli_id: &str,
    bin: std::path::PathBuf,
    accepted: &ThreadSendAccepted,
    files_dir: &std::path::Path,
    session: Option<String>,
    system: &str,
    agent_file: Option<&str>,
    restricted: bool,
) -> CliJob {
    let (thread, files) = (&accepted.thread, &accepted.user.attachments);
    let cwd = thread
        .cwd
        .as_deref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(crate::home);
    let path = |a: &Attachment| {
        attachments::path(files_dir, a)
            .to_string_lossy()
            .into_owned()
    };
    let listed: Vec<(String, String)> = files.iter().map(|a| (path(a), a.name.clone())).collect();
    let images: Vec<String> = files
        .iter()
        .filter(|a| a.kind == Kind::Image)
        .map(path)
        .collect();
    let prompt = cli::attach_prompt(&accepted.user.content, &listed);
    let attach_dir = files_dir.to_string_lossy();
    let (args, stdin) = cli::argv(&cli::Invocation {
        cli: cli_id,
        model: &accepted.user.model,
        cwd: &cwd.to_string_lossy(),
        session: session.as_deref(),
        system,
        prompt: &prompt,
        agent_file,
        permissions: thread.permissions,
        effort: thread.effort.as_deref(),
        attach_dir: (!files.is_empty()).then_some(&*attach_dir),
        images: &images,
        restricted,
    });
    CliJob {
        cli: cli_id.into(),
        spec: cli::Spec {
            bin,
            args,
            stdin,
            cwd,
        },
        session,
    }
}

#[derive(Clone)]
struct Outcome {
    state: MessageState,
    content: String,
    stream_seq: u64,
    stop_reason: Option<String>,
    error: Option<String>,
}

impl Outcome {
    fn failed(message: String, content: String, stream_seq: u64) -> Self {
        Self {
            state: MessageState::Failed,
            content,
            stream_seq,
            stop_reason: None,
            error: Some(message),
        }
    }
}

/// Visible note for a response the provider cut off at its output limit.
fn truncation_note(reason: Option<&str>) -> Option<&'static str> {
    matches!(reason, Some("length" | "max_tokens")).then_some(NOTE_LIMIT)
}

/// Retries the final commit, then falls back to a minimal state update so the
/// row can never stay in flight.
async fn commit_outcome(
    chat: &Engine,
    job: &Job,
    outcome: &Outcome,
) -> Result<(ThreadSummary, ThreadMessage), String> {
    for attempt in 0..3u64 {
        let (chat, o) = (chat.clone(), outcome.clone());
        let (thread_id, message_id) = (job.thread_id.clone(), job.message_id.clone());
        let result = blocking(move || {
            chat.with(|i| {
                i.store.finish(
                    &thread_id,
                    &message_id,
                    &Finish {
                        state: o.state,
                        content: &o.content,
                        stream_seq: o.stream_seq,
                        stop_reason: o.stop_reason.as_deref(),
                        error: o.error.as_deref(),
                    },
                )
            })
        })
        .await;
        if let Ok(done) = result {
            return Ok(done);
        }
        tokio::time::sleep(std::time::Duration::from_millis(200 * (attempt + 1))).await;
    }
    let chat = chat.clone();
    let (thread_id, message_id) = (job.thread_id.clone(), job.message_id.clone());
    blocking(move || chat.with(|i| i.store.finish_minimal(&thread_id, &message_id))).await
}

async fn run_stream(chat: Engine, job: Job, sink: Arc<dyn EventSink>) {
    let stop = job.guard.stop.clone();
    let outcome = stream(&chat, &job, &*sink, &stop).await;
    let finished = commit_outcome(&chat, &job, &outcome).await;
    // The entry is removed on every path, including panics, when `job` drops.
    drop(job.guard);
    if let Ok((thread, message)) = finished {
        sink.send(ThreadStreamEvent::Final {
            thread: thread.clone(),
            message,
        });
        chat.notify(thread.revision, &thread.thread_id);
    }
}

fn stopped_outcome(content: String, seq: u64) -> Outcome {
    Outcome {
        state: MessageState::Stopped,
        content,
        stream_seq: seq,
        stop_reason: Some("stopped".into()),
        error: None,
    }
}

/// Streamed assistant text: delta events to the webview plus periodic persistence.
struct Acc {
    content: String,
    seq: u64,
    pending: usize,
    last_flush: Instant,
}

impl Acc {
    fn new() -> Self {
        Self {
            content: String::new(),
            seq: 0,
            pending: 0,
            last_flush: Instant::now(),
        }
    }

    /// Appends and emits `text`; false when it would exceed the stored-content cap.
    fn push(&mut self, job: &Job, sink: &dyn EventSink, text: String) -> bool {
        if self.content.len() + text.len() > CONTENT_CAP {
            return false;
        }
        self.content.push_str(&text);
        self.seq += 1;
        self.pending += text.len();
        sink.send(ThreadStreamEvent::Delta {
            message_id: job.message_id.clone(),
            seq: self.seq,
            text,
        });
        true
    }

    async fn flush_due(&mut self, chat: &Engine, job: &Job) {
        if self.pending < FLUSH_BYTES && self.last_flush.elapsed() < FLUSH_INTERVAL {
            return;
        }
        let (chat, id, text, seq) = (
            chat.clone(),
            job.message_id.clone(),
            self.content.clone(),
            self.seq,
        );
        let _ = blocking(move || chat.with(|i| i.store.flush(&id, &text, seq))).await;
        self.pending = 0;
        self.last_flush = Instant::now();
    }

    fn oversized(self) -> Outcome {
        Outcome {
            state: MessageState::Completed,
            content: self.content,
            stream_seq: self.seq,
            stop_reason: Some("size_limit".into()),
            error: Some(NOTE_SIZE.into()),
        }
    }
}

async fn mark_streaming(chat: &Engine, job: &Job) -> Result<(), String> {
    let (chat, id) = (chat.clone(), job.message_id.clone());
    blocking(move || chat.with(|i| i.store.mark_streaming(&id))).await
}

async fn stream(chat: &Engine, job: &Job, sink: &dyn EventSink, stop: &Notify) -> Outcome {
    match &job.target {
        Target::Api(api) => stream_api(chat, job, api, sink, stop).await,
        Target::Cli(cli) => stream_cli(chat, job, cli, sink, stop).await,
    }
}

async fn stream_api(
    chat: &Engine,
    job: &Job,
    api: &ApiJob,
    sink: &dyn EventSink,
    stop: &Notify,
) -> Outcome {
    let stopped = stop.notified();
    tokio::pin!(stopped);

    let key = if api.provider.api_key_set {
        let (chat, id) = (chat.clone(), api.provider.instance_id.clone());
        match blocking(move || (chat.0.hooks.api_key)(&id)).await {
            Ok(Some(key)) => Some(key),
            Ok(None) if api.provider.kind != ApiKind::OpenaiCompatible => {
                return Outcome::failed(
                    "The API key is missing from the system key store. Re-enter the API key."
                        .into(),
                    String::new(),
                    0,
                );
            }
            Ok(None) => None,
            Err(message) => return Outcome::failed(message, String::new(), 0),
        }
    } else {
        None
    };
    let key_text = key.as_ref().map(|k| k.as_str());
    let client = match chat.client() {
        Ok(c) => c,
        Err(m) => return Outcome::failed(m, String::new(), 0),
    };
    let request = http::ChatRequest {
        kind: api.provider.kind,
        base_url: &api.provider.base_url,
        headers: &api.provider.headers,
        key: key_text,
        model: &job.model,
        system: &job.system,
        max_tokens: api.max_tokens,
        messages: &api.context,
        attachments_dir: &api.attachments_dir,
    };
    let mut response = tokio::select! {
        _ = &mut stopped => return stopped_outcome(String::new(), 0),
        r = http::open_stream(&client, &request) => match r {
            Ok(r) => r,
            Err(m) => return Outcome::failed(http::redact(&m, key_text), String::new(), 0),
        },
    };
    if let Err(m) = mark_streaming(chat, job).await {
        return Outcome::failed(m, String::new(), 0);
    }

    let mut parser = http::SseParser::default();
    let mut acc = Acc::new();
    let (mut done, mut stop_reason): (bool, Option<String>) = (false, None);
    let mut failure: Option<String> = None;
    let mut oversized = false;

    'read: loop {
        let chunk = tokio::select! {
            _ = &mut stopped => return stopped_outcome(acc.content, acc.seq),
            c = response.chunk() => c,
        };
        let eof = matches!(chunk, Ok(None));
        let events = match chunk {
            Ok(Some(bytes)) => parser.push(&bytes),
            Ok(None) => Ok(parser.finish().into_iter().collect()),
            Err(e) if e.is_timeout() => {
                failure = Some("The provider did not respond for 120 seconds.".into());
                break;
            }
            Err(_) => break,
        };
        let events = match events {
            Ok(e) => e,
            Err(m) => {
                failure = Some(m);
                break;
            }
        };
        for event in events {
            for mapped in http::map_event(api.provider.kind, &event) {
                match mapped {
                    http::Mapped::Text(text) => {
                        if !acc.push(job, sink, text) {
                            oversized = true;
                            break 'read;
                        }
                    }
                    http::Mapped::Stop(reason) => stop_reason = Some(reason),
                    http::Mapped::Done => done = true,
                    http::Mapped::Error(m) => {
                        failure = Some(http::redact(&m, key_text));
                        break 'read;
                    }
                }
            }
        }
        if done || eof {
            break;
        }
        acc.flush_due(chat, job).await;
    }

    if let Some(message) = failure {
        return Outcome::failed(message, acc.content, acc.seq);
    }
    if oversized {
        return acc.oversized();
    }
    if !done && stop_reason.is_none() {
        return Outcome::failed(
            "The connection closed before the response finished; the partial response was kept."
                .into(),
            acc.content,
            acc.seq,
        );
    }
    Outcome {
        state: MessageState::Completed,
        content: acc.content,
        stream_seq: acc.seq,
        error: truncation_note(stop_reason.as_deref()).map(Into::into),
        stop_reason,
    }
}

/// How long the pipes may stay open after the CLI exits or reports its final event.
const DRAIN: std::time::Duration = std::time::Duration::from_secs(2);

/// Runs the CLI, then settles the stored session id. A session id is kept only
/// once the turn produced text or exited successfully (it may not exist
/// otherwise). A resumed send that fails without text clears it, so the next
/// send starts fresh instead of resuming a session the CLI cannot find.
async fn stream_cli(
    chat: &Engine,
    job: &Job,
    run: &CliJob,
    sink: &dyn EventSink,
    stop: &Notify,
) -> Outcome {
    let mut seen = None;
    let outcome = run_cli(chat, job, run, sink, stop, &mut seen).await;
    let next = if !outcome.content.is_empty() || outcome.state == MessageState::Completed {
        seen.filter(|s| run.session.as_deref() != Some(s.as_str()))
            .map(Some)
    } else if run.session.is_some() && outcome.state == MessageState::Failed {
        Some(None)
    } else {
        None
    };
    if let Some(next) = next {
        let (chat, thread) = (chat.clone(), job.thread_id.clone());
        let _ =
            blocking(move || chat.with(|i| i.store.set_native_session(&thread, next.as_deref())))
                .await;
    }
    outcome
}

/// Runs the CLI and maps its JSONL stdout onto the same deltas as an API stream.
/// The process group dies with `proc` on every return path (stop included).
async fn run_cli(
    chat: &Engine,
    job: &Job,
    run: &CliJob,
    sink: &dyn EventSink,
    stop: &Notify,
    session: &mut Option<String>,
) -> Outcome {
    let stopped = stop.notified();
    tokio::pin!(stopped);
    let mut proc = match cli::Proc::spawn(&run.spec) {
        Ok(p) => p,
        Err(m) => return Outcome::failed(m, String::new(), 0),
    };
    let _group = chat.track_group(proc.pgid());
    if let Err(m) = mark_streaming(chat, job).await {
        return Outcome::failed(m, String::new(), 0);
    }

    let mut parser = cli::Parser::new(&run.cli);
    let mut splitter = cli::LineSplitter::default();
    let mut acc = Acc::new();
    let mut fallback: Option<String> = None;
    let (mut failure, mut oversized) = (None::<String>, false);
    let mut buf = [0u8; 8192];
    // No inactivity limit: a generation runs until it ends or is stopped explicitly.
    let mut exited = false;
    // Set once the CLI exited or sent its final event; the pipes then get `DRAIN` to close.
    let mut drain_until: Option<tokio::time::Instant> = None;

    'read: loop {
        let read = tokio::select! {
            _ = &mut stopped => return stopped_outcome(acc.content, acc.seq),
            r = proc.stdout.read(&mut buf) => r,
            _ = proc.child.wait(), if !exited => {
                exited = true;
                drain_until.get_or_insert(tokio::time::Instant::now() + DRAIN);
                continue;
            }
            _ = tokio::time::sleep_until(drain_until.unwrap_or_else(tokio::time::Instant::now)), if drain_until.is_some() => {
                proc.kill();
                break;
            }
        };
        let n = read.unwrap_or(0);
        let lines = if n == 0 {
            splitter.finish()
        } else {
            splitter.push(&buf[..n])
        };
        for line in lines {
            for event in parser.line(&line) {
                match event {
                    cli::Ev::Text(text) => {
                        if !acc.push(job, sink, text) {
                            oversized = true;
                            break 'read;
                        }
                    }
                    cli::Ev::Final(text) => {
                        fallback = Some(text);
                        drain_until.get_or_insert(tokio::time::Instant::now() + DRAIN);
                    }
                    cli::Ev::Error(m) => {
                        failure = Some(http::redact(&m, None));
                        break 'read;
                    }
                    cli::Ev::Session(id) => {
                        if cli::valid_session(&id) {
                            *session = Some(id);
                        }
                    }
                }
            }
        }
        if n == 0 {
            break;
        }
        acc.flush_due(chat, job).await;
    }

    if let Some(message) = failure {
        return Outcome::failed(message, acc.content, acc.seq);
    }
    if oversized {
        return acc.oversized();
    }
    let (success, status, stderr) = tokio::select! {
        _ = &mut stopped => return stopped_outcome(acc.content, acc.seq),
        r = proc.finish() => r,
    };
    if !success {
        let detail = if stderr.is_empty() {
            String::new()
        } else {
            format!(": {stderr}")
        };
        return Outcome::failed(
            format!("The CLI exited ({status}){detail}"),
            acc.content,
            acc.seq,
        );
    }
    if acc.content.is_empty() {
        // Some CLIs only report the complete answer at the end.
        let text = fallback.unwrap_or_default();
        if text.is_empty() || !acc.push(job, sink, text) {
            return Outcome::failed("The CLI returned no response.".into(), acc.content, acc.seq);
        }
    }
    Outcome {
        state: MessageState::Completed,
        content: acc.content.trim_end().to_string(),
        stream_seq: acc.seq,
        stop_reason: Some("stop".into()),
        error: None,
    }
}
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{os::unix::fs::PermissionsExt, path::Path};
    use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

    struct Recorder(UnboundedSender<ThreadStreamEvent>);

    impl EventSink for Recorder {
        fn send(&self, event: ThreadStreamEvent) {
            let _ = self.0.send(event);
        }
    }

    /// An engine whose "claude" is the shell script `body`, plus a CLI thread.
    fn setup(body: &str, dir: &Path) -> (Engine, ThreadSummary) {
        let bin = dir.join("claude");
        std::fs::write(&bin, format!("#!/bin/sh\n{body}")).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let engine = Engine::new(
            dir.join("data"),
            Hooks {
                api_key: Box::new(|_| Ok(None)),
                threads_changed: Box::new(|_, _| {}),
                resolve_cli: Box::new(move |_| Some(bin.clone())),
            },
        );
        let thread = engine
            .with(|i| {
                i.settings.mutate(&i.dir.clone(), None, |s| {
                    s.cli_providers.push(CliProvider {
                        instance_id: "claude".into(),
                        cli: "claude".into(),
                        label: "Claude".into(),
                        enabled: true,
                        models: vec![],
                    });
                    Ok(())
                })?;
                i.store.create(
                    &ThreadCreate {
                        operation_id: "c1".into(),
                        project: dir.to_string_lossy().into_owned(),
                        instance_id: "claude".into(),
                        model: "m".into(),
                        title: "T".into(),
                        cwd: Some(dir.to_string_lossy().into_owned()),
                        effort: None,
                        workspace_id: None,
                        permissions: Permissions::default(),
                        workspace: Workspace::default(),
                    },
                    "T",
                    ThreadKind::Cli,
                )
            })
            .unwrap();
        (engine, thread)
    }

    async fn send(
        engine: &Engine,
        thread: &ThreadSummary,
    ) -> (ThreadSendAccepted, UnboundedReceiver<ThreadStreamEvent>) {
        let (tx, rx) = unbounded_channel();
        let accepted = engine
            .send(
                ThreadSend {
                    operation_id: "s1".into(),
                    thread_id: thread.thread_id.clone(),
                    expected_revision: thread.revision,
                    instance_id: "claude".into(),
                    model: "m".into(),
                    text: "hi".into(),
                    attachments: vec![],
                },
                Arc::new(Recorder(tx)),
            )
            .await
            .unwrap();
        (accepted, rx)
    }

    fn assistant(engine: &Engine, thread_id: &str) -> ThreadMessage {
        let snap = engine.with(|i| i.store.snapshot(thread_id)).unwrap();
        snap.messages.into_iter().last().unwrap()
    }

    #[tokio::test]
    async fn cli_send_streams_and_persists_without_a_host_ui() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, thread) = setup(
            r#"printf '%s\n' '{"type":"stream_event","event":{"type":"content_block_delta","delta":{"type":"text_delta","text":"hello"}}}' '{"type":"result","result":"hello"}'"#,
            dir.path(),
        );
        let (accepted, mut rx) = send(&engine, &thread).await;
        let mut deltas = String::new();
        let message = loop {
            match rx.recv().await.expect("final event") {
                ThreadStreamEvent::Delta { text, .. } => deltas.push_str(&text),
                ThreadStreamEvent::Final { message, .. } => break message,
            }
        };
        assert_eq!(deltas, "hello");
        assert_eq!(message.message_id, accepted.assistant.message_id);
        assert_eq!(message.state, MessageState::Completed);
        let stored = assistant(&engine, &thread.thread_id);
        assert_eq!(
            (stored.state, stored.content.as_str()),
            (MessageState::Completed, "hello")
        );
        assert!(!engine.is_active(&thread.thread_id).unwrap());
    }

    #[tokio::test]
    async fn stop_kills_the_cli_and_persists_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, thread) = setup(
            r#"printf '%s\n' '{"type":"stream_event","event":{"type":"content_block_delta","delta":{"type":"text_delta","text":"part"}}}'
exec sleep 60"#,
            dir.path(),
        );
        let (_, mut rx) = send(&engine, &thread).await;
        assert!(matches!(
            rx.recv().await,
            Some(ThreadStreamEvent::Delta { .. })
        ));
        let stopper = engine.clone();
        let id = thread.thread_id.clone();
        blocking(move || stopper.stop(&id)).await.unwrap();
        let Some(ThreadStreamEvent::Final { message, .. }) = rx.recv().await else {
            panic!("expected a final event");
        };
        assert_eq!(message.state, MessageState::Stopped);
        assert_eq!(assistant(&engine, &thread.thread_id).content, "part");
        assert!(engine.0.groups.lock().unwrap().is_empty());
    }

    #[test]
    fn group_guard_untracks_and_exit_drains() {
        let engine = Engine::new(
            PathBuf::new(),
            Hooks {
                api_key: Box::new(|_| Ok(None)),
                threads_changed: Box::new(|_, _| {}),
                resolve_cli: Box::new(|_| None),
            },
        );
        let guard = engine.track_group(Some(4_000_000_000)); // not a real group
        assert_eq!(engine.0.groups.lock().unwrap().len(), 1);
        drop(guard);
        assert!(engine.0.groups.lock().unwrap().is_empty());
        let _held = engine.track_group(Some(4_000_000_000));
        engine.kill_cli_groups();
        assert!(engine.0.groups.lock().unwrap().is_empty());
    }

    #[test]
    fn active_guard_removes_its_own_entry_only() {
        let engine = Engine::new(
            PathBuf::new(),
            Hooks {
                api_key: Box::new(|_| Ok(None)),
                threads_changed: Box::new(|_, _| {}),
                resolve_cli: Box::new(|_| None),
            },
        );
        let first = ActiveGuard::new(&engine, "t".into()).unwrap();
        let second = ActiveGuard::new(&engine, "t".into()).unwrap();
        drop(first);
        assert!(engine.active().unwrap().contains_key("t"));
        let handle = std::thread::spawn(move || {
            let _guard = second;
            panic!("stream failed");
        });
        assert!(handle.join().is_err());
        assert!(engine.active().unwrap().is_empty());
    }

    #[test]
    fn truncation_notes() {
        assert_eq!(truncation_note(Some("length")), Some(NOTE_LIMIT));
        assert_eq!(truncation_note(Some("max_tokens")), Some(NOTE_LIMIT));
        assert_eq!(truncation_note(Some("stop")), None);
        assert_eq!(truncation_note(None), None);
    }
}
