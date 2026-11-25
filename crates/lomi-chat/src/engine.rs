//! Chat send lifecycle without any UI framework: storage handle, the registry of
//! running generations, and the send pipeline (validate, commit the dispatch
//! intent, stream, commit the outcome). Hosts inject event delivery, change
//! notification, API key lookup and CLI resolution through [`Hooks`].
use crate::{
    acp::{self, AcpSession},
    attachments::{self, Attachment, Kind},
    checkpoint::{self, UndoReport},
    cli,
    codex_server::{self, CodexSession},
    http,
    session::{self, ClaudeSession},
    settings::{self, *},
    storage::{self, Owner},
    store::{self, *},
};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{
        Arc, Mutex, MutexGuard, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{io::AsyncReadExt, sync::Notify};
use zeroize::Zeroizing;

const FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(750);
const FLUSH_BYTES: usize = 16 * 1024;
/// Stored assistant output never exceeds what a later request could carry.
const CONTENT_CAP: usize = store::MAX_CONTEXT;
const NOTE_LIMIT: &str = "Response hit the output limit.";
const NOTE_SIZE: &str = "Response exceeded the size limit and was truncated.";
/// Idle persistent Claude sessions are killed after this long.
const SESSION_IDLE: Duration = Duration::from_secs(600);
const REAP_EVERY: Duration = Duration::from_secs(30);
/// How long a stopped turn waits for the CLI's `result` before the process is killed.
const INTERRUPT_WAIT: Duration = Duration::from_secs(5);

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
    /// Persistent Claude processes by thread. Never held across `.await`.
    sessions: Mutex<HashMap<String, Arc<ClaudeSession>>>,
    /// Persistent Codex app-servers by thread. Never held across `.await`.
    codex: Mutex<HashMap<String, Arc<CodexSession>>>,
    /// Persistent ACP agents (`agy acp`, `kimi acp`) by thread. Never held across `.await`.
    acp: Mutex<HashMap<String, Arc<AcpSession>>>,
    reaper: AtomicBool,
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
            sessions: Mutex::new(HashMap::new()),
            codex: Mutex::new(HashMap::new()),
            acp: Mutex::new(HashMap::new()),
            reaper: AtomicBool::new(false),
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
            let mut store = Store::open(&dir)?;
            store.restricted = self.0.restricted;
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

    fn sessions(&self) -> Result<MutexGuard<'_, HashMap<String, Arc<ClaudeSession>>>, String> {
        self.0
            .sessions
            .lock()
            .map_err(|_| "Chat state is unavailable.".into())
    }

    fn codex_sessions(&self) -> Result<MutexGuard<'_, HashMap<String, Arc<CodexSession>>>, String> {
        self.0
            .codex
            .lock()
            .map_err(|_| "Chat state is unavailable.".into())
    }

    fn acp_sessions(&self) -> Result<MutexGuard<'_, HashMap<String, Arc<AcpSession>>>, String> {
        self.0
            .acp
            .lock()
            .map_err(|_| "Chat state is unavailable.".into())
    }

    /// The thread's warm ACP agent, or a new one when it is missing, dead or its settings changed.
    fn live_acp(
        &self,
        thread_id: &str,
        run: &CliJob,
        p: &acp::Params,
    ) -> Result<Arc<AcpSession>, String> {
        let key = session::Key::with(&run.spec, p.key_args());
        let mut map = self.acp_sessions()?;
        if let Some(s) = map.get(thread_id) {
            if s.alive() && s.key == key {
                return Ok(s.clone());
            }
            s.kill();
        }
        let s = AcpSession::spawn(&run.spec, p, |pid| self.track_group(pid))?;
        map.insert(thread_id.into(), s.clone());
        drop(map);
        self.start_reaper();
        Ok(s)
    }

    /// Kills an ACP session and forgets it unless a newer one replaced it.
    fn drop_acp(&self, thread_id: &str, s: &Arc<AcpSession>) {
        s.kill();
        if let Ok(mut map) = self.acp_sessions()
            && map.get(thread_id).is_some_and(|c| Arc::ptr_eq(c, s))
        {
            map.remove(thread_id);
        }
    }

    /// The thread's warm Codex app-server, or a new one when it is missing, dead or its settings changed.
    fn live_codex(
        &self,
        thread_id: &str,
        run: &CliJob,
        p: &codex_server::Params,
    ) -> Result<Arc<CodexSession>, String> {
        let key = session::Key::with(&run.spec, p.key_args());
        let mut map = self.codex_sessions()?;
        if let Some(s) = map.get(thread_id) {
            if s.alive() && s.key == key {
                return Ok(s.clone());
            }
            s.kill();
        }
        let s = CodexSession::spawn(&run.spec, p, |pid| self.track_group(pid))?;
        map.insert(thread_id.into(), s.clone());
        drop(map);
        self.start_reaper();
        Ok(s)
    }

    /// Kills a Codex session and forgets it unless a newer one replaced it.
    fn drop_codex(&self, thread_id: &str, s: &Arc<CodexSession>) {
        s.kill();
        if let Ok(mut map) = self.codex_sessions()
            && map.get(thread_id).is_some_and(|c| Arc::ptr_eq(c, s))
        {
            map.remove(thread_id);
        }
    }

    /// The thread's warm Claude process, or a new one when it is missing, dead or its settings changed.
    fn live_session(&self, thread_id: &str, run: &CliJob) -> Result<Arc<ClaudeSession>, String> {
        let key = session::Key::new(&run.spec);
        let mut map = self.sessions()?;
        if let Some(s) = map.get(thread_id) {
            if s.alive() && s.key == key {
                return Ok(s.clone());
            }
            s.kill();
        }
        let s = ClaudeSession::spawn(&run.spec, run.session.as_deref(), |pid| {
            self.track_group(pid)
        })?;
        map.insert(thread_id.into(), s.clone());
        drop(map);
        self.start_reaper();
        Ok(s)
    }

    /// Kills a session and forgets it unless a newer one replaced it.
    fn drop_session(&self, thread_id: &str, s: &Arc<ClaudeSession>) {
        s.kill();
        if let Ok(mut map) = self.sessions()
            && map.get(thread_id).is_some_and(|c| Arc::ptr_eq(c, s))
        {
            map.remove(thread_id);
        }
    }

    /// Kills the thread's warm session, e.g. after the thread was deleted.
    pub fn forget_session(&self, thread_id: &str) {
        if let Some(s) = self.sessions().ok().and_then(|mut m| m.remove(thread_id)) {
            s.kill();
        }
        if let Some(s) = self
            .codex_sessions()
            .ok()
            .and_then(|mut m| m.remove(thread_id))
        {
            s.kill();
        }
        if let Some(s) = self
            .acp_sessions()
            .ok()
            .and_then(|mut m| m.remove(thread_id))
        {
            s.kill();
        }
    }

    /// Unified diff of one file of a turn. Only files recorded for the turn are allowed.
    /// Blocking: call from `spawn_blocking`.
    pub fn turn_diff(
        &self,
        thread_id: &str,
        message_id: &str,
        path: &str,
    ) -> Result<String, String> {
        let (cwd, cp) = self.turn_context(thread_id, message_id)?;
        if !cp.changes.files.iter().any(|f| f.path == path) {
            return Err("That file is not part of this turn.".into());
        }
        checkpoint::file_diff(&cwd, &cp.before, &cp.after, path)
    }

    /// Restores the files a turn changed and marks it undone; returns the report
    /// and the new thread revision. Blocking: call from `spawn_blocking`.
    pub fn turn_undo(
        &self,
        thread_id: &str,
        message_id: &str,
    ) -> Result<(UndoReport, u64), String> {
        // Registered as active for the whole undo, so a send is refused meanwhile.
        let _guard = {
            let mut active = self.active()?;
            if active.contains_key(thread_id) {
                return Err("Stop the reply before undoing.".into());
            }
            let stop = Arc::new(Notify::new());
            active.insert(thread_id.into(), stop.clone());
            ActiveGuard {
                chat: self.clone(),
                thread_id: thread_id.into(),
                stop,
            }
        };
        let (cwd, cp) = self.turn_context(thread_id, message_id)?;
        if cp.changes.undone {
            return Err("This turn was already undone.".into());
        }
        let report = checkpoint::undo(&cwd, &cp.before, &cp.after)?;
        let revision = if report.restored.is_empty() {
            self.with(|i| Ok(i.store.thread(thread_id)?.revision))?
        } else {
            self.with(|i| i.store.mark_undone(thread_id, message_id))?
        };
        Ok((report, revision))
    }

    fn turn_context(
        &self,
        thread_id: &str,
        message_id: &str,
    ) -> Result<(std::path::PathBuf, Checkpoint), String> {
        self.with(|i| {
            let cwd = i
                .store
                .thread(thread_id)?
                .cwd
                .ok_or("This thread has no folder.")?;
            Ok((cwd.into(), i.store.turn_checkpoint(thread_id, message_id)?))
        })
    }

    /// Deletes the checkpoint refs of a deleted thread; best effort.
    /// Blocking: call from `spawn_blocking`.
    pub fn remove_checkpoints(&self, thread_id: &str, cwd: Option<&str>) {
        if let Some(cwd) = cwd {
            let _ = checkpoint::remove_refs(
                std::path::Path::new(cwd),
                &format!("refs/lomi/chat/{thread_id}/"),
            );
        }
    }

    /// Kills idle or dead sessions of threads without a running turn.
    fn reap_idle(&self, max: Duration) {
        let (Ok(mut map), Ok(mut codex), Ok(mut acp), Ok(active)) = (
            self.sessions(),
            self.codex_sessions(),
            self.acp_sessions(),
            self.active(),
        ) else {
            return;
        };
        let keep = |id: &String, w: &session::Wire| {
            let keep = active.contains_key(id) || (w.alive() && w.idle() < max);
            if !keep {
                w.kill();
            }
            keep
        };
        map.retain(|id, s| keep(id, s));
        codex.retain(|id, s| keep(id, s));
        acp.retain(|id, s| keep(id, s));
    }

    /// Kills sessions of deleted threads. Blocking: reads the store.
    fn reap_deleted(&self) {
        let ids: Vec<String> = match (
            self.sessions(),
            self.codex_sessions(),
            self.acp_sessions(),
            self.active(),
        ) {
            (Ok(map), Ok(codex), Ok(acp), Ok(active)) => map
                .keys()
                .chain(codex.keys())
                .chain(acp.keys())
                .filter(|id| !active.contains_key(*id))
                .cloned()
                .collect(),
            _ => return,
        };
        let gone = self.with(|i| {
            Ok(ids
                .into_iter()
                .filter(|id| i.store.thread(id).is_err_and(|e| e == GONE))
                .collect::<Vec<_>>())
        });
        if let Ok(gone) = gone {
            for id in gone {
                self.forget_session(&id);
            }
        }
    }

    /// Starts the single background reaper on first use. Needs a Tokio runtime.
    fn start_reaper(&self) {
        if self.0.reaper.swap(true, Ordering::Relaxed) {
            return;
        }
        let weak = Arc::downgrade(&self.0);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(REAP_EVERY).await;
                let Some(shared) = weak.upgrade() else { break };
                let engine = Engine(shared);
                engine.reap_idle(SESSION_IDLE);
                let _ = blocking(move || {
                    engine.reap_deleted();
                    Ok(())
                })
                .await;
            }
        });
    }

    /// Answers a pending tool-permission prompt of a running turn.
    pub fn respond(
        &self,
        thread_id: &str,
        request_id: &str,
        decision: Decision,
    ) -> Result<(), String> {
        let claude = self.sessions()?.get(thread_id).cloned();
        if let Some(s) = claude {
            return s.respond(request_id, decision);
        }
        let codex = self.codex_sessions()?.get(thread_id).cloned();
        if let Some(s) = codex {
            return s.respond(request_id, decision);
        }
        let s = self
            .acp_sessions()?
            .get(thread_id)
            .cloned()
            .ok_or(session::NOT_PENDING)?;
        s.respond(request_id, decision)
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
                // An undo holds the thread's active entry.
                if self.is_active(&t.thread_id)? {
                    return Err("This thread is already waiting for a response.".into());
                }
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
                        // Only the one-shot (Host) path reads the agent file; ACP threads use plan mode.
                        let agent_file = if id == "kimi"
                            && self.0.restricted
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
                let checkpoint_cwd = (matches!(target, Target::Cli(_))
                    && a.thread.permissions != Permissions::ReadOnly)
                    .then(|| a.thread.cwd.as_deref().map(std::path::PathBuf::from))
                    .flatten();
                let job = Job {
                    thread_id: a.thread.thread_id.clone(),
                    message_id: a.assistant.message_id.clone(),
                    model: request.model.clone(),
                    system: settings.behavior.system_instructions.clone(),
                    target,
                    guard,
                    checkpoint_cwd,
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
    /// Prompt of a turn run on the thread's persistent process (`spec` is then its argv).
    live: Option<String>,
    permissions: Permissions,
    /// Turn of a thread on the persistent Codex app-server (`spec` is then `app-server`).
    codex: Option<codex_server::Params>,
    /// Turn of a thread on the persistent ACP agent (`spec` is then `acp`).
    acp: Option<Box<acp::Params>>,
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
    /// Folder to checkpoint around the turn: CLI threads that may edit files.
    checkpoint_cwd: Option<std::path::PathBuf>,
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
    let live = cli_id == "claude" && !restricted;
    let server = cli_id == "codex" && !restricted;
    let agent = matches!(cli_id, "agy" | "kimi") && !restricted;
    let inv = cli::Invocation {
        cli: cli_id,
        model: &accepted.user.model,
        cwd: &cwd.to_string_lossy(),
        session: session.as_deref(),
        system,
        prompt: &prompt,
        agent_file,
        permissions: thread.permissions,
        effort: thread.effort.as_deref(),
        // A persistent process always gets the folder so later attachments need no restart.
        attach_dir: (live || !files.is_empty()).then_some(&*attach_dir),
        images: &images,
        restricted,
    };
    let (args, stdin) = if live {
        (cli::claude_session_argv(&inv), None)
    } else if server {
        (vec!["app-server".into()], None)
    } else if agent {
        (vec!["acp".into()], None)
    } else {
        cli::argv(&inv)
    };
    let codex = server.then(|| codex_server::Params {
        cwd: inv.cwd.into(),
        model: (inv.model != cli::DEFAULT_MODEL).then(|| inv.model.into()),
        effort: inv.effort.map(Into::into),
        permissions: inv.permissions,
        system: system.into(),
        prompt: prompt.clone(),
        images: images.clone(),
    });
    let acp = agent.then(|| {
        Box::new(acp::Params {
            cwd: inv.cwd.into(),
            model: (inv.model != cli::DEFAULT_MODEL).then(|| inv.model.into()),
            permissions: inv.permissions,
            prompt: prompt.clone(),
            images: images.clone(),
            attach_dir: attach_dir.clone().into_owned(),
        })
    });
    CliJob {
        cli: cli_id.into(),
        spec: cli::Spec {
            bin,
            args,
            stdin,
            interactive: live || server || agent,
            cwd,
        },
        session,
        codex,
        acp,
        live: live.then_some(prompt),
        permissions: thread.permissions,
    }
}

#[derive(Clone)]
struct Outcome {
    state: MessageState,
    content: String,
    stream_seq: u64,
    stop_reason: Option<String>,
    error: Option<String>,
    activity: Vec<Activity>,
    usage: Option<Usage>,
    /// The native session could not be spawned, resumed or handshaken (its stored id is stale).
    start_failed: bool,
}

impl Outcome {
    /// Failure before any stream state exists.
    fn failed(message: String, content: String, stream_seq: u64) -> Self {
        Self {
            start_failed: true,
            state: MessageState::Failed,
            content,
            stream_seq,
            stop_reason: None,
            error: Some(message),
            activity: Vec::new(),
            usage: None,
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
    checkpoint: Option<&Checkpoint>,
) -> Result<(ThreadSummary, ThreadMessage), String> {
    for attempt in 0..3u64 {
        let (chat, o) = (chat.clone(), outcome.clone());
        let checkpoint = checkpoint.cloned();
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
                        activity: &o.activity,
                        usage: o.usage.as_ref(),
                        checkpoint: checkpoint.as_ref(),
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
    // A stop during the checkpoint ends the turn before the CLI is started.
    let early = tokio::select! {
        p = capture_before(&job) => Some(p),
        _ = stop.notified() => None,
    };
    let (outcome, checkpoint) = match early {
        None => (stopped_outcome(Acc::new()), None),
        Some(pending) => {
            let mut outcome = stream(&chat, &job, &*sink, &stop).await;
            close_activities(&mut outcome.activity);
            let checkpoint = match pending {
                Some(p) => capture_after(p).await,
                None => None,
            };
            (outcome, checkpoint)
        }
    };
    let finished = commit_outcome(&chat, &job, &outcome, checkpoint.as_ref()).await;
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

/// A turn's "before" checkpoint, taken when the turn starts.
struct PendingCheckpoint {
    cwd: std::path::PathBuf,
    /// `refs/lomi/chat/<thread>/<message>`; holds the `before` and `after` refs.
    prefix: String,
    before: String,
}

/// Upper bound of one checkpoint operation; a slower repository gets no checkpoint this turn.
const CHECKPOINT_TIMEOUT: Duration = Duration::from_secs(20);

/// Runs blocking `work` for at most `limit`. A result that arrives after the
/// deadline (or after the caller gave up) is handed to `discard` instead.
async fn bounded<T: Send + 'static>(
    limit: Duration,
    work: impl FnOnce() -> T + Send + 'static,
    discard: impl FnOnce(T) + Send + 'static,
) -> Option<T> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::task::spawn_blocking(move || {
        if let Err(late) = tx.send(work()) {
            discard(late);
        }
    });
    tokio::time::timeout(limit, rx).await.ok()?.ok()
}

/// Records the folder state before a turn. Any failure only skips checkpoints.
/// The folder may also be edited by the user or other chats during the turn;
/// that is accepted (the diff can include those edits) and `undo` skips files
/// changed after the turn.
async fn capture_before(job: &Job) -> Option<PendingCheckpoint> {
    let cwd = job.checkpoint_cwd.clone()?;
    let prefix = format!("refs/lomi/chat/{}/{}", job.thread_id, job.message_id);
    let reference = format!("{prefix}/before");
    let (dir, late_dir, late_prefix) = (cwd.clone(), cwd.clone(), prefix.clone());
    let before = bounded(
        CHECKPOINT_TIMEOUT,
        move || checkpoint::capture(&dir, &reference).ok().flatten(),
        // The turn went on without it: drop the ref the late capture just wrote.
        move |late| {
            if late.is_some() {
                let _ = checkpoint::remove_refs(&late_dir, &late_prefix);
            }
        },
    )
    .await
    .flatten()?;
    Some(PendingCheckpoint {
        cwd,
        prefix,
        before,
    })
}

/// Records the state after the turn and its changed files; `None` (refs
/// removed) when nothing changed, git failed or it took too long.
async fn capture_after(p: PendingCheckpoint) -> Option<Checkpoint> {
    let (late_cwd, late_prefix) = (p.cwd.clone(), p.prefix.clone());
    bounded(
        CHECKPOINT_TIMEOUT,
        move || {
            let done =
                checkpoint::capture(&p.cwd, &format!("{}/after", p.prefix)).and_then(|after| {
                    match after {
                        Some(after) => {
                            checkpoint::changes(&p.cwd, &p.before, &after).map(|f| (after, f))
                        }
                        None => Ok((String::new(), Vec::new())),
                    }
                });
            match done {
                Ok((after, files)) if !files.is_empty() => Some(Checkpoint {
                    before: p.before,
                    after,
                    changes: TurnChanges {
                        files,
                        undone: false,
                    },
                }),
                _ => {
                    let _ = checkpoint::remove_refs(&p.cwd, &p.prefix);
                    None
                }
            }
        },
        // Too late to be used: remove the refs, `before` included.
        move |_| {
            let _ = checkpoint::remove_refs(&late_cwd, &late_prefix);
        },
    )
    .await
    .flatten()
}

/// A finished turn has nothing still running or awaiting an answer.
fn close_activities(activity: &mut [Activity]) {
    for a in activity {
        if let Some(p) = a
            .approval
            .as_mut()
            .filter(|p| p.state == ApprovalState::Pending)
        {
            p.state = ApprovalState::Expired;
        }
        if a.status == ActivityStatus::Running {
            a.status = ActivityStatus::Failed;
        }
    }
}

fn stopped_outcome(acc: Acc) -> Outcome {
    Outcome {
        start_failed: false,
        state: MessageState::Stopped,
        content: acc.content,
        stream_seq: acc.seq,
        stop_reason: Some("stopped".into()),
        error: None,
        activity: acc.activity,
        usage: acc.usage,
    }
}

/// Streamed assistant text: delta events to the webview plus periodic persistence.
struct Acc {
    content: String,
    /// UTF-16 length of `content`: the JS string index activities are anchored to.
    utf16: u64,
    seq: u64,
    pending: usize,
    last_flush: Instant,
    activity: Vec<Activity>,
    usage: Option<Usage>,
}

impl Acc {
    fn new() -> Self {
        Self {
            content: String::new(),
            utf16: 0,
            seq: 0,
            pending: 0,
            last_flush: Instant::now(),
            activity: Vec::new(),
            usage: None,
        }
    }

    /// Inserts or replaces an activity by id and emits its full state. A new id is
    /// anchored at the current text length; an update keeps its first position.
    fn upsert(&mut self, message_id: &str, sink: &dyn EventSink, mut a: Activity) {
        a.clamp();
        if let Some(i) = self.activity.iter().position(|e| e.id == a.id) {
            a.at = self.activity[i].at;
            // The CLI's own tool events know nothing about the permission prompt.
            if a.approval.is_none() {
                a.approval = self.activity[i].approval.clone();
            }
            self.activity[i] = a.clone();
        // An activity with an approval is never dropped: the turn would wait for it forever.
        } else if self.activity.len() < MAX_ACTIVITIES || a.approval.is_some() {
            a.at = self.utf16;
            self.activity.push(a.clone());
        } else {
            return;
        }
        self.pending += 1 + a.title.len() + a.detail.as_ref().map_or(0, String::len);
        sink.send(ThreadStreamEvent::Activity {
            message_id: message_id.into(),
            activity: a,
        });
    }

    /// Moves matching pending approvals to `to` and emits the changed activities.
    fn settle(
        &mut self,
        message_id: &str,
        sink: &dyn EventSink,
        pick: impl Fn(&Approval) -> bool,
        to: ApprovalState,
    ) {
        let changed: Vec<Activity> = self
            .activity
            .iter()
            .filter(|a| {
                a.approval
                    .as_ref()
                    .is_some_and(|p| p.state == ApprovalState::Pending && pick(p))
            })
            .cloned()
            .map(|mut a| {
                a.approval.as_mut().expect("filtered").state = to;
                // An expired prompt means the tool never ran.
                if to == ApprovalState::Expired && a.status == ActivityStatus::Running {
                    a.status = ActivityStatus::Failed;
                }
                a
            })
            .collect();
        for a in changed {
            self.upsert(message_id, sink, a);
        }
    }

    /// Failed outcome that keeps what streamed so far.
    fn failed(self, message: String) -> Outcome {
        Outcome {
            start_failed: false,
            state: MessageState::Failed,
            content: self.content,
            stream_seq: self.seq,
            stop_reason: None,
            error: Some(message),
            activity: self.activity,
            usage: self.usage,
        }
    }

    /// Appends and emits `text`; false when it would exceed the stored-content cap.
    fn push(&mut self, message_id: &str, sink: &dyn EventSink, mut text: String) -> bool {
        // Text resuming after an activity must not glue onto the previous block.
        if !text.is_empty()
            && !self.content.is_empty()
            && !self.content.ends_with('\n')
            && self.activity.last().is_some_and(|a| a.at == self.utf16)
        {
            text.insert_str(0, "\n\n");
        }
        if self.content.len() + text.len() > CONTENT_CAP {
            return false;
        }
        self.content.push_str(&text);
        self.utf16 += text.encode_utf16().count() as u64;
        self.seq += 1;
        self.pending += text.len();
        sink.send(ThreadStreamEvent::Delta {
            message_id: message_id.into(),
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
        let (activity, usage) = (self.activity.clone(), self.usage.clone());
        let _ = blocking(move || {
            chat.with(|i| i.store.flush(&id, &text, seq, &activity, usage.as_ref()))
        })
        .await;
        self.pending = 0;
        self.last_flush = Instant::now();
    }

    fn oversized(self) -> Outcome {
        Outcome {
            start_failed: false,
            state: MessageState::Completed,
            content: self.content,
            stream_seq: self.seq,
            stop_reason: Some("size_limit".into()),
            error: Some(NOTE_SIZE.into()),
            activity: self.activity,
            usage: self.usage,
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
        _ = &mut stopped => return stopped_outcome(Acc::new()),
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
            _ = &mut stopped => return stopped_outcome(acc),
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
                        if !acc.push(&job.message_id, sink, text) {
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
        return acc.failed(message);
    }
    if oversized {
        return acc.oversized();
    }
    if !done && stop_reason.is_none() {
        return acc.failed(
            "The connection closed before the response finished; the partial response was kept."
                .into(),
        );
    }
    Outcome {
        start_failed: false,
        state: MessageState::Completed,
        content: acc.content,
        stream_seq: acc.seq,
        error: truncation_note(stop_reason.as_deref()).map(Into::into),
        stop_reason,
        activity: acc.activity,
        usage: acc.usage,
    }
}

/// How long the pipes may stay open after the CLI exits or reports its final event.
const DRAIN: Duration = session::DRAIN;

/// Runs the CLI, then settles the stored session id. A session id is kept only
/// once the turn produced text or exited successfully (it may not exist
/// otherwise). A resumed send whose session could not be started clears it, so
/// the next send starts fresh instead of resuming a session the CLI cannot find;
/// a failure of the turn itself (rate limit, ...) keeps it.
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
    } else if run.session.is_some() && outcome.start_failed {
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
    if let Some(prompt) = &run.live {
        return run_live(chat, job, run, prompt, sink, stop, session).await;
    }
    if let Some(p) = &run.codex {
        return run_codex(chat, job, run, p, sink, stop, session).await;
    }
    if let Some(p) = &run.acp {
        return run_acp(chat, job, run, p, sink, stop, session).await;
    }
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
    // Any stdout at all: without it a failed exit is a failed start (e.g. an unknown `--resume`).
    let mut heard = false;

    'read: loop {
        let read = tokio::select! {
            _ = &mut stopped => return stopped_outcome(acc),
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
        heard |= n > 0;
        let lines = if n == 0 {
            splitter.finish()
        } else {
            splitter.push(&buf[..n])
        };
        for line in lines {
            for event in parser.line(&line) {
                match event {
                    cli::Ev::Text(text) => {
                        if !acc.push(&job.message_id, sink, text) {
                            oversized = true;
                            break 'read;
                        }
                    }
                    cli::Ev::Activity(a) => acc.upsert(&job.message_id, sink, a),
                    cli::Ev::Usage(u) => acc.usage = Some(u),
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
        return acc.failed(message);
    }
    if oversized {
        return acc.oversized();
    }
    let (success, status, stderr) = tokio::select! {
        _ = &mut stopped => return stopped_outcome(acc),
        r = proc.finish() => r,
    };
    if !success {
        let detail = if stderr.is_empty() {
            String::new()
        } else {
            format!(": {stderr}")
        };
        let mut outcome = acc.failed(format!("The CLI exited ({status}){detail}"));
        outcome.start_failed = !heard;
        return outcome;
    }
    if acc.content.is_empty() {
        // Some CLIs only report the complete answer at the end.
        let text = fallback.unwrap_or_default();
        if text.is_empty() || !acc.push(&job.message_id, sink, text) {
            return acc.failed("The CLI returned no response.".into());
        }
    }
    Outcome {
        start_failed: false,
        state: MessageState::Completed,
        content: acc.content.trim_end().to_string(),
        stream_seq: acc.seq,
        stop_reason: Some("stop".into()),
        error: None,
        activity: acc.activity,
        usage: acc.usage,
    }
}

/// Runs one turn on the thread's persistent Claude process. Tool-permission
/// prompts become activities with a pending approval; the turn ends at the
/// CLI's `result` line and the process stays warm for the next one.
async fn run_live(
    chat: &Engine,
    job: &Job,
    run: &CliJob,
    prompt: &str,
    sink: &dyn EventSink,
    stop: &Notify,
    sid: &mut Option<String>,
) -> Outcome {
    let stopped = stop.notified();
    tokio::pin!(stopped);
    let session = match chat.live_session(&job.thread_id, run) {
        Ok(s) => s,
        Err(m) => return Outcome::failed(m, String::new(), 0),
    };
    if let Err(m) = mark_streaming(chat, job).await {
        return Outcome::failed(m, String::new(), 0);
    }
    let mut guard = session.rx().await;
    let rx = &mut *guard; // split borrow of the two receivers
    rx.drain();
    if session.send_user(prompt).is_err() {
        chat.drop_session(&job.thread_id, &session);
        return Outcome::failed(session.exit_detail(), String::new(), 0);
    }
    let mut parser = cli::Parser::new(&run.cli);
    let mut acc = Acc::new();
    let mut fallback = None::<String>;
    let (mut failure, mut oversized) = (None::<String>, false);
    // Set once a stop sent the interrupt: the CLI then gets `INTERRUPT_WAIT` to end the turn.
    let mut deadline: Option<tokio::time::Instant> = None;
    // The process produced no output at all: it never started (e.g. `--resume` was refused).
    let mut heard = false;
    loop {
        let line = tokio::select! {
            _ = &mut stopped, if deadline.is_none() => {
                session.deny_pending();
                acc.settle(&job.message_id, sink, |_| true, ApprovalState::Expired);
                session.interrupt();
                deadline = Some(tokio::time::Instant::now() + INTERRUPT_WAIT);
                continue;
            }
            _ = tokio::time::sleep_until(deadline.unwrap_or_else(tokio::time::Instant::now)), if deadline.is_some() => {
                chat.drop_session(&job.thread_id, &session);
                return stopped_outcome(acc);
            }
            Some(a) = rx.answers.recv() => {
                settle_answer(&mut acc, &job.message_id, sink, &a);
                continue;
            }
            l = rx.lines.recv() => l,
        };
        let Some(line) = line else {
            chat.drop_session(&job.thread_id, &session);
            acc.settle(&job.message_id, sink, |_| true, ApprovalState::Expired);
            if deadline.is_some() {
                return stopped_outcome(acc);
            }
            let start_failed = !heard;
            let mut outcome = acc.failed(session.exit_detail());
            outcome.start_failed = start_failed;
            return outcome;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        heard |= v["type"] != "control_response";
        match v["type"].as_str() {
            Some("control_response") => continue,
            Some("control_cancel_request") => {
                if let Some(id) = v["request_id"].as_str() {
                    session.cancel_pending(id);
                    acc.settle(
                        &job.message_id,
                        sink,
                        |p| p.request_id == id,
                        ApprovalState::Expired,
                    );
                }
                continue;
            }
            Some("control_request") => {
                on_control(
                    &session,
                    run.permissions,
                    &v,
                    &mut acc,
                    &job.message_id,
                    sink,
                );
                continue;
            }
            _ => {}
        }
        for event in parser.line(&line) {
            match event {
                cli::Ev::Text(text) => oversized |= !acc.push(&job.message_id, sink, text),
                cli::Ev::Activity(a) => acc.upsert(&job.message_id, sink, a),
                cli::Ev::Usage(u) => acc.usage = Some(u),
                cli::Ev::Final(text) => fallback = Some(text),
                cli::Ev::Error(m) => failure = Some(http::redact(&m, None)),
                cli::Ev::Session(id) => {
                    if cli::valid_session(&id) {
                        *sid = Some(id);
                    }
                }
            }
        }
        if oversized {
            // The rest of the answer cannot be kept; end the process rather than consume it.
            chat.drop_session(&job.thread_id, &session);
            acc.settle(&job.message_id, sink, |_| true, ApprovalState::Expired);
            return acc.oversized();
        }
        if v["type"] == "result" {
            break;
        }
        acc.flush_due(chat, job).await;
    }
    // Answers already given but not yet applied win over expiry.
    while let Ok(a) = rx.answers.try_recv() {
        settle_answer(&mut acc, &job.message_id, sink, &a);
    }
    session.deny_pending();
    acc.settle(&job.message_id, sink, |_| true, ApprovalState::Expired);
    session.touch();
    if deadline.is_some() {
        return stopped_outcome(acc);
    }
    if let Some(message) = failure {
        return acc.failed(message);
    }
    if acc.content.is_empty() {
        let text = fallback.unwrap_or_default();
        if text.is_empty() || !acc.push(&job.message_id, sink, text) {
            return acc.failed("The CLI returned no response.".into());
        }
    }
    Outcome {
        start_failed: false,
        state: MessageState::Completed,
        content: acc.content.trim_end().to_string(),
        stream_seq: acc.seq,
        stop_reason: Some("stop".into()),
        error: None,
        activity: acc.activity,
        usage: acc.usage,
    }
}

/// Applies the user's answer to the matching pending approval.
fn settle_answer(acc: &mut Acc, message_id: &str, sink: &dyn EventSink, a: &session::Answer) {
    let state = if a.allowed {
        ApprovalState::Allowed
    } else {
        ApprovalState::Denied
    };
    acc.settle(message_id, sink, |p| p.request_id == a.request_id, state);
}

/// Runs one turn on the thread's persistent `codex app-server`. Approval
/// requests become activities with a pending approval; the turn ends at
/// `turn/completed` and the process stays warm for the next one.
async fn run_codex(
    chat: &Engine,
    job: &Job,
    run: &CliJob,
    p: &codex_server::Params,
    sink: &dyn EventSink,
    stop: &Notify,
    sid: &mut Option<String>,
) -> Outcome {
    let stopped = stop.notified();
    tokio::pin!(stopped);
    let session = match chat.live_codex(&job.thread_id, run, p) {
        Ok(s) => s,
        Err(m) => return Outcome::failed(m, String::new(), 0),
    };
    if let Err(m) = mark_streaming(chat, job).await {
        return Outcome::failed(m, String::new(), 0);
    }
    let mut guard = session.rx().await;
    let rx = &mut *guard; // split borrow of the two receivers
    rx.drain();
    let thread = match session.thread() {
        Some(t) => t,
        None => {
            let started = tokio::select! {
                _ = &mut stopped => None,
                r = codex_server::start(&session, rx, p, run.session.as_deref()) => Some(r),
            };
            match started {
                Some(Ok(t)) => t,
                Some(Err(m)) => {
                    chat.drop_codex(&job.thread_id, &session);
                    return Outcome::failed(http::redact(&m, None), String::new(), 0);
                }
                None => {
                    chat.drop_codex(&job.thread_id, &session);
                    return stopped_outcome(Acc::new());
                }
            }
        }
    };
    if cli::valid_session(&thread) {
        *sid = Some(thread.clone());
    }
    let turn_req = match session.request("turn/start", p.turn_params(&thread)) {
        Ok(id) => id,
        Err(_) => {
            chat.drop_codex(&job.thread_id, &session);
            return Outcome::failed(session.exit_detail(), String::new(), 0);
        }
    };
    let mut mapper = codex_server::Mapper::default();
    let mut acc = Acc::new();
    let (mut turn, mut end) = (None::<String>, None);
    let (mut failure, mut oversized, mut interrupted) = (None::<String>, false, false);
    // Set once a stop was requested: the server then gets `INTERRUPT_WAIT` to end the turn.
    let mut deadline: Option<tokio::time::Instant> = None;
    loop {
        // The turn id may arrive after the stop; the interrupt needs it.
        if deadline.is_some()
            && !interrupted
            && let Some(t) = &turn
        {
            session.interrupt(&thread, t);
            interrupted = true;
        }
        let line = tokio::select! {
            _ = &mut stopped, if deadline.is_none() => {
                session.decline_pending();
                acc.settle(&job.message_id, sink, |_| true, ApprovalState::Expired);
                deadline = Some(tokio::time::Instant::now() + INTERRUPT_WAIT);
                continue;
            }
            _ = tokio::time::sleep_until(deadline.unwrap_or_else(tokio::time::Instant::now)), if deadline.is_some() => {
                chat.drop_codex(&job.thread_id, &session);
                return stopped_outcome(acc);
            }
            Some(a) = rx.answers.recv() => {
                settle_answer(&mut acc, &job.message_id, sink, &a);
                continue;
            }
            l = rx.lines.recv() => l,
        };
        let Some(line) = line else {
            chat.drop_codex(&job.thread_id, &session);
            acc.settle(&job.message_id, sink, |_| true, ApprovalState::Expired);
            if deadline.is_some() {
                return stopped_outcome(acc);
            }
            return acc.failed(session.exit_detail());
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        match (v["method"].is_string(), v.get("id")) {
            // A server request: approvals wait for the user, the rest is refused.
            (true, Some(id)) => {
                match codex_server::parse_prompt(&v) {
                    Some(prompt) => {
                        on_prompt(
                            &session,
                            p.permissions,
                            prompt,
                            &mut acc,
                            &job.message_id,
                            sink,
                        );
                    }
                    None => {
                        let _ = session.write(codex_server::unsupported_line(id));
                    }
                }
                continue;
            }
            // A response; only the `turn/start` one matters.
            (false, Some(id)) => {
                if *id == turn_req {
                    if let Some(e) = v.get("error") {
                        let m = e["message"].as_str().unwrap_or("Codex refused the turn.");
                        failure = Some(http::redact(m, None));
                        break;
                    }
                    turn = codex_server::started_turn(&v).map(String::from).or(turn);
                }
                continue;
            }
            _ => {}
        }
        if v["method"] == "turn/started" {
            turn = codex_server::started_turn(&v).map(String::from).or(turn);
        }
        if let Some((id, e)) = codex_server::turn_end(&v) {
            // A late completion of an earlier, interrupted turn is not ours.
            if turn.as_deref().is_none_or(|t| t == id) {
                end = Some(e);
                break;
            }
            continue;
        }
        for event in mapper.notification(&v) {
            match event {
                cli::Ev::Text(text) => oversized |= !acc.push(&job.message_id, sink, text),
                cli::Ev::Activity(a) => acc.upsert(&job.message_id, sink, a),
                cli::Ev::Usage(u) => acc.usage = Some(u),
                _ => {}
            }
        }
        if oversized {
            // The rest of the answer cannot be kept; end the process rather than consume it.
            chat.drop_codex(&job.thread_id, &session);
            acc.settle(&job.message_id, sink, |_| true, ApprovalState::Expired);
            return acc.oversized();
        }
        acc.flush_due(chat, job).await;
    }
    // Answers already given but not yet applied win over expiry.
    while let Ok(a) = rx.answers.try_recv() {
        settle_answer(&mut acc, &job.message_id, sink, &a);
    }
    session.decline_pending();
    acc.settle(&job.message_id, sink, |_| true, ApprovalState::Expired);
    session.touch();
    if deadline.is_some() || end == Some(codex_server::End::Interrupted) {
        return stopped_outcome(acc);
    }
    if let Some(codex_server::End::Failed(m)) = end {
        failure = Some(http::redact(&m, None));
    }
    if let Some(message) = failure {
        return acc.failed(message);
    }
    if acc.content.is_empty() && acc.activity.is_empty() {
        return acc.failed("The CLI returned no response.".into());
    }
    Outcome {
        start_failed: false,
        state: MessageState::Completed,
        content: acc.content.trim_end().to_string(),
        stream_seq: acc.seq,
        stop_reason: Some("stop".into()),
        error: None,
        activity: acc.activity,
        usage: acc.usage,
    }
}

/// Runs one turn on the thread's persistent ACP agent. Permission requests
/// become activities with a pending approval; the turn ends with the
/// `session/prompt` response and the process stays warm for the next one.
async fn run_acp(
    chat: &Engine,
    job: &Job,
    run: &CliJob,
    p: &acp::Params,
    sink: &dyn EventSink,
    stop: &Notify,
    sid: &mut Option<String>,
) -> Outcome {
    let stopped = stop.notified();
    tokio::pin!(stopped);
    let session = match chat.live_acp(&job.thread_id, run, p) {
        Ok(s) => s,
        Err(m) => return Outcome::failed(m, String::new(), 0),
    };
    if let Err(m) = mark_streaming(chat, job).await {
        return Outcome::failed(m, String::new(), 0);
    }
    let mut guard = session.rx().await;
    let rx = &mut *guard; // split borrow of the two receivers
    rx.drain();
    let native = match session.native() {
        Some(n) => n,
        None => {
            let started = tokio::select! {
                _ = &mut stopped => None,
                r = acp::start(&session, rx, p, run.session.as_deref()) => Some(r),
            };
            match started {
                Some(Ok(n)) => n,
                Some(Err(m)) => {
                    chat.drop_acp(&job.thread_id, &session);
                    return Outcome::failed(http::redact(&m, None), String::new(), 0);
                }
                None => {
                    chat.drop_acp(&job.thread_id, &session);
                    return stopped_outcome(Acc::new());
                }
            }
        }
    };
    if cli::valid_session(&native) {
        *sid = Some(native.clone());
    }
    let images = if session.accepts_images() {
        acp::image_blocks(&p.images).await
    } else {
        Vec::new()
    };
    let Ok(prompt_req) = session.request("session/prompt", p.prompt_params(&native, images)) else {
        chat.drop_acp(&job.thread_id, &session);
        return Outcome::failed(session.exit_detail(), String::new(), 0);
    };
    let mut mapper = acp::Mapper::default();
    let mut acc = Acc::new();
    let (mut end, mut failure, mut oversized) = (None::<acp::End>, None::<String>, false);
    // Set once a stop was requested: the agent then gets `INTERRUPT_WAIT` to end the turn.
    let mut deadline: Option<tokio::time::Instant> = None;
    loop {
        let line = tokio::select! {
            _ = &mut stopped, if deadline.is_none() => {
                session.cancel(&native);
                session.cancel_pending();
                acc.settle(&job.message_id, sink, |_| true, ApprovalState::Expired);
                deadline = Some(tokio::time::Instant::now() + INTERRUPT_WAIT);
                continue;
            }
            _ = tokio::time::sleep_until(deadline.unwrap_or_else(tokio::time::Instant::now)), if deadline.is_some() => {
                chat.drop_acp(&job.thread_id, &session);
                return stopped_outcome(acc);
            }
            Some(a) = rx.answers.recv() => {
                settle_answer(&mut acc, &job.message_id, sink, &a);
                continue;
            }
            l = rx.lines.recv() => l,
        };
        let Some(line) = line else {
            chat.drop_acp(&job.thread_id, &session);
            acc.settle(&job.message_id, sink, |_| true, ApprovalState::Expired);
            if deadline.is_some() {
                return stopped_outcome(acc);
            }
            return acc.failed(session.exit_detail());
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        match (v["method"].is_string(), v.get("id")) {
            // An agent request: permissions wait for the user, the rest is refused.
            (true, Some(id)) => {
                match acp::parse_prompt(&v) {
                    Some(prompt) => {
                        on_acp_prompt(
                            &session,
                            &mut mapper,
                            prompt,
                            &mut acc,
                            &job.message_id,
                            sink,
                        );
                    }
                    None => {
                        let _ = session.write(acp::unsupported_line(id));
                    }
                }
                continue;
            }
            // A response; only the `session/prompt` one matters.
            (false, Some(id)) => {
                if *id == prompt_req {
                    if let Some(e) = v.get("error") {
                        let m = e["message"].as_str().unwrap_or("The CLI refused the turn.");
                        failure = Some(http::redact(m, None));
                    } else {
                        acc.usage = acp::usage(&v["result"]).or(acc.usage.take());
                        end = Some(acp::turn_end(&v["result"]));
                    }
                    break;
                }
                continue;
            }
            _ => {}
        }
        for event in mapper.update(&v) {
            match event {
                cli::Ev::Text(text) => oversized |= !acc.push(&job.message_id, sink, text),
                cli::Ev::Activity(a) => acc.upsert(&job.message_id, sink, a),
                _ => {}
            }
        }
        if oversized {
            // The rest of the answer cannot be kept; end the process rather than consume it.
            chat.drop_acp(&job.thread_id, &session);
            acc.settle(&job.message_id, sink, |_| true, ApprovalState::Expired);
            return acc.oversized();
        }
        acc.flush_due(chat, job).await;
    }
    for event in mapper.finish() {
        if let cli::Ev::Activity(a) = event {
            acc.upsert(&job.message_id, sink, a);
        }
    }
    // Answers already given but not yet applied win over expiry.
    while let Ok(a) = rx.answers.try_recv() {
        settle_answer(&mut acc, &job.message_id, sink, &a);
    }
    session.cancel_pending();
    acc.settle(&job.message_id, sink, |_| true, ApprovalState::Expired);
    session.touch();
    if deadline.is_some() || end == Some(acp::End::Cancelled) {
        return stopped_outcome(acc);
    }
    if let Some(acp::End::Failed(m)) = &end {
        failure = Some(http::redact(m, None));
    }
    if let Some(message) = failure {
        return acc.failed(message);
    }
    if acc.content.is_empty() {
        return acc.failed("The CLI returned no response.".into());
    }
    let stop_reason = match end {
        Some(acp::End::Done(r)) => Some(r.to_string()),
        _ => Some("stop".into()),
    };
    Outcome {
        start_failed: false,
        state: MessageState::Completed,
        content: acc.content.trim_end().to_string(),
        stream_seq: acc.seq,
        error: truncation_note(stop_reason.as_deref()).map(Into::into),
        stop_reason,
        activity: acc.activity,
        usage: acc.usage,
    }
}

/// Turns a permission request into a pending approval on its activity. A
/// read-only thread never sees requests for anything that may change things:
/// those are rejected here and the activity shows as denied.
fn on_acp_prompt(
    session: &AcpSession,
    mapper: &mut acp::Mapper,
    prompt: acp::Prompt,
    acc: &mut Acc,
    message_id: &str,
    sink: &dyn EventSink,
) {
    let Some(mut a) = mapper.tool(&prompt.tool) else {
        let _ = session.write(acp::unsupported_line(&prompt.id));
        return;
    };
    let denied = session.permissions == Permissions::ReadOnly && acp::mutating(a.kind);
    // Registered before the UI sees it, so an immediate answer finds it.
    let request_id = if denied {
        session.scoped(&prompt)
    } else {
        session.add_pending(&prompt)
    };
    a.approval = Some(Approval {
        request_id,
        state: if denied {
            ApprovalState::Denied
        } else {
            ApprovalState::Pending
        },
        can_remember: prompt.remember && !denied,
    });
    if denied {
        a.status = ActivityStatus::Failed;
        session.reject(&prompt);
    } else {
        a.status = ActivityStatus::Running;
    }
    acc.upsert(message_id, sink, a);
}

/// Turns an approval request into a pending approval on its activity. A
/// read-only thread is never asked: Lomi declines on its own authority.
fn on_prompt(
    session: &CodexSession,
    permissions: Permissions,
    prompt: codex_server::Prompt,
    acc: &mut Acc,
    message_id: &str,
    sink: &dyn EventSink,
) {
    let mut a = acc
        .activity
        .iter()
        .find(|a| a.id == prompt.item_id)
        .cloned()
        .unwrap_or_else(|| prompt.activity());
    let denied = permissions == Permissions::ReadOnly;
    let request_id = if denied {
        let _ = session.write(codex_server::decision_line(
            &prompt.id,
            Decision::Deny,
            false,
        ));
        session.scoped(&prompt)
    } else {
        session.add_pending(&prompt)
    };
    a.status = if denied {
        ActivityStatus::Failed
    } else {
        ActivityStatus::Running
    };
    a.approval = Some(Approval {
        request_id,
        state: if denied {
            ApprovalState::Denied
        } else {
            ApprovalState::Pending
        },
        can_remember: prompt.remember && !denied,
    });
    acc.upsert(message_id, sink, a);
}

/// Handles a `control_request` line: permission prompts become pending approvals, the rest is refused.
/// A read-only thread is not asked about tools that may change things; they are denied here.
fn on_control(
    session: &ClaudeSession,
    permissions: Permissions,
    v: &serde_json::Value,
    acc: &mut Acc,
    message_id: &str,
    sink: &dyn EventSink,
) {
    let Some(t) = session::parse_tool_request(v) else {
        if let Some(id) = v["request_id"].as_str() {
            let _ = session.write(session::unsupported_line(id));
        }
        return;
    };
    let mut a = acc
        .activity
        .iter()
        .find(|a| a.id == t.tool_use_id)
        .cloned()
        .unwrap_or_else(|| cli::claude_activity(&t.tool_use_id, &t.tool_name, &t.input));
    let denied = permissions == Permissions::ReadOnly && !session::read_only_tool(&t.tool_name);
    a.status = if denied {
        ActivityStatus::Failed
    } else {
        ActivityStatus::Running
    };
    a.approval = Some(Approval {
        request_id: t.request_id.clone(),
        state: if denied {
            ApprovalState::Denied
        } else {
            ApprovalState::Pending
        },
        can_remember: t.suggestions.is_some() && !denied,
    });
    if denied {
        let _ = session.write(session::reply_line(&t, Decision::Deny, false));
    } else {
        // Registered before the UI sees it, so an immediate answer finds it.
        session.add_pending(t);
    }
    acc.upsert(message_id, sink, a);
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
    /// `restricted` selects the one-shot path; otherwise the script is a persistent session.
    fn setup(body: &str, dir: &Path, restricted: bool) -> (Engine, ThreadSummary) {
        setup_cli("claude", body, dir, restricted)
    }

    /// Like [`setup`] for any CLI; the provider instance id is the CLI id.
    fn setup_cli(
        cli_id: &str,
        body: &str,
        dir: &Path,
        restricted: bool,
    ) -> (Engine, ThreadSummary) {
        setup_with(cli_id, body, dir, restricted, Permissions::default(), dir)
    }

    /// Like [`setup_cli`] with explicit thread permissions and working folder.
    fn setup_with(
        cli_id: &str,
        body: &str,
        dir: &Path,
        restricted: bool,
        permissions: Permissions,
        cwd: &Path,
    ) -> (Engine, ThreadSummary) {
        let bin = dir.join(cli_id);
        std::fs::write(&bin, format!("#!/bin/sh\n{body}")).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let hooks = Hooks {
            api_key: Box::new(|_| Ok(None)),
            threads_changed: Box::new(|_, _| {}),
            resolve_cli: Box::new(move |_| Some(bin.clone())),
        };
        let root = dir.join("data");
        let engine = if restricted {
            Engine::restricted(root, hooks)
        } else {
            Engine::new(root, hooks)
        };
        let thread = engine
            .with(|i| {
                i.settings.mutate(&i.dir.clone(), None, |s| {
                    s.cli_providers.push(CliProvider {
                        instance_id: cli_id.into(),
                        cli: cli_id.into(),
                        label: cli_id.into(),
                        enabled: true,
                        models: vec![],
                    });
                    Ok(())
                })?;
                i.store.create(
                    &ThreadCreate {
                        operation_id: "c1".into(),
                        project: dir.to_string_lossy().into_owned(),
                        instance_id: cli_id.into(),
                        model: "m".into(),
                        title: "T".into(),
                        cwd: Some(cwd.to_string_lossy().into_owned()),
                        effort: None,
                        workspace_id: None,
                        permissions,
                        workspace: Workspace::default(),
                    },
                    "T",
                    ThreadKind::Cli,
                )
            })
            .unwrap();
        (engine, thread)
    }

    /// A persistent-session thread that may edit, so approval prompts reach the user.
    fn setup_edit(cli_id: &str, body: &str, dir: &Path) -> (Engine, ThreadSummary) {
        setup_with(cli_id, body, dir, false, Permissions::Edit, dir)
    }

    async fn send(
        engine: &Engine,
        thread: &ThreadSummary,
    ) -> (ThreadSendAccepted, UnboundedReceiver<ThreadStreamEvent>) {
        send_op(engine, &thread.thread_id, thread.revision, "s1").await
    }

    async fn send_op(
        engine: &Engine,
        thread_id: &str,
        revision: u64,
        operation: &str,
    ) -> (ThreadSendAccepted, UnboundedReceiver<ThreadStreamEvent>) {
        send_as("claude", engine, thread_id, revision, operation).await
    }

    async fn send_as(
        instance: &str,
        engine: &Engine,
        thread_id: &str,
        revision: u64,
        operation: &str,
    ) -> (ThreadSendAccepted, UnboundedReceiver<ThreadStreamEvent>) {
        let (tx, rx) = unbounded_channel();
        let accepted = engine
            .send(
                ThreadSend {
                    operation_id: operation.into(),
                    thread_id: thread_id.into(),
                    expected_revision: revision,
                    instance_id: instance.into(),
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
            true,
        );
        let (accepted, mut rx) = send(&engine, &thread).await;
        let mut deltas = String::new();
        let message = loop {
            match rx.recv().await.expect("final event") {
                ThreadStreamEvent::Delta { text, .. } => deltas.push_str(&text),
                ThreadStreamEvent::Final { message, .. } => break message,
                ThreadStreamEvent::Activity { .. } => {}
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
            true,
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

    /// Persistent-session fake: one prompt, a permission request, then an answer-dependent reply.
    const LIVE: &str = r#"
turn() {
  printf '%s\n' '{"type":"system","subtype":"init","session_id":"0b3e8a1c-2d4f-4a6b-9c7d-1e2f3a4b5c6d"}'
}
reply() {
  printf '%s\n' "{\"type\":\"stream_event\",\"event\":{\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"$1 $$\"}}}" '{"type":"result","result":"x"}'
}
read -r init
read -r first
turn
printf '%s\n' '{"type":"control_request","request_id":"R1","request":{"subtype":"can_use_tool","tool_name":"Write","input":{"file_path":"b.txt","content":"x"},"permission_suggestions":[{"type":"setMode","mode":"acceptEdits","destination":"session"}],"tool_use_id":"toolu_1"}}'
read -r answer
case "$answer" in *'"behavior":"allow"'*) reply allowed;; *) reply denied;; esac
read -r second
turn
reply again
read -r third
"#;

    async fn final_of(
        rx: &mut UnboundedReceiver<ThreadStreamEvent>,
    ) -> (ThreadSummary, ThreadMessage) {
        loop {
            if let ThreadStreamEvent::Final { thread, message } = rx.recv().await.expect("final") {
                return (thread, message);
            }
        }
    }

    /// Drives the installed `claude` (Claude Code): `cargo test -p lomi-chat real_claude -- --ignored`.
    #[tokio::test]
    #[ignore = "spends a few tokens of the local Claude Code account"]
    async fn real_claude_session_approves_and_stays_warm() {
        let dir = tempfile::tempdir().unwrap();
        let bin = which("claude").expect("claude on PATH");
        let hooks = Hooks {
            api_key: Box::new(|_| Ok(None)),
            threads_changed: Box::new(|_, _| {}),
            resolve_cli: Box::new(move |_| Some(bin.clone())),
        };
        let engine = Engine::new(dir.path().join("data"), hooks);
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
                        project: dir.path().to_string_lossy().into_owned(),
                        instance_id: "claude".into(),
                        model: "haiku".into(),
                        title: "T".into(),
                        cwd: Some(dir.path().to_string_lossy().into_owned()),
                        effort: None,
                        workspace_id: None,
                        permissions: Permissions::Edit,
                        workspace: Workspace::default(),
                    },
                    "T",
                    ThreadKind::Cli,
                )
            })
            .unwrap();
        let turn = |op: &'static str, revision: u64, text: &'static str| {
            let engine = engine.clone();
            let tid = thread.thread_id.clone();
            async move {
                let (tx, rx) = unbounded_channel();
                engine
                    .send(
                        ThreadSend {
                            operation_id: op.into(),
                            thread_id: tid,
                            expected_revision: revision,
                            instance_id: "claude".into(),
                            model: "haiku".into(),
                            text: text.into(),
                            attachments: vec![],
                        },
                        Arc::new(Recorder(tx)),
                    )
                    .await
                    .unwrap();
                rx
            }
        };
        let mut rx = turn(
            "s1",
            thread.revision,
            "Run exactly this shell command with the Bash tool: python3 -c \"open('made.txt','w').write('x')\" and then reply DONE.",
        )
        .await;
        let (summary, message) = loop {
            match rx.recv().await.expect("event") {
                ThreadStreamEvent::Activity { activity, .. } => {
                    if let Some(a) = activity
                        .approval
                        .filter(|a| a.state == ApprovalState::Pending)
                    {
                        engine
                            .respond(&thread.thread_id, &a.request_id, Decision::Allow)
                            .unwrap();
                    }
                }
                ThreadStreamEvent::Final { thread, message } => break (thread, message),
                _ => {}
            }
        };
        assert_eq!(
            message.state,
            MessageState::Completed,
            "{:?}",
            message.error
        );
        assert!(dir.path().join("made.txt").exists());
        assert!(message.activity.iter().any(|a| {
            a.approval
                .as_ref()
                .is_some_and(|a| a.state == ApprovalState::Allowed)
        }));
        let first = engine.0.sessions.lock().unwrap()[&thread.thread_id].clone();
        let mut rx = turn("s2", summary.revision, "Reply with the word AGAIN.").await;
        let message = loop {
            if let ThreadStreamEvent::Final { message, .. } = rx.recv().await.expect("event") {
                break message;
            }
        };
        assert!(message.content.contains("AGAIN"), "{}", message.content);
        let again = engine.0.sessions.lock().unwrap()[&thread.thread_id].clone();
        assert!(
            Arc::ptr_eq(&first, &again),
            "the second turn reused the process"
        );
        engine.forget_session(&thread.thread_id);
    }

    fn which(name: &str) -> Option<PathBuf> {
        std::env::split_paths(&std::env::var_os("PATH")?)
            .map(|d| d.join(name))
            .find(|p| p.is_file())
    }

    #[tokio::test]
    async fn live_session_asks_permission_and_stays_warm() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, thread) = setup_edit("claude", LIVE, dir.path());
        let (_, mut rx) = send(&engine, &thread).await;
        let pending = loop {
            if let Some(ThreadStreamEvent::Activity { activity, .. }) = rx.recv().await {
                break activity;
            }
        };
        assert_eq!(pending.id, "toolu_1");
        assert_eq!(pending.kind, ActivityKind::Edit);
        assert_eq!(pending.status, ActivityStatus::Running);
        assert_eq!(
            pending.approval,
            Some(Approval {
                request_id: "R1".into(),
                state: ApprovalState::Pending,
                can_remember: true
            })
        );
        let tid = thread.thread_id.clone();
        assert!(engine.respond(&tid, "nope", Decision::Allow).is_err());
        engine.respond(&tid, "R1", Decision::AllowSession).unwrap();
        assert_eq!(
            engine.respond(&tid, "R1", Decision::Allow).unwrap_err(),
            "This request is no longer pending."
        );
        let (summary, message) = final_of(&mut rx).await;
        assert_eq!(message.state, MessageState::Completed);
        let first_pid = message
            .content
            .strip_prefix("allowed ")
            .expect("allowed")
            .to_string();
        let a = &message.activity[0];
        assert_eq!(a.approval.as_ref().unwrap().state, ApprovalState::Allowed);
        // The native session id was stored from the init line.
        let stored = engine.with(|i| i.store.native_session(&tid)).unwrap();
        assert_eq!(
            stored.as_deref(),
            Some("0b3e8a1c-2d4f-4a6b-9c7d-1e2f3a4b5c6d")
        );
        assert_eq!(engine.0.sessions.lock().unwrap().len(), 1);
        // The second turn runs in the same process.
        let (_, mut rx) = send_op(&engine, &tid, summary.revision, "s2").await;
        let (_, message) = final_of(&mut rx).await;
        assert_eq!(message.content, format!("again {first_pid}"));
        engine.reap_idle(Duration::ZERO);
        assert!(engine.0.sessions.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn stop_interrupts_a_pending_prompt_and_expires_it() {
        let dir = tempfile::tempdir().unwrap();
        let body = r#"read -r init
read -r first
printf '%s\n' '{"type":"control_request","request_id":"R1","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{"command":"ls"},"tool_use_id":"toolu_1"}}'
read -r deny
printf '%s\n' "$deny" > denied.txt
read -r interrupt
printf '%s\n' '{"type":"result","subtype":"error_during_execution","is_error":true}'
read -r never"#;
        let (engine, thread) = setup_edit("claude", body, dir.path());
        let (_, mut rx) = send(&engine, &thread).await;
        let ThreadStreamEvent::Activity { activity, .. } = rx.recv().await.unwrap() else {
            panic!("expected the prompt");
        };
        assert!(!activity.approval.unwrap().can_remember);
        let (stopper, id) = (engine.clone(), thread.thread_id.clone());
        blocking(move || stopper.stop(&id)).await.unwrap();
        let (_, message) = final_of(&mut rx).await;
        assert_eq!(message.state, MessageState::Stopped);
        let a = &message.activity[0];
        assert_eq!(a.approval.as_ref().unwrap().state, ApprovalState::Expired);
        assert_eq!(a.status, ActivityStatus::Failed);
        let denied = std::fs::read_to_string(dir.path().join("denied.txt")).unwrap();
        assert!(denied.contains(r#""behavior":"deny""#) && denied.contains(r#""interrupt":true"#));
        // The process answered the interrupt, so it was kept.
        assert_eq!(engine.0.sessions.lock().unwrap().len(), 1);
        engine.kill_cli_groups();
    }

    #[tokio::test]
    async fn live_session_death_fails_the_turn_and_is_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, thread) = setup(
            "read -r a\nread -r b\necho oops >&2\nexit 3",
            dir.path(),
            false,
        );
        let (_, mut rx) = send(&engine, &thread).await;
        let (_, message) = final_of(&mut rx).await;
        assert_eq!(message.state, MessageState::Failed);
        let error = message.error.unwrap();
        assert!(
            error.contains("The CLI exited") && error.contains("oops"),
            "{error}"
        );
        assert!(engine.0.sessions.lock().unwrap().is_empty());
    }

    /// Persistent app-server fake: handshake, one approval round trip, then a second turn.
    /// The client's request ids are deterministic: initialize 1, thread/start 2, turns 3 and 4.
    const SERVER: &str = r#"
read -r init
printf '%s\n' '{"id":1,"result":{"userAgent":"x"}}'
read -r initialized
read -r start
printf '%s\n' '{"id":2,"result":{"thread":{"id":"0b3e8a1c-2d4f-4a6b-9c7d-1e2f3a4b5c6d"}}}'
read -r first
printf '%s\n' '{"id":3,"result":{"turn":{"id":"T1","status":"inProgress"}}}' '{"method":"turn/started","params":{"turn":{"id":"T1"}}}' '{"method":"item/started","params":{"item":{"type":"commandExecution","id":"I1","command":"/bin/zsh -lc ls","status":"inProgress"}}}'
printf '%s\n' '{"id":8,"method":"item/tool/requestUserInput","params":{}}'
printf '%s\n' '{"id":7,"method":"item/commandExecution/requestApproval","params":{"itemId":"I1","command":"/bin/zsh -lc ls","availableDecisions":["accept","acceptForSession","cancel"]}}'
read -r refused
printf '%s\n' "$refused" > refused.txt
read -r answer
reply() {
  printf '%s\n' '{"method":"item/completed","params":{"item":{"type":"commandExecution","id":"I1","command":"/bin/zsh -lc ls","status":"completed","exitCode":0}}}' "{\"method\":\"item/agentMessage/delta\",\"params\":{\"itemId\":\"M$2\",\"delta\":\"$1 $$\"}}" "{\"method\":\"turn/completed\",\"params\":{\"turn\":{\"id\":\"$3\",\"status\":\"completed\"}}}"
}
case "$answer" in *'"decision":"acceptForSession"'*) reply session 1 T1;; *) reply other 1 T1;; esac
read -r second
printf '%s\n' '{"id":4,"result":{"turn":{"id":"T2"}}}'
reply again 2 T2
read -r third
"#;

    #[tokio::test]
    async fn codex_server_asks_approval_and_stays_warm() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, thread) = setup_edit("codex", SERVER, dir.path());
        let (_, mut rx) = send_as("codex", &engine, &thread.thread_id, thread.revision, "s1").await;
        let pending = loop {
            if let Some(ThreadStreamEvent::Activity { activity, .. }) = rx.recv().await
                && activity.approval.is_some()
            {
                break activity;
            }
        };
        assert_eq!(pending.id, "I1");
        assert_eq!(pending.kind, ActivityKind::Execute);
        assert_eq!(pending.title, "ls");
        assert_eq!(pending.status, ActivityStatus::Running);
        let rid = pending.approval.as_ref().unwrap().request_id.clone();
        assert!(rid.ends_with(":7"), "{rid}");
        assert_eq!(
            pending.approval,
            Some(Approval {
                request_id: rid.clone(),
                state: ApprovalState::Pending,
                can_remember: true
            })
        );
        let tid = thread.thread_id.clone();
        assert!(engine.respond(&tid, "nope", Decision::Allow).is_err());
        // The bare JSON-RPC id of a (possibly earlier) process never matches.
        assert!(engine.respond(&tid, "7", Decision::Allow).is_err());
        engine.respond(&tid, &rid, Decision::AllowSession).unwrap();
        assert_eq!(
            engine.respond(&tid, &rid, Decision::Allow).unwrap_err(),
            "This request is no longer pending."
        );
        let (summary, message) = final_of(&mut rx).await;
        assert_eq!(
            message.state,
            MessageState::Completed,
            "{:?}",
            message.error
        );
        let pid = message
            .content
            .strip_prefix("session ")
            .expect("accepted for the session")
            .to_string();
        let a = &message.activity[0];
        assert_eq!(a.approval.as_ref().unwrap().state, ApprovalState::Allowed);
        assert_eq!(a.status, ActivityStatus::Completed);
        // Unsupported server requests were refused with a JSON-RPC error.
        let refused = std::fs::read_to_string(dir.path().join("refused.txt")).unwrap();
        assert!(
            refused.contains(r#""id":8"#) && refused.contains("-32601"),
            "{refused}"
        );
        let stored = engine.with(|i| i.store.native_session(&tid)).unwrap();
        assert_eq!(
            stored.as_deref(),
            Some("0b3e8a1c-2d4f-4a6b-9c7d-1e2f3a4b5c6d")
        );
        // The second turn runs in the same process without a new handshake.
        let (_, mut rx) = send_as("codex", &engine, &tid, summary.revision, "s2").await;
        let (_, message) = final_of(&mut rx).await;
        assert_eq!(message.content, format!("again {pid}"));
        assert_eq!(engine.0.codex.lock().unwrap().len(), 1);
        assert!(engine.0.sessions.lock().unwrap().is_empty());
        engine.reap_idle(Duration::ZERO);
        assert!(engine.0.codex.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn stop_interrupts_the_codex_turn_and_expires_the_prompt() {
        let dir = tempfile::tempdir().unwrap();
        let body = r#"read -r init
printf '%s\n' '{"id":1,"result":{}}'
read -r initialized
read -r start
printf '%s\n' '{"id":2,"result":{"thread":{"id":"th-1"}}}'
read -r first
printf '%s\n' '{"id":3,"result":{"turn":{"id":"T1"}}}' '{"id":5,"method":"item/fileChange/requestApproval","params":{"itemId":"F1","reason":"write"}}'
read -r declined
printf '%s\n' "$declined" > declined.txt
read -r interrupt
printf '%s\n' "$interrupt" > interrupt.txt
printf '%s\n' '{"method":"turn/completed","params":{"turn":{"id":"T1","status":"interrupted"}}}'
read -r never"#;
        let (engine, thread) = setup_edit("codex", body, dir.path());
        let (_, mut rx) = send_as("codex", &engine, &thread.thread_id, thread.revision, "s1").await;
        let ThreadStreamEvent::Activity { activity, .. } = rx.recv().await.unwrap() else {
            panic!("expected the prompt");
        };
        assert_eq!(activity.kind, ActivityKind::Edit);
        let (stopper, id) = (engine.clone(), thread.thread_id.clone());
        blocking(move || stopper.stop(&id)).await.unwrap();
        let (_, message) = final_of(&mut rx).await;
        assert_eq!(message.state, MessageState::Stopped);
        let a = &message.activity[0];
        assert_eq!(a.approval.as_ref().unwrap().state, ApprovalState::Expired);
        assert_eq!(a.status, ActivityStatus::Failed);
        let declined = std::fs::read_to_string(dir.path().join("declined.txt")).unwrap();
        assert!(declined.contains(r#""decision":"decline""#), "{declined}");
        let interrupt = std::fs::read_to_string(dir.path().join("interrupt.txt")).unwrap();
        assert!(
            interrupt.contains(r#""method":"turn/interrupt""#)
                && interrupt.contains(r#""turnId":"T1""#)
                && interrupt.contains(r#""threadId":"th-1""#),
            "{interrupt}"
        );
        // The server answered the interrupt, so it was kept.
        assert_eq!(engine.0.codex.lock().unwrap().len(), 1);
        engine.kill_cli_groups();
    }

    #[tokio::test]
    async fn codex_server_death_fails_the_turn_and_is_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, thread) = setup_cli(
            "codex",
            "read -r a\necho oops >&2\nexit 3",
            dir.path(),
            false,
        );
        let (_, mut rx) = send_as("codex", &engine, &thread.thread_id, thread.revision, "s1").await;
        let (_, message) = final_of(&mut rx).await;
        assert_eq!(message.state, MessageState::Failed);
        let error = message.error.unwrap();
        assert!(error.contains("oops"), "{error}");
        assert!(engine.0.codex.lock().unwrap().is_empty());
    }

    /// Drives the installed `codex` app-server: `cargo test -p lomi-chat real_codex -- --ignored`.
    #[tokio::test]
    #[ignore = "spends a few tokens of the local Codex account"]
    async fn real_codex_session_runs_a_command_and_stays_warm() {
        let dir = tempfile::tempdir().unwrap();
        let bin = which("codex").expect("codex on PATH");
        let hooks = Hooks {
            api_key: Box::new(|_| Ok(None)),
            threads_changed: Box::new(|_, _| {}),
            resolve_cli: Box::new(move |_| Some(bin.clone())),
        };
        let engine = Engine::new(dir.path().join("data"), hooks);
        let thread = engine
            .with(|i| {
                i.settings.mutate(&i.dir.clone(), None, |s| {
                    s.cli_providers.push(CliProvider {
                        instance_id: "codex".into(),
                        cli: "codex".into(),
                        label: "Codex".into(),
                        enabled: true,
                        models: vec![],
                    });
                    Ok(())
                })?;
                i.store.create(
                    &ThreadCreate {
                        operation_id: "c1".into(),
                        project: dir.path().to_string_lossy().into_owned(),
                        instance_id: "codex".into(),
                        model: cli::DEFAULT_MODEL.into(),
                        title: "T".into(),
                        cwd: Some(dir.path().to_string_lossy().into_owned()),
                        effort: None,
                        workspace_id: None,
                        permissions: Permissions::Edit,
                        workspace: Workspace::default(),
                    },
                    "T",
                    ThreadKind::Cli,
                )
            })
            .unwrap();
        let turn = |op: &'static str, revision: u64, text: &'static str| {
            let engine = engine.clone();
            let tid = thread.thread_id.clone();
            async move {
                let (tx, rx) = unbounded_channel();
                engine
                    .send(
                        ThreadSend {
                            operation_id: op.into(),
                            thread_id: tid,
                            expected_revision: revision,
                            instance_id: "codex".into(),
                            model: cli::DEFAULT_MODEL.into(),
                            text: text.into(),
                            attachments: vec![],
                        },
                        Arc::new(Recorder(tx)),
                    )
                    .await
                    .unwrap();
                rx
            }
        };
        let mut rx = turn(
            "s1",
            thread.revision,
            "Run the shell command `echo lomi-check` and then reply DONE.",
        )
        .await;
        let (summary, message) = loop {
            match rx.recv().await.expect("event") {
                ThreadStreamEvent::Activity { activity, .. } => {
                    // Not expected in the workspace sandbox, but answer if it happens.
                    if let Some(a) = activity
                        .approval
                        .filter(|a| a.state == ApprovalState::Pending)
                    {
                        engine
                            .respond(&thread.thread_id, &a.request_id, Decision::Allow)
                            .unwrap();
                    }
                }
                ThreadStreamEvent::Final { thread, message } => break (thread, message),
                _ => {}
            }
        };
        assert_eq!(
            message.state,
            MessageState::Completed,
            "{:?}",
            message.error
        );
        assert!(message.content.contains("DONE"), "{}", message.content);
        assert!(
            message
                .activity
                .iter()
                .any(|a| a.kind == ActivityKind::Execute && a.status == ActivityStatus::Completed)
        );
        assert!(message.usage.is_some());
        let first = engine.0.codex.lock().unwrap()[&thread.thread_id].clone();
        let mut rx = turn("s2", summary.revision, "Reply with the word AGAIN.").await;
        let (_, message) = final_of(&mut rx).await;
        assert!(message.content.contains("AGAIN"), "{}", message.content);
        let again = engine.0.codex.lock().unwrap()[&thread.thread_id].clone();
        assert!(
            Arc::ptr_eq(&first, &again),
            "the second turn reused the process"
        );
        engine.forget_session(&thread.thread_id);
    }

    /// Handshake of the fake ACP agents below. The client's request ids are deterministic:
    /// initialize 1, session/new 2, session/set_mode 3 (read-only threads), turns 4 and 5.
    const ACP_HANDSHAKE: &str = r#"
read -r init
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1,"agentCapabilities":{"promptCapabilities":{"image":false},"sessionCapabilities":{"resume":{}}}}}'
read -r new
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"sessionId":"0b3e8a1c-2d4f-4a6b-9c7d-1e2f3a4b5c6d","models":{"currentModelId":"m"}}}'
read -r mode
printf '%s\n' "$mode" > mode.txt
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{}}'
read -r first
"#;

    fn acp_script(rest: &str) -> String {
        format!("{ACP_HANDSHAKE}{rest}")
    }

    #[tokio::test]
    async fn acp_agent_asks_permission_and_stays_warm() {
        let dir = tempfile::tempdir().unwrap();
        let body = acp_script(
            r#"
printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"tool_call","toolCallId":"T1","title":"Read a.txt","kind":"read","status":"in_progress"}}}'
printf '%s\n' '{"jsonrpc":"2.0","id":8,"method":"fs/read_text_file","params":{}}'
printf '%s\n' '{"jsonrpc":"2.0","id":"p7","method":"session/request_permission","params":{"toolCall":{"toolCallId":"T1"},"options":[{"optionId":"a1","name":"Allow","kind":"allow_once"},{"optionId":"a2","name":"Always","kind":"allow_always"},{"optionId":"r1","name":"Deny","kind":"reject_once"}]}}'
read -r refused
printf '%s\n' "$refused" > refused.txt
read -r answer
reply() {
  printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"tool_call_update","toolCallId":"T1","status":"completed"}}}' "{\"jsonrpc\":\"2.0\",\"method\":\"session/update\",\"params\":{\"update\":{\"sessionUpdate\":\"agent_message_chunk\",\"content\":{\"type\":\"text\",\"text\":\"$1 $$\"}}}}" "{\"jsonrpc\":\"2.0\",\"id\":$2,\"result\":{\"stopReason\":\"end_turn\",\"usage\":{\"inputTokens\":3,\"outputTokens\":1}}}"
}
case "$answer" in *'"optionId":"a2"'*) reply session 4;; *) reply other 4;; esac
read -r second
reply again 5
read -r third
"#,
        );
        let (engine, thread) = setup_cli("agy", &body, dir.path(), false);
        let (_, mut rx) = send_as("agy", &engine, &thread.thread_id, thread.revision, "s1").await;
        let pending = loop {
            if let Some(ThreadStreamEvent::Activity { activity, .. }) = rx.recv().await
                && activity.approval.is_some()
            {
                break activity;
            }
        };
        assert_eq!(pending.id, "T1");
        assert_eq!(pending.kind, ActivityKind::Read);
        assert_eq!(pending.title, "Read a.txt");
        assert_eq!(pending.status, ActivityStatus::Running);
        let rid = pending.approval.as_ref().unwrap().request_id.clone();
        assert!(rid.ends_with(":p7"), "{rid}");
        assert_eq!(
            pending.approval,
            Some(Approval {
                request_id: rid.clone(),
                state: ApprovalState::Pending,
                can_remember: true
            })
        );
        let tid = thread.thread_id.clone();
        assert!(engine.respond(&tid, "nope", Decision::Allow).is_err());
        // The bare JSON-RPC id of a (possibly earlier) process never matches.
        assert!(engine.respond(&tid, "p7", Decision::Allow).is_err());
        engine.respond(&tid, &rid, Decision::AllowSession).unwrap();
        assert_eq!(
            engine.respond(&tid, &rid, Decision::Allow).unwrap_err(),
            "This request is no longer pending."
        );
        let (summary, message) = final_of(&mut rx).await;
        assert_eq!(
            message.state,
            MessageState::Completed,
            "{:?}",
            message.error
        );
        let pid = message
            .content
            .strip_prefix("session ")
            .expect("allowed for the session")
            .to_string();
        let a = &message.activity[0];
        assert_eq!(a.approval.as_ref().unwrap().state, ApprovalState::Allowed);
        assert_eq!(a.status, ActivityStatus::Completed);
        assert_eq!(message.usage.as_ref().unwrap().input_tokens, 3);
        let refused = std::fs::read_to_string(dir.path().join("refused.txt")).unwrap();
        assert!(
            refused.contains(r#""id":8"#) && refused.contains("-32601"),
            "{refused}"
        );
        // A read-only thread runs in the agent's plan mode.
        let mode = std::fs::read_to_string(dir.path().join("mode.txt")).unwrap();
        assert!(
            mode.contains(r#""method":"session/set_mode""#) && mode.contains(r#""modeId":"plan""#),
            "{mode}"
        );
        let stored = engine.with(|i| i.store.native_session(&tid)).unwrap();
        assert_eq!(
            stored.as_deref(),
            Some("0b3e8a1c-2d4f-4a6b-9c7d-1e2f3a4b5c6d")
        );
        // The second turn runs in the same process without a new handshake.
        let (_, mut rx) = send_as("agy", &engine, &tid, summary.revision, "s2").await;
        let (_, message) = final_of(&mut rx).await;
        assert_eq!(message.content, format!("again {pid}"));
        assert_eq!(engine.0.acp.lock().unwrap().len(), 1);
        assert!(engine.0.codex.lock().unwrap().is_empty());
        engine.reap_idle(Duration::ZERO);
        assert!(engine.0.acp.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn acp_read_only_thread_rejects_changes_itself() {
        let dir = tempfile::tempdir().unwrap();
        let body = acp_script(
            r#"
printf '%s\n' '{"jsonrpc":"2.0","id":9,"method":"session/request_permission","params":{"toolCall":{"toolCallId":"E1","title":"Edit a.txt","kind":"edit","status":"pending"},"options":[{"optionId":"a1","name":"Allow","kind":"allow_once"},{"optionId":"r1","name":"Deny","kind":"reject_once"}]}}'
read -r rejected
printf '%s\n' "$rejected" > rejected.txt
printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"no"}}}}' '{"jsonrpc":"2.0","id":4,"result":{"stopReason":"end_turn"}}'
read -r never
"#,
        );
        let (engine, thread) = setup_cli("kimi", &body, dir.path(), false);
        let (_, mut rx) = send_as("kimi", &engine, &thread.thread_id, thread.revision, "s1").await;
        let (_, message) = final_of(&mut rx).await;
        assert_eq!(
            message.state,
            MessageState::Completed,
            "{:?}",
            message.error
        );
        let a = &message.activity[0];
        assert_eq!(a.approval.as_ref().unwrap().state, ApprovalState::Denied);
        assert_eq!(a.status, ActivityStatus::Failed);
        let rejected = std::fs::read_to_string(dir.path().join("rejected.txt")).unwrap();
        assert!(
            rejected.contains(r#""id":9"#) && rejected.contains(r#""optionId":"r1""#),
            "{rejected}"
        );
        engine.kill_cli_groups();
    }

    #[tokio::test]
    async fn stop_cancels_the_acp_turn_and_expires_the_prompt() {
        let dir = tempfile::tempdir().unwrap();
        let body = acp_script(
            r#"
printf '%s\n' '{"jsonrpc":"2.0","id":5,"method":"session/request_permission","params":{"toolCall":{"toolCallId":"F1","title":"Fetch","kind":"fetch"},"options":[{"optionId":"a1","name":"Allow","kind":"allow_once"}]}}'
read -r cancel
printf '%s\n' "$cancel" > cancel.txt
read -r declined
printf '%s\n' "$declined" > declined.txt
printf '%s\n' '{"jsonrpc":"2.0","id":4,"result":{"stopReason":"cancelled"}}'
read -r never
"#,
        );
        let (engine, thread) = setup_cli("agy", &body, dir.path(), false);
        let (_, mut rx) = send_as("agy", &engine, &thread.thread_id, thread.revision, "s1").await;
        let ThreadStreamEvent::Activity { activity, .. } = rx.recv().await.unwrap() else {
            panic!("expected the prompt");
        };
        assert_eq!(activity.kind, ActivityKind::Fetch);
        let (stopper, id) = (engine.clone(), thread.thread_id.clone());
        blocking(move || stopper.stop(&id)).await.unwrap();
        let (_, message) = final_of(&mut rx).await;
        assert_eq!(message.state, MessageState::Stopped);
        let a = &message.activity[0];
        assert_eq!(a.approval.as_ref().unwrap().state, ApprovalState::Expired);
        assert_eq!(a.status, ActivityStatus::Failed);
        let cancel = std::fs::read_to_string(dir.path().join("cancel.txt")).unwrap();
        assert!(
            cancel.contains(r#""method":"session/cancel""#) && !cancel.contains(r#""id""#),
            "{cancel}"
        );
        let declined = std::fs::read_to_string(dir.path().join("declined.txt")).unwrap();
        assert!(declined.contains(r#""outcome":"cancelled""#), "{declined}");
        // The agent ended the turn itself, so the process was kept.
        assert_eq!(engine.0.acp.lock().unwrap().len(), 1);
        engine.kill_cli_groups();
    }

    #[tokio::test]
    async fn acp_agent_death_fails_the_turn_and_is_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, thread) = setup_cli(
            "kimi",
            "read -r a\necho oops >&2\nexit 3",
            dir.path(),
            false,
        );
        let (_, mut rx) = send_as("kimi", &engine, &thread.thread_id, thread.revision, "s1").await;
        let (_, message) = final_of(&mut rx).await;
        assert_eq!(message.state, MessageState::Failed);
        let error = message.error.unwrap();
        assert!(error.contains("oops"), "{error}");
        assert!(engine.0.acp.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn claude_read_only_thread_denies_changing_tools_itself() {
        let dir = tempfile::tempdir().unwrap();
        let body = r#"read -r init
read -r first
printf '%s\n' '{"type":"control_request","request_id":"R1","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{"command":"rm x"},"tool_use_id":"toolu_1"}}'
read -r deny
printf '%s\n' "$deny" > denied.txt
printf '%s\n' '{"type":"stream_event","event":{"type":"content_block_delta","delta":{"type":"text_delta","text":"no"}}}' '{"type":"result","result":"x"}'
read -r never"#;
        let (engine, thread) = setup(body, dir.path(), false);
        let (_, mut rx) = send(&engine, &thread).await;
        let (_, message) = final_of(&mut rx).await;
        assert_eq!(message.state, MessageState::Completed);
        let a = &message.activity[0];
        assert_eq!(a.approval.as_ref().unwrap().state, ApprovalState::Denied);
        assert_eq!(a.status, ActivityStatus::Failed);
        let denied = std::fs::read_to_string(dir.path().join("denied.txt")).unwrap();
        assert!(denied.contains(r#""behavior":"deny""#), "{denied}");
        let tid = thread.thread_id.clone();
        assert!(engine.respond(&tid, "R1", Decision::Allow).is_err());
        engine.kill_cli_groups();
    }

    #[tokio::test]
    async fn codex_read_only_thread_declines_approvals_itself() {
        let dir = tempfile::tempdir().unwrap();
        let body = r#"read -r init
printf '%s\n' '{"id":1,"result":{}}'
read -r initialized
read -r start
printf '%s\n' '{"id":2,"result":{"thread":{"id":"th-1"}}}'
read -r first
printf '%s\n' '{"id":3,"result":{"turn":{"id":"T1"}}}' '{"id":5,"method":"item/fileChange/requestApproval","params":{"itemId":"F1","reason":"write"}}'
read -r declined
printf '%s\n' "$declined" > declined.txt
printf '%s\n' '{"method":"item/agentMessage/delta","params":{"itemId":"M","delta":"no"}}' '{"method":"turn/completed","params":{"turn":{"id":"T1","status":"completed"}}}'
read -r never"#;
        let (engine, thread) = setup_cli("codex", body, dir.path(), false);
        let (_, mut rx) = send_as("codex", &engine, &thread.thread_id, thread.revision, "s1").await;
        let (_, message) = final_of(&mut rx).await;
        assert_eq!(
            message.state,
            MessageState::Completed,
            "{:?}",
            message.error
        );
        let a = &message.activity[0];
        assert_eq!(a.approval.as_ref().unwrap().state, ApprovalState::Denied);
        assert_eq!(a.status, ActivityStatus::Failed);
        let declined = std::fs::read_to_string(dir.path().join("declined.txt")).unwrap();
        assert!(declined.contains(r#""decision":"decline""#), "{declined}");
        engine.kill_cli_groups();
    }

    /// A fake ACP agent whose `session/new` result carries `modes`; `mode_reply` answers
    /// `session/set_mode` (None: the client must not send it, so the prompt is request 3).
    fn acp_modes_script(modes: &str, mode_reply: Option<&str>) -> String {
        let (set_mode, prompt) = match mode_reply {
            Some(r) => (format!("read -r mode\nprintf '%s\\n' '{r}'\n"), 4),
            None => (String::new(), 3),
        };
        format!(
            r#"
read -r init
printf '%s\n' '{{"jsonrpc":"2.0","id":1,"result":{{"protocolVersion":1,"agentCapabilities":{{}}}}}}'
read -r new
printf '%s\n' '{{"jsonrpc":"2.0","id":2,"result":{{"sessionId":"0b3e8a1c-2d4f-4a6b-9c7d-1e2f3a4b5c6d","models":{{"currentModelId":"m"}},{modes}}}}}'
{set_mode}read -r first
printf '%s\n' "$first" > first.txt
printf '%s\n' '{{"jsonrpc":"2.0","method":"session/update","params":{{"update":{{"sessionUpdate":"agent_message_chunk","content":{{"type":"text","text":"ok"}}}}}}}}' '{{"jsonrpc":"2.0","id":{prompt},"result":{{"stopReason":"end_turn"}}}}'
read -r never
"#
        )
    }

    const MODE_REFUSED: &str =
        r#"{"jsonrpc":"2.0","id":3,"error":{"code":-32000,"message":"nope"}}"#;

    async fn acp_turn(body: &str, permissions: Permissions, dir: &Path) -> (Engine, ThreadMessage) {
        let (engine, thread) = setup_with("kimi", body, dir, false, permissions, dir);
        let (_, mut rx) = send_as("kimi", &engine, &thread.thread_id, thread.revision, "s1").await;
        let (_, message) = final_of(&mut rx).await;
        (engine, message)
    }

    #[tokio::test]
    async fn acp_read_only_and_edit_need_their_mode() {
        let plan_listed = r#""modes":{"availableModes":[{"id":"plan"},{"id":"default"}]}"#;
        for (permissions, name, modes, reply) in [
            // set_mode refused
            (
                Permissions::ReadOnly,
                "read-only",
                plan_listed,
                Some(MODE_REFUSED),
            ),
            (Permissions::Edit, "edit", plan_listed, Some(MODE_REFUSED)),
            // no matching mode listed
            (
                Permissions::ReadOnly,
                "read-only",
                r#""modes":{"availableModes":[{"id":"default"}]}"#,
                None,
            ),
            (
                Permissions::Edit,
                "edit",
                r#""modes":{"availableModes":[{"id":"plan"}]}"#,
                None,
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (engine, message) =
                acp_turn(&acp_modes_script(modes, reply), permissions, dir.path()).await;
            assert_eq!(message.state, MessageState::Failed, "{name}");
            assert_eq!(
                message.error.as_deref(),
                Some(format!("This agent did not accept the {name} mode.").as_str())
            );
            assert!(engine.0.acp.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn acp_full_access_ignores_a_refused_mode_and_a_current_mode_is_not_set_again() {
        let dir = tempfile::tempdir().unwrap();
        let body = acp_modes_script(
            r#""modes":{"availableModes":[{"id":"yolo"}]}"#,
            Some(MODE_REFUSED),
        );
        let (engine, message) = acp_turn(&body, Permissions::Full, dir.path()).await;
        assert_eq!(
            message.state,
            MessageState::Completed,
            "{:?}",
            message.error
        );
        engine.kill_cli_groups();

        let dir = tempfile::tempdir().unwrap();
        let current = r#""modes":{"currentModeId":"plan","availableModes":[{"id":"plan"}]}"#;
        let (engine, message) = acp_turn(
            &acp_modes_script(current, None),
            Permissions::ReadOnly,
            dir.path(),
        )
        .await;
        assert_eq!(
            message.state,
            MessageState::Completed,
            "{:?}",
            message.error
        );
        let first = std::fs::read_to_string(dir.path().join("first.txt")).unwrap();
        assert!(first.contains(r#""method":"session/prompt""#), "{first}");
        engine.kill_cli_groups();
    }

    /// Stored native session after one send of `body` on a thread that had one.
    async fn session_after(body: &str, restricted: bool) -> Option<String> {
        let dir = tempfile::tempdir().unwrap();
        let (engine, thread) = setup(body, dir.path(), restricted);
        let id = "0b3e8a1c-2d4f-4a6b-9c7d-1e2f3a4b5c6d";
        let tid = thread.thread_id.clone();
        engine
            .with(|i| i.store.set_native_session(&tid, Some(id)))
            .unwrap();
        let (_, mut rx) = send(&engine, &thread).await;
        let (_, message) = final_of(&mut rx).await;
        assert_eq!(message.state, MessageState::Failed);
        engine.kill_cli_groups();
        engine.with(|i| i.store.native_session(&tid)).unwrap()
    }

    #[tokio::test]
    async fn only_a_failed_start_clears_the_stored_session() {
        let id = Some("0b3e8a1c-2d4f-4a6b-9c7d-1e2f3a4b5c6d".to_string());
        let limited = r#"{"type":"result","is_error":true,"result":"Rate limited"}"#;
        // One-shot CLI: dies without output (unknown --resume) vs. fails after speaking.
        assert_eq!(session_after("exit 1", true).await, None);
        assert_eq!(
            session_after(&format!("echo '{limited}'\nexit 1"), true).await,
            id
        );
        // Persistent CLI: dies before any output vs. a failed turn.
        assert_eq!(session_after("read -r init\nexit 1", false).await, None);
        let turn = format!("read -r init\nread -r first\necho '{limited}'\nread -r never");
        assert_eq!(session_after(&turn, false).await, id);
    }

    #[tokio::test]
    async fn bounded_discards_a_late_result() {
        let (tx, rx) = std::sync::mpsc::channel();
        let slow = bounded(
            Duration::from_millis(50),
            || {
                std::thread::sleep(Duration::from_millis(300));
                7
            },
            move |late| tx.send(late).unwrap(),
        )
        .await;
        assert_eq!(slow, None);
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), 7);
        assert_eq!(bounded(Duration::from_secs(5), || 1, |_| ()).await, Some(1));
    }

    #[tokio::test]
    async fn stop_during_the_checkpoint_ends_the_turn_promptly() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repo(dir.path());
        // Hashing a GiB of zeros keeps `git add` busy for seconds.
        let big = std::fs::File::create(repo.join("big.bin")).unwrap();
        big.set_len(1 << 30).unwrap();
        let marker = dir.path().join("started");
        let body = format!("touch {}\n{EDITING_CLI}", marker.display());
        let (engine, thread) =
            setup_with("claude", &body, dir.path(), true, Permissions::Edit, &repo);
        let (_, mut rx) = send(&engine, &thread).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let (stopper, id) = (engine.clone(), thread.thread_id.clone());
        blocking(move || stopper.stop(&id)).await.unwrap();
        let message = tokio::time::timeout(Duration::from_secs(2), final_message(&mut rx))
            .await
            .expect("the stop must not wait for the checkpoint");
        assert_eq!(message.state, MessageState::Stopped);
        assert!(!marker.exists(), "the CLI must not start after a stop");
    }

    /// Drives the installed `agy` ACP agent: `cargo test -p lomi-chat real_agy -- --ignored`.
    #[tokio::test]
    #[ignore = "spends a few tokens of the local Antigravity account"]
    async fn real_agy_session_answers_and_stays_warm() {
        let dir = tempfile::tempdir().unwrap();
        let bin = which("agy").expect("agy on PATH");
        let hooks = Hooks {
            api_key: Box::new(|_| Ok(None)),
            threads_changed: Box::new(|_, _| {}),
            resolve_cli: Box::new(move |_| Some(bin.clone())),
        };
        let engine = Engine::new(dir.path().join("data"), hooks);
        let thread = engine
            .with(|i| {
                i.settings.mutate(&i.dir.clone(), None, |s| {
                    s.cli_providers.push(CliProvider {
                        instance_id: "agy".into(),
                        cli: "agy".into(),
                        label: "Antigravity".into(),
                        enabled: true,
                        models: vec![],
                    });
                    Ok(())
                })?;
                i.store.create(
                    &ThreadCreate {
                        operation_id: "c1".into(),
                        project: dir.path().to_string_lossy().into_owned(),
                        instance_id: "agy".into(),
                        model: cli::DEFAULT_MODEL.into(),
                        title: "T".into(),
                        cwd: Some(dir.path().to_string_lossy().into_owned()),
                        effort: None,
                        workspace_id: None,
                        permissions: Permissions::Edit,
                        workspace: Workspace::default(),
                    },
                    "T",
                    ThreadKind::Cli,
                )
            })
            .unwrap();
        let turn = |op: &'static str, revision: u64, text: &'static str| {
            let engine = engine.clone();
            let tid = thread.thread_id.clone();
            async move {
                let (tx, rx) = unbounded_channel();
                engine
                    .send(
                        ThreadSend {
                            operation_id: op.into(),
                            thread_id: tid,
                            expected_revision: revision,
                            instance_id: "agy".into(),
                            model: cli::DEFAULT_MODEL.into(),
                            text: text.into(),
                            attachments: vec![],
                        },
                        Arc::new(Recorder(tx)),
                    )
                    .await
                    .unwrap();
                rx
            }
        };
        let mut rx = turn("s1", thread.revision, "Reply with the single word PONG.").await;
        let (summary, message) = loop {
            match rx.recv().await.expect("event") {
                ThreadStreamEvent::Activity { activity, .. } => {
                    // Not expected for a plain reply, but answer if it happens.
                    if let Some(a) = activity
                        .approval
                        .filter(|a| a.state == ApprovalState::Pending)
                    {
                        engine
                            .respond(&thread.thread_id, &a.request_id, Decision::Allow)
                            .unwrap();
                    }
                }
                ThreadStreamEvent::Final { thread, message } => break (thread, message),
                _ => {}
            }
        };
        assert_eq!(
            message.state,
            MessageState::Completed,
            "{:?}",
            message.error
        );
        assert!(message.content.contains("PONG"), "{}", message.content);
        assert!(message.usage.is_some());
        let first = engine.0.acp.lock().unwrap()[&thread.thread_id].clone();
        let mut rx = turn("s2", summary.revision, "Reply with the word AGAIN.").await;
        let (_, message) = final_of(&mut rx).await;
        assert!(message.content.contains("AGAIN"), "{}", message.content);
        let again = engine.0.acp.lock().unwrap()[&thread.thread_id].clone();
        assert!(
            Arc::ptr_eq(&first, &again),
            "the second turn reused the process"
        );
        engine.forget_session(&thread.thread_id);
    }

    #[test]
    fn approvals_settle_once_and_survive_tool_events() {
        let (tx, mut rx) = unbounded_channel();
        let sink = Recorder(tx);
        let mut acc = Acc::new();
        let mut a = act("t");
        a.approval = Some(Approval {
            request_id: "R".into(),
            state: ApprovalState::Pending,
            can_remember: false,
        });
        acc.upsert("m", &sink, a);
        // A later tool event without approval keeps the prompt.
        acc.upsert("m", &sink, act("t"));
        assert_eq!(
            acc.activity[0].approval.as_ref().unwrap().state,
            ApprovalState::Pending
        );
        acc.settle(
            "m",
            &sink,
            |p| p.request_id == "other",
            ApprovalState::Allowed,
        );
        assert_eq!(
            acc.activity[0].approval.as_ref().unwrap().state,
            ApprovalState::Pending
        );
        acc.settle("m", &sink, |p| p.request_id == "R", ApprovalState::Denied);
        // Only pending prompts move: expiry leaves an answered one alone.
        acc.settle("m", &sink, |_| true, ApprovalState::Expired);
        let a = &acc.activity[0];
        assert_eq!(a.approval.as_ref().unwrap().state, ApprovalState::Denied);
        assert_eq!(a.status, ActivityStatus::Running);
        let mut events = 0;
        while rx.try_recv().is_ok() {
            events += 1;
        }
        assert_eq!(events, 3); // insert, tool event, denied
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

    fn act(id: &str) -> Activity {
        Activity {
            id: id.into(),
            kind: ActivityKind::Other,
            title: "t".into(),
            status: ActivityStatus::Running,
            at: 0,
            detail: None,
            diff: None,
            approval: None,
        }
    }

    #[test]
    fn activities_anchor_at_utf16_offsets_and_stay_bounded() {
        let (tx, mut rx) = unbounded_channel();
        let sink = Recorder(tx);
        let mut acc = Acc::new();
        assert!(acc.push("m", &sink, "zażółć \u{1F600}".into()));
        acc.upsert("m", &sink, act("a"));
        assert_eq!(acc.activity[0].at, 9); // 7 BMP units + one surrogate pair
        assert!(acc.push("m", &sink, "!".into()));
        let mut update = act("a");
        update.status = ActivityStatus::Completed;
        update.detail = Some("é".repeat(DETAIL_CAP));
        update.diff = Some(ActivityDiff {
            path: "p".into(),
            before: Some("x".repeat(DIFF_CAP + 1)),
            after: "é".repeat(DIFF_CAP),
        });
        acc.upsert("m", &sink, update);
        let a = &acc.activity[0];
        assert_eq!((a.at, a.status), (9, ActivityStatus::Completed));
        assert_eq!(a.detail.as_ref().unwrap().len(), DETAIL_CAP);
        let d = a.diff.as_ref().unwrap();
        assert_eq!(
            (d.before.as_ref().unwrap().len(), d.after.len()),
            (DIFF_CAP, DIFF_CAP)
        );
        for i in 0..MAX_ACTIVITIES + 5 {
            acc.upsert("m", &sink, act(&format!("n{i}")));
        }
        assert_eq!(acc.activity.len(), MAX_ACTIVITIES);
        let mut events = 0;
        while let Ok(e) = rx.try_recv() {
            events += matches!(e, ThreadStreamEvent::Activity { .. }) as usize;
        }
        // 1 first insert + 1 update + the capped inserts; overflow ids emit nothing.
        assert_eq!(events, 2 + MAX_ACTIVITIES - 1);
    }

    #[test]
    fn text_after_an_activity_is_separated_and_approvals_bypass_the_cap() {
        let (tx, _rx) = unbounded_channel();
        let sink = Recorder(tx);
        let mut acc = Acc::new();
        assert!(acc.push("m", &sink, "starts.".into()));
        acc.upsert("m", &sink, act("a"));
        assert!(acc.push("m", &sink, "The port".into()));
        assert!(acc.push("m", &sink, " ok".into()));
        assert_eq!(acc.content, "starts.\n\nThe port ok");
        assert_eq!(acc.activity[0].at, 7);
        assert_eq!(acc.utf16, acc.content.encode_utf16().count() as u64);
        for i in 0..MAX_ACTIVITIES {
            acc.upsert("m", &sink, act(&format!("n{i}")));
        }
        let mut asked = act("ask");
        asked.approval = Some(Approval {
            request_id: "r".into(),
            state: ApprovalState::Pending,
            can_remember: false,
        });
        acc.upsert("m", &sink, asked);
        assert!(acc.activity.iter().any(|a| a.id == "ask"));
        close_activities(&mut acc.activity);
        let last = acc.activity.last().unwrap();
        assert_eq!(
            (last.status, last.approval.as_ref().unwrap().state),
            (ActivityStatus::Failed, ApprovalState::Expired)
        );
        assert!(
            acc.activity
                .iter()
                .all(|a| a.status != ActivityStatus::Running)
        );
    }

    fn git(dir: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["-c", "user.name=t", "-c", "user.email=t@t"])
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {out:?}");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// A git work tree `repo` holding a committed `a.txt`.
    fn repo(dir: &Path) -> std::path::PathBuf {
        let repo = dir.join("repo");
        std::fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        std::fs::write(repo.join("a.txt"), "one\n").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "init"]);
        repo
    }

    const EDITING_CLI: &str = r#"echo two > a.txt
printf '%s\n' '{"type":"result","result":"done"}'"#;

    async fn final_message(rx: &mut UnboundedReceiver<ThreadStreamEvent>) -> ThreadMessage {
        loop {
            if let ThreadStreamEvent::Final { message, .. } = rx.recv().await.expect("final") {
                return message;
            }
        }
    }

    fn refs(repo: &Path) -> String {
        git(repo, &["for-each-ref", "refs/lomi/chat/"])
    }

    #[tokio::test]
    async fn editing_turn_records_changes_and_can_be_undone() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repo(dir.path());
        let (engine, thread) = setup_with(
            "claude",
            EDITING_CLI,
            dir.path(),
            true,
            Permissions::Edit,
            &repo,
        );
        let (accepted, mut rx) = send(&engine, &thread).await;
        let message = final_message(&mut rx).await;
        let changes = message.changes.clone().expect("changes");
        assert!(!changes.undone);
        assert_eq!(changes.files.len(), 1);
        assert_eq!(changes.files[0].path, "a.txt");
        assert_eq!(refs(&repo).lines().count(), 2);
        assert_eq!(assistant(&engine, &thread.thread_id).changes, Some(changes));

        let (e, t, m) = (
            engine.clone(),
            thread.thread_id.clone(),
            accepted.assistant.message_id.clone(),
        );
        let diff = blocking(move || {
            assert!(e.turn_diff(&t, &m, "other.txt").is_err());
            e.turn_diff(&t, &m, "a.txt")
        })
        .await
        .unwrap();
        assert!(diff.contains("+two"), "{diff}");

        let (e, t, m) = (
            engine.clone(),
            thread.thread_id.clone(),
            accepted.assistant.message_id.clone(),
        );
        let (report, revision) = blocking(move || e.turn_undo(&t, &m)).await.unwrap();
        assert_eq!(report.restored, vec!["a.txt".to_string()]);
        assert_eq!(
            std::fs::read_to_string(repo.join("a.txt")).unwrap(),
            "one\n"
        );
        assert!(
            assistant(&engine, &thread.thread_id)
                .changes
                .unwrap()
                .undone
        );
        assert!(
            engine
                .with(|i| i.store.thread(&thread.thread_id))
                .unwrap()
                .revision
                >= revision
        );

        let (e, t, m) = (
            engine.clone(),
            thread.thread_id.clone(),
            accepted.assistant.message_id.clone(),
        );
        assert!(blocking(move || e.turn_undo(&t, &m)).await.is_err());

        engine.remove_checkpoints(&thread.thread_id, repo.to_str());
        assert!(refs(&repo).is_empty());
    }

    #[tokio::test]
    async fn turn_without_edits_leaves_no_refs() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repo(dir.path());
        let (engine, thread) = setup_with(
            "claude",
            r#"printf '%s\n' '{"type":"result","result":"done"}'"#,
            dir.path(),
            true,
            Permissions::Full,
            &repo,
        );
        let (_, mut rx) = send(&engine, &thread).await;
        assert!(final_message(&mut rx).await.changes.is_none());
        assert!(refs(&repo).is_empty());
    }

    #[tokio::test]
    async fn read_only_thread_captures_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repo(dir.path());
        let (engine, thread) = setup_with(
            "claude",
            EDITING_CLI,
            dir.path(),
            true,
            Permissions::ReadOnly,
            &repo,
        );
        let (_, mut rx) = send(&engine, &thread).await;
        assert!(final_message(&mut rx).await.changes.is_none());
        assert!(refs(&repo).is_empty());
    }

    #[tokio::test]
    async fn non_git_thread_captures_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain");
        std::fs::create_dir(&plain).unwrap();
        let (engine, thread) = setup_with(
            "claude",
            EDITING_CLI,
            dir.path(),
            true,
            Permissions::Edit,
            &plain,
        );
        let (_, mut rx) = send(&engine, &thread).await;
        let message = final_message(&mut rx).await;
        assert_eq!(message.state, MessageState::Completed);
        assert!(message.changes.is_none());
    }
}
