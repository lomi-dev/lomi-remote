//! Host-owned PTY sessions; one Rust parser per session, bounded observer queues,
//! explicit connection-bound control, and ephemeral byte-count receipts.
use lomi_remote_protocol::{
    ConsumerAuthorizationId, SessionEpoch, TerminalSessionId, ipc::LocalShellIntegration,
    streams::WorkingDirectory,
};
use lomi_terminal_state::{GridPatch, Snapshot, TerminalState};
#[cfg(any(unix, windows))]
use std::thread;
use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use uuid::Uuid;

pub mod shell;

pub const ATTACHMENT_BYTES: usize = 1024 * 1024;
pub const MAX_ATTACHMENTS: usize = 64;
pub const MAX_SESSIONS: usize = 32;
pub const INPUT_LIMIT: usize = 16384;
pub const RECEIPT_LIMIT: usize = 128;
pub const LEASE_TTL: Duration = Duration::from_secs(5);
const WRITE_DEADLINE: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    UnsupportedPlatform,
    SessionMissing,
    SessionExists,
    StaleEpoch,
    ResourceExhausted,
    InvalidArgument,
    /// No executable was successfully started.
    SpawnFailed,
    /// A child may already have performed startup effects; cleanup was attempted.
    SpawnOutcomeUnknown,
    StateFailed,
    SessionExited,
    ControlRequired,
    LeaseExpired,
    SequenceConflict,
    RenderAckRequired,
    CleanupFailed,
    /// Trusted final gate rejected before the protected terminal action.
    FenceRejected,
    OutcomeUnknown,
}
pub type Result<T> = std::result::Result<T, Error>;
/// Trusted local configuration, never a request DTO. Host resolves profile IDs,
/// executable/arguments/environment and workspace root before calling spawn.
#[derive(Clone)]
pub struct SpawnProfile {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub environment: Vec<(String, String)>,
    /// Trusted Host-owned descriptor. Remote RPC can only select its profile ID.
    pub shell_integration: Option<LocalShellIntegration>,
    pub rows: u16,
    pub cols: u16,
    pub history: usize,
}
/// Non-wire capability supplied by the authenticated coordinator. A reconnect
/// creates a fresh value even if the actor is unchanged; it inherits no lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedConnection {
    id: Uuid,
    actor: ConsumerAuthorizationId,
}
impl AuthenticatedConnection {
    pub fn new(actor: ConsumerAuthorizationId) -> Self {
        Self {
            id: Uuid::new_v4(),
            actor,
        }
    }
    pub fn actor(&self) -> ConsumerAuthorizationId {
        self.actor
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct ControlLease {
    token: Uuid,
    pub version: u64,
    pub next_input_seq: u64,
    pub next_input_id: u64,
    pub next_resize_seq: u64,
}
impl ControlLease {
    pub fn wire_token(&self) -> String {
        self.token.to_string()
    }
    pub fn wire_binding(&self) -> lomi_remote_protocol::rpc::LeaseBinding {
        lomi_remote_protocol::rpc::LeaseBinding {
            token: self
                .wire_token()
                .try_into()
                .expect("generated UUID is a bounded lease token"),
            version: lomi_remote_protocol::DecimalU64(self.version),
        }
    }
}
impl std::fmt::Debug for ControlLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ControlLease([REDACTED])")
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputOutcome {
    Accepted,
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputReceipt {
    pub input_id: u64,
    pub input_seq: u64,
    pub submitted_bytes: usize,
    pub accepted_bytes: usize,
    pub outcome: InputOutcome,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResizeReceipt {
    pub resize_seq: u64,
    pub rows: u16,
    pub cols: u16,
}
#[derive(Debug, Clone)]
pub enum TerminalEvent {
    State(Box<GridPatch>),
    ControlChanged {
        sequence: u64,
        version: u64,
        controlled: bool,
    },
    Exited {
        sequence: u64,
    },
    ResyncRequired,
}
/// Event plus Host-side CWD captured under the same terminal lock and sequence.
/// This additive envelope keeps the established TerminalEvent variants stable.
pub struct TerminalEventEnvelope {
    pub event: Arc<TerminalEvent>,
    pub working_directory: Option<WorkingDirectory>,
}
#[derive(Default)]
struct Queue {
    events: VecDeque<(usize, Arc<TerminalEvent>, Option<WorkingDirectory>)>,
    bytes: usize,
    overflow: bool,
    notified: bool,
}
struct Subscriber {
    connection: AuthenticatedConnection,
    queue: Arc<Mutex<Queue>>,
    snapshot_seq: u64,
    ack: Option<u64>,
}
/// Snapshot and queue registration occur in one session lock. Polling does not
/// acquire the terminal/model lock and cannot block the PTY reader.
pub struct Attachment {
    pub snapshot: Snapshot,
    pub working_directory: Option<WorkingDirectory>,
    id: Uuid,
    core: Weak<Mutex<Core>>,
    queue: Arc<Mutex<Queue>>,
}
impl Attachment {
    pub fn try_next(&self) -> Option<Arc<TerminalEvent>> {
        self.try_next_with_metadata().map(|queued| queued.event)
    }
    pub fn try_next_with_metadata(&self) -> Option<TerminalEventEnvelope> {
        let mut queue = self.queue.lock().ok()?;
        if queue.overflow && !queue.notified {
            queue.notified = true;
            return Some(TerminalEventEnvelope {
                event: Arc::new(TerminalEvent::ResyncRequired),
                working_directory: None,
            });
        }
        let (bytes, event, working_directory) = queue.events.pop_front()?;
        queue.bytes -= bytes;
        Some(TerminalEventEnvelope {
            event,
            working_directory,
        })
    }
    pub fn resync_required(&self) -> bool {
        self.queue.lock().map_or(true, |q| q.overflow)
    }
    pub fn acknowledge(&self, connection: &AuthenticatedConnection, through: u64) -> Result<()> {
        self.acknowledge_checked(connection, through, || true)
    }
    /// Recheck trusted proof after acquiring Core, before reading or changing ACK state.
    /// The predicate runs under Core: it must not block, acquire Domain/Store, or
    /// reenter terminal locks. The owner supplies pinned proof, atomic gates and time;
    /// this callback alone does not serialize durable authorization facts.
    pub fn acknowledge_checked(
        &self,
        connection: &AuthenticatedConnection,
        through: u64,
        mut current_fence: impl FnMut() -> bool,
    ) -> Result<()> {
        let core = self.core.upgrade().ok_or(Error::SessionMissing)?;
        let mut core = core.lock().map_err(|_| Error::StateFailed)?;
        if !current_fence() {
            return Err(Error::FenceRejected);
        }
        let current = core.last.sequence.0;
        let subscriber = core
            .subscribers
            .get_mut(&self.id)
            .ok_or(Error::RenderAckRequired)?;
        if &subscriber.connection != connection
            || through < subscriber.snapshot_seq
            || through > current
            || subscriber.ack.is_some_and(|old| through < old)
        {
            return Err(Error::InvalidArgument);
        }
        subscriber.ack = Some(through);
        Ok(())
    }
}
impl Drop for Attachment {
    fn drop(&mut self) {
        if let Some(core) = self.core.upgrade()
            && let Ok(mut core) = core.lock()
            && let Some(sub) = core.subscribers.remove(&self.id)
            && core
                .lease
                .as_ref()
                .is_some_and(|l| l.connection == sub.connection && l.attachment == self.id)
        {
            core.revoke();
        }
    }
}
struct LeaseState {
    connection: AuthenticatedConnection,
    attachment: Uuid,
    credential: ControlLease,
    expires: Instant,
}
struct SavedInput {
    connection: AuthenticatedConnection,
    receipt: InputReceipt,
}
#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    pub host_replies: u64,
    pub output_bytes: u64,
    pub subscriber_overflows: u64,
}
struct Core {
    epoch: SessionEpoch,
    model: TerminalState,
    last: Snapshot,
    subscribers: HashMap<Uuid, Subscriber>,
    lease: Option<LeaseState>,
    lease_version: u64,
    input_seq: u64,
    input_id: u64,
    history: usize,
    resize_seq: u64,
    inputs: VecDeque<SavedInput>,
    resizes: VecDeque<(AuthenticatedConnection, ResizeReceipt)>,
    exited: bool,
    closing: bool,
    exited_at: Option<Instant>,
    retired: bool,
    retirement: Option<Uuid>,
    stats: SessionStats,
    #[cfg(any(unix, windows))]
    pty: backend::Pty,
}
impl Core {
    fn check(&self, epoch: SessionEpoch) -> Result<()> {
        self.check_read(epoch)?;
        if self.exited || self.closing {
            Err(Error::SessionExited)
        } else {
            Ok(())
        }
    }
    fn check_read(&self, epoch: SessionEpoch) -> Result<()> {
        if self.epoch != epoch {
            Err(Error::StaleEpoch)
        } else if self.retired {
            Err(Error::SessionMissing)
        } else {
            Ok(())
        }
    }
    fn publish(&mut self, event: TerminalEvent, bytes: usize) {
        self.publish_with_metadata(event, bytes, None);
    }
    fn publish_with_metadata(
        &mut self,
        event: TerminalEvent,
        bytes: usize,
        working_directory: Option<WorkingDirectory>,
    ) {
        let event = Arc::new(event);
        self.subscribers.retain(|_, subscriber| {
            let Ok(mut queue) = subscriber.queue.lock() else {
                return false;
            };
            if bytes > ATTACHMENT_BYTES.saturating_sub(queue.bytes) || queue.events.len() >= 128 {
                queue.events.clear();
                queue.bytes = 0;
                queue.overflow = true;
                self.stats.subscriber_overflows = self.stats.subscriber_overflows.saturating_add(1);
                false
            } else {
                queue
                    .events
                    .push_back((bytes, event.clone(), working_directory.clone()));
                queue.bytes += bytes;
                true
            }
        });
        if self.lease.as_ref().is_some_and(|lease| {
            self.subscribers
                .get(&lease.attachment)
                .is_none_or(|s| s.connection != lease.connection || s.ack.is_none())
        }) {
            self.revoke();
        }
    }
    fn state_changed(&mut self) -> Result<()> {
        let next = self.model.snapshot().map_err(|_| Error::StateFailed)?;
        let delta = GridPatch::between(&self.last, &next).map_err(|_| Error::StateFailed)?;
        let grid_bytes = serde_json::to_vec(&delta)
            .map_err(|_| Error::StateFailed)?
            .len();
        let working_directory = self
            .model
            .working_directory()
            .and_then(|path| WorkingDirectory::try_from(path.to_owned()).ok());
        let bytes = grid_bytes.saturating_add(
            working_directory
                .as_ref()
                .map_or(0, |path| path.as_str().len()),
        );
        self.last = next;
        self.publish_with_metadata(
            TerminalEvent::State(Box::new(delta)),
            bytes,
            working_directory,
        );
        Ok(())
    }
    fn control_changed(&mut self, controlled: bool) {
        if self.model.feed(&[]).is_err() {
            self.exited = true;
            self.exited_at.get_or_insert_with(Instant::now);
            return;
        }
        if let Ok(snapshot) = self.model.snapshot() {
            self.last = snapshot;
            self.publish(
                TerminalEvent::ControlChanged {
                    sequence: self.last.sequence.0,
                    version: self.lease_version,
                    controlled,
                },
                128,
            );
        } else {
            self.exited = true;
            self.exited_at.get_or_insert_with(Instant::now);
        }
    }
    fn revoke(&mut self) {
        if self.lease.take().is_some() {
            self.lease_version = self.lease_version.saturating_add(1);
            self.control_changed(false);
        }
    }
    fn check_lease(
        &mut self,
        connection: &AuthenticatedConnection,
        credential: &ControlLease,
        now: Instant,
    ) -> Result<()> {
        if self.lease.as_ref().is_some_and(|l| {
            self.subscribers
                .get(&l.attachment)
                .is_none_or(|s| s.connection != l.connection || s.ack.is_none())
        }) {
            self.revoke();
            return Err(Error::ControlRequired);
        }
        if self.lease.as_ref().is_some_and(|l| now >= l.expires) {
            self.revoke();
            return Err(Error::LeaseExpired);
        }
        if self.lease.as_ref().is_none_or(|l| {
            &l.connection != connection
                || l.credential.token != credential.token
                || l.credential.version != credential.version
        }) {
            return Err(Error::ControlRequired);
        }
        Ok(())
    }
    fn disconnect(&mut self, connection: &AuthenticatedConnection) {
        self.subscribers
            .retain(|_, sub| &sub.connection != connection);
        if self
            .lease
            .as_ref()
            .is_some_and(|l| &l.connection == connection)
        {
            self.revoke();
        }
    }
}
struct Session {
    core: Arc<Mutex<Core>>,
    stopping: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
    // Acquired before map/Core; never wait for this gate under either lock.
    retirement_gate: Arc<Mutex<()>>,
}
impl Session {
    fn stop(&self) -> Result<()> {
        self.stopping.store(true, Ordering::Release);
        // Do not hold Core while waiting: pump observes stopping, drops its
        // reader, then closes the remaining PTY handles before bounded reap.
        if let Some(worker) = self.worker.lock().map_err(|_| Error::StateFailed)?.take() {
            worker.join().map_err(|_| Error::CleanupFailed)?;
        }
        let mut core = self.core.lock().unwrap_or_else(|p| p.into_inner());
        core.revoke();
        #[cfg(any(unix, windows))]
        {
            core.pty.stop()
        }
        #[cfg(not(any(unix, windows)))]
        {
            Ok(())
        }
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
// Only a matching reservation can be cancelled. Recover poison on unwind so
// a panicking persistence callback cannot leave a permanently reserved model.
struct RetirementReservation<'a> {
    session: &'a Session,
    token: Uuid,
}
impl Drop for RetirementReservation<'_> {
    fn drop(&mut self) {
        let mut core = self.session.core.lock().unwrap_or_else(|p| p.into_inner());
        if core.retirement == Some(self.token) {
            core.retirement = None;
        }
    }
}
/// Trusted host-only exit identity; contains no terminal output.
pub struct ExitedSession {
    pub session_id: TerminalSessionId,
    pub session_epoch: SessionEpoch,
    pub exited_at: Instant,
}
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum RetirementWait {
    Retire,
    Stop,
    Shutdown,
    Attach,
}
#[cfg(test)]
type RetirementWaitHook = Arc<dyn Fn(RetirementWait, TerminalSessionId) + Send + Sync>;
// Published sessions and pending admissions share one exclusion point. Pending
// slots remain charged until their creator has dropped every owned resource.
#[derive(Default)]
struct SessionRegistry {
    published: HashMap<TerminalSessionId, Arc<Session>>,
    pending: HashMap<TerminalSessionId, Arc<SpawnControl>>,
}
impl std::ops::Deref for SessionRegistry {
    type Target = HashMap<TerminalSessionId, Arc<Session>>;
    fn deref(&self) -> &Self::Target {
        &self.published
    }
}
impl std::ops::DerefMut for SessionRegistry {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.published
    }
}
impl SessionRegistry {
    fn occupied(&self) -> usize {
        self.published.len() + self.pending.len()
    }
    fn accepts_spawn(&self, id: TerminalSessionId, control: &Arc<SpawnControl>) -> bool {
        !control.cancelled.load(Ordering::Acquire)
            && self
                .pending
                .get(&id)
                .is_some_and(|current| Arc::ptr_eq(current, control))
            && !self.published.contains_key(&id)
    }
}
struct SpawnControl {
    cancelled: AtomicBool,
    // Publication and a stop of this exact admission share the eventual
    // session's retirement gate. Never wait for it while holding the map.
    gate: Arc<Mutex<()>>,
}
/// Owned, non-wire admission for exactly one session ID/epoch/profile. Dropping
/// it releases only this admission; it never starts a child or retries a command.
/// The service must outlive the preparation, including all backend cleanup.
pub struct SpawnPreparation<'a> {
    service: &'a TerminalService,
    id: TerminalSessionId,
    epoch: SessionEpoch,
    profile: SpawnProfile,
    model: Option<TerminalState>,
    last: Option<Snapshot>,
    control: Arc<SpawnControl>,
}
impl SpawnPreparation<'_> {
    /// Execute this admission once. Callbacks run without the sessions map or
    /// Core held; the backend still invokes before_spawn at its pre-exec gate.
    pub fn spawn_with_checks(
        self,
        before_spawn: impl FnOnce() -> bool,
        startup_check: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let mut before_spawn = Some(before_spawn);
        let mut result = None;
        self.spawn_with_checks_until(
            Instant::now() + Duration::from_secs(6),
            || {
                *result.get_or_insert_with(|| {
                    before_spawn
                        .take()
                        .is_some_and(|before_spawn| before_spawn())
                })
            },
            startup_check,
        )
    }
    /// Execute this admission once using an existing operation deadline and a
    /// repeatable final fence for bounded handshakes.
    pub fn spawn_with_checks_until(
        self,
        deadline: Instant,
        before_spawn: impl FnMut() -> bool,
        startup_check: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.service
            .spawn_prepared(self, deadline, before_spawn, startup_check)
    }
}
impl Drop for SpawnPreparation<'_> {
    fn drop(&mut self) {
        let mut sessions = self
            .service
            .sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if sessions
            .pending
            .get(&self.id)
            .is_some_and(|current| Arc::ptr_eq(current, &self.control))
        {
            sessions.pending.remove(&self.id);
        }
    }
}
#[derive(Default)]
pub struct TerminalService {
    sessions: Mutex<SessionRegistry>,
    #[cfg(test)]
    retirement_wait_hook: Mutex<Option<RetirementWaitHook>>,
    #[cfg(unix)]
    #[cfg_attr(all(unix, feature = "owned-host-fixture"), allow(dead_code))]
    worker_executable: Option<PathBuf>,
    #[cfg(target_os = "macos")]
    worker_profile: Option<PathBuf>,
    shell_bundle_root: Option<PathBuf>,
}
impl TerminalService {
    pub fn new() -> Self {
        Self::default()
    }
    /// Use the same executable's private worker mode for crash-supervised PTYs.
    pub fn with_worker(executable: PathBuf) -> Self {
        #[cfg(not(unix))]
        let _ = executable;
        Self {
            sessions: Mutex::default(),
            #[cfg(test)]
            retirement_wait_hook: Mutex::default(),
            #[cfg(unix)]
            worker_executable: Some(executable),
            #[cfg(target_os = "macos")]
            worker_profile: None,
            shell_bundle_root: None,
        }
    }
    /// Bind macOS workers to the selected account's privileged custody service.
    /// Shell arguments and environment travel only through authenticated IPC;
    /// a missing service never selects an uncontained fallback.
    pub fn with_worker_in_profile(executable: PathBuf, profile_dir: PathBuf) -> Self {
        let mut service = Self::with_worker(executable);
        service.shell_bundle_root = Some(shell::bundle_path(&profile_dir));
        #[cfg(target_os = "macos")]
        {
            service.worker_profile = Some(profile_dir);
            service
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = profile_dir;
            service
        }
    }
    // Tests pause only after a concrete Arc/snapshot has been captured. Clone
    // the hook before invoking it so a barrier never holds the hook mutex.
    #[cfg(test)]
    fn before_retirement_wait(&self, kind: RetirementWait, id: TerminalSessionId) {
        let hook = self.retirement_wait_hook.lock().unwrap().clone();
        if let Some(hook) = hook {
            hook(kind, id);
        }
    }
    fn session(&self, id: TerminalSessionId) -> Result<Arc<Session>> {
        self.sessions
            .lock()
            .map_err(|_| Error::StateFailed)?
            .get(&id)
            .cloned()
            .ok_or(Error::SessionMissing)
    }
    /// Call only after durable intent and a final coordinator fence check. This
    /// service neither owns the DB transaction nor invents/replays an intent.
    pub fn spawn(
        &self,
        id: TerminalSessionId,
        epoch: SessionEpoch,
        profile: &SpawnProfile,
    ) -> Result<()> {
        self.spawn_with_startup_check(id, epoch, profile, || Ok(()))
    }
    /// Trusted non-wire integrity check after child acquisition, before the
    /// reader starts. Failure cannot undo startup effects and is always unknown.
    /// The callback itself must be bounded and must not retain the child/model.
    pub fn spawn_with_startup_check(
        &self,
        id: TerminalSessionId,
        epoch: SessionEpoch,
        profile: &SpawnProfile,
        startup_check: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.spawn_with_checks(id, epoch, profile, || true, startup_check)
    }
    /// Trusted checks bracket child startup. The pre-spawn fence runs after
    /// allocation immediately before exec; rejection proves no child ran. The
    /// post-spawn check cannot undo startup effects. Both callbacks must be bounded.
    pub fn spawn_with_checks(
        &self,
        id: TerminalSessionId,
        epoch: SessionEpoch,
        profile: &SpawnProfile,
        before_spawn: impl FnOnce() -> bool,
        startup_check: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let mut before_spawn = Some(before_spawn);
        let mut result = None;
        self.spawn_with_checks_until(
            id,
            epoch,
            profile,
            Instant::now() + Duration::from_secs(6),
            || {
                *result.get_or_insert_with(|| {
                    before_spawn
                        .take()
                        .is_some_and(|before_spawn| before_spawn())
                })
            },
            startup_check,
        )
    }
    /// Spawn using the original monotonic operation deadline. The repeatable
    /// fence is checked after custodian preparation and while awaiting startup.
    pub fn spawn_with_checks_until(
        &self,
        id: TerminalSessionId,
        epoch: SessionEpoch,
        profile: &SpawnProfile,
        deadline: Instant,
        before_spawn: impl FnMut() -> bool,
        startup_check: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.prepare_spawn(id, epoch, profile)?
            .spawn_with_checks_until(deadline, before_spawn, startup_check)
    }
    /// Reserve capacity/identity and capture the trusted profile before any
    /// backend work. No Store/domain acquisition belongs under the map lock.
    pub fn prepare_spawn(
        &self,
        id: TerminalSessionId,
        epoch: SessionEpoch,
        profile: &SpawnProfile,
    ) -> Result<SpawnPreparation<'_>> {
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (id, epoch, profile);
            Err(Error::UnsupportedPlatform)
        }
        #[cfg(any(unix, windows))]
        {
            let mut sessions = self.sessions.lock().map_err(|_| Error::StateFailed)?;
            if sessions.contains_key(&id) || sessions.pending.contains_key(&id) {
                return Err(Error::SessionExists);
            }
            if sessions.occupied() >= MAX_SESSIONS {
                return Err(Error::ResourceExhausted);
            }
            let model = TerminalState::new_with_epoch(
                profile.rows.into(),
                profile.cols.into(),
                profile.history,
                epoch,
            )
            .map_err(|_| Error::InvalidArgument)?;
            let last = model.snapshot().map_err(|_| Error::StateFailed)?;
            let control = Arc::new(SpawnControl {
                cancelled: AtomicBool::new(false),
                gate: Arc::new(Mutex::new(())),
            });
            let preparation = SpawnPreparation {
                service: self,
                id,
                epoch,
                profile: profile.clone(),
                model: Some(model),
                last: Some(last),
                control: control.clone(),
            };
            sessions.pending.insert(id, control);
            Ok(preparation)
        }
    }
    fn spawn_prepared(
        &self,
        mut preparation: SpawnPreparation<'_>,
        deadline: Instant,
        mut before_spawn: impl FnMut() -> bool,
        startup_check: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (preparation, deadline, before_spawn, startup_check);
            Err(Error::UnsupportedPlatform)
        }
        #[cfg(any(unix, windows))]
        {
            let id = preparation.id;
            let epoch = preparation.epoch;
            let mut pre_spawn_gate = || {
                if Instant::now() >= deadline
                    || preparation.control.cancelled.load(Ordering::Acquire)
                {
                    return false;
                }
                let permitted = before_spawn();
                permitted
                    && !preparation.control.cancelled.load(Ordering::Acquire)
                    && Instant::now() < deadline
            };
            if !pre_spawn_gate() {
                return Err(if preparation.control.cancelled.load(Ordering::Acquire) {
                    Error::SpawnFailed
                } else {
                    Error::FenceRejected
                });
            }
            let materialized = if preparation.profile.shell_integration.is_some() {
                let bundle = self
                    .shell_bundle_root
                    .as_deref()
                    .ok_or(Error::InvalidArgument)?;
                Some(shell::build_spawn_profile(
                    &preparation.profile,
                    bundle,
                    deadline,
                    &mut pre_spawn_gate,
                )?)
            } else {
                None
            };
            let profile = materialized.as_ref().unwrap_or(&preparation.profile);
            let model = preparation.model.take().ok_or(Error::StateFailed)?;
            let last = preparation.last.take().ok_or(Error::StateFailed)?;
            if preparation.control.cancelled.load(Ordering::Acquire) {
                return Err(Error::SpawnFailed);
            }
            if !pre_spawn_gate() {
                return Err(if preparation.control.cancelled.load(Ordering::Acquire) {
                    Error::SpawnFailed
                } else {
                    Error::FenceRejected
                });
            }
            #[cfg(all(unix, feature = "owned-host-fixture"))]
            let (pty, reader) = supervisor::owned_fixture::spawn(profile, pre_spawn_gate)?;
            #[cfg(all(unix, not(feature = "owned-host-fixture")))]
            let (pty, reader) = match &self.worker_executable {
                Some(executable) => {
                    #[cfg(all(
                        target_os = "macos",
                        feature = "experimental-macos-coalition-cleanup"
                    ))]
                    if let Some(directory) = &self.worker_profile {
                        supervisor::macos_coalition::spawn(
                            executable,
                            directory,
                            profile,
                            pre_spawn_gate,
                            deadline,
                        )?
                    } else {
                        supervisor::spawn(executable, profile, pre_spawn_gate)?
                    }
                    #[cfg(all(
                        target_os = "macos",
                        not(feature = "experimental-macos-coalition-cleanup")
                    ))]
                    {
                        let directory =
                            self.worker_profile.as_ref().ok_or(Error::InvalidArgument)?;
                        supervisor::macos_privileged::spawn(
                            executable,
                            directory,
                            profile,
                            pre_spawn_gate,
                            deadline,
                        )?
                    }
                    #[cfg(not(target_os = "macos"))]
                    supervisor::spawn(executable, profile, pre_spawn_gate)?
                }
                None => {
                    #[cfg(target_os = "macos")]
                    {
                        return Err(Error::InvalidArgument);
                    }
                    #[cfg(not(target_os = "macos"))]
                    unix::Pty::spawn(profile, pre_spawn_gate)?
                }
            };
            #[cfg(windows)]
            let (pty, reader) = backend::Pty::spawn(profile, pre_spawn_gate)?;
            if startup_check().is_err() {
                drop(reader);
                drop(pty);
                return Err(Error::SpawnOutcomeUnknown);
            }
            let core = Arc::new(Mutex::new(Core {
                epoch,
                model,
                last,
                subscribers: HashMap::new(),
                lease: None,
                lease_version: 0,
                input_seq: 0,
                input_id: 0,
                history: profile.history,
                resize_seq: 0,
                inputs: VecDeque::new(),
                resizes: VecDeque::new(),
                exited: false,
                closing: false,
                exited_at: None,
                retired: false,
                retirement: None,
                stats: SessionStats::default(),
                pty,
            }));
            let stopping = Arc::new(AtomicBool::new(false));
            let worker_core = core.clone();
            let worker_stopping = stopping.clone();
            let worker = thread::Builder::new()
                .name("lomi-terminal-reader".into())
                .spawn(move || {
                    let cleanup = worker_core.clone();
                    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        backend::pump(worker_core, worker_stopping, reader)
                    }))
                    .is_err()
                    {
                        let mut core = cleanup.lock().unwrap_or_else(|p| p.into_inner());
                        core.exited = true;
                        core.exited_at.get_or_insert_with(Instant::now);
                        core.revoke();
                        let _ = core.pty.stop();
                    }
                })
                .map_err(|_| Error::SpawnOutcomeUnknown)?;
            let session = Arc::new(Session {
                core,
                stopping,
                worker: Mutex::new(Some(worker)),
                retirement_gate: preparation.control.gate.clone(),
            });
            let gate = preparation
                .control
                .gate
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| Error::SpawnOutcomeUnknown)?;
            if !sessions.accepts_spawn(id, &preparation.control) {
                // session owns the actual child/reader; its Drop uses the
                // existing stop/reap path after these guards are released.
                return Err(Error::SpawnOutcomeUnknown);
            }
            sessions.pending.remove(&id);
            sessions.insert(id, session);
            drop(sessions);
            drop(gate);
            Ok(())
        }
    }
    /// Bounded host lifecycle observations, independent of attached views.
    /// No model lock remains held while the coordinator persists these IDs.
    pub fn exited_sessions(&self) -> Result<Vec<ExitedSession>> {
        let sessions = self.sessions.lock().map_err(|_| Error::StateFailed)?;
        let mut exits = Vec::new();
        for (id, session) in sessions.iter() {
            let core = session.core.lock().map_err(|_| Error::StateFailed)?;
            if core.exited && !core.retired {
                #[cfg(any(unix, windows))]
                if !core.pty.cleanup_ready()? {
                    continue;
                }
                exits.push(ExitedSession {
                    session_id: *id,
                    session_epoch: core.epoch,
                    exited_at: core.exited_at.unwrap_or_else(Instant::now),
                });
            }
        }
        exits.sort_by_key(|exit| (exit.exited_at, exit.session_id.to_bytes()));
        Ok(exits)
    }
    pub fn at_capacity(&self) -> Result<bool> {
        Ok(self
            .sessions
            .lock()
            .map_err(|_| Error::StateFailed)?
            .occupied()
            >= MAX_SESSIONS)
    }
    /// Reserve an exited model with no subscribers/control, persist without
    /// map/Core locks, then commit that exact reservation before RAM removal.
    /// The internal gate excludes attach, claim, stop and shutdown throughout.
    /// Persistence must not reenter a gated operation on this same session.
    pub fn retire_exited(
        &self,
        id: TerminalSessionId,
        epoch: SessionEpoch,
        persist: impl FnOnce() -> bool,
    ) -> Result<bool> {
        let session = match self.session(id) {
            Ok(session) => session,
            Err(Error::SessionMissing) => return Ok(false),
            Err(error) => return Err(error),
        };
        // A persistence panic does not corrupt the gate's data (there is none).
        #[cfg(test)]
        self.before_retirement_wait(RetirementWait::Retire, id);
        let gate = session
            .retirement_gate
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let token = Uuid::new_v4();
        {
            let sessions = self.sessions.lock().map_err(|_| Error::StateFailed)?;
            if !sessions
                .get(&id)
                .is_some_and(|current| Arc::ptr_eq(current, &session))
            {
                return Ok(false);
            }
            let mut core = session.core.lock().map_err(|_| Error::StateFailed)?;
            core.check_read(epoch)?;
            if !core.exited
                || !core.subscribers.is_empty()
                || core.lease.is_some()
                || core.retirement.is_some()
            {
                return Ok(false);
            }
            core.retirement = Some(token);
        }
        let reservation = RetirementReservation {
            session: &session,
            token,
        };
        if !persist() {
            return Ok(false);
        }
        {
            let mut sessions = self.sessions.lock().map_err(|_| Error::StateFailed)?;
            let mut core = session.core.lock().map_err(|_| Error::StateFailed)?;
            // The gate excludes every map remover and subscriber/lease creator.
            // Validate identity anyway; never remove a replacement generation.
            if !sessions
                .get(&id)
                .is_some_and(|current| Arc::ptr_eq(current, &session))
                || core.epoch != epoch
                || core.retirement != Some(token)
                || !core.exited
                || !core.subscribers.is_empty()
                || core.lease.is_some()
            {
                return Err(Error::StateFailed);
            }
            core.retired = true;
            core.retirement = None;
            sessions.remove(&id);
        }
        drop(reservation);
        drop(gate);
        session.stop()?;
        Ok(true)
    }
    pub fn snapshot(&self, id: TerminalSessionId, epoch: SessionEpoch) -> Result<Snapshot> {
        let session = self.session(id)?;
        let _gate = session
            .retirement_gate
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let core = session.core.lock().map_err(|_| Error::StateFailed)?;
        core.check_read(epoch)?;
        Ok(core.last.clone())
    }
    pub fn attach(
        &self,
        id: TerminalSessionId,
        epoch: SessionEpoch,
        connection: &AuthenticatedConnection,
    ) -> Result<Attachment> {
        self.attach_checked(id, epoch, connection, || true)
    }
    /// Recheck trusted proof after retirement/Core waits, before snapshot disclosure
    /// or mutation. The predicate runs under terminal locks: it must not block,
    /// acquire Domain/Store, or reenter terminal locks. The owner supplies pinned
    /// proof, atomic gates and time; this alone does not serialize durable facts.
    pub fn attach_checked(
        &self,
        id: TerminalSessionId,
        epoch: SessionEpoch,
        connection: &AuthenticatedConnection,
        mut current_fence: impl FnMut() -> bool,
    ) -> Result<Attachment> {
        let session = self.session(id)?;
        #[cfg(test)]
        self.before_retirement_wait(RetirementWait::Attach, id);
        let _gate = session
            .retirement_gate
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let mut core = session.core.lock().map_err(|_| Error::StateFailed)?;
        if !current_fence() {
            return Err(Error::FenceRejected);
        }
        core.check_read(epoch)?;
        if core.subscribers.len() >= MAX_ATTACHMENTS {
            return Err(Error::ResourceExhausted);
        }
        let attachment = Uuid::new_v4();
        let queue = Arc::new(Mutex::new(Queue::default()));
        let snapshot = core.last.clone();
        let working_directory = core
            .model
            .working_directory()
            .and_then(|path| WorkingDirectory::try_from(path.to_owned()).ok());
        // A late final-screen subscription still needs a contiguous closing
        // event. Advance the shared auxiliary sequence, never a private fork;
        // its initial snapshot remains the checkpoint before that event.
        if core.exited {
            core.model.feed(&[]).map_err(|_| Error::StateFailed)?;
            core.last = core.model.snapshot().map_err(|_| Error::StateFailed)?;
        }
        core.subscribers.insert(
            attachment,
            Subscriber {
                connection: connection.clone(),
                queue: queue.clone(),
                snapshot_seq: snapshot.sequence.0,
                ack: None,
            },
        );
        if core.exited {
            let sequence = core.last.sequence.0;
            core.publish(TerminalEvent::Exited { sequence }, 128);
        }
        Ok(Attachment {
            snapshot,
            working_directory,
            id: attachment,
            core: Arc::downgrade(&session.core),
            queue,
        })
    }
    pub fn claim(
        &self,
        id: TerminalSessionId,
        epoch: SessionEpoch,
        connection: &AuthenticatedConnection,
    ) -> Result<ControlLease> {
        self.claim_checked(id, epoch, connection, || true)
    }
    /// Apply the trusted nonblocking gate after internal waits, before lease checks
    /// can revoke or change state. See [`Self::attach_checked`] for lock restrictions.
    pub fn claim_checked(
        &self,
        id: TerminalSessionId,
        epoch: SessionEpoch,
        connection: &AuthenticatedConnection,
        mut current_fence: impl FnMut() -> bool,
    ) -> Result<ControlLease> {
        let session = self.session(id)?;
        let _gate = session
            .retirement_gate
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let mut core = session.core.lock().map_err(|_| Error::StateFailed)?;
        if !current_fence() {
            return Err(Error::FenceRejected);
        }
        core.check(epoch)?;
        let now = Instant::now();
        if core.lease.as_ref().is_some_and(|l| now >= l.expires) {
            core.revoke();
        }
        if core.lease.is_some() {
            return Err(Error::ControlRequired);
        }
        let attachment = core
            .subscribers
            .iter()
            .filter(|(_, s)| {
                &s.connection == connection
                    && s.ack
                        .is_some_and(|ack| core.last.sequence.0.saturating_sub(ack) <= 64)
            })
            .max_by_key(|(_, s)| s.ack)
            .map(|(id, _)| *id)
            .ok_or(Error::RenderAckRequired)?;
        core.lease_version = core
            .lease_version
            .checked_add(1)
            .ok_or(Error::ResourceExhausted)?;
        let credential = ControlLease {
            token: Uuid::new_v4(),
            version: core.lease_version,
            next_input_seq: core
                .input_seq
                .checked_add(1)
                .ok_or(Error::ResourceExhausted)?,
            next_input_id: core
                .input_id
                .checked_add(1)
                .ok_or(Error::ResourceExhausted)?,
            next_resize_seq: core
                .resize_seq
                .checked_add(1)
                .ok_or(Error::ResourceExhausted)?,
        };
        core.lease = Some(LeaseState {
            connection: connection.clone(),
            attachment,
            credential: credential.clone(),
            expires: now + LEASE_TTL,
        });
        core.control_changed(true);
        if core.lease.is_none() {
            return Err(Error::RenderAckRequired);
        }
        Ok(credential)
    }
    pub fn renew(
        &self,
        id: TerminalSessionId,
        epoch: SessionEpoch,
        connection: &AuthenticatedConnection,
        lease: &ControlLease,
    ) -> Result<ControlLease> {
        self.renew_checked(id, epoch, connection, lease, || true)
    }
    /// Apply the trusted nonblocking gate after internal waits, before lease checks
    /// can revoke or change state. See [`Self::attach_checked`] for lock restrictions.
    pub fn renew_checked(
        &self,
        id: TerminalSessionId,
        epoch: SessionEpoch,
        connection: &AuthenticatedConnection,
        lease: &ControlLease,
        mut current_fence: impl FnMut() -> bool,
    ) -> Result<ControlLease> {
        let session = self.session(id)?;
        let _gate = session
            .retirement_gate
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let mut core = session.core.lock().map_err(|_| Error::StateFailed)?;
        if !current_fence() {
            return Err(Error::FenceRejected);
        }
        core.check(epoch)?;
        let now = Instant::now();
        core.check_lease(connection, lease, now)?;
        let next_input_id = core
            .input_id
            .checked_add(1)
            .ok_or(Error::ResourceExhausted)?;
        let next_input_seq = core
            .input_seq
            .checked_add(1)
            .ok_or(Error::ResourceExhausted)?;
        let next_resize_seq = core
            .resize_seq
            .checked_add(1)
            .ok_or(Error::ResourceExhausted)?;
        let lease = core.lease.as_mut().ok_or(Error::ControlRequired)?;
        lease.expires = now + LEASE_TTL;
        lease.credential.next_input_id = next_input_id;
        lease.credential.next_input_seq = next_input_seq;
        lease.credential.next_resize_seq = next_resize_seq;
        Ok(lease.credential.clone())
    }
    pub fn release(
        &self,
        id: TerminalSessionId,
        epoch: SessionEpoch,
        connection: &AuthenticatedConnection,
        lease: &ControlLease,
    ) -> Result<()> {
        self.release_checked(id, epoch, connection, lease, || true)
    }
    /// Apply the trusted nonblocking gate after internal waits, before lease checks
    /// can revoke or change state. See [`Self::attach_checked`] for lock restrictions.
    pub fn release_checked(
        &self,
        id: TerminalSessionId,
        epoch: SessionEpoch,
        connection: &AuthenticatedConnection,
        lease: &ControlLease,
        mut current_fence: impl FnMut() -> bool,
    ) -> Result<()> {
        let session = self.session(id)?;
        let mut core = session.core.lock().map_err(|_| Error::StateFailed)?;
        if !current_fence() {
            return Err(Error::FenceRejected);
        }
        core.check(epoch)?;
        core.check_lease(connection, lease, Instant::now())?;
        core.revoke();
        Ok(())
    }
    /// The coordinator supplies a nonblocking trusted fence/auth predicate. It
    /// is rechecked, along with lease expiry, immediately before each syscall.
    #[allow(clippy::too_many_arguments)]
    pub fn input(
        &self,
        id: TerminalSessionId,
        epoch: SessionEpoch,
        connection: &AuthenticatedConnection,
        lease: &ControlLease,
        input_id: u64,
        input_seq: u64,
        bytes: &[u8],
        mut current_fence: impl FnMut() -> bool,
    ) -> Result<InputReceipt> {
        if bytes.is_empty() || bytes.len() > INPUT_LIMIT {
            return Err(Error::InvalidArgument);
        }
        let session = self.session(id)?;
        let mut core = session.core.lock().map_err(|_| Error::StateFailed)?;
        core.check(epoch)?;
        core.check_lease(connection, lease, Instant::now())?;
        if let Some(previous) = core.inputs.iter().find(|r| r.receipt.input_id == input_id) {
            if &previous.connection != connection
                || previous.receipt.input_seq != input_seq
                || previous.receipt.submitted_bytes != bytes.len()
            {
                return Err(Error::SequenceConflict);
            }
            return Ok(previous.receipt.clone());
        }
        if input_id <= core.input_id {
            return Err(Error::SequenceConflict);
        }
        if input_seq
            != core
                .input_seq
                .checked_add(1)
                .ok_or(Error::ResourceExhausted)?
        {
            return Err(Error::SequenceConflict);
        }
        core.input_seq = input_seq;
        core.input_id = input_id;
        let mut receipt = InputReceipt {
            input_id,
            input_seq,
            submitted_bytes: bytes.len(),
            accepted_bytes: 0,
            outcome: InputOutcome::Unknown,
        };
        let deadline = Instant::now() + WRITE_DEADLINE;
        #[cfg(any(unix, windows))]
        while receipt.accepted_bytes < bytes.len() {
            if Instant::now() >= deadline
                || core.check_lease(connection, lease, Instant::now()).is_err()
                || !current_fence()
            {
                break;
            }
            match core.pty.write(&bytes[receipt.accepted_bytes..]) {
                Ok(0) => break,
                Ok(n) => receipt.accepted_bytes += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1))
                }
                Err(_) => break,
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (&mut current_fence, deadline);
        }
        if receipt.accepted_bytes == bytes.len() {
            receipt.outcome = InputOutcome::Accepted;
        }
        if core.inputs.len() == RECEIPT_LIMIT {
            core.inputs.pop_front();
        }
        core.inputs.push_back(SavedInput {
            connection: connection.clone(),
            receipt: receipt.clone(),
        });
        Ok(receipt)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn resize(
        &self,
        id: TerminalSessionId,
        epoch: SessionEpoch,
        connection: &AuthenticatedConnection,
        lease: &ControlLease,
        resize_seq: u64,
        rows: u16,
        cols: u16,
        mut current_fence: impl FnMut() -> bool,
    ) -> Result<ResizeReceipt> {
        let session = self.session(id)?;
        let mut core = session.core.lock().map_err(|_| Error::StateFailed)?;
        core.check(epoch)?;
        core.check_lease(connection, lease, Instant::now())?;
        if let Some((owner, previous)) = core
            .resizes
            .iter()
            .find(|(_, r)| r.resize_seq == resize_seq)
        {
            return if owner == connection && previous.rows == rows && previous.cols == cols {
                Ok(previous.clone())
            } else {
                Err(Error::SequenceConflict)
            };
        }
        if resize_seq
            != core
                .resize_seq
                .checked_add(1)
                .ok_or(Error::ResourceExhausted)?
            || !current_fence()
        {
            return Err(Error::SequenceConflict);
        }
        // Validate dimensions before changing the real PTY; a throwaway model is
        // bounded and carries no user output or replies.
        TerminalState::new_with_epoch(rows.into(), cols.into(), core.history, epoch)
            .map_err(|_| Error::InvalidArgument)?;
        core.check_lease(connection, lease, Instant::now())?;
        if !current_fence() {
            return Err(Error::SequenceConflict);
        }
        core.resize_seq = resize_seq;
        #[cfg(any(unix, windows))]
        core.pty
            .resize(rows, cols)
            .map_err(|_| Error::OutcomeUnknown)?;
        core.model
            .resize(rows.into(), cols.into())
            .map_err(|_| Error::OutcomeUnknown)?;
        core.state_changed().map_err(|_| Error::OutcomeUnknown)?;
        let receipt = ResizeReceipt {
            resize_seq,
            rows,
            cols,
        };
        if core.resizes.len() == RECEIPT_LIMIT {
            core.resizes.pop_front();
        }
        core.resizes
            .push_back((connection.clone(), receipt.clone()));
        Ok(receipt)
    }
    /// Read-only cache freshness check; this never renews or acquires control.
    pub fn lease_is_current(
        &self,
        id: TerminalSessionId,
        epoch: SessionEpoch,
        connection: &AuthenticatedConnection,
        lease: &ControlLease,
    ) -> bool {
        self.session(id)
            .ok()
            .and_then(|session| {
                session.core.lock().ok().map(|core| {
                    core.check(epoch).is_ok()
                        && core.lease.as_ref().is_some_and(|current| {
                            current.expires > Instant::now()
                                && &current.connection == connection
                                && current.credential.token == lease.token
                                && current.credential.version == lease.version
                                && core
                                    .subscribers
                                    .get(&current.attachment)
                                    .is_some_and(|s| &s.connection == connection && s.ack.is_some())
                        })
                })
            })
            .unwrap_or(false)
    }
    pub fn disconnect(&self, connection: &AuthenticatedConnection) {
        if let Ok(sessions) = self.sessions.lock() {
            for session in sessions.values() {
                if let Ok(mut core) = session.core.lock() {
                    core.disconnect(connection);
                }
            }
        }
    }
    pub fn stats(&self, id: TerminalSessionId) -> Result<SessionStats> {
        Ok(self
            .session(id)?
            .core
            .lock()
            .map_err(|_| Error::StateFailed)?
            .stats
            .clone())
    }
    pub fn stop(&self, id: TerminalSessionId) -> Result<()> {
        self.stop_checked(id, || true)
    }
    /// Stop only the published session with this exact epoch. Registry absence
    /// is not cleanup proof: a caller recording durable removal must treat an
    /// error as unresolved instead of checkpointing a successful stop.
    pub fn stop_exact_checked(
        &self,
        id: TerminalSessionId,
        epoch: SessionEpoch,
        before_stop: impl FnOnce() -> bool,
    ) -> Result<()> {
        let session = self
            .sessions
            .lock()
            .map_err(|_| Error::StateFailed)?
            .get(&id)
            .cloned()
            .ok_or(Error::SessionMissing)?;
        {
            let core = session.core.lock().map_err(|_| Error::StateFailed)?;
            if core.epoch != epoch {
                return Err(Error::StaleEpoch);
            }
        }
        // Epoch is immutable for this Session Arc. The existing retirement
        // path checks that the same Arc still owns the map entry before it can
        // remove or stop it, so a replacement can never satisfy this proof.
        self.stop_session_checked(id, session, before_stop)
    }
    /// Recheck a trusted deadline/fence before requesting cleanup. Published
    /// sessions retain their final map-excluded check. A pending admission uses
    /// its publication gate without the map; cancellation is reported unknown
    /// because exec may already have happened. False has no stop effect.
    /// Callbacks must not reenter an operation gated on this same identity.
    pub fn stop_checked(
        &self,
        id: TerminalSessionId,
        before_stop: impl FnOnce() -> bool,
    ) -> Result<()> {
        let (session, pending) = {
            let sessions = self.sessions.lock().map_err(|_| Error::StateFailed)?;
            (
                sessions.get(&id).cloned(),
                sessions.pending.get(&id).cloned(),
            )
        };
        if let Some(session) = session {
            return self.stop_session_checked(id, session, before_stop);
        }
        let control = pending.ok_or(Error::SessionMissing)?;
        let gate = control.gate.lock().unwrap_or_else(|p| p.into_inner());
        let session = {
            let sessions = self.sessions.lock().map_err(|_| Error::StateFailed)?;
            if sessions
                .pending
                .get(&id)
                .is_some_and(|current| Arc::ptr_eq(current, &control))
            {
                None
            } else {
                // Publication may have won the gate. Capture that exact
                // generation; a later replacement must never be stopped.
                sessions
                    .get(&id)
                    .filter(|session| Arc::ptr_eq(&session.retirement_gate, &control.gate))
                    .cloned()
                    .ok_or(Error::SessionMissing)
                    .map(Some)?
            }
        };
        if let Some(session) = session {
            drop(gate);
            return self.stop_session_checked(id, session, before_stop);
        }
        // Gate excludes publication; this callback may acquire Store/domain
        // without owning the sessions map or any Core. Reject has no stop effect.
        if !before_stop() {
            return Err(Error::FenceRejected);
        }
        control.cancelled.store(true, Ordering::Release);
        // Exec may already have happened. Creator keeps the admission and actual
        // resource until cleanup; never report a successful synchronous stop.
        Err(Error::SpawnOutcomeUnknown)
    }
    fn stop_session_checked(
        &self,
        id: TerminalSessionId,
        session: Arc<Session>,
        before_stop: impl FnOnce() -> bool,
    ) -> Result<()> {
        #[cfg(test)]
        self.before_retirement_wait(RetirementWait::Stop, id);
        let gate = session
            .retirement_gate
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        {
            let mut sessions = self.sessions.lock().map_err(|_| Error::StateFailed)?;
            if !sessions
                .get(&id)
                .is_some_and(|current| Arc::ptr_eq(current, &session))
            {
                return Err(Error::SessionMissing);
            }
            if !before_stop() {
                return Err(Error::FenceRejected);
            }
            sessions.remove(&id);
        }
        drop(gate);
        session.stop()
    }
    /// Cancel pending admissions and clean the published-session snapshot.
    /// Pending creators own cleanup until they return/unwind; this is not a hard
    /// drain of concurrent spawn callers. Quiesce/join callers first when a
    /// synchronous drain is required. Admissions after the snapshot are allowed.
    pub fn shutdown(&self) -> Result<()> {
        // Cleanup must continue after map poisoning, including poisoning after
        // this snapshot. Recover only to find/remove exact captured identities;
        // preserve the error and never remove a replacement generation.
        let mut result = Ok(());
        let sessions: Vec<_> = {
            let sessions = match self.sessions.lock() {
                Ok(sessions) => sessions,
                Err(poisoned) => {
                    result = Err(Error::StateFailed);
                    poisoned.into_inner()
                }
            };
            // Snapshot semantics: cancel only admissions present now. Their
            // creators retain cleanup ownership and capacity until completion.
            // For a synchronous drain, quiesce/join callers first (as Host does).
            for control in sessions.pending.values() {
                control.cancelled.store(true, Ordering::Release);
            }
            sessions
                .iter()
                .map(|(id, session)| (*id, session.clone()))
                .collect()
        };
        for (id, session) in sessions {
            #[cfg(test)]
            self.before_retirement_wait(RetirementWait::Shutdown, id);
            let gate = session
                .retirement_gate
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            {
                let mut sessions = match self.sessions.lock() {
                    Ok(sessions) => sessions,
                    Err(poisoned) => {
                        result = Err(Error::StateFailed);
                        poisoned.into_inner()
                    }
                };
                if sessions
                    .get(&id)
                    .is_some_and(|current| Arc::ptr_eq(current, &session))
                {
                    sessions.remove(&id);
                }
            }
            drop(gate);
            // The captured Arc remains our cleanup responsibility even if a
            // concurrent remover already installed another generation.
            if let Err(e) = session.stop() {
                result = Err(e);
            }
        }
        result
    }
}
impl Drop for TerminalService {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}
#[cfg(unix)]
mod unix;

#[cfg(unix)]
mod supervisor;
/// Private same-executable entry point. Call before CLI parsing.
#[cfg(unix)]
pub fn internal_pty_worker() -> i32 {
    supervisor::run()
}
/// Private root-custodian entry for a per-PTY child. The descriptor must be an
/// inherited root-authenticated Unix control socket; the child independently
/// verifies the peer, credentials, and cohort before it can execute a profile.
#[doc(hidden)]
#[cfg(target_os = "macos")]
pub fn run_internal_privileged_pty_child(control_fd: i32) -> i32 {
    supervisor::macos_privileged::run_child(control_fd)
}

#[doc(hidden)]
#[cfg(target_os = "macos")]
pub fn run_internal_privileged_pty_broker(registration: &std::path::Path) -> i32 {
    supervisor::macos_privileged::run_broker(registration)
}

#[doc(hidden)]
#[cfg(target_os = "macos")]
pub fn run_internal_privileged_pty_controller(
    registration: &std::path::Path,
    generation: &std::path::Path,
) -> i32 {
    supervisor::macos_privileged::run_controller(registration, generation)
}

#[doc(hidden)]
#[cfg(target_os = "macos")]
pub fn run_internal_privileged_pty_admin(registration: &std::path::Path, drain: bool) -> i32 {
    supervisor::macos_privileged::run_admin(registration, drain)
}
/// Private launchd generation entry, never a user-selected shell command.
#[cfg(all(target_os = "macos", feature = "experimental-macos-coalition-cleanup"))]
pub fn internal_pty_coalition(directory: &std::path::Path) -> i32 {
    supervisor::macos_coalition::run(directory)
}
/// Private same-executable protocol child entry. Its only capability argument
/// is an inherited Unix socket descriptor established by the custodian.
#[cfg(all(target_os = "macos", feature = "experimental-macos-coalition-cleanup"))]
pub fn internal_pty_coalition_protocol(fd: i32) -> i32 {
    supervisor::macos_coalition::protocol_child(fd)
}

#[cfg(windows)]
mod windows;
#[cfg(unix)]
use unix as backend;
#[cfg(windows)]
use windows as backend;

/// Private teardown-only startup recovery for the experimental macOS backend.
/// Call before the first new spawn; an unknown generation is never replayed.
#[cfg(all(target_os = "macos", feature = "experimental-macos-coalition-cleanup"))]
pub fn internal_pty_coalition_recover(profile_dir: &std::path::Path) -> Result<()> {
    supervisor::macos_coalition::recover(profile_dir)
}

#[cfg(all(test, unix))]
mod retirement_lock_tests {
    use super::*;

    #[test]
    fn retirement_releases_map_and_core_before_cleanup_joins_worker() {
        let temp = tempfile::tempdir().unwrap();
        let service = Arc::new(TerminalService::new());
        let id = TerminalSessionId::from_bytes([41; 16]).unwrap();
        let epoch = SessionEpoch::from_bytes([42; 16]).unwrap();
        service
            .spawn(
                id,
                epoch,
                &SpawnProfile {
                    executable: "/bin/sh".into(),
                    args: vec!["-c".into(), "exit 0".into()],
                    cwd: temp.path().into(),
                    environment: vec![],
                    shell_integration: None,
                    rows: 8,
                    cols: 40,
                    history: 0,
                },
            )
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while service.exited_sessions().unwrap().is_empty() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(2));
        }
        let session = service.session(id).unwrap();
        // A stale unwinding guard must never cancel another reservation.
        let replacement_token = Uuid::from_bytes([11; 16]);
        session.core.lock().unwrap().retirement = Some(replacement_token);
        drop(RetirementReservation {
            session: &session,
            token: Uuid::from_bytes([12; 16]),
        });
        assert_eq!(
            session.core.lock().unwrap().retirement,
            Some(replacement_token)
        );
        session.core.lock().unwrap().retirement = None;
        if let Some(worker) = session.worker.lock().unwrap().take() {
            worker.join().unwrap();
        }
        let (start_tx, start_rx) = std::sync::mpsc::channel();
        let checking = service.clone();
        let core = session.core.clone();
        let worker = thread::spawn(move || {
            start_rx.recv().unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let removed = checking
                    .sessions
                    .try_lock()
                    .is_ok_and(|sessions| !sessions.contains_key(&id));
                if removed && core.try_lock().is_ok() {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "cleanup joined under map/Core exclusion"
                );
                thread::sleep(Duration::from_millis(1));
            }
        });
        *session.worker.lock().unwrap() = Some(worker);
        assert!(
            service
                .retire_exited(id, epoch, || {
                    assert!(service.sessions.try_lock().is_ok());
                    assert!(session.core.try_lock().is_ok());
                    start_tx.send(()).unwrap();
                    true
                })
                .unwrap()
        );
    }
}

#[cfg(all(test, unix))]
mod retirement_successor_tests {
    use super::*;
    use std::sync::{Barrier, mpsc};

    fn exited_session(
        service: &TerminalService,
        directory: &std::path::Path,
        id: TerminalSessionId,
        epoch: SessionEpoch,
    ) -> Arc<Session> {
        service
            .spawn(
                id,
                epoch,
                &SpawnProfile {
                    executable: "/bin/sh".into(),
                    args: vec!["-c".into(), "exit 0".into()],
                    cwd: directory.into(),
                    environment: vec![],
                    shell_integration: None,
                    rows: 8,
                    cols: 40,
                    history: 0,
                },
            )
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !service
            .exited_sessions()
            .unwrap()
            .iter()
            .any(|exit| exit.session_id == id)
        {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(2));
        }
        service.session(id).unwrap()
    }

    fn pause_after_capture(
        service: &TerminalService,
        selected: RetirementWait,
        selected_id: TerminalSessionId,
    ) -> (mpsc::Receiver<()>, Arc<Barrier>) {
        let (entered_tx, entered_rx) = mpsc::channel();
        let release = Arc::new(Barrier::new(2));
        let worker_release = release.clone();
        *service.retirement_wait_hook.lock().unwrap() = Some(Arc::new(move |kind, id| {
            if kind == selected && id == selected_id {
                entered_tx.send(()).unwrap();
                worker_release.wait();
            }
        }));
        (entered_rx, release)
    }

    #[test]
    fn stale_retire_stop_and_shutdown_waiters_preserve_same_id_replacement() {
        for kind in [
            RetirementWait::Retire,
            RetirementWait::Stop,
            RetirementWait::Shutdown,
        ] {
            let temp = tempfile::tempdir().unwrap();
            let service = Arc::new(TerminalService::new());
            let id = TerminalSessionId::from_bytes([61; 16]).unwrap();
            let epoch = SessionEpoch::from_bytes([62; 16]).unwrap();
            let old = exited_session(&service, temp.path(), id, epoch);
            let (entered, release) = pause_after_capture(&service, kind, id);
            let effect = Arc::new(AtomicBool::new(false));
            let worker_effect = effect.clone();
            let waiting = service.clone();
            let waiter = thread::spawn(move || match kind {
                RetirementWait::Retire => assert!(
                    !waiting
                        .retire_exited(id, epoch, || {
                            worker_effect.store(true, Ordering::Release);
                            true
                        })
                        .unwrap()
                ),
                RetirementWait::Stop => assert!(matches!(
                    waiting.stop_checked(id, || {
                        worker_effect.store(true, Ordering::Release);
                        true
                    }),
                    Err(Error::SessionMissing)
                )),
                RetirementWait::Shutdown => waiting.shutdown().unwrap(),
                RetirementWait::Attach => unreachable!(),
            });
            // This signal occurs after cloning OLD, before waiting on its gate.
            entered.recv_timeout(Duration::from_secs(2)).unwrap();
            let removed = service.sessions.lock().unwrap().remove(&id).unwrap();
            assert!(Arc::ptr_eq(&removed, &old));
            let replacement_epoch = SessionEpoch::from_bytes([63; 16]).unwrap();
            let replacement = exited_session(&service, temp.path(), id, replacement_epoch);
            release.wait();
            waiter.join().unwrap();
            *service.retirement_wait_hook.lock().unwrap() = None;
            assert!(
                !effect.load(Ordering::Acquire),
                "stale waiter reached persistence/stop gate"
            );
            let current = service.session(id).unwrap();
            assert!(Arc::ptr_eq(&current, &replacement));
            assert!(!replacement.stopping.load(Ordering::Acquire));
            assert!(!replacement.core.lock().unwrap().retired);
            assert!(service.snapshot(id, replacement_epoch).is_ok());
            if kind == RetirementWait::Shutdown {
                assert!(old.stopping.load(Ordering::Acquire));
                assert!(old.worker.lock().unwrap().is_none());
            }
            old.stop().unwrap();
            service.shutdown().unwrap();
        }
    }

    #[test]
    fn queued_old_attachment_is_rejected_after_successful_retirement() {
        let temp = tempfile::tempdir().unwrap();
        let service = Arc::new(TerminalService::new());
        let id = TerminalSessionId::from_bytes([64; 16]).unwrap();
        let epoch = SessionEpoch::from_bytes([65; 16]).unwrap();
        let _old = exited_session(&service, temp.path(), id, epoch);
        let (entered, release) = pause_after_capture(&service, RetirementWait::Attach, id);
        let attaching = service.clone();
        let waiter = thread::spawn(move || {
            let connection = AuthenticatedConnection::new(
                ConsumerAuthorizationId::from_bytes([66; 16]).unwrap(),
            );
            assert!(matches!(
                attaching.attach(id, epoch, &connection),
                Err(Error::SessionMissing)
            ));
        });
        entered.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(service.retire_exited(id, epoch, || true).unwrap());
        release.wait();
        waiter.join().unwrap();
        *service.retirement_wait_hook.lock().unwrap() = None;
        assert!(service.sessions.lock().unwrap().is_empty());
    }

    #[test]
    fn shutdown_after_snapshot_map_poison_cleans_every_capture_and_preserves_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let service = Arc::new(TerminalService::new());
        let id1 = TerminalSessionId::from_bytes([67; 16]).unwrap();
        let id2 = TerminalSessionId::from_bytes([68; 16]).unwrap();
        let epoch = SessionEpoch::from_bytes([69; 16]).unwrap();
        let old1 = exited_session(&service, temp.path(), id1, epoch);
        let old2 = exited_session(&service, temp.path(), id2, epoch);
        let (entered_tx, entered_rx) = mpsc::channel();
        let release = Arc::new(Barrier::new(2));
        let worker_release = release.clone();
        let once = AtomicBool::new(false);
        *service.retirement_wait_hook.lock().unwrap() = Some(Arc::new(move |kind, _| {
            if kind == RetirementWait::Shutdown && !once.swap(true, Ordering::AcqRel) {
                entered_tx.send(()).unwrap();
                worker_release.wait();
            }
        }));
        let shutting_down = service.clone();
        let waiter = thread::spawn(move || shutting_down.shutdown());
        // The first hook runs after the entire snapshot, before any cleanup.
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        service.sessions.lock().unwrap().remove(&id1);
        let replacement_epoch = SessionEpoch::from_bytes([70; 16]).unwrap();
        let replacement = exited_session(&service, temp.path(), id1, replacement_epoch);
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _map = service.sessions.lock().unwrap();
            panic!("synthetic map poison after shutdown snapshot");
        }));
        assert!(poisoned.is_err());
        release.wait();
        assert!(matches!(waiter.join().unwrap(), Err(Error::StateFailed)));
        *service.retirement_wait_hook.lock().unwrap() = None;
        // Each captured session was cleaned, including the replaced old Arc.
        for old in [&old1, &old2] {
            assert!(old.stopping.load(Ordering::Acquire));
            assert!(old.worker.lock().unwrap().is_none());
        }
        assert!(!replacement.stopping.load(Ordering::Acquire));
        {
            let map = service.sessions.lock().unwrap_or_else(|p| p.into_inner());
            assert_eq!(map.len(), 1);
            assert!(Arc::ptr_eq(map.get(&id1).unwrap(), &replacement));
            assert!(!map.contains_key(&id2));
        }
        // The error remains truthful while later cleanup still proceeds.
        assert!(matches!(service.shutdown(), Err(Error::StateFailed)));
        assert!(replacement.stopping.load(Ordering::Acquire));
    }
}

/// Test controller support; never enabled by a production default.
#[cfg(all(unix, feature = "owned-host-fixture"))]
pub use supervisor::owned_fixture::controller_main as owned_host_fixture_main;

/// Dedicated fixture helper; unavailable without the owned test feature.
#[cfg(all(unix, feature = "owned-host-fixture"))]
pub fn owned_host_fixture_shell_probe(
    database: &std::path::Path,
    expected: &std::path::Path,
    shell: &std::path::Path,
) -> std::io::Result<std::process::Output> {
    supervisor::owned_fixture::probe::shell_probe(database, expected, shell)
}
#[cfg(all(unix, feature = "owned-host-fixture"))]
pub fn owned_host_fixture_probe_running_barrier() -> std::io::Result<()> {
    supervisor::owned_fixture::probe::running_barrier()
}

// Source-authored pure admission tests: no PTY, command, socket, or backend.
#[cfg(all(test, any(unix, windows)))]
mod spawn_reservation_tests {
    use super::*;
    use std::sync::{Barrier, atomic::AtomicUsize};

    fn identity(value: u8) -> TerminalSessionId {
        TerminalSessionId::from_bytes([value; 16]).unwrap()
    }
    fn epoch() -> SessionEpoch {
        SessionEpoch::from_bytes([211; 16]).unwrap()
    }
    fn profile() -> SpawnProfile {
        SpawnProfile {
            executable: PathBuf::from("/pure-admission-unused"),
            args: Vec::new(),
            cwd: PathBuf::from("/"),
            environment: Vec::new(),
            shell_integration: None,
            rows: 8,
            cols: 40,
            history: 0,
        }
    }

    #[test]
    fn concurrent_same_id_reserves_exactly_one_slot() {
        let service = TerminalService::new();
        let admitted = AtomicUsize::new(0);
        let barrier = Barrier::new(5);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let service = &service;
                let admitted = &admitted;
                let barrier = &barrier;
                scope.spawn(move || {
                    let preparation = service.prepare_spawn(identity(212), epoch(), &profile());
                    let expected = match &preparation {
                        Ok(_) => {
                            admitted.fetch_add(1, Ordering::AcqRel);
                            true
                        }
                        Err(error) => *error == Error::SessionExists,
                    };
                    barrier.wait();
                    barrier.wait();
                    assert!(expected, "unexpected admission failure");
                    drop(preparation);
                });
            }
            barrier.wait();
            let count = admitted.load(Ordering::Acquire);
            let occupied = service.sessions.lock().unwrap().occupied();
            barrier.wait();
            assert_eq!(count, 1);
            assert_eq!(occupied, 1);
        });
        assert_eq!(service.sessions.lock().unwrap().occupied(), 0);
    }

    #[test]
    fn concurrent_distinct_admissions_cannot_overbook_capacity() {
        let service = TerminalService::new();
        let admitted = AtomicUsize::new(0);
        let barrier = Barrier::new(MAX_SESSIONS + 2);
        std::thread::scope(|scope| {
            for value in 1..=MAX_SESSIONS + 1 {
                let service = &service;
                let admitted = &admitted;
                let barrier = &barrier;
                scope.spawn(move || {
                    let preparation =
                        service.prepare_spawn(identity(value as u8), epoch(), &profile());
                    let expected = match &preparation {
                        Ok(_) => {
                            admitted.fetch_add(1, Ordering::AcqRel);
                            true
                        }
                        Err(error) => *error == Error::ResourceExhausted,
                    };
                    barrier.wait();
                    barrier.wait();
                    assert!(expected, "unexpected admission failure");
                    drop(preparation);
                });
            }
            barrier.wait();
            let count = admitted.load(Ordering::Acquire);
            let at_capacity = service.at_capacity().unwrap();
            barrier.wait();
            assert_eq!(count, MAX_SESSIONS);
            assert!(at_capacity);
        });
        assert!(!service.at_capacity().unwrap());
    }

    #[test]
    fn preparation_captures_profile_and_unwind_releases_admission() {
        let service = TerminalService::new();
        let mut trusted = profile();
        let preparation = service
            .prepare_spawn(identity(213), epoch(), &trusted)
            .unwrap();
        trusted.args.push("changed-after-admission".into());
        assert!(preparation.profile.args.is_empty());
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _owned = preparation;
            panic!("synthetic creator unwind before backend acquisition");
        }));
        assert!(panic.is_err());
        assert!(
            service
                .prepare_spawn(identity(213), epoch(), &profile())
                .is_ok()
        );
    }

    #[test]
    fn unwinding_guard_recovers_map_poison_and_releases_only_its_slot() {
        let service = TerminalService::new();
        let preparation = service
            .prepare_spawn(identity(214), epoch(), &profile())
            .unwrap();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _map = service.sessions.lock().unwrap();
            panic!("synthetic registry poison");
        }));
        assert!(panic.is_err());
        drop(preparation);
        assert!(
            service
                .sessions
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .pending
                .is_empty()
        );
    }

    #[test]
    fn pending_stop_checks_without_map_and_preserves_unknown_cleanup_ownership() {
        let service = TerminalService::new();
        let preparation = service
            .prepare_spawn(identity(215), epoch(), &profile())
            .unwrap();
        let stopped = service.stop_checked(identity(215), || {
            assert!(service.sessions.try_lock().is_ok());
            true
        });
        assert_eq!(stopped, Err(Error::SpawnOutcomeUnknown));
        assert!(preparation.control.cancelled.load(Ordering::Acquire));
        let sessions = service.sessions.lock().unwrap();
        assert_eq!(sessions.occupied(), 1);
        assert!(!sessions.accepts_spawn(identity(215), &preparation.control));
        drop(sessions);
        assert!(matches!(
            service.prepare_spawn(identity(215), epoch(), &profile()),
            Err(Error::SessionExists)
        ));
        drop(preparation);
        assert!(
            service
                .prepare_spawn(identity(215), epoch(), &profile())
                .is_ok()
        );
    }

    #[test]
    fn pending_stop_rejection_and_callback_panic_do_not_cancel_or_poison_map() {
        let service = TerminalService::new();
        let preparation = service
            .prepare_spawn(identity(216), epoch(), &profile())
            .unwrap();
        assert_eq!(
            service.stop_checked(identity(216), || false),
            Err(Error::FenceRejected)
        );
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = service.stop_checked(identity(216), || {
                assert!(service.sessions.try_lock().is_ok());
                panic!("synthetic trusted gate unwind");
            });
        }));
        assert!(panic.is_err());
        assert!(
            service
                .sessions
                .lock()
                .unwrap()
                .accepts_spawn(identity(216), &preparation.control)
        );
        // Gate poison contains no protected data; the next exact stop recovers.
        assert_eq!(service.stop(identity(216)), Err(Error::SpawnOutcomeUnknown));
    }

    #[test]
    fn shutdown_invalidates_snapshot_but_allows_later_admissions() {
        let service = TerminalService::new();
        let old = service
            .prepare_spawn(identity(217), epoch(), &profile())
            .unwrap();
        service.shutdown().unwrap();
        let replacement = service
            .prepare_spawn(identity(218), epoch(), &profile())
            .unwrap();
        let sessions = service.sessions.lock().unwrap();
        assert!(!sessions.accepts_spawn(identity(217), &old.control));
        assert!(sessions.accepts_spawn(identity(218), &replacement.control));
        assert_eq!(sessions.occupied(), 2);
        drop(sessions);
        drop(old);
        let same_id = service
            .prepare_spawn(identity(217), epoch(), &profile())
            .unwrap();
        assert!(
            service
                .sessions
                .lock()
                .unwrap()
                .accepts_spawn(identity(217), &same_id.control)
        );
    }

    #[test]
    fn concurrent_shutdown_leaves_cleanup_with_creator_and_preserves_later_slot() {
        let service = Arc::new(TerminalService::new());
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (complete_tx, complete_rx) = std::sync::mpsc::channel();
        let creating = service.clone();
        let creator = std::thread::spawn(move || {
            let preparation = creating
                .prepare_spawn(identity(220), epoch(), &profile())
                .unwrap();
            ready_tx.send(()).unwrap();
            complete_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(
                !creating
                    .sessions
                    .lock()
                    .unwrap()
                    .accepts_spawn(identity(220), &preparation.control)
            );
            drop(preparation);
        });
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        service.shutdown().unwrap();
        // Cancellation has not released a creator-owned slot prematurely.
        assert!(matches!(
            service.prepare_spawn(identity(220), epoch(), &profile()),
            Err(Error::SessionExists)
        ));
        let later = service
            .prepare_spawn(identity(221), epoch(), &profile())
            .unwrap();
        complete_tx.send(()).unwrap();
        creator.join().unwrap();
        assert!(
            service
                .sessions
                .lock()
                .unwrap()
                .accepts_spawn(identity(221), &later.control)
        );
        assert!(
            service
                .prepare_spawn(identity(220), epoch(), &profile())
                .is_ok()
        );
    }

    #[test]
    fn stale_completion_and_drop_cannot_publish_or_erase_new_admission() {
        let service = TerminalService::new();
        let old = service
            .prepare_spawn(identity(219), epoch(), &profile())
            .unwrap();
        // Synthetic stale completion: only production ownership code may remove
        // a pending entry, but even corrupted/stale bookkeeping fails closed.
        service
            .sessions
            .lock()
            .unwrap()
            .pending
            .remove(&identity(219));
        let new = service
            .prepare_spawn(identity(219), epoch(), &profile())
            .unwrap();
        let sessions = service.sessions.lock().unwrap();
        assert!(!sessions.accepts_spawn(identity(219), &old.control));
        assert!(sessions.accepts_spawn(identity(219), &new.control));
        drop(sessions);
        drop(old);
        assert!(
            service
                .sessions
                .lock()
                .unwrap()
                .accepts_spawn(identity(219), &new.control)
        );
    }
}

// Pure lock/gate regressions: inert backend, no PTY, worker, process or socket.
#[cfg(all(test, unix))]
mod checked_gate_tests {
    use super::*;
    use std::sync::{Barrier, atomic::AtomicUsize};

    fn fixture() -> (
        Arc<TerminalService>,
        Arc<Session>,
        TerminalSessionId,
        SessionEpoch,
        AuthenticatedConnection,
    ) {
        let id = TerminalSessionId::from_bytes([221; 16]).unwrap();
        let epoch = SessionEpoch::from_bytes([222; 16]).unwrap();
        let model = TerminalState::new_with_epoch(8, 40, 0, epoch).unwrap();
        let last = model.snapshot().unwrap();
        let core = Arc::new(Mutex::new(Core {
            epoch,
            model,
            last,
            subscribers: HashMap::new(),
            lease: None,
            lease_version: 0,
            input_seq: 0,
            input_id: 0,
            history: 0,
            resize_seq: 0,
            inputs: VecDeque::new(),
            resizes: VecDeque::new(),
            exited: false,
            closing: false,
            exited_at: None,
            retired: false,
            retirement: None,
            stats: SessionStats::default(),
            pty: unix::Pty::inert_for_test(),
        }));
        let session = Arc::new(Session {
            core,
            stopping: Arc::new(AtomicBool::new(false)),
            worker: Mutex::new(None),
            retirement_gate: Arc::new(Mutex::new(())),
        });
        let service = Arc::new(TerminalService::new());
        service.sessions.lock().unwrap().insert(id, session.clone());
        let connection =
            AuthenticatedConnection::new(ConsumerAuthorizationId::from_bytes([223; 16]).unwrap());
        (service, session, id, epoch, connection)
    }

    #[derive(PartialEq)]
    struct State {
        screen: Vec<u8>,
        model: Vec<u8>,
        counters: (u64, u64, u64, u64),
        lease: Option<(ControlLease, Instant)>,
        subscribers: Vec<(Uuid, Option<u64>, String)>,
    }
    fn state(core: &Core) -> State {
        let mut subscribers: Vec<_> = core
            .subscribers
            .iter()
            .map(|(id, sub)| {
                let queue = sub.queue.lock().unwrap();
                (
                    *id,
                    sub.ack,
                    format!(
                        "{:?}/{}/{}/{}",
                        queue.events, queue.bytes, queue.overflow, queue.notified
                    ),
                )
            })
            .collect();
        subscribers.sort_by_key(|(id, _, _)| *id);
        State {
            screen: serde_json::to_vec(&core.last).unwrap(),
            model: serde_json::to_vec(&core.model.snapshot().unwrap()).unwrap(),
            counters: (
                core.lease_version,
                core.input_seq,
                core.input_id,
                core.resize_seq,
            ),
            lease: core
                .lease
                .as_ref()
                .map(|lease| (lease.credential.clone(), lease.expires)),
            subscribers,
        }
    }

    #[test]
    fn attach_gate_holds_retirement_and_core_and_denial_preserves_exited_screen() {
        let (service, session, id, epoch, connection) = fixture();
        session.core.lock().unwrap().exited = true;
        let before = state(&session.core.lock().unwrap());
        let allowed = AtomicBool::new(true);
        let calls = AtomicUsize::new(0);
        let entered = Barrier::new(2);
        let mut gate = || {
            // Test-only nonblocking lock diagnostics; production predicates must
            // never acquire or reenter terminal locks.
            assert!(matches!(
                session.core.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
            assert!(matches!(
                session.retirement_gate.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
            calls.fetch_add(1, Ordering::AcqRel);
            allowed.load(Ordering::Acquire)
        };
        let retirement = session.retirement_gate.lock().unwrap();
        let denied = std::thread::scope(|scope| {
            let waiter = scope.spawn(|| {
                entered.wait();
                service.attach_checked(id, epoch, &connection, &mut gate)
            });
            entered.wait();
            // The barrier starts the call while retirement is held; it does not
            // prove that the waiter has reached the mutex acquisition.
            allowed.store(false, Ordering::Release);
            drop(retirement);
            waiter.join().unwrap()
        });
        assert!(matches!(denied, Err(Error::FenceRejected)));
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert!(
            state(&session.core.lock().unwrap()) == before,
            "denied gate changed protected terminal state"
        );
        allowed.store(true, Ordering::Release);
        let attachment = service
            .attach_checked(id, epoch, &connection, &mut gate)
            .unwrap();
        assert_eq!(calls.load(Ordering::Acquire), 2);
        assert_eq!(
            attachment.snapshot.sequence.0 + 1,
            session
                .core
                .lock()
                .unwrap()
                .model
                .snapshot()
                .unwrap()
                .sequence
                .0
        );
        assert!(matches!(
            attachment.try_next().as_deref(),
            Some(TerminalEvent::Exited { .. })
        ));
        assert_eq!(session.core.lock().unwrap().subscribers.len(), 1);
    }

    #[derive(Clone, Copy)]
    enum Method {
        Acknowledge,
        Claim,
        Renew,
        Release,
    }
    fn apply(
        method: Method,
        service: &TerminalService,
        identity: (TerminalSessionId, SessionEpoch),
        connection: &AuthenticatedConnection,
        attachment: &Attachment,
        lease: &ControlLease,
        gate: &mut impl FnMut() -> bool,
    ) -> Result<()> {
        let (id, epoch) = identity;
        match method {
            Method::Acknowledge => {
                attachment.acknowledge_checked(connection, attachment.snapshot.sequence.0, gate)
            }
            Method::Claim => service
                .claim_checked(id, epoch, connection, gate)
                .map(|_| ()),
            Method::Renew => service
                .renew_checked(id, epoch, connection, lease, gate)
                .map(|_| ()),
            Method::Release => service.release_checked(id, epoch, connection, lease, gate),
        }
    }

    #[test]
    fn ack_and_lease_gates_hold_core_preserve_denied_state_and_can_retry() {
        for method in [
            Method::Acknowledge,
            Method::Claim,
            Method::Renew,
            Method::Release,
        ] {
            let (service, session, id, epoch, connection) = fixture();
            let attachment = service.attach(id, epoch, &connection).unwrap();
            attachment
                .acknowledge(&connection, attachment.snapshot.sequence.0)
                .unwrap();
            let lease = service.claim(id, epoch, &connection).unwrap();
            {
                let mut core = session.core.lock().unwrap();
                if matches!(method, Method::Claim) {
                    // Gate denial must precede claim's expiry-driven revoke.
                    core.lease.as_mut().unwrap().expires = Instant::now() - Duration::from_secs(1);
                }
                if matches!(method, Method::Acknowledge) {
                    core.subscribers.get_mut(&attachment.id).unwrap().ack = None;
                }
            }
            let before = state(&session.core.lock().unwrap());
            let allowed = AtomicBool::new(true);
            let calls = AtomicUsize::new(0);
            let entered = Barrier::new(2);
            let mut gate = || {
                // Successful retry has no competing holder: WouldBlock proves
                // that this method itself holds Core while invoking its gate.
                assert!(matches!(
                    session.core.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                ));
                calls.fetch_add(1, Ordering::AcqRel);
                allowed.load(Ordering::Acquire)
            };
            let core = session.core.lock().unwrap();
            let denied = std::thread::scope(|scope| {
                let waiter = scope.spawn(|| {
                    entered.wait();
                    apply(
                        method,
                        &service,
                        (id, epoch),
                        &connection,
                        &attachment,
                        &lease,
                        &mut gate,
                    )
                });
                entered.wait();
                // Core remains held when the owner revokes this operation's gate.
                // This start barrier does not prove the waiter has reached lock().
                allowed.store(false, Ordering::Release);
                drop(core);
                waiter.join().unwrap()
            });
            assert_eq!(denied, Err(Error::FenceRejected));
            assert_eq!(calls.load(Ordering::Acquire), 1);
            assert!(
                state(&session.core.lock().unwrap()) == before,
                "denied gate changed protected terminal state"
            );
            allowed.store(true, Ordering::Release);
            apply(
                method,
                &service,
                (id, epoch),
                &connection,
                &attachment,
                &lease,
                &mut gate,
            )
            .unwrap();
            assert_eq!(calls.load(Ordering::Acquire), 2);
            let core = session.core.lock().unwrap();
            match method {
                Method::Acknowledge => assert_eq!(
                    core.subscribers[&attachment.id].ack,
                    Some(attachment.snapshot.sequence.0)
                ),
                Method::Claim => {
                    assert!(core.lease.as_ref().unwrap().credential.version > lease.version)
                }
                Method::Renew => {
                    assert!(core.lease.as_ref().unwrap().expires > before.lease.unwrap().1)
                }
                Method::Release => assert!(core.lease.is_none()),
            }
        }
    }

    #[test]
    fn denied_expired_renew_and_release_do_not_revoke_or_publish_control_changes() {
        for method in [Method::Renew, Method::Release] {
            let (service, session, id, epoch, connection) = fixture();
            let attachment = service.attach(id, epoch, &connection).unwrap();
            attachment
                .acknowledge(&connection, attachment.snapshot.sequence.0)
                .unwrap();
            let lease = service.claim(id, epoch, &connection).unwrap();
            session.core.lock().unwrap().lease.as_mut().unwrap().expires =
                Instant::now() - Duration::from_secs(1);
            let before = state(&session.core.lock().unwrap());
            assert_eq!(
                apply(
                    method,
                    &service,
                    (id, epoch),
                    &connection,
                    &attachment,
                    &lease,
                    &mut || false
                ),
                Err(Error::FenceRejected)
            );
            assert!(
                state(&session.core.lock().unwrap()) == before,
                "denied gate changed protected terminal state"
            );
        }
    }
}
