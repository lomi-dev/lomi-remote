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

    #[cfg(unix)]
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

// Source-authored pure admission tests: no PTY, command, socket, or backend.

// Pure lock/gate regressions: inert backend, no PTY, worker, process or socket.
