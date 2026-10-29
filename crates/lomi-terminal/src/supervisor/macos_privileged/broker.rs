//! Root-owned rendezvous and bounded runtime for per-PTY controllers.
//!
//! The broker accepts only the registered Host image and the registered root
//! controller image. User profiles remain in memory and are forwarded over the
//! authenticated per-generation socket; durable records contain lifecycle
//! pins only.

use super::{Error, capability, journal, manager, wire};
use lomi_platform::{
    process,
    service_macos::custody::{self, PrivilegedCustodianRegistration},
    unix,
};
use serde_json::{Map, Value};
use std::{
    collections::HashMap,
    ffi::{CString, OsStr},
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd},
        unix::{
            ffi::OsStrExt,
            fs::MetadataExt,
            net::{UnixListener, UnixStream},
        },
    },
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use uuid::Uuid;

const BROKER_LOCK: &str = "broker.lock";
const SOCKET_LEAF: &str = "broker.sock";
const SOCKET_DIRECTORY_MODE: u32 = 0o711;
const STATE_DIRECTORY_MODE: u32 = 0o700;
const SOCKET_MODE: u32 = 0o600;
const MAX_GENERATIONS: usize = 64;
const MAX_CONNECTION_WORKERS: usize = 128;
const MAX_REQUEST_WINDOW_NS: u64 = 10_000_000_000;
const HANDSHAKE_WINDOW: Duration = Duration::from_secs(3);
const CONTROLLER_HELLO_WINDOW: Duration = Duration::from_secs(10);
const CONTROLLER_WAIT_INTERVAL: Duration = Duration::from_millis(100);
const CLEANUP_WINDOW: Duration = Duration::from_secs(5);
const ADMIN_DRAIN_WINDOW: Duration = Duration::from_secs(55);
const STARTUP_RECOVERY_RETRY: Duration = Duration::from_millis(100);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const ADMIN_READY_ERROR: &str = "NOT_READY";

type Result<T> = std::result::Result<T, Error>;

static SIGNAL_SHUTDOWN: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn signal_shutdown(_: libc::c_int) {
    SIGNAL_SHUTDOWN.store(true, Ordering::Relaxed);
}

pub(crate) fn run_broker(registration_path: &Path) -> i32 {
    match run_broker_inner(registration_path) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn run_broker_inner(registration_path: &Path) -> Result<()> {
    if unsafe { libc::getuid() } != 0
        || unsafe { libc::geteuid() } != 0
        || unsafe { libc::getgid() } != 0
        || unsafe { libc::getegid() } != 0
    {
        return Err(Error::CleanupFailed);
    }
    process::require_child_ownership().map_err(|_| Error::CleanupFailed)?;
    let registration = Arc::new(
        custody::load_privileged_custodian(registration_path).map_err(|_| Error::CleanupFailed)?,
    );
    let current_exe = std::env::current_exe().map_err(|_| Error::CleanupFailed)?;
    if current_exe != registration.executable_path() {
        return Err(Error::CleanupFailed);
    }

    let instance_lock = BrokerLock::acquire(&registration)?;
    journal::recover_auxiliary_storage(&registration)?;
    let endpoint = SocketEndpoint::bind(&registration)?;
    install_signal_handlers()?;

    let runtime = Arc::new(BrokerRuntime::new(registration, instance_lock));
    let recovery_runtime = Arc::clone(&runtime);
    let recovery = thread::Builder::new()
        .name("lomi-pty-broker-recovery".to_owned())
        .spawn(move || {
            let ready = recover_startup(&recovery_runtime);
            recovery_runtime.finish_recovery(ready);
        })
        .map_err(|_| Error::ResourceExhausted)?;
    runtime.store_worker(recovery);

    let result = accept_loop(&runtime, &endpoint);
    runtime.close_and_cancel();
    let shutdown_deadline = deadline_after(ADMIN_DRAIN_WINDOW)?;
    let recovery_finished = wait_recovery(&runtime, shutdown_deadline);
    let sessions_finished = runtime.wait_for_sessions(shutdown_deadline);
    let workers_finished = runtime.wait_for_workers(shutdown_deadline);
    runtime.join_finished_workers();
    drop(endpoint);
    if SIGNAL_SHUTDOWN.load(Ordering::Acquire)
        || !recovery_finished
        || !sessions_finished
        || !workers_finished
    {
        return Err(Error::CleanupFailed);
    }
    result
}

fn install_signal_handlers() -> Result<()> {
    SIGNAL_SHUTDOWN.store(false, Ordering::Relaxed);
    for signal in [libc::SIGTERM, libc::SIGINT] {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = signal_shutdown as *const () as usize;
        action.sa_flags = 0;
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0 {
            return Err(Error::CleanupFailed);
        }
    }
    Ok(())
}

struct BrokerRuntime {
    // Every worker retains this same Arc, so an offline maintainer cannot
    // acquire the kernel lease while any worker can still publish a record.
    _instance_lock: BrokerLock,
    registration: Arc<PrivilegedCustodianRegistration>,
    runtime_id: String,
    state: Mutex<RuntimeState>,
    changed: Condvar,
    stopping: AtomicBool,
    worker_count: AtomicUsize,
    workers: Mutex<Vec<JoinHandle<()>>>,
}

struct RuntimeState {
    recovery_complete: bool,
    ready: bool,
    admission_open: bool,
    draining: bool,
    drain_running: bool,
    reservations: HashMap<String, Arc<SessionControl>>,
    generations: HashMap<String, Arc<SessionControl>>,
    pending: HashMap<String, PendingController>,
}

struct SessionControl {
    cancelled: AtomicBool,
    host: Mutex<Option<UnixStream>>,
    controller: Mutex<Option<UnixStream>>,
    commit_gate: Mutex<()>,
}

impl SessionControl {
    fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            host: Mutex::new(None),
            controller: Mutex::new(None),
            commit_gate: Mutex::new(()),
        }
    }

    fn set_host(&self, stream: &UnixStream) -> Result<()> {
        let _gate = self.commit_gate.lock().map_err(|_| Error::CleanupFailed)?;
        if self.is_cancelled() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return Err(Error::SpawnFailed);
        }
        *self.host.lock().map_err(|_| Error::CleanupFailed)? =
            Some(stream.try_clone().map_err(|_| Error::SpawnFailed)?);
        Ok(())
    }

    fn cancel(&self) {
        let _gate = self.commit_gate.lock().ok();
        self.cancelled.store(true, Ordering::Release);
        if let Ok(host) = self.host.lock()
            && let Some(host) = host.as_ref()
        {
            let _ = host.shutdown(std::net::Shutdown::Both);
        }
        if let Ok(controller) = self.controller.lock()
            && let Some(controller) = controller.as_ref()
        {
            let _ = controller.shutdown(std::net::Shutdown::Write);
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn set_controller(&self, stream: &UnixStream) -> Result<()> {
        let _gate = self.commit_gate.lock().map_err(|_| Error::CleanupFailed)?;
        if self.is_cancelled() {
            let _ = stream.shutdown(std::net::Shutdown::Write);
            return Err(Error::SpawnFailed);
        }
        *self.controller.lock().map_err(|_| Error::CleanupFailed)? =
            Some(stream.try_clone().map_err(|_| Error::SpawnFailed)?);
        Ok(())
    }

    fn try_commit(&self, stream: &UnixStream, deadline_ns: u64) -> Result<Option<bool>> {
        let _gate = self.commit_gate.lock().map_err(|_| Error::CleanupFailed)?;
        if self.is_cancelled() || wire::mach_now_ns().map_or(true, |now| now >= deadline_ns) {
            return Ok(None);
        }
        wire::try_send_byte_once(stream, b'E').map(Some)
    }
}

struct PendingController {
    deadline_ns: u64,
    sender: SyncSender<ControllerConnection>,
}

struct ControllerConnection {
    stream: UnixStream,
    hello: wire::ControllerHello,
}

impl BrokerRuntime {
    fn new(registration: Arc<PrivilegedCustodianRegistration>, instance_lock: BrokerLock) -> Self {
        Self {
            _instance_lock: instance_lock,
            registration,
            runtime_id: Uuid::new_v4().to_string(),
            state: Mutex::new(RuntimeState {
                recovery_complete: false,
                ready: false,
                admission_open: false,
                draining: false,
                drain_running: false,
                reservations: HashMap::new(),
                generations: HashMap::new(),
                pending: HashMap::new(),
            }),
            changed: Condvar::new(),
            stopping: AtomicBool::new(false),
            worker_count: AtomicUsize::new(0),
            workers: Mutex::new(Vec::new()),
        }
    }

    fn finish_recovery(&self, ready: bool) {
        if let Ok(mut state) = self.state.lock() {
            state.recovery_complete = true;
            state.ready = ready;
            state.admission_open =
                ready && !state.draining && !self.stopping.load(Ordering::Acquire);
            self.changed.notify_all();
        }
    }

    fn store_worker(&self, worker: JoinHandle<()>) {
        if let Ok(mut workers) = self.workers.lock() {
            workers.push(worker);
        }
    }

    fn join_finished_workers(&self) {
        let finished = {
            let Ok(mut workers) = self.workers.lock() else {
                return;
            };
            let mut finished = Vec::new();
            let mut index = 0;
            while index < workers.len() {
                if workers[index].is_finished() {
                    finished.push(workers.swap_remove(index));
                } else {
                    index += 1;
                }
            }
            finished
        };
        for worker in finished {
            let _ = worker.join();
        }
    }

    fn reserve(&self, request_id: &str) -> Result<Arc<SessionControl>> {
        let control = Arc::new(SessionControl::new());
        let mut state = self.state.lock().map_err(|_| Error::CleanupFailed)?;
        if !state.recovery_complete || !state.ready || !state.admission_open || state.draining {
            return Err(Error::ResourceExhausted);
        }
        if state.reservations.len() + state.generations.len() >= MAX_GENERATIONS
            || state.reservations.contains_key(request_id)
        {
            return Err(Error::ResourceExhausted);
        }
        state
            .reservations
            .insert(request_id.to_owned(), Arc::clone(&control));
        Ok(control)
    }

    fn activate_generation(
        &self,
        request_id: &str,
        nonce: &str,
        control: &Arc<SessionControl>,
        deadline_ns: u64,
        sender: SyncSender<ControllerConnection>,
    ) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| Error::CleanupFailed)?;
        if state.reservations.remove(request_id).is_none() || state.generations.contains_key(nonce)
        {
            return Err(Error::CleanupFailed);
        }
        state
            .generations
            .insert(nonce.to_owned(), Arc::clone(control));
        state.pending.insert(
            nonce.to_owned(),
            PendingController {
                deadline_ns,
                sender,
            },
        );
        self.changed.notify_all();
        Ok(())
    }

    fn finish_generation(&self, request_id: &str, nonce: Option<&str>, unknown: bool) {
        if let Ok(mut state) = self.state.lock() {
            state.reservations.remove(request_id);
            if let Some(nonce) = nonce {
                state.pending.remove(nonce);
                state.generations.remove(nonce);
            }
            if unknown {
                state.ready = false;
                state.admission_open = false;
            }
            self.changed.notify_all();
        }
    }

    fn close_and_cancel(&self) {
        self.stopping.store(true, Ordering::Release);
        let controls = if let Ok(mut state) = self.state.lock() {
            state.admission_open = false;
            state.draining = true;
            state
                .reservations
                .values()
                .chain(state.generations.values())
                .cloned()
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        for control in controls {
            control.cancel();
        }
        self.changed.notify_all();
    }

    fn wait_for_sessions(&self, deadline_ns: u64) -> bool {
        loop {
            let active = self.state.lock().map_or(true, |state| {
                !state.reservations.is_empty() || !state.generations.is_empty()
            });
            if !active {
                return true;
            }
            if wire::mach_now_ns().map_or(true, |now| now >= deadline_ns) {
                return false;
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn wait_for_workers(&self, deadline_ns: u64) -> bool {
        loop {
            self.join_finished_workers();
            if self.worker_count.load(Ordering::Acquire) == 0 {
                return true;
            }
            if wire::mach_now_ns().map_or(true, |now| now >= deadline_ns) {
                return false;
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn spawn_worker(self: &Arc<Self>, stream: UnixStream) {
        let permit =
            self.worker_count
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    (current < MAX_CONNECTION_WORKERS).then_some(current + 1)
                });
        if permit.is_err() {
            return;
        }
        let runtime = Arc::clone(self);
        match thread::Builder::new()
            .name("lomi-pty-broker-peer".to_owned())
            .spawn(move || {
                let _permit = WorkerPermit(&runtime.worker_count);
                handle_connection(&runtime, stream);
            }) {
            Ok(worker) => self.store_worker(worker),
            Err(_) => {
                self.worker_count.fetch_sub(1, Ordering::AcqRel);
            }
        }
    }
}

struct WorkerPermit<'a>(&'a AtomicUsize);

impl Drop for WorkerPermit<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn accept_loop(runtime: &Arc<BrokerRuntime>, endpoint: &SocketEndpoint) -> Result<()> {
    loop {
        runtime.join_finished_workers();
        if SIGNAL_SHUTDOWN.load(Ordering::Acquire) || runtime.stopping.load(Ordering::Acquire) {
            return Ok(());
        }
        endpoint.validate()?;
        match endpoint.listener.accept() {
            Ok((stream, _)) => runtime.spawn_worker(stream),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(POLL_INTERVAL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Error::CleanupFailed),
        }
    }
}

fn handle_connection(runtime: &Arc<BrokerRuntime>, stream: UnixStream) {
    let Ok((peer_uid, peer_gid)) = peer_credentials(&stream) else {
        return;
    };
    if peer_uid == 0 {
        let Ok(proof) =
            custody::capture_privileged_custodian_root_peer_proof(&runtime.registration, &stream)
        else {
            return;
        };
        if proof.peer_uid() != 0
            || proof.registration_key() != runtime.registration.registration_key()
        {
            return;
        }
        let Ok(deadline_ns) = deadline_after(CONTROLLER_HELLO_WINDOW) else {
            return;
        };
        let Ok(value) = wire::read_canonical_json(&stream, deadline_ns) else {
            return;
        };
        match string_field(&value, "operation") {
            Ok("adminStatus") => handle_admin_status(runtime, &stream, &value),
            Ok("adminDrain") => handle_admin_drain(runtime, &stream, &value),
            _ if string_field(&value, "kind") == Ok("hello") => {
                handle_controller_hello(runtime, stream, proof.audit_token(), value)
            }
            _ => {}
        }
    } else if peer_uid == runtime.registration.owner_uid()
        && peer_gid == runtime.registration.owner_gid()
    {
        let Ok(proof) =
            custody::capture_privileged_custodian_peer_proof(&runtime.registration, &stream)
        else {
            return;
        };
        if proof.peer_uid() != runtime.registration.owner_uid()
            || proof.peer_gid() != runtime.registration.owner_gid()
            || proof.registration_key() != runtime.registration.registration_key()
        {
            return;
        }
        let Ok(deadline_ns) = deadline_after(HANDSHAKE_WINDOW) else {
            return;
        };
        let Ok(value) = wire::read_canonical_json(&stream, deadline_ns) else {
            return;
        };
        if let Ok(HostRequest::Spawn {
            request_id,
            deadline_ns,
        }) = parse_host_request(&value, &runtime.registration)
        {
            let _ = handle_spawn(runtime, stream, request_id, deadline_ns);
        }
    }
}

fn handle_controller_hello(
    runtime: &BrokerRuntime,
    stream: UnixStream,
    peer_audit: [u32; 8],
    value: Value,
) {
    let Ok(hello) = wire::parse_hello(value) else {
        return;
    };
    let Ok(peer_identity) = capability::identity_from_audit(&peer_audit) else {
        return;
    };
    if hello.registration_key != runtime.registration.registration_key()
        || hello.pid != peer_identity.pid()
        || hello.pidversion != peer_identity.pidversion()
        || hello.audit != peer_identity.audit()
        || hello.resource != peer_identity.resource()
        || hello.jetsam != peer_identity.jetsam()
    {
        return;
    }
    let pending = {
        let Ok(state) = runtime.state.lock() else {
            return;
        };
        state
            .pending
            .get(&hello.generation_nonce)
            .map(|value| (value.deadline_ns, value.sender.clone()))
    };
    let Some((deadline_ns, sender)) = pending else {
        return;
    };
    if wire::mach_now_ns().map_or(true, |now| now >= deadline_ns) {
        return;
    }
    let generation_directory = runtime
        .registration
        .state_directory()
        .join("generations")
        .join(&hello.generation_nonce);
    let Ok(record) = journal::read_record(&runtime.registration, &generation_directory) else {
        return;
    };
    if record.generation_nonce() != hello.generation_nonce
        || record.registration_key() != runtime.registration.registration_key()
        || record.deadline_ns() != deadline_ns
        || record.state() != journal::GenerationState::Prepared
        || record.controller().is_some()
    {
        return;
    }
    let Ok(mut state) = runtime.state.lock() else {
        return;
    };
    if state.pending.remove(&hello.generation_nonce).is_none() {
        return;
    }
    runtime.changed.notify_all();
    drop(state);
    let _ = sender.try_send(ControllerConnection { stream, hello });
}

enum HostRequest {
    Spawn {
        request_id: String,
        deadline_ns: u64,
    },
}

fn parse_host_request(
    value: &Value,
    registration: &PrivilegedCustodianRegistration,
) -> Result<HostRequest> {
    let object = object_exact(
        value,
        &[
            "version",
            "operation",
            "registrationKey",
            "requestId",
            "deadlineNs",
        ],
    )?;
    if number(object, "version")? != 1
        || string_field(value, "operation")? != "spawn"
        || string_field(value, "registrationKey")? != registration.registration_key()
    {
        return Err(Error::InvalidArgument);
    }
    let request_id = string_field(value, "requestId")?.to_owned();
    validate_uuid(&request_id)?;
    let deadline_ns = number(object, "deadlineNs")?;
    let now = wire::mach_now_ns()?;
    if deadline_ns <= now || deadline_ns - now > MAX_REQUEST_WINDOW_NS {
        return Err(Error::InvalidArgument);
    }
    Ok(HostRequest::Spawn {
        request_id,
        deadline_ns,
    })
}

fn handle_admin_status(runtime: &BrokerRuntime, stream: &UnixStream, value: &Value) {
    let Ok(request) = parse_admin_request(value, &runtime.registration, "adminStatus") else {
        return;
    };
    let ready = runtime.state.lock().is_ok_and(|state| {
        state.recovery_complete
            && state.ready
            && state.admission_open
            && !state.draining
            && !runtime.stopping.load(Ordering::Acquire)
    });
    let response = if ready {
        serde_json::json!({
            "version": 1,
            "state": "ready",
            "registrationKey": runtime.registration.registration_key(),
            "requestId": request,
            "runtimeId": runtime.runtime_id,
        })
    } else {
        serde_json::json!({
            "version": 1,
            "state": "notReady",
            "registrationKey": runtime.registration.registration_key(),
            "requestId": request,
            "runtimeId": runtime.runtime_id,
            "error": ADMIN_READY_ERROR,
        })
    };
    let Ok(deadline_ns) = deadline_after(HANDSHAKE_WINDOW) else {
        return;
    };
    let _ = wire::send_json(stream, &response, deadline_ns);
}

fn parse_admin_request(
    value: &Value,
    registration: &PrivilegedCustodianRegistration,
    operation: &str,
) -> Result<String> {
    let object = object_exact(
        value,
        &["version", "operation", "registrationKey", "requestId"],
    )?;
    if number(object, "version")? != 1
        || string_field(value, "operation")? != operation
        || string_field(value, "registrationKey")? != registration.registration_key()
    {
        return Err(Error::InvalidArgument);
    }
    let request_id = string_field(value, "requestId")?.to_owned();
    validate_uuid(&request_id)?;
    Ok(request_id)
}

fn handle_admin_drain(runtime: &Arc<BrokerRuntime>, stream: &UnixStream, value: &Value) {
    let Ok(request_id) = parse_admin_request(value, &runtime.registration, "adminDrain") else {
        return;
    };
    let _permit = match DrainPermit::acquire(runtime) {
        Ok(permit) => permit,
        Err(_) => return,
    };
    let deadline_ns = match deadline_after(ADMIN_DRAIN_WINDOW) {
        Ok(deadline) => deadline,
        Err(_) => return,
    };
    let controls = {
        let Ok(mut state) = runtime.state.lock() else {
            return;
        };
        state.admission_open = false;
        state.draining = true;
        state
            .reservations
            .values()
            .chain(state.generations.values())
            .cloned()
            .collect::<Vec<_>>()
    };
    for control in controls {
        control.cancel();
    }
    runtime.changed.notify_all();

    if !wait_recovery(runtime, deadline_ns) || !runtime.wait_for_sessions(deadline_ns) {
        return;
    }
    if cleanup_inventory(runtime, deadline_ns).is_err() {
        return;
    }
    if !journal::list_records(&runtime.registration).is_ok_and(|records| records.is_empty()) {
        return;
    }
    let Ok(receipt) = custody::write_privileged_custodian_drain_receipt(
        &runtime.registration,
        &runtime.runtime_id,
        &request_id,
    ) else {
        return;
    };
    let response = serde_json::json!({
        "version": 1,
        "state": "drained",
        "registrationKey": runtime.registration.registration_key(),
        "requestId": request_id,
        "runtimeId": receipt.runtime_id(),
        "drainedGenerationCount": receipt.drained_generation_count(),
        "drainedSetSha256": receipt.drained_set_sha256(),
    });
    let _ = wire::send_json(stream, &response, deadline_ns);
}

struct DrainPermit(Arc<BrokerRuntime>);

impl DrainPermit {
    fn acquire(runtime: &Arc<BrokerRuntime>) -> Result<Self> {
        let mut state = runtime.state.lock().map_err(|_| Error::CleanupFailed)?;
        if state.drain_running {
            return Err(Error::ResourceExhausted);
        }
        state.drain_running = true;
        Ok(Self(Arc::clone(runtime)))
    }
}

impl Drop for DrainPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.state.lock() {
            state.drain_running = false;
            self.0.changed.notify_all();
        }
    }
}

fn wait_recovery(runtime: &BrokerRuntime, deadline_ns: u64) -> bool {
    loop {
        if runtime
            .state
            .lock()
            .is_ok_and(|state| state.recovery_complete)
        {
            return true;
        }
        if wire::mach_now_ns().map_or(true, |now| now >= deadline_ns) {
            return false;
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn handle_spawn(
    runtime: &Arc<BrokerRuntime>,
    host: UnixStream,
    request_id: String,
    deadline_ns: u64,
) -> Result<()> {
    let control = match runtime.reserve(&request_id) {
        Ok(control) => control,
        Err(Error::ResourceExhausted) => {
            // The authenticated request was refused before any reservation,
            // journal record, or launch-manager operation was accepted.
            wire::write_spawn_outcome(&host, wire::SpawnOutcome::Refused, deadline_ns)?;
            wire::write_ack_cleaned(&host)?;
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    if let Err(error) = control.set_host(&host) {
        runtime.finish_generation(&request_id, None, false);
        return Err(error);
    }
    let mut nonce = None;
    let mut durable = false;
    let mut completed = false;
    let result = run_generation(
        runtime,
        &host,
        &request_id,
        deadline_ns,
        &control,
        &mut nonce,
        &mut durable,
    );
    if result.is_ok() {
        completed = true;
    }
    runtime.finish_generation(&request_id, nonce.as_deref(), durable && !completed);
    result
}

fn run_generation(
    runtime: &Arc<BrokerRuntime>,
    host: &UnixStream,
    request_id: &str,
    deadline_ns: u64,
    control: &Arc<SessionControl>,
    nonce_out: &mut Option<String>,
    durable_out: &mut bool,
) -> Result<()> {
    let initial = wire::read_canonical_json(host, deadline_ns)?;
    let request = wire::parse_start(initial, request_id, deadline_ns)?;
    if control.is_cancelled() || wire::mach_now_ns()? >= deadline_ns {
        return Err(Error::SpawnFailed);
    }
    let nonce = Uuid::new_v4().to_string();
    let generation_directory = runtime
        .registration
        .state_directory()
        .join("generations")
        .join(&nonce);
    *nonce_out = Some(nonce.clone());
    *durable_out = true;
    journal::create_prepared(
        &runtime.registration,
        &generation_directory,
        &nonce,
        deadline_ns,
    )?;
    let (sender, receiver) = mpsc::sync_channel(1);
    runtime.activate_generation(request_id, &nonce, control, deadline_ns, sender)?;

    let mut job = match manager::prepare_until(
        &runtime.registration,
        &nonce,
        &generation_directory,
        deadline_ns,
    ) {
        Ok(job) => job,
        Err(_) => return Err(Error::SpawnOutcomeUnknown),
    };
    if control.is_cancelled() || runtime.stopping.load(Ordering::Acquire) {
        cleanup_not_started(runtime, &nonce, &generation_directory, &mut job)?;
        notify_known_no_fork(host, deadline_ns, control)?;
        return Ok(());
    }
    match job.bootstrap(deadline_ns) {
        Ok(()) => {}
        Err(Error::SpawnFailed) => {
            cleanup_not_started(runtime, &nonce, &generation_directory, &mut job)?;
            notify_known_no_fork(host, deadline_ns, control)?;
            return Ok(());
        }
        Err(error) => return Err(error),
    }

    let connection = match wait_for_controller(
        runtime,
        &receiver,
        &generation_directory,
        &nonce,
        deadline_ns,
        control,
    ) {
        Ok(Some(connection)) => connection,
        Ok(None) => {
            if let Some(record) =
                cleaned_not_started_record(runtime, &generation_directory, &nonce)?
            {
                cleanup_cleaned(
                    runtime,
                    &nonce,
                    &generation_directory,
                    &mut job,
                    Some(&record),
                )?;
                notify_known_no_fork(host, deadline_ns, control)?;
                return Ok(());
            }
            if control.is_cancelled()
                && cleanup_not_started(runtime, &nonce, &generation_directory, &mut job).is_ok()
            {
                notify_known_no_fork(host, deadline_ns, control)?;
                return Ok(());
            }
            if control.is_cancelled()
                && let Some(record) =
                    wait_for_not_started(runtime, &generation_directory, &nonce, deadline_ns)?
            {
                cleanup_cleaned(
                    runtime,
                    &nonce,
                    &generation_directory,
                    &mut job,
                    Some(&record),
                )?;
                notify_known_no_fork(host, deadline_ns, control)?;
                return Ok(());
            }
            return Err(Error::SpawnOutcomeUnknown);
        }
        Err(error) => return Err(error),
    };
    if control.is_cancelled() || runtime.stopping.load(Ordering::Acquire) {
        drop(connection);
        if let Some(record) =
            wait_for_not_started(runtime, &generation_directory, &nonce, deadline_ns)?
        {
            cleanup_cleaned(
                runtime,
                &nonce,
                &generation_directory,
                &mut job,
                Some(&record),
            )?;
            return Ok(());
        }
        return Err(Error::SpawnOutcomeUnknown);
    }
    if control.set_controller(&connection.stream).is_err() {
        drop(connection);
        if let Some(record) =
            wait_for_not_started(runtime, &generation_directory, &nonce, deadline_ns)?
        {
            cleanup_cleaned(
                runtime,
                &nonce,
                &generation_directory,
                &mut job,
                Some(&record),
            )?;
            notify_known_no_fork(host, deadline_ns, control)?;
            return Ok(());
        }
        return Err(Error::SpawnOutcomeUnknown);
    }

    let mut start = request;
    start.generation_nonce = nonce.clone();
    if wire::write_start(&connection.stream, &start).is_err() {
        return Err(Error::SpawnOutcomeUnknown);
    }
    let relay = relay_generation(host, &connection.stream, deadline_ns, control)?;

    let record = journal::read_record(&runtime.registration, &generation_directory)?;
    if !cleaned_record_matches(&record, &connection.hello) {
        return Err(Error::SpawnOutcomeUnknown);
    }
    match relay {
        RelayOutcome::Started | RelayOutcome::Cancelled => {
            // The controller's A is only forwarded after the durable record
            // is read back and matched to the kernel-authenticated Hello.
            if !control.is_cancelled() {
                wire::write_ack_cleaned(host)?;
            }
        }
        RelayOutcome::Refused => {
            wire::write_spawn_outcome(host, wire::SpawnOutcome::Refused, deadline_ns)?;
            wire::write_ack_cleaned(host)?;
        }
    }
    cleanup_cleaned(
        runtime,
        &nonce,
        &generation_directory,
        &mut job,
        Some(&record),
    )?;
    Ok(())
}

fn wait_for_controller(
    runtime: &BrokerRuntime,
    receiver: &Receiver<ControllerConnection>,
    generation_directory: &Path,
    nonce: &str,
    deadline_ns: u64,
    control: &SessionControl,
) -> Result<Option<ControllerConnection>> {
    loop {
        if cleaned_not_started_record(runtime, generation_directory, nonce)?.is_some() {
            return Ok(None);
        }
        let now = match wire::mach_now_ns() {
            Ok(now) => now,
            Err(_) => return Ok(None),
        };
        if now >= deadline_ns {
            return Ok(None);
        }
        if control.is_cancelled() || runtime.stopping.load(Ordering::Acquire) {
            return Ok(None);
        }
        let interval_ns = u64::try_from(CONTROLLER_WAIT_INTERVAL.as_nanos())
            .map_err(|_| Error::InvalidArgument)?;
        let wait = Duration::from_nanos((deadline_ns - now).min(interval_ns));
        match receiver.recv_timeout(wait) {
            Ok(connection) => return Ok(Some(connection)),
            Err(mpsc::RecvTimeoutError::Disconnected | mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

fn wait_for_not_started(
    runtime: &BrokerRuntime,
    generation_directory: &Path,
    nonce: &str,
    deadline_ns: u64,
) -> Result<Option<journal::GenerationRecord>> {
    loop {
        if let Some(record) = cleaned_not_started_record(runtime, generation_directory, nonce)? {
            return Ok(Some(record));
        }
        let now = match wire::mach_now_ns() {
            Ok(now) => now,
            Err(_) => return Ok(None),
        };
        if now >= deadline_ns {
            return Ok(None);
        }
        let interval_ns = u64::try_from(CONTROLLER_WAIT_INTERVAL.as_nanos())
            .map_err(|_| Error::InvalidArgument)?;
        thread::sleep(Duration::from_nanos((deadline_ns - now).min(interval_ns)));
    }
}

fn cleaned_not_started_record(
    runtime: &BrokerRuntime,
    generation_directory: &Path,
    nonce: &str,
) -> Result<Option<journal::GenerationRecord>> {
    let record = journal::read_record(&runtime.registration, generation_directory)?;
    if record.state() != journal::GenerationState::Cleaned
        || record.completion_disposition() != Some(journal::CompletionDisposition::NotStarted)
    {
        return Ok(None);
    }
    if record.generation_nonce() != nonce
        || record.registration_key() != runtime.registration.registration_key()
        || record.controller().is_some()
        || record.kernel_restart_proof_sha256().is_some()
    {
        return Err(Error::SpawnOutcomeUnknown);
    }
    Ok(Some(record))
}

fn notify_known_no_fork(
    host: &UnixStream,
    deadline_ns: u64,
    control: &SessionControl,
) -> Result<()> {
    if control.is_cancelled() {
        return Ok(());
    }
    wire::write_spawn_outcome(host, wire::SpawnOutcome::Refused, deadline_ns)?;
    wire::write_ack_cleaned(host)
}

fn cleanup_not_started(
    runtime: &BrokerRuntime,
    nonce: &str,
    generation_directory: &Path,
    job: &mut manager::GenerationJob,
) -> Result<()> {
    let current = journal::read_record(&runtime.registration, generation_directory)?;
    if current.state() == journal::GenerationState::Prepared {
        let mut claimed = journal::claim_controller(&runtime.registration, generation_directory)?;
        claimed.mark_not_started()?;
    } else if current.state() != journal::GenerationState::Cleaned
        || current.completion_disposition() != Some(journal::CompletionDisposition::NotStarted)
    {
        return Err(Error::SpawnOutcomeUnknown);
    }
    let cleaned = journal::read_record(&runtime.registration, generation_directory)?;
    if !is_cleaned_not_started(&cleaned, &runtime.registration, nonce) {
        return Err(Error::CleanupFailed);
    }
    let deadline = deadline_after(CLEANUP_WINDOW)?;
    manager::bootout_cleaned(&runtime.registration, job, &cleaned, deadline)?;
    journal::remove_cleaned_record(&runtime.registration, nonce, &cleaned.canonical_bytes()?)?;
    Ok(())
}

fn is_cleaned_not_started(
    record: &journal::GenerationRecord,
    registration: &PrivilegedCustodianRegistration,
    nonce: &str,
) -> bool {
    record.state() == journal::GenerationState::Cleaned
        && record.completion_disposition() == Some(journal::CompletionDisposition::NotStarted)
        && record.generation_nonce() == nonce
        && record.registration_key() == registration.registration_key()
        && record.controller().is_none()
        && record.kernel_restart_proof_sha256().is_none()
}

fn cleanup_cleaned(
    runtime: &BrokerRuntime,
    nonce: &str,
    generation_directory: &Path,
    job: &mut manager::GenerationJob,
    expected: Option<&journal::GenerationRecord>,
) -> Result<()> {
    let cleaned = journal::read_record(&runtime.registration, generation_directory)?;
    if cleaned.state() != journal::GenerationState::Cleaned {
        return Err(Error::CleanupFailed);
    }
    if let Some(expected) = expected
        && expected.canonical_bytes()? != cleaned.canonical_bytes()?
    {
        return Err(Error::CleanupFailed);
    }
    let deadline = deadline_after(CLEANUP_WINDOW)?;
    manager::bootout_cleaned(&runtime.registration, job, &cleaned, deadline)?;
    journal::remove_cleaned_record(&runtime.registration, nonce, &cleaned.canonical_bytes()?)?;
    Ok(())
}

fn cleaned_record_matches(
    record: &journal::GenerationRecord,
    hello: &wire::ControllerHello,
) -> bool {
    if record.state() != journal::GenerationState::Cleaned
        || record.generation_nonce() != hello.generation_nonce
        || record.registration_key() != hello.registration_key
    {
        return false;
    }
    record.completion_disposition() == Some(journal::CompletionDisposition::Drained)
        && record.controller().is_some_and(|controller| {
            controller.pid == hello.pid
                && controller.pidversion == hello.pidversion
                && controller.audit == hello.audit
                && controller.resource == hello.resource
                && controller.jetsam == hello.jetsam
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RelayOutcome {
    Started,
    Refused,
    Cancelled,
}

enum MasterReply {
    Master(OwnedFd),
    Refused,
    Cancelled,
}

fn relay_generation(
    host: &UnixStream,
    controller: &UnixStream,
    deadline_ns: u64,
    control: &SessionControl,
) -> Result<RelayOutcome> {
    let master = match wait_for_master(host, controller, deadline_ns, control)? {
        MasterReply::Master(master) => master,
        MasterReply::Refused => {
            read_controller_ack(controller)?;
            return Ok(RelayOutcome::Refused);
        }
        MasterReply::Cancelled => {
            cancel_controller(controller, deadline_ns);
            return match wait_for_cleaned_ack(host, controller, deadline_ns, control)? {
                Some(wire::SpawnOutcome::Refused) => Ok(RelayOutcome::Refused),
                None => Ok(RelayOutcome::Cancelled),
                Some(wire::SpawnOutcome::Started) => Err(Error::SpawnOutcomeUnknown),
            };
        }
    };
    if wire::send_d_with_master(host, master.as_raw_fd(), deadline_ns).is_err() {
        cancel_controller(controller, deadline_ns);
        let _ = wait_for_cleaned_ack(host, controller, deadline_ns, control);
        return Err(Error::SpawnOutcomeUnknown);
    }

    match wait_for_host_byte(host, controller, deadline_ns, control, b'I')? {
        RelayByte::Expected => wire::write_start_intent(controller, deadline_ns)?,
        RelayByte::Cancelled => {
            cancel_controller(controller, deadline_ns);
            return match wait_for_cleaned_ack(host, controller, deadline_ns, control)? {
                Some(wire::SpawnOutcome::Refused) => Ok(RelayOutcome::Refused),
                None => Ok(RelayOutcome::Cancelled),
                Some(wire::SpawnOutcome::Started) => Err(Error::SpawnOutcomeUnknown),
            };
        }
        RelayByte::ControllerRefused => {
            read_controller_ack(controller)?;
            return Ok(RelayOutcome::Refused);
        }
        RelayByte::ControllerFailed => return Err(Error::SpawnOutcomeUnknown),
    }
    match wait_for_controller_byte(host, controller, deadline_ns, control, b'F')? {
        RelayByte::Expected => {}
        RelayByte::Cancelled => {
            cancel_controller(controller, deadline_ns);
            return match wait_for_cleaned_ack(host, controller, deadline_ns, control)? {
                Some(wire::SpawnOutcome::Refused) => Ok(RelayOutcome::Refused),
                None => Ok(RelayOutcome::Cancelled),
                Some(wire::SpawnOutcome::Started) => Err(Error::SpawnOutcomeUnknown),
            };
        }
        RelayByte::ControllerRefused => {
            read_controller_ack(controller)?;
            return Ok(RelayOutcome::Refused);
        }
        RelayByte::ControllerFailed => return Err(Error::SpawnOutcomeUnknown),
    }
    relay_final_commit(host, controller, deadline_ns, control)
}

fn relay_final_commit(
    host: &UnixStream,
    controller: &UnixStream,
    deadline_ns: u64,
    control: &SessionControl,
) -> Result<RelayOutcome> {
    let gate = request_fresh_gate(host, controller, deadline_ns, control);
    if !matches!(gate, Ok(true)) {
        cancel_controller(controller, deadline_ns);
        return match wait_for_cleaned_ack(host, controller, deadline_ns, control)? {
            Some(wire::SpawnOutcome::Refused) => Ok(RelayOutcome::Refused),
            None => Ok(RelayOutcome::Cancelled),
            Some(wire::SpawnOutcome::Started) => Err(Error::SpawnOutcomeUnknown),
        };
    }
    match wait_for_host_decision(host, controller, deadline_ns, control) {
        Ok(RelayByte::Expected) => match control.try_commit(controller, deadline_ns) {
            Ok(Some(true)) => {}
            Ok(Some(false) | None) | Err(_) => {
                // The Host's authorization was consumed. E is attempted once;
                // backpressure or cancellation cannot reuse that decision.
                cancel_controller(controller, deadline_ns);
                let _ = wait_for_cleaned_ack(host, controller, deadline_ns, control);
                return Err(Error::SpawnOutcomeUnknown);
            }
        },
        Ok(RelayByte::Cancelled) | Err(_) => {
            cancel_controller(controller, deadline_ns);
            return match wait_for_cleaned_ack(host, controller, deadline_ns, control)? {
                Some(wire::SpawnOutcome::Refused) => Ok(RelayOutcome::Refused),
                None => Ok(RelayOutcome::Cancelled),
                Some(wire::SpawnOutcome::Started) => Err(Error::SpawnOutcomeUnknown),
            };
        }
        Ok(RelayByte::ControllerRefused) => {
            read_controller_ack(controller)?;
            return Ok(RelayOutcome::Refused);
        }
        Ok(RelayByte::ControllerFailed) => return Err(Error::SpawnOutcomeUnknown),
    }

    match wait_for_spawn_outcome(host, controller, deadline_ns, control) {
        Ok(wire::SpawnOutcome::Started) => {
            // S is the controller's positive user-exec acknowledgement. The
            // Host never receives success from D, F, E, EOF, or journal state.
            if wire::write_spawn_outcome(host, wire::SpawnOutcome::Started, deadline_ns).is_err() {
                cancel_controller(controller, deadline_ns);
                let _ = wait_for_cleaned_ack(host, controller, deadline_ns, control);
                return Err(Error::SpawnOutcomeUnknown);
            }
            match wait_for_cleaned_ack(host, controller, deadline_ns, control)? {
                None => Ok(RelayOutcome::Started),
                Some(_) => Err(Error::SpawnOutcomeUnknown),
            }
        }
        Ok(wire::SpawnOutcome::Refused) => {
            read_controller_ack(controller)?;
            Ok(RelayOutcome::Refused)
        }
        Err(_) => {
            let _ = controller.shutdown(std::net::Shutdown::Write);
            Err(Error::SpawnOutcomeUnknown)
        }
    }
}

fn request_fresh_gate(
    host: &UnixStream,
    controller: &UnixStream,
    deadline_ns: u64,
    control: &SessionControl,
) -> Result<bool> {
    if !wait_writable(controller, deadline_ns, control)? {
        return Ok(false);
    }
    if control.is_cancelled() || wire::mach_now_ns().map_or(true, |now| now >= deadline_ns) {
        return Ok(false);
    }
    wire::write_final_authorization_request(host, deadline_ns)?;
    Ok(true)
}

fn wait_writable(stream: &UnixStream, deadline_ns: u64, control: &SessionControl) -> Result<bool> {
    loop {
        if control.is_cancelled() || wire::mach_now_ns().map_or(true, |now| now >= deadline_ns) {
            return Ok(false);
        }
        let mut descriptor = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, 10) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::SpawnOutcomeUnknown);
        }
        if result == 0 {
            continue;
        }
        if descriptor.revents & libc::POLLNVAL != 0 {
            return Err(Error::SpawnOutcomeUnknown);
        }
        if descriptor.revents & (libc::POLLERR | libc::POLLHUP) != 0 {
            return Err(Error::SpawnOutcomeUnknown);
        }
        if descriptor.revents & libc::POLLOUT != 0 {
            return Ok(true);
        }
    }
}

fn cancel_controller(controller: &UnixStream, deadline_ns: u64) {
    if wire::mach_now_ns().is_ok_and(|now| now < deadline_ns) {
        if wire::write_cancel(controller, deadline_ns).is_ok() {
            return;
        }
    }
    let _ = controller.shutdown(std::net::Shutdown::Write);
}

enum RelayByte {
    Expected,
    Cancelled,
    ControllerRefused,
    ControllerFailed,
}

fn wait_for_master(
    host: &UnixStream,
    controller: &UnixStream,
    deadline_ns: u64,
    control: &SessionControl,
) -> Result<MasterReply> {
    loop {
        if control.is_cancelled() {
            return Ok(MasterReply::Cancelled);
        }
        let (host_ready, controller_ready) = wire::poll_streams(
            host.as_raw_fd(),
            Some(controller.as_raw_fd()),
            Some(deadline_ns),
        )?;
        if controller_ready {
            return match wire::receive_ready(controller, deadline_ns)? {
                wire::ReadyReply::Master(master) => Ok(MasterReply::Master(master)),
                wire::ReadyReply::Refused => Ok(MasterReply::Refused),
            };
        }
        if host_ready {
            match wire::read_byte(host, deadline_ns)? {
                Some(b'X') | None => return Ok(MasterReply::Cancelled),
                _ => return Err(Error::SpawnFailed),
            }
        }
    }
}

fn wait_for_host_byte(
    host: &UnixStream,
    controller: &UnixStream,
    deadline_ns: u64,
    control: &SessionControl,
    expected: u8,
) -> Result<RelayByte> {
    loop {
        if control.is_cancelled() {
            return Ok(RelayByte::Cancelled);
        }
        let (host_ready, controller_ready) = wire::poll_streams(
            host.as_raw_fd(),
            Some(controller.as_raw_fd()),
            Some(deadline_ns),
        )?;
        if controller_ready {
            return match wire::read_spawn_outcome(controller, deadline_ns) {
                Ok(wire::SpawnOutcome::Refused) => Ok(RelayByte::ControllerRefused),
                _ => Ok(RelayByte::ControllerFailed),
            };
        }
        if host_ready {
            return match wire::read_byte(host, deadline_ns)? {
                Some(byte) if byte == expected => Ok(RelayByte::Expected),
                Some(b'X') | None => Ok(RelayByte::Cancelled),
                _ => Err(Error::SpawnFailed),
            };
        }
    }
}

fn wait_for_controller_byte(
    host: &UnixStream,
    controller: &UnixStream,
    deadline_ns: u64,
    control: &SessionControl,
    expected: u8,
) -> Result<RelayByte> {
    loop {
        if control.is_cancelled() {
            return Ok(RelayByte::Cancelled);
        }
        let (host_ready, controller_ready) = wire::poll_streams(
            host.as_raw_fd(),
            Some(controller.as_raw_fd()),
            Some(deadline_ns),
        )?;
        if controller_ready {
            return match wire::read_byte(controller, deadline_ns)? {
                Some(byte) if byte == expected => Ok(RelayByte::Expected),
                Some(b'N') => Ok(RelayByte::ControllerRefused),
                Some(b'X') | None => Ok(RelayByte::Cancelled),
                _ => Err(Error::SpawnOutcomeUnknown),
            };
        }
        if host_ready {
            match wire::read_byte(host, deadline_ns)? {
                Some(b'X') | None => return Ok(RelayByte::Cancelled),
                Some(_) => return Err(Error::SpawnFailed),
            }
        }
    }
}

fn wait_for_host_decision(
    host: &UnixStream,
    controller: &UnixStream,
    deadline_ns: u64,
    control: &SessionControl,
) -> Result<RelayByte> {
    loop {
        if control.is_cancelled() {
            return Ok(RelayByte::Cancelled);
        }
        let (host_ready, controller_ready) = wire::poll_streams(
            host.as_raw_fd(),
            Some(controller.as_raw_fd()),
            Some(deadline_ns),
        )?;
        if controller_ready {
            return match wire::read_spawn_outcome(controller, deadline_ns) {
                Ok(wire::SpawnOutcome::Refused) => Ok(RelayByte::ControllerRefused),
                _ => Ok(RelayByte::ControllerFailed),
            };
        }
        if host_ready {
            return match wire::read_decision(host, deadline_ns)? {
                wire::Decision::Commit => Ok(RelayByte::Expected),
                wire::Decision::Cancel => Ok(RelayByte::Cancelled),
            };
        }
    }
}

fn wait_for_spawn_outcome(
    host: &UnixStream,
    controller: &UnixStream,
    deadline_ns: u64,
    control: &SessionControl,
) -> Result<wire::SpawnOutcome> {
    loop {
        if control.is_cancelled() {
            return Err(Error::SpawnOutcomeUnknown);
        }
        let (host_ready, controller_ready) = wire::poll_streams(
            host.as_raw_fd(),
            Some(controller.as_raw_fd()),
            Some(deadline_ns),
        )?;
        if controller_ready {
            return wire::read_spawn_outcome(controller, deadline_ns);
        }
        if host_ready {
            match wire::read_byte(host, deadline_ns)? {
                Some(b'X') | None => return Err(Error::SpawnOutcomeUnknown),
                Some(_) => return Err(Error::SpawnOutcomeUnknown),
            }
        }
    }
}

fn read_controller_ack(controller: &UnixStream) -> Result<()> {
    let cleanup_deadline = deadline_after(CLEANUP_WINDOW)?;
    if wire::read_byte(controller, cleanup_deadline)? == Some(b'A') {
        Ok(())
    } else {
        Err(Error::SpawnOutcomeUnknown)
    }
}

fn wait_for_cleaned_ack(
    host: &UnixStream,
    controller: &UnixStream,
    deadline_ns: u64,
    control: &SessionControl,
) -> Result<Option<wire::SpawnOutcome>> {
    let mut host_closed = control.is_cancelled();
    let mut cleanup_deadline = if host_closed {
        Some(deadline_after(CLEANUP_WINDOW)?)
    } else {
        None
    };
    loop {
        let (host_ready, controller_ready) = wire::poll_streams(
            host.as_raw_fd(),
            Some(controller.as_raw_fd()),
            cleanup_deadline,
        )?;
        if controller_ready {
            return match wire::read_byte(controller, u64::MAX)? {
                Some(b'A') => Ok(None),
                Some(b'N') => {
                    read_controller_ack(controller)?;
                    Ok(Some(wire::SpawnOutcome::Refused))
                }
                _ => Err(Error::SpawnOutcomeUnknown),
            };
        }
        if host_ready && !host_closed {
            match wire::read_byte(host, u64::MAX)? {
                None | Some(b'X') => {
                    host_closed = true;
                    cleanup_deadline = Some(deadline_after(CLEANUP_WINDOW)?);
                    if wire::mach_now_ns().is_ok_and(|now| now < deadline_ns) {
                        let _ = wire::write_cancel(controller, deadline_ns);
                    } else {
                        let _ = controller.shutdown(std::net::Shutdown::Write);
                    }
                }
                Some(_) => return Err(Error::SpawnOutcomeUnknown),
            }
        }
        if control.is_cancelled() && !host_closed {
            host_closed = true;
            cleanup_deadline = Some(deadline_after(CLEANUP_WINDOW)?);
            if wire::mach_now_ns().is_ok_and(|now| now < deadline_ns) {
                let _ = wire::write_cancel(controller, deadline_ns);
            } else {
                let _ = controller.shutdown(std::net::Shutdown::Write);
            }
        }
    }
}

fn cleanup_inventory(runtime: &BrokerRuntime, deadline_ns: u64) -> Result<()> {
    let records = journal::list_records(&runtime.registration)?;
    if records.len() > MAX_GENERATIONS {
        return Err(Error::CleanupFailed);
    }
    let mut unresolved = false;
    for record in records {
        if wire::mach_now_ns()? >= deadline_ns {
            return Err(Error::CleanupFailed);
        }
        let generation_directory = runtime
            .registration
            .state_directory()
            .join("generations")
            .join(record.generation_nonce());
        let cleaned = if record.state() == journal::GenerationState::Cleaned {
            record
        } else {
            match journal::recover_after_kernel_restart(
                &runtime.registration,
                &generation_directory,
            ) {
                Ok(cleaned) => cleaned,
                Err(_) => {
                    unresolved = true;
                    continue;
                }
            }
        };
        if cleaned.state() != journal::GenerationState::Cleaned {
            unresolved = true;
            continue;
        }
        let mut job = match manager::from_record_until(
            &runtime.registration,
            cleaned.generation_nonce(),
            &generation_directory,
            deadline_ns,
        ) {
            Ok(job) => job,
            Err(_) => {
                unresolved = true;
                continue;
            }
        };
        if manager::bootout_cleaned(&runtime.registration, &mut job, &cleaned, deadline_ns).is_err()
        {
            unresolved = true;
            continue;
        }
        if journal::remove_cleaned_record(
            &runtime.registration,
            cleaned.generation_nonce(),
            &cleaned.canonical_bytes()?,
        )
        .is_err()
        {
            unresolved = true;
        }
    }
    if unresolved {
        Err(Error::CleanupFailed)
    } else {
        Ok(())
    }
}

fn recover_startup(runtime: &BrokerRuntime) -> bool {
    let Ok(deadline_ns) = deadline_after(ADMIN_DRAIN_WINDOW) else {
        return false;
    };
    loop {
        if cleanup_inventory(runtime, deadline_ns).is_ok()
            && journal::list_records(&runtime.registration).is_ok_and(|records| records.is_empty())
        {
            return true;
        }
        let Ok(now) = wire::mach_now_ns() else {
            return false;
        };
        if now >= deadline_ns {
            return false;
        }
        let retry_ns = STARTUP_RECOVERY_RETRY.as_nanos() as u64;
        thread::sleep(Duration::from_nanos((deadline_ns - now).min(retry_ns)));
    }
}

fn deadline_after(duration: Duration) -> Result<u64> {
    let now = wire::mach_now_ns()?;
    let duration = u64::try_from(duration.as_nanos()).map_err(|_| Error::InvalidArgument)?;
    now.checked_add(duration).ok_or(Error::InvalidArgument)
}

fn validate_uuid(value: &str) -> Result<()> {
    let id = Uuid::parse_str(value).map_err(|_| Error::InvalidArgument)?;
    if id.is_nil() || id.to_string() != value {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

fn object_exact<'a>(value: &'a Value, keys: &[&str]) -> Result<&'a Map<String, Value>> {
    let object = value.as_object().ok_or(Error::InvalidArgument)?;
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(Error::InvalidArgument);
    }
    Ok(object)
}

fn string_field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(Error::InvalidArgument)
}

fn number(object: &Map<String, Value>, key: &str) -> Result<u64> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(Error::InvalidArgument)
}

fn peer_credentials(stream: &UnixStream) -> Result<(u32, u32)> {
    let mut uid = 0;
    let mut gid = 0;
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(Error::SpawnFailed);
    }
    Ok((uid, gid))
}

struct BrokerLock(File);

impl BrokerLock {
    fn acquire(registration: &PrivilegedCustodianRegistration) -> Result<Self> {
        let directory = PinnedDirectory::open(
            registration.state_directory(),
            Some(STATE_DIRECTORY_MODE),
            0,
            0,
        )?;
        let name = cstring(OsStr::new(BROKER_LOCK))?;
        let fd = unsafe {
            libc::openat(
                directory.handle.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(Error::CleanupFailed);
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(|_| Error::CleanupFailed)?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
        {
            return Err(Error::CleanupFailed);
        }
        unix::reject_acl_grants_readonly(&file).map_err(|_| Error::CleanupFailed)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Error::ResourceExhausted);
        }
        directory.validate()?;
        Ok(Self(file))
    }
}

struct PinnedDirectory {
    path: PathBuf,
    handle: File,
    identity: FileIdentity,
    owner: u32,
    group: u32,
    mode: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl PinnedDirectory {
    fn open(path: &Path, mode: Option<u32>, owner: u32, group: u32) -> Result<Self> {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(Error::InvalidArgument);
        }
        let mut current = File::open("/").map_err(|_| Error::CleanupFailed)?;
        validate_directory(
            &current,
            0,
            current.metadata().map_err(|_| Error::CleanupFailed)?.gid(),
            None,
        )?;
        let parts: Vec<_> = path.components().skip(1).collect();
        for (index, part) in parts.iter().enumerate() {
            let Component::Normal(name) = part else {
                return Err(Error::InvalidArgument);
            };
            let name = cstring(name)?;
            let fd = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(Error::CleanupFailed);
            }
            let next = unsafe { File::from_raw_fd(fd) };
            let final_component = index + 1 == parts.len();
            validate_directory(
                &next,
                if final_component { owner } else { 0 },
                if final_component {
                    group
                } else {
                    next.metadata().map_err(|_| Error::CleanupFailed)?.gid()
                },
                if final_component { mode } else { None },
            )?;
            current = next;
        }
        if path.canonicalize().map_err(|_| Error::CleanupFailed)? != path {
            return Err(Error::CleanupFailed);
        }
        let metadata = current.metadata().map_err(|_| Error::CleanupFailed)?;
        let identity = FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        Ok(Self {
            path: path.to_path_buf(),
            handle: current,
            identity,
            owner,
            group,
            mode: mode.unwrap_or(metadata.mode() & 0o7777),
        })
    }

    fn validate(&self) -> Result<()> {
        validate_directory(&self.handle, self.owner, self.group, Some(self.mode))?;
        let metadata = self.handle.metadata().map_err(|_| Error::CleanupFailed)?;
        if identity(&metadata) != self.identity {
            return Err(Error::CleanupFailed);
        }
        let current = Self::open(&self.path, Some(self.mode), self.owner, self.group)?;
        if current.identity != self.identity {
            return Err(Error::CleanupFailed);
        }
        Ok(())
    }
}

fn validate_directory(file: &File, owner: u32, group: u32, mode: Option<u32>) -> Result<()> {
    let metadata = file.metadata().map_err(|_| Error::CleanupFailed)?;
    if !metadata.is_dir()
        || metadata.uid() != owner
        || metadata.gid() != group
        || metadata.mode() & 0o022 != 0
        || mode.is_some_and(|expected| metadata.mode() & 0o7777 != expected)
    {
        return Err(Error::CleanupFailed);
    }
    unix::reject_acl_grants_readonly(file).map_err(|_| Error::CleanupFailed)
}

fn identity(metadata: &std::fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

struct SocketEndpoint {
    listener: UnixListener,
    parent: PinnedDirectory,
    leaf: CString,
    path: PathBuf,
    identity: FileIdentity,
    uid: u32,
    gid: u32,
}

impl SocketEndpoint {
    fn bind(registration: &PrivilegedCustodianRegistration) -> Result<Self> {
        let parent = PinnedDirectory::open(
            registration.socket_parent(),
            Some(SOCKET_DIRECTORY_MODE),
            0,
            0,
        )?;
        let path = registration.socket_path().to_path_buf();
        if path.parent() != Some(registration.socket_parent())
            || path.file_name() != Some(OsStr::new(SOCKET_LEAF))
        {
            return Err(Error::CleanupFailed);
        }
        let leaf = cstring(OsStr::new(SOCKET_LEAF))?;
        remove_stale_socket(
            &parent,
            &leaf,
            registration.owner_uid(),
            registration.owner_gid(),
        )?;
        parent.validate()?;
        let bytes = path.as_os_str().as_bytes();
        let offset = std::mem::offset_of!(libc::sockaddr_un, sun_path);
        let empty: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        if bytes.is_empty() || bytes.len() + 1 > empty.sun_path.len() {
            return Err(Error::InvalidArgument);
        }
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(Error::CleanupFailed);
        }
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        set_cloexec(socket.as_raw_fd())?;
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        address.sun_family = libc::AF_UNIX as _;
        address.sun_len = (offset + bytes.len() + 1)
            .try_into()
            .map_err(|_| Error::InvalidArgument)?;
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                address.sun_path.as_mut_ptr().cast::<u8>(),
                bytes.len(),
            );
        }
        let old_mask = unsafe { libc::umask(0o077) };
        let bind_result = unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                address.sun_len as libc::socklen_t,
            )
        };
        unsafe { libc::umask(old_mask) };
        if bind_result != 0 {
            return Err(Error::CleanupFailed);
        }
        let bound_identity = match socket_identity(&parent, &leaf) {
            Ok(identity) => identity,
            Err(error) => return Err(error),
        };
        if unsafe {
            libc::fchownat(
                parent.handle.as_raw_fd(),
                leaf.as_ptr(),
                registration.owner_uid(),
                registration.owner_gid(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
            || unsafe {
                libc::fchmodat(
                    parent.handle.as_raw_fd(),
                    leaf.as_ptr(),
                    SOCKET_MODE as libc::mode_t,
                    0,
                )
            } != 0
            || unsafe { libc::listen(socket.as_raw_fd(), 64) } != 0
        {
            let _ = unlink_bound_socket(&parent, &leaf, bound_identity);
            return Err(Error::CleanupFailed);
        }
        let socket_identity = match socket_metadata(
            &parent,
            &leaf,
            registration.owner_uid(),
            registration.owner_gid(),
        ) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = unlink_bound_socket(&parent, &leaf, bound_identity);
                return Err(error);
            }
        };
        if let Err(error) = set_nonblocking(socket.as_raw_fd()) {
            let _ = unlink_bound_socket(&parent, &leaf, bound_identity);
            return Err(error);
        }
        if let Err(error) = parent.validate() {
            let _ = unlink_bound_socket(&parent, &leaf, bound_identity);
            return Err(error);
        }
        let listener = unsafe { UnixListener::from_raw_fd(socket.into_raw_fd()) };
        Ok(Self {
            listener,
            parent,
            leaf,
            path,
            identity: socket_identity,
            uid: registration.owner_uid(),
            gid: registration.owner_gid(),
        })
    }

    fn validate(&self) -> Result<()> {
        self.parent.validate()?;
        if socket_metadata(&self.parent, &self.leaf, self.uid, self.gid)? != self.identity {
            return Err(Error::CleanupFailed);
        }
        if self.path.canonicalize().map_err(|_| Error::CleanupFailed)? != self.path {
            return Err(Error::CleanupFailed);
        }
        Ok(())
    }
}

impl Drop for SocketEndpoint {
    fn drop(&mut self) {
        let _ = unlink_if_identity(
            &self.parent,
            &self.leaf,
            self.uid,
            self.gid,
            Some(self.identity),
        );
    }
}

fn socket_metadata(
    parent: &PinnedDirectory,
    leaf: &CString,
    uid: u32,
    gid: u32,
) -> Result<FileIdentity> {
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            parent.handle.as_raw_fd(),
            leaf.as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
        || metadata.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || metadata.st_uid != uid
        || metadata.st_gid != gid
        || metadata.st_nlink != 1
        || metadata.st_mode as u32 & 0o777 != SOCKET_MODE
    {
        return Err(Error::CleanupFailed);
    }
    Ok(FileIdentity {
        device: metadata.st_dev as u64,
        inode: metadata.st_ino as u64,
    })
}

fn socket_identity(parent: &PinnedDirectory, leaf: &CString) -> Result<FileIdentity> {
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            parent.handle.as_raw_fd(),
            leaf.as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
        || metadata.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || metadata.st_nlink != 1
    {
        return Err(Error::CleanupFailed);
    }
    Ok(FileIdentity {
        device: metadata.st_dev as u64,
        inode: metadata.st_ino as u64,
    })
}

fn unlink_bound_socket(
    parent: &PinnedDirectory,
    leaf: &CString,
    expected: FileIdentity,
) -> Result<()> {
    parent.validate()?;
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            parent.handle.as_raw_fd(),
            leaf.as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
        || metadata.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || metadata.st_nlink != 1
        || metadata.st_dev as u64 != expected.device
        || metadata.st_ino as u64 != expected.inode
    {
        return Err(Error::CleanupFailed);
    }
    if unsafe { libc::unlinkat(parent.handle.as_raw_fd(), leaf.as_ptr(), 0) } != 0
        || unsafe { libc::fsync(parent.handle.as_raw_fd()) } != 0
    {
        return Err(Error::CleanupFailed);
    }
    Ok(())
}

fn remove_stale_socket(parent: &PinnedDirectory, leaf: &CString, uid: u32, gid: u32) -> Result<()> {
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            parent.handle.as_raw_fd(),
            leaf.as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(())
        } else {
            Err(Error::CleanupFailed)
        };
    }
    if metadata.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || metadata.st_uid != uid
        || metadata.st_gid != gid
        || metadata.st_nlink != 1
        || metadata.st_mode as u32 & 0o777 != SOCKET_MODE
    {
        return Err(Error::CleanupFailed);
    }
    let expected = FileIdentity {
        device: metadata.st_dev as u64,
        inode: metadata.st_ino as u64,
    };
    unlink_if_identity(parent, leaf, uid, gid, Some(expected))
}

fn unlink_if_identity(
    parent: &PinnedDirectory,
    leaf: &CString,
    uid: u32,
    gid: u32,
    expected: Option<FileIdentity>,
) -> Result<()> {
    parent.validate()?;
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            parent.handle.as_raw_fd(),
            leaf.as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(())
        } else {
            Err(Error::CleanupFailed)
        };
    }
    if metadata.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || metadata.st_uid != uid
        || metadata.st_gid != gid
        || metadata.st_nlink != 1
        || metadata.st_mode as u32 & 0o777 != SOCKET_MODE
        || expected.is_some_and(|identity| {
            identity.device != metadata.st_dev as u64 || identity.inode != metadata.st_ino as u64
        })
    {
        return Err(Error::CleanupFailed);
    }
    if unsafe { libc::unlinkat(parent.handle.as_raw_fd(), leaf.as_ptr(), 0) } != 0
        || unsafe { libc::fsync(parent.handle.as_raw_fd()) } != 0
    {
        return Err(Error::CleanupFailed);
    }
    Ok(())
}

fn set_cloexec(fd: libc::c_int) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0 {
        return Err(Error::CleanupFailed);
    }
    Ok(())
}

fn set_nonblocking(fd: libc::c_int) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        return Err(Error::CleanupFailed);
    }
    Ok(())
}

fn cstring(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| Error::InvalidArgument)
}
