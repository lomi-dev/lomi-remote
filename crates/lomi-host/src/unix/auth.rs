//! Host-owned credential worker. Only this thread opens the selected provider.
use super::owner_domain::{Error as DomainError, Operation as OwnerOperation};
use super::shared_owner::{
    AuthSelectionSnapshot, AuthStatusSnapshot, Error as OwnerError, SharedOwner,
};
use super::*;
use lomi_host_auth::{Config, HostAuth, RetainedRevocationAcknowledgement, Status};
use lomi_host_http::{PollOutcome, Transport};
use lomi_platform::secrets::{self, SecretStorage, Selection};
use lomi_remote_protocol::{
    DecimalU64, HostEnrollmentRevocationAckParams, HostEnrollmentRevocationAckResult, OperationId,
    ipc::LocalAuthConfiguration,
};
use std::sync::mpsc::{self, SyncSender};
use std::time::{SystemTime, UNIX_EPOCH};
#[path = "channel.rs"]
pub(super) mod channel;
#[path = "cloud.rs"]
pub(super) mod cloud;

#[path = "remote_ingress.rs"]
mod remote_ingress;

#[cfg(any(unix, windows))]
pub(super) use cloud::OwnedNormalPublicationObservation;

#[cfg(any(unix, windows))]
pub(super) use cloud::{
    NormalPublicationDriver, NormalPublicationObservation, NormalPublicationOriginError,
};
#[path = "peer.rs"]
pub(super) mod peer;
#[path = "remote_connection.rs"]
pub(super) mod remote_connection;

fn owner_local_error(error: OwnerError) -> LocalError {
    match error {
        OwnerError::Store(error) => store_error(error),
        _ => LocalError::Unavailable,
    }
}
fn owner_busy(error: &OwnerError) -> bool {
    matches!(
        error,
        OwnerError::Domain(DomainError::Busy) | OwnerError::Store(StoreError::Busy)
    )
}
// LoginStart reads a config/generation pair before admitting its one writer.
// If either snapshot is contended, retry the pair under the SAME operation so
// no stale config is combined with a later generation. The closure returns only
// owned snapshots; SharedOwner has dropped both guards before this wait.
fn login_start_snapshot(
    operation: &OwnerOperation<'_>,
    mut read_pair: impl FnMut() -> Result<(AuthSelectionSnapshot, AuthStatusSnapshot), OwnerError>,
) -> Result<(AuthSelectionSnapshot, AuthStatusSnapshot), LocalError> {
    loop {
        operation.check().map_err(|_| LocalError::Unavailable)?;
        match read_pair() {
            Ok(snapshot) => return Ok(snapshot),
            Err(error) if owner_busy(&error) => {
                let remaining = operation
                    .deadline()
                    .saturating_duration_since(std::time::Instant::now());
                let wait = remaining.min(Duration::from_millis(10));
                if !wait.is_zero() {
                    std::thread::park_timeout(wait);
                }
            }
            Err(error) => return Err(owner_local_error(error)),
        }
    }
}
// Local status reads can briefly contend with another OwnerDomain or Store
// turn. Retry only that typed Domain contention under the same request
// operation; this keeps the original deadline and cancellation latch intact.
fn read_owner_status_with_busy_retry<T>(
    operation: &OwnerOperation<'_>,
    read: impl FnMut() -> Result<T, OwnerError>,
) -> Result<T, LocalError> {
    read_owner_status_with_busy_retry_and_wait(operation, read, std::thread::park_timeout)
}

fn read_owner_status_with_busy_retry_and_wait<T>(
    operation: &OwnerOperation<'_>,
    mut read: impl FnMut() -> Result<T, OwnerError>,
    mut wait: impl FnMut(Duration),
) -> Result<T, LocalError> {
    loop {
        operation.check().map_err(|_| LocalError::Unavailable)?;
        match read() {
            Ok(value) => return Ok(value),
            Err(OwnerError::Domain(DomainError::Busy)) => {
                let remaining = operation
                    .deadline()
                    .saturating_duration_since(std::time::Instant::now());
                let delay = remaining.min(Duration::from_millis(10));
                if !delay.is_zero() {
                    wait(delay);
                }
            }
            Err(error) => return Err(owner_local_error(error)),
        }
    }
}

// Retry only typed read contention, outside both owner guards. Never repeat a
// provider/effect stage, admit another operation, or turn ordinary Busy into a
// permanent authorization failure.
macro_rules! worker_read {
    ($runtime:expr, $read:expr) => {{
        let runtime = $runtime;
        loop {
            if let Err(error) = runtime.check() {
                break Err(error);
            }
            match $read {
                Ok(value) => break Ok(value),
                Err(error) if owner_busy(&error) => {
                    if let Err(error) = runtime.busy() {
                        break Err(error);
                    }
                }
                Err(error) => break Err(StepError::from(error)),
            }
        }
    }};
}
macro_rules! commit_local_turn {
    ($turn:expr, $operation:expr) => {{
        loop {
            $operation.check().map_err(|_| LocalError::Unavailable)?;
            match $turn.try_commit() {
                Err(error) if owner_busy(&error) => {
                    std::thread::park_timeout(Duration::from_millis(10))
                }
                result => break result.map_err(owner_local_error),
            }
        }
    }};
}
macro_rules! commit_worker_turn {
    ($turn:expr, $runtime:expr) => {{
        loop {
            if $runtime.check().is_err() {
                break Err(OwnerError::Domain(DomainError::Stale));
            }
            match $turn.try_commit() {
                Err(error) if owner_busy(&error) => {
                    if $runtime.busy().is_err() {
                        break Err(OwnerError::Domain(DomainError::Stale));
                    }
                }
                result => break result,
            }
        }
    }};
}

#[derive(Clone)]
pub(super) struct Handle {
    owner: Arc<SharedOwner>,
    wake: SyncSender<Command>,
    state: Arc<Mutex<View>>,
    retry_requested: Arc<AtomicBool>,
    gate: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    #[cfg(any(unix, windows))]
    public_setup: Option<Arc<super::public_configuration::PublicSetup>>,
}
enum Command {
    Wake(OperationId),
    Configure,
    Logout,
}
struct View {
    status: LocalLoginStatus,
    presentation: Option<LocalLoginPresentation>,
}
fn initial() -> View {
    View {
        status: LocalLoginStatus {
            phase: LocalAuthPhase::Unconfigured,
            storage: LocalAuthStorage::Unconfigured,
            network: LocalAuthNetwork::Idle,
            generation: DecimalU64(0),
            locked: true,
            pending_cloud_revoke: false,
            operation_id: None,
            access_expires_at: None,
            refresh_at: None,
        },
        presentation: None,
    }
}

pub(super) fn configuration(
    identity: &lomi_host_store::Identity,
    config: &LocalAuthConfiguration,
) -> Result<Config, LocalError> {
    config.validate().map_err(|_| LocalError::InvalidArgument)?;
    match config.provider {
        #[cfg(target_os = "linux")]
        LocalAuthProvider::LinuxSecretService => {}
        #[cfg(unix)]
        LocalAuthProvider::ProtectedFile => {}
        #[cfg(target_os = "macos")]
        LocalAuthProvider::MacOsKeychain => {
            let path = Path::new(
                config
                    .keychain_path
                    .as_ref()
                    .ok_or(LocalError::InvalidArgument)?
                    .as_str(),
            );
            if !path.is_absolute()
                || path.canonicalize().ok().as_deref() != Some(path)
                || !path.is_file()
            {
                return Err(LocalError::InvalidArgument);
            }
        }
        #[cfg(windows)]
        LocalAuthProvider::WindowsDpapi => {}
        _ => return Err(LocalError::InvalidArgument),
    }
    let identity = Config::new(
        identity.host_id,
        identity.profile_id,
        config.origin.as_str().to_owned(),
        config
            .client_id
            .as_str()
            .to_owned()
            .try_into()
            .map_err(|_| LocalError::InvalidArgument)?,
    )
    .map_err(|_| LocalError::InvalidArgument)?;
    if let Some(origin) = &config.remote_api_origin {
        lomi_host_http::RemoteApiOrigin::new(&identity, origin.as_str().to_owned())
            .map_err(|_| LocalError::InvalidArgument)?;
    }
    Ok(identity)
}
impl Handle {
    #[cfg(any(unix, windows))]
    fn configure_public(
        &self,
        setup: &super::public_configuration::PublicSetup,
        operation: &OwnerOperation<'_>,
        config: &LocalAuthConfiguration,
    ) -> Result<LocalResult, LocalError> {
        // Validation can perform filesystem IO, hence runs after the owned
        // identity snapshot has released Domain/Store and before pending intent.
        let identity = self.owner.identity(operation).map_err(owner_local_error)?;
        configuration(&identity, config)?;
        let _request = loop {
            operation.check().map_err(|_| LocalError::Unavailable)?;
            match setup.request.try_lock() {
                Ok(guard) => break guard,
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::park_timeout(Duration::from_millis(10))
                }
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(LocalError::Unavailable),
            }
        };
        let mut turn = self
            .owner
            .begin_public_configuration(operation, config.clone())
            .map_err(owner_local_error)?;
        setup.pending.store(true, Ordering::Release);
        if let Ok(mut view) = self.state.lock() {
            view.presentation = None;
        }
        self.paused.store(true, Ordering::Release);
        self.gate.store(true, Ordering::Release);
        // The announcement precedes IO exclusion. Logout uses neither request
        // nor IO and can persist its fence while this writer waits for IO.
        let _exclusive = loop {
            operation.check().map_err(|_| LocalError::Unavailable)?;
            match setup.io.try_write() {
                Ok(guard) => break guard,
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::park_timeout(Duration::from_millis(10))
                }
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(LocalError::Unavailable),
            }
        };
        loop {
            operation.check().map_err(|_| LocalError::Unavailable)?;
            match setup.configure_owned(&mut turn) {
                Ok(()) => break,
                Err(LocalError::Unavailable) if turn.is_pending() => {
                    std::thread::park_timeout(Duration::from_millis(10));
                }
                Err(error) => {
                    set_failed(&self.state, LocalAuthStorage::Unavailable, &self.gate);
                    return Err(error);
                }
            }
        }
        setup.pending.store(false, Ordering::Release);
        self.paused.store(false, Ordering::Release);
        self.retry_requested.store(true, Ordering::Release);
        let _ = self.wake.try_send(Command::Configure);
        Ok(LocalResult::AuthConfigured {})
    }
    pub(super) fn is_authorized(&self, operation: &OwnerOperation<'_>) -> bool {
        #[cfg(any(unix, windows))]
        if self
            .public_setup
            .as_ref()
            .is_some_and(|setup| setup.pending.load(Ordering::Acquire))
        {
            return false;
        }
        !self.gate.load(Ordering::Acquire)
            && !self.paused.load(Ordering::Acquire)
            && self
                .owner
                .remote_authorization(operation)
                .is_ok_and(|state| !state.locked && !state.pending_cloud_revoke)
    }
    pub(super) fn dispatch(
        &self,
        operation: &OwnerOperation<'_>,
        call: LocalCall,
    ) -> Result<LocalResult, LocalError> {
        match call {
            LocalCall::AuthConfigure(params) => {
                #[cfg(any(unix, windows))]
                if let Some(setup) = &self.public_setup {
                    return self.configure_public(setup, operation, &params.configuration);
                }
                // Public file configuration is Unix-only. Do not silently use
                // the legacy database-only writer on another platform.
                Err(LocalError::Unavailable)
            }
            LocalCall::LoginStart(params) => {
                #[cfg(any(unix, windows))]
                if self
                    .public_setup
                    .as_ref()
                    .is_some_and(|s| s.pending.load(Ordering::Acquire))
                {
                    return Err(LocalError::Unavailable);
                }
                let (selected, status) = login_start_snapshot(operation, || {
                    Ok((
                        self.owner.auth_selection(operation)?,
                        self.owner.auth_status(operation)?,
                    ))
                })?;
                let config = selected.configuration.ok_or(LocalError::InvalidArgument)?;
                configuration(&selected.identity, &config)?;
                let generation = status.authorization.generation;
                let mut turn = self
                    .owner
                    .begin_login(operation, params.operation_id, config, generation)
                    .map_err(owner_local_error)?;
                let intent = commit_local_turn!(turn, operation)?;
                self.retry_requested.store(true, Ordering::Release);
                let _ = self.wake.try_send(Command::Wake(intent.operation_id));
                Ok(LocalResult::LoginAccepted(LocalLoginAccepted {
                    operation_id: intent.operation_id,
                    generation: DecimalU64(intent.generation),
                }))
            }
            LocalCall::Logout(_) => {
                self.gate.store(true, Ordering::Release);
                let outcome = self
                    .owner
                    .begin_local_logout(operation)
                    .map_err(owner_local_error)
                    .and_then(|mut turn| commit_local_turn!(turn, operation));
                let state = match outcome {
                    Ok(state) => state,
                    Err(error) => {
                        self.retry_requested.store(false, Ordering::Release);
                        self.paused.store(true, Ordering::Release);
                        set_failed(&self.state, LocalAuthStorage::Unavailable, &self.gate);
                        return Err(error);
                    }
                };
                self.retry_requested.store(true, Ordering::Release);
                let _ = self.wake.try_send(Command::Logout);
                let mut view = self.state.lock().map_err(|_| LocalError::Unavailable)?;
                view.presentation = None;
                view.status.phase = LocalAuthPhase::PendingRevoke;
                view.status.generation = DecimalU64(state.generation);
                view.status.locked = true;
                view.status.pending_cloud_revoke = true;
                view.status.operation_id = None;
                Ok(LocalResult::LoginStatus(view.status.clone()))
            }
            LocalCall::LoginStatus {} | LocalCall::LoginPresentation {} => {
                let snapshot = read_owner_status_with_busy_retry(operation, || {
                    self.owner.auth_status(operation)
                })?;
                let state = snapshot.authorization;
                let intent = snapshot.intent;
                let deferred_intent = snapshot.deferred_intent;
                let view = self.state.lock().map_err(|_| LocalError::Unavailable)?;
                if matches!(call, LocalCall::LoginPresentation {}) {
                    if state.pending_cloud_revoke
                        || intent.is_none()
                        || view.status.generation.0 != state.generation
                        || view.status.operation_id != intent.map(|i| i.operation_id)
                    {
                        return Err(LocalError::Conflict);
                    }
                    return view
                        .presentation
                        .clone()
                        .map(LocalResult::LoginPresentation)
                        .ok_or(LocalError::Unavailable);
                }
                let mut status = view.status.clone();
                status.generation = DecimalU64(state.generation);
                status.locked = !self.is_authorized(operation);
                status.pending_cloud_revoke = state.pending_cloud_revoke;
                status.operation_id = if state.pending_cloud_revoke {
                    deferred_intent.map(|i| i.operation_id)
                } else {
                    intent.map(|i| i.operation_id)
                };
                if state.pending_cloud_revoke {
                    status.phase = LocalAuthPhase::PendingRevoke;
                } else if state.locked && status.phase == LocalAuthPhase::Ready {
                    status.phase = LocalAuthPhase::Locked;
                }
                Ok(LocalResult::LoginStatus(status))
            }
            _ => Err(LocalError::InvalidArgument),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DomainError, OwnerError, OwnerOperation, read_owner_status_with_busy_retry,
        read_owner_status_with_busy_retry_and_wait,
    };
    use std::{
        sync::atomic::{AtomicBool, Ordering},
        time::{Duration, Instant},
    };

    #[test]
    fn status_read_retries_typed_domain_busy_under_the_same_operation() {
        let cancelled = AtomicBool::new(false);
        let operation = OwnerOperation::new(Instant::now() + Duration::from_secs(1), &cancelled);
        let mut attempts = 0;

        let value = read_owner_status_with_busy_retry(&operation, || {
            attempts += 1;
            if attempts < 3 {
                Err(OwnerError::Domain(DomainError::Busy))
            } else {
                Ok(17)
            }
        })
        .unwrap();

        assert_eq!(value, 17);
        assert_eq!(attempts, 3);
    }

    #[test]
    fn persistent_status_contention_stops_at_the_request_deadline() {
        let cancelled = AtomicBool::new(false);
        let operation = OwnerOperation::new(Instant::now() + Duration::from_millis(25), &cancelled);
        let mut attempts = 0;

        let result = read_owner_status_with_busy_retry(&operation, || {
            attempts += 1;
            Err::<(), _>(OwnerError::Domain(DomainError::Busy))
        });

        assert!(result.is_err());
        assert!(attempts > 0);
    }

    #[test]
    fn status_retry_honors_cancellation_and_does_not_retry_hard_errors() {
        let cancelled = AtomicBool::new(false);
        let operation = OwnerOperation::new(Instant::now() + Duration::from_secs(1), &cancelled);
        let mut attempts = 0;

        let cancelled_result = read_owner_status_with_busy_retry_and_wait(
            &operation,
            || {
                attempts += 1;
                Err::<(), _>(OwnerError::Domain(DomainError::Busy))
            },
            |_| cancelled.store(true, Ordering::SeqCst),
        );

        assert!(cancelled_result.is_err());
        assert_eq!(attempts, 1);

        cancelled.store(false, Ordering::SeqCst);
        let hard_error_operation =
            OwnerOperation::new(Instant::now() + Duration::from_secs(1), &cancelled);
        let mut hard_error_attempts = 0;
        let hard_error = read_owner_status_with_busy_retry(&hard_error_operation, || {
            hard_error_attempts += 1;
            Err::<(), _>(OwnerError::Domain(DomainError::Poisoned))
        });

        assert!(hard_error.is_err());
        assert_eq!(hard_error_attempts, 1);
    }
}

pub(super) fn start(
    endpoint: Arc<OwnerEndpoint>,
    owner: Arc<SharedOwner>,
    stopping: Arc<AtomicBool>,
    coordinator: std::sync::Weak<super::Coordinator>,
) -> (Handle, thread::JoinHandle<()>) {
    start_inner(endpoint, owner, stopping, coordinator)
}

fn start_inner(
    endpoint: Arc<OwnerEndpoint>,
    owner: Arc<SharedOwner>,
    stopping: Arc<AtomicBool>,
    coordinator: std::sync::Weak<super::Coordinator>,
) -> (Handle, thread::JoinHandle<()>) {
    let (wake, receiver) = mpsc::sync_channel(8);
    let initial_view = initial();
    let state = Arc::new(Mutex::new(initial_view));
    let retry_requested = Arc::new(AtomicBool::new(false));
    let gate = Arc::new(AtomicBool::new(true));
    let paused = Arc::new(AtomicBool::new(false));
    #[cfg(any(unix, windows))]
    let public_setup = Arc::new(super::public_configuration::PublicSetup::new(
        endpoint.clone(),
    ));
    let handle = Handle {
        owner: owner.clone(),
        wake,
        state: state.clone(),
        retry_requested: retry_requested.clone(),
        gate: gate.clone(),
        paused: paused.clone(),
        #[cfg(any(unix, windows))]
        public_setup: Some(public_setup.clone()),
    };
    let worker = thread::spawn(move || {
        let anchor = Instant::now();
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut explicit_retry = false;
        while !stopping.load(Ordering::Acquire) {
            if explicit_retry && !await_explicit_retry(&receiver, &stopping, &retry_requested) {
                return;
            }
            explicit_retry = false;
            #[cfg(any(unix, windows))]
            let _public_io = match public_setup.enter_owned(&paused) {
                Ok(Some(guard)) => guard,
                Ok(None) => {
                    let _ = receiver.recv_timeout(Duration::from_millis(250));
                    continue;
                }
                Err(()) => {
                    set_failed(&state, LocalAuthStorage::Unavailable, &gate);
                    return;
                }
            };
            #[cfg(not(any(unix, windows)))]
            paused.store(false, Ordering::Release);
            retry_requested.store(false, Ordering::Release);
            let operation =
                OwnerOperation::new(Instant::now() + Duration::from_secs(60), &stopping);
            let aborted = std::cell::Cell::new(false);
            let runtime = Runtime {
                aborted: &aborted,
                owner: &owner,
                operation: &operation,
                #[cfg(any(unix, windows))]
                public_io: &_public_io,
                state: &state,
                stopping: &stopping,
                receiver: &receiver,
                retry_requested: &retry_requested,
                gate: &gate,
                paused: &paused,
                base: wall.saturating_add(anchor.elapsed().as_secs()),
                anchor: Instant::now(),
            };
            let base = match observed(runtime) {
                Ok(base) => base,
                Err(_) => {
                    set_failed(&state, LocalAuthStorage::Unavailable, &gate);
                    explicit_retry = true;
                    continue;
                }
            };
            let attempt_anchor = Instant::now();
            let runtime = Runtime {
                base,
                anchor: attempt_anchor,
                ..runtime
            };
            let selected = worker_read!(runtime, owner.auth_selection(&operation))
                .map_err(|_| ())
                .and_then(|snapshot| {
                    snapshot
                        .configuration
                        .map(|c| {
                            configuration(&snapshot.identity, &c)
                                .map(|trusted| (c, trusted))
                                .map_err(|_| ())
                        })
                        .transpose()
                });
            let selected = match selected {
                Ok(value) => value,
                Err(()) => {
                    suspend(runtime);
                    set_failed(&state, LocalAuthStorage::Unavailable, &gate);
                    explicit_retry = true;
                    continue;
                }
            };
            if let Some((selected, trusted)) = selected {
                if runtime.check().is_err() {
                    continue;
                }
                let provider: Result<Box<dyn SecretStorage + '_>, secrets::Error> = match selected
                    .provider
                {
                    #[cfg(target_os = "linux")]
                    LocalAuthProvider::LinuxSecretService => {
                        lomi_platform::secret_service::SecretService::open(
                            endpoint.profile(),
                            Selection::SecretService,
                            endpoint.discovery().profile_id,
                        )
                        .map(|p| Box::new(p) as Box<dyn SecretStorage>)
                    }
                    #[cfg(unix)]
                    LocalAuthProvider::ProtectedFile => platform::secrets::ProtectedFile::open(
                        endpoint.profile(),
                        Selection::ProtectedFile(
                            secrets::ProtectedFileAcknowledgement::OsPermissionsOnly,
                        ),
                    )
                    .map(|p| Box::new(p) as Box<dyn SecretStorage>),
                    #[cfg(target_os = "macos")]
                    LocalAuthProvider::MacOsKeychain => platform::keychain::MacOsKeychain::open(
                        endpoint.profile(),
                        Selection::MacOsKeychain,
                        endpoint.discovery().profile_id,
                        Path::new(selected.keychain_path.as_ref().unwrap().as_str()),
                    )
                    .map(|p| Box::new(p) as Box<dyn SecretStorage>),
                    #[cfg(windows)]
                    LocalAuthProvider::WindowsDpapi => platform::secrets::WindowsDpapi::open(
                        endpoint.profile(),
                        Selection::WindowsDpapi,
                    )
                    .map(|p| Box::new(p) as Box<dyn SecretStorage>),
                    _ => Err(secrets::Error::Unavailable),
                };
                match provider {
                    Ok(mut provider) => {
                        if runtime.check().is_err() {
                            continue;
                        }
                        let now = base.saturating_add(attempt_anchor.elapsed().as_secs());
                        match HostAuth::open(provider.as_mut(), trusted.clone(), now) {
                            Ok(mut auth) => {
                                if runtime.check().is_err() {
                                    continue;
                                }
                                if !qualify_cloud_history(runtime, auth.status()) {
                                    suspend(runtime);
                                    set_failed(&state, LocalAuthStorage::Unavailable, &gate);
                                    explicit_retry = true;
                                    continue;
                                }
                                if let Ok(transport) = Transport::new(&trusted) {
                                    let apis = InjectedApis {
                                        pairing: None,
                                        channel: None,
                                        enabled: true,
                                        channels_enabled: true,
                                    };
                                    run_with_apis_and_coordinator(
                                        &mut auth,
                                        &transport,
                                        &trusted,
                                        Some(&selected),
                                        runtime,
                                        apis,
                                        coordinator.clone(),
                                    );
                                    explicit_retry = true;
                                } else {
                                    set_failed(&state, LocalAuthStorage::Available, &gate);
                                }
                            }
                            Err(error) => {
                                suspend(runtime);
                                auth_failed(&state, error, &gate);
                                explicit_retry = true;
                            }
                        }
                    }
                    Err(error) => {
                        suspend(runtime);
                        set_failed(&state, storage(error.state()), &gate);
                    }
                }
            }
            if stopping.load(Ordering::Acquire) {
                break;
            }
            if explicit_retry {
                continue;
            }
            // A locked/unavailable selected provider never selects a replacement.
            let _ = receiver.recv_timeout(Duration::from_secs(1));
        }
    });
    (handle, worker)
}
fn qualify_cloud_history(runtime: Runtime<'_>, status: Status) -> bool {
    let Ok(history) = worker_read!(runtime, runtime.owner.auth_history(runtime.operation)) else {
        return false;
    };
    match status {
        Status::ExchangePrepared | Status::Unconfirmed | Status::Ready | Status::Rotating => {
            mark_cloud_possible(runtime, history.authorization.generation).is_ok()
        }
        Status::Revoked => true,
        _ => history.cloud_may_exist == Some(false),
    }
}
fn mark_cloud_possible(runtime: Runtime<'_>, generation: u64) -> Result<(), StepError> {
    let mut turn = runtime
        .owner
        .begin_mark_cloud_authorization_possible(runtime.operation, generation)?;
    commit_worker_turn!(turn, runtime).map_err(StepError::from)
}
fn await_explicit_retry(
    receiver: &mpsc::Receiver<Command>,
    stopping: &AtomicBool,
    retry_requested: &AtomicBool,
) -> bool {
    // Never automatically repeat an uncertain publication. A fresh explicit
    // login/logout command permits reopening and inspecting the same provider.
    loop {
        if retry_requested.load(Ordering::Acquire) {
            return true;
        }
        match receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(Command::Wake(_) | Command::Logout | Command::Configure)
            | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return false,
        }
    }
    false
}
fn suspend(runtime: Runtime<'_>) {
    runtime.gate.store(true, Ordering::Release);
    if let Ok(state) = worker_read!(
        runtime,
        runtime.owner.authorization_state(runtime.operation)
    ) && !state.locked
        && let Ok(mut turn) = runtime
            .owner
            .begin_suspend_authorization(runtime.operation, state.generation)
    {
        let _ = commit_worker_turn!(turn, runtime);
    }
}
fn storage(value: secrets::StorageState) -> LocalAuthStorage {
    match value {
        secrets::StorageState::Available => LocalAuthStorage::Available,
        secrets::StorageState::Locked => LocalAuthStorage::Locked,
        secrets::StorageState::Unconfigured => LocalAuthStorage::Unconfigured,
        secrets::StorageState::Unavailable => LocalAuthStorage::Unavailable,
    }
}
fn set_failed(state: &Mutex<View>, storage: LocalAuthStorage, gate: &AtomicBool) {
    gate.store(true, Ordering::Release);
    if let Ok(mut view) = state.lock() {
        view.status.storage = storage;
        view.status.phase = LocalAuthPhase::Unavailable;
        view.presentation = None;
    }
}
fn auth_failed(state: &Mutex<View>, error: lomi_host_auth::Error, gate: &AtomicBool) {
    set_failed(
        state,
        match error {
            lomi_host_auth::Error::Storage(e) => storage(e.state()),
            _ => LocalAuthStorage::Unavailable,
        },
        gate,
    );
}
fn current(runtime: Runtime<'_>, generation: u64) -> bool {
    worker_read!(
        runtime,
        runtime.owner.authorization_state(runtime.operation)
    )
    .is_ok_and(|s| s.generation == generation && !s.pending_cloud_revoke)
}
// Internal injection boundary: production always uses the concrete HTTPS transport.
pub(super) trait AuthTransport {
    fn revoke(
        &self,
        host: lomi_remote_protocol::HostId,
        request: &lomi_remote_protocol::HostRevokeParams,
        access: &lomi_remote_protocol::HostAccessCredential,
    ) -> Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error>;

    /// Older injected transports deny the new proof-only operation by default.
    /// A denial is never an acknowledgement and keeps the prior recovery path
    /// available for implementations that do not support this endpoint.
    fn revocation_ack(
        &self,
        _host: lomi_remote_protocol::HostId,
        _request: &lomi_remote_protocol::HostRevocationAckParams,
    ) -> Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error> {
        Err(lomi_host_http::Error::Remote(
            lomi_host_http::HostFailure::AuthRequired,
        ))
    }

    /// Older injected transports treat the historical enrollment proof route
    /// as absent, preserving the existing exchange/register fallback.
    fn enrollment_revocation_ack(
        &self,
        _host: lomi_remote_protocol::HostId,
        _request: &HostEnrollmentRevocationAckParams,
    ) -> Result<HostEnrollmentRevocationAckResult, lomi_host_http::Error> {
        Err(lomi_host_http::Error::Remote(
            lomi_host_http::HostFailure::ResourceNotFound,
        ))
    }

    fn initiate(
        &self,
        request: &lomi_remote_protocol::EnrollmentInitiateParams,
    ) -> Result<lomi_remote_protocol::EnrollmentInitiateResult, lomi_host_http::Error>;
    fn poll(
        &self,
        device: &lomi_remote_protocol::DeviceCode,
    ) -> Result<PollOutcome, lomi_host_http::Error>;
    fn exchange(
        &self,
        request: &lomi_remote_protocol::HostAuthorizationExchangeParams,
    ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error>;
    fn register(
        &self,
        request: &lomi_remote_protocol::HostRegisterParams,
        access: &lomi_remote_protocol::HostAccessCredential,
    ) -> Result<lomi_remote_protocol::HostRegisterResult, lomi_host_http::Error>;
    fn refresh(
        &self,
        request: &lomi_remote_protocol::HostAuthorizationRefreshParams,
    ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error>;
}
impl AuthTransport for Transport {
    fn revoke(
        &self,
        host: lomi_remote_protocol::HostId,
        request: &lomi_remote_protocol::HostRevokeParams,
        access: &lomi_remote_protocol::HostAccessCredential,
    ) -> Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error> {
        Transport::revoke(self, host, request, access)
    }

    fn revocation_ack(
        &self,
        host: lomi_remote_protocol::HostId,
        request: &lomi_remote_protocol::HostRevocationAckParams,
    ) -> Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error> {
        Transport::revocation_ack(self, host, request)
    }

    fn enrollment_revocation_ack(
        &self,
        host: lomi_remote_protocol::HostId,
        request: &HostEnrollmentRevocationAckParams,
    ) -> Result<HostEnrollmentRevocationAckResult, lomi_host_http::Error> {
        Transport::enrollment_revocation_ack(self, host, request)
    }

    fn initiate(
        &self,
        request: &lomi_remote_protocol::EnrollmentInitiateParams,
    ) -> Result<lomi_remote_protocol::EnrollmentInitiateResult, lomi_host_http::Error> {
        Transport::initiate(self, request)
    }
    fn poll(
        &self,
        device: &lomi_remote_protocol::DeviceCode,
    ) -> Result<PollOutcome, lomi_host_http::Error> {
        Transport::poll(self, device)
    }
    fn exchange(
        &self,
        request: &lomi_remote_protocol::HostAuthorizationExchangeParams,
    ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error> {
        Transport::exchange(self, request)
    }
    fn register(
        &self,
        request: &lomi_remote_protocol::HostRegisterParams,
        access: &lomi_remote_protocol::HostAccessCredential,
    ) -> Result<lomi_remote_protocol::HostRegisterResult, lomi_host_http::Error> {
        Transport::register(self, request, access)
    }
    fn refresh(
        &self,
        request: &lomi_remote_protocol::HostAuthorizationRefreshParams,
    ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error> {
        Transport::refresh(self, request)
    }
}
#[derive(Clone, Copy)]
pub(super) struct RuntimeWithOperation<'a, 'operation> {
    owner: &'a SharedOwner,
    operation: &'operation OwnerOperation<'a>,
    #[cfg(any(unix, windows))]
    public_io: &'a super::public_configuration::WorkerPublicIo<'a>,
    state: &'a Mutex<View>,
    stopping: &'a AtomicBool,
    receiver: &'a mpsc::Receiver<Command>,
    retry_requested: &'a AtomicBool,
    gate: &'a AtomicBool,
    paused: &'a AtomicBool,
    base: u64,
    anchor: Instant,
    aborted: &'operation std::cell::Cell<bool>,
}

type Runtime<'a> = RuntimeWithOperation<'a, 'a>;

impl<'a, 'operation> RuntimeWithOperation<'a, 'operation> {
    pub(super) fn with_operation<'next>(
        self,
        operation: &'next OwnerOperation<'a>,
        aborted: &'next std::cell::Cell<bool>,
    ) -> RuntimeWithOperation<'a, 'next> {
        self.with_operation_at(operation, aborted, self.base, self.anchor)
    }

    pub(super) fn with_operation_at<'next>(
        self,
        operation: &'next OwnerOperation<'a>,
        aborted: &'next std::cell::Cell<bool>,
        base: u64,
        anchor: Instant,
    ) -> RuntimeWithOperation<'a, 'next> {
        RuntimeWithOperation {
            owner: self.owner,
            operation,
            #[cfg(any(unix, windows))]
            public_io: self.public_io,
            state: self.state,
            stopping: self.stopping,
            receiver: self.receiver,
            retry_requested: self.retry_requested,
            gate: self.gate,
            paused: self.paused,
            base,
            anchor,
            aborted,
        }
    }

    pub(super) fn started_git_terminal_latches(
        self,
    ) -> owner_domain::StartedGitTerminalLatches<'a> {
        owner_domain::StartedGitTerminalLatches::from_runtime(
            self.gate,
            self.paused,
            self.stopping,
            &self.public_io.setup().pending,
        )
    }

    fn projected_time(self) -> u64 {
        self.base.saturating_add(self.anchor.elapsed().as_secs())
    }
    fn with_clock_floor(self, floor: u64) -> Self {
        if floor <= self.projected_time() {
            return self;
        }
        // This returns a fresh projection for the next handoff. It preserves
        // the same OwnerOperation and its monotonic deadline.
        Self {
            base: floor,
            anchor: Instant::now(),
            ..self
        }
    }
    fn check(self) -> Result<(), StepError> {
        if self.aborted.get() {
            return Err(StepError::Stale);
        }
        if self.operation.check().is_err() {
            self.aborted.set(true);
            return Err(StepError::Stale);
        }
        if self.stopping.load(Ordering::Acquire) || self.paused.load(Ordering::Acquire) {
            self.aborted.set(true);
            return Err(StepError::Stale);
        }
        #[cfg(any(unix, windows))]
        if self.public_io.setup().pending.load(Ordering::Acquire) {
            self.aborted.set(true);
            return Err(StepError::Stale);
        }
        Ok(())
    }
    /// Read-only check for whether queued ingress output can make progress on
    /// the next actor pass. The ingress stage still performs all authorization
    /// and per-fragment checks before disclosing data.
    fn ingress_can_advance(self) -> bool {
        !self.aborted.get()
            && !self.operation.cancellation_latch().load(Ordering::Acquire)
            && Instant::now() < self.operation.deadline()
            && !self.stopping.load(Ordering::Acquire)
            && !self.gate.load(Ordering::Acquire)
            && !self.paused.load(Ordering::Acquire)
            && !self.public_io.setup().pending.load(Ordering::Acquire)
    }
    fn busy(self) -> Result<(), StepError> {
        self.check()?;
        // Busy retains the same turn and original operation. Commands are left
        // queued so Configure/Logout dispatch follows dropping attempt and IO.
        std::thread::park_timeout(
            Duration::from_millis(10).min(
                self.operation
                    .deadline()
                    .saturating_duration_since(Instant::now()),
            ),
        );
        self.check()
    }
}
fn advance_clock_projection(
    runtime: Runtime<'_>,
    floor: u64,
    base: &mut u64,
    anchor: &mut Instant,
) {
    // Called only after a non-retained turn. Held continuations keep their
    // admission projection and fixed effect checkpoints.
    let fresh = runtime.with_clock_floor(floor);
    *base = fresh.base;
    *anchor = fresh.anchor;
}
#[cfg(any(unix, windows))]
fn ready_from_existing_worker(
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    runtime: Runtime<'_>,
    transport: &dyn AuthTransport,
) -> Result<(), StepError> {
    use super::shared_owner::{ConfiguredWorkerAttempt, WorkerReadyError};
    let retained_rotation = auth.status() == Status::Rotating;
    let now = runtime.projected_time();
    let retained_enrollment =
        auth.status() == Status::Unconfirmed && auth.enrollment_revocation_ack_request(now).is_ok();
    let map = |error| match error {
        WorkerReadyError::Provider(lomi_host_auth::Error::Expired) if retained_rotation => {
            StepError::ExpiredRotation
        }
        WorkerReadyError::Provider(lomi_host_auth::Error::Expired) if retained_enrollment => {
            StepError::ExpiredEnrollment
        }
        WorkerReadyError::Provider(error) => StepError::Auth(error),
        WorkerReadyError::Http(error) => StepError::Http(error),
        WorkerReadyError::Domain(_) | WorkerReadyError::Stale => StepError::Stale,
        WorkerReadyError::Store(_) => StepError::Auth(lomi_host_auth::Error::Sealed),
    };

    let attempt_result = ConfiguredWorkerAttempt::from_existing_worker(
        auth,
        runtime.public_io,
        runtime.gate,
        runtime.paused,
        runtime.base,
        runtime.anchor,
    );
    let mut attempt = attempt_result.map_err(map)?;
    let _ = transport;

    let turn_result = attempt.begin_ready(runtime.owner, runtime.operation);
    let mut turn = turn_result.map_err(map)?;
    let mut cleanup_until = None;
    loop {
        if runtime.check().is_err() {
            // Attenuation only. The retained turn must observe cancellation and
            // finish its own same-ticket preaccept abort, even after expiry.
            turn.notice_cancel();
            cleanup_until.get_or_insert_with(|| Instant::now() + Duration::from_secs(5));
        }
        let step_result = turn.try_step();
        match step_result {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(WorkerReadyError::Domain(DomainError::Busy)) => {
                // Runtime::busy would return before the typed abort can release
                // its original writer. This separate reserve authorizes only
                // failure cleanup; it never extends operation/HTTP authority.
                if turn.pending_abort_error().is_some() {
                    cleanup_until.get_or_insert_with(|| Instant::now() + Duration::from_secs(5));
                }
                let until = cleanup_until.unwrap_or_else(|| runtime.operation.deadline());
                if cleanup_until.is_some_and(|until| Instant::now() >= until) {
                    // A permanently unavailable lock remains conservatively
                    // fenced by the turn's Drop, rather than minting recovery.
                    let pending_error = turn.pending_abort_error();

                    return Err(pending_error.map(map).unwrap_or(StepError::Stale));
                }
                std::thread::park_timeout(
                    Duration::from_millis(10).min(until.saturating_duration_since(Instant::now())),
                );
            }
            Err(error) => return Err(map(error)),
        }
    }
}
impl From<OwnerError> for StepError {
    fn from(error: OwnerError) -> Self {
        match error {
            OwnerError::Store(StoreError::Fenced)
            | OwnerError::Domain(
                DomainError::Stale
                | DomainError::Cancelled
                | DomainError::Deadline
                | DomainError::Busy,
            ) => Self::Stale,
            _ => Self::Auth(lomi_host_auth::Error::Sealed),
        }
    }
}

struct InjectedApis<'a> {
    pairing: Option<&'a dyn peer::PeerApi>,
    channel: Option<&'a dyn channel::ChannelApi>,
    enabled: bool,
    channels_enabled: bool,
}
#[derive(Default)]
struct IdleScheduler {
    channel_next: bool,
}
impl IdleScheduler {
    fn select_channel(&mut self, channels_enabled: bool) -> bool {
        if !channels_enabled {
            return false;
        }
        let selected = self.channel_next;
        self.channel_next = !self.channel_next;
        selected
    }
}
// Retain the former publication wait behavior only for its cancellation tests.
// Production publication scheduling is owned by the Cloud worker.

// Admission management only. This identity cannot mint Ready or transfer any
// existing effect continuation. Renewal occurs only after every class settled.
struct WorkerOperationUnits<'a> {
    initial: &'a OwnerOperation<'a>,
    initial_aborted: &'a std::cell::Cell<bool>,
    next: Option<OwnerOperation<'a>>,
    next_aborted: std::cell::Cell<bool>,
    started: bool,
}
impl<'a> WorkerOperationUnits<'a> {
    fn new(initial: &'a OwnerOperation<'a>, aborted: &'a std::cell::Cell<bool>) -> Self {
        Self {
            initial,
            initial_aborted: aborted,
            next: None,
            next_aborted: std::cell::Cell::new(false),
            started: false,
        }
    }
    fn operation(&self) -> &OwnerOperation<'a> {
        self.next.as_ref().unwrap_or(self.initial)
    }
    fn aborted(&self) -> &std::cell::Cell<bool> {
        if self.next.is_some() {
            &self.next_aborted
        } else {
            self.initial_aborted
        }
    }
    fn admit_after_settlement(&mut self, stopping: &'a AtomicBool) {
        self.next = Some(OwnerOperation::new(
            Instant::now() + Duration::from_secs(60),
            stopping,
        ));
        self.next_aborted.set(false);
    }
}

fn run_with_apis_and_coordinator(
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    transport: &dyn AuthTransport,
    config: &Config,
    selected_configuration: Option<&LocalAuthConfiguration>,
    runtime: Runtime<'_>,
    apis: InjectedApis<'_>,
    coordinator: std::sync::Weak<super::Coordinator>,
) {
    run_with_apis_inner(
        auth,
        transport,
        config,
        selected_configuration,
        runtime,
        apis,
        coordinator,
    );
}

fn run_with_apis_inner(
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    transport: &dyn AuthTransport,
    config: &Config,
    selected_configuration: Option<&LocalAuthConfiguration>,
    runtime: Runtime<'_>,
    apis: InjectedApis<'_>,
    coordinator: std::sync::Weak<super::Coordinator>,
) {
    let mut ingress =
        remote_ingress::Registry::with_coordinator(runtime.stopping, coordinator.clone());
    let Runtime {
        owner,
        operation,
        #[cfg(any(unix, windows))]
            public_io: _,
        aborted: _,
        state,
        stopping,
        receiver,
        retry_requested,
        gate,
        paused,
        mut base,
        mut anchor,
    } = runtime;
    let mut was_active = match worker_read!(runtime, owner.auth_selection(operation)) {
        Ok(snapshot) => snapshot.verified_generation.is_some(),
        Err(_) => {
            set_failed(state, LocalAuthStorage::Unavailable, gate);
            return;
        }
    };
    let mut verified_generation = None;
    let mut cloud = cloud::Worker::default();
    let mut peer = peer::Worker::default();
    let mut channel = channel::Worker::default();
    let mut idle = IdleScheduler::default();
    let initial_runtime = runtime;
    let mut units = WorkerOperationUnits::new(runtime.operation, runtime.aborted);
    let mut immediate_ingress_pass = false;
    while !stopping.load(Ordering::Acquire) || ingress.has_active_git_writer() {
        let retained = cloud.has_retained_operation()
            || peer.has_retained_operation()
            || channel.has_retained_operation()
            || ingress.has_retained_operation();
        if units.started && !retained {
            cloud.finish_operation();
            units.admit_after_settlement(stopping);
        }
        units.started = true;
        let mut runtime =
            initial_runtime.with_operation_at(units.operation(), units.aborted(), base, anchor);
        let operation = runtime.operation;
        let wait = remote_ingress::actor_wait_duration(std::mem::take(&mut immediate_ingress_pass));
        match receiver.recv_timeout(wait) {
            Ok(Command::Wake(id)) => {
                let _ = id;
            }
            Ok(Command::Logout | Command::Configure) | Err(_) => {}
        }
        if stopping.load(Ordering::Acquire) {
            if ingress.has_active_git_writer() {
                ingress.cancel_started_git();
                let _ = ingress.advance_started_git(auth, runtime);
                continue;
            }
            break;
        }
        if paused.load(Ordering::Acquire) {
            if ingress.has_active_git_writer() {
                ingress.cancel_started_git();
                let _ = ingress.advance_started_git(auth, runtime);
                continue;
            }
            set_failed(state, LocalAuthStorage::Unavailable, gate);
            return;
        }
        // Consume earlier intent notifications before this attempt. A new
        // explicit request racing a failure remains visible even if try_send fails.
        retry_requested.store(false, Ordering::Release);
        let mut now = runtime.projected_time();
        if ingress.has_active_git_writer()
            && (operation.check().is_err() || runtime.check().is_err())
        {
            ingress.cancel_started_git();
            immediate_ingress_pass = ingress.advance_started_git(auth, runtime);
            continue;
        }
        if matches!(operation.check(), Err(DomainError::Deadline))
            && !stopping.load(Ordering::Acquire)
            && !paused.load(Ordering::Acquire)
            && !runtime.public_io.setup().pending.load(Ordering::Acquire)
        {
            // End the old unit, preserving every durable original intent/ID.
            // Closing the volatile gate forces a real Ready resume if a writer
            // attenuation occurred. No old continuation reaches the new unit.
            cloud.finish_operation();
            peer.discard_retained_operation();
            channel.discard_retained_operation();
            ingress.discard();
            gate.store(true, Ordering::Release);
            continue;
        }
        if runtime.check().is_err() {
            if ingress.has_active_git_writer() {
                ingress.cancel_started_git();
                immediate_ingress_pass = ingress.advance_started_git(auth, runtime);
                continue;
            }
            return;
        }
        // Retained effect scopes have their OWN fixed clock checkpoints. A
        // standalone Mutation writer here would stale their original admission.
        let snapshot = if ingress.has_active_git_writer() {
            match ingress.started_git_auth_status(owner) {
                Ok(Some(snapshot)) => Ok(snapshot),
                Err(error) if owner_busy(&error) => {
                    if runtime.busy().is_err() {
                        ingress.cancel_started_git();
                        immediate_ingress_pass = ingress.advance_started_git(auth, runtime);
                    }
                    continue;
                }
                Ok(None) | Err(_) => {
                    ingress.cancel_started_git();
                    immediate_ingress_pass = ingress.advance_started_git(auth, runtime);
                    continue;
                }
            }
        } else {
            (if retained { Ok(now) } else { observed(runtime) }).and_then(|floor| {
                now = floor;
                if !retained {
                    runtime = runtime.with_clock_floor(floor);
                    base = runtime.base;
                    anchor = runtime.anchor;
                }
                worker_read!(runtime, owner.auth_status(operation))
            })
        };
        let Ok(snapshot) = snapshot else {
            if matches!(operation.check(), Err(DomainError::Deadline)) {
                cloud.finish_operation();
                peer.discard_retained_operation();
                channel.discard_retained_operation();
                ingress.discard();
                gate.store(true, Ordering::Release);
                continue;
            }
            if let Ok(mut turn) = owner.begin_seal_authorization(operation) {
                let _ = commit_worker_turn!(turn, runtime);
            }
            set_failed(state, LocalAuthStorage::Unavailable, gate);
            return;
        };
        let fence = snapshot.authorization;
        let intent = snapshot.intent;
        let deferred_intent = snapshot.deferred_intent;
        if ingress.has_active_git_writer() {
            let Some(continuation) = ingress.started_git_continuation() else {
                ingress.cancel_started_git();
                immediate_ingress_pass = ingress.advance_started_git(auth, runtime);
                continue;
            };
            let deadlines = auth.credential_deadlines().ok();
            let active_valid = auth.status() == Status::Ready
                && !fence.locked
                && !fence.pending_cloud_revoke
                && fence.generation == continuation.runtime().scope.authorization_generation
                && intent.is_none()
                && !gate.load(Ordering::Acquire)
                && !runtime.public_io.setup().pending.load(Ordering::Acquire)
                && deadlines.is_some_and(|deadlines| {
                    now < deadlines.access_expires_at && now < deadlines.refresh_at
                });
            if !active_valid {
                ingress.cancel_started_git();
            }
            if fence.locked
                || fence.pending_cloud_revoke
                || fence.generation != continuation.runtime().scope.authorization_generation
            {
                ingress.discard_other_ingress_for_started_git();
            }
            immediate_ingress_pass = ingress.advance_started_git(auth, runtime);
            continue;
        }
        if verified_generation != Some(fence.generation) {
            if verified_generation.is_some() {
                was_active = false;
                cloud.finish_operation();
                peer.discard_retained_operation();
                channel.discard_retained_operation();
                ingress.discard();
            }
            verified_generation = Some(fence.generation);
        }
        if auth
            .credential_deadlines()
            .is_ok_and(|d| now >= d.access_expires_at)
            && !fence.locked
        {
            cloud.finish_operation();
            peer.discard_retained_operation();
            channel.discard_retained_operation();
            ingress.discard();
            gate.store(true, Ordering::Release);
            let outcome = owner
                .begin_suspend_authorization(operation, fence.generation)
                .and_then(|mut turn| commit_worker_turn!(turn, runtime));
            if !matches!(outcome, Ok(_) | Err(OwnerError::Store(StoreError::Fenced))) {
                set_failed(state, LocalAuthStorage::Unavailable, gate);
                return;
            }
        }

        let phase = match auth.status() {
            Status::Empty => LocalAuthPhase::Idle,
            Status::PendingInit => LocalAuthPhase::Initializing,
            Status::AwaitingApproval => LocalAuthPhase::AwaitingApproval,
            Status::Approved | Status::ExchangePrepared => LocalAuthPhase::Exchanging,
            Status::Unconfirmed => LocalAuthPhase::Registering,
            Status::Ready => LocalAuthPhase::Ready,
            Status::Rotating => LocalAuthPhase::Refreshing,
            Status::Revoked => LocalAuthPhase::Locked,
            Status::Sealed => LocalAuthPhase::Unavailable,
        };
        if let Ok(mut view) = state.lock() {
            view.status.phase = if fence.pending_cloud_revoke {
                LocalAuthPhase::PendingRevoke
            } else {
                phase
            };
            view.status.storage = LocalAuthStorage::Available;
            view.status.generation = DecimalU64(fence.generation);
            view.status.locked = fence.locked;
            view.status.pending_cloud_revoke = fence.pending_cloud_revoke;
            view.status.operation_id = if fence.pending_cloud_revoke {
                deferred_intent.map(|i| i.operation_id)
            } else {
                intent.map(|i| i.operation_id)
            };
            let deadlines = auth.credential_deadlines().ok();
            view.status.access_expires_at = deadlines.map(|d| DecimalU64(d.access_expires_at));
            view.status.refresh_at = deadlines.map(|d| DecimalU64(d.refresh_at));
            view.presentation = if fence.pending_cloud_revoke || intent.is_none() {
                None
            } else {
                auth.enrollment_presentation(now).ok().and_then(|p| {
                    Some(LocalLoginPresentation {
                        user_code: p.user_code,
                        verification_url: format!("{}/device", config.origin()).try_into().ok()?,
                        expires_at: DecimalU64(p.expires_at),
                        next_poll_at: DecimalU64(p.next_poll_at),
                    })
                })
            };
        }
        let diagnostic_status = state.lock().ok().map(|view| view.status.clone());
        if let (Some(coordinator), Some(status)) = (coordinator.upgrade(), diagnostic_status) {
            coordinator.observe_authentication(&status);
        }
        if !fence.pending_cloud_revoke && fence.locked && intent.is_none() && !was_active {
            continue;
        }
        let mut requested_immediate_ingress_pass = false;
        let result: Result<bool, StepError> = (|| {
            runtime.check()?;
            if fence.pending_cloud_revoke {
                ingress.discard();
                channel.discard_retained_operation();
                if cloud.logout_epoch_step(auth, config, runtime, fence.generation)? {
                    return Ok(false);
                }
                return revoke_step(auth, transport, config, runtime, fence.generation)
                    .map(|()| false);
            }
            match auth.status() {
                Status::Revoked if intent.is_some() => auth.restart_after_revocation(now)?,
                Status::Empty if intent.is_some() => auth.initialize()?,
                Status::PendingInit if intent.is_some() => {
                    network(state, LocalAuthNetwork::Working);
                    runtime.check()?;
                    let response = transport.initiate(&auth.init_request()?)?;
                    // Measure enrollment TTL conservatively from request start.
                    let floor = observed(runtime)?;
                    if !retained {
                        advance_clock_projection(runtime, floor, &mut base, &mut anchor);
                    }
                    if current(runtime, fence.generation) {
                        runtime.check()?;
                        auth.accept_initiation(response, now)?;
                    }
                }
                Status::AwaitingApproval if intent.is_some() => {
                    if auth.enrollment_presentation(now).is_err() {
                        auth.reset_expired_enrollment(now)?;
                        return Ok(false);
                    }
                    let device = match auth.device_poll_credential(now) {
                        Ok(device) => device,
                        Err(lomi_host_auth::Error::PollTooEarly) => return Ok(false),
                        Err(e) => return Err(e.into()),
                    };
                    network(state, LocalAuthNetwork::Working);
                    runtime.check()?;
                    let response = transport.poll(&device);
                    let response = response?;
                    now = observed(runtime)?;
                    if !retained {
                        advance_clock_projection(runtime, now, &mut base, &mut anchor);
                    }
                    if !current(runtime, fence.generation) {
                        return Ok(false);
                    }
                    match response {
                        PollOutcome::Approved {
                            bootstrap, context, ..
                        } => {
                            let result =
                                auth.accept_tls_approval(config.origin(), context, bootstrap, now);
                            result?;
                        }
                        PollOutcome::Pending => {}
                        PollOutcome::SlowDown | PollOutcome::RateLimited => {
                            auth.accept_tls_slow_down(config.origin(), now)?
                        }
                        PollOutcome::Expired => { /* Local durable expiry remains authoritative. */
                        }
                        PollOutcome::Denied => {
                            auth.reset_tls_denied_enrollment(config.origin(), now)?
                        }
                        PollOutcome::InvalidRequest | PollOutcome::InvalidGrant => {
                            return Err(StepError::Rejected);
                        }
                    }
                }
                Status::Approved if intent.is_some() => {
                    let prepared = auth.prepare_exchange(now);
                    match prepared {
                        Err(lomi_host_auth::Error::Expired) => {
                            auth.reset_expired_enrollment(now)?
                        }
                        result => result?,
                    }
                }
                Status::ExchangePrepared if intent.is_some() => {
                    mark_cloud_possible(runtime, fence.generation)?;
                    network(state, LocalAuthNetwork::Working);
                    runtime.check()?;
                    let request = normal_exchange_request(auth, now)?;
                    let response = transport.exchange(&request)?;
                    now = observed(runtime)?;
                    if !retained {
                        advance_clock_projection(runtime, now, &mut base, &mut anchor);
                    }
                    if current(runtime, fence.generation) {
                        runtime.check()?;
                        auth.accept_exchange(response, now)?;
                    }
                }
                Status::Unconfirmed if intent.is_some() => {
                    now = trusted_now(runtime)?;
                    let handoff = runtime.with_clock_floor(now);
                    if !retained {
                        base = handoff.base;
                        anchor = handoff.anchor;
                    }
                    ready_from_existing_worker(auth, handoff, transport)?;
                    was_active = true;
                }
                Status::Ready => {
                    if intent.is_some()
                        || fence.locked
                        || gate.load(Ordering::Acquire)
                        || auth.credential_deadlines()?.refresh_at <= now
                    {
                        ingress.discard();
                    } else {
                        // Preparation never pauses normal cloud/peer/channel
                        // priority. A later writer may stale this candidate;
                        // the next poll discards it without renewing provenance.
                        let expected_scope = cloud
                            .cached_eligibility()
                            .map(|eligibility| &eligibility.binding.scope);
                        let observation = runtime.owner.cloud_publication_fence_observation(
                            runtime.operation,
                            fence.generation,
                            expected_scope,
                        )?;
                        match observation {
                            super::shared_owner::CloudPublicationFenceObservation::CloseIngress => {
                                // A durable publication intent or a proven
                                // binding invalidation fences every live remote
                                // connection. A clear observation grants no
                                // eligibility; ordinary request gates remain
                                // authoritative below.
                                ingress.discard();
                            }
                            super::shared_owner::CloudPublicationFenceObservation::Clear => {
                                ingress.poll(auth, runtime, cloud.cached_eligibility());
                            }
                            super::shared_owner::CloudPublicationFenceObservation::Defer => {
                                // Store contention is a bounded pause. In
                                // particular, do not run Cloud's strict Domain
                                // observer while an ingress writer owns it.
                                return Ok(false);
                            }
                        }
                        if ingress.has_active_git_writer() {
                            // The retained Git writer owns the Domain ticket.
                            // Advance its finalization but defer Cloud/peer/
                            // channel readers until that ticket is released.
                            requested_immediate_ingress_pass =
                                ingress.advance(auth, runtime, cloud.cached_eligibility());
                            return Ok(requested_immediate_ingress_pass);
                        }
                    }
                    if intent.is_some()
                        || (was_active && (fence.locked || gate.load(Ordering::Acquire)))
                    {
                        ingress.discard();
                        channel.discard_retained_operation();
                        now = trusted_now(runtime)?;
                        let handoff = runtime.with_clock_floor(now);
                        if !retained {
                            base = handoff.base;
                            anchor = handoff.anchor;
                        }
                        ready_from_existing_worker(auth, handoff, transport)?;
                        was_active = true;
                    } else if intent.is_some()
                        || fence.locked
                        || gate.load(Ordering::Acquire)
                        || auth.credential_deadlines()?.refresh_at <= now
                    {
                        cloud.finish_operation();
                        peer.discard_retained_operation();
                        channel.discard_retained_operation();
                        ingress.discard();
                        auth.prepare_rotation(now)?;
                    } else if peer.has_retained_operation() {
                        let eligibility = cloud.cached_eligibility().ok_or(StepError::Stale)?;
                        peer.step(auth, config, runtime, eligibility, apis.pairing)?;
                    } else if channel.has_retained_operation() {
                        let eligibility = cloud.cached_eligibility().ok_or(StepError::Stale)?;
                        channel.step(auth, config, runtime, eligibility, apis.channel)?;
                        ingress.after_channel_step(&mut channel, auth, runtime, eligibility);
                    } else {
                        let outcome = cloud.step(auth, config, runtime, fence.generation)?;
                        if let cloud::StepOutcome::PeerEligible(eligibility) = outcome {
                            if apis.enabled {
                                // Exactly one class runs, even when its selected turn
                                // only prepares locally or waits for bounded backoff.
                                if idle.select_channel(apis.channels_enabled) {
                                    channel.step(
                                        auth,
                                        config,
                                        runtime,
                                        &eligibility,
                                        apis.channel,
                                    )?;
                                    ingress.after_channel_step(
                                        &mut channel,
                                        auth,
                                        runtime,
                                        &eligibility,
                                    );
                                } else {
                                    peer.step(auth, config, runtime, &eligibility, apis.pairing)?;
                                }
                            }
                        }
                    }
                    // Heartbeat/refresh/configuration work above keeps priority.
                    // The driver owns only socket/crypto/codecs and request state.
                    requested_immediate_ingress_pass =
                        ingress.advance(auth, runtime, cloud.cached_eligibility());
                }
                Status::Rotating => {
                    ingress.discard();
                    channel.discard_retained_operation();
                    now = trusted_now(runtime)?;
                    let handoff = runtime.with_clock_floor(now);
                    if !retained {
                        base = handoff.base;
                        anchor = handoff.anchor;
                    }
                    ready_from_existing_worker(auth, handoff, transport)?;
                    was_active = true;
                }
                _ => {}
            }
            Ok(requested_immediate_ingress_pass)
        })();
        match result {
            Err(StepError::Stale) => {
                immediate_ingress_pass = false;
                continue;
            }
            Ok(request_immediate) => {
                immediate_ingress_pass = request_immediate;
                network(state, LocalAuthNetwork::Available);
            }
            Err(error) if global_credential_auth_required(&error) => {
                immediate_ingress_pass = false;
                // A failure during logout is never a revoke acknowledgement and
                // must preserve the exact logout generation/recovery material.
                if fence.pending_cloud_revoke {
                    network(state, LocalAuthNetwork::Unavailable);
                    for _ in 0..4 {
                        if stopping.load(Ordering::Acquire) {
                            return;
                        }
                        let _ = receiver.recv_timeout(Duration::from_millis(250));
                    }
                    continue;
                }
                // Sample the durable high-water mark for the exact proof
                // check. This read does not change a retained scope or its
                // operation deadline.
                let now = match trusted_now(runtime) {
                    Ok(now) => now,
                    Err(StepError::Stale) => continue,
                    Err(_) => {
                        set_failed(state, LocalAuthStorage::Unavailable, gate);
                        return;
                    }
                };
                let registered_credential =
                    matches!(auth.status(), Status::Ready | Status::Rotating);
                let retained_enrollment_proof = enrollment_retirement_available(auth, now);
                let eligible = (registered_credential || retained_enrollment_proof)
                    && selected_configuration.is_some();
                if !eligible {
                    // Preserve the prior generic authority-rejection behavior
                    // for phases where there is no retained host credential to
                    // bind to the exact selected configuration.
                    gate.store(true, Ordering::Release);
                    let outcome = owner
                        .begin_authority_rejection(operation, fence.generation)
                        .and_then(|mut turn| commit_worker_turn!(turn, runtime));
                    if !matches!(outcome, Ok(_) | Err(OwnerError::Store(StoreError::Fenced))) {
                        set_failed(state, LocalAuthStorage::Unavailable, gate);
                        return;
                    }
                    if let Ok(mut view) = state.lock() {
                        view.presentation = None;
                    }
                    network(state, LocalAuthNetwork::Unavailable);
                    continue;
                }
                let selected_configuration =
                    selected_configuration.expect("eligible checked configuration");
                gate.store(true, Ordering::Release);
                let outcome = owner
                    .begin_credential_rejection(
                        operation,
                        fence.generation,
                        selected_configuration.clone(),
                    )
                    .and_then(|mut turn| commit_worker_turn!(turn, runtime));
                match outcome {
                    Ok(_) | Err(OwnerError::Store(StoreError::Fenced)) => {
                        if let Ok(mut view) = state.lock() {
                            view.presentation = None;
                        }
                        network(state, LocalAuthNetwork::Unavailable);
                    }
                    Err(OwnerError::Domain(
                        DomainError::Stale | DomainError::Cancelled | DomainError::Deadline,
                    )) => continue,
                    Err(_) => {
                        set_failed(state, LocalAuthStorage::Unavailable, gate);
                        return;
                    }
                }
            }
            Err(
                StepError::Http(lomi_host_http::Error::DataRemote(
                    lomi_host_http::DataFailure::ScopeDenied,
                ))
                | StepError::Rejected,
            ) => {
                immediate_ingress_pass = false;
                // Workspace/contract rejection keeps the existing generic
                // fence semantics; it is not credential-specific proof.
                if fence.pending_cloud_revoke {
                    network(state, LocalAuthNetwork::Unavailable);
                    for _ in 0..4 {
                        if stopping.load(Ordering::Acquire) {
                            return;
                        }
                        let _ = receiver.recv_timeout(Duration::from_millis(250));
                    }
                    continue;
                }
                gate.store(true, Ordering::Release);
                let outcome = owner
                    .begin_authority_rejection(operation, fence.generation)
                    .and_then(|mut turn| commit_worker_turn!(turn, runtime));
                if !matches!(outcome, Ok(_) | Err(OwnerError::Store(StoreError::Fenced))) {
                    set_failed(state, LocalAuthStorage::Unavailable, gate);
                    return;
                }
                if let Ok(mut view) = state.lock() {
                    view.presentation = None;
                }
                network(state, LocalAuthNetwork::Unavailable);
            }
            Err(StepError::ExpiredEnrollment) => {
                let now = match trusted_now(runtime) {
                    Ok(now) => now,
                    Err(StepError::Stale) => continue,
                    Err(_) => {
                        set_failed(state, LocalAuthStorage::Unavailable, gate);
                        return;
                    }
                };
                let retained_enrollment_proof = enrollment_retirement_available(auth, now);
                if fence.pending_cloud_revoke && retained_enrollment_proof {
                    network(state, LocalAuthNetwork::Unavailable);
                    let Some(selected_configuration) = selected_configuration else {
                        set_failed(state, LocalAuthStorage::Unavailable, gate);
                        return;
                    };
                    let retry_at = Instant::now() + Duration::from_secs(5);
                    match wait_pending_enrollment_reprobe(
                        runtime,
                        fence.generation,
                        selected_configuration,
                        deferred_intent,
                        retry_at,
                    ) {
                        Ok(_) | Err(StepError::Stale) => continue,
                        Err(_) => {
                            set_failed(state, LocalAuthStorage::Unavailable, gate);
                            return;
                        }
                    }
                }
                if !fence.pending_cloud_revoke
                    && intent.is_some()
                    && selected_configuration.is_some()
                    && retained_enrollment_proof
                {
                    let selected_configuration =
                        selected_configuration.expect("guard checked configuration");
                    gate.store(true, Ordering::Release);
                    let outcome = owner
                        .begin_credential_rejection(
                            operation,
                            fence.generation,
                            selected_configuration.clone(),
                        )
                        .and_then(|mut turn| commit_worker_turn!(turn, runtime));
                    match outcome {
                        Ok(_) | Err(OwnerError::Store(StoreError::Fenced)) => {
                            if let Ok(mut view) = state.lock() {
                                view.presentation = None;
                            }
                            network(state, LocalAuthNetwork::Unavailable);
                            continue;
                        }
                        Err(OwnerError::Domain(
                            DomainError::Stale | DomainError::Cancelled | DomainError::Deadline,
                        )) => continue,
                        Err(_) => {
                            set_failed(state, LocalAuthStorage::Unavailable, gate);
                            return;
                        }
                    }
                }
                suspend(runtime);
                auth_failed(state, lomi_host_auth::Error::Expired, gate);
                return;
            }
            Err(StepError::ExpiredRotation)
                if fence.pending_cloud_revoke && auth.status() == Status::Rotating =>
            {
                network(state, LocalAuthNetwork::Unavailable);
                let Some(selected_configuration) = selected_configuration else {
                    set_failed(state, LocalAuthStorage::Unavailable, gate);
                    return;
                };
                let retry_at = Instant::now() + Duration::from_secs(5);
                match wait_pending_rotation_reprobe(
                    runtime,
                    fence.generation,
                    selected_configuration,
                    deferred_intent,
                    retry_at,
                ) {
                    Ok(_) | Err(StepError::Stale) => continue,
                    Err(_) => {
                        set_failed(state, LocalAuthStorage::Unavailable, gate);
                        return;
                    }
                }
            }
            Err(StepError::ExpiredRotation)
                if !fence.pending_cloud_revoke
                    && intent.is_some()
                    && auth.status() == Status::Rotating
                    && selected_configuration.is_some() =>
            {
                let selected_configuration = selected_configuration.expect("guard checked config");
                gate.store(true, Ordering::Release);
                let outcome = owner
                    .begin_credential_rejection(
                        operation,
                        fence.generation,
                        selected_configuration.clone(),
                    )
                    .and_then(|mut turn| commit_worker_turn!(turn, runtime));
                match outcome {
                    Ok(_) | Err(OwnerError::Store(StoreError::Fenced)) => {
                        if let Ok(mut view) = state.lock() {
                            view.presentation = None;
                        }
                        network(state, LocalAuthNetwork::Unavailable);
                    }
                    Err(OwnerError::Domain(
                        DomainError::Stale | DomainError::Cancelled | DomainError::Deadline,
                    )) => continue,
                    Err(_) => {
                        set_failed(state, LocalAuthStorage::Unavailable, gate);
                        return;
                    }
                }
            }
            Err(StepError::ExpiredRotation) => {
                suspend(runtime);
                auth_failed(state, lomi_host_auth::Error::Expired, gate);
                return;
            }
            Err(StepError::Http(_)) => {
                network(state, LocalAuthNetwork::Unavailable);
                // Network outage keeps local terminals and durable operation intact.
                for _ in 0..4 {
                    if stopping.load(Ordering::Acquire) {
                        return;
                    }
                    let _ = receiver.recv_timeout(Duration::from_millis(250));
                }
            }
            Err(StepError::Auth(lomi_host_auth::Error::Expired))
                if matches!(auth.status(), Status::AwaitingApproval | Status::Approved) =>
            {
                // No exchange intent exists. Definite expiry may reset in place;
                // an expired server challenge before local enrollment expiry
                // leaves the reserved poll cadence intact until expiry/denial.
                match auth.reset_expired_enrollment(now) {
                    Ok(()) | Err(lomi_host_auth::Error::InvalidState) => {}
                    Err(error) => {
                        suspend(runtime);
                        auth_failed(state, error, gate);
                        return;
                    }
                }
            }
            Err(StepError::Auth(error)) => {
                suspend(runtime);
                auth_failed(state, error, gate);
                return;
            }
        }
    }
}
fn fresh_access(auth: &HostAuth<'_, dyn SecretStorage + '_>, now: u64) -> bool {
    auth.status() == Status::Ready
        && auth
            .credential_deadlines()
            .is_ok_and(|d| now < d.access_expires_at)
}
fn enrollment_retirement_available<S: SecretStorage + ?Sized>(
    auth: &HostAuth<'_, S>,
    now: u64,
) -> bool {
    matches!(
        auth.status(),
        Status::ExchangePrepared | Status::Unconfirmed
    ) && auth.enrollment_revocation_ack_request(now).is_ok()
}
fn normal_exchange_request(
    auth: &HostAuth<'_, dyn SecretStorage + '_>,
    now: u64,
) -> Result<lomi_remote_protocol::HostAuthorizationExchangeParams, StepError> {
    match auth.exchange_request(now) {
        Ok(request) => Ok(request),
        Err(lomi_host_auth::Error::Expired) if enrollment_retirement_available(auth, now) => {
            Err(StepError::ExpiredEnrollment)
        }
        Err(error) => Err(error.into()),
    }
}
fn normal_registration_request(
    auth: &HostAuth<'_, dyn SecretStorage + '_>,
    now: u64,
) -> Result<
    (
        lomi_remote_protocol::HostAccessCredential,
        lomi_remote_protocol::HostRegisterParams,
    ),
    StepError,
> {
    match auth.registration_request(now) {
        Ok(request) => Ok(request),
        Err(lomi_host_auth::Error::Expired) if enrollment_retirement_available(auth, now) => {
            Err(StepError::ExpiredEnrollment)
        }
        Err(error) => Err(error.into()),
    }
}
fn global_credential_auth_required(error: &StepError) -> bool {
    matches!(
        error,
        StepError::Http(lomi_host_http::Error::Remote(
            lomi_host_http::HostFailure::AuthRequired
        )) | StepError::Http(lomi_host_http::Error::DataRemote(
            lomi_host_http::DataFailure::AuthRequired
        ))
    )
}

/// A single absolute deadline bounds the retry wait. Wake storms may prompt
/// revalidation but cannot move the deadline or trigger another network probe.
fn wait_pending_proof_reprobe(
    runtime: Runtime<'_>,
    generation: u64,
    configuration: &LocalAuthConfiguration,
    deferred: Option<lomi_host_store::LoginIntent>,
    deadline: Instant,
) -> Result<bool, StepError> {
    loop {
        runtime.check()?;
        let status = worker_read!(runtime, runtime.owner.auth_status(runtime.operation))?;
        if status.authorization.generation != generation
            || !status.authorization.pending_cloud_revoke
            || status.deferred_intent != deferred
        {
            return Ok(false);
        }
        let selection = worker_read!(runtime, runtime.owner.auth_selection(runtime.operation))?;
        if selection.configuration.as_ref() != Some(configuration) {
            return Ok(false);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(true);
        }
        let wait = remaining.min(Duration::from_millis(250));
        match runtime.receiver.recv_timeout(wait) {
            Ok(Command::Wake(_) | Command::Logout | Command::Configure) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(StepError::Stale),
        }
    }
}

fn wait_pending_rotation_reprobe(
    runtime: Runtime<'_>,
    generation: u64,
    configuration: &LocalAuthConfiguration,
    deferred: Option<lomi_host_store::LoginIntent>,
    deadline: Instant,
) -> Result<bool, StepError> {
    wait_pending_proof_reprobe(runtime, generation, configuration, deferred, deadline)
}

fn wait_pending_enrollment_reprobe(
    runtime: Runtime<'_>,
    generation: u64,
    configuration: &LocalAuthConfiguration,
    deferred: Option<lomi_host_store::LoginIntent>,
    deadline: Instant,
) -> Result<bool, StepError> {
    wait_pending_proof_reprobe(runtime, generation, configuration, deferred, deadline)
}

fn pending_current(runtime: Runtime<'_>, generation: u64) -> bool {
    worker_read!(
        runtime,
        runtime.owner.authorization_state(runtime.operation)
    )
    .is_ok_and(|s| s.generation == generation && s.pending_cloud_revoke)
}
fn acknowledge_revoke(
    runtime: Runtime<'_>,
    generation: u64,
    verified_cloud: bool,
) -> Result<(), StepError> {
    let result = if verified_cloud {
        let mut turn = runtime
            .owner
            .begin_acknowledge_authorization_revoke(runtime.operation, generation)?;
        commit_worker_turn!(turn, runtime)
    } else {
        let mut turn = runtime
            .owner
            .begin_acknowledge_local_authorization_logout(runtime.operation, generation)?;
        commit_worker_turn!(turn, runtime)
    };
    match result {
        Ok(_) | Err(OwnerError::Store(StoreError::Fenced)) => Ok(()),
        Err(e) => Err(e.into()),
    }
}
fn probe_enrollment_retirement_ack(
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    transport: &dyn AuthTransport,
    config: &Config,
    runtime: Runtime<'_>,
    generation: u64,
    host: lomi_remote_protocol::HostId,
    now: u64,
) -> Result<bool, StepError> {
    let request = auth.enrollment_revocation_ack_request(now)?;
    runtime.check()?;
    match transport.enrollment_revocation_ack(host, &request) {
        Ok(result) => {
            let now = observed(runtime)?;
            if pending_current(runtime, generation) && !runtime.stopping.load(Ordering::Acquire) {
                runtime.check()?;
                // Persist the authenticated terminal secret state first. The
                // following loop performs the exact-generation Store handoff.
                auth.accept_enrollment_revocation_ack(config.origin(), &request, result, now)?;
            }
            Ok(true)
        }
        Err(lomi_host_http::Error::Remote(
            lomi_host_http::HostFailure::AuthRequired
            | lomi_host_http::HostFailure::ResourceNotFound,
        )) => {
            // A typed denial is not an ACK. Let the caller use the exact
            // ordinary exchange/register request if its local deadline remains.
            observed(runtime)?;
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}
fn revoke_step(
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    transport: &dyn AuthTransport,
    config: &Config,
    runtime: Runtime<'_>,
    generation: u64,
) -> Result<(), StepError> {
    let Runtime {
        owner,
        operation,
        state,
        stopping,
        ..
    } = runtime;
    let now = observed(runtime)?;
    if !pending_current(runtime, generation) {
        return Ok(());
    }
    match auth.status() {
        Status::Empty => {
            if worker_read!(runtime, owner.auth_history(operation))?.cloud_may_exist != Some(false)
            {
                return Err(lomi_host_auth::Error::InvalidState.into());
            }
            acknowledge_revoke(runtime, generation, false)?;
        }
        Status::PendingInit | Status::AwaitingApproval | Status::Approved => {
            let pristine = worker_read!(runtime, owner.auth_history(operation))?.cloud_may_exist
                == Some(false);
            if !pristine {
                return Err(lomi_host_auth::Error::InvalidState.into());
            }
            auth.cancel_pending_login(now)?;
            acknowledge_revoke(runtime, generation, false)?;
        }
        Status::ExchangePrepared => {
            let host = worker_read!(runtime, owner.identity(operation))?.host_id;
            network(state, LocalAuthNetwork::Working);
            runtime.check()?;
            if !probe_enrollment_retirement_ack(
                auth, transport, config, runtime, generation, host, now,
            )? {
                let now = observed(runtime)?;
                if !pending_current(runtime, generation) || stopping.load(Ordering::Acquire) {
                    return Ok(());
                }
                mark_cloud_possible(runtime, generation)?;
                network(state, LocalAuthNetwork::Working);
                runtime.check()?;
                let request = normal_exchange_request(auth, now)?;
                let result = transport.exchange(&request)?;
                let now = observed(runtime)?;
                if pending_current(runtime, generation) {
                    runtime.check()?;
                    auth.accept_exchange(result, now)?;
                }
            }
        }
        Status::Unconfirmed => {
            let host = worker_read!(runtime, owner.identity(operation))?.host_id;
            network(state, LocalAuthNetwork::Working);
            runtime.check()?;
            if !probe_enrollment_retirement_ack(
                auth, transport, config, runtime, generation, host, now,
            )? {
                let now = observed(runtime)?;
                if !pending_current(runtime, generation) || stopping.load(Ordering::Acquire) {
                    return Ok(());
                }
                let (access, request) = normal_registration_request(auth, now)?;
                network(state, LocalAuthNetwork::Working);
                runtime.check()?;
                let result = transport.register(&request, &access)?;
                observed(runtime)?;
                if pending_current(runtime, generation) {
                    runtime.check()?;
                    auth.confirm_registration(result)?;
                }
            }
        }
        Status::Ready | Status::Rotating => {
            runtime.check()?;
            let access = auth.revocation_credential()?;
            let request = lomi_remote_protocol::HostRevokeParams {
                expected_host_access_epoch: auth.verified_host_access_epoch()?,
            };
            let host = worker_read!(runtime, owner.identity(operation))?.host_id;
            network(state, LocalAuthNetwork::Working);
            match transport.revoke(host, &request, &access) {
                Ok(result) => {
                    let now = observed(runtime)?;
                    if pending_current(runtime, generation) {
                        // Secret ACK is durable first; its Revoked state repairs a
                        // crash before the exact-generation SQLite acknowledgement.
                        runtime.check()?;
                        auth.accept_tls_revocation(config.origin(), result, now)?;
                    }
                }
                Err(lomi_host_http::Error::Remote(lomi_host_http::HostFailure::AuthRequired)) => {
                    let now = observed(runtime)?;
                    if !pending_current(runtime, generation) || stopping.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    let acknowledgement = auth.revocation_ack_request(now)?;
                    runtime.check()?;
                    match transport.revocation_ack(host, &acknowledgement) {
                        Ok(result) => {
                            let now = observed(runtime)?;
                            if pending_current(runtime, generation)
                                && !stopping.load(Ordering::Acquire)
                            {
                                runtime.check()?;
                                // Secret ACK is durable first; its Revoked state
                                // repairs a crash before SQLite acknowledgement.
                                auth.accept_revocation_ack(
                                    config.origin(),
                                    &acknowledgement,
                                    result,
                                    now,
                                )?;
                            }
                        }
                        Err(lomi_host_http::Error::Remote(
                            lomi_host_http::HostFailure::AuthRequired
                            | lomi_host_http::HostFailure::ResourceNotFound,
                        )) => {
                            // Closed proof/route denial is not an ACK. Retain
                            // the exact historical rotation recovery behavior;
                            // its retry identity and original deadline remain
                            // in HostAuth. Generic HTTP status failures are not
                            // classified as endpoint absence.
                            let now = observed(runtime)?;
                            if !pending_current(runtime, generation)
                                || stopping.load(Ordering::Acquire)
                            {
                                return Ok(());
                            }
                            if auth.status() == Status::Ready {
                                auth.prepare_rotation(now)?;
                            } else {
                                runtime.check()?;
                                let request = match auth.rotation_request(now) {
                                    Ok(request) => request,
                                    Err(lomi_host_auth::Error::Expired)
                                        if auth.status() == Status::Rotating =>
                                    {
                                        // Keep the exact old rotation and wait
                                        // for another idempotent revoke/ACK
                                        // probe. Never refresh expired proof.
                                        return Err(StepError::ExpiredRotation);
                                    }
                                    Err(error) => return Err(error.into()),
                                };
                                let result = transport.refresh(&request)?;
                                let now = observed(runtime)?;
                                if pending_current(runtime, generation)
                                    && !stopping.load(Ordering::Acquire)
                                {
                                    runtime.check()?;
                                    auth.accept_rotation(result, now)?;
                                }
                            }
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        Status::Revoked => {
            let host = worker_read!(runtime, owner.identity(operation))?.host_id;
            match auth.retained_revocation_acknowledgement()? {
                RetainedRevocationAcknowledgement::Host(acknowledgement)
                    if acknowledgement.host_id == host => {}
                RetainedRevocationAcknowledgement::NoFamily { host_id, .. } if host_id == host => {}
                _ => return Err(lomi_host_auth::Error::InvalidResponse.into()),
            }
            acknowledge_revoke(runtime, generation, true)?;
        }
        Status::Sealed => return Err(lomi_host_auth::Error::Sealed.into()),
    }
    Ok(())
}
fn observed(runtime: Runtime<'_>) -> Result<u64, StepError> {
    runtime.check()?;
    let now = runtime.projected_time();
    let mut turn = runtime
        .owner
        .begin_observe_authorization_clock(runtime.operation, now)?;
    commit_worker_turn!(turn, runtime).map_err(StepError::from)
}
fn trusted_now(runtime: Runtime<'_>) -> Result<u64, StepError> {
    let projected = runtime.projected_time();
    let snapshot = worker_read!(runtime, runtime.owner.auth_status(runtime.operation))?;
    Ok(projected.max(snapshot.authorization.clock_floor))
}
fn network(state: &Mutex<View>, network: LocalAuthNetwork) {
    if let Ok(mut view) = state.lock() {
        view.status.network = network;
    }
}
#[derive(Debug)]
enum StepError {
    Auth(lomi_host_auth::Error),
    Http(lomi_host_http::Error),
    ExpiredEnrollment,
    ExpiredRotation,
    Rejected,
    Stale,
}
impl From<lomi_host_auth::Error> for StepError {
    fn from(e: lomi_host_auth::Error) -> Self {
        Self::Auth(e)
    }
}
impl From<lomi_host_http::Error> for StepError {
    fn from(e: lomi_host_http::Error) -> Self {
        Self::Http(e)
    }
}

// Immutable evidence captured only by the actual selected auth worker.
pub(super) struct RemoteWorkerEvidence<'w, 'p, 's, 'r> {
    // The actual borrow excludes credential/provider mutation for the whole turn.
    _auth: &'w HostAuth<'p, dyn SecretStorage + 's>,
    runtime: Runtime<'r>,
    eligibility: &'r cloud::PeerEligibility,
    provider: peer::ProviderCapture,
    trusted: Config,
    origin: lomi_host_auth::peer_policy::RemoteOrigin,
    io_identity: super::public_configuration::WorkerPublicIoIdentity,
    operation_identity: owner_domain::OperationIdentity,
}
impl<'a, 'operation> RuntimeWithOperation<'a, 'operation> {
    // Private Runtime is constructed only by the selected actual auth worker.
    // No factory accepting caller booleans, public identity or replacement IO.
    pub(in crate::unix::auth) fn remote_worker_evidence<'w, 'p, 's>(
        self,
        auth: &'w HostAuth<'p, dyn SecretStorage + 's>,
        eligibility: &'operation cloud::PeerEligibility,
    ) -> peer::ResultPeer<RemoteWorkerEvidence<'w, 'p, 's, 'operation>>
    where
        'a: 'operation,
    {
        let runtime: Runtime<'operation> = RuntimeWithOperation {
            owner: self.owner,
            operation: self.operation,
            public_io: self.public_io,
            state: self.state,
            stopping: self.stopping,
            receiver: self.receiver,
            retry_requested: self.retry_requested,
            gate: self.gate,
            paused: self.paused,
            base: self.base,
            anchor: self.anchor,
            aborted: self.aborted,
        };
        peer::check_peer_runtime(runtime)?;
        let provider = peer::ProviderCapture::read(auth, runtime, eligibility)?;
        let trusted = auth.trusted_configuration().clone();
        let origin = peer::policy(lomi_host_auth::peer_policy::RemoteOrigin::new(
            &trusted,
            eligibility.binding.scope.remote_api_origin.clone(),
        ))?;
        let evidence = RemoteWorkerEvidence {
            _auth: auth,
            runtime,
            eligibility,
            provider,
            trusted,
            origin,
            io_identity: runtime.public_io.retained_identity(),
            operation_identity: runtime.operation.retained_identity(),
        };
        if !evidence.current() {
            return Err(peer::PeerError::Invalid);
        }
        Ok(evidence)
    }
}
impl<'w, 'p, 's, 'r> RemoteWorkerEvidence<'w, 'p, 's, 'r> {
    pub(super) fn auth(&self) -> &HostAuth<'p, dyn SecretStorage + 's> {
        self._auth
    }
    pub(super) fn owner(&self) -> &'r SharedOwner {
        self.runtime.owner
    }
    pub(super) fn operation(&self) -> &'r OwnerOperation<'r> {
        self.runtime.operation
    }
    pub(super) fn eligibility(&self) -> &'r cloud::PeerEligibility {
        self.eligibility
    }
    pub(super) fn provider(&self) -> &peer::ProviderCapture {
        &self.provider
    }
    pub(super) fn trusted(&self) -> &Config {
        &self.trusted
    }
    pub(super) fn origin(&self) -> &lomi_host_auth::peer_policy::RemoteOrigin {
        &self.origin
    }
    pub(super) fn now(&self) -> Option<self::remote_connection::TrustedNow> {
        let monotonic = Instant::now();
        let elapsed = monotonic.checked_duration_since(self.runtime.anchor)?;
        let wall = Duration::from_secs(self.runtime.base).checked_add(elapsed)?;
        if wall.is_zero() || wall.as_secs() > i64::MAX as u64 {
            return None;
        }
        Some(self::remote_connection::TrustedNow { wall, monotonic })
    }
    /// No Domain, Store, provider IO or lock acquisition. The actual immutable
    /// HostAuth and public IO lease remain borrowed even during a Core wait.
    pub(super) fn current(&self) -> bool {
        if self.runtime.check().is_err()
            || self.runtime.gate.load(Ordering::Acquire)
            || !self.runtime.public_io.is_same_lease(&self.io_identity)
            || !self
                .runtime
                .operation
                .is_same_admission(&self.operation_identity)
        {
            return false;
        }
        self.now().is_some_and(|now| {
            self.provider
                .valid_for_owner(now.wall.as_secs(), self.eligibility)
        })
    }
    pub(super) fn gate_denied(&self) -> &'r AtomicBool {
        self.runtime.gate
    }
    /// Actual public setup fence; never a point-in-time copied permission.
    pub(super) fn public_setup_pending(&self) -> &'r AtomicBool {
        &self.runtime.public_io.setup().pending
    }
    pub(super) fn paused(&self) -> &'r AtomicBool {
        self.runtime.paused
    }
    pub(super) fn stopping(&self) -> &'r AtomicBool {
        self.runtime.stopping
    }
}
