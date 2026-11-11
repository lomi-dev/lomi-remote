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
    use super::super::shared_owner::SharedOwner;
    use super::{
        AuthTransport, DomainError, IdleScheduler, LocalAuthNetwork, LocalAuthPhase,
        LocalAuthStorage, OwnerError, OwnerOperation, RuntimeWithOperation, StepError, WorkClass,
        await_explicit_retry, cloud, cloud_step_requests_immediate_pass,
        read_owner_status_with_busy_retry, read_owner_status_with_busy_retry_and_wait,
        remote_ingress, revoke_step, suspend_expired,
    };
    use lomi_host_auth::{Config, HostAuth, Status};
    use lomi_host_store::{HostStore, Limits};
    use lomi_platform::secrets::{
        ProviderKind, ProviderStatus, SecretBundle, SecretStorage, StorageState,
    };
    use lomi_remote_crypto::{
        HostEnrollmentChallengeContext, prepare_host_enrollment_challenge,
        verify_host_key_initiation,
    };
    use lomi_remote_protocol::{
        DecimalU64, EnrollmentId, EnrollmentInitiateResult, HostAuthorizationId,
        HostAuthorizationResult, HostEnrollmentTokenContext, HostId, HostRegisterResult,
        LocalIpcVersion, OperationId,
        ipc::{
            LocalAuthConfiguration, LocalAuthProvider, LocalFileAcknowledgement,
            LocalLoginPresentation,
        },
    };
    use std::{
        collections::VecDeque,
        fs,
        path::PathBuf,
        sync::atomic::{AtomicBool, AtomicU64, Ordering},
        sync::{Arc, Mutex, mpsc},
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };
    use uuid::Uuid;

    struct RetirementMemoryStorage(
        Arc<Mutex<Option<Vec<u8>>>>,
        Arc<Mutex<Option<Arc<AtomicBool>>>>,
    );
    impl SecretStorage for RetirementMemoryStorage {
        fn status(&self) -> ProviderStatus {
            ProviderStatus {
                kind: Some(ProviderKind::ProtectedFile),
                state: StorageState::Available,
            }
        }
        fn load(&self) -> Result<Option<SecretBundle>, lomi_platform::secrets::Error> {
            self.0
                .lock()
                .unwrap()
                .clone()
                .map(SecretBundle::new)
                .transpose()
        }
        fn replace(&mut self, bundle: &SecretBundle) -> Result<(), lomi_platform::secrets::Error> {
            *self.0.lock().unwrap() = Some(bundle.expose().to_vec());
            if let Some(cancelled) = self.1.lock().unwrap().as_ref() {
                cancelled.store(true, Ordering::Release);
            }
            Ok(())
        }
    }

    struct RetirementTestDirectory(PathBuf);
    impl RetirementTestDirectory {
        fn new() -> Self {
            #[cfg(target_os = "macos")]
            let temp_root = PathBuf::from("/private/tmp");
            #[cfg(not(target_os = "macos"))]
            let temp_root = std::env::temp_dir().canonicalize().unwrap();
            let path = temp_root.join(format!(
                "lomi-self-retirement-{}-{}",
                std::process::id(),
                Uuid::new_v4()
            ));
            fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(path)
        }
    }
    impl Drop for RetirementTestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn retirement_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn retirement_configuration() -> LocalAuthConfiguration {
        LocalAuthConfiguration {
            version: 1,
            origin: "https://identity.example".to_owned().try_into().unwrap(),
            remote_api_origin: None,
            relay_endpoint: None,
            client_id: "host".to_owned().try_into().unwrap(),
            provider: LocalAuthProvider::ProtectedFile,
            keychain_path: None,
            protected_file_acknowledgement: Some(LocalFileAcknowledgement::OsPermissionsOnly),
        }
    }

    fn retirement_ready_auth<'a>(
        storage: &'a mut RetirementMemoryStorage,
        config: Config,
        host_id: HostId,
        now: u64,
    ) -> HostAuth<'a, dyn SecretStorage + 'a> {
        let mut auth =
            HostAuth::open(storage as &mut dyn SecretStorage, config.clone(), now).unwrap();
        auth.initialize().unwrap();
        let initiation = auth.init_request().unwrap();
        let committed = verify_host_key_initiation(&initiation).unwrap();
        let pin = committed.descriptor.commitment().unwrap();
        auth.accept_initiation(
            EnrollmentInitiateResult {
                enrollment_id: EnrollmentId::from_bytes([3; 16]).unwrap(),
                device_code: "synthetic_device".to_owned().try_into().unwrap(),
                user_code: "SYNTHETIC-CODE".to_owned().try_into().unwrap(),
                expires_in_seconds: DecimalU64(600),
                poll_interval_seconds: DecimalU64(5),
            },
            now,
        )
        .unwrap();
        let challenge = prepare_host_enrollment_challenge(
            &committed,
            &pin,
            [4; 16],
            &HostEnrollmentChallengeContext {
                enrollment_id: [3; 16],
                bootstrap_session_id: [5; 16],
                operation_id: [6; 16],
                nonce: [7; 32],
                audience: config.exchange_audience(),
                expires_at: DecimalU64(now + 500),
            },
        )
        .unwrap();
        let challenge = challenge
            .canonical()
            .unwrap()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        auth.accept_tls_approval(
            config.origin(),
            HostEnrollmentTokenContext {
                account_id: lomi_remote_protocol::AccountId::from_bytes([4; 16]).unwrap(),
                challenge: challenge.try_into().unwrap(),
            },
            "synthetic_bootstrap".to_owned().try_into().unwrap(),
            now,
        )
        .unwrap();
        auth.prepare_exchange(now).unwrap();
        let exchange = auth.exchange_request(now).unwrap();
        auth.accept_exchange(
            HostAuthorizationResult {
                account_id: lomi_remote_protocol::AccountId::from_bytes([4; 16]).unwrap(),
                host_id,
                host_authorization_id: HostAuthorizationId::from_bytes([8; 16]).unwrap(),
                access: "synthetic_access".to_owned().try_into().unwrap(),
                refresh: "synthetic_refresh".to_owned().try_into().unwrap(),
                rotation_id: exchange.operation_id,
                expires_in_seconds: DecimalU64(300),
            },
            now,
        )
        .unwrap();
        auth.confirm_registration(HostRegisterResult {
            host_id,
            host_access_epoch: DecimalU64(12),
        })
        .unwrap();
        auth
    }

    struct RetirementTransport {
        provider: Arc<Mutex<Option<Vec<u8>>>>,
        config: Config,
        rotation_time: u64,
        rotation: Option<lomi_remote_protocol::HostAuthorizationRefreshParams>,
        responses: Mutex<VecDeque<bool>>,
        response_delays: Mutex<VecDeque<Duration>>,
        acknowledgement_responses: Mutex<VecDeque<bool>>,
        after_self_retire: Option<Arc<dyn Fn() + Send + Sync>>,
        revokes: Mutex<Vec<lomi_remote_protocol::HostRevokeParams>>,
        acknowledgements: Mutex<Vec<lomi_remote_protocol::HostRevocationAckParams>>,
        retirements: Mutex<Vec<lomi_remote_protocol::HostSelfRetirementParams>>,
        refresh_calls: AtomicU64,
    }
    impl AuthTransport for RetirementTransport {
        fn revoke(
            &self,
            _host: HostId,
            request: &lomi_remote_protocol::HostRevokeParams,
            _access: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error> {
            self.revokes.lock().unwrap().push(request.clone());
            Err(lomi_host_http::Error::Remote(
                lomi_host_http::HostFailure::AuthRequired,
            ))
        }
        fn revocation_ack(
            &self,
            host: HostId,
            request: &lomi_remote_protocol::HostRevocationAckParams,
        ) -> Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error> {
            self.acknowledgements.lock().unwrap().push(request.clone());
            if !self
                .acknowledgement_responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(false)
            {
                return Err(lomi_host_http::Error::Remote(
                    lomi_host_http::HostFailure::AuthRequired,
                ));
            }
            Ok(lomi_remote_protocol::HostRevokeResult {
                host_id: host,
                host_access_epoch: DecimalU64(request.expected_host_access_epoch.0 + 1),
            })
        }
        fn self_retire(
            &self,
            host: HostId,
            request: &lomi_remote_protocol::HostSelfRetirementParams,
        ) -> Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error> {
            let bytes = self.provider.lock().unwrap().clone().unwrap();
            let mut provider = RetirementMemoryStorage(
                Arc::new(Mutex::new(Some(bytes))),
                Arc::new(Mutex::new(None)),
            );
            let reopened =
                HostAuth::open(&mut provider, self.config.clone(), self.rotation_time).unwrap();
            assert_eq!(reopened.status(), Status::Rotating);
            if let Some(rotation) = &self.rotation {
                assert_eq!(
                    reopened.rotation_request(self.rotation_time).unwrap(),
                    *rotation,
                    "self-retirement must leave the old rotation request untouched before ACK"
                );
            }
            self.retirements.lock().unwrap().push(request.clone());
            if let Some(delay) = self.response_delays.lock().unwrap().pop_front() {
                thread::sleep(delay);
            }
            if !self.responses.lock().unwrap().pop_front().unwrap_or(true) {
                return Err(lomi_host_http::Error::Timeout);
            }
            if let Some(after) = &self.after_self_retire {
                after();
            }
            Ok(lomi_remote_protocol::HostRevokeResult {
                host_id: host,
                host_access_epoch: DecimalU64(request.expected_host_access_epoch.0 + 1),
            })
        }
        fn enrollment_revocation_ack(
            &self,
            _host: HostId,
            _request: &lomi_remote_protocol::HostEnrollmentRevocationAckParams,
        ) -> Result<lomi_remote_protocol::HostEnrollmentRevocationAckResult, lomi_host_http::Error>
        {
            Err(lomi_host_http::Error::Remote(
                lomi_host_http::HostFailure::ResourceNotFound,
            ))
        }
        fn initiate(
            &self,
            _request: &lomi_remote_protocol::EnrollmentInitiateParams,
        ) -> Result<EnrollmentInitiateResult, lomi_host_http::Error> {
            Err(lomi_host_http::Error::Timeout)
        }
        fn poll(
            &self,
            _device: &lomi_remote_protocol::DeviceCode,
        ) -> Result<super::PollOutcome, lomi_host_http::Error> {
            Err(lomi_host_http::Error::Timeout)
        }
        fn exchange(
            &self,
            _request: &lomi_remote_protocol::HostAuthorizationExchangeParams,
        ) -> Result<HostAuthorizationResult, lomi_host_http::Error> {
            Err(lomi_host_http::Error::Timeout)
        }
        fn register(
            &self,
            _request: &lomi_remote_protocol::HostRegisterParams,
            _access: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<HostRegisterResult, lomi_host_http::Error> {
            Err(lomi_host_http::Error::Timeout)
        }
        fn refresh(
            &self,
            _request: &lomi_remote_protocol::HostAuthorizationRefreshParams,
        ) -> Result<HostAuthorizationResult, lomi_host_http::Error> {
            self.refresh_calls.fetch_add(1, Ordering::Relaxed);
            Err(lomi_host_http::Error::Timeout)
        }
    }

    #[test]
    fn expired_auth_suspension_preserves_available_provider_and_clears_login_data() {
        #[cfg(target_os = "macos")]
        let temp_root = PathBuf::from("/private/tmp");
        #[cfg(not(target_os = "macos"))]
        let temp_root = std::env::temp_dir().canonicalize().unwrap();
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = temp_root.join(format!(
            "lomi-expired-suspend-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let database = directory.join("host.sqlite3");
        let mut store = HostStore::open(&database, Limits::default()).unwrap();
        let identity = store.identity().clone();
        let runtime_id = store.runtime_id();
        store.enable_authorization(0).unwrap();
        let owner = SharedOwner::new(store).unwrap();
        let profile = directory.join("profile");
        fs::create_dir(&profile).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&profile, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let endpoint = Arc::new(
            super::super::platform::OwnerEndpoint::bind(
                super::super::platform::OwnerLock::acquire(&profile).unwrap(),
                super::super::platform::LocalDiscovery {
                    version: LocalIpcVersion::CURRENT,
                    profile_id: identity.profile_id,
                    host_id: identity.host_id,
                    runtime_id,
                    build_id: "expired-suspend-tests".to_owned(),
                },
            )
            .unwrap(),
        );
        let setup = Arc::new(super::super::public_configuration::PublicSetup::new(
            endpoint,
        ));
        let stopping = AtomicBool::new(false);
        let paused = AtomicBool::new(false);
        let public_io = setup.enter_owned(&paused).unwrap().unwrap();
        let gate = AtomicBool::new(false);
        let retry_requested = AtomicBool::new(false);
        let (_sender, receiver) = mpsc::channel();
        let cancelled = AtomicBool::new(false);
        let operation = OwnerOperation::new(Instant::now() + Duration::from_secs(30), &cancelled);
        let aborted = std::cell::Cell::new(false);
        let state = Mutex::new(super::initial());
        {
            let mut view = state.lock().unwrap();
            view.status.phase = LocalAuthPhase::Ready;
            view.status.storage = LocalAuthStorage::Available;
            view.status.network = LocalAuthNetwork::Available;
            view.status.locked = false;
            view.presentation = Some(LocalLoginPresentation {
                user_code: "SYNTHETIC-CODE".to_owned().try_into().unwrap(),
                verification_url: "https://identity.example/device"
                    .to_owned()
                    .try_into()
                    .unwrap(),
                expires_at: DecimalU64(30),
                next_poll_at: DecimalU64(5),
            });
        }
        let runtime = RuntimeWithOperation {
            owner: &owner,
            operation: &operation,
            public_io: &public_io,
            state: &state,
            stopping: &stopping,
            receiver: &receiver,
            retry_requested: &retry_requested,
            gate: &gate,
            paused: &paused,
            base: 10,
            anchor: Instant::now(),
            aborted: &aborted,
        };
        suspend_expired(runtime, 0).unwrap();

        let view = state.lock().unwrap();
        assert_eq!(view.status.phase, LocalAuthPhase::Locked);
        assert_eq!(view.status.storage, LocalAuthStorage::Available);
        assert_eq!(view.status.network, LocalAuthNetwork::Unavailable);
        assert!(view.status.locked);
        assert!(view.presentation.is_none());
        assert!(gate.load(Ordering::Acquire));
        assert!(owner.authorization_state(&operation).unwrap().locked);
        drop(view);

        let stale_cancelled = AtomicBool::new(false);
        let stale_operation =
            OwnerOperation::new(Instant::now() + Duration::from_secs(30), &stale_cancelled);
        let stale_aborted = std::cell::Cell::new(false);
        let stale_runtime = runtime.with_operation(&stale_operation, &stale_aborted);
        let (before_status, before_presentation) = {
            let mut view = state.lock().unwrap();
            view.status.phase = LocalAuthPhase::Refreshing;
            view.status.storage = LocalAuthStorage::Unavailable;
            view.status.network = LocalAuthNetwork::Working;
            view.status.locked = false;
            (view.status.clone(), view.presentation.clone())
        };
        assert!(matches!(
            suspend_expired(stale_runtime, 99),
            Err(StepError::Stale)
        ));
        let view = state.lock().unwrap();
        assert_eq!(view.status, before_status);
        assert_eq!(view.presentation, before_presentation);
        drop(view);
        drop(public_io);
        drop(setup);
        drop(owner);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn expired_rotation_uses_exact_durable_retirement_and_promotes_normal_enrollment() {
        use super::super::shared_owner::SharedOwner;

        let directory = RetirementTestDirectory::new();
        let profile = directory.0.join("profile");
        let lock = super::super::platform::OwnerLock::acquire(&profile).unwrap();
        let database = lock.prepare_database().unwrap();
        let mut store = HostStore::open(&database, Limits::default()).unwrap();
        let identity = store.identity().clone();
        let runtime_id = store.runtime_id();
        let local_configuration = retirement_configuration();
        store.configure_auth(&local_configuration).unwrap();
        let config = Config::new(
            identity.host_id,
            identity.profile_id,
            "https://identity.example".into(),
            "host".to_owned().try_into().unwrap(),
        )
        .unwrap();
        let owner = SharedOwner::new(store).unwrap();
        let now = retirement_now();
        let mut storage =
            RetirementMemoryStorage(Arc::new(Mutex::new(None)), Arc::new(Mutex::new(None)));
        let provider = storage.0.clone();
        let cancel_on_replace = storage.1.clone();
        let mut auth = retirement_ready_auth(&mut storage, config.clone(), identity.host_id, now);

        let seed_cancelled = AtomicBool::new(false);
        let seed_operation =
            OwnerOperation::new(Instant::now() + Duration::from_secs(60), &seed_cancelled);
        owner.seed_test_ready(&seed_operation, &auth).unwrap();
        auth.prepare_rotation(now).unwrap();
        let old_rotation = auth.rotation_request(now + 1).unwrap();
        assert_eq!(
            auth.rotation_request(now + 301),
            Err(lomi_host_auth::Error::Expired)
        );
        assert_eq!(auth.status(), Status::Rotating);

        let endpoint = Arc::new(
            super::super::platform::OwnerEndpoint::bind(
                lock,
                super::super::platform::LocalDiscovery {
                    version: LocalIpcVersion::CURRENT,
                    profile_id: identity.profile_id,
                    host_id: identity.host_id,
                    runtime_id,
                    build_id: "self-retirement-integration-tests".to_owned(),
                },
            )
            .unwrap(),
        );
        let setup = Arc::new(super::super::public_configuration::PublicSetup::new(
            endpoint,
        ));
        let stopping = AtomicBool::new(false);
        let paused = AtomicBool::new(false);
        let public_io = setup.enter_owned(&paused).unwrap().unwrap();
        let operation_cancelled = Arc::new(AtomicBool::new(false));
        let operation = OwnerOperation::new(
            Instant::now() + Duration::from_secs(60),
            &operation_cancelled,
        );
        let mut logout = owner.begin_local_logout(&operation).unwrap();
        logout.try_commit().unwrap();
        drop(logout);
        let generation = owner.authorization_state(&operation).unwrap().generation;
        let trigger = OperationId::from_bytes([30; 16]).unwrap();
        owner
            .begin_login(&operation, trigger, local_configuration.clone(), generation)
            .unwrap()
            .try_commit()
            .unwrap();

        let state = Mutex::new(super::initial());
        let (sender, receiver) = mpsc::channel();
        let gate = AtomicBool::new(true);
        let retry_requested = AtomicBool::new(false);
        let aborted = std::cell::Cell::new(false);
        let runtime = RuntimeWithOperation {
            owner: &owner,
            operation: &operation,
            public_io: &public_io,
            state: &state,
            stopping: &stopping,
            receiver: &receiver,
            retry_requested: &retry_requested,
            gate: &gate,
            paused: &paused,
            base: now + 301,
            anchor: Instant::now(),
            aborted: &aborted,
        };
        let mut transport = RetirementTransport {
            provider,
            config: config.clone(),
            rotation_time: now + 1,
            rotation: Some(old_rotation.clone()),
            responses: Mutex::new(VecDeque::from([false, true])),
            response_delays: Mutex::new(VecDeque::from([Duration::ZERO, Duration::ZERO])),
            acknowledgement_responses: Mutex::new(VecDeque::from([false, false, true])),
            after_self_retire: {
                let barrier = Arc::new(std::sync::Barrier::new(2));
                let hold_owner = owner.clone();
                Some(Arc::new(move || {
                    let worker_barrier = barrier.clone();
                    let worker_owner = hold_owner.clone();
                    thread::spawn(move || worker_owner.hold_store_for_test(worker_barrier));
                    // Wait until the second thread owns the Store mutex, then
                    // release it after the intent deadline crosses during the
                    // worker's post-response guarded reads.
                    barrier.wait();
                    let release_barrier = barrier.clone();
                    thread::spawn(move || {
                        thread::sleep(Duration::from_secs(2));
                        release_barrier.wait();
                    });
                }) as Arc<dyn Fn() + Send + Sync>)
            },
            revokes: Mutex::new(Vec::new()),
            acknowledgements: Mutex::new(Vec::new()),
            retirements: Mutex::new(Vec::new()),
            refresh_calls: AtomicU64::new(0),
        };

        assert!(matches!(
            revoke_step(&mut auth, &transport, &config, runtime, generation),
            Err(StepError::Http(lomi_host_http::Error::Timeout))
        ));
        let first_journal = owner
            .host_self_retirement_journal(&operation, generation, &local_configuration)
            .unwrap()
            .unwrap();
        assert_eq!(first_journal.trigger_operation_id, Some(trigger));
        assert_eq!(
            auth.status(),
            Status::Rotating,
            "unknown send does not accept ACK"
        );

        // Retry the same signed intent one second before its deadline. The
        // simulated successful HTTP response returns after that deadline.
        let late_runtime = runtime.with_clock_floor(now + 600);
        revoke_step(&mut auth, &transport, &config, late_runtime, generation).unwrap();
        assert_eq!(
            auth.status(),
            Status::Rotating,
            "late result cannot alter provider"
        );
        assert_eq!(
            owner
                .host_self_retirement_journal(&operation, generation, &local_configuration,)
                .unwrap(),
            Some(first_journal.clone()),
            "late result keeps its exact recovery journal"
        );
        assert!(
            owner
                .auth_status(&operation)
                .unwrap()
                .authorization
                .pending_cloud_revoke
        );

        // The next loop resolves a possibly committed result through the
        // ordinary read-only ACK path. Simulate a process stop after provider
        // acceptance so a fresh worker turn must finish the Store ACK.
        *cancel_on_replace.lock().unwrap() = Some(operation_cancelled.clone());
        let acknowledgement_runtime = runtime.with_clock_floor(now + 602);
        revoke_step(
            &mut auth,
            &transport,
            &config,
            acknowledgement_runtime,
            generation,
        )
        .unwrap();

        let requests = transport.retirements.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0], requests[1],
            "unknown retry resends exact signed intent"
        );
        assert_ne!(requests[0].operation_id, old_rotation.rotation_id);
        drop(requests);
        assert_eq!(transport.revokes.lock().unwrap().len(), 3);
        assert_eq!(transport.acknowledgements.lock().unwrap().len(), 3);
        assert_eq!(transport.refresh_calls.load(Ordering::Relaxed), 0);
        assert_eq!(auth.status(), Status::Revoked);
        drop(auth);

        let mut recovered_auth = HostAuth::open(
            &mut storage as &mut dyn SecretStorage,
            config.clone(),
            now + 602,
        )
        .unwrap();
        assert_eq!(recovered_auth.status(), Status::Revoked);
        let recovery_cancelled = AtomicBool::new(false);
        let recovery_operation = OwnerOperation::new(
            Instant::now() + Duration::from_secs(60),
            &recovery_cancelled,
        );
        assert!(
            owner
                .auth_status(&recovery_operation)
                .unwrap()
                .authorization
                .pending_cloud_revoke
        );
        let recovery_aborted = std::cell::Cell::new(false);
        let recovery_runtime = RuntimeWithOperation {
            owner: &owner,
            operation: &recovery_operation,
            public_io: &public_io,
            state: &state,
            stopping: &stopping,
            receiver: &receiver,
            retry_requested: &retry_requested,
            gate: &gate,
            paused: &paused,
            base: now + 602,
            anchor: Instant::now(),
            aborted: &recovery_aborted,
        };
        revoke_step(
            &mut recovered_auth,
            &transport,
            &config,
            recovery_runtime,
            generation,
        )
        .unwrap();
        let state_after = owner.auth_status(&recovery_operation).unwrap();
        assert_eq!(state_after.authorization.generation, generation);
        assert!(!state_after.authorization.pending_cloud_revoke);
        assert!(state_after.authorization.locked);
        assert_eq!(state_after.deferred_intent, None);
        assert_eq!(
            state_after.intent,
            Some(lomi_host_store::LoginIntent {
                operation_id: trigger,
                generation,
            })
        );
        assert_eq!(
            owner.host_self_retirement_journal(
                &recovery_operation,
                generation,
                &local_configuration,
            ),
            Err(OwnerError::Store(lomi_host_store::StoreError::Fenced))
        );

        drop(recovered_auth);
        *cancel_on_replace.lock().unwrap() = None;
        let mut next_auth = HostAuth::open(&mut storage, config.clone(), now + 603).unwrap();
        next_auth.restart_after_revocation(now + 603).unwrap();
        let _new_enrollment = next_auth.init_request().unwrap();
        next_auth
            .accept_initiation(
                EnrollmentInitiateResult {
                    enrollment_id: EnrollmentId::from_bytes([31; 16]).unwrap(),
                    device_code: "next_device".to_owned().try_into().unwrap(),
                    user_code: "NEXT-CODE".to_owned().try_into().unwrap(),
                    expires_in_seconds: DecimalU64(600),
                    poll_interval_seconds: DecimalU64(5),
                },
                now + 603,
            )
            .unwrap();
        assert_eq!(next_auth.status(), Status::AwaitingApproval);

        // Exercise a timely 200 from the new retirement route as well. The
        // ordinary local enrollment above becomes ready, then a fresh logout
        // queues another explicit login behind this family's ACK.
        drop(next_auth);
        *storage.0.lock().unwrap() = None;
        let mut ready_again =
            retirement_ready_auth(&mut storage, config.clone(), identity.host_id, now + 604);
        let seed_cancelled = AtomicBool::new(false);
        let seed_operation =
            OwnerOperation::new(Instant::now() + Duration::from_secs(60), &seed_cancelled);
        owner
            .seed_test_ready(&seed_operation, &ready_again)
            .unwrap();

        let timely_cancelled = AtomicBool::new(false);
        let timely_operation =
            OwnerOperation::new(Instant::now() + Duration::from_secs(60), &timely_cancelled);
        let mut timely_logout = owner.begin_local_logout(&timely_operation).unwrap();
        let timely_fence = timely_logout.try_commit().unwrap();
        drop(timely_logout);
        let timely_generation = timely_fence.generation;
        let timely_trigger = OperationId::from_bytes([34; 16]).unwrap();
        owner
            .begin_login(
                &timely_operation,
                timely_trigger,
                local_configuration.clone(),
                timely_generation,
            )
            .unwrap()
            .try_commit()
            .unwrap();
        ready_again.prepare_rotation(now + 604).unwrap();
        let timely_rotation = ready_again.rotation_request(now + 605).unwrap();
        transport.rotation_time = now + 605;
        transport.rotation = Some(timely_rotation.clone());
        let timely_aborted = std::cell::Cell::new(false);
        let timely_runtime = RuntimeWithOperation {
            owner: &owner,
            operation: &timely_operation,
            public_io: &public_io,
            state: &state,
            stopping: &stopping,
            receiver: &receiver,
            retry_requested: &retry_requested,
            gate: &gate,
            paused: &paused,
            base: now + 606,
            anchor: Instant::now(),
            aborted: &timely_aborted,
        };
        revoke_step(
            &mut ready_again,
            &transport,
            &config,
            timely_runtime,
            timely_generation,
        )
        .unwrap();
        assert_eq!(ready_again.status(), Status::Revoked);
        let timely_state = owner.auth_status(&timely_operation).unwrap();
        assert_eq!(timely_state.authorization.generation, timely_generation);
        assert!(!timely_state.authorization.pending_cloud_revoke);
        assert!(timely_state.authorization.locked);
        assert_eq!(timely_state.deferred_intent, None);
        assert_eq!(
            timely_state.intent,
            Some(lomi_host_store::LoginIntent {
                operation_id: timely_trigger,
                generation: timely_generation,
            })
        );
        assert_eq!(transport.retirements.lock().unwrap().len(), 3);
        drop(sender);
        drop(public_io);
        drop(setup);
        drop(owner);
    }

    #[test]
    fn pristine_local_logout_ack_promotes_login_before_normal_enrollment() {
        use super::super::shared_owner::SharedOwner;

        let directory = RetirementTestDirectory::new();
        let profile = directory.0.join("profile");
        let lock = super::super::platform::OwnerLock::acquire(&profile).unwrap();
        let database = lock.prepare_database().unwrap();
        let mut store = HostStore::open(&database, Limits::default()).unwrap();
        let identity = store.identity().clone();
        let runtime_id = store.runtime_id();
        let local_configuration = retirement_configuration();
        store.configure_auth(&local_configuration).unwrap();
        let config = Config::new(
            identity.host_id,
            identity.profile_id,
            "https://identity.example".into(),
            "host".to_owned().try_into().unwrap(),
        )
        .unwrap();
        let owner = SharedOwner::new(store).unwrap();
        let now = retirement_now();
        let mut storage =
            RetirementMemoryStorage(Arc::new(Mutex::new(None)), Arc::new(Mutex::new(None)));
        let provider = storage.0.clone();
        let mut auth =
            HostAuth::open(&mut storage as &mut dyn SecretStorage, config.clone(), now).unwrap();
        assert_eq!(auth.status(), Status::Empty);

        let cancelled = AtomicBool::new(false);
        let operation = OwnerOperation::new(Instant::now() + Duration::from_secs(60), &cancelled);
        let mut logout = owner.begin_local_logout(&operation).unwrap();
        let fenced = logout.try_commit().unwrap();
        drop(logout);
        let generation = fenced.generation;
        let trigger = OperationId::from_bytes([32; 16]).unwrap();
        owner
            .begin_login(&operation, trigger, local_configuration.clone(), generation)
            .unwrap()
            .try_commit()
            .unwrap();

        let endpoint = Arc::new(
            super::super::platform::OwnerEndpoint::bind(
                lock,
                super::super::platform::LocalDiscovery {
                    version: LocalIpcVersion::CURRENT,
                    profile_id: identity.profile_id,
                    host_id: identity.host_id,
                    runtime_id,
                    build_id: "local-logout-ack-integration-tests".to_owned(),
                },
            )
            .unwrap(),
        );
        let setup = Arc::new(super::super::public_configuration::PublicSetup::new(
            endpoint,
        ));
        let stopping = AtomicBool::new(false);
        let paused = AtomicBool::new(false);
        let public_io = setup.enter_owned(&paused).unwrap().unwrap();
        let state = Mutex::new(super::initial());
        let (sender, receiver) = mpsc::channel();
        let gate = AtomicBool::new(true);
        let retry_requested = AtomicBool::new(false);
        let aborted = std::cell::Cell::new(false);
        let runtime = RuntimeWithOperation {
            owner: &owner,
            operation: &operation,
            public_io: &public_io,
            state: &state,
            stopping: &stopping,
            receiver: &receiver,
            retry_requested: &retry_requested,
            gate: &gate,
            paused: &paused,
            base: now,
            anchor: Instant::now(),
            aborted: &aborted,
        };
        let transport = RetirementTransport {
            provider,
            config: config.clone(),
            rotation_time: now,
            rotation: None,
            responses: Mutex::new(VecDeque::new()),
            response_delays: Mutex::new(VecDeque::new()),
            acknowledgement_responses: Mutex::new(VecDeque::new()),
            after_self_retire: None,
            revokes: Mutex::new(Vec::new()),
            acknowledgements: Mutex::new(Vec::new()),
            retirements: Mutex::new(Vec::new()),
            refresh_calls: AtomicU64::new(0),
        };

        revoke_step(&mut auth, &transport, &config, runtime, generation).unwrap();
        assert!(transport.revokes.lock().unwrap().is_empty());
        assert!(transport.acknowledgements.lock().unwrap().is_empty());
        assert!(transport.retirements.lock().unwrap().is_empty());
        let promoted = owner.auth_status(&operation).unwrap();
        assert_eq!(promoted.authorization.generation, generation);
        assert!(!promoted.authorization.pending_cloud_revoke);
        assert!(promoted.authorization.locked);
        assert_eq!(promoted.deferred_intent, None);
        assert_eq!(
            promoted.intent,
            Some(lomi_host_store::LoginIntent {
                operation_id: trigger,
                generation,
            })
        );
        assert_eq!(
            owner.auth_history(&operation).unwrap().cloud_may_exist,
            Some(false)
        );

        // The promoted intent proceeds through ordinary enrollment while the
        // authorization fence remains locked pending approval.
        auth.initialize().unwrap();
        let _request = auth.init_request().unwrap();
        auth.accept_initiation(
            EnrollmentInitiateResult {
                enrollment_id: EnrollmentId::from_bytes([33; 16]).unwrap(),
                device_code: "local_ack_device".to_owned().try_into().unwrap(),
                user_code: "LOCAL-ACK".to_owned().try_into().unwrap(),
                expires_in_seconds: DecimalU64(600),
                poll_interval_seconds: DecimalU64(5),
            },
            now + 1,
        )
        .unwrap();
        assert_eq!(auth.status(), Status::AwaitingApproval);
        drop(sender);
        drop(public_io);
        drop(setup);
        drop(owner);
    }

    #[test]
    fn self_retirement_response_is_not_accepted_after_generation_or_config_change() {
        use super::super::shared_owner::SharedOwner;

        for change_configuration in [false, true] {
            let directory = RetirementTestDirectory::new();
            let profile = directory.0.join("profile");
            let lock = super::super::platform::OwnerLock::acquire(&profile).unwrap();
            let database = lock.prepare_database().unwrap();
            let mut store = HostStore::open(&database, Limits::default()).unwrap();
            let identity = store.identity().clone();
            let runtime_id = store.runtime_id();
            let local_configuration = retirement_configuration();
            store.configure_auth(&local_configuration).unwrap();
            let config = Config::new(
                identity.host_id,
                identity.profile_id,
                "https://identity.example".into(),
                "host".to_owned().try_into().unwrap(),
            )
            .unwrap();
            let owner = SharedOwner::new(store).unwrap();
            let now = retirement_now();
            let mut storage =
                RetirementMemoryStorage(Arc::new(Mutex::new(None)), Arc::new(Mutex::new(None)));
            let provider = storage.0.clone();
            let mut auth =
                retirement_ready_auth(&mut storage, config.clone(), identity.host_id, now);
            let seed_cancelled = AtomicBool::new(false);
            let seed_operation =
                OwnerOperation::new(Instant::now() + Duration::from_secs(60), &seed_cancelled);
            owner.seed_test_ready(&seed_operation, &auth).unwrap();
            auth.prepare_rotation(now).unwrap();
            let old_rotation = auth.rotation_request(now + 1).unwrap();

            let operation_cancelled = AtomicBool::new(false);
            let operation = OwnerOperation::new(
                Instant::now() + Duration::from_secs(60),
                &operation_cancelled,
            );
            let mut logout = owner.begin_local_logout(&operation).unwrap();
            let generation = logout.try_commit().unwrap().generation;
            drop(logout);
            let trigger = OperationId::from_bytes([35; 16]).unwrap();
            owner
                .begin_login(&operation, trigger, local_configuration.clone(), generation)
                .unwrap()
                .try_commit()
                .unwrap();

            let endpoint = Arc::new(
                super::super::platform::OwnerEndpoint::bind(
                    lock,
                    super::super::platform::LocalDiscovery {
                        version: LocalIpcVersion::CURRENT,
                        profile_id: identity.profile_id,
                        host_id: identity.host_id,
                        runtime_id,
                        build_id: "stale-self-retirement-tests".to_owned(),
                    },
                )
                .unwrap(),
            );
            let setup = Arc::new(super::super::public_configuration::PublicSetup::new(
                endpoint,
            ));
            let stopping = AtomicBool::new(false);
            let paused = AtomicBool::new(false);
            let public_io = setup.enter_owned(&paused).unwrap().unwrap();
            let state = Mutex::new(super::initial());
            let (sender, receiver) = mpsc::channel();
            let gate = AtomicBool::new(true);
            let retry_requested = AtomicBool::new(false);
            let aborted = std::cell::Cell::new(false);
            let runtime = RuntimeWithOperation {
                owner: &owner,
                operation: &operation,
                public_io: &public_io,
                state: &state,
                stopping: &stopping,
                receiver: &receiver,
                retry_requested: &retry_requested,
                gate: &gate,
                paused: &paused,
                base: now + 2,
                anchor: Instant::now(),
                aborted: &aborted,
            };

            let owner_after = owner.clone();
            let changed_configuration = LocalAuthConfiguration {
                remote_api_origin: Some("https://remote.example".to_owned().try_into().unwrap()),
                ..local_configuration.clone()
            };
            let after_self_retire: Arc<dyn Fn() + Send + Sync> = if change_configuration {
                Arc::new(move || {
                    owner_after
                        .configure_auth_for_test(&changed_configuration)
                        .unwrap();
                })
            } else {
                Arc::new(move || {
                    let cancelled = AtomicBool::new(false);
                    let stale_operation =
                        OwnerOperation::new(Instant::now() + Duration::from_secs(60), &cancelled);
                    let mut logout = owner_after.begin_local_logout(&stale_operation).unwrap();
                    logout.try_commit().unwrap();
                })
            };
            let transport = RetirementTransport {
                provider,
                config: config.clone(),
                rotation_time: now + 1,
                rotation: Some(old_rotation),
                responses: Mutex::new(VecDeque::from([true])),
                response_delays: Mutex::new(VecDeque::new()),
                acknowledgement_responses: Mutex::new(VecDeque::new()),
                after_self_retire: Some(after_self_retire),
                revokes: Mutex::new(Vec::new()),
                acknowledgements: Mutex::new(Vec::new()),
                retirements: Mutex::new(Vec::new()),
                refresh_calls: AtomicU64::new(0),
            };

            assert!(revoke_step(&mut auth, &transport, &config, runtime, generation).is_err());
            assert_eq!(auth.status(), Status::Rotating);
            assert_eq!(transport.retirements.lock().unwrap().len(), 1);
            assert!(transport.refresh_calls.load(Ordering::Relaxed) == 0);
            if change_configuration {
                let changed = owner
                    .auth_selection(&operation)
                    .unwrap()
                    .configuration
                    .unwrap();
                assert_eq!(
                    changed.remote_api_origin.as_ref().unwrap().as_str(),
                    "https://remote.example"
                );
                assert!(
                    owner
                        .auth_status(&operation)
                        .unwrap()
                        .authorization
                        .pending_cloud_revoke
                );
                assert!(
                    owner
                        .host_self_retirement_journal(&operation, generation, &changed)
                        .unwrap()
                        .is_some()
                );
            } else {
                let current = OwnerOperation::new(
                    Instant::now() + Duration::from_secs(60),
                    &operation_cancelled,
                );
                assert_eq!(
                    owner.authorization_state(&current).unwrap().generation,
                    generation + 1
                );
                assert!(
                    owner
                        .authorization_state(&current)
                        .unwrap()
                        .pending_cloud_revoke
                );
                assert_eq!(
                    owner.host_self_retirement_journal(&current, generation, &local_configuration,),
                    Err(OwnerError::Store(lomi_host_store::StoreError::Fenced))
                );
            }
            drop(sender);
            drop(public_io);
            drop(setup);
            drop(owner);
        }
    }

    #[test]
    fn actor_wait_tracks_cloud_and_reserved_stage_progress() {
        use cloud::StepOutcome;

        assert_eq!(
            remote_ingress::actor_wait_duration(cloud_step_requests_immediate_pass(&Ok(
                StepOutcome::Network
            ))),
            Duration::ZERO
        );
        assert_eq!(
            remote_ingress::actor_wait_duration(cloud_step_requests_immediate_pass(&Ok(
                StepOutcome::Deferred
            ))),
            Duration::from_millis(250)
        );
        assert_eq!(
            remote_ingress::actor_wait_duration(cloud_step_requests_immediate_pass(&Err(
                StepError::Stale
            ))),
            Duration::from_millis(250)
        );

        let mut idle = IdleScheduler::default();
        let class = idle
            .select_class(false, false, false, false, true, true)
            .unwrap();
        assert!(!idle.after_step(class, false, true, false));
        let immediate = idle.should_wake_after_step(class, false, true, true);
        assert_eq!(
            remote_ingress::actor_wait_duration(immediate),
            Duration::ZERO
        );

        // Errors and idle/backoff turns keep the reservation's ordinary wait.
        assert_eq!(
            remote_ingress::actor_wait_duration(
                idle.should_wake_after_step(class, false, true, false)
            ),
            Duration::from_millis(250)
        );

        assert!(idle.after_step(class, false, false, true));
        assert!(!idle.should_wake_after_step(class, false, false, true));
        assert_eq!(
            remote_ingress::actor_wait_duration(
                idle.should_wake_after_step(class, false, false, true)
            ),
            Duration::from_millis(250)
        );
    }

    #[test]
    fn idle_scheduler_defers_without_changing_class_alternation() {
        let mut idle = IdleScheduler::default();

        assert_eq!(
            idle.select_class(false, false, false, false, false, true),
            None
        );
        let class = idle
            .select_class(false, false, false, false, true, true)
            .unwrap();
        assert_eq!(class, WorkClass::Peer);
        assert!(idle.after_step(class, false, false, false));
        assert_eq!(
            idle.select_class(false, false, false, false, false, true),
            None
        );
        let class = idle
            .select_class(false, false, false, false, true, true)
            .unwrap();
        assert_eq!(class, WorkClass::Channel);
        assert!(idle.after_step(class, false, false, false));
    }

    #[test]
    fn established_ingress_work_does_not_suppress_pair_channel_alternation() {
        let mut idle = IdleScheduler::default();

        for expected in [
            WorkClass::Peer,
            WorkClass::Channel,
            WorkClass::Peer,
            WorkClass::Channel,
        ] {
            let class = idle
                .select_class(false, false, false, false, true, true)
                .unwrap();
            assert_eq!(class, expected);
            assert!(idle.after_step(class, false, false, false));
        }
    }

    #[test]
    fn idle_scheduler_keeps_peer_only_when_channels_are_disabled() {
        let mut idle = IdleScheduler::default();

        for _ in 0..2 {
            let class = idle
                .select_class(false, false, false, false, true, false)
                .unwrap();
            assert_eq!(class, WorkClass::Peer);
            assert!(idle.after_step(class, false, false, false));
        }
        assert_eq!(
            idle.select_class(false, false, false, false, true, true),
            Some(WorkClass::Channel)
        );
        assert!(idle.after_step(WorkClass::Channel, false, false, false));
        assert_eq!(
            idle.select_class(false, false, false, false, true, true),
            Some(WorkClass::Peer)
        );
        assert!(idle.after_step(WorkClass::Peer, false, false, false));
    }

    #[test]
    fn reserved_work_runs_poll_prepare_and_send_before_yielding() {
        let mut idle = IdleScheduler::default();
        let mut authority_revision = 0;
        let channel_cached_revision = authority_revision;

        let selected = idle
            .select_class(false, false, false, false, true, true)
            .unwrap();
        assert_eq!(selected, WorkClass::Peer);
        assert!(!idle.after_step(selected, false, true, false)); // poll loaded cache
        assert_eq!(
            idle.select_class(false, true, false, false, true, true),
            Some(selected)
        );
        authority_revision += 1; // peer journal prepare advances its own continuation
        assert!(!idle.after_step(selected, true, true, true)); // prepare created intent
        assert_eq!(
            idle.select_class(true, true, false, false, true, true),
            Some(selected)
        );
        authority_revision += 1; // peer send/ack advances authority again
        assert!(idle.after_step(selected, false, true, true)); // send settled

        // The sibling may have cached an observation before the peer journal
        // writes. Its stale item consumes one turn, then the next reservation
        // polls under the new owner revision before preparing/sending.
        assert_ne!(channel_cached_revision, authority_revision);
        let selected = idle
            .select_class(false, false, false, true, true, true)
            .unwrap();
        assert_eq!(selected, WorkClass::Channel);
        let stale_channel_work = channel_cached_revision != authority_revision;
        assert!(stale_channel_work);
        assert!(idle.after_step(selected, false, false, stale_channel_work)); // stale cache dropped
        assert_eq!(
            idle.select_class(false, false, false, false, true, true),
            Some(WorkClass::Peer)
        );
        assert!(!idle.after_step(WorkClass::Peer, false, true, false));
        authority_revision += 1;
        assert!(!idle.after_step(WorkClass::Peer, true, true, true));
        authority_revision += 1;
        assert!(idle.after_step(WorkClass::Peer, false, true, true));
        assert_eq!(
            idle.select_class(false, false, false, false, true, true),
            Some(WorkClass::Channel)
        );
        let fresh_channel_observation = authority_revision;
        assert!(!idle.after_step(WorkClass::Channel, false, true, false)); // fresh poll
        assert_eq!(fresh_channel_observation, authority_revision);
        authority_revision += 1;
        assert!(!idle.after_step(WorkClass::Channel, true, true, true)); // prepare
        authority_revision += 1;
        assert!(idle.after_step(WorkClass::Channel, false, true, true)); // send
        assert!(authority_revision > fresh_channel_observation);
    }

    #[test]
    fn pending_setup_defers_retained_classes_without_consuming_reservations() {
        let mut idle = IdleScheduler::default();

        // A cached Peer reservation is held while setup owns this turn.
        assert_eq!(
            idle.select_class_for_ready_turn(false, false, true, false, false, false, false),
            Some(WorkClass::Peer)
        );
        assert!(!idle.after_step(WorkClass::Peer, false, true, false));
        let peer_cached_reservation = idle.reservation;
        assert_eq!(
            idle.select_class_for_ready_turn(true, true, true, true, true, true, true),
            None
        );
        assert_eq!(idle.reservation, peer_cached_reservation);
        assert_eq!(
            idle.select_class_for_ready_turn(false, false, true, false, false, false, false),
            Some(WorkClass::Peer)
        );
        assert!(!idle.after_step(WorkClass::Peer, true, true, false));
        let peer_active_reservation = idle.reservation;
        assert_eq!(
            idle.select_class_for_ready_turn(true, true, true, true, true, true, true),
            None
        );
        assert_eq!(idle.reservation, peer_active_reservation);
        assert_eq!(
            idle.select_class_for_ready_turn(false, true, true, true, true, false, false),
            Some(WorkClass::Peer)
        );
        assert!(idle.after_step(WorkClass::Peer, false, false, true));

        // Releasing Peer yields to cached Channel work. Its cached and active
        // phases are paused the same way, then the next reservation is Peer.
        assert_eq!(
            idle.select_class_for_ready_turn(false, false, false, false, true, false, false),
            Some(WorkClass::Channel)
        );
        assert!(!idle.after_step(WorkClass::Channel, false, true, false));
        let channel_cached_reservation = idle.reservation;
        assert_eq!(
            idle.select_class_for_ready_turn(true, true, true, true, true, true, true),
            None
        );
        assert_eq!(idle.reservation, channel_cached_reservation);
        assert_eq!(
            idle.select_class_for_ready_turn(false, false, false, false, true, false, false),
            Some(WorkClass::Channel)
        );
        assert!(!idle.after_step(WorkClass::Channel, true, true, false));
        let channel_active_reservation = idle.reservation;
        assert_eq!(
            idle.select_class_for_ready_turn(true, true, true, true, true, true, true),
            None
        );
        assert_eq!(idle.reservation, channel_active_reservation);
        assert_eq!(
            idle.select_class_for_ready_turn(false, false, false, true, true, false, false),
            Some(WorkClass::Channel)
        );
        assert!(idle.after_step(WorkClass::Channel, false, false, true));
        assert_eq!(
            idle.select_class_for_ready_turn(false, false, true, false, false, true, true),
            Some(WorkClass::Peer)
        );
    }

    #[test]
    fn staged_output_defers_retained_class_until_message_drains_then_yields_to_idle() {
        let mut idle = IdleScheduler::default();
        let class = idle
            .select_class_for_ready_turn(false, false, false, false, true, false, true)
            .unwrap();
        assert_eq!(class, WorkClass::Channel);
        assert!(!idle.after_step(class, false, true, false));
        let cached_reservation = idle.reservation;

        // A finite queued message can have multiple fragments. Keep the same
        // idle reservation while each staged fragment is sent.
        assert_eq!(
            idle.select_class_for_ready_turn(true, true, true, true, true, true, true),
            None
        );
        assert_eq!(idle.reservation, cached_reservation);
        assert_eq!(
            idle.select_class_for_ready_turn(true, true, true, true, true, true, true),
            None
        );
        assert_eq!(idle.reservation, cached_reservation);

        // The last fragment drains the staged message. A terminal producer may
        // still have another event ready, but that next message is not staged
        // until ingress advances after this normal idle opportunity.
        let terminal_producer_has_next_event = true;
        let staged_output_pending = false;
        assert!(terminal_producer_has_next_event);
        assert_eq!(
            idle.select_class_for_ready_turn(
                staged_output_pending,
                false,
                false,
                false,
                true,
                false,
                true,
            ),
            Some(class)
        );
        assert_eq!(idle.reservation, cached_reservation);
    }

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

    #[test]
    fn explicit_retry_wait_returns_immediately_when_stopping() {
        let stopping = Arc::new(AtomicBool::new(true));
        let retry_requested = Arc::new(AtomicBool::new(false));
        let (command_sender, receiver) = mpsc::channel();
        let (done_sender, done_receiver) = mpsc::channel();
        let waiter = thread::spawn(move || {
            let result = await_explicit_retry(&receiver, &stopping, &retry_requested);
            done_sender.send(result).unwrap();
        });

        assert!(
            !done_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("stopped retry wait should return promptly")
        );
        waiter.join().unwrap();
        drop(command_sender);
    }

    #[test]
    fn explicit_retry_wait_observes_stop_while_waiting() {
        let stopping = Arc::new(AtomicBool::new(false));
        let retry_requested = Arc::new(AtomicBool::new(false));
        let (command_sender, receiver) = mpsc::channel();
        let (started_sender, started_receiver) = mpsc::channel();
        let (done_sender, done_receiver) = mpsc::channel();
        let thread_stopping = Arc::clone(&stopping);
        let waiter = thread::spawn(move || {
            started_sender.send(()).unwrap();
            let result = await_explicit_retry(&receiver, &thread_stopping, &retry_requested);
            done_sender.send(result).unwrap();
        });

        started_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("retry waiter should start");
        thread::sleep(Duration::from_millis(20));
        stopping.store(true, Ordering::Release);

        assert!(
            !done_receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("retry wait should observe stop within one poll interval")
        );
        waiter.join().unwrap();
        drop(command_sender);
    }

    #[test]
    fn explicit_retry_wait_still_returns_for_a_requested_retry() {
        let stopping = AtomicBool::new(false);
        let retry_requested = AtomicBool::new(true);
        let (_command_sender, receiver) = mpsc::channel();

        assert!(await_explicit_retry(&receiver, &stopping, &retry_requested));
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
                        lomi_platform::secret_service::HostProfileContext::open(
                            endpoint.profile().path(),
                        )
                        .and_then(|host_context| {
                            lomi_platform::secret_service::SecretService::open(
                                endpoint.profile(),
                                host_context,
                                Selection::SecretService,
                                endpoint.discovery().profile_id,
                            )
                            .map(|p| Box::new(p) as Box<dyn SecretStorage>)
                        })
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
        if stopping.load(Ordering::Acquire) {
            return false;
        }
        if retry_requested.load(Ordering::Acquire) {
            return true;
        }
        match receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(Command::Wake(_) | Command::Logout | Command::Configure)
            | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return false,
        }
    }
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
fn suspend_expired(runtime: Runtime<'_>, generation: u64) -> Result<(), StepError> {
    runtime.gate.store(true, Ordering::Release);
    let state = worker_read!(
        runtime,
        runtime.owner.authorization_state(runtime.operation)
    )?;
    if state.generation != generation || state.pending_cloud_revoke {
        return Err(StepError::Stale);
    }
    if !state.locked {
        let mut turn = runtime
            .owner
            .begin_suspend_authorization(runtime.operation, generation)?;
        commit_worker_turn!(turn, runtime)?;
    }
    runtime.check()?;
    let mut view = runtime
        .state
        .lock()
        .map_err(|_| StepError::Auth(lomi_host_auth::Error::Sealed))?;
    view.status.phase = LocalAuthPhase::Locked;
    view.status.storage = LocalAuthStorage::Available;
    view.status.network = LocalAuthNetwork::Unavailable;
    view.status.locked = true;
    view.presentation = None;
    Ok(())
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

    /// Injected transports deny self-retirement unless they opt into the
    /// purpose-specific proof route. This response never counts as an ACK.
    fn self_retire(
        &self,
        _host: lomi_remote_protocol::HostId,
        _request: &lomi_remote_protocol::HostSelfRetirementParams,
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

    fn self_retire(
        &self,
        host: lomi_remote_protocol::HostId,
        request: &lomi_remote_protocol::HostSelfRetirementParams,
    ) -> Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error> {
        Transport::self_retire(self, host, request)
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
        WorkerReadyError::ExpiredBeforeAccept if retained_rotation => StepError::ExpiredRotation,
        WorkerReadyError::ExpiredBeforeAccept if retained_enrollment => {
            StepError::ExpiredEnrollment
        }
        WorkerReadyError::ExpiredBeforeAccept => StepError::Auth(lomi_host_auth::Error::Expired),
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorkClass {
    Peer,
    Channel,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorkPhase {
    Poll,
    CachedFirst,
    Active,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WorkReservation {
    class: WorkClass,
    phase: WorkPhase,
}
#[derive(Default)]
struct IdleScheduler {
    channel_next: bool,
    reservation: Option<WorkReservation>,
}
impl IdleScheduler {
    fn reset_reservation(&mut self) {
        self.reservation = None;
    }
    fn select_class_for_ready_turn(
        &mut self,
        priority_ingress_pending: bool,
        peer_active: bool,
        peer_cached: bool,
        channel_active: bool,
        channel_cached: bool,
        discovery_allowed: bool,
        channels_enabled: bool,
    ) -> Option<WorkClass> {
        if priority_ingress_pending {
            return None;
        }
        self.select_class(
            peer_active,
            peer_cached,
            channel_active,
            channel_cached,
            discovery_allowed,
            channels_enabled,
        )
    }
    fn select_class(
        &mut self,
        peer_active: bool,
        peer_cached: bool,
        channel_active: bool,
        channel_cached: bool,
        discovery_allowed: bool,
        channels_enabled: bool,
    ) -> Option<WorkClass> {
        if let Some(reservation) = self.reservation {
            let (active, cached, discovery) = match reservation.class {
                WorkClass::Peer => (peer_active, peer_cached, discovery_allowed),
                WorkClass::Channel => (
                    channel_active,
                    channel_cached,
                    discovery_allowed && channels_enabled,
                ),
            };
            if active || cached || (reservation.phase == WorkPhase::Poll && discovery) {
                return Some(reservation.class);
            }
            self.reservation = None;
        }
        let peer_runnable = peer_active || peer_cached || discovery_allowed;
        let channel_runnable =
            channel_active || channel_cached || (discovery_allowed && channels_enabled);
        let class = match (peer_runnable, channel_runnable) {
            (false, false) => return None,
            (true, false) => WorkClass::Peer,
            (false, true) => WorkClass::Channel,
            (true, true) if self.channel_next => WorkClass::Channel,
            (true, true) => WorkClass::Peer,
        };
        self.reservation = Some(WorkReservation {
            class,
            phase: WorkPhase::Poll,
        });
        Some(class)
    }
    fn after_step(
        &mut self,
        class: WorkClass,
        active: bool,
        cached: bool,
        consumed_work: bool,
    ) -> bool {
        let Some(mut reservation) = self.reservation else {
            return false;
        };
        if reservation.class != class {
            return false;
        }
        let release = match reservation.phase {
            WorkPhase::Poll => {
                if active {
                    reservation.phase = WorkPhase::Active;
                    false
                } else if consumed_work {
                    true
                } else if cached {
                    reservation.phase = WorkPhase::CachedFirst;
                    false
                } else {
                    true
                }
            }
            WorkPhase::CachedFirst => {
                if active {
                    reservation.phase = WorkPhase::Active;
                    false
                } else if consumed_work || !cached {
                    true
                } else {
                    false
                }
            }
            WorkPhase::Active => !active,
        };
        if release {
            self.reservation = None;
            self.channel_next = class == WorkClass::Peer;
            true
        } else {
            self.reservation = Some(reservation);
            false
        }
    }
    fn should_wake_after_step(
        &self,
        class: WorkClass,
        active: bool,
        cached: bool,
        succeeded: bool,
    ) -> bool {
        succeeded
            && (active || cached)
            && self
                .reservation
                .is_some_and(|reservation| reservation.class == class)
    }
}

fn cloud_step_requests_immediate_pass(outcome: &Result<cloud::StepOutcome, StepError>) -> bool {
    matches!(outcome, Ok(cloud::StepOutcome::Network))
}

#[derive(Default)]
enum PublicationBarrier {
    #[default]
    Open,
    Publishing(lomi_host_store::CloudRuntimeScope),
    Revalidating(lomi_host_store::CloudRuntimeScope),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicationBarrierObservation {
    Close,
    Suspend,
    Continue,
    Defer,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CloudOutcomeKind {
    Network,
    Deferred,
    PeerEligible,
}
impl PublicationBarrier {
    fn is_active(&self) -> bool {
        !matches!(self, Self::Open)
    }
    fn expected_scope(&self) -> Option<&lomi_host_store::CloudRuntimeScope> {
        match self {
            Self::Open => None,
            Self::Publishing(scope) | Self::Revalidating(scope) => Some(scope),
        }
    }
    fn is_publishing(&self) -> bool {
        matches!(self, Self::Publishing(_))
    }
    fn is_revalidating(&self) -> bool {
        matches!(self, Self::Revalidating(_))
    }
    fn pause(&mut self, scope: lomi_host_store::CloudRuntimeScope) -> bool {
        if self
            .expected_scope()
            .is_some_and(|expected| expected != &scope)
        {
            return false;
        }
        *self = Self::Publishing(scope);
        true
    }
    fn begin_revalidation(&mut self) -> bool {
        let Self::Publishing(scope) = self else {
            return false;
        };
        *self = Self::Revalidating(scope.clone());
        true
    }
    fn reset(&mut self) {
        *self = Self::Open;
    }
    fn retains_operation(&self) -> bool {
        self.is_active()
    }
    fn observe(
        &mut self,
        observation: super::shared_owner::CloudPublicationFenceObservation,
        cloud: &mut cloud::Worker,
    ) -> PublicationBarrierObservation {
        use super::shared_owner::CloudPublicationFenceObservation as Observation;
        match observation {
            Observation::CloseIngress => {
                self.reset();
                PublicationBarrierObservation::Close
            }
            Observation::PauseIngress(scope) => {
                if self.pause(scope) {
                    PublicationBarrierObservation::Suspend
                } else {
                    self.reset();
                    PublicationBarrierObservation::Close
                }
            }
            Observation::Clear => {
                if self.is_publishing()
                    && !self
                        .expected_scope()
                        .is_some_and(|scope| cloud.require_fresh_runtime_read(scope))
                {
                    self.reset();
                    return PublicationBarrierObservation::Close;
                }
                if self.is_publishing() && !self.begin_revalidation() {
                    self.reset();
                    return PublicationBarrierObservation::Close;
                }
                if self.is_active() {
                    PublicationBarrierObservation::Suspend
                } else {
                    PublicationBarrierObservation::Continue
                }
            }
            Observation::Defer => PublicationBarrierObservation::Defer,
        }
    }
    fn release_ingress_for(&mut self, outcome: CloudOutcomeKind) -> bool {
        if self.is_active() && outcome == CloudOutcomeKind::PeerEligible && self.is_revalidating() {
            self.reset();
        }
        self.allows_ingress_io()
    }
    fn allows_ingress_io(&self) -> bool {
        !self.is_active()
    }
}

fn worker_unit_retained(
    cloud: bool,
    peer: bool,
    channel: bool,
    ingress: bool,
    publication_barrier: &PublicationBarrier,
) -> bool {
    cloud || peer || channel || ingress || publication_barrier.retains_operation()
}

#[cfg(test)]
mod publication_barrier_tests {
    use super::*;
    use lomi_remote_protocol::{HostId, RuntimeId};
    use std::sync::atomic::AtomicBool;

    fn make_scope(generation: u64) -> lomi_host_store::CloudRuntimeScope {
        lomi_host_store::CloudRuntimeScope {
            authorization_generation: generation,
            remote_api_origin: "https://remote.example".to_owned(),
            host_id: HostId::from_bytes([1; 16]).unwrap(),
            owner_runtime_id: RuntimeId::from_bytes([2; 16]).unwrap(),
            owner_generation: 3,
        }
    }

    #[test]
    fn production_gate_suspends_every_outcome_until_fresh_revalidation() {
        let scope = make_scope(7);
        let mut barrier = PublicationBarrier::default();
        let mut cloud = cloud::Worker::default();

        assert_eq!(
            barrier.observe(
                super::super::shared_owner::CloudPublicationFenceObservation::PauseIngress(
                    scope.clone()
                ),
                &mut cloud,
            ),
            PublicationBarrierObservation::Suspend
        );
        assert!(barrier.retains_operation());
        assert!(!barrier.allows_ingress_io());
        for outcome in [
            CloudOutcomeKind::Network,
            CloudOutcomeKind::Deferred,
            CloudOutcomeKind::PeerEligible,
        ] {
            assert!(!barrier.release_ingress_for(outcome));
        }
        assert_eq!(
            barrier.observe(
                super::super::shared_owner::CloudPublicationFenceObservation::Defer,
                &mut cloud,
            ),
            PublicationBarrierObservation::Defer
        );
        assert!(barrier.is_publishing());
        assert!(!barrier.allows_ingress_io());

        assert_eq!(
            barrier.observe(
                super::super::shared_owner::CloudPublicationFenceObservation::Clear,
                &mut cloud,
            ),
            PublicationBarrierObservation::Suspend
        );
        assert!(barrier.is_revalidating());
        assert!(cloud.fresh_runtime_read_is_retained_get());
        // Simulated Network outcomes test the production gate only; no HTTP is run here.
        assert!(!barrier.release_ingress_for(CloudOutcomeKind::Network));
        assert!(!barrier.release_ingress_for(CloudOutcomeKind::Network));
        assert!(!barrier.release_ingress_for(CloudOutcomeKind::Deferred));
        assert!(barrier.release_ingress_for(CloudOutcomeKind::PeerEligible));
        assert!(!barrier.is_active());
        assert!(barrier.allows_ingress_io());
    }

    #[test]
    fn new_debt_reuses_the_pinned_scope_and_restarts_revalidation() {
        let scope = make_scope(7);
        let mut barrier = PublicationBarrier::default();
        let mut cloud = cloud::Worker::default();

        assert_eq!(
            barrier.observe(
                super::super::shared_owner::CloudPublicationFenceObservation::PauseIngress(
                    scope.clone()
                ),
                &mut cloud,
            ),
            PublicationBarrierObservation::Suspend
        );
        assert_eq!(
            barrier.observe(
                super::super::shared_owner::CloudPublicationFenceObservation::Clear,
                &mut cloud,
            ),
            PublicationBarrierObservation::Suspend
        );
        assert_eq!(
            barrier.observe(
                super::super::shared_owner::CloudPublicationFenceObservation::PauseIngress(
                    scope.clone()
                ),
                &mut cloud,
            ),
            PublicationBarrierObservation::Suspend
        );
        assert!(!barrier.release_ingress_for(CloudOutcomeKind::PeerEligible));
        assert!(barrier.is_publishing());
        assert_eq!(
            barrier.observe(
                super::super::shared_owner::CloudPublicationFenceObservation::PauseIngress(
                    make_scope(8)
                ),
                &mut cloud,
            ),
            PublicationBarrierObservation::Close
        );
        assert!(!barrier.is_active());

        assert_eq!(
            barrier.observe(
                super::super::shared_owner::CloudPublicationFenceObservation::PauseIngress(
                    scope.clone()
                ),
                &mut cloud,
            ),
            PublicationBarrierObservation::Suspend
        );
        assert!(barrier.is_publishing());
        assert!(!barrier.release_ingress_for(CloudOutcomeKind::PeerEligible));
        assert_eq!(
            barrier.observe(
                super::super::shared_owner::CloudPublicationFenceObservation::Clear,
                &mut cloud,
            ),
            PublicationBarrierObservation::Suspend
        );
        assert!(barrier.is_revalidating());
        assert!(cloud.fresh_runtime_read_is_retained_get());
        assert_eq!(barrier.expected_scope(), Some(&scope));
    }

    #[test]
    fn publication_barrier_retains_original_operation_and_deadline() {
        let cancelled = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(30);
        let original = OwnerOperation::new(deadline, &cancelled);
        let identity = original.retained_identity();
        let aborted = std::cell::Cell::new(false);
        let stopping = AtomicBool::new(false);
        let mut units = WorkerOperationUnits::new(&original, &aborted);
        units.started = true;
        let mut barrier = PublicationBarrier::default();
        let mut cloud = cloud::Worker::default();

        assert_eq!(
            barrier.observe(
                super::super::shared_owner::CloudPublicationFenceObservation::PauseIngress(
                    make_scope(7)
                ),
                &mut cloud,
            ),
            PublicationBarrierObservation::Suspend
        );
        let retained = worker_unit_retained(false, false, false, false, &barrier);
        if units.started && !retained {
            units.admit_after_settlement(&stopping);
        }

        assert!(retained);
        assert!(units.operation().is_same_admission(&identity));
        assert_eq!(units.operation().deadline(), deadline);
    }

    #[test]
    fn finite_ingress_work_keeps_its_original_deadline_and_cancellation() {
        let cancelled = AtomicBool::new(false);
        let expired_deadline = Instant::now() - Duration::from_secs(1);
        let original = OwnerOperation::new(expired_deadline, &cancelled);
        let identity = original.retained_identity();
        let aborted = std::cell::Cell::new(false);
        let stopping = AtomicBool::new(false);
        let mut units = WorkerOperationUnits::new(&original, &aborted);
        units.started = true;
        let barrier = PublicationBarrier::default();

        assert!(worker_unit_retained(false, false, false, true, &barrier));
        assert_eq!(units.operation().check(), Err(DomainError::Deadline));
        assert!(units.operation().is_same_admission(&identity));
        assert_eq!(units.operation().deadline(), expired_deadline);

        // After the actor's existing expiry cleanup discards ingress, only then
        // may settlement admit a successor operation.
        assert!(!worker_unit_retained(false, false, false, false, &barrier));
        units.admit_after_settlement(&stopping);
        assert!(!units.operation().is_same_admission(&identity));
        assert!(units.operation().deadline() > Instant::now());

        let cancelled = AtomicBool::new(false);
        let cancelled_deadline = Instant::now() + Duration::from_secs(30);
        let cancelled_operation = OwnerOperation::new(cancelled_deadline, &cancelled);
        let cancelled_identity = cancelled_operation.retained_identity();
        cancelled.store(true, Ordering::Release);
        assert_eq!(cancelled_operation.check(), Err(DomainError::Cancelled));
        assert!(cancelled_operation.is_same_admission(&cancelled_identity));
        assert_eq!(cancelled_operation.deadline(), cancelled_deadline);
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
    let mut publication_barrier = PublicationBarrier::default();
    let mut peer = peer::Worker::default();
    let mut channel = channel::Worker::default();
    let mut idle = IdleScheduler::default();
    let initial_runtime = runtime;
    let mut units = WorkerOperationUnits::new(runtime.operation, runtime.aborted);
    let mut immediate_ingress_pass = false;
    while !stopping.load(Ordering::Acquire) || ingress.has_active_git_writer() {
        let scheduling_time = Instant::now();
        let retained = worker_unit_retained(
            cloud.has_retained_operation(),
            peer.has_retained_operation(),
            channel.has_retained_operation(),
            ingress.has_retained_operation_at(scheduling_time),
            &publication_barrier,
        );
        let settled_at_message_boundary = units.started
            && !retained
            && units.operation().check().is_ok()
            && ingress.suspend_at_message_boundary(scheduling_time);
        if settled_at_message_boundary {
            cloud.finish_operation();
            idle.reset_reservation();
            units.admit_after_settlement(stopping);
        }
        // Rejected settlement must not issue a standalone clock mutation
        // against the other connections' still-retained peer scopes.
        let retained = retained || (units.started && !settled_at_message_boundary);
        units.started = true;
        let mut runtime =
            initial_runtime.with_operation_at(units.operation(), units.aborted(), base, anchor);
        if settled_at_message_boundary {
            // This no-eligibility poll preserves only the established socket
            // resource and applies the original peer cutoff before the fresh
            // Cloud read/heartbeat and maintenance pairing read below.
            ingress.poll(auth, runtime, None);
        }
        let operation = runtime.operation;
        let wait = remote_ingress::actor_wait_duration(std::mem::take(&mut immediate_ingress_pass));
        match receiver.recv_timeout(wait) {
            Ok(Command::Wake(id)) => {
                let _ = id;
            }
            Ok(Command::Logout | Command::Configure) | Err(_) => {}
        }
        if stopping.load(Ordering::Acquire) {
            publication_barrier.reset();
            if ingress.has_active_git_writer() {
                ingress.cancel_started_git();
                let _ = ingress.advance_started_git(auth, runtime);
                continue;
            }
            break;
        }
        if paused.load(Ordering::Acquire) {
            publication_barrier.reset();
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
            idle.reset_reservation();
            publication_barrier.reset();
            ingress.discard();
            gate.store(true, Ordering::Release);
            units.admit_after_settlement(stopping);
            continue;
        }
        if runtime.check().is_err() {
            if ingress.has_active_git_writer() {
                ingress.cancel_started_git();
                immediate_ingress_pass = ingress.advance_started_git(auth, runtime);
                continue;
            }
            publication_barrier.reset();
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
                idle.reset_reservation();
                publication_barrier.reset();
                ingress.discard();
                gate.store(true, Ordering::Release);
                units.admit_after_settlement(stopping);
                continue;
            }
            if let Ok(mut turn) = owner.begin_seal_authorization(operation) {
                let _ = commit_worker_turn!(turn, runtime);
            }
            publication_barrier.reset();
            set_failed(state, LocalAuthStorage::Unavailable, gate);
            return;
        };
        let fence = snapshot.authorization;
        let intent = snapshot.intent;
        let deferred_intent = snapshot.deferred_intent;
        if publication_barrier.is_active() && fence.pending_cloud_revoke {
            publication_barrier.reset();
            ingress.discard();
        }
        if publication_barrier.is_active() && auth.status() != Status::Ready {
            publication_barrier.reset();
            ingress.discard();
        }
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
                idle.reset_reservation();
                publication_barrier.reset();
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
            idle.reset_reservation();
            publication_barrier.reset();
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
                publication_barrier.reset();
                ingress.discard();
                channel.discard_retained_operation();
                idle.reset_reservation();
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
                        publication_barrier.reset();
                        ingress.discard();
                    } else {
                        let expected_scope = publication_barrier.expected_scope().or_else(|| {
                            cloud
                                .cached_eligibility()
                                .map(|eligibility| &eligibility.binding.scope)
                        });
                        let observation = runtime.owner.cloud_publication_fence_observation(
                            runtime.operation,
                            fence.generation,
                            expected_scope,
                        )?;
                        let observation = if ingress.has_active_git_writer() {
                            match observation {
                                super::shared_owner::CloudPublicationFenceObservation::PauseIngress(
                                    _,
                                ) => super::shared_owner::CloudPublicationFenceObservation::CloseIngress,
                                other => other,
                            }
                        } else {
                            observation
                        };
                        match publication_barrier.observe(observation, &mut cloud) {
                            PublicationBarrierObservation::Close => {
                                ingress.discard();
                            }
                            PublicationBarrierObservation::Suspend => {
                                ingress.poll(auth, runtime, None);
                            }
                            PublicationBarrierObservation::Continue => {
                                ingress.poll(auth, runtime, cloud.cached_eligibility());
                            }
                            PublicationBarrierObservation::Defer => {
                                // Store contention is a bounded pause. In
                                // particular, do not run Cloud's strict Domain
                                // observer while an ingress writer owns it.
                                if publication_barrier.is_active() {
                                    ingress.poll(auth, runtime, None);
                                }
                                return Ok(false);
                            }
                        }
                        if ingress.has_active_git_writer() {
                            // The retained Git writer owns the Domain ticket.
                            // Advance its finalization but defer Cloud/peer/
                            // channel readers until that ticket is released.
                            requested_immediate_ingress_pass |=
                                ingress.advance(auth, runtime, cloud.cached_eligibility());
                            return Ok(requested_immediate_ingress_pass);
                        }
                    }
                    if intent.is_some()
                        || (was_active && (fence.locked || gate.load(Ordering::Acquire)))
                    {
                        ingress.discard();
                        channel.discard_retained_operation();
                        idle.reset_reservation();
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
                        idle.reset_reservation();
                        ingress.discard();
                        auth.prepare_rotation(now)?;
                    } else {
                        // Recheck heartbeat eligibility every Ready turn, even
                        // while a peer or channel operation is retained.
                        let cloud_result = cloud.step(auth, config, runtime, fence.generation);
                        requested_immediate_ingress_pass |=
                            cloud_step_requests_immediate_pass(&cloud_result);
                        let outcome = match cloud_result {
                            Ok(outcome) => outcome,
                            Err(error) => {
                                if publication_barrier.is_active() && cloud.is_blocked() {
                                    publication_barrier.reset();
                                    ingress.discard();
                                }
                                return Err(error);
                            }
                        };
                        if cloud.take_rejected_fresh_runtime_read() {
                            publication_barrier.reset();
                            ingress.discard();
                            return Ok(false);
                        }
                        let outcome_kind = match &outcome {
                            cloud::StepOutcome::Network => CloudOutcomeKind::Network,
                            cloud::StepOutcome::Deferred => CloudOutcomeKind::Deferred,
                            cloud::StepOutcome::PeerEligible(_) => CloudOutcomeKind::PeerEligible,
                        };
                        if !publication_barrier.release_ingress_for(outcome_kind) {
                            match outcome {
                                cloud::StepOutcome::Network => {
                                    debug_assert!(requested_immediate_ingress_pass);
                                    return Ok(true);
                                }
                                cloud::StepOutcome::Deferred => {
                                    if cloud.is_blocked() {
                                        publication_barrier.reset();
                                        ingress.discard();
                                    }
                                    return Ok(false);
                                }
                                cloud::StepOutcome::PeerEligible(_) => return Ok(false),
                            }
                        }
                        // A network step may replace the heartbeat before its
                        // cached eligibility is revalidated on the next pass.
                        let outcome = match outcome {
                            cloud::StepOutcome::Network => {
                                debug_assert!(requested_immediate_ingress_pass);
                                return Ok(true);
                            }
                            outcome => outcome,
                        };
                        if let cloud::StepOutcome::PeerEligible(eligibility) = outcome {
                            let peer_active = peer.has_active_work();
                            let peer_cached = peer.has_cached_work();
                            let channel_active = channel.has_active_work();
                            let channel_cached = channel.has_cached_work();
                            let setup_pending = ingress.has_pending_setup();
                            let staged_output_pending =
                                ingress.has_staged_output(runtime, Some(&eligibility));
                            let due_peer_refresh = ingress.has_due_peer_refresh(Instant::now());
                            let priority_ingress_pending = ingress.idle_priority_pending(
                                setup_pending,
                                staged_output_pending,
                                due_peer_refresh,
                            );
                            let discovery_allowed = apis.enabled && !setup_pending;
                            // Cloud retains priority above. Advance due peer
                            // refreshes, setup, or staged output before idle
                            // Peer/Channel work. A message settlement grants
                            // one global idle turn across all channels, even
                            // while sibling messages remain staged. Keep the
                            // reservation; producer-only readiness never blocks
                            // the gap after a finite message drains.
                            if let Some(class) = idle.select_class_for_ready_turn(
                                priority_ingress_pending,
                                peer_active,
                                peer_cached,
                                channel_active,
                                channel_cached,
                                discovery_allowed,
                                apis.channels_enabled,
                            ) {
                                match class {
                                    WorkClass::Channel => {
                                        let result = channel.step(
                                            auth,
                                            config,
                                            runtime,
                                            &eligibility,
                                            apis.channel,
                                        );
                                        if result.is_ok() {
                                            ingress.after_channel_step(
                                                &mut channel,
                                                auth,
                                                runtime,
                                                &eligibility,
                                            );
                                        }
                                        let released = idle.after_step(
                                            class,
                                            channel.has_active_work(),
                                            channel.has_cached_work(),
                                            channel.scheduled_item_consumed(),
                                        );
                                        if released {
                                            channel.discard_cached_work();
                                        }
                                        requested_immediate_ingress_pass |= idle
                                            .should_wake_after_step(
                                                class,
                                                channel.has_active_work(),
                                                channel.has_cached_work(),
                                                result.is_ok(),
                                            );
                                        result?;
                                    }
                                    WorkClass::Peer => {
                                        let result = peer.step(
                                            auth,
                                            config,
                                            runtime,
                                            &eligibility,
                                            apis.pairing,
                                        );
                                        let released = idle.after_step(
                                            class,
                                            peer.has_active_work(),
                                            peer.has_cached_work(),
                                            peer.scheduled_item_consumed(),
                                        );
                                        if released {
                                            peer.discard_cached_work();
                                        }
                                        requested_immediate_ingress_pass |= idle
                                            .should_wake_after_step(
                                                class,
                                                peer.has_active_work(),
                                                peer.has_cached_work(),
                                                result.is_ok(),
                                            );
                                        result?;
                                    }
                                }
                            }
                        }
                    }
                    // Heartbeat/refresh/configuration work above keeps priority.
                    // The driver owns only socket/crypto/codecs and request state.
                    if publication_barrier.allows_ingress_io() {
                        requested_immediate_ingress_pass |=
                            ingress.advance(auth, runtime, cloud.cached_eligibility());
                    }
                }
                Status::Rotating => {
                    ingress.discard();
                    channel.discard_retained_operation();
                    idle.reset_reservation();
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
                if publication_barrier.is_active() {
                    publication_barrier.reset();
                    ingress.discard();
                }
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
                if publication_barrier.is_active() {
                    publication_barrier.reset();
                    ingress.discard();
                }
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
                if publication_barrier.is_active() {
                    publication_barrier.reset();
                    ingress.discard();
                }
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
                match suspend_expired(runtime, fence.generation) {
                    Ok(()) => return,
                    Err(StepError::Stale) => continue,
                    Err(_) => {
                        set_failed(state, LocalAuthStorage::Unavailable, gate);
                        return;
                    }
                }
            }
            Err(StepError::ExpiredRotation)
                if fence.pending_cloud_revoke && auth.status() == Status::Rotating =>
            {
                if publication_barrier.is_active() {
                    publication_barrier.reset();
                    ingress.discard();
                }
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
                if publication_barrier.is_active() {
                    publication_barrier.reset();
                    ingress.discard();
                }
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
                if publication_barrier.is_active() {
                    publication_barrier.reset();
                    ingress.discard();
                }
                match suspend_expired(runtime, fence.generation) {
                    Ok(()) => return,
                    Err(StepError::Stale) => continue,
                    Err(_) => {
                        set_failed(state, LocalAuthStorage::Unavailable, gate);
                        return;
                    }
                }
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
                if publication_barrier.is_active() {
                    publication_barrier.reset();
                    ingress.discard();
                }
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
        let selected = worker_read!(runtime, runtime.owner.auth_selection(runtime.operation))?;
        let mut turn = runtime.owner.begin_acknowledge_local_authorization_logout(
            runtime.operation,
            generation,
            selected.configuration,
        )?;
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
                            if stopping.load(Ordering::Acquire) {
                                return Ok(());
                            }
                            retire_pending_family(auth, transport, config, runtime, generation)?;
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

fn retire_pending_family(
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    transport: &dyn AuthTransport,
    config: &Config,
    runtime: Runtime<'_>,
    generation: u64,
) -> Result<(), StepError> {
    let now = observed(runtime)?;
    if !pending_current(runtime, generation) {
        return Ok(());
    }
    let selected = worker_read!(runtime, runtime.owner.auth_selection(runtime.operation))?;
    let Some(selected_configuration) = selected.configuration.clone() else {
        return Err(lomi_host_auth::Error::InvalidState.into());
    };
    let selected_trusted = configuration(&selected.identity, &selected_configuration)
        .map_err(|_| StepError::Auth(lomi_host_auth::Error::InvalidConfig))?;
    if selected_trusted != *config {
        return Ok(());
    }
    let status = worker_read!(runtime, runtime.owner.auth_status(runtime.operation))?;
    if status.authorization.generation != generation || !status.authorization.pending_cloud_revoke {
        return Ok(());
    }
    let binding = auth.self_retirement_binding()?;
    let existing = worker_read!(
        runtime,
        runtime.owner.host_self_retirement_journal(
            runtime.operation,
            generation,
            &selected_configuration,
        )
    )?;
    let trigger = status.deferred_intent.map(|intent| intent.operation_id);
    if let Some(journal) = &existing
        && now >= journal.intent.expires_at.0
        && (journal.trigger_operation_id == trigger || trigger.is_none())
    {
        network(runtime.state, LocalAuthNetwork::Unavailable);
        let _ = wait_pending_proof_reprobe(
            runtime,
            generation,
            &selected_configuration,
            status.deferred_intent,
            Instant::now() + Duration::from_secs(5),
        )?;
        return Ok(());
    }

    let operation_id = OperationId::from_bytes(*uuid::Uuid::new_v4().as_bytes())
        .map_err(|_| StepError::Auth(lomi_host_auth::Error::InvalidResponse))?;
    let mut turn = runtime.owner.begin_host_self_retirement(
        runtime.operation,
        generation,
        selected_configuration.clone(),
        binding,
        operation_id,
        now,
    )?;
    let journal = commit_worker_turn!(turn, runtime)?;
    let request = auth.self_retirement_request(&journal.intent, now)?;
    let host = journal.intent.binding.host_id;
    network(runtime.state, LocalAuthNetwork::Working);
    runtime.check()?;
    let result = transport.self_retire(host, &request)?;

    let now = observed(runtime)?;
    let status = worker_read!(runtime, runtime.owner.auth_status(runtime.operation))?;
    let selected_after = worker_read!(runtime, runtime.owner.auth_selection(runtime.operation))?;
    let journal_after = worker_read!(
        runtime,
        runtime.owner.host_self_retirement_journal(
            runtime.operation,
            generation,
            &selected_configuration,
        )
    )?;
    if status.authorization.generation != generation
        || !status.authorization.pending_cloud_revoke
        || selected_after.configuration.as_ref() != Some(&selected_configuration)
        || configuration(&selected_after.identity, &selected_configuration)
            .map_err(|_| StepError::Auth(lomi_host_auth::Error::InvalidConfig))?
            != *config
        || journal_after.as_ref() != Some(&journal)
    {
        return Ok(());
    }
    runtime.check()?;
    // The guarded Store reads above can wait on an owner turn. Re-sample the
    // monotonic projection after those reads so acceptance cannot use a
    // pre-wait timestamp for an intent that expired while they were blocked.
    let acceptance_now = now
        .max(runtime.projected_time())
        .max(status.authorization.clock_floor);
    if acceptance_now >= journal.intent.expires_at.0 {
        // The late response may have committed remotely. Keep the provider and
        // durable intent untouched so the next read-only ACK probe can repair it.
        network(runtime.state, LocalAuthNetwork::Unavailable);
        return Ok(());
    }
    auth.accept_self_retirement(config.origin(), &request, result, acceptance_now)?;
    acknowledge_revoke(runtime, generation, true)?;
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
