//! Private actual Host Actor/Auth-app cycle fixture. This uses the same real
//! SQLite identity, ProtectedFile, actor calls and HTTPS server across process
//! phases; it never injects credentials or a Ready HostAuth state.
use super::*;

#[path = "managed_cloud_fixture.rs"]
mod managed_cloud_fixture;

use lomi_host_auth::{Config, HostAuth, RetainedRevocationAcknowledgement, Status};
use lomi_platform::{
    secrets::{ProtectedFileAcknowledgement, Selection},
    unix::{LocalDiscovery, OwnerEndpoint, OwnerLock, secrets::ProtectedFile},
};
use lomi_remote_protocol::{
    HostId, LocalIpcVersion, OperationId, PublicClientId,
    ipc::{
        LocalAuthConfiguration, LocalAuthConfigure, LocalAuthPhase, LocalAuthProvider, LocalCall,
        LocalFileAcknowledgement, LocalLoginPresentation, LocalLoginStart, LocalLoginStatus,
        LocalResult,
    },
    rpc::Confirmed,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender},
    },
    thread,
    time::{Duration, Instant},
};

const ACTOR_PHASE_ENV: &str = "LOMI_E2_AUTH_ACTOR_PHASE";
const READY_FILE: &str = "ready.json";
const SERVER_DROP_FILE: &str = "server-drop.json";
const SERVER_DROP_READY_FILE: &str = "server-drop.ready";
const SECRET_ACK_FILE: &str = "secret-ack.json";
const REOPENED_FILE: &str = "reopened.json";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicActorInit {
    user_code: String,
    host_id: HostId,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReadyDeadline {
    refresh_at: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServerDropMarker {
    committed: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RotationDeadline {
    rotation_expires_at: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SecretAckMarker {
    operation_id: OperationId,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReopenedInit {
    user_code: String,
    host_id: HostId,
    operation_id: OperationId,
}

struct ActorFixture {
    phase: String,
    profile_dir: PathBuf,
    root_der: Vec<u8>,
    origin: String,
}
struct ActorProfile {
    fixture: ActorFixture,
    endpoint: Arc<OwnerEndpoint>,
    owner: Arc<super::super::super::shared_owner::SharedOwner>,
    config: Config,
    host_id: HostId,
}
struct ActorWorker {
    stopping: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}
impl ActorWorker {
    fn stop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        if self
            .join
            .take()
            .is_some_and(|worker| worker.join().is_err())
        {
            fail("actor_worker_join");
        }
    }
}
impl Drop for ActorWorker {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        if let Some(worker) = self.join.take() {
            let _ = worker.join();
        }
    }
}

#[test]
#[ignore = "requires the private auth-app TLS handler and live fixture account"]
fn actual_host_actor_cycle() {
    let fixture = actor_fixture();
    match fixture.phase.as_str() {
        "enroll" => enroll(&fixture),
        "rotate-lost" => rotate_lost(&fixture),
        "ack-stop" => acknowledge_and_stop(&fixture),
        "repair" => repair_after_reopen(&fixture),
        _ => fail("actor_phase"),
    }
}

fn actor_fixture() -> ActorFixture {
    let phase = required_env(ACTOR_PHASE_ENV, 32);
    if !matches!(
        phase.as_str(),
        "enroll" | "rotate-lost" | "ack-stop" | "repair"
    ) {
        fail("actor_phase");
    }
    let directory = required_env("LOMI_E2_AUTH_CYCLE_DIR", 512);
    let (base, profile_dir) = super::private_paths_with_leaf(&directory, "host-actor-cycle");
    let creating = phase == "enroll";
    match fs::symlink_metadata(&profile_dir) {
        Ok(metadata) if !creating => {
            validate_directory(&metadata, 0o700, "actor_profile_directory");
            if fs::canonicalize(&profile_dir).ok().as_deref() != Some(profile_dir.as_path()) {
                fail("actor_profile_path");
            }
        }
        Ok(_) => fail("actor_profile_exists"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && creating => {}
        Err(_) => fail("actor_profile_missing"),
    }
    let root_path = required_env("LOMI_E2_AUTH_CYCLE_ROOT_DER", 512);
    let root_der = read_root_der(&root_path, &base);
    let origin = required_env("LOMI_E2_AUTH_CYCLE_ORIGIN", 256);
    validate_origin(&origin);
    ActorFixture {
        phase,
        profile_dir,
        root_der,
        origin,
    }
}

fn open_actor_profile(fixture: &ActorFixture) -> ActorProfile {
    let lock = match OwnerLock::acquire(&fixture.profile_dir) {
        Ok(value) => value,
        Err(_) => fail("actor_owner_lock"),
    };
    let database = match lock.prepare_database() {
        Ok(value) => value,
        Err(_) => fail("actor_database_path"),
    };
    let mut store = match super::super::super::HostStore::open(
        &database,
        super::super::super::Limits::default(),
    ) {
        Ok(value) => value,
        Err(_) => fail("actor_store_open"),
    };
    if super::super::super::public_configuration::startup(&mut store, lock.profile()).is_err() {
        fail("actor_public_configuration");
    }
    store.seal_authorization();
    let identity = store.identity().clone();
    let host_id = identity.host_id;
    let config = match Config::new(
        identity.host_id,
        identity.profile_id,
        fixture.origin.clone(),
        match PublicClientId::try_from(CLIENT_ID.to_owned()) {
            Ok(value) => value,
            Err(_) => fail("actor_client_id"),
        },
    ) {
        Ok(value) => value,
        Err(_) => fail("actor_auth_config"),
    };
    if fixture.phase != "enroll" {
        let initial: PublicActorInit =
            read_rendezvous(&fixture.profile_dir, USER_CODE_FILE, "actor_init_read");
        if initial.host_id != host_id {
            fail("actor_host_id_changed");
        }
    }
    let discovery = LocalDiscovery {
        version: LocalIpcVersion::CURRENT,
        profile_id: identity.profile_id,
        host_id,
        runtime_id: store.runtime_id(),
        build_id: "host-auth-actor-fixture".to_owned(),
    };
    let endpoint = match OwnerEndpoint::bind(lock, discovery) {
        Ok(value) => Arc::new(value),
        Err(_) => fail("actor_endpoint"),
    };
    let owner = match super::super::super::shared_owner::SharedOwner::new(store) {
        Ok(value) => value,
        Err(_) => fail("actor_shared_owner"),
    };
    ActorProfile {
        fixture: ActorFixture {
            phase: fixture.phase.clone(),
            profile_dir: fixture.profile_dir.clone(),
            root_der: fixture.root_der.clone(),
            origin: fixture.origin.clone(),
        },
        endpoint,
        owner,
        config,
        host_id,
    }
}

fn auth_configuration(fixture: &ActorFixture) -> LocalAuthConfiguration {
    LocalAuthConfiguration {
        version: 1,
        origin: match fixture.origin.clone().try_into() {
            Ok(value) => value,
            Err(_) => fail("actor_local_origin"),
        },
        remote_api_origin: None,
        relay_endpoint: None,
        client_id: match CLIENT_ID.to_owned().try_into() {
            Ok(value) => value,
            Err(_) => fail("actor_local_client_id"),
        },
        provider: LocalAuthProvider::ProtectedFile,
        keychain_path: None,
        protected_file_acknowledgement: Some(LocalFileAcknowledgement::OsPermissionsOnly),
    }
}

fn start_actor(
    profile: &ActorProfile,
    stopping: Arc<AtomicBool>,
    ack_checkpoint: Option<SyncSender<()>>,
) -> (super::super::Handle, ActorWorker, Arc<AtomicBool>) {
    let (handle, join) = super::super::start_with_auth_fixture(
        profile.endpoint.clone(),
        profile.owner.clone(),
        stopping.clone(),
        std::sync::Weak::new(),
        profile.fixture.root_der.clone(),
        ack_checkpoint,
    );
    (
        handle,
        ActorWorker {
            stopping: stopping.clone(),
            join: Some(join),
        },
        stopping,
    )
}

fn enroll(fixture: &ActorFixture) {
    let profile = open_actor_profile(fixture);
    let stopping = Arc::new(AtomicBool::new(false));
    let (handle, mut worker, stopping) = start_actor(&profile, stopping, None);
    dispatch(
        &handle,
        &stopping,
        LocalCall::AuthConfigure(LocalAuthConfigure {
            configuration: auth_configuration(fixture),
            operator_intent: Confirmed::Confirmed,
        }),
        "actor_configure",
    );
    let operation_id = new_operation_id();
    match dispatch(
        &handle,
        &stopping,
        LocalCall::LoginStart(LocalLoginStart { operation_id }),
        "actor_login_start",
    ) {
        LocalResult::LoginAccepted(accepted) if accepted.operation_id == operation_id => {}
        _ => fail("actor_login_not_accepted"),
    }
    let presentation = wait_for_presentation(&handle, &stopping, Duration::from_secs(30));
    write_rendezvous(
        &fixture.profile_dir,
        USER_CODE_FILE,
        &PublicActorInit {
            user_code: presentation.user_code.expose_wire().to_owned(),
            host_id: profile.host_id,
        },
    );
    actor_stage("public_init");

    // The parent runner approves this exact public code while the actor stays
    // alive. The only remote calls afterward are poll, exchange and register.
    let status = wait_until_ready(&handle, &stopping, Duration::from_secs(180));
    let operation = owner_operation(&stopping);
    let selection = match profile.owner.auth_selection(&operation) {
        Ok(value) => value,
        Err(_) => fail("actor_ready_store_read"),
    };
    if selection.verified_generation != Some(status.generation.0)
        || selection
            .configuration
            .as_ref()
            .is_none_or(|c| c.remote_api_origin.is_some())
    {
        fail("actor_ready_not_verified_auth_only");
    }
    let refresh_at = status.refresh_at.map(|value| value.0).unwrap_or(0);
    if refresh_at <= wall_now() {
        fail("actor_refresh_deadline");
    }
    stop_actor(&mut worker);
    write_rendezvous(
        &fixture.profile_dir,
        READY_FILE,
        &ReadyDeadline { refresh_at },
    );
    actor_stage("ready_verified");
}

fn wait_until_ready(
    handle: &super::super::Handle,
    stopping: &AtomicBool,
    timeout: Duration,
) -> LocalLoginStatus {
    let deadline = Instant::now() + timeout;
    let mut telemetry = ReadyStatusTelemetry::default();
    match wait_for_ready_status(
        stopping,
        deadline,
        |deadline| {
            let result = login_status(handle, stopping, deadline);
            if let Ok(status) = &result
                && let Some(bucket) = telemetry.observe(status)
            {
                actor_status(bucket);
            }
            result
        },
        Instant::now,
        thread::sleep,
    ) {
        Ok(status) => status,
        Err(ReadyWaitError::Cancelled) => fail("actor_ready_cancelled"),
        Err(ReadyWaitError::Deadline) => fail("actor_ready_timeout"),
        Err(ReadyWaitError::Unexpected) => fail("actor_login_status"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusReadError {
    Unavailable,
    Unexpected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadyWaitError {
    Cancelled,
    Deadline,
    Unexpected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadyStatusBucket {
    Initializing,
    AwaitingApproval,
    Exchanging,
    Registering,
    ReadyLocked,
    ReadyAuthorized,
    Locked,
    PendingRevoke,
    StorageUnavailable,
    StorageLocked,
    Unconfigured,
    Idle,
    Refreshing,
    Unavailable,
    Other,
}
impl ReadyStatusBucket {
    fn as_str(self) -> &'static str {
        match self {
            Self::Initializing => "initializing",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Exchanging => "exchanging",
            Self::Registering => "registering",
            Self::ReadyLocked => "ready_locked",
            Self::ReadyAuthorized => "ready_authorized",
            Self::Locked => "locked",
            Self::PendingRevoke => "pending_revoke",
            Self::StorageUnavailable => "storage_unavailable",
            Self::StorageLocked => "storage_locked",
            Self::Unconfigured => "unconfigured",
            Self::Idle => "idle",
            Self::Refreshing => "refreshing",
            Self::Unavailable => "unavailable",
            Self::Other => "other",
        }
    }
}

fn ready_status_bucket(status: &LocalLoginStatus) -> ReadyStatusBucket {
    use lomi_remote_protocol::ipc::LocalAuthStorage;
    if status.pending_cloud_revoke || status.phase == LocalAuthPhase::PendingRevoke {
        return ReadyStatusBucket::PendingRevoke;
    }
    match status.storage {
        LocalAuthStorage::Unavailable => return ReadyStatusBucket::StorageUnavailable,
        LocalAuthStorage::Locked => return ReadyStatusBucket::StorageLocked,
        LocalAuthStorage::Unconfigured | LocalAuthStorage::Available => {}
    }
    if status.storage == LocalAuthStorage::Unconfigured
        && !matches!(
            status.phase,
            LocalAuthPhase::Unconfigured | LocalAuthPhase::Idle
        )
    {
        return ReadyStatusBucket::Other;
    }
    match status.phase {
        LocalAuthPhase::Initializing => ReadyStatusBucket::Initializing,
        LocalAuthPhase::AwaitingApproval => ReadyStatusBucket::AwaitingApproval,
        LocalAuthPhase::Exchanging => ReadyStatusBucket::Exchanging,
        LocalAuthPhase::Registering => ReadyStatusBucket::Registering,
        LocalAuthPhase::Ready if status.locked => ReadyStatusBucket::ReadyLocked,
        LocalAuthPhase::Ready => ReadyStatusBucket::ReadyAuthorized,
        LocalAuthPhase::Locked => ReadyStatusBucket::Locked,
        LocalAuthPhase::PendingRevoke => ReadyStatusBucket::PendingRevoke,
        LocalAuthPhase::Unconfigured => ReadyStatusBucket::Unconfigured,
        LocalAuthPhase::Idle => ReadyStatusBucket::Idle,
        LocalAuthPhase::Refreshing => ReadyStatusBucket::Refreshing,
        LocalAuthPhase::Unavailable => ReadyStatusBucket::Unavailable,
    }
}

const MAX_READY_STATUS_RECORDS: usize = 32;
#[derive(Default)]
struct ReadyStatusTelemetry {
    last: Option<ReadyStatusBucket>,
    emitted: usize,
}
impl ReadyStatusTelemetry {
    fn observe(&mut self, status: &LocalLoginStatus) -> Option<ReadyStatusBucket> {
        let bucket = ready_status_bucket(status);
        let changed = self.last != Some(bucket);
        self.last = Some(bucket);
        if !changed || self.emitted >= MAX_READY_STATUS_RECORDS {
            return None;
        }
        self.emitted += 1;
        Some(bucket)
    }
}

fn wait_for_ready_status(
    stopping: &AtomicBool,
    deadline: Instant,
    mut read_status: impl FnMut(Instant) -> Result<LocalLoginStatus, StatusReadError>,
    mut now: impl FnMut() -> Instant,
    mut sleep: impl FnMut(Duration),
) -> Result<LocalLoginStatus, ReadyWaitError> {
    loop {
        if stopping.load(Ordering::Acquire) {
            return Err(ReadyWaitError::Cancelled);
        }
        if now() >= deadline {
            return Err(ReadyWaitError::Deadline);
        }
        let result = read_status(deadline);
        if stopping.load(Ordering::Acquire) {
            return Err(ReadyWaitError::Cancelled);
        }
        if now() >= deadline {
            return Err(ReadyWaitError::Deadline);
        }
        match result {
            Ok(status)
                if status.phase == LocalAuthPhase::Ready
                    && !status.locked
                    && !status.pending_cloud_revoke =>
            {
                return Ok(status);
            }
            Ok(_) | Err(StatusReadError::Unavailable) => {}
            Err(StatusReadError::Unexpected) => return Err(ReadyWaitError::Unexpected),
        }
        let remaining = deadline.saturating_duration_since(now());
        if remaining.is_zero() {
            return Err(ReadyWaitError::Deadline);
        }
        sleep(remaining.min(Duration::from_millis(25)));
    }
}

fn rotate_lost(fixture: &ActorFixture) {
    let ready: ReadyDeadline =
        read_rendezvous(&fixture.profile_dir, READY_FILE, "actor_ready_read");
    if wall_now() < ready.refresh_at {
        fail("actor_refresh_started_early");
    }
    require_absent(
        &fixture.profile_dir.join(SERVER_DROP_FILE),
        "actor_server_drop_exists",
    );
    require_absent(
        &fixture.profile_dir.join(SERVER_DROP_READY_FILE),
        "actor_server_drop_ready_exists",
    );
    let profile = open_actor_profile(fixture);
    let stopping = Arc::new(AtomicBool::new(false));
    let (_handle, mut worker, stopping) = start_actor(&profile, stopping, None);
    wait_for_server_drop(fixture, &stopping, Duration::from_secs(30));
    stop_actor(&mut worker);

    let mut storage = protected_storage(&profile.endpoint);
    let auth = match HostAuth::open(&mut storage, profile.config.clone(), wall_now()) {
        Ok(value) => value,
        Err(_) => fail("actor_rotation_reopen"),
    };
    if auth.status() != Status::Rotating {
        fail("actor_rotation_not_retained");
    }
    let rotation_expires_at = match auth.credential_deadlines() {
        Ok(deadlines) => match deadlines.rotation_expires_at {
            Some(value) if value > wall_now() => value,
            _ => fail("actor_rotation_deadline"),
        },
        Err(_) => fail("actor_rotation_deadline"),
    };
    drop(auth);
    drop(storage);
    write_rendezvous(
        &fixture.profile_dir,
        ROTATION_FILE,
        &RotationDeadline {
            rotation_expires_at,
        },
    );
    actor_stage("rotation_retained");
}

fn acknowledge_and_stop(fixture: &ActorFixture) {
    let rotation: RotationDeadline =
        read_rendezvous(&fixture.profile_dir, ROTATION_FILE, "actor_rotation_read");
    if wall_now() < rotation.rotation_expires_at {
        fail("actor_rotation_not_expired");
    }
    let profile = open_actor_profile(fixture);
    let mut storage = protected_storage(&profile.endpoint);
    let auth = match HostAuth::open(&mut storage, profile.config.clone(), wall_now()) {
        Ok(value) => value,
        Err(_) => fail("actor_ack_original_secret_open"),
    };
    if auth.status() != Status::Rotating {
        fail("actor_ack_original_not_rotating");
    }
    let original_epoch = match auth.verified_host_access_epoch() {
        Ok(value) => value.0,
        Err(_) => fail("actor_ack_original_epoch"),
    };
    drop(auth);
    drop(storage);
    let stopping = Arc::new(AtomicBool::new(false));
    let (checkpoint_tx, checkpoint_rx) = mpsc::sync_channel(1);
    let (handle, mut worker, stopping) = start_actor(&profile, stopping, Some(checkpoint_tx));
    let operation_id = new_operation_id();
    match dispatch(
        &handle,
        &stopping,
        LocalCall::LoginStart(LocalLoginStart { operation_id }),
        "actor_ack_login_start",
    ) {
        LocalResult::LoginAccepted(accepted) if accepted.operation_id == operation_id => {}
        _ => fail("actor_ack_login_not_accepted"),
    }
    match checkpoint_rx.recv_timeout(Duration::from_secs(60)) {
        Ok(()) => {}
        Err(_) => fail("actor_ack_checkpoint_timeout"),
    }
    stop_actor(&mut worker);
    let read_not_cancelled = AtomicBool::new(false);
    let operation = owner_operation(&read_not_cancelled);
    let snapshot = match profile.owner.auth_status(&operation) {
        Ok(value) => value,
        Err(_) => fail("actor_ack_store_read"),
    };
    if !snapshot.authorization.pending_cloud_revoke
        || snapshot.intent.is_some()
        || snapshot.deferred_intent.map(|intent| intent.operation_id) != Some(operation_id)
        || !snapshot.authorization.locked
    {
        fail("actor_ack_store_handoff_too_early");
    }
    let selection = match profile.owner.auth_selection(&operation) {
        Ok(value) => value,
        Err(_) => fail("actor_ack_selection_read"),
    };
    if selection.verified_generation.is_some() {
        fail("actor_ack_verified_generation_retained");
    }
    let mut storage = protected_storage(&profile.endpoint);
    let auth = match HostAuth::open(&mut storage, profile.config.clone(), wall_now()) {
        Ok(value) => value,
        Err(_) => fail("actor_ack_secret_reopen"),
    };
    if auth.status() != Status::Revoked {
        fail("actor_ack_secret_not_revoked");
    }
    match auth.retained_revocation_acknowledgement() {
        Ok(RetainedRevocationAcknowledgement::Host(result))
            if result.host_id == profile.host_id
                && original_epoch.checked_add(1) == Some(result.host_access_epoch.0) => {}
        _ => fail("actor_ack_secret_receipt"),
    }
    drop(auth);
    drop(storage);
    write_rendezvous(
        &fixture.profile_dir,
        SECRET_ACK_FILE,
        &SecretAckMarker { operation_id },
    );
    actor_stage("secret_ack_store_pending");
}

fn repair_after_reopen(fixture: &ActorFixture) {
    let init: PublicActorInit =
        read_rendezvous(&fixture.profile_dir, USER_CODE_FILE, "actor_init_read");
    let receipt: SecretAckMarker = read_rendezvous(
        &fixture.profile_dir,
        SECRET_ACK_FILE,
        "actor_secret_ack_read",
    );
    let profile = open_actor_profile(fixture);
    if profile.host_id != init.host_id {
        fail("actor_repair_host_id_changed");
    }
    let stopping = Arc::new(AtomicBool::new(false));
    let (handle, mut worker, stopping) = start_actor(&profile, stopping, None);
    let presentation = wait_for_presentation(&handle, &stopping, Duration::from_secs(30));
    stop_actor(&mut worker);
    let read_not_cancelled = AtomicBool::new(false);
    let operation = owner_operation(&read_not_cancelled);
    let snapshot = match profile.owner.auth_status(&operation) {
        Ok(value) => value,
        Err(_) => fail("actor_repair_store_read"),
    };
    let selection = match profile.owner.auth_selection(&operation) {
        Ok(value) => value,
        Err(_) => fail("actor_repair_selection_read"),
    };
    let history = match profile.owner.auth_history(&operation) {
        Ok(value) => value,
        Err(_) => fail("actor_repair_history_read"),
    };
    if snapshot.authorization.pending_cloud_revoke
        || !snapshot.authorization.locked
        || snapshot.intent.map(|intent| intent.operation_id) != Some(receipt.operation_id)
        || snapshot.deferred_intent.is_some()
        || selection.verified_generation.is_some()
        || selection
            .configuration
            .as_ref()
            .is_none_or(|c| c.remote_api_origin.is_some())
        || history.cloud_may_exist != Some(false)
    {
        fail("actor_repair_store_state");
    }
    write_rendezvous(
        &fixture.profile_dir,
        REOPENED_FILE,
        &ReopenedInit {
            user_code: presentation.user_code.expose_wire().to_owned(),
            host_id: profile.host_id,
            operation_id: receipt.operation_id,
        },
    );
    actor_stage("repair_reinitiated_locked");
}

fn wait_for_presentation(
    handle: &super::super::Handle,
    stopping: &AtomicBool,
    timeout: Duration,
) -> LocalLoginPresentation {
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            fail("actor_presentation_timeout");
        }
        let operation = owner_operation(stopping);
        match handle.dispatch(&operation, LocalCall::LoginPresentation {}) {
            Ok(LocalResult::LoginPresentation(value)) => return value,
            Err(
                super::super::super::LocalError::Conflict
                | super::super::super::LocalError::Unavailable,
            ) => {
                thread::sleep(Duration::from_millis(25));
            }
            _ => fail("actor_presentation_status"),
        }
    }
}

fn login_status(
    handle: &super::super::Handle,
    stopping: &AtomicBool,
    deadline: Instant,
) -> Result<LocalLoginStatus, StatusReadError> {
    let operation = super::super::super::owner_domain::Operation::new(deadline, stopping);
    match handle.dispatch(&operation, LocalCall::LoginStatus {}) {
        Ok(LocalResult::LoginStatus(status)) => Ok(status),
        Ok(_) => Err(StatusReadError::Unexpected),
        Err(super::super::super::LocalError::Unavailable) => Err(StatusReadError::Unavailable),
        Err(_) => Err(StatusReadError::Unexpected),
    }
}

fn dispatch(
    handle: &super::super::Handle,
    stopping: &AtomicBool,
    call: LocalCall,
    stage: &'static str,
) -> LocalResult {
    let operation = owner_operation(stopping);
    match handle.dispatch(&operation, call) {
        Ok(value) => value,
        Err(_) => fail(stage),
    }
}

fn owner_operation(stopping: &AtomicBool) -> super::super::super::owner_domain::Operation<'_> {
    super::super::super::owner_domain::Operation::new(
        Instant::now() + Duration::from_secs(30),
        stopping,
    )
}

fn actor_stage(stage: &'static str) {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    if writeln!(output, "LOMI_AUTH_ACTOR_STAGE={stage}")
        .and_then(|()| output.flush())
        .is_err()
    {
        fail("actor_stage_flush");
    }
}

fn actor_status(bucket: ReadyStatusBucket) {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    if writeln!(output, "LOMI_AUTH_ACTOR_STATUS={}", bucket.as_str())
        .and_then(|()| output.flush())
        .is_err()
    {
        fail("actor_status_flush");
    }
}

fn new_operation_id() -> OperationId {
    match OperationId::from_bytes(uuid::Uuid::new_v4().into_bytes()) {
        Ok(value) => value,
        Err(_) => fail("actor_operation_id"),
    }
}

fn wait_for_server_drop(fixture: &ActorFixture, stopping: &AtomicBool, timeout: Duration) {
    let path = fixture.profile_dir.join(SERVER_DROP_READY_FILE);
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            fail("actor_server_drop_timeout");
        }
        match fs::symlink_metadata(&path) {
            Ok(before) => {
                validate_server_drop_ready(&before);
                let ready = open_private_regular(&path, 0o600, 0, "actor_server_drop_ready_open");
                let opened = match ready.metadata() {
                    Ok(value) => value,
                    Err(_) => fail("actor_server_drop_ready_stat"),
                };
                validate_server_drop_ready(&opened);
                let after = match fs::symlink_metadata(&path) {
                    Ok(value) => value,
                    Err(_) => fail("actor_server_drop_ready_replaced"),
                };
                validate_server_drop_ready(&after);
                if before.dev() != opened.dev()
                    || before.ino() != opened.ino()
                    || opened.dev() != after.dev()
                    || opened.ino() != after.ino()
                {
                    fail("actor_server_drop_ready_replaced");
                }
                drop(ready);
                let marker: ServerDropMarker =
                    read_rendezvous(&fixture.profile_dir, SERVER_DROP_FILE, "actor_server_drop");
                if !marker.committed {
                    fail("actor_server_drop_not_committed");
                }
                stopping.store(true, Ordering::Release);
                return;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => fail("actor_server_drop_stat"),
        }
    }
}

fn require_absent(path: &std::path::Path, stage: &'static str) {
    match fs::symlink_metadata(path) {
        Ok(_) => fail(stage),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => fail(stage),
    }
}

fn validate_server_drop_ready(metadata: &std::fs::Metadata) {
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() != 0
    {
        fail("actor_server_drop_ready_metadata");
    }
}

fn protected_storage<'owner>(endpoint: &'owner OwnerEndpoint) -> ProtectedFile<'owner> {
    match ProtectedFile::open(
        endpoint.profile(),
        Selection::ProtectedFile(ProtectedFileAcknowledgement::OsPermissionsOnly),
    ) {
        Ok(value) => value,
        Err(_) => fail("actor_protected_storage"),
    }
}

fn stop_actor(worker: &mut ActorWorker) {
    worker.stop();
}

#[cfg(test)]
mod ready_status_retry_tests {
    use super::*;
    use std::{cell::Cell, cell::RefCell};

    fn status(phase: LocalAuthPhase, locked: bool) -> LocalLoginStatus {
        LocalLoginStatus {
            phase,
            storage: lomi_remote_protocol::ipc::LocalAuthStorage::Available,
            network: lomi_remote_protocol::ipc::LocalAuthNetwork::Idle,
            generation: lomi_remote_protocol::DecimalU64(3),
            locked,
            pending_cloud_revoke: false,
            operation_id: None,
            access_expires_at: None,
            refresh_at: None,
        }
    }

    #[test]
    fn ready_status_telemetry_uses_only_closed_safe_buckets() {
        use lomi_remote_protocol::ipc::LocalAuthStorage;

        let cases = [
            (
                status(LocalAuthPhase::Initializing, true),
                ReadyStatusBucket::Initializing,
                "initializing",
            ),
            (
                status(LocalAuthPhase::AwaitingApproval, true),
                ReadyStatusBucket::AwaitingApproval,
                "awaiting_approval",
            ),
            (
                status(LocalAuthPhase::Exchanging, true),
                ReadyStatusBucket::Exchanging,
                "exchanging",
            ),
            (
                status(LocalAuthPhase::Registering, true),
                ReadyStatusBucket::Registering,
                "registering",
            ),
            (
                status(LocalAuthPhase::Ready, true),
                ReadyStatusBucket::ReadyLocked,
                "ready_locked",
            ),
            (
                status(LocalAuthPhase::Ready, false),
                ReadyStatusBucket::ReadyAuthorized,
                "ready_authorized",
            ),
            (
                status(LocalAuthPhase::Locked, true),
                ReadyStatusBucket::Locked,
                "locked",
            ),
            (
                status(LocalAuthPhase::PendingRevoke, true),
                ReadyStatusBucket::PendingRevoke,
                "pending_revoke",
            ),
            (
                {
                    let mut value = status(LocalAuthPhase::Unavailable, true);
                    value.storage = LocalAuthStorage::Unavailable;
                    value
                },
                ReadyStatusBucket::StorageUnavailable,
                "storage_unavailable",
            ),
            (
                {
                    let mut value = status(LocalAuthPhase::Unavailable, true);
                    value.storage = LocalAuthStorage::Locked;
                    value
                },
                ReadyStatusBucket::StorageLocked,
                "storage_locked",
            ),
            (
                {
                    let mut value = status(LocalAuthPhase::Ready, false);
                    value.storage = LocalAuthStorage::Unconfigured;
                    value
                },
                ReadyStatusBucket::Other,
                "other",
            ),
        ];

        for (status, expected, label) in cases {
            let bucket = ready_status_bucket(&status);
            assert_eq!(bucket, expected);
            assert_eq!(bucket.as_str(), label);
        }

        let mut pending = status(LocalAuthPhase::Unavailable, true);
        pending.pending_cloud_revoke = true;
        assert_eq!(
            ready_status_bucket(&pending),
            ReadyStatusBucket::PendingRevoke
        );
        assert_eq!(
            ready_status_bucket(&status(LocalAuthPhase::Idle, true)).as_str(),
            "idle"
        );
        assert_eq!(
            ready_status_bucket(&status(LocalAuthPhase::Unconfigured, true)).as_str(),
            "unconfigured"
        );
        assert_eq!(
            ready_status_bucket(&status(LocalAuthPhase::Refreshing, true)).as_str(),
            "refreshing"
        );
        assert_eq!(
            ready_status_bucket(&status(LocalAuthPhase::Unavailable, true)).as_str(),
            "unavailable"
        );
    }

    #[test]
    fn ready_status_telemetry_suppresses_duplicates_and_caps_records() {
        let mut telemetry = ReadyStatusTelemetry::default();
        let initializing = status(LocalAuthPhase::Initializing, true);
        let ready = status(LocalAuthPhase::Ready, false);
        assert_eq!(
            telemetry.observe(&initializing),
            Some(ReadyStatusBucket::Initializing)
        );
        assert_eq!(telemetry.observe(&initializing), None);
        assert_eq!(
            telemetry.observe(&ready),
            Some(ReadyStatusBucket::ReadyAuthorized)
        );

        let mut emitted = 2;
        for index in 0..(MAX_READY_STATUS_RECORDS + 20) {
            let value = if index % 2 == 0 {
                &initializing
            } else {
                &ready
            };
            emitted += usize::from(telemetry.observe(value).is_some());
        }
        assert_eq!(emitted, MAX_READY_STATUS_RECORDS);
        assert_eq!(telemetry.emitted, MAX_READY_STATUS_RECORDS);
        assert_eq!(telemetry.observe(&initializing), None);
        assert_eq!(telemetry.emitted, MAX_READY_STATUS_RECORDS);
    }

    #[test]
    fn retries_read_contention_until_ready_with_one_deadline() {
        let stopping = AtomicBool::new(false);
        let start = Instant::now();
        let elapsed = Cell::new(Duration::ZERO);
        let calls = Cell::new(0);
        let sleeps = RefCell::new(Vec::new());
        let deadlines = RefCell::new(Vec::new());
        let deadline = start + Duration::from_millis(100);
        let result = wait_for_ready_status(
            &stopping,
            deadline,
            |attempt_deadline| {
                deadlines.borrow_mut().push(attempt_deadline);
                let call = calls.get() + 1;
                calls.set(call);
                if call <= 2 {
                    Err(StatusReadError::Unavailable)
                } else {
                    Ok(status(LocalAuthPhase::Ready, false))
                }
            },
            || start + elapsed.get(),
            |delay| {
                sleeps.borrow_mut().push(delay);
                elapsed.set(elapsed.get() + delay);
            },
        );

        assert_eq!(result.unwrap().phase, LocalAuthPhase::Ready);
        assert_eq!(calls.get(), 3);
        assert_eq!(*sleeps.borrow(), [Duration::from_millis(25); 2]);
        assert_eq!(elapsed.get(), Duration::from_millis(50));
        assert_eq!(*deadlines.borrow(), [deadline; 3]);
    }

    #[test]
    fn permanent_status_failure_is_not_retried() {
        let stopping = AtomicBool::new(false);
        let start = Instant::now();
        let elapsed = Cell::new(Duration::ZERO);
        let calls = Cell::new(0);
        let result = wait_for_ready_status(
            &stopping,
            start + Duration::from_secs(1),
            |_| {
                calls.set(calls.get() + 1);
                Err(StatusReadError::Unexpected)
            },
            || start + elapsed.get(),
            |delay| elapsed.set(elapsed.get() + delay),
        );

        assert_eq!(result, Err(ReadyWaitError::Unexpected));
        assert_eq!(calls.get(), 1);
        assert_eq!(elapsed.get(), Duration::ZERO);
    }

    #[test]
    fn persistent_unavailable_expires_at_the_original_deadline() {
        let stopping = AtomicBool::new(false);
        let start = Instant::now();
        let elapsed = Cell::new(Duration::ZERO);
        let calls = Cell::new(0);
        let sleeps = RefCell::new(Vec::new());
        let result = wait_for_ready_status(
            &stopping,
            start + Duration::from_millis(40),
            |_| {
                calls.set(calls.get() + 1);
                Err(StatusReadError::Unavailable)
            },
            || start + elapsed.get(),
            |delay| {
                sleeps.borrow_mut().push(delay);
                elapsed.set(elapsed.get() + delay);
            },
        );

        assert_eq!(result, Err(ReadyWaitError::Deadline));
        assert_eq!(calls.get(), 2);
        assert_eq!(
            *sleeps.borrow(),
            [Duration::from_millis(25), Duration::from_millis(15)]
        );
        assert_eq!(elapsed.get(), Duration::from_millis(40));
    }

    #[test]
    fn cancellation_during_a_contended_read_prevents_another_retry() {
        let stopping = AtomicBool::new(false);
        let start = Instant::now();
        let calls = Cell::new(0);
        let sleeps = Cell::new(0);
        let result = wait_for_ready_status(
            &stopping,
            start + Duration::from_secs(1),
            |_| {
                calls.set(calls.get() + 1);
                stopping.store(true, Ordering::Release);
                Err(StatusReadError::Unavailable)
            },
            Instant::now,
            |_| sleeps.set(sleeps.get() + 1),
        );

        assert_eq!(result, Err(ReadyWaitError::Cancelled));
        assert_eq!(calls.get(), 1);
        assert_eq!(sleeps.get(), 0);
    }
}
