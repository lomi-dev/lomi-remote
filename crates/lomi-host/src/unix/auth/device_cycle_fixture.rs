//! Private actual Auth-app/HostAuth cycle fixture. The parent Auth-app test owns
//! the HTTPS listener and private PostgreSQL fixture; this test owns the real
//! HostAuth identity and the protected-file lifecycle across child processes.

use lomi_host_auth::{Config, Error as HostAuthError, HostAuth, Status};
use lomi_host_http::{Error as HttpError, HostFailure, PollOutcome, Transport};
use lomi_platform::{
    secrets::{ProtectedFileAcknowledgement, Selection},
    unix::{OwnerLock, secrets::ProtectedFile},
};
use lomi_remote_protocol::{HostId, HostRevokeParams, PublicClientId, ipc::IpcProfileId};
use serde::{Deserialize, Serialize};
use std::{
    env,
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const CLIENT_ID: &str = "lomi-desktop-dev";
const MAX_RENDEZVOUS_BYTES: u64 = 256;
const MAX_ROOT_DER_BYTES: u64 = 16 * 1024;
const USER_CODE_FILE: &str = "public-init.json";
const ROTATION_FILE: &str = "rotation.json";

mod actor_cycle_fixture;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicInit {
    user_code: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RotationIntent {
    prepared_at: u64,
}

struct Fixture {
    phase: String,
    profile_dir: PathBuf,
    root_der: Vec<u8>,
    origin: String,
    host: HostId,
    config: Config,
}

/// Run as three separate test-binary processes, with one private profile and
/// one actual HostAuth-generated identity shared between all phases.
#[cfg(feature = "cloud-fixture")]
#[test]
#[ignore = "requires the private auth-app TLS handler and live fixture account"]
pub(crate) fn actual_host_auth_cycle() {
    let fixture = fixture();
    match fixture.phase.as_str() {
        "initiate" => initiate(&fixture),
        "rotate-lost" => rotate_lost(&fixture),
        "ack-reopen" => acknowledge_after_reopen(&fixture),
        _ => fail("phase"),
    }
}

fn fixture() -> Fixture {
    let phase = required_env("LOMI_E2_AUTH_CYCLE_PHASE", 32);
    if !matches!(phase.as_str(), "initiate" | "rotate-lost" | "ack-reopen") {
        fail("phase");
    }

    let directory = required_env("LOMI_E2_AUTH_CYCLE_DIR", 512);
    let (base, profile_dir) = private_paths(&directory);
    let phase_is_init = phase == "initiate";
    match fs::symlink_metadata(&profile_dir) {
        Ok(metadata) => {
            if phase_is_init {
                fail("profile_exists");
            }
            validate_directory(&metadata, 0o700, "profile_directory");
            if fs::canonicalize(&profile_dir).ok().as_deref() != Some(profile_dir.as_path()) {
                fail("profile_path");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && phase_is_init => {}
        Err(_) => fail("profile_missing"),
    }

    let root_path = required_env("LOMI_E2_AUTH_CYCLE_ROOT_DER", 512);
    let root_der = read_root_der(&root_path, &base);

    let origin = required_env("LOMI_E2_AUTH_CYCLE_ORIGIN", 256);
    validate_origin(&origin);
    let host_text = required_env("LOMI_E2_AUTH_CYCLE_HOST_ID", 36);
    let host = parse_host_id(&host_text);
    let profile_text = required_env("LOMI_E2_AUTH_CYCLE_PROFILE_ID", 36);
    let profile_id = match IpcProfileId::try_from(profile_text.clone()) {
        Ok(value) if String::from(value) == profile_text => value,
        _ => fail("profile_id"),
    };
    let client = match PublicClientId::try_from(CLIENT_ID.to_owned()) {
        Ok(value) => value,
        Err(_) => fail("client_id"),
    };
    let config = match Config::new(host, profile_id, origin.clone(), client) {
        Ok(value) => value,
        Err(_) => fail("config"),
    };

    Fixture {
        phase,
        profile_dir,
        root_der,
        origin,
        host,
        config,
    }
}

fn initiate(fixture: &Fixture) {
    let owner = owner_lock(fixture);
    let mut storage = protected_storage(&owner);
    let now = wall_now();
    let mut auth = host_auth(&mut storage, fixture, now);
    if auth.status() != Status::Empty {
        fail("init_state");
    }
    if auth.initialize().is_err() {
        fail("init_initialize");
    }
    let request = match auth.init_request() {
        Ok(value) => value,
        Err(_) => fail("init_request"),
    };
    let transport = transport(fixture);
    let response = match transport.initiate(&request) {
        Ok(value) => value,
        Err(_) => fail("init_http"),
    };
    if auth.accept_initiation(response, wall_now()).is_err() {
        fail("init_accept");
    }
    let presentation = match auth.enrollment_presentation(wall_now()) {
        Ok(value) => value,
        Err(_) => fail("init_presentation"),
    };
    let rendezvous = PublicInit {
        user_code: presentation.user_code.expose_wire().to_owned(),
    };
    write_rendezvous(&fixture.profile_dir, USER_CODE_FILE, &rendezvous);
    println!("LOMI_AUTH_CYCLE_STAGE=initiate_complete");
}

fn rotate_lost(fixture: &Fixture) {
    let owner = owner_lock(fixture);
    let mut storage = protected_storage(&owner);
    let mut auth = host_auth(&mut storage, fixture, wall_now());
    if auth.status() != Status::AwaitingApproval {
        fail("poll_state");
    }
    let transport = transport(fixture);
    let (bootstrap, context, approval_now) = poll_approved(&mut auth, &transport, fixture);
    if auth
        .accept_tls_approval(&fixture.origin, context, bootstrap, approval_now)
        .is_err()
    {
        fail("approval_accept");
    }

    let exchange_now = wall_now();
    if auth.prepare_exchange(exchange_now).is_err() {
        fail("exchange_prepare");
    }
    let exchange = match auth.exchange_request(exchange_now) {
        Ok(value) => value,
        Err(_) => fail("exchange_request"),
    };
    let result = match transport.exchange(&exchange) {
        Ok(value) => value,
        Err(_) => fail("exchange_http"),
    };
    if auth.accept_exchange(result, wall_now()).is_err() {
        fail("exchange_accept");
    }

    let registration_now = wall_now();
    let (access, registration) = match auth.registration_request(registration_now) {
        Ok(value) => value,
        Err(_) => fail("registration_request"),
    };
    let result = match transport.register(&registration, &access) {
        Ok(value) => value,
        Err(_) => fail("registration_http"),
    };
    if auth.confirm_registration(result).is_err() || auth.status() != Status::Ready {
        fail("registration_accept");
    }

    let prepared_at = wall_now();
    if auth.prepare_rotation(prepared_at).is_err() {
        fail("rotation_prepare");
    }
    let rotation = match auth.rotation_request(prepared_at) {
        Ok(value) => value,
        Err(_) => fail("rotation_request"),
    };
    // Persist only the public timestamp needed to simulate local expiry in the
    // final process. The retained credentials and signed request stay in HostAuth.
    write_rendezvous(
        &fixture.profile_dir,
        ROTATION_FILE,
        &RotationIntent { prepared_at },
    );
    match transport.refresh(&rotation) {
        Err(HttpError::FixtureIoTls) => {}
        _ => fail("refresh_response_not_lost"),
    }
    if auth.status() != Status::Rotating {
        fail("rotation_not_retained");
    }
    println!("LOMI_AUTH_CYCLE_STAGE=rotate_lost_retained");
}

fn acknowledge_after_reopen(fixture: &Fixture) {
    let intent: RotationIntent =
        read_rendezvous(&fixture.profile_dir, ROTATION_FILE, "rotation_read");
    if intent.prepared_at == 0 || intent.prepared_at > wall_now() {
        fail("rotation_time");
    }
    let now = match intent.prepared_at.checked_add(301) {
        Some(value) => value,
        None => fail("rotation_time"),
    };

    let acknowledged = {
        let owner = owner_lock(fixture);
        let mut storage = protected_storage(&owner);
        let mut auth = host_auth(&mut storage, fixture, now);
        if auth.status() != Status::Rotating {
            fail("reopen_rotation_state");
        }
        match auth.rotation_request(now) {
            Err(HostAuthError::Expired) => {}
            _ => fail("rotation_not_expired"),
        }

        let transport = transport(fixture);
        let access = match auth.revocation_credential() {
            Ok(value) => value,
            Err(_) => fail("revoke_credential"),
        };
        let request = HostRevokeParams {
            expected_host_access_epoch: match auth.verified_host_access_epoch() {
                Ok(value) => value,
                Err(_) => fail("revoke_epoch"),
            },
        };
        match transport.revoke(fixture.host, &request, &access) {
            Err(HttpError::Remote(HostFailure::AuthRequired)) => {}
            _ => fail("revoke_not_auth_required"),
        }

        let original_request = match auth.revocation_ack_request(now) {
            Ok(value) => value,
            Err(_) => fail("ack_request"),
        };
        let result = match transport.revocation_ack(fixture.host, &original_request) {
            Ok(value) => value,
            Err(_) => fail("ack_http"),
        };
        if result.host_id != fixture.host || result.host_access_epoch.0 == 0 {
            fail("ack_result");
        }
        if auth
            .accept_revocation_ack(&fixture.origin, &original_request, result, now)
            .is_err()
            || auth.status() != Status::Revoked
        {
            fail("ack_accept");
        }
        match auth.revocation_acknowledgement() {
            Ok(value) => value,
            Err(_) => fail("ack_local_result"),
        }
    };

    let owner = owner_lock(fixture);
    let mut storage = protected_storage(&owner);
    let auth = host_auth(&mut storage, fixture, now);
    if auth.status() != Status::Revoked {
        fail("ack_not_durable");
    }
    match auth.revocation_acknowledgement() {
        Ok(value) if value == acknowledged => {}
        _ => fail("ack_reopen_mismatch"),
    }
    println!("LOMI_AUTH_CYCLE_STAGE=ack_reopened_durable");
}

fn poll_approved(
    auth: &mut HostAuth<'_, ProtectedFile<'_>>,
    transport: &Transport,
    fixture: &Fixture,
) -> (
    lomi_remote_protocol::EnrollmentBootstrapCredential,
    lomi_remote_protocol::HostEnrollmentTokenContext,
    u64,
) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() >= deadline {
            fail("approval_poll_timeout");
        }
        let now = wall_now();
        let device = match auth.device_poll_credential(now) {
            Ok(value) => value,
            Err(HostAuthError::PollTooEarly) => {
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(_) => fail("approval_poll_reserve"),
        };
        match transport.poll(&device) {
            Ok(PollOutcome::Approved {
                bootstrap, context, ..
            }) => return (bootstrap, context, wall_now()),
            Ok(PollOutcome::Pending) => thread::sleep(Duration::from_millis(100)),
            Ok(PollOutcome::SlowDown) => {
                if auth
                    .accept_tls_slow_down(&fixture.origin, wall_now())
                    .is_err()
                {
                    fail("approval_poll_slow_down");
                }
            }
            _ => fail("approval_poll_result"),
        }
    }
}

fn transport(fixture: &Fixture) -> Transport {
    match Transport::with_test_root(&fixture.config, &fixture.root_der) {
        Ok(value) => value,
        Err(_) => fail("transport"),
    }
}

fn owner_lock(fixture: &Fixture) -> OwnerLock {
    match OwnerLock::acquire(&fixture.profile_dir) {
        Ok(value) => value,
        Err(_) => fail("owner_lock"),
    }
}

fn protected_storage<'owner>(owner: &'owner OwnerLock) -> ProtectedFile<'owner> {
    match ProtectedFile::open(
        owner.profile(),
        Selection::ProtectedFile(ProtectedFileAcknowledgement::OsPermissionsOnly),
    ) {
        Ok(value) => value,
        Err(_) => fail("protected_storage"),
    }
}

fn host_auth<'auth, 'profile>(
    storage: &'auth mut ProtectedFile<'profile>,
    fixture: &Fixture,
    now: u64,
) -> HostAuth<'auth, ProtectedFile<'profile>> {
    match HostAuth::open(storage, fixture.config.clone(), now) {
        Ok(value) => value,
        Err(_) => fail("host_auth_open"),
    }
}

fn private_paths(directory: &str) -> (PathBuf, PathBuf) {
    private_paths_with_leaf(directory, "host-auth-cycle")
}

fn private_paths_with_leaf(directory: &str, expected_leaf: &'static str) -> (PathBuf, PathBuf) {
    let (parent, suffix) = if let Some(value) = directory.strip_prefix("/tmp/") {
        (Path::new("/tmp"), value)
    } else if let Some(value) = directory.strip_prefix("/private/tmp/") {
        (Path::new("/private/tmp"), value)
    } else {
        fail("profile_path");
    };
    let mut pieces = suffix.split('/');
    let base_name = pieces.next().unwrap_or_default();
    if pieces.next() != Some(expected_leaf) || pieces.next().is_some() {
        fail("profile_path");
    }
    let run_id = match base_name.strip_prefix("lomi-e2-") {
        Some(value) => value,
        None => fail("profile_path"),
    };
    match uuid::Uuid::parse_str(run_id) {
        Ok(value) if value.to_string() == run_id => {}
        _ => fail("profile_path"),
    }

    let base_input = parent.join(base_name);
    let base = match fs::canonicalize(&base_input) {
        Ok(value) => value,
        Err(_) => fail("fixture_base"),
    };
    let metadata = match fs::symlink_metadata(&base_input) {
        Ok(value) => value,
        Err(_) => fail("fixture_base"),
    };
    validate_directory(&metadata, 0o700, "fixture_base");
    if base.file_name().and_then(|value| value.to_str()) != Some(base_name)
        || !matches!(base.parent(), Some(path) if path == Path::new("/tmp") || path == Path::new("/private/tmp"))
    {
        fail("fixture_base");
    }
    let profile_dir = base.join(expected_leaf);
    (base, profile_dir)
}

fn read_root_der(path: &str, base: &Path) -> Vec<u8> {
    let supplied = PathBuf::from(path);
    let expected = base.join("runtime-tls-root.der");
    if !supplied.is_absolute()
        || fs::canonicalize(&supplied).ok().as_deref() != Some(expected.as_path())
    {
        fail("root_path");
    }
    let file = open_private_regular(&supplied, 0o600, MAX_ROOT_DER_BYTES, "root_file");
    let mut bytes = Vec::new();
    if file
        .take(MAX_ROOT_DER_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.is_empty()
        || bytes.len() as u64 > MAX_ROOT_DER_BYTES
    {
        fail("root_file");
    }
    bytes
}

fn write_rendezvous<T: Serialize>(directory: &Path, name: &str, value: &T) {
    let bytes = match serde_json::to_vec(value) {
        Ok(value) if !value.is_empty() && value.len() as u64 <= MAX_RENDEZVOUS_BYTES => value,
        _ => fail("rendezvous_encode"),
    };
    let path = directory.join(name);
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let mut file = match options.open(&path) {
        Ok(value) => value,
        Err(_) => fail("rendezvous_write"),
    };
    validate_file(&file, 0o600, MAX_RENDEZVOUS_BYTES, "rendezvous_write");
    if file.write_all(&bytes).is_err()
        || file.sync_all().is_err()
        || File::open(directory)
            .and_then(|value| value.sync_all())
            .is_err()
    {
        fail("rendezvous_write");
    }
}

fn read_rendezvous<T: for<'de> Deserialize<'de>>(
    directory: &Path,
    name: &str,
    stage: &'static str,
) -> T {
    let file = open_private_regular(&directory.join(name), 0o600, MAX_RENDEZVOUS_BYTES, stage);
    let mut bytes = Vec::new();
    if file
        .take(MAX_RENDEZVOUS_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.is_empty()
        || bytes.len() as u64 > MAX_RENDEZVOUS_BYTES
    {
        fail(stage);
    }
    match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => fail(stage),
    }
}

fn open_private_regular(path: &Path, mode: u32, limit: u64, stage: &'static str) -> File {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = match options.open(path) {
        Ok(value) => value,
        Err(_) => fail(stage),
    };
    validate_file(&file, mode, limit, stage);
    file
}

fn validate_file(file: &File, mode: u32, limit: u64, stage: &'static str) {
    let metadata = match file.metadata() {
        Ok(value) => value,
        Err(_) => fail(stage),
    };
    let valid = metadata.is_file()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o777 == mode
        && metadata.nlink() == 1
        && metadata.len() <= limit;
    if !valid {
        fail(stage);
    }
}

fn validate_directory(metadata: &Metadata, mode: u32, stage: &'static str) {
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != mode
        || metadata.nlink() < 2
    {
        fail(stage);
    }
}

fn parse_host_id(value: &str) -> HostId {
    match HostId::try_from(value.to_owned()) {
        Ok(host) if String::from(host) == value => host,
        _ => fail("host_id"),
    }
}

fn validate_origin(origin: &str) {
    let port = match origin.strip_prefix("https://127.0.0.1:") {
        Some(value) => value,
        None => fail("origin"),
    };
    if port.is_empty()
        || port.len() > 5
        || port.starts_with('0')
        || !port.bytes().all(|byte| byte.is_ascii_digit())
    {
        fail("origin");
    }
    match port.parse::<u16>() {
        Ok(value) if value != 0 && value.to_string() == port => {}
        _ => fail("origin"),
    }
}

fn required_env(name: &str, max_len: usize) -> String {
    match env::var(name) {
        Ok(value) if !value.is_empty() && value.len() <= max_len => value,
        _ => fail("fixture_env"),
    }
}

fn wall_now() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(value) if value.as_secs() > 0 => value.as_secs(),
        _ => fail("clock"),
    }
}

fn fail(stage: &'static str) -> ! {
    panic!("LOMI_AUTH_CYCLE_FAILURE={stage}");
}
