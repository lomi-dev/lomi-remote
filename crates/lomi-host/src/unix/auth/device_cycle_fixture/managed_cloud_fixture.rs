//! Private managed Cloud actor integration fixture.
//!
//! The ignored native test drives managed startup and Local IPC without
//! injecting a Ready state or synthesizing Cloud credentials.

#![cfg(all(unix, test, feature = "cloud-fixture"))]

use lomi_platform::unix::{LocalClient, OwnerLock, REQUEST_TIMEOUT};
use lomi_remote_protocol::{
    HostId, MutationContext, OperationId, TerminalContext, WorkspaceContext,
    ipc::{
        LocalAuthClientId, LocalAuthConfiguration, LocalAuthConfigure, LocalAuthPhase,
        LocalAuthProvider, LocalError, LocalFileAcknowledgement, LocalLoginAccepted,
        LocalLoginPresentation, LocalLoginStart, LocalLoginStatus, LocalOperatorIntent,
        LocalProjectName, LocalResult, LocalRootPath, LocalWorkspaceAdd, LocalWorkspaceRead,
        LocalWorkspaceTarget,
    },
    rpc::Confirmed,
    rpc::{
        RequestKind, RpcCall, RpcRequest, RpcResponse, RpcResult, TerminalCloseParams,
        TerminalCreateParams, WorkspaceState,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;
use std::{
    env,
    fs::{self, DirBuilder, File, Metadata, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    thread,
    time::{Duration, Instant},
};

const CONTEXT_PATH_ENV: &str = "LOMI_E2_MANAGED_CLOUD_CONTEXT_PATH";
const CONTEXT_SHA_ENV: &str = "LOMI_E2_MANAGED_CLOUD_CONTEXT_SHA256";
const JOINED_CONTEXT_PATH_ENV: &str = "LOMI_E2_MANAGED_JOINED_CLOUD_CONTEXT_PATH";
const JOINED_CONTEXT_SHA_ENV: &str = "LOMI_E2_MANAGED_JOINED_CLOUD_CONTEXT_SHA256";
const CONTEXT_FILE: &str = "managed-host-context.json";
const CA_FILE: &str = "runtime-tls-root.der";
const PROFILE_PARENT: &str = "h";
const PROFILE_LEAF: &str = "h";
const PROJECT_DIR: &str = "managed-host-project";
const PUBLIC_INIT_FILE: &str = "managed-host-public-init.json";
const STOP_FILE: &str = "managed-host-stop.json";
const RESULT_FILE: &str = "managed-host-result.json";
const JOINED_INIT_FILE: &str = "managed-joined-public-init.json";
const JOINED_STATE_FILE: &str = "managed-joined-state.json";
const JOINED_UNSHARE_FILE: &str = "managed-joined-unshare.json";
const JOINED_UNSHARE_ACK_FILE: &str = "managed-joined-unshare-ack.json";
const JOINED_STOP_FILE: &str = "managed-joined-stop.json";
const JOINED_RESULT_FILE: &str = "managed-joined-result.json";
const JOINED_CLIENT_ID: &str = "lomi-managed-cloud-fixture";
const MAX_CONTEXT_BYTES: u64 = 4096;
const MAX_JOINED_CONTEXT_BYTES: u64 = 8192;
const MAX_CA_BYTES: u64 = 16 * 1024;
const MAX_RENDEZVOUS_BYTES: u64 = 256;
const MAX_RESULT_BYTES: u64 = 2048;
const MAX_JOINED_RESULT_BYTES: u64 = 8192;
const MAX_JOINED_STAGES: usize = 24;
const READY_TIMEOUT: Duration = Duration::from_secs(180);
const PRESENTATION_TIMEOUT: Duration = Duration::from_secs(30);
const STOP_MARKER_TIMEOUT: Duration = Duration::from_secs(180);
const ACTOR_START_TIMEOUT: Duration = Duration::from_secs(15);
const ACTOR_FINISH_TIMEOUT: Duration = Duration::from_secs(45);
const WATCHDOG_TIMEOUT: Duration = Duration::from_secs(420);
// The joined driver is one absolute-budgeted phase. The existing 420s
// watchdog also needs the 5s DaemonStop connect, 10s IPC request, 45s actor
// join, and 5s report margin after the driver returns.
const JOINED_DRIVE_TIMEOUT: Duration = Duration::from_secs(350);
const JOINED_CONNECT_BUDGET: Duration = Duration::from_secs(3);
const JOINED_LOCAL_REQUEST_BUDGET: Duration = REQUEST_TIMEOUT;
const JOINED_CONTROL_POLL_INTERVAL: Duration = Duration::from_millis(50);
const JOINED_CONTROL_POLL_BUDGET: Duration = Duration::from_millis(250);
const JOINED_STOP_CONNECT_BUDGET: Duration = Duration::from_secs(5);
const JOINED_STOP_REQUEST_BUDGET: Duration = REQUEST_TIMEOUT;
const JOINED_RESULT_CAPTURE_MARGIN: Duration = Duration::from_secs(5);
const JOINED_STOP_CLEANUP_IPC_BUDGET: Duration = Duration::from_secs(40);
const JOINED_SHUTDOWN_BUDGET: Duration = Duration::from_secs(60);
const JOINED_AFTER_STOP_RESERVE: Duration = Duration::from_secs(105);
const JOINED_STOP_CONTROL_MIN_WINDOW: Duration = Duration::from_secs(1);
const JOINED_UNSHARE_ACK_MARGIN: Duration = Duration::from_secs(1);
const JOINED_AFTER_UNSHARE_ACK_RESERVE: Duration = Duration::from_millis(107_250);
const JOINED_AFTER_UNSHARE_RPC_RESERVE: Duration = Duration::from_millis(117_250);
const JOINED_AFTER_UNSHARE_CONTROL_RESERVE: Duration = Duration::from_millis(127_250);
const JOINED_AFTER_PRE_CLOSE_INSPECT_RESERVE: Duration = Duration::from_secs(95);
const JOINED_AFTER_CLOSE_RPC_RESERVE: Duration = Duration::from_secs(85);
const JOINED_AFTER_CLOSE_INSPECT_RESERVE: Duration = Duration::from_secs(75);
// Duration's Add implementation is not const on the pinned stable toolchain.
// The deadline regression below checks this against shutdown + capture margin.
const JOINED_AFTER_WORKSPACE_REMOVE_RESERVE: Duration = Duration::from_secs(65);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManagedContext {
    format_version: u32,
    run_id: String,
    auth_origin: String,
    remote_api_origin: String,
    client_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JoinedManagedContext {
    format_version: u32,
    run_id: String,
    auth_origin: String,
    remote_api_origin: String,
    client_id: String,
    relay_endpoint: String,
    terminal_worker_path: String,
    terminal_worker_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicInit {
    user_code: String,
    host_id: HostId,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StopMarker {
    stop: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ManagedPublicResult {
    format_version: u32,
    status: &'static str,
    outcome: &'static str,
    host_id: Option<HostId>,
    ready: bool,
    workspace_shared: bool,
    stop_observed: bool,
    stop_requested: bool,
    actor_returned: bool,
    actor_succeeded: bool,
    actor_joined: bool,
    owner_lock_released: bool,
    project_removed: bool,
    failure_stage: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JoinedPublicInit {
    format_version: u32,
    run_id: String,
    user_code: String,
    host_id: HostId,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JoinedPublicState {
    format_version: u32,
    status: &'static str,
    run_id: String,
    stage: &'static str,
    host_id: HostId,
    workspace: WorkspaceContext,
    terminal: TerminalContext,
    unshare_request_id: String,
    stop_request_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JoinedControl {
    format_version: u32,
    run_id: String,
    request_id: String,
    action: JoinedControlAction,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum JoinedControlAction {
    Unshare,
    Stop,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JoinedUnshareAcknowledgement {
    format_version: u32,
    run_id: String,
    request_id: String,
    action: JoinedControlAction,
    acknowledged: bool,
    host_id: HostId,
    workspace: WorkspaceContext,
    terminal: TerminalContext,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ManagedJoinedPublicResult {
    format_version: u32,
    status: &'static str,
    outcome: &'static str,
    run_id: String,
    host_id: Option<HostId>,
    workspace: Option<WorkspaceContext>,
    terminal: Option<TerminalContext>,
    unshare_request_id: String,
    stop_request_id: String,
    auth_ready: bool,
    workspace_imported: bool,
    terminal_created: bool,
    workspace_shared: bool,
    unshare_control_observed: bool,
    unshare_acknowledged: bool,
    stop_control_observed: bool,
    terminal_closed: bool,
    project_removed: bool,
    stop_requested: bool,
    actor_returned: bool,
    actor_succeeded: bool,
    actor_joined: bool,
    owner_lock_released: bool,
    stages: Vec<&'static str>,
    failure_stage: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DirectoryIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileFingerprint {
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
    nlink: u64,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

struct FixturePaths {
    runtime_root: PathBuf,
    runtime_identity: DirectoryIdentity,
    artifacts: PathBuf,
    artifacts_identity: DirectoryIdentity,
    tls: PathBuf,
    tls_identity: DirectoryIdentity,
    profile_parent: PathBuf,
    profile: PathBuf,
    project: PathBuf,
    public_init: PathBuf,
    stop: PathBuf,
    result: PathBuf,
    joined_init: PathBuf,
    joined_state: PathBuf,
    joined_unshare: PathBuf,
    joined_unshare_ack: PathBuf,
    joined_stop: PathBuf,
    joined_result: PathBuf,
    root_der: Vec<u8>,
    context: ManagedContext,
    joined_context: Option<JoinedManagedContext>,
}

#[derive(Clone)]
struct JoinedActorConfig {
    worker_executable: PathBuf,
    worker_sha256: String,
}

struct JoinedProgress {
    report: ManagedJoinedPublicResult,
}

#[derive(Clone, Copy)]
enum WatchdogCommand {
    Finished,
    StopNow,
}

struct ManagedWatchdog {
    sender: Option<Sender<WatchdogCommand>>,
    join: Option<thread::JoinHandle<()>>,
    fired: Arc<AtomicBool>,
}

struct ManagedActor {
    profile: PathBuf,
    profile_parent_identity: DirectoryIdentity,
    profile_identity: DirectoryIdentity,
    ready: Receiver<lomi_remote_protocol::RuntimeId>,
    finished: Receiver<bool>,
    join: Option<thread::JoinHandle<()>>,
    shutdown_attempted: bool,
}

#[test]
#[ignore = "requires the private auth-app TLS controller and database fixture"]
fn managed_cloud_actor_uses_host_store_identity_and_real_local_ipc() {
    match run_managed_cloud_actor_fixture() {
        Ok(()) => {}
        Err(stage) => panic!("LOMI_MANAGED_CLOUD_FAILURE={stage}"),
    }
}

#[test]
#[ignore = "requires the private joined auth/API/relay and database fixture"]
fn managed_joined_cloud_creates_one_local_terminal_before_workspace_share() {
    match run_managed_joined_cloud_actor_fixture() {
        Ok(()) => {}
        Err(stage) => panic!("LOMI_MANAGED_JOINED_CLOUD_FAILURE={stage}"),
    }
}

fn run_managed_cloud_actor_fixture() -> Result<(), &'static str> {
    // The managed host starts the production TerminalService even though this
    // fixture never creates a terminal or shell. Establish child ownership
    // before adding any fixture threads.
    crate::testsupport::initialize_child_ownership();
    let paths = load_fixture_paths()?;
    preflight_fresh_paths(&paths)?;
    stage("context_validated");

    let profile_parent_identity = create_private_directory(&paths.profile_parent)?;
    let profile_identity = create_private_directory(&paths.profile)?;
    let socket_path = paths.profile.join("host.sock");
    if socket_path.as_os_str().as_encoded_bytes().len() > 100 {
        return Err("profile_socket_path");
    }

    let mut report = ManagedPublicResult {
        format_version: 1,
        status: "UNREVIEWED_MANAGED_CLOUD_ACTOR_FIXTURE",
        outcome: "failed",
        host_id: None,
        ready: false,
        workspace_shared: false,
        stop_observed: false,
        stop_requested: false,
        actor_returned: false,
        actor_succeeded: false,
        actor_joined: false,
        owner_lock_released: false,
        project_removed: false,
        failure_stage: None,
    };

    let mut watchdog = ManagedWatchdog::start(paths.profile.clone())?;
    let mut actor = ManagedActor::start(
        &paths.profile,
        &paths.root_der,
        profile_parent_identity,
        profile_identity,
        None,
    )?;
    let drive_result = match actor.wait_until_started() {
        Ok(runtime_id) => {
            stage("managed_actor_started");
            drive_local_actor(&paths, runtime_id, &mut report)
        }
        Err(stage) => Err(stage),
    };

    let stopped = actor.stop_and_join();
    report.stop_requested = stopped.stop_requested;
    report.actor_returned = stopped.actor_returned;
    report.actor_succeeded = stopped.actor_succeeded;
    report.actor_joined = stopped.actor_joined;
    report.owner_lock_released = stopped.owner_lock_released;

    let watchdog_ok = watchdog.finish();
    if !watchdog_ok {
        report.failure_stage.get_or_insert("watchdog_expired");
    }
    if let Err(stage) = drive_result {
        report.failure_stage.get_or_insert(stage);
    }
    if !stopped.stop_requested {
        report.failure_stage.get_or_insert("shutdown_rpc");
    }
    if !stopped.actor_returned {
        report.failure_stage.get_or_insert("managed_actor_return");
    }
    if !stopped.actor_succeeded {
        report.failure_stage.get_or_insert("managed_actor_failed");
    }
    if !stopped.actor_joined {
        report.failure_stage.get_or_insert("managed_actor_join");
    }
    if !stopped.owner_lock_released {
        report.failure_stage.get_or_insert("owner_lock_release");
    }

    let passed = report.failure_stage.is_none()
        && report.host_id.is_some()
        && report.ready
        && report.workspace_shared
        && report.stop_observed
        && report.project_removed
        && report.stop_requested
        && report.actor_returned
        && report.actor_succeeded
        && report.actor_joined
        && report.owner_lock_released
        && watchdog_ok;
    report.outcome = if passed { "passed" } else { "failed" };
    if !passed && report.failure_stage.is_none() {
        report.failure_stage = Some("incomplete_result");
    }
    verify_directory_identity(&paths.artifacts, paths.artifacts_identity)
        .map_err(|_| "artifacts_directory_changed")?;
    write_private_json(&paths.result, &report, MAX_RESULT_BYTES).map_err(|_| "result_write")?;
    stage(if passed {
        "managed_actor_complete"
    } else {
        "managed_actor_failed"
    });
    if passed {
        Ok(())
    } else {
        Err(report.failure_stage.unwrap_or("managed_actor_failed"))
    }
}

fn run_managed_joined_cloud_actor_fixture() -> Result<(), &'static str> {
    // Establish subprocess ownership before this fixture creates actor,
    // watchdog, or terminal-worker threads/processes.
    crate::testsupport::initialize_child_ownership();
    let paths = load_joined_fixture_paths()?;
    preflight_fresh_paths(&paths)?;
    let context = paths
        .joined_context
        .as_ref()
        .ok_or("joined_context_missing")?;
    let mut progress = JoinedProgress::new(context.run_id.clone());
    progress.stage("context_validated");

    let profile_parent_identity = create_private_directory(&paths.profile_parent)?;
    let profile_identity = create_private_directory(&paths.profile)?;
    let socket_path = paths.profile.join("host.sock");
    if socket_path.as_os_str().as_encoded_bytes().len() > 100 {
        progress.fail("profile_socket_path");
        return write_joined_failure(&paths, progress, "profile_socket_path");
    }

    let joined_actor = JoinedActorConfig {
        worker_executable: joined_worker_path(&paths.artifacts, &context.terminal_worker_path)?,
        worker_sha256: context.terminal_worker_sha256.clone(),
    };
    let mut watchdog = ManagedWatchdog::start(paths.profile.clone())?;
    let joined_deadline = Instant::now() + JOINED_DRIVE_TIMEOUT;
    let mut actor = ManagedActor::start(
        &paths.profile,
        &paths.root_der,
        profile_parent_identity,
        profile_identity,
        Some(joined_actor),
    )?;
    let drive_result = match actor.wait_until_started_until(joined_deadline) {
        Ok(runtime_id) => {
            progress.stage("managed_actor_started");
            drive_joined_local_actor(&paths, runtime_id, joined_deadline, &mut progress)
        }
        Err(stage) => Err(stage),
    };

    let stopped = actor.stop_and_join();
    progress.report.stop_requested = stopped.stop_requested;
    progress.report.actor_returned = stopped.actor_returned;
    progress.report.actor_succeeded = stopped.actor_succeeded;
    progress.report.actor_joined = stopped.actor_joined;
    progress.report.owner_lock_released = stopped.owner_lock_released;

    let watchdog_ok = watchdog.finish();
    if !watchdog_ok {
        progress.fail("watchdog_expired");
    }
    if let Err(stage) = drive_result {
        progress.fail(stage);
    }
    if !stopped.stop_requested {
        progress.fail("shutdown_rpc");
    }
    if !stopped.actor_returned {
        progress.fail("managed_actor_return");
    }
    if !stopped.actor_succeeded {
        progress.fail("managed_actor_failed");
    }
    if !stopped.actor_joined {
        progress.fail("managed_actor_join");
    }
    if !stopped.owner_lock_released {
        progress.fail("owner_lock_release");
    }

    let passed = progress.report.failure_stage.is_none()
        && progress.report.host_id.is_some()
        && progress.report.workspace.is_some()
        && progress.report.terminal.is_some()
        && progress.report.auth_ready
        && progress.report.workspace_imported
        && progress.report.terminal_created
        && progress.report.workspace_shared
        && progress.report.unshare_control_observed
        && progress.report.unshare_acknowledged
        && progress.report.stop_control_observed
        && progress.report.terminal_closed
        && progress.report.project_removed
        && progress.report.stop_requested
        && progress.report.actor_returned
        && progress.report.actor_succeeded
        && progress.report.actor_joined
        && progress.report.owner_lock_released
        && watchdog_ok;
    progress.stage(if passed {
        "joined_actor_complete"
    } else {
        "joined_actor_failed"
    });
    let report = &mut progress.report;
    report.outcome = if passed { "passed" } else { "failed" };
    if !passed && report.failure_stage.is_none() {
        report.failure_stage = Some("incomplete_result");
    }
    verify_directory_identity(&paths.artifacts, paths.artifacts_identity)
        .map_err(|_| "joined_artifacts_directory_changed")?;
    write_private_json(&paths.joined_result, report, MAX_JOINED_RESULT_BYTES)
        .map_err(|_| "joined_result_write")?;
    if passed {
        Ok(())
    } else {
        Err(report.failure_stage.unwrap_or("joined_actor_failed"))
    }
}

fn write_joined_failure(
    paths: &FixturePaths,
    mut progress: JoinedProgress,
    failure: &'static str,
) -> Result<(), &'static str> {
    progress.fail(failure);
    progress.report.outcome = "failed";
    verify_directory_identity(&paths.artifacts, paths.artifacts_identity)
        .map_err(|_| "joined_artifacts_directory_changed")?;
    write_private_json(
        &paths.joined_result,
        &progress.report,
        MAX_JOINED_RESULT_BYTES,
    )
    .map_err(|_| "joined_result_write")?;
    Err(failure)
}

impl JoinedProgress {
    fn new(run_id: String) -> Self {
        let unshare_request_id = uuid::Uuid::new_v4().to_string();
        let mut stop_request_id = uuid::Uuid::new_v4().to_string();
        while stop_request_id == unshare_request_id {
            stop_request_id = uuid::Uuid::new_v4().to_string();
        }
        Self {
            report: ManagedJoinedPublicResult {
                format_version: 2,
                status: "UNREVIEWED_MANAGED_JOINED_CLOUD_FIXTURE",
                outcome: "failed",
                run_id,
                host_id: None,
                workspace: None,
                terminal: None,
                unshare_request_id,
                stop_request_id,
                auth_ready: false,
                workspace_imported: false,
                terminal_created: false,
                workspace_shared: false,
                unshare_control_observed: false,
                unshare_acknowledged: false,
                stop_control_observed: false,
                terminal_closed: false,
                project_removed: false,
                stop_requested: false,
                actor_returned: false,
                actor_succeeded: false,
                actor_joined: false,
                owner_lock_released: false,
                stages: Vec::new(),
                failure_stage: None,
            },
        }
    }

    fn stage(&mut self, name: &'static str) {
        if self.report.stages.len() < MAX_JOINED_STAGES {
            self.report.stages.push(name);
            joined_stage(name);
        } else {
            self.fail("stage_limit");
        }
    }

    fn fail(&mut self, name: &'static str) {
        self.report.failure_stage.get_or_insert(name);
    }
}

fn load_fixture_paths() -> Result<FixturePaths, &'static str> {
    let supplied_context = required_env(CONTEXT_PATH_ENV, 1024)?;
    let expected_context_sha = required_sha_env(CONTEXT_SHA_ENV)?;
    let supplied_path = PathBuf::from(supplied_context);
    if !supplied_path.is_absolute() {
        return Err("context_path");
    }
    let runtime_parent = if cfg!(target_os = "macos") {
        Path::new("/private/tmp")
    } else {
        Path::new("/tmp")
    };
    if supplied_path.file_name().and_then(|value| value.to_str()) != Some(CONTEXT_FILE)
        || supplied_path
            .parent()
            .and_then(Path::file_name)
            .and_then(|value| value.to_str())
            != Some("cloud-artifacts")
    {
        return Err("context_path");
    }
    let supplied_root = supplied_path
        .parent()
        .and_then(Path::parent)
        .ok_or("context_path")?;
    let root_name = supplied_root
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("runtime_path")?;
    let run_id = root_name
        .strip_prefix("lomi-consumer-acl-a4-scram-runtime-")
        .ok_or("runtime_path")?;
    if !canonical_uuid(run_id) {
        return Err("runtime_path");
    }
    let runtime_root =
        runtime_parent.join(format!("lomi-consumer-acl-a4-scram-runtime-{}", run_id));
    let artifacts = runtime_root.join("cloud-artifacts");
    let tls = artifacts.join("tls");
    let context_path = artifacts.join(CONTEXT_FILE);
    if fs::canonicalize(supplied_root).map_err(|_| "runtime_path")? != runtime_root
        || fs::canonicalize(&supplied_path).map_err(|_| "context_path")? != context_path
        || fs::canonicalize(&runtime_root).map_err(|_| "runtime_path")? != runtime_root
        || fs::canonicalize(&context_path).map_err(|_| "context_path")? != context_path
    {
        return Err("runtime_path");
    }
    let runtime_identity =
        private_directory_identity(&runtime_root).map_err(|_| "runtime_directory")?;
    let artifacts_identity =
        private_directory_identity(&artifacts).map_err(|_| "artifacts_directory")?;
    let tls_identity = private_directory_identity(&tls).map_err(|_| "tls_directory")?;

    let context_raw =
        read_private_regular(&context_path, MAX_CONTEXT_BYTES).map_err(|_| "context_read")?;
    if sha256_hex(&context_raw) != expected_context_sha {
        return Err("context_hash");
    }
    let context: ManagedContext =
        serde_json::from_slice(&context_raw).map_err(|_| "context_schema")?;
    if context.format_version != 1
        || context.run_id != run_id
        || !valid_origin(&context.auth_origin)
        || !valid_origin(&context.remote_api_origin)
        || !valid_client_id(&context.client_id)
    {
        return Err("context_values");
    }
    let root_der =
        read_private_regular(&tls.join(CA_FILE), MAX_CA_BYTES).map_err(|_| "tls_root")?;
    if root_der.is_empty() {
        return Err("tls_root");
    }

    let profile_parent = runtime_root.join(PROFILE_PARENT);
    let profile = profile_parent.join(PROFILE_LEAF);
    let project = artifacts.join(PROJECT_DIR);
    Ok(FixturePaths {
        runtime_root,
        runtime_identity,
        artifacts: artifacts.clone(),
        artifacts_identity,
        tls,
        tls_identity,
        profile_parent,
        profile,
        project,
        public_init: artifacts.join(PUBLIC_INIT_FILE),
        stop: artifacts.join(STOP_FILE),
        result: artifacts.join(RESULT_FILE),
        joined_init: artifacts.join(JOINED_INIT_FILE),
        joined_state: artifacts.join(JOINED_STATE_FILE),
        joined_unshare: artifacts.join(JOINED_UNSHARE_FILE),
        joined_unshare_ack: artifacts.join(JOINED_UNSHARE_ACK_FILE),
        joined_stop: artifacts.join(JOINED_STOP_FILE),
        joined_result: artifacts.join(JOINED_RESULT_FILE),
        root_der,
        context,
        joined_context: None,
    })
}

fn load_joined_fixture_paths() -> Result<FixturePaths, &'static str> {
    let supplied_context = required_env(JOINED_CONTEXT_PATH_ENV, 1024)?;
    let expected_context_sha = required_sha_env(JOINED_CONTEXT_SHA_ENV)?;
    let supplied_path = PathBuf::from(supplied_context);
    if !supplied_path.is_absolute()
        || supplied_path.file_name().and_then(|value| value.to_str()) != Some(CONTEXT_FILE)
        || supplied_path
            .parent()
            .and_then(Path::file_name)
            .and_then(|value| value.to_str())
            != Some("cloud-artifacts")
    {
        return Err("joined_context_path");
    }
    let supplied_root = supplied_path
        .parent()
        .and_then(Path::parent)
        .ok_or("joined_context_path")?;
    let root_name = supplied_root
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("joined_runtime_path")?;
    let run_id = root_name
        .strip_prefix("lomi-consumer-acl-a4-scram-runtime-")
        .ok_or("joined_runtime_path")?;
    if !canonical_uuid(run_id) {
        return Err("joined_runtime_path");
    }
    let runtime_parent = if cfg!(target_os = "macos") {
        Path::new("/private/tmp")
    } else {
        Path::new("/tmp")
    };
    let runtime_root = runtime_parent.join(format!("lomi-consumer-acl-a4-scram-runtime-{run_id}"));
    let artifacts = runtime_root.join("cloud-artifacts");
    let tls = artifacts.join("tls");
    let context_path = artifacts.join(CONTEXT_FILE);
    if fs::canonicalize(supplied_root).map_err(|_| "joined_runtime_path")? != runtime_root
        || fs::canonicalize(&supplied_path).map_err(|_| "joined_context_path")? != context_path
        || fs::canonicalize(&runtime_root).map_err(|_| "joined_runtime_path")? != runtime_root
        || fs::canonicalize(&context_path).map_err(|_| "joined_context_path")? != context_path
    {
        return Err("joined_runtime_path");
    }
    let runtime_identity =
        private_directory_identity(&runtime_root).map_err(|_| "joined_runtime_directory")?;
    let artifacts_identity =
        private_directory_identity(&artifacts).map_err(|_| "joined_artifacts_directory")?;
    let tls_identity = private_directory_identity(&tls).map_err(|_| "joined_tls_directory")?;

    let context_raw = read_private_regular(&context_path, MAX_JOINED_CONTEXT_BYTES)
        .map_err(|_| "joined_context_read")?;
    if sha256_hex(&context_raw) != expected_context_sha {
        return Err("joined_context_hash");
    }
    let joined_context: JoinedManagedContext =
        serde_json::from_slice(&context_raw).map_err(|_| "joined_context_schema")?;
    validate_joined_context(&joined_context, run_id, &artifacts)?;
    let worker_executable = joined_worker_path(&artifacts, &joined_context.terminal_worker_path)?;
    let root_der =
        read_private_regular(&tls.join(CA_FILE), MAX_CA_BYTES).map_err(|_| "joined_tls_root")?;
    if root_der.is_empty() {
        return Err("joined_tls_root");
    }

    let profile_parent = runtime_root.join(PROFILE_PARENT);
    let profile = profile_parent.join(PROFILE_LEAF);
    let project = artifacts.join(PROJECT_DIR);
    let context = ManagedContext {
        format_version: 1,
        run_id: joined_context.run_id.clone(),
        auth_origin: joined_context.auth_origin.clone(),
        remote_api_origin: joined_context.remote_api_origin.clone(),
        client_id: joined_context.client_id.clone(),
    };
    let paths = FixturePaths {
        runtime_root,
        runtime_identity,
        artifacts: artifacts.clone(),
        artifacts_identity,
        tls,
        tls_identity,
        profile_parent,
        profile,
        project,
        public_init: artifacts.join(PUBLIC_INIT_FILE),
        stop: artifacts.join(STOP_FILE),
        result: artifacts.join(RESULT_FILE),
        joined_init: artifacts.join(JOINED_INIT_FILE),
        joined_state: artifacts.join(JOINED_STATE_FILE),
        joined_unshare: artifacts.join(JOINED_UNSHARE_FILE),
        joined_unshare_ack: artifacts.join(JOINED_UNSHARE_ACK_FILE),
        joined_stop: artifacts.join(JOINED_STOP_FILE),
        joined_result: artifacts.join(JOINED_RESULT_FILE),
        root_der,
        context,
        joined_context: Some(joined_context),
    };
    // The pinned executable has a fixed path in the closed artifact tree. The
    // managed runner independently snapshots and revalidates its bytes before
    // making it the TerminalService worker.
    if worker_executable != artifacts.join("rust-target/debug/lomiremote") {
        return Err("joined_worker_path");
    }
    Ok(paths)
}

fn validate_joined_context(
    context: &JoinedManagedContext,
    run_id: &str,
    artifacts: &Path,
) -> Result<(), &'static str> {
    if context.format_version != 2
        || context.run_id != run_id
        || !valid_origin(&context.auth_origin)
        || !valid_origin(&context.remote_api_origin)
        || context.client_id != JOINED_CLIENT_ID
        || !valid_relay_endpoint(&context.relay_endpoint)
        || !valid_sha256_lower(&context.terminal_worker_sha256)
    {
        return Err("joined_context_values");
    }
    joined_worker_path(artifacts, &context.terminal_worker_path)?;
    Ok(())
}

fn joined_worker_path(artifacts: &Path, supplied: &str) -> Result<PathBuf, &'static str> {
    let expected = artifacts.join("rust-target/debug/lomiremote");
    let path = PathBuf::from(supplied);
    if path != expected || fs::canonicalize(&path).map_err(|_| "joined_worker_path")? != expected {
        return Err("joined_worker_path");
    }
    Ok(expected)
}

fn valid_relay_endpoint(value: &str) -> bool {
    let Some(port) = value
        .strip_prefix("wss://127.0.0.1:")
        .and_then(|value| value.strip_suffix("/v2/relay"))
    else {
        return false;
    };
    if port.is_empty()
        || port.len() > 5
        || port.starts_with('0')
        || !port.bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    let Ok(parsed_port) = port.parse::<u16>() else {
        return false;
    };
    parsed_port >= 1024
        && parsed_port.to_string() == port
        && lomi_remote_protocol::ipc::LocalRelayEndpoint::try_from(value.to_owned()).is_ok()
}

fn valid_sha256_lower(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn preflight_fresh_paths(paths: &FixturePaths) -> Result<(), &'static str> {
    verify_directory_identity(&paths.runtime_root, paths.runtime_identity)
        .map_err(|_| "runtime_directory_changed")?;
    verify_directory_identity(&paths.artifacts, paths.artifacts_identity)
        .map_err(|_| "artifacts_directory_changed")?;
    verify_directory_identity(&paths.tls, paths.tls_identity)
        .map_err(|_| "tls_directory_changed")?;
    require_absent(&paths.profile_parent)?;
    require_absent(&paths.profile)?;
    require_absent(&paths.project)?;
    require_absent(&paths.public_init)?;
    require_absent(&paths.stop)?;
    require_absent(&paths.result)?;
    if paths.joined_context.is_some() {
        require_absent(&paths.joined_init)?;
        require_absent(&paths.joined_state)?;
        require_absent(&paths.joined_unshare)?;
        require_absent(&paths.joined_unshare_ack)?;
        require_absent(&paths.joined_stop)?;
        require_absent(&paths.joined_result)?;
    }
    if paths
        .runtime_root
        .join("cloud-artifacts")
        .join(CONTEXT_FILE)
        != paths.artifacts.join(CONTEXT_FILE)
        || paths.tls != paths.artifacts.join("tls")
    {
        return Err("fixture_path_binding");
    }
    Ok(())
}

fn drive_local_actor(
    paths: &FixturePaths,
    runtime_id: lomi_remote_protocol::RuntimeId,
    progress: &mut ManagedPublicResult,
) -> Result<(), &'static str> {
    let mut client = LocalClient::connect_with_timeout(&paths.profile, Duration::from_secs(3))
        .map_err(|_| "local_ipc_connect")?;
    if client.discovery().runtime_id != runtime_id {
        return Err("runtime_identity");
    }
    let host_id = client.discovery().host_id;
    progress.host_id = Some(host_id);

    let configuration = LocalAuthConfiguration {
        version: 1,
        origin: paths
            .context
            .auth_origin
            .clone()
            .try_into()
            .map_err(|_| "auth_origin")?,
        remote_api_origin: Some(
            paths
                .context
                .remote_api_origin
                .clone()
                .try_into()
                .map_err(|_| "remote_api_origin")?,
        ),
        relay_endpoint: None,
        client_id: LocalAuthClientId::try_from(paths.context.client_id.clone())
            .map_err(|_| "client_id")?,
        provider: LocalAuthProvider::ProtectedFile,
        keychain_path: None,
        protected_file_acknowledgement: Some(LocalFileAcknowledgement::OsPermissionsOnly),
    };
    request_expected(
        &mut client,
        lomi_remote_protocol::ipc::LocalCall::AuthConfigure(LocalAuthConfigure {
            configuration,
            operator_intent: Confirmed::Confirmed,
        }),
        "auth_configure",
        |result| matches!(result, LocalResult::AuthConfigured {}),
    )?;
    stage("auth_configured");

    let operation_id =
        OperationId::from_bytes(uuid::Uuid::new_v4().into_bytes()).map_err(|_| "operation_id")?;
    let accepted = request_typed::<LocalLoginAccepted>(
        &mut client,
        lomi_remote_protocol::ipc::LocalCall::LoginStart(LocalLoginStart { operation_id }),
        "login_start",
        |result| match result {
            LocalResult::LoginAccepted(value) if value.operation_id == operation_id => {
                Some(value.clone())
            }
            _ => None,
        },
    )?;
    let presentation = wait_for_presentation(&mut client)?;
    if presentation.user_code.expose_wire().is_empty()
        || presentation.user_code.expose_wire().len() > 32
    {
        return Err("user_code");
    }
    verify_directory_identity(&paths.artifacts, paths.artifacts_identity)
        .map_err(|_| "artifacts_directory_changed")?;
    write_private_json(
        &paths.public_init,
        &PublicInit {
            user_code: presentation.user_code.expose_wire().to_owned(),
            host_id,
        },
        MAX_RENDEZVOUS_BYTES,
    )
    .map_err(|_| "public_init_write")?;
    stage("public_init_ready");

    let ready = wait_for_ready(&mut client, accepted.generation.0)?;
    if ready.generation != accepted.generation {
        return Err("ready_generation");
    }
    progress.ready = true;
    stage("host_ready");

    verify_directory_identity(&paths.artifacts, paths.artifacts_identity)
        .map_err(|_| "artifacts_directory_changed")?;
    let project_identity =
        create_private_directory(&paths.project).map_err(|_| "project_create")?;
    if directory_is_empty(&paths.project).map_err(|_| "project_inspect")? == false {
        return Err("project_not_empty");
    }
    let project_path = paths.project.canonicalize().map_err(|_| "project_path")?;
    if project_path != paths.project {
        return Err("project_path");
    }
    let name = LocalProjectName::try_from("Managed cloud fixture".to_owned())
        .map_err(|_| "project_name")?;
    let root_path = LocalRootPath::try_from(project_path.to_string_lossy().into_owned())
        .map_err(|_| "project_path")?;
    let workspace = request_typed(
        &mut client,
        lomi_remote_protocol::ipc::LocalCall::WorkspaceAdd(LocalWorkspaceAdd {
            name,
            root_path,
            operator_intent: Confirmed::Confirmed,
        }),
        "workspace_import",
        |result: &LocalResult| match result {
            LocalResult::Workspace(summary) => Some(summary.clone()),
            _ => None,
        },
    )?;
    let workspace_id = workspace.workspace_id;
    let shared = request_typed(
        &mut client,
        lomi_remote_protocol::ipc::LocalCall::Share(LocalWorkspaceTarget {
            workspace_id,
            operator_intent: Confirmed::Confirmed,
        }),
        "workspace_share",
        |result: &LocalResult| match result {
            LocalResult::Workspace(summary)
                if summary.workspace_id == workspace_id
                    && summary.sharing == lomi_remote_protocol::ipc::LocalSharing::Enabled =>
            {
                Some(())
            }
            _ => None,
        },
    )?;
    let _ = shared;
    progress.workspace_shared = true;
    stage("workspace_shared");

    wait_for_stop_marker(
        &paths.stop,
        &paths.artifacts,
        paths.artifacts_identity,
        STOP_MARKER_TIMEOUT,
    )?;
    progress.stop_observed = true;
    stage("stop_marker_observed");

    request_expected(
        &mut client,
        lomi_remote_protocol::ipc::LocalCall::Unshare(LocalWorkspaceTarget {
            workspace_id,
            operator_intent: Confirmed::Confirmed,
        }),
        "workspace_unshare",
        |result| {
            matches!(result, LocalResult::Workspace(summary)
                if summary.workspace_id == workspace_id
                    && summary.sharing == lomi_remote_protocol::ipc::LocalSharing::Disabled)
        },
    )?;
    request_expected(
        &mut client,
        lomi_remote_protocol::ipc::LocalCall::WorkspaceRemove(LocalWorkspaceTarget {
            workspace_id,
            operator_intent: Confirmed::Confirmed,
        }),
        "workspace_remove",
        |result| matches!(result, LocalResult::Removed(id) if *id == workspace_id),
    )?;
    verify_directory_identity(&paths.artifacts, paths.artifacts_identity)
        .map_err(|_| "artifacts_directory_changed")?;
    remove_empty_owned_directory(&paths.project, project_identity)
        .map_err(|_| "project_cleanup")?;
    progress.project_removed = true;
    stage("workspace_cleanup_complete");
    drop(client);
    Ok(())
}

fn drive_joined_local_actor(
    paths: &FixturePaths,
    runtime_id: lomi_remote_protocol::RuntimeId,
    joined_deadline: Instant,
    progress: &mut JoinedProgress,
) -> Result<(), &'static str> {
    joined_admit_now(joined_deadline, Duration::ZERO, Duration::ZERO)?;
    let joined_context = paths
        .joined_context
        .as_ref()
        .ok_or("joined_context_missing")?;
    joined_admit_now(joined_deadline, Duration::ZERO, JOINED_CONNECT_BUDGET)?;
    let mut client = LocalClient::connect_with_timeout(&paths.profile, JOINED_CONNECT_BUDGET)
        .map_err(|_| "joined_local_ipc_connect")?;
    joined_admit_now(joined_deadline, Duration::ZERO, Duration::ZERO)?;
    if client.discovery().runtime_id != runtime_id {
        return Err("joined_runtime_identity");
    }
    let host_id = client.discovery().host_id;
    progress.report.host_id = Some(host_id);

    let configuration = LocalAuthConfiguration {
        version: 1,
        origin: joined_context
            .auth_origin
            .clone()
            .try_into()
            .map_err(|_| "joined_auth_origin")?,
        remote_api_origin: Some(
            joined_context
                .remote_api_origin
                .clone()
                .try_into()
                .map_err(|_| "joined_remote_api_origin")?,
        ),
        relay_endpoint: Some(
            joined_context
                .relay_endpoint
                .clone()
                .try_into()
                .map_err(|_| "joined_relay_endpoint")?,
        ),
        client_id: LocalAuthClientId::try_from(joined_context.client_id.clone())
            .map_err(|_| "joined_client_id")?,
        provider: LocalAuthProvider::ProtectedFile,
        keychain_path: None,
        protected_file_acknowledgement: Some(LocalFileAcknowledgement::OsPermissionsOnly),
    };
    request_expected_joined(
        &mut client,
        lomi_remote_protocol::ipc::LocalCall::AuthConfigure(LocalAuthConfigure {
            configuration,
            operator_intent: Confirmed::Confirmed,
        }),
        joined_deadline,
        Duration::ZERO,
        "joined_auth_configure",
        |result| matches!(result, LocalResult::AuthConfigured {}),
    )?;
    progress.stage("auth_configured_with_relay");

    let operation_id =
        OperationId::from_bytes(uuid::Uuid::new_v4().into_bytes()).map_err(|_| "operation_id")?;
    let accepted = request_typed_joined::<LocalLoginAccepted>(
        &mut client,
        lomi_remote_protocol::ipc::LocalCall::LoginStart(LocalLoginStart { operation_id }),
        joined_deadline,
        Duration::ZERO,
        "joined_login_start",
        |result| match result {
            LocalResult::LoginAccepted(value) if value.operation_id == operation_id => {
                Some(value.clone())
            }
            _ => None,
        },
    )?;
    let presentation =
        wait_for_presentation_joined(&mut client, joined_deadline, PRESENTATION_TIMEOUT)?;
    if presentation.user_code.expose_wire().is_empty()
        || presentation.user_code.expose_wire().len() > 32
    {
        return Err("joined_user_code");
    }
    verify_directory_identity(&paths.artifacts, paths.artifacts_identity)
        .map_err(|_| "joined_artifacts_directory_changed")?;
    write_private_json(
        &paths.joined_init,
        &JoinedPublicInit {
            format_version: 2,
            run_id: joined_context.run_id.clone(),
            user_code: presentation.user_code.expose_wire().to_owned(),
            host_id,
        },
        MAX_RENDEZVOUS_BYTES,
    )
    .map_err(|_| "joined_public_init_write")?;
    progress.stage("device_code_ready");

    let ready = wait_for_ready_joined(
        &mut client,
        accepted.generation.0,
        joined_deadline,
        READY_TIMEOUT,
    )?;
    if ready.generation != accepted.generation {
        return Err("joined_ready_generation");
    }
    progress.report.auth_ready = true;
    progress.stage("host_ready");

    verify_directory_identity(&paths.artifacts, paths.artifacts_identity)
        .map_err(|_| "joined_artifacts_directory_changed")?;
    let project_identity =
        create_private_directory(&paths.project).map_err(|_| "joined_project_create")?;
    if !directory_is_empty(&paths.project).map_err(|_| "joined_project_inspect")? {
        return Err("joined_project_not_empty");
    }
    let project_path = paths
        .project
        .canonicalize()
        .map_err(|_| "joined_project_path")?;
    if project_path != paths.project {
        return Err("joined_project_path");
    }
    let root_path = LocalRootPath::try_from(project_path.to_string_lossy().into_owned())
        .map_err(|_| "joined_project_path")?;
    let workspace = request_typed_joined(
        &mut client,
        lomi_remote_protocol::ipc::LocalCall::WorkspaceAdd(LocalWorkspaceAdd {
            name: LocalProjectName::try_from("Managed joined cloud fixture".to_owned())
                .map_err(|_| "joined_project_name")?,
            root_path,
            operator_intent: Confirmed::Confirmed,
        }),
        joined_deadline,
        Duration::ZERO,
        "joined_workspace_import",
        |result: &LocalResult| match result {
            LocalResult::Workspace(summary) => Some(summary.clone()),
            _ => None,
        },
    )?;
    let workspace_id = workspace.workspace_id;
    progress.report.workspace_imported = true;
    progress.stage("workspace_imported");

    // Create the one real terminal using the ordinary Local IPC RPC path while
    // this workspace is still private. Cloud publication starts only after
    // the host has committed the running session into WorkspaceState.
    let before_terminal = inspect_workspace_joined(
        &mut client,
        workspace_id,
        "joined_workspace_before_terminal",
        joined_deadline,
        Duration::ZERO,
    )?;
    let create_operation =
        OperationId::from_bytes(uuid::Uuid::new_v4().into_bytes()).map_err(|_| "operation_id")?;
    let create_request = local_rpc_request(RpcCall::TerminalCreate(TerminalCreateParams {
        mutation: MutationContext {
            operation_id: create_operation,
            context: before_terminal.context.clone(),
            expected_revision: before_terminal.domain_revision,
        },
        tab_name: "Managed joined terminal"
            .to_owned()
            .try_into()
            .map_err(|_| "joined_terminal_name")?,
        profile_id: "default"
            .to_owned()
            .try_into()
            .map_err(|_| "joined_terminal_profile")?,
    }))?;
    match local_rpc_joined(
        &mut client,
        create_request,
        "joined_terminal_create",
        joined_deadline,
        Duration::ZERO,
    )? {
        RpcResult::TerminalCreate(receipt)
            if receipt.operation_id() == create_operation
                && receipt.state() == lomi_remote_protocol::OperationState::Succeeded => {}
        _ => return Err("joined_terminal_create"),
    }
    let private_state = inspect_workspace_joined(
        &mut client,
        workspace_id,
        "joined_terminal_verify",
        joined_deadline,
        Duration::ZERO,
    )?;
    let private_terminal = exactly_one_running_terminal(&private_state)?;
    if private_terminal.workspace != private_state.context {
        return Err("joined_terminal_context");
    }
    progress.report.terminal_created = true;
    progress.stage("terminal_created_before_share");

    request_expected_joined(
        &mut client,
        lomi_remote_protocol::ipc::LocalCall::Share(LocalWorkspaceTarget {
            workspace_id,
            operator_intent: Confirmed::Confirmed,
        }),
        joined_deadline,
        Duration::ZERO,
        "joined_workspace_share",
        |result| {
            matches!(result, LocalResult::Workspace(summary)
                if summary.workspace_id == workspace_id
                    && summary.sharing == lomi_remote_protocol::ipc::LocalSharing::Enabled)
        },
    )?;
    let shared_state = inspect_workspace_joined(
        &mut client,
        workspace_id,
        "joined_workspace_shared",
        joined_deadline,
        Duration::ZERO,
    )?;
    let terminal = exactly_one_running_terminal(&shared_state)?;
    if terminal.session_id != private_terminal.session_id
        || terminal.session_epoch != private_terminal.session_epoch
        || terminal.pane_id != private_terminal.pane_id
        || terminal.workspace != shared_state.context
    {
        return Err("joined_terminal_changed_at_share");
    }
    progress.report.workspace = Some(shared_state.context.clone());
    progress.report.terminal = Some(terminal.clone());
    progress.report.workspace_shared = true;
    progress.stage("workspace_shared_with_live_terminal");

    let unshare_request_id = progress.report.unshare_request_id.clone();
    let stop_request_id = progress.report.stop_request_id.clone();
    verify_directory_identity(&paths.artifacts, paths.artifacts_identity)
        .map_err(|_| "joined_artifacts_directory_changed")?;
    write_private_json(
        &paths.joined_state,
        &JoinedPublicState {
            format_version: 2,
            status: "UNREVIEWED_JOINED_CLOUD_HOST_FIXTURE",
            run_id: joined_context.run_id.clone(),
            stage: "workspaceShared",
            host_id,
            workspace: shared_state.context.clone(),
            terminal: terminal.clone(),
            unshare_request_id: unshare_request_id.clone(),
            stop_request_id: stop_request_id.clone(),
        },
        MAX_JOINED_CONTEXT_BYTES,
    )
    .map_err(|_| "joined_state_write")?;
    progress.stage("joined_state_ready");

    wait_for_joined_control(
        &paths.joined_unshare,
        &paths.joined_stop,
        &paths.artifacts,
        paths.artifacts_identity,
        &joined_context.run_id,
        &unshare_request_id,
        JoinedControlAction::Unshare,
        true,
        joined_deadline,
        JOINED_AFTER_UNSHARE_CONTROL_RESERVE,
    )?;
    progress.report.unshare_control_observed = true;
    progress.stage("unshare_control_received");

    request_expected_joined(
        &mut client,
        lomi_remote_protocol::ipc::LocalCall::Unshare(LocalWorkspaceTarget {
            workspace_id,
            operator_intent: Confirmed::Confirmed,
        }),
        joined_deadline,
        JOINED_AFTER_UNSHARE_RPC_RESERVE,
        "joined_workspace_unshare",
        |result| {
            matches!(result, LocalResult::Workspace(summary)
                if summary.workspace_id == workspace_id
                    && summary.sharing == lomi_remote_protocol::ipc::LocalSharing::Disabled)
        },
    )?;
    let unshared_state = inspect_workspace_joined(
        &mut client,
        workspace_id,
        "joined_unshare_verify",
        joined_deadline,
        JOINED_AFTER_UNSHARE_ACK_RESERVE,
    )?;
    let unshared_terminal = exactly_one_running_terminal(&unshared_state)?;
    if unshared_terminal.session_id != terminal.session_id
        || unshared_terminal.session_epoch != terminal.session_epoch
        || unshared_terminal.pane_id != terminal.pane_id
    {
        return Err("joined_terminal_stopped_by_unshare");
    }
    progress.report.workspace = Some(unshared_state.context.clone());
    progress.report.terminal = Some(unshared_terminal.clone());
    progress.report.unshare_acknowledged = true;
    write_private_json(
        &paths.joined_unshare_ack,
        &JoinedUnshareAcknowledgement {
            format_version: 2,
            run_id: joined_context.run_id.clone(),
            request_id: unshare_request_id,
            action: JoinedControlAction::Unshare,
            acknowledged: true,
            host_id,
            workspace: unshared_state.context,
            terminal: unshared_terminal,
        },
        MAX_JOINED_CONTEXT_BYTES,
    )
    .map_err(|_| "joined_unshare_ack_write")?;
    progress.stage("unshare_acknowledged_terminal_still_running");

    // Keep the real host, Local IPC and original terminal alive until the
    // external controller has checked post-unshare denial/revoke behavior.
    wait_for_joined_control(
        &paths.joined_stop,
        &paths.joined_unshare,
        &paths.artifacts,
        paths.artifacts_identity,
        &joined_context.run_id,
        &stop_request_id,
        JoinedControlAction::Stop,
        false,
        joined_deadline,
        JOINED_AFTER_STOP_RESERVE,
    )?;
    progress.report.stop_control_observed = true;
    progress.stage("stop_control_received");

    let pre_close = inspect_workspace_joined(
        &mut client,
        workspace_id,
        "joined_terminal_before_close",
        joined_deadline,
        JOINED_AFTER_PRE_CLOSE_INSPECT_RESERVE,
    )?;
    let current_terminal = exactly_one_running_terminal(&pre_close)?;
    if current_terminal.session_id != terminal.session_id
        || current_terminal.session_epoch != terminal.session_epoch
        || current_terminal.pane_id != terminal.pane_id
    {
        return Err("joined_terminal_changed_before_close");
    }
    let close_operation =
        OperationId::from_bytes(uuid::Uuid::new_v4().into_bytes()).map_err(|_| "operation_id")?;
    let close_request = local_rpc_request(RpcCall::TerminalClose(TerminalCloseParams {
        mutation: MutationContext {
            operation_id: close_operation,
            context: pre_close.context.clone(),
            expected_revision: pre_close.domain_revision,
        },
        pane_id: current_terminal.pane_id,
        expected_session: Some(current_terminal),
    }))?;
    match local_rpc_joined(
        &mut client,
        close_request,
        "joined_terminal_close",
        joined_deadline,
        JOINED_AFTER_CLOSE_RPC_RESERVE,
    )? {
        RpcResult::TerminalClose(receipt)
            if receipt.operation_id() == close_operation
                && receipt.state() == lomi_remote_protocol::OperationState::Succeeded => {}
        _ => return Err("joined_terminal_close"),
    }
    let closed_state = inspect_workspace_joined(
        &mut client,
        workspace_id,
        "joined_terminal_close_verify",
        joined_deadline,
        JOINED_AFTER_CLOSE_INSPECT_RESERVE,
    )?;
    if !closed_state.validate().is_ok() || workspace_session_count(&closed_state) != 0 {
        return Err("joined_terminal_still_present");
    }
    progress.report.terminal_closed = true;
    progress.stage("terminal_closed");

    request_expected_joined(
        &mut client,
        lomi_remote_protocol::ipc::LocalCall::WorkspaceRemove(LocalWorkspaceTarget {
            workspace_id,
            operator_intent: Confirmed::Confirmed,
        }),
        joined_deadline,
        JOINED_AFTER_WORKSPACE_REMOVE_RESERVE,
        "joined_workspace_remove",
        |result| matches!(result, LocalResult::Removed(id) if *id == workspace_id),
    )?;
    verify_directory_identity(&paths.artifacts, paths.artifacts_identity)
        .map_err(|_| "joined_artifacts_directory_changed")?;
    remove_empty_owned_directory(&paths.project, project_identity)
        .map_err(|_| "joined_project_cleanup")?;
    progress.report.project_removed = true;
    progress.stage("workspace_cleanup_complete");
    drop(client);
    Ok(())
}

fn inspect_workspace(
    client: &mut LocalClient,
    workspace_id: lomi_remote_protocol::WorkspaceId,
    failure: &'static str,
) -> Result<WorkspaceState, &'static str> {
    let result = client
        .request(lomi_remote_protocol::ipc::LocalCall::WorkspaceInspect(
            LocalWorkspaceRead { workspace_id },
        ))
        .map_err(|_| failure)?;
    match result.result {
        Ok(LocalResult::WorkspaceState(state)) if state.validate().is_ok() => Ok(*state),
        _ => Err(failure),
    }
}

fn inspect_workspace_joined(
    client: &mut LocalClient,
    workspace_id: lomi_remote_protocol::WorkspaceId,
    failure: &'static str,
    deadline: Instant,
    reserve_after: Duration,
) -> Result<WorkspaceState, &'static str> {
    joined_admit_now(deadline, JOINED_LOCAL_REQUEST_BUDGET, reserve_after)?;
    let state = inspect_workspace(client, workspace_id, failure)?;
    joined_admit_now(deadline, Duration::ZERO, reserve_after)?;
    Ok(state)
}

fn local_rpc_request(call: RpcCall) -> Result<RpcRequest, &'static str> {
    let request_id = format!("joined-{}", uuid::Uuid::new_v4())
        .try_into()
        .map_err(|_| "joined_rpc_request_id")?;
    Ok(RpcRequest {
        v: lomi_remote_protocol::ApplicationMajor,
        r#type: RequestKind::Request,
        request_id,
        timeout_ms: 10_000u64.try_into().map_err(|_| "joined_rpc_timeout")?,
        call,
    })
}

fn local_rpc(
    client: &mut LocalClient,
    request: RpcRequest,
    failure: &'static str,
) -> Result<RpcResult, &'static str> {
    let expected_request_id = request.request_id.clone();
    let response = client
        .request(lomi_remote_protocol::ipc::LocalCall::Rpc(Box::new(request)))
        .map_err(|_| failure)?;
    match response.result {
        Ok(LocalResult::Rpc(response)) => match *response {
            RpcResponse::Result {
                request_id, result, ..
            } if request_id == expected_request_id => Ok(result),
            _ => Err(failure),
        },
        _ => Err(failure),
    }
}

fn local_rpc_joined(
    client: &mut LocalClient,
    request: RpcRequest,
    failure: &'static str,
    deadline: Instant,
    reserve_after: Duration,
) -> Result<RpcResult, &'static str> {
    joined_admit_now(deadline, JOINED_LOCAL_REQUEST_BUDGET, reserve_after)?;
    let result = local_rpc(client, request, failure)?;
    joined_admit_now(deadline, Duration::ZERO, reserve_after)?;
    Ok(result)
}

fn exactly_one_running_terminal(state: &WorkspaceState) -> Result<TerminalContext, &'static str> {
    state.validate().map_err(|_| "joined_workspace_invalid")?;
    let mut sessions = Vec::new();
    for tab in &state.tabs.0 {
        collect_running_sessions(&tab.layout, &mut sessions);
    }
    if sessions.len() != 1 {
        return Err("joined_terminal_count");
    }
    sessions.pop().ok_or("joined_terminal_count")
}

fn collect_running_sessions(
    layout: &lomi_remote_protocol::rpc::TerminalLayout,
    sessions: &mut Vec<TerminalContext>,
) {
    match layout {
        lomi_remote_protocol::rpc::TerminalLayout::Pane { pane }
            if pane.state == lomi_remote_protocol::rpc::PaneState::Running =>
        {
            if let Some(session) = &pane.session {
                sessions.push(session.clone());
            }
        }
        lomi_remote_protocol::rpc::TerminalLayout::Pane { .. } => {}
        lomi_remote_protocol::rpc::TerminalLayout::Split { first, second, .. } => {
            collect_running_sessions(first, sessions);
            collect_running_sessions(second, sessions);
        }
    }
}

fn workspace_session_count(state: &WorkspaceState) -> usize {
    fn count(layout: &lomi_remote_protocol::rpc::TerminalLayout) -> usize {
        match layout {
            lomi_remote_protocol::rpc::TerminalLayout::Pane { pane } => {
                usize::from(pane.session.is_some())
            }
            lomi_remote_protocol::rpc::TerminalLayout::Split { first, second, .. } => {
                count(first) + count(second)
            }
        }
    }
    state.tabs.0.iter().map(|tab| count(&tab.layout)).sum()
}

fn wait_for_joined_control(
    path: &Path,
    other_control: &Path,
    artifacts: &Path,
    artifacts_identity: DirectoryIdentity,
    run_id: &str,
    request_id: &str,
    action: JoinedControlAction,
    reject_other_control: bool,
    joined_deadline: Instant,
    reserve_after: Duration,
) -> Result<(), &'static str> {
    let now = Instant::now();
    let timeout = joined_control_timeout_at(joined_deadline, now, reserve_after)?;
    let poll_deadline = now + timeout;
    let mut first_poll = true;
    loop {
        let now = Instant::now();
        if !first_poll && now >= poll_deadline {
            return Err("joined_control_timeout");
        }
        joined_admit_at(
            joined_deadline,
            now,
            JOINED_CONTROL_POLL_BUDGET,
            reserve_after,
        )?;
        verify_directory_identity(artifacts, artifacts_identity)
            .map_err(|_| "joined_artifacts_directory_changed")?;
        if reject_other_control
            && !matches!(fs::symlink_metadata(other_control), Err(ref error) if error.kind() == std::io::ErrorKind::NotFound)
        {
            return Err("joined_control_order");
        }
        match read_optional_private_json::<JoinedControl>(path, MAX_RENDEZVOUS_BYTES) {
            Ok(Some(control)) if joined_control_matches(&control, run_id, request_id, &action) => {
                joined_admit_now(joined_deadline, Duration::ZERO, reserve_after)?;
                return Ok(());
            }
            Ok(Some(_)) => return Err("joined_control_mismatch"),
            Ok(None) => {
                first_poll = false;
                let now = Instant::now();
                if now >= poll_deadline {
                    return Err("joined_control_timeout");
                }
                let sleep = poll_deadline
                    .saturating_duration_since(now)
                    .min(JOINED_CONTROL_POLL_INTERVAL);
                thread::sleep(sleep);
            }
            Err(_) => return Err("joined_control_invalid"),
        }
    }
}

fn joined_control_matches(
    control: &JoinedControl,
    run_id: &str,
    request_id: &str,
    action: &JoinedControlAction,
) -> bool {
    control.format_version == 2
        && control.run_id == run_id
        && canonical_uuid(&control.request_id)
        && control.request_id == request_id
        && control.action == *action
}

fn wait_for_presentation(client: &mut LocalClient) -> Result<LocalLoginPresentation, &'static str> {
    wait_for_presentation_until(client, Instant::now() + PRESENTATION_TIMEOUT)
}

fn wait_for_presentation_until(
    client: &mut LocalClient,
    deadline: Instant,
) -> Result<LocalLoginPresentation, &'static str> {
    while Instant::now() < deadline {
        let response = client
            .request(lomi_remote_protocol::ipc::LocalCall::LoginPresentation {})
            .map_err(|_| "login_presentation")?;
        match response.result {
            Ok(LocalResult::LoginPresentation(value)) => return Ok(value),
            Err(LocalError::Conflict | LocalError::Unavailable) => {}
            _ => return Err("login_presentation"),
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err("login_presentation_timeout")
}

fn wait_for_presentation_joined(
    client: &mut LocalClient,
    joined_deadline: Instant,
    phase_timeout: Duration,
) -> Result<LocalLoginPresentation, &'static str> {
    let deadline = joined_deadline.min(Instant::now() + phase_timeout);
    loop {
        joined_admit_now(deadline, JOINED_LOCAL_REQUEST_BUDGET, Duration::ZERO)
            .map_err(|_| "joined_login_presentation_deadline")?;
        let response = client
            .request(lomi_remote_protocol::ipc::LocalCall::LoginPresentation {})
            .map_err(|_| "login_presentation")?;
        joined_admit_now(deadline, Duration::ZERO, Duration::ZERO)
            .map_err(|_| "joined_login_presentation_deadline")?;
        match response.result {
            Ok(LocalResult::LoginPresentation(value)) => return Ok(value),
            Err(LocalError::Conflict | LocalError::Unavailable) => {
                joined_sleep_before_next_call(
                    deadline,
                    JOINED_LOCAL_REQUEST_BUDGET,
                    Duration::from_millis(25),
                    "login_presentation_timeout",
                )?;
            }
            _ => return Err("login_presentation"),
        }
    }
}

fn wait_for_ready(
    client: &mut LocalClient,
    expected_generation: u64,
) -> Result<LocalLoginStatus, &'static str> {
    wait_for_ready_until(client, expected_generation, Instant::now() + READY_TIMEOUT)
}

fn wait_for_ready_until(
    client: &mut LocalClient,
    expected_generation: u64,
    deadline: Instant,
) -> Result<LocalLoginStatus, &'static str> {
    while Instant::now() < deadline {
        let response = client
            .request(lomi_remote_protocol::ipc::LocalCall::LoginStatus {})
            .map_err(|_| "login_status")?;
        match response.result {
            Ok(LocalResult::LoginStatus(status))
                if status.phase == LocalAuthPhase::Ready
                    && !status.locked
                    && !status.pending_cloud_revoke
                    && status.storage == lomi_remote_protocol::ipc::LocalAuthStorage::Available
                    && status.generation.0 == expected_generation =>
            {
                return Ok(status);
            }
            Ok(LocalResult::LoginStatus(_))
            | Err(LocalError::Conflict | LocalError::Unavailable) => {}
            _ => return Err("login_status"),
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err("login_ready_timeout")
}

fn wait_for_ready_joined(
    client: &mut LocalClient,
    expected_generation: u64,
    joined_deadline: Instant,
    phase_timeout: Duration,
) -> Result<LocalLoginStatus, &'static str> {
    let deadline = joined_deadline.min(Instant::now() + phase_timeout);
    loop {
        joined_admit_now(deadline, JOINED_LOCAL_REQUEST_BUDGET, Duration::ZERO)
            .map_err(|_| "joined_login_ready_deadline")?;
        let response = client
            .request(lomi_remote_protocol::ipc::LocalCall::LoginStatus {})
            .map_err(|_| "login_status")?;
        joined_admit_now(deadline, Duration::ZERO, Duration::ZERO)
            .map_err(|_| "joined_login_ready_deadline")?;
        match response.result {
            Ok(LocalResult::LoginStatus(status))
                if status.phase == LocalAuthPhase::Ready
                    && !status.locked
                    && !status.pending_cloud_revoke
                    && status.storage == lomi_remote_protocol::ipc::LocalAuthStorage::Available
                    && status.generation.0 == expected_generation =>
            {
                return Ok(status);
            }
            Ok(LocalResult::LoginStatus(_))
            | Err(LocalError::Conflict | LocalError::Unavailable) => {
                joined_sleep_before_next_call(
                    deadline,
                    JOINED_LOCAL_REQUEST_BUDGET,
                    Duration::from_millis(100),
                    "login_ready_timeout",
                )?;
            }
            _ => return Err("login_status"),
        }
    }
}

fn joined_remaining(deadline: Instant) -> Result<Duration, &'static str> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err("joined_drive_deadline")
    } else {
        Ok(remaining)
    }
}

fn joined_admit_at(
    deadline: Instant,
    now: Instant,
    call_budget: Duration,
    reserve_after: Duration,
) -> Result<(), &'static str> {
    let required = call_budget
        .checked_add(reserve_after)
        .ok_or("joined_drive_deadline")?;
    let remaining = deadline.saturating_duration_since(now);
    if remaining.is_zero() || remaining < required {
        Err("joined_drive_deadline")
    } else {
        Ok(())
    }
}

fn joined_admit_now(
    deadline: Instant,
    call_budget: Duration,
    reserve_after: Duration,
) -> Result<(), &'static str> {
    joined_admit_at(deadline, Instant::now(), call_budget, reserve_after)
}

fn joined_sleep_before_next_call(
    deadline: Instant,
    next_call_budget: Duration,
    interval: Duration,
    failure: &'static str,
) -> Result<(), &'static str> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let sleep_budget = remaining.checked_sub(next_call_budget).ok_or(failure)?;
    if sleep_budget.is_zero() {
        return Err(failure);
    }
    thread::sleep(interval.min(sleep_budget));
    Ok(())
}

fn joined_control_timeout_at(
    deadline: Instant,
    now: Instant,
    reserve_after: Duration,
) -> Result<Duration, &'static str> {
    let available = joined_remaining_at(deadline, now)?;
    let required = reserve_after
        .checked_add(JOINED_CONTROL_POLL_BUDGET)
        .ok_or("joined_control_timeout")?;
    let wait_budget = available
        .checked_sub(required)
        .ok_or("joined_control_timeout")?;
    Ok(wait_budget.min(STOP_MARKER_TIMEOUT))
}

fn joined_remaining_at(deadline: Instant, now: Instant) -> Result<Duration, &'static str> {
    let remaining = deadline.saturating_duration_since(now);
    if remaining.is_zero() {
        Err("joined_drive_deadline")
    } else {
        Ok(remaining)
    }
}

fn wait_for_stop_marker(
    path: &Path,
    artifacts: &Path,
    artifacts_identity: DirectoryIdentity,
    timeout: Duration,
) -> Result<(), &'static str> {
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            return Err("stop_marker_timeout");
        }
        verify_directory_identity(artifacts, artifacts_identity)
            .map_err(|_| "artifacts_directory_changed")?;
        match read_optional_private_json::<StopMarker>(path, MAX_RENDEZVOUS_BYTES) {
            Ok(Some(marker)) if marker.stop => return Ok(()),
            Ok(Some(_)) => return Err("stop_marker_value"),
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(_) => return Err("stop_marker_invalid"),
        }
    }
}

fn request_expected(
    client: &mut LocalClient,
    call: lomi_remote_protocol::ipc::LocalCall,
    stage: &'static str,
    expected: impl FnOnce(&LocalResult) -> bool,
) -> Result<(), &'static str> {
    let response = client.request(call).map_err(|_| stage)?;
    match response.result {
        Ok(value) if expected(&value) => Ok(()),
        _ => Err(stage),
    }
}

fn request_expected_joined(
    client: &mut LocalClient,
    call: lomi_remote_protocol::ipc::LocalCall,
    deadline: Instant,
    reserve_after: Duration,
    stage: &'static str,
    expected: impl FnOnce(&LocalResult) -> bool,
) -> Result<(), &'static str> {
    joined_admit_now(deadline, JOINED_LOCAL_REQUEST_BUDGET, reserve_after)?;
    request_expected(client, call, stage, expected)?;
    joined_admit_now(deadline, Duration::ZERO, reserve_after)
}

fn request_typed<T>(
    client: &mut LocalClient,
    call: lomi_remote_protocol::ipc::LocalCall,
    stage: &'static str,
    select: impl FnOnce(&LocalResult) -> Option<T>,
) -> Result<T, &'static str> {
    let response = client.request(call).map_err(|_| stage)?;
    match response.result {
        Ok(value) => select(&value).ok_or(stage),
        Err(_) => Err(stage),
    }
}

fn request_typed_joined<T>(
    client: &mut LocalClient,
    call: lomi_remote_protocol::ipc::LocalCall,
    deadline: Instant,
    reserve_after: Duration,
    stage: &'static str,
    select: impl FnOnce(&LocalResult) -> Option<T>,
) -> Result<T, &'static str> {
    joined_admit_now(deadline, JOINED_LOCAL_REQUEST_BUDGET, reserve_after)?;
    let result = request_typed(client, call, stage, select)?;
    joined_admit_now(deadline, Duration::ZERO, reserve_after)?;
    Ok(result)
}

struct StopOutcome {
    stop_requested: bool,
    actor_returned: bool,
    actor_succeeded: bool,
    actor_joined: bool,
    owner_lock_released: bool,
}

impl ManagedActor {
    fn start(
        profile: &Path,
        root_der: &[u8],
        profile_parent_identity: DirectoryIdentity,
        profile_identity: DirectoryIdentity,
        joined: Option<JoinedActorConfig>,
    ) -> Result<Self, &'static str> {
        let profile_for_thread = profile.to_path_buf();
        let auth_root = root_der.to_vec();
        let remote_root = root_der.to_vec();
        let relay_root = root_der.to_vec();
        let (ready_tx, ready) = mpsc::channel();
        let (finished_tx, finished) = mpsc::channel();
        let join = thread::Builder::new()
            .name("managed-cloud-actor-fixture".to_owned())
            .spawn(move || {
                let ready = move |runtime_id| {
                    if ready_tx.send(runtime_id).is_ok() {
                        Ok(())
                    } else {
                        Err(crate::HostError::Unavailable)
                    }
                };
                let result = match joined {
                    Some(joined) => crate::unix::run_with_managed_joined_fixture(
                        &profile_for_thread,
                        auth_root,
                        remote_root,
                        relay_root,
                        &joined.worker_executable,
                        &joined.worker_sha256,
                        ready,
                        |result| result,
                    ),
                    None => crate::unix::run_with_managed_cloud_fixture(
                        &profile_for_thread,
                        auth_root,
                        remote_root,
                        ready,
                        |result| result,
                    ),
                };
                let _ = finished_tx.send(result.is_ok());
            })
            .map_err(|_| "managed_actor_thread")?;
        Ok(Self {
            profile: profile.to_path_buf(),
            profile_parent_identity,
            profile_identity,
            ready,
            finished,
            join: Some(join),
            shutdown_attempted: false,
        })
    }

    fn wait_until_started(&self) -> Result<lomi_remote_protocol::RuntimeId, &'static str> {
        self.ready
            .recv_timeout(ACTOR_START_TIMEOUT)
            .map_err(|_| "managed_actor_start_timeout")
    }

    fn wait_until_started_until(
        &self,
        deadline: Instant,
    ) -> Result<lomi_remote_protocol::RuntimeId, &'static str> {
        let timeout = joined_remaining(deadline)?.min(ACTOR_START_TIMEOUT);
        let runtime_id = self
            .ready
            .recv_timeout(timeout)
            .map_err(|_| "managed_actor_start_timeout")?;
        joined_admit_now(deadline, Duration::ZERO, Duration::ZERO)?;
        Ok(runtime_id)
    }

    fn stop_and_join(&mut self) -> StopOutcome {
        self.shutdown_attempted = true;
        let stop_requested = request_daemon_stop(&self.profile, Duration::from_secs(5));
        let actor_result = self.finished.recv_timeout(ACTOR_FINISH_TIMEOUT).ok();
        let actor_returned = actor_result.is_some();
        let actor_succeeded = actor_result == Some(true);
        let actor_joined = if actor_returned {
            self.join.take().is_some_and(|join| join.join().is_ok())
        } else {
            false
        };
        let owner_lock_released = if actor_joined {
            owner_endpoint_and_lock_released(
                &self.profile,
                self.profile_parent_identity,
                self.profile_identity,
            )
        } else {
            false
        };
        StopOutcome {
            stop_requested,
            actor_returned,
            actor_succeeded,
            actor_joined,
            owner_lock_released,
        }
    }
}

impl Drop for ManagedActor {
    fn drop(&mut self) {
        if self.join.is_none() || self.shutdown_attempted {
            return;
        }
        self.shutdown_attempted = true;
        let _ = request_daemon_stop(&self.profile, Duration::from_secs(5));
        if self.finished.recv_timeout(ACTOR_FINISH_TIMEOUT).is_ok()
            && let Some(join) = self.join.take()
        {
            let _ = join.join();
        }
    }
}

fn request_daemon_stop(profile: &Path, connect_budget: Duration) -> bool {
    let deadline = Instant::now() + connect_budget;
    loop {
        match LocalClient::connect_with_timeout(profile, Duration::from_millis(250)) {
            Ok(mut client) => {
                let response = client.request(lomi_remote_protocol::ipc::LocalCall::DaemonStop(
                    LocalOperatorIntent {
                        operator_intent: Confirmed::Confirmed,
                    },
                ));
                return matches!(
                    response,
                    Ok(response) if matches!(response.result, Ok(LocalResult::Stopping {}))
                );
            }
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            Err(_) => return false,
        }
    }
}

impl ManagedWatchdog {
    fn start(profile: PathBuf) -> Result<Self, &'static str> {
        let (sender, receiver) = mpsc::channel();
        let fired = Arc::new(AtomicBool::new(false));
        let fired_thread = fired.clone();
        let join = thread::Builder::new()
            .name("managed-cloud-actor-watchdog".to_owned())
            .spawn(move || match receiver.recv_timeout(WATCHDOG_TIMEOUT) {
                Ok(WatchdogCommand::Finished) => {}
                Ok(WatchdogCommand::StopNow) | Err(mpsc::RecvTimeoutError::Timeout) => {
                    fired_thread.store(true, Ordering::Release);
                    let _ = request_daemon_stop(&profile, Duration::from_secs(5));
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    fired_thread.store(true, Ordering::Release);
                    let _ = request_daemon_stop(&profile, Duration::from_secs(5));
                }
            })
            .map_err(|_| "watchdog_thread")?;
        Ok(Self {
            sender: Some(sender),
            join: Some(join),
            fired,
        })
    }

    fn finish(&mut self) -> bool {
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(WatchdogCommand::Finished);
        }
        if let Some(join) = self.join.take() {
            if join.join().is_err() {
                return false;
            }
        }
        !self.fired.load(Ordering::Acquire)
    }
}

impl Drop for ManagedWatchdog {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(WatchdogCommand::StopNow);
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn owner_endpoint_and_lock_released(
    profile: &Path,
    profile_parent_identity: DirectoryIdentity,
    profile_identity: DirectoryIdentity,
) -> bool {
    let parent = profile.parent().unwrap_or_else(|| Path::new("/"));
    if verify_directory_identity(parent, profile_parent_identity).is_err()
        || verify_directory_identity(profile, profile_identity).is_err()
        || require_absent(&profile.join("discovery.json")).is_err()
        || require_absent(&profile.join("host.sock")).is_err()
    {
        return false;
    }
    match OwnerLock::acquire(profile) {
        Ok(lock) => {
            drop(lock);
            verify_directory_identity(parent, profile_parent_identity).is_ok()
                && verify_directory_identity(profile, profile_identity).is_ok()
        }
        Err(_) => false,
    }
}

fn create_private_directory(path: &Path) -> Result<DirectoryIdentity, &'static str> {
    require_absent(path)?;
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    builder.create(path).map_err(|_| "directory_create")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| "directory_mode")?;
    private_directory_identity(path)
}

fn private_directory_identity(path: &Path) -> Result<DirectoryIdentity, &'static str> {
    let before = fs::symlink_metadata(path).map_err(|_| "directory_stat")?;
    let identity = directory_identity(&before)?;
    if before.mode() & 0o777 != 0o700 || before.uid() != unsafe { libc::geteuid() } {
        return Err("directory_permissions");
    }
    if fs::canonicalize(path).map_err(|_| "directory_canonical")? != path {
        return Err("directory_canonical");
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY);
    let opened = options.open(path).map_err(|_| "directory_open")?;
    let opened_meta = opened.metadata().map_err(|_| "directory_stat")?;
    if directory_identity(&opened_meta)? != identity {
        return Err("directory_replaced");
    }
    validate_private_fd(&opened).map_err(|_| "directory_acl")?;
    let after = fs::symlink_metadata(path).map_err(|_| "directory_replaced")?;
    if directory_identity(&after)? != identity || after.mode() & 0o777 != 0o700 {
        return Err("directory_replaced");
    }
    Ok(identity)
}

fn directory_identity(metadata: &Metadata) -> Result<DirectoryIdentity, &'static str> {
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() < 2
    {
        return Err("directory_type");
    }
    Ok(DirectoryIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode() & 0o777,
    })
}

fn validate_private_fd(file: &File) -> Result<(), &'static str> {
    let metadata = file.metadata().map_err(|_| "file_stat")?;
    let expected_mode = if metadata.is_dir() {
        0o700
    } else if metadata.is_file() {
        0o600
    } else {
        return Err("file_type");
    };
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != expected_mode {
        return Err("file_permissions");
    }
    reject_fixture_allow_acls(file)
}

#[cfg(target_os = "macos")]
fn reject_fixture_allow_acls(file: &File) -> Result<(), &'static str> {
    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut libc::c_void;
        fn acl_get_entry(
            acl: *mut libc::c_void,
            id: libc::c_int,
            entry: *mut *mut libc::c_void,
        ) -> libc::c_int;
        fn acl_get_tag_type(entry: *mut libc::c_void, tag: *mut libc::c_int) -> libc::c_int;
        fn acl_free(acl: *mut libc::c_void) -> libc::c_int;
    }

    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
    if acl.is_null() {
        return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(())
        } else {
            Err("acl_read")
        };
    }
    struct Acl(*mut libc::c_void);
    impl Drop for Acl {
        fn drop(&mut self) {
            unsafe {
                acl_free(self.0);
            }
        }
    }
    let _guard = Acl(acl);
    let mut selector = 0;
    loop {
        let mut entry = std::ptr::null_mut();
        if unsafe { acl_get_entry(acl, selector, &mut entry) } != 0 {
            return if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                Ok(())
            } else {
                Err("acl_read")
            };
        }
        let mut tag = 0;
        if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 || tag != 2 {
            // KAUTH_ACE_DENY is 2; unknown or allow entries fail closed.
            return Err("acl_grant");
        }
        selector = -1;
    }
}

#[cfg(not(target_os = "macos"))]
fn reject_fixture_allow_acls(_file: &File) -> Result<(), &'static str> {
    Ok(())
}

fn verify_directory_identity(path: &Path, expected: DirectoryIdentity) -> Result<(), &'static str> {
    if private_directory_identity(path)? != expected {
        return Err("directory_identity");
    }
    Ok(())
}

fn remove_empty_owned_directory(
    path: &Path,
    expected: DirectoryIdentity,
) -> Result<(), &'static str> {
    verify_directory_identity(path, expected)?;
    if !directory_is_empty(path)? {
        return Err("directory_not_empty");
    }
    fs::remove_dir(path).map_err(|_| "directory_remove")?;
    require_absent(path)
}

fn directory_is_empty(path: &Path) -> Result<bool, &'static str> {
    let mut entries = fs::read_dir(path).map_err(|_| "directory_read")?;
    Ok(entries.next().is_none())
}

fn validate_file(metadata: &Metadata, limit: u64) -> Result<FileFingerprint, &'static str> {
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > limit
    {
        return Err("file_metadata");
    }
    Ok(file_fingerprint(metadata))
}

fn file_fingerprint(metadata: &Metadata) -> FileFingerprint {
    FileFingerprint {
        dev: metadata.dev(),
        ino: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode() & 0o777,
        nlink: metadata.nlink(),
        len: metadata.len(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
    }
}

fn read_private_regular(path: &Path, limit: u64) -> Result<Vec<u8>, &'static str> {
    let before = fs::symlink_metadata(path).map_err(|_| "file_stat")?;
    let expected = validate_file(&before, limit)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let mut file = options.open(path).map_err(|_| "file_open")?;
    let opened = file.metadata().map_err(|_| "file_stat")?;
    if validate_file(&opened, limit)? != expected {
        return Err("file_replaced");
    }
    validate_private_fd(&file).map_err(|_| "file_acl")?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "file_read")?;
    if bytes.is_empty() || bytes.len() as u64 > limit {
        return Err("file_size");
    }
    let opened_after = file.metadata().map_err(|_| "file_stat")?;
    let path_after = fs::symlink_metadata(path).map_err(|_| "file_replaced")?;
    if validate_file(&opened_after, limit)? != expected
        || validate_file(&path_after, limit)? != expected
        || bytes.len() as u64 != expected.len
    {
        return Err("file_changed");
    }
    Ok(bytes)
}

fn write_private_json<T: Serialize>(
    path: &Path,
    value: &T,
    limit: u64,
) -> Result<(), &'static str> {
    require_absent(path)?;
    let bytes = serde_json::to_vec(value).map_err(|_| "json_encode")?;
    if bytes.is_empty() || bytes.len() as u64 > limit {
        return Err("json_size");
    }
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let mut file = options.open(path).map_err(|_| "file_create")?;
    let expected = validate_file(&file.metadata().map_err(|_| "file_stat")?, limit)?;
    if expected.len != 0 {
        return Err("file_create");
    }
    validate_private_fd(&file).map_err(|_| "file_acl")?;
    file.write_all(&bytes).map_err(|_| "file_write")?;
    file.sync_all().map_err(|_| "file_sync")?;
    let after = file.metadata().map_err(|_| "file_stat")?;
    let path_after = fs::symlink_metadata(path).map_err(|_| "file_replaced")?;
    let after_id = validate_file(&after, limit)?;
    if validate_file(&path_after, limit)? != after_id || after_id.len != bytes.len() as u64 {
        return Err("file_changed");
    }
    let parent = path.parent().ok_or("file_parent")?;
    let mut directory = OpenOptions::new();
    directory
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY);
    directory
        .open(parent)
        .and_then(|value| value.sync_all())
        .map_err(|_| "directory_sync")?;
    Ok(())
}

fn read_optional_private_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    limit: u64,
) -> Result<Option<T>, &'static str> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("rendezvous_stat"),
        Ok(_) => {
            let raw = read_private_regular(path, limit)?;
            serde_json::from_slice(&raw)
                .map(Some)
                .map_err(|_| "rendezvous_schema")
        }
    }
}

fn require_absent(path: &Path) -> Result<(), &'static str> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err("path_not_fresh"),
    }
}

fn required_env(name: &str, max_len: usize) -> Result<String, &'static str> {
    match env::var(name) {
        Ok(value) if !value.is_empty() && value.len() <= max_len => Ok(value),
        _ => Err("fixture_environment"),
    }
}

fn required_sha_env(name: &str) -> Result<String, &'static str> {
    let value = required_env(name, 64)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("context_hash_pin");
    }
    Ok(value)
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}

fn valid_origin(value: &str) -> bool {
    let Some(port) = value.strip_prefix("https://127.0.0.1:") else {
        return false;
    };
    if port.is_empty()
        || port.len() > 5
        || port.starts_with('0')
        || !port.bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    port.parse::<u16>()
        .is_ok_and(|parsed| parsed != 0 && parsed.to_string() == port)
}

fn valid_client_id(value: &str) -> bool {
    LocalAuthClientId::try_from(value.to_owned()).is_ok_and(|parsed| String::from(parsed) == value)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn stage(name: &'static str) {
    println!("LOMI_MANAGED_CLOUD_STAGE={name}");
}

fn joined_stage(name: &'static str) {
    println!("LOMI_MANAGED_JOINED_CLOUD_STAGE={name}");
}

#[cfg(test)]
mod joined_fixture_contract_tests {
    use super::*;
    use crate::testsupport::BuilderExt as _;
    use serde_json::json;

    fn joined_context(artifacts: &Path) -> JoinedManagedContext {
        JoinedManagedContext {
            format_version: 2,
            run_id: "12345678-1234-4234-8234-123456789abc".to_owned(),
            auth_origin: "https://127.0.0.1:41001".to_owned(),
            remote_api_origin: "https://127.0.0.1:41002".to_owned(),
            client_id: JOINED_CLIENT_ID.to_owned(),
            relay_endpoint: "wss://127.0.0.1:41003/v2/relay".to_owned(),
            terminal_worker_path: artifacts
                .join("rust-target/debug/lomiremote")
                .to_string_lossy()
                .into_owned(),
            terminal_worker_sha256: "a".repeat(64),
        }
    }

    fn make_worker(artifacts: &Path) -> PathBuf {
        let debug = artifacts.join("rust-target/debug");
        fs::create_dir_all(&debug).unwrap();
        fs::set_permissions(debug.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&debug, fs::Permissions::from_mode(0o700)).unwrap();
        let worker = debug.join("lomiremote");
        fs::write(&worker, b"public fake worker fixture bytes").unwrap();
        fs::set_permissions(&worker, fs::Permissions::from_mode(0o700)).unwrap();
        worker
    }

    #[test]
    fn joined_context_is_v2_closed_and_pins_worker_inside_artifact_tree() {
        let directory = tempfile::Builder::new().private_tempdir().unwrap();
        let artifacts = directory.path().join("cloud-artifacts");
        fs::create_dir(&artifacts).unwrap();
        fs::set_permissions(&artifacts, fs::Permissions::from_mode(0o700)).unwrap();
        let worker = make_worker(&artifacts);
        let valid = joined_context(&artifacts);
        assert!(validate_joined_context(&valid, &valid.run_id, &artifacts).is_ok());
        assert_eq!(
            joined_worker_path(&artifacts, worker.to_str().unwrap()).unwrap(),
            worker
        );

        let mut wrong_version = joined_context(&artifacts);
        wrong_version.format_version = 1;
        assert!(validate_joined_context(&wrong_version, &valid.run_id, &artifacts).is_err());
        let mut wrong_run = joined_context(&artifacts);
        wrong_run.run_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned();
        assert!(validate_joined_context(&wrong_run, &valid.run_id, &artifacts).is_err());
        let mut wrong_client = joined_context(&artifacts);
        wrong_client.client_id = "untrusted-client".to_owned();
        assert!(validate_joined_context(&wrong_client, &valid.run_id, &artifacts).is_err());
        let mut wrong_hash = joined_context(&artifacts);
        wrong_hash.terminal_worker_sha256 = "A".repeat(64);
        assert!(validate_joined_context(&wrong_hash, &valid.run_id, &artifacts).is_err());
        let mut traversal = joined_context(&artifacts);
        traversal.terminal_worker_path = artifacts
            .join("rust-target/debug/../../outside")
            .to_string_lossy()
            .into_owned();
        assert!(validate_joined_context(&traversal, &valid.run_id, &artifacts).is_err());

        let alias = artifacts.join("rust-target/debug/worker-alias");
        std::os::unix::fs::symlink(&worker, &alias).unwrap();
        assert!(joined_worker_path(&artifacts, alias.to_str().unwrap()).is_err());
        fs::remove_file(&worker).unwrap();
        std::os::unix::fs::symlink(&alias, &worker).unwrap();
        assert!(joined_worker_path(&artifacts, worker.to_str().unwrap()).is_err());
    }

    #[test]
    fn relay_endpoint_is_loopback_wss_with_a_canonical_nonprivileged_port() {
        for valid in [
            "wss://127.0.0.1:1024/v2/relay",
            "wss://127.0.0.1:41003/v2/relay",
            "wss://127.0.0.1:65535/v2/relay",
        ] {
            assert!(valid_relay_endpoint(valid), "{valid}");
        }
        for invalid in [
            "ws://127.0.0.1:41003/v2/relay",
            "wss://localhost:41003/v2/relay",
            "wss://127.0.0.1:443/v2/relay",
            "wss://127.0.0.1:0/v2/relay",
            "wss://127.0.0.1:041003/v2/relay",
            "wss://127.0.0.1:65536/v2/relay",
            "wss://127.0.0.1:41003/v2/relay?next=example.com",
            "wss://user@127.0.0.1:41003/v2/relay",
            "wss://192.0.2.5:41003/v2/relay",
        ] {
            assert!(!valid_relay_endpoint(invalid), "{invalid}");
        }
    }

    #[test]
    fn joined_controls_are_single_action_run_and_request_correlated() {
        let control = JoinedControl {
            format_version: 2,
            run_id: "12345678-1234-4234-8234-123456789abc".to_owned(),
            request_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            action: JoinedControlAction::Unshare,
        };
        assert!(joined_control_matches(
            &control,
            &control.run_id,
            &control.request_id,
            &JoinedControlAction::Unshare
        ));
        assert!(!joined_control_matches(
            &control,
            &control.run_id,
            &control.request_id,
            &JoinedControlAction::Stop
        ));
        assert!(!joined_control_matches(
            &control,
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            &control.request_id,
            &JoinedControlAction::Unshare
        ));
        let extra = json!({
            "formatVersion": 2,
            "runId": control.run_id,
            "requestId": control.request_id,
            "action": "unshare",
            "arbitraryRpc": "daemon.stop"
        });
        assert!(serde_json::from_value::<JoinedControl>(extra).is_err());
    }

    #[test]
    fn joined_result_schema_is_separate_and_contains_only_public_fixture_receipts() {
        let progress = JoinedProgress::new("12345678-1234-4234-8234-123456789abc".to_owned());
        assert_ne!(
            progress.report.unshare_request_id,
            progress.report.stop_request_id
        );
        let value = serde_json::to_value(progress.report).unwrap();
        let object = value.as_object().unwrap();
        let expected = [
            "formatVersion",
            "status",
            "outcome",
            "runId",
            "hostId",
            "workspace",
            "terminal",
            "unshareRequestId",
            "stopRequestId",
            "authReady",
            "workspaceImported",
            "terminalCreated",
            "workspaceShared",
            "unshareControlObserved",
            "unshareAcknowledged",
            "stopControlObserved",
            "terminalClosed",
            "projectRemoved",
            "stopRequested",
            "actorReturned",
            "actorSucceeded",
            "actorJoined",
            "ownerLockReleased",
            "stages",
            "failureStage",
        ];
        let mut actual = object.keys().map(String::as_str).collect::<Vec<_>>();
        let mut expected = expected.to_vec();
        actual.sort_unstable();
        expected.sort_unstable();
        assert_eq!(actual, expected);
        let serialized = value.to_string();
        assert!(!serialized.contains("terminalWorkerPath"));
        assert!(!serialized.contains("userCode"));
        assert!(!serialized.contains("privateKey"));
    }

    #[test]
    fn joined_deadline_stays_within_existing_watchdog_budget() {
        assert_eq!(
            JOINED_SHUTDOWN_BUDGET,
            JOINED_STOP_CONNECT_BUDGET + JOINED_STOP_REQUEST_BUDGET + ACTOR_FINISH_TIMEOUT
        );
        assert_eq!(
            JOINED_AFTER_STOP_RESERVE,
            JOINED_STOP_CLEANUP_IPC_BUDGET + JOINED_SHUTDOWN_BUDGET + JOINED_RESULT_CAPTURE_MARGIN
        );
        assert_eq!(
            JOINED_STOP_CLEANUP_IPC_BUDGET,
            JOINED_LOCAL_REQUEST_BUDGET * 4
        );
        assert_eq!(
            JOINED_AFTER_PRE_CLOSE_INSPECT_RESERVE,
            JOINED_LOCAL_REQUEST_BUDGET + JOINED_AFTER_CLOSE_RPC_RESERVE
        );
        assert_eq!(
            JOINED_AFTER_CLOSE_RPC_RESERVE,
            JOINED_LOCAL_REQUEST_BUDGET + JOINED_AFTER_CLOSE_INSPECT_RESERVE
        );
        assert_eq!(
            JOINED_AFTER_CLOSE_INSPECT_RESERVE,
            JOINED_LOCAL_REQUEST_BUDGET + JOINED_AFTER_WORKSPACE_REMOVE_RESERVE
        );
        assert_eq!(
            JOINED_AFTER_UNSHARE_ACK_RESERVE,
            JOINED_STOP_CONTROL_MIN_WINDOW
                + JOINED_CONTROL_POLL_BUDGET
                + JOINED_UNSHARE_ACK_MARGIN
                + JOINED_AFTER_STOP_RESERVE
        );
        assert_eq!(
            JOINED_AFTER_UNSHARE_RPC_RESERVE,
            JOINED_LOCAL_REQUEST_BUDGET + JOINED_AFTER_UNSHARE_ACK_RESERVE
        );
        assert_eq!(
            JOINED_AFTER_UNSHARE_CONTROL_RESERVE,
            JOINED_LOCAL_REQUEST_BUDGET + JOINED_AFTER_UNSHARE_RPC_RESERVE
        );
        assert!(
            JOINED_DRIVE_TIMEOUT + JOINED_SHUTDOWN_BUDGET + JOINED_RESULT_CAPTURE_MARGIN
                < WATCHDOG_TIMEOUT
        );
        assert!(joined_remaining(Instant::now() - Duration::from_millis(1)).is_err());
    }

    #[test]
    fn joined_ipc_and_late_stop_admission_preserve_cleanup_and_shutdown_budget() {
        let now = Instant::now();
        assert!(
            joined_admit_at(
                now + JOINED_LOCAL_REQUEST_BUDGET,
                now,
                JOINED_LOCAL_REQUEST_BUDGET,
                Duration::ZERO,
            )
            .is_ok()
        );
        assert!(
            joined_admit_at(
                now + JOINED_LOCAL_REQUEST_BUDGET - Duration::from_nanos(1),
                now,
                JOINED_LOCAL_REQUEST_BUDGET,
                Duration::ZERO,
            )
            .is_err()
        );

        let stop_budget = JOINED_AFTER_STOP_RESERVE + JOINED_CONTROL_POLL_BUDGET;
        let stop_deadline = now + stop_budget + Duration::from_secs(1);
        assert_eq!(
            joined_control_timeout_at(stop_deadline, now, JOINED_AFTER_STOP_RESERVE).unwrap(),
            Duration::from_secs(1)
        );

        let latest_safe_stop = now + stop_budget;
        assert!(
            joined_admit_at(
                now + stop_budget - Duration::from_nanos(1),
                now,
                JOINED_CONTROL_POLL_BUDGET,
                JOINED_AFTER_STOP_RESERVE,
            )
            .is_err()
        );
        assert!(
            joined_admit_at(
                latest_safe_stop,
                now,
                JOINED_CONTROL_POLL_BUDGET,
                JOINED_AFTER_STOP_RESERVE,
            )
            .is_ok()
        );
        assert!(
            joined_control_timeout_at(
                now + stop_budget - Duration::from_nanos(1),
                now,
                JOINED_AFTER_STOP_RESERVE,
            )
            .is_err()
        );

        let after_late_stop = latest_safe_stop + Duration::from_millis(1);
        assert!(
            joined_admit_at(
                stop_deadline,
                after_late_stop,
                Duration::ZERO,
                JOINED_AFTER_STOP_RESERVE,
            )
            .is_err()
        );
    }

    #[test]
    fn v1_and_v2_context_deserializers_do_not_accept_each_others_schema() {
        let legacy = json!({
            "formatVersion": 1,
            "runId": "12345678-1234-4234-8234-123456789abc",
            "authOrigin": "https://127.0.0.1:41001",
            "remoteApiOrigin": "https://127.0.0.1:41002",
            "clientId": JOINED_CLIENT_ID
        });
        let joined = json!({
            "formatVersion": 2,
            "runId": "12345678-1234-4234-8234-123456789abc",
            "authOrigin": "https://127.0.0.1:41001",
            "remoteApiOrigin": "https://127.0.0.1:41002",
            "clientId": JOINED_CLIENT_ID,
            "relayEndpoint": "wss://127.0.0.1:41003/v2/relay",
            "terminalWorkerPath": "/private/tmp/private/cloud-artifacts/rust-target/debug/lomiremote",
            "terminalWorkerSha256": "a".repeat(64)
        });
        assert!(serde_json::from_value::<ManagedContext>(legacy.clone()).is_ok());
        assert!(serde_json::from_value::<JoinedManagedContext>(joined.clone()).is_ok());
        assert!(serde_json::from_value::<ManagedContext>(joined).is_err());
        assert!(serde_json::from_value::<JoinedManagedContext>(legacy).is_err());
    }
}
