//! Windows handoff for updating or removing the loaded CLI.
//!
//! The caller copies its already-running, Authenticode-pinned CLI into an
//! owner-private profile directory. The child receives one inherited handle:
//! a real handle to the parent process. The worker does not rediscover a PID,
//! and it waits for that exact parent to exit before changing active images.

use super::service_admin::{MaintenanceStorage, RegisteredBootHost};
use super::*;
use lomi_remote_protocol::{HostId, LocalIpcVersion, OperationId, ipc::IpcProfileId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    mem,
    os::windows::{
        ffi::OsStringExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Path, PathBuf},
    ptr, thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{Foundation::*, Storage::FileSystem::*, System::Threading::*};

type Result<T, E = Error> = std::result::Result<T, E>;

const JOB_SCHEMA: u8 = 1;
const MAX_JOB_BYTES: usize = 64 * 1024;
const MAX_IMAGE_BYTES: u64 = 256 * 1024 * 1024;
const ACK_TIMEOUT: Duration = Duration::from_secs(10);
const PARENT_EXIT_TIMEOUT: Duration = Duration::from_secs(30);
const ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
const JOBS_DIR: &str = "maintenance-jobs";
const WORKERS_DIR: &str = "maintenance-workers";
const ADMIN_JOB_SUFFIX: &str = ".json";
const ADMIN_LOCK_SUFFIX: &str = ".lock";
const ADMIN_WORKER_SUFFIX: &str = ".exe";
const EMPTY_MAINTENANCE_DIR: &str = ".lomi-maintenance-v1";
const EMPTY_JOB_PREFIX: &str = "job-";
const EMPTY_WORKER_NAME: &str = "worker.exe";
const EMPTY_JOB_FILE: &str = "job.json";
const EMPTY_LOCK_FILE: &str = "job.lock";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerOutcome {
    NotRequired,
    Pending,
    Complete,
    RevocationPending,
    CleanupUncertain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerPhase {
    FenceAndStop,
    PurgeAfterRecovery,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Identity,
    Permission,
    Io,
    Deadline,
    Uncertain,
    Busy,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "MAINTENANCE_JOB_INVALID",
            Self::Identity => "MAINTENANCE_IDENTITY_MISMATCH",
            Self::Permission => "MAINTENANCE_PERMISSION_DENIED",
            Self::Io => "MAINTENANCE_IO_ERROR",
            Self::Deadline => "MAINTENANCE_HANDOFF_TIMEOUT",
            Self::Uncertain => "MAINTENANCE_OUTCOME_UNCERTAIN",
            Self::Busy => "MAINTENANCE_JOB_BUSY",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Prepared,
    Accepted,
    Running,
    Completed,
    RevocationPending,
    Failed,
    Uncertain,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobAcceptance {
    pub job_id: String,
    pub state: JobState,
    /// Exact verified copied image used to query a Boot job after uninstall
    /// removes the stable installation image.
    pub status_executable: Option<PathBuf>,
    /// Profile selector required when the copied Boot worker is invoked for
    /// its durable status command.
    pub status_profile: Option<PathBuf>,
}

impl JobAcceptance {
    fn local(job_id: String, state: JobState) -> Self {
        Self {
            job_id,
            state,
            status_executable: None,
            status_profile: None,
        }
    }

    fn boot(
        job_id: String,
        state: JobState,
        status_executable: &Path,
        status_profile: &Path,
    ) -> Self {
        Self {
            job_id,
            state,
            status_executable: Some(status_executable.to_path_buf()),
            status_profile: Some(status_profile.to_path_buf()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePins {
    pub origin: String,
    pub primary_target: String,
    pub helper_target: Option<String>,
    pub platform: String,
    pub signer_thumbprint: String,
    pub root_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    /// `None` installs the latest release selected by the pinned target's
    /// verified TUF metadata; `Some` additionally pins an exact version.
    Update {
        expected_version: Option<String>,
    },
    Uninstall {
        purge: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JobRecord {
    schema: u8,
    job_id: String,
    state: JobState,
    profile: String,
    install: String,
    active_executable: String,
    active_executable_sha256: String,
    #[serde(default)]
    parent_executable_sha256: Option<String>,
    worker_executable: String,
    worker_executable_sha256: String,
    host_id: String,
    profile_id: String,
    account_sid: String,
    #[serde(default)]
    operator_sid: Option<String>,
    #[serde(default)]
    owner_account: Option<String>,
    mode: String,
    was_running: bool,
    active_terminals: u64,
    inherited_parent_handle: usize,
    release: ReleasePins,
    action: Action,
    #[serde(default)]
    owner_outcome: Option<OwnerOutcome>,
    #[serde(default)]
    owner_operation_id: Option<String>,
    #[serde(default)]
    owner_phase: Option<OwnerPhase>,
    outcome_code: Option<String>,
}

/// Fresh installs have no Host UUIDs yet. Keep this identity in a separate
/// closed record shape so an absent database can never be confused with an
/// initialized Host record containing optional IDs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EmptyReservationRecord {
    schema: u8,
    job_id: String,
    state: JobState,
    profile: String,
    profile_volume: u64,
    profile_file: u64,
    install: String,
    install_volume: u64,
    install_file: u64,
    active_executable: String,
    active_executable_sha256: String,
    worker_executable: String,
    worker_executable_sha256: String,
    account_sid: String,
    inherited_parent_handle: usize,
    release: ReleasePins,
    outcome_code: Option<String>,
}

/// Worker claim for an uninitialized reservation. The exact native proof is
/// reacquired after the parent exits and held through activation removal.
pub struct EmptyReservationWorkerJob {
    record: EmptyReservationRecord,
    job_dir: PathBuf,
    proof: Option<crate::empty_profile::EmptyHostProfile>,
    install_directory: Option<PrivateProfile>,
}

impl EmptyReservationWorkerJob {
    pub fn profile(&self) -> &Path {
        Path::new(&self.record.profile)
    }
    pub fn install(&self) -> &Path {
        Path::new(&self.record.install)
    }
    pub fn active_executable(&self) -> &Path {
        Path::new(&self.record.active_executable)
    }
    pub fn proof(&self) -> Result<&crate::empty_profile::EmptyHostProfile, Error> {
        self.proof.as_ref().ok_or(Error::Invalid)
    }
    pub fn release(&self) -> &ReleasePins {
        &self.record.release
    }
    pub fn check_install_current(&self) -> Result<(), Error> {
        let install = self.install_directory.as_ref().ok_or(Error::Invalid)?;
        install.check_current().map_err(map_error)?;
        if private_identity(install) != (self.record.install_volume, self.record.install_file) {
            return Err(Error::Identity);
        }
        Ok(())
    }
}

pub struct WorkerJob {
    record: JobRecord,
    profile: PathBuf,
    admin_storage: Option<MaintenanceStorage>,
}

impl WorkerJob {
    pub fn job_id(&self) -> &str {
        &self.record.job_id
    }
    pub fn profile(&self) -> &Path {
        &self.profile
    }
    pub fn install(&self) -> &Path {
        Path::new(&self.record.install)
    }
    pub fn active_executable(&self) -> &Path {
        Path::new(&self.record.active_executable)
    }
    pub fn worker_executable(&self) -> &Path {
        Path::new(&self.record.worker_executable)
    }
    pub fn host_id(&self) -> Result<HostId, Error> {
        HostId::try_from(self.record.host_id.clone()).map_err(|_| Error::Invalid)
    }
    pub fn profile_id(&self) -> Result<IpcProfileId, Error> {
        IpcProfileId::try_from(self.record.profile_id.clone()).map_err(|_| Error::Invalid)
    }
    pub fn mode(&self) -> Result<crate::service_observation::ServiceMode, Error> {
        match self.record.mode.as_str() {
            "manual" => Ok(crate::service_observation::ServiceMode::Manual),
            "login" => Ok(crate::service_observation::ServiceMode::Login),
            "boot" => Ok(crate::service_observation::ServiceMode::Boot),
            _ => Err(Error::Invalid),
        }
    }
    pub fn was_running(&self) -> bool {
        self.record.was_running
    }
    pub fn active_terminals(&self) -> u64 {
        self.record.active_terminals
    }
    pub fn release(&self) -> &ReleasePins {
        &self.record.release
    }
    pub fn action(&self) -> &Action {
        &self.record.action
    }
    pub fn account_sid(&self) -> &str {
        &self.record.account_sid
    }
    pub fn operator_sid(&self) -> &str {
        self.record
            .operator_sid
            .as_deref()
            .unwrap_or(&self.record.account_sid)
    }
    pub fn owner_account(&self) -> Option<&str> {
        self.record.owner_account.as_deref()
    }
    pub fn owner_outcome(&self) -> Option<OwnerOutcome> {
        self.record.owner_outcome
    }
    pub fn owner_phase(&self) -> Option<OwnerPhase> {
        self.record.owner_phase
    }
    /// Rebind this sealed Boot job to the protected registration it names.
    /// The operator SID is checked from the live process token; no SID is
    /// accepted from a caller.
    pub fn verified_boot_binding(&self) -> Result<RegisteredBootHost, Error> {
        if self.admin_storage.is_none() || self.record.mode != "boot" {
            return Err(Error::Invalid);
        }
        let (operator_sid, _) =
            super::service_admin::current_account().map_err(|_| Error::Identity)?;
        if self.record.operator_sid.as_deref() != Some(operator_sid.as_str()) {
            return Err(Error::Identity);
        }
        let binding = super::service_admin::registered_boot_host_for_sid(
            &self.record.account_sid,
            Path::new(&self.record.active_executable),
        )
        .map_err(|_| Error::Identity)?;
        if !record_matches_boot_binding(&self.record, &binding)
            || binding.signer_thumbprint() != self.record.release.signer_thumbprint
        {
            return Err(Error::Identity);
        }
        Ok(binding)
    }

    /// After copied-image recovery, refresh the durable active-image hash
    /// against the same sealed Boot registration and return that binding.
    pub fn refresh_boot_binding_after_recovery(
        &mut self,
        release: &ReleasePins,
    ) -> Result<RegisteredBootHost, Error> {
        if self.admin_storage.is_none() || self.record.release != *release {
            return Err(Error::Identity);
        }
        let binding = self.verified_boot_binding()?;
        refresh_boot_job_after_recovery(&binding, &self.record.job_id, release)?;
        let storage = self.admin_storage.as_ref().ok_or(Error::Invalid)?;
        self.record =
            read_admin_record(storage, &self.record.job_id, true)?.ok_or(Error::Uncertain)?;
        Ok(binding)
    }
    pub fn expected_version(&self) -> Option<&str> {
        match &self.record.action {
            Action::Update { expected_version } => expected_version.as_deref(),
            Action::Uninstall { .. } => None,
        }
    }
    pub fn purge(&self) -> Option<bool> {
        match &self.record.action {
            Action::Update { .. } => None,
            Action::Uninstall { purge } => Some(*purge),
        }
    }
}

/// Closed owner-context request read from the admin-created, owner-readable
/// maintenance capsule. It contains no caller-selected paths or account IDs.
pub struct OwnerContinuationRequest {
    profile: PathBuf,
    identity: (HostId, IpcProfileId),
    action: Action,
    operation_id: OperationId,
    phase: OwnerPhase,
    account: String,
    binding: crate::service_observation::ServiceBinding,
    _storage: MaintenanceStorage,
}

impl OwnerContinuationRequest {
    pub fn profile(&self) -> &Path {
        &self.profile
    }
    pub fn identity(&self) -> (HostId, IpcProfileId) {
        self.identity
    }
    pub fn operation_id(&self) -> OperationId {
        self.operation_id
    }
    pub fn phase(&self) -> OwnerPhase {
        self.phase
    }
    pub fn purge(&self) -> bool {
        matches!(self.action, Action::Uninstall { purge: true })
    }
    pub fn binding(&self) -> &crate::service_observation::ServiceBinding {
        &self.binding
    }
    pub fn account(&self) -> &str {
        &self.account
    }
}

/// Copy the current signed image and launch it with a closed durable request.
/// The child returns an accepted or uncertain job state; it never reports that
/// installation has completed merely because CreateProcess succeeded.
pub fn begin(
    profile: &Path,
    install: &Path,
    executable: &Path,
    host_id: HostId,
    profile_id: IpcProfileId,
    mode: crate::service_observation::ServiceMode,
    was_running: bool,
    active_terminals: u64,
    release: ReleasePins,
    action: Action,
) -> Result<JobAcceptance, Error> {
    validate_release(&release)?;
    validate_action(&action)?;
    let profile = normalized(profile)?;
    let install = normalized(install)?;
    let executable = normalized(executable)?;
    if executable.parent() != Some(install.as_path()) || !install.is_dir() {
        return Err(Error::Identity);
    }
    let private = PrivateProfile::open(&profile, false).map_err(map_error)?;
    private.check_current().map_err(map_error)?;
    let sid = private.sid.clone();

    let active = open_image(&executable)?;
    let active_sha256 = hash_file(active.try_clone().map_err(map_io)?)?;
    verify_signer(&executable, &release.signer_thumbprint)?;

    let job_id = uuid::Uuid::new_v4().to_string();
    let jobs = profile.join(JOBS_DIR);
    let workers = profile.join(WORKERS_DIR);
    PrivateProfile::open(&jobs, true).map_err(map_error)?;
    PrivateProfile::open(&workers, true).map_err(map_error)?;
    let worker = workers.join(format!("{job_id}.exe"));
    let mut parent_handle: HANDLE = ptr::null_mut();
    unsafe {
        if DuplicateHandle(
            GetCurrentProcess(),
            GetCurrentProcess(),
            GetCurrentProcess(),
            &mut parent_handle,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        ) == 0
        {
            return Err(map_io(std::io::Error::last_os_error()));
        }
    }
    let parent_guard = Handle::new(parent_handle).map_err(map_io)?;
    let worker_sha256 =
        copy_private_worker(&executable, &worker, &sid, &release.signer_thumbprint)?;
    let record = JobRecord {
        schema: JOB_SCHEMA,
        job_id: job_id.clone(),
        state: JobState::Prepared,
        profile: text_path(&profile)?,
        install: text_path(&install)?,
        active_executable: text_path(&executable)?,
        active_executable_sha256: active_sha256,
        parent_executable_sha256: None,
        worker_executable: text_path(&worker)?,
        worker_executable_sha256: worker_sha256,
        host_id: host_id.into(),
        profile_id: profile_id.into(),
        account_sid: sid.clone(),
        operator_sid: None,
        owner_account: None,
        mode: mode.as_str().to_owned(),
        was_running,
        active_terminals,
        inherited_parent_handle: parent_guard.0 as usize,
        release,
        action,
        owner_outcome: None,
        owner_operation_id: None,
        owner_phase: None,
        outcome_code: None,
    };
    let path = job_path(&profile, &job_id)?;
    write_new_record(&path, &record, &sid)?;
    create_private_new(&job_lock_path(&profile, &job_id)?, &sid)?;
    if let Err(error) = launch_worker(
        &worker,
        &[
            std::ffi::OsString::from(&job_id),
            profile.as_os_str().to_os_string(),
        ],
        parent_guard.0,
        &profile,
    ) {
        if let Ok(_lock) = lock_job(&profile, &job_id, &sid, Instant::now() + ACK_TIMEOUT) {
            if let Some(mut record) = read_record(&profile, &job_id)? {
                record.state = JobState::Failed;
                record.outcome_code = Some("WORKER_START_FAILED".to_owned());
                write_record(&path, &record, &sid)?;
            }
        }
        return Err(error);
    }
    drop(parent_guard);
    drop(active);

    let deadline = Instant::now() + ACK_TIMEOUT;
    loop {
        match read_record(&profile, &job_id)? {
            Some(record) if record.state == JobState::Accepted => {
                return Ok(JobAcceptance::local(job_id, JobState::Accepted));
            }
            Some(record) if matches!(record.state, JobState::Failed | JobState::Uncertain) => {
                return Ok(JobAcceptance::local(job_id, record.state));
            }
            _ => {}
        }
        if Instant::now() >= deadline {
            let lock = lock_job(
                &profile,
                &job_id,
                &sid,
                Instant::now() + Duration::from_millis(250),
            );
            let Some(mut record) = read_record(&profile, &job_id)? else {
                return Err(Error::Uncertain);
            };
            if record.state == JobState::Prepared {
                if lock.is_ok() {
                    record.state = JobState::Uncertain;
                    record.outcome_code = Some("WORKER_ACCEPTANCE_UNCERTAIN".to_owned());
                    write_record(&path, &record, &sid)?;
                } else {
                    return Ok(JobAcceptance::local(job_id, JobState::Uncertain));
                }
            }
            return Ok(JobAcceptance::local(job_id, record.state));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Launch removal for a positively proven empty reservation. The job is
/// stored under the exact private install root, outside activation objects,
/// and binds both native directory objects plus the current account SID.
pub fn begin_empty_uninstall(
    proof: &crate::empty_profile::EmptyHostProfile,
    install: &Path,
    executable: &Path,
    release: ReleasePins,
) -> Result<JobAcceptance, Error> {
    validate_release(&release)?;
    let install = normalized(install)?;
    let executable = normalized(executable)?;
    let profile = normalized(proof.profile_path())?;
    if executable.parent() != Some(install.as_path()) || !install.is_dir() {
        return Err(Error::Identity);
    }
    proof.recheck().map_err(|_| Error::Identity)?;
    let profile_identity = proof.profile_identity();
    let install_private = PrivateProfile::open(&install, false).map_err(map_error)?;
    install_private.check_current().map_err(map_error)?;
    let install_identity = private_identity(&install_private);
    let sid = install_private.sid.clone();
    if current_sid().map_err(map_error)? != sid {
        return Err(Error::Identity);
    }

    let active = open_image(&executable)?;
    let active_sha256 = hash_file(active.try_clone().map_err(map_io)?)?;
    verify_signer(&executable, &release.signer_thumbprint)?;

    let job_id = Uuid::new_v4().to_string();
    let maintenance = install.join(EMPTY_MAINTENANCE_DIR);
    let maintenance_private = PrivateProfile::open(&maintenance, true).map_err(map_error)?;
    maintenance_private.check_current().map_err(map_error)?;
    let job_dir = maintenance.join(format!("{EMPTY_JOB_PREFIX}{job_id}"));
    let job_private = create_empty_job_directory(&job_dir, &sid)?;
    job_private.check_current().map_err(map_error)?;
    let worker = job_dir.join(EMPTY_WORKER_NAME);
    let worker_sha256 =
        copy_private_worker(&executable, &worker, &sid, &release.signer_thumbprint)?;
    let mut parent_handle: HANDLE = ptr::null_mut();
    unsafe {
        if DuplicateHandle(
            GetCurrentProcess(),
            GetCurrentProcess(),
            GetCurrentProcess(),
            &mut parent_handle,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        ) == 0
        {
            let _ = std::fs::remove_file(&worker);
            return Err(map_io(std::io::Error::last_os_error()));
        }
    }
    let parent_guard = Handle::new(parent_handle).map_err(map_io)?;
    let record = EmptyReservationRecord {
        schema: 1,
        job_id: job_id.clone(),
        state: JobState::Prepared,
        profile: text_path(&profile)?,
        profile_volume: profile_identity.0,
        profile_file: profile_identity.1,
        install: text_path(&install)?,
        install_volume: install_identity.0,
        install_file: install_identity.1,
        active_executable: text_path(&executable)?,
        active_executable_sha256: active_sha256,
        worker_executable: text_path(&worker)?,
        worker_executable_sha256: worker_sha256,
        account_sid: sid.clone(),
        inherited_parent_handle: parent_guard.0 as usize,
        release,
        outcome_code: None,
    };
    validate_empty_record(&job_dir, &job_id, &record)?;
    write_empty_new(&job_dir, &record, &sid)?;
    create_private_new(&job_dir.join(EMPTY_LOCK_FILE), &sid)?;
    if launch_worker_entrypoint(
        &worker,
        "--internal-maintenance-empty-worker-v1",
        &[std::ffi::OsString::from(&job_id)],
        parent_guard.0,
        &job_dir,
    )
    .is_err()
    {
        if let Ok(_lock) = lock_empty_job(&job_dir, &sid, Instant::now() + ACK_TIMEOUT) {
            if let Some(mut current) = read_empty_record(&job_dir, &job_id)? {
                current.state = JobState::Failed;
                current.outcome_code = Some("WORKER_START_FAILED".to_owned());
                write_empty_record(&job_dir, &current, &sid)?;
                return Ok(JobAcceptance::local(job_id, JobState::Failed));
            }
        }
        return Err(Error::Uncertain);
    }
    drop(parent_guard);
    drop(active);

    let deadline = Instant::now() + ACK_TIMEOUT;
    loop {
        if let Some(record) = read_empty_record(&job_dir, &job_id)? {
            if record.state == JobState::Accepted
                || matches!(record.state, JobState::Failed | JobState::Uncertain)
            {
                return Ok(JobAcceptance::local(job_id, record.state));
            }
        }
        if Instant::now() >= deadline {
            if let Ok(_lock) =
                lock_empty_job(&job_dir, &sid, Instant::now() + Duration::from_millis(250))
                && let Some(mut record) = read_empty_record(&job_dir, &job_id)?
                && record.state == JobState::Prepared
            {
                record.state = JobState::Uncertain;
                record.outcome_code = Some("WORKER_ACCEPTANCE_UNCERTAIN".to_owned());
                write_empty_record(&job_dir, &record, &sid)?;
            }
            return Ok(JobAcceptance::local(job_id, JobState::Uncertain));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Start a protected Boot Host maintenance job. The job and copied worker live
/// under the SID-bound ProgramData maintenance area. For uninstall, the caller
/// must finish the owner-context fence and Host stop before this function
/// launches the elevated same-operator worker. Optional purge is deferred
/// until the copied worker has waited for this image to exit and recovered
/// any interrupted activation.
pub fn begin_boot(
    binding: &RegisteredBootHost,
    release: ReleasePins,
    action: Action,
    owner_continuation: Option<Box<dyn FnOnce(&str) -> Result<OwnerOutcome, Error>>>,
) -> Result<JobAcceptance, Error> {
    validate_release(&release)?;
    validate_action(&action)?;
    if release.signer_thumbprint != binding.signer_thumbprint() {
        return Err(Error::Identity);
    }
    let fresh = super::service_admin::registered_boot_host_for_sid(
        binding.account_sid(),
        binding.executable(),
    )
    .map_err(|_| Error::Identity)?;
    if &fresh != binding {
        return Err(Error::Identity);
    }
    let (operator_sid, _) = super::service_admin::current_account().map_err(|_| Error::Identity)?;
    let storage = super::service_admin::maintenance_storage_for_admin(binding.account_sid())
        .map_err(|_| Error::Identity)?;

    let needs_owner = matches!(action, Action::Uninstall { .. });
    if needs_owner != owner_continuation.is_some() {
        return Err(Error::Invalid);
    }
    let executable = normalized(binding.executable())?;
    if executable.parent() != Some(binding.install()) {
        return Err(Error::Identity);
    }
    let active = open_image(&executable)?;
    let active_sha256 = hash_file(active.try_clone().map_err(map_io)?)?;
    verify_signer(&executable, &release.signer_thumbprint)?;

    let job_id = uuid::Uuid::new_v4().to_string();
    let worker = admin_worker_path(&storage, &job_id)?;
    let worker_sha256 = copy_admin_worker(
        &executable,
        &worker,
        binding.account_sid(),
        &release.signer_thumbprint,
    )?;
    let mut parent_handle: HANDLE = ptr::null_mut();
    unsafe {
        if DuplicateHandle(
            GetCurrentProcess(),
            GetCurrentProcess(),
            GetCurrentProcess(),
            &mut parent_handle,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        ) == 0
        {
            let _ = std::fs::remove_file(&worker);
            return Err(map_io(std::io::Error::last_os_error()));
        }
    }
    let parent_guard = Handle::new(parent_handle).map_err(map_io)?;
    let identity = binding.identity();
    let mut record = JobRecord {
        schema: 2,
        job_id: job_id.clone(),
        state: JobState::Prepared,
        profile: text_path(binding.profile())?,
        install: text_path(binding.install())?,
        active_executable: text_path(&executable)?,
        active_executable_sha256: active_sha256,
        parent_executable_sha256: Some(worker_sha256.clone()),
        worker_executable: text_path(&worker)?,
        worker_executable_sha256: worker_sha256,
        host_id: identity.host_id.into(),
        profile_id: identity.profile_id.into(),
        account_sid: binding.account_sid().to_owned(),
        operator_sid: Some(operator_sid),
        owner_account: Some(binding.account().to_owned()),
        mode: "boot".to_owned(),
        was_running: binding.running(),
        active_terminals: 0,
        inherited_parent_handle: parent_guard.0 as usize,
        release,
        action,
        owner_outcome: Some(if needs_owner {
            OwnerOutcome::Pending
        } else {
            OwnerOutcome::NotRequired
        }),
        owner_operation_id: needs_owner.then(|| Uuid::new_v4().to_string()),
        owner_phase: needs_owner.then_some(OwnerPhase::FenceAndStop),
        outcome_code: None,
    };
    create_admin_lock_file(&storage, &job_id)?;
    write_admin_record(&storage, &record)?;
    // Recovery can atomically replace the active image. Keep the verified
    // ProgramData copy as the immutable proof for this parent's image.
    drop(active);

    if let Some(continuation) = owner_continuation {
        let outcome = match continuation(&job_id) {
            Ok(outcome)
                if matches!(
                    outcome,
                    OwnerOutcome::Complete
                        | OwnerOutcome::RevocationPending
                        | OwnerOutcome::CleanupUncertain
                ) =>
            {
                outcome
            }
            _ => {
                record.state = JobState::Uncertain;
                record.outcome_code = Some("OWNER_CONTINUATION_UNCERTAIN".to_owned());
                write_admin_record(&storage, &record)?;
                return Ok(JobAcceptance::boot(
                    job_id,
                    JobState::Uncertain,
                    &worker,
                    binding.profile(),
                ));
            }
        };
        let latest = read_admin_record(&storage, &job_id, true)?.ok_or(Error::Uncertain)?;
        let expected = match (&record.action, outcome) {
            (Action::Uninstall { purge: true }, OwnerOutcome::Complete) => {
                (OwnerPhase::PurgeAfterRecovery, OwnerOutcome::Pending)
            }
            (_, owner_outcome) => (OwnerPhase::Complete, owner_outcome),
        };
        if latest.owner_phase != Some(expected.0) || latest.owner_outcome != Some(expected.1) {
            record.state = JobState::Uncertain;
            record.outcome_code = Some("OWNER_FENCE_PHASE_NOT_COMPLETED".to_owned());
            write_admin_record(&storage, &record)?;
            return Ok(JobAcceptance::boot(
                job_id,
                JobState::Uncertain,
                &worker,
                binding.profile(),
            ));
        }
        record = latest;
        if outcome == OwnerOutcome::CleanupUncertain {
            record.state = JobState::Uncertain;
            record.outcome_code = Some("OWNER_CLEANUP_UNCERTAIN".to_owned());
            write_admin_record(&storage, &record)?;
            return Ok(JobAcceptance::boot(
                job_id,
                JobState::Uncertain,
                &worker,
                binding.profile(),
            ));
        }
    }

    if let Err(error) = launch_worker(
        &worker,
        &[std::ffi::OsString::from(&job_id)],
        parent_guard.0,
        &storage.path,
    ) {
        record.state = JobState::Failed;
        record.outcome_code = Some("WORKER_START_FAILED".to_owned());
        write_admin_record(&storage, &record)?;
        return Err(error);
    }
    drop(parent_guard);
    let deadline = Instant::now() + ACK_TIMEOUT;
    loop {
        let latest = read_admin_record(&storage, &job_id, true)?.ok_or(Error::Uncertain)?;
        if matches!(
            latest.state,
            JobState::Accepted | JobState::Failed | JobState::Uncertain
        ) {
            return Ok(JobAcceptance::boot(
                job_id,
                latest.state,
                &worker,
                binding.profile(),
            ));
        }
        if Instant::now() >= deadline {
            if latest.state == JobState::Prepared {
                let _lock = match lock_admin_job(
                    &storage,
                    &job_id,
                    Instant::now() + Duration::from_millis(250),
                ) {
                    Ok(lock) => lock,
                    Err(_) => {
                        return Ok(JobAcceptance::boot(
                            job_id,
                            JobState::Uncertain,
                            &worker,
                            binding.profile(),
                        ));
                    }
                };
                let mut uncertain =
                    read_admin_record(&storage, &job_id, true)?.ok_or(Error::Uncertain)?;
                if uncertain.state == JobState::Prepared {
                    uncertain.state = JobState::Uncertain;
                    uncertain.outcome_code = Some("WORKER_ACCEPTANCE_UNCERTAIN".to_owned());
                    write_admin_record(&storage, &uncertain)?;
                }
                return Ok(JobAcceptance::boot(
                    job_id,
                    JobState::Uncertain,
                    &worker,
                    binding.profile(),
                ));
            }
            return Ok(JobAcceptance::boot(
                job_id,
                latest.state,
                &worker,
                binding.profile(),
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

pub fn image_sha256(path: &Path) -> Result<String, Error> {
    hash_path(path)
}

/// Validate the worker's private capsule and loaded signed image before any
// operation is started. `profile` is a locator and must match the capsule.
pub fn claim_worker(profile: &Path, job_id: &str) -> Result<WorkerJob, Error> {
    validate_job_id(job_id)?;
    let profile = normalized(profile)?;
    let private = PrivateProfile::open(&profile, false).map_err(map_error)?;
    let _lock = lock_job(&profile, job_id, &private.sid, Instant::now() + ACK_TIMEOUT)?;
    let mut record = read_record(&profile, job_id)?.ok_or(Error::Invalid)?;
    validate_record(&profile, job_id, &record)?;
    if record.state != JobState::Prepared {
        return Err(Error::Invalid);
    }
    let current = normalized(&std::env::current_exe().map_err(map_io)?)?;
    if current != Path::new(&record.worker_executable) {
        return Err(Error::Identity);
    }
    if hash_path(&current)? != record.worker_executable_sha256 {
        return Err(Error::Identity);
    }
    verify_signer(&current, &record.release.signer_thumbprint)?;
    let parent = record.inherited_parent_handle as HANDLE;
    if parent.is_null() || unsafe { GetProcessId(parent) } == 0 {
        return Err(Error::Identity);
    }
    if unsafe { WaitForSingleObject(parent, 0) } != WAIT_TIMEOUT {
        record.state = JobState::Uncertain;
        record.outcome_code = Some("PARENT_EXITED_BEFORE_ACCEPTANCE".to_owned());
        write_record(&job_path(&profile, job_id)?, &record, &record.account_sid)?;
        return Err(Error::Invalid);
    }
    verify_parent_image(parent, &record)?;
    record.state = JobState::Accepted;
    record.outcome_code = None;
    write_record(&job_path(&profile, job_id)?, &record, &record.account_sid)?;
    Ok(WorkerJob {
        record,
        profile,
        admin_storage: None,
    })
}

/// Claim the worker copied into an empty reservation's validated install
/// root. The owner lock is not acquired until the parent exits.
pub fn claim_empty_worker(job_id: &str) -> Result<EmptyReservationWorkerJob, Error> {
    validate_job_id(job_id)?;
    let current = normalized(&std::env::current_exe().map_err(map_io)?)?;
    let job_dir = current.parent().ok_or(Error::Identity)?.to_path_buf();
    let expected_dir = job_dir
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or(Error::Identity)?;
    if expected_dir != format!("{EMPTY_JOB_PREFIX}{job_id}")
        || current.file_name() != Some(std::ffi::OsStr::new(EMPTY_WORKER_NAME))
    {
        return Err(Error::Identity);
    }
    let job_private = PrivateProfile::open(&job_dir, false).map_err(map_error)?;
    let _lock = lock_empty_job(&job_dir, &job_private.sid, Instant::now() + ACK_TIMEOUT)?;
    check_empty_job_contents(&job_dir, &job_private.sid)?;
    let mut record = read_empty_record(&job_dir, job_id)?.ok_or(Error::Invalid)?;
    validate_empty_record(&job_dir, job_id, &record)?;
    if record.state != JobState::Prepared {
        return Err(Error::Invalid);
    }
    if current_sid().map_err(map_error)? != record.account_sid
        || current != Path::new(&record.worker_executable)
        || hash_path(&current)? != record.worker_executable_sha256
    {
        return Err(Error::Identity);
    }
    verify_signer(&current, &record.release.signer_thumbprint)?;
    let profile = normalized(Path::new(&record.profile))?;
    let profile_private = PrivateProfile::open(&profile, false).map_err(map_error)?;
    if private_identity(&profile_private) != (record.profile_volume, record.profile_file)
        || profile_private.sid != record.account_sid
    {
        return Err(Error::Identity);
    }
    let parent = record.inherited_parent_handle as HANDLE;
    if parent.is_null() || unsafe { GetProcessId(parent) } == 0 {
        return Err(Error::Identity);
    }
    if unsafe { WaitForSingleObject(parent, 0) } != WAIT_TIMEOUT {
        record.state = JobState::Uncertain;
        record.outcome_code = Some("PARENT_EXITED_BEFORE_ACCEPTANCE".to_owned());
        write_empty_record(&job_dir, &record, &record.account_sid)?;
        return Err(Error::Invalid);
    }
    verify_empty_parent(parent, &record)?;
    record.state = JobState::Accepted;
    record.outcome_code = None;
    write_empty_record(&job_dir, &record, &record.account_sid)?;
    Ok(EmptyReservationWorkerJob {
        record,
        job_dir,
        proof: None,
        install_directory: None,
    })
}

/// Wait for the exact parent HANDLE, reacquire the empty reservation proof,
/// compare the recorded profile object, and persist Running before removal.
pub fn mark_empty_worker_running(job: &mut EmptyReservationWorkerJob) -> Result<(), Error> {
    if job.record.state != JobState::Accepted {
        return Err(Error::Invalid);
    }
    let parent = job.record.inherited_parent_handle as HANDLE;
    if parent.is_null() || unsafe { GetProcessId(parent) } == 0 {
        return Err(Error::Identity);
    }
    let wait = unsafe {
        WaitForSingleObject(
            parent,
            u32::try_from(PARENT_EXIT_TIMEOUT.as_millis()).map_err(|_| Error::Invalid)?,
        )
    };
    if wait == WAIT_TIMEOUT {
        mark_empty_uncertain(job, "PARENT_EXIT_TIMEOUT")?;
        return Err(Error::Deadline);
    }
    if wait != WAIT_OBJECT_0 {
        mark_empty_uncertain(job, "PARENT_HANDLE_UNCERTAIN")?;
        return Err(Error::Uncertain);
    }

    let _lock = lock_empty_job(
        &job.job_dir,
        &job.record.account_sid,
        Instant::now() + ACK_TIMEOUT,
    )?;
    check_empty_job_contents(&job.job_dir, &job.record.account_sid)?;
    let mut current = read_empty_record(&job.job_dir, &job.record.job_id)?.ok_or(Error::Invalid)?;
    if current.state != JobState::Accepted {
        return Err(Error::Uncertain);
    }
    if verify_empty_parent(parent, &current).is_err() {
        set_empty_uncertain(&job.job_dir, &mut current, "PARENT_IMAGE_CHANGED")?;
        job.record = current;
        return Err(Error::Identity);
    }

    let proof = match crate::empty_profile::EmptyHostProfile::acquire(Path::new(&current.profile)) {
        Ok(proof) => proof,
        Err(_) => {
            current.state = JobState::Uncertain;
            current.outcome_code = Some("EMPTY_RESERVATION_CHANGED".to_owned());
            write_empty_record(&job.job_dir, &current, &current.account_sid)?;
            job.record = current;
            return Err(Error::Uncertain);
        }
    };
    if proof.profile_identity() != (current.profile_volume, current.profile_file) {
        current.state = JobState::Uncertain;
        current.outcome_code = Some("PROFILE_OBJECT_CHANGED".to_owned());
        write_empty_record(&job.job_dir, &current, &current.account_sid)?;
        job.record = current;
        return Err(Error::Identity);
    }
    if proof.recheck().is_err() {
        set_empty_uncertain(&job.job_dir, &mut current, "EMPTY_RESERVATION_CHANGED")?;
        job.record = current;
        return Err(Error::Uncertain);
    }
    let install = match PrivateProfile::open(Path::new(&current.install), false) {
        Ok(install) => install,
        Err(_) => {
            set_empty_uncertain(&job.job_dir, &mut current, "INSTALL_UNAVAILABLE")?;
            job.record = current;
            return Err(Error::Identity);
        }
    };
    if private_identity(&install) != (current.install_volume, current.install_file)
        || install.sid != current.account_sid
    {
        current.state = JobState::Uncertain;
        current.outcome_code = Some("INSTALL_OBJECT_CHANGED".to_owned());
        write_empty_record(&job.job_dir, &current, &current.account_sid)?;
        job.record = current;
        return Err(Error::Identity);
    }
    if install.check_current().is_err() {
        set_empty_uncertain(&job.job_dir, &mut current, "INSTALL_OBJECT_CHANGED")?;
        job.record = current;
        return Err(Error::Identity);
    }
    current.state = JobState::Running;
    current.outcome_code = None;
    write_empty_record(&job.job_dir, &current, &current.account_sid)?;
    job.record = current;
    job.proof = Some(proof);
    job.install_directory = Some(install);
    Ok(())
}

pub fn finish_empty_worker(
    job: &mut EmptyReservationWorkerJob,
    state: JobState,
    code: &'static str,
) -> Result<(), Error> {
    if job.record.state != JobState::Running
        || !matches!(
            state,
            JobState::Completed | JobState::Uncertain | JobState::Failed
        )
    {
        return Err(Error::Invalid);
    }
    if job.proof.is_none() || job.install_directory.is_none() {
        return Err(Error::Invalid);
    }
    let _lock = lock_empty_job(
        &job.job_dir,
        &job.record.account_sid,
        Instant::now() + ACK_TIMEOUT,
    )?;
    let mut record = read_empty_record(&job.job_dir, &job.record.job_id)?.ok_or(Error::Invalid)?;
    if record.state != JobState::Running {
        return Err(Error::Uncertain);
    }
    record.state = state;
    record.outcome_code = (state != JobState::Completed).then(|| code.to_owned());
    write_empty_record(&job.job_dir, &record, &record.account_sid)?;
    job.record = record;
    Ok(())
}

fn mark_empty_uncertain(
    job: &mut EmptyReservationWorkerJob,
    code: &'static str,
) -> Result<(), Error> {
    let _lock = lock_empty_job(
        &job.job_dir,
        &job.record.account_sid,
        Instant::now() + ACK_TIMEOUT,
    )?;
    let mut record = read_empty_record(&job.job_dir, &job.record.job_id)?.ok_or(Error::Invalid)?;
    if record.state != JobState::Accepted {
        return Err(Error::Uncertain);
    }
    record.state = JobState::Uncertain;
    record.outcome_code = Some(code.to_owned());
    write_empty_record(&job.job_dir, &record, &record.account_sid)?;
    job.record = record;
    Ok(())
}

fn set_empty_uncertain(
    job_dir: &Path,
    record: &mut EmptyReservationRecord,
    code: &'static str,
) -> Result<(), Error> {
    record.state = JobState::Uncertain;
    record.outcome_code = Some(code.to_owned());
    write_empty_record(job_dir, record, &record.account_sid)
}

/// Claim an elevated Boot Host job. The owner SID is derived from this
/// verified worker image path and then rechecked against its protected
/// registration; no account identity comes from worker arguments.
pub fn claim_boot_worker(job_id: &str) -> Result<WorkerJob, Error> {
    validate_job_id(job_id)?;
    let current = normalized(&std::env::current_exe().map_err(map_io)?)?;
    let owner_sid = current
        .parent()
        .and_then(Path::file_name)
        .and_then(std::ffi::OsStr::to_str)
        .ok_or(Error::Identity)?;
    let storage = super::service_admin::maintenance_storage_for_admin(owner_sid)
        .map_err(|_| Error::Identity)?;
    let expected_worker = admin_worker_path(&storage, job_id)?;
    if current != expected_worker {
        return Err(Error::Identity);
    }
    let _lock = lock_admin_job(&storage, job_id, Instant::now() + ACK_TIMEOUT)?;
    let mut record = read_admin_record(&storage, job_id, true)?.ok_or(Error::Invalid)?;
    if record.state != JobState::Prepared {
        return Err(Error::Invalid);
    }
    let (operator_sid, _) = super::service_admin::current_account().map_err(|_| Error::Identity)?;
    if record.operator_sid.as_deref() != Some(operator_sid.as_str()) {
        return Err(Error::Identity);
    }
    let binding = super::service_admin::registered_boot_host_for_sid(
        &record.account_sid,
        Path::new(&record.active_executable),
    )
    .map_err(|_| Error::Identity)?;
    if binding.account() != record.owner_account.as_deref().ok_or(Error::Invalid)?
        || binding.profile() != Path::new(&record.profile)
        || binding.install() != Path::new(&record.install)
        || binding.executable() != Path::new(&record.active_executable)
        || binding.signer_thumbprint() != record.release.signer_thumbprint
        || String::from(binding.identity().host_id) != record.host_id
        || String::from(binding.identity().profile_id) != record.profile_id
    {
        return Err(Error::Identity);
    }
    if hash_path(binding.executable())? != record.active_executable_sha256 {
        return Err(Error::Identity);
    }
    if hash_path(&current)? != record.worker_executable_sha256 {
        return Err(Error::Identity);
    }
    verify_signer(&current, &record.release.signer_thumbprint)?;
    let parent = record.inherited_parent_handle as HANDLE;
    if parent.is_null() || unsafe { GetProcessId(parent) } == 0 {
        return Err(Error::Identity);
    }
    if unsafe { WaitForSingleObject(parent, 0) } != WAIT_TIMEOUT {
        record.state = JobState::Uncertain;
        record.outcome_code = Some("PARENT_EXITED_BEFORE_ACCEPTANCE".to_owned());
        write_admin_record(&storage, &record)?;
        return Err(Error::Invalid);
    }
    verify_parent_image(parent, &record)?;
    record.state = JobState::Accepted;
    record.outcome_code = None;
    write_admin_record(&storage, &record)?;
    Ok(WorkerJob {
        profile: PathBuf::from(&record.profile),
        record,
        admin_storage: Some(storage),
    })
}

/// Validate the owner-readable uninstall capsule after CreateProcessWithLogonW
/// has started the exact registered image in its native owner account.
pub fn claim_owner_continuation(
    job_id: &str,
    release: &ReleasePins,
) -> Result<OwnerContinuationRequest, Error> {
    validate_job_id(job_id)?;
    let binding = super::service_admin::registered_boot_host_for_owner_executable()
        .map_err(|_| Error::Identity)?;
    let storage = super::service_admin::maintenance_storage_for_owner(binding.account_sid())
        .map_err(|_| Error::Identity)?;
    let record = read_admin_record(&storage, job_id, true)?.ok_or(Error::Invalid)?;
    validate_admin_record(&storage, job_id, &record)?;
    let current = normalized(&std::env::current_exe().map_err(map_io)?)?;
    if !(matches!(record.state, JobState::Prepared | JobState::Running)
        && matches!(
            (record.state, record.owner_phase),
            (JobState::Prepared, Some(OwnerPhase::FenceAndStop))
                | (JobState::Running, Some(OwnerPhase::PurgeAfterRecovery))
        ))
        || record.owner_outcome != Some(OwnerOutcome::Pending)
        || !matches!(record.action, Action::Uninstall { .. })
        || record.account_sid != binding.account_sid()
        || record.owner_account.as_deref() != Some(binding.account())
        || binding.signer_thumbprint() != record.release.signer_thumbprint
        || record.profile != text_path(binding.profile())?
        || record.install != text_path(binding.install())?
        || record.active_executable != text_path(binding.executable())?
        || record.host_id != String::from(binding.identity().host_id)
        || record.profile_id != String::from(binding.identity().profile_id)
        || record.release != *release
        || current != binding.executable()
        || hash_path(&current)? != record.active_executable_sha256
    {
        return Err(Error::Identity);
    }
    verify_signer(&current, &record.release.signer_thumbprint)?;
    let operation_id = OperationId::from_bytes(
        Uuid::parse_str(record.owner_operation_id.as_deref().ok_or(Error::Invalid)?)
            .map_err(|_| Error::Invalid)?
            .into_bytes(),
    )
    .map_err(|_| Error::Invalid)?;
    Ok(OwnerContinuationRequest {
        profile: binding.profile().to_path_buf(),
        identity: (binding.identity().host_id, binding.identity().profile_id),
        action: record.action,
        operation_id,
        phase: record.owner_phase.ok_or(Error::Invalid)?,
        account: binding.account().to_owned(),
        binding: crate::service_observation::ServiceBinding {
            account: crate::service_observation::ServiceAccount::Windows {
                sid: binding.account_sid().to_owned(),
                name: binding.account().to_owned(),
            },
            mode: crate::service_observation::ServiceMode::Boot,
            profile: binding.profile().to_path_buf(),
            executable: binding.executable().to_path_buf(),
        },
        _storage: storage,
    })
}

/// Advance exactly one owner continuation phase in the protected job record.
/// Each update is a compare-and-set under the job lock, so a phase cannot be
/// replayed or skipped.
pub fn complete_owner_phase(
    binding: &RegisteredBootHost,
    job_id: &str,
    release: &ReleasePins,
    expected: OwnerPhase,
    outcome: OwnerOutcome,
) -> Result<OwnerPhase, Error> {
    validate_job_id(job_id)?;
    validate_release(release)?;
    let current_binding = super::service_admin::registered_boot_host_for_sid(
        binding.account_sid(),
        binding.executable(),
    )
    .map_err(|_| Error::Identity)?;
    ensure_same_boot_identity(binding, &current_binding)?;
    let storage = super::service_admin::maintenance_storage_for_admin(binding.account_sid())
        .map_err(|_| Error::Identity)?;
    let _lock = lock_admin_job(&storage, job_id, Instant::now() + ACK_TIMEOUT)?;
    let mut record = read_admin_record(&storage, job_id, true)?.ok_or(Error::Invalid)?;
    let (operator_sid, _) = super::service_admin::current_account().map_err(|_| Error::Identity)?;
    if !matches!(
        (record.state, expected),
        (JobState::Prepared, OwnerPhase::FenceAndStop)
            | (JobState::Running, OwnerPhase::PurgeAfterRecovery)
    ) || record.release != *release
        || record.operator_sid.as_deref() != Some(operator_sid.as_str())
        || record.owner_phase != Some(expected)
        || record.owner_outcome != Some(OwnerOutcome::Pending)
        || !matches!(record.action, Action::Uninstall { .. })
        || !record_matches_boot_binding(&record, &current_binding)
    {
        return Err(Error::Identity);
    }
    let (next, owner_outcome) = match (expected, outcome, &record.action) {
        (OwnerPhase::FenceAndStop, OwnerOutcome::Complete, Action::Uninstall { purge: true }) => {
            (OwnerPhase::PurgeAfterRecovery, OwnerOutcome::Pending)
        }
        (OwnerPhase::FenceAndStop, OwnerOutcome::Complete, Action::Uninstall { purge: false }) => {
            (OwnerPhase::Complete, OwnerOutcome::Complete)
        }
        (OwnerPhase::FenceAndStop, OwnerOutcome::RevocationPending, Action::Uninstall { .. }) => {
            (OwnerPhase::Complete, OwnerOutcome::RevocationPending)
        }
        (OwnerPhase::PurgeAfterRecovery, accepted, Action::Uninstall { purge: true })
            if matches!(
                accepted,
                OwnerOutcome::Complete
                    | OwnerOutcome::RevocationPending
                    | OwnerOutcome::CleanupUncertain
            ) =>
        {
            (OwnerPhase::Complete, accepted)
        }
        _ => return Err(Error::Invalid),
    };
    record.owner_phase = Some(next);
    record.owner_outcome = Some(owner_outcome);
    write_admin_record(&storage, &record)?;
    Ok(next)
}

/// Refresh the active signed image binding after recovery while retaining the
/// exact pre-recovery parent hash and immutable copied worker image.
pub fn refresh_boot_job_after_recovery(
    binding: &RegisteredBootHost,
    job_id: &str,
    release: &ReleasePins,
) -> Result<(), Error> {
    validate_job_id(job_id)?;
    validate_release(release)?;
    let current_binding = super::service_admin::registered_boot_host_for_sid(
        binding.account_sid(),
        binding.executable(),
    )
    .map_err(|_| Error::Identity)?;
    ensure_same_boot_identity(binding, &current_binding)?;
    let storage = super::service_admin::maintenance_storage_for_admin(binding.account_sid())
        .map_err(|_| Error::Identity)?;
    let _lock = lock_admin_job(&storage, job_id, Instant::now() + ACK_TIMEOUT)?;
    let mut record = read_admin_record(&storage, job_id, true)?.ok_or(Error::Invalid)?;
    let (operator_sid, _) = super::service_admin::current_account().map_err(|_| Error::Identity)?;
    if !matches!(record.state, JobState::Prepared | JobState::Running)
        || record.release != *release
        || record.operator_sid.as_deref() != Some(operator_sid.as_str())
        || !(matches!(
            (&record.action, record.owner_phase, record.owner_outcome),
            (
                Action::Uninstall { .. },
                Some(OwnerPhase::PurgeAfterRecovery | OwnerPhase::Complete),
                _
            )
        ) || matches!(
            (&record.action, record.owner_phase, record.owner_outcome),
            (Action::Update { .. }, None, Some(OwnerOutcome::NotRequired))
        ))
        || !record_matches_boot_binding(&record, &current_binding)
        || current_binding.signer_thumbprint() != release.signer_thumbprint
    {
        return Err(Error::Identity);
    }
    let executable = normalized(current_binding.executable())?;
    let image_sha256 = hash_path(&executable)?;
    verify_signer(&executable, &release.signer_thumbprint)?;
    record.active_executable_sha256 = image_sha256;
    write_admin_record(&storage, &record)
}

fn ensure_same_boot_identity(
    expected: &RegisteredBootHost,
    actual: &RegisteredBootHost,
) -> Result<(), Error> {
    if expected.account_sid() != actual.account_sid()
        || expected.account() != actual.account()
        || expected.profile() != actual.profile()
        || expected.install() != actual.install()
        || expected.executable() != actual.executable()
        || expected.identity() != actual.identity()
        || expected.signer_thumbprint() != actual.signer_thumbprint()
    {
        return Err(Error::Identity);
    }
    Ok(())
}

fn record_matches_boot_binding(record: &JobRecord, binding: &RegisteredBootHost) -> bool {
    record.account_sid == binding.account_sid()
        && record.owner_account.as_deref() == Some(binding.account())
        && Path::new(&record.profile) == binding.profile()
        && Path::new(&record.install) == binding.install()
        && Path::new(&record.active_executable) == binding.executable()
        && record.release.signer_thumbprint == binding.signer_thumbprint()
        && record.host_id == String::from(binding.identity().host_id)
        && record.profile_id == String::from(binding.identity().profile_id)
}

/// The worker waits on the exact inherited parent handle. A PID is never
/// looked up or reopened, and active-image mutation starts only after exit.
pub fn mark_running(job: &mut WorkerJob) -> Result<(), Error> {
    if job.record.state != JobState::Accepted {
        return Err(Error::Invalid);
    }
    let parent = job.record.inherited_parent_handle as HANDLE;
    if parent.is_null() || unsafe { GetProcessId(parent) } == 0 {
        return Err(Error::Identity);
    }
    let wait = unsafe {
        WaitForSingleObject(
            parent,
            u32::try_from(PARENT_EXIT_TIMEOUT.as_millis()).map_err(|_| Error::Invalid)?,
        )
    };
    if wait == WAIT_TIMEOUT {
        mark_worker_uncertain(job, "PARENT_EXIT_TIMEOUT")?;
        return Err(Error::Deadline);
    }
    if wait != WAIT_OBJECT_0 {
        mark_worker_uncertain(job, "PARENT_HANDLE_UNCERTAIN")?;
        return Err(Error::Uncertain);
    }
    if let Some(storage) = &job.admin_storage {
        let _lock = lock_admin_job(storage, &job.record.job_id, Instant::now() + ACK_TIMEOUT)?;
        let record = read_admin_record(storage, &job.record.job_id, true)?.ok_or(Error::Invalid)?;
        if record.state != JobState::Accepted {
            return Err(Error::Uncertain);
        }
        verify_parent_image(parent, &record)?;
        job.record = record;
        job.record.state = JobState::Running;
        persist(job)
    } else {
        let _lock = lock_job(
            &job.profile,
            &job.record.job_id,
            &job.record.account_sid,
            Instant::now() + ACK_TIMEOUT,
        )?;
        let record = read_record(&job.profile, &job.record.job_id)?.ok_or(Error::Invalid)?;
        if record.state != JobState::Accepted {
            return Err(Error::Uncertain);
        }
        verify_parent_image(parent, &record)?;
        job.record = record;
        job.record.state = JobState::Running;
        persist(job)
    }
}

pub fn finish_worker(
    job: &mut WorkerJob,
    state: JobState,
    code: &'static str,
) -> Result<(), Error> {
    if job.record.state != JobState::Running
        || !matches!(
            state,
            JobState::Completed
                | JobState::RevocationPending
                | JobState::Failed
                | JobState::Uncertain
        )
    {
        return Err(Error::Invalid);
    }
    if let Some(storage) = &job.admin_storage {
        let _lock = lock_admin_job(storage, &job.record.job_id, Instant::now() + ACK_TIMEOUT)?;
        let current =
            read_admin_record(storage, &job.record.job_id, true)?.ok_or(Error::Invalid)?;
        if current.state != JobState::Running {
            return Err(Error::Uncertain);
        }
        job.record = current;
        job.record.state = state;
        job.record.outcome_code = (state != JobState::Completed).then(|| code.to_owned());
        persist(job)
    } else {
        let _lock = lock_job(
            &job.profile,
            &job.record.job_id,
            &job.record.account_sid,
            Instant::now() + ACK_TIMEOUT,
        )?;
        let current = read_record(&job.profile, &job.record.job_id)?.ok_or(Error::Invalid)?;
        if current.state != JobState::Running {
            return Err(Error::Uncertain);
        }
        job.record = current;
        job.record.state = state;
        job.record.outcome_code = (state != JobState::Completed).then(|| code.to_owned());
        persist(job)
    }
}

/// Read a durable result. Cleanup touches only this job's exact private worker
/// image after the recorded operation is terminal; unknown files are ignored.
pub fn status(profile: &Path, job_id: &str, json: bool) -> u8 {
    let current_worker = match read_current_admin_worker(profile, job_id) {
        Ok(record) => record,
        Err(error) => {
            eprintln!("{error}");
            return 4;
        }
    };
    let owner_boot_binding = super::service_admin::registered_boot_host_for_owner_executable().ok();
    let boot_binding = if let Some(binding) = owner_boot_binding {
        Some(binding)
    } else {
        match super::service_admin::registered_boot_host_for_current_executable() {
            Ok(binding) => binding,
            Err(error) => {
                eprintln!("{error}");
                return 4;
            }
        }
    };
    if current_worker.is_none() && boot_binding.is_none() {
        match read_current_empty_job(profile, job_id) {
            Ok(Some(record)) => return report_empty_job(record, json),
            Ok(None) => {}
            Err(error) => {
                eprintln!("{error}");
                return 4;
            }
        }
    }
    let result: Result<JobRecord, Error> = if let Some(record) = current_worker {
        Ok(record)
    } else {
        (|| {
            // The protected Boot worker's directory identifies the owner SID.
            // Resolve it from this exact registered image before consulting the
            // caller's ordinary profile; an elevated operator may have a
            // different default profile from the Host owner.
            if let Some(binding) = boot_binding {
                let (caller_sid, _) =
                    super::service_admin::current_account().map_err(|_| Error::Identity)?;
                if normalized(profile)? != binding.profile() {
                    return Err(Error::Identity);
                }
                let owner_route = caller_sid == binding.account_sid();
                let storage = if owner_route {
                    super::service_admin::maintenance_storage_for_owner(binding.account_sid())
                } else {
                    super::service_admin::maintenance_storage_for_admin(binding.account_sid())
                }
                .map_err(|_| Error::Identity)?;
                let record = read_admin_record(&storage, job_id, true)?.ok_or(Error::Invalid)?;
                validate_admin_record(&storage, job_id, &record)?;
                if !record_matches_boot_binding(&record, &binding) {
                    return Err(Error::Identity);
                }
                if !owner_route && record.operator_sid.as_deref() != Some(caller_sid.as_str()) {
                    return Err(Error::Permission);
                }
                if maintenance_finished(record.state) {
                    cleanup_worker(&record);
                }
                return Ok(record);
            }

            let profile = normalized(profile)?;
            match std::fs::symlink_metadata(profile.join(JOBS_DIR)) {
                Ok(_) => {
                    if let Some(record) = read_record(&profile, job_id)? {
                        validate_record(&profile, job_id, &record)?;
                        if maintenance_finished(record.state) {
                            cleanup_worker(&record);
                        }
                        return Ok(record);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(map_io(error)),
            }
            let (owner_sid, _) =
                super::service_admin::current_account().map_err(|_| Error::Identity)?;
            let storage = super::service_admin::maintenance_storage_for_owner(&owner_sid)
                .map_err(|_| Error::Identity)?;
            let record = read_admin_record(&storage, job_id, true)?.ok_or(Error::Invalid)?;
            validate_admin_record(&storage, job_id, &record)?;
            if Path::new(&record.profile) != profile {
                return Err(Error::Identity);
            }
            if maintenance_finished(record.state) {
                cleanup_worker(&record);
            }
            Ok(record)
        })()
    };
    match result {
        Ok(record) => {
            if json {
                let payload = serde_json::json!({
                    "version": LocalIpcVersion::CURRENT,
                    "jobId": record.job_id,
                    "state": record.state,
                    "hostId": record.host_id,
                    "profileId": record.profile_id,
                    "mode": record.mode,
                    "ownerOutcome": record.owner_outcome,
                    "ownerPhase": record.owner_phase,
                    "outcomeCode": record.outcome_code,
                    "nextStep": if record.state == JobState::RevocationPending {
                        Some("Revoke this Host from the account controls. After acknowledgment, obtain and verify the signed Lomi Remote bundle, reinstall it for this Host profile, then run uninstall --purge --confirm to finish local cleanup.")
                    } else {
                        None
                    },
                });
                if serde_json::to_writer(std::io::stdout().lock(), &payload).is_err() {
                    return 4;
                }
                println!();
            } else {
                println!("Maintenance job {}: {:?}", record.job_id, record.state);
                if let Some(code) = record.outcome_code {
                    println!("Outcome: {code}");
                }
                if let Some(phase) = record.owner_phase {
                    println!("Owner phase: {phase:?}");
                }
                if record.state == JobState::RevocationPending {
                    println!(
                        "The local Host fence and pending cloud revoke were retained. Revoke this Host from the account controls. After acknowledgment, obtain and verify the signed Lomi Remote bundle, reinstall it for this Host profile, then run `lomiremote uninstall --purge --confirm` to finish local cleanup."
                    );
                }
                if record.owner_outcome == Some(OwnerOutcome::CleanupUncertain) {
                    println!(
                        "Owner-context purge cleanup is uncertain. The installed command and Host profile remain available; inspect the retained profile before retrying the confirmed uninstall."
                    );
                }
            }
            if matches!(record.state, JobState::Completed) {
                0
            } else if matches!(
                record.state,
                JobState::Prepared | JobState::Accepted | JobState::Running
            ) {
                0
            } else {
                7
            }
        }
        Err(error) => {
            if json {
                let payload = serde_json::json!({
                    "version": LocalIpcVersion::CURRENT,
                    "error": { "code": error.to_string() },
                });
                if serde_json::to_writer(std::io::stdout().lock(), &payload).is_err() {
                    return 4;
                }
                println!();
            }
            eprintln!("{error}");
            4
        }
    }
}

fn read_current_empty_job(
    requested_profile: &Path,
    job_id: &str,
) -> Result<Option<EmptyReservationRecord>, Error> {
    validate_job_id(job_id)?;
    let requested_profile = normalized(requested_profile)?;
    if requested_profile.join(JOBS_DIR).exists()
        && read_record(&requested_profile, job_id)?.is_some()
    {
        return Ok(None);
    }
    let executable = normalized(&std::env::current_exe().map_err(map_io)?)?;
    let parent = executable.parent().ok_or(Error::Identity)?;
    let job_dir = if parent.file_name()
        == Some(std::ffi::OsStr::new(&format!("{EMPTY_JOB_PREFIX}{job_id}")))
    {
        parent.to_path_buf()
    } else {
        empty_job_dir(parent, job_id)?
    };
    if !job_dir.exists() {
        return Ok(None);
    }
    let private = PrivateProfile::open(&job_dir, false).map_err(map_error)?;
    if private.sid != current_sid().map_err(map_error)? {
        return Err(Error::Identity);
    }
    let _lock = lock_empty_job(&job_dir, &private.sid, Instant::now() + ACK_TIMEOUT)?;
    check_empty_job_contents(&job_dir, &private.sid)?;
    let Some(record) = read_empty_record(&job_dir, job_id)? else {
        return Ok(None);
    };
    if requested_profile != Path::new(&record.profile) {
        return Err(Error::Identity);
    }
    Ok(Some(record))
}

/// Read the job record for the exact copied Boot worker image. This route is
/// needed after uninstall removes the active Boot registration: the worker's
/// protected SID/job path and signed-image hash still bind the durable capsule,
/// and the current token must match its recorded operator.
fn read_current_admin_worker(
    requested_profile: &Path,
    job_id: &str,
) -> Result<Option<JobRecord>, Error> {
    validate_job_id(job_id)?;
    let executable = normalized(&std::env::current_exe().map_err(map_io)?)?;
    if executable.file_name() != Some(std::ffi::OsStr::new(&format!("worker-{job_id}.exe"))) {
        return Ok(None);
    }
    let Some(owner_sid) = executable
        .parent()
        .and_then(Path::file_name)
        .and_then(std::ffi::OsStr::to_str)
        .filter(|sid| valid_sid(sid))
    else {
        return Ok(None);
    };
    let Some(owner_directory) = executable.parent() else {
        return Ok(None);
    };
    if owner_directory.parent().and_then(Path::file_name)
        != Some(std::ffi::OsStr::new("MaintenanceJobs"))
        || owner_directory
            .parent()
            .and_then(Path::parent)
            .and_then(Path::file_name)
            != Some(std::ffi::OsStr::new("LomiRemote"))
    {
        return Ok(None);
    }
    let storage = super::service_admin::maintenance_storage_for_job_status(owner_sid)
        .map_err(|_| Error::Identity)?;
    if admin_worker_path(&storage, job_id)? != executable {
        return Ok(None);
    }
    let (operator_sid, _) = super::service_admin::current_account().map_err(|_| Error::Identity)?;
    let record = read_admin_record(&storage, job_id, true)?.ok_or(Error::Invalid)?;
    if record.worker_executable != text_path(&executable)?
        || Path::new(&record.profile) != normalized(requested_profile)?
        || record.operator_sid.as_deref() != Some(operator_sid.as_str())
        || hash_path(&executable)? != record.worker_executable_sha256
        || verify_signer(&executable, &record.release.signer_thumbprint).is_err()
    {
        return Err(Error::Identity);
    }
    Ok(Some(record))
}

fn report_empty_job(record: EmptyReservationRecord, json: bool) -> u8 {
    if json {
        let payload = serde_json::json!({
            "version": LocalIpcVersion::CURRENT,
            "jobId": record.job_id,
            "state": record.state,
            "profileKind": "empty_reservation",
            "outcomeCode": record.outcome_code,
            "purge": "no_mutable_host_data",
        });
        if serde_json::to_writer(std::io::stdout().lock(), &payload).is_err() {
            return 4;
        }
        println!();
    } else {
        println!(
            "Fresh-profile maintenance job {}: {:?}",
            record.job_id, record.state
        );
        if let Some(code) = record.outcome_code {
            println!("Outcome: {code}");
        }
        println!("No Host data existed to purge.");
    }
    match record.state {
        JobState::Completed | JobState::Accepted | JobState::Running => 0,
        _ => 7,
    }
}

fn maintenance_finished(state: JobState) -> bool {
    matches!(
        state,
        JobState::Completed | JobState::RevocationPending | JobState::Failed | JobState::Uncertain
    )
}

fn persist(job: &WorkerJob) -> Result<(), Error> {
    if let Some(storage) = &job.admin_storage {
        write_admin_record(storage, &job.record)
    } else {
        write_record(
            &job_path(&job.profile, &job.record.job_id)?,
            &job.record,
            &job.record.account_sid,
        )
    }
}

fn mark_worker_uncertain(job: &mut WorkerJob, code: &'static str) -> Result<(), Error> {
    if let Some(storage) = &job.admin_storage {
        let _lock = lock_admin_job(storage, &job.record.job_id, Instant::now() + ACK_TIMEOUT)?;
        let mut record =
            read_admin_record(storage, &job.record.job_id, true)?.ok_or(Error::Invalid)?;
        if record.state != JobState::Accepted {
            return Err(Error::Uncertain);
        }
        record.state = JobState::Uncertain;
        record.outcome_code = Some(code.to_owned());
        write_admin_record(storage, &record)?;
        job.record = record;
        return Ok(());
    }
    let _lock = lock_job(
        &job.profile,
        &job.record.job_id,
        &job.record.account_sid,
        Instant::now() + ACK_TIMEOUT,
    )?;
    let mut record = read_record(&job.profile, &job.record.job_id)?.ok_or(Error::Invalid)?;
    if record.state != JobState::Accepted {
        return Err(Error::Uncertain);
    }
    record.state = JobState::Uncertain;
    record.outcome_code = Some(code.to_owned());
    write_record(
        &job_path(&job.profile, &job.record.job_id)?,
        &record,
        &record.account_sid,
    )?;
    job.record = record;
    Ok(())
}

fn validate_record(profile: &Path, job_id: &str, record: &JobRecord) -> Result<(), Error> {
    validate_job_id(job_id)?;
    if record.schema != JOB_SCHEMA
        || record.job_id != job_id
        || normalized(Path::new(&record.profile))? != profile
        || !valid_digest(&record.active_executable_sha256)
        || !valid_digest(&record.worker_executable_sha256)
        || !valid_sid(&record.account_sid)
        || record.inherited_parent_handle == 0
    {
        return Err(Error::Invalid);
    }
    let private = PrivateProfile::open(profile, false).map_err(map_error)?;
    let _jobs = PrivateProfile::open(&profile.join(JOBS_DIR), false).map_err(map_error)?;
    let _workers = PrivateProfile::open(&profile.join(WORKERS_DIR), false).map_err(map_error)?;
    if private.sid != record.account_sid {
        return Err(Error::Identity);
    }
    let install = super::normalized(Path::new(&record.install)).map_err(map_error)?;
    let active = super::normalized(Path::new(&record.active_executable)).map_err(map_error)?;
    let worker = super::normalized(Path::new(&record.worker_executable)).map_err(map_error)?;
    let expected_worker = profile
        .join(WORKERS_DIR)
        .join(format!("{job_id}{ADMIN_WORKER_SUFFIX}"));
    if install.components().count() <= 2
        || active.parent() != Some(install.as_path())
        || worker != expected_worker
        || !profile
            .join(JOBS_DIR)
            .join(format!("{job_id}.json"))
            .is_file()
    {
        return Err(Error::Identity);
    }
    validate_release(&record.release)?;
    validate_action(&record.action)
}

fn validate_release(release: &ReleasePins) -> Result<(), Error> {
    if !release.origin.starts_with("https://")
        || release.origin.len() > 2048
        || release.origin.bytes().any(|byte| byte.is_ascii_control())
        || !valid_target(&release.primary_target)
        || release
            .helper_target
            .as_deref()
            .is_some_and(|target| !valid_target(target) || target == release.primary_target)
        || !valid_digest(&release.root_sha256)
        || !valid_platform(&release.platform)
        || release.signer_thumbprint.len() != 40
        || !release
            .signer_thumbprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase())
        || release.helper_target.is_none()
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

fn validate_action(action: &Action) -> Result<(), Error> {
    match action {
        Action::Update { expected_version } => {
            if let Some(expected_version) = expected_version {
                if expected_version.is_empty()
                    || expected_version.len() > 128
                    || !expected_version
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b".+-_".contains(&byte))
                {
                    return Err(Error::Invalid);
                }
            }
        }
        Action::Uninstall { .. } => {}
    }
    Ok(())
}

fn valid_target(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.starts_with('/')
        && value
            .split('/')
            .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._/-".contains(&byte))
}

fn valid_platform(value: &str) -> bool {
    matches!(value, "windows-x86_64" | "windows-aarch64")
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_sid(value: &str) -> bool {
    value.starts_with("S-1-")
        && value.len() <= 184
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'S' || byte == b'-')
}

fn validate_job_id(value: &str) -> Result<(), Error> {
    let uuid = uuid::Uuid::parse_str(value).map_err(|_| Error::Invalid)?;
    if uuid.to_string() != value {
        return Err(Error::Invalid);
    }
    Ok(())
}

fn normalized(path: &Path) -> Result<PathBuf, Error> {
    let path = path.canonicalize().map_err(map_io)?;
    let path = super::normalized(&path).map_err(map_error)?;
    let text = path.to_str().ok_or(Error::Invalid)?;
    if !path.is_absolute()
        || text.len() > 2048
        || text.chars().any(char::is_control)
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(Error::Invalid);
    }
    Ok(path)
}

fn text_path(path: &Path) -> Result<String, Error> {
    path.to_str().map(str::to_owned).ok_or(Error::Invalid)
}

fn job_path(profile: &Path, job_id: &str) -> Result<PathBuf, Error> {
    validate_job_id(job_id)?;
    Ok(profile.join(JOBS_DIR).join(format!("{job_id}.json")))
}

fn job_lock_path(profile: &Path, job_id: &str) -> Result<PathBuf, Error> {
    validate_job_id(job_id)?;
    Ok(profile.join(JOBS_DIR).join(format!("{job_id}.lock")))
}

fn lock_job(profile: &Path, job_id: &str, sid: &str, deadline: Instant) -> Result<File, Error> {
    let path = job_lock_path(profile, job_id)?;
    loop {
        let raw = unsafe {
            CreateFileW(
                super::wide(path.as_os_str()).as_ptr(),
                GENERIC_READ | GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
                ptr::null_mut(),
            )
        };
        if raw != INVALID_HANDLE_VALUE {
            let info = match information(raw) {
                Ok(info) => info,
                Err(error) => {
                    unsafe { CloseHandle(raw) };
                    return Err(map_error(error));
                }
            };
            if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
                != 0
                || info.nNumberOfLinks != 1
                || info.nFileSizeHigh != 0
                || info.nFileSizeLow != 0
            {
                unsafe { CloseHandle(raw) };
                return Err(Error::Identity);
            }
            if let Err(error) = validate_security(raw, sid, true, false) {
                unsafe { CloseHandle(raw) };
                return Err(map_error(error));
            }
            return Ok(unsafe { File::from_raw_handle(raw) });
        }
        let error = std::io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(32 | 33)) {
            return Err(map_io(error));
        }
        if Instant::now() >= deadline {
            return Err(Error::Busy);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn read_record(profile: &Path, job_id: &str) -> Result<Option<JobRecord>, Error> {
    validate_job_id(job_id)?;
    let profile = normalized(profile)?;
    let private = PrivateProfile::open(&profile, false).map_err(map_error)?;
    let _jobs = PrivateProfile::open(&profile.join(JOBS_DIR), false).map_err(map_error)?;
    private.check_current().map_err(map_error)?;
    let path = job_path(&profile, job_id)?;
    let file = match open_regular(&path, false, false, &private.sid) {
        Ok(file) => file,
        Err(super::Error::Io(error))
            if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(map_error(error)),
    };
    let mut bytes = Vec::new();
    file.take((MAX_JOB_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(map_io)?;
    if bytes.is_empty() || bytes.len() > MAX_JOB_BYTES {
        return Err(Error::Invalid);
    }
    let record: JobRecord = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
    validate_record(&profile, job_id, &record)?;
    Ok(Some(record))
}

fn private_identity(profile: &PrivateProfile) -> (u64, u64) {
    (u64::from(profile.identity.volume), profile.identity.index)
}

fn create_empty_job_directory(path: &Path, sid: &str) -> Result<PrivateProfile, Error> {
    let descriptor = security(sid, true).map_err(map_error)?;
    if unsafe {
        CreateDirectoryW(
            super::wide(path.as_os_str()).as_ptr(),
            &descriptor.attributes,
        )
    } == 0
    {
        return if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            Err(Error::Busy)
        } else {
            Err(map_io(std::io::Error::last_os_error()))
        };
    }
    let private = PrivateProfile::open(path, false).map_err(map_error)?;
    if private.sid != sid {
        return Err(Error::Identity);
    }
    private.check_current().map_err(map_error)?;
    Ok(private)
}

fn empty_job_dir(install: &Path, job_id: &str) -> Result<PathBuf, Error> {
    validate_job_id(job_id)?;
    Ok(install
        .join(EMPTY_MAINTENANCE_DIR)
        .join(format!("{EMPTY_JOB_PREFIX}{job_id}")))
}

fn empty_job_path(job_dir: &Path) -> PathBuf {
    job_dir.join(EMPTY_JOB_FILE)
}

fn empty_lock_path(job_dir: &Path) -> PathBuf {
    job_dir.join(EMPTY_LOCK_FILE)
}

fn lock_empty_job(job_dir: &Path, sid: &str, deadline: Instant) -> Result<File, Error> {
    let path = empty_lock_path(job_dir);
    loop {
        let raw = unsafe {
            CreateFileW(
                super::wide(path.as_os_str()).as_ptr(),
                GENERIC_READ | GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
                ptr::null_mut(),
            )
        };
        if raw != INVALID_HANDLE_VALUE {
            let info = match information(raw) {
                Ok(info) => info,
                Err(error) => {
                    unsafe { CloseHandle(raw) };
                    return Err(map_error(error));
                }
            };
            if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
                != 0
                || info.nNumberOfLinks != 1
                || info.nFileSizeHigh != 0
                || info.nFileSizeLow != 0
            {
                unsafe { CloseHandle(raw) };
                return Err(Error::Identity);
            }
            if let Err(error) = validate_security(raw, sid, true, false) {
                unsafe { CloseHandle(raw) };
                return Err(map_error(error));
            }
            return Ok(unsafe { File::from_raw_handle(raw) });
        }
        let error = std::io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(32 | 33)) {
            return Err(map_io(error));
        }
        if Instant::now() >= deadline {
            return Err(Error::Busy);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn read_empty_record(
    job_dir: &Path,
    job_id: &str,
) -> Result<Option<EmptyReservationRecord>, Error> {
    validate_job_id(job_id)?;
    let job_dir = normalized(job_dir)?;
    let private = PrivateProfile::open(&job_dir, false).map_err(map_error)?;
    private.check_current().map_err(map_error)?;
    let file = match open_regular(&empty_job_path(&job_dir), false, false, &private.sid) {
        Ok(file) => file,
        Err(super::Error::Io(error))
            if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(map_error(error)),
    };
    let mut bytes = Vec::new();
    file.take((MAX_JOB_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(map_io)?;
    if bytes.is_empty() || bytes.len() > MAX_JOB_BYTES {
        return Err(Error::Invalid);
    }
    let record: EmptyReservationRecord =
        serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
    validate_empty_record(&job_dir, job_id, &record)?;
    Ok(Some(record))
}

fn validate_empty_record(
    job_dir: &Path,
    job_id: &str,
    record: &EmptyReservationRecord,
) -> Result<(), Error> {
    validate_job_id(job_id)?;
    let job_dir = normalized(job_dir)?;
    let install = normalized(Path::new(&record.install))?;
    let profile = normalized(Path::new(&record.profile))?;
    let active = Path::new(&record.active_executable);
    let worker = normalized(Path::new(&record.worker_executable))?;
    if record.schema != 1
        || record.job_id != job_id
        || record.inherited_parent_handle == 0
        || !valid_sid(&record.account_sid)
        || !valid_digest(&record.active_executable_sha256)
        || !valid_digest(&record.worker_executable_sha256)
        || !active.is_absolute()
        || active.to_string_lossy().len() > 2048
        || active.to_string_lossy().chars().any(char::is_control)
        || active.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || active.parent() != Some(install.as_path())
        || !active
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| name.eq_ignore_ascii_case("lomiremote.exe"))
        || worker != job_dir.join(EMPTY_WORKER_NAME)
        || job_dir != empty_job_dir(&install, job_id)?
    {
        return Err(Error::Invalid);
    }
    validate_release(&record.release)?;
    let job_private = PrivateProfile::open(&job_dir, false).map_err(map_error)?;
    if job_private.sid != record.account_sid {
        return Err(Error::Identity);
    }
    let _worker_file =
        open_regular(&worker, false, false, &record.account_sid).map_err(map_error)?;
    if hash_path(&worker)? != record.worker_executable_sha256 {
        return Err(Error::Identity);
    }
    verify_signer(&worker, &record.release.signer_thumbprint)?;
    let install_private = PrivateProfile::open(&install, false).map_err(map_error)?;
    if install_private.sid != record.account_sid
        || private_identity(&install_private) != (record.install_volume, record.install_file)
    {
        return Err(Error::Identity);
    }
    let profile_private = PrivateProfile::open(&profile, false).map_err(map_error)?;
    if profile_private.sid != record.account_sid
        || private_identity(&profile_private) != (record.profile_volume, record.profile_file)
    {
        return Err(Error::Identity);
    }
    Ok(())
}

fn write_empty_new(
    job_dir: &Path,
    record: &EmptyReservationRecord,
    sid: &str,
) -> Result<(), Error> {
    let bytes = serde_json::to_vec(record).map_err(|_| Error::Invalid)?;
    if bytes.is_empty() || bytes.len() > MAX_JOB_BYTES {
        return Err(Error::Invalid);
    }
    let mut file = create_private_new(&empty_job_path(job_dir), sid)?;
    file.write_all(&bytes).map_err(map_io)?;
    file.sync_all().map_err(map_io)
}

fn check_empty_job_contents(job_dir: &Path, sid: &str) -> Result<(), Error> {
    let mut saw_worker = false;
    let mut saw_record = false;
    let mut saw_lock = false;
    let mut count = 0usize;
    for entry in std::fs::read_dir(job_dir).map_err(map_io)? {
        let entry = entry.map_err(map_io)?;
        count = count.checked_add(1).ok_or(Error::Invalid)?;
        match entry.file_name().to_str() {
            Some(EMPTY_WORKER_NAME) if !saw_worker => {
                open_image(&entry.path())?;
                saw_worker = true;
            }
            Some(EMPTY_JOB_FILE) if !saw_record => {
                open_regular(&entry.path(), false, false, sid).map_err(map_error)?;
                saw_record = true;
            }
            Some(EMPTY_LOCK_FILE) if !saw_lock => saw_lock = true,
            _ => return Err(Error::Identity),
        }
    }
    if count != 3 || !saw_worker || !saw_record || !saw_lock {
        return Err(Error::Identity);
    }
    Ok(())
}

fn write_empty_record(
    job_dir: &Path,
    record: &EmptyReservationRecord,
    sid: &str,
) -> Result<(), Error> {
    let bytes = serde_json::to_vec(record).map_err(|_| Error::Invalid)?;
    if bytes.is_empty() || bytes.len() > MAX_JOB_BYTES {
        return Err(Error::Invalid);
    }
    let job_private = PrivateProfile::open(job_dir, false).map_err(map_error)?;
    if job_private.sid != sid {
        return Err(Error::Identity);
    }
    job_private.check_current().map_err(map_error)?;
    let suffix = Uuid::new_v4();
    let path = empty_job_path(job_dir);
    let temp = path.with_extension(format!("{suffix}.tmp"));
    let result = (|| {
        let mut file = create_private_new(&temp, sid)?;
        file.write_all(&bytes).map_err(map_io)?;
        file.sync_all().map_err(map_io)?;
        let staged = super::object(&information(file.as_raw_handle()).map_err(map_error)?);
        job_private.check_current().map_err(map_error)?;
        drop(file);
        if unsafe {
            MoveFileExW(
                super::wide(temp.as_os_str()).as_ptr(),
                super::wide(path.as_os_str()).as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(map_io(std::io::Error::last_os_error()));
        }
        job_private.check_current().map_err(map_error)?;
        let mut committed = open_regular(&path, false, false, sid).map_err(map_error)?;
        let info = information(committed.as_raw_handle()).map_err(map_error)?;
        if super::object(&info) != staged
            || info.nNumberOfLinks != 1
            || info.nFileSizeHigh != 0
            || u64::from(info.nFileSizeLow) != bytes.len() as u64
        {
            return Err(Error::Identity);
        }
        let mut observed = Vec::with_capacity(bytes.len());
        committed
            .take((MAX_JOB_BYTES + 1) as u64)
            .read_to_end(&mut observed)
            .map_err(map_io)?;
        if observed != bytes {
            return Err(Error::Uncertain);
        }
        job_private.check_current().map_err(map_error)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

fn write_new_record(path: &Path, record: &JobRecord, sid: &str) -> Result<(), Error> {
    let bytes = serde_json::to_vec(record).map_err(|_| Error::Invalid)?;
    if bytes.is_empty() || bytes.len() > MAX_JOB_BYTES {
        return Err(Error::Invalid);
    }
    let mut file = create_private_new(path, sid)?;
    file.write_all(&bytes).map_err(map_io)?;
    file.sync_all().map_err(map_io)
}

fn write_record(path: &Path, record: &JobRecord, sid: &str) -> Result<(), Error> {
    let bytes = serde_json::to_vec(record).map_err(|_| Error::Invalid)?;
    if bytes.is_empty() || bytes.len() > MAX_JOB_BYTES {
        return Err(Error::Invalid);
    }
    let profile = path.parent().and_then(Path::parent).ok_or(Error::Invalid)?;
    let private = PrivateProfile::open(profile, false).map_err(map_error)?;
    private.check_current().map_err(map_error)?;
    let suffix = uuid::Uuid::new_v4();
    let temp = path.with_extension(format!("{suffix}.tmp"));
    let result = (|| {
        let mut file = create_private_new(&temp, sid)?;
        file.write_all(&bytes).map_err(map_io)?;
        file.sync_all().map_err(map_io)?;
        let staged = super::object(&information(file.as_raw_handle()).map_err(map_error)?);
        private.check_current().map_err(map_error)?;
        drop(file);
        let wide_temp = super::wide(temp.as_os_str());
        let wide_path = super::wide(path.as_os_str());
        if unsafe {
            MoveFileExW(
                wide_temp.as_ptr(),
                wide_path.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(map_io(std::io::Error::last_os_error()));
        }
        private.check_current().map_err(map_error)?;
        let mut committed = open_regular(path, false, false, sid).map_err(map_error)?;
        let info = information(committed.as_raw_handle()).map_err(map_error)?;
        if super::object(&info) != staged
            || info.nNumberOfLinks != 1
            || info.nFileSizeHigh != 0
            || u64::from(info.nFileSizeLow) != bytes.len() as u64
        {
            return Err(Error::Identity);
        }
        let mut observed = Vec::with_capacity(bytes.len());
        committed
            .take((MAX_JOB_BYTES + 1) as u64)
            .read_to_end(&mut observed)
            .map_err(map_io)?;
        if observed != bytes {
            return Err(Error::Uncertain);
        }
        private.check_current().map_err(map_error)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

fn create_private_new(path: &Path, sid: &str) -> Result<File, Error> {
    let descriptor = security(sid, false).map_err(map_error)?;
    let raw = unsafe {
        CreateFileW(
            super::wide(path.as_os_str()).as_ptr(),
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            &descriptor.attributes,
            CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(map_io(std::io::Error::last_os_error()));
    }
    validate_security(raw, sid, true, false).map_err(map_error)?;
    Ok(unsafe { File::from_raw_handle(raw) })
}

fn copy_private_worker(
    source: &Path,
    destination: &Path,
    sid: &str,
    signer: &str,
) -> Result<String, Error> {
    verify_signer(source, signer)?;
    let mut input = open_image(source)?;
    let mut output = create_private_new(destination, sid)?;
    let mut digest = Sha256::new();
    let mut copied = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer).map_err(map_io)?;
        if read == 0 {
            break;
        }
        copied = copied.checked_add(read as u64).ok_or(Error::Invalid)?;
        if copied > MAX_IMAGE_BYTES {
            return Err(Error::Invalid);
        }
        digest.update(&buffer[..read]);
        output.write_all(&buffer[..read]).map_err(map_io)?;
    }
    if copied == 0 {
        return Err(Error::Invalid);
    }
    output.sync_all().map_err(map_io)?;
    let hash = hex(&digest.finalize());
    drop(output);
    if hash_path(destination)? != hash {
        return Err(Error::Identity);
    }
    verify_signer(destination, signer)?;
    Ok(hash)
}

fn open_image(path: &Path) -> Result<File, Error> {
    let path = normalized(path)?;
    let raw = unsafe {
        CreateFileW(
            super::wide(path.as_os_str()).as_ptr(),
            GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(map_io(std::io::Error::last_os_error()));
    }
    let info = information(raw).map_err(map_error)?;
    if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
        || info.nNumberOfLinks != 1
        || info.nFileSizeHigh != 0
        || info.nFileSizeLow == 0
        || u64::from(info.nFileSizeLow) > MAX_IMAGE_BYTES
    {
        unsafe { CloseHandle(raw) };
        return Err(Error::Identity);
    }
    Ok(unsafe { File::from_raw_handle(raw) })
}

fn hash_path(path: &Path) -> Result<String, Error> {
    let file = open_image(path)?;
    hash_file(file)
}

fn hash_file(mut file: File) -> Result<String, Error> {
    file.seek(SeekFrom::Start(0)).map_err(map_io)?;
    let mut digest = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(map_io)?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or(Error::Invalid)?;
        if total > MAX_IMAGE_BYTES {
            return Err(Error::Invalid);
        }
        digest.update(&buffer[..read]);
    }
    if total == 0 {
        return Err(Error::Identity);
    }
    Ok(hex(&digest.finalize()))
}

fn verify_signer(path: &Path, signer: &str) -> Result<(), Error> {
    super::service_admin::verify_authenticode_image(path, signer).map_err(|_| Error::Identity)
}

fn launch_worker(
    executable: &Path,
    arguments: &[std::ffi::OsString],
    parent_handle: HANDLE,
    current_directory: &Path,
) -> Result<(), Error> {
    launch_worker_entrypoint(
        executable,
        "--internal-maintenance-worker-v1",
        arguments,
        parent_handle,
        current_directory,
    )
}

fn launch_worker_entrypoint(
    executable: &Path,
    entrypoint: &str,
    arguments: &[std::ffi::OsString],
    parent_handle: HANDLE,
    current_directory: &Path,
) -> Result<(), Error> {
    let application = super::wide(executable.as_os_str());
    if arguments.is_empty()
        || arguments.len() > 3
        || !matches!(
            entrypoint,
            "--internal-maintenance-worker-v1" | "--internal-maintenance-empty-worker-v1"
        )
    {
        return Err(Error::Invalid);
    }
    let mut command = format!("{} {entrypoint}", quote_arg(executable));
    for argument in arguments {
        command.push(' ');
        command.push_str(&quote_text(&argument.to_string_lossy()));
    }
    let mut command_line: Vec<u16> = command.encode_utf16().chain(Some(0)).collect();
    let current = super::wide(current_directory.as_os_str());
    let mut parent = parent_handle;
    let mut required = 0usize;
    unsafe {
        let _ = InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut required);
    }
    if required == 0 || required > 64 * 1024 {
        return Err(Error::Io);
    }
    let mut storage = vec![0usize; required.div_ceil(mem::size_of::<usize>())];
    let attributes = storage.as_mut_ptr().cast::<core::ffi::c_void>();
    unsafe {
        if InitializeProcThreadAttributeList(attributes, 1, 0, &mut required) == 0 {
            return Err(map_io(std::io::Error::last_os_error()));
        }
    }
    struct AttributeList(*mut core::ffi::c_void);
    impl Drop for AttributeList {
        fn drop(&mut self) {
            unsafe { DeleteProcThreadAttributeList(self.0) };
        }
    }
    let attribute_guard = AttributeList(attributes);
    unsafe {
        if UpdateProcThreadAttribute(
            attributes,
            0,
            ATTRIBUTE_HANDLE_LIST,
            (&mut parent as *mut HANDLE).cast(),
            mem::size_of::<HANDLE>(),
            ptr::null_mut(),
            ptr::null_mut(),
        ) == 0
        {
            return Err(map_io(std::io::Error::last_os_error()));
        }
    }
    let mut startup: STARTUPINFOEXW = unsafe { mem::zeroed() };
    startup.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.lpAttributeList = attributes;
    let mut process: PROCESS_INFORMATION = unsafe { mem::zeroed() };
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            1,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
            ptr::null_mut(),
            current.as_ptr(),
            &mut startup.StartupInfo as *mut STARTUPINFOW,
            &mut process,
        )
    };
    drop(attribute_guard);
    if created == 0 {
        return Err(map_io(std::io::Error::last_os_error()));
    }
    unsafe {
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    Ok(())
}

fn verify_parent_image(parent: HANDLE, record: &JobRecord) -> Result<(), Error> {
    let mut buffer = vec![0u16; 32768];
    let mut length = buffer.len() as u32;
    if unsafe { QueryFullProcessImageNameW(parent, 0, buffer.as_mut_ptr(), &mut length) } == 0 {
        return Err(Error::Identity);
    }
    buffer.truncate(length as usize);
    let path = PathBuf::from(std::ffi::OsString::from_wide(&buffer));
    let path = normalized(&path)?;
    if path != Path::new(&record.active_executable)
        || hash_path(&path)? != record.active_executable_sha256
    {
        return Err(Error::Identity);
    }
    verify_signer(&path, &record.release.signer_thumbprint)?;
    if record.mode == "boot" {
        let parent_hash = record
            .parent_executable_sha256
            .as_deref()
            .ok_or(Error::Invalid)?;
        if parent_hash != record.worker_executable_sha256
            || hash_path(Path::new(&record.worker_executable))? != parent_hash
        {
            return Err(Error::Identity);
        }
        verify_signer(
            Path::new(&record.worker_executable),
            &record.release.signer_thumbprint,
        )?;
    } else if record.parent_executable_sha256.is_some() {
        return Err(Error::Invalid);
    }
    Ok(())
}

fn verify_empty_parent(parent: HANDLE, record: &EmptyReservationRecord) -> Result<(), Error> {
    let mut buffer = vec![0u16; 32768];
    let mut length = buffer.len() as u32;
    if unsafe { QueryFullProcessImageNameW(parent, 0, buffer.as_mut_ptr(), &mut length) } == 0 {
        return Err(Error::Identity);
    }
    buffer.truncate(length as usize);
    let path = PathBuf::from(std::ffi::OsString::from_wide(&buffer));
    let path = normalized(&path)?;
    if path != Path::new(&record.active_executable)
        || hash_path(&path)? != record.active_executable_sha256
    {
        return Err(Error::Identity);
    }
    verify_signer(&path, &record.release.signer_thumbprint)
}

fn cleanup_worker(record: &JobRecord) {
    let path = Path::new(&record.worker_executable);
    if hash_path(path).is_ok_and(|hash| hash == record.worker_executable_sha256)
        && verify_signer(path, &record.release.signer_thumbprint).is_ok()
    {
        let _ = std::fs::remove_file(path);
    }
}

fn admin_job_path(storage: &MaintenanceStorage, job_id: &str) -> Result<PathBuf, Error> {
    validate_job_id(job_id)?;
    Ok(storage.path.join(format!("job-{job_id}{ADMIN_JOB_SUFFIX}")))
}

fn admin_lock_path(storage: &MaintenanceStorage, job_id: &str) -> Result<PathBuf, Error> {
    validate_job_id(job_id)?;
    Ok(storage
        .path
        .join(format!("job-{job_id}{ADMIN_LOCK_SUFFIX}")))
}

fn admin_worker_path(storage: &MaintenanceStorage, job_id: &str) -> Result<PathBuf, Error> {
    validate_job_id(job_id)?;
    Ok(storage
        .path
        .join(format!("worker-{job_id}{ADMIN_WORKER_SUFFIX}")))
}

fn create_admin_lock_file(storage: &MaintenanceStorage, job_id: &str) -> Result<(), Error> {
    let path = admin_lock_path(storage, job_id)?;
    let descriptor = super::Security::new("O:BA G:BA D:P(A;;FA;;;SY)(A;;FA;;;BA)")
        .map_err(|_| Error::Permission)?;
    let raw = unsafe {
        CreateFileW(
            super::wide(path.as_os_str()).as_ptr(),
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES,
            0,
            &descriptor.attributes,
            CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(map_io(std::io::Error::last_os_error()));
    }
    let file = unsafe { File::from_raw_handle(raw) };
    let info = information(raw).map_err(map_error)?;
    if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
        || info.nNumberOfLinks != 1
        || info.nFileSizeHigh != 0
        || info.nFileSizeLow != 0
    {
        return Err(Error::Identity);
    }
    super::service_admin::verify_maintenance_file_security(raw, &storage.owner_sid, false)
        .map_err(|_| Error::Permission)?;
    drop(file);
    Ok(())
}

fn lock_admin_job(
    storage: &MaintenanceStorage,
    job_id: &str,
    deadline: Instant,
) -> Result<File, Error> {
    let path = admin_lock_path(storage, job_id)?;
    loop {
        let raw = unsafe {
            CreateFileW(
                super::wide(path.as_os_str()).as_ptr(),
                GENERIC_READ | GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
                ptr::null_mut(),
            )
        };
        if raw != INVALID_HANDLE_VALUE {
            let info = information(raw).map_err(map_error)?;
            if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
                != 0
                || info.nNumberOfLinks != 1
                || info.nFileSizeHigh != 0
                || info.nFileSizeLow != 0
            {
                unsafe { CloseHandle(raw) };
                return Err(Error::Identity);
            }
            super::service_admin::verify_maintenance_file_security(raw, &storage.owner_sid, false)
                .map_err(|_| {
                    unsafe { CloseHandle(raw) };
                    Error::Permission
                })?;
            return Ok(unsafe { File::from_raw_handle(raw) });
        }
        let error = std::io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(32 | 33)) {
            return Err(map_io(error));
        }
        if Instant::now() >= deadline {
            return Err(Error::Busy);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn read_admin_record(
    storage: &MaintenanceStorage,
    job_id: &str,
    owner_read: bool,
) -> Result<Option<JobRecord>, Error> {
    let path = admin_job_path(storage, job_id)?;
    let raw = unsafe {
        CreateFileW(
            super::wide(path.as_os_str()).as_ptr(),
            GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return match unsafe { GetLastError() } {
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(None),
            _ => Err(map_io(std::io::Error::last_os_error())),
        };
    }
    let file = unsafe { File::from_raw_handle(raw) };
    let info = information(raw).map_err(map_error)?;
    if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
        || info.nNumberOfLinks != 1
        || info.nFileSizeHigh != 0
        || u64::from(info.nFileSizeLow) > MAX_JOB_BYTES as u64
    {
        return Err(Error::Identity);
    }
    super::service_admin::verify_maintenance_file_security(raw, &storage.owner_sid, owner_read)
        .map_err(|_| Error::Permission)?;
    let mut bytes = Vec::with_capacity(info.nFileSizeLow as usize);
    file.take((MAX_JOB_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(map_io)?;
    if bytes.is_empty() || bytes.len() > MAX_JOB_BYTES {
        return Err(Error::Invalid);
    }
    let record: JobRecord = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
    validate_admin_record(storage, job_id, &record)?;
    Ok(Some(record))
}

fn write_admin_record(storage: &MaintenanceStorage, record: &JobRecord) -> Result<(), Error> {
    validate_admin_record(storage, &record.job_id, record)?;
    let bytes = serde_json::to_vec(record).map_err(|_| Error::Invalid)?;
    if bytes.is_empty() || bytes.len() > MAX_JOB_BYTES {
        return Err(Error::Invalid);
    }
    let path = admin_job_path(storage, &record.job_id)?;
    let temporary = storage.path.join(format!(
        ".job-{}-{}.tmp",
        record.job_id,
        uuid::Uuid::new_v4()
    ));
    let descriptor = super::Security::new(&format!(
        "O:BA G:BA D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;{})",
        storage.owner_sid
    ))
    .map_err(|_| Error::Permission)?;
    let raw = unsafe {
        CreateFileW(
            super::wide(temporary.as_os_str()).as_ptr(),
            GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES,
            0,
            &descriptor.attributes,
            CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(map_io(std::io::Error::last_os_error()));
    }
    let mut file = unsafe { File::from_raw_handle(raw) };
    file.write_all(&bytes).map_err(map_io)?;
    file.sync_all().map_err(map_io)?;
    let info = information(raw).map_err(map_error)?;
    if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
        || info.nNumberOfLinks != 1
    {
        return Err(Error::Identity);
    }
    super::service_admin::verify_maintenance_file_security(raw, &storage.owner_sid, true)
        .map_err(|_| Error::Permission)?;
    drop(file);
    if unsafe {
        MoveFileExW(
            super::wide(temporary.as_os_str()).as_ptr(),
            super::wide(path.as_os_str()).as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        let error = std::io::Error::last_os_error();
        let _ = std::fs::remove_file(&temporary);
        return Err(map_io(error));
    }
    Ok(())
}

fn validate_admin_record(
    storage: &MaintenanceStorage,
    job_id: &str,
    record: &JobRecord,
) -> Result<(), Error> {
    validate_job_id(job_id)?;
    let expected_worker = admin_worker_path(storage, job_id)?;
    let profile = super::normalized(Path::new(&record.profile)).map_err(map_error)?;
    let install = super::normalized(Path::new(&record.install)).map_err(map_error)?;
    let active = super::normalized(Path::new(&record.active_executable)).map_err(map_error)?;
    let worker = super::normalized(Path::new(&record.worker_executable)).map_err(map_error)?;
    let host_id = HostId::try_from(record.host_id.clone()).map_err(|_| Error::Invalid)?;
    let profile_id =
        IpcProfileId::try_from(record.profile_id.clone()).map_err(|_| Error::Invalid)?;
    if record.schema != 2
        || record.job_id != job_id
        || record.account_sid != storage.owner_sid
        || record.operator_sid.as_deref().is_none_or(str::is_empty)
        || record.owner_account.as_deref().is_none_or(str::is_empty)
        || record
            .operator_sid
            .as_deref()
            .is_some_and(|sid| !valid_sid(sid))
        || record
            .owner_account
            .as_deref()
            .is_some_and(|account| account.len() > 512 || account.chars().any(char::is_control))
        || record.mode != "boot"
        || record.inherited_parent_handle == 0
        || !valid_digest(&record.active_executable_sha256)
        || !valid_digest(&record.worker_executable_sha256)
        || record
            .parent_executable_sha256
            .as_deref()
            .is_none_or(|digest| !valid_digest(digest) || digest != record.worker_executable_sha256)
        || record
            .owner_operation_id
            .as_deref()
            .is_some_and(|operation_id| {
                Uuid::parse_str(operation_id).map_or(true, |id| id.to_string() != operation_id)
            })
        || (matches!(record.action, Action::Uninstall { .. })
            && (record.owner_operation_id.is_none() || record.owner_phase.is_none()))
        || (matches!(record.action, Action::Update { .. })
            && (record.owner_outcome != Some(OwnerOutcome::NotRequired)
                || record.owner_operation_id.is_some()
                || record.owner_phase.is_some()))
        || matches!(
            (record.owner_phase, record.owner_outcome, &record.action),
            (
                Some(OwnerPhase::FenceAndStop),
                Some(owner_outcome),
                Action::Uninstall { .. }
            ) if owner_outcome != OwnerOutcome::Pending
        )
        || matches!(
            (record.owner_phase, record.owner_outcome, &record.action),
            (
                Some(OwnerPhase::PurgeAfterRecovery),
                Some(owner_outcome),
                Action::Uninstall { purge: true }
            ) if owner_outcome != OwnerOutcome::Pending
        )
        || matches!(
            (record.owner_phase, record.owner_outcome, &record.action),
            (
                Some(OwnerPhase::PurgeAfterRecovery),
                _,
                Action::Uninstall { purge: false }
            )
        )
        || matches!(
            (record.owner_phase, record.owner_outcome, &record.action),
            (
                Some(OwnerPhase::Complete),
                Some(OwnerOutcome::Pending),
                Action::Uninstall { .. }
            )
        )
        || String::from(host_id) != record.host_id
        || String::from(profile_id) != record.profile_id
        || profile.components().count() <= 2
        || install.components().count() <= 2
        || active.parent() != Some(install.as_path())
        || worker != expected_worker
    {
        return Err(Error::Invalid);
    }
    validate_release(&record.release)?;
    validate_action(&record.action)
}

fn copy_admin_worker(
    source: &Path,
    destination: &Path,
    owner_sid: &str,
    signer: &str,
) -> Result<String, Error> {
    verify_signer(source, signer)?;
    let mut input = open_image(source)?;
    let descriptor = super::Security::new("O:BA G:BA D:P(A;;FA;;;SY)(A;;FA;;;BA)")
        .map_err(|_| Error::Permission)?;
    let raw = unsafe {
        CreateFileW(
            super::wide(destination.as_os_str()).as_ptr(),
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES,
            0,
            &descriptor.attributes,
            CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(map_io(std::io::Error::last_os_error()));
    }
    let mut output = unsafe { File::from_raw_handle(raw) };
    let mut digest = Sha256::new();
    let mut copied = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = input.read(&mut buffer).map_err(map_io)?;
        if read == 0 {
            break;
        }
        copied = copied.checked_add(read as u64).ok_or(Error::Invalid)?;
        if copied > MAX_IMAGE_BYTES {
            return Err(Error::Invalid);
        }
        digest.update(&buffer[..read]);
        output.write_all(&buffer[..read]).map_err(map_io)?;
    }
    if copied == 0 {
        return Err(Error::Identity);
    }
    output.sync_all().map_err(map_io)?;
    let info = information(raw).map_err(map_error)?;
    if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
        || info.nNumberOfLinks != 1
        || u64::from(info.nFileSizeLow) != copied
    {
        return Err(Error::Identity);
    }
    super::service_admin::verify_maintenance_file_security(raw, owner_sid, false)
        .map_err(|_| Error::Permission)?;
    let hash = hex(&digest.finalize());
    drop(output);
    if hash_path(destination)? != hash {
        return Err(Error::Identity);
    }
    verify_signer(destination, signer)?;
    Ok(hash)
}

fn quote_arg(path: &Path) -> String {
    quote_text(path.to_str().unwrap_or_default())
}

fn quote_text(value: &str) -> String {
    let mut output = String::from("\"");
    let mut slashes = 0usize;
    for ch in value.chars() {
        if ch == '\\' {
            slashes += 1;
            continue;
        }
        if ch == '"' {
            output.push_str(&"\\".repeat(slashes.saturating_mul(2).saturating_add(1)));
            output.push('"');
            slashes = 0;
            continue;
        }
        output.push_str(&"\\".repeat(slashes));
        slashes = 0;
        output.push(ch);
    }
    output.push_str(&"\\".repeat(slashes.saturating_mul(2)));
    output.push('"');
    output
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn map_io(error: std::io::Error) -> Error {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        Error::Permission
    } else {
        Error::Io
    }
}

fn map_error(error: super::Error) -> Error {
    match error {
        super::Error::PermissionDenied => Error::Permission,
        super::Error::Io(error) => map_io(error),
        _ => Error::Invalid,
    }
}
