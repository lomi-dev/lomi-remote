//! Durable per-generation state. Records contain only root registration pins,
//! a generation nonce/deadline, and the controller's kernel identity; user
//! command arguments, environment, and terminal data are never persisted.

use super::{Error, capability};
use lomi_platform::noexec_process::NoExecHostProcessWitness;
use lomi_platform::service_macos::custody::PrivilegedCustodianRegistration;
use sha2::{Digest, Sha256};
use std::{
    ffi::{CStr, CString},
    fs::File,
    io::{self, Read},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::ffi::OsStrExt,
    },
    path::Path,
};
use uuid::Uuid;

const GENERATIONS_DIRECTORY: &str = "generations";
const STAGING_DIRECTORY: &str = "staging";
const RETIRED_DIRECTORY: &str = "retired";
const RECORD_FILE: &str = "record.json";
const LOCK_FILE: &str = "controller.lock";
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const RECORD_LIMIT: usize = 16 * 1024;
const GENERATION_LIMIT: usize = 64;
const AUXILIARY_LEAF_LIMIT: usize = 32;

// Broker threads publish, enumerate, and retire generations concurrently.
// Controllers run in separate processes and remain protected by controller.lock.
static INVENTORY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn inventory_lock() -> Result<std::sync::MutexGuard<'static, ()>, Error> {
    INVENTORY_LOCK.lock().map_err(|_| Error::CleanupFailed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GenerationState {
    Prepared,
    ControllerReady,
    StartCommitted,
    Closing,
    Cleaned,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CompletionDisposition {
    Drained,
    NotStarted,
    KernelRestart,
}

impl CompletionDisposition {
    fn as_str(self) -> &'static str {
        match self {
            Self::Drained => "drained",
            Self::NotStarted => "notStarted",
            Self::KernelRestart => "kernelRestart",
        }
    }

    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "drained" => Ok(Self::Drained),
            "notStarted" => Ok(Self::NotStarted),
            "kernelRestart" => Ok(Self::KernelRestart),
            _ => Err(Error::CleanupFailed),
        }
    }
}

#[derive(Clone, Copy)]
enum PinPolicy {
    Exact,
    HistoricalCleaned,
    Historical,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ControllerIdentity {
    pub(super) pid: i32,
    pub(super) pidversion: u32,
    pub(super) audit: [u32; 8],
    pub(super) resource: u64,
    pub(super) jetsam: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct GenerationRecord {
    version: u8,
    state: GenerationState,
    generation_nonce: String,
    registration_key: String,
    owner_uid: u32,
    profile_device: u64,
    profile_inode: u64,
    executable_device: u64,
    executable_inode: u64,
    executable_size: u64,
    executable_sha256: String,
    signing_identifier: String,
    signing_team_identifier: String,
    signing_code_directory_hash: String,
    deadline_ns: u64,
    preparation_process: NoExecHostProcessWitness,
    kernel_restart_proof_sha256: Option<String>,
    completion_disposition: Option<CompletionDisposition>,
    controller: Option<ControllerIdentity>,
}

impl GenerationRecord {
    pub(super) fn state(&self) -> GenerationState {
        self.state
    }

    pub(super) fn generation_nonce(&self) -> &str {
        &self.generation_nonce
    }

    pub(super) fn registration_key(&self) -> &str {
        &self.registration_key
    }

    pub(super) fn deadline_ns(&self) -> u64 {
        self.deadline_ns
    }

    pub(super) fn controller(&self) -> Option<&ControllerIdentity> {
        self.controller.as_ref()
    }

    pub(super) fn kernel_restart_proof_sha256(&self) -> Option<&str> {
        self.kernel_restart_proof_sha256.as_deref()
    }

    pub(super) fn preparation_process(&self) -> &NoExecHostProcessWitness {
        &self.preparation_process
    }

    pub(super) fn completion_disposition(&self) -> Option<CompletionDisposition> {
        self.completion_disposition
    }

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        let value = self.to_json();
        serde_json::to_vec(&value).map_err(|_| Error::CleanupFailed)
    }

    fn to_json(&self) -> serde_json::Value {
        let controller = self
            .controller
            .as_ref()
            .map_or(serde_json::Value::Null, |token| {
                serde_json::json!({
                    "pid": token.pid,
                    "pidVersion": token.pidversion,
                    "audit": token.audit,
                    "resource": token.resource,
                    "jetsam": token.jetsam,
                })
            });
        serde_json::json!({
            "version": self.version,
            "state": self.state.as_str(),
            "generationNonce": self.generation_nonce,
            "registrationKey": self.registration_key,
            "ownerUid": self.owner_uid,
            "profileDevice": self.profile_device,
            "profileInode": self.profile_inode,
            "executableDevice": self.executable_device,
            "executableInode": self.executable_inode,
            "executableSize": self.executable_size,
            "executableSha256": self.executable_sha256,
            "signingIdentifier": self.signing_identifier,
            "signingTeamIdentifier": self.signing_team_identifier,
            "signingCodeDirectoryHash": self.signing_code_directory_hash,
            "deadlineNs": self.deadline_ns,
            "preparationProcess": &self.preparation_process,
            "kernelRestartProofSha256": &self.kernel_restart_proof_sha256,
            "completionDisposition": self.completion_disposition.map(|value| value.as_str()),
            "controller": controller,
        })
    }
}

impl GenerationState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "Prepared",
            Self::ControllerReady => "ControllerReady",
            Self::StartCommitted => "StartCommitted",
            Self::Closing => "Closing",
            Self::Cleaned => "Cleaned",
            Self::Unknown => "Unknown",
        }
    }

    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "Prepared" => Ok(Self::Prepared),
            "ControllerReady" => Ok(Self::ControllerReady),
            "StartCommitted" => Ok(Self::StartCommitted),
            "Closing" => Ok(Self::Closing),
            "Cleaned" => Ok(Self::Cleaned),
            "Unknown" => Ok(Self::Unknown),
            _ => Err(Error::CleanupFailed),
        }
    }
}

/// Rootbroker calls this before invoking the launch manager. The returned
/// record is canonical and may be included in a sorted generation-set digest.
pub(super) fn create_prepared(
    registration: &PrivilegedCustodianRegistration,
    generation_directory: &Path,
    generation_nonce: &str,
    deadline_ns: u64,
) -> Result<GenerationRecord, Error> {
    require_root()?;
    let _inventory = inventory_lock()?;
    validate_nonce(generation_nonce)?;
    if deadline_ns == 0 {
        return Err(Error::InvalidArgument);
    }
    let expected_directory = registration
        .state_directory()
        .join(GENERATIONS_DIRECTORY)
        .join(generation_nonce);
    if generation_directory != expected_directory {
        return Err(Error::CleanupFailed);
    }
    let preparation_process =
        NoExecHostProcessWitness::capture_current().map_err(|_| Error::CleanupFailed)?;
    let pins = RegistrationPins::from_registration(registration)?;
    let state_fd = open_directory_path(registration.state_directory(), DIRECTORY_MODE)?;
    let generations_fd = ensure_directory_at(state_fd.as_raw_fd(), GENERATIONS_DIRECTORY)?;
    let staging_fd = ensure_directory_at(state_fd.as_raw_fd(), STAGING_DIRECTORY)?;
    let retired_fd = ensure_directory_at(state_fd.as_raw_fd(), RETIRED_DIRECTORY)?;
    ensure_namespace_capacity(
        &registration.state_directory().join(GENERATIONS_DIRECTORY),
        GENERATION_LIMIT,
        true,
    )?;
    ensure_namespace_capacity(
        &registration.state_directory().join(STAGING_DIRECTORY),
        GENERATION_LIMIT,
        true,
    )?;
    ensure_namespace_capacity(
        &registration.state_directory().join(RETIRED_DIRECTORY),
        GENERATION_LIMIT,
        true,
    )?;
    if directory_exists_at(generations_fd.as_raw_fd(), generation_nonce)?
        || directory_exists_at(staging_fd.as_raw_fd(), generation_nonce)?
        || directory_exists_at(retired_fd.as_raw_fd(), generation_nonce)?
    {
        return Err(Error::CleanupFailed);
    }
    let staging_name = cstr(generation_nonce)?;
    let directory_fd = create_directory_at(staging_fd.as_raw_fd(), generation_nonce)?;
    let lock = create_lock_file(directory_fd.as_raw_fd())?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(Error::CleanupFailed);
    }

    let record = GenerationRecord {
        version: 1,
        state: GenerationState::Prepared,
        generation_nonce: generation_nonce.to_owned(),
        registration_key: pins.registration_key,
        owner_uid: pins.owner_uid,
        profile_device: pins.profile_device,
        profile_inode: pins.profile_inode,
        executable_device: pins.executable_device,
        executable_inode: pins.executable_inode,
        executable_size: pins.executable_size,
        executable_sha256: pins.executable_sha256,
        signing_identifier: pins.signing_identifier,
        signing_team_identifier: pins.signing_team_identifier,
        signing_code_directory_hash: pins.signing_code_directory_hash,
        deadline_ns,
        preparation_process,
        kernel_restart_proof_sha256: None,
        completion_disposition: None,
        controller: None,
    };
    validate_record(&record, registration, generation_nonce, PinPolicy::Exact)?;
    atomic_write(directory_fd.as_raw_fd(), None, &record.canonical_bytes()?)?;
    if unsafe { libc::fsync(directory_fd.as_raw_fd()) } != 0 {
        return Err(Error::CleanupFailed);
    }
    if unsafe {
        libc::renameatx_np(
            staging_fd.as_raw_fd(),
            staging_name.as_ptr(),
            generations_fd.as_raw_fd(),
            staging_name.as_ptr(),
            libc::RENAME_EXCL,
        )
    } != 0
    {
        return Err(Error::CleanupFailed);
    }
    let staging_synced = unsafe { libc::fsync(staging_fd.as_raw_fd()) } == 0;
    let generations_synced = unsafe { libc::fsync(generations_fd.as_raw_fd()) } == 0;
    if !staging_synced || !generations_synced {
        return Err(Error::CleanupFailed);
    }
    Ok(record)
}

/// Claim an already prepared generation. The exclusive nonblocking flock is
/// held for this value's lifetime, preventing a second controller from replaying
/// the generation while rootbroker reads atomic snapshots concurrently.
pub(super) fn claim_controller(
    registration: &PrivilegedCustodianRegistration,
    generation_directory: &Path,
) -> Result<GenerationJournal, Error> {
    require_root()?;
    let _inventory = inventory_lock()?;
    let generation_nonce = generation_directory
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(Error::CleanupFailed)?;
    validate_nonce(generation_nonce)?;
    let (_generations_fd, directory_fd) =
        open_generation_directory(registration, generation_directory, generation_nonce)?;
    let lock = open_lock_file(directory_fd.as_raw_fd())?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(Error::CleanupFailed);
    }
    let record = read_record_at(
        directory_fd.as_raw_fd(),
        registration,
        generation_nonce,
        PinPolicy::Exact,
    )?;
    validate_record(&record, registration, generation_nonce, PinPolicy::Exact)?;
    if record.state != GenerationState::Prepared || record.controller.is_some() {
        return Err(Error::CleanupFailed);
    }
    Ok(GenerationJournal {
        directory: directory_fd,
        _lock: Some(lock),
        record,
    })
}

/// Read a stable atomic snapshot without claiming the controller lock.
pub(super) fn read_record(
    registration: &PrivilegedCustodianRegistration,
    generation_directory: &Path,
) -> Result<GenerationRecord, Error> {
    require_root()?;
    let _inventory = inventory_lock()?;
    read_record_unlocked(registration, generation_directory)
}

fn read_record_unlocked(
    registration: &PrivilegedCustodianRegistration,
    generation_directory: &Path,
) -> Result<GenerationRecord, Error> {
    let generation_nonce = generation_directory
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(Error::CleanupFailed)?;
    validate_nonce(generation_nonce)?;
    let (_generations_fd, directory_fd) =
        open_generation_directory(registration, generation_directory, generation_nonce)?;
    let record = read_record_at(
        directory_fd.as_raw_fd(),
        registration,
        generation_nonce,
        PinPolicy::Historical,
    )?;
    validate_record(
        &record,
        registration,
        generation_nonce,
        PinPolicy::Historical,
    )?;
    Ok(record)
}

/// Convert a pre-reboot generation to a durable cleanup record only when the
/// platform proves a kernel restart for the exact preparation-process witness.
/// The per-generation launch job is never replayed during recovery.
pub(super) fn recover_after_kernel_restart(
    registration: &PrivilegedCustodianRegistration,
    generation_directory: &Path,
) -> Result<GenerationRecord, Error> {
    require_root()?;
    let _inventory = inventory_lock()?;
    let generation_nonce = generation_directory
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(Error::CleanupFailed)?;
    validate_nonce(generation_nonce)?;
    let (_generations_fd, directory_fd) =
        open_generation_directory(registration, generation_directory, generation_nonce)?;
    let lock = open_lock_file(directory_fd.as_raw_fd())?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(Error::CleanupFailed);
    }
    let current = read_record_at(
        directory_fd.as_raw_fd(),
        registration,
        generation_nonce,
        PinPolicy::Historical,
    )?;
    if current.state == GenerationState::Cleaned {
        return Ok(current);
    }
    let witness = current.preparation_process();
    let retirement = witness.verify_retired().map_err(|_| Error::CleanupFailed)?;
    if !retirement.proves_kernel_restart_for(witness) {
        return Err(Error::CleanupFailed);
    }
    let retirement_json = retirement
        .canonical_json()
        .map_err(|_| Error::CleanupFailed)?;
    let mut hasher = Sha256::new();
    hasher.update(b"lomi-terminal-kernel-restart-proof-v1\0");
    hasher.update(retirement_json.as_bytes());
    let proof = hex(&hasher.finalize());

    let mut recovered = current.clone();
    recovered.state = GenerationState::Cleaned;
    recovered.controller = None;
    recovered.kernel_restart_proof_sha256 = Some(proof);
    recovered.completion_disposition = Some(CompletionDisposition::KernelRestart);
    validate_record(
        &recovered,
        registration,
        generation_nonce,
        PinPolicy::Historical,
    )?;
    atomic_write(
        directory_fd.as_raw_fd(),
        Some(&current.canonical_bytes()?),
        &recovered.canonical_bytes()?,
    )?;
    Ok(recovered)
}

/// Read all bounded generation records. Historical pins are exposed for
/// quarantine or kernel-restart recovery; only exact-current Prepared records
/// can be claimed for execution. Any malformed record fails closed.
pub(super) fn list_records(
    registration: &PrivilegedCustodianRegistration,
) -> Result<Vec<GenerationRecord>, Error> {
    require_root()?;
    let _inventory = inventory_lock()?;
    let state_fd = open_directory_path(registration.state_directory(), DIRECTORY_MODE)?;
    let generations_fd = match open_directory_at(state_fd.as_raw_fd(), GENERATIONS_DIRECTORY) {
        Ok(fd) => fd,
        Err(libc::ENOENT) => return Ok(Vec::new()),
        Err(_) => return Err(Error::CleanupFailed),
    };
    secure_directory(generations_fd.as_raw_fd(), DIRECTORY_MODE)?;
    let mut names = namespace_names(generations_fd.as_raw_fd(), GENERATION_LIMIT)?;
    let directory = registration.state_directory().join(GENERATIONS_DIRECTORY);
    names.sort_unstable();
    let mut records = Vec::with_capacity(names.len());
    for name in names {
        records.push(read_record_unlocked(registration, &directory.join(name))?);
    }
    Ok(records)
}

/// Clean staging and retired namespaces during broker startup, while the
/// caller holds the sole broker lease and before accepting any requests.
/// Staging generations cannot have been launched; retired generations were
/// moved only after a Cleaned record and independent job-absence proof.
pub(super) fn recover_auxiliary_storage(
    registration: &PrivilegedCustodianRegistration,
) -> Result<(), Error> {
    require_root()?;
    let _inventory = inventory_lock()?;
    let state_fd = open_directory_path(registration.state_directory(), DIRECTORY_MODE)?;
    recover_auxiliary_namespaces(registration, state_fd.as_raw_fd())
}

/// Remove a Cleaned record after the caller has independently proved its exact
/// per-generation LaunchDaemon job is absent. This also requires the controller
/// lock to be free and exact canonical bytes; Unknown and active records stay.
pub(super) fn remove_cleaned_record(
    registration: &PrivilegedCustodianRegistration,
    generation_nonce: &str,
    expected_canonical_record: &[u8],
) -> Result<(), Error> {
    require_root()?;
    let _inventory = inventory_lock()?;
    validate_nonce(generation_nonce)?;
    let directory = registration
        .state_directory()
        .join(GENERATIONS_DIRECTORY)
        .join(generation_nonce);
    let (generations_fd, generation_fd) =
        open_generation_directory(registration, &directory, generation_nonce)?;
    let lock = open_lock_file(generation_fd.as_raw_fd())?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(Error::CleanupFailed);
    }
    let record = read_record_at(
        generation_fd.as_raw_fd(),
        registration,
        generation_nonce,
        PinPolicy::HistoricalCleaned,
    )?;
    if record.state != GenerationState::Cleaned
        || record.canonical_bytes()? != expected_canonical_record
    {
        return Err(Error::CleanupFailed);
    }
    validate_generation_contents(
        registration,
        generation_fd.as_raw_fd(),
        generation_nonce,
        AuxiliaryKind::LiveCleaned,
    )?;
    let state_fd = open_directory_path(registration.state_directory(), DIRECTORY_MODE)?;
    let retired_fd = ensure_directory_at(state_fd.as_raw_fd(), RETIRED_DIRECTORY)?;
    let retired_path = registration.state_directory().join(RETIRED_DIRECTORY);
    ensure_namespace_capacity(&retired_path, GENERATION_LIMIT, true)?;
    let generation_name = cstr(generation_nonce)?;
    if unsafe {
        libc::renameatx_np(
            generations_fd.as_raw_fd(),
            generation_name.as_ptr(),
            retired_fd.as_raw_fd(),
            generation_name.as_ptr(),
            libc::RENAME_EXCL,
        )
    } != 0
    {
        return Err(Error::CleanupFailed);
    }
    let generations_synced = unsafe { libc::fsync(generations_fd.as_raw_fd()) } == 0;
    let retired_synced = unsafe { libc::fsync(retired_fd.as_raw_fd()) } == 0;
    if !generations_synced || !retired_synced {
        return Err(Error::CleanupFailed);
    }
    cleanup_auxiliary_directory(
        registration,
        &retired_fd,
        generation_nonce,
        AuxiliaryKind::Retired,
    )?;
    Ok(())
}

#[derive(Clone, Copy)]
enum AuxiliaryKind {
    Staging,
    Retired,
    LiveCleaned,
}

fn cleanup_auxiliary_directory(
    registration: &PrivilegedCustodianRegistration,
    parent: &OwnedFd,
    name: &str,
    kind: AuxiliaryKind,
) -> Result<(), Error> {
    validate_nonce(name)?;
    let directory =
        open_directory_at(parent.as_raw_fd(), name).map_err(|_| Error::CleanupFailed)?;
    secure_directory(directory.as_raw_fd(), DIRECTORY_MODE)?;
    let mut leaves = validate_generation_contents(registration, directory.as_raw_fd(), name, kind)?;
    // Staging recovery requires a present record to retain its lock. Remove
    // temps, then the record, and the lock last so interruption stays valid.
    leaves.sort_unstable_by_key(|leaf| {
        if valid_record_temporary(leaf) {
            0
        } else if leaf == RECORD_FILE {
            1
        } else {
            2
        }
    });
    for leaf in leaves {
        let leaf_name = leaf.as_str();
        let leaf_c = cstr(leaf_name)?;
        if unsafe { libc::unlinkat(directory.as_raw_fd(), leaf_c.as_ptr(), 0) } != 0 {
            return Err(Error::CleanupFailed);
        }
        if leaf_name == RECORD_FILE && unsafe { libc::fsync(directory.as_raw_fd()) } != 0 {
            return Err(Error::CleanupFailed);
        }
    }
    if unsafe { libc::fsync(directory.as_raw_fd()) } != 0 {
        return Err(Error::CleanupFailed);
    }
    let name = cstr(name)?;
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0
        || unsafe { libc::fsync(parent.as_raw_fd()) } != 0
    {
        return Err(Error::CleanupFailed);
    }
    Ok(())
}

fn validate_generation_contents(
    registration: &PrivilegedCustodianRegistration,
    directory: RawFd,
    generation_nonce: &str,
    kind: AuxiliaryKind,
) -> Result<Vec<String>, Error> {
    let leaves = leaf_names(directory, AUXILIARY_LEAF_LIMIT)?;
    let mut has_record = false;
    let mut has_lock = false;
    for leaf in &leaves {
        let is_record = leaf == RECORD_FILE;
        let is_lock = leaf == LOCK_FILE;
        if !is_record && !is_lock && !valid_record_temporary(leaf) {
            return Err(Error::CleanupFailed);
        }
        let file = open_auxiliary_file(directory, leaf)?;
        secure_gc_file(file.as_raw_fd())?;
        if is_record {
            has_record = true;
            let record = read_record_at(
                directory,
                registration,
                generation_nonce,
                match kind {
                    AuxiliaryKind::Staging => PinPolicy::Historical,
                    AuxiliaryKind::Retired | AuxiliaryKind::LiveCleaned => {
                        PinPolicy::HistoricalCleaned
                    }
                },
            )?;
            let expected_state = match kind {
                AuxiliaryKind::Staging => GenerationState::Prepared,
                AuxiliaryKind::Retired | AuxiliaryKind::LiveCleaned => GenerationState::Cleaned,
            };
            if record.state != expected_state {
                return Err(Error::CleanupFailed);
            }
        } else if is_lock {
            has_lock = true;
        }
    }
    match kind {
        AuxiliaryKind::Staging if has_record && !has_lock => {
            return Err(Error::CleanupFailed);
        }
        AuxiliaryKind::LiveCleaned if !has_record || !has_lock => {
            return Err(Error::CleanupFailed);
        }
        AuxiliaryKind::Staging | AuxiliaryKind::Retired | AuxiliaryKind::LiveCleaned => {}
    }
    Ok(leaves)
}

fn recover_auxiliary_namespaces(
    registration: &PrivilegedCustodianRegistration,
    state_fd: RawFd,
) -> Result<(), Error> {
    let live = namespace_names_optional(state_fd, GENERATIONS_DIRECTORY)?;
    let staging = namespace_names_optional(state_fd, STAGING_DIRECTORY)?;
    let retired = namespace_names_optional(state_fd, RETIRED_DIRECTORY)?;
    let live_set: std::collections::HashSet<&str> = live
        .as_ref()
        .map(|(_, names)| names.iter().map(String::as_str).collect())
        .unwrap_or_default();
    let mut auxiliary_set = std::collections::HashSet::new();
    for (_, names) in staging.iter().chain(retired.iter()) {
        for name in names {
            if live_set.contains(name.as_str()) || !auxiliary_set.insert(name.as_str()) {
                return Err(Error::CleanupFailed);
            }
        }
    }
    if let Some((parent, names)) = &staging {
        validate_auxiliary_namespace(
            registration,
            parent.as_raw_fd(),
            names,
            AuxiliaryKind::Staging,
        )?;
    }
    if let Some((parent, names)) = &retired {
        validate_auxiliary_namespace(
            registration,
            parent.as_raw_fd(),
            names,
            AuxiliaryKind::Retired,
        )?;
    }
    if let Some((parent, names)) = staging {
        for name in names {
            cleanup_auxiliary_directory(registration, &parent, &name, AuxiliaryKind::Staging)?;
        }
    }
    if let Some((parent, names)) = retired {
        for name in names {
            cleanup_auxiliary_directory(registration, &parent, &name, AuxiliaryKind::Retired)?;
        }
    }
    Ok(())
}

fn validate_auxiliary_namespace(
    registration: &PrivilegedCustodianRegistration,
    parent_fd: RawFd,
    names: &[String],
    kind: AuxiliaryKind,
) -> Result<(), Error> {
    for name in names {
        let directory = open_directory_at(parent_fd, name).map_err(|_| Error::CleanupFailed)?;
        secure_directory(directory.as_raw_fd(), DIRECTORY_MODE)?;
        validate_generation_contents(registration, directory.as_raw_fd(), name, kind)?;
    }
    Ok(())
}

fn namespace_names(parent_fd: RawFd, limit: usize) -> Result<Vec<String>, Error> {
    let names = directory_entry_names(parent_fd, limit)?;
    for name in &names {
        validate_nonce(name)?;
        let child = open_directory_at(parent_fd, name).map_err(|_| Error::CleanupFailed)?;
        secure_directory(child.as_raw_fd(), DIRECTORY_MODE)?;
    }
    Ok(names)
}

fn namespace_names_optional(
    state_fd: RawFd,
    name: &str,
) -> Result<Option<(OwnedFd, Vec<String>)>, Error> {
    let Some(parent) = open_optional_directory_at(state_fd, name)? else {
        return Ok(None);
    };
    let names = namespace_names(parent.as_raw_fd(), GENERATION_LIMIT)?;
    Ok(Some((parent, names)))
}

fn leaf_names(directory: RawFd, limit: usize) -> Result<Vec<String>, Error> {
    directory_entry_names(directory, limit)
}

fn directory_entry_names(directory: RawFd, limit: usize) -> Result<Vec<String>, Error> {
    let fd = unsafe {
        libc::openat(
            directory,
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(Error::CleanupFailed);
    }
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        unsafe { libc::close(fd) };
        return Err(Error::CleanupFailed);
    }
    struct DirectoryStream(*mut libc::DIR);
    impl Drop for DirectoryStream {
        fn drop(&mut self) {
            unsafe { libc::closedir(self.0) };
        }
    }
    let stream = DirectoryStream(stream);
    let mut names = Vec::new();
    loop {
        unsafe { *libc::__error() = 0 };
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            if io::Error::last_os_error().raw_os_error() != Some(0) {
                return Err(Error::CleanupFailed);
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }
            .to_str()
            .map_err(|_| Error::CleanupFailed)?;
        if name == "." || name == ".." {
            continue;
        }
        names.push(name.to_owned());
        if names.len() > limit {
            return Err(Error::CleanupFailed);
        }
    }
    Ok(names)
}

fn valid_record_temporary(name: &str) -> bool {
    let Some(uuid) = name
        .strip_prefix(".record.")
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    Uuid::parse_str(uuid).is_ok_and(|parsed| parsed.to_string() == uuid)
}

fn open_auxiliary_file(directory: RawFd, name: &str) -> Result<OwnedFd, Error> {
    let name = cstr(name)?;
    let fd = unsafe {
        libc::openat(
            directory,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(Error::CleanupFailed);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn secure_gc_file(fd: RawFd) -> Result<(), Error> {
    let stat = fstat(fd)?;
    let mode = (stat.st_mode & 0o777) as u32;
    // An interrupted create may leave a file before fchmod. Accept only a
    // more-restrictive owner-only mode for unlinking; never grant permissions.
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_nlink != 1
        || mode & !FILE_MODE != 0
        || stat.st_mode & (libc::S_ISUID | libc::S_ISGID | libc::S_ISVTX) != 0
    {
        return Err(Error::CleanupFailed);
    }
    reject_acl_grants(fd)
}

/// SHA-256 over canonical Cleaned records sorted by nonce. Length prefixes
/// prevent concatenation ambiguity and make the lifecycle receipt reproducible.
pub(super) fn generation_set_digest(records: &[GenerationRecord]) -> Result<String, Error> {
    if records.len() > GENERATION_LIMIT
        || records
            .iter()
            .any(|record| record.state != GenerationState::Cleaned)
    {
        return Err(Error::CleanupFailed);
    }
    let mut ordered: Vec<&GenerationRecord> = records.iter().collect();
    ordered.sort_unstable_by(|left, right| left.generation_nonce.cmp(&right.generation_nonce));
    if ordered
        .windows(2)
        .any(|pair| pair[0].generation_nonce == pair[1].generation_nonce)
        || ordered
            .windows(2)
            .any(|pair| pair[0].registration_key != pair[1].registration_key)
    {
        return Err(Error::CleanupFailed);
    }
    let mut digest = Sha256::new();
    digest.update(b"lomi-terminal-generation-cleanup-v1\0");
    for record in ordered {
        let bytes = record.canonical_bytes()?;
        let length = u64::try_from(bytes.len()).map_err(|_| Error::CleanupFailed)?;
        digest.update(length.to_be_bytes());
        digest.update(bytes);
    }
    Ok(hex(&digest.finalize()))
}

pub(super) struct GenerationJournal {
    directory: OwnedFd,
    _lock: Option<File>,
    record: GenerationRecord,
}

impl GenerationJournal {
    pub(super) fn record(&self) -> &GenerationRecord {
        &self.record
    }

    /// Caller must hold local proof that this controller has not called
    /// Command::spawn, created a helper, or sent the shell profile to one. The
    /// durable Prepared state is the only state allowed to use this outcome.
    pub(super) fn mark_not_started(&mut self) -> Result<(), Error> {
        if self.record.state != GenerationState::Prepared
            || self.record.controller.is_some()
            || self.record.kernel_restart_proof_sha256.is_some()
        {
            return Err(Error::CleanupFailed);
        }
        let mut next = self.record.clone();
        next.state = GenerationState::Cleaned;
        next.completion_disposition = Some(CompletionDisposition::NotStarted);
        self.persist(next)
    }

    pub(super) fn mark_controller_ready(
        &mut self,
        identity: &capability::Identity,
    ) -> Result<(), Error> {
        if self.record.state != GenerationState::Prepared
            || self.record.controller.is_some()
            || identity.pid() != unsafe { libc::getpid() }
            || identity.audit()[1] != 0
            || identity.audit()[5] as i32 != identity.pid()
            || identity.audit()[7] != identity.pidversion()
        {
            return Err(Error::CleanupFailed);
        }
        let mut next = self.record.clone();
        next.state = GenerationState::ControllerReady;
        next.controller = Some(ControllerIdentity {
            pid: identity.pid(),
            pidversion: identity.pidversion(),
            audit: identity.audit(),
            resource: identity.resource(),
            jetsam: identity.jetsam(),
        });
        self.persist(next)
    }

    /// Persist before sending the child's E commit byte; if that write fails,
    /// neither child nor broker receives commit.
    pub(super) fn mark_start_committed(&mut self) -> Result<(), Error> {
        if self.record.state != GenerationState::ControllerReady || self.record.controller.is_none()
        {
            return Err(Error::CleanupFailed);
        }
        let mut next = self.record.clone();
        next.state = GenerationState::StartCommitted;
        self.persist(next)
    }

    pub(super) fn mark_closing(&mut self) -> Result<(), Error> {
        if !matches!(
            self.record.state,
            GenerationState::ControllerReady | GenerationState::StartCommitted
        ) {
            return Err(Error::CleanupFailed);
        }
        let mut next = self.record.clone();
        next.state = GenerationState::Closing;
        self.persist(next)
    }

    pub(super) fn mark_cleaned(
        &mut self,
        remaining_members: u64,
        direct_child_reaped: bool,
    ) -> Result<(), Error> {
        if self.record.state != GenerationState::Closing
            || self.record.controller.is_none()
            || remaining_members != 0
            || !direct_child_reaped
        {
            return Err(Error::CleanupFailed);
        }
        let mut next = self.record.clone();
        next.state = GenerationState::Cleaned;
        next.completion_disposition = Some(CompletionDisposition::Drained);
        self.persist(next)
    }

    /// Unknown is sticky: it can never be converted to a cleanup certificate.
    pub(super) fn mark_unknown(&mut self) -> Result<(), Error> {
        if self.record.state == GenerationState::Cleaned {
            return Err(Error::CleanupFailed);
        }
        if self.record.state == GenerationState::Unknown {
            return Ok(());
        }
        let mut next = self.record.clone();
        next.state = GenerationState::Unknown;
        self.persist(next)
    }

    fn persist(&mut self, next: GenerationRecord) -> Result<(), Error> {
        require_root()?;
        let lock = self._lock.as_ref().ok_or(Error::CleanupFailed)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Error::CleanupFailed);
        }
        let old = self.record.canonical_bytes()?;
        let new = next.canonical_bytes()?;
        atomic_write(self.directory.as_raw_fd(), Some(&old), &new)?;
        self.record = next;
        Ok(())
    }
}

#[derive(Clone)]
struct RegistrationPins {
    registration_key: String,
    owner_uid: u32,
    profile_device: u64,
    profile_inode: u64,
    executable_device: u64,
    executable_inode: u64,
    executable_size: u64,
    executable_sha256: String,
    signing_identifier: String,
    signing_team_identifier: String,
    signing_code_directory_hash: String,
}

impl RegistrationPins {
    fn from_registration(registration: &PrivilegedCustodianRegistration) -> Result<Self, Error> {
        Ok(Self {
            registration_key: registration.registration_key().to_owned(),
            owner_uid: registration.owner_uid(),
            profile_device: registration.profile_device(),
            profile_inode: registration.profile_inode(),
            executable_device: registration.executable_device(),
            executable_inode: registration.executable_inode(),
            executable_size: registration.executable_size(),
            executable_sha256: registration.executable_sha256().to_owned(),
            signing_identifier: registration.signing_identifier().to_owned(),
            signing_team_identifier: registration.signing_team_identifier().to_owned(),
            signing_code_directory_hash: registration.signing_code_directory_hash().to_owned(),
        })
    }
}

fn validate_record(
    record: &GenerationRecord,
    registration: &PrivilegedCustodianRegistration,
    generation_nonce: &str,
    pin_policy: PinPolicy,
) -> Result<(), Error> {
    let pins = RegistrationPins::from_registration(registration)?;
    validate_nonce(&record.generation_nonce)?;
    if record.version != 1
        || record.generation_nonce != generation_nonce
        || record.registration_key != pins.registration_key
        || record.owner_uid != pins.owner_uid
        || record.owner_uid == 0
        || record.profile_device != pins.profile_device
        || record.profile_device == 0
        || record.profile_inode != pins.profile_inode
        || record.profile_inode == 0
        || record.executable_device == 0
        || record.executable_inode == 0
        || record.executable_size == 0
        || record.signing_identifier != pins.signing_identifier
        || record.signing_team_identifier != pins.signing_team_identifier
        || record.deadline_ns == 0
    {
        return Err(Error::CleanupFailed);
    }
    let state_shape = match record.state {
        GenerationState::Prepared => {
            record.controller.is_none()
                && record.kernel_restart_proof_sha256.is_none()
                && record.completion_disposition.is_none()
        }
        GenerationState::ControllerReady
        | GenerationState::StartCommitted
        | GenerationState::Closing => {
            record.controller.is_some()
                && record.kernel_restart_proof_sha256.is_none()
                && record.completion_disposition.is_none()
        }
        GenerationState::Cleaned => match record.completion_disposition {
            Some(CompletionDisposition::Drained) => {
                record.controller.is_some() && record.kernel_restart_proof_sha256.is_none()
            }
            Some(CompletionDisposition::NotStarted) => {
                record.controller.is_none() && record.kernel_restart_proof_sha256.is_none()
            }
            Some(CompletionDisposition::KernelRestart) => {
                record.controller.is_none() && record.kernel_restart_proof_sha256.is_some()
            }
            None => false,
        },
        GenerationState::Unknown => {
            record.kernel_restart_proof_sha256.is_none() && record.completion_disposition.is_none()
        }
    };
    if !state_shape || record.preparation_process.canonical_json().is_err() {
        return Err(Error::CleanupFailed);
    }
    if let Some(proof) = &record.kernel_restart_proof_sha256 {
        validate_hash(proof, 64)?;
    }
    let exact_executable = record.executable_device == pins.executable_device
        && record.executable_inode == pins.executable_inode
        && record.executable_size == pins.executable_size
        && record.executable_sha256 == pins.executable_sha256
        && record.signing_code_directory_hash == pins.signing_code_directory_hash;
    let historical_allowed = match pin_policy {
        PinPolicy::Exact => false,
        PinPolicy::HistoricalCleaned => record.state == GenerationState::Cleaned,
        PinPolicy::Historical => true,
    };
    if !exact_executable && !historical_allowed {
        return Err(Error::CleanupFailed);
    }
    validate_hash(&record.executable_sha256, 64)?;
    validate_identifier(&record.signing_identifier, 512)?;
    validate_team(&record.signing_team_identifier)?;
    if !matches!(record.signing_code_directory_hash.len(), 40 | 64) {
        return Err(Error::CleanupFailed);
    }
    validate_hash(
        &record.signing_code_directory_hash,
        record.signing_code_directory_hash.len(),
    )?;
    if let Some(controller) = &record.controller {
        if controller.pid <= 0
            || controller.pidversion == 0
            || controller.audit[1] != 0
            || controller.audit[5] as i32 != controller.pid
            || controller.audit[7] != controller.pidversion
            || controller.resource == 0
            || controller.jetsam == 0
        {
            return Err(Error::CleanupFailed);
        }
    }
    Ok(())
}

fn parse_record(
    bytes: &[u8],
    registration: &PrivilegedCustodianRegistration,
    generation_nonce: &str,
    pin_policy: PinPolicy,
) -> Result<GenerationRecord, Error> {
    if bytes.is_empty() || bytes.len() > RECORD_LIMIT {
        return Err(Error::CleanupFailed);
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| Error::CleanupFailed)?;
    let object = exact_object(
        &value,
        &[
            "version",
            "state",
            "generationNonce",
            "registrationKey",
            "ownerUid",
            "profileDevice",
            "profileInode",
            "executableDevice",
            "executableInode",
            "executableSize",
            "executableSha256",
            "signingIdentifier",
            "signingTeamIdentifier",
            "signingCodeDirectoryHash",
            "deadlineNs",
            "preparationProcess",
            "kernelRestartProofSha256",
            "completionDisposition",
            "controller",
        ],
    )?;
    let controller = match object.get("controller").ok_or(Error::CleanupFailed)? {
        serde_json::Value::Null => None,
        value => {
            let token = exact_object(value, &["pid", "pidVersion", "audit", "resource", "jetsam"])?;
            let audit_value = token
                .get("audit")
                .and_then(serde_json::Value::as_array)
                .filter(|values| values.len() == 8)
                .ok_or(Error::CleanupFailed)?;
            let mut audit = [0; 8];
            for (target, value) in audit.iter_mut().zip(audit_value) {
                *target = value
                    .as_u64()
                    .and_then(|number| u32::try_from(number).ok())
                    .ok_or(Error::CleanupFailed)?;
            }
            Some(ControllerIdentity {
                pid: number_i32(token, "pid")?,
                pidversion: number_u32(token, "pidVersion")?,
                audit,
                resource: number_u64(token, "resource")?,
                jetsam: number_u64(token, "jetsam")?,
            })
        }
    };
    let record = GenerationRecord {
        version: number_u8(object, "version")?,
        state: GenerationState::parse(&string(object, "state")?)?,
        generation_nonce: string(object, "generationNonce")?,
        registration_key: string(object, "registrationKey")?,
        owner_uid: number_u32(object, "ownerUid")?,
        profile_device: number_u64(object, "profileDevice")?,
        profile_inode: number_u64(object, "profileInode")?,
        executable_device: number_u64(object, "executableDevice")?,
        executable_inode: number_u64(object, "executableInode")?,
        executable_size: number_u64(object, "executableSize")?,
        executable_sha256: string(object, "executableSha256")?,
        signing_identifier: string(object, "signingIdentifier")?,
        signing_team_identifier: string(object, "signingTeamIdentifier")?,
        signing_code_directory_hash: string(object, "signingCodeDirectoryHash")?,
        deadline_ns: number_u64(object, "deadlineNs")?,
        preparation_process: serde_json::from_value(
            object
                .get("preparationProcess")
                .ok_or(Error::CleanupFailed)?
                .clone(),
        )
        .map_err(|_| Error::CleanupFailed)?,
        kernel_restart_proof_sha256: match object
            .get("kernelRestartProofSha256")
            .ok_or(Error::CleanupFailed)?
        {
            serde_json::Value::Null => None,
            value => Some(value.as_str().ok_or(Error::CleanupFailed)?.to_owned()),
        },
        completion_disposition: match object
            .get("completionDisposition")
            .ok_or(Error::CleanupFailed)?
        {
            serde_json::Value::Null => None,
            value => Some(CompletionDisposition::parse(
                value.as_str().ok_or(Error::CleanupFailed)?,
            )?),
        },
        controller,
    };
    validate_record(&record, registration, generation_nonce, pin_policy)?;
    if record.canonical_bytes()? != bytes {
        return Err(Error::CleanupFailed);
    }
    Ok(record)
}

fn open_generation_directory(
    registration: &PrivilegedCustodianRegistration,
    generation_directory: &Path,
    generation_nonce: &str,
) -> Result<(OwnedFd, OwnedFd), Error> {
    validate_nonce(generation_nonce)?;
    let state_path = registration.state_directory();
    let expected = state_path
        .join(GENERATIONS_DIRECTORY)
        .join(generation_nonce);
    if generation_directory != expected {
        return Err(Error::CleanupFailed);
    }
    let state_fd = open_directory_path(state_path, DIRECTORY_MODE)?;
    let generations_fd = open_directory_at(state_fd.as_raw_fd(), GENERATIONS_DIRECTORY)
        .map_err(|_| Error::CleanupFailed)?;
    secure_directory(generations_fd.as_raw_fd(), DIRECTORY_MODE)?;
    let generation_fd = open_directory_at(generations_fd.as_raw_fd(), generation_nonce)
        .map_err(|_| Error::CleanupFailed)?;
    secure_directory(generation_fd.as_raw_fd(), DIRECTORY_MODE)?;
    Ok((generations_fd, generation_fd))
}

fn open_directory_path(path: &Path, mode: u32) -> Result<OwnedFd, Error> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::CleanupFailed)?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(Error::CleanupFailed);
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    secure_directory(fd.as_raw_fd(), mode)?;
    Ok(fd)
}

fn open_directory_at(parent: RawFd, name: &str) -> Result<OwnedFd, i32> {
    let name = CString::new(name).map_err(|_| libc::EINVAL)?;
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO))
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn open_optional_directory_at(parent: RawFd, name: &str) -> Result<Option<OwnedFd>, Error> {
    match open_directory_at(parent, name) {
        Ok(directory) => {
            secure_directory(directory.as_raw_fd(), DIRECTORY_MODE)?;
            Ok(Some(directory))
        }
        Err(libc::ENOENT) => Ok(None),
        Err(_) => Err(Error::CleanupFailed),
    }
}

fn ensure_directory_at(parent: RawFd, name: &str) -> Result<OwnedFd, Error> {
    match open_directory_at(parent, name) {
        Ok(directory) => {
            secure_directory(directory.as_raw_fd(), DIRECTORY_MODE)?;
            Ok(directory)
        }
        Err(libc::ENOENT) => {
            let name_c = cstr(name)?;
            if unsafe { libc::mkdirat(parent, name_c.as_ptr(), DIRECTORY_MODE as _) } != 0 {
                return Err(Error::CleanupFailed);
            }
            let directory = open_directory_at(parent, name).map_err(|_| Error::CleanupFailed)?;
            if unsafe { libc::fchown(directory.as_raw_fd(), 0, 0) } != 0
                || unsafe { libc::fchmod(directory.as_raw_fd(), DIRECTORY_MODE as _) } != 0
            {
                return Err(Error::CleanupFailed);
            }
            secure_directory(directory.as_raw_fd(), DIRECTORY_MODE)?;
            if unsafe { libc::fsync(parent) } != 0 {
                return Err(Error::CleanupFailed);
            }
            Ok(directory)
        }
        Err(_) => Err(Error::CleanupFailed),
    }
}

fn create_directory_at(parent: RawFd, name: &str) -> Result<OwnedFd, Error> {
    let name_c = cstr(name)?;
    if unsafe { libc::mkdirat(parent, name_c.as_ptr(), DIRECTORY_MODE as _) } != 0 {
        return Err(Error::CleanupFailed);
    }
    let directory = open_directory_at(parent, name).map_err(|_| Error::CleanupFailed)?;
    if unsafe { libc::fchown(directory.as_raw_fd(), 0, 0) } != 0
        || unsafe { libc::fchmod(directory.as_raw_fd(), DIRECTORY_MODE as _) } != 0
    {
        return Err(Error::CleanupFailed);
    }
    secure_directory(directory.as_raw_fd(), DIRECTORY_MODE)?;
    if unsafe { libc::fsync(parent) } != 0 {
        return Err(Error::CleanupFailed);
    }
    Ok(directory)
}

fn directory_exists_at(parent: RawFd, name: &str) -> Result<bool, Error> {
    let name = cstr(name)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(false)
        } else {
            Err(Error::CleanupFailed)
        };
    }
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(Error::CleanupFailed);
    }
    Ok(true)
}

fn ensure_namespace_capacity(
    path: &Path,
    limit: usize,
    reject_at_limit: bool,
) -> Result<(), Error> {
    let parent = open_directory_path(path, DIRECTORY_MODE)?;
    let names = namespace_names(parent.as_raw_fd(), limit)?;
    if reject_at_limit && names.len() >= limit {
        return Err(Error::CleanupFailed);
    }
    Ok(())
}

fn secure_directory(fd: RawFd, expected_mode: u32) -> Result<(), Error> {
    let stat = fstat(fd)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || stat.st_uid != 0
        || stat.st_gid != 0
        || (stat.st_mode & 0o777) as u32 != expected_mode
        || stat.st_mode & (libc::S_ISUID | libc::S_ISGID | libc::S_ISVTX) != 0
    {
        return Err(Error::CleanupFailed);
    }
    reject_acl_grants(fd)?;
    Ok(())
}

fn create_lock_file(directory: RawFd) -> Result<File, Error> {
    let name = cstr(LOCK_FILE)?;
    let fd = unsafe {
        libc::openat(
            directory,
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            FILE_MODE as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(Error::CleanupFailed);
    }
    let file = unsafe { File::from_raw_fd(fd) };
    if unsafe { libc::fchown(file.as_raw_fd(), 0, 0) } != 0
        || unsafe { libc::fchmod(file.as_raw_fd(), FILE_MODE as libc::mode_t) } != 0
    {
        return Err(Error::CleanupFailed);
    }
    secure_file(file.as_raw_fd(), FILE_MODE)?;
    if unsafe { libc::fsync(file.as_raw_fd()) } != 0 || unsafe { libc::fsync(directory) } != 0 {
        return Err(Error::CleanupFailed);
    }
    Ok(file)
}

fn open_lock_file(directory: RawFd) -> Result<File, Error> {
    let name = cstr(LOCK_FILE)?;
    let fd = unsafe {
        libc::openat(
            directory,
            name.as_ptr(),
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(Error::CleanupFailed);
    }
    let file = unsafe { File::from_raw_fd(fd) };
    secure_file(file.as_raw_fd(), FILE_MODE)?;
    Ok(file)
}

fn secure_file(fd: RawFd, expected_mode: u32) -> Result<(), Error> {
    let stat = fstat(fd)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_nlink != 1
        || (stat.st_mode & 0o777) as u32 != expected_mode
        || stat.st_mode & (libc::S_ISUID | libc::S_ISGID | libc::S_ISVTX) != 0
    {
        return Err(Error::CleanupFailed);
    }
    reject_acl_grants(fd)?;
    Ok(())
}

fn reject_acl_grants(fd: RawFd) -> Result<(), Error> {
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(Error::CleanupFailed);
    }
    let file = unsafe { File::from_raw_fd(duplicate) };
    lomi_platform::unix::reject_acl_grants_readonly(&file).map_err(|_| Error::CleanupFailed)
}

fn read_record_at(
    directory: RawFd,
    registration: &PrivilegedCustodianRegistration,
    generation_nonce: &str,
    pin_policy: PinPolicy,
) -> Result<GenerationRecord, Error> {
    let name = cstr(RECORD_FILE)?;
    let fd = unsafe {
        libc::openat(
            directory,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(Error::CleanupFailed);
    }
    let file = unsafe { File::from_raw_fd(fd) };
    secure_file(file.as_raw_fd(), FILE_MODE)?;
    let metadata = file.metadata().map_err(|_| Error::CleanupFailed)?;
    if metadata.len() == 0 || metadata.len() > RECORD_LIMIT as u64 {
        return Err(Error::CleanupFailed);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((RECORD_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::CleanupFailed)?;
    if bytes.len() != metadata.len() as usize {
        return Err(Error::CleanupFailed);
    }
    parse_record(&bytes, registration, generation_nonce, pin_policy)
}

fn atomic_write(directory: RawFd, expected_old: Option<&[u8]>, new: &[u8]) -> Result<(), Error> {
    if new.is_empty() || new.len() > RECORD_LIMIT {
        return Err(Error::CleanupFailed);
    }
    let existing = read_raw_record(directory)?;
    match (expected_old, existing.as_deref()) {
        (None, None) => {}
        (Some(expected), Some(actual)) if expected == actual => {}
        _ => return Err(Error::CleanupFailed),
    }
    let temporary = format!(".record.{}.tmp", Uuid::new_v4());
    let temporary_c = cstr(&temporary)?;
    let file = unsafe {
        libc::openat(
            directory,
            temporary_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            FILE_MODE as libc::c_uint,
        )
    };
    if file < 0 {
        return Err(Error::CleanupFailed);
    }
    let file = unsafe { OwnedFd::from_raw_fd(file) };
    let result = (|| {
        if unsafe { libc::fchown(file.as_raw_fd(), 0, 0) } != 0
            || unsafe { libc::fchmod(file.as_raw_fd(), FILE_MODE as _) } != 0
        {
            return Err(Error::CleanupFailed);
        }
        secure_file(file.as_raw_fd(), FILE_MODE)?;
        write_all(file.as_raw_fd(), new)?;
        if unsafe { libc::fsync(file.as_raw_fd()) } != 0 {
            return Err(Error::CleanupFailed);
        }
        let target = cstr(RECORD_FILE)?;
        if unsafe { libc::renameat(directory, temporary_c.as_ptr(), directory, target.as_ptr()) }
            != 0
        {
            return Err(Error::CleanupFailed);
        }
        if unsafe { libc::fsync(directory) } != 0 {
            return Err(Error::CleanupFailed);
        }
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(directory, temporary_c.as_ptr(), 0);
        }
    }
    result
}

fn read_raw_record(directory: RawFd) -> Result<Option<Vec<u8>>, Error> {
    let name = cstr(RECORD_FILE)?;
    let fd = unsafe {
        libc::openat(
            directory,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(Error::CleanupFailed)
        };
    }
    let file = unsafe { File::from_raw_fd(fd) };
    secure_file(file.as_raw_fd(), FILE_MODE)?;
    let metadata = file.metadata().map_err(|_| Error::CleanupFailed)?;
    if metadata.len() == 0 || metadata.len() > RECORD_LIMIT as u64 {
        return Err(Error::CleanupFailed);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((RECORD_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::CleanupFailed)?;
    if bytes.len() != metadata.len() as usize {
        return Err(Error::CleanupFailed);
    }
    Ok(Some(bytes))
}

fn write_all(fd: RawFd, bytes: &[u8]) -> Result<(), Error> {
    let mut offset = 0;
    while offset < bytes.len() {
        let written =
            unsafe { libc::write(fd, bytes[offset..].as_ptr().cast(), bytes.len() - offset) };
        if written > 0 {
            offset += written as usize;
            continue;
        }
        if written < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(Error::CleanupFailed);
    }
    Ok(())
}

fn fstat(fd: RawFd) -> Result<libc::stat, Error> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(Error::CleanupFailed);
    }
    Ok(unsafe { stat.assume_init() })
}

fn exact_object<'a>(
    value: &'a serde_json::Value,
    fields: &[&str],
) -> Result<&'a serde_json::Map<String, serde_json::Value>, Error> {
    let object = value.as_object().ok_or(Error::CleanupFailed)?;
    if object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err(Error::CleanupFailed);
    }
    Ok(object)
}

fn string(
    object: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<String, Error> {
    object
        .get(name)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or(Error::CleanupFailed)
}

fn number_u64(
    object: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<u64, Error> {
    object
        .get(name)
        .and_then(serde_json::Value::as_u64)
        .ok_or(Error::CleanupFailed)
}

fn number_u32(
    object: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<u32, Error> {
    u32::try_from(number_u64(object, name)?).map_err(|_| Error::CleanupFailed)
}

fn number_u8(object: &serde_json::Map<String, serde_json::Value>, name: &str) -> Result<u8, Error> {
    u8::try_from(number_u64(object, name)?).map_err(|_| Error::CleanupFailed)
}

fn number_i32(
    object: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<i32, Error> {
    object
        .get(name)
        .and_then(serde_json::Value::as_i64)
        .and_then(|number| i32::try_from(number).ok())
        .ok_or(Error::CleanupFailed)
}

fn validate_nonce(nonce: &str) -> Result<(), Error> {
    if nonce.len() != 36
        || nonce.as_bytes()[8] != b'-'
        || nonce.as_bytes()[13] != b'-'
        || nonce.as_bytes()[18] != b'-'
        || nonce.as_bytes()[23] != b'-'
        || !nonce
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 8 | 13 | 18 | 23) || byte.is_ascii_hexdigit())
        || nonce.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(Error::CleanupFailed);
    }
    let parsed = Uuid::parse_str(nonce).map_err(|_| Error::CleanupFailed)?;
    if parsed.to_string() != nonce {
        return Err(Error::CleanupFailed);
    }
    Ok(())
}

fn validate_hash(value: &str, length: usize) -> Result<(), Error> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::CleanupFailed);
    }
    Ok(())
}

fn validate_identifier(value: &str, max: usize) -> Result<(), Error> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(Error::CleanupFailed);
    }
    Ok(())
}

fn validate_team(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(Error::CleanupFailed);
    }
    Ok(())
}

fn cstr(value: &str) -> Result<CString, Error> {
    CString::new(value).map_err(|_| Error::CleanupFailed)
}

fn require_root() -> Result<(), Error> {
    if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0 {
        return Err(Error::CleanupFailed);
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}
