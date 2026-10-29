//! Root-owned cleanup receipt shared by the broker and updater barrier.
//! No process absence, timeout, or missing control channel proves cleanup.
use super::*;
use crate::noexec_process::NoExecHostProcessWitness;

const DRAIN_FILE: &str = "drained.json";
const GENERATIONS: &str = "generations";
const GENERATION_LIMIT: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DrainDisk {
    version: u8,
    registration_key: String,
    owner_uid: u32,
    profile_device: u64,
    profile_inode: u64,
    executable_sha256: String,
    runtime_id: String,
    request_id: String,
    drained_generation_count: u32,
    drained_set_sha256: String,
}

pub struct PrivilegedCustodianDrainReceipt {
    disk: DrainDisk,
}
impl PrivilegedCustodianDrainReceipt {
    pub fn runtime_id(&self) -> &str {
        &self.disk.runtime_id
    }
    pub fn request_id(&self) -> &str {
        &self.disk.request_id
    }
    pub fn drained_generation_count(&self) -> u32 {
        self.disk.drained_generation_count
    }
    pub fn drained_set_sha256(&self) -> &str {
        &self.disk.drained_set_sha256
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenerationDisk {
    version: u8,
    state: String,
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
    controller: Option<ControllerDisk>,
    preparation_process: NoExecHostProcessWitness,
    kernel_restart_proof_sha256: Option<String>,
    completion_disposition: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ControllerDisk {
    pid: i32,
    pid_version: u32,
    audit: [u32; 8],
    resource: u64,
    jetsam: u64,
}

fn canonical_uuid(text: &str) -> bool {
    uuid::Uuid::parse_str(text).is_ok_and(|uuid| !uuid.is_nil() && uuid.to_string() == text)
}

fn validate_cleaned(
    bytes: &[u8],
    nonce: &str,
    registration: &PrivilegedCustodianRegistration,
) -> Result<()> {
    let record: GenerationDisk = serde_json::from_slice(bytes).map_err(|_| Error::Conflict)?;
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| Error::Conflict)?;
    if serde_json::to_vec(&value).map_err(|_| Error::Conflict)? != bytes
        || record.version != 1
        || record.state != "Cleaned"
        || !canonical_uuid(nonce)
        || record.generation_nonce != nonce
        || record.registration_key != registration.registration_key()
        || record.owner_uid != registration.owner_uid()
        || record.profile_device != registration.profile_device()
        || record.profile_inode != registration.profile_inode()
        || record.executable_device == 0
        || record.executable_inode == 0
        || record.executable_size == 0
        || record.executable_size > MAX_EXECUTABLE_BYTES
        || !valid_lower_hex(&record.executable_sha256, 32)
        || record.signing_identifier != registration.signing_identifier()
        || record.signing_team_identifier != registration.signing_team_identifier()
        || !(valid_lower_hex(&record.signing_code_directory_hash, 20)
            || valid_lower_hex(&record.signing_code_directory_hash, 32))
        || record.deadline_ns == 0
        || record.preparation_process.canonical_json().is_err()
    {
        return Err(Error::Conflict);
    }
    match record.completion_disposition.as_deref() {
        Some("drained")
            if record.controller.is_some() && record.kernel_restart_proof_sha256.is_none() => {}
        Some("notStarted")
            if record.controller.is_none() && record.kernel_restart_proof_sha256.is_none() => {}
        Some("kernelRestart")
            if record.controller.is_none() && record.kernel_restart_proof_sha256.is_some() => {}
        _ => return Err(Error::Conflict),
    }
    if let Some(controller) = record.controller {
        if controller.pid <= 0
            || controller.pid_version == 0
            || controller.audit[1] != 0
            || controller.audit[5] as i32 != controller.pid
            || controller.audit[7] != controller.pid_version
            || controller.resource == 0
            || controller.jetsam == 0
        {
            return Err(Error::Conflict);
        }
    }
    if let Some(proof_sha) = record.kernel_restart_proof_sha256 {
        if !valid_lower_hex(&proof_sha, 32)
            || !record
                .preparation_process
                .verify_retired()
                .is_ok_and(|proof| proof.proves_kernel_restart_for(&record.preparation_process))
        {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}

fn open_generation(parent: &Directory, nonce: &str) -> Result<Directory> {
    if !canonical_uuid(nonce) {
        return Err(Error::Conflict);
    }
    let name = c(OsStr::new(nonce))?;
    let fd = unsafe {
        libc::openat(
            parent.0.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(Error::Conflict);
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|_| Error::Conflict)?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != STATE_MODE
    {
        return Err(Error::Conflict);
    }
    crate::unix::reject_acl_grants(&file).map_err(|_| Error::Conflict)?;
    Ok(Directory(file))
}

fn cleaned_inventory(registration: &PrivilegedCustodianRegistration) -> Result<(u32, String)> {
    let generations = Directory::open_optional_root(
        &registration.state_directory().join(GENERATIONS),
        Some(STATE_MODE),
    )?;
    let mut digest = Sha256::new();
    digest.update(b"lomi-terminal-generation-cleanup-v1\0");
    let Some(generations) = generations else {
        return Ok((0, hex(&digest.finalize())));
    };
    let names = generations.names()?;
    if names.len() > GENERATION_LIMIT {
        return Err(Error::Conflict);
    }
    for nonce in &names {
        let generation = open_generation(&generations, nonce)?;
        let bytes = generation.read("record.json")?.ok_or(Error::Conflict)?;
        validate_cleaned(&bytes, nonce, registration)?;
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(&bytes);
    }
    if generations.names()? != names {
        return Err(Error::Conflict);
    }
    Ok((
        u32::try_from(names.len()).map_err(|_| Error::Conflict)?,
        hex(&digest.finalize()),
    ))
}

fn validate_receipt(
    registration: &PrivilegedCustodianRegistration,
    disk: &DrainDisk,
) -> Result<()> {
    if disk.version != 1
        || disk.registration_key != registration.registration_key()
        || disk.owner_uid != registration.owner_uid()
        || disk.profile_device != registration.profile_device()
        || disk.profile_inode != registration.profile_inode()
        || disk.executable_sha256 != registration.executable_sha256()
        || !canonical_uuid(&disk.runtime_id)
        || !canonical_uuid(&disk.request_id)
        || disk.drained_generation_count as usize > GENERATION_LIMIT
        || !valid_lower_hex(&disk.drained_set_sha256, 32)
    {
        return Err(Error::Conflict);
    }
    if cleaned_inventory(registration)?
        != (
            disk.drained_generation_count,
            disk.drained_set_sha256.clone(),
        )
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// The broker closes admission and joins every cleanup before this named write.
/// The write independently rejects every unclean/unknown generation and is
/// idempotent over one exact root-owned inventory.
pub fn write_privileged_custodian_drain_receipt(
    registration: &PrivilegedCustodianRegistration,
    runtime_id: &str,
    request_id: &str,
) -> Result<PrivilegedCustodianDrainReceipt> {
    require_root()?;
    validate_registration_disk(&registration.disk, true)?;
    write_receipt(registration, runtime_id, request_id)
}

pub(super) fn write_offline_receipt(
    registration: &PrivilegedCustodianRegistration,
) -> Result<PrivilegedCustodianDrainReceipt> {
    require_root()?;
    validate_registration_maintenance(&registration.disk)?;
    write_receipt(
        registration,
        &uuid::Uuid::new_v4().to_string(),
        &uuid::Uuid::new_v4().to_string(),
    )
}

fn write_receipt(
    registration: &PrivilegedCustodianRegistration,
    runtime_id: &str,
    request_id: &str,
) -> Result<PrivilegedCustodianDrainReceipt> {
    if !canonical_uuid(runtime_id) || !canonical_uuid(request_id) {
        return Err(Error::Invalid);
    }
    let (count, hash) = cleaned_inventory(registration)?;
    let disk = DrainDisk {
        version: 1,
        registration_key: registration.registration_key().to_owned(),
        owner_uid: registration.owner_uid(),
        profile_device: registration.profile_device(),
        profile_inode: registration.profile_inode(),
        executable_sha256: registration.executable_sha256().to_owned(),
        runtime_id: runtime_id.to_owned(),
        request_id: request_id.to_owned(),
        drained_generation_count: count,
        drained_set_sha256: hash,
    };
    let state = Directory::open(registration.state_directory(), Some(STATE_MODE), None)?;
    let bytes = serde_json::to_vec(&disk).map_err(|_| Error::Invalid)?;
    match state.read(DRAIN_FILE)? {
        Some(current) if current == bytes => {}
        Some(current) => state.replace_exact(DRAIN_FILE, &current, &bytes)?,
        None => state.publish(DRAIN_FILE, &bytes)?,
    }
    validate_receipt(registration, &disk)?;
    Ok(PrivilegedCustodianDrainReceipt { disk })
}

/// Also works during interrupted image activation: metadata and cleanup remain
/// pinned to the old registration, while its executable may already differ.
pub fn verify_privileged_custodian_drained(
    registration: &PrivilegedCustodianRegistration,
) -> Result<PrivilegedCustodianDrainReceipt> {
    require_root()?;
    validate_registration_maintenance(&registration.disk)?;
    let state = Directory::open(registration.state_directory(), Some(STATE_MODE), None)?;
    let bytes = state.read(DRAIN_FILE)?.ok_or(Error::Conflict)?;
    let disk: DrainDisk = serde_json::from_slice(&bytes).map_err(|_| Error::Conflict)?;
    validate_receipt(registration, &disk)?;
    Ok(PrivilegedCustodianDrainReceipt { disk })
}

pub(super) fn verify_uninstalled(
    registration: &PrivilegedCustodianRegistration,
    expected_sha256: &str,
) -> Result<()> {
    require_root()?;
    let state = Directory::open(registration.state_directory(), Some(STATE_MODE), None)?;
    let bytes = state.read(DRAIN_FILE)?.ok_or(Error::Conflict)?;
    if format!("{:x}", Sha256::digest(&bytes)) != expected_sha256 {
        return Err(Error::Conflict);
    }
    let disk: DrainDisk = serde_json::from_slice(&bytes).map_err(|_| Error::Conflict)?;
    validate_receipt(registration, &disk)
}
