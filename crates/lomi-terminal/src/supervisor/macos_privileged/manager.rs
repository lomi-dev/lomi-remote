//! Root-owned per-generation launchd jobs. Labels and plists are derived only
//! from the validated custody registration and canonical generation nonce.

use super::{Error, journal, wire};
use lomi_platform::{
    process,
    service_macos::custody::{self, PrivilegedCustodianRegistration},
    unix,
};
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt, process::CommandExt},
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::Duration,
};
use uuid::Uuid;

const LAUNCH_DAEMONS: &str = "/Library/LaunchDaemons";
const GENERATIONS_DIRECTORY: &str = "generations";
const FILE_MODE: u32 = 0o600;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PLIST_LIMIT: usize = 16 * 1024;
const MANAGER_OUTPUT_LIMIT: usize = 32 * 1024;
const QUERY_WINDOW: Duration = Duration::from_secs(3);
const COMMAND_CLEANUP_WINDOW: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const CONTROLLER_ARGUMENT: &str = "--internal-privileged-pty-controller";

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileId {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LeafIdentity {
    id: FileId,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
}

struct PinnedDirectory {
    path: PathBuf,
    handle: File,
    identity: FileId,
    final_mode: Option<u32>,
}

impl PinnedDirectory {
    fn open(path: &Path, final_mode: Option<u32>) -> Result<Self> {
        if !path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err(Error::InvalidArgument);
        }
        let root = File::open("/").map_err(|_| Error::CleanupFailed)?;
        validate_directory(&root, None)?;
        let mut current = root;
        let components: Vec<_> = path.components().skip(1).collect();
        for (index, component) in components.iter().enumerate() {
            let Component::Normal(name) = component else {
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
            let is_final = index + 1 == components.len();
            validate_directory(&next, if is_final { final_mode } else { None })?;
            current = next;
        }
        if path.canonicalize().map_err(|_| Error::CleanupFailed)? != path {
            return Err(Error::CleanupFailed);
        }
        let identity = file_id(&current.metadata().map_err(|_| Error::CleanupFailed)?);
        Ok(Self {
            path: path.to_path_buf(),
            handle: current,
            identity,
            final_mode,
        })
    }

    fn validate(&self) -> Result<()> {
        validate_directory(&self.handle, self.final_mode)?;
        if file_id(&self.handle.metadata().map_err(|_| Error::CleanupFailed)?) != self.identity {
            return Err(Error::CleanupFailed);
        }
        let current = Self::open(&self.path, self.final_mode)?;
        if current.identity != self.identity {
            return Err(Error::CleanupFailed);
        }
        Ok(())
    }

    fn sync(&self) -> Result<()> {
        self.handle.sync_all().map_err(|_| Error::CleanupFailed)
    }
}

fn validate_directory(file: &File, final_mode: Option<u32>) -> Result<()> {
    let metadata = file.metadata().map_err(|_| Error::CleanupFailed)?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || final_mode.is_some_and(|mode| metadata.mode() & 0o7777 != mode)
        || final_mode.is_some() && metadata.gid() != 0
    {
        return Err(Error::CleanupFailed);
    }
    unix::reject_acl_grants_readonly(file).map_err(|_| Error::CleanupFailed)
}

fn file_id(metadata: &std::fs::Metadata) -> FileId {
    FileId {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn leaf_identity(metadata: &std::fs::Metadata) -> LeafIdentity {
    LeafIdentity {
        id: file_id(metadata),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode(),
        links: metadata.nlink(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RegistrationBinding {
    registration_key: String,
    owner_uid: u32,
    owner_gid: u32,
    profile_path: PathBuf,
    profile_device: u64,
    profile_inode: u64,
    executable_path: PathBuf,
    executable_device: u64,
    executable_inode: u64,
    executable_size: u64,
    executable_sha256: String,
    signing_identifier: String,
    signing_team_identifier: String,
    signing_code_directory_hash: String,
    registration_path: PathBuf,
    state_directory: PathBuf,
    launch_daemon_label: String,
    launch_daemon_plist_path: PathBuf,
}

impl RegistrationBinding {
    fn from_registration(registration: &PrivilegedCustodianRegistration) -> Self {
        Self {
            registration_key: registration.registration_key().to_owned(),
            owner_uid: registration.owner_uid(),
            owner_gid: registration.owner_gid(),
            profile_path: registration.profile_path().to_path_buf(),
            profile_device: registration.profile_device(),
            profile_inode: registration.profile_inode(),
            executable_path: registration.executable_path().to_path_buf(),
            executable_device: registration.executable_device(),
            executable_inode: registration.executable_inode(),
            executable_size: registration.executable_size(),
            executable_sha256: registration.executable_sha256().to_owned(),
            signing_identifier: registration.signing_identifier().to_owned(),
            signing_team_identifier: registration.signing_team_identifier().to_owned(),
            signing_code_directory_hash: registration.signing_code_directory_hash().to_owned(),
            registration_path: registration.registration_path().to_path_buf(),
            state_directory: registration.state_directory().to_path_buf(),
            launch_daemon_label: registration.launch_daemon_label().to_owned(),
            launch_daemon_plist_path: registration.launch_daemon_plist_path(),
        }
    }

    fn load_current(&self) -> Result<PrivilegedCustodianRegistration> {
        let current = custody::load_privileged_custodian(&self.registration_path)
            .map_err(|_| Error::CleanupFailed)?;
        if *self != Self::from_registration(&current) {
            return Err(Error::CleanupFailed);
        }
        Ok(current)
    }

    fn require_current(&self, registration: &PrivilegedCustodianRegistration) -> Result<()> {
        if *self != Self::from_registration(registration) {
            return Err(Error::CleanupFailed);
        }
        self.load_current().map(|_| ())
    }
}

/// One exact launchd generation. Only a fresh value from [`prepare`] may make
/// its single bootstrap attempt; values reconstructed during recovery are
/// observation/cleanup-only.
pub(super) struct GenerationJob {
    registration: RegistrationBinding,
    nonce: String,
    generation_path: PathBuf,
    generation_directory: PinnedDirectory,
    launch_daemons: PinnedDirectory,
    label: String,
    plist_name: CString,
    plist_path: PathBuf,
    plist_bytes: Vec<u8>,
    plist_identity: Option<LeafIdentity>,
    prepared_record: Option<Vec<u8>>,
    bootstrap_allowed: bool,
}

impl GenerationJob {
    pub(super) fn label(&self) -> &str {
        &self.label
    }

    pub(super) fn plist_path(&self) -> &Path {
        &self.plist_path
    }

    /// Make exactly one launchctl bootstrap attempt under the request's
    /// original Mach-continuous deadline. After the manager command is spawned,
    /// every error is an uncertain start and can never be retried for this
    /// generation.
    pub(super) fn bootstrap(&mut self, deadline_ns: u64) -> Result<()> {
        if !self.bootstrap_allowed {
            return Err(Error::SpawnOutcomeUnknown);
        }
        self.bootstrap_allowed = false;
        if unsafe { libc::geteuid() } != 0 || deadline_ns == 0 {
            return Err(Error::SpawnFailed);
        }
        let now = wire::mach_now_ns().map_err(|_| Error::SpawnFailed)?;
        if now >= deadline_ns {
            return Err(Error::SpawnFailed);
        }
        let registration = self.registration.load_current()?;
        self.generation_directory.validate()?;
        self.launch_daemons.validate()?;
        self.validate_plist()?;
        let prepared_bytes = self
            .prepared_record
            .as_deref()
            .ok_or(Error::SpawnOutcomeUnknown)?;
        let record = journal::read_record(&registration, &self.generation_path)?;
        if record.state() != journal::GenerationState::Prepared
            || record.canonical_bytes()? != prepared_bytes
            || !record_matches_registration(&record, &registration)?
        {
            return Err(Error::SpawnOutcomeUnknown);
        }
        let target = format!("system/{}", self.label);
        let observed = observe_job(
            &target,
            &self.plist_path,
            &registration.executable_path(),
            &registration.registration_path(),
            &self.generation_path,
            deadline_ns,
        )
        .map_err(|_| Error::SpawnOutcomeUnknown)?;
        if observed.is_some() {
            return Err(Error::SpawnOutcomeUnknown);
        }
        self.generation_directory.validate()?;
        self.launch_daemons.validate()?;
        self.validate_plist()?;
        let path = self.plist_path.to_str().ok_or(Error::SpawnFailed)?;
        let result = run_launchctl(&["bootstrap", "system", path], deadline_ns);
        let output = match result {
            Ok(output) => output,
            Err(Error::SpawnFailed) => return Err(Error::SpawnFailed),
            Err(_) => return Err(Error::SpawnOutcomeUnknown),
        };
        if output.status != 0 || !output.stdout.is_empty() || !output.stderr.is_empty() {
            return Err(Error::SpawnOutcomeUnknown);
        }
        loop {
            match observe_job(
                &target,
                &self.plist_path,
                registration.executable_path(),
                registration.registration_path(),
                &self.generation_path,
                deadline_ns,
            ) {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => {}
                Err(_) => return Err(Error::SpawnOutcomeUnknown),
            }
            if wire::mach_now_ns().map_or(true, |now| now >= deadline_ns) {
                return Err(Error::SpawnOutcomeUnknown);
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn validate_plist(&self) -> Result<()> {
        let Some((bytes, identity)) = read_regular(&self.launch_daemons, &self.plist_name)? else {
            return Err(Error::CleanupFailed);
        };
        if bytes != self.plist_bytes || Some(identity) != self.plist_identity {
            return Err(Error::CleanupFailed);
        }
        Ok(())
    }
}

/// Create a new exact plist for an already-durable Prepared journal record.
/// Existing manager jobs or plist files are conflicts; they are never adopted.
pub(super) fn prepare(
    registration: &PrivilegedCustodianRegistration,
    nonce: &str,
    generation_directory: &Path,
) -> Result<GenerationJob> {
    prepare_until(
        registration,
        nonce,
        generation_directory,
        deadline_after(QUERY_WINDOW)?,
    )
}

pub(super) fn prepare_until(
    registration: &PrivilegedCustodianRegistration,
    nonce: &str,
    generation_directory: &Path,
    deadline_ns: u64,
) -> Result<GenerationJob> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(Error::InvalidArgument);
    }
    if deadline_ns == 0 || wire::mach_now_ns()? >= deadline_ns {
        return Err(Error::SpawnFailed);
    }
    validate_nonce(nonce)?;
    let binding = RegistrationBinding::from_registration(registration);
    binding.require_current(registration)?;
    let generation_path = expected_generation_path(registration, nonce)?;
    if generation_directory != generation_path {
        return Err(Error::InvalidArgument);
    }
    let generation = PinnedDirectory::open(generation_directory, Some(PRIVATE_DIRECTORY_MODE))?;
    let records = journal::list_records(registration)?;
    if records.len() > 64
        || records
            .iter()
            .filter(|record| record.generation_nonce() == nonce)
            .count()
            != 1
    {
        return Err(Error::CleanupFailed);
    }
    let record = journal::read_record(registration, generation_directory)?;
    if record.state() != journal::GenerationState::Prepared
        || record.registration_key() != registration.registration_key()
        || record.generation_nonce() != nonce
        || !record_matches_registration(&record, registration)?
    {
        return Err(Error::CleanupFailed);
    }
    let launch_daemons = PinnedDirectory::open(Path::new(LAUNCH_DAEMONS), None)?;
    let (label, plist_name, plist_path, plist_bytes) =
        job_definition(registration, nonce, generation_directory)?;
    if observe_job(
        &format!("system/{label}"),
        &plist_path,
        registration.executable_path(),
        registration.registration_path(),
        generation_directory,
        deadline_ns,
    )?
    .is_some()
    {
        return Err(Error::CleanupFailed);
    }
    if read_regular(&launch_daemons, &plist_name)?.is_some() {
        return Err(Error::CleanupFailed);
    }
    launch_daemons.validate()?;
    generation.validate()?;
    let plist_identity = publish_new(&launch_daemons, &plist_name, &plist_bytes)?;
    let job = GenerationJob {
        registration: binding,
        nonce: nonce.to_owned(),
        generation_path,
        generation_directory: generation,
        launch_daemons,
        label,
        plist_name,
        plist_path,
        plist_bytes,
        plist_identity: Some(plist_identity),
        prepared_record: Some(record.canonical_bytes()?),
        bootstrap_allowed: true,
    };
    job.validate_plist()?;
    Ok(job)
}

/// Reconstruct a generation for exact manager observation and cleanup only.
/// Historical Cleaned records may be garbage-collected after the root image
/// changes; active records retain their original executable pins in the journal.
pub(super) fn from_record(
    registration: &PrivilegedCustodianRegistration,
    nonce: &str,
    generation_directory: &Path,
) -> Result<GenerationJob> {
    from_record_until(
        registration,
        nonce,
        generation_directory,
        deadline_after(QUERY_WINDOW)?,
    )
}

pub(super) fn from_record_until(
    registration: &PrivilegedCustodianRegistration,
    nonce: &str,
    generation_directory: &Path,
    deadline_ns: u64,
) -> Result<GenerationJob> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(Error::InvalidArgument);
    }
    if deadline_ns == 0 || wire::mach_now_ns()? >= deadline_ns {
        return Err(Error::SpawnFailed);
    }
    validate_nonce(nonce)?;
    let binding = RegistrationBinding::from_registration(registration);
    binding.require_current(registration)?;
    let generation_path = expected_generation_path(registration, nonce)?;
    if generation_directory != generation_path {
        return Err(Error::InvalidArgument);
    }
    let generation = PinnedDirectory::open(generation_directory, Some(PRIVATE_DIRECTORY_MODE))?;
    let records = journal::list_records(registration)?;
    if records.len() > 64
        || records
            .iter()
            .filter(|record| record.generation_nonce() == nonce)
            .count()
            != 1
    {
        return Err(Error::CleanupFailed);
    }
    let record = journal::read_record(registration, generation_directory)?;
    if record.registration_key() != registration.registration_key()
        || record.generation_nonce() != nonce
    {
        return Err(Error::CleanupFailed);
    }
    let launch_daemons = PinnedDirectory::open(Path::new(LAUNCH_DAEMONS), None)?;
    let (label, plist_name, plist_path, plist_bytes) =
        job_definition(registration, nonce, generation_directory)?;
    let plist_identity = match read_regular(&launch_daemons, &plist_name)? {
        Some((bytes, identity)) if bytes == plist_bytes => Some(identity),
        None if record.state() == journal::GenerationState::Cleaned => None,
        _ => return Err(Error::CleanupFailed),
    };
    let observed = observe_job(
        &format!("system/{label}"),
        &plist_path,
        registration.executable_path(),
        registration.registration_path(),
        generation_directory,
        deadline_ns,
    )?;
    if plist_identity.is_none() && observed.is_some() {
        return Err(Error::CleanupFailed);
    }
    let job = GenerationJob {
        registration: binding,
        nonce: nonce.to_owned(),
        generation_path,
        generation_directory: generation,
        launch_daemons,
        label,
        plist_name,
        plist_path,
        plist_bytes,
        plist_identity,
        prepared_record: None,
        bootstrap_allowed: false,
    };
    job.generation_directory.validate()?;
    job.launch_daemons.validate()?;
    Ok(job)
}

/// Boot out and remove only a journal-authenticated Cleaned generation. The
/// supplied deadline is shared by the caller across its complete inventory.
pub(super) fn bootout_cleaned(
    registration: &PrivilegedCustodianRegistration,
    job: &mut GenerationJob,
    expected_cleaned_record: &journal::GenerationRecord,
    deadline_ns: u64,
) -> Result<()> {
    if unsafe { libc::geteuid() } != 0
        || expected_cleaned_record.state() != journal::GenerationState::Cleaned
        || expected_cleaned_record.generation_nonce() != job.nonce
        || expected_cleaned_record.registration_key() != registration.registration_key()
    {
        return Err(Error::CleanupFailed);
    }
    job.registration.require_current(registration)?;
    job.generation_directory.validate()?;
    job.launch_daemons.validate()?;
    let actual = journal::read_record(registration, &job.generation_path)?;
    if actual.canonical_bytes()? != expected_cleaned_record.canonical_bytes()? {
        return Err(Error::CleanupFailed);
    }
    match (
        job.plist_identity,
        read_regular(&job.launch_daemons, &job.plist_name)?,
    ) {
        (Some(expected), Some((bytes, identity)))
            if bytes == job.plist_bytes && identity == expected => {}
        (None, None) => {}
        _ => return Err(Error::CleanupFailed),
    }
    let target = format!("system/{}", job.label);
    let observed = observe_job(
        &target,
        &job.plist_path,
        registration.executable_path(),
        registration.registration_path(),
        &job.generation_path,
        deadline_ns,
    )?;
    if observed.is_some() {
        // One bootout call only. Its acknowledgement can be lost after launchd
        // acted, so manager absence is the only completion criterion.
        let target_arg = target.as_str();
        let _ = run_launchctl(&["bootout", target_arg], deadline_ns);
    }
    loop {
        if observe_job(
            &target,
            &job.plist_path,
            registration.executable_path(),
            registration.registration_path(),
            &job.generation_path,
            deadline_ns,
        )?
        .is_none()
        {
            break;
        }
        if wire::mach_now_ns().map_or(true, |now| now >= deadline_ns) {
            return Err(Error::CleanupFailed);
        }
        thread::sleep(POLL_INTERVAL);
    }
    job.generation_directory.validate()?;
    job.launch_daemons.validate()?;
    let actual = journal::read_record(registration, &job.generation_path)?;
    if actual.canonical_bytes()? != expected_cleaned_record.canonical_bytes()? {
        return Err(Error::CleanupFailed);
    }
    if let Some(identity) = job.plist_identity {
        remove_exact(
            &job.launch_daemons,
            &job.plist_name,
            &job.plist_bytes,
            identity,
        )?;
        job.plist_identity = None;
    } else if read_regular(&job.launch_daemons, &job.plist_name)?.is_some() {
        return Err(Error::CleanupFailed);
    }
    Ok(())
}

fn expected_generation_path(
    registration: &PrivilegedCustodianRegistration,
    nonce: &str,
) -> Result<PathBuf> {
    let path = registration
        .state_directory()
        .join(GENERATIONS_DIRECTORY)
        .join(nonce);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(Error::InvalidArgument);
    }
    Ok(path)
}

fn validate_nonce(nonce: &str) -> Result<()> {
    let uuid = Uuid::parse_str(nonce).map_err(|_| Error::InvalidArgument)?;
    if uuid.is_nil() || uuid.to_string() != nonce {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

fn record_matches_registration(
    record: &journal::GenerationRecord,
    registration: &PrivilegedCustodianRegistration,
) -> Result<bool> {
    let bytes = record.canonical_bytes()?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| Error::CleanupFailed)?;
    Ok(
        value["registrationKey"].as_str() == Some(registration.registration_key())
            && value["ownerUid"].as_u64() == Some(u64::from(registration.owner_uid()))
            && value["profileDevice"].as_u64() == Some(registration.profile_device())
            && value["profileInode"].as_u64() == Some(registration.profile_inode())
            && value["executableDevice"].as_u64() == Some(registration.executable_device())
            && value["executableInode"].as_u64() == Some(registration.executable_inode())
            && value["executableSize"].as_u64() == Some(registration.executable_size())
            && value["executableSha256"].as_str() == Some(registration.executable_sha256())
            && value["signingIdentifier"].as_str() == Some(registration.signing_identifier())
            && value["signingTeamIdentifier"].as_str()
                == Some(registration.signing_team_identifier())
            && value["signingCodeDirectoryHash"].as_str()
                == Some(registration.signing_code_directory_hash()),
    )
}

fn job_definition(
    registration: &PrivilegedCustodianRegistration,
    nonce: &str,
    generation_directory: &Path,
) -> Result<(String, CString, PathBuf, Vec<u8>)> {
    let label = format!(
        "dev.lomi.remote.privileged-pty.{}.{}",
        registration.owner_uid(),
        nonce
    );
    let plist_name = cstring(OsStr::new(&format!("{label}.plist")))?;
    let plist_path = Path::new(LAUNCH_DAEMONS).join(format!("{label}.plist"));
    if plist_path.parent() != Some(Path::new(LAUNCH_DAEMONS))
        || plist_path.file_name() != Some(OsStr::new(&format!("{label}.plist")))
    {
        return Err(Error::CleanupFailed);
    }
    let values = [
        registration
            .executable_path()
            .to_str()
            .ok_or(Error::InvalidArgument)?,
        registration
            .registration_path()
            .to_str()
            .ok_or(Error::InvalidArgument)?,
        generation_directory
            .to_str()
            .ok_or(Error::InvalidArgument)?,
    ];
    let escaped = values
        .iter()
        .map(|value| xml(value))
        .collect::<Result<Vec<_>>>()?;
    let label_xml = xml(&label)?;
    let bytes = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>Label</key><string>{label_xml}</string><key>ProgramArguments</key><array><string>{}</string><string>{CONTROLLER_ARGUMENT}</string><string>{}</string><string>{}</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><false/><key>UserName</key><string>root</string><key>GroupName</key><string>wheel</string><key>Umask</key><integer>63</integer><key>WorkingDirectory</key><string>/</string><key>EnvironmentVariables</key><dict><key>LC_ALL</key><string>C</string><key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin</string></dict><key>StandardOutPath</key><string>/dev/null</string><key>StandardErrorPath</key><string>/dev/null</string></dict></plist>",
        escaped[0], escaped[1], escaped[2]
    )
    .into_bytes();
    if bytes.is_empty() || bytes.len() > PLIST_LIMIT {
        return Err(Error::InvalidArgument);
    }
    Ok((label, plist_name, plist_path, bytes))
}

fn xml(value: &str) -> Result<String> {
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(Error::InvalidArgument);
    }
    Ok(value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;"))
}

fn cstring(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| Error::InvalidArgument)
}

fn read_regular(
    directory: &PinnedDirectory,
    name: &CString,
) -> Result<Option<(Vec<u8>, LeafIdentity)>> {
    let fd = unsafe {
        libc::openat(
            directory.handle.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(Error::CleanupFailed)
        };
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let before = file.metadata().map_err(|_| Error::CleanupFailed)?;
    validate_regular_metadata(&before)?;
    if before.len() > PLIST_LIMIT as u64 {
        return Err(Error::CleanupFailed);
    }
    let identity = leaf_identity(&before);
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take((PLIST_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::CleanupFailed)?;
    if bytes.len() > PLIST_LIMIT {
        return Err(Error::CleanupFailed);
    }
    let after = file.metadata().map_err(|_| Error::CleanupFailed)?;
    if leaf_identity(&after) != identity
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(Error::CleanupFailed);
    }
    unix::reject_acl_grants_readonly(&file).map_err(|_| Error::CleanupFailed)?;
    Ok(Some((bytes, identity)))
}

fn validate_regular_metadata(metadata: &std::fs::Metadata) -> Result<()> {
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != FILE_MODE
    {
        return Err(Error::CleanupFailed);
    }
    Ok(())
}

fn publish_new(directory: &PinnedDirectory, name: &CString, bytes: &[u8]) -> Result<LeafIdentity> {
    let temporary = format!(".lomi-pty-generation-{}.tmp", Uuid::new_v4());
    let temporary = cstring(OsStr::new(&temporary))?;
    let destination = fstatat(directory, name)?;
    if destination.is_some() {
        return Err(Error::CleanupFailed);
    }
    let fd = unsafe {
        libc::openat(
            directory.handle.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            FILE_MODE as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(Error::CleanupFailed);
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let created = file.metadata().map_err(|_| Error::CleanupFailed)?;
    let created_id = file_id(&created);
    let mut temporary_guard = TemporaryLeaf {
        directory,
        name: temporary.clone(),
        identity: created_id,
        armed: true,
    };
    if !created.is_file() || created.uid() != 0 || created.nlink() != 1 {
        return Err(Error::CleanupFailed);
    }
    if unsafe { libc::fchmod(file.as_raw_fd(), FILE_MODE as libc::mode_t) } != 0 {
        return Err(Error::CleanupFailed);
    }
    unix::reject_acl_grants_readonly(&file).map_err(|_| Error::CleanupFailed)?;
    file.write_all(bytes).map_err(|_| Error::CleanupFailed)?;
    file.sync_all().map_err(|_| Error::CleanupFailed)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| Error::CleanupFailed)?;
    let mut staged = Vec::with_capacity(bytes.len());
    (&mut file)
        .take((PLIST_LIMIT + 1) as u64)
        .read_to_end(&mut staged)
        .map_err(|_| Error::CleanupFailed)?;
    if staged != bytes {
        return Err(Error::CleanupFailed);
    }
    let after_write = file.metadata().map_err(|_| Error::CleanupFailed)?;
    validate_regular_metadata(&after_write)?;
    let written_identity = leaf_identity(&after_write);
    if written_identity.id != created_id {
        return Err(Error::CleanupFailed);
    }
    directory.validate()?;
    if fstatat(directory, name)?.is_some() {
        return Err(Error::CleanupFailed);
    }
    if unsafe {
        libc::renameatx_np(
            directory.handle.as_raw_fd(),
            temporary.as_ptr(),
            directory.handle.as_raw_fd(),
            name.as_ptr(),
            libc::RENAME_EXCL,
        )
    } != 0
    {
        return Err(Error::CleanupFailed);
    }
    temporary_guard.armed = false;
    directory.sync()?;
    let (published, identity) = read_regular(directory, name)?.ok_or(Error::CleanupFailed)?;
    if published != bytes || identity != written_identity {
        return Err(Error::CleanupFailed);
    }
    Ok(identity)
}

struct TemporaryLeaf<'a> {
    directory: &'a PinnedDirectory,
    name: CString,
    identity: FileId,
    armed: bool,
}

impl Drop for TemporaryLeaf<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if fstatat_identity(self.directory, &self.name).ok().flatten() == Some(self.identity) {
            unsafe {
                libc::unlinkat(self.directory.handle.as_raw_fd(), self.name.as_ptr(), 0);
                libc::fsync(self.directory.handle.as_raw_fd());
            }
        }
    }
}

fn fstatat_identity(directory: &PinnedDirectory, name: &CString) -> Result<Option<FileId>> {
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            directory.handle.as_raw_fd(),
            name.as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
            || metadata.st_uid != 0
            || metadata.st_nlink != 1
        {
            return Err(Error::CleanupFailed);
        }
        return Ok(Some(FileId {
            device: metadata.st_dev as u64,
            inode: metadata.st_ino as u64,
        }));
    }
    if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        Ok(None)
    } else {
        Err(Error::CleanupFailed)
    }
}

fn fstatat(directory: &PinnedDirectory, name: &CString) -> Result<Option<LeafIdentity>> {
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            directory.handle.as_raw_fd(),
            name.as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
            || metadata.st_uid != 0
            || metadata.st_gid != 0
            || metadata.st_nlink != 1
            || metadata.st_mode as u32 & 0o7777 != FILE_MODE
        {
            return Err(Error::CleanupFailed);
        }
        return Ok(Some(LeafIdentity {
            id: FileId {
                device: metadata.st_dev as u64,
                inode: metadata.st_ino as u64,
            },
            uid: metadata.st_uid,
            gid: metadata.st_gid,
            mode: metadata.st_mode as u32,
            links: metadata.st_nlink as u64,
        }));
    }
    if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        Ok(None)
    } else {
        Err(Error::CleanupFailed)
    }
}

fn remove_exact(
    directory: &PinnedDirectory,
    name: &CString,
    expected_bytes: &[u8],
    expected_identity: LeafIdentity,
) -> Result<()> {
    let (bytes, identity) = read_regular(directory, name)?.ok_or(Error::CleanupFailed)?;
    if bytes != expected_bytes || identity != expected_identity {
        return Err(Error::CleanupFailed);
    }
    directory.validate()?;
    if fstatat(directory, name)? != Some(expected_identity) {
        return Err(Error::CleanupFailed);
    }
    if unsafe { libc::unlinkat(directory.handle.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(Error::CleanupFailed);
    }
    directory.sync()?;
    if fstatat(directory, name)?.is_some() {
        return Err(Error::CleanupFailed);
    }
    Ok(())
}

#[derive(Debug)]
struct ManagerOutput {
    status: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn deadline_after(duration: Duration) -> Result<u64> {
    wire::mach_now_ns()?
        .checked_add(u64::try_from(duration.as_nanos()).map_err(|_| Error::InvalidArgument)?)
        .ok_or(Error::InvalidArgument)
}

fn run_launchctl(arguments: &[&str], deadline_ns: u64) -> Result<ManagerOutput> {
    if deadline_ns == 0 || wire::mach_now_ns().map_err(|_| Error::SpawnFailed)? >= deadline_ns {
        return Err(Error::SpawnFailed);
    }
    process::require_child_ownership().map_err(|_| Error::SpawnFailed)?;
    let mut command = Command::new("/bin/launchctl");
    command
        .args(arguments)
        .current_dir("/")
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn().map_err(|_| Error::SpawnFailed)?;
    let mut reaped = false;
    let result = (|| {
        let mut stdout = child.stdout.take().ok_or(Error::CleanupFailed)?;
        let mut stderr = child.stderr.take().ok_or(Error::CleanupFailed)?;
        for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                return Err(Error::CleanupFailed);
            }
        }
        let mut output = Vec::new();
        let mut errors = Vec::new();
        loop {
            read_available(&mut stdout, &mut output)?;
            read_available(&mut stderr, &mut errors)?;
            if output.len() > MANAGER_OUTPUT_LIMIT || errors.len() > MANAGER_OUTPUT_LIMIT {
                return Err(Error::CleanupFailed);
            }
            if let Some(status) = child.try_wait().map_err(|_| Error::CleanupFailed)? {
                reaped = true;
                drain_available(&mut stdout, &mut output)?;
                drain_available(&mut stderr, &mut errors)?;
                if output.len() > MANAGER_OUTPUT_LIMIT || errors.len() > MANAGER_OUTPUT_LIMIT {
                    return Err(Error::CleanupFailed);
                }
                return Ok(ManagerOutput {
                    status: status.code().unwrap_or(-1),
                    stdout: output,
                    stderr: errors,
                });
            }
            if wire::mach_now_ns().map_err(|_| Error::CleanupFailed)? >= deadline_ns {
                return Err(Error::CleanupFailed);
            }
            thread::sleep(POLL_INTERVAL);
        }
    })();
    if !reaped {
        if process::require_unreaped_child(&child).is_err() {
            return Err(Error::CleanupFailed);
        }
        unsafe {
            libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
        }
        let cleanup_deadline = deadline_after(COMMAND_CLEANUP_WINDOW).unwrap_or(deadline_ns);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if wire::mach_now_ns().is_ok_and(|now| now < cleanup_deadline) => {
                    thread::sleep(POLL_INTERVAL);
                }
                _ => return Err(Error::CleanupFailed),
            }
        }
    }
    result
}

fn read_available(reader: &mut impl Read, destination: &mut Vec<u8>) -> Result<()> {
    let mut buffer = [0u8; 4096];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(count) => {
                destination.extend_from_slice(&buffer[..count]);
                if destination.len() > MANAGER_OUTPUT_LIMIT {
                    return Err(Error::CleanupFailed);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::CleanupFailed),
        }
    }
}

fn drain_available(reader: &mut impl Read, destination: &mut Vec<u8>) -> Result<()> {
    let mut buffer = [0u8; 4096];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(count) => {
                destination.extend_from_slice(&buffer[..count]);
                if destination.len() > MANAGER_OUTPUT_LIMIT {
                    return Err(Error::CleanupFailed);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::CleanupFailed),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ManagerObservation;

fn observe_job(
    target: &str,
    plist_path: &Path,
    executable: &Path,
    registration_path: &Path,
    generation_path: &Path,
    deadline_ns: u64,
) -> Result<Option<ManagerObservation>> {
    let output = run_launchctl(&["print", target], deadline_ns)?;
    if output.status == 113 {
        if !output.stdout.is_empty() {
            return Err(Error::CleanupFailed);
        }
        return Ok(None);
    }
    if output.status != 0 || !output.stderr.is_empty() {
        return Err(Error::CleanupFailed);
    }
    let text = std::str::from_utf8(&output.stdout).map_err(|_| Error::CleanupFailed)?;
    parse_observation(
        text,
        target,
        plist_path,
        executable,
        registration_path,
        generation_path,
    )
    .map(Some)
}

fn parse_observation(
    text: &str,
    target: &str,
    plist_path: &Path,
    executable: &Path,
    registration_path: &Path,
    generation_path: &Path,
) -> Result<ManagerObservation> {
    let plist = plist_path.to_str().ok_or(Error::CleanupFailed)?;
    let executable = executable.to_str().ok_or(Error::CleanupFailed)?;
    let registration = registration_path.to_str().ok_or(Error::CleanupFailed)?;
    let generation = generation_path.to_str().ok_or(Error::CleanupFailed)?;
    if text.lines().last() != Some("}")
        || text
            .lines()
            .skip(1)
            .any(|line| !line.is_empty() && !line.starts_with('\t') && line != "}")
    {
        return Err(Error::CleanupFailed);
    }
    let mut lines = text.lines();
    if lines.next() != Some(format!("{target} = {{").as_str()) {
        return Err(Error::CleanupFailed);
    }
    let (mut seen_path, mut seen_program, mut seen_arguments, mut seen_state, mut seen_pid) =
        (false, false, false, false, false);
    let mut state = None;
    let mut pid = None;
    while let Some(line) = lines.next() {
        if line.starts_with("\t\t") {
            continue;
        }
        if let Some(value) = line.strip_prefix("\tpath = ") {
            if seen_path || value != plist {
                return Err(Error::CleanupFailed);
            }
            seen_path = true;
        } else if let Some(value) = line.strip_prefix("\tprogram = ") {
            if seen_program || value != executable {
                return Err(Error::CleanupFailed);
            }
            seen_program = true;
        } else if line == "\targuments = {" {
            if seen_arguments {
                return Err(Error::CleanupFailed);
            }
            seen_arguments = true;
            for argument in [executable, CONTROLLER_ARGUMENT, registration, generation] {
                let wanted = format!("\t\t{argument}");
                if lines.next() != Some(wanted.as_str()) {
                    return Err(Error::CleanupFailed);
                }
            }
            if lines.next() != Some("\t}") {
                return Err(Error::CleanupFailed);
            }
        } else if let Some(value) = line.strip_prefix("\tstate = ") {
            if seen_state
                || !matches!(
                    value,
                    "running" | "not running" | "waiting" | "spawn scheduled" | "SIGTERMed"
                )
            {
                return Err(Error::CleanupFailed);
            }
            seen_state = true;
            state = Some(value);
        } else if let Some(value) = line.strip_prefix("\tpid = ") {
            if seen_pid || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(Error::CleanupFailed);
            }
            seen_pid = true;
            let parsed = value.parse::<u32>().map_err(|_| Error::CleanupFailed)?;
            if parsed == 0 || parsed > i32::MAX as u32 {
                return Err(Error::CleanupFailed);
            }
            pid = Some(parsed);
        }
    }
    let running = state == Some("running");
    if !seen_path
        || !seen_program
        || !seen_arguments
        || !seen_state
        || seen_pid != pid.is_some()
        || running != pid.is_some()
    {
        return Err(Error::CleanupFailed);
    }
    Ok(ManagerObservation)
}
