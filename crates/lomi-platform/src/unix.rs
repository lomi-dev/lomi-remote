pub(crate) mod diagnostics;
#[cfg(target_os = "macos")]
pub mod keychain;
#[cfg(target_os = "linux")]
pub mod secret_service;
pub mod secrets;
pub(crate) mod setup_journal;
use lomi_remote_protocol::{
    HostId, LocalIpcVersion, RequestId, RuntimeId,
    ipc::{
        self, AuthenticatedLocalPeer, IpcNonce, IpcProfileId, LocalCall, LocalClientHello,
        LocalHelloProbe, LocalOsOwner, LocalRequest, LocalResponse, LocalServerHello,
        TrustedLocalPeerAdapter,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use uuid::Uuid;

const SOCKET: &str = "host.sock";
const DISCOVERY: &str = "discovery.json";
const DISCOVERY_LIMIT: u64 = 4096;
const HOST_INIT_RECEIPT: &str = "host-init.json";
const HOST_INIT_RECEIPT_TEMP: &str = "host-init.tmp";
const HOST_INIT_RECEIPT_LIMIT: u64 = 16 * 1024;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Errors have a closed display vocabulary, safe for CLI diagnostics.
#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    InvalidProfile,
    Busy,
    InvalidEndpoint,
    PermissionDenied,
    InvalidFrame,
    Incompatible,
    Deadline,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Io(_) => "LOCAL_IO_ERROR",
            Self::InvalidProfile => "INVALID_PROFILE",
            Self::Busy => "HOST_BUSY",
            Self::InvalidEndpoint => "INVALID_ENDPOINT",
            Self::PermissionDenied => "LOCAL_PERMISSION_DENIED",
            Self::InvalidFrame => "INVALID_LOCAL_FRAME",
            Self::Incompatible => "UPDATE_REQUIRED",
            Self::Deadline => "LOCAL_DEADLINE",
        })
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
pub type Result<T> = std::result::Result<T, Error>;

/// Nanoseconds on the machine-wide monotonic clock. Unlike `Instant`, this
/// representation may be passed to a child process on the same boot to keep
/// one operation deadline across a privilege/account transition.
pub fn monotonic_nanos() -> Result<u64> {
    let mut value = std::mem::MaybeUninit::<libc::timespec>::uninit();
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, value.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let value = unsafe { value.assume_init() };
    let seconds = u64::try_from(value.tv_sec).map_err(|_| Error::Deadline)?;
    let nanos = u64::try_from(value.tv_nsec).map_err(|_| Error::Deadline)?;
    if nanos >= 1_000_000_000 {
        return Err(Error::Deadline);
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|total| total.checked_add(nanos))
        .ok_or(Error::Deadline)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Object {
    device: u64,
    inode: u64,
}
fn object(m: &fs::Metadata) -> Object {
    Object {
        device: m.dev(),
        inode: m.ino(),
    }
}
fn uid() -> u32 {
    unsafe { libc::geteuid() }
}
fn private_regular(file: &File) -> Result<()> {
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != uid() || m.mode() & 0o777 != 0o600 || m.nlink() != 1 {
        return Err(Error::InvalidProfile);
    }
    reject_acl_grants(file)?;
    Ok(())
}

// Darwin mode bits do not account for extended ACL grants. Deny entries may
// safely restrict access further; accept no extended allow entry in this trust
// boundary, including on ancestors. Symbols/constants are from sys/acl.h.
#[cfg(target_os = "macos")]
pub(crate) fn reject_acl_grants(file: &File) -> Result<()> {
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
        return if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(())
        } else {
            Err(Error::InvalidProfile)
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
            return if io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                Ok(())
            } else {
                Err(Error::InvalidProfile)
            };
        }
        let mut tag = 0;
        if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 || tag != 2 {
            // KAUTH_ACE_DENY is 2; unknown tags also fail closed.
            return Err(Error::InvalidProfile);
        }
        selector = -1;
    }
}
/// On macOS, reject inherited or explicit ACL grants on a file already opened
/// by the caller. Other Unix targets retain their existing mode checks. This
/// read-only check uses the held descriptor rather than reopening a pathname.
pub fn reject_acl_grants_readonly(file: &File) -> Result<()> {
    reject_acl_grants(file)
}
#[cfg(not(target_os = "macos"))]
pub(crate) fn reject_acl_grants(_file: &File) -> Result<()> {
    Ok(())
}
fn trusted_directory(file: &File, final_component: bool) -> Result<()> {
    let m = file.metadata()?;
    if !m.is_dir() || (m.uid() != uid() && m.uid() != 0) {
        return Err(Error::InvalidProfile);
    }
    if final_component {
        if m.uid() != uid() || m.mode() & 0o777 != 0o700 {
            return Err(Error::InvalidProfile);
        }
    } else if m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0 {
        return Err(Error::InvalidProfile);
    }
    reject_acl_grants(file)
}

fn open_directory_chain(path: &Path, create: bool) -> Result<File> {
    let parts: Vec<_> = path.components().collect();
    if parts.first() != Some(&std::path::Component::RootDir) || parts.len() < 2 {
        return Err(Error::InvalidProfile);
    }
    let mut directory = File::open("/")?;
    trusted_directory(&directory, false)?;
    for (index, component) in parts.iter().enumerate().skip(1) {
        let std::path::Component::Normal(name) = component else {
            return Err(Error::InvalidProfile);
        };
        let name =
            std::ffi::CString::new(name.as_encoded_bytes()).map_err(|_| Error::InvalidProfile)?;
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let mut fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 && create && io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
            if unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) } != 0
                && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
            {
                return Err(io::Error::last_os_error().into());
            }
            fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        }
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let next = unsafe { File::from_raw_fd(fd) };
        trusted_directory(&next, index + 1 == parts.len())?;
        directory = next;
    }
    Ok(directory)
}
fn open_regular(path: &Path, create: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(create)
        .create(create)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    private_regular(&file)?;
    Ok(file)
}

/// An owner-private, fixed-name input file for a local native editor save.
/// The operation ID, not a caller-selected path, determines the filename.
pub struct NativeEditorStageFile {
    path: PathBuf,
    file: File,
}
impl NativeEditorStageFile {
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
    pub fn into_parts(self) -> (PathBuf, File) {
        (self.path, self.file)
    }
}

/// Open or create the single canonical staging file for an operation.
/// Existing files are never truncated here; the staging client must explicitly
/// replace the contents after validating the returned path.
pub fn open_native_editor_stage(
    profile_path: &Path,
    operation_id: ipc::NativeIntentId,
    create: bool,
) -> Result<NativeEditorStageFile> {
    let profile = PrivateProfile::open(profile_path, false)?;
    let name = format!("native-editor-{}.stage", String::from(operation_id));
    let name = std::ffi::CString::new(name).map_err(|_| Error::InvalidProfile)?;
    let flags = libc::O_RDWR
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | if create { libc::O_CREAT } else { 0 };
    let fd = unsafe { libc::openat(profile.directory.as_raw_fd(), name.as_ptr(), flags, 0o600) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    private_regular(&file)?;
    profile.check_current()?;
    let path = profile.path.join(name.to_string_lossy().as_ref());
    let mut file = file;
    file.seek(SeekFrom::Start(0))?;
    Ok(NativeEditorStageFile { path, file })
}

/// A validated private directory. A same-UID malicious process is outside the
/// local trust boundary; other OS identities cannot modify its entries.
#[derive(Debug)]
pub struct PrivateProfile {
    path: PathBuf,
    directory: File,
    identity: Object,
}
impl PrivateProfile {
    pub(crate) fn open(path: &Path, create: bool) -> Result<Self> {
        if !path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(Error::InvalidProfile);
        }
        let directory = open_directory_chain(path, create)?;
        let m = directory.metadata()?;
        if !m.is_dir()
            || m.uid() != uid()
            || m.mode() & 0o777 != 0o700
            || path.canonicalize()? != path
        {
            return Err(Error::InvalidProfile);
        }
        let this = Self {
            path: path.to_path_buf(),
            directory,
            identity: object(&m),
        };
        this.check_current()?;
        Ok(this)
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn check_current(&self) -> Result<()> {
        let current = open_directory_chain(&self.path, false)?;
        let m = current.metadata()?;
        if !m.is_dir()
            || object(&m) != self.identity
            || m.uid() != uid()
            || m.mode() & 0o777 != 0o700
        {
            return Err(Error::InvalidProfile);
        }
        Ok(())
    }
    pub(crate) fn directory(&self) -> &File {
        &self.directory
    }
}

/// Never unlink owner.lock: all contenders must lock the same persistent inode.
#[derive(Debug)]
pub struct OwnerLock {
    profile: PrivateProfile,
    _file: File,
}
impl Drop for OwnerLock {
    fn drop(&mut self) {
        // A concurrent fork may retain this open-file description until exec,
        // even with O_CLOEXEC. End ownership explicitly before closing our FD.
        // Never unlink the persistent lock inode.
        let _ = unsafe { libc::flock(self._file.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn setup_start_mode_result_matches(call: &LocalCall, result: &ipc::LocalResult) -> Option<bool> {
    match (call, result) {
        (LocalCall::SetupStartModeRead {}, ipc::LocalResult::SetupStartMode(_)) => Some(true),
        (LocalCall::SetupStartModeSave(requested), ipc::LocalResult::SetupStartMode(saved)) => {
            Some(requested == saved)
        }
        (LocalCall::SetupStartModeRead {} | LocalCall::SetupStartModeSave(_), _) => Some(false),
        _ => None,
    }
}

impl OwnerLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        let profile = PrivateProfile::open(path, true)?;
        let file = open_regular(&profile.path.join("owner.lock"), true)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::WouldBlock {
                Err(Error::Busy)
            } else {
                Err(error.into())
            };
        }
        profile.check_current()?;
        Ok(Self {
            profile,
            _file: file,
        })
    }
    /// Acquire the real profile owner lock without creating a profile or lock
    /// inode. Used by read-only setup inspection that must exclude a live Host.
    pub fn acquire_existing(path: &Path) -> Result<Self> {
        let profile = PrivateProfile::open(path, false)?;
        let file = open_regular(&profile.path.join("owner.lock"), false)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::WouldBlock {
                Err(Error::Busy)
            } else {
                Err(error.into())
            };
        }
        profile.check_current()?;
        Ok(Self {
            profile,
            _file: file,
        })
    }
    pub fn profile(&self) -> &PrivateProfile {
        &self.profile
    }
    pub(crate) fn check_empty_reservation(&self) -> Result<()> {
        self.profile.check_current()?;
        let named_lock = open_regular(&self.profile.path.join("owner.lock"), false)?;
        if object(&named_lock.metadata()?) != object(&self._file.metadata()?)
            || self.read_host_initialization_receipt()?.is_some()
            || self.database_set_exists()?
        {
            return Err(Error::InvalidProfile);
        }
        // At most two entries are inspected: the persistent lock is the only
        // allowed reservation artifact. Receipts, staging, provider bindings,
        // SQLite sidecars and unknown entries all prevent this classification.
        let mut entries = fs::read_dir(&self.profile.path)?;
        let first = entries.next().transpose()?.ok_or(Error::InvalidProfile)?;
        if first.file_name() != "owner.lock" || entries.next().is_some() {
            return Err(Error::InvalidProfile);
        }
        self.profile.check_current()?;
        let named_lock = open_regular(&self.profile.path.join("owner.lock"), false)?;
        if object(&named_lock.metadata()?) != object(&self._file.metadata()?) {
            return Err(Error::InvalidProfile);
        }
        Ok(())
    }
    /// Stable filesystem identity for binding a durable Host initialization
    /// receipt to this exact private profile directory.
    pub fn profile_identity(&self) -> (u64, u64) {
        (self.profile.identity.device, self.profile.identity.inode)
    }
    /// Read the bounded, owner-private initialization receipt without
    /// following a link. The owner lock must remain held for the whole
    /// initialize/recover transition.
    pub fn read_host_initialization_receipt(&self) -> Result<Option<Vec<u8>>> {
        read_private_receipt(&self.profile)
    }
    /// Atomically replace and durably sync the bounded initialization receipt.
    /// The owner lock must remain held for the whole transition.
    pub fn replace_host_initialization_receipt(&self, bytes: &[u8]) -> Result<()> {
        replace_private_receipt(&self.profile, bytes)
    }
    /// Return whether any database file or SQLite sidecar exists, validating
    /// every present entry as an owner-private regular file first.
    pub fn database_set_exists(&self) -> Result<bool> {
        self.profile.check_current()?;
        let mut exists = false;
        for name in [
            "host.sqlite3",
            "host.sqlite3-wal",
            "host.sqlite3-shm",
            "host.sqlite3-journal",
        ] {
            match open_profile_regular(&self.profile, name, false) {
                Ok(_) => exists = true,
                Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        self.profile.check_current()?;
        Ok(exists)
    }
    /// Sync the validated database file after a successful SQLite checkpoint.
    pub fn sync_database(&self) -> Result<()> {
        self.profile.check_current()?;
        let database = open_profile_regular(&self.profile, "host.sqlite3", false)?;
        database.sync_all()?;
        self.profile.check_current()
    }
    /// SQLite is opened only after validating all preexisting sidecars. Its
    /// parent is private, and a new database starts with owner-only permissions.
    pub fn prepare_database(&self) -> Result<PathBuf> {
        self.profile.check_current()?;
        let path = self.profile.path.join("host.sqlite3");
        drop(open_regular(&path, true)?);
        for suffix in ["-wal", "-shm"] {
            match open_regular(
                &self.profile.path.join(format!("host.sqlite3{suffix}")),
                false,
            ) {
                Ok(_) => {}
                Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(path)
    }

    /// Validate an existing SQLite database and any sidecars without creating
    /// files. The returned path is suitable for opening only while this owner
    /// lock remains held.
    pub fn validate_existing_database(&self) -> Result<PathBuf> {
        self.profile.check_current()?;
        let path = self.profile.path.join("host.sqlite3");
        drop(open_regular(&path, false)?);
        for suffix in ["-wal", "-shm", "-journal"] {
            let sidecar = self.profile.path.join(format!("host.sqlite3{suffix}"));
            match open_regular(&sidecar, false) {
                Ok(_) => {}
                Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        self.profile.check_current()?;
        Ok(path)
    }
}

fn profile_entry_name(value: &str) -> Result<std::ffi::CString> {
    std::ffi::CString::new(value).map_err(|_| Error::InvalidProfile)
}

fn open_profile_regular(profile: &PrivateProfile, value: &str, create: bool) -> Result<File> {
    profile.check_current()?;
    let name = profile_entry_name(value)?;
    let fd = unsafe {
        libc::openat(
            profile.directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | if create { libc::O_CREAT } else { 0 },
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    private_regular(&file)?;
    profile.check_current()?;
    Ok(file)
}

fn read_private_receipt(profile: &PrivateProfile) -> Result<Option<Vec<u8>>> {
    profile.check_current()?;
    let file = match open_profile_regular(profile, HOST_INIT_RECEIPT, false) {
        Ok(file) => file,
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let length = file.metadata()?.len();
    if length == 0 || length > HOST_INIT_RECEIPT_LIMIT {
        return Err(Error::InvalidProfile);
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(HOST_INIT_RECEIPT_LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > HOST_INIT_RECEIPT_LIMIT {
        return Err(Error::InvalidProfile);
    }
    profile.check_current()?;
    Ok(Some(bytes))
}

fn remove_private_receipt_temp(profile: &PrivateProfile) -> Result<()> {
    match open_profile_regular(profile, HOST_INIT_RECEIPT_TEMP, false) {
        Ok(file) => {
            drop(file);
            let name = profile_entry_name(HOST_INIT_RECEIPT_TEMP)?;
            if unsafe { libc::unlinkat(profile.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            Ok(())
        }
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn replace_private_receipt(profile: &PrivateProfile, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() as u64 > HOST_INIT_RECEIPT_LIMIT {
        return Err(Error::InvalidProfile);
    }
    profile.check_current()?;
    match open_profile_regular(profile, HOST_INIT_RECEIPT, false) {
        Ok(_) => {}
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    remove_private_receipt_temp(profile)?;
    let temp_name = profile_entry_name(HOST_INIT_RECEIPT_TEMP)?;
    let fd = unsafe {
        libc::openat(
            profile.directory.as_raw_fd(),
            temp_name.as_ptr(),
            libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let mut temp = unsafe { File::from_raw_fd(fd) };
    let outcome = (|| {
        temp.write_all(bytes)?;
        temp.sync_all()?;
        private_regular(&temp)?;
        if temp.metadata()?.len() != bytes.len() as u64 {
            return Err(Error::InvalidProfile);
        }
        profile.check_current()?;
        let receipt_name = profile_entry_name(HOST_INIT_RECEIPT)?;
        if unsafe {
            libc::renameat(
                profile.directory.as_raw_fd(),
                temp_name.as_ptr(),
                profile.directory.as_raw_fd(),
                receipt_name.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        profile.directory.sync_all()?;
        profile.check_current()
    })();
    drop(temp);
    if outcome.is_err() {
        remove_private_receipt_temp(profile)?;
    }
    outcome
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalDiscovery {
    pub version: LocalIpcVersion,
    pub profile_id: IpcProfileId,
    pub host_id: HostId,
    pub runtime_id: RuntimeId,
    pub build_id: String,
}
impl LocalDiscovery {
    fn validate(&self) -> Result<()> {
        if self.version.major != LocalIpcVersion::CURRENT.major {
            return Err(Error::Incompatible);
        }
        if self.build_id.is_empty()
            || self.build_id.len() > 128
            || !self
                .build_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-+".contains(&b))
        {
            return Err(Error::InvalidEndpoint);
        }
        Ok(())
    }
}

/// Native listener owns its lock until after endpoint removal. The coordinator
/// must drop the store/PTY services before dropping this owner.
pub struct OwnerEndpoint {
    listener: UnixListener,
    lock: OwnerLock,
    discovery: LocalDiscovery,
    socket_identity: Object,
    discovery_identity: Option<Object>,
}
impl OwnerEndpoint {
    pub fn bind(lock: OwnerLock, discovery: LocalDiscovery) -> Result<Self> {
        discovery.validate()?;
        lock.profile.check_current()?;
        let socket = lock.profile.path.join(SOCKET);
        if socket.as_os_str().as_encoded_bytes().len() > 100 {
            return Err(Error::InvalidEndpoint);
        }
        match fs::symlink_metadata(&socket) {
            Ok(m) if m.file_type().is_socket() && m.uid() == uid() && m.mode() & 0o777 == 0o600 => {
                fs::remove_file(&socket)?
            }
            Ok(_) => return Err(Error::InvalidEndpoint),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let listener = UnixListener::bind(&socket)?;
        // Install cleanup immediately, before every fallible post-bind step.
        let identity = object(&fs::symlink_metadata(&socket)?);
        let mut this = Self {
            listener,
            lock,
            discovery,
            socket_identity: identity,
            discovery_identity: None,
        };
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        this.listener.set_nonblocking(true)?;
        this.lock.profile.check_current()?;
        let output = this.lock.profile.path.join(DISCOVERY);
        match open_regular(&output, false) {
            Ok(_) => {}
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let mut temporary = tempfile::NamedTempFile::new_in(&this.lock.profile.path)?;
        serde_json::to_writer(&mut temporary, &this.discovery)
            .map_err(|_| Error::InvalidEndpoint)?;
        temporary.as_file().sync_all()?;
        temporary.persist(&output).map_err(|e| Error::Io(e.error))?;
        this.discovery_identity = Some(object(&fs::symlink_metadata(output)?));
        this.lock.profile.directory.sync_all()?;
        Ok(this)
    }
    pub fn discovery(&self) -> &LocalDiscovery {
        &self.discovery
    }
    pub fn profile(&self) -> &PrivateProfile {
        &self.lock.profile
    }
    pub fn wait(&self, timeout: Duration) -> Result<bool> {
        let mut descriptor = libc::pollfd {
            fd: self.listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe {
            libc::poll(
                &mut descriptor,
                1,
                timeout.as_millis().min(i32::MAX as u128) as i32,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(error.into());
        }
        Ok(result > 0 && descriptor.revents & libc::POLLIN != 0)
    }
    /// Nonblocking accept. The coordinator limits concurrent handshakes before
    /// calling this; no unbounded threads or request queues live in this adapter.
    pub fn accept(&self) -> Result<Option<UnixStream>> {
        match self.listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                authenticate(&stream)?;
                Ok(Some(stream))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    pub fn handshake(&self, stream: UnixStream) -> Result<LocalConnection> {
        let peer = authenticate(&stream)?;
        let mut connection = LocalConnection::new(stream, Instant::now() + HANDSHAKE_TIMEOUT)?;
        let hello: LocalClientHello = connection.read()?;
        let reply = ipc::answer_local_hello(
            &hello,
            &peer,
            &LocalOsOwner::UnixUid(uid()),
            self.discovery.profile_id,
            self.discovery.host_id,
            self.discovery.runtime_id,
        )
        .map_err(|_| Error::PermissionDenied)?;
        connection.write(&reply)?;
        connection.version = reply.version;
        Ok(connection)
    }
}
impl Drop for OwnerEndpoint {
    fn drop(&mut self) {
        if self.lock.profile.check_current().is_err() {
            return;
        }
        for (name, identity) in [
            (SOCKET, Some(self.socket_identity)),
            (DISCOVERY, self.discovery_identity),
        ] {
            let path = self.lock.profile.path.join(name);
            if identity
                .is_some_and(|id| fs::symlink_metadata(&path).is_ok_and(|m| object(&m) == id))
            {
                let _ = fs::remove_file(path);
            }
        }
        let _ = self.lock.profile.directory.sync_all();
    }
}

struct SocketPeer<'a>(&'a UnixStream);
impl TrustedLocalPeerAdapter for SocketPeer<'_> {
    fn connected_owner(&self) -> std::result::Result<LocalOsOwner, &'static str> {
        peer_uid(self.0)
            .map(LocalOsOwner::UnixUid)
            .map_err(|_| "LOCAL_OS_AUTHENTICATION_FAILED")
    }
}
fn authenticate(stream: &UnixStream) -> Result<AuthenticatedLocalPeer> {
    AuthenticatedLocalPeer::from_os_adapter(&SocketPeer(stream), &LocalOsOwner::UnixUid(uid()))
        .map_err(|_| Error::PermissionDenied)
}
#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&credentials) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut size,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if size as usize != std::mem::size_of_val(&credentials) {
        return Err(io::Error::other("invalid peer identity"));
    }
    Ok(credentials.uid)
}
#[cfg(not(target_os = "linux"))]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let (mut user, mut group) = (0, 0);
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut user, &mut group) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(user)
    }
}

/// Each syscall receives only the time left on an absolute frame deadline.
/// A peer trickling bytes cannot reset the budget indefinitely.
pub struct LocalConnection {
    stream: UnixStream,
    deadline: Instant,
    version: LocalIpcVersion,
}
impl LocalConnection {
    fn new(stream: UnixStream, deadline: Instant) -> Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            deadline,
            version: LocalIpcVersion::CURRENT,
        })
    }
    pub fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = deadline;
    }
    pub fn version(&self) -> LocalIpcVersion {
        self.version.clone()
    }
    /// Readiness only; a subsequent frame read still uses its own absolute
    /// deadline. HUP is readable so the caller observes EOF and releases leases.
    pub fn wait_readable(&self, timeout: Duration) -> Result<bool> {
        let deadline = Instant::now().checked_add(timeout).ok_or(Error::Deadline)?;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let millis = remaining
                .as_millis()
                .saturating_add(u128::from(remaining.subsec_nanos() % 1_000_000 != 0))
                .min(i32::MAX as u128) as i32;
            let mut descriptor = libc::pollfd {
                fd: self.stream.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut descriptor, 1, millis) };
            if result >= 0 {
                return Ok(result > 0);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error.into());
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
        }
    }
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "local deadline"))
    }
    fn wait_io(&self, events: libc::c_short) -> io::Result<()> {
        loop {
            let remaining = self.remaining()?;
            let millis = remaining
                .as_millis()
                .saturating_add(u128::from(remaining.subsec_nanos() % 1_000_000 != 0))
                .min(i32::MAX as u128) as i32;
            let mut descriptor = libc::pollfd {
                fd: self.stream.as_raw_fd(),
                events,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut descriptor, 1, millis) };
            if result > 0 {
                self.remaining()?;
                return Ok(());
            }
            if result == 0 {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "local deadline"));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
    pub fn read<T: serde::de::DeserializeOwned>(&mut self) -> Result<T> {
        let mut prefix = [0; 4];
        self.read_exact(&mut prefix)?;
        let length = ipc::local_frame_length(prefix).map_err(|_| Error::InvalidFrame)?;
        let mut payload = vec![0; length];
        self.read_exact(&mut payload)?;
        let value: serde_json::Value =
            serde_json::from_slice(&payload).map_err(|_| Error::InvalidFrame)?;
        if value
            .get("version")
            .and_then(|v| v.get("major"))
            .and_then(|v| v.as_u64())
            .is_some_and(|major| major != 1)
        {
            return Err(Error::Incompatible);
        }
        let result = serde_json::from_slice(&payload).map_err(|_| Error::InvalidFrame)?;
        self.remaining().map_err(|_| Error::Deadline)?;
        Ok(result)
    }
    pub fn write(&mut self, value: &impl Serialize) -> Result<()> {
        let frame = ipc::encode_local_frame(value).map_err(|_| Error::InvalidFrame)?;
        self.write_all(&frame)?;
        self.remaining().map_err(|_| Error::Deadline)?;
        Ok(())
    }
    pub fn read_request(&mut self) -> Result<LocalRequest> {
        let request: LocalRequest = self.read()?;
        if request.version != self.version {
            return Err(Error::Incompatible);
        }
        if let LocalCall::Rpc(request) = &request.call {
            request.call.validate().map_err(|_| Error::InvalidFrame)?;
        }
        Ok(request)
    }
}
impl Read for LocalConnection {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            self.remaining()?;
            match self.stream.read(buffer) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait_io(libc::POLLIN)?
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                result => return result,
            }
        }
    }
}
impl Write for LocalConnection {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        loop {
            self.remaining()?;
            match self.stream.write(buffer) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait_io(libc::POLLOUT)?
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

pub struct LocalClient {
    connection: LocalConnection,
    discovery: LocalDiscovery,
    events: std::collections::VecDeque<(usize, ipc::LocalStreamEvent)>,
    event_bytes: usize,
    subscriptions: std::collections::HashMap<String, StreamBinding>,
    poisoned: bool,
}
enum StreamBinding {
    Terminal(lomi_remote_protocol::TerminalContext),
    Workspace(lomi_remote_protocol::WorkspaceContext),
    Files(lomi_remote_protocol::WorkspaceContext),
}
impl LocalClient {
    /// Bind Desktop to the administrator-installed macOS Host. A preexisting
    /// GUI-host process is left running for explicit migration; its compatible
    /// wire version alone cannot certify the required executable identity.
    #[cfg(target_os = "macos")]
    pub fn verify_macos_host_executable(&self, profile: &Path, executable: &Path) -> Result<()> {
        if self.poisoned {
            return Err(Error::InvalidEndpoint);
        }
        crate::service_macos::custody::verify_installed_host_peer(
            profile,
            executable,
            &self.connection.stream,
        )
        .map_err(|_| Error::Incompatible)
    }
    pub fn connect(profile: &Path) -> Result<Self> {
        Self::connect_with_timeout(profile, HANDSHAKE_TIMEOUT)
    }
    pub fn connect_with_timeout(profile: &Path, timeout: Duration) -> Result<Self> {
        let deadline = Instant::now().checked_add(timeout).ok_or(Error::Deadline)?;
        let profile = PrivateProfile::open(profile, false)?;
        let file = open_regular(&profile.path.join(DISCOVERY), false)?;
        if file.metadata()?.len() > DISCOVERY_LIMIT {
            return Err(Error::InvalidEndpoint);
        }
        let mut bytes = Vec::new();
        file.take(DISCOVERY_LIMIT + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > DISCOVERY_LIMIT {
            return Err(Error::InvalidEndpoint);
        }
        let envelope: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| Error::InvalidEndpoint)?;
        if envelope
            .get("version")
            .and_then(|v| v.get("major"))
            .and_then(|v| v.as_u64())
            .is_some_and(|v| v != 1)
        {
            return Err(Error::Incompatible);
        }
        let discovery: LocalDiscovery =
            serde_json::from_slice(&bytes).map_err(|_| Error::InvalidEndpoint)?;
        discovery.validate()?;
        let socket = profile.path.join(SOCKET);
        let m = fs::symlink_metadata(&socket)?;
        if !m.file_type().is_socket() || m.uid() != uid() || m.mode() & 0o777 != 0o600 {
            return Err(Error::InvalidEndpoint);
        }
        let stream = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
        stream.connect_timeout(
            &socket2::SockAddr::unix(socket)?,
            deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(Error::Deadline)?,
        )?;
        let stream = UnixStream::from(std::os::fd::OwnedFd::from(stream));
        let peer = authenticate(&stream)?;
        profile.check_current()?;
        let hello = LocalClientHello {
            version: LocalIpcVersion::CURRENT,
            profile_id: discovery.profile_id,
            nonce: IpcNonce::from_bytes(*Uuid::new_v4().as_bytes())
                .map_err(|_| Error::InvalidFrame)?,
        };
        let mut probe = LocalHelloProbe::new(
            hello.clone(),
            discovery.host_id,
            discovery.runtime_id,
            LocalOsOwner::UnixUid(uid()),
        );
        let mut connection = LocalConnection::new(stream, deadline)?;
        connection.write(&hello)?;
        let reply: LocalServerHello = connection.read()?;
        connection.version = probe
            .verify(&reply, &peer)
            .map_err(|_| Error::Incompatible)?;
        Ok(Self {
            connection,
            discovery,
            events: std::collections::VecDeque::new(),
            event_bytes: 0,
            subscriptions: std::collections::HashMap::new(),
            poisoned: false,
        })
    }
    // Inspect the peer of this authenticated connection; never use this PID
    // as authority to send OS signals.
    #[cfg(target_os = "linux")]
    pub(crate) fn service_peer_pid(&self) -> Result<u32> {
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                self.connection.stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            )
        } != 0
            || length as usize != std::mem::size_of::<libc::ucred>()
            || credentials.pid <= 0
        {
            return Err(Error::PermissionDenied);
        }
        Ok(credentials.pid as u32)
    }
    // SDK sys/un.h: SOL_LOCAL=0, LOCAL_PEERPID=0x002. This PID is
    // connection authentication evidence only, never signal authority.
    #[cfg(target_os = "macos")]
    pub(crate) fn service_peer_pid(&self) -> Result<u32> {
        let mut pid: libc::pid_t = 0;
        let mut length = std::mem::size_of_val(&pid) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                self.connection.stream.as_raw_fd(),
                0,
                0x002,
                (&mut pid as *mut libc::pid_t).cast(),
                &mut length,
            )
        } != 0
            || length as usize != std::mem::size_of_val(&pid)
            || pid <= 0
        {
            return Err(Error::PermissionDenied);
        }
        Ok(pid as u32)
    }
    pub fn discovery(&self) -> &LocalDiscovery {
        &self.discovery
    }
    pub fn request(&mut self, call: LocalCall) -> Result<LocalResponse> {
        if self.poisoned {
            return Err(Error::InvalidFrame);
        }
        let result = self.request_inner(call, None);
        if result.is_err() {
            self.poison();
        }
        result
    }
    /// Execute a native effect using live, per-effect host challenges. The
    /// same absolute request deadline covers the initial call, every
    /// challenge, and the final joined result.
    pub fn request_guarded(
        &mut self,
        call: LocalCall,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<LocalResponse> {
        if self.poisoned {
            return Err(Error::InvalidFrame);
        }
        let result = (|| {
            let timeout = match &call {
                LocalCall::NativeEditorExecuteGuarded(request) => match &request.effect {
                    ipc::LocalNativeEditorEffect::DesktopFiles { timeout_ms, .. } => {
                        Duration::from_millis(timeout_ms.get())
                    }
                    _ => REQUEST_TIMEOUT,
                },
                LocalCall::NativeGitPrepareGuarded(request) => {
                    Duration::from_millis(request.timeout_ms.get())
                }
                LocalCall::NativeGitExecuteGuarded(request) => {
                    Duration::from_millis(request.timeout_ms.get())
                }
                _ => REQUEST_TIMEOUT,
            };
            let deadline = Instant::now().checked_add(timeout).ok_or(Error::Deadline)?;
            self.request_guarded_inner(call, check, deadline)
        })();
        if result.is_err() {
            self.poison();
        }
        result
    }
    /// Apply incoming stream events while awaiting a reply. This lets a client
    /// validate/assemble live data without buffering an entire snapshot in its
    /// 1 MiB transport queue. The callback must not reenter this connection.
    pub fn request_with_events(
        &mut self,
        call: LocalCall,
        handler: &mut dyn FnMut(ipc::LocalStreamEvent) -> Result<()>,
    ) -> Result<LocalResponse> {
        if self.poisoned {
            return Err(Error::InvalidFrame);
        }
        let result = (|| {
            while let Some(event) = self.try_next_event() {
                handler(event)?;
            }
            self.request_inner(call, Some(handler))
        })();
        if result.is_err() {
            self.poison();
        }
        result
    }
    fn poison(&mut self) {
        self.poisoned = true;
        let _ = self.connection.stream.shutdown(std::net::Shutdown::Both);
        self.events.clear();
        self.event_bytes = 0;
    }
    fn decode_event(&mut self, value: serde_json::Value) -> Result<(usize, ipc::LocalStreamEvent)> {
        let frame = ipc::encode_local_frame(&value).map_err(|_| Error::InvalidFrame)?;
        let event = ipc::decode_local_stream_event(&frame).map_err(|_| Error::InvalidFrame)?;
        self.validate_event(&event)?;
        use lomi_remote_protocol::{TerminalStreamFrame as T, WorkspaceStreamFrame as W};
        let retired = match &event {
            ipc::LocalStreamEvent::Terminal(T::Delta(delta))
                if matches!(
                    delta.change,
                    lomi_remote_protocol::streams::TerminalChange::Exit(_)
                ) =>
            {
                Some(&delta.subscription_id)
            }
            ipc::LocalStreamEvent::Terminal(T::ResyncRequired(value)) => {
                Some(&value.subscription_id)
            }
            ipc::LocalStreamEvent::Workspace(W::ResyncRequired(value)) => {
                Some(&value.subscription_id)
            }
            _ => None,
        };
        if let Some(subscription) = retired {
            self.subscriptions.remove(subscription.as_str());
        }
        Ok((frame.len(), event))
    }
    /// Drain an already received event without I/O. Consumer assembly and render
    /// ACKs remain explicit; this transport never claims a frame was rendered.
    pub fn try_next_event(&mut self) -> Option<ipc::LocalStreamEvent> {
        let (bytes, event) = self.events.pop_front()?;
        self.event_bytes -= bytes;
        Some(event)
    }
    pub fn next_event(&mut self, timeout: Duration) -> Result<Option<ipc::LocalStreamEvent>> {
        if self.poisoned {
            return Err(Error::InvalidFrame);
        }
        if let Some(event) = self.try_next_event() {
            return Ok(Some(event));
        }
        self.connection
            .set_deadline(Instant::now().checked_add(timeout).ok_or(Error::Deadline)?);
        let result = (|| {
            if !self.connection.wait_readable(timeout)? {
                return Ok(None);
            }
            let value = self.connection.read::<serde_json::Value>()?;
            Ok(Some(self.decode_event(value)?.1))
        })();
        if result.is_err() {
            self.poison();
        }
        result
    }
    fn request_inner(
        &mut self,
        call: LocalCall,
        mut handler: Option<&mut dyn FnMut(ipc::LocalStreamEvent) -> Result<()>>,
    ) -> Result<LocalResponse> {
        self.connection
            .set_deadline(Instant::now() + REQUEST_TIMEOUT);
        let request = LocalRequest {
            version: self.connection.version.clone(),
            request_id: RequestId::try_from(Uuid::new_v4().simple().to_string())
                .map_err(|_| Error::InvalidFrame)?,
            call,
        };
        self.connection.write(&request)?;
        let response: LocalResponse = loop {
            let value = self.connection.read::<serde_json::Value>()?;
            if value.get("version").is_some() {
                break serde_json::from_value(value).map_err(|_| Error::InvalidFrame)?;
            }
            let (bytes, event) = self.decode_event(value)?;
            if let Some(handler) = handler.as_mut() {
                handler(event)?;
                continue;
            }
            if bytes > 1024 * 1024 - self.event_bytes {
                return Err(Error::InvalidFrame);
            }
            self.event_bytes += bytes;
            self.events.push_back((bytes, event));
        };
        if response.version != request.version || response.request_id != request.request_id {
            return Err(Error::InvalidFrame);
        }
        if let Ok(result) = &response.result {
            self.validate_result(&request.call, result)?;
        }
        if let (LocalCall::Rpc(request), Ok(ipc::LocalResult::Rpc(reply))) =
            (&request.call, &response.result)
        {
            lomi_remote_protocol::decode_response_for(
                &serde_json::to_vec(reply).map_err(|_| Error::InvalidFrame)?,
                request,
            )
            .map_err(|_| Error::InvalidFrame)?;
            if let lomi_remote_protocol::RpcResponse::Result { result, .. } = reply.as_ref() {
                use lomi_remote_protocol::RpcResult as R;
                let binding = match result {
                    R::TerminalAttach(m) | R::TerminalSnapshot(m) => Some((
                        m.subscription_id.as_str().to_owned(),
                        StreamBinding::Terminal(m.terminal.clone()),
                    )),
                    R::WorkspaceSubscribe(m) => Some((
                        m.subscription_id.as_str().to_owned(),
                        StreamBinding::Workspace(m.context.clone()),
                    )),
                    R::FilesWatch(m) => {
                        let lomi_remote_protocol::RpcCall::FilesWatch(params) = &request.call
                        else {
                            return Err(Error::InvalidFrame);
                        };
                        Some((
                            m.subscription_id.as_str().to_owned(),
                            StreamBinding::Files(params.context.clone()),
                        ))
                    }
                    _ => None,
                };
                if let Some((id, binding)) = binding {
                    match &binding {
                        StreamBinding::Workspace(_) => {
                            self.subscriptions
                                .retain(|_, value| !matches!(value, StreamBinding::Workspace(_)));
                            self.events.retain(|(_, event)| {
                                !matches!(event, ipc::LocalStreamEvent::Workspace(_))
                            });
                        }
                        StreamBinding::Files(_) => {
                            self.subscriptions
                                .retain(|_, value| !matches!(value, StreamBinding::Files(_)));
                            self.events.retain(|(_, event)| {
                                !matches!(event, ipc::LocalStreamEvent::Files(_))
                            });
                        }
                        StreamBinding::Terminal(_) => {}
                    }
                    self.event_bytes = self.events.iter().map(|(size, _)| *size).sum();
                    if self.subscriptions.len() >= 64
                        || self.subscriptions.insert(id, binding).is_some()
                    {
                        return Err(Error::InvalidFrame);
                    }
                }
            }
        }
        Ok(response)
    }
    fn request_guarded_inner(
        &mut self,
        call: LocalCall,
        check: &mut dyn FnMut() -> Result<()>,
        deadline: Instant,
    ) -> Result<LocalResponse> {
        let (operation_id, sticky_failure) = match &call {
            LocalCall::NativeEditorExecuteGuarded(request) => (
                request.blob.operation_id,
                matches!(
                    &request.effect,
                    ipc::LocalNativeEditorEffect::DesktopFiles { .. }
                ),
            ),
            LocalCall::NativeGitPrepareGuarded(request) => (request.operation_id, true),
            LocalCall::NativeGitExecuteGuarded(request) => (request.operation_id, true),
            _ => return Err(Error::InvalidFrame),
        };
        self.connection.set_deadline(deadline);
        let request = LocalRequest {
            version: self.connection.version.clone(),
            request_id: RequestId::try_from(Uuid::new_v4().simple().to_string())
                .map_err(|_| Error::InvalidFrame)?,
            call,
        };
        self.connection.write(&request)?;
        let mut challenges = std::collections::BTreeSet::new();
        let challenge_limit = if matches!(
            &request.call,
            LocalCall::NativeEditorExecuteGuarded(value)
                if matches!(&value.effect, ipc::LocalNativeEditorEffect::DesktopFiles { .. })
        ) {
            ipc::DESKTOP_FILE_CHALLENGE_LIMIT
        } else {
            8192
        };
        let mut check_failed = false;
        loop {
            let value = self.connection.read::<serde_json::Value>()?;
            if value.get("version").is_some() {
                let response: LocalResponse =
                    serde_json::from_value(value).map_err(|_| Error::InvalidFrame)?;
                if response.version != request.version || response.request_id != request.request_id
                {
                    return Err(Error::InvalidFrame);
                }
                if let Ok(ipc::LocalResult::NativeEffectChallenge(challenge)) = &response.result {
                    if challenge.operation_id != operation_id
                        || challenges.len() >= challenge_limit
                        || !challenges.insert(challenge.challenge)
                    {
                        return Err(Error::InvalidFrame);
                    }
                    let decision = LocalRequest {
                        version: request.version.clone(),
                        request_id: request.request_id.clone(),
                        call: LocalCall::NativeEffectDecision(ipc::LocalNativeEffectDecision {
                            operation_id,
                            challenge: challenge.challenge,
                            allowed: if sticky_failure && check_failed {
                                false
                            } else {
                                let allowed =
                                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                        check()
                                    }))
                                    .map_err(|_| Error::InvalidFrame)?
                                    .is_ok();
                                if sticky_failure && !allowed {
                                    check_failed = true;
                                }
                                allowed
                            },
                        }),
                    };
                    self.connection.set_deadline(deadline);
                    self.connection.write(&decision)?;
                    continue;
                }
                if let Ok(result) = &response.result {
                    self.validate_result(&request.call, result)?;
                }
                return Ok(response);
            }
            let (bytes, event) = self.decode_event(value)?;
            if bytes > 1024 * 1024 - self.event_bytes {
                return Err(Error::InvalidFrame);
            }
            self.event_bytes += bytes;
            self.events.push_back((bytes, event));
        }
    }
    fn validate_result(&self, call: &LocalCall, result: &ipc::LocalResult) -> Result<()> {
        if let Some(valid) = crate::ipc_result::matches(
            call,
            result,
            self.discovery.host_id,
            self.discovery.runtime_id,
        ) {
            return if valid {
                Ok(())
            } else {
                Err(Error::InvalidFrame)
            };
        }
        use ipc::LocalResult as R;
        let valid = match (call, result) {
            (LocalCall::DaemonStop(_), R::Stopping {}) => true,
            (LocalCall::AuthConfigure(_), R::AuthConfigured {})
            | (LocalCall::LoginStart(_), R::LoginAccepted(_))
            | (LocalCall::LoginStatus {}, R::LoginStatus(_))
            | (LocalCall::Logout(_), R::LoginStatus(_))
            | (LocalCall::LoginPresentation {}, R::LoginPresentation(_)) => true,
            (LocalCall::Status {}, R::Status(s)) => {
                s.host_id == self.discovery.host_id && s.runtime_id == self.discovery.runtime_id
            }
            (LocalCall::HostNameSet(request), R::HostNameSet(name)) => name == &request.name,
            (LocalCall::HostNameSet(_), _) => false,
            (LocalCall::MaintenancePrepare(_), R::MaintenanceStatus(s)) => {
                s.host_id == self.discovery.host_id && s.runtime_id == self.discovery.runtime_id
            }
            (LocalCall::SetupStartModeRead {}, _) | (LocalCall::SetupStartModeSave(_), _) => {
                setup_start_mode_result_matches(call, result) == Some(true)
            }
            (LocalCall::Doctor {}, R::Doctor(_))
            | (LocalCall::Workspaces {}, R::Workspaces(_))
            | (LocalCall::Profiles {}, R::Profiles(_))
            | (LocalCall::Rpc(_), R::Rpc(_)) => true,
            (LocalCall::WorkspaceAdd(p), R::Workspace(w)) => p.name == w.name,
            (LocalCall::WorkspaceImport(p), R::WorkspaceImported(receipt)) => {
                p.workspace_id == receipt.import_id
            }
            (LocalCall::ShellProfileRegister(p), R::ShellProfileRegistered { profile_id }) => {
                p.profile_id == *profile_id
            }
            (
                LocalCall::StreamAck(ipc::LocalStreamAck::Workspace(ack)),
                R::StreamAcknowledged(id),
            ) => {
                ack.subscription_id == *id
                    && matches!(self.subscriptions.get(id.as_str()),
                    Some(StreamBinding::Workspace(context)) if context == &ack.context)
            }
            (LocalCall::StreamAck(ipc::LocalStreamAck::Files(ack)), R::StreamAcknowledged(id)) => {
                ack.subscription_id == *id
                    && matches!(self.subscriptions.get(id.as_str()),
                    Some(StreamBinding::Files(context)) if context == &ack.context)
            }
            (LocalCall::WorkspaceInspect(p), R::WorkspaceState(w)) => {
                p.workspace_id == w.context.workspace_id
                    && w.context.runtime_id == self.discovery.runtime_id
                    && w.validate().is_ok()
            }
            (LocalCall::WorkspaceRemove(p), R::Removed(id)) => p.workspace_id == *id,
            (LocalCall::Share(p), R::Workspace(w)) => {
                p.workspace_id == w.workspace_id && w.sharing == ipc::LocalSharing::Enabled
            }
            (LocalCall::Unshare(p), R::Workspace(w)) => {
                p.workspace_id == w.workspace_id && w.sharing == ipc::LocalSharing::Disabled
            }
            (LocalCall::NativeIntent(p), R::NativeIntent(id)) => p.intent_id == *id,
            (LocalCall::NativeBindJob(p), R::NativeLease(lease)) => p.intent_id == lease.intent_id,
            (LocalCall::NativeFileStage(p), R::NativeFileStage(stage)) => {
                p.operation_id == stage.operation_id
            }
            (
                LocalCall::NativeEditorExecute(p) | LocalCall::NativeEditorExecuteGuarded(p),
                R::NativeEditor(result),
            ) => p.blob.operation_id == result.operation_id,
            (LocalCall::NativeEditorStatus(p), R::NativeEditor(result)) => {
                p.intent_id == result.operation_id
            }
            (LocalCall::NativeEditorAcknowledge(p), R::NativeEditorAcknowledged(id)) => {
                p.intent_id == *id
            }
            (LocalCall::NativeGitPrepareGuarded(p), R::NativeGit(result)) => {
                p.operation_id == result.operation_id
            }
            (LocalCall::NativeGitExecuteGuarded(p), R::NativeGit(result)) => {
                p.operation_id == result.operation_id
            }
            (
                LocalCall::NativeGitStatus(p)
                | LocalCall::NativeGitCancelPrepared(p)
                | LocalCall::NativeGitAcknowledge(p),
                R::NativeGit(result),
            ) => p.intent_id == result.operation_id,
            (LocalCall::NativeAcknowledge(p), R::NativeAcknowledged(id)) => p.intent_id == *id,
            (
                LocalCall::NativeAcquire(p)
                | LocalCall::NativeCheck(p)
                | LocalCall::NativeRenew(p)
                | LocalCall::NativeRequestFinish(p)
                | LocalCall::NativeReconcile(p),
                R::NativeLease(lease),
            ) => p.intent_id == lease.intent_id,
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(Error::InvalidFrame)
        }
    }
    fn validate_event(&self, event: &ipc::LocalStreamEvent) -> Result<()> {
        use lomi_remote_protocol::{TerminalStreamFrame as T, WorkspaceStreamFrame as W};
        let valid = match event {
            ipc::LocalStreamEvent::Files(frame) => {
                use lomi_remote_protocol::FileWatchFrame as F;
                let (context, id) = match frame {
                    F::Invalidated(v) => (&v.context, &v.subscription_id),
                    F::Ack(v) => (&v.context, &v.subscription_id),
                    F::ResyncRequired(v) => (&v.context, &v.subscription_id),
                };
                matches!(self.subscriptions.get(id.as_str()), Some(StreamBinding::Files(expected)) if expected == context)
            }
            ipc::LocalStreamEvent::Terminal(frame) => {
                let (terminal, id) = match frame {
                    T::SnapshotMetadata(v) => (&v.terminal, &v.subscription_id),
                    T::SnapshotChunk(v) => (&v.terminal, &v.subscription_id),
                    T::SnapshotComplete(v) => (&v.terminal, &v.subscription_id),
                    T::Delta(v) => (&v.terminal, &v.subscription_id),
                    T::DeltaMetadata(v) => (&v.terminal, &v.subscription_id),
                    T::DeltaChunk(v) => (&v.terminal, &v.subscription_id),
                    T::DeltaComplete(v) => (&v.terminal, &v.subscription_id),
                    T::Ack(v) => (&v.terminal, &v.subscription_id),
                    T::ResyncRequired(v) => (&v.terminal, &v.subscription_id),
                };
                matches!(self.subscriptions.get(id.as_str()), Some(StreamBinding::Terminal(expected)) if expected == terminal)
            }
            ipc::LocalStreamEvent::Workspace(frame) => {
                let (context, id) = match frame {
                    W::SnapshotMetadata(v) => (Some(&v.context), &v.subscription_id),
                    W::SnapshotChunk(v) => (None, &v.subscription_id),
                    W::SnapshotComplete(v) => (None, &v.subscription_id),
                    W::Event(v) => (Some(&v.context), &v.subscription_id),
                    W::Ack(v) => (Some(&v.context), &v.subscription_id),
                    W::ResyncRequired(v) => (Some(&v.context), &v.subscription_id),
                };
                matches!(self.subscriptions.get(id.as_str()), Some(StreamBinding::Workspace(expected)) if context.is_none_or(|value|expected == value))
            }
        };
        if valid {
            Ok(())
        } else {
            Err(Error::InvalidFrame)
        }
    }
}

pub mod public_config;
