//! Windows local IPC and explicitly selected user-scope secret storage.
pub mod backup;
pub(crate) mod diagnostics;

pub mod file_security_service;
pub mod maintenance;
pub mod public_config;
pub mod secrets;
pub mod service;
pub mod service_admin;
pub(crate) mod setup_journal;
pub mod task;
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
    ffi::{OsStr, c_void},
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    mem,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Component, Path, PathBuf},
    ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use uuid::Uuid;
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{
        IO::*,
        Pipes::*,
        SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
        Threading::*,
    },
};
const DISCOVERY: &str = "discovery.json";
const DISCOVERY_LIMIT: u64 = 4096;
const HOST_INIT_RECEIPT: &str = "host-init.json";
const HOST_INIT_RECEIPT_TEMP: &str = "host-init.tmp";
const HOST_INIT_RECEIPT_LIMIT: u64 = 16 * 1024;
const MAX_CONNECTIONS: usize = 32;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
// If the kernel cannot confirm cancellation, never free its referenced buffers.
// Fail the entire adapter closed and preserve that one bounded operation instead.
static IO_POISONED: AtomicBool = AtomicBool::new(false);
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
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::TimedOut {
            Self::Deadline
        } else {
            Self::Io(e)
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;
fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}
fn check(ok: i32) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
#[derive(Debug)]
struct Handle(HANDLE, AtomicBool);
impl Handle {
    fn new(h: HANDLE) -> io::Result<Self> {
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(h, AtomicBool::new(false)))
        }
    }
}
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}
impl Handle {
    fn close(&self) {
        if !self.1.swap(true, Ordering::AcqRel) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        self.close();
    }
}
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
struct Security {
    _descriptor: Local,
    attributes: SECURITY_ATTRIBUTES,
}
impl Security {
    fn new(sddl: &str) -> Result<Self> {
        let mut d = ptr::null_mut();
        unsafe {
            check(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl).as_ptr(),
                1,
                &mut d,
                ptr::null_mut(),
            ))?;
        }
        Ok(Self {
            _descriptor: Local(d),
            attributes: SECURITY_ATTRIBUTES {
                nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: d,
                bInheritHandle: 0,
            },
        })
    }
}
fn sid_text(sid: PSID) -> Result<String> {
    let mut text = ptr::null_mut();
    unsafe {
        check(ConvertSidToStringSidW(sid, &mut text))?;
    }
    let _guard = Local(text.cast());
    let mut length = 0;
    unsafe {
        while *text.add(length) != 0 {
            length += 1;
            if length > 256 {
                return Err(Error::PermissionDenied);
            }
        }
        String::from_utf16(std::slice::from_raw_parts(text, length))
            .map_err(|_| Error::PermissionDenied)
    }
}
fn process_sid(process: HANDLE) -> Result<String> {
    let mut t = ptr::null_mut();
    unsafe {
        check(OpenProcessToken(process, TOKEN_QUERY, &mut t))?;
    }
    let t = Handle::new(t)?;
    let mut len = 0;
    unsafe {
        GetTokenInformation(t.0, TokenUser, ptr::null_mut(), 0, &mut len);
    }
    if len == 0 || len > 4096 {
        return Err(Error::PermissionDenied);
    }
    let mut b = vec![0usize; (len as usize).div_ceil(mem::size_of::<usize>())];
    unsafe {
        check(GetTokenInformation(
            t.0,
            TokenUser,
            b.as_mut_ptr().cast(),
            len,
            &mut len,
        ))?;
        sid_text((*b.as_ptr().cast::<TOKEN_USER>()).User.Sid)
    }
}
fn current_sid() -> Result<String> {
    process_sid(unsafe { GetCurrentProcess() })
}
fn security(sid: &str, directory: bool) -> Result<Security> {
    Security::new(&format!(
        "O:{sid}D:P(A;{};FA;;;{sid})",
        if directory { "OICI" } else { "" }
    ))
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Object {
    volume: u32,
    index: u64,
}
fn information(handle: HANDLE) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = unsafe { mem::zeroed() };
    unsafe {
        check(GetFileInformationByHandle(handle, &mut info))?;
    }
    Ok(info)
}
fn object(info: &BY_HANDLE_FILE_INFORMATION) -> Object {
    Object {
        volume: info.dwVolumeSerialNumber,
        index: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
    }
}
fn trusted_sid(sid: &str, owner: &str) -> bool {
    sid == owner
        || matches!(
            sid,
            "S-1-5-18"
                | "S-1-5-32-544"
                | "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        )
}
fn validate_security(handle: HANDLE, owner: &str, private: bool, directory: bool) -> Result<()> {
    let (mut descriptor, mut sid, mut acl) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    let code = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut sid,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(Error::PermissionDenied);
    }
    let _guard = Local(descriptor);
    let found = sid_text(sid)?;
    if (private && found != owner) || (!private && !trusted_sid(&found, owner)) || acl.is_null() {
        return Err(Error::InvalidProfile);
    }
    let mut control = 0;
    let mut revision = 0;
    unsafe {
        check(GetSecurityDescriptorControl(
            descriptor,
            &mut control,
            &mut revision,
        ))?;
    }
    if private && directory && control & SE_DACL_PROTECTED == 0 {
        return Err(Error::InvalidProfile);
    }
    let mut owner_grant = false;
    for index in 0..unsafe { (*acl).AceCount } {
        let mut ace = ptr::null_mut();
        unsafe {
            check(GetAce(acl, index as u32, &mut ace))?;
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        // Inherit-only entries do not affect this object, but a private
        // directory must also protect files that SQLite creates beneath it.
        // Ancestor traversal checks concern rights on the ancestor itself.
        if header.AceFlags as u32 & INHERIT_ONLY_ACE != 0 && !(private && directory) {
            continue;
        }
        if header.AceType == ACCESS_DENIED_ACE_TYPE as u8 {
            // Deny-only entries can restrict access but cannot grant authority.
            continue;
        }
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8 {
            return Err(Error::InvalidProfile);
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let who = sid_text((&allowed.SidStart as *const u32).cast_mut().cast())?;
        if private {
            let flags = if directory {
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
            } else {
                0
            };
            if who != owner
                || allowed.Mask != FILE_ALL_ACCESS
                || header.AceFlags as u32 & !INHERITED_ACE != flags
            {
                return Err(Error::InvalidProfile);
            }
            owner_grant = true;
        } else if allowed.Mask
            & (FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER | DELETE | GENERIC_ALL | GENERIC_WRITE)
            != 0
            && !trusted_sid(&who, owner)
        {
            return Err(Error::InvalidProfile);
        }
    }
    if private && !owner_grant {
        return Err(Error::InvalidProfile);
    }
    Ok(())
}
fn open_path(path: &Path, write: bool, create: bool, directory: bool, sid: &str) -> Result<Handle> {
    let sd = security(sid, directory)?;
    let access = READ_CONTROL
        | FILE_READ_ATTRIBUTES
        | if directory {
            0
        } else {
            GENERIC_READ | if write { GENERIC_WRITE } else { 0 }
        };
    let h = Handle::new(unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &sd.attributes,
            if create { OPEN_ALWAYS } else { OPEN_EXISTING },
            FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    0
                },
            ptr::null_mut(),
        )
    })?;
    let info = information(h.0)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (!directory && info.nNumberOfLinks != 1)
    {
        return Err(Error::InvalidProfile);
    }
    Ok(h)
}
fn open_regular(path: &Path, write: bool, create: bool, sid: &str) -> Result<File> {
    let h = open_path(path, write, create, false, sid)?;
    validate_security(h.0, sid, true, false)?;
    let raw = h.0;
    mem::forget(h);
    Ok(unsafe { File::from_raw_handle(raw) })
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
    profile.check_current()?;
    let name = format!("native-editor-{}.stage", String::from(operation_id));
    let path = profile.path.join(name);
    let file = open_regular(&path, true, create, &profile.sid)?;
    profile.check_current()?;
    let mut file = file;
    file.seek(SeekFrom::Start(0))?;
    Ok(NativeEditorStageFile { path, file })
}
fn normalized(path: &Path) -> Result<PathBuf> {
    let text = path.to_str().ok_or(Error::InvalidProfile)?;
    let text = text.strip_prefix(r"\\?\").unwrap_or(text);
    if text.len() < 3
        || !text.as_bytes()[0].is_ascii_alphabetic()
        || text.as_bytes().get(1..3) != Some(&b":\\"[..])
        || text.len() > 2048
        || text.chars().any(char::is_control)
    {
        return Err(Error::InvalidProfile);
    }
    let path = PathBuf::from(text);
    if path
        .components()
        .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    {
        return Err(Error::InvalidProfile);
    }
    Ok(path)
}
#[derive(Debug)]
pub struct PrivateProfile {
    path: PathBuf,
    _directories: Vec<Handle>,
    identity: Object,
    sid: String,
}
impl PrivateProfile {
    fn open(path: &Path, create: bool) -> Result<Self> {
        let path = normalized(path)?;
        let sid = current_sid()?;
        let sd = security(&sid, true)?;
        let mut built = PathBuf::new();
        let mut directories = Vec::new();
        for part in path.components() {
            built.push(part.as_os_str());
            if matches!(part, Component::Prefix(_)) {
                continue;
            }
            if !built.exists() && create {
                unsafe {
                    if CreateDirectoryW(wide(&built).as_ptr(), &sd.attributes) == 0
                        && GetLastError() != ERROR_ALREADY_EXISTS
                    {
                        return Err(io::Error::last_os_error().into());
                    }
                }
            }
            let h = open_path(&built, false, false, true, &sid)?;
            validate_security(h.0, &sid, built == path, true)?;
            directories.push(h);
        }
        if normalized(&path.canonicalize()?)? != path {
            return Err(Error::InvalidProfile);
        }
        let identity = object(&information(
            directories.last().ok_or(Error::InvalidProfile)?.0,
        )?);
        Ok(Self {
            path,
            _directories: directories,
            identity,
            sid,
        })
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    fn check_current(&self) -> Result<()> {
        let h = open_path(&self.path, false, false, true, &self.sid)?;
        validate_security(h.0, &self.sid, true, true)?;
        if object(&information(h.0)?) != self.identity
            || normalized(&self.path.canonicalize()?)? != self.path
        {
            return Err(Error::InvalidProfile);
        }
        Ok(())
    }
}
#[derive(Debug)]
pub struct OwnerLock {
    profile: PrivateProfile,
    _file: File,
}
impl OwnerLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        let profile = PrivateProfile::open(path, true)?;
        let file = open_regular(&profile.path.join("owner.lock"), true, true, &profile.sid)?;
        let mut ov = unsafe { mem::zeroed() };
        if unsafe {
            LockFileEx(
                file.as_raw_handle(),
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                u32::MAX,
                u32::MAX,
                &mut ov,
            )
        } == 0
        {
            return if unsafe { GetLastError() } == ERROR_LOCK_VIOLATION {
                Err(Error::Busy)
            } else {
                Err(io::Error::last_os_error().into())
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
        let file = open_regular(&profile.path.join("owner.lock"), true, false, &profile.sid)?;
        let mut overlapped = unsafe { mem::zeroed() };
        if unsafe {
            LockFileEx(
                file.as_raw_handle(),
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        } == 0
        {
            return if unsafe { GetLastError() } == ERROR_LOCK_VIOLATION {
                Err(Error::Busy)
            } else {
                Err(io::Error::last_os_error().into())
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
        let named_lock = open_regular(
            &self.profile.path.join("owner.lock"),
            false,
            false,
            &self.profile.sid,
        )?;
        if object(&information(named_lock.as_raw_handle())?)
            != object(&information(self._file.as_raw_handle())?)
            || self.read_host_initialization_receipt()?.is_some()
            || self.database_set_exists()?
        {
            return Err(Error::InvalidProfile);
        }
        let mut entries = fs::read_dir(&self.profile.path)?;
        let first = entries.next().transpose()?.ok_or(Error::InvalidProfile)?;
        if first.file_name() != "owner.lock" || entries.next().is_some() {
            return Err(Error::InvalidProfile);
        }
        self.profile.check_current()?;
        let named_lock = open_regular(
            &self.profile.path.join("owner.lock"),
            false,
            false,
            &self.profile.sid,
        )?;
        if object(&information(named_lock.as_raw_handle())?)
            != object(&information(self._file.as_raw_handle())?)
        {
            return Err(Error::InvalidProfile);
        }
        Ok(())
    }
    /// Stable filesystem identity for binding a durable Host initialization
    /// receipt to this exact private profile directory.
    pub fn profile_identity(&self) -> (u64, u64) {
        (
            u64::from(self.profile.identity.volume),
            self.profile.identity.index,
        )
    }
    /// Read the bounded, owner-private initialization receipt without
    /// following a reparse point. The owner lock must remain held for the
    /// whole initialize/recover transition.
    pub fn read_host_initialization_receipt(&self) -> Result<Option<Vec<u8>>> {
        read_private_receipt(&self.profile)
    }
    /// Atomically replace and durably flush the bounded initialization receipt.
    pub fn replace_host_initialization_receipt(&self, bytes: &[u8]) -> Result<()> {
        replace_private_receipt(&self.profile, &self.profile.sid, bytes)
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
            match open_regular(
                &self.profile.path.join(name),
                false,
                false,
                &self.profile.sid,
            ) {
                Ok(_) => exists = true,
                Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        self.profile.check_current()?;
        Ok(exists)
    }
    /// Flush the validated database file after a successful SQLite checkpoint.
    pub fn sync_database(&self) -> Result<()> {
        self.profile.check_current()?;
        let database = open_regular(
            &self.profile.path.join("host.sqlite3"),
            true,
            false,
            &self.profile.sid,
        )?;
        database.sync_all()?;
        self.profile.check_current()
    }
    pub fn prepare_database(&self) -> Result<PathBuf> {
        self.profile.check_current()?;
        let path = self.profile.path.join("host.sqlite3");
        drop(open_regular(&path, true, true, &self.profile.sid)?);
        for suffix in ["-wal", "-shm"] {
            // SQLite's default creation inherits the parent's DACL but can
            // select the elevated token's Administrators owner. Pin both
            // sidecars to this exact account before SQLite opens the database.
            drop(open_regular(
                &self.profile.path.join(format!("host.sqlite3{suffix}")),
                true,
                true,
                &self.profile.sid,
            )?);
        }
        Ok(path)
    }

    /// Validate the existing database and sidecars without creating files.
    /// The returned path is suitable for opening only while this owner lock
    /// remains held.
    pub fn validate_existing_database(&self) -> Result<PathBuf> {
        self.profile.check_current()?;
        let path = self.profile.path.join("host.sqlite3");
        drop(open_regular(&path, false, false, &self.profile.sid)?);
        for suffix in ["-wal", "-shm", "-journal"] {
            let sidecar = self.profile.path.join(format!("host.sqlite3{suffix}"));
            match open_regular(&sidecar, false, false, &self.profile.sid) {
                Ok(_) => {}
                Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        self.profile.check_current()?;
        Ok(path)
    }
}

fn read_private_receipt(profile: &PrivateProfile) -> Result<Option<Vec<u8>>> {
    profile.check_current()?;
    let file = match open_regular(
        &profile.path.join(HOST_INIT_RECEIPT),
        false,
        false,
        &profile.sid,
    ) {
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

fn remove_private_receipt_temp(profile: &PrivateProfile, sid: &str) -> Result<()> {
    let path = profile.path.join(HOST_INIT_RECEIPT_TEMP);
    match open_regular(&path, false, false, sid) {
        Ok(file) => {
            drop(file);
            fs::remove_file(path)?;
            Ok(())
        }
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn replace_private_receipt(profile: &PrivateProfile, sid: &str, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() as u64 > HOST_INIT_RECEIPT_LIMIT {
        return Err(Error::InvalidProfile);
    }
    profile.check_current()?;
    match open_regular(&profile.path.join(HOST_INIT_RECEIPT), false, false, sid) {
        Ok(_) => {}
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    remove_private_receipt_temp(profile, sid)?;
    let temporary = profile.path.join(HOST_INIT_RECEIPT_TEMP);
    let output = profile.path.join(HOST_INIT_RECEIPT);
    let mut file = open_regular(&temporary, true, true, sid)?;
    file.set_len(0)?;
    let outcome = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        if file.metadata()?.len() != bytes.len() as u64 {
            return Err(Error::InvalidProfile);
        }
        profile.check_current()?;
        drop(file);
        if unsafe {
            MoveFileExW(
                wide(&temporary).as_ptr(),
                wide(&output).as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        profile.check_current()
    })();
    if outcome.is_err() {
        remove_private_receipt_temp(profile, sid)?;
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
fn pipe_name(profile: &PrivateProfile, id: IpcProfileId) -> String {
    format!(
        r"\\.\pipe\Lomi-Local-v1-{}-{}",
        profile.sid,
        String::from(id)
    )
}
struct Overlap {
    state: OVERLAPPED,
    _event: Handle,
}
unsafe impl Send for Overlap {}
impl Overlap {
    fn new() -> io::Result<Box<Self>> {
        let event = Handle::new(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) })?;
        let mut state: OVERLAPPED = unsafe { mem::zeroed() };
        state.hEvent = event.0;
        Ok(Box::new(Self {
            state,
            _event: event,
        }))
    }
}
fn millis(deadline: Instant) -> u32 {
    deadline
        .saturating_duration_since(Instant::now())
        .as_millis()
        .saturating_add(1)
        .min((u32::MAX - 1) as u128) as u32
}
fn cancel_drain(handle: HANDLE, ov: &OVERLAPPED) -> bool {
    unsafe {
        CancelIoEx(handle, ov);
        WaitForSingleObject(ov.hEvent, 500) == WAIT_OBJECT_0
    }
}
struct Listener {
    pipe: Arc<Handle>,
    overlap: Option<Box<Overlap>>,
    connected: bool,
}
impl Listener {
    fn new(name: &str, sid: &str, first: bool) -> Result<Self> {
        if IO_POISONED.load(Ordering::Acquire) {
            return Err(Error::InvalidEndpoint);
        }
        let sd = Security::new(&format!("O:{sid}D:P(A;;GA;;;{sid})"))?;
        let handle = unsafe {
            CreateNamedPipeW(
                wide(name).as_ptr(),
                PIPE_ACCESS_DUPLEX
                    | FILE_FLAG_OVERLAPPED
                    | if first {
                        FILE_FLAG_FIRST_PIPE_INSTANCE
                    } else {
                        0
                    },
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                (MAX_CONNECTIONS + 1) as u32,
                65536,
                65536,
                0,
                &sd.attributes,
            )
        };
        if handle == INVALID_HANDLE_VALUE
            && first
            && matches!(
                unsafe { GetLastError() },
                ERROR_ACCESS_DENIED | ERROR_PIPE_BUSY
            )
        {
            return Err(Error::Busy);
        }
        let pipe = Arc::new(Handle::new(handle)?);
        let mut overlap = Overlap::new()?;
        let mut connected = false;
        if unsafe { ConnectNamedPipe(pipe.0, &mut overlap.state) } == 0 {
            match unsafe { GetLastError() } {
                ERROR_IO_PENDING => {}
                ERROR_PIPE_CONNECTED => {
                    connected = true;
                    unsafe {
                        SetEvent(overlap.state.hEvent);
                    }
                }
                _ => return Err(io::Error::last_os_error().into()),
            }
        }
        Ok(Self {
            pipe,
            overlap: Some(overlap),
            connected,
        })
    }
    fn ready(&self, timeout: Duration) -> Result<bool> {
        let ov = self.overlap.as_ref().ok_or(Error::InvalidEndpoint)?;
        match unsafe {
            WaitForSingleObject(
                ov.state.hEvent,
                timeout.as_millis().min((u32::MAX - 1) as u128) as u32,
            )
        } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(io::Error::last_os_error().into()),
        }
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        if let Some(ov) = self.overlap.take()
            && !cancel_drain(self.pipe.0, &ov.state)
        {
            IO_POISONED.store(true, Ordering::Release);
            mem::forget(ov);
            mem::forget(self.pipe.clone());
        }
    }
}
struct Permit(Arc<AtomicUsize>);
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
/// Accepted native stream. The endpoint retains its owner lock independently.
pub struct PipeStream {
    pipe: Arc<Handle>,
    _process: Handle,
    _permit: Option<Permit>,
    sid: String,
}
struct KernelPeer<'a>(&'a str);
impl TrustedLocalPeerAdapter for KernelPeer<'_> {
    fn connected_owner(&self) -> std::result::Result<LocalOsOwner, &'static str> {
        Ok(LocalOsOwner::WindowsSid(self.0.to_owned()))
    }
}
fn authenticate(stream: &PipeStream, expected: &str) -> Result<AuthenticatedLocalPeer> {
    AuthenticatedLocalPeer::from_os_adapter(
        &KernelPeer(&stream.sid),
        &LocalOsOwner::WindowsSid(expected.to_owned()),
    )
    .map_err(|_| Error::PermissionDenied)
}
fn peer_process(pipe: HANDLE, server: bool, sid: &str) -> Result<(Handle, u32)> {
    let mut pid = 0;
    unsafe {
        check(if server {
            GetNamedPipeServerProcessId(pipe, &mut pid)
        } else {
            GetNamedPipeClientProcessId(pipe, &mut pid)
        })?;
    }
    if pid == 0 {
        return Err(Error::PermissionDenied);
    }
    let process = Handle::new(unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid)
    })?;
    if unsafe { WaitForSingleObject(process.0, 0) } != WAIT_TIMEOUT
        || process_sid(process.0)? != sid
    {
        return Err(Error::PermissionDenied);
    }
    Ok((process, pid))
}
pub struct OwnerEndpoint {
    listener: Mutex<Option<Listener>>,
    lock: OwnerLock,
    discovery: LocalDiscovery,
    discovery_identity: Option<Object>,
    active: Arc<AtomicUsize>,
    name: String,
}
impl OwnerEndpoint {
    pub fn bind(lock: OwnerLock, discovery: LocalDiscovery) -> Result<Self> {
        discovery.validate()?;
        lock.profile.check_current()?;
        let name = pipe_name(&lock.profile, discovery.profile_id);
        let listener = Listener::new(&name, &lock.profile.sid, true)?;
        let mut this = Self {
            listener: Mutex::new(Some(listener)),
            lock,
            discovery,
            discovery_identity: None,
            active: Arc::new(AtomicUsize::new(0)),
            name,
        };
        let output = this.lock.profile.path.join(DISCOVERY);
        match open_regular(&output, false, false, &this.lock.profile.sid) {
            Ok(_) => {}
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let temporary = this
            .lock
            .profile
            .path
            .join(format!("discovery-{}.tmp", Uuid::new_v4()));
        let sd = security(&this.lock.profile.sid, false)?;
        let h = Handle::new(unsafe {
            CreateFileW(
                wide(&temporary).as_ptr(),
                GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                0,
                &sd.attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        })?;
        let raw = h.0;
        mem::forget(h);
        let mut file = unsafe { File::from_raw_handle(raw) };
        let result = (|| {
            serde_json::to_writer(&mut file, &this.discovery)
                .map_err(|_| Error::InvalidEndpoint)?;
            file.sync_all()?;
            Ok(())
        })();
        drop(file);
        if let Err(e) = result {
            let _ = fs::remove_file(&temporary);
            return Err(e);
        }
        if unsafe {
            MoveFileExW(
                wide(&temporary).as_ptr(),
                wide(&output).as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            let _ = fs::remove_file(&temporary);
            return Err(io::Error::last_os_error().into());
        }
        let published = open_regular(&output, false, false, &this.lock.profile.sid)?;
        this.discovery_identity = Some(object(&information(published.as_raw_handle())?));
        Ok(this)
    }
    pub fn discovery(&self) -> &LocalDiscovery {
        &self.discovery
    }
    pub fn profile(&self) -> &PrivateProfile {
        &self.lock.profile
    }
    pub fn wait(&self, timeout: Duration) -> Result<bool> {
        if self.active.load(Ordering::Acquire) >= MAX_CONNECTIONS {
            return Ok(false);
        }
        self.listener
            .lock()
            .map_err(|_| Error::InvalidEndpoint)?
            .as_ref()
            .ok_or(Error::InvalidEndpoint)?
            .ready(timeout)
    }
    pub fn accept(&self) -> Result<Option<PipeStream>> {
        if self.active.load(Ordering::Acquire) >= MAX_CONNECTIONS {
            return Ok(None);
        }
        self.lock.profile.check_current()?;
        let mut guard = self.listener.lock().map_err(|_| Error::InvalidEndpoint)?;
        if self.active.load(Ordering::Acquire) >= MAX_CONNECTIONS {
            return Ok(None);
        }
        let old = guard.as_ref().ok_or(Error::InvalidEndpoint)?;
        if !old.ready(Duration::ZERO)? {
            return Ok(None);
        }
        // Install the next instance even when this peer disconnected early.
        // A failed connect/identity check cannot leave a permanently ready slot.
        let next = Listener::new(&self.name, &self.lock.profile.sid, false)?;
        let mut old = guard.replace(next).ok_or(Error::InvalidEndpoint)?;
        let mut completed = 0;
        let ov = old.overlap.as_ref().ok_or(Error::InvalidEndpoint)?;
        if !old.connected
            && unsafe { GetOverlappedResult(old.pipe.0, &ov.state, &mut completed, 0) } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        old.overlap.take();
        let (process, _) = peer_process(old.pipe.0, false, &self.lock.profile.sid)?;
        self.active.fetch_add(1, Ordering::AcqRel);
        Ok(Some(PipeStream {
            pipe: old.pipe.clone(),
            _process: process,
            _permit: Some(Permit(self.active.clone())),
            sid: self.lock.profile.sid.clone(),
        }))
    }
    pub fn handshake(&self, stream: PipeStream) -> Result<LocalConnection> {
        let peer = authenticate(&stream, &self.lock.profile.sid)?;
        let mut connection = LocalConnection::new(stream, Instant::now() + HANDSHAKE_TIMEOUT)?;
        let hello: LocalClientHello = connection.read()?;
        let reply = ipc::answer_local_hello(
            &hello,
            &peer,
            &LocalOsOwner::WindowsSid(self.lock.profile.sid.clone()),
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
        let path = self.lock.profile.path.join(DISCOVERY);
        if let Ok(file) = open_regular(&path, false, false, &self.lock.profile.sid) {
            let same = information(file.as_raw_handle())
                .is_ok_and(|info| Some(object(&info)) == self.discovery_identity);
            drop(file);
            if same {
                let _ = fs::remove_file(path);
            }
        }
    }
}
struct IoOperation {
    overlap: Box<Overlap>,
    buffer: Vec<u8>,
    _pipe: Arc<Handle>,
}
pub struct LocalConnection {
    stream: PipeStream,
    deadline: Instant,
    version: LocalIpcVersion,
    poisoned: bool,
}
impl LocalConnection {
    fn new(stream: PipeStream, deadline: Instant) -> Result<Self> {
        Ok(Self {
            stream,
            deadline,
            version: LocalIpcVersion::CURRENT,
            poisoned: false,
        })
    }
    pub fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = deadline;
    }
    pub fn version(&self) -> LocalIpcVersion {
        self.version.clone()
    }
    fn poison(&mut self) {
        self.poisoned = true;
        unsafe {
            CancelIoEx(self.stream.pipe.0, ptr::null());
        }
        self.stream.pipe.close();
    }
    pub fn wait_readable(&self, timeout: Duration) -> Result<bool> {
        if self.poisoned {
            return Err(Error::InvalidFrame);
        }
        let deadline = Instant::now().checked_add(timeout).ok_or(Error::Deadline)?;
        loop {
            let mut available = 0;
            if unsafe {
                PeekNamedPipe(
                    self.stream.pipe.0,
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    &mut available,
                    ptr::null_mut(),
                )
            } == 0
            {
                if unsafe { GetLastError() } == ERROR_BROKEN_PIPE {
                    return Ok(true);
                }
                return Err(io::Error::last_os_error().into());
            }
            if available > 0 {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(
                Duration::from_millis(2).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }
    fn io(&mut self, buffer: &mut [u8], write: bool) -> io::Result<usize> {
        if self.poisoned || IO_POISONED.load(Ordering::Acquire) {
            return Err(io::Error::other("local transport unavailable"));
        }
        if Instant::now() >= self.deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if buffer.is_empty() {
            return Ok(0);
        }
        let size = buffer.len().min(ipc::LOCAL_IPC_FRAME_BYTES + 4);
        let mut op = Box::new(IoOperation {
            overlap: Overlap::new()?,
            buffer: if write {
                buffer[..size].to_vec()
            } else {
                vec![0; size]
            },
            _pipe: self.stream.pipe.clone(),
        });
        let mut transferred = 0;
        let success = unsafe {
            if write {
                WriteFile(
                    self.stream.pipe.0,
                    op.buffer.as_ptr(),
                    size as u32,
                    ptr::null_mut(),
                    &mut op.overlap.state,
                )
            } else {
                ReadFile(
                    self.stream.pipe.0,
                    op.buffer.as_mut_ptr(),
                    size as u32,
                    ptr::null_mut(),
                    &mut op.overlap.state,
                )
            }
        };
        if success == 0 {
            let error = unsafe { GetLastError() };
            if error != ERROR_IO_PENDING {
                return Err(io::Error::from_raw_os_error(error as i32));
            }
            let wait =
                unsafe { WaitForSingleObject(op.overlap.state.hEvent, millis(self.deadline)) };
            if wait != WAIT_OBJECT_0 {
                if !cancel_drain(self.stream.pipe.0, &op.overlap.state) {
                    IO_POISONED.store(true, Ordering::Release);
                    mem::forget(op);
                }
                self.poison();
                return Err(if wait == WAIT_TIMEOUT {
                    io::ErrorKind::TimedOut.into()
                } else {
                    io::Error::last_os_error()
                });
            }
        }
        // lpNumberOfBytes{Read,Written} stays NULL: every kernel-referenced
        // address belongs to the owned operation, including cancellation fallback.
        unsafe {
            check(GetOverlappedResult(
                self.stream.pipe.0,
                &op.overlap.state,
                &mut transferred,
                0,
            ))?;
        }
        if Instant::now() > self.deadline {
            self.poison();
            return Err(io::ErrorKind::TimedOut.into());
        }
        let n = transferred as usize;
        if n > size {
            return Err(io::Error::other("invalid local IO size"));
        }
        if !write {
            buffer[..n].copy_from_slice(&op.buffer[..n]);
        }
        Ok(n)
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
            .is_some_and(|v| v != 1)
        {
            return Err(Error::Incompatible);
        }
        let result = serde_json::from_slice(&payload).map_err(|_| Error::InvalidFrame);
        if Instant::now() > self.deadline {
            self.poison();
            return Err(Error::Deadline);
        }
        result
    }
    pub fn write(&mut self, value: &impl Serialize) -> Result<()> {
        let frame = ipc::encode_local_frame(value).map_err(|_| Error::InvalidFrame)?;
        self.write_all(&frame)?;
        if Instant::now() > self.deadline {
            self.poison();
            return Err(Error::Deadline);
        }
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
        self.io(buffer, false)
    }
}
impl Write for LocalConnection {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.io(
            &mut buffer[..buffer.len().min(ipc::LOCAL_IPC_FRAME_BYTES + 4)].to_vec(),
            true,
        )
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct LocalClient {
    connection: LocalConnection,
    discovery: LocalDiscovery,
    server_process_id: u32,
    events: std::collections::VecDeque<(usize, ipc::LocalStreamEvent)>,
    event_bytes: usize,
    subscriptions: std::collections::HashMap<String, StreamBinding>,
    poisoned: bool,
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
enum StreamBinding {
    Terminal(lomi_remote_protocol::TerminalContext),
    Workspace(lomi_remote_protocol::WorkspaceContext),
    Files(lomi_remote_protocol::WorkspaceContext),
}
impl LocalClient {
    pub fn connect(profile: &Path) -> Result<Self> {
        Self::connect_with_timeout(profile, HANDSHAKE_TIMEOUT)
    }
    pub fn connect_with_timeout(path: &Path, timeout: Duration) -> Result<Self> {
        let deadline = Instant::now().checked_add(timeout).ok_or(Error::Deadline)?;
        let profile = PrivateProfile::open(path, false)?;
        let file = open_regular(&profile.path.join(DISCOVERY), false, false, &profile.sid)?;
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
        let name = wide(pipe_name(&profile, discovery.profile_id));
        let pipe = loop {
            if Instant::now() >= deadline {
                return Err(Error::Deadline);
            }
            let handle = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    ptr::null_mut(),
                )
            };
            if handle != INVALID_HANDLE_VALUE {
                break Arc::new(Handle::new(handle)?);
            }
            let error = unsafe { GetLastError() };
            if error != ERROR_PIPE_BUSY {
                return Err(io::Error::from_raw_os_error(error as i32).into());
            }
            if unsafe { WaitNamedPipeW(name.as_ptr(), millis(deadline)) } == 0 {
                return Err(if unsafe { GetLastError() } == ERROR_SEM_TIMEOUT {
                    Error::Deadline
                } else {
                    io::Error::last_os_error().into()
                });
            }
        };
        // The server's PID/SID come only from the connected pipe and process token.
        let (process, server_process_id) = peer_process(pipe.0, true, &profile.sid)?;
        profile.check_current()?;
        let stream = PipeStream {
            pipe,
            _process: process,
            _permit: None,
            sid: profile.sid.clone(),
        };
        let peer = authenticate(&stream, &profile.sid)?;
        let hello = LocalClientHello {
            version: LocalIpcVersion::CURRENT,
            profile_id: discovery.profile_id,
            nonce: IpcNonce::from_bytes(Uuid::new_v4().into_bytes())
                .map_err(|_| Error::InvalidFrame)?,
        };
        let mut probe = LocalHelloProbe::new(
            hello.clone(),
            discovery.host_id,
            discovery.runtime_id,
            LocalOsOwner::WindowsSid(profile.sid),
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
            server_process_id,
            events: std::collections::VecDeque::new(),
            event_bytes: 0,
            subscriptions: std::collections::HashMap::new(),
            poisoned: false,
        })
    }
    pub fn discovery(&self) -> &LocalDiscovery {
        &self.discovery
    }
    /// PID returned by GetNamedPipeServerProcessId for the connected pipe.
    /// The corresponding process handle and its SID/liveness checks remain
    /// retained by this client connection.
    pub fn server_process_id(&self) -> u32 {
        self.server_process_id
    }
    pub fn request(&mut self, call: LocalCall) -> Result<LocalResponse> {
        self.request_with_timeout(call, REQUEST_TIMEOUT)
    }
    /// One absolute budget for the complete request, including stream events.
    /// A failed or expired request poisons this connection like `request`.
    pub fn request_with_timeout(
        &mut self,
        call: LocalCall,
        timeout: Duration,
    ) -> Result<LocalResponse> {
        if self.poisoned {
            return Err(Error::InvalidFrame);
        }
        let result = Instant::now()
            .checked_add(timeout)
            .ok_or(Error::Deadline)
            .and_then(|deadline| self.request_inner(call, None, deadline));
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
            self.request_inner(call, Some(handler), Instant::now() + REQUEST_TIMEOUT)
        })();
        if result.is_err() {
            self.poison();
        }
        result
    }
    fn poison(&mut self) {
        self.poisoned = true;
        self.connection.poison();
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
        deadline: Instant,
    ) -> Result<LocalResponse> {
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        self.connection.set_deadline(deadline);
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
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
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
