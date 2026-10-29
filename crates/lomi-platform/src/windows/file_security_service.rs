//! Explicitly installed LocalSystem broker for Windows audit-SACL operations.
//!
//! The ordinary host service remains an unprivileged, per-account service.
//! This adapter installs a separate automatic LocalSystem service only after
//! an elevated administrator confirms the selected ordinary account SID. Its
//! executable is a signed, hash-addressed copy in a protected ProgramData tree.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::{OsStr, OsString, c_void},
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    mem,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Component, Path, PathBuf},
    ptr,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;
use windows_service::{
    define_windows_service,
    service::{
        Service, ServiceAccess, ServiceConfig, ServiceControl, ServiceControlAccept,
        ServiceErrorControl, ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState,
        ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use windows_sys::Win32::{
    Foundation::{GetLastError, *},
    Security::WinTrust::{
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
        WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4, WTD_REVOKE_NONE,
        WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTD_UICONTEXT_INSTALL,
        WinVerifyTrust,
    },
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            ConvertStringSidToSidW, GetSecurityInfo, SE_FILE_OBJECT, SE_SERVICE, SetSecurityInfo,
        },
        *,
    },
    Storage::FileSystem::{
        FindClose, FindFirstStreamW, FindNextStreamW, WIN32_FIND_STREAM_DATA, *,
    },
    System::{
        Com::CoTaskMemFree,
        Services::{
            ChangeServiceConfig2W, QueryServiceConfig2W, SERVICE_ALL_ACCESS,
            SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, SERVICE_ENUMERATE_DEPENDENTS,
            SERVICE_INTERROGATE, SERVICE_PAUSE_CONTINUE, SERVICE_QUERY_CONFIG,
            SERVICE_QUERY_STATUS, SERVICE_REQUIRED_PRIVILEGES_INFOW, SERVICE_START, SERVICE_STOP,
            SERVICE_USER_DEFINED_CONTROL,
        },
        SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
        Threading::*,
    },
    UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath},
};

const ROOT: &str = "LomiRemoteFileSecurity";
const RELEASES: &str = "releases";
const RELEASE_SOURCES: &str = "sources";
const BINARY: &str = "lomiremote.exe";
const REGISTRATION: &str = "registration.json";
const UPGRADE: &str = "upgrade.pending.json";
const SYSTEM_SID: &str = "S-1-5-18";
const ADMIN_SID: &str = "S-1-5-32-544";
const TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const SERVICE_PREFIX: &str = "LomiFileSecurity-";
const MAX_REGISTRATION: u64 = 16 * 1024;
const MAX_RELEASE_SOURCE: u64 = 256 * 1024 * 1024;
const MAX_TRUST_BUFFER: u32 = 16 * 1024;
const WAIT: Duration = Duration::from_secs(45);
const POLL: Duration = Duration::from_millis(100);
const MANAGEMENT_LOCK: &str = "management.lock";
const REQUIRED_PRIVILEGES: [&str; 3] = [
    "SeSecurityPrivilege",
    "SeImpersonatePrivilege",
    "SeChangeNotifyPrivilege",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Conflict,
    AdministratorRequired,
    Manager,
    Deadline,
    NotReady,
    NotInstalled,
    ProtectedPath,
    UnsignedExecutable,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "FILE_SECURITY_SERVICE_INVALID_ARGUMENT",
            Self::Conflict => "FILE_SECURITY_SERVICE_OWNERSHIP_CONFLICT",
            Self::AdministratorRequired => "FILE_SECURITY_SERVICE_REQUIRES_ELEVATED_ADMINISTRATOR",
            Self::Manager => "FILE_SECURITY_SERVICE_MANAGER_UNAVAILABLE",
            Self::Deadline => "FILE_SECURITY_SERVICE_OPERATION_UNCERTAIN",
            Self::NotReady => "FILE_SECURITY_SERVICE_RECOVERY_REQUIRED",
            Self::NotInstalled => "FILE_SECURITY_SERVICE_NOT_INSTALLED",
            Self::ProtectedPath => "FILE_SECURITY_SERVICE_PROTECTED_PATH_INVALID",
            Self::UnsignedExecutable => "FILE_SECURITY_SERVICE_SIGNED_EXECUTABLE_REQUIRED",
        })
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Intent,
    Registered,
    Deleting,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Registration {
    version: u8,
    #[serde(rename = "ownerSID")]
    owner_sid: String,
    #[serde(rename = "serviceName")]
    service_name: String,
    #[serde(rename = "executableSHA256")]
    executable_sha256: String,
    #[serde(rename = "installationID")]
    installation_id: String,
    phase: Phase,
}

/// Both endpoints remain pinned while SCM and our registration are reconciled.
/// A restarted command may select either signed endpoint, including rollback.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Upgrade {
    version: u8,
    previous: Registration,
    next: Registration,
    restart: bool,
}

#[derive(Clone)]
struct Layout {
    program_data: PathBuf,
    root: PathBuf,
    owner: PathBuf,
    objects: PathBuf,
    registration: PathBuf,
}
impl Layout {
    fn for_owner(owner_sid: &str) -> Result<Self> {
        let program_data = program_data()?;
        let owner_hash = sha256(owner_sid.as_bytes());
        let root = program_data.join(ROOT);
        let owner = root.join(owner_hash);
        let objects = owner.join("objects");
        let registration = owner.join(REGISTRATION);
        Ok(Self {
            program_data,
            root,
            owner,
            objects,
            registration,
        })
    }
    fn executable(&self, digest: &str) -> PathBuf {
        self.objects.join(digest).join(BINARY)
    }
}

/// Pins the administrator-owned release area used to stage TUF-verified broker
/// images. The selected ordinary account is represented only by its SID hash;
/// it receives no access to this subtree.
pub struct BrokerReleaseArea {
    path: PathBuf,
    administrator_sid: String,
    _pins: Vec<File>,
    _directory: File,
}
impl BrokerReleaseArea {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Save an authenticated target under its digest and return a handle-pinned
    /// path suitable for `run`. The caller must retain the release TrustStore
    /// lock through this method and the adapter call; that lock serializes
    /// publication and recovery of the deterministic pending file.
    pub fn stage_source(&self, bytes: &[u8]) -> Result<BrokerReleaseSource> {
        if bytes.is_empty() || bytes.len() as u64 > MAX_RELEASE_SOURCE {
            return Err(Error::Invalid);
        }
        let sources = self.path.join(RELEASE_SOURCES);
        let source_directory = create_release_private_directory(&sources, &self.administrator_sid)?;
        let digest = sha256(bytes);
        let path = sources.join(format!("{digest}.exe"));
        let temporary = sources.join(format!(".{digest}.tmp"));

        remove_stale_release_temps(&sources, &self.administrator_sid)?;
        if release_path_exists(&path)? {
            let file = verified_release_source(
                &path,
                &self.administrator_sid,
                bytes.len() as u64,
                &digest,
            )?;
            return Ok(BrokerReleaseSource {
                path,
                _directory: source_directory,
                _file: file,
            });
        }

        let mut writer = create_release_private_file(&temporary, &self.administrator_sid)?;
        check_single_link_file(&writer, &temporary)?;
        validate_release_private_acl(&writer, &self.administrator_sid, false)?;
        validate_no_alternate_streams(&temporary)?;
        if writer.write_all(bytes).is_err() || writer.sync_all().is_err() {
            drop(writer);
            discard_release_temp(&temporary, &self.administrator_sid)?;
            return Err(Error::ProtectedPath);
        }
        drop(writer);
        drop(verified_release_source(
            &temporary,
            &self.administrator_sid,
            bytes.len() as u64,
            &digest,
        )?);

        match publish_release_source(&temporary, &path) {
            Ok(()) => {}
            Err(Error::Conflict) => {
                // Another administrator process may have published the same
                // digest. Reuse only an exact verified final object.
                let file = verified_release_source(
                    &path,
                    &self.administrator_sid,
                    bytes.len() as u64,
                    &digest,
                )?;
                discard_release_temp(&temporary, &self.administrator_sid)?;
                return Ok(BrokerReleaseSource {
                    path,
                    _directory: source_directory,
                    _file: file,
                });
            }
            Err(error) => return Err(error),
        }
        let file =
            verified_release_source(&path, &self.administrator_sid, bytes.len() as u64, &digest)?;
        Ok(BrokerReleaseSource {
            path,
            _directory: source_directory,
            _file: file,
        })
    }
}

/// A content-addressed source image held open against replacement while the
/// file-security service adapter rechecks its Authenticode signature.
pub struct BrokerReleaseSource {
    path: PathBuf,
    _directory: File,
    _file: File,
}
impl BrokerReleaseSource {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}
struct TaskMemory(*mut u16);
impl Drop for TaskMemory {
    fn drop(&mut self) {
        unsafe { CoTaskMemFree(self.0.cast()) };
    }
}
struct NativeHandle(HANDLE);
impl NativeHandle {
    fn new(value: HANDLE) -> Result<Self> {
        if value.is_null() || value == INVALID_HANDLE_VALUE {
            Err(Error::ProtectedPath)
        } else {
            Ok(Self(value))
        }
    }
}
impl Drop for NativeHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}
fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}
fn path_text(path: &Path) -> Result<String> {
    path.to_str().map(str::to_owned).ok_or(Error::Invalid)
}
fn local_absolute(path: &Path) -> Result<()> {
    let text = path_text(path)?;
    if !path.is_absolute()
        || text.starts_with(r"\\")
        || text.starts_with(r"\\?")
        || text.starts_with(r"\\.")
        || !text.as_bytes().get(1).is_some_and(|b| *b == b':')
        || text.chars().any(|ch| ch.is_control() || ch == '\0')
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(Error::ProtectedPath);
    }
    Ok(())
}
fn normalized_path(path: &Path) -> Result<String> {
    local_absolute(path)?;
    let mut text = path_text(path)?.replace('/', "\\").to_ascii_lowercase();
    while text.len() > 3 && text.ends_with('\\') {
        text.pop();
    }
    Ok(text)
}
fn final_path(handle: HANDLE) -> Result<PathBuf> {
    let needed = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            ptr::null_mut(),
            0,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    if needed == 0 || needed > 32768 {
        return Err(Error::ProtectedPath);
    }
    let mut buffer = vec![0u16; needed as usize + 1];
    let written = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    if written == 0 || written as usize >= buffer.len() {
        return Err(Error::ProtectedPath);
    }
    let mut text = OsString::from_wide(&buffer[..written as usize])
        .into_string()
        .map_err(|_| Error::ProtectedPath)?;
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        text = rest.to_owned();
    } else {
        return Err(Error::ProtectedPath);
    }
    let path = PathBuf::from(text);
    local_absolute(&path)?;
    Ok(path)
}
fn check_final_path(handle: HANDLE, expected: &Path) -> Result<()> {
    if normalized_path(&final_path(handle)?)? == normalized_path(expected)? {
        Ok(())
    } else {
        Err(Error::ProtectedPath)
    }
}
fn open_path(
    path: &Path,
    access: u32,
    share: u32,
    creation: u32,
    flags: u32,
    security: *const SECURITY_ATTRIBUTES,
) -> Result<File> {
    local_absolute(path)?;
    let name = wide(path.as_os_str());
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            share,
            security,
            creation,
            flags,
            ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(match unsafe { GetLastError() } {
            ERROR_ACCESS_DENIED => Error::ProtectedPath,
            _ => Error::ProtectedPath,
        });
    }
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}
fn open_directory(path: &Path) -> Result<File> {
    open_path(
        path,
        FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        ptr::null(),
    )
}
fn open_readonly_file(path: &Path) -> Result<File> {
    open_path(
        path,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT,
        ptr::null(),
    )
}
fn file_info(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = unsafe { mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) } == 0 {
        return Err(Error::ProtectedPath);
    }
    Ok(info)
}
fn check_directory(file: &File, path: &Path) -> Result<()> {
    let info = file_info(file)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(Error::ProtectedPath);
    }
    check_final_path(file.as_raw_handle().cast(), path)
}
fn check_regular_file(file: &File, path: &Path) -> Result<()> {
    let info = file_info(file)?;
    if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || info.nNumberOfLinks == 0
    {
        return Err(Error::ProtectedPath);
    }
    check_final_path(file.as_raw_handle().cast(), path)
}
fn check_single_link_file(file: &File, path: &Path) -> Result<BY_HANDLE_FILE_INFORMATION> {
    check_regular_file(file, path)?;
    let info = file_info(file)?;
    if info.nNumberOfLinks != 1 {
        return Err(Error::ProtectedPath);
    }
    Ok(info)
}
fn same_file_identity(
    left: &BY_HANDLE_FILE_INFORMATION,
    right: &BY_HANDLE_FILE_INFORMATION,
) -> bool {
    left.dwVolumeSerialNumber == right.dwVolumeSerialNumber
        && left.nFileIndexHigh == right.nFileIndexHigh
        && left.nFileIndexLow == right.nFileIndexLow
        && left.nNumberOfLinks == right.nNumberOfLinks
        && left.nFileSizeHigh == right.nFileSizeHigh
        && left.nFileSizeLow == right.nFileSizeLow
}
fn stream_name(data: &WIN32_FIND_STREAM_DATA) -> Result<String> {
    let end = data
        .cStreamName
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(Error::ProtectedPath)?;
    OsString::from_wide(&data.cStreamName[..end])
        .into_string()
        .map_err(|_| Error::ProtectedPath)
}
fn validate_no_alternate_streams(path: &Path) -> Result<()> {
    let path = wide(path.as_os_str());
    let mut data: WIN32_FIND_STREAM_DATA = unsafe { mem::zeroed() };
    let search = unsafe {
        FindFirstStreamW(
            path.as_ptr(),
            FindStreamInfoStandard,
            (&mut data as *mut WIN32_FIND_STREAM_DATA).cast(),
            0,
        )
    };
    if search.is_null() || search == INVALID_HANDLE_VALUE {
        return match unsafe { GetLastError() } {
            ERROR_INVALID_FUNCTION | ERROR_NOT_SUPPORTED => Ok(()),
            _ => Err(Error::ProtectedPath),
        };
    }
    let valid = loop {
        if !stream_name(&data).is_ok_and(|name| name.eq_ignore_ascii_case("::$DATA")) {
            break false;
        }
        if unsafe { FindNextStreamW(search, (&mut data as *mut WIN32_FIND_STREAM_DATA).cast()) }
            == 0
        {
            break unsafe { GetLastError() } == ERROR_HANDLE_EOF;
        }
    };
    unsafe { FindClose(search) };
    if valid {
        Ok(())
    } else {
        Err(Error::ProtectedPath)
    }
}

fn sid_text(sid: PSID) -> Result<String> {
    if sid.is_null() {
        return Err(Error::ProtectedPath);
    }
    let mut output = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut output) } == 0 || output.is_null() {
        return Err(Error::ProtectedPath);
    }
    let _output = Local(output.cast());
    let mut length = 0usize;
    unsafe {
        while *output.add(length) != 0 {
            length += 1;
            if length > 256 {
                return Err(Error::ProtectedPath);
            }
        }
        String::from_utf16(std::slice::from_raw_parts(output, length))
            .map_err(|_| Error::ProtectedPath)
    }
}
fn sid_from_text(value: &str) -> Result<Local> {
    let mut output = ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(wide(value).as_ptr(), &mut output) } == 0 || output.is_null()
    {
        return Err(Error::Invalid);
    }
    Ok(Local(output.cast()))
}
fn lookup_user_sid(sid: PSID) -> Result<()> {
    let (mut name_len, mut domain_len, mut kind) = (0u32, 0u32, 0i32);
    unsafe {
        LookupAccountSidW(
            ptr::null(),
            sid,
            ptr::null_mut(),
            &mut name_len,
            ptr::null_mut(),
            &mut domain_len,
            &mut kind,
        );
    }
    if name_len == 0 || name_len > 32768 || domain_len > 32768 {
        return Err(Error::Invalid);
    }
    let mut name = vec![0u16; name_len as usize];
    let mut domain = vec![0u16; domain_len as usize];
    if unsafe {
        LookupAccountSidW(
            ptr::null(),
            sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    } == 0
        || kind != SidTypeUser
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn validate_owner_sid(value: &str) -> Result<String> {
    let parts: Vec<&str> = value.split('-').collect();
    if parts.len() != 8 || parts[..4] != ["S", "1", "5", "21"] {
        return Err(Error::Invalid);
    }
    for part in &parts[4..] {
        let number = part.parse::<u32>().map_err(|_| Error::Invalid)?;
        if number == 0 || number.to_string() != *part {
            return Err(Error::Invalid);
        }
    }
    let sid = sid_from_text(value)?;
    let canonical = sid_text(sid.0.cast())?;
    if canonical != value {
        return Err(Error::Invalid);
    }
    lookup_user_sid(sid.0.cast())?;
    Ok(canonical)
}
fn current_token_sid() -> Result<String> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(Error::AdministratorRequired);
    }
    let token = NativeHandle::new(token)?;
    let mut needed = 0u32;
    unsafe {
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 || needed > 65536 {
        return Err(Error::AdministratorRequired);
    }
    let mut storage = vec![0usize; (needed as usize).div_ceil(mem::size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            storage.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(Error::AdministratorRequired);
    }
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    sid_text(user.User.Sid)
}
fn unimpersonated() -> Result<()> {
    let mut token = ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } != 0 {
        unsafe { CloseHandle(token) };
        return Err(Error::Conflict);
    }
    if unsafe { GetLastError() } != ERROR_NO_TOKEN {
        return Err(Error::AdministratorRequired);
    }
    Ok(())
}
fn require_elevated_admin() -> Result<()> {
    unimpersonated()?;
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(Error::AdministratorRequired);
    }
    let token = NativeHandle::new(token)?;
    let mut elevation: TOKEN_ELEVATION = unsafe { mem::zeroed() };
    let mut returned = 0u32;
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    } == 0
        || elevation.TokenIsElevated == 0
    {
        return Err(Error::AdministratorRequired);
    }
    let admin = sid_from_text(ADMIN_SID)?;
    let mut member = 0;
    // A non-null token for CheckTokenMembership must be an impersonation
    // token. We have already rejected thread impersonation, so NULL checks
    // the effective process identity without passing a primary token.
    if unsafe { CheckTokenMembership(ptr::null_mut(), admin.0.cast(), &mut member) } == 0
        || member == 0
    {
        return Err(Error::AdministratorRequired);
    }
    Ok(())
}
fn program_data() -> Result<PathBuf> {
    let mut output = ptr::null_mut();
    let status =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, ptr::null_mut(), &mut output) };
    if status < 0 || output.is_null() {
        return Err(Error::ProtectedPath);
    }
    let _output = TaskMemory(output);
    let mut length = 0usize;
    unsafe {
        while *output.add(length) != 0 {
            length += 1;
            if length > 32768 {
                return Err(Error::ProtectedPath);
            }
        }
        let path = PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(
            output, length,
        )));
        local_absolute(&path)?;
        Ok(path)
    }
}

fn is_trusted_path_writer(sid: &str) -> bool {
    matches!(sid, SYSTEM_SID | ADMIN_SID | TRUSTED_INSTALLER_SID)
}
fn write_mask() -> u32 {
    FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | FILE_WRITE_EA
        | FILE_WRITE_ATTRIBUTES
        | FILE_ADD_SUBDIRECTORY
        | FILE_DELETE_CHILD
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | GENERIC_WRITE
        | GENERIC_ALL
}
fn security_descriptor(handle: HANDLE) -> Result<(Local, PSID, *mut ACL)> {
    let (mut descriptor, mut acl, mut owner) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    if unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    } != ERROR_SUCCESS
        || descriptor.is_null()
    {
        return Err(Error::ProtectedPath);
    }
    Ok((Local(descriptor), owner, acl))
}
fn validate_ancestor_acl(file: &File) -> Result<()> {
    let (descriptor, owner, acl) = security_descriptor(file.as_raw_handle().cast())?;
    if !is_trusted_path_writer(&sid_text(owner)?) || acl.is_null() {
        return Err(Error::ProtectedPath);
    }
    let mut present = 0;
    let mut dacl = ptr::null_mut();
    let mut defaulted = 0;
    if unsafe {
        GetSecurityDescriptorDacl(descriptor.0.cast(), &mut present, &mut dacl, &mut defaulted)
    } == 0
        || present == 0
        || dacl.is_null()
    {
        return Err(Error::ProtectedPath);
    }
    for index in 0..unsafe { (*dacl).AceCount } {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(dacl, index as u32, &mut ace) } == 0 {
            return Err(Error::ProtectedPath);
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        // An inherit-only ACE does not authorize mutation of this directory.
        if header.AceFlags & INHERIT_ONLY_ACE as u8 != 0 {
            continue;
        }
        if header.AceType == ACCESS_DENIED_ACE_TYPE as u8 {
            continue;
        }
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8 {
            return Err(Error::ProtectedPath);
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        // Creating a sibling in C:\\ or ProgramData cannot replace a pinned,
        // protected child. Standard Windows ancestors allow that operation.
        // Delete-child and descriptor/owner changes can replace that child.
        let ancestor_mutation = DELETE | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;
        if allowed.Mask & ancestor_mutation != 0
            && !is_trusted_path_writer(&sid_text(
                (&allowed.SidStart as *const u32).cast_mut().cast(),
            )?)
        {
            return Err(Error::ProtectedPath);
        }
    }
    Ok(())
}
fn validate_owned_acl(file: &File, owner_sid: Option<&str>, directory: bool) -> Result<()> {
    let (descriptor, owner, _) = security_descriptor(file.as_raw_handle().cast())?;
    if !matches!(sid_text(owner)?.as_str(), SYSTEM_SID | ADMIN_SID) {
        return Err(Error::ProtectedPath);
    }
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor.0.cast(), &mut control, &mut revision) }
        == 0
        || control & SE_DACL_PROTECTED == 0
    {
        return Err(Error::ProtectedPath);
    }
    let mut present = 0;
    let mut dacl = ptr::null_mut();
    let mut defaulted = 0;
    if unsafe {
        GetSecurityDescriptorDacl(descriptor.0.cast(), &mut present, &mut dacl, &mut defaulted)
    } == 0
        || present == 0
        || dacl.is_null()
    {
        return Err(Error::ProtectedPath);
    }
    let mut system_full = false;
    let mut admin_full = false;
    let mut owner_read = owner_sid.is_none();
    for index in 0..unsafe { (*dacl).AceCount } {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(dacl, index as u32, &mut ace) } == 0 {
            return Err(Error::ProtectedPath);
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceType == ACCESS_DENIED_ACE_TYPE as u8 {
            continue;
        }
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8 {
            return Err(Error::ProtectedPath);
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = sid_text((&allowed.SidStart as *const u32).cast_mut().cast())?;
        if allowed.Mask & write_mask() != 0 && !matches!(sid.as_str(), SYSTEM_SID | ADMIN_SID) {
            return Err(Error::ProtectedPath);
        }
        if sid == SYSTEM_SID && allowed.Mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS {
            system_full = true;
        }
        if sid == ADMIN_SID && allowed.Mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS {
            admin_full = true;
        }
        if owner_sid == Some(sid.as_str())
            && allowed.Mask & (GENERIC_READ | FILE_READ_DATA | FILE_LIST_DIRECTORY) != 0
        {
            owner_read = true;
        }
        if let Some(owner_sid) = owner_sid
            && sid == owner_sid
            && allowed.Mask & write_mask() != 0
        {
            return Err(Error::ProtectedPath);
        }
    }
    let _ = directory;
    if !system_full || !admin_full || !owner_read {
        return Err(Error::ProtectedPath);
    }
    Ok(())
}
fn validate_admin_only_acl(file: &File) -> Result<()> {
    let (descriptor, owner, _) = security_descriptor(file.as_raw_handle().cast())?;
    if !matches!(sid_text(owner)?.as_str(), SYSTEM_SID | ADMIN_SID) {
        return Err(Error::ProtectedPath);
    }
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor.0.cast(), &mut control, &mut revision) }
        == 0
        || control & SE_DACL_PROTECTED == 0
    {
        return Err(Error::ProtectedPath);
    }
    let mut present = 0;
    let mut dacl = ptr::null_mut();
    let mut defaulted = 0;
    if unsafe {
        GetSecurityDescriptorDacl(descriptor.0.cast(), &mut present, &mut dacl, &mut defaulted)
    } == 0
        || present == 0
        || dacl.is_null()
    {
        return Err(Error::ProtectedPath);
    }
    let mut system_full = false;
    let mut admin_full = false;
    for index in 0..unsafe { (*dacl).AceCount } {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(dacl, index as u32, &mut ace) } == 0 {
            return Err(Error::ProtectedPath);
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceType == ACCESS_DENIED_ACE_TYPE as u8 {
            continue;
        }
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8 {
            return Err(Error::ProtectedPath);
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = sid_text((&allowed.SidStart as *const u32).cast_mut().cast())?;
        if sid == SYSTEM_SID && allowed.Mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS {
            system_full = true;
        } else if sid == ADMIN_SID && allowed.Mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS {
            admin_full = true;
        } else if !matches!(sid.as_str(), SYSTEM_SID | ADMIN_SID) {
            return Err(Error::ProtectedPath);
        }
    }
    if system_full && admin_full {
        Ok(())
    } else {
        Err(Error::ProtectedPath)
    }
}
fn set_file_dacl(file: &File, sddl: &str) -> Result<()> {
    let descriptor = SecurityDescriptor::new(sddl)?;
    let mut present = 0;
    let mut acl = ptr::null_mut();
    let mut defaulted = 0;
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor.descriptor.0.cast(),
            &mut present,
            &mut acl,
            &mut defaulted,
        )
    } == 0
        || present == 0
        || acl.is_null()
        || unsafe {
            SetSecurityInfo(
                file.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                acl,
                ptr::null_mut(),
            )
        } != ERROR_SUCCESS
    {
        return Err(Error::ProtectedPath);
    }
    Ok(())
}
fn validate_directory_chain(path: &Path, owner_sid: Option<&str>) -> Result<Vec<File>> {
    local_absolute(path)?;
    let mut current = PathBuf::new();
    let mut handles = Vec::new();
    let components: Vec<Component<'_>> = path.components().collect();
    if components.len() < 2 {
        return Err(Error::ProtectedPath);
    }
    for component in components {
        match component {
            Component::Prefix(prefix) => {
                current.push(prefix.as_os_str());
                // A drive prefix alone is drive-relative (C:). Hold and
                // validate it only after RootDir has made it absolute.
                continue;
            }
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(name) => current.push(name),
            Component::CurDir | Component::ParentDir => return Err(Error::ProtectedPath),
        }
        let handle = open_directory(&current)?;
        check_directory(&handle, &current)?;
        validate_ancestor_acl(&handle)?;
        handles.push(handle);
    }
    if let Some(owner) = owner_sid {
        let last = handles.last().ok_or(Error::ProtectedPath)?;
        validate_owned_acl(last, Some(owner), true)?;
    }
    Ok(handles)
}
fn directory_sddl(owner_sid: Option<&str>) -> String {
    match owner_sid {
        Some(owner) => format!(
            "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GX;;;AU)(A;OICI;GRGX;;;{owner})"
        ),
        None => "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GX;;;AU)".into(),
    }
}
fn file_sddl(owner_sid: &str) -> String {
    format!("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;{owner_sid})")
}
struct SecurityDescriptor {
    descriptor: Local,
    attributes: SECURITY_ATTRIBUTES,
}
impl SecurityDescriptor {
    fn new(sddl: &str) -> Result<Self> {
        let mut descriptor = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl).as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
            || descriptor.is_null()
        {
            return Err(Error::ProtectedPath);
        }
        Ok(Self {
            descriptor: Local(descriptor.cast()),
            attributes: SECURITY_ATTRIBUTES {
                nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            },
        })
    }
}
fn create_directory(path: &Path, owner_sid: Option<&str>) -> Result<()> {
    let descriptor = SecurityDescriptor::new(&directory_sddl(owner_sid))?;
    let result = unsafe {
        CreateDirectoryW(
            wide(path.as_os_str()).as_ptr(),
            &descriptor.attributes as *const SECURITY_ATTRIBUTES,
        )
    };
    if result == 0 {
        match unsafe { GetLastError() } {
            ERROR_ALREADY_EXISTS => {}
            ERROR_ACCESS_DENIED => return Err(Error::AdministratorRequired),
            _ => return Err(Error::ProtectedPath),
        }
    }
    let handle = open_directory(path)?;
    check_directory(&handle, path)?;
    validate_owned_acl(&handle, owner_sid, true)?;
    Ok(())
}
fn ensure_layout(layout: &Layout, owner_sid: &str, digest: &str) -> Result<Vec<File>> {
    let mut pins = validate_directory_chain(&layout.program_data, None)?;
    create_directory(&layout.root, None)?;
    pins.extend(validate_directory_chain(&layout.root, None)?);
    create_directory(&layout.owner, Some(owner_sid))?;
    pins.extend(validate_directory_chain(&layout.owner, Some(owner_sid))?);
    create_directory(&layout.objects, Some(owner_sid))?;
    pins.extend(validate_directory_chain(&layout.objects, Some(owner_sid))?);
    let object_dir = layout.objects.join(digest);
    create_directory(&object_dir, Some(owner_sid))?;
    pins.extend(validate_directory_chain(&object_dir, Some(owner_sid))?);
    Ok(pins)
}

/// Create or validate the separate administrator-only release area for a
/// selected ordinary account. A different elevated administrator identity
/// cannot adopt an existing area because its leaf DACL must match the current
/// token SID exactly.
pub fn prepare_broker_release_area(owner_sid: &str) -> Result<BrokerReleaseArea> {
    let owner_sid = validate_owner_sid(owner_sid)?;
    require_elevated_admin()?;
    let administrator_sid = current_token_sid()?;
    if owner_sid == administrator_sid {
        return Err(Error::Conflict);
    }

    let layout = Layout::for_owner(&owner_sid)?;
    let mut pins = validate_directory_chain(&layout.program_data, None)?;
    create_directory(&layout.root, None)?;
    pins.extend(validate_directory_chain(&layout.root, None)?);

    let release_root = layout.root.join(RELEASES);
    create_directory(&release_root, None)?;
    pins.extend(validate_directory_chain(&release_root, None)?);

    let path = release_root.join(sha256(owner_sid.as_bytes()));
    let directory = create_release_private_directory(&path, &administrator_sid)?;
    Ok(BrokerReleaseArea {
        path,
        administrator_sid,
        _pins: pins,
        _directory: directory,
    })
}

fn validate_release_private_acl(file: &File, owner_sid: &str, directory: bool) -> Result<()> {
    let (descriptor, owner, acl) = security_descriptor(file.as_raw_handle().cast())?;
    if sid_text(owner)? != owner_sid || acl.is_null() {
        return Err(Error::ProtectedPath);
    }
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor.0.cast(), &mut control, &mut revision) }
        == 0
        || control & SE_DACL_PROTECTED == 0
    {
        return Err(Error::ProtectedPath);
    }
    let mut present = 0;
    let mut dacl = ptr::null_mut();
    let mut defaulted = 0;
    if unsafe {
        GetSecurityDescriptorDacl(descriptor.0.cast(), &mut present, &mut dacl, &mut defaulted)
    } == 0
        || present == 0
        || dacl.is_null()
    {
        return Err(Error::ProtectedPath);
    }
    let expected_flags = if directory {
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    } else {
        0
    };
    let mut owner_full = false;
    for index in 0..unsafe { (*dacl).AceCount } {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(dacl, index as u32, &mut ace) } == 0 {
            return Err(Error::ProtectedPath);
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceType == ACCESS_DENIED_ACE_TYPE as u8 {
            continue;
        }
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8 {
            return Err(Error::ProtectedPath);
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = sid_text((&allowed.SidStart as *const u32).cast_mut().cast())?;
        let flags = header.AceFlags as u32 & !INHERITED_ACE;
        if sid != owner_sid || allowed.Mask != FILE_ALL_ACCESS || flags != expected_flags {
            return Err(Error::ProtectedPath);
        }
        owner_full = true;
    }
    if owner_full {
        Ok(())
    } else {
        Err(Error::ProtectedPath)
    }
}

fn create_release_private_directory(path: &Path, owner_sid: &str) -> Result<File> {
    let descriptor =
        SecurityDescriptor::new(&format!("O:{owner_sid}D:P(A;OICI;FA;;;{owner_sid})"))?;
    if unsafe {
        CreateDirectoryW(
            wide(path.as_os_str()).as_ptr(),
            &descriptor.attributes as *const SECURITY_ATTRIBUTES,
        )
    } == 0
    {
        match unsafe { GetLastError() } {
            ERROR_ALREADY_EXISTS => {}
            ERROR_ACCESS_DENIED => return Err(Error::AdministratorRequired),
            _ => return Err(Error::ProtectedPath),
        }
    }
    let directory = open_directory(path)?;
    check_directory(&directory, path)?;
    validate_release_private_acl(&directory, owner_sid, true)?;
    Ok(directory)
}

fn create_release_private_file(path: &Path, owner_sid: &str) -> Result<File> {
    let descriptor = SecurityDescriptor::new(&format!("O:{owner_sid}D:P(A;;FA;;;{owner_sid})"))?;
    let name = wide(path.as_os_str());
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ,
            &descriptor.attributes,
            CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return match unsafe { GetLastError() } {
            ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS => Err(Error::Conflict),
            ERROR_ACCESS_DENIED => Err(Error::AdministratorRequired),
            _ => Err(Error::ProtectedPath),
        };
    }
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}

fn open_release_private_file(path: &Path, owner_sid: &str) -> Result<File> {
    let file = open_path(
        path,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL,
        ptr::null(),
    )?;
    validate_release_private_acl(&file, owner_sid, false)?;
    Ok(file)
}

fn release_path_exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(Error::ProtectedPath),
    }
}

fn verified_release_source(
    path: &Path,
    owner_sid: &str,
    expected_size: u64,
    expected_digest: &str,
) -> Result<File> {
    let mut file = open_release_private_file(path, owner_sid)?;
    check_single_link_file(&file, path)?;
    validate_release_private_acl(&file, owner_sid, false)?;
    validate_no_alternate_streams(path)?;
    if file.metadata().map_err(|_| Error::ProtectedPath)?.len() != expected_size
        || hash_file(&mut file)? != expected_digest
    {
        return Err(Error::Conflict);
    }
    Ok(file)
}

fn discard_release_temp(path: &Path, owner_sid: &str) -> Result<()> {
    let file = open_release_private_file(path, owner_sid)?;
    check_single_link_file(&file, path)?;
    validate_release_private_acl(&file, owner_sid, false)?;
    validate_no_alternate_streams(path)?;
    if file.metadata().map_err(|_| Error::ProtectedPath)?.len() > MAX_RELEASE_SOURCE {
        return Err(Error::Conflict);
    }
    drop(file);
    std::fs::remove_file(path).map_err(|_| Error::ProtectedPath)
}

fn remove_stale_release_temps(directory: &Path, owner_sid: &str) -> Result<()> {
    for entry in std::fs::read_dir(directory).map_err(|_| Error::ProtectedPath)? {
        let entry = entry.map_err(|_| Error::ProtectedPath)?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(digest) = name
            .strip_prefix('.')
            .and_then(|name| name.strip_suffix(".tmp"))
        else {
            continue;
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            continue;
        }
        discard_release_temp(&entry.path(), owner_sid)?;
    }
    Ok(())
}

fn publish_release_source(temporary: &Path, destination: &Path) -> Result<()> {
    let temporary = wide(temporary.as_os_str());
    let destination = wide(destination.as_os_str());
    if unsafe {
        MoveFileExW(
            temporary.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } != 0
    {
        Ok(())
    } else {
        match unsafe { GetLastError() } {
            ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS => Err(Error::Conflict),
            _ => Err(Error::ProtectedPath),
        }
    }
}

fn validate_layout(layout: &Layout, owner_sid: &str, digest: &str) -> Result<Vec<File>> {
    let mut handles = validate_directory_chain(&layout.program_data, None)?;
    handles.extend(validate_directory_chain(&layout.root, None)?);
    handles.extend(validate_directory_chain(&layout.owner, Some(owner_sid))?);
    handles.extend(validate_directory_chain(&layout.objects, Some(owner_sid))?);
    handles.extend(validate_directory_chain(
        &layout.objects.join(digest),
        Some(owner_sid),
    )?);
    Ok(handles)
}

struct ManagementLock {
    _pins: Vec<File>,
    _lock: File,
}
fn ensure_management_parent(layout: &Layout, owner_sid: &str) -> Result<Vec<File>> {
    let mut pins = validate_directory_chain(&layout.program_data, None)?;
    create_directory(&layout.root, None)?;
    pins.extend(validate_directory_chain(&layout.root, None)?);
    create_directory(&layout.owner, Some(owner_sid))?;
    pins.extend(validate_directory_chain(&layout.owner, Some(owner_sid))?);
    Ok(pins)
}
fn acquire_management_lock(layout: &Layout, owner_sid: &str) -> Result<ManagementLock> {
    let pins = ensure_management_parent(layout, owner_sid)?;
    let path = layout.owner.join(MANAGEMENT_LOCK);
    let descriptor = SecurityDescriptor::new("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")?;
    let name = wide(path.as_os_str());
    let deadline = Instant::now() + WAIT;
    let handle = loop {
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_NONE,
                &descriptor.attributes,
                OPEN_ALWAYS,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
            break handle;
        }
        match unsafe { GetLastError() } {
            ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION => {
                if Instant::now() >= deadline {
                    return Err(Error::Deadline);
                }
                thread::sleep(POLL);
            }
            _ => return Err(Error::ProtectedPath),
        }
    };
    let lock = unsafe { File::from_raw_handle(handle.cast()) };
    check_single_link_file(&lock, &path)?;
    validate_admin_only_acl(&lock)?;
    if lock.metadata().map_err(|_| Error::ProtectedPath)?.len() != 0 {
        return Err(Error::Conflict);
    }
    Ok(ManagementLock {
        _pins: pins,
        _lock: lock,
    })
}

fn hash_file(file: &mut File) -> Result<String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| Error::ProtectedPath)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| Error::ProtectedPath)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| Error::ProtectedPath)?;
    Ok(format!("{:x}", hash.finalize()))
}
fn verify_authenticode(file: &File, path: &Path) -> Result<()> {
    let path = wide(path.as_os_str());
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path.as_ptr(),
        hFile: file.as_raw_handle().cast(),
        pgKnownSubject: ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4,
        dwUIContext: WTD_UICONTEXT_INSTALL,
        ..unsafe { mem::zeroed() }
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    let closed = unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    if status == ERROR_SUCCESS as i32 && closed == ERROR_SUCCESS as i32 {
        Ok(())
    } else {
        Err(Error::UnsignedExecutable)
    }
}
fn source_file(path: &Path) -> Result<File> {
    local_absolute(path)?;
    let file = open_path(
        path,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT,
        ptr::null(),
    )?;
    let final_path = final_path(file.as_raw_handle().cast())?;
    check_single_link_file(&file, &final_path)?;
    validate_no_alternate_streams(&final_path)?;
    Ok(file)
}
fn open_protected_file(path: &Path, owner_sid: &str) -> Result<File> {
    let file = open_readonly_file(path)?;
    check_single_link_file(&file, path)?;
    validate_owned_acl(&file, Some(owner_sid), false)?;
    validate_no_alternate_streams(path)?;
    Ok(file)
}
fn admin_only_sddl() -> &'static str {
    "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
}
fn open_admin_only_file(path: &Path) -> Result<File> {
    let file = open_readonly_file(path)?;
    check_single_link_file(&file, path)?;
    validate_admin_only_acl(&file)?;
    validate_no_alternate_streams(path)?;
    Ok(file)
}
fn promote_staged_image(path: &Path, owner_sid: &str, digest: &str) -> Result<()> {
    let mut file = open_path(
        path,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC,
        FILE_SHARE_READ,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT,
        ptr::null(),
    )?;
    check_single_link_file(&file, path)?;
    validate_admin_only_acl(&file)?;
    validate_no_alternate_streams(path)?;
    if hash_file(&mut file)? != digest {
        return Err(Error::Conflict);
    }
    verify_authenticode(&file, path)?;
    if hash_file(&mut file)? != digest {
        return Err(Error::Conflict);
    }
    set_file_dacl(&file, &file_sddl(owner_sid))?;
    validate_owned_acl(&file, Some(owner_sid), false)?;
    if hash_file(&mut file)? != digest {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn copy_pinned_image(
    source_path: &Path,
    source: &mut File,
    layout: &Layout,
    owner_sid: &str,
    digest: &str,
    installation_id: &str,
    phase: &Phase,
) -> Result<()> {
    let destination = layout.executable(digest);
    let temporary = destination.with_file_name(format!("{BINARY}.{installation_id}.pending"));
    match open_protected_file(&destination, owner_sid) {
        Ok(mut existing) => {
            if hash_file(&mut existing)? != digest {
                return Err(Error::Conflict);
            }
            verify_authenticode(&existing, &destination)?;
            if hash_file(&mut existing)? != digest {
                return Err(Error::Conflict);
            }
            discard_private_temp(&temporary)?;
            return Ok(());
        }
        Err(Error::ProtectedPath) => {
            if destination.exists() {
                // A crash after the atomic rename can leave the complete image
                // private to administrators. Only a durable Intent may finish
                // that ACL update after checking the bytes and signature.
                if *phase != Phase::Intent {
                    return Err(Error::Conflict);
                }
                promote_staged_image(&destination, owner_sid, digest)?;
                discard_private_temp(&temporary)?;
                return Ok(());
            }
        }
        Err(error) => return Err(error),
    }
    if *phase != Phase::Intent {
        return Err(Error::Conflict);
    }
    let security = SecurityDescriptor::new(admin_only_sddl())?;
    let mut target = match open_path(
        &temporary,
        FILE_WRITE_DATA | FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ,
        CREATE_NEW,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL,
        &security.attributes,
    ) {
        Ok(file) => file,
        Err(Error::ProtectedPath) if temporary.exists() => {
            // This deterministic name is bound to the durable installation ID
            // and is inaccessible to the selected owner while incomplete.
            let existing = open_admin_only_file(&temporary)?;
            check_single_link_file(&existing, &temporary)?;
            drop(existing);
            if unsafe {
                SetFileAttributesW(wide(temporary.as_os_str()).as_ptr(), FILE_ATTRIBUTE_NORMAL)
            } == 0
            {
                return Err(Error::ProtectedPath);
            }
            open_path(
                &temporary,
                FILE_WRITE_DATA | FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL,
                ptr::null(),
            )?
        }
        Err(error) => return Err(error),
    };
    check_single_link_file(&target, &temporary)?;
    validate_admin_only_acl(&target)?;
    validate_no_alternate_streams(&temporary)?;
    let source_identity = check_single_link_file(source, source_path)?;
    validate_no_alternate_streams(source_path)?;
    target.set_len(0).map_err(|_| Error::ProtectedPath)?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error::ProtectedPath)?;
    io::copy(source, &mut target).map_err(|_| Error::ProtectedPath)?;
    if !same_file_identity(
        &source_identity,
        &check_single_link_file(source, source_path)?,
    ) || hash_file(source)? != digest
    {
        return Err(Error::Conflict);
    }
    validate_no_alternate_streams(source_path)?;
    target.sync_all().map_err(|_| Error::ProtectedPath)?;
    if hash_file(&mut target)? != digest {
        return Err(Error::Conflict);
    }
    verify_authenticode(&target, &temporary)?;
    if hash_file(&mut target)? != digest {
        return Err(Error::Conflict);
    }
    validate_no_alternate_streams(&temporary)?;
    if unsafe {
        SetFileAttributesW(
            wide(temporary.as_os_str()).as_ptr(),
            FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM,
        )
    } == 0
    {
        return Err(Error::ProtectedPath);
    }
    target.sync_all().map_err(|_| Error::ProtectedPath)?;
    drop(target);
    let published = unsafe {
        MoveFileExW(
            wide(temporary.as_os_str()).as_ptr(),
            wide(destination.as_os_str()).as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } != 0;
    if !published && !destination.exists() {
        return Err(Error::ProtectedPath);
    }
    if *phase != Phase::Intent {
        return Err(Error::Conflict);
    }
    promote_staged_image(&destination, owner_sid, digest)?;
    discard_private_temp(&temporary)?;
    let mut pinned = open_protected_file(&destination, owner_sid)?;
    if hash_file(&mut pinned)? != digest {
        return Err(Error::Conflict);
    }
    verify_authenticode(&pinned, &destination)?;
    if hash_file(&mut pinned)? != digest {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn discard_private_temp(path: &Path) -> Result<()> {
    let file = match open_admin_only_file(path) {
        Ok(file) => file,
        Err(Error::ProtectedPath) if !path.exists() => return Ok(()),
        Err(error) => return Err(error),
    };
    drop(file);
    if unsafe { SetFileAttributesW(wide(path.as_os_str()).as_ptr(), FILE_ATTRIBUTE_NORMAL) } == 0 {
        return Err(Error::ProtectedPath);
    }
    if unsafe { DeleteFileW(wide(path.as_os_str()).as_ptr()) } == 0 {
        return Err(Error::ProtectedPath);
    }
    Ok(())
}

fn registration_path(layout: &Layout) -> Result<Option<File>> {
    protected_record_path(&layout.registration)
}
fn protected_record_path(path: &Path) -> Result<Option<File>> {
    match open_readonly_file(path) {
        Ok(file) => {
            check_single_link_file(&file, path)?;
            validate_no_alternate_streams(path)?;
            Ok(Some(file))
        }
        Err(Error::ProtectedPath) => {
            if std::fs::symlink_metadata(path).is_ok() {
                Err(Error::Conflict)
            } else {
                Ok(None)
            }
        }
        Err(error) => Err(error),
    }
}
fn load_registration(layout: &Layout, owner_sid: &str) -> Result<Option<Registration>> {
    let Some(mut file) = registration_path(layout)? else {
        return Ok(None);
    };
    validate_owned_acl(&file, Some(owner_sid), false)?;
    let size = file.metadata().map_err(|_| Error::ProtectedPath)?.len();
    if size == 0 || size > MAX_REGISTRATION {
        return Err(Error::Conflict);
    }
    let mut bytes = Vec::with_capacity(size as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| Error::ProtectedPath)?;
    let record: Registration = serde_json::from_slice(&bytes).map_err(|_| Error::Conflict)?;
    validate_registration(&record, owner_sid)?;
    Ok(Some(record))
}
fn validate_registration(record: &Registration, owner_sid: &str) -> Result<()> {
    if record.version != 1
        || record.owner_sid != owner_sid
        || record.service_name != service_name(owner_sid)
        || record.executable_sha256.len() != 64
        || !record
            .executable_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Error::Conflict);
    }
    let id = Uuid::parse_str(&record.installation_id).map_err(|_| Error::Conflict)?;
    if id.to_string() != record.installation_id {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn save_registration(layout: &Layout, owner_sid: &str, record: &Registration) -> Result<()> {
    validate_registration(record, owner_sid)?;
    let bytes = serde_json::to_vec(record).map_err(|_| Error::NotReady)?;
    save_protected_record(layout, owner_sid, &layout.registration, &bytes)
}
fn save_protected_record(
    layout: &Layout,
    owner_sid: &str,
    path: &Path,
    bytes: &[u8],
) -> Result<()> {
    if bytes.len() as u64 > MAX_REGISTRATION {
        return Err(Error::NotReady);
    }
    let temporary = layout
        .owner
        .join(format!("registration.{}.pending", Uuid::new_v4()));
    let security = SecurityDescriptor::new(&file_sddl(owner_sid))?;
    let mut file = open_path(
        &temporary,
        FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ,
        CREATE_NEW,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL,
        &security.attributes,
    )?;
    file.write_all(&bytes).map_err(|_| Error::ProtectedPath)?;
    file.sync_all().map_err(|_| Error::ProtectedPath)?;
    drop(file);
    let source = wide(temporary.as_os_str());
    let destination = wide(path.as_os_str());
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        let _ = unsafe { DeleteFileW(source.as_ptr()) };
        return Err(Error::ProtectedPath);
    }
    let stored = open_protected_file(path, owner_sid)?;
    validate_owned_acl(&stored, Some(owner_sid), false)
}
fn delete_registration(layout: &Layout, owner_sid: &str) -> Result<()> {
    delete_protected_record(&layout.registration, owner_sid)
}
fn delete_protected_record(path: &Path, owner_sid: &str) -> Result<()> {
    let Some(file) = protected_record_path(path)? else {
        return Ok(());
    };
    validate_owned_acl(&file, Some(owner_sid), false)?;
    drop(file);
    if unsafe { DeleteFileW(wide(path.as_os_str()).as_ptr()) } == 0 {
        return Err(Error::ProtectedPath);
    }
    Ok(())
}

fn load_upgrade(layout: &Layout, owner_sid: &str) -> Result<Option<Upgrade>> {
    let Some(mut file) = protected_record_path(&layout.owner.join(UPGRADE))? else {
        return Ok(None);
    };
    validate_owned_acl(&file, Some(owner_sid), false)?;
    let size = file.metadata().map_err(|_| Error::ProtectedPath)?.len();
    if size == 0 || size > MAX_REGISTRATION {
        return Err(Error::Conflict);
    }
    let mut bytes = Vec::with_capacity(size as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| Error::ProtectedPath)?;
    let upgrade: Upgrade = serde_json::from_slice(&bytes).map_err(|_| Error::Conflict)?;
    validate_registration(&upgrade.previous, owner_sid)?;
    validate_registration(&upgrade.next, owner_sid)?;
    if upgrade.version != 1
        || upgrade.previous.phase != Phase::Registered
        || upgrade.next.phase != Phase::Registered
        || upgrade.previous.installation_id != upgrade.next.installation_id
        || upgrade.previous.executable_sha256 == upgrade.next.executable_sha256
    {
        return Err(Error::Conflict);
    }
    Ok(Some(upgrade))
}

fn require_no_upgrade(layout: &Layout, owner_sid: &str) -> Result<()> {
    if load_upgrade(layout, owner_sid)?.is_some() {
        return Err(Error::NotReady);
    }
    Ok(())
}

fn service_name(owner_sid: &str) -> String {
    format!("{SERVICE_PREFIX}{}", &sha256(owner_sid.as_bytes())[..32])
}
fn quote(value: &str) -> Result<String> {
    if value.contains('\0') {
        return Err(Error::Invalid);
    }
    if !value.is_empty()
        && !value
            .chars()
            .any(|ch| matches!(ch, '"' | ' ' | '\n' | '\t' | '\u{b}'))
    {
        return Ok(value.to_owned());
    }
    let mut output = String::from("\"");
    let mut slashes = 0usize;
    for ch in value.chars() {
        if ch == '\\' {
            slashes += 1;
            continue;
        }
        output.extend(std::iter::repeat_n(
            '\\',
            if ch == '"' { slashes * 2 + 1 } else { slashes },
        ));
        slashes = 0;
        output.push(ch);
    }
    output.extend(std::iter::repeat_n('\\', slashes * 2));
    output.push('"');
    Ok(output)
}
fn expected_arguments(record: &Registration, layout: &Layout) -> Vec<String> {
    vec![
        path_text(&layout.executable(&record.executable_sha256)).unwrap_or_default(),
        "--internal-file-security-broker".into(),
        record.owner_sid.clone(),
        record.installation_id.clone(),
    ]
}
fn expected_command(record: &Registration, layout: &Layout) -> Result<String> {
    let args = expected_arguments(record, layout);
    let command = args
        .iter()
        .map(|arg| quote(arg))
        .collect::<Result<Vec<_>>>()?
        .join(" ");
    if command.len() > 4096 {
        return Err(Error::Invalid);
    }
    Ok(command)
}
fn service_info(record: &Registration, layout: &Layout) -> Result<ServiceInfo> {
    Ok(ServiceInfo {
        name: OsString::from(&record.service_name),
        display_name: OsString::from(&record.service_name),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: layout.executable(&record.executable_sha256),
        launch_arguments: expected_arguments(record, layout)
            .into_iter()
            .skip(1)
            .map(OsString::from)
            .collect(),
        dependencies: Vec::new(),
        account_name: Some(OsString::from("LocalSystem")),
        account_password: None,
    })
}
fn service_manager(creating: bool) -> Result<ServiceManager> {
    let access = if creating {
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE
    } else {
        ServiceManagerAccess::CONNECT
    };
    ServiceManager::local_computer(None::<&str>, access).map_err(scm_error)
}
fn scm_error(error: windows_service::Error) -> Error {
    match error {
        windows_service::Error::Winapi(ref error) if error.raw_os_error() == Some(1072) => {
            Error::Deadline
        }
        windows_service::Error::Winapi(ref error) if error.raw_os_error() == Some(5) => {
            Error::AdministratorRequired
        }
        _ => Error::Manager,
    }
}
fn missing_service(error: &windows_service::Error) -> bool {
    matches!(error, windows_service::Error::Winapi(error) if error.raw_os_error() == Some(1060))
}
fn marked_for_delete(error: &windows_service::Error) -> bool {
    matches!(error, windows_service::Error::Winapi(error) if error.raw_os_error() == Some(1072))
}
fn open_service(
    manager: &ServiceManager,
    record: &Registration,
    access: ServiceAccess,
) -> Result<Option<Service>> {
    match manager.open_service(
        OsStr::new(&record.service_name),
        ServiceAccess::QUERY_CONFIG
            | ServiceAccess::QUERY_STATUS
            | ServiceAccess::READ_CONTROL
            | access,
    ) {
        Ok(service) => Ok(Some(service)),
        Err(error) if missing_service(&error) => Ok(None),
        Err(error) if marked_for_delete(&error) => Err(Error::Deadline),
        Err(error) => Err(scm_error(error)),
    }
}
fn account_sid(account: &OsStr) -> Result<String> {
    let account = wide(account);
    let (mut sid_len, mut domain_len, mut kind) = (0u32, 0u32, 0i32);
    unsafe {
        LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            ptr::null_mut(),
            &mut sid_len,
            ptr::null_mut(),
            &mut domain_len,
            &mut kind,
        );
    }
    if sid_len == 0 || sid_len > 4096 || domain_len > 32768 {
        return Err(Error::Conflict);
    }
    let mut sid = vec![0usize; (sid_len as usize).div_ceil(mem::size_of::<usize>())];
    let mut domain = vec![0u16; domain_len as usize];
    if unsafe {
        LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    } == 0
    {
        return Err(Error::Conflict);
    }
    sid_text(sid.as_mut_ptr().cast())
}
fn matches_config(
    record: &Registration,
    layout: &Layout,
    config: &ServiceConfig,
    deleting: bool,
) -> Result<()> {
    if config.service_type != ServiceType::OWN_PROCESS
        || (config.start_type != ServiceStartType::AutoStart
            && !(deleting && config.start_type == ServiceStartType::Disabled))
        || config.error_control != ServiceErrorControl::Normal
        || !config.dependencies.is_empty()
        || config.display_name != OsStr::new(&record.service_name)
        || config
            .load_order_group
            .as_ref()
            .is_some_and(|group| !group.is_empty())
    {
        return Err(Error::Conflict);
    }
    let raw = config.executable_path.to_str().ok_or(Error::Conflict)?;
    if raw != expected_command(record, layout)?
        || account_sid(config.account_name.as_deref().ok_or(Error::Conflict)?)? != SYSTEM_SID
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn required_privileges(service: &Service) -> Result<Vec<String>> {
    let handle = service.raw_handle();
    let mut needed = 0u32;
    unsafe {
        QueryServiceConfig2W(
            handle,
            SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
            ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    if needed > MAX_TRUST_BUFFER {
        return Err(Error::Conflict);
    }
    let allocation = (needed as usize).max(mem::size_of::<SERVICE_REQUIRED_PRIVILEGES_INFOW>());
    let mut storage = vec![0usize; allocation.div_ceil(mem::size_of::<usize>())];
    let capacity = storage.len() * mem::size_of::<usize>();
    if unsafe {
        QueryServiceConfig2W(
            handle,
            SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
            storage.as_mut_ptr().cast(),
            capacity as u32,
            &mut needed,
        )
    } == 0
        || needed as usize > capacity
        || needed > MAX_TRUST_BUFFER
    {
        return Err(Error::Conflict);
    }
    if needed == 0 {
        let info = unsafe { &*storage.as_ptr().cast::<SERVICE_REQUIRED_PRIVILEGES_INFOW>() };
        return if info.pmszRequiredPrivileges.is_null() {
            Ok(Vec::new())
        } else {
            Err(Error::Conflict)
        };
    }
    let info = unsafe { &*storage.as_ptr().cast::<SERVICE_REQUIRED_PRIVILEGES_INFOW>() };
    let base = storage.as_ptr() as usize;
    let end = base.checked_add(needed as usize).ok_or(Error::Conflict)?;
    let mut current = info.pmszRequiredPrivileges as usize;
    if info.pmszRequiredPrivileges.is_null() {
        return Ok(Vec::new());
    }
    if current < base || current >= end || current % mem::align_of::<u16>() != 0 {
        return Err(Error::Conflict);
    }
    let mut output = Vec::new();
    let mut total = 0usize;
    loop {
        if current + 2 > end || total > 2048 {
            return Err(Error::Conflict);
        }
        let ptr = current as *const u16;
        let mut length = 0usize;
        unsafe {
            while current + (length + 1) * 2 <= end && *ptr.add(length) != 0 {
                length += 1;
                if length > 256 {
                    return Err(Error::Conflict);
                }
            }
        }
        if length == 0 {
            // A normal MULTI_SZ reaches its final empty element after the
            // prior string's terminator has already been consumed. For an
            // empty list, accept either a single bounded NUL or the optional
            // second NUL, while rejecting any nonempty trailing value.
            if total == 0 && current + 4 <= end && unsafe { *ptr.add(1) } != 0 {
                return Err(Error::Conflict);
            }
            break;
        }
        let name = unsafe { OsString::from_wide(std::slice::from_raw_parts(ptr, length)) }
            .into_string()
            .map_err(|_| Error::Conflict)?;
        output.push(name);
        total += length + 1;
        current += (length + 1) * 2;
    }
    Ok(output)
}
fn exact_privileges(service: &Service) -> Result<bool> {
    let mut got = required_privileges(service)?;
    let mut expected = REQUIRED_PRIVILEGES.map(str::to_owned).to_vec();
    got.sort();
    expected.sort();
    Ok(got == expected)
}
fn validate_service_security(service: &Service, require_protected_dacl: bool) -> Result<()> {
    let (mut descriptor, mut acl, mut owner) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    if unsafe {
        GetSecurityInfo(
            service.raw_handle(),
            SE_SERVICE,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    } != ERROR_SUCCESS
        || descriptor.is_null()
        || acl.is_null()
        || !matches!(sid_text(owner)?.as_str(), SYSTEM_SID | ADMIN_SID)
    {
        return Err(Error::Conflict);
    }
    let descriptor = Local(descriptor);
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor.0.cast(), &mut control, &mut revision) }
        == 0
        || (require_protected_dacl && control & SE_DACL_PROTECTED == 0)
    {
        return Err(Error::Conflict);
    }
    let mut present = 0;
    let mut dacl = ptr::null_mut();
    let mut defaulted = 0;
    if unsafe {
        GetSecurityDescriptorDacl(descriptor.0.cast(), &mut present, &mut dacl, &mut defaulted)
    } == 0
        || present == 0
        || dacl.is_null()
    {
        return Err(Error::Conflict);
    }
    let query_only = SERVICE_QUERY_CONFIG
        | SERVICE_QUERY_STATUS
        | SERVICE_ENUMERATE_DEPENDENTS
        | SERVICE_INTERROGATE
        | READ_CONTROL
        | GENERIC_READ;
    let recovery_system_rights = query_only
        | SERVICE_START
        | SERVICE_STOP
        | SERVICE_PAUSE_CONTINUE
        | SERVICE_USER_DEFINED_CONTROL
        | GENERIC_EXECUTE;
    let (mut system_full, mut system_recovery, mut admin_full) = (false, false, false);
    for index in 0..unsafe { (*dacl).AceCount } {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(dacl, index as u32, &mut ace) } == 0 {
            return Err(Error::Conflict);
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceType == ACCESS_DENIED_ACE_TYPE as u8 {
            continue;
        }
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8 {
            return Err(Error::Conflict);
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = sid_text((&allowed.SidStart as *const u32).cast_mut().cast())?;
        if sid == SYSTEM_SID {
            system_full |= allowed.Mask & GENERIC_ALL != 0
                || allowed.Mask & SERVICE_ALL_ACCESS == SERVICE_ALL_ACCESS;
            system_recovery |= allowed.Mask & !recovery_system_rights == 0
                && (allowed.Mask & GENERIC_READ != 0
                    || allowed.Mask & (SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS)
                        == (SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS));
            continue;
        }
        if sid == ADMIN_SID {
            admin_full |= allowed.Mask & GENERIC_ALL != 0
                || allowed.Mask & SERVICE_ALL_ACCESS == SERVICE_ALL_ACCESS;
            continue;
        }
        // Non-admin principals may query the service. All other service
        // rights include configuration changes, start/stop, deletion or
        // security descriptor changes and are rejected, including generic
        // execute/write/all masks.
        // Before our DACL is installed, CreateService's documented default
        // grants authenticated users custom controls. The fixed broker rejects
        // all such controls, and an Intent cannot enter privileged dispatch.
        let tolerated = if !require_protected_dacl && sid == "S-1-5-11" {
            query_only | SERVICE_USER_DEFINED_CONTROL
        } else {
            query_only
        };
        if allowed.Mask & !tolerated != 0 {
            return Err(Error::Conflict);
        }
    }
    if admin_full && (system_full || (!require_protected_dacl && system_recovery)) {
        Ok(())
    } else {
        Err(Error::Conflict)
    }
}
fn set_known_service_dacl(service: &Service) -> Result<()> {
    let descriptor = SecurityDescriptor::new("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)")?;
    let admin_owner = sid_from_text(ADMIN_SID)?;
    let mut present = 0;
    let mut acl = ptr::null_mut();
    let mut defaulted = 0;
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor.descriptor.0.cast(),
            &mut present,
            &mut acl,
            &mut defaulted,
        )
    } == 0
        || present == 0
        || acl.is_null()
        || unsafe {
            SetSecurityInfo(
                service.raw_handle(),
                SE_SERVICE,
                OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                admin_owner.0.cast(),
                ptr::null_mut(),
                acl,
                ptr::null_mut(),
            )
        } != ERROR_SUCCESS
    {
        return Err(Error::ProtectedPath);
    }
    validate_service_security(service, true)
}
fn set_required_privileges(service: &Service) -> Result<()> {
    let mut multistring = Vec::new();
    for privilege in REQUIRED_PRIVILEGES {
        multistring.extend(privilege.encode_utf16());
        multistring.push(0);
    }
    multistring.push(0);
    let info = SERVICE_REQUIRED_PRIVILEGES_INFOW {
        pmszRequiredPrivileges: multistring.as_mut_ptr(),
    };
    if unsafe {
        ChangeServiceConfig2W(
            service.raw_handle(),
            SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
            (&info as *const SERVICE_REQUIRED_PRIVILEGES_INFOW).cast(),
        )
    } == 0
    {
        return Err(scm_error(windows_service::Error::Winapi(
            io::Error::last_os_error(),
        )));
    }
    if !exact_privileges(service)? {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn verify_service(
    service: &Service,
    record: &Registration,
    layout: &Layout,
    deleting: bool,
) -> Result<()> {
    validate_service_security(service, true)?;
    matches_config(
        record,
        layout,
        &service.query_config().map_err(scm_error)?,
        deleting,
    )?;
    if !deleting && !exact_privileges(service)? {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn wait_state(service: &Service, wanted: ServiceState, deadline: Instant) -> Result<ServiceStatus> {
    loop {
        let status = service.query_status().map_err(scm_error)?;
        if status.current_state == wanted {
            return Ok(status);
        }
        if wanted == ServiceState::Running && status.current_state == ServiceState::Stopped {
            return Err(Error::NotReady);
        }
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        thread::sleep(POLL);
    }
}
fn start_service(service: &Service) -> Result<()> {
    let status = service.query_status().map_err(scm_error)?;
    if status.current_state == ServiceState::Running {
        return Ok(());
    }
    if status.current_state != ServiceState::Stopped {
        wait_state(service, ServiceState::Running, Instant::now() + WAIT)?;
        return Ok(());
    }
    match service.start::<&OsStr>(&[]) {
        Ok(()) => {}
        Err(windows_service::Error::Winapi(ref error)) if error.raw_os_error() == Some(1056) => {}
        Err(error) => return Err(scm_error(error)),
    }
    wait_state(service, ServiceState::Running, Instant::now() + WAIT)?;
    Ok(())
}
fn stop_service(service: &Service) -> Result<()> {
    let status = service.query_status().map_err(scm_error)?;
    if status.current_state == ServiceState::Stopped {
        return Ok(());
    }
    if matches!(
        status.current_state,
        ServiceState::Running | ServiceState::Paused
    ) {
        service.stop().map_err(scm_error)?;
    }
    wait_state(service, ServiceState::Stopped, Instant::now() + WAIT)?;
    Ok(())
}

fn verify_image(layout: &Layout, record: &Registration, owner_sid: &str) -> Result<()> {
    let _dirs = validate_layout(layout, owner_sid, &record.executable_sha256)?;
    let path = layout.executable(&record.executable_sha256);
    let mut file = open_protected_file(&path, owner_sid)?;
    if hash_file(&mut file)? != record.executable_sha256 {
        return Err(Error::Conflict);
    }
    verify_authenticode(&file, &path)?;
    if hash_file(&mut file)? != record.executable_sha256 {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn inspect_record_and_service(
    layout: &Layout,
    owner_sid: &str,
    record: &Registration,
    access: ServiceAccess,
) -> Result<Option<Service>> {
    validate_registration(record, owner_sid)?;
    // An interrupted install may have committed its intent before publishing
    // the image. Status/removal must remain possible without executing it.
    // Only Registered records are eligible for start or privileged dispatch.
    let _registration_pins = validate_directory_chain(&layout.owner, Some(owner_sid))?;
    if record.phase == Phase::Registered {
        verify_image(layout, record, owner_sid)?;
    }
    let manager = service_manager(false)?;
    let service = open_service(&manager, record, access)?;
    if let Some(service) = &service {
        if record.phase == Phase::Intent {
            // CreateService can succeed before the process applies our known
            // service DACL. Intent recovery accepts only an exact command and
            // a trusted, non-weak descriptor; privilege drift remains repairable.
            validate_service_security(service, false)?;
            matches_config(
                record,
                layout,
                &service.query_config().map_err(scm_error)?,
                false,
            )?;
            let _ = required_privileges(service)?;
        } else {
            verify_service(service, record, layout, record.phase == Phase::Deleting)?;
        }
    }
    Ok(service)
}

fn open_source_signed(executable: &Path) -> Result<(File, String, String)> {
    let mut file = source_file(executable)?;
    let path = final_path(file.as_raw_handle().cast())?;
    let digest = hash_file(&mut file)?;
    verify_authenticode(&file, &path)?;
    if hash_file(&mut file)? != digest {
        return Err(Error::Conflict);
    }
    Ok((file, digest, path_text(&path)?))
}
fn install(owner_sid: &str, executable: &Path) -> Result<String> {
    require_elevated_admin()?;
    let layout = Layout::for_owner(owner_sid)?;
    let _management_lock = acquire_management_lock(&layout, owner_sid)?;
    require_no_upgrade(&layout, owner_sid)?;
    let (mut source, digest, source_path) = open_source_signed(executable)?;
    let _layout_pins = ensure_layout(&layout, owner_sid, &digest)?;
    let mut record = match load_registration(&layout, owner_sid)? {
        Some(record) => {
            if record.executable_sha256 != digest || record.phase == Phase::Deleting {
                return Err(Error::Conflict);
            }
            record
        }
        None => Registration {
            version: 1,
            owner_sid: owner_sid.to_owned(),
            service_name: service_name(owner_sid),
            executable_sha256: digest.clone(),
            installation_id: Uuid::new_v4().to_string(),
            phase: Phase::Intent,
        },
    };
    validate_registration(&record, owner_sid)?;
    // A deterministic service name without our exact durable intent is foreign.
    let manager = service_manager(true)?;
    let access = ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::QUERY_CONFIG
        | ServiceAccess::QUERY_STATUS
        | ServiceAccess::READ_CONTROL
        | ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::DELETE
        | ServiceAccess::WRITE_DAC
        | ServiceAccess::WRITE_OWNER;
    let existing = open_service(&manager, &record, access)?;
    if record.phase == Phase::Intent && load_registration(&layout, owner_sid)?.is_none() {
        if existing.is_some() {
            return Err(Error::Conflict);
        }
        save_registration(&layout, owner_sid, &record)?;
    }
    copy_pinned_image(
        Path::new(&source_path),
        &mut source,
        &layout,
        owner_sid,
        &digest,
        &record.installation_id,
        &record.phase,
    )?;
    verify_image(&layout, &record, owner_sid)?;
    let service = match existing {
        Some(service) => {
            validate_service_security(&service, record.phase != Phase::Intent)?;
            matches_config(
                &record,
                &layout,
                &service.query_config().map_err(scm_error)?,
                false,
            )?;
            if record.phase == Phase::Intent {
                let privileges_exact = exact_privileges(&service)?;
                set_known_service_dacl(&service)?;
                if !privileges_exact {
                    set_required_privileges(&service)?;
                }
            }
            verify_service(&service, &record, &layout, false)?;
            service
        }
        None => match manager.create_service(&service_info(&record, &layout)?, access) {
            Ok(service) => {
                if let Err(error) = set_known_service_dacl(&service) {
                    let _ = service.delete();
                    return Err(error);
                }
                matches_config(
                    &record,
                    &layout,
                    &service.query_config().map_err(scm_error)?,
                    false,
                )?;
                set_required_privileges(&service)?;
                verify_service(&service, &record, &layout, false)?;
                service
            }
            Err(error) => {
                if let windows_service::Error::Winapi(ref io_error) = error
                    && io_error.raw_os_error() == Some(1073)
                {
                    return Err(Error::Conflict);
                }
                return Err(scm_error(error));
            }
        },
    };
    if record.phase != Phase::Registered {
        record.phase = Phase::Registered;
        save_registration(&layout, owner_sid, &record)?;
    }
    start_service(&service)?;
    verify_service(&service, &record, &layout, false)?;
    Ok(format!(
        "File security service {} installed for {} with automatic system startup and started immediately.",
        record.service_name, owner_sid
    ))
}

/// Reconcile an existing service to a verified pinned image without a delete /
/// recreate gap. Durable intent precedes the first service change. A crash
/// between SCM and registration updates can prevent startup, but cannot make
/// dispatch trust an image that disagrees with the protected registration.
fn upgrade(owner_sid: &str, executable: &Path) -> Result<String> {
    require_elevated_admin()?;
    let layout = Layout::for_owner(owner_sid)?;
    let _management_lock = acquire_management_lock(&layout, owner_sid)?;
    let (mut source, digest, source_path) = open_source_signed(executable)?;
    let current = load_registration(&layout, owner_sid)?.ok_or(Error::NotInstalled)?;
    if current.phase != Phase::Registered {
        return Err(Error::NotReady);
    }
    let _image_pins = validate_layout(&layout, owner_sid, &current.executable_sha256)?;
    verify_image(&layout, &current, owner_sid)?;
    let manager = service_manager(false)?;
    let service = open_service(
        &manager,
        &current,
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::STOP,
    )?
    .ok_or(Error::NotInstalled)?;
    let existing_upgrade = load_upgrade(&layout, owner_sid)?;
    if existing_upgrade.is_none() {
        verify_service(&service, &current, &layout, false)?;
        if digest == current.executable_sha256 {
            return Ok(format!(
                "File security service {} already uses this signed release.",
                current.service_name
            ));
        }
    } else if existing_upgrade.as_ref().is_some_and(|transaction| {
        digest != transaction.previous.executable_sha256
            && digest != transaction.next.executable_sha256
    }) {
        // A new repository head cannot replace either endpoint until the
        // protected pending transaction has been reconciled first.
        return Err(Error::NotReady);
    }
    let _new_image_pins = ensure_layout(&layout, owner_sid, &digest)?;
    copy_pinned_image(
        Path::new(&source_path),
        &mut source,
        &layout,
        owner_sid,
        &digest,
        &current.installation_id,
        &Phase::Intent,
    )?;
    let transaction = match existing_upgrade {
        Some(transaction) => transaction,
        None => {
            let state = service.query_status().map_err(scm_error)?.current_state;
            if !matches!(state, ServiceState::Running | ServiceState::Stopped) {
                return Err(Error::NotReady);
            }
            let mut next = current.clone();
            next.executable_sha256 = digest.clone();
            let transaction = Upgrade {
                version: 1,
                previous: current.clone(),
                next,
                restart: state == ServiceState::Running,
            };
            let bytes = serde_json::to_vec(&transaction).map_err(|_| Error::NotReady)?;
            save_protected_record(&layout, owner_sid, &layout.owner.join(UPGRADE), &bytes)?;
            transaction
        }
    };
    let desired = if digest == transaction.next.executable_sha256 {
        &transaction.next
    } else if digest == transaction.previous.executable_sha256 {
        &transaction.previous
    } else {
        return Err(Error::Conflict);
    };
    reconcile_pending_upgrade(&layout, owner_sid, &current, &transaction, desired)
}

/// Resume a journaled broker upgrade using only its already-pinned protected
/// endpoint. This recovery runs before the release updater fetches a newer
/// target, so an advanced repository head cannot strand the transaction.
pub fn resume_pending_upgrade(owner_sid: &str) -> Result<Option<String>> {
    let owner_sid = validate_owner_sid(owner_sid)?;
    require_elevated_admin()?;
    let layout = Layout::for_owner(&owner_sid)?;
    let _management_lock = acquire_management_lock(&layout, &owner_sid)?;
    let Some(transaction) = load_upgrade(&layout, &owner_sid)? else {
        return Ok(None);
    };
    let current = load_registration(&layout, &owner_sid)?.ok_or(Error::NotInstalled)?;
    let result = reconcile_pending_upgrade(
        &layout,
        &owner_sid,
        &current,
        &transaction,
        &transaction.next,
    )?;
    Ok(Some(result))
}

fn reconcile_pending_upgrade(
    layout: &Layout,
    owner_sid: &str,
    current: &Registration,
    transaction: &Upgrade,
    desired: &Registration,
) -> Result<String> {
    if (current != &transaction.previous && current != &transaction.next)
        || (desired != &transaction.previous && desired != &transaction.next)
    {
        return Err(Error::Conflict);
    }
    let mut image_pins = Vec::new();
    for endpoint in [&transaction.previous, &transaction.next] {
        image_pins.extend(validate_layout(
            layout,
            owner_sid,
            &endpoint.executable_sha256,
        )?);
        verify_image(layout, endpoint, owner_sid)?;
    }
    let manager = service_manager(false)?;
    let service = open_service(
        &manager,
        current,
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::STOP,
    )?
    .ok_or(Error::NotInstalled)?;
    validate_service_security(&service, true)?;
    if !exact_privileges(&service)? {
        return Err(Error::Conflict);
    }
    let config = service.query_config().map_err(scm_error)?;
    if matches_config(&transaction.previous, &layout, &config, false).is_err()
        && matches_config(&transaction.next, &layout, &config, false).is_err()
    {
        return Err(Error::Conflict);
    }
    let startup_deadline = Instant::now() + WAIT;
    while service.query_status().map_err(scm_error)?.current_state == ServiceState::StartPending {
        // After a crash between SCM and registration replacement, an automatic
        // start may correctly fail closed. Both Stopped and Running allow this
        // same invocation to reconcile; waiting only for Running would require
        // an unnecessary second recovery command.
        if Instant::now() >= startup_deadline {
            return Err(Error::Deadline);
        }
        thread::sleep(POLL);
    }
    stop_service(&service)?;
    // Both protected endpoints and the exact stopped SCM registration were
    // checked before changing its command. Required privileges stay unchanged.
    service
        .change_config(&service_info(desired, &layout)?)
        .map_err(scm_error)?;
    verify_service(&service, desired, &layout, false)?;
    save_registration(&layout, owner_sid, desired)?;
    if transaction.restart {
        start_service(&service)?;
        verify_service(&service, desired, &layout, false)?;
    }
    delete_protected_record(&layout.owner.join(UPGRADE), owner_sid)?;
    Ok(format!(
        "File security service {} now uses the journaled signed release; its previous running state was restored.",
        desired.service_name
    ))
}

fn status(owner_sid: &str) -> Result<String> {
    let layout = Layout::for_owner(owner_sid)?;
    if load_upgrade(&layout, owner_sid)?.is_some() {
        return Ok(format!(
            "File security service upgrade is pending for {}. Resume with the selected signed release using `lomiremote service file-security upgrade --owner-sid {} --confirm-system-service`.",
            owner_sid, owner_sid
        ));
    }
    let record = load_registration(&layout, owner_sid)?;
    let Some(record) = record else {
        let manager = service_manager(false)?;
        let probe = Registration {
            version: 1,
            owner_sid: owner_sid.to_owned(),
            service_name: service_name(owner_sid),
            executable_sha256: "0".repeat(64),
            installation_id: Uuid::nil().to_string(),
            phase: Phase::Intent,
        };
        if open_service(&manager, &probe, ServiceAccess::empty())?.is_some() {
            return Err(Error::Conflict);
        }
        return Ok(format!(
            "File security service is not installed for {}. An elevated administrator can run `lomiremote service file-security install --owner-sid {} --confirm-system-service`.",
            owner_sid, owner_sid
        ));
    };
    let Some(service) =
        inspect_record_and_service(&layout, owner_sid, &record, ServiceAccess::empty())?
    else {
        return match record.phase {
            Phase::Intent => Ok(format!(
                "File security service installation is pending for {}. An elevated administrator can resume with `lomiremote service file-security install --owner-sid {} --confirm-system-service`.",
                owner_sid, owner_sid
            )),
            Phase::Deleting => Ok(format!(
                "File security service removal is pending for {}. An elevated administrator can resume with `lomiremote service file-security uninstall --owner-sid {}`.",
                owner_sid, owner_sid
            )),
            Phase::Registered => Err(Error::NotReady),
        };
    };
    match record.phase {
        Phase::Intent => Ok(format!(
            "File security service {} is registered but installation recovery is pending. Resume with `lomiremote service file-security install --owner-sid {} --confirm-system-service`.",
            record.service_name, owner_sid
        )),
        Phase::Deleting => Ok(format!(
            "File security service {} is being removed. Resume with `lomiremote service file-security uninstall --owner-sid {}`.",
            record.service_name, owner_sid
        )),
        Phase::Registered => {
            let status = service.query_status().map_err(scm_error)?;
            if status.current_state == ServiceState::Running {
                Ok(format!(
                    "File security service {} is running for {}.",
                    record.service_name, owner_sid
                ))
            } else {
                Ok(format!(
                    "File security service {} is installed and stopped for {}. Start it with `lomiremote service file-security start --owner-sid {}`.",
                    record.service_name, owner_sid, owner_sid
                ))
            }
        }
    }
}
fn start(owner_sid: &str) -> Result<String> {
    require_elevated_admin()?;
    let layout = Layout::for_owner(owner_sid)?;
    let _management_lock = acquire_management_lock(&layout, owner_sid)?;
    require_no_upgrade(&layout, owner_sid)?;
    let record = load_registration(&layout, owner_sid)?.ok_or(Error::NotInstalled)?;
    if record.phase != Phase::Registered {
        return Err(Error::NotReady);
    }
    let service = inspect_record_and_service(&layout, owner_sid, &record, ServiceAccess::START)?
        .ok_or(Error::NotInstalled)?;
    start_service(&service)?;
    Ok(format!(
        "File security service {} started.",
        record.service_name
    ))
}
fn stop(owner_sid: &str) -> Result<String> {
    require_elevated_admin()?;
    let layout = Layout::for_owner(owner_sid)?;
    let _management_lock = acquire_management_lock(&layout, owner_sid)?;
    require_no_upgrade(&layout, owner_sid)?;
    let record = load_registration(&layout, owner_sid)?.ok_or(Error::NotInstalled)?;
    if record.phase != Phase::Registered {
        return Err(Error::NotReady);
    }
    let service = inspect_record_and_service(&layout, owner_sid, &record, ServiceAccess::STOP)?
        .ok_or(Error::NotInstalled)?;
    stop_service(&service)?;
    Ok(format!(
        "File security service {} stopped.",
        record.service_name
    ))
}
fn uninstall(owner_sid: &str) -> Result<String> {
    require_elevated_admin()?;
    let layout = Layout::for_owner(owner_sid)?;
    let _management_lock = acquire_management_lock(&layout, owner_sid)?;
    require_no_upgrade(&layout, owner_sid)?;
    let Some(mut record) = load_registration(&layout, owner_sid)? else {
        let manager = service_manager(false)?;
        let probe = Registration {
            version: 1,
            owner_sid: owner_sid.to_owned(),
            service_name: service_name(owner_sid),
            executable_sha256: "0".repeat(64),
            installation_id: Uuid::nil().to_string(),
            phase: Phase::Intent,
        };
        if open_service(&manager, &probe, ServiceAccess::empty())?.is_some() {
            return Err(Error::Conflict);
        }
        return Ok(format!(
            "File security service is not installed for {}.",
            owner_sid
        ));
    };
    if record.phase != Phase::Deleting {
        let service = inspect_record_and_service(
            &layout,
            owner_sid,
            &record,
            ServiceAccess::STOP
                | ServiceAccess::DELETE
                | ServiceAccess::WRITE_DAC
                | ServiceAccess::WRITE_OWNER,
        )?;
        if service.is_none() {
            delete_registration(&layout, owner_sid)?;
            return Ok(format!(
                "File security service for {} is uninstalled.",
                owner_sid
            ));
        }
        if record.phase == Phase::Intent {
            set_known_service_dacl(service.as_ref().ok_or(Error::NotInstalled)?)?;
        }
        record.phase = Phase::Deleting;
        save_registration(&layout, owner_sid, &record)?;
    }
    let manager = service_manager(true)?;
    let Some(service) = open_service(
        &manager,
        &record,
        ServiceAccess::STOP | ServiceAccess::DELETE,
    )?
    else {
        delete_registration(&layout, owner_sid)?;
        return Ok(format!(
            "File security service for {} is uninstalled.",
            owner_sid
        ));
    };
    verify_service(&service, &record, &layout, true)?;
    stop_service(&service)?;
    service.delete().map_err(scm_error)?;
    drop(service);
    let deadline = Instant::now() + WAIT;
    loop {
        match manager.open_service(
            OsStr::new(&record.service_name),
            ServiceAccess::QUERY_STATUS,
        ) {
            Err(error) if missing_service(&error) => break,
            Err(error) if marked_for_delete(&error) => {}
            Err(error) => return Err(scm_error(error)),
            Ok(service) => {
                let status = service.query_status().map_err(scm_error)?;
                if status.current_state != ServiceState::Stopped {
                    return Err(Error::Conflict);
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        thread::sleep(POLL);
    }
    // The old pinned executable is deliberately retained after service removal.
    delete_registration(&layout, owner_sid)?;
    Ok(format!(
        "File security service for {} is uninstalled.",
        owner_sid
    ))
}

/// Run an explicit per-owner service management command. Installation always
/// requires both an elevated administrator token and the confirmation flag.
pub fn run(
    operation: &str,
    owner_sid: Option<&str>,
    confirm_system_service: bool,
    executable: &Path,
) -> Result<String> {
    let owner_sid = validate_owner_sid(owner_sid.ok_or(Error::Invalid)?)?;
    match operation {
        "install" if confirm_system_service => install(&owner_sid, executable),
        "upgrade" if confirm_system_service => upgrade(&owner_sid, executable),
        "install" => Err(Error::Invalid),
        "upgrade" => Err(Error::Invalid),
        "status" => status(&owner_sid),
        "start" => start(&owner_sid),
        "stop" => stop(&owner_sid),
        "uninstall" => uninstall(&owner_sid),
        _ => Err(Error::Invalid),
    }
}

struct Runtime {
    owner_sid: String,
    record: Registration,
    layout: Layout,
}
static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static SERVICE_FAILED: AtomicBool = AtomicBool::new(false);
define_windows_service!(ffi_service_main, service_main);

fn validate_runtime(runtime: &Runtime) -> Result<()> {
    if current_token_sid()? != SYSTEM_SID {
        return Err(Error::Conflict);
    }
    unimpersonated()?;
    let record = load_registration(&runtime.layout, &runtime.owner_sid)?.ok_or(Error::Conflict)?;
    if record != runtime.record || record.phase != Phase::Registered {
        return Err(Error::Conflict);
    }
    verify_image(&runtime.layout, &record, &runtime.owner_sid)?;
    let current = std::env::current_exe().map_err(|_| Error::ProtectedPath)?;
    let current = source_file(&current)?;
    check_final_path(
        current.as_raw_handle().cast(),
        &runtime.layout.executable(&record.executable_sha256),
    )?;
    let mut current = current;
    if hash_file(&mut current)? != record.executable_sha256 {
        return Err(Error::Conflict);
    }
    verify_authenticode(
        &current,
        &runtime.layout.executable(&record.executable_sha256),
    )?;
    let manager = service_manager(false)?;
    let service =
        open_service(&manager, &record, ServiceAccess::empty())?.ok_or(Error::Conflict)?;
    verify_service(&service, &record, &runtime.layout, false)?;
    let status = service.query_status().map_err(scm_error)?;
    match status.current_state {
        // dispatch and ServiceMain validate before reporting Running.
        ServiceState::StartPending => {}
        ServiceState::Running if status.process_id == Some(unsafe { GetCurrentProcessId() }) => {}
        _ => return Err(Error::Conflict),
    }
    Ok(())
}
fn runtime_status(
    handle: ServiceStatusHandle,
    state: ServiceState,
    checkpoint: u32,
    failed: bool,
    accepts_stop: bool,
) -> Result<()> {
    handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if accepts_stop {
                ServiceControlAccept::STOP
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(u32::from(failed)),
            checkpoint,
            wait_hint: if matches!(
                state,
                ServiceState::StartPending | ServiceState::StopPending
            ) {
                Duration::from_secs(15)
            } else {
                Duration::ZERO
            },
            process_id: None,
        })
        .map_err(|_| Error::Manager)
}
fn service_main(arguments: Vec<OsString>) {
    let Some(runtime) = RUNTIME.get() else {
        SERVICE_FAILED.store(true, Ordering::Release);
        return;
    };
    // SCM includes the service name as argv[0], even when StartService was
    // called without additional arguments.
    if arguments.len() != 1
        || arguments[0] != OsStr::new(&runtime.record.service_name)
        || validate_runtime(runtime).is_err()
    {
        SERVICE_FAILED.store(true, Ordering::Release);
        return;
    }
    let stopping = Arc::new(AtomicBool::new(false));
    let signal = stopping.clone();
    let service_name = runtime.record.service_name.clone();
    let status_holder = Arc::new(OnceLock::<ServiceStatusHandle>::new());
    let callback_status = status_holder.clone();
    let handler =
        match service_control_handler::register(&service_name, move |control| match control {
            ServiceControl::Stop => {
                signal.store(true, Ordering::Release);
                if let Some(handle) = callback_status.get() {
                    let _ = runtime_status(*handle, ServiceState::StopPending, 1, false, false);
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }) {
            Ok(handle) => handle,
            Err(_) => {
                SERVICE_FAILED.store(true, Ordering::Release);
                return;
            }
        };
    let _ = status_holder.set(handler);
    if runtime_status(handler, ServiceState::StartPending, 1, false, false).is_err() {
        SERVICE_FAILED.store(true, Ordering::Release);
        return;
    }
    let owner_sid = runtime.owner_sid.clone();
    let stopping_for_worker = stopping.clone();
    let worker = thread::Builder::new()
        .name("lomi-file-security-broker".into())
        .spawn(move || lomi_files::run_security_broker(&owner_sid, &stopping_for_worker));
    let Ok(worker) = worker else {
        SERVICE_FAILED.store(true, Ordering::Release);
        let _ = runtime_status(handler, ServiceState::Stopped, 0, true, false);
        return;
    };
    if runtime_status(handler, ServiceState::Running, 0, false, true).is_err() {
        stopping.store(true, Ordering::Release);
        SERVICE_FAILED.store(true, Ordering::Release);
    }
    let mut checkpoint = 1u32;
    let mut last_checkpoint = Instant::now();
    while !worker.is_finished() {
        if stopping.load(Ordering::Acquire) && last_checkpoint.elapsed() >= Duration::from_secs(1) {
            checkpoint = checkpoint.saturating_add(1);
            let _ = runtime_status(handler, ServiceState::StopPending, checkpoint, false, false);
            last_checkpoint = Instant::now();
        }
        thread::sleep(POLL);
    }
    let worker_failed = worker.join().map(|result| result.is_err()).unwrap_or(true);
    let failed = worker_failed || SERVICE_FAILED.load(Ordering::Acquire);
    SERVICE_FAILED.store(failed, Ordering::Release);
    let _ = runtime_status(handler, ServiceState::Stopped, 0, failed, false);
}

/// SCM-only entry point. It is reachable only from the hidden executable
/// command; runtime checks bind the protected registration, service config,
/// LocalSystem token, current image, and pinned image hash before dispatch.
pub fn dispatch(owner_sid: String, installation_id: String) -> Result<()> {
    let owner_sid = validate_owner_sid(&owner_sid)?;
    let installation_id_value = Uuid::parse_str(&installation_id).map_err(|_| Error::Invalid)?;
    if installation_id_value.to_string() != installation_id || current_token_sid()? != SYSTEM_SID {
        return Err(Error::Conflict);
    }
    unimpersonated()?;
    let layout = Layout::for_owner(&owner_sid)?;
    let record = load_registration(&layout, &owner_sid)?.ok_or(Error::Conflict)?;
    if record.installation_id != installation_id || record.phase != Phase::Registered {
        return Err(Error::Conflict);
    }
    let runtime = Runtime {
        owner_sid,
        record,
        layout,
    };
    validate_runtime(&runtime)?;
    RUNTIME.set(runtime).map_err(|_| Error::Conflict)?;
    if service_dispatcher::start(
        &RUNTIME.get().ok_or(Error::Conflict)?.record.service_name,
        ffi_service_main,
    )
    .is_err()
        || SERVICE_FAILED.load(Ordering::Acquire)
    {
        Err(Error::NotReady)
    } else {
        Ok(())
    }
}
