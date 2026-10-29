//! Elevated SCM management for an explicitly selected ordinary account.
//!
//! The service account is never provisioned here. The signed updater owns the
//! protected HostServices image set; this module verifies that set before it
//! binds the deterministic SCM service to it. Passwords exist only in the
//! caller's hidden prompt buffer and this module's zeroizing UTF-16 buffer.

use super::{
    Error as NativeError, Handle, Local, LocalClient, current_sid, information, normalized,
    open_path, sid_text, wide,
};
use crate::windows::service::{self, Error as ServiceError};
use lomi_remote_protocol::{
    HostId,
    ipc::{IpcProfileId, LocalCall, LocalResult},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
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
use uuid::Uuid;
use windows_service::{
    service::{Service, ServiceAccess, ServiceExitCode, ServiceState},
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GENERIC_MAPPING, MapGenericMask, OWNER_SECURITY_INFORMATION,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{
        Authentication::Identity::{
            LSA_HANDLE, LSA_OBJECT_ATTRIBUTES, LSA_UNICODE_STRING, LsaAddAccountRights, LsaClose,
            LsaOpenPolicy, POLICY_CREATE_ACCOUNT, POLICY_LOOKUP_NAMES,
        },
        Authorization::{
            ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetSecurityInfo,
            NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SetEntriesInAclW, SetSecurityInfo, TRUSTEE_IS_SID,
            TRUSTEE_IS_USER, TRUSTEE_W,
        },
        Cryptography::{
            CERT_FIND_SUBJECT_CERT, CERT_INFO, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CERT_SHA1_HASH_PROP_ID,
            CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM, CertCloseStore, CertFindCertificateInStore,
            CertFreeCertificateContext, CertGetCertificateContextProperty, CryptMsgClose,
            CryptMsgGetParam, CryptQueryObject,
        },
        WinTrust::{
            WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
            WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4, WTD_REVOKE_NONE,
            WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTD_UICONTEXT_INSTALL,
            WinVerifyTrust,
        },
        *,
    },
    Storage::FileSystem::*,
    System::{
        Com::CoTaskMemFree,
        IO::OVERLAPPED,
        Registry::{
            HKEY_LOCAL_MACHINE, REG_EXPAND_SZ, REG_SZ, RRF_NOEXPAND, RRF_RT_REG_EXPAND_SZ,
            RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY, RegGetValueW,
        },
        Services::{
            ChangeServiceConfigW, CloseServiceHandle, CreateServiceW, OpenSCManagerW, OpenServiceW,
            SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE, SERVICE_ALL_ACCESS,
            SERVICE_AUTO_START, SERVICE_CHANGE_CONFIG, SERVICE_ERROR_NORMAL, SERVICE_NO_CHANGE,
            SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STOP,
            SERVICE_WIN32_OWN_PROCESS, SetServiceObjectSecurity,
        },
        SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
        Threading::*,
    },
    UI::Shell::{
        CreateProfile, FOLDERID_ProgramData, FOLDERID_Windows, GetUserProfileDirectoryW,
        SHGetKnownFolderPath,
    },
};
use zeroize::Zeroizing;

const HOST_SERVICES: &str = "LomiRemote\\HostServices";
const MAINTENANCE_JOBS: &str = "MaintenanceJobs";
const MAINTENANCE_ROOT_ACL_LOCK: &str = ".owner-traverse-acl.lock";
const INSTALL_DIR: &str = "Install";
const CLI_IMAGE: &str = "lomiremote.exe";
const HELPER_IMAGE: &str = "lomiremote-host.exe";
const REGISTRATION: &str = "registration.json";
const JOURNAL: &str = "journal.json";
const MANAGEMENT_LOCK: &str = "management.lock";
const MAX_RECORD: u64 = 64 * 1024;
const MAX_IMAGE: u64 = 256 * 1024 * 1024;
const MAX_HOST_DATABASE_SNAPSHOT: u64 = 1024 * 1024 * 1024;
const WAIT: Duration = Duration::from_secs(45);
const POLL: Duration = Duration::from_millis(50);
const SYSTEM_SID: &str = "S-1-5-18";
const ADMIN_SID: &str = "S-1-5-32-544";
const TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const MAINTENANCE_ROOT_OWNER_ACCESS: u32 = READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE;
const BUILTIN_ADMINS_SID: &str = "S-1-5-32-544";
const SE_SERVICE_LOGON_RIGHT: &str = "SeServiceLogonRight";
const ACE_ALLOWED_TYPE: u8 = ACCESS_ALLOWED_ACE_TYPE as u8;
const ACE_DENIED_TYPE: u8 = ACCESS_DENIED_ACE_TYPE as u8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Conflict,
    AdministratorRequired,
    AccountNotOrdinary,
    CredentialsRequired,
    NotInstalled,
    Manager,
    NotReady,
    Deadline,
    ProtectedImageRequired,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "ADMIN_SERVICE_INVALID_CONFIGURATION",
            Self::Conflict => "ADMIN_SERVICE_OWNERSHIP_CONFLICT",
            Self::AdministratorRequired => "ADMIN_SERVICE_REQUIRES_ELEVATED_ADMINISTRATOR",
            Self::AccountNotOrdinary => "ADMIN_SERVICE_DEDICATED_NONADMIN_ACCOUNT_REQUIRED",
            Self::CredentialsRequired => "ADMIN_SERVICE_OS_CREDENTIALS_OR_LOGON_RIGHT_REQUIRED",
            Self::NotInstalled => "ADMIN_SERVICE_NOT_INSTALLED",
            Self::Manager => "ADMIN_SERVICE_MANAGER_UNAVAILABLE",
            Self::NotReady => "ADMIN_SERVICE_HOST_NOT_READY",
            Self::Deadline => "ADMIN_SERVICE_OPERATION_UNCERTAIN",
            Self::ProtectedImageRequired => "ADMIN_SERVICE_VERIFIED_UPDATER_IMAGE_REQUIRED",
        })
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;

/// Return the effective Windows account's native SID and canonical name.
/// This is an identity lookup only; it does not authorize service changes.
pub fn current_account() -> std::result::Result<(String, String), Error> {
    let sid = current_sid().map_err(native)?;
    let account = lookup_account_sid(&sid)?;
    Ok((sid, account))
}

/// Resolve and validate the selected dedicated ordinary account without
/// accepting a profile path or changing local security policy.
pub fn selected_account_identity(account: &str) -> std::result::Result<(String, String), Error> {
    require_administrator()?;
    let identity = resolve_account(account)?;
    Ok((identity.sid, identity.canonical))
}

fn native(_: NativeError) -> Error {
    Error::Conflict
}

fn path_text(path: &Path) -> Result<String> {
    service::text(path.as_os_str()).map_err(|_| Error::Invalid)
}

fn scm(error: windows_service::Error) -> Error {
    match error {
        windows_service::Error::Winapi(ref e)
            if matches!(e.raw_os_error(), Some(1069 | 1057 | 1079)) =>
        {
            Error::CredentialsRequired
        }
        windows_service::Error::Winapi(ref e) if e.raw_os_error() == Some(1072) => Error::Deadline,
        _ => Error::Manager,
    }
}

/// A password received from the native hidden prompt. The input is immediately
/// zeroized after copying into a fixed-size NUL-terminated secret buffer.
pub struct ServicePassword(Zeroizing<Vec<u16>>);

impl ServicePassword {
    pub fn from_utf16(password: Vec<u16>) -> Result<Self> {
        let secret = Zeroizing::new(password);
        if secret.is_empty() || secret.contains(&0) || secret.len() > 4096 {
            return Err(Error::Invalid);
        }
        let mut terminated = Zeroizing::new(Vec::with_capacity(secret.len() + 1));
        terminated.extend_from_slice(&secret);
        terminated.push(0);
        Ok(Self(terminated))
    }

    fn nul_terminated(&self) -> Result<*const u16> {
        if self.0.len() < 2
            || self.0.last() != Some(&0)
            || self.0[..self.0.len() - 1].contains(&0)
            || self.0.len() > 4097
        {
            return Err(Error::Invalid);
        }
        Ok(self.0.as_ptr())
    }

    fn selected_logon_credential(
        &self,
    ) -> std::result::Result<crate::setup_context::WindowsLogonCredential, Error> {
        let length = self.0.len().checked_sub(1).ok_or(Error::Invalid)?;
        if self.0.last() != Some(&0) || self.0[..length].contains(&0) {
            return Err(Error::Invalid);
        }
        let mut copy = Zeroizing::new(Vec::with_capacity(length));
        copy.extend_from_slice(&self.0[..length]);
        crate::setup_context::WindowsLogonCredential::from_utf16(mem::take(&mut *copy))
            .map_err(|_| Error::CredentialsRequired)
    }
}

/// Verified, pinned image pair prepared by the signed updater. The expected
/// file digests and signer thumbprint come from signed TUF metadata, not CLI
/// overrides. Handles deny write/delete sharing while an SCM operation uses
/// these exact bytes.
pub struct VerifiedHostServiceImage {
    owner_sid: String,
    canonical_account: String,
    install: PathBuf,
    cli_path: PathBuf,
    helper_path: PathBuf,
    cli_sha256: String,
    helper_sha256: String,
    signer_thumbprint: String,
    _directory_pins: AdminDirectoryPins,
    cli: PinnedImageFile,
    helper: PinnedImageFile,
}

/// Holds the same selected-user `owner.lock` byte-range lock used by Host.
/// It exposes only the native app-profile binding, never profile file bytes.
pub struct HostOwnerLock {
    _file: File,
    _directories: Vec<Handle>,
    profile: PathBuf,
    owner_sid: String,
}

/// An administrator-private, bounded copy of the selected Host's SQLite
/// database components. Source handles remain open without write/delete
/// sharing while callers validate signed schema policy and publish images.
pub struct HostDatabaseSnapshot {
    directory: PathBuf,
    directory_handle: Option<Handle>,
    _parent_pins: AdminDirectoryPins,
    _profile_pins: Vec<Handle>,
    profile_directory: Handle,
    profile_identity: DatabaseIdentity,
    profile: PathBuf,
    owner_sid: String,
    sources: Vec<DatabaseSource>,
}

/// Read-only selected-account hold on the same empty management lock used by
/// administrator operations. The owner can exclude concurrent management
/// changes without being able to write protected records or lock contents.
struct OwnerControlLock {
    _handle: Handle,
    _directory_pins: AdminDirectoryPins,
}

struct DatabaseSource {
    name: &'static str,
    file: File,
    identity: DatabaseIdentity,
    copy_to_snapshot: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DatabaseIdentity {
    volume: u32,
    file_index: u64,
    size: u64,
    links: u32,
    attributes: u32,
    creation_time: u64,
    write_time: u64,
}

impl HostOwnerLock {
    pub fn profile_path(&self) -> &Path {
        &self.profile
    }

    pub fn owner_sid(&self) -> &str {
        &self.owner_sid
    }

    /// Copy only the fixed Host database and WAL input into an
    /// administrator-private temporary directory. A nonempty rollback
    /// journal is rejected because SQLite recovery can act on its embedded
    /// super-journal path; an empty journal is pinned but omitted. The owner
    /// lock, held profile ancestry, and deny-write source handles remain part
    /// of the returned capability for its entire lifetime.
    pub fn snapshot_database(&self) -> Result<HostDatabaseSnapshot> {
        snapshot_host_database(self)
    }
}

/// Run only the fixed selected-account profile initializer from the exact
/// signed updater image. The caller must have reserved an Intent and released
/// the profile owner lock; this method holds the service manager lock while
/// checking the Intent before and after the child. The secret is copied only
/// into another zeroizing native-logon capability and is never serialized.
pub fn initialize_first_install_profile(
    account: &str,
    profile: &Path,
    password: &ServicePassword,
    image: &VerifiedHostServiceImage,
) -> Result<()> {
    require_administrator()?;
    let identity = resolve_account(account)?;
    if profile != native_app_profile_path(&identity, false)?
        || image.owner_sid != identity.sid
        || image.canonical_account != identity.canonical
    {
        return Err(Error::Conflict);
    }
    image.recheck()?;
    {
        let _manager_lock = AdminLock::acquire(&identity.sid)?;
        verify_install_intent_record(&identity, profile, image, false)?;
    }

    let selected = crate::setup_context::select_windows_account(&identity.canonical)
        .map_err(|_| Error::AccountNotOrdinary)?;
    let selected_windows = selected.windows().ok_or(Error::AccountNotOrdinary)?;
    let registered_user_profile = profile.parent().ok_or(Error::Conflict)?;
    if selected_windows.sid() != identity.sid
        || selected_windows.name() != identity.canonical
        || selected_windows.home() != registered_user_profile
    {
        return Err(Error::Conflict);
    }
    let credential = password.selected_logon_credential()?;
    let arguments = [
        OsString::from("--internal-initialize-profile"),
        profile.as_os_str().to_os_string(),
    ];
    let result = crate::setup_context::reexec_windows_as_selected(
        &selected,
        &credential,
        &image.cli_path,
        &arguments,
    )
    .map_err(|error| match error {
        crate::setup_context::Error::OperationUncertain => Error::Deadline,
        crate::setup_context::Error::SpawnFailed
        | crate::setup_context::Error::DifferentAccountRequiresNativeLogon => {
            Error::CredentialsRequired
        }
        _ => Error::NotReady,
    })?;
    if !result.success() {
        return Err(Error::NotReady);
    }
    image.recheck()?;
    let _manager_lock = AdminLock::acquire(&identity.sid)?;
    verify_install_intent_record(&identity, profile, image, false)
}

impl HostDatabaseSnapshot {
    pub fn path(&self) -> &Path {
        &self.directory
    }

    /// Recheck the still-pinned source namespace and object identities after
    /// schema inspection and before a release mutation.
    pub fn verify_sources(&self) -> Result<()> {
        if normalized(&self.profile.canonicalize().map_err(|_| Error::Conflict)?).map_err(native)?
            != self.profile
            || database_identity(self.profile_directory.0)? != self.profile_identity
        {
            return Err(Error::Conflict);
        }
        verify_owner_private_object(self.profile_directory.0, &self.owner_sid, true)?;
        for source in &self.sources {
            if database_identity(source.file.as_raw_handle().cast())? != source.identity {
                return Err(Error::Conflict);
            }
            verify_owner_private_object(
                source.file.as_raw_handle().cast(),
                &self.owner_sid,
                false,
            )?;
        }
        let directory = self.directory_handle.as_ref().ok_or(Error::Conflict)?;
        verify_admin_only_security(directory.0, true)?;
        if database_identity(directory.0)?.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || normalized(&self.directory.canonicalize().map_err(|_| Error::Conflict)?)
                .map_err(native)?
                != self.directory
        {
            return Err(Error::Conflict);
        }
        let mut copied_total = 0u64;
        for entry in fs::read_dir(&self.directory).map_err(|_| Error::Conflict)? {
            let entry = entry.map_err(|_| Error::Conflict)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(Error::Conflict);
            };
            if !matches!(
                name,
                "host.sqlite3" | "host.sqlite3-journal" | "host.sqlite3-wal" | "host.sqlite3-shm"
            ) {
                return Err(Error::Conflict);
            }
            let file = Handle::new(unsafe {
                CreateFileW(
                    wide(&entry.path()).as_ptr(),
                    FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                    FILE_SHARE_READ,
                    ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                    ptr::null_mut(),
                )
            })
            .map_err(|_| Error::Conflict)?;
            let info = information(file.0).map_err(native)?;
            if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
                != 0
                || info.nNumberOfLinks != 1
            {
                return Err(Error::Conflict);
            }
            let file_identity = database_identity(file.0)?;
            copied_total = copied_total
                .checked_add(file_identity.size)
                .ok_or(Error::Conflict)?;
            if copied_total > MAX_HOST_DATABASE_SNAPSHOT {
                return Err(Error::Conflict);
            }
            verify_admin_only_security(file.0, false)?;
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<()> {
        let Some(directory_handle) = self.directory_handle.as_ref() else {
            return SnapshotCleanup {
                directory: &self.directory,
            }
            .cleanup();
        };
        verify_admin_only_security(directory_handle.0, true)?;
        let directory_identity = database_identity(directory_handle.0)?;
        if directory_identity.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
            != FILE_ATTRIBUTE_DIRECTORY
        {
            return Err(Error::Conflict);
        }
        for entry in fs::read_dir(&self.directory).map_err(|_| Error::Conflict)? {
            let entry = entry.map_err(|_| Error::Conflict)?;
            let name = entry.file_name();
            if !matches!(
                name.to_str(),
                Some(
                    "host.sqlite3"
                        | "host.sqlite3-journal"
                        | "host.sqlite3-wal"
                        | "host.sqlite3-shm"
                )
            ) {
                return Err(Error::Conflict);
            }
            let raw = unsafe {
                CreateFileW(
                    wide(&entry.path()).as_ptr(),
                    FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE | SYNCHRONIZE,
                    FILE_SHARE_READ,
                    ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                    ptr::null_mut(),
                )
            };
            let file = Handle::new(raw).map_err(|_| Error::Conflict)?;
            let info = information(file.0).map_err(native)?;
            if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
                != 0
                || info.nNumberOfLinks != 1
            {
                return Err(Error::Conflict);
            }
            verify_admin_only_security(file.0, false)?;
            drop(file);
            if unsafe { DeleteFileW(wide(&entry.path()).as_ptr()) } == 0 {
                return Err(Error::Conflict);
            }
        }
        drop(self.directory_handle.take());
        if unsafe { RemoveDirectoryW(wide(&self.directory).as_ptr()) } == 0 {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

impl Drop for HostDatabaseSnapshot {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

struct SnapshotDirectoryReservation {
    path: PathBuf,
    armed: bool,
}

impl SnapshotDirectoryReservation {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SnapshotDirectoryReservation {
    fn drop(&mut self) {
        if self.armed {
            let mut snapshot = SnapshotCleanup {
                directory: &self.path,
            };
            let _ = snapshot.cleanup();
        }
    }
}

struct SnapshotCleanup<'a> {
    directory: &'a Path,
}

impl SnapshotCleanup<'_> {
    fn cleanup(&mut self) -> Result<()> {
        let raw = unsafe {
            CreateFileW(
                wide(self.directory).as_ptr(),
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            )
        };
        let directory = Handle::new(raw).map_err(|_| Error::Conflict)?;
        let info = information(directory.0).map_err(native)?;
        if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
            != FILE_ATTRIBUTE_DIRECTORY
        {
            return Err(Error::Conflict);
        }
        verify_admin_only_security(directory.0, true)?;
        for entry in fs::read_dir(self.directory).map_err(|_| Error::Conflict)? {
            let entry = entry.map_err(|_| Error::Conflict)?;
            if !matches!(
                entry.file_name().to_str(),
                Some(
                    "host.sqlite3"
                        | "host.sqlite3-journal"
                        | "host.sqlite3-wal"
                        | "host.sqlite3-shm"
                )
            ) {
                return Err(Error::Conflict);
            }
            let file = Handle::new(unsafe {
                CreateFileW(
                    wide(&entry.path()).as_ptr(),
                    FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE | SYNCHRONIZE,
                    FILE_SHARE_READ,
                    ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                    ptr::null_mut(),
                )
            })
            .map_err(|_| Error::Conflict)?;
            let info = information(file.0).map_err(native)?;
            if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
                != 0
                || info.nNumberOfLinks != 1
            {
                return Err(Error::Conflict);
            }
            verify_admin_only_security(file.0, false)?;
            drop(file);
            if unsafe { DeleteFileW(wide(&entry.path()).as_ptr()) } == 0 {
                return Err(Error::Conflict);
            }
        }
        drop(directory);
        if unsafe { RemoveDirectoryW(wide(self.directory).as_ptr()) } == 0 {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

struct PinnedImageFile {
    path: PathBuf,
    file: File,
    identity: ImageIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ImageIdentity {
    volume: u32,
    file_index: u64,
    size: u64,
    links: u32,
    attributes: u32,
    write_time: u64,
}

impl PinnedImageFile {
    fn open(path: &Path, owner_sid: &str, expected_sha256: &str, signer: &str) -> Result<Self> {
        let sd = super::Security::new(&admin_image_acl(owner_sid, false)).map_err(native)?;
        let raw = unsafe {
            CreateFileW(
                wide(path).as_ptr(),
                FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                FILE_SHARE_READ,
                &sd.attributes,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
                ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(Error::ProtectedImageRequired);
        }
        let file = unsafe { File::from_raw_handle(raw) };
        let before = image_identity(file.as_raw_handle().cast())?;
        if before.links != 1
            || before.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || before.size == 0
            || before.size > MAX_IMAGE
        {
            return Err(Error::ProtectedImageRequired);
        }
        verify_admin_image_security(file.as_raw_handle().cast(), owner_sid, false)?;
        let final_path = normalized(
            &path
                .canonicalize()
                .map_err(|_| Error::ProtectedImageRequired)?,
        )
        .map_err(native)?;
        if final_path != path {
            return Err(Error::ProtectedImageRequired);
        }
        let digest = hash_file(&file)?;
        if digest != expected_sha256 {
            return Err(Error::ProtectedImageRequired);
        }
        verify_authenticode(&file, path, signer)?;
        if image_identity(file.as_raw_handle().cast())? != before || hash_file(&file)? != digest {
            return Err(Error::ProtectedImageRequired);
        }
        Ok(Self {
            path: path.to_path_buf(),
            file,
            identity: before,
        })
    }

    fn recheck(&self, owner_sid: &str, signer: &str, sha256: &str) -> Result<()> {
        if image_identity(self.file.as_raw_handle().cast())? != self.identity
            || hash_file(&self.file)? != sha256
        {
            return Err(Error::Conflict);
        }
        verify_admin_image_security(self.file.as_raw_handle().cast(), owner_sid, false)?;
        verify_authenticode(&self.file, &self.path, signer)
    }
}

impl VerifiedHostServiceImage {
    /// Open only the updater-owned ProgramData install location for `account`.
    /// No arbitrary source path or environment variable is accepted.
    pub fn open(
        account: &str,
        cli_sha256: &str,
        helper_sha256: &str,
        signer_thumbprint: &str,
    ) -> Result<Self> {
        require_administrator()?;
        let identity = resolve_account(account)?;
        validate_hex_digest(cli_sha256)?;
        validate_hex_digest(helper_sha256)?;
        let signer = canonical_thumbprint(signer_thumbprint)?;
        let root = program_data_root()?.join(HOST_SERVICES);
        let owner_dir = root.join(&identity.sid);
        let install = owner_dir.join(INSTALL_DIR);
        let directory_pins = pin_admin_tree(&install, &identity.sid)?;
        verify_admin_image_directory(&install, &identity.sid, true)?;
        let cli_path = install.join(CLI_IMAGE);
        let helper_path = install.join(HELPER_IMAGE);
        let cli = PinnedImageFile::open(&cli_path, &identity.sid, cli_sha256, &signer)?;
        let helper = PinnedImageFile::open(&helper_path, &identity.sid, helper_sha256, &signer)?;
        Ok(Self {
            owner_sid: identity.sid,
            canonical_account: identity.canonical,
            install,
            cli_path,
            helper_path,
            cli_sha256: cli_sha256.to_owned(),
            helper_sha256: helper_sha256.to_owned(),
            signer_thumbprint: signer,
            _directory_pins: directory_pins,
            cli,
            helper,
        })
    }

    pub fn account_sid(&self) -> &str {
        &self.owner_sid
    }

    pub fn profile_path(&self) -> Result<PathBuf> {
        profile_path_for_account(&self.canonical_account, &self.owner_sid, None)
    }

    fn recheck(&self) -> Result<()> {
        self.cli
            .recheck(&self.owner_sid, &self.signer_thumbprint, &self.cli_sha256)?;
        self.helper.recheck(
            &self.owner_sid,
            &self.signer_thumbprint,
            &self.helper_sha256,
        )?;
        verify_admin_image_directory(&self.install, &self.owner_sid, true)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminServiceStatus {
    pub registered: bool,
    pub account_sid: String,
    pub account: String,
    pub profile: PathBuf,
    pub executable: PathBuf,
    pub helper: PathBuf,
    pub mode: &'static str,
    pub autostart: bool,
    pub phase: &'static str,
    pub running: bool,
    pub ready: bool,
    pub process_id: Option<u32>,
    pub host_id: Option<HostId>,
    pub profile_id: Option<IpcProfileId>,
    pub cli_sha256: String,
    pub helper_sha256: String,
    pub resume_after_update: bool,
}

/// Root-protected Host and IPC-profile identities observed from the selected
/// profile database. The Host service must also match the owner-complete
/// initialization receipt before accepting work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminHostIdentity {
    pub host_id: HostId,
    pub profile_id: IpcProfileId,
}

/// The verified binding for a protected Windows Boot installation.
///
/// This value can be created only by matching the current process image to the
/// SID-keyed ProgramData registration and its exact SCM configuration. The
/// account, profile, Host identity, and image paths are never accepted from
/// command-line arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredBootHost {
    account_sid: String,
    account: String,
    profile: PathBuf,
    install: PathBuf,
    executable: PathBuf,
    helper: PathBuf,
    identity: AdminHostIdentity,
    cli_sha256: String,
    helper_sha256: String,
    signer_thumbprint: String,
    phase: &'static str,
    running: bool,
}

impl RegisteredBootHost {
    pub fn account_sid(&self) -> &str {
        &self.account_sid
    }

    pub fn account(&self) -> &str {
        &self.account
    }

    pub fn profile(&self) -> &Path {
        &self.profile
    }

    pub fn install(&self) -> &Path {
        &self.install
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn helper(&self) -> &Path {
        &self.helper
    }

    pub fn identity(&self) -> AdminHostIdentity {
        self.identity
    }

    pub fn cli_sha256(&self) -> &str {
        &self.cli_sha256
    }

    pub fn helper_sha256(&self) -> &str {
        &self.helper_sha256
    }

    pub fn signer_thumbprint(&self) -> &str {
        &self.signer_thumbprint
    }

    pub fn phase(&self) -> &'static str {
        self.phase
    }

    pub fn running(&self) -> bool {
        self.running
    }
}

/// Pinned ProgramData storage for one selected Host's maintenance jobs.
/// The owner SID may traverse and read its public status records, while only
/// SYSTEM and elevated administrators can create or replace those records.
pub(super) struct MaintenanceStorage {
    pub(super) path: PathBuf,
    pub(super) owner_sid: String,
    _pins: Vec<AdminDirectoryPins>,
}

fn parse_host_identity(host_id: &str, profile_id: &str) -> Result<AdminHostIdentity> {
    Ok(AdminHostIdentity {
        host_id: HostId::try_from(host_id.to_owned()).map_err(|_| Error::Conflict)?,
        profile_id: IpcProfileId::try_from(profile_id.to_owned()).map_err(|_| Error::Conflict)?,
    })
}

#[derive(Debug)]
struct AccountIdentity {
    sid: String,
    canonical: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Registration {
    version: u8,
    operator_sid: String,
    account_sid: String,
    account: String,
    profile: String,
    service_name: String,
    command: String,
    executable: String,
    helper: String,
    cli_sha256: String,
    helper_sha256: String,
    signer_thumbprint: String,
    mode: String,
    phase: Phase,
    resume_after_update: bool,
    #[serde(default)]
    host_id: Option<HostId>,
    #[serde(default)]
    profile_id: Option<IpcProfileId>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Intent,
    CredentialsRequired,
    Configured,
    Starting,
    Ready,
    Updating,
    Deleting,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u8,
    operation_id: String,
    operation: String,
    phase: Phase,
    operator_sid: String,
    account_sid: String,
    account: String,
    service_name: String,
    profile: String,
    command: String,
    executable: String,
    helper: String,
    cli_sha256: String,
    helper_sha256: String,
    signer_thumbprint: String,
    mode: String,
    resume_after_update: bool,
}

struct AdminLock {
    _handle: Handle,
    _directory_pins: AdminDirectoryPins,
}

struct AdminDirectoryPins {
    _directories: Vec<Handle>,
}

impl Journal {
    fn matches(&self, record: &Registration) -> bool {
        self.version == 1
            && Uuid::parse_str(&self.operation_id).is_ok()
            && matches!(
                self.operation.as_str(),
                "install"
                    | "create_service"
                    | "repair_credentials"
                    | "configured"
                    | "start"
                    | "image_update"
                    | "image_update_credentials_repair"
                    | "image_update_complete"
                    | "uninstall"
            )
            && self.phase == record.phase
            && self.operator_sid == record.operator_sid
            && self.account_sid == record.account_sid
            && self.account == record.account
            && self.service_name == record.service_name
            && self.profile == record.profile
            && self.command == record.command
            && self.executable == record.executable
            && self.helper == record.helper
            && self.cli_sha256 == record.cli_sha256
            && self.helper_sha256 == record.helper_sha256
            && self.signer_thumbprint == record.signer_thumbprint
            && self.mode == record.mode
            && self.resume_after_update == record.resume_after_update
    }
}

impl Registration {
    fn name_for_sid(sid: &str) -> String {
        let digest = Sha256::digest(sid.as_bytes());
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x50;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        format!("LomiRemote-{}", Uuid::from_bytes(bytes))
    }

    fn command(&self) -> Result<String> {
        let arguments = [
            self.executable.as_str(),
            "--internal-scm",
            self.service_name.as_str(),
            self.profile.as_str(),
        ];
        let command = arguments
            .iter()
            .map(|argument| service::quote(argument).map_err(|_| Error::Invalid))
            .collect::<Result<Vec<_>>>()?
            .join(" ");
        if command.len() > 4096
            || service::parse(&command).map_err(|_| Error::Invalid)?
                != arguments
                    .iter()
                    .map(|arg| arg.to_string())
                    .collect::<Vec<_>>()
        {
            return Err(Error::Invalid);
        }
        Ok(command)
    }

    fn validate(&self) -> Result<()> {
        let normalized_profile = normalized(&PathBuf::from(&self.profile)).map_err(native)?;
        let normalized_executable = normalized(&PathBuf::from(&self.executable)).map_err(native)?;
        let normalized_helper = normalized(&PathBuf::from(&self.helper)).map_err(native)?;
        if self.version != 1
            || self.host_id.is_some() != self.profile_id.is_some()
            || self.mode != "boot"
            || self.account_sid.is_empty()
            || self.operator_sid.is_empty()
            || self.account.is_empty()
            || self.account.len() > 512
            || self.profile.len() > 4096
            || self.executable.len() > 4096
            || self.helper.len() > 4096
            || self.service_name.len() > 128
            || self.account.chars().any(char::is_control)
            || self.profile.is_empty()
            || !Path::new(&self.profile).is_absolute()
            || self.profile != path_text(&normalized_profile)?
            || self.service_name != Self::name_for_sid(&self.account_sid)
            || self.executable != path_text(&normalized_executable)?
            || self.helper != path_text(&normalized_helper)?
            || self.command != self.command()?
            || self.cli_sha256.len() != 64
            || self.helper_sha256.len() != 64
            || self
                .cli_sha256
                .bytes()
                .chain(self.helper_sha256.bytes())
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
            || canonical_thumbprint(&self.signer_thumbprint)? != self.signer_thumbprint
            || self.account_sid == SYSTEM_SID
            || self.account_sid == "S-1-5-19"
            || self.account_sid == "S-1-5-20"
            || self.account_sid == ADMIN_SID
            || !self.service_name.starts_with("LomiRemote-")
            || Uuid::parse_str(
                self.service_name
                    .strip_prefix("LomiRemote-")
                    .ok_or(Error::Invalid)?,
            )
            .is_err()
        {
            return Err(Error::Conflict);
        }
        if service::account_sid(&self.account).map_err(|_| Error::Conflict)? != self.account_sid {
            return Err(Error::Conflict);
        }
        Ok(())
    }

    fn service_registration(&self) -> service::Registration {
        service::Registration {
            version: 1,
            operator_sid: self.operator_sid.clone(),
            account_sid: self.account_sid.clone(),
            account: self.account.clone(),
            profile: self.profile.clone(),
            executable: self.executable.clone(),
            name: self.service_name.clone(),
            command: self.command.clone(),
            mode: "boot".to_owned(),
            phase: service::Phase::Registered,
            fixture: false,
        }
    }

    fn host_dispatch_allowed(&self) -> bool {
        matches!(
            self.phase,
            Phase::Configured | Phase::Starting | Phase::Ready
        ) && self.host_id.is_some()
            && self.profile_id.is_some()
    }

    fn host_identity(&self) -> Option<AdminHostIdentity> {
        Some(AdminHostIdentity {
            host_id: self.host_id?,
            profile_id: self.profile_id?,
        })
    }
}

impl AdminServiceStatus {
    fn from_record(
        record: &Registration,
        running: bool,
        ready: bool,
        process_id: Option<u32>,
    ) -> Self {
        Self {
            registered: true,
            account_sid: record.account_sid.clone(),
            account: record.account.clone(),
            profile: PathBuf::from(&record.profile),
            executable: PathBuf::from(&record.executable),
            helper: PathBuf::from(&record.helper),
            mode: "boot",
            autostart: true,
            phase: match record.phase {
                Phase::Intent => "intent",
                Phase::CredentialsRequired => "credentials_required",
                Phase::Configured => "configured",
                Phase::Starting => "starting",
                Phase::Ready => "ready",
                Phase::Updating => "updating",
                Phase::Deleting => "deleting",
            },
            running,
            ready,
            process_id,
            host_id: record.host_id,
            profile_id: record.profile_id,
            cli_sha256: record.cli_sha256.clone(),
            helper_sha256: record.helper_sha256.clone(),
            resume_after_update: record.resume_after_update,
        }
    }
}

fn status_service(record: &Registration, allow_missing: bool) -> Result<Option<Service>> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(scm)?;
    let service_registration = record.service_registration();
    let access =
        ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS | ServiceAccess::READ_CONTROL;
    let service = match manager.open_service(&record.service_name, access) {
        Ok(service) => service,
        Err(error) if service::missing(&error) && allow_missing => return Ok(None),
        Err(error) if service::missing(&error) => return Err(Error::NotInstalled),
        Err(error) if service::deleting(&error) => return Err(Error::Deadline),
        Err(error) => return Err(scm(error)),
    };
    service_registration
        .matches(&service.query_config().map_err(scm)?)
        .map_err(|_| Error::Conflict)?;
    verify_service_security(&service, &record.account_sid, false)?;
    service::recovery(&service).map_err(|_| Error::Conflict)?;
    Ok(Some(service))
}

// CreateServiceW has no security-descriptor argument. If an interrupted first
// install left the exact intent-bound service with its default SCM DACL, only
// harden it after checking that its complete config, stopped state, failure
// actions, and trusted owner match the durable intent.
fn harden_intent_service(record: &Registration) -> Result<()> {
    let journal = load_journal_for_sid(&record.account_sid)?.ok_or(Error::Conflict)?;
    if !journal.matches(record) || journal.operation != "create_service" {
        return Err(Error::Conflict);
    }
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(scm)?;
    let service = manager
        .open_service(
            &record.service_name,
            ServiceAccess::QUERY_CONFIG
                | ServiceAccess::QUERY_STATUS
                | ServiceAccess::READ_CONTROL
                | ServiceAccess::WRITE_DAC,
        )
        .map_err(scm)?;
    record
        .service_registration()
        .matches(&service.query_config().map_err(scm)?)
        .map_err(|_| Error::Conflict)?;
    service::recovery(&service).map_err(|_| Error::Conflict)?;
    if service.query_status().map_err(scm)?.current_state != ServiceState::Stopped {
        return Err(Error::Conflict);
    }
    verify_service_owner(&service)?;
    set_service_dacl(&record.service_name, &record.account_sid)?;
    // Validate the hardened ACL through the same service handle whose exact
    // configuration and trusted owner were checked above. A newly-created
    // service can still have SCM's default DACL at this recovery point.
    verify_service_security(&service, &record.account_sid, true)
}

fn process_identity(process_id: u32, expected_sid: &str, expected_image: &Path) -> Result<()> {
    if process_id == 0 {
        return Err(Error::NotReady);
    }
    let process = Handle::new(unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
            0,
            process_id,
        )
    })
    .map_err(|_| Error::NotReady)?;
    if unsafe { WaitForSingleObject(process.0, 0) } != WAIT_TIMEOUT {
        return Err(Error::NotReady);
    }
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) } == 0 {
        return Err(Error::NotReady);
    }
    let token = Handle::new(token).map_err(|_| Error::NotReady)?;
    let mut user_size = 0u32;
    unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut user_size) };
    if user_size == 0 || user_size > 4096 {
        return Err(Error::NotReady);
    }
    let mut user = vec![0usize; (user_size as usize).div_ceil(mem::size_of::<usize>())];
    let mut returned = 0u32;
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            user.as_mut_ptr().cast(),
            user_size,
            &mut returned,
        )
    } == 0
        || unsafe { sid_text((*user.as_ptr().cast::<TOKEN_USER>()).User.Sid) }.map_err(native)?
            != expected_sid
    {
        return Err(Error::NotReady);
    }
    let mut path = vec![0u16; 32768];
    let mut count = path.len() as u32;
    if unsafe { QueryFullProcessImageNameW(process.0, 0, path.as_mut_ptr(), &mut count) } == 0
        || count == 0
        || count as usize > path.len()
    {
        return Err(Error::NotReady);
    }
    path.truncate(count as usize);
    let actual = normalized(&PathBuf::from(OsString::from_wide(&path))).map_err(native)?;
    if actual != expected_image {
        return Err(Error::NotReady);
    }
    Ok(())
}

fn status_for_record(record: &Registration, require_images: bool) -> Result<AdminServiceStatus> {
    record.validate()?;
    let Some(service) = status_service(record, true)? else {
        let mut result = AdminServiceStatus::from_record(record, false, false, None);
        result.registered = false;
        return Ok(result);
    };
    let status = service.query_status().map_err(scm)?;
    if require_images {
        verify_recorded_images(record)?;
    }
    let running = status.current_state == ServiceState::Running;
    let ready = if running {
        let process_id = status.process_id.ok_or(Error::NotReady)?;
        process_identity(
            process_id,
            &record.account_sid,
            Path::new(&record.executable),
        )?;
        // The Host service publishes SCM Running only after its authenticated
        // Host readiness handshake. Configured is dispatch-allowed for an
        // owner-started service after an update, but still requires that SCM
        // state and the exact PID/token/image proof above.
        record.host_dispatch_allowed()
    } else {
        false
    };
    Ok(AdminServiceStatus::from_record(
        record,
        running,
        ready,
        status.process_id,
    ))
}

fn verify_recorded_images(record: &Registration) -> Result<()> {
    let root = program_data_root()?.join(HOST_SERVICES);
    let install = root.join(&record.account_sid).join(INSTALL_DIR);
    if Path::new(&record.executable) != install.join(CLI_IMAGE)
        || Path::new(&record.helper) != install.join(HELPER_IMAGE)
    {
        return Err(Error::ProtectedImageRequired);
    }
    let _pins = pin_admin_tree(&install, &record.account_sid)?;
    verify_admin_image_directory(&install, &record.account_sid, true)?;
    let cli = PinnedImageFile::open(
        Path::new(&record.executable),
        &record.account_sid,
        &record.cli_sha256,
        &record.signer_thumbprint,
    )?;
    let helper = PinnedImageFile::open(
        Path::new(&record.helper),
        &record.account_sid,
        &record.helper_sha256,
        &record.signer_thumbprint,
    )?;
    drop((cli, helper));
    Ok(())
}

/// Read an administrator-managed Host service record and its exact SCM state.
/// The selected account may inspect its own service through read-only public
/// registration and SCM query rights; cross-account inspection requires admin.
pub fn inspect(account: &str) -> Result<Option<AdminServiceStatus>> {
    let identity = resolve_account(account)?;
    authorize_read(&identity.sid)?;
    let Some(record) = load_registration_for_sid(&identity.sid)? else {
        return Ok(None);
    };
    if record.account != identity.canonical {
        return Err(Error::Conflict);
    }
    Ok(Some(status_for_record(&record, true)?))
}

/// Resolve the protected Boot Host whose registered CLI is this process image.
///
/// A non-Boot executable returns `None`, so ordinary per-user installations
/// continue through their existing path. A Boot image requires an elevated
/// administrator for update or uninstall. The selected owner is derived from
/// the SID directory containing the protected executable, then checked
/// against the signed registration and the live SCM configuration.
pub fn registered_boot_host_for_current_executable() -> Result<Option<RegisteredBootHost>> {
    let executable = normalized(
        &std::env::current_exe()
            .and_then(|path| path.canonicalize())
            .map_err(|_| Error::Conflict)?,
    )
    .map_err(native)?;
    let root = normalized(&program_data_root()?.join(HOST_SERVICES)).map_err(native)?;
    let Ok(relative) = executable.strip_prefix(&root) else {
        return Ok(None);
    };
    let parts = relative.components().collect::<Vec<_>>();
    let [
        std::path::Component::Normal(owner_sid),
        std::path::Component::Normal(install),
        std::path::Component::Normal(image),
    ] = parts.as_slice()
    else {
        return Ok(None);
    };
    let Some(owner_sid) = owner_sid.to_str() else {
        return Ok(None);
    };
    if *install != OsStr::new(INSTALL_DIR) || *image != OsStr::new(CLI_IMAGE) {
        return Ok(None);
    }
    require_administrator()?;
    registered_boot_host_for_sid(owner_sid, &executable).map(Some)
}

/// Read the protected Boot binding for a SID already recovered from a
/// verified maintenance capsule. Callers must validate that capsule before
/// supplying its SID; the result is then compared field-for-field with it.
pub(super) fn registered_boot_host_for_sid(
    owner_sid: &str,
    expected_executable: &Path,
) -> Result<RegisteredBootHost> {
    require_administrator()?;
    let identity = resolve_account(owner_sid)?;
    if identity.sid != owner_sid {
        return Err(Error::Conflict);
    }
    let record = load_registration_for_sid(owner_sid)?.ok_or(Error::NotInstalled)?;
    if record.account != identity.canonical
        || record.account_sid != identity.sid
        || record.mode != "boot"
        || normalized(expected_executable).map_err(native)? != Path::new(&record.executable)
        || normalized(Path::new(&record.executable)).map_err(native)?
            != service_directory(owner_sid)?
                .join(INSTALL_DIR)
                .join(CLI_IMAGE)
        || normalized(Path::new(&record.helper)).map_err(native)?
            != service_directory(owner_sid)?
                .join(INSTALL_DIR)
                .join(HELPER_IMAGE)
    {
        return Err(Error::Conflict);
    }
    registered_boot_host_from_record(record, expected_executable)
}

/// Revalidate a registered Boot binding and report whether its service needs
/// a stop attempt. Only a positively observed `Stopped` state is considered
/// stopped; pending and paused states must not take the caller's no-op path.
/// This intentionally works while the registration journal is in an Updating
/// phase, where ordinary service control is fenced and the only safe no-op is
/// a positively observed stopped service.
pub fn registered_boot_host_needs_stop(expected: &RegisteredBootHost) -> Result<bool> {
    require_administrator()?;
    let record = load_registration_for_sid(expected.account_sid())?.ok_or(Error::NotInstalled)?;
    let current = registered_boot_host_for_sid(expected.account_sid(), expected.executable())?;
    if record.account_sid != expected.account_sid
        || record.account != expected.account
        || Path::new(&record.profile) != expected.profile
        || Path::new(&record.executable) != expected.executable
        || Path::new(&record.helper) != expected.helper
        || record.host_identity() != Some(expected.identity)
        || record.cli_sha256 != expected.cli_sha256
        || record.helper_sha256 != expected.helper_sha256
        || record.signer_thumbprint != expected.signer_thumbprint
        || current.account_sid != expected.account_sid
        || current.account != expected.account
        || current.profile != expected.profile
        || current.install != expected.install
        || current.executable != expected.executable
        || current.helper != expected.helper
        || current.identity != expected.identity
        || current.cli_sha256 != expected.cli_sha256
        || current.helper_sha256 != expected.helper_sha256
        || current.signer_thumbprint != expected.signer_thumbprint
    {
        return Err(Error::Conflict);
    }
    let service = status_service(&record, true)?.ok_or(Error::NotInstalled)?;
    Ok(service.query_status().map_err(scm)?.current_state != ServiceState::Stopped)
}

/// Resolve the owner-side Boot binding without elevating. This is used only by
/// the closed owner continuation after it has been launched in that exact
/// account; it never grants access to the administrator updater area.
pub(super) fn registered_boot_host_for_owner_executable() -> Result<RegisteredBootHost> {
    let executable = normalized(
        &std::env::current_exe()
            .and_then(|path| path.canonicalize())
            .map_err(|_| Error::Conflict)?,
    )
    .map_err(native)?;
    let root = normalized(&program_data_root()?.join(HOST_SERVICES)).map_err(native)?;
    let relative = executable
        .strip_prefix(&root)
        .map_err(|_| Error::Conflict)?;
    let parts = relative.components().collect::<Vec<_>>();
    let [
        std::path::Component::Normal(owner_sid),
        std::path::Component::Normal(install),
        std::path::Component::Normal(image),
    ] = parts.as_slice()
    else {
        return Err(Error::Conflict);
    };
    let owner_sid = owner_sid.to_str().ok_or(Error::Conflict)?;
    if *install != OsStr::new(INSTALL_DIR)
        || *image != OsStr::new(CLI_IMAGE)
        || current_sid().map_err(native)? != owner_sid
    {
        return Err(Error::Conflict);
    }
    let identity = resolve_account(owner_sid)?;
    let record = load_registration_for_sid(owner_sid)?.ok_or(Error::NotInstalled)?;
    if record.account != identity.canonical
        || record.account_sid != identity.sid
        || record.mode != "boot"
    {
        return Err(Error::Conflict);
    }
    registered_boot_host_from_record(record, &executable)
}

fn registered_boot_host_from_record(
    record: Registration,
    expected_executable: &Path,
) -> Result<RegisteredBootHost> {
    record.validate()?;
    if record.mode != "boot"
        || normalized(Path::new(&record.executable)).map_err(native)?
            != normalized(expected_executable).map_err(native)?
    {
        return Err(Error::Conflict);
    }
    let identity = record.host_identity().ok_or(Error::Conflict)?;
    let status = status_for_record(&record, false)?;
    let install = service_directory(&record.account_sid)?.join(INSTALL_DIR);
    Ok(RegisteredBootHost {
        account_sid: record.account_sid,
        account: record.account,
        profile: PathBuf::from(record.profile),
        install,
        executable: PathBuf::from(record.executable),
        helper: PathBuf::from(record.helper),
        identity,
        cli_sha256: record.cli_sha256,
        helper_sha256: record.helper_sha256,
        signer_thumbprint: record.signer_thumbprint,
        phase: status.phase,
        running: status.running,
    })
}

/// Verify the user-only Host endpoint against the SCM PID already observed by
/// `inspect`. The PID comparison uses the OS-reported server PID captured by
/// LocalClient while retaining its authenticated server process handle.
pub fn authenticated_host_status(profile: &Path, expected_pid: u32) -> bool {
    if expected_pid == 0 {
        return false;
    }
    let Ok(mut client) = LocalClient::connect_with_timeout(profile, Duration::from_secs(2)) else {
        return false;
    };
    if client.server_process_id() != expected_pid {
        return false;
    }
    let discovery = client.discovery().clone();
    matches!(
        client.request_with_timeout(LocalCall::Status {}, Duration::from_secs(2)),
        Ok(response)
            if matches!(response.result,
                Ok(LocalResult::Status(ref status))
                    if status.host_id == discovery.host_id
                        && status.runtime_id == discovery.runtime_id)
    )
}

/// Acquire the registered Host's exact profile owner lock from an elevated
/// updater. The profile path comes only from the SID-bound protected service
/// registration and its native Windows profile binding.
pub fn acquire_registered_host_owner_lock(account: &str) -> Result<HostOwnerLock> {
    require_administrator()?;
    let identity = resolve_account(account)?;
    let record = load_registration_for_sid(&identity.sid)?.ok_or(Error::NotInstalled)?;
    if record.account != identity.canonical
        || record.account_sid != identity.sid
        || record.phase == Phase::Deleting
    {
        return Err(Error::Conflict);
    }
    let profile = native_app_profile_path(&identity, false)?;
    if Path::new(&record.profile) != profile {
        return Err(Error::Conflict);
    }
    reject_legacy_manager(&profile)?;
    acquire_host_owner_lock(profile, &identity.sid, false)
}

/// Acquire the native profile lock for an explicitly authorized first install.
/// It refuses existing manager registrations and creates only the fixed app
/// profile directory and empty owner.lock under the selected user's default
/// Windows profile directory.
pub fn acquire_initial_host_owner_lock(account: &str) -> Result<HostOwnerLock> {
    require_administrator()?;
    let identity = resolve_account(account)?;
    if load_registration_for_sid(&identity.sid)?.is_some()
        || service_object_exists_for_sid(&identity.sid)?
    {
        return Err(Error::Conflict);
    }
    let profile = native_app_profile_path(&identity, true)?;
    reject_legacy_manager(&profile)?;
    acquire_host_owner_lock(profile, &identity.sid, true)
}

fn authorize_read(target_sid: &str) -> Result<()> {
    if current_sid().map_err(native)? == target_sid {
        Ok(())
    } else {
        require_administrator()
    }
}

fn authorize_owner_control(target_sid: &str) -> Result<()> {
    let mut raw_token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(Error::AccountNotOrdinary);
    }
    let token = Handle::new(raw_token).map_err(|_| Error::AccountNotOrdinary)?;
    if current_sid().map_err(native)? != target_sid || token_has_group(token.0, BUILTIN_ADMINS_SID)?
    {
        return Err(Error::AccountNotOrdinary);
    }
    Ok(())
}

fn run_owner_control(operation: &str, identity: &AccountIdentity) -> Result<AdminServiceStatus> {
    let _owner_lock = OwnerControlLock::acquire(&identity.sid)?;
    let record = load_registration_for_sid(&identity.sid)?.ok_or(Error::NotInstalled)?;
    if record.account != identity.canonical
        || record.account_sid != identity.sid
        || record.mode != "boot"
        || matches!(
            record.phase,
            Phase::Intent | Phase::Updating | Phase::Deleting
        )
    {
        return Err(Error::Conflict);
    }
    if operation == "start" && record.phase == Phase::CredentialsRequired {
        return Err(Error::CredentialsRequired);
    }
    if operation == "start" && record.host_identity().is_none() {
        return Err(Error::Conflict);
    }
    verify_recorded_images(&record)?;
    let access = match operation {
        "start" => ServiceAccess::START,
        "stop" => ServiceAccess::STOP,
        _ => return Err(Error::Invalid),
    };
    let service = open_for_control(&record, access)?;
    verify_service_security(&service, &record.account_sid, true)?;
    let state = service.query_status().map_err(scm)?.current_state;
    if operation == "start" {
        if state != ServiceState::Running {
            match service.start::<&str>(&[]) {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error,
                        windows_service::Error::Winapi(ref e)
                            if e.raw_os_error() == Some(ERROR_SERVICE_ALREADY_RUNNING as i32)
                    ) => {}
                Err(error)
                    if matches!(
                        error,
                        windows_service::Error::Winapi(ref e)
                            if e.raw_os_error() == Some(ERROR_SERVICE_LOGON_FAILED as i32)
                    ) =>
                {
                    return Err(Error::CredentialsRequired);
                }
                Err(error) => return Err(scm(error)),
            }
        }
        wait_state(&service, ServiceState::Running, Instant::now() + WAIT)?;
        let status = status_for_record(&record, true)?;
        if !status.ready {
            return Err(Error::NotReady);
        }
        Ok(status)
    } else {
        if !matches!(state, ServiceState::Stopped | ServiceState::StopPending) {
            service.stop().map_err(scm)?;
        }
        wait_state(&service, ServiceState::Stopped, Instant::now() + WAIT)?;
        let status = status_for_record(&record, true)?;
        if status.running {
            return Err(Error::NotReady);
        }
        Ok(status)
    }
}

struct ScmHandle(SC_HANDLE);

impl Drop for ScmHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseServiceHandle(self.0) };
        }
    }
}

fn open_native_manager(access: u32) -> Result<ScmHandle> {
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), access) };
    if manager.is_null() {
        let error = unsafe { GetLastError() };
        return Err(if error == ERROR_ACCESS_DENIED {
            Error::AdministratorRequired
        } else {
            Error::Manager
        });
    }
    Ok(ScmHandle(manager))
}

fn configure_native_service(
    record: &Registration,
    password: &ServicePassword,
    create: bool,
) -> Result<()> {
    let manager = open_native_manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
    let name = wide(OsStr::new(&record.service_name));
    let command = wide(OsStr::new(&record.command));
    let account = wide(OsStr::new(&record.account));
    let dependencies = [0u16, 0u16];
    let display = wide(OsStr::new(&record.service_name));
    let password_ptr = password.nul_terminated()?;
    let result = if create {
        let handle = unsafe {
            CreateServiceW(
                manager.0,
                name.as_ptr(),
                display.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                command.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                dependencies.as_ptr(),
                account.as_ptr(),
                password_ptr,
            )
        };
        if handle.is_null() {
            Err(unsafe { GetLastError() })
        } else {
            unsafe { CloseServiceHandle(handle) };
            Ok(())
        }
    } else {
        let handle = unsafe {
            OpenServiceW(
                manager.0,
                name.as_ptr(),
                SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | WRITE_DAC,
            )
        };
        if handle.is_null() {
            Err(unsafe { GetLastError() })
        } else {
            let changed = unsafe {
                ChangeServiceConfigW(
                    handle,
                    SERVICE_NO_CHANGE,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    command.as_ptr(),
                    ptr::null(),
                    ptr::null_mut(),
                    dependencies.as_ptr(),
                    account.as_ptr(),
                    password_ptr,
                    display.as_ptr(),
                )
            };
            let error = if changed == 0 {
                Some(unsafe { GetLastError() })
            } else {
                None
            };
            unsafe { CloseServiceHandle(handle) };
            error.map_or(Ok(()), Err)
        }
    };
    result.map_err(|code| match code {
        ERROR_SERVICE_LOGON_FAILED | ERROR_ACCOUNT_RESTRICTION | ERROR_INVALID_PASSWORD => {
            Error::CredentialsRequired
        }
        ERROR_ACCESS_DENIED => Error::AdministratorRequired,
        ERROR_SERVICE_EXISTS => Error::Conflict,
        _ => Error::Manager,
    })?;
    set_service_dacl(&record.service_name, &record.account_sid)?;
    Ok(())
}

fn set_service_dacl(service_name: &str, account_sid: &str) -> Result<()> {
    let manager = open_native_manager(SC_MANAGER_CONNECT)?;
    let name = wide(OsStr::new(service_name));
    let service = unsafe {
        OpenServiceW(
            manager.0,
            name.as_ptr(),
            WRITE_DAC | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
        )
    };
    if service.is_null() {
        return Err(Error::Manager);
    }
    let handle = ScmHandle(service);
    let owner_access = service_query_rights() | SERVICE_START | SERVICE_STOP;
    let descriptor = super::Security::new(&format!(
        "O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x{owner_access:08x};;;{account_sid})"
    ))
    .map_err(native)?;
    if unsafe {
        SetServiceObjectSecurity(
            handle.0,
            DACL_SECURITY_INFORMATION,
            descriptor.attributes.lpSecurityDescriptor.cast(),
        )
    } == 0
    {
        return Err(Error::Manager);
    }
    Ok(())
}

fn ensure_service_logon_right(account_sid: &str) -> Result<()> {
    let sid_wide = wide(OsStr::new(account_sid));
    let mut sid = ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(sid_wide.as_ptr(), &mut sid) } == 0 || sid.is_null() {
        return Err(Error::AccountNotOrdinary);
    }
    let _sid = Local(sid.cast());
    let mut attributes: LSA_OBJECT_ATTRIBUTES = unsafe { mem::zeroed() };
    attributes.Length = mem::size_of::<LSA_OBJECT_ATTRIBUTES>() as u32;
    let mut policy: LSA_HANDLE = 0;
    let status = unsafe {
        LsaOpenPolicy(
            ptr::null(),
            &attributes,
            (POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT) as u32,
            &mut policy,
        )
    };
    if status != 0 || policy == 0 {
        return Err(Error::CredentialsRequired);
    }
    let mut right_wide = wide(OsStr::new(SE_SERVICE_LOGON_RIGHT));
    let right = LSA_UNICODE_STRING {
        Length: ((right_wide.len() - 1) * mem::size_of::<u16>()) as u16,
        MaximumLength: (right_wide.len() * mem::size_of::<u16>()) as u16,
        Buffer: right_wide.as_mut_ptr(),
    };
    let add_status = unsafe { LsaAddAccountRights(policy, sid, &right, 1) };
    unsafe { LsaClose(policy) };
    if add_status != 0 {
        return Err(Error::CredentialsRequired);
    }
    Ok(())
}

fn open_for_control(record: &Registration, required: ServiceAccess) -> Result<Service> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(scm)?;
    let access = ServiceAccess::QUERY_CONFIG
        | ServiceAccess::QUERY_STATUS
        | ServiceAccess::READ_CONTROL
        | required;
    let service = manager
        .open_service(&record.service_name, access)
        .map_err(scm)?;
    record
        .service_registration()
        .matches(&service.query_config().map_err(scm)?)
        .map_err(|_| Error::Conflict)?;
    service::recovery(&service).map_err(|_| Error::Conflict)?;
    Ok(service)
}

impl OwnerControlLock {
    fn acquire(owner_sid: &str) -> Result<Self> {
        let directory = service_directory(owner_sid)?;
        let directory_pins = verify_store_directory(&directory, owner_sid)?;
        let path = directory.join(MANAGEMENT_LOCK);
        let raw = unsafe {
            CreateFileW(
                wide(&path).as_ptr(),
                GENERIC_READ | READ_CONTROL,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
                ptr::null_mut(),
            )
        };
        let handle = Handle::new(raw).map_err(|_| Error::Conflict)?;
        let info = information(handle.0).map_err(native)?;
        if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || info.nNumberOfLinks != 1
            || info.nFileSizeHigh != 0
            || info.nFileSizeLow != 0
        {
            return Err(Error::ProtectedImageRequired);
        }
        verify_management_lock_security(handle.0, owner_sid, true)?;
        Ok(Self {
            _handle: handle,
            _directory_pins: directory_pins,
        })
    }
}

fn wait_state(service: &Service, wanted: ServiceState, deadline: Instant) -> Result<()> {
    let status = service::wait(service, wanted, deadline).map_err(|error| match error {
        ServiceError::CredentialsRequired => Error::CredentialsRequired,
        ServiceError::Deadline => Error::Deadline,
        _ => Error::NotReady,
    })?;
    if wanted == ServiceState::Stopped
        && !matches!(status.exit_code, ServiceExitCode::Win32(0 | 1077))
    {
        return Err(Error::NotReady);
    }
    Ok(())
}

fn wait_stopped_for_credential_repair(
    service: &Service,
    deadline: Instant,
    known_logon_failure: bool,
) -> Result<()> {
    let status =
        service::wait(service, ServiceState::Stopped, deadline).map_err(|error| match error {
            ServiceError::CredentialsRequired => Error::CredentialsRequired,
            ServiceError::Deadline => Error::Deadline,
            _ => Error::NotReady,
        })?;
    let accepted = matches!(status.exit_code, ServiceExitCode::Win32(0 | 1077))
        || (known_logon_failure && status.exit_code == ServiceExitCode::Win32(1069));
    if !accepted {
        return Err(Error::NotReady);
    }
    Ok(())
}

fn start_registered(record: &Registration) -> Result<AdminServiceStatus> {
    if record.host_identity().is_none() {
        return Err(Error::Conflict);
    }
    verify_recorded_images(record)?;
    let configured = status_service(record, true)?.ok_or(Error::NotInstalled)?;
    let queried = configured.query_config().map_err(scm)?;
    record
        .service_registration()
        .matches(&queried)
        .map_err(|_| Error::Conflict)?;
    set_service_dacl(&record.service_name, &record.account_sid)?;
    let mut starting = record.clone();
    starting.phase = Phase::Starting;
    save_journal(&starting, "start")?;
    save_registration(&starting)?;
    let service = open_for_control(&starting, ServiceAccess::START)?;
    if service.query_status().map_err(scm)?.current_state != ServiceState::Running {
        match service.start::<&str>(&[]) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error,
                    windows_service::Error::Winapi(ref e)
                        if e.raw_os_error() == Some(ERROR_SERVICE_ALREADY_RUNNING as i32)
                ) => {}
            Err(error)
                if matches!(
                    error,
                    windows_service::Error::Winapi(ref e)
                        if e.raw_os_error() == Some(ERROR_SERVICE_LOGON_FAILED as i32)
                ) =>
            {
                let mut failed = starting;
                failed.phase = Phase::CredentialsRequired;
                save_journal(&failed, "repair_credentials")?;
                save_registration(&failed)?;
                return Err(Error::CredentialsRequired);
            }
            Err(error) => return Err(scm(error)),
        }
    }
    wait_state(&service, ServiceState::Running, Instant::now() + WAIT)?;
    let mut latest = starting;
    latest.phase = Phase::Ready;
    latest.resume_after_update = false;
    save_journal(&latest, "start")?;
    save_registration(&latest)?;
    let status = status_for_record(&latest, true)?;
    if !status.ready {
        return Err(Error::NotReady);
    }
    Ok(status)
}

fn stop_registered(record: &Registration) -> Result<AdminServiceStatus> {
    let service = open_for_control(record, ServiceAccess::STOP)?;
    let state = service.query_status().map_err(scm)?.current_state;
    if !matches!(state, ServiceState::Stopped | ServiceState::StopPending) {
        service.stop().map_err(scm)?;
    }
    wait_state(&service, ServiceState::Stopped, Instant::now() + WAIT)?;
    let status = status_for_record(record, true)?;
    if status.running {
        return Err(Error::NotReady);
    }
    Ok(status)
}

fn reject_legacy_manager(profile: &Path) -> Result<()> {
    let name = profile
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or(Error::Invalid)?;
    for suffix in ["service-windows", "service-windows-login"] {
        let marker = profile
            .with_file_name(format!("{name}-{suffix}"))
            .join("registration.json");
        match std::fs::symlink_metadata(&marker) {
            Ok(_) => return Err(Error::Conflict),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error::Conflict),
        }
    }
    Ok(())
}

fn remove_json(path: &Path, owner_sid: &str, public: bool) -> Result<()> {
    let value: Option<serde_json::Value> = read_json(path, owner_sid, public)?;
    if value.is_none() {
        return Ok(());
    }
    if unsafe { DeleteFileW(wide(path).as_ptr()) } == 0 {
        return Err(Error::Deadline);
    }
    Ok(())
}

fn uninstall(owner_sid: &str) -> Result<String> {
    let Some(mut record) = load_registration_for_sid(owner_sid)? else {
        return Err(Error::NotInstalled);
    };
    // Validate (and, for an interrupted first CreateServiceW, harden) the
    // exact service before replacing its create intent with an uninstall
    // journal. Otherwise the default SCM DACL can prevent both the strict
    // status check and any later retry after the original proof is lost.
    if service_object_exists(&record)? {
        match status_service(&record, true) {
            Ok(Some(_)) => {}
            Err(Error::Conflict) if record.phase == Phase::Intent => {
                harden_intent_service(&record)?;
                status_service(&record, true)?.ok_or(Error::Conflict)?;
            }
            Ok(None) => {}
            Err(error) => return Err(error),
        }
    }
    record.phase = Phase::Deleting;
    save_journal(&record, "uninstall")?;
    save_registration(&record)?;
    if status_service(&record, true)?.is_some() {
        let service = open_for_control(&record, ServiceAccess::STOP | ServiceAccess::DELETE)?;
        let current = service.query_status().map_err(scm)?.current_state;
        if !matches!(current, ServiceState::Stopped | ServiceState::StopPending) {
            service.stop().map_err(scm)?;
        }
        wait_state(&service, ServiceState::Stopped, Instant::now() + WAIT)?;
        service.delete().map_err(scm)?;
        drop(service);
        let deadline = Instant::now() + WAIT;
        loop {
            if Instant::now() >= deadline {
                return Err(Error::Deadline);
            }
            match status_service(&record, true) {
                Ok(None) => break,
                Err(Error::Deadline) => thread::sleep(POLL),
                Ok(Some(_)) => thread::sleep(POLL),
                Err(error) => return Err(error),
            }
        }
    }
    remove_json(&registration_path(owner_sid)?, owner_sid, true)?;
    remove_json(&journal_path(owner_sid)?, owner_sid, false)?;
    // SeServiceLogonRight is intentionally retained. It belongs to the
    // account-wide local security policy and may serve other applications.
    Ok("Administrator-managed Host service uninstalled; account logon right retained.".into())
}

/// Durable maintenance lease held across updater stop, activation/rollback,
/// and image-binding completion. Dropping an incomplete lease releases the
/// lock but leaves the registration in `updating`, which blocks Host startup.
pub struct ImageUpdateGuard {
    _lock: AdminLock,
    _image_directory_pins: AdminDirectoryPins,
    record: Registration,
    previously_running: bool,
}

impl ImageUpdateGuard {
    pub fn previously_running(&self) -> bool {
        self.previously_running
    }

    /// The service's currently registered image hashes. The updater may
    /// replace only these exact old files or an already-published new image
    /// while the durable `updating` phase blocks Host startup.
    pub fn current_image_hashes(&self) -> (&str, &str) {
        (&self.record.cli_sha256, &self.record.helper_sha256)
    }

    /// One-time explicit migration for a legacy registration without root
    /// identity pins. The caller must hold the selected account's exact
    /// OwnerLock and supply identity read from its validated database
    /// snapshot. This accepts only the already-stopped, exact updating
    /// service and never changes an existing pin.
    pub fn bind_existing_host_identity(
        &mut self,
        owner_lock: &HostOwnerLock,
        host_id: &str,
        profile_id: &str,
    ) -> Result<()> {
        let identity = parse_host_identity(host_id, profile_id)?;
        if owner_lock.owner_sid != self.record.account_sid
            || owner_lock.profile_path() != Path::new(&self.record.profile)
            || self.record.phase != Phase::Updating
        {
            return Err(Error::Conflict);
        }
        if let Some(existing) = self.record.host_identity() {
            return if existing == identity {
                Ok(())
            } else {
                Err(Error::Conflict)
            };
        }
        verify_recorded_images(&self.record)?;
        let service = status_service(&self.record, false)?.ok_or(Error::Conflict)?;
        let status = service.query_status().map_err(scm)?;
        if status.current_state != ServiceState::Stopped
            || !matches!(status.exit_code, ServiceExitCode::Win32(0 | 1077 | 1069))
        {
            return Err(Error::Conflict);
        }
        let mut record = self.record.clone();
        record.host_id = Some(identity.host_id);
        record.profile_id = Some(identity.profile_id);
        record.validate()?;
        save_registration(&record)?;
        self.record = record;
        Ok(())
    }

    /// Bind the verified updater image after activation or rollback. This does
    /// not restart the Host; the updater decides from its durable transaction
    /// whether and when to call `run("start", ...)`.
    pub fn complete(self, image: &VerifiedHostServiceImage) -> Result<AdminServiceStatus> {
        image.recheck()?;
        let credential_repair_update = credential_repair_journal_matches(&self.record)?;
        if image.owner_sid != self.record.account_sid
            || image.canonical_account != self.record.account
            || self.record.host_identity().is_none()
            || path_text(&image.cli_path)? != self.record.executable
            || path_text(&image.helper_path)? != self.record.helper
        {
            return Err(Error::Conflict);
        }
        let service = status_service(&self.record, true)?.ok_or(Error::NotInstalled)?;
        if service.query_status().map_err(scm)?.current_state != ServiceState::Stopped {
            return Err(Error::Conflict);
        }
        set_service_dacl(&self.record.service_name, &self.record.account_sid)?;
        verify_service_security(&service, &self.record.account_sid, true)?;
        let mut record = self.record.clone();
        record.cli_sha256 = image.cli_sha256.clone();
        record.helper_sha256 = image.helper_sha256.clone();
        record.signer_thumbprint = image.signer_thumbprint.clone();
        record.phase = Phase::Configured;
        if credential_repair_update {
            // For the typed 1069 repair transaction, publish the new image
            // binding before replacing its recovery marker. If interrupted
            // between these writes, the Configured registration matches the
            // activated bytes and an explicit fresh-password retry can begin
            // a new repair transaction from the still-observed 1069 state.
            save_registration(&record)?;
            save_journal(&record, "image_update_complete")?;
        } else {
            save_journal(&record, "image_update_complete")?;
            save_registration(&record)?;
        }
        status_for_record(&record, true)
    }
}

/// Stop the exact registered Host and durably block SCM startup before the
/// updater changes either protected image. If interrupted, this call can be
/// repeated while the record remains in `updating`.
fn begin_image_update_inner(
    account: &str,
    recovery_only: bool,
    credential_repair: bool,
) -> Result<ImageUpdateGuard> {
    require_administrator()?;
    let identity = resolve_account(account)?;
    let lock = AdminLock::acquire(&identity.sid)?;
    let mut record = load_registration_for_sid(&identity.sid)?.ok_or(Error::NotInstalled)?;
    if record.account != identity.canonical || record.phase == Phase::Deleting {
        return Err(Error::Conflict);
    }
    if credential_repair
        && !matches!(
            record.phase,
            Phase::Configured | Phase::Starting | Phase::Ready | Phase::Updating
        )
    {
        return Err(Error::Conflict);
    }
    if recovery_only && record.phase != Phase::Updating {
        return Err(Error::Conflict);
    }
    let credential_repair_marker = credential_repair_journal_matches(&record)?;
    if credential_repair_marker && !credential_repair {
        // An interrupted update admitted from a known logon failure must be
        // resumed only through the explicit fresh-credential repair path.
        return Err(Error::CredentialsRequired);
    }
    if record.phase == Phase::Updating && credential_repair && !recovery_only {
        return Err(Error::Conflict);
    }
    let install = program_data_root()?
        .join(HOST_SERVICES)
        .join(&record.account_sid)
        .join(INSTALL_DIR);
    if Path::new(&record.executable) != install.join(CLI_IMAGE)
        || Path::new(&record.helper) != install.join(HELPER_IMAGE)
    {
        return Err(Error::ProtectedImageRequired);
    }
    let image_directory_pins = pin_admin_tree(&install, &record.account_sid)?;
    verify_admin_image_directory(&install, &record.account_sid, true)?;
    status_service(&record, false)?.ok_or(Error::NotInstalled)?;
    let service = open_for_control(&record, ServiceAccess::STOP)?;
    let status = service.query_status().map_err(scm)?;
    let known_logon_failure = status.current_state == ServiceState::Stopped
        && status.exit_code == ServiceExitCode::Win32(1069);
    if known_logon_failure && !credential_repair {
        // A generic update must not persist Updating from an unhandled
        // service-logon failure; an explicit password repair is required.
        return Err(Error::CredentialsRequired);
    }
    if credential_repair_marker && !known_logon_failure {
        // A persisted 1069 disposition never substitutes for the current
        // stopped-service observation on a retry.
        return Err(Error::Conflict);
    }
    if record.phase == Phase::Updating
        && credential_repair
        && !credential_repair_marker
        && known_logon_failure
    {
        // Supplying a password does not turn an unrelated interrupted update
        // into a credential-repair transaction.
        return Err(Error::CredentialsRequired);
    }
    let previously_running = if record.phase == Phase::Updating {
        record.resume_after_update
    } else {
        let ready = status_for_record(&record, true)?;
        // SCM Running is published only after Host startup readiness. This
        // elevated updater cannot use the selected account's user-only IPC
        // endpoint, so the retained SCM PID/token/image checks are the
        // authority for preserving the previous running state here.
        ready.running && ready.ready && ready.process_id.is_some()
    };
    if record.phase != Phase::Updating {
        if credential_repair && known_logon_failure {
            // Journal the typed no-start disposition before advancing the
            // registration. Either side of an interrupted two-file update
            // remains recoverable only by matching this exact protected
            // marker plus a fresh SCM 1069 observation.
            save_journal(&record, "image_update_credentials_repair")?;
            record.phase = Phase::Updating;
            record.resume_after_update = false;
            save_registration(&record)?;
            save_journal(&record, "image_update_credentials_repair")?;
        } else {
            record.phase = Phase::Updating;
            record.resume_after_update = previously_running;
            save_journal(&record, "image_update")?;
            save_registration(&record)?;
        }
    }
    if !matches!(
        status.current_state,
        ServiceState::Stopped | ServiceState::StopPending
    ) {
        service.stop().map_err(scm)?;
    }
    if credential_repair && known_logon_failure {
        wait_stopped_for_credential_repair(&service, Instant::now() + WAIT, true)?;
    } else {
        wait_state(&service, ServiceState::Stopped, Instant::now() + WAIT)?;
    }
    Ok(ImageUpdateGuard {
        _lock: lock,
        _image_directory_pins: image_directory_pins,
        record,
        previously_running,
    })
}

pub fn begin_image_update(account: &str) -> Result<ImageUpdateGuard> {
    begin_image_update_inner(account, false, false)
}

/// Begin an image update for an explicit, fresh-credential repair request.
/// The only additional stopped state admitted is SCM's exact Win32 1069
/// logon-failure result on the validated registered service. All other
/// nonzero stop results remain fenced.
pub fn begin_image_update_for_credentials_repair(account: &str) -> Result<ImageUpdateGuard> {
    begin_image_update_inner(account, false, true)
}

/// Explicit updater recovery entry for a persisted `updating` record. It
/// never starts the Host and returns the stored pre-update running decision.
pub fn recover_image_update(account: &str) -> Result<ImageUpdateGuard> {
    begin_image_update_inner(account, true, false)
}

/// Explicit fresh-credential recovery for an update that was durably marked
/// as originating from the exact SCM no-start 1069 result.
pub fn recover_image_update_for_credentials_repair(account: &str) -> Result<ImageUpdateGuard> {
    begin_image_update_inner(account, true, true)
}

/// Called from the SCM dispatcher callback before the Host accepts requests.
/// It verifies the selected-account binding and protected image/configuration;
/// it does not assume QueryServiceStatusEx exposes a PID in StartPending.
pub fn validate_host_dispatch(
    service_name: &str,
    profile: &Path,
    executable: &Path,
) -> Result<Option<AdminHostIdentity>> {
    validate_host_binding(service_name, profile, executable)
        .map(|record| record.and_then(|record| record.host_identity()))
}

/// Strict post-dispatch check for a Host that has reported Running to SCM.
/// Kept separate from dispatcher entry because StartPending PID semantics are
/// not a reliable process-identity witness.
pub fn validate_host_running(service_name: &str, profile: &Path, executable: &Path) -> Result<()> {
    let Some(record) = validate_host_binding(service_name, profile, executable)? else {
        return Ok(());
    };
    let service = status_service(&record, false)?.ok_or(Error::Conflict)?;
    let status = service.query_status().map_err(scm)?;
    if status.current_state != ServiceState::Running
        || status.process_id != Some(unsafe { GetCurrentProcessId() })
    {
        return Err(Error::Conflict);
    }
    process_identity(
        status.process_id.ok_or(Error::Conflict)?,
        &record.account_sid,
        Path::new(&record.executable),
    )
}

fn validate_host_binding(
    service_name: &str,
    profile: &Path,
    executable: &Path,
) -> Result<Option<Registration>> {
    let sid = current_sid().map_err(native)?;
    let mut raw_token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(Error::AccountNotOrdinary);
    }
    let token = Handle::new(raw_token).map_err(|_| Error::AccountNotOrdinary)?;
    if token_has_group(token.0, BUILTIN_ADMINS_SID)? {
        return Err(Error::AccountNotOrdinary);
    }
    let Some(record) = load_registration_for_sid(&sid)? else {
        if service_name == Registration::name_for_sid(&sid) {
            return Err(Error::Conflict);
        }
        // Existing per-user/manual service registrations are handled by their
        // original owner. The SID-derived admin service name never falls back.
        return Ok(None);
    };
    if record.account_sid != sid
        || record.service_name != service_name
        || !record.host_dispatch_allowed()
        || normalized(profile).map_err(native)? != PathBuf::from(&record.profile)
        || normalized(executable).map_err(native)? != PathBuf::from(&record.executable)
    {
        return Err(Error::Conflict);
    }
    verify_recorded_images(&record)?;
    status_service(&record, false)?.ok_or(Error::Conflict)?;
    Ok(Some(record))
}

/// Ordinary current-account service and login adapters call this before
/// claiming the same account's profile. The durable ProgramData record is the
/// conflict witness; malformed present records fail closed.
pub(super) fn is_managed_for_current_sid(owner_sid: &str) -> Result<bool> {
    match load_registration_for_sid(owner_sid) {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(Error::ProtectedImageRequired) => Err(Error::Conflict),
        Err(error) => Err(error),
    }
}

fn initial_record(
    operator_sid: &str,
    identity: &AccountIdentity,
    profile: &Path,
    image: &VerifiedHostServiceImage,
) -> Result<Registration> {
    if image.owner_sid != identity.sid
        || image.canonical_account != identity.canonical
        || image.cli_path.parent() != Some(image.install.as_path())
        || image.helper_path.parent() != Some(image.install.as_path())
    {
        return Err(Error::Conflict);
    }
    let profile = normalized(profile).map_err(native)?;
    let mut record = Registration {
        version: 1,
        operator_sid: operator_sid.to_owned(),
        account_sid: identity.sid.clone(),
        account: identity.canonical.clone(),
        profile: path_text(&profile)?,
        service_name: Registration::name_for_sid(&identity.sid),
        command: String::new(),
        executable: path_text(&image.cli_path)?,
        helper: path_text(&image.helper_path)?,
        cli_sha256: image.cli_sha256.clone(),
        helper_sha256: image.helper_sha256.clone(),
        signer_thumbprint: image.signer_thumbprint.clone(),
        mode: "boot".into(),
        phase: Phase::Intent,
        resume_after_update: false,
        host_id: None,
        profile_id: None,
    };
    record.command = record.command()?;
    record.validate()?;
    Ok(record)
}

/// Reserve first installation while the updater still holds the selected
/// account's HostOwnerLock. This writes the exact protected Intent record but
/// does not create, configure, or start an SCM service; the caller can then
/// release the profile lock before the Host process is launched.
pub fn prepare_install_intent(
    account: &str,
    image: &VerifiedHostServiceImage,
    owner_lock: &HostOwnerLock,
) -> Result<()> {
    require_administrator()?;
    let identity = resolve_account(account)?;
    image.recheck()?;
    if image.owner_sid != identity.sid
        || image.canonical_account != identity.canonical
        || owner_lock.owner_sid != identity.sid
    {
        return Err(Error::Conflict);
    }
    let profile = native_app_profile_path(&identity, false)?;
    if owner_lock.profile_path() != profile {
        return Err(Error::Conflict);
    }
    reject_legacy_manager(&profile)?;
    let _lock = AdminLock::acquire(&identity.sid)?;
    let profile_text = path_text(&profile)?;
    let operator_sid = current_sid().map_err(native)?;
    let mut existing_identity = None;
    if let Some(existing) = load_registration_for_sid(&identity.sid)? {
        if existing.account != identity.canonical
            || existing.account_sid != identity.sid
            || existing.operator_sid != operator_sid
            || existing.profile != profile_text
            || !matches!(existing.phase, Phase::Intent | Phase::CredentialsRequired)
        {
            return Err(Error::Conflict);
        }
        let journal = load_journal_for_sid(&identity.sid)?.ok_or(Error::Conflict)?;
        if !journal_matches_registration(&journal, &existing)
            || !matches!(
                journal.operation.as_str(),
                "install" | "create_service" | "repair_credentials"
            )
        {
            return Err(Error::Conflict);
        }
        if service_object_exists(&existing)? {
            let service = status_service(&existing, false)?.ok_or(Error::Conflict)?;
            if service.query_status().map_err(scm)?.current_state != ServiceState::Stopped {
                return Err(Error::Conflict);
            }
        }
        if same_service_image(&existing, image) && existing.phase == Phase::Intent {
            return Ok(());
        }
        if same_service_image(&existing, image) {
            existing_identity = existing.host_identity();
        }
    } else if service_object_exists_for_sid(&identity.sid)? {
        return Err(Error::Conflict);
    }
    let mut record = initial_record(&operator_sid, &identity, &profile, image)?;
    if let Some(existing) = existing_identity {
        record.host_id = Some(existing.host_id);
        record.profile_id = Some(existing.profile_id);
    }
    save_journal(&record, "install")?;
    save_registration(&record)
}

/// Bind the first-install intent to the exact identity recovered from the
/// selected account's database snapshot. The protected registration is the
/// root-owned identity pin; an existing pin can only be confirmed, never
/// replaced.
pub fn bind_install_intent_identity(
    account: &str,
    image: &VerifiedHostServiceImage,
    owner_lock: &HostOwnerLock,
    host_id: &str,
    profile_id: &str,
) -> Result<()> {
    let identity = parse_host_identity(host_id, profile_id)?;
    require_administrator()?;
    let selected = resolve_account(account)?;
    if image.owner_sid != selected.sid
        || image.canonical_account != selected.canonical
        || owner_lock.owner_sid != selected.sid
        || owner_lock.profile_path() != native_app_profile_path(&selected, false)?
    {
        return Err(Error::Conflict);
    }
    image.recheck()?;
    let _lock = AdminLock::acquire(&selected.sid)?;
    let mut record = load_registration_for_sid(&selected.sid)?.ok_or(Error::Conflict)?;
    let journal = load_journal_for_sid(&selected.sid)?.ok_or(Error::Conflict)?;
    if record.account != selected.canonical
        || record.account_sid != selected.sid
        || record.profile != path_text(owner_lock.profile_path())?
        || record.phase != Phase::Intent
        || !same_service_image(&record, image)
        || !journal.matches(&record)
        || !matches!(
            journal.operation.as_str(),
            "install" | "create_service" | "repair_credentials"
        )
    {
        return Err(Error::Conflict);
    }
    if let Some(existing) = record.host_identity() {
        return if existing == identity {
            Ok(())
        } else {
            Err(Error::Conflict)
        };
    }
    record.host_id = Some(identity.host_id);
    record.profile_id = Some(identity.profile_id);
    record.validate()?;
    save_registration(&record)
}

/// Explicitly pin a legacy credential-repair intent to its existing database
/// identity. This is only available while the exact registered service is
/// stopped and its recorded image/configuration remain valid.
pub fn bind_credential_repair_identity(
    account: &str,
    image: &VerifiedHostServiceImage,
    owner_lock: &HostOwnerLock,
    host_id: &str,
    profile_id: &str,
) -> Result<()> {
    let identity = parse_host_identity(host_id, profile_id)?;
    require_administrator()?;
    let selected = resolve_account(account)?;
    if image.owner_sid != selected.sid
        || image.canonical_account != selected.canonical
        || owner_lock.owner_sid != selected.sid
        || owner_lock.profile_path() != native_app_profile_path(&selected, false)?
    {
        return Err(Error::Conflict);
    }
    image.recheck()?;
    let _lock = AdminLock::acquire(&selected.sid)?;
    let mut record = load_registration_for_sid(&selected.sid)?.ok_or(Error::Conflict)?;
    let journal = load_journal_for_sid(&selected.sid)?.ok_or(Error::Conflict)?;
    if record.account != selected.canonical
        || record.account_sid != selected.sid
        || record.profile != path_text(owner_lock.profile_path())?
        || record.phase != Phase::CredentialsRequired
        || !same_service_image(&record, image)
        || !journal.matches(&record)
        || journal.operation != "repair_credentials"
    {
        return Err(Error::Conflict);
    }
    if let Some(existing) = record.host_identity() {
        return if existing == identity {
            Ok(())
        } else {
            Err(Error::Conflict)
        };
    }
    verify_recorded_images(&record)?;
    let service = status_service(&record, false)?.ok_or(Error::Conflict)?;
    let status = service.query_status().map_err(scm)?;
    if status.current_state != ServiceState::Stopped
        || !matches!(status.exit_code, ServiceExitCode::Win32(0 | 1077 | 1069))
    {
        return Err(Error::Conflict);
    }
    record.host_id = Some(identity.host_id);
    record.profile_id = Some(identity.profile_id);
    record.validate()?;
    save_registration(&record)
}

/// Revalidate a reserved first-install Intent after the selected-account
/// initializer has released its owner lock. This is read-only; it never
/// repairs or rebinds a changed registration.
pub fn verify_install_intent(
    account: &str,
    image: &VerifiedHostServiceImage,
    owner_lock: &HostOwnerLock,
) -> Result<()> {
    require_administrator()?;
    let identity = resolve_account(account)?;
    if image.owner_sid != identity.sid
        || image.canonical_account != identity.canonical
        || owner_lock.owner_sid != identity.sid
    {
        return Err(Error::Conflict);
    }
    let profile = native_app_profile_path(&identity, false)?;
    if owner_lock.profile_path() != profile {
        return Err(Error::Conflict);
    }
    image.recheck()?;
    let _lock = AdminLock::acquire(&identity.sid)?;
    verify_install_intent_record(&identity, &profile, image, true)
}

fn verify_install_intent_record(
    identity: &AccountIdentity,
    profile: &Path,
    image: &VerifiedHostServiceImage,
    require_identity: bool,
) -> Result<()> {
    image.recheck()?;
    let profile_text = path_text(profile)?;
    let record = load_registration_for_sid(&identity.sid)?.ok_or(Error::Conflict)?;
    let journal = load_journal_for_sid(&identity.sid)?.ok_or(Error::Conflict)?;
    if record.account != identity.canonical
        || record.account_sid != identity.sid
        || record.profile != profile_text
        || record.phase != Phase::Intent
        || (require_identity && record.host_identity().is_none())
        || !same_service_image(&record, image)
        || !journal.matches(&record)
        || !matches!(
            journal.operation.as_str(),
            "install" | "create_service" | "repair_credentials"
        )
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Recover only a protected first-install intent while the caller holds the
/// selected profile's owner lease. If CreateServiceW completed before the
/// process stopped, harden its exact stopped intent-bound object so the caller
/// can retry installation with fresh credentials.
pub fn recover_install_intent(
    account: &str,
    owner_lock: &HostOwnerLock,
) -> Result<Option<AdminServiceStatus>> {
    require_administrator()?;
    let identity = resolve_account(account)?;
    let Some(record) = load_registration_for_sid(&identity.sid)? else {
        return Ok(None);
    };
    if record.account != identity.canonical
        || record.account_sid != identity.sid
        || record.phase != Phase::Intent
    {
        return Ok(None);
    }
    let profile = native_app_profile_path(&identity, false)?;
    if owner_lock.owner_sid != identity.sid || owner_lock.profile_path() != profile {
        return Err(Error::Conflict);
    }
    let _lock = AdminLock::acquire(&identity.sid)?;
    let current = load_registration_for_sid(&identity.sid)?.ok_or(Error::Conflict)?;
    let journal = load_journal_for_sid(&identity.sid)?.ok_or(Error::Conflict)?;
    if current != record
        || !journal.matches(&record)
        || !matches!(journal.operation.as_str(), "install" | "create_service")
    {
        return Err(Error::Conflict);
    }
    verify_recorded_images(&record)?;
    if service_object_exists(&record)? {
        if journal.operation == "create_service" {
            harden_intent_service(&record)?;
        } else {
            // The install journal precedes CreateServiceW. A service object
            // already present at this phase cannot be attributed to that
            // operation.
            return Err(Error::Conflict);
        }
    }
    status_for_record(&record, true).map(Some)
}

fn journal_matches_registration(journal: &Journal, record: &Registration) -> bool {
    journal.version == 1
        && journal.operator_sid == record.operator_sid
        && journal.account_sid == record.account_sid
        && journal.account == record.account
        && journal.service_name == record.service_name
        && journal.profile == record.profile
        && journal.command == record.command
        && journal.executable == record.executable
        && journal.helper == record.helper
        && journal.cli_sha256 == record.cli_sha256
        && journal.helper_sha256 == record.helper_sha256
        && journal.signer_thumbprint == record.signer_thumbprint
        && journal.mode == record.mode
        && journal.phase == record.phase
        && journal.resume_after_update == record.resume_after_update
}

fn same_service_image(record: &Registration, image: &VerifiedHostServiceImage) -> bool {
    record.account_sid == image.owner_sid
        && record.account == image.canonical_account
        && image.cli_path.to_str() == Some(record.executable.as_str())
        && image.helper_path.to_str() == Some(record.helper.as_str())
        && record.cli_sha256 == image.cli_sha256
        && record.helper_sha256 == image.helper_sha256
        && record.signer_thumbprint == image.signer_thumbprint
}

fn service_object_exists(record: &Registration) -> Result<bool> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(scm)?;
    match manager.open_service(&record.service_name, ServiceAccess::QUERY_CONFIG) {
        Ok(_) => Ok(true),
        Err(error) if service::missing(&error) => Ok(false),
        Err(error) if service::deleting(&error) => Err(Error::Deadline),
        Err(error) => Err(scm(error)),
    }
}

fn service_object_exists_for_sid(owner_sid: &str) -> Result<bool> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(scm)?;
    match manager.open_service(
        &Registration::name_for_sid(owner_sid),
        ServiceAccess::QUERY_CONFIG,
    ) {
        Ok(_) => Ok(true),
        Err(error) if service::missing(&error) => Ok(false),
        Err(error) if service::deleting(&error) => Err(Error::Deadline),
        Err(error) => Err(scm(error)),
    }
}

fn install_or_repair(
    operation: &str,
    account: &str,
    password: ServicePassword,
    image: Option<&VerifiedHostServiceImage>,
) -> Result<AdminServiceStatus> {
    require_administrator()?;
    let identity = resolve_account(account)?;
    ensure_service_logon_right(&identity.sid)?;
    let profile = profile_path_for_account(&identity.canonical, &identity.sid, Some(&password))?;
    let profile_text = path_text(&profile)?;
    let _lock = AdminLock::acquire(&identity.sid)?;
    let registration = load_registration_for_sid(&identity.sid)?;
    if let Some(image) = image {
        image.recheck()?;
        if image.owner_sid != identity.sid || image.canonical_account != identity.canonical {
            return Err(Error::Conflict);
        }
    }
    let mut record = match registration {
        Some(record) => {
            if record.account != identity.canonical
                || record.profile != profile_text
                || record.phase == Phase::Deleting
            {
                return Err(Error::Conflict);
            }
            if let Some(image) = image
                && !same_service_image(&record, image)
            {
                return Err(Error::Conflict);
            }
            if !matches!(
                record.phase,
                Phase::Intent
                    | Phase::CredentialsRequired
                    | Phase::Configured
                    | Phase::Starting
                    | Phase::Ready
            ) {
                return Err(Error::Conflict);
            }
            record
        }
        None if operation == "install" => return Err(Error::Conflict),
        None => return Err(Error::NotInstalled),
    };
    if image.is_none() {
        verify_recorded_images(&record)?;
    }
    if operation == "install" && record.phase == Phase::Ready {
        return Ok(status_for_record(&record, true)?);
    }
    if operation == "repair-credentials"
        && image.is_some()
        && !same_service_image(&record, image.unwrap())
    {
        return Err(Error::Conflict);
    }
    if !matches!(
        record.phase,
        Phase::Intent
            | Phase::CredentialsRequired
            | Phase::Configured
            | Phase::Starting
            | Phase::Ready
    ) {
        return Err(Error::Conflict);
    }
    if record.host_identity().is_none() {
        return Err(Error::Conflict);
    }

    let existing = match status_service(&record, true) {
        Err(Error::Conflict) if record.phase == Phase::Intent => {
            harden_intent_service(&record)?;
            status_service(&record, true)?
        }
        other => other?,
    };
    if existing.is_some() {
        let service = open_for_control(&record, ServiceAccess::STOP)?;
        let status = service.query_status().map_err(scm)?;
        if status.current_state != ServiceState::Stopped {
            service.stop().map_err(scm)?;
            wait_state(&service, ServiceState::Stopped, Instant::now() + WAIT)?;
        }
    }

    let creating = existing.is_none();
    if creating && record.phase != Phase::Intent {
        return Err(Error::Conflict);
    }
    save_journal(
        &record,
        if creating {
            "create_service"
        } else {
            "repair_credentials"
        },
    )?;
    configure_native_service(&record, &password, creating)?;

    let service = status_service(&record, false)?.ok_or(Error::Conflict)?;
    let queried = service.query_config().map_err(scm)?;
    record
        .service_registration()
        .matches(&queried)
        .map_err(|_| Error::Conflict)?;
    service::recovery(&service).map_err(|_| Error::Conflict)?;
    record.phase = Phase::Configured;
    save_journal(&record, "configured")?;
    save_registration(&record)?;
    start_registered(&record)
}

/// Administrator-managed boot service operations. Install and credential
/// repair require a zeroizing password plus a pinned updater image capability.
/// Status is read-only and can be called by the selected account. That account
/// may also start or stop only its own exact boot service; all configuration,
/// image, credential, and registration mutations remain administrator-only.
pub fn run(
    operation: &str,
    account: &str,
    password: Option<ServicePassword>,
    image: Option<&VerifiedHostServiceImage>,
) -> Result<String> {
    match operation {
        "install" | "repair-credentials" => {
            let password = password.ok_or(Error::CredentialsRequired)?;
            let status = install_or_repair(operation, account, password, image)?;
            Ok(status_summary(&status))
        }
        "status" => {
            let status = inspect(account)?.ok_or(Error::NotInstalled)?;
            Ok(status_summary(&status))
        }
        "start" => {
            let identity = resolve_account(account)?;
            if current_sid().map_err(native)? == identity.sid {
                authorize_owner_control(&identity.sid)?;
                return Ok(status_summary(&run_owner_control("start", &identity)?));
            }
            require_administrator()?;
            let _lock = AdminLock::acquire(&identity.sid)?;
            let record = load_registration_for_sid(&identity.sid)?.ok_or(Error::NotInstalled)?;
            if !matches!(
                record.phase,
                Phase::Configured | Phase::Starting | Phase::Ready
            ) {
                return Err(Error::Conflict);
            }
            Ok(status_summary(&start_registered(&record)?))
        }
        "stop" => {
            let identity = resolve_account(account)?;
            if current_sid().map_err(native)? == identity.sid {
                authorize_owner_control(&identity.sid)?;
                return Ok(status_summary(&run_owner_control("stop", &identity)?));
            }
            require_administrator()?;
            let _lock = AdminLock::acquire(&identity.sid)?;
            let record = load_registration_for_sid(&identity.sid)?.ok_or(Error::NotInstalled)?;
            if matches!(
                record.phase,
                Phase::Intent | Phase::Updating | Phase::Deleting
            ) {
                return Err(Error::Conflict);
            }
            Ok(status_summary(&stop_registered(&record)?))
        }
        "restart" => {
            require_administrator()?;
            let identity = resolve_account(account)?;
            let _lock = AdminLock::acquire(&identity.sid)?;
            let record = load_registration_for_sid(&identity.sid)?.ok_or(Error::NotInstalled)?;
            if !matches!(
                record.phase,
                Phase::Configured | Phase::Starting | Phase::Ready
            ) {
                return Err(Error::Conflict);
            }
            let _ = stop_registered(&record)?;
            Ok(status_summary(&start_registered(&record)?))
        }
        "uninstall" => {
            require_administrator()?;
            let identity = resolve_account(account)?;
            let _lock = AdminLock::acquire(&identity.sid)?;
            uninstall(&identity.sid)
        }
        _ => Err(Error::Invalid),
    }
}

fn status_summary(status: &AdminServiceStatus) -> String {
    format!(
        "Administrator-managed Host service {} (mode={}, phase={}, running={}, ready={}).",
        if status.registered {
            "registered"
        } else {
            "absent"
        },
        status.mode,
        status.phase,
        status.running,
        status.ready
    )
}

fn require_administrator() -> Result<()> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(Error::AdministratorRequired);
    }
    let token = Handle::new(token).map_err(|_| Error::AdministratorRequired)?;
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
        || !token_has_group(token.0, BUILTIN_ADMINS_SID)?
    {
        return Err(Error::AdministratorRequired);
    }
    Ok(())
}

fn token_has_group(token: HANDLE, wanted: &str) -> Result<bool> {
    let mut size = 0u32;
    unsafe { GetTokenInformation(token, TokenGroups, ptr::null_mut(), 0, &mut size) };
    if size == 0 || size > 1024 * 1024 {
        return Err(Error::Conflict);
    }
    let words = (size as usize).div_ceil(mem::size_of::<usize>());
    let mut buffer = vec![0usize; words];
    if unsafe {
        GetTokenInformation(
            token,
            TokenGroups,
            buffer.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    } == 0
    {
        return Err(Error::Conflict);
    }
    let groups = unsafe { &*buffer.as_ptr().cast::<TOKEN_GROUPS>() };
    if groups.GroupCount > 4096 {
        return Err(Error::Conflict);
    }
    for group in
        unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize) }
    {
        if sid_text(group.Sid).map_err(native)? == wanted {
            return Ok(true);
        }
    }
    Ok(false)
}

fn resolve_account(account: &str) -> Result<AccountIdentity> {
    if account.is_empty() || account.len() > 512 || account.chars().any(char::is_control) {
        return Err(Error::Invalid);
    }
    let account_wide = wide(OsStr::new(account));
    let (mut sid_bytes, mut domain_chars, mut kind) = (0u32, 0u32, 0i32);
    unsafe {
        LookupAccountNameW(
            ptr::null(),
            account_wide.as_ptr(),
            ptr::null_mut(),
            &mut sid_bytes,
            ptr::null_mut(),
            &mut domain_chars,
            &mut kind,
        );
    }
    if sid_bytes == 0 || sid_bytes > 4096 || domain_chars > 4096 {
        return Err(Error::AccountNotOrdinary);
    }
    let mut sid_storage = vec![0usize; (sid_bytes as usize).div_ceil(mem::size_of::<usize>())];
    let mut domain = vec![0u16; domain_chars as usize];
    unsafe {
        LookupAccountNameW(
            ptr::null(),
            account_wide.as_ptr(),
            sid_storage.as_mut_ptr().cast(),
            &mut sid_bytes,
            domain.as_mut_ptr(),
            &mut domain_chars,
            &mut kind,
        );
    }
    if kind != SidTypeUser || domain_chars == 0 {
        return Err(Error::AccountNotOrdinary);
    }
    domain.truncate(domain_chars as usize);
    while domain.last() == Some(&0) {
        domain.pop();
    }
    let sid = sid_text(sid_storage.as_mut_ptr().cast()).map_err(native)?;
    let canonical = lookup_account_sid(&sid)?;
    if sid == SYSTEM_SID || sid == "S-1-5-19" || sid == "S-1-5-20" || sid == ADMIN_SID {
        return Err(Error::AccountNotOrdinary);
    }
    Ok(AccountIdentity { sid, canonical })
}

fn lookup_account_sid(sid: &str) -> Result<String> {
    let sid_wide = wide(OsStr::new(sid));
    let mut sid_pointer = ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(sid_wide.as_ptr(), &mut sid_pointer) } == 0
        || sid_pointer.is_null()
    {
        return Err(Error::AccountNotOrdinary);
    }
    let _sid_guard = Local(sid_pointer.cast());
    let mut name_chars = 0u32;
    let mut domain_chars = 0u32;
    let mut kind = 0i32;
    unsafe {
        LookupAccountSidW(
            ptr::null(),
            sid_pointer,
            ptr::null_mut(),
            &mut name_chars,
            ptr::null_mut(),
            &mut domain_chars,
            &mut kind,
        );
    }
    if name_chars == 0 || name_chars > 4096 || domain_chars > 4096 {
        return Err(Error::AccountNotOrdinary);
    }
    let mut name = vec![0u16; name_chars as usize];
    let mut domain = vec![0u16; domain_chars as usize];
    if unsafe {
        LookupAccountSidW(
            ptr::null(),
            sid_pointer,
            name.as_mut_ptr(),
            &mut name_chars,
            domain.as_mut_ptr(),
            &mut domain_chars,
            &mut kind,
        )
    } == 0
    {
        return Err(Error::AccountNotOrdinary);
    }
    name.truncate(name_chars as usize);
    domain.truncate(domain_chars as usize);
    while name.last() == Some(&0) {
        name.pop();
    }
    while domain.last() == Some(&0) {
        domain.pop();
    }
    let user = String::from_utf16(&name).map_err(|_| Error::Invalid)?;
    let domain = String::from_utf16(&domain).map_err(|_| Error::Invalid)?;
    Ok(if domain.is_empty() {
        user
    } else {
        format!("{domain}\\{user}")
    })
}

fn split_logon_name(name: &str) -> Result<(Vec<u16>, Vec<u16>)> {
    if let Some((domain, user)) = name.split_once('\\') {
        if domain.is_empty() || user.is_empty() || user.contains('\\') {
            return Err(Error::Invalid);
        }
        Ok((wide(OsStr::new(user)), wide(OsStr::new(domain))))
    } else if name.contains('@') {
        Ok((wide(OsStr::new(name)), Vec::new()))
    } else {
        Err(Error::Invalid)
    }
}

fn profile_path_for_account(
    canonical_account: &str,
    expected_sid: &str,
    password: Option<&ServicePassword>,
) -> Result<PathBuf> {
    let (username, domain) = split_logon_name(canonical_account)?;
    let Some(password) = password else {
        return registered_profile_path(canonical_account, expected_sid);
    };
    let password_ptr = password.nul_terminated()?;
    let domain_ptr = if domain.is_empty() {
        ptr::null()
    } else {
        domain.as_ptr()
    };
    let mut token = ptr::null_mut();
    if unsafe {
        LogonUserW(
            username.as_ptr(),
            domain_ptr,
            password_ptr,
            LOGON32_LOGON_SERVICE,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
    } == 0
    {
        return Err(Error::CredentialsRequired);
    }
    let token = Handle::new(token).map_err(|_| Error::CredentialsRequired)?;
    let mut user_size = 0u32;
    unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut user_size) };
    if user_size == 0 || user_size > 4096 {
        return Err(Error::AccountNotOrdinary);
    }
    let mut user_buffer = vec![0usize; (user_size as usize).div_ceil(mem::size_of::<usize>())];
    let mut returned = 0u32;
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            user_buffer.as_mut_ptr().cast(),
            user_size,
            &mut returned,
        )
    } == 0
    {
        return Err(Error::AccountNotOrdinary);
    }
    let token_sid = unsafe { sid_text((*user_buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid) }
        .map_err(native)?;
    if token_sid != expected_sid || token_has_group(token.0, BUILTIN_ADMINS_SID)? {
        return Err(Error::AccountNotOrdinary);
    }
    let mut profile_chars = 0u32;
    unsafe { GetUserProfileDirectoryW(token.0, ptr::null_mut(), &mut profile_chars) };
    if profile_chars == 0 || profile_chars > 32768 {
        return Err(Error::AccountNotOrdinary);
    }
    let mut profile = vec![0u16; profile_chars as usize];
    if unsafe { GetUserProfileDirectoryW(token.0, profile.as_mut_ptr(), &mut profile_chars) } == 0 {
        return Err(Error::AccountNotOrdinary);
    }
    profile.truncate(profile_chars as usize);
    while profile.last() == Some(&0) {
        profile.pop();
    }
    let profile_root = normalized(&PathBuf::from(OsString::from_wide(&profile))).map_err(native)?;
    let profile_dir = if profile_root.exists() {
        profile_root
    } else {
        create_user_profile(expected_sid, canonical_account)?
    };
    let profile_dir = normalized(&profile_dir).map_err(native)?;
    service::pin(&profile_dir, expected_sid, false).map_err(|_| Error::AccountNotOrdinary)?;
    Ok(profile_dir.join(".lomiRemote"))
}

fn native_app_profile_path(identity: &AccountIdentity, create_profile: bool) -> Result<PathBuf> {
    let mut root = registered_profile_image_path(&identity.sid)?;
    if root.is_none() && create_profile {
        let username = identity
            .canonical
            .rsplit_once('\\')
            .map(|(_, username)| username)
            .unwrap_or(&identity.canonical);
        let created = create_user_profile(&identity.sid, username)?;
        let created = normalized(&created).map_err(native)?;
        root = registered_profile_image_path(&identity.sid)?;
        if root.as_ref() != Some(&created) {
            return Err(Error::Conflict);
        }
    }
    let root = root.ok_or(Error::NotInstalled)?;
    let profile = normalized(&root.join(".lomiRemote")).map_err(native)?;
    if profile.parent() != Some(root.as_path()) {
        return Err(Error::Conflict);
    }
    Ok(profile)
}

fn registered_profile_image_path(owner_sid: &str) -> Result<Option<PathBuf>> {
    let key = wide(format!(
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{owner_sid}"
    ));
    let value = wide("ProfileImagePath");
    let mut units = vec![0u16; 32768];
    let mut value_type = 0u32;
    let mut bytes = (units.len() * mem::size_of::<u16>()) as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_SUBKEY_WOW6464KEY | RRF_NOEXPAND,
            &mut value_type,
            units.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS
        || !matches!(value_type, REG_SZ | REG_EXPAND_SZ)
        || bytes as usize > units.len() * mem::size_of::<u16>()
        || bytes as usize % mem::size_of::<u16>() != 0
    {
        return Err(Error::Conflict);
    }
    units.truncate(bytes as usize / mem::size_of::<u16>());
    let end = units
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(Error::Conflict)?;
    if units[end + 1..].iter().any(|unit| *unit != 0) {
        return Err(Error::Conflict);
    }
    let raw = String::from_utf16(&units[..end]).map_err(|_| Error::Conflict)?;
    if raw.is_empty() || raw.chars().any(char::is_control) {
        return Err(Error::Conflict);
    }
    let expanded = if value_type == REG_EXPAND_SZ {
        let windows = known_folder_path(&FOLDERID_Windows)?;
        let windows_text = windows.to_str().ok_or(Error::Conflict)?;
        let drive = windows_text.get(..2).ok_or(Error::Conflict)?;
        if !drive.as_bytes().get(0).is_some_and(u8::is_ascii_alphabetic)
            || drive.as_bytes().get(1) != Some(&b':')
        {
            return Err(Error::Conflict);
        }
        let expanded = raw.replace("%SystemDrive%", drive);
        if expanded.contains('%') {
            return Err(Error::Conflict);
        }
        expanded
    } else {
        if raw.contains('%') {
            return Err(Error::Conflict);
        }
        raw
    };
    Ok(Some(normalized(Path::new(&expanded)).map_err(native)?))
}

fn known_folder_path(folder: &windows_sys::core::GUID) -> Result<PathBuf> {
    let mut output = ptr::null_mut();
    let status = unsafe { SHGetKnownFolderPath(folder, 0, ptr::null_mut(), &mut output) };
    if status < 0 || output.is_null() {
        return Err(Error::Conflict);
    }
    unsafe {
        let mut length = 0usize;
        while *output.add(length) != 0 {
            length += 1;
            if length > 32768 {
                CoTaskMemFree(output.cast());
                return Err(Error::Conflict);
            }
        }
        let path = PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(
            output, length,
        )));
        CoTaskMemFree(output.cast());
        normalized(&path).map_err(native)
    }
}

struct ThreadPrivilegeScope {
    token: Handle,
    previous: Vec<TOKEN_PRIVILEGES>,
    impersonating_self: bool,
}

fn revert_thread_impersonation_or_abort() {
    if unsafe { RevertToSelf() } == 0 {
        // Returning to normal code while still impersonating the updater's
        // elevated token would violate this scope's security boundary.
        std::process::abort();
    }
}

impl ThreadPrivilegeScope {
    fn backup_restore() -> Result<Self> {
        let thread = unsafe { GetCurrentThread() };
        let mut existing = ptr::null_mut();
        if unsafe { OpenThreadToken(thread, TOKEN_QUERY, 1, &mut existing) } != 0 {
            unsafe { CloseHandle(existing) };
            return Err(Error::Conflict);
        }
        if unsafe { GetLastError() } != ERROR_NO_TOKEN {
            return Err(Error::AdministratorRequired);
        }
        if unsafe { ImpersonateSelf(SecurityImpersonation) } == 0 {
            return Err(Error::AdministratorRequired);
        }
        let mut raw_token = ptr::null_mut();
        if unsafe {
            OpenThreadToken(
                thread,
                TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                1,
                &mut raw_token,
            )
        } == 0
        {
            revert_thread_impersonation_or_abort();
            return Err(Error::AdministratorRequired);
        }
        let token = match Handle::new(raw_token) {
            Ok(token) => token,
            Err(_) => {
                revert_thread_impersonation_or_abort();
                return Err(Error::AdministratorRequired);
            }
        };
        let mut scope = Self {
            token,
            previous: Vec::with_capacity(2),
            impersonating_self: true,
        };
        for name in ["SeBackupPrivilege", "SeRestorePrivilege"] {
            let privilege = wide(name);
            let mut luid = LUID::default();
            if unsafe { LookupPrivilegeValueW(ptr::null(), privilege.as_ptr(), &mut luid) } == 0 {
                return Err(Error::AdministratorRequired);
            }
            let mut enabled: TOKEN_PRIVILEGES = unsafe { mem::zeroed() };
            enabled.PrivilegeCount = 1;
            enabled.Privileges[0] = LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            };
            let mut previous: TOKEN_PRIVILEGES = unsafe { mem::zeroed() };
            let mut returned = 0u32;
            unsafe { SetLastError(ERROR_SUCCESS) };
            let adjusted = unsafe {
                AdjustTokenPrivileges(
                    scope.token.0,
                    0,
                    &enabled,
                    mem::size_of::<TOKEN_PRIVILEGES>() as u32,
                    &mut previous,
                    &mut returned,
                )
            };
            let adjustment_error = unsafe { GetLastError() };
            if adjusted != 0 {
                scope.previous.push(previous);
            }
            if adjusted == 0 || adjustment_error == ERROR_NOT_ALL_ASSIGNED {
                return Err(Error::AdministratorRequired);
            }
        }
        Ok(scope)
    }

    fn restore_checked(&mut self) -> Result<()> {
        while let Some(previous) = self.previous.pop() {
            unsafe { SetLastError(ERROR_SUCCESS) };
            if unsafe {
                AdjustTokenPrivileges(
                    self.token.0,
                    0,
                    &previous,
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            } == 0
                || unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED
            {
                self.previous.push(previous);
                return Err(Error::AdministratorRequired);
            }
        }
        if self.impersonating_self {
            revert_thread_impersonation_or_abort();
            self.impersonating_self = false;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<()> {
        self.restore_checked()
    }
}

impl Drop for ThreadPrivilegeScope {
    fn drop(&mut self) {
        if self.restore_checked().is_err() {
            std::process::abort();
        }
    }
}

fn acquire_host_owner_lock(
    profile: PathBuf,
    owner_sid: &str,
    create: bool,
) -> Result<HostOwnerLock> {
    let _privileges = ThreadPrivilegeScope::backup_restore()?;
    let directories = pin_host_profile_tree(&profile, owner_sid, create)?;
    let lock_path = profile.join("owner.lock");
    let security =
        super::Security::new(&format!("O:{owner_sid}D:P(A;;FA;;;{owner_sid})")).map_err(native)?;
    let disposition = if create { CREATE_NEW } else { OPEN_EXISTING };
    let mut raw = unsafe {
        CreateFileW(
            wide(&lock_path).as_ptr(),
            FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &security.attributes,
            disposition,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE && create && unsafe { GetLastError() } == ERROR_FILE_EXISTS {
        raw = unsafe {
            CreateFileW(
                wide(&lock_path).as_ptr(),
                FILE_READ_DATA
                    | FILE_WRITE_DATA
                    | FILE_READ_ATTRIBUTES
                    | READ_CONTROL
                    | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            )
        };
    }
    let handle = Handle::new(raw).map_err(|_| Error::Conflict)?;
    let info = information(handle.0).map_err(native)?;
    if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || info.nNumberOfLinks != 1
        || info.nFileSizeHigh != 0
        || info.nFileSizeLow != 0
    {
        return Err(Error::Conflict);
    }
    verify_owner_private_object(handle.0, owner_sid, false)?;
    let mut overlapped = unsafe { mem::zeroed::<OVERLAPPED>() };
    if unsafe {
        LockFileEx(
            handle.0,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    } == 0
    {
        return Err(Error::NotReady);
    }
    let canonical =
        normalized(&profile.canonicalize().map_err(|_| Error::Conflict)?).map_err(native)?;
    if canonical != profile {
        return Err(Error::Conflict);
    }
    _privileges.finish()?;
    let raw = handle.0;
    mem::forget(handle);
    let file = unsafe { File::from_raw_handle(raw.cast()) };
    Ok(HostOwnerLock {
        _file: file,
        _directories: directories,
        profile,
        owner_sid: owner_sid.to_owned(),
    })
}

fn snapshot_host_database(owner_lock: &HostOwnerLock) -> Result<HostDatabaseSnapshot> {
    if owner_lock.owner_sid.is_empty()
        || normalized(&owner_lock.profile).map_err(native)? != owner_lock.profile
    {
        return Err(Error::Conflict);
    }

    // The selected profile is intentionally readable only by its owner. Use
    // backup privilege only while opening and copying these three fixed
    // database components; ThreadPrivilegeScope checks restoration on every
    // success and aborts if restoration cannot be confirmed.
    let privileges = ThreadPrivilegeScope::backup_restore()?;
    let profile_pins = pin_host_profile_tree(&owner_lock.profile, &owner_lock.owner_sid, false)?;
    let profile_directory = Handle::new(unsafe {
        CreateFileW(
            wide(&owner_lock.profile).as_ptr(),
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    })
    .map_err(|_| Error::Conflict)?;
    let profile_info = information(profile_directory.0).map_err(native)?;
    if profile_info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
        != FILE_ATTRIBUTE_DIRECTORY
    {
        return Err(Error::Conflict);
    }
    verify_owner_private_object(profile_directory.0, &owner_lock.owner_sid, true)?;
    let profile_identity = database_identity(profile_directory.0)?;

    let parent = service_directory(&owner_lock.owner_sid)?;
    let parent_pins = pin_admin_tree(&parent, &owner_lock.owner_sid)?;
    let directory = parent.join(format!(".database-schema-{}", Uuid::new_v4()));
    let directory_security =
        super::Security::new("O:BA G:BA D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)").map_err(native)?;
    if unsafe { CreateDirectoryW(wide(&directory).as_ptr(), &directory_security.attributes) } == 0 {
        return Err(Error::Conflict);
    }
    let mut reservation = SnapshotDirectoryReservation {
        path: directory.clone(),
        armed: true,
    };
    let directory_handle = Handle::new(unsafe {
        CreateFileW(
            wide(&directory).as_ptr(),
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    })
    .map_err(|_| Error::Conflict)?;
    let directory_info = information(directory_handle.0).map_err(native)?;
    if directory_info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
        != FILE_ATTRIBUTE_DIRECTORY
    {
        return Err(Error::Conflict);
    }
    verify_admin_only_security(directory_handle.0, true)?;

    let mut sources = Vec::with_capacity(3);
    let mut total = 0u64;
    for name in ["host.sqlite3", "host.sqlite3-journal", "host.sqlite3-wal"] {
        let path = owner_lock.profile.join(name);
        let raw = unsafe {
            CreateFileW(
                wide(&path).as_ptr(),
                FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                FILE_SHARE_READ,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT
                    | FILE_FLAG_SEQUENTIAL_SCAN
                    | FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            let error = unsafe { GetLastError() };
            if matches!(error, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) {
                continue;
            }
            return Err(Error::Conflict);
        }
        let file = unsafe { File::from_raw_handle(raw) };
        let info = information(file.as_raw_handle().cast()).map_err(native)?;
        if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || info.nNumberOfLinks != 1
        {
            return Err(Error::Conflict);
        }
        let identity = database_identity(file.as_raw_handle().cast())?;
        total = total.checked_add(identity.size).ok_or(Error::Conflict)?;
        if total > MAX_HOST_DATABASE_SNAPSHOT {
            return Err(Error::Conflict);
        }
        if name == "host.sqlite3-journal" && identity.size != 0 {
            // A hot rollback journal can carry a super-journal pathname.
            // SQLite recovery may delete that path, so privileged SQLite is
            // never given user-controlled rollback-journal bytes.
            return Err(Error::Conflict);
        }
        verify_owner_private_object(file.as_raw_handle().cast(), &owner_lock.owner_sid, false)?;
        sources.push(DatabaseSource {
            name,
            file,
            identity,
            copy_to_snapshot: name != "host.sqlite3-journal",
        });
    }
    if !sources.is_empty() && sources[0].name != "host.sqlite3" {
        return Err(Error::Conflict);
    }

    let snapshot = HostDatabaseSnapshot {
        directory,
        directory_handle: Some(directory_handle),
        _parent_pins: parent_pins,
        _profile_pins: profile_pins,
        profile_directory,
        profile_identity,
        profile: owner_lock.profile.clone(),
        owner_sid: owner_lock.owner_sid.clone(),
        sources,
    };
    for source in &snapshot.sources {
        copy_database_component(&snapshot.directory, source)?;
    }
    snapshot.verify_sources()?;
    privileges.finish()?;
    reservation.disarm();
    Ok(snapshot)
}

fn copy_database_component(directory: &Path, source: &DatabaseSource) -> Result<()> {
    if !source.copy_to_snapshot {
        return Ok(());
    }
    let destination = directory.join(source.name);
    let security = super::Security::new("O:BA G:BA D:P(A;;FA;;;SY)(A;;FA;;;BA)").map_err(native)?;
    let raw = unsafe {
        CreateFileW(
            wide(&destination).as_ptr(),
            FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ,
            &security.attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    let output_handle = Handle::new(raw).map_err(|_| Error::Conflict)?;
    let output_identity = database_identity(output_handle.0)?;
    if output_identity.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || output_identity.links != 1
    {
        return Err(Error::Conflict);
    }
    verify_admin_only_security(output_handle.0, false)?;
    let raw = output_handle.0;
    mem::forget(output_handle);
    let mut output = unsafe { File::from_raw_handle(raw.cast()) };
    let mut input = source.file.try_clone().map_err(|_| Error::Conflict)?;
    input
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error::Conflict)?;
    let mut copied = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer).map_err(|_| Error::Conflict)?;
        if count == 0 {
            break;
        }
        copied = copied.checked_add(count as u64).ok_or(Error::Conflict)?;
        if copied > source.identity.size || copied > MAX_HOST_DATABASE_SNAPSHOT {
            return Err(Error::Conflict);
        }
        output
            .write_all(&buffer[..count])
            .map_err(|_| Error::Conflict)?;
    }
    if copied != source.identity.size {
        return Err(Error::Conflict);
    }
    output.sync_all().map_err(|_| Error::Conflict)?;
    let info = information(output.as_raw_handle().cast()).map_err(native)?;
    let copied_identity = database_identity(output.as_raw_handle().cast())?;
    if copied_identity.size != copied
        || copied_identity.links != 1
        || info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
    {
        return Err(Error::Conflict);
    }
    verify_admin_only_security(output.as_raw_handle().cast(), false)?;
    Ok(())
}

fn database_identity(handle: HANDLE) -> Result<DatabaseIdentity> {
    let info = information(handle).map_err(native)?;
    Ok(DatabaseIdentity {
        volume: info.dwVolumeSerialNumber,
        file_index: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
        size: ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64,
        links: info.nNumberOfLinks,
        attributes: info.dwFileAttributes,
        creation_time: ((info.ftCreationTime.dwHighDateTime as u64) << 32)
            | info.ftCreationTime.dwLowDateTime as u64,
        write_time: ((info.ftLastWriteTime.dwHighDateTime as u64) << 32)
            | info.ftLastWriteTime.dwLowDateTime as u64,
    })
}

fn pin_host_profile_tree(
    profile: &Path,
    owner_sid: &str,
    create_profile_leaf: bool,
) -> Result<Vec<Handle>> {
    let profile = normalized(profile).map_err(native)?;
    let user_root = profile.parent().ok_or(Error::Conflict)?;
    let mut built = PathBuf::new();
    let mut directories = Vec::new();
    for component in profile.components() {
        built.push(component.as_os_str());
        if matches!(component, std::path::Component::Prefix(_)) {
            continue;
        }
        if built == profile
            && create_profile_leaf
            && !matches!(std::fs::symlink_metadata(&built), Ok(_))
        {
            let security =
                super::Security::new(&format!("O:{owner_sid}D:P(A;OICI;FA;;;{owner_sid})"))
                    .map_err(native)?;
            if unsafe { CreateDirectoryW(wide(&built).as_ptr(), &security.attributes) } == 0
                && unsafe { GetLastError() } != ERROR_ALREADY_EXISTS
            {
                return Err(Error::Conflict);
            }
        }
        let directory = open_host_directory(&built)?;
        if built == profile {
            verify_owner_private_object(directory.0, owner_sid, true)?;
        } else if built == user_root {
            verify_user_profile_root(directory.0, owner_sid)?;
        } else {
            verify_admin_profile_ancestor(directory.0, owner_sid)?;
        }
        directories.push(directory);
    }
    if normalized(&profile.canonicalize().map_err(|_| Error::Conflict)?).map_err(native)? != profile
    {
        return Err(Error::Conflict);
    }
    Ok(directories)
}

fn open_host_directory(path: &Path) -> Result<Handle> {
    let handle = Handle::new(unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    })
    .map_err(|_| Error::Conflict)?;
    let info = information(handle.0).map_err(native)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err(Error::Conflict);
    }
    Ok(handle)
}

fn verify_owner_private_object(handle: HANDLE, owner_sid: &str, directory: bool) -> Result<()> {
    let (owner, acl, descriptor) = security_parts(handle)?;
    if sid_text(owner).map_err(native)? != owner_sid {
        return Err(Error::Conflict);
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
    {
        return Err(Error::Conflict);
    }
    let acl = unsafe { &*acl };
    if acl.AceCount == 0 || acl.AceCount > 32 {
        return Err(Error::Conflict);
    }
    let expected_flags = if directory {
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    } else {
        0
    };
    let mut owner_full = false;
    for index in 0..acl.AceCount {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(acl, index as u32, &mut ace) } == 0 || ace.is_null() {
            return Err(Error::Conflict);
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceType == ACE_DENIED_TYPE {
            continue;
        }
        if header.AceType != ACE_ALLOWED_TYPE {
            return Err(Error::Conflict);
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = sid_text((&allowed.SidStart as *const u32).cast_mut().cast()).map_err(native)?;
        if sid != owner_sid
            || allowed.Mask != FILE_ALL_ACCESS
            || header.AceFlags as u32 & !INHERITED_ACE != expected_flags
        {
            return Err(Error::Conflict);
        }
        owner_full = true;
    }
    if !owner_full {
        return Err(Error::Conflict);
    }
    drop_security_parts(descriptor);
    Ok(())
}

fn verify_user_profile_root(handle: HANDLE, owner_sid: &str) -> Result<()> {
    let (owner, acl, descriptor) = security_parts(handle)?;
    if sid_text(owner).map_err(native)? != owner_sid {
        return Err(Error::Conflict);
    }
    let acl = unsafe { &*acl };
    if acl.AceCount == 0 || acl.AceCount > 512 {
        return Err(Error::Conflict);
    }
    let forbidden = FILE_DELETE_CHILD
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | FILE_WRITE_EA
        | FILE_WRITE_ATTRIBUTES
        | GENERIC_WRITE
        | GENERIC_ALL;
    let mut owner_full = false;
    for index in 0..acl.AceCount {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(acl, index as u32, &mut ace) } == 0 || ace.is_null() {
            return Err(Error::Conflict);
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceFlags as u32 & INHERIT_ONLY_ACE != 0 || header.AceType == ACE_DENIED_TYPE {
            continue;
        }
        if header.AceType != ACE_ALLOWED_TYPE {
            return Err(Error::Conflict);
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = sid_text((&allowed.SidStart as *const u32).cast_mut().cast()).map_err(native)?;
        let mask = file_access_mask(allowed.Mask);
        if sid == owner_sid {
            if mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS {
                owner_full = true;
            }
        } else if !matches!(sid.as_str(), SYSTEM_SID | ADMIN_SID | TRUSTED_INSTALLER_SID)
            && mask & forbidden != 0
        {
            return Err(Error::Conflict);
        }
    }
    drop_security_parts(descriptor);
    if owner_full {
        Ok(())
    } else {
        Err(Error::Conflict)
    }
}

fn verify_admin_profile_ancestor(handle: HANDLE, owner_sid: &str) -> Result<()> {
    let (owner, acl, descriptor) = security_parts(handle)?;
    let owner = sid_text(owner).map_err(native)?;
    if !matches!(
        owner.as_str(),
        SYSTEM_SID | ADMIN_SID | TRUSTED_INSTALLER_SID
    ) {
        return Err(Error::Conflict);
    }
    let acl = unsafe { &*acl };
    if acl.AceCount == 0 || acl.AceCount > 512 {
        return Err(Error::Conflict);
    }
    let forbidden = FILE_DELETE_CHILD
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | FILE_WRITE_EA
        | FILE_WRITE_ATTRIBUTES
        | GENERIC_WRITE
        | GENERIC_ALL;
    for index in 0..acl.AceCount {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(acl, index as u32, &mut ace) } == 0 || ace.is_null() {
            return Err(Error::Conflict);
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceFlags as u32 & INHERIT_ONLY_ACE != 0 || header.AceType == ACE_DENIED_TYPE {
            continue;
        }
        if header.AceType != ACE_ALLOWED_TYPE {
            return Err(Error::Conflict);
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = sid_text((&allowed.SidStart as *const u32).cast_mut().cast()).map_err(native)?;
        if sid != SYSTEM_SID
            && sid != ADMIN_SID
            && sid != TRUSTED_INSTALLER_SID
            && sid != owner_sid
            && file_access_mask(allowed.Mask) & forbidden != 0
        {
            return Err(Error::Conflict);
        }
    }
    drop_security_parts(descriptor);
    Ok(())
}

fn security_parts(handle: HANDLE) -> Result<(PSID, *mut ACL, PSECURITY_DESCRIPTOR)> {
    let mut owner = ptr::null_mut();
    let mut acl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let status = unsafe {
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
    };
    if status != ERROR_SUCCESS || owner.is_null() || acl.is_null() || descriptor.is_null() {
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor.cast()) };
        }
        return Err(Error::Conflict);
    }
    Ok((owner, acl, descriptor))
}

fn drop_security_parts(descriptor: PSECURITY_DESCRIPTOR) {
    if !descriptor.is_null() {
        unsafe { LocalFree(descriptor.cast()) };
    }
}

fn registered_profile_path(canonical_account: &str, expected_sid: &str) -> Result<PathBuf> {
    let record = load_registration_for_sid(expected_sid)?;
    if let Some(record) = record {
        if record.account != canonical_account || record.account_sid != expected_sid {
            return Err(Error::Conflict);
        }
        return Ok(PathBuf::from(record.profile));
    }
    Err(Error::NotInstalled)
}

fn create_user_profile(sid: &str, account: &str) -> Result<PathBuf> {
    let username = account
        .rsplit_once('\\')
        .map(|(_, user)| user)
        .unwrap_or(account);
    let sid_wide = wide(OsStr::new(sid));
    let username_wide = wide(OsStr::new(username));
    let chars = 32768u32;
    let mut path = vec![0u16; chars as usize];
    let result = unsafe {
        CreateProfile(
            sid_wide.as_ptr(),
            username_wide.as_ptr(),
            path.as_mut_ptr(),
            chars,
        )
    };
    if result < 0 {
        return Err(Error::AccountNotOrdinary);
    }
    let length = path.iter().position(|u| *u == 0).ok_or(Error::Invalid)?;
    Ok(PathBuf::from(OsString::from_wide(&path[..length])))
}

fn program_data_root() -> Result<PathBuf> {
    let mut output = ptr::null_mut();
    let hr =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, ptr::null_mut(), &mut output) };
    if hr < 0 || output.is_null() {
        return Err(Error::ProtectedImageRequired);
    }
    let path = unsafe {
        let mut length = 0usize;
        while *output.add(length) != 0 {
            length += 1;
            if length > 32768 {
                CoTaskMemFree(output.cast());
                return Err(Error::ProtectedImageRequired);
            }
        }
        let result = PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(
            output, length,
        )));
        CoTaskMemFree(output.cast());
        result
    };
    normalized(&path).map_err(native)
}

fn validate_hex_digest(value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Invalid);
    }
    Ok(())
}

fn canonical_thumbprint(value: &str) -> Result<String> {
    let value = value.replace(' ', "").to_ascii_uppercase();
    if value.len() != 40 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Invalid);
    }
    Ok(value)
}

fn image_identity(handle: HANDLE) -> Result<ImageIdentity> {
    let info = information(handle).map_err(native)?;
    Ok(ImageIdentity {
        volume: info.dwVolumeSerialNumber,
        file_index: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
        size: ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64,
        links: info.nNumberOfLinks,
        attributes: info.dwFileAttributes,
        write_time: ((info.ftLastWriteTime.dwHighDateTime as u64) << 32)
            | info.ftLastWriteTime.dwLowDateTime as u64,
    })
}

fn hash_file(file: &File) -> Result<String> {
    let mut file = file
        .try_clone()
        .map_err(|_| Error::ProtectedImageRequired)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| Error::ProtectedImageRequired)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| Error::ProtectedImageRequired)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(Error::ProtectedImageRequired)?;
        if total > MAX_IMAGE {
            return Err(Error::ProtectedImageRequired);
        }
        hash.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| Error::ProtectedImageRequired)?;
    Ok(format!("{:x}", hash.finalize()))
}

/// Verify the exact canonical Windows image and its Authenticode signer.
/// This is used by the same-account maintenance handoff to stage only the
/// already-running signed CLI. It accepts no caller-selected trust material.
pub fn verify_authenticode_image(
    path: &Path,
    expected_thumbprint: &str,
) -> std::result::Result<(), Error> {
    let canonical = path
        .canonicalize()
        .map_err(|_| Error::ProtectedImageRequired)?;
    let canonical = normalized(&canonical).map_err(native)?;
    if canonical != path {
        return Err(Error::ProtectedImageRequired);
    }
    let raw = unsafe {
        CreateFileW(
            wide(canonical.as_os_str()).as_ptr(),
            GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(Error::ProtectedImageRequired);
    }
    let file = unsafe { File::from_raw_handle(raw) };
    let before = image_identity(file.as_raw_handle().cast())?;
    if before.links != 1
        || before.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || before.size == 0
        || before.size > MAX_IMAGE
    {
        return Err(Error::ProtectedImageRequired);
    }
    let digest = hash_file(&file)?;
    verify_authenticode(&file, &canonical, expected_thumbprint)?;
    if image_identity(file.as_raw_handle().cast())? != before || hash_file(&file)? != digest {
        return Err(Error::ProtectedImageRequired);
    }
    Ok(())
}

fn verify_authenticode(file: &File, path: &Path, expected_thumbprint: &str) -> Result<()> {
    let wide_path = wide(path.as_os_str());
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide_path.as_ptr(),
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
    let close_status = unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    if status != ERROR_SUCCESS as i32 || close_status != ERROR_SUCCESS as i32 {
        return Err(Error::ProtectedImageRequired);
    }

    // WinVerifyTrust validates the Authenticode chain; CryptQueryObject then
    // identifies the actual embedded signer so the updater's independent
    // release thumbprint is enforced as well.
    let mut encoding = 0u32;
    let mut content = 0u32;
    let mut format = 0u32;
    let mut store = ptr::null_mut();
    let mut message = ptr::null_mut();
    let mut context = ptr::null_mut();
    if unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide_path.as_ptr().cast(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            &mut encoding,
            &mut content,
            &mut format,
            &mut store,
            &mut message,
            &mut context,
        )
    } == 0
        || message.is_null()
        || store.is_null()
    {
        return Err(Error::ProtectedImageRequired);
    }
    let signer_result = (|| {
        let mut size = 0u32;
        if unsafe {
            CryptMsgGetParam(
                message,
                CMSG_SIGNER_INFO_PARAM,
                0,
                ptr::null_mut(),
                &mut size,
            )
        } == 0
            || size == 0
            || size > 64 * 1024
        {
            return Err(Error::ProtectedImageRequired);
        }
        let mut words = vec![0usize; (size as usize).div_ceil(mem::size_of::<usize>())];
        if unsafe {
            CryptMsgGetParam(
                message,
                CMSG_SIGNER_INFO_PARAM,
                0,
                words.as_mut_ptr().cast(),
                &mut size,
            )
        } == 0
        {
            return Err(Error::ProtectedImageRequired);
        }
        let signer: CMSG_SIGNER_INFO = unsafe { ptr::read_unaligned(words.as_ptr().cast()) };
        let mut certificate_info = CERT_INFO::default();
        certificate_info.Issuer = signer.Issuer;
        certificate_info.SerialNumber = signer.SerialNumber;
        let certificate = unsafe {
            CertFindCertificateInStore(
                store,
                encoding,
                0,
                CERT_FIND_SUBJECT_CERT,
                (&certificate_info as *const CERT_INFO).cast(),
                ptr::null(),
            )
        };
        if certificate.is_null() {
            return Err(Error::ProtectedImageRequired);
        }
        let mut hash = [0u8; 20];
        let mut hash_bytes = hash.len() as u32;
        let got_hash = unsafe {
            CertGetCertificateContextProperty(
                certificate,
                CERT_SHA1_HASH_PROP_ID,
                hash.as_mut_ptr().cast(),
                &mut hash_bytes,
            )
        } != 0;
        unsafe { CertFreeCertificateContext(certificate) };
        if !got_hash || hash_bytes as usize != hash.len() {
            return Err(Error::ProtectedImageRequired);
        }
        let actual = hash
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>();
        if actual != expected_thumbprint {
            return Err(Error::ProtectedImageRequired);
        }
        Ok(())
    })();
    unsafe {
        CryptMsgClose(message);
        CertCloseStore(store, 0);
    }
    signer_result
}

fn admin_image_acl(owner_sid: &str, directory: bool) -> String {
    if directory {
        format!("O:BA G:BA D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;{owner_sid})")
    } else {
        format!("O:BA G:BA D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;{owner_sid})")
    }
}

fn verify_admin_image_directory(path: &Path, owner_sid: &str, exact: bool) -> Result<()> {
    let handle = open_path(path, false, false, true, owner_sid).map_err(native)?;
    verify_admin_image_security(handle.0, owner_sid, true)?;
    if exact
        && normalized(
            &path
                .canonicalize()
                .map_err(|_| Error::ProtectedImageRequired)?,
        )
        .map_err(native)?
            != path
    {
        return Err(Error::ProtectedImageRequired);
    }
    Ok(())
}

fn verify_admin_image_security(handle: HANDLE, owner_sid: &str, directory: bool) -> Result<()> {
    verify_protected_security(
        handle,
        owner_sid,
        directory,
        Some(GENERIC_READ | GENERIC_EXECUTE),
        directory,
    )
}

fn verify_public_registration_security(handle: HANDLE, owner_sid: &str) -> Result<()> {
    verify_protected_security(handle, owner_sid, false, Some(GENERIC_READ), false)
}

fn verify_admin_only_security(handle: HANDLE, directory: bool) -> Result<()> {
    verify_protected_security(handle, "", directory, None, directory)
}

/// The shared job root stays private to SYSTEM and Administrators for listing
/// and mutation. Each registered owner receives only a noninheriting traverse
/// and metadata grant so its exact SID directory can open its protected job
/// record. This lets the owner process reach its capsule without exposing the
/// shared directory contents or sibling owner namespaces.
fn verify_maintenance_jobs_root_security(
    handle: HANDLE,
    required_owner: Option<&str>,
) -> Result<()> {
    let (owner, dacl, descriptor) = security_parts(handle)?;
    let result = (|| {
        let owner = sid_text(owner).map_err(native)?;
        if !matches!(
            owner.as_str(),
            SYSTEM_SID | ADMIN_SID | TRUSTED_INSTALLER_SID
        ) {
            return Err(Error::ProtectedImageRequired);
        }
        let mut control = 0u16;
        let mut revision = 0u32;
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
            || control & SE_DACL_PROTECTED == 0
        {
            return Err(Error::ProtectedImageRequired);
        }
        let acl = unsafe { &*dacl };
        if acl.AceCount < 2 || acl.AceCount > 4096 {
            return Err(Error::ProtectedImageRequired);
        }
        let mut system_full = false;
        let mut admins_full = false;
        let mut owner_sids = std::collections::HashSet::new();
        for index in 0..acl.AceCount {
            let mut ace = ptr::null_mut();
            if unsafe { GetAce(dacl, index as u32, &mut ace) } == 0 || ace.is_null() {
                return Err(Error::ProtectedImageRequired);
            }
            let header = unsafe { &*ace.cast::<ACE_HEADER>() };
            if header.AceType != ACE_ALLOWED_TYPE {
                return Err(Error::ProtectedImageRequired);
            }
            let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            let sid =
                sid_text((&allowed.SidStart as *const u32).cast_mut().cast()).map_err(native)?;
            let mask = file_access_mask(allowed.Mask);
            match sid.as_str() {
                SYSTEM_SID => {
                    if mask != FILE_ALL_ACCESS
                        || header.AceFlags as u32 != (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
                        || system_full
                    {
                        return Err(Error::ProtectedImageRequired);
                    }
                    system_full = true;
                }
                ADMIN_SID => {
                    if mask != FILE_ALL_ACCESS
                        || header.AceFlags as u32 != (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
                        || admins_full
                    {
                        return Err(Error::ProtectedImageRequired);
                    }
                    admins_full = true;
                }
                _ => {
                    if !valid_sid_text(&sid)
                        || mask != MAINTENANCE_ROOT_OWNER_ACCESS
                        || header.AceFlags != 0
                        || !owner_sids.insert(sid)
                    {
                        return Err(Error::ProtectedImageRequired);
                    }
                }
            }
        }
        if !system_full
            || !admins_full
            || required_owner.is_some_and(|sid| !owner_sids.contains(sid))
        {
            return Err(Error::ProtectedImageRequired);
        }
        Ok(())
    })();
    drop_security_parts(descriptor);
    result
}

fn ensure_maintenance_root_owner_traverse(
    handle: HANDLE,
    owner_sid: &str,
    root: &Path,
) -> Result<()> {
    let _acl_lock = lock_maintenance_root_acl(root)?;
    verify_maintenance_jobs_root_security(handle, None)?;
    if verify_maintenance_jobs_root_security(handle, Some(owner_sid)).is_ok() {
        return Ok(());
    }

    let mut sid_wide: Vec<u16> = owner_sid.encode_utf16().chain(Some(0)).collect();
    let mut sid = ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(sid_wide.as_mut_ptr(), &mut sid) } == 0 || sid.is_null() {
        return Err(Error::ProtectedImageRequired);
    }
    let _sid = Local(sid.cast());
    let (_, old_acl, descriptor) = security_parts(handle)?;
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: MAINTENANCE_ROOT_OWNER_ACCESS,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: 0,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: sid.cast(),
        },
    };
    let mut new_acl = ptr::null_mut();
    let acl_status = unsafe { SetEntriesInAclW(1, &entry, old_acl, &mut new_acl) };
    if acl_status != ERROR_SUCCESS || new_acl.is_null() {
        drop_security_parts(descriptor);
        return Err(Error::ProtectedImageRequired);
    }
    let set_status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            new_acl,
            ptr::null_mut(),
        )
    };
    unsafe { LocalFree(new_acl.cast()) };
    drop_security_parts(descriptor);
    if set_status != ERROR_SUCCESS {
        return Err(Error::ProtectedImageRequired);
    }
    verify_maintenance_jobs_root_security(handle, Some(owner_sid))
}

fn lock_maintenance_root_acl(root: &Path) -> Result<Handle> {
    let path = root.join(MAINTENANCE_ROOT_ACL_LOCK);
    let security = super::Security::new("O:BA G:BA D:P(A;;FA;;;SY)(A;;FA;;;BA)").map_err(native)?;
    let deadline = Instant::now() + WAIT;
    loop {
        let raw = unsafe {
            CreateFileW(
                wide(&path).as_ptr(),
                GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                0,
                &security.attributes,
                OPEN_ALWAYS,
                FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if raw != INVALID_HANDLE_VALUE {
            let handle = Handle::new(raw).map_err(|_| Error::ProtectedImageRequired)?;
            let info = information(handle.0).map_err(native)?;
            if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
                != 0
                || info.nNumberOfLinks != 1
            {
                return Err(Error::ProtectedImageRequired);
            }
            verify_admin_only_security(handle.0, false)?;
            return Ok(handle);
        }
        let error = unsafe { GetLastError() };
        if error != ERROR_SHARING_VIOLATION || Instant::now() >= deadline {
            return Err(Error::ProtectedImageRequired);
        }
        thread::sleep(POLL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

fn open_maintenance_root_for_acl(root: &Path) -> Result<Handle> {
    let security =
        super::Security::new("O:BA G:BA D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)").map_err(native)?;
    let handle = Handle::new(unsafe {
        CreateFileW(
            wide(root).as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &security.attributes,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    })
    .map_err(|_| Error::ProtectedImageRequired)?;
    let info = information(handle.0).map_err(native)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err(Error::ProtectedImageRequired);
    }
    Ok(handle)
}

fn valid_sid_text(sid: &str) -> bool {
    let mut fields = sid.split('-');
    fields.next() == Some("S")
        && fields
            .next()
            .is_some_and(|revision| revision.parse::<u8>().is_ok())
        && fields
            .next()
            .is_some_and(|authority| authority.parse::<u64>().is_ok())
        && fields
            .next()
            .is_some_and(|first| first.parse::<u32>().is_ok())
        && fields.all(|field| !field.is_empty() && field.parse::<u32>().is_ok())
}

fn verify_service_owner(service: &Service) -> Result<()> {
    use windows_sys::Win32::Security::Authorization::SE_SERVICE;
    let mut owner = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            service.raw_handle(),
            SE_SERVICE,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || owner.is_null() || descriptor.is_null() {
        return Err(Error::Conflict);
    }
    let _descriptor = Local(descriptor.cast());
    let owner = sid_text(owner).map_err(native)?;
    if owner == ADMIN_SID || owner == SYSTEM_SID {
        Ok(())
    } else {
        Err(Error::Conflict)
    }
}

fn verify_service_security(
    service: &Service,
    account_sid: &str,
    require_owner_control: bool,
) -> Result<()> {
    use windows_sys::Win32::Security::Authorization::SE_SERVICE;
    let mut owner = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            service.raw_handle(),
            SE_SERVICE,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || owner.is_null() || dacl.is_null() || descriptor.is_null() {
        return Err(Error::Conflict);
    }
    let _descriptor = Local(descriptor.cast());
    let owner = sid_text(owner).map_err(native)?;
    if owner != ADMIN_SID && owner != SYSTEM_SID {
        return Err(Error::Conflict);
    }
    let acl = unsafe { &*dacl };
    if acl.AceCount == 0 || acl.AceCount > 16 {
        return Err(Error::Conflict);
    }
    let query_rights = service_query_rights();
    let owner_control_rights = query_rights | SERVICE_START | SERVICE_STOP;
    let mut target_control_ace = false;
    for index in 0..acl.AceCount {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(dacl, index as u32, &mut ace) } == 0 || ace.is_null() {
            return Err(Error::Conflict);
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceType != ACE_ALLOWED_TYPE || header.AceFlags != 0 {
            return Err(Error::Conflict);
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = sid_text((&allowed.SidStart as *const u32).cast_mut().cast()).map_err(native)?;
        if sid == account_sid {
            let valid_mask = if require_owner_control {
                allowed.Mask == owner_control_rights
            } else {
                allowed.Mask == query_rights || allowed.Mask == owner_control_rights
            };
            if !valid_mask || target_control_ace {
                return Err(Error::Conflict);
            }
            target_control_ace = true;
        } else if sid == SYSTEM_SID || sid == ADMIN_SID {
            if allowed.Mask != GENERIC_ALL && allowed.Mask != SERVICE_ALL_ACCESS {
                return Err(Error::Conflict);
            }
        } else {
            return Err(Error::Conflict);
        }
    }
    if !target_control_ace {
        return Err(Error::Conflict);
    }
    Ok(())
}

const fn service_query_rights() -> u32 {
    SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL
}

fn verify_protected_security(
    handle: HANDLE,
    target_sid: &str,
    _directory: bool,
    target_access: Option<u32>,
    require_protected_dacl: bool,
) -> Result<()> {
    let mut owner = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_null() || owner.is_null() || dacl.is_null() {
        return Err(Error::ProtectedImageRequired);
    }
    let _descriptor = Local(descriptor.cast());
    let owner_text = sid_text(owner).map_err(native)?;
    if !matches!(
        owner_text.as_str(),
        SYSTEM_SID | ADMIN_SID | TRUSTED_INSTALLER_SID
    ) {
        return Err(Error::ProtectedImageRequired);
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || (require_protected_dacl && control & SE_DACL_PROTECTED == 0)
    {
        return Err(Error::ProtectedImageRequired);
    }
    let acl = unsafe { &*dacl };
    if acl.AceCount == 0 || acl.AceCount > 256 {
        return Err(Error::ProtectedImageRequired);
    }
    let write_mask = FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | FILE_WRITE_EA
        | FILE_WRITE_ATTRIBUTES
        | FILE_DELETE_CHILD
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | GENERIC_WRITE
        | GENERIC_ALL;
    let mut target_read = false;
    for index in 0..acl.AceCount {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(dacl, index as u32, &mut ace) } == 0 || ace.is_null() {
            return Err(Error::ProtectedImageRequired);
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        let sid = match header.AceType {
            ACE_ALLOWED_TYPE => unsafe {
                sid_text(
                    (&(*ace.cast::<ACCESS_ALLOWED_ACE>()).SidStart as *const u32)
                        .cast_mut()
                        .cast(),
                )
            },
            ACE_DENIED_TYPE => unsafe {
                sid_text(
                    (&(*ace.cast::<ACCESS_DENIED_ACE>()).SidStart as *const u32)
                        .cast_mut()
                        .cast(),
                )
            },
            _ => return Err(Error::ProtectedImageRequired),
        }
        .map_err(native)?;
        if sid != target_sid
            && sid != SYSTEM_SID
            && sid != ADMIN_SID
            && sid != TRUSTED_INSTALLER_SID
            && sid != ""
        {
            return Err(Error::ProtectedImageRequired);
        }
        if header.AceType == ACE_ALLOWED_TYPE {
            let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            let access_mask = file_access_mask(allowed.Mask);
            if sid == target_sid && target_access.is_some() {
                if access_mask & write_mask != 0 {
                    return Err(Error::ProtectedImageRequired);
                }
                let required =
                    file_access_mask(target_access.ok_or(Error::ProtectedImageRequired)?);
                if access_mask & required == required {
                    target_read = true;
                }
            } else if access_mask & write_mask != 0
                && !matches!(sid.as_str(), SYSTEM_SID | ADMIN_SID | TRUSTED_INSTALLER_SID)
            {
                return Err(Error::ProtectedImageRequired);
            }
        }
    }
    if target_access.is_some() && !target_read {
        return Err(Error::ProtectedImageRequired);
    }
    Ok(())
}

fn file_access_mask(mut mask: u32) -> u32 {
    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ,
        GenericWrite: FILE_GENERIC_WRITE,
        GenericExecute: FILE_GENERIC_EXECUTE,
        GenericAll: FILE_ALL_ACCESS,
    };
    unsafe { MapGenericMask(&mut mask, &mapping) };
    mask
}

fn service_directory(owner_sid: &str) -> Result<PathBuf> {
    Ok(program_data_root()?
        .join("LomiRemote")
        .join("HostServices")
        .join(owner_sid))
}

pub(super) fn maintenance_storage_for_admin(owner_sid: &str) -> Result<MaintenanceStorage> {
    require_administrator()?;
    let record = load_registration_for_sid(owner_sid)?.ok_or(Error::NotInstalled)?;
    if record.account_sid != owner_sid || record.mode != "boot" {
        return Err(Error::Conflict);
    }
    maintenance_storage(owner_sid, true)
}

/// Open an existing protected job namespace for a worker whose exact path is
/// checked against the durable job record. This status-only route remains
/// available after uninstall removes the Boot registration; callers must
/// still authorize the record's recorded operator or owner.
pub(super) fn maintenance_storage_for_job_status(owner_sid: &str) -> Result<MaintenanceStorage> {
    require_administrator()?;
    maintenance_storage(owner_sid, false)
}

pub(super) fn maintenance_storage_for_owner(owner_sid: &str) -> Result<MaintenanceStorage> {
    if current_sid().map_err(native)? != owner_sid {
        return Err(Error::Conflict);
    }
    maintenance_storage(owner_sid, false)
}

fn maintenance_storage(owner_sid: &str, create: bool) -> Result<MaintenanceStorage> {
    if owner_sid.is_empty()
        || owner_sid.len() > 184
        || !owner_sid
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'S' | b'-'))
    {
        return Err(Error::Invalid);
    }
    let base = program_data_root()?.join("LomiRemote");
    let base = normalized(&base).map_err(native)?;
    let base_pins = pin_admin_tree(&base, owner_sid)?;
    let root = base.join(MAINTENANCE_JOBS);
    if create {
        let security = super::Security::new("O:BA G:BA D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
            .map_err(native)?;
        let created = unsafe { CreateDirectoryW(wide(&root).as_ptr(), &security.attributes) };
        if created == 0 && unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
            return Err(Error::ProtectedImageRequired);
        }
    }
    let root = normalized(&root).map_err(native)?;
    let root_pins = pin_admin_tree(&root, owner_sid)?;
    let root_handle = if create {
        open_maintenance_root_for_acl(&root)?
    } else {
        open_path(&root, false, false, true, owner_sid).map_err(native)?
    };
    if create {
        ensure_maintenance_root_owner_traverse(root_handle.0, owner_sid, &root)?;
    } else {
        verify_maintenance_jobs_root_security(root_handle.0, Some(owner_sid))?;
    }
    drop(root_handle);
    let owner = root.join(owner_sid);
    if create {
        let security =
            super::Security::new(&admin_record_acl(owner_sid, false, true)).map_err(native)?;
        let created = unsafe { CreateDirectoryW(wide(&owner).as_ptr(), &security.attributes) };
        if created == 0 && unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
            return Err(Error::ProtectedImageRequired);
        }
    }
    let owner = normalized(&owner).map_err(native)?;
    let owner_pins = pin_admin_tree(&owner, owner_sid)?;
    let owner_handle = open_path(&owner, false, false, true, owner_sid).map_err(native)?;
    verify_protected_security(owner_handle.0, owner_sid, true, Some(GENERIC_EXECUTE), true)?;
    if normalized(
        &owner
            .canonicalize()
            .map_err(|_| Error::ProtectedImageRequired)?,
    )
    .map_err(native)?
        != owner
    {
        return Err(Error::ProtectedImageRequired);
    }
    drop(owner_handle);
    Ok(MaintenanceStorage {
        path: owner,
        owner_sid: owner_sid.to_owned(),
        _pins: vec![base_pins, root_pins, owner_pins],
    })
}

pub(super) fn verify_maintenance_file_security(
    handle: HANDLE,
    owner_sid: &str,
    owner_read: bool,
) -> Result<()> {
    if owner_read {
        verify_public_registration_security(handle, owner_sid)
    } else {
        verify_admin_only_security(handle, false)
    }
}

fn pin_admin_tree(path: &Path, target_sid: &str) -> Result<AdminDirectoryPins> {
    let path = normalized(path).map_err(native)?;
    let mut built = PathBuf::new();
    let mut directories = Vec::new();
    for component in path.components() {
        built.push(component.as_os_str());
        if matches!(component, std::path::Component::Prefix(_)) {
            continue;
        }
        let handle = open_path(&built, false, false, true, target_sid).map_err(native)?;
        verify_admin_ancestor_security(handle.0)?;
        directories.push(handle);
    }
    if normalized(
        &path
            .canonicalize()
            .map_err(|_| Error::ProtectedImageRequired)?,
    )
    .map_err(native)?
        != path
    {
        return Err(Error::ProtectedImageRequired);
    }
    Ok(AdminDirectoryPins {
        _directories: directories,
    })
}

fn verify_admin_ancestor_security(handle: HANDLE) -> Result<()> {
    let mut owner = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || owner.is_null() || dacl.is_null() || descriptor.is_null() {
        return Err(Error::ProtectedImageRequired);
    }
    let _descriptor = Local(descriptor.cast());
    let owner = sid_text(owner).map_err(native)?;
    if !matches!(
        owner.as_str(),
        SYSTEM_SID | ADMIN_SID | TRUSTED_INSTALLER_SID
    ) {
        return Err(Error::ProtectedImageRequired);
    }
    let acl = unsafe { &*dacl };
    if acl.AceCount == 0 || acl.AceCount > 512 {
        return Err(Error::ProtectedImageRequired);
    }
    let replace_existing_child = FILE_DELETE_CHILD
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | FILE_WRITE_EA
        | FILE_WRITE_ATTRIBUTES
        | GENERIC_WRITE
        | GENERIC_ALL;
    for index in 0..acl.AceCount {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(dacl, index as u32, &mut ace) } == 0 || ace.is_null() {
            return Err(Error::ProtectedImageRequired);
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceFlags as u32 & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        if header.AceType == ACE_DENIED_TYPE {
            continue;
        }
        if header.AceType != ACE_ALLOWED_TYPE {
            return Err(Error::ProtectedImageRequired);
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = sid_text((&allowed.SidStart as *const u32).cast_mut().cast()).map_err(native)?;
        let mask = file_access_mask(allowed.Mask);
        if !matches!(sid.as_str(), SYSTEM_SID | ADMIN_SID | TRUSTED_INSTALLER_SID)
            && mask & replace_existing_child != 0
        {
            return Err(Error::ProtectedImageRequired);
        }
    }
    Ok(())
}

fn verify_store_directory(path: &Path, owner_sid: &str) -> Result<AdminDirectoryPins> {
    let pins = pin_admin_tree(path, owner_sid)?;
    let handle = open_path(path, false, false, true, owner_sid).map_err(native)?;
    verify_protected_security(handle.0, owner_sid, true, Some(GENERIC_EXECUTE), true)?;
    if normalized(
        &path
            .canonicalize()
            .map_err(|_| Error::ProtectedImageRequired)?,
    )
    .map_err(native)?
        != path
    {
        return Err(Error::ProtectedImageRequired);
    }
    Ok(pins)
}

fn registration_path(owner_sid: &str) -> Result<PathBuf> {
    Ok(service_directory(owner_sid)?.join(REGISTRATION))
}

fn journal_path(owner_sid: &str) -> Result<PathBuf> {
    Ok(service_directory(owner_sid)?.join(JOURNAL))
}

impl AdminLock {
    fn acquire(owner_sid: &str) -> Result<Self> {
        let directory = service_directory(owner_sid)?;
        let directory_pins = verify_store_directory(&directory, owner_sid)?;
        let path = directory.join(MANAGEMENT_LOCK);
        let sd = super::Security::new(&management_lock_acl(owner_sid)).map_err(native)?;
        let raw = unsafe {
            CreateFileW(
                wide(&path).as_ptr(),
                GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC,
                0,
                &sd.attributes,
                OPEN_ALWAYS,
                FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(if unsafe { GetLastError() } == ERROR_SHARING_VIOLATION {
                Error::Conflict
            } else {
                Error::ProtectedImageRequired
            });
        }
        let lock = Handle::new(raw).map_err(|_| Error::Conflict)?;
        let info = information(lock.0).map_err(native)?;
        if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || info.nNumberOfLinks != 1
            || info.nFileSizeHigh != 0
            || info.nFileSizeLow != 0
        {
            return Err(Error::ProtectedImageRequired);
        }
        verify_management_lock_security(lock.0, owner_sid, false)?;
        set_management_lock_dacl(lock.0, sd.attributes.lpSecurityDescriptor.cast())?;
        verify_management_lock_security(lock.0, owner_sid, true)?;
        Ok(Self {
            _handle: lock,
            _directory_pins: directory_pins,
        })
    }
}

fn management_lock_acl(owner_sid: &str) -> String {
    format!("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;{owner_sid})")
}

fn set_management_lock_dacl(
    handle: HANDLE,
    descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
) -> Result<()> {
    let mut present = 0;
    let mut dacl = ptr::null_mut();
    let mut defaulted = 0;
    if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
        == 0
        || present == 0
        || dacl.is_null()
    {
        return Err(Error::ProtectedImageRequired);
    }
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(Error::ProtectedImageRequired);
    }
    Ok(())
}

fn verify_management_lock_security(
    handle: HANDLE,
    owner_sid: &str,
    require_owner_read: bool,
) -> Result<()> {
    let (owner, dacl, descriptor) = security_parts(handle)?;
    let result = (|| {
        if sid_text(owner).map_err(native)? != ADMIN_SID {
            return Err(Error::ProtectedImageRequired);
        }
        let mut control = 0u16;
        let mut revision = 0u32;
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
            || control & SE_DACL_PROTECTED == 0
        {
            return Err(Error::ProtectedImageRequired);
        }
        let acl = unsafe { &*dacl };
        if (require_owner_read && acl.AceCount != 3)
            || (!require_owner_read && !matches!(acl.AceCount, 2 | 3))
        {
            return Err(Error::ProtectedImageRequired);
        }
        let mut system = false;
        let mut admins = false;
        let mut owner_read = false;
        for index in 0..acl.AceCount {
            let mut ace = ptr::null_mut();
            if unsafe { GetAce(dacl, index as u32, &mut ace) } == 0 || ace.is_null() {
                return Err(Error::ProtectedImageRequired);
            }
            let header = unsafe { &*ace.cast::<ACE_HEADER>() };
            if header.AceType != ACE_ALLOWED_TYPE || header.AceFlags != 0 {
                return Err(Error::ProtectedImageRequired);
            }
            let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            let sid =
                sid_text((&allowed.SidStart as *const u32).cast_mut().cast()).map_err(native)?;
            match sid.as_str() {
                SYSTEM_SID | ADMIN_SID
                    if allowed.Mask == GENERIC_ALL
                        || file_access_mask(allowed.Mask) == FILE_ALL_ACCESS =>
                {
                    let slot = if sid == SYSTEM_SID {
                        &mut system
                    } else {
                        &mut admins
                    };
                    if *slot {
                        return Err(Error::ProtectedImageRequired);
                    }
                    *slot = true;
                }
                sid if sid == owner_sid
                    && (allowed.Mask == GENERIC_READ
                        || file_access_mask(allowed.Mask) == FILE_GENERIC_READ) =>
                {
                    if owner_read {
                        return Err(Error::ProtectedImageRequired);
                    }
                    owner_read = true;
                }
                _ => return Err(Error::ProtectedImageRequired),
            }
        }
        if !system || !admins || (require_owner_read && !owner_read) {
            return Err(Error::ProtectedImageRequired);
        }
        Ok(())
    })();
    drop_security_parts(descriptor);
    result
}

fn read_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    owner_sid: &str,
    public: bool,
) -> Result<Option<T>> {
    let sd = super::Security::new(&admin_record_acl(owner_sid, public, false)).map_err(native)?;
    let raw = unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            GENERIC_READ | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            &sd.attributes,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return match unsafe { GetLastError() } {
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(None),
            _ => Err(Error::Conflict),
        };
    }
    let file = unsafe { File::from_raw_handle(raw) };
    let info = image_identity(file.as_raw_handle().cast())?;
    if info.links != 1
        || info.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || info.size > MAX_RECORD
    {
        return Err(Error::Conflict);
    }
    if public {
        verify_public_registration_security(file.as_raw_handle().cast(), owner_sid)?;
    } else {
        verify_admin_only_security(file.as_raw_handle().cast(), false)?;
    }
    let mut bytes = Vec::with_capacity(info.size as usize);
    file.take(MAX_RECORD + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Conflict)?;
    if bytes.len() as u64 > MAX_RECORD {
        return Err(Error::Conflict);
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| Error::Conflict)
}

fn admin_record_acl(owner_sid: &str, public: bool, directory: bool) -> String {
    if directory {
        format!("O:BA G:BA D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;GX;;;{owner_sid})")
    } else if public {
        format!("O:BA G:BA D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;{owner_sid})")
    } else {
        "O:BA G:BA D:P(A;;FA;;;SY)(A;;FA;;;BA)".to_owned()
    }
}

fn write_json<T: Serialize>(path: &Path, owner_sid: &str, public: bool, value: &T) -> Result<()> {
    let parent = path.parent().ok_or(Error::Invalid)?;
    let _pins = verify_store_directory(parent, owner_sid)?;
    let old = read_json::<serde_json::Value>(path, owner_sid, public)?;
    let _ = old;
    let temporary = parent.join(format!(".service-admin-{}.tmp", Uuid::new_v4()));
    let sd = super::Security::new(&admin_record_acl(owner_sid, public, false)).map_err(native)?;
    let raw = unsafe {
        CreateFileW(
            wide(&temporary).as_ptr(),
            GENERIC_WRITE | READ_CONTROL,
            0,
            &sd.attributes,
            CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(Error::Conflict);
    }
    let mut file = unsafe { File::from_raw_handle(raw) };
    let bytes = serde_json::to_vec(value).map_err(|_| Error::Invalid)?;
    if bytes.len() as u64 > MAX_RECORD {
        return Err(Error::Invalid);
    }
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| Error::Deadline)?;
    let staged_identity = image_identity(file.as_raw_handle().cast())?;
    if staged_identity.links != 1
        || staged_identity.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
            != 0
    {
        return Err(Error::Conflict);
    }
    if public {
        verify_public_registration_security(file.as_raw_handle().cast(), owner_sid)?;
    } else {
        verify_admin_only_security(file.as_raw_handle().cast(), false)?;
    }
    drop(file);
    if normalized(&parent.canonicalize().map_err(|_| Error::Conflict)?).map_err(native)? != parent {
        return Err(Error::Conflict);
    }
    let mut flags = MOVEFILE_WRITE_THROUGH;
    if path.exists() {
        flags |= MOVEFILE_REPLACE_EXISTING;
    }
    if unsafe { MoveFileExW(wide(&temporary).as_ptr(), wide(path).as_ptr(), flags) } == 0 {
        return Err(Error::Deadline);
    }
    Ok(())
}

fn load_registration_for_sid(owner_sid: &str) -> Result<Option<Registration>> {
    let path = registration_path(owner_sid)?;
    let Some(record): Option<Registration> = read_json(&path, owner_sid, true)? else {
        return Ok(None);
    };
    record.validate()?;
    Ok(Some(record))
}

fn load_journal_for_sid(owner_sid: &str) -> Result<Option<Journal>> {
    let path = journal_path(owner_sid)?;
    let Some(journal): Option<Journal> = read_json(&path, owner_sid, false)? else {
        return Ok(None);
    };
    if journal.version != 1
        || Uuid::parse_str(&journal.operation_id)
            .map(|id| id.to_string() != journal.operation_id)
            .unwrap_or(true)
        || !matches!(
            journal.operation.as_str(),
            "install"
                | "create_service"
                | "repair_credentials"
                | "configured"
                | "start"
                | "image_update"
                | "image_update_credentials_repair"
                | "image_update_complete"
                | "uninstall"
        )
    {
        return Err(Error::Conflict);
    }
    Ok(Some(journal))
}

fn save_registration(record: &Registration) -> Result<()> {
    record.validate()?;
    write_json(
        &registration_path(&record.account_sid)?,
        &record.account_sid,
        true,
        record,
    )
}

fn save_journal(record: &Registration, operation: &str) -> Result<()> {
    let journal = Journal {
        version: 1,
        operation_id: Uuid::new_v4().to_string(),
        operation: operation.to_owned(),
        phase: record.phase,
        operator_sid: record.operator_sid.clone(),
        account_sid: record.account_sid.clone(),
        account: record.account.clone(),
        service_name: record.service_name.clone(),
        profile: record.profile.clone(),
        command: record.command.clone(),
        executable: record.executable.clone(),
        helper: record.helper.clone(),
        cli_sha256: record.cli_sha256.clone(),
        helper_sha256: record.helper_sha256.clone(),
        signer_thumbprint: record.signer_thumbprint.clone(),
        mode: record.mode.clone(),
        resume_after_update: record.resume_after_update,
    };
    write_json(
        &journal_path(&record.account_sid)?,
        &record.account_sid,
        false,
        &journal,
    )
}

/// A credential-repair image update may be retried after a crash only when
/// the protected journal records that the transition began from SCM's exact
/// no-start Win32 1069 state. The registration can be one durable write
/// ahead of the journal during a crash, so accept only that same operation
/// with every binding field intact and the journal phase either the prior
/// dispatchable phase or Updating.
fn credential_repair_journal_matches(record: &Registration) -> Result<bool> {
    let Some(journal) = load_journal_for_sid(&record.account_sid)? else {
        return Ok(false);
    };
    if journal.operation != "image_update_credentials_repair"
        || !matches!(
            journal.phase,
            Phase::Configured | Phase::Starting | Phase::Ready | Phase::Updating
        )
        || !matches!(
            record.phase,
            Phase::Configured | Phase::Starting | Phase::Ready | Phase::Updating
        )
    {
        return Ok(false);
    }
    let transition_pair = record.phase == Phase::Updating
        && matches!(
            journal.phase,
            Phase::Configured | Phase::Starting | Phase::Ready
        );
    if (journal.phase != record.phase && !transition_pair)
        || (journal.phase == record.phase
            && journal.resume_after_update != record.resume_after_update)
        || (transition_pair && record.resume_after_update)
    {
        return Ok(false);
    }
    Ok(journal.version == 1
        && Uuid::parse_str(&journal.operation_id).is_ok()
        && journal.operator_sid == record.operator_sid
        && journal.account_sid == record.account_sid
        && journal.account == record.account
        && journal.service_name == record.service_name
        && journal.profile == record.profile
        && journal.command == record.command
        && journal.executable == record.executable
        && journal.helper == record.helper
        && journal.cli_sha256 == record.cli_sha256
        && journal.helper_sha256 == record.helper_sha256
        && journal.signer_thumbprint == record.signer_thumbprint
        && journal.mode == record.mode)
}
