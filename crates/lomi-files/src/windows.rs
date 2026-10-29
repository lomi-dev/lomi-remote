//! Handle-relative Explorer engine for Windows.
//!
//! Every component is opened with `NtCreateFile` relative to the handle of its
//! parent directory, with `FILE_OPEN_REPARSE_POINT`, so a symbolic link,
//! junction or any other reparse point is opened as itself and never
//! traversed. The recorded file identity (volume serial + 128-bit file id) of
//! every ancestor is re-validated on each call. Names are refused when they
//! could address something other than one entry of one directory: path
//! separators, alternate data streams (`:`), wildcard and control characters,
//! trailing dots or spaces, DOS device names and the 8.3 alias of `.git`.
//!
//! NTFS timestamps tick far more coarsely than the clock they are stamped
//! from, so two quick mutations can leave a directory's timestamps equal. A
//! per-entry generation, bumped by every mutation made through this engine,
//! is therefore part of every revision token.

use crate::common::{classify, is_private_staging_name, mint};
use crate::types::*;
use crate::{
    GitFilePrecondition, GitFinalTarget, GitPublication, GitPublishOutcome, GitPullFile,
    GitPullNodeKind, GitPullPrecondition, GitPullPublication, GitWorktreePrecondition,
};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::c_void;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::FileExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle, RawHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_DISPOSITION_DELETE,
    FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_INFORMATION,
    FILE_DISPOSITION_INFORMATION_EX, FILE_DISPOSITION_POSIX_SEMANTICS, FILE_NON_DIRECTORY_FILE,
    FILE_OPEN, FILE_OPEN_NO_RECALL, FILE_OPEN_REPARSE_POINT, FILE_RENAME_REPLACE_IF_EXISTS,
    FILE_SYNCHRONOUS_IO_NONALERT, FileDispositionInformation, FileDispositionInformationEx,
    FileNamesInformation, FileRenameInformation, FileRenameInformationEx, NtCreateFile,
    NtQueryDirectoryFile, NtQueryEaFile, NtSetEaFile, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_NO_TOKEN, ERROR_NOT_ALL_ASSIGNED, GetLastError,
    INVALID_HANDLE_VALUE, LocalFree, SetLastError, UNICODE_STRING,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSidToSidW, GetSecurityInfo, SE_FILE_OBJECT,
    SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACL, ATTRIBUTE_SECURITY_INFORMATION, AdjustTokenPrivileges, DACL_SECURITY_INFORMATION,
    DuplicateTokenEx, GROUP_SECURITY_INFORMATION, GetLengthSid, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, GetSecurityDescriptorSacl, GetTokenInformation,
    InitializeSecurityDescriptor, LABEL_SECURITY_INFORMATION, LUID_AND_ATTRIBUTES,
    LookupPrivilegeValueW, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PROTECTED_SACL_SECURITY_INFORMATION, SACL_SECURITY_INFORMATION, SCOPE_SECURITY_INFORMATION,
    SE_DACL_PROTECTED, SE_PRIVILEGE_ENABLED, SE_SACL_PROTECTED, SE_SECURITY_NAME,
    SECURITY_DESCRIPTOR, SecurityAnonymous, SecurityDelegation, SecurityIdentification,
    SecurityImpersonation, SetSecurityDescriptorControl, SetSecurityDescriptorDacl,
    SetSecurityDescriptorOwner, TOKEN_ADJUST_PRIVILEGES, TOKEN_DUPLICATE, TOKEN_IMPERSONATE,
    TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER, TokenImpersonation, TokenImpersonationLevel,
    TokenUser, UNPROTECTED_DACL_SECURITY_INFORMATION, UNPROTECTED_SACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, DELETE, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DEVICE,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_TEMPORARY, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_OVERLAPPED, FILE_ID_INFO, FILE_LIST_DIRECTORY,
    FILE_NOTIFY_CHANGE_ATTRIBUTES, FILE_NOTIFY_CHANGE_CREATION, FILE_NOTIFY_CHANGE_DIR_NAME,
    FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SIZE,
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_STREAM_INFO, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
    FILE_WRITE_EA, FileBasicInfo, FileIdInfo, FileStreamInfo, FlushFileBuffers,
    GetFileInformationByHandle, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
    OPEN_EXISTING, READ_CONTROL, ReadDirectoryChangesW, SYNCHRONIZE, SetFileInformationByHandle,
    WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::IO::{
    CancelIoEx, GetOverlappedResult, IO_STATUS_BLOCK, OVERLAPPED,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken, SetThreadToken,
};

#[path = "windows/desktop_git.rs"]
pub(crate) mod desktop_git;
#[path = "windows/desktop_git_symlink.rs"]
pub(crate) mod desktop_git_symlink;
#[path = "windows/owner_git.rs"]
pub(crate) mod owner_git;
#[path = "windows/security_broker.rs"]
mod security_broker;
pub use security_broker::{
    BrokerSymlinkTemp, BrokerTemp, SecurityBrokerClient, SecurityBrokerError, SecurityBrokerResult,
    SourceSnapshot, TempToken, run_security_broker,
};
#[path = "windows/desktop.rs"]
pub(super) mod desktop;

const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;

const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const SHARE_READ_WRITE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;
const SYNC: u32 = FILE_SYNCHRONOUS_IO_NONALERT;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

const STATUS_NO_MORE_FILES: i32 = 0x8000_0006u32 as i32;
const STATUS_NO_SUCH_FILE: i32 = 0xC000_000Fu32 as i32;
const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;
const STATUS_INVALID_INFO_CLASS: i32 = 0xC000_0003u32 as i32;
const STATUS_NOT_SUPPORTED: i32 = 0xC000_00BBu32 as i32;
const STATUS_BUFFER_OVERFLOW: i32 = 0x8000_0005u32 as i32;
const STATUS_NO_EAS_ON_FILE: i32 = 0xC000_0052u32 as i32;
const MAX_GIT_EA_BYTES: usize = 256 * 1024;
const WATCH_BUFFER_SIZE: usize = 16 * 1024;
const ERROR_IO_PENDING: i32 = 997;
const ERROR_IO_INCOMPLETE: i32 = 996;
const ERROR_NOTIFY_ENUM_DIR: i32 = 1022;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct Ident {
    volume: u64,
    id: u128,
}

/// What one open handle reports about its entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Info {
    ident: Ident,
    attributes: u32,
    size: u64,
    nlink: u32,
    last_write: i64,
    change: i64,
}

/// Audit policy either came from a privileged local handle or was captured by
/// the LocalSystem broker. Broker tokens are operation-scoped and deliberately
/// kept outside this value so equality compares policy, never authority.
#[derive(Clone, Debug, PartialEq, Eq)]
enum AuditSacl {
    Direct {
        present: bool,
        sacl: Option<Vec<u8>>,
        protected: bool,
    },
    Broker([u8; 32]),
}

/// Security data queried and applied through held file handles. Audit SACL
/// access requires ACCESS_SYSTEM_SECURITY locally or a broker digest.
#[derive(Clone, Debug, PartialEq, Eq)]
struct NativeFileSecurity {
    owner: Vec<u8>,
    group: Vec<u8>,
    dacl: Option<Vec<u8>>,
    dacl_present: bool,
    dacl_protected: bool,
    label: Option<Vec<u8>>,
    resource_attributes: Option<Vec<u8>>,
    scope: Option<Vec<u8>>,
    audit_sacl: AuditSacl,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GitFileSecurity {
    attributes: u32,
    extended: NativeFileSecurity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EaRecord {
    flags: u8,
    name: Vec<u8>,
    value: Vec<u8>,
}

/// Metadata captured from one selected regular file or symlink opened without
/// following its leaf. The source's reparse bytes are retained for rechecks,
/// but never copied to a restored destination.
#[derive(Clone, Debug, PartialEq, Eq)]
struct GitLeafSecurity {
    info: Info,
    kind: GitPullNodeKind,
    extended: NativeFileSecurity,
    eas: Vec<EaRecord>,
    reparse: Option<Vec<u8>>,
}

/// Holds the optional broker source record and an ordinary no-follow source
/// handle until the replacement has passed its final local recheck.
struct CapturedGitLeafSecurity {
    security: GitLeafSecurity,
    broker_source: Option<BrokerSourceCapture>,
    _file: File,
}

struct NativeSecurityDescriptor(*mut c_void);

impl Drop for NativeSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

fn native_no_check_read_error<E>(
    error: LocalNativeFileReadError<std::convert::Infallible>,
) -> LocalNativeFileReadError<E> {
    match error {
        LocalNativeFileReadError::File(error) => LocalNativeFileReadError::File(error),
        LocalNativeFileReadError::Check(never) => match never {},
    }
}

struct Node {
    parent: Option<EntryRef>,
    name: Vec<u8>,
    ident: Ident,
}

struct PullCreatedDir {
    parent: OwnedHandle,
    identity: Ident,
    child: OwnedHandle,
}

/// Owner-private sibling directory used to keep a Git replacement's copied
/// security descriptor out of a shared project or metadata directory until
/// the one-leaf rename publishes it.
struct GitPrivateStageDirectory {
    parent: OwnedHandle,
    parent_identity: Ident,
    name: Vec<u16>,
    identity: Ident,
    owner: Vec<u8>,
    directory: Option<OwnedHandle>,
}

impl GitPrivateStageDirectory {
    fn create(parent: &OwnedHandle) -> Result<Self> {
        let parent_info = info_of(parent.as_raw_handle())?;
        if kind_of(&parent_info) != Kind::Directory
            || parent_info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(Error::Changed);
        }
        let parent = parent.try_clone().map_err(map_os)?;
        let owner_text = current_process_user_sid().map_err(git_native_security_error)?;
        let owner_text = owner_text
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut owner_sid = null_mut();
        if unsafe { ConvertStringSidToSidW(owner_text.as_ptr(), &mut owner_sid) } == 0
            || owner_sid.is_null()
        {
            return Err(Error::Unsupported);
        }
        let owner_sid = NativeSid(owner_sid);
        let owner_len = unsafe { GetLengthSid(owner_sid.0) } as usize;
        if owner_len == 0 || owner_len > 64 * 1024 {
            return Err(Error::Unsupported);
        }
        let owner = unsafe { std::slice::from_raw_parts(owner_sid.0.cast::<u8>(), owner_len) };
        let dacl = native_owner_only_dacl(owner).map_err(git_native_security_error)?;

        for _ in 0..100 {
            let name_text = format!("lomi-temp-{}.tmp", uuid::Uuid::new_v4());
            let name = name_text.encode_utf16().collect::<Vec<_>>();
            let stage_parent = parent.try_clone().map_err(map_os)?;
            let mut descriptor: SECURITY_DESCRIPTOR = unsafe { zeroed() };
            if unsafe {
                InitializeSecurityDescriptor(
                    (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                    SECURITY_DESCRIPTOR_REVISION,
                )
            } == 0
                || unsafe {
                    SetSecurityDescriptorOwner(
                        (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                        owner_sid.0,
                        0,
                    )
                } == 0
                || unsafe {
                    SetSecurityDescriptorDacl(
                        (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                        1,
                        dacl.as_ptr().cast::<ACL>(),
                        0,
                    )
                } == 0
                || unsafe {
                    SetSecurityDescriptorControl(
                        (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                        SE_DACL_PROTECTED,
                        SE_DACL_PROTECTED,
                    )
                } == 0
            {
                return Err(Error::Unsupported);
            }
            let directory = match open_relative_with_security_and_share(
                parent.as_raw_handle(),
                &name,
                GIT_DIRECTORY_ACCESS | READ_CONTROL,
                FILE_CREATE,
                FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | SYNC,
                FILE_ATTRIBUTE_HIDDEN,
                SHARE_READ_WRITE,
                false,
                (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
            ) {
                Ok(directory) => directory,
                Err(Error::Exists) => continue,
                Err(error) => return Err(error),
            };
            let info = info_of(directory.as_raw_handle())?;
            let stage = Self {
                parent: stage_parent,
                parent_identity: parent_info.ident,
                name,
                identity: info.ident,
                owner: owner.to_vec(),
                directory: Some(directory),
            };
            if kind_of(&info) != Kind::Directory
                || info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || !read_dir_names(stage.handle()?.as_raw_handle())?.is_empty()
            {
                return Err(Error::Changed);
            }
            verify_native_private_stage_directory(stage.handle()?.as_raw_handle(), owner)?;
            if info_of(stage.parent.as_raw_handle())?.ident != parent_info.ident {
                return Err(Error::Changed);
            }
            return Ok(stage);
        }
        Err(Error::Limit)
    }

    fn handle(&self) -> Result<&OwnedHandle> {
        self.directory.as_ref().ok_or(Error::Changed)
    }

    fn remove_empty(&mut self) -> Result<()> {
        if let Some(directory) = self.directory.as_ref() {
            let info = info_of(directory.as_raw_handle())?;
            if info.ident != self.identity
                || kind_of(&info) != Kind::Directory
                || !read_dir_names(directory.as_raw_handle())?.is_empty()
            {
                return Err(Error::Changed);
            }
        }
        let _ = self.directory.take();
        let parent_info = info_of(self.parent.as_raw_handle())?;
        if parent_info.ident != self.parent_identity || kind_of(&parent_info) != Kind::Directory {
            return Err(Error::Changed);
        }
        let directory = open_relative_with_share(
            self.parent.as_raw_handle(),
            &self.name,
            DELETE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | SYNC,
            0,
            SHARE_READ_WRITE,
            false,
        )?;
        let info = info_of(directory.as_raw_handle())?;
        if info.ident != self.identity
            || kind_of(&info) != Kind::Directory
            || info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || !read_dir_names(directory.as_raw_handle())?.is_empty()
        {
            return Err(Error::Changed);
        }
        verify_native_private_stage_directory(directory.as_raw_handle(), &self.owner)?;
        delete_entry(directory.as_raw_handle())?;
        sync_git_directory(self.parent.as_raw_handle())?;
        Ok(())
    }
}

impl Drop for GitPrivateStageDirectory {
    fn drop(&mut self) {
        let _ = self.remove_empty();
    }
}

struct NativeSid(*mut c_void);

impl Drop for NativeSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

struct StagedPullFile {
    source: GitPullFile,
    target_parent: OwnedHandle,
    target_parent_identity: Ident,
    target_name: Vec<u16>,
    temp_name: Option<Vec<u16>>,
    temp_identity: Option<Ident>,
    temp_handle: Option<OwnedHandle>,
    temp_file: Option<File>,
    broker_temp: Option<NativeFileTemporary>,
    source_security: Option<GitFileSecurity>,
    published_security: Option<GitFileSecurity>,
}

struct GitPublishedGuard {
    base: EntryRef,
    parent_suffix: Vec<Vec<u8>>,
    parent_identities: Vec<Ident>,
    target_name: Vec<u8>,
    file_identity: Ident,
    revision: String,
    content_digest: [u8; 32],
    content_len: usize,
    security: GitFileSecurity,
    file: File,
}

/// One short-lived authenticated broker connection shared only by captures
/// and temps in a single publisher operation.
#[derive(Clone)]
struct BrokerSession(Arc<Mutex<SecurityBrokerClient>>);

impl BrokerSession {
    fn connect() -> NativeResult<Self, LocalNativeFileError> {
        let sid = current_process_user_sid()?;
        let client = SecurityBrokerClient::connect(&sid).map_err(local_broker_error)?;
        Ok(Self(Arc::new(Mutex::new(client))))
    }

    fn capture_source(&self, source: &File) -> NativeResult<SourceSnapshot, LocalNativeFileError> {
        self.0
            .lock()
            .map_err(|_| LocalNativeFileError::Limit)?
            .capture_source(source)
            .map_err(local_broker_error)
    }

    fn capture_source_pinned(
        &self,
        source: &File,
    ) -> NativeResult<SourceSnapshot, LocalNativeFileError> {
        self.0
            .lock()
            .map_err(|_| LocalNativeFileError::Limit)?
            .capture_source_pinned(source)
            .map_err(local_broker_error)
    }

    fn recheck_source(
        &self,
        source: &SourceSnapshot,
    ) -> NativeResult<[u8; 32], LocalNativeFileError> {
        self.0
            .lock()
            .map_err(|_| LocalNativeFileError::Limit)?
            .recheck_source(source)
            .map_err(local_broker_error)
    }

    fn finalize_temp_security(
        &self,
        source: &SourceSnapshot,
        temp: &TempToken,
    ) -> NativeResult<(), LocalNativeFileError> {
        self.0
            .lock()
            .map_err(|_| LocalNativeFileError::Limit)?
            .finalize_temp_security(source, temp)
            .map_err(local_broker_error)
    }

    fn create_temp(
        &self,
        parent: &OwnedHandle,
        name: &str,
    ) -> NativeResult<(OwnedHandle, TempToken, String), LocalNativeFileError> {
        let parent_file = duplicate_handle_as_file(parent.as_raw_handle())?;
        let temp = self
            .0
            .lock()
            .map_err(|_| LocalNativeFileError::Limit)?
            .create_temp(&parent_file, name)
            .map_err(local_broker_error)?;
        let (file, token) = temp.into_parts();
        let handle = unsafe { OwnedHandle::from_raw_handle(file.into_raw_handle()) };
        Ok((handle, token, name.to_owned()))
    }

    fn create_symlink_temp(
        &self,
        parent: &OwnedHandle,
        name: &str,
        substitute: &[u16],
        print: &[u16],
        relative: bool,
        directory: bool,
    ) -> NativeResult<BrokerSymlinkTemp, LocalNativeFileError> {
        let parent_file = duplicate_handle_as_file(parent.as_raw_handle())?;
        self.0
            .lock()
            .map_err(|_| LocalNativeFileError::Limit)?
            .create_symlink_temp(&parent_file, name, substitute, print, relative, directory)
            .map_err(local_broker_error)
    }

    fn release_source(&self, source: &SourceSnapshot) {
        if let Ok(mut client) = self.0.lock() {
            let _ = client.release_source(source);
        }
    }

    fn try_release_temp(&self, temp: &TempToken) -> NativeResult<(), LocalNativeFileError> {
        self.0
            .lock()
            .map_err(|_| LocalNativeFileError::Limit)?
            .release_temp(temp)
            .map_err(local_broker_error)
    }

    fn finalize_published_temp(
        &self,
        temp: &TempToken,
        published: &File,
    ) -> NativeResult<(), LocalNativeFileError> {
        self.0
            .lock()
            .map_err(|_| LocalNativeFileError::Limit)?
            .finalize_published_temp(temp, published)
            .map_err(local_broker_error)
    }

    fn discard_temp(&self, temp: &TempToken) {
        if let Ok(mut client) = self.0.lock() {
            let _ = client.discard_temp(temp);
        }
    }
}

struct BrokerSourceCapture {
    session: BrokerSession,
    source: Option<SourceSnapshot>,
    _file: File,
}

impl BrokerSourceCapture {
    fn digest(&self) -> NativeResult<[u8; 32], LocalNativeFileError> {
        self.source
            .as_ref()
            .map(SourceSnapshot::digest)
            .ok_or(LocalNativeFileError::Changed)
    }

    fn recheck(&self) -> NativeResult<(), LocalNativeFileError> {
        let source = self.source.as_ref().ok_or(LocalNativeFileError::Changed)?;
        if self.session.recheck_source(source)? != source.digest() {
            return Err(LocalNativeFileError::Changed);
        }
        Ok(())
    }

    fn finalize(&self, temp: &TempToken) -> NativeResult<(), LocalNativeFileError> {
        self.recheck()?;
        self.session.finalize_temp_security(
            self.source.as_ref().ok_or(LocalNativeFileError::Changed)?,
            temp,
        )
    }

    fn release(&mut self) {
        if let Some(source) = self.source.take() {
            self.session.release_source(&source);
        }
    }
}

impl Drop for BrokerSourceCapture {
    fn drop(&mut self) {
        self.release();
    }
}

struct CapturedNativeSecurity {
    security: NativeFileSecurity,
    broker_source: Option<BrokerSourceCapture>,
}

thread_local! {
    static ACTIVE_SECURITY_BROKER: RefCell<Option<BrokerSession>> = const { RefCell::new(None) };
}

struct BrokerOperationScope(Option<BrokerSession>);

impl BrokerOperationScope {
    fn enter() -> Self {
        Self(ACTIVE_SECURITY_BROKER.with(|active| active.borrow_mut().take()))
    }
}

impl Drop for BrokerOperationScope {
    fn drop(&mut self) {
        let previous = self.0.take();
        ACTIVE_SECURITY_BROKER.with(|active| *active.borrow_mut() = previous);
    }
}

fn active_broker_session() -> Option<BrokerSession> {
    ACTIVE_SECURITY_BROKER.with(|active| active.borrow().clone())
}

fn operation_broker_session() -> NativeResult<BrokerSession, LocalNativeFileError> {
    if let Some(session) = active_broker_session() {
        return Ok(session);
    }
    let session = BrokerSession::connect()?;
    ACTIVE_SECURITY_BROKER.with(|active| *active.borrow_mut() = Some(session.clone()));
    Ok(session)
}

type NativeResult<T, E> = std::result::Result<T, E>;

#[derive(Default)]
struct Registry {
    nodes: HashMap<EntryRef, Node>,
    by_name: HashMap<(EntryRef, Vec<u8>), EntryRef>,
}

pub struct FileRoot {
    root: OwnedHandle,
    root_path: PathBuf,
    root_ident: Ident,
    root_entry: EntryRef,
    owner_metadata: Option<OwnerMetadataBinding>,
    salt: [u8; 16],
    protected: Mutex<Vec<Ident>>,
    registry: Mutex<Registry>,
    /// Mutation generation per entry; see the module documentation.
    generation: Mutex<HashMap<Ident, u64>>,
    /// Serializes mutations so identity/revision checks and the operation that
    /// follows them cannot interleave with another mutation of this root.
    write: Mutex<()>,
}

struct OwnerMetadataBinding {
    path: PathBuf,
    components: Vec<Vec<u8>>,
    identities: Vec<Ident>,
    protected_paths: Vec<PathBuf>,
    allow_workspace_descendant: bool,
    /// Retain all named ancestor handles in addition to the root handle.
    _ancestor_handles: Vec<OwnedHandle>,
}

struct OpenedOwnerMetadataPath {
    root: OwnedHandle,
    path: PathBuf,
    components: Vec<Vec<u8>>,
    identities: Vec<Ident>,
    ancestor_handles: Vec<OwnedHandle>,
}

// ---- status / error mapping -------------------------------------------------

fn map_status(status: i32, ancestor: bool) -> Error {
    match status as u32 {
        // OBJECT_NAME_NOT_FOUND, OBJECT_PATH_NOT_FOUND, NO_SUCH_FILE, DELETE_PENDING
        0xC000_0034 | 0xC000_003A | 0xC000_000F | 0xC000_0056 => Error::NotFound,
        // NOT_A_DIRECTORY: something on the path is no longer what was recorded.
        0xC000_0103 if ancestor => Error::Changed,
        0xC000_0103 => Error::NotFound,
        // REPARSE_POINT_ENCOUNTERED, IO_REPARSE_TAG_NOT_HANDLED
        0xC000_050B | 0xC000_0279 => Error::Changed,
        // FILE_IS_A_DIRECTORY
        0xC000_00BA => Error::Invalid,
        // OBJECT_NAME_COLLISION
        0xC000_0035 => Error::Exists,
        // DIRECTORY_NOT_EMPTY
        0xC000_0101 => Error::NotEmpty,
        // NOT_SAME_DEVICE
        0xC000_00D4 => Error::Unsupported,
        // PRIVILEGE_NOT_HELD: full SACL state cannot be established.
        0xC000_0061 => Error::Unsupported,
        // OBJECT_NAME_INVALID, OBJECT_PATH_SYNTAX_BAD, INVALID_PARAMETER, NAME_TOO_LONG
        0xC000_0033 | 0xC000_003B | 0xC000_000D | 0xC000_0106 => Error::Invalid,
        // ACCESS_DENIED, SHARING_VIOLATION, CANNOT_DELETE, MEDIA_WRITE_PROTECTED
        0xC000_0022 | 0xC000_0043 | 0xC000_0121 | 0xC000_00A2 => {
            Error::Io(std::io::ErrorKind::PermissionDenied)
        }
        _ => Error::Io(std::io::ErrorKind::Other),
    }
}

fn map_os(error: std::io::Error) -> Error {
    match error.raw_os_error() {
        // ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND
        Some(2) | Some(3) => Error::NotFound,
        // ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION
        Some(5) | Some(32) => Error::Io(std::io::ErrorKind::PermissionDenied),
        _ => Error::Io(error.kind()),
    }
}

// ---- names ------------------------------------------------------------------

fn is_reserved_device(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").trim_end_matches(' ');
    let upper = stem.to_uppercase();
    if matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    let mut chars = upper.chars();
    let prefix: String = chars.by_ref().take(3).collect();
    (prefix == "COM" || prefix == "LPT")
        && matches!(
            chars.next(),
            Some('1'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}')
        )
        && chars.next().is_none()
}

/// True for names the engine will address: exactly one directory entry, free of
/// anything Win32 or NTFS would reinterpret.
fn valid_component(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." {
        return false;
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return false;
    }
    if name.encode_utf16().count() > 255 {
        return false;
    }
    if name
        .chars()
        .any(|c| (c as u32) < 0x20 || "\\/:*?\"<>|".contains(c))
    {
        return false;
    }
    !is_reserved_device(name)
}

fn component(name: &[u8]) -> Result<Vec<u16>> {
    let text = std::str::from_utf8(name).map_err(|_| Error::Invalid)?;
    if !valid_component(text) {
        return Err(Error::Invalid);
    }
    Ok(text.encode_utf16().collect())
}

/// `.git` in any spelling an NTFS volume could resolve to it: any case, the
/// 8.3 alias `GIT~<n>`, and trailing dots/spaces that Win32 strips.
fn is_git_name(name: &[u8]) -> bool {
    let text = String::from_utf8_lossy(name);
    let trimmed = text.trim_end_matches(['.', ' ']);
    if trimmed.eq_ignore_ascii_case(".git") {
        return true;
    }
    let upper = trimmed.to_ascii_uppercase();
    upper
        .strip_prefix("GIT~")
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

fn native_source_precondition(
    identity: Ident,
    kind: Kind,
) -> crate::desktop::DesktopSourcePrecondition {
    let kind = match kind {
        Kind::File => crate::desktop::DesktopFileKind::File,
        Kind::Directory => crate::desktop::DesktopFileKind::Directory,
        Kind::Symlink => crate::desktop::DesktopFileKind::Symlink,
        Kind::Other => crate::desktop::DesktopFileKind::Other,
    };
    crate::desktop::DesktopSourcePrecondition {
        identity: crate::desktop::DesktopFileIdentity {
            volume: identity.volume.to_string(),
            file_id: identity.id.to_string(),
        },
        kind,
    }
}

fn check_expected_native_source(
    expected: Option<&crate::desktop::DesktopSourcePrecondition>,
    identity: Ident,
    kind: Kind,
) -> Result<()> {
    if let Some(expected) = expected {
        if !expected.identity.is_valid() || *expected != native_source_precondition(identity, kind)
        {
            return Err(Error::Changed);
        }
    }
    Ok(())
}

fn check_native_mutation_phase(
    check: &mut impl FnMut(LocalNativeFileCheckPhase) -> bool,
    phase: LocalNativeFileCheckPhase,
) -> Result<()> {
    if check(phase) {
        Ok(())
    } else {
        Err(Error::Changed)
    }
}

/// NTFS compares names case-insensitively; the registry must too.
fn fold(name: &[u8]) -> Vec<u8> {
    String::from_utf8_lossy(name).to_lowercase().into_bytes()
}

// ---- handles ----------------------------------------------------------------

fn open_relative(
    dir: RawHandle,
    name: &[u16],
    access: u32,
    disposition: u32,
    options: u32,
    attributes: u32,
    ancestor: bool,
) -> Result<OwnedHandle> {
    open_relative_with_share(
        dir,
        name,
        access,
        disposition,
        options,
        attributes,
        SHARE_ALL,
        ancestor,
    )
}

/// Handle-relative open with an explicit sharing policy. Security-sensitive
/// Git leaf handles use this to prevent new writers after their final metadata
/// check; ordinary opens keep the existing share-all behavior above.
fn open_relative_with_share(
    dir: RawHandle,
    name: &[u16],
    access: u32,
    disposition: u32,
    options: u32,
    attributes: u32,
    share: u32,
    ancestor: bool,
) -> Result<OwnedHandle> {
    let bytes = name.len().checked_mul(2).ok_or(Error::Invalid)?;
    let length = u16::try_from(bytes).map_err(|_| Error::Invalid)?;
    let unicode = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: name.as_ptr() as *mut u16,
    };
    let object = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: dir,
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: null(),
        SecurityQualityOfService: null(),
    };
    let mut handle = null_mut();
    let mut status_block: IO_STATUS_BLOCK = unsafe { zeroed() };
    let mut open = || unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &object,
            &mut status_block,
            null(),
            attributes,
            share,
            disposition,
            options,
            null(),
            0,
        )
    };
    let status = if access & ACCESS_SYSTEM_SECURITY != 0 {
        with_system_security_privilege(open)?
    } else {
        open()
    };
    if status < 0 {
        return Err(map_status(status, ancestor));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

/// Create a new handle-relative object with an explicit security descriptor.
/// This is deliberately separate from `open_relative`: ordinary Git and
/// remote publication retains the existing inherited-security behavior.
fn open_relative_with_security(
    dir: RawHandle,
    name: &[u16],
    access: u32,
    disposition: u32,
    options: u32,
    attributes: u32,
    ancestor: bool,
    security_descriptor: *mut c_void,
) -> Result<OwnedHandle> {
    open_relative_with_security_and_share(
        dir,
        name,
        access,
        disposition,
        options,
        attributes,
        SHARE_ALL,
        ancestor,
        security_descriptor,
    )
}

fn open_relative_with_security_and_share(
    dir: RawHandle,
    name: &[u16],
    access: u32,
    disposition: u32,
    options: u32,
    attributes: u32,
    share: u32,
    ancestor: bool,
    security_descriptor: *mut c_void,
) -> Result<OwnedHandle> {
    if security_descriptor.is_null() || disposition != FILE_CREATE {
        return Err(Error::Invalid);
    }
    let bytes = name.len().checked_mul(2).ok_or(Error::Invalid)?;
    let length = u16::try_from(bytes).map_err(|_| Error::Invalid)?;
    let unicode = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: name.as_ptr() as *mut u16,
    };
    let object = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: dir,
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: security_descriptor.cast_const().cast(),
        SecurityQualityOfService: null(),
    };
    let mut handle = null_mut();
    let mut status_block: IO_STATUS_BLOCK = unsafe { zeroed() };
    let mut open = || unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &object,
            &mut status_block,
            null(),
            attributes,
            share,
            disposition,
            options,
            null(),
            0,
        )
    };
    let status = if access & ACCESS_SYSTEM_SECURITY != 0 {
        with_system_security_privilege(open)?
    } else {
        open()
    };
    if status < 0 {
        return Err(map_status(status, ancestor));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

/// Opens one handle with ACCESS_SYSTEM_SECURITY enabled only for the open.
/// Any CreateFileW call that requests this right must use this wrapper too.
fn open_createfilew(
    desired_access: u32,
    open: impl FnOnce(u32) -> (*mut c_void, u32),
) -> Result<OwnedHandle> {
    let open = || open(desired_access);
    let (handle, last_error) = if desired_access & ACCESS_SYSTEM_SECURITY != 0 {
        with_system_security_privilege(open)?
    } else {
        open()
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(map_os(std::io::Error::from_raw_os_error(last_error as i32)));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

struct SystemSecurityTokenScope {
    previous_thread: Option<OwnedHandle>,
    temporary: OwnedHandle,
    active: bool,
}

impl SystemSecurityTokenScope {
    fn install() -> Result<Self> {
        let mut previous_raw = null_mut();
        let previous_thread = if unsafe {
            OpenThreadToken(
                GetCurrentThread(),
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                1,
                &mut previous_raw,
            )
        } != 0
        {
            Some(unsafe { OwnedHandle::from_raw_handle(previous_raw) })
        } else if unsafe { GetLastError() } == ERROR_NO_TOKEN {
            None
        } else {
            return Err(Error::Unsupported);
        };

        let process_token = if previous_thread.is_none() {
            let mut raw = null_mut();
            if unsafe {
                OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw)
            } == 0
            {
                return Err(Error::Unsupported);
            }
            Some(unsafe { OwnedHandle::from_raw_handle(raw) })
        } else {
            None
        };
        let source = previous_thread
            .as_ref()
            .or(process_token.as_ref())
            .ok_or(Error::Unsupported)?;

        // Never raise a caller-provided impersonation token's level. Anonymous
        // and identification tokens cannot safely perform the requested open.
        let impersonation_level = if previous_thread.is_some() {
            let mut level = SecurityAnonymous;
            let mut returned = 0u32;
            if unsafe {
                GetTokenInformation(
                    source.as_raw_handle(),
                    TokenImpersonationLevel,
                    (&mut level as *mut i32).cast::<c_void>(),
                    size_of::<i32>() as u32,
                    &mut returned,
                )
            } == 0
                || returned < size_of::<i32>() as u32
                || level == SecurityAnonymous
                || level == SecurityIdentification
                || (level != SecurityImpersonation && level != SecurityDelegation)
            {
                return Err(Error::Unsupported);
            }
            level
        } else {
            SecurityImpersonation
        };

        let mut duplicate_raw = null_mut();
        if unsafe {
            DuplicateTokenEx(
                source.as_raw_handle(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE | TOKEN_QUERY,
                null(),
                impersonation_level,
                TokenImpersonation,
                &mut duplicate_raw,
            )
        } == 0
        {
            return Err(Error::Unsupported);
        }
        let temporary = unsafe { OwnedHandle::from_raw_handle(duplicate_raw) };

        let mut luid = unsafe { std::mem::zeroed() };
        if unsafe { LookupPrivilegeValueW(null(), SE_SECURITY_NAME, &mut luid) } == 0 {
            return Err(Error::Unsupported);
        }
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        unsafe { SetLastError(0) };
        let adjusted = unsafe {
            AdjustTokenPrivileges(
                temporary.as_raw_handle(),
                0,
                &privileges,
                0,
                null_mut(),
                null_mut(),
            )
        };
        let adjust_error = unsafe { GetLastError() };
        if adjusted == 0 {
            return Err(Error::Unsupported);
        }
        if adjust_error == ERROR_NOT_ALL_ASSIGNED {
            return Err(Error::Unsupported);
        }
        if adjust_error != 0 {
            return Err(Error::Unsupported);
        }

        let mut scope = Self {
            previous_thread,
            temporary,
            active: true,
        };
        if unsafe { SetThreadToken(null(), scope.temporary.as_raw_handle()) } == 0 {
            scope.restore();
            return Err(Error::Unsupported);
        }
        Ok(scope)
    }

    fn restore(&mut self) {
        if !self.active {
            return;
        }
        let token = self
            .previous_thread
            .as_ref()
            .map_or(null_mut(), |handle| handle.as_raw_handle());
        if unsafe { SetThreadToken(null(), token) } == 0 {
            // Returning with a different effective caller would violate the
            // security boundary for every subsequent operation on this thread.
            std::process::abort();
        }
        self.active = false;
    }
}

impl Drop for SystemSecurityTokenScope {
    fn drop(&mut self) {
        self.restore();
    }
}

fn with_system_security_privilege<T>(operation: impl FnOnce() -> T) -> Result<T> {
    let mut scope = SystemSecurityTokenScope::install()?;
    let result = operation();
    scope.restore();
    Ok(result)
}

fn info_of(handle: RawHandle) -> Result<Info> {
    let mut by_handle: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(handle, &mut by_handle) } == 0 {
        return Err(map_os(std::io::Error::last_os_error()));
    }
    let mut basic: FILE_BASIC_INFO = unsafe { zeroed() };
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            (&mut basic as *mut FILE_BASIC_INFO).cast::<c_void>(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(map_os(std::io::Error::last_os_error()));
    }
    // 64-bit file index everywhere; the 128-bit id where the volume has one.
    let mut ident = Ident {
        volume: u64::from(by_handle.dwVolumeSerialNumber),
        id: (u128::from(by_handle.nFileIndexHigh) << 32) | u128::from(by_handle.nFileIndexLow),
    };
    let mut wide: FILE_ID_INFO = unsafe { zeroed() };
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&mut wide as *mut FILE_ID_INFO).cast::<c_void>(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    } != 0
    {
        ident = Ident {
            volume: wide.VolumeSerialNumber,
            id: u128::from_le_bytes(wide.FileId.Identifier),
        };
    }
    Ok(Info {
        ident,
        attributes: by_handle.dwFileAttributes,
        size: (u64::from(by_handle.nFileSizeHigh) << 32) | u64::from(by_handle.nFileSizeLow),
        nlink: by_handle.nNumberOfLinks,
        last_write: basic.LastWriteTime,
        change: basic.ChangeTime,
    })
}

fn kind_of(info: &Info) -> Kind {
    if info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        Kind::Symlink
    } else if info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        Kind::Directory
    } else if info.attributes & FILE_ATTRIBUTE_DEVICE != 0 {
        Kind::Other
    } else {
        Kind::File
    }
}

const DIRECTORY_ACCESS: u32 =
    FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
const GIT_DIRECTORY_ACCESS: u32 = DIRECTORY_ACCESS | FILE_WRITE_DATA;
const DIRECTORY_OPTIONS: u32 = FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | SYNC;
// Omitting FILE_SYNCHRONOUS_IO_NONALERT creates an asynchronous native handle,
// the NT equivalent needed for ReadDirectoryChangesW with OVERLAPPED.
const WATCH_DIRECTORY_OPTIONS: u32 = FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT;
const ATTRIBUTE_ACCESS: u32 = FILE_READ_ATTRIBUTES | SYNCHRONIZE;
const ATTRIBUTE_OPTIONS: u32 = FILE_OPEN_REPARSE_POINT | SYNC;

/// Opens the leaf `name` of `dir` for attribute access only (never follows).
fn open_attributes(dir: RawHandle, name: &[u16]) -> Result<(OwnedHandle, Info)> {
    let handle = open_relative(
        dir,
        name,
        ATTRIBUTE_ACCESS,
        FILE_OPEN,
        ATTRIBUTE_OPTIONS,
        0,
        false,
    )?;
    let info = info_of(handle.as_raw_handle())?;
    Ok((handle, info))
}

fn read_dir_names(dir: RawHandle) -> Result<Vec<Vec<u8>>> {
    let mut buffer = vec![0u64; 8192]; // 64 KiB, 8-byte aligned
    let mut names = Vec::new();
    let mut restart = true;
    loop {
        let mut status_block: IO_STATUS_BLOCK = unsafe { zeroed() };
        let status = unsafe {
            NtQueryDirectoryFile(
                dir,
                null_mut(),
                None,
                null(),
                &mut status_block,
                buffer.as_mut_ptr().cast::<c_void>(),
                (buffer.len() * 8) as u32,
                FileNamesInformation,
                false,
                null(),
                restart,
            )
        };
        restart = false;
        if status == STATUS_NO_MORE_FILES || status == STATUS_NO_SUCH_FILE {
            return Ok(names);
        }
        if status < 0 {
            return Err(map_status(status, false));
        }
        let base = buffer.as_ptr().cast::<u8>();
        let mut offset = 0usize;
        loop {
            // FILE_NAMES_INFORMATION: next u32, index u32, length u32, name[].
            let record = unsafe { base.add(offset) };
            let next = unsafe { record.cast::<u32>().read_unaligned() } as usize;
            let length = unsafe { record.add(8).cast::<u32>().read_unaligned() } as usize;
            let units = unsafe {
                std::slice::from_raw_parts(record.add(12).cast::<u16>(), length / 2).to_vec()
            };
            // A name that is not valid UTF-16 cannot be represented: skip it.
            if let Ok(name) = String::from_utf16(&units)
                && name != "."
                && name != ".."
            {
                if names.len() >= MAX_DIR_ENTRIES {
                    return Err(Error::Limit);
                }
                names.push(name.into_bytes());
            }
            if next == 0 {
                break;
            }
            offset += next;
        }
    }
}

fn path_ident(path: &Path) -> Option<Ident> {
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let owned = open_createfilew(FILE_READ_ATTRIBUTES, |desired_access| {
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                desired_access,
                SHARE_ALL,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                null_mut(),
            )
        };
        (handle, unsafe { GetLastError() })
    })
    .ok()?;
    info_of(owned.as_raw_handle()).ok().map(|info| info.ident)
}

fn ancestor_idents(path: &Path) -> Vec<Ident> {
    path.ancestors().filter_map(path_ident).collect()
}

fn open_owner_metadata_path(path: &Path) -> Result<OpenedOwnerMetadataPath> {
    if !path.is_absolute() || path.as_os_str().len() > 32_768 {
        return Err(Error::Invalid);
    }
    let mut components = path.components();
    let prefix = match components.next() {
        Some(Component::Prefix(prefix))
            if matches!(
                prefix.kind(),
                Prefix::Disk(_)
                    | Prefix::VerbatimDisk(_)
                    | Prefix::UNC(_, _)
                    | Prefix::VerbatimUNC(_, _)
            ) =>
        {
            prefix
        }
        _ => return Err(Error::Invalid),
    };
    let root = match components.next() {
        Some(Component::RootDir) => Component::RootDir,
        _ => return Err(Error::Invalid),
    };
    let mut canonical = PathBuf::from(prefix.as_os_str());
    canonical.push(root.as_os_str());
    let wide = canonical
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let root_handle = open_createfilew(DIRECTORY_ACCESS, |desired_access| {
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                desired_access,
                SHARE_ALL,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        (handle, unsafe { GetLastError() })
    })?;
    let root_info = info_of(root_handle.as_raw_handle())?;
    if kind_of(&root_info) != Kind::Directory
        || root_info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(Error::Protected);
    }
    let mut handles = vec![root_handle];
    let mut relative_components = Vec::new();
    let mut identities = vec![root_info.ident];

    for part in components {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                if relative_components.pop().is_some() {
                    identities.pop();
                    handles.pop();
                    canonical.pop();
                }
            }
            Component::Normal(name) => {
                let name = name.to_str().ok_or(Error::Invalid)?;
                let name_bytes = name.as_bytes();
                let wide_name = component(name_bytes)?;
                let child = open_relative(
                    handles.last().ok_or(Error::Changed)?.as_raw_handle(),
                    &wide_name,
                    DIRECTORY_ACCESS,
                    FILE_OPEN,
                    FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | SYNC,
                    0,
                    true,
                )?;
                let child_info = info_of(child.as_raw_handle())?;
                if kind_of(&child_info) != Kind::Directory
                    || child_info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                {
                    return Err(Error::Protected);
                }
                relative_components.push(name_bytes.to_vec());
                identities.push(child_info.ident);
                canonical.push(name);
                handles.push(child);
            }
            Component::Prefix(_) | Component::RootDir => return Err(Error::Invalid),
        }
    }
    if relative_components.is_empty() {
        return Err(Error::Protected);
    }
    let root = handles.pop().ok_or(Error::Changed)?;
    Ok(OpenedOwnerMetadataPath {
        root,
        path: canonical,
        components: relative_components,
        identities,
        ancestor_handles: handles,
    })
}

fn check_owner_metadata_protection(
    metadata_path: &Path,
    metadata_identities: &[Ident],
    protected_paths: &[PathBuf],
    allow_workspace_descendant: bool,
) -> Result<()> {
    let metadata_identity = *metadata_identities.last().ok_or(Error::Changed)?;
    for (index, protected_path) in protected_paths.iter().enumerate() {
        let canonical_protected = protected_path.canonicalize().map_err(map_os)?;
        let protected_identity = path_ident(&canonical_protected).ok_or(Error::Protected)?;
        let verified_workspace_descendant = allow_workspace_descendant
            && index == 0
            && metadata_path != canonical_protected
            && metadata_path.starts_with(&canonical_protected)
            && metadata_identities[..metadata_identities.len().saturating_sub(1)]
                .contains(&protected_identity);
        if verified_workspace_descendant {
            continue;
        }
        if canonical_protected.starts_with(metadata_path)
            || metadata_path.starts_with(&canonical_protected)
        {
            return Err(Error::Protected);
        }
        let protected_ancestors = ancestor_idents(&canonical_protected);
        if metadata_identities.contains(&protected_identity)
            || protected_ancestors.contains(&metadata_identity)
        {
            return Err(Error::Protected);
        }
    }
    Ok(())
}

/// `FILE_RENAME_INFORMATION[_EX]`: flags/ReplaceIfExists, root, name.
#[repr(C)]
struct RenameInfo {
    flags: u32,
    root: RawHandle,
    name_length: u32,
    name: [u16; 1],
}

/// Renames the entry behind `source` into `target_dir` under `name` and never
/// replaces an existing destination.
fn rename_no_replace(source: RawHandle, target_dir: RawHandle, name: &[u16]) -> Result<()> {
    let bytes = size_of::<RenameInfo>() - size_of::<u16>() + name.len() * 2;
    let mut buffer = vec![0u64; bytes.div_ceil(8)];
    let info = buffer.as_mut_ptr().cast::<RenameInfo>();
    unsafe {
        (*info).flags = 0; // no FILE_RENAME_REPLACE_IF_EXISTS
        (*info).root = target_dir;
        (*info).name_length = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(name.as_ptr(), (*info).name.as_mut_ptr(), name.len());
    }
    let call = |class| {
        let mut status_block: IO_STATUS_BLOCK = unsafe { zeroed() };
        unsafe {
            NtSetInformationFile(
                source,
                &mut status_block,
                info.cast::<c_void>(),
                bytes as u32,
                class,
            )
        }
    };
    let mut status = call(FileRenameInformationEx);
    if matches!(
        status,
        STATUS_INVALID_INFO_CLASS | STATUS_NOT_SUPPORTED | STATUS_INVALID_PARAMETER
    ) {
        // Older systems lack the Ex class; the bytes are identical and a zero
        // first member means ReplaceIfExists = FALSE.
        status = call(FileRenameInformation);
    }
    if status < 0 {
        return Err(map_status(status, false));
    }
    Ok(())
}

/// Renames `source` over an existing target in one handle-relative operation.
fn rename_replace(source: RawHandle, target_dir: RawHandle, name: &[u16]) -> Result<()> {
    let bytes = size_of::<RenameInfo>() - size_of::<u16>() + name.len() * 2;
    let mut buffer = vec![0u64; bytes.div_ceil(8)];
    let info = buffer.as_mut_ptr().cast::<RenameInfo>();
    unsafe {
        (*info).flags = FILE_RENAME_REPLACE_IF_EXISTS;
        (*info).root = target_dir;
        (*info).name_length = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(name.as_ptr(), (*info).name.as_mut_ptr(), name.len());
    }
    let call = |class| {
        let mut status_block: IO_STATUS_BLOCK = unsafe { zeroed() };
        unsafe {
            NtSetInformationFile(
                source,
                &mut status_block,
                info.cast::<c_void>(),
                bytes as u32,
                class,
            )
        }
    };
    let mut status = call(FileRenameInformationEx);
    if matches!(
        status,
        STATUS_INVALID_INFO_CLASS | STATUS_NOT_SUPPORTED | STATUS_INVALID_PARAMETER
    ) {
        status = call(FileRenameInformation);
    }
    if status < 0 {
        return Err(map_status(status, false));
    }
    Ok(())
}

/// Deletes the entry behind `handle` (a file, a link itself, or an empty
/// directory) with POSIX semantics where the system has them.
fn delete_entry(handle: RawHandle) -> Result<()> {
    let ex = FILE_DISPOSITION_INFORMATION_EX {
        Flags: FILE_DISPOSITION_DELETE
            | FILE_DISPOSITION_POSIX_SEMANTICS
            | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
    };
    let mut status_block: IO_STATUS_BLOCK = unsafe { zeroed() };
    let mut status = unsafe {
        NtSetInformationFile(
            handle,
            &mut status_block,
            (&ex as *const FILE_DISPOSITION_INFORMATION_EX).cast::<c_void>(),
            size_of::<FILE_DISPOSITION_INFORMATION_EX>() as u32,
            FileDispositionInformationEx,
        )
    };
    if matches!(
        status,
        STATUS_INVALID_INFO_CLASS | STATUS_NOT_SUPPORTED | STATUS_INVALID_PARAMETER
    ) {
        let classic = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
        status = unsafe {
            NtSetInformationFile(
                handle,
                &mut status_block,
                (&classic as *const FILE_DISPOSITION_INFORMATION).cast::<c_void>(),
                size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
                FileDispositionInformation,
            )
        };
    }
    if status < 0 {
        return Err(map_status(status, false));
    }
    Ok(())
}

fn symlink_reparse_name(path_buffer: &[u8], offset: u16, length: u16) -> Result<&[u8]> {
    let offset = usize::from(offset);
    let length = usize::from(length);
    if offset % 2 != 0 || length % 2 != 0 {
        return Err(Error::Invalid);
    }
    let end = offset.checked_add(length).ok_or(Error::Invalid)?;
    path_buffer.get(offset..end).ok_or(Error::Invalid)
}

fn git_windows_symlink_target(bytes: &[u8], max_bytes: usize) -> Result<Vec<u8>> {
    const SYMLINK_TAG: u32 = 0xA000_000C;
    const MAX_REPARSE_BYTES: usize = 16 * 1024;

    if bytes.len() < 20 || bytes.len() > MAX_REPARSE_BYTES {
        return Err(Error::Invalid);
    }
    let tag = u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| Error::Invalid)?);
    let data_length = usize::from(u16::from_le_bytes(
        bytes[4..6].try_into().map_err(|_| Error::Invalid)?,
    ));
    if tag != SYMLINK_TAG
        || data_length < 12
        || data_length.checked_add(8) != Some(bytes.len())
        || bytes[6..8] != [0, 0]
    {
        return Err(Error::Invalid);
    }

    let substitute_offset =
        u16::from_le_bytes(bytes[8..10].try_into().map_err(|_| Error::Invalid)?);
    let substitute_length =
        u16::from_le_bytes(bytes[10..12].try_into().map_err(|_| Error::Invalid)?);
    let print_offset = u16::from_le_bytes(bytes[12..14].try_into().map_err(|_| Error::Invalid)?);
    let print_length = u16::from_le_bytes(bytes[14..16].try_into().map_err(|_| Error::Invalid)?);
    let flags = u32::from_le_bytes(bytes[16..20].try_into().map_err(|_| Error::Invalid)?);
    if flags & !1 != 0 {
        return Err(Error::Invalid);
    }

    let path_buffer = &bytes[20..];
    let substitute = symlink_reparse_name(path_buffer, substitute_offset, substitute_length)?;
    // Validate the unused print name too, so malformed offsets cannot hide in
    // an otherwise valid substitute-name buffer.
    symlink_reparse_name(path_buffer, print_offset, print_length)?;
    if substitute.is_empty() {
        return Err(Error::Invalid);
    }
    let units = substitute
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    if units.contains(&0) {
        return Err(Error::Invalid);
    }
    let mut target = String::from_utf16(&units).map_err(|_| Error::Invalid)?;

    // Match Git for Windows' normalize_ntpath() before UTF-8 conversion.
    if target.starts_with('\\') {
        if target.starts_with("\\??\\") || target.starts_with("\\\\?\\") {
            target.drain(..4);
        } else if target
            .get(..12)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("\\DosDevices\\"))
        {
            target.drain(..12);
        }
        if target
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("UNC\\"))
        {
            target.replace_range(..3, "\\");
        }
    }
    target = target.replace('\\', "/");
    if target.is_empty() {
        return Err(Error::Invalid);
    }
    let target = target.into_bytes();
    if target.len() > max_bytes {
        return Err(Error::Limit);
    }
    Ok(target)
}

fn map_reparse_read_error(error: SecurityBrokerError) -> Error {
    match error {
        SecurityBrokerError::Invalid => Error::Invalid,
        SecurityBrokerError::Changed => Error::Changed,
        SecurityBrokerError::Limit => Error::Limit,
        SecurityBrokerError::Unsupported => Error::Unsupported,
        SecurityBrokerError::Io(kind) => Error::Io(kind),
    }
}

impl FileRoot {
    /// Pins `root`. Refuses a root that contains, or lies inside, any of the
    /// `host_protected` paths (host data/secrets), by identity and not text.
    pub fn open(root: &Path, host_protected: &[&Path]) -> Result<Self> {
        Self::open_with_root_entry(root, host_protected, mint())
    }

    /// Like [`FileRoot::open`] but with a caller-chosen identifier for the root
    /// entry (the host uses the workspace id, so clients need no extra lookup).
    pub fn open_with_root_entry(
        root: &Path,
        host_protected: &[&Path],
        root_entry: EntryRef,
    ) -> Result<Self> {
        let canonical = root.canonicalize().map_err(map_os)?;
        let wide: Vec<u16> = canonical
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let root_handle = open_createfilew(DIRECTORY_ACCESS, |desired_access| {
            let handle = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    desired_access,
                    SHARE_ALL,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    null_mut(),
                )
            };
            (handle, unsafe { GetLastError() })
        })?;
        let info = info_of(root_handle.as_raw_handle())?;
        if kind_of(&info) != Kind::Directory {
            return Err(Error::Invalid);
        }
        let root_ident = info.ident;
        let mut protected = Vec::new();
        for path in host_protected {
            let Ok(canonical_protected) = path.canonicalize() else {
                continue;
            };
            if canonical_protected.starts_with(&canonical)
                || canonical.starts_with(&canonical_protected)
            {
                return Err(Error::Protected);
            }
            if let Some(ident) = path_ident(&canonical_protected) {
                // Identity guard too: junctions and renamed ancestors.
                if ident == root_ident || ancestor_idents(&canonical).contains(&ident) {
                    return Err(Error::Protected);
                }
                if ancestor_idents(&canonical_protected).contains(&root_ident) {
                    return Err(Error::Protected);
                }
                protected.push(ident);
            }
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        let mut registry = Registry::default();
        registry.nodes.insert(
            root_entry,
            Node {
                parent: None,
                name: Vec::new(),
                ident: root_ident,
            },
        );
        Ok(Self {
            root: root_handle,
            root_path: canonical,
            root_ident,
            root_entry,
            owner_metadata: None,
            salt,
            protected: Mutex::new(protected),
            registry: Mutex::new(registry),
            generation: Mutex::new(HashMap::new()),
            write: Mutex::new(()),
        })
    }

    /// Open a Git metadata directory by component-wise relative handles with
    /// every reparse point refused. This crate-internal constructor is held
    /// only by `OwnerGitMetadataRoot` and does not widen Explorer roots.
    pub(crate) fn open_owner_git_metadata(
        root: &Path,
        workspace_root: &Path,
        host_protected: &[&Path],
    ) -> Result<Self> {
        Self::open_owner_git_metadata_scoped(root, workspace_root, host_protected, false)
    }

    pub(crate) fn open_owner_git_metadata_from_verified_pointer(
        root: &Path,
        workspace_root: &Path,
        host_protected: &[&Path],
    ) -> Result<Self> {
        Self::open_owner_git_metadata_scoped(root, workspace_root, host_protected, true)
    }

    fn open_owner_git_metadata_scoped(
        root: &Path,
        workspace_root: &Path,
        host_protected: &[&Path],
        allow_workspace_descendant: bool,
    ) -> Result<Self> {
        let mut opened = open_owner_metadata_path(root)?;
        let info = info_of(opened.root.as_raw_handle())?;
        if kind_of(&info) != Kind::Directory || info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(Error::Protected);
        }
        let root_ident = info.ident;
        let mut protected_paths = Vec::with_capacity(host_protected.len() + 1);
        protected_paths.push(workspace_root.to_path_buf());
        protected_paths.extend(host_protected.iter().map(|path| path.to_path_buf()));
        check_owner_metadata_protection(
            &opened.path,
            &opened.identities,
            &protected_paths,
            allow_workspace_descendant,
        )?;

        let mut protected = Vec::with_capacity(host_protected.len());
        for path in host_protected {
            let canonical = path.canonicalize().map_err(map_os)?;
            protected.push(path_ident(&canonical).ok_or(Error::Protected)?);
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        let root_entry = mint();
        let mut registry = Registry::default();
        registry.nodes.insert(
            root_entry,
            Node {
                parent: None,
                name: Vec::new(),
                ident: root_ident,
            },
        );
        let binding = OwnerMetadataBinding {
            path: opened.path.clone(),
            components: opened.components,
            identities: opened.identities,
            protected_paths,
            allow_workspace_descendant,
            _ancestor_handles: std::mem::take(&mut opened.ancestor_handles),
        };
        Ok(Self {
            root: opened.root,
            root_path: opened.path,
            root_ident,
            root_entry,
            owner_metadata: Some(binding),
            salt,
            protected: Mutex::new(protected),
            registry: Mutex::new(registry),
            generation: Mutex::new(HashMap::new()),
            write: Mutex::new(()),
        })
    }

    pub(crate) fn open_owner_git_metadata_from_workspace_marker(
        &self,
        root: &Path,
        workspace_root: &Path,
        host_protected: &[&Path],
        repository: EntryRef,
        repository_path: &Path,
        marker: &GitPullPrecondition,
        expected_entry: Option<EntryRef>,
    ) -> Result<Self> {
        self.pin_native_directory(self.root_entry, workspace_root)?;
        self.pin_native_directory(repository, repository_path)?;
        if marker.parent != repository
            || marker.name != b".git"
            || !matches!(
                marker.kind,
                Some(GitPullNodeKind::File | GitPullNodeKind::Directory)
            )
        {
            return Err(Error::Invalid);
        }
        self.check_git_desktop_marker(marker)?;
        match marker.kind {
            Some(GitPullNodeKind::Directory) => {
                crate::owner_git_metadata::pointer_resolves_to(b".git", "", repository_path, root)?;
                if expected_entry != marker.entry {
                    return Err(Error::Changed);
                }
            }
            Some(GitPullNodeKind::File) => {
                let revision = marker.revision.as_deref().ok_or(Error::Invalid)?;
                let pointer = self.read_snapshot_chunk(
                    marker.entry.ok_or(Error::Invalid)?,
                    revision,
                    0,
                    4096,
                )?;
                if pointer.meta.size > 4096 || pointer.truncated {
                    return Err(Error::Limit);
                }
                crate::owner_git_metadata::pointer_resolves_to(
                    &pointer.bytes,
                    "gitdir: ",
                    repository_path,
                    root,
                )?;
            }
            _ => return Err(Error::Invalid),
        }
        self.check_git_desktop_marker(marker)?;
        let opened = Self::open_owner_git_metadata_from_verified_pointer(
            root,
            workspace_root,
            host_protected,
        )?;
        if let Some(expected_entry) = expected_entry {
            let (expected_handle, expected_info) = self.open_dir(expected_entry)?;
            let expected_ident = info_of(expected_handle.as_raw_handle())?.ident;
            if expected_ident != opened.root_ident || expected_info.ident != expected_ident {
                return Err(Error::Changed);
            }
        } else if opened.owner_metadata.as_ref().is_some_and(|binding| {
            binding.identities.len() > 1
                && binding.identities[..binding.identities.len() - 1].contains(&self.root_ident)
        }) {
            return Err(Error::Changed);
        }
        self.check_git_desktop_marker(marker)?;
        self.pin_native_directory(self.root_entry, workspace_root)?;
        Ok(opened)
    }

    pub(crate) fn owner_git_metadata_path(&self) -> Result<PathBuf> {
        self.owner_metadata
            .as_ref()
            .map(|binding| binding.path.clone())
            .ok_or(Error::Protected)
    }

    /// Match the root identity byte layout used by lomi-git's existing
    /// `path_identity` (volume serial followed by the file index).
    pub(crate) fn owner_git_metadata_identity(&self) -> Result<Vec<u8>> {
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
        if unsafe { GetFileInformationByHandle(self.root.as_raw_handle(), &mut info) } == 0 {
            return Err(map_os(std::io::Error::last_os_error()));
        }
        let mut identity = Vec::with_capacity(12);
        identity.extend_from_slice(&info.dwVolumeSerialNumber.to_le_bytes());
        let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
        identity.extend_from_slice(&index.to_le_bytes());
        Ok(identity)
    }

    pub(crate) fn check_owner_git_metadata_binding(&self) -> Result<()> {
        let binding = self.owner_metadata.as_ref().ok_or(Error::Protected)?;
        let current = open_owner_metadata_path(&binding.path)?;
        if current.path != binding.path
            || current.components != binding.components
            || current.identities != binding.identities
        {
            return Err(Error::Changed);
        }
        check_owner_metadata_protection(
            &binding.path,
            &binding.identities,
            &binding.protected_paths,
            binding.allow_workspace_descendant,
        )
    }

    pub fn root_entry(&self) -> EntryRef {
        self.root_entry
    }

    /// Starts a bounded, overlapped watcher on a validated, pinned directory.
    /// Descendants are reopened relative to the pinned root without following
    /// reparse points; the resulting handle is validated against its identity.
    pub fn watch_directory(&self, entry: EntryRef) -> Result<DirectoryWatch> {
        let (directory, info) = self.open_dir(entry)?;
        let handle = self.open_dir_for_watch(entry, info.ident)?;
        let watch = DirectoryWatch {
            handle,
            _directory: directory,
            state: Mutex::new(Box::pin(WatchState::new())),
        };
        {
            let mut state = watch.state.lock().map_err(|_| Error::Limit)?;
            arm_directory_watch(watch.handle.as_raw_handle(), state.as_mut().get_mut())?;
        }
        Ok(watch)
    }

    fn open_dir_for_watch(&self, entry: EntryRef, expected: Ident) -> Result<OwnedHandle> {
        let root_info = info_of(self.root.as_raw_handle())?;
        if root_info.ident != self.root_ident {
            return Err(Error::Changed);
        }

        let chain = self.chain(entry)?;
        if chain.is_empty() {
            let wide: Vec<u16> = self
                .root_path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let handle = open_createfilew(DIRECTORY_ACCESS, |desired_access| {
                let handle = unsafe {
                    CreateFileW(
                        wide.as_ptr(),
                        desired_access,
                        SHARE_ALL,
                        null(),
                        OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS
                            | FILE_FLAG_OPEN_REPARSE_POINT
                            | FILE_FLAG_OVERLAPPED,
                        null_mut(),
                    )
                };
                (handle, unsafe { GetLastError() })
            })?;
            let info = info_of(handle.as_raw_handle())?;
            if info.ident != expected || kind_of(&info) != Kind::Directory {
                return Err(Error::Changed);
            }
            return Ok(handle);
        }

        let mut parent = self.root.try_clone().map_err(map_os)?;
        let mut leaf_info = root_info;
        for (name, ident) in chain {
            let name = component(&name)?;
            let next = open_relative(
                parent.as_raw_handle(),
                &name,
                DIRECTORY_ACCESS,
                FILE_OPEN,
                WATCH_DIRECTORY_OPTIONS,
                0,
                true,
            )
            .map_err(|error| match error {
                Error::NotFound => Error::NotFound,
                Error::Io(_) | Error::Changed | Error::Invalid => Error::Changed,
                other => other,
            })?;
            leaf_info = info_of(next.as_raw_handle())?;
            if leaf_info.ident != ident || kind_of(&leaf_info) != Kind::Directory {
                return Err(Error::Changed);
            }
            parent = next;
        }
        if leaf_info.ident != expected {
            return Err(Error::Changed);
        }
        Ok(parent)
    }

    /// Registers an approved git directory (gitdir/commondir) as protected from
    /// File API mutation. Identity based; the caller has already validated it.
    pub fn protect(&self, path: &Path) -> Result<()> {
        let ident = path_ident(path).ok_or(Error::NotFound)?;
        let mut protected = self.protected.lock().map_err(|_| Error::Limit)?;
        if !protected.contains(&ident) {
            protected.push(ident);
        }
        Ok(())
    }

    fn is_protected_ident(&self, ident: &Ident) -> bool {
        *ident == self.root_ident
            || self
                .protected
                .lock()
                .map(|p| p.contains(ident))
                .unwrap_or(true)
    }

    fn generation_of(&self, ident: &Ident) -> u64 {
        self.generation
            .lock()
            .map(|g| g.get(ident).copied().unwrap_or(0))
            .unwrap_or(u64::MAX)
    }

    /// Marks `ident` as changed by this engine even if its timestamps did not
    /// tick.
    fn touch(&self, ident: Ident) {
        if let Ok(mut generation) = self.generation.lock() {
            *generation.entry(ident).or_insert(0) += 1;
        }
    }

    fn revision(&self, info: &Info) -> String {
        let mut hash = Sha256::new();
        hash.update(self.salt);
        hash.update(info.ident.volume.to_le_bytes());
        hash.update(info.ident.id.to_le_bytes());
        for value in [
            info.size,
            info.last_write as u64,
            info.change as u64,
            u64::from(info.attributes),
            u64::from(info.nlink),
            self.generation_of(&info.ident),
        ] {
            hash.update(value.to_le_bytes());
        }
        let digest = hash.finalize();
        let mut out = String::from("r");
        for byte in &digest[..16] {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    fn meta(&self, entry: EntryRef, name: &[u8], info: &Info) -> Meta {
        let kind = kind_of(info);
        Meta {
            entry,
            name: name.to_vec(),
            kind,
            size: if kind == Kind::File { info.size } else { 0 },
            revision: self.revision(info),
            nlink: u64::from(info.nlink),
        }
    }

    /// Records (or reuses) the entry for `(parent, name)` with this identity.
    fn register(&self, parent: EntryRef, name: &[u8], ident: Ident) -> Result<EntryRef> {
        let mut registry = self.registry.lock().map_err(|_| Error::Limit)?;
        let key = (parent, fold(name));
        if let Some(existing) = registry.by_name.get(&key).copied() {
            if registry
                .nodes
                .get(&existing)
                .is_some_and(|n| n.ident == ident)
            {
                if let Some(node) = registry.nodes.get_mut(&existing) {
                    // Keep the on-disk spelling of the name current.
                    node.name = name.to_vec();
                }
                return Ok(existing);
            }
            registry.nodes.remove(&existing);
            registry.by_name.remove(&key);
        }
        if registry.nodes.len() >= MAX_REGISTERED_ENTRIES {
            // Generation reset: every previously issued id (but the root)
            // becomes NotFound and clients resync by listing again.
            registry.nodes.retain(|id, _| *id == self.root_entry);
            registry.by_name.clear();
        }
        let id = mint();
        registry.nodes.insert(
            id,
            Node {
                parent: Some(parent),
                name: name.to_vec(),
                ident,
            },
        );
        registry.by_name.insert(key, id);
        Ok(id)
    }

    fn chain(&self, entry: EntryRef) -> Result<Vec<(Vec<u8>, Ident)>> {
        let registry = self.registry.lock().map_err(|_| Error::Limit)?;
        let mut chain = Vec::new();
        let mut cursor = entry;
        while cursor != self.root_entry {
            let node = registry.nodes.get(&cursor).ok_or(Error::NotFound)?;
            chain.push((node.name.clone(), node.ident));
            cursor = node.parent.ok_or(Error::NotFound)?;
            if chain.len() > 4096 {
                return Err(Error::Limit);
            }
        }
        chain.reverse();
        Ok(chain)
    }

    fn entry_has_private_staging_name(&self, entry: EntryRef) -> Result<bool> {
        Ok(self
            .chain(entry)?
            .iter()
            .any(|(name, _)| is_private_staging_name(name)))
    }

    fn node(&self, entry: EntryRef) -> Result<(Option<EntryRef>, Vec<u8>, Ident)> {
        let registry = self.registry.lock().map_err(|_| Error::Limit)?;
        let node = registry.nodes.get(&entry).ok_or(Error::NotFound)?;
        Ok((node.parent, node.name.clone(), node.ident))
    }

    /// Opens the directory `entry`, validating the recorded identity of every
    /// ancestor. Never traverses a reparse point.
    fn open_dir(&self, entry: EntryRef) -> Result<(OwnedHandle, Info)> {
        self.open_dir_with_final_access(entry, DIRECTORY_ACCESS)
    }

    fn open_git_directory(&self, entry: EntryRef) -> Result<(OwnedHandle, Info)> {
        self.open_dir_with_final_access(entry, GIT_DIRECTORY_ACCESS)
    }

    fn open_dir_with_final_access(
        &self,
        entry: EntryRef,
        final_access: u32,
    ) -> Result<(OwnedHandle, Info)> {
        let chain = self.chain(entry)?;
        let root = self.root.try_clone().map_err(map_os)?;
        let root_info = info_of(root.as_raw_handle())?;
        if root_info.ident != self.root_ident {
            return Err(Error::Changed);
        }
        let mut handle = root;
        let mut info = root_info;
        let last = chain.len().saturating_sub(1);
        for (index, (name, ident)) in chain.into_iter().enumerate() {
            let name = component(&name)?;
            let next = open_relative(
                handle.as_raw_handle(),
                &name,
                if index == last {
                    final_access
                } else {
                    DIRECTORY_ACCESS
                },
                FILE_OPEN,
                DIRECTORY_OPTIONS,
                0,
                true,
            )
            .map_err(|e| match e {
                Error::NotFound => Error::NotFound,
                Error::Io(_) | Error::Changed | Error::Invalid => Error::Changed,
                other => other,
            })?;
            let next_info = info_of(next.as_raw_handle())?;
            if next_info.ident != ident || kind_of(&next_info) != Kind::Directory {
                return Err(Error::Changed);
            }
            handle = next;
            info = next_info;
        }
        Ok((handle, info))
    }

    /// Parent directory handle plus the leaf's validated (not followed) info.
    fn open_leaf(&self, entry: EntryRef) -> Result<(OwnedHandle, Vec<u8>, Info)> {
        let (parent, name, ident) = self.node(entry)?;
        let parent = parent.ok_or(Error::Invalid)?;
        let (parent_handle, _) = self.open_dir(parent)?;
        let (_leaf, info) = open_attributes(parent_handle.as_raw_handle(), &component(&name)?)?;
        if info.ident != ident {
            return Err(Error::Changed);
        }
        Ok((parent_handle, name, info))
    }

    fn check_revision(&self, info: &Info, expected: Option<&str>) -> Result<()> {
        match expected {
            Some(expected) if self.revision(info) != expected => Err(Error::Changed),
            _ => Ok(()),
        }
    }

    pub fn stat(&self, entry: EntryRef, expected_revision: Option<&str>) -> Result<Meta> {
        if self.entry_has_private_staging_name(entry)? {
            return Err(Error::NotFound);
        }
        if entry == self.root_entry {
            let info = info_of(self.root.as_raw_handle())?;
            if info.ident != self.root_ident {
                return Err(Error::Changed);
            }
            self.check_revision(&info, expected_revision)?;
            return Ok(self.meta(entry, b"", &info));
        }
        let (_parent, name, info) = self.open_leaf(entry)?;
        self.check_revision(&info, expected_revision)?;
        Ok(self.meta(entry, &name, &info))
    }

    /// Host-only native launch binding to the admitted worktree handle and its
    /// current no-reparse absolute pathname. Never exposed through file RPCs.
    #[doc(hidden)]
    pub fn pin_native_directory(&self, entry: EntryRef, absolute_path: &Path) -> Result<File> {
        if self.entry_has_private_staging_name(entry)? {
            return Err(Error::NotFound);
        }
        let (held, held_info) = self.open_dir(entry)?;
        let (_named, named_info) =
            native_open_absolute_directory_no_follow(absolute_path).map_err(|_| Error::Changed)?;
        if held_info.ident != named_info.ident {
            return Err(Error::Changed);
        }
        Ok(File::from(held))
    }

    /// Return a desktop-only native identity for the exact leaf admitted by
    /// this FileRoot registry entry. The identity comes from the pinned parent
    /// and no-follow leaf, not from reopening a host path.
    #[doc(hidden)]
    pub fn desktop_source_precondition(
        &self,
        entry: EntryRef,
    ) -> Result<crate::desktop::DesktopSourcePrecondition> {
        let (_handle, _name, info) = self.open_leaf(entry)?;
        let kind = match kind_of(&info) {
            Kind::File => crate::desktop::DesktopFileKind::File,
            Kind::Directory => crate::desktop::DesktopFileKind::Directory,
            Kind::Symlink => crate::desktop::DesktopFileKind::Symlink,
            Kind::Other => crate::desktop::DesktopFileKind::Other,
        };
        Ok(crate::desktop::DesktopSourcePrecondition {
            identity: crate::desktop::DesktopFileIdentity {
                volume: info.ident.volume.to_string(),
                file_id: info.ident.id.to_string(),
            },
            kind,
        })
    }

    /// Resolve a registered entry to its current absolute path while retaining
    /// FileRoot's no-reparse identity binding. Path components come only from
    /// the registry, and the supplied path must still name this exact root.
    #[doc(hidden)]
    pub fn native_entry_binding(
        &self,
        absolute_root: &Path,
        entry: EntryRef,
    ) -> Result<(PathBuf, crate::desktop::DesktopSourcePrecondition)> {
        let _guard = self.write.lock().map_err(|_| Error::Limit)?;
        if self.entry_has_private_staging_name(entry)? || self.chain_is_protected(entry)? {
            return Err(Error::Protected);
        }

        let held_root_info = info_of(self.root.as_raw_handle())?;
        if held_root_info.ident != self.root_ident {
            return Err(Error::Changed);
        }
        let (_named_root, named_root_info) =
            native_open_absolute_directory_no_follow(absolute_root).map_err(|_| Error::Changed)?;
        if named_root_info.ident != self.root_ident {
            return Err(Error::Changed);
        }

        let mut path = absolute_root.to_path_buf();
        let (identity, kind) = if entry == self.root_entry {
            (self.root_ident, Kind::Directory)
        } else {
            for (name, _) in self.chain(entry)? {
                let name = String::from_utf8(name).map_err(|_| Error::Invalid)?;
                path.push(name);
            }
            let (_parent, _name, info) = self.open_leaf(entry)?;
            (info.ident, kind_of(&info))
        };
        Ok((path, native_source_precondition(identity, kind)))
    }

    pub fn list(&self, parent: EntryRef, cursor: Option<&[u8]>, limit: usize) -> Result<Page> {
        if self.entry_has_private_staging_name(parent)? {
            return Err(Error::NotFound);
        }
        let limit = limit.clamp(1, MAX_PAGE);
        let (dir, _) = self.open_dir(parent)?;
        let mut names: Vec<Vec<u8>> = read_dir_names(dir.as_raw_handle())?
            .into_iter()
            .filter(|n| {
                !is_private_staging_name(n) && std::str::from_utf8(n).is_ok_and(valid_component)
            })
            .collect();
        names.sort();
        let start = match cursor {
            Some(cursor) => names.partition_point(|n| n.as_slice() <= cursor),
            None => 0,
        };
        let mut entries = Vec::new();
        let mut last = None;
        let mut index = start;
        while index < names.len() && entries.len() < limit {
            let name = &names[index];
            index += 1;
            last = Some(name.clone());
            let wide = component(name)?;
            // A name that vanished or became unreadable mid-listing is skipped.
            let Ok((_handle, info)) = open_attributes(dir.as_raw_handle(), &wide) else {
                continue;
            };
            let id = self.register(parent, name, info.ident)?;
            entries.push(self.meta(id, name, &info));
        }
        let truncated = index < names.len();
        Ok(Page {
            entries,
            next: if truncated { last } else { None },
            truncated,
        })
    }

    pub fn read(
        &self,
        entry: EntryRef,
        expected_revision: Option<&str>,
        offset: u64,
        max_bytes: usize,
    ) -> Result<ReadResult> {
        self.read_with_binary_policy(entry, expected_revision, offset, max_bytes, false)
            .map(|(result, _)| result)
    }

    /// Read one bounded raw chunk for a private Git snapshot. Unlike Explorer
    /// reads, this host-internal API preserves binary bytes. It retains the
    /// same pinned-entry, no-follow, hard-link, and revision checks as `read`.
    /// Do not expose this result through a remote file-read DTO.
    #[doc(hidden)]
    pub fn read_snapshot_chunk(
        &self,
        entry: EntryRef,
        expected_revision: &str,
        offset: u64,
        max_bytes: usize,
    ) -> Result<SnapshotChunk> {
        let (read, executable) =
            self.read_with_binary_policy(entry, Some(expected_revision), offset, max_bytes, true)?;
        let truncated = offset.saturating_add(read.bytes.len() as u64) < read.meta.size;
        Ok(SnapshotChunk {
            meta: read.meta,
            offset: read.offset,
            encoding: read.encoding,
            bytes: read.bytes,
            truncated,
            executable,
        })
    }

    /// Read a symlink target from its no-follow reparse buffer for a private
    /// Git snapshot. This host-internal path never opens or stats the target.
    #[doc(hidden)]
    pub fn readlink_snapshot(
        &self,
        entry: EntryRef,
        expected_revision: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>> {
        if self.entry_has_private_staging_name(entry)? {
            return Err(Error::NotFound);
        }
        if max_bytes == 0 || max_bytes > 1024 * 1024 {
            return Err(Error::Invalid);
        }

        let (parent_entry, name, expected_ident) = self.node(entry)?;
        let parent_entry = parent_entry.ok_or(Error::Invalid)?;
        self.pin_native_directory(self.root_entry, &self.root_path)?;
        let (parent, parent_before) = self.open_dir(parent_entry)?;
        if kind_of(&parent_before) != Kind::Directory {
            return Err(Error::Changed);
        }
        let leaf = open_relative_with_share(
            parent.as_raw_handle(),
            &component(&name)?,
            ATTRIBUTE_ACCESS,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT | SYNC,
            0,
            FILE_SHARE_READ,
            false,
        )?;
        let before = info_of(leaf.as_raw_handle())?;
        if before.ident != expected_ident || kind_of(&before) != Kind::Symlink || before.nlink != 1
        {
            return Err(Error::Protected);
        }
        self.check_revision(&before, Some(expected_revision))?;

        let reparse = security_broker::read_symlink_reparse_buffer(leaf.as_raw_handle())
            .map_err(map_reparse_read_error)?;
        let target = git_windows_symlink_target(&reparse, max_bytes)?;
        let after = info_of(leaf.as_raw_handle())?;
        if after != before || kind_of(&after) != Kind::Symlink {
            return Err(Error::Changed);
        }
        self.check_revision(&after, Some(expected_revision))?;

        if self.node(entry)? != (Some(parent_entry), name.clone(), expected_ident) {
            return Err(Error::Changed);
        }
        let (parent_after, parent_after_info) = self.open_dir(parent_entry)?;
        if parent_after_info.ident != parent_before.ident
            || kind_of(&parent_after_info) != Kind::Directory
        {
            return Err(Error::Changed);
        }
        let (_named_leaf, named_after) =
            open_attributes(parent_after.as_raw_handle(), &component(&name)?)?;
        if named_after.ident != expected_ident || kind_of(&named_after) != Kind::Symlink {
            return Err(Error::Changed);
        }
        self.check_revision(&named_after, Some(expected_revision))?;
        self.pin_native_directory(self.root_entry, &self.root_path)?;

        Ok(target)
    }

    /// Publishes a prepared Git index or reference under the FileRoot barrier.
    #[doc(hidden)]
    pub fn publish_git(
        &self,
        publication: &GitPublication,
        continue_check: impl FnMut() -> bool,
    ) -> Result<GitPublishOutcome> {
        let _broker_scope = BrokerOperationScope::enter();
        publication.validate().map_err(|_| Error::Invalid)?;
        if matches!(
            publication.final_file.target,
            GitFinalTarget::WorktreeIgnore { .. } | GitFinalTarget::LocalExclude { .. }
        ) {
            return Err(Error::Invalid);
        }
        let _guard = self.write.lock().map_err(|_| Error::Limit)?;
        self.publish_git_locked(publication, continue_check)
    }

    /// Publishes a fixed Desktop Ignore target while rechecking the selected
    /// worktree entry under the same write barrier immediately before rename.
    #[doc(hidden)]
    pub fn publish_git_desktop_ignore(
        &self,
        publication: &GitPublication,
        repository: EntryRef,
        repository_preconditions: &[GitPullPrecondition],
        selected: &GitPullPrecondition,
        continue_check: impl FnMut() -> bool,
    ) -> Result<GitPublishOutcome> {
        let _broker_scope = BrokerOperationScope::enter();
        publication.validate().map_err(|_| Error::Invalid)?;
        if !matches!(
            publication.final_file.target,
            GitFinalTarget::WorktreeIgnore { .. } | GitFinalTarget::LocalExclude { .. }
        ) || !publication.objects.is_empty()
            || !publication.worktree_preconditions.is_empty()
        {
            return Err(Error::Invalid);
        }
        let _guard = self.write.lock().map_err(|_| Error::Limit)?;
        let mut preceding = Vec::new();
        self.publish_git_locked_batch(
            publication,
            continue_check,
            &mut preceding,
            false,
            Some((repository, repository_preconditions, selected)),
        )
        .map(|(outcome, _)| outcome)
    }

    fn publish_git_locked(
        &self,
        publication: &GitPublication,
        continue_check: impl FnMut() -> bool,
    ) -> Result<GitPublishOutcome> {
        let mut preceding = Vec::new();
        self.publish_git_locked_batch(publication, continue_check, &mut preceding, false, None)
            .map(|(outcome, _)| outcome)
    }

    fn publish_git_locked_batch(
        &self,
        publication: &GitPublication,
        mut continue_check: impl FnMut() -> bool,
        preceding: &mut [GitPublishedGuard],
        capture_guard: bool,
        desktop_selected: Option<(EntryRef, &[GitPullPrecondition], &GitPullPrecondition)>,
    ) -> Result<(GitPublishOutcome, Option<GitPublishedGuard>)> {
        publication.validate().map_err(|_| Error::Invalid)?;
        let desktop_ignore_target = matches!(
            &publication.final_file.target,
            GitFinalTarget::WorktreeIgnore { .. } | GitFinalTarget::LocalExclude { .. }
        );
        if desktop_ignore_target != desktop_selected.is_some() {
            return Err(Error::Protected);
        }
        let mut info_creation_guard: Option<GitInfoCreationGuard> = None;
        self.require_git_dir(publication.git_dir)?;
        self.require_git_dir(publication.common_dir)?;
        self.validate_git_target(publication)?;
        self.check_git_preconditions_with_published(&publication.preconditions, preceding)?;
        self.check_git_worktree_preconditions(&publication.worktree_preconditions)?;
        if let Some((repository, repository_preconditions, selected)) = desktop_selected {
            self.check_git_desktop_repository(
                repository,
                publication.git_dir,
                publication.common_dir,
                repository_preconditions,
                info_creation_guard.as_ref(),
            )?;
            self.check_git_desktop_selected(repository, selected)?;
        }
        self.check_git_target_precondition(publication, preceding)?;
        if !continue_check() {
            return Ok((GitPublishOutcome::AbortedBeforeFinalRename, None));
        }

        let (common_handle, common_info) = self.open_git_directory(publication.common_dir)?;
        let (objects_handle, _) = open_git_child_dir(common_handle.as_raw_handle(), b"objects")?;
        let target_name = component(publication.final_file.target.name())?;
        let mut lock_name_bytes = publication.final_file.target.name().to_vec();
        lock_name_bytes.extend_from_slice(b".lock");
        let lock_name = component(&lock_name_bytes)?;
        let (base_handle, base_info) = self.open_git_publication_parent(publication)?;
        let info_creation_baseline = self.git_info_creation_baseline(
            publication,
            desktop_selected,
            &base_handle,
            base_info.ident,
        )?;
        let mut created_dirs = Vec::new();
        let target_parent = if publication.final_file.parent_suffix.is_empty() {
            base_handle.try_clone().map_err(map_os)?
        } else {
            match create_git_target_parent(
                &base_handle,
                &publication.final_file.parent_suffix,
                &mut created_dirs,
                publication.final_file.parent,
                preceding,
                &mut continue_check,
                |ident| self.touch(ident),
                || {},
            ) {
                Ok(parent) => parent,
                Err(error) => {
                    cleanup_created_git_dirs(&base_handle, &created_dirs);
                    return Err(error);
                }
            }
        };
        if let Some(baseline) = info_creation_baseline {
            info_creation_guard =
                Some(self.finish_git_info_creation(&base_handle, &created_dirs, baseline)?);
        }
        let target_parent_identity = match info_of(target_parent.as_raw_handle()) {
            Ok(info) => info.ident,
            Err(error) => {
                cleanup_created_git_dirs(&base_handle, &created_dirs);
                return Err(error);
            }
        };
        let (source_security, source_broker_capture) =
            match capture_git_named_file_security(target_parent.as_raw_handle(), &target_name) {
                Ok(security) => security,
                Err(error) => {
                    cleanup_created_git_dirs(&base_handle, &created_dirs);
                    return Err(error);
                }
            };
        if source_security.is_some() != publication.final_file.expected.entry.is_some() {
            cleanup_created_git_dirs(&base_handle, &created_dirs);
            return Err(Error::Changed);
        }
        if source_security
            .as_ref()
            .is_some_and(|security| security.attributes & FILE_ATTRIBUTE_READONLY != 0)
        {
            cleanup_created_git_dirs(&base_handle, &created_dirs);
            return Err(Error::Protected);
        }
        let lock_name_text =
            String::from_utf8(lock_name_bytes.clone()).map_err(|_| Error::Invalid)?;
        let mut lock_temp = match native_temp_named(
            &target_parent,
            &lock_name_text,
            source_broker_capture.as_ref().map(|source| &source.session),
        ) {
            Ok(lock) => lock,
            Err(error) => {
                cleanup_created_git_dirs(&base_handle, &created_dirs);
                return Err(git_native_security_error(error));
            }
        };
        let lock = match lock_temp.handle.try_clone().map_err(map_os) {
            Ok(handle) => handle,
            Err(error) => {
                cleanup_created_git_dirs(&base_handle, &created_dirs);
                return Err(error);
            }
        };
        let lock_info = match info_of(lock.as_raw_handle()) {
            Ok(info) if kind_of(&info) == Kind::File && info.nlink == 1 => info,
            Ok(_) => {
                cleanup_created_git_dirs(&base_handle, &created_dirs);
                return Err(Error::Protected);
            }
            Err(error) => {
                cleanup_created_git_dirs(&base_handle, &created_dirs);
                return Err(error);
            }
        };
        let lock_file_clone = match lock.try_clone().map_err(map_os) {
            Ok(handle) => handle,
            Err(error) => {
                cleanup_created_git_dirs(&base_handle, &created_dirs);
                return Err(error);
            }
        };
        let mut lock_file = unsafe { File::from_raw_handle(lock_file_clone.into_raw_handle()) };
        let mut publication_visible = false;
        let mut guard_file = None;
        let mut published_security = None;
        let publication_digest: [u8; 32] = Sha256::digest(&publication.final_file.bytes).into();
        let content_digest = if capture_guard {
            publication_digest
        } else {
            [0; 32]
        };
        let work = (|| -> Result<GitPublishOutcome> {
            let private_security = native_owner_only_file_security(lock.as_raw_handle())?;
            if !write_git_bytes(
                &mut lock_file,
                &publication.final_file.bytes,
                &mut continue_check,
            )? {
                return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
            }
            let final_security = if let Some(source) = source_security.as_ref() {
                let metadata_handle = if let Some(capture) = source_broker_capture.as_ref() {
                    capture.recheck().map_err(git_native_security_error)?;
                    check_git_named_file_security(
                        target_parent.as_raw_handle(),
                        &target_name,
                        source_security.as_ref(),
                    )?;
                    let token = lock_temp.broker_token.as_ref().ok_or(Error::Unsupported)?;
                    capture.finalize(token).map_err(git_native_security_error)?;
                    lock_temp
                        .open_publish_handle()
                        .map_err(git_native_security_error)?
                } else {
                    if matches!(source.extended.audit_sacl, AuditSacl::Broker(_)) {
                        return Err(Error::Changed);
                    }
                    lock.as_raw_handle()
                };
                let final_security = apply_git_file_security(metadata_handle, Some(source), true)?;
                if final_security != *source
                    || git_file_security(metadata_handle)? != final_security
                {
                    return Err(Error::Changed);
                }
                final_security
            } else {
                let final_security = git_file_security(lock.as_raw_handle())?;
                if final_security.extended != private_security.extended {
                    return Err(Error::Changed);
                }
                final_security
            };
            published_security = Some(final_security);
            lock_file.sync_all().map_err(map_os)?;
            if hash_git_file(&mut lock_file, publication.final_file.bytes.len())?
                != publication_digest
            {
                return Err(Error::Changed);
            }
            if capture_guard {
                // Retain a read-only handle to the exact owned temporary inode
                // so later batch steps can verify its content and pathname.
                let verification_access = FILE_READ_DATA
                    | FILE_WRITE_DATA
                    | FILE_READ_ATTRIBUTES
                    | READ_CONTROL
                    | SYNCHRONIZE;
                let verification_options =
                    FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_OPEN_NO_RECALL | SYNC;
                let verification_handle = match open_relative(
                    target_parent.as_raw_handle(),
                    &lock_name,
                    verification_access | ACCESS_SYSTEM_SECURITY,
                    FILE_OPEN,
                    verification_options,
                    0,
                    false,
                ) {
                    Ok(handle) => handle,
                    Err(Error::Unsupported | Error::Io(std::io::ErrorKind::PermissionDenied)) => {
                        open_relative(
                            target_parent.as_raw_handle(),
                            &lock_name,
                            verification_access,
                            FILE_OPEN,
                            verification_options,
                            0,
                            false,
                        )?
                    }
                    Err(error) => return Err(error),
                };
                let verification_info = info_of(verification_handle.as_raw_handle())?;
                if kind_of(&verification_info) != Kind::File
                    || verification_info.nlink != 1
                    || verification_info.ident != lock_info.ident
                {
                    return Err(Error::Changed);
                }
                let mut verification_file =
                    unsafe { File::from_raw_handle(verification_handle.into_raw_handle()) };
                if hash_git_file(&mut verification_file, publication.final_file.bytes.len())?
                    != content_digest
                {
                    return Err(Error::Changed);
                }
                guard_file = Some(verification_file);
            }

            for object in &publication.objects {
                if !continue_check() {
                    return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
                }
                let hex = object.object_id.as_bytes();
                let (prefix, suffix) = hex.split_at(2);
                let (prefix_handle, _) =
                    open_or_create_git_child_dir(objects_handle.as_raw_handle(), prefix)?;
                if let Err(error) = install_git_object(
                    prefix_handle.as_raw_handle(),
                    suffix,
                    &object.bytes,
                    &mut continue_check,
                ) {
                    if error == Error::Changed && !continue_check() {
                        return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
                    }
                    return Err(error);
                }
            }

            self.check_git_preconditions_with_current(
                &publication.preconditions,
                preceding,
                Some((publication, &base_handle, &created_dirs)),
            )?;
            self.check_git_worktree_preconditions(&publication.worktree_preconditions)?;
            if let Some((repository, repository_preconditions, selected)) = desktop_selected {
                self.check_git_desktop_repository(
                    repository,
                    publication.git_dir,
                    publication.common_dir,
                    repository_preconditions,
                    info_creation_guard.as_ref(),
                )?;
                self.check_git_desktop_selected(repository, selected)?;
            }
            if publication.final_file.parent_suffix.is_empty() {
                self.check_git_target_precondition(publication, preceding)?;
            } else {
                let parent = verify_git_target_parent(
                    &base_handle,
                    &publication.final_file.parent_suffix,
                    &created_dirs,
                )?;
                if info_of(parent.as_raw_handle())?.ident != target_parent_identity
                    || git_target_exists(parent.as_raw_handle(), &target_name)?
                {
                    return Err(Error::Changed);
                }
            }
            if !continue_check() {
                return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
            }
            let (current_base, current_base_info) =
                self.open_git_publication_parent(publication)?;
            if current_base_info.ident != base_info.ident {
                return Err(Error::Changed);
            }
            let current_parent = verify_git_target_parent(
                &current_base,
                &publication.final_file.parent_suffix,
                &created_dirs,
            )?;
            if info_of(current_parent.as_raw_handle())?.ident != target_parent_identity {
                return Err(Error::Changed);
            }
            if publication.final_file.parent_suffix.is_empty() {
                self.check_git_target_precondition(publication, preceding)?;
            } else if git_target_exists(current_parent.as_raw_handle(), &target_name)? {
                return Err(Error::Changed);
            }
            check_git_lock_identity(
                target_parent.as_raw_handle(),
                &lock_name,
                lock.as_raw_handle(),
                lock_info.ident,
            )?;
            self.check_git_preconditions_with_current(
                &publication.preconditions,
                preceding,
                Some((publication, &base_handle, &created_dirs)),
            )?;
            if !continue_check() {
                return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
            }
            self.check_git_preconditions_with_current(
                &publication.preconditions,
                preceding,
                Some((publication, &base_handle, &created_dirs)),
            )?;
            self.check_git_worktree_preconditions(&publication.worktree_preconditions)?;
            if let Some((repository, repository_preconditions, selected)) = desktop_selected {
                self.check_git_desktop_repository(
                    repository,
                    publication.git_dir,
                    publication.common_dir,
                    repository_preconditions,
                    info_creation_guard.as_ref(),
                )?;
                self.check_git_desktop_selected(repository, selected)?;
            }
            let (final_base, final_base_info) = self.open_git_publication_parent(publication)?;
            if final_base_info.ident != base_info.ident {
                return Err(Error::Changed);
            }
            let final_parent = verify_git_target_parent(
                &final_base,
                &publication.final_file.parent_suffix,
                &created_dirs,
            )?;
            if info_of(final_parent.as_raw_handle())?.ident != target_parent_identity {
                return Err(Error::Changed);
            }
            if publication.final_file.parent_suffix.is_empty() {
                self.check_git_target_precondition(publication, preceding)?;
            } else if git_target_exists(final_parent.as_raw_handle(), &target_name)? {
                return Err(Error::Changed);
            }
            check_git_lock_identity(
                target_parent.as_raw_handle(),
                &lock_name,
                lock.as_raw_handle(),
                lock_info.ident,
            )?;
            check_git_named_file_security(
                target_parent.as_raw_handle(),
                &target_name,
                source_security.as_ref(),
            )?;
            let lock_security = git_file_security(lock.as_raw_handle())?;
            if published_security.as_ref() != Some(&lock_security)
                || hash_git_file(&mut lock_file, publication.final_file.bytes.len())?
                    != publication_digest
            {
                return Err(Error::Changed);
            }
            self.check_git_target_precondition(publication, preceding)?;
            if let Some((repository, repository_preconditions, selected)) = desktop_selected {
                self.check_git_desktop_repository(
                    repository,
                    publication.git_dir,
                    publication.common_dir,
                    repository_preconditions,
                    info_creation_guard.as_ref(),
                )?;
                self.check_git_desktop_selected(repository, selected)?;
            }
            let lock_rename_handle = lock_temp
                .open_publish_handle()
                .map_err(git_native_security_error)?;
            if rename_replace(
                lock_rename_handle,
                current_parent.as_raw_handle(),
                &target_name,
            )
            .is_err()
            {
                publication_visible = true;
                return Ok(GitPublishOutcome::UncertainAfterFinalRename);
            }
            if lock_temp.detach_published().is_err() {
                publication_visible = true;
                return Ok(GitPublishOutcome::UncertainAfterFinalRename);
            }
            publication_visible = true;
            let Ok((visible_base, visible_base_info)) =
                self.open_git_publication_parent(publication)
            else {
                return Ok(GitPublishOutcome::UncertainAfterFinalRename);
            };
            if visible_base_info.ident != base_info.ident {
                return Ok(GitPublishOutcome::UncertainAfterFinalRename);
            }
            let Ok(visible_parent) = verify_git_target_parent(
                &visible_base,
                &publication.final_file.parent_suffix,
                &created_dirs,
            ) else {
                return Ok(GitPublishOutcome::UncertainAfterFinalRename);
            };
            let Ok(visible_parent_info) = info_of(visible_parent.as_raw_handle()) else {
                return Ok(GitPublishOutcome::UncertainAfterFinalRename);
            };
            if visible_parent_info.ident != target_parent_identity {
                return Ok(GitPublishOutcome::UncertainAfterFinalRename);
            }
            if check_git_lock_identity(
                visible_parent.as_raw_handle(),
                &target_name,
                lock.as_raw_handle(),
                lock_info.ident,
            )
            .is_err()
                || sync_git_directory(visible_parent.as_raw_handle()).is_err()
            {
                return Ok(GitPublishOutcome::UncertainAfterFinalRename);
            }
            if git_file_security(lock.as_raw_handle()).ok().as_ref() != published_security.as_ref()
                || hash_git_file(&mut lock_file, publication.final_file.bytes.len()).ok()
                    != Some(publication_digest)
            {
                return Ok(GitPublishOutcome::UncertainAfterFinalRename);
            }
            self.touch(visible_parent_info.ident);
            self.touch(common_info.ident);
            Ok(GitPublishOutcome::Published)
        })();
        let mut work = match work {
            Err(_) if publication_visible => Ok(GitPublishOutcome::UncertainAfterFinalRename),
            other => other,
        };
        let mut produced_guard = None;
        if matches!(&work, Ok(GitPublishOutcome::Published)) && capture_guard {
            let captured = guard_file.take().map_or(Err(Error::Changed), |file| {
                self.capture_git_published_guard(
                    publication,
                    target_parent.as_raw_handle(),
                    file,
                    content_digest,
                )
            });
            match captured {
                Ok(guard) => produced_guard = Some(guard),
                Err(_) => work = Ok(GitPublishOutcome::UncertainAfterFinalRename),
            }
        }
        drop(lock_file);
        if !publication_visible {
            cleanup_created_git_dirs(&base_handle, &created_dirs);
        }
        work.map(|outcome| (outcome, produced_guard))
    }

    /// Publishes a prepared fast-forward worktree/index/ref update while
    /// holding the same FileRoot mutation barrier used by Explorer writes.
    #[doc(hidden)]
    pub fn publish_git_pull(
        &self,
        publication: &GitPullPublication,
        mut continue_check: impl FnMut() -> bool,
    ) -> Result<GitPublishOutcome> {
        let _broker_scope = BrokerOperationScope::enter();
        publication.validate().map_err(|_| Error::Invalid)?;
        if publication
            .files
            .iter()
            .any(|file| file.kind == GitPullNodeKind::Symlink)
        {
            // Reparse-point creation is intentionally unsupported until a
            // descriptor-relative, privilege-independent implementation is
            // available for this platform.
            return Err(Error::Unsupported);
        }
        let _guard = self.write.lock().map_err(|_| Error::Limit)?;
        let first = &publication.metadata[0];
        for metadata in &publication.metadata {
            metadata.validate().map_err(|_| Error::Invalid)?;
            self.require_git_dir(metadata.git_dir)?;
            self.require_git_dir(metadata.common_dir)?;
            self.validate_git_target(metadata)?;
            self.check_git_preconditions(&metadata.preconditions)?;
            self.check_git_precondition(&metadata.final_file.expected)?;
        }
        let mut pull_security = HashMap::<Vec<Vec<u8>>, Option<GitFileSecurity>>::new();
        for file in &publication.files {
            self.validate_pull_worktree_path(file)?;
            self.check_git_pull_precondition(&file.expected, true)?;
            if file.contents.is_some() {
                pull_security.insert(
                    file.path.clone(),
                    self.capture_git_pull_file_security(file)?,
                );
            }
        }
        if !continue_check() {
            return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
        }

        // Install all referenced objects before changing the worktree. The
        // ordered metadata publishers repeat object verification when they
        // replace the index and refs later in the batch.
        let (common_handle, _) = self.open_git_directory(first.common_dir)?;
        let (objects_handle, _) = open_git_child_dir(common_handle.as_raw_handle(), b"objects")?;
        for object in &first.objects {
            if !continue_check() {
                return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
            }
            let hex = object.object_id.as_bytes();
            let (prefix, suffix) = hex.split_at(2);
            let (prefix_handle, _) =
                open_or_create_git_child_dir(objects_handle.as_raw_handle(), prefix)?;
            if let Err(error) = install_git_object(
                prefix_handle.as_raw_handle(),
                suffix,
                &object.bytes,
                &mut continue_check,
            ) {
                if error == Error::Changed && !continue_check() {
                    return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
                }
                return Err(error);
            }
        }

        let mut created_directories = Vec::<PullCreatedDir>::new();
        let mut created_identities = HashMap::<Vec<Vec<u8>>, Ident>::new();
        let mut staged = Vec::<StagedPullFile>::with_capacity(publication.files.len());
        let mut visible = false;
        let work = (|| -> Result<GitPublishOutcome> {
            self.check_git_preconditions(&first.preconditions)?;
            for source in publication
                .files
                .iter()
                .filter(|file| file.contents.is_none() && file.kind == GitPullNodeKind::File)
            {
                if !continue_check() {
                    return Ok(if visible {
                        GitPublishOutcome::UncertainAfterFinalRename
                    } else {
                        GitPublishOutcome::AbortedBeforeFinalRename
                    });
                }
                if !source.parent_suffix.is_empty() {
                    return Err(Error::Invalid);
                }
                self.check_git_pull_precondition(&source.expected, true)?;
                let parent_prefix_len = source.path.len().checked_sub(1).ok_or(Error::Invalid)?;
                let chain = self.chain(source.parent)?;
                if chain
                    .iter()
                    .map(|(name, _)| name)
                    .ne(source.path[..parent_prefix_len].iter())
                {
                    return Err(Error::Protected);
                }
                let (parent, _) = self.open_dir(source.parent)?;
                let name = component(&source.name)?;
                let expected_ident = source
                    .expected
                    .entry
                    .map(|entry| self.node(entry).map(|node| node.2))
                    .transpose()?;
                let handle = open_relative(
                    parent.as_raw_handle(),
                    &name,
                    DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                    FILE_OPEN,
                    FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | SYNC,
                    FILE_ATTRIBUTE_NORMAL,
                    false,
                )?;
                let info = info_of(handle.as_raw_handle())?;
                if kind_of(&info) != Kind::File
                    || info.nlink != 1
                    || expected_ident != Some(info.ident)
                {
                    return Err(Error::Changed);
                }
                if !continue_check() {
                    return Ok(if visible {
                        GitPublishOutcome::UncertainAfterFinalRename
                    } else {
                        GitPublishOutcome::AbortedBeforeFinalRename
                    });
                }
                if delete_entry(handle.as_raw_handle()).is_err() {
                    return Err(Error::Changed);
                }
                visible = true;
                if sync_git_directory(parent.as_raw_handle()).is_err() {
                    return Ok(GitPublishOutcome::UncertainAfterFinalRename);
                }
                self.touch(info_of(parent.as_raw_handle())?.ident);
            }

            let mut directories: Vec<_> = publication
                .files
                .iter()
                .filter(|file| file.kind == GitPullNodeKind::Directory)
                .collect();
            directories.sort_by(|left, right| {
                right
                    .path
                    .len()
                    .cmp(&left.path.len())
                    .then_with(|| right.path.cmp(&left.path))
            });
            for source in directories {
                if !continue_check() {
                    return Ok(if visible {
                        GitPublishOutcome::UncertainAfterFinalRename
                    } else {
                        GitPublishOutcome::AbortedBeforeFinalRename
                    });
                }
                if !source.parent_suffix.is_empty() {
                    return Err(Error::Invalid);
                }
                self.check_git_pull_precondition(&source.expected, false)?;
                let parent_prefix_len = source.path.len().checked_sub(1).ok_or(Error::Invalid)?;
                let chain = self.chain(source.parent)?;
                if chain
                    .iter()
                    .map(|(name, _)| name)
                    .ne(source.path[..parent_prefix_len].iter())
                {
                    return Err(Error::Protected);
                }
                let (parent, _) = self.open_dir(source.parent)?;
                let name = component(&source.name)?;
                let expected_ident = source
                    .expected
                    .entry
                    .map(|entry| self.node(entry).map(|node| node.2))
                    .transpose()?;
                let handle = open_relative(
                    parent.as_raw_handle(),
                    &name,
                    DELETE | DIRECTORY_ACCESS,
                    FILE_OPEN,
                    DIRECTORY_OPTIONS,
                    FILE_ATTRIBUTE_NORMAL,
                    false,
                )?;
                let info = info_of(handle.as_raw_handle())?;
                if kind_of(&info) != Kind::Directory || expected_ident != Some(info.ident) {
                    return Err(Error::Changed);
                }
                if !continue_check() {
                    return Ok(if visible {
                        GitPublishOutcome::UncertainAfterFinalRename
                    } else {
                        GitPublishOutcome::AbortedBeforeFinalRename
                    });
                }
                if delete_entry(handle.as_raw_handle()).is_err() {
                    return Err(Error::Changed);
                }
                visible = true;
                if sync_git_directory(parent.as_raw_handle()).is_err() {
                    return Ok(GitPublishOutcome::UncertainAfterFinalRename);
                }
                self.touch(info_of(parent.as_raw_handle())?.ident);
            }

            for source in publication
                .files
                .iter()
                .filter(|file| file.contents.is_some())
            {
                if !continue_check() {
                    return Ok(if visible {
                        GitPublishOutcome::UncertainAfterFinalRename
                    } else {
                        GitPublishOutcome::AbortedBeforeFinalRename
                    });
                }
                let parent_prefix_len = source
                    .path
                    .len()
                    .checked_sub(source.parent_suffix.len() + 1)
                    .ok_or(Error::Invalid)?;
                let parent_chain = self.chain(source.parent)?;
                if parent_chain
                    .iter()
                    .map(|(name, _)| name)
                    .ne(source.path[..parent_prefix_len].iter())
                {
                    return Err(Error::Protected);
                }
                let (base_handle, _) = self.open_dir(source.parent)?;
                let mut parent_handle = base_handle.try_clone().map_err(map_os)?;
                let mut full_parent_path = source.path[..parent_prefix_len].to_vec();
                for component_name in &source.parent_suffix {
                    if !continue_check() {
                        return Ok(if visible {
                            GitPublishOutcome::UncertainAfterFinalRename
                        } else {
                            GitPublishOutcome::AbortedBeforeFinalRename
                        });
                    }
                    let wide = component(component_name)?;
                    full_parent_path.push(component_name.clone());
                    if let Some(expected_identity) = created_identities.get(&full_parent_path) {
                        let (child, info) =
                            open_git_child_dir(parent_handle.as_raw_handle(), component_name)?;
                        if info.ident != *expected_identity {
                            return Err(Error::Changed);
                        }
                        parent_handle = child;
                        continue;
                    }
                    let child = open_relative(
                        parent_handle.as_raw_handle(),
                        &wide,
                        DELETE | GIT_DIRECTORY_ACCESS | READ_CONTROL | WRITE_DAC,
                        FILE_CREATE,
                        DIRECTORY_OPTIONS,
                        FILE_ATTRIBUTE_NORMAL,
                        false,
                    )
                    .map_err(|error| {
                        if error == Error::Exists {
                            Error::Changed
                        } else {
                            error
                        }
                    })?;
                    let info = info_of(child.as_raw_handle())?;
                    if kind_of(&info) != Kind::Directory {
                        return Err(Error::Changed);
                    }
                    native_owner_only_directory_dacl(child.as_raw_handle())?;
                    created_directories.push(PullCreatedDir {
                        parent: parent_handle.try_clone().map_err(map_os)?,
                        identity: info.ident,
                        child: child.try_clone().map_err(map_os)?,
                    });
                    created_identities.insert(full_parent_path.clone(), info.ident);
                    visible = true;
                    sync_git_directory(parent_handle.as_raw_handle())?;
                    self.touch(info_of(parent_handle.as_raw_handle())?.ident);
                    parent_handle = child;
                }
                let target_name = component(&source.name)?;
                let parent_info = info_of(parent_handle.as_raw_handle())?;
                if kind_of(&parent_info) != Kind::Directory {
                    return Err(Error::Changed);
                }
                let target_parent_identity = parent_info.ident;
                let mut staged_file = StagedPullFile {
                    source: source.clone(),
                    target_parent: parent_handle,
                    target_parent_identity,
                    target_name,
                    temp_name: None,
                    temp_identity: None,
                    temp_handle: None,
                    temp_file: None,
                    broker_temp: None,
                    source_security: pull_security.get(&source.path).cloned().flatten(),
                    published_security: None,
                };
                if let Some(contents) = source.contents.as_ref() {
                    if !continue_check() {
                        return Ok(if visible {
                            GitPublishOutcome::UncertainAfterFinalRename
                        } else {
                            GitPublishOutcome::AbortedBeforeFinalRename
                        });
                    }
                    let temp = native_temp_with_broker(&staged_file.target_parent, None)
                        .map_err(git_native_security_error)?;
                    let wide = temp.name.clone();
                    let handle = temp.handle.try_clone().map_err(map_os)?;
                    let info = info_of(handle.as_raw_handle())?;
                    if kind_of(&info) != Kind::File || info.nlink != 1 {
                        return Err(Error::Protected);
                    }
                    let file_handle = handle.try_clone().map_err(map_os)?;
                    let file = unsafe { File::from_raw_handle(file_handle.into_raw_handle()) };
                    staged_file.temp_name = Some(wide);
                    staged_file.temp_identity = Some(info.ident);
                    staged_file.temp_handle = Some(handle);
                    staged_file.temp_file = Some(file);
                    staged_file.broker_temp = Some(temp);
                    staged.push(staged_file);
                    let item = staged.last_mut().ok_or(Error::Changed)?;
                    let temp_handle = item
                        .temp_handle
                        .as_ref()
                        .ok_or(Error::Changed)?
                        .as_raw_handle();
                    let private_security = native_owner_only_file_security(temp_handle)?;
                    let inherited_security = item
                        .source_security
                        .is_none()
                        .then(|| private_security.clone());
                    if !write_git_bytes(
                        item.temp_file.as_mut().ok_or(Error::Changed)?,
                        contents,
                        &mut continue_check,
                    )? {
                        return Ok(if visible {
                            GitPublishOutcome::UncertainAfterFinalRename
                        } else {
                            GitPublishOutcome::AbortedBeforeFinalRename
                        });
                    }
                    let published_security = if let Some(source) = item.source_security.as_ref() {
                        let (current_source, broker_source) = capture_git_named_file_security(
                            item.target_parent.as_raw_handle(),
                            &item.target_name,
                        )?;
                        if current_source.as_ref() != Some(source) {
                            return Err(Error::Changed);
                        }
                        let metadata_handle =
                            match (broker_source.as_ref(), item.broker_temp.as_ref()) {
                                (Some(capture), Some(temp)) => {
                                    let token =
                                        temp.broker_token.as_ref().ok_or(Error::Unsupported)?;
                                    capture.finalize(token).map_err(git_native_security_error)?;
                                    item.broker_temp
                                        .as_mut()
                                        .ok_or(Error::Changed)?
                                        .open_publish_handle()
                                        .map_err(git_native_security_error)?
                                }
                                (None, Some(temp)) if temp.broker_token.is_some() => {
                                    return Err(Error::Unsupported);
                                }
                                (None, _)
                                    if matches!(
                                        source.extended.audit_sacl,
                                        AuditSacl::Broker(_)
                                    ) =>
                                {
                                    return Err(Error::Changed);
                                }
                                _ => temp_handle,
                            };
                        let actual = apply_git_file_security(metadata_handle, Some(source), false)?;
                        if actual != *source {
                            return Err(Error::Changed);
                        }
                        if git_file_security(metadata_handle)? != actual {
                            return Err(Error::Changed);
                        }
                        actual
                    } else {
                        let inherited = inherited_security.as_ref().ok_or(Error::Changed)?;
                        let actual = git_file_security(temp_handle)?;
                        if actual != *inherited {
                            return Err(Error::Changed);
                        }
                        actual
                    };
                    item.temp_file
                        .as_ref()
                        .ok_or(Error::Changed)?
                        .sync_all()
                        .map_err(map_os)?;
                    let expected_digest: [u8; 32] = Sha256::digest(contents).into();
                    if hash_git_file(
                        item.temp_file.as_mut().ok_or(Error::Changed)?,
                        contents.len(),
                    )? != expected_digest
                    {
                        return Err(Error::Changed);
                    }
                    item.published_security = Some(published_security);
                }
            }

            self.check_git_preconditions(&first.preconditions)?;
            for item in &staged {
                self.recheck_pull_install_target(item, &created_identities)?;
            }
            for item in &mut staged {
                if !continue_check() {
                    return Ok(if visible {
                        GitPublishOutcome::UncertainAfterFinalRename
                    } else {
                        GitPublishOutcome::AbortedBeforeFinalRename
                    });
                }
                self.recheck_pull_install_target(item, &created_identities)?;
                let temp_handle = item.temp_handle.as_ref().ok_or(Error::Changed)?;
                if info_of(temp_handle.as_raw_handle())?.ident
                    != item.temp_identity.ok_or(Error::Changed)?
                {
                    return Err(Error::Changed);
                }
                if !continue_check() {
                    return Ok(if visible {
                        GitPublishOutcome::UncertainAfterFinalRename
                    } else {
                        GitPublishOutcome::AbortedBeforeFinalRename
                    });
                }
                self.recheck_pull_install_target(item, &created_identities)?;
                let temp_security = git_file_security(temp_handle.as_raw_handle())?;
                let contents = item.source.contents.as_ref().ok_or(Error::Changed)?;
                let expected_digest: [u8; 32] = Sha256::digest(contents).into();
                if item.published_security.as_ref() != Some(&temp_security)
                    || hash_git_file(
                        item.temp_file.as_mut().ok_or(Error::Changed)?,
                        contents.len(),
                    )? != expected_digest
                {
                    return Err(Error::Changed);
                }
                check_git_named_file_security(
                    item.target_parent.as_raw_handle(),
                    &item.target_name,
                    item.source_security.as_ref(),
                )?;
                let rename_handle = item
                    .broker_temp
                    .as_mut()
                    .ok_or(Error::Changed)?
                    .open_publish_handle()
                    .map_err(git_native_security_error)?;
                if rename_replace(
                    rename_handle,
                    item.target_parent.as_raw_handle(),
                    &item.target_name,
                )
                .is_err()
                {
                    return Ok(GitPublishOutcome::UncertainAfterFinalRename);
                }
                if item
                    .broker_temp
                    .as_mut()
                    .ok_or(Error::Changed)?
                    .detach_published()
                    .is_err()
                {
                    return Ok(GitPublishOutcome::UncertainAfterFinalRename);
                }
                item.temp_name = None;
                visible = true;
                let contents = item.source.contents.as_ref().ok_or(Error::Changed)?;
                let expected_digest: [u8; 32] = Sha256::digest(contents).into();
                if check_git_named_file_security(
                    item.target_parent.as_raw_handle(),
                    &item.target_name,
                    item.published_security.as_ref(),
                )
                .is_err()
                    || hash_git_file(
                        item.temp_file.as_mut().ok_or(Error::Changed)?,
                        contents.len(),
                    )
                    .ok()
                        != Some(expected_digest)
                {
                    return Ok(GitPublishOutcome::UncertainAfterFinalRename);
                }
                if sync_git_directory(item.target_parent.as_raw_handle()).is_err() {
                    return Ok(GitPublishOutcome::UncertainAfterFinalRename);
                }
                self.touch(info_of(item.target_parent.as_raw_handle())?.ident);
            }

            let mut published_guards = Vec::with_capacity(publication.metadata.len());
            for metadata in &publication.metadata {
                match self.publish_git_locked_batch(
                    metadata,
                    &mut continue_check,
                    &mut published_guards,
                    true,
                    None,
                ) {
                    Ok((GitPublishOutcome::Published, Some(guard))) => {
                        visible = true;
                        published_guards.push(guard);
                    }
                    Ok((GitPublishOutcome::Published, None)) => {
                        visible = true;
                        return Ok(GitPublishOutcome::UncertainAfterFinalRename);
                    }
                    Ok((GitPublishOutcome::AbortedBeforeFinalRename, _)) => {
                        return Ok(if visible {
                            GitPublishOutcome::UncertainAfterFinalRename
                        } else {
                            GitPublishOutcome::AbortedBeforeFinalRename
                        });
                    }
                    Ok((GitPublishOutcome::UncertainAfterFinalRename, _)) => {
                        visible = true;
                        return Ok(GitPublishOutcome::UncertainAfterFinalRename);
                    }
                    Err(error) => {
                        return if visible {
                            Ok(GitPublishOutcome::UncertainAfterFinalRename)
                        } else {
                            Err(error)
                        };
                    }
                }
            }
            Ok(GitPublishOutcome::Published)
        })();
        let work = match work {
            Err(_) if visible => Ok(GitPublishOutcome::UncertainAfterFinalRename),
            other => other,
        };

        for item in &staged {
            if let (Some(name), Some(handle), Some(identity)) = (
                item.temp_name.as_ref(),
                item.temp_handle.as_ref(),
                item.temp_identity,
            ) {
                if open_attributes(item.target_parent.as_raw_handle(), name)
                    .and_then(|(entry, _)| info_of(entry.as_raw_handle()))
                    .is_ok_and(|info| info.ident == identity)
                {
                    let _ = delete_entry(handle.as_raw_handle());
                }
            }
        }

        if !visible {
            for created in created_directories.iter().rev() {
                if info_of(created.child.as_raw_handle())
                    .is_ok_and(|info| info.ident == created.identity)
                {
                    let _ = delete_entry(created.child.as_raw_handle());
                    let _ = sync_git_directory(created.parent.as_raw_handle());
                    self.touch(
                        info_of(created.parent.as_raw_handle())
                            .map(|info| info.ident)
                            .unwrap_or(created.identity),
                    );
                }
            }
        }
        work
    }

    fn validate_pull_worktree_path(&self, file: &GitPullFile) -> Result<()> {
        if file.path.iter().any(|component| is_git_name(component)) {
            return Err(Error::Protected);
        }
        let parent_prefix_len = file
            .path
            .len()
            .checked_sub(file.parent_suffix.len() + 1)
            .ok_or(Error::Invalid)?;
        let chain = self.chain(file.parent)?;
        if chain
            .iter()
            .map(|(name, _)| name)
            .ne(file.path[..parent_prefix_len].iter())
        {
            return Err(Error::Protected);
        }
        Ok(())
    }

    fn capture_git_pull_file_security(
        &self,
        file: &GitPullFile,
    ) -> Result<Option<GitFileSecurity>> {
        let Some(entry) = file.expected.entry else {
            return Ok(None);
        };
        if !file.parent_suffix.is_empty() {
            return Err(Error::Changed);
        }
        if file.expected.kind != Some(GitPullNodeKind::File) || file.kind != GitPullNodeKind::File {
            return Err(Error::Unsupported);
        }
        let (recorded_parent, recorded_name, _) = self.node(entry)?;
        if recorded_parent != Some(file.parent) || recorded_name != file.name {
            return Err(Error::Changed);
        }
        let (parent, _) = self.open_dir(file.parent)?;
        let name = component(&file.name)?;
        let security =
            git_named_file_security(parent.as_raw_handle(), &name)?.ok_or(Error::Changed)?;
        if security.attributes & FILE_ATTRIBUTE_READONLY != 0 {
            return Err(Error::Protected);
        }
        Ok(Some(security))
    }

    fn recheck_pull_install_target(
        &self,
        item: &StagedPullFile,
        created: &HashMap<Vec<Vec<u8>>, Ident>,
    ) -> Result<()> {
        let prefix_len = item
            .source
            .path
            .len()
            .checked_sub(item.source.parent_suffix.len() + 1)
            .ok_or(Error::Invalid)?;
        let (base, _) = self.open_dir(item.source.parent)?;
        let mut current = base.try_clone().map_err(map_os)?;
        let mut full_path = item.source.path[..prefix_len].to_vec();
        for component_name in &item.source.parent_suffix {
            full_path.push(component_name.clone());
            let expected = created.get(&full_path).ok_or(Error::Changed)?;
            let (child, info) = open_git_child_dir(current.as_raw_handle(), component_name)?;
            if info.ident != *expected {
                return Err(Error::Changed);
            }
            current = child;
        }
        if info_of(current.as_raw_handle())?.ident != item.target_parent_identity {
            return Err(Error::Changed);
        }
        if item.source.parent_suffix.is_empty()
            && item.source.expected.kind == Some(GitPullNodeKind::File)
        {
            self.check_git_pull_precondition(&item.source.expected, true)?;
        } else {
            match open_attributes(item.target_parent.as_raw_handle(), &item.target_name) {
                Err(Error::NotFound) => {}
                Ok(_) => return Err(Error::Changed),
                Err(error) => return Err(error),
            }
        }
        check_git_named_file_security(
            item.target_parent.as_raw_handle(),
            &item.target_name,
            item.source_security.as_ref(),
        )?;
        Ok(())
    }

    fn check_git_pull_precondition(
        &self,
        value: &GitPullPrecondition,
        check_revision: bool,
    ) -> Result<()> {
        let (parent, _) = self.open_dir(value.parent)?;
        let name = component(&value.name)?;
        match (value.entry, value.kind) {
            (Some(entry), Some(expected_kind)) => {
                let (recorded_parent, recorded_name, expected_ident) = self.node(entry)?;
                if recorded_parent != Some(value.parent) || recorded_name != value.name {
                    return Err(Error::Changed);
                }
                let (_leaf, info) = open_attributes(parent.as_raw_handle(), &name)?;
                let actual_kind = match kind_of(&info) {
                    Kind::File => GitPullNodeKind::File,
                    Kind::Directory => GitPullNodeKind::Directory,
                    Kind::Symlink => GitPullNodeKind::Symlink,
                    Kind::Other => return Err(Error::Changed),
                };
                if info.ident != expected_ident
                    || actual_kind != expected_kind
                    || (actual_kind == GitPullNodeKind::File && info.nlink != 1)
                {
                    return Err(Error::Changed);
                }
                if check_revision {
                    self.check_revision(&info, value.revision.as_deref())?;
                }
                Ok(())
            }
            (None, None) if value.revision.is_none() => {
                match open_attributes(parent.as_raw_handle(), &name) {
                    Err(Error::NotFound) => Ok(()),
                    Ok(_) => Err(Error::Changed),
                    Err(error) => Err(error),
                }
            }
            _ => Err(Error::Invalid),
        }
    }

    fn validate_git_target(&self, publication: &GitPublication) -> Result<()> {
        let final_file = &publication.final_file;
        match &final_file.target {
            GitFinalTarget::Index | GitFinalTarget::DetachedHead => {
                if final_file.parent != publication.git_dir || !final_file.parent_suffix.is_empty()
                {
                    return Err(Error::Protected);
                }
            }
            GitFinalTarget::BranchHead { reference }
            | GitFinalTarget::RemoteTrackingHead { reference } => {
                match &final_file.target {
                    GitFinalTarget::BranchHead { .. } => {
                        crate::git::validate_branch_reference(reference)
                    }
                    GitFinalTarget::RemoteTrackingHead { .. } => {
                        crate::git::validate_remote_tracking_reference(reference)
                    }
                    _ => unreachable!(),
                }
                .map_err(|_| Error::Invalid)?;
                for part in &final_file.parent_suffix {
                    component(part)?;
                }
                for part in reference {
                    component(part)?;
                }
                let common_chain = self.chain(publication.common_dir)?;
                let parent_chain = self.chain(final_file.parent)?;
                if parent_chain.len() < common_chain.len()
                    || parent_chain[..common_chain.len()] != common_chain
                {
                    return Err(Error::Protected);
                }
                let prefix_len = parent_chain.len() - common_chain.len();
                let reference_parent_len = reference.len() - 1;
                if prefix_len + final_file.parent_suffix.len() != reference_parent_len
                    || parent_chain[common_chain.len()..]
                        .iter()
                        .map(|(name, _)| name)
                        .ne(reference[..prefix_len].iter())
                    || final_file
                        .parent_suffix
                        .iter()
                        .ne(reference[prefix_len..reference_parent_len].iter())
                {
                    return Err(Error::Protected);
                }
            }
            GitFinalTarget::WorktreeIgnore { repository } => {
                if final_file.parent != *repository || !final_file.parent_suffix.is_empty() {
                    return Err(Error::Protected);
                }
                let chain = self.chain(*repository)?;
                if chain.iter().any(|(name, ident)| {
                    is_git_name(name)
                        || (*ident != self.root_ident && self.is_protected_ident(ident))
                }) {
                    return Err(Error::Protected);
                }
                let (_, info) = self.open_dir(*repository)?;
                if kind_of(&info) != Kind::Directory {
                    return Err(Error::Changed);
                }
            }
            GitFinalTarget::LocalExclude { common_dir } => {
                if *common_dir != publication.common_dir {
                    return Err(Error::Protected);
                }
                let common_chain = self.chain(*common_dir)?;
                if final_file.parent_suffix.is_empty() {
                    let info_chain = self.chain(final_file.parent)?;
                    if info_chain.len() != common_chain.len() + 1
                        || info_chain[..common_chain.len()] != common_chain
                        || info_chain.last().map(|(name, _)| name.as_slice()) != Some(b"info")
                    {
                        return Err(Error::Protected);
                    }
                    self.require_git_metadata_parent(final_file.parent)?;
                } else if final_file.parent != *common_dir
                    || final_file.parent_suffix.len() != 1
                    || final_file.parent_suffix.first().map(Vec::as_slice) != Some(b"info")
                    || final_file.expected.entry.is_some()
                {
                    return Err(Error::Protected);
                } else {
                    self.require_git_metadata_parent(*common_dir)?;
                }
            }
        }
        Ok(())
    }

    fn require_git_dir(&self, entry: EntryRef) -> Result<()> {
        if self.owner_metadata.is_some() {
            self.check_owner_git_metadata_binding()?;
            if entry != self.root_entry {
                return Err(Error::Protected);
            }
            let (handle, info) = self.open_dir(entry)?;
            if kind_of(&info) != Kind::Directory
                || info.ident != self.root_ident
                || info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                return Err(Error::Changed);
            }
            let _ = handle;
            return Ok(());
        }
        let chain = self.chain(entry)?;
        if !chain.iter().any(|(name, _)| is_git_name(name)) {
            return Err(Error::Protected);
        }
        let (handle, info) = self.open_dir(entry)?;
        if kind_of(&info) != Kind::Directory || !self.is_protected_ident(&info.ident) {
            return Err(Error::Protected);
        }
        let _ = handle;
        Ok(())
    }

    fn require_git_metadata_parent(&self, entry: EntryRef) -> Result<()> {
        if self.owner_metadata.is_some() {
            self.check_owner_git_metadata_binding()?;
            let chain = self.chain(entry)?;
            if !(chain.is_empty() || (chain.len() == 1 && chain[0].0.as_slice() == b"info")) {
                return Err(Error::Protected);
            }
            let (handle, info) = self.open_dir(entry)?;
            if kind_of(&info) != Kind::Directory
                || info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                return Err(Error::Changed);
            }
            let _ = handle;
            return Ok(());
        }
        let chain = self.chain(entry)?;
        let Some(git_index) = chain.iter().position(|(name, _)| is_git_name(name)) else {
            return Err(Error::Protected);
        };
        if !chain[..=git_index]
            .iter()
            .any(|(_, ident)| self.is_protected_ident(ident))
        {
            return Err(Error::Protected);
        }
        let (handle, info) = self.open_dir(entry)?;
        if kind_of(&info) != Kind::Directory {
            return Err(Error::Invalid);
        }
        let _ = handle;
        Ok(())
    }

    fn check_git_preconditions(&self, values: &[GitFilePrecondition]) -> Result<()> {
        for value in values {
            self.check_git_precondition(value)?;
        }
        Ok(())
    }

    fn check_git_preconditions_with_published(
        &self,
        values: &[GitFilePrecondition],
        preceding: &mut [GitPublishedGuard],
    ) -> Result<()> {
        self.check_git_preconditions_with_current(values, preceding, None)
    }

    fn check_git_preconditions_with_current(
        &self,
        values: &[GitFilePrecondition],
        preceding: &mut [GitPublishedGuard],
        current: Option<(&GitPublication, &OwnedHandle, &[CreatedGitDir])>,
    ) -> Result<()> {
        let check_current = || -> Result<()> {
            if let Some((publication, base, directories)) = current {
                if !publication.final_file.parent_suffix.is_empty() {
                    let (fresh, info) = self.open_git_directory(publication.final_file.parent)?;
                    if info.ident != info_of(base.as_raw_handle())?.ident {
                        return Err(Error::Changed);
                    }
                    verify_git_target_parent(
                        &fresh,
                        &publication.final_file.parent_suffix,
                        directories,
                    )?;
                }
            }
            Ok(())
        };
        check_current()?;
        for value in values {
            let current_prefix = current.is_some_and(|(publication, _, _)| {
                !publication.final_file.parent_suffix.is_empty()
                    && value == &publication.final_file.expected
                    && value.entry.is_none()
                    && value.revision.is_none()
            });
            let replaced = preceding.iter().any(|guard| {
                if guard.parent_suffix.is_empty() {
                    value.parent == guard.base && value.name == guard.target_name
                } else {
                    value.parent == guard.base
                        && value.entry.is_none()
                        && value.revision.is_none()
                        && value.name == guard.parent_suffix[0]
                }
            });
            if !replaced && !current_prefix {
                self.check_git_precondition(value)?;
            }
        }
        for guard in preceding {
            self.check_git_published_guard(guard)?;
        }
        check_current()
    }

    fn check_git_precondition_with_published(
        &self,
        value: &GitFilePrecondition,
        preceding: &mut [GitPublishedGuard],
    ) -> Result<()> {
        let replaced = preceding.iter().any(|guard| {
            if guard.parent_suffix.is_empty() {
                value.parent == guard.base && value.name == guard.target_name
            } else {
                value.parent == guard.base
                    && value.entry.is_none()
                    && value.revision.is_none()
                    && value.name == guard.parent_suffix[0]
            }
        });
        if replaced {
            for guard in preceding {
                self.check_git_published_guard(guard)?;
            }
            Ok(())
        } else {
            self.check_git_precondition(value)
        }
    }

    fn check_git_published_guard(&self, guard: &mut GitPublishedGuard) -> Result<()> {
        if guard.parent_suffix.len() != guard.parent_identities.len() {
            return Err(Error::Changed);
        }
        let (mut parent, _) = self.open_git_directory(guard.base)?;
        for (component_name, expected) in guard
            .parent_suffix
            .iter()
            .zip(guard.parent_identities.iter())
        {
            let (next, info) = open_git_child_dir(parent.as_raw_handle(), component_name)?;
            if info.ident != *expected {
                return Err(Error::Changed);
            }
            parent = next;
        }

        let (path_file, path_info) =
            open_attributes(parent.as_raw_handle(), &component(&guard.target_name)?)?;
        let handle_info = info_of(guard.file.as_raw_handle())?;
        if kind_of(&path_info) != Kind::File
            || kind_of(&handle_info) != Kind::File
            || path_info.nlink != 1
            || handle_info.nlink != 1
            || path_info.ident != guard.file_identity
            || handle_info.ident != guard.file_identity
            || self.revision(&path_info) != guard.revision
            || self.revision(&handle_info) != guard.revision
            || git_named_file_security(parent.as_raw_handle(), &component(&guard.target_name)?)?
                .as_ref()
                != Some(&guard.security)
            || git_file_security(guard.file.as_raw_handle())? != guard.security
            || hash_git_file(&mut guard.file, guard.content_len)? != guard.content_digest
        {
            return Err(Error::Changed);
        }
        drop(path_file);
        Ok(())
    }

    fn capture_git_published_guard(
        &self,
        publication: &GitPublication,
        target_parent_handle: RawHandle,
        mut file: File,
        content_digest: [u8; 32],
    ) -> Result<GitPublishedGuard> {
        let final_file = &publication.final_file;
        let (mut parent, _) = self.open_git_directory(final_file.parent)?;
        let mut parent_identities = Vec::with_capacity(final_file.parent_suffix.len());
        for component_name in &final_file.parent_suffix {
            let (next, info) = open_git_child_dir(parent.as_raw_handle(), component_name)?;
            parent_identities.push(info.ident);
            parent = next;
        }
        let target_parent_identity = info_of(parent.as_raw_handle())?.ident;
        let installed_parent_identity = info_of(target_parent_handle)?.ident;
        if target_parent_identity != installed_parent_identity {
            return Err(Error::Changed);
        }

        let target_name = final_file.target.name().to_vec();
        let (_path_file, path_info) =
            open_attributes(parent.as_raw_handle(), &component(&target_name)?)?;
        let handle_info = info_of(file.as_raw_handle())?;
        if kind_of(&path_info) != Kind::File
            || kind_of(&handle_info) != Kind::File
            || path_info.nlink != 1
            || handle_info.nlink != 1
            || path_info.ident != handle_info.ident
            || self.revision(&path_info) != self.revision(&handle_info)
            || git_named_file_security(parent.as_raw_handle(), &component(&target_name)?)?.as_ref()
                != Some(&git_file_security(file.as_raw_handle())?)
            || hash_git_file(&mut file, final_file.bytes.len())? != content_digest
        {
            return Err(Error::Changed);
        }
        let security = git_file_security(file.as_raw_handle())?;
        Ok(GitPublishedGuard {
            base: final_file.parent,
            parent_suffix: final_file.parent_suffix.clone(),
            parent_identities,
            target_name,
            file_identity: handle_info.ident,
            revision: self.revision(&handle_info),
            content_digest,
            content_len: final_file.bytes.len(),
            security,
            file,
        })
    }

    fn check_git_worktree_preconditions(&self, values: &[GitWorktreePrecondition]) -> Result<()> {
        for value in values {
            let (parent_handle, _) = self.open_dir(value.parent)?;
            match value.entry {
                Some(entry) => {
                    let (recorded_parent, recorded_name, _) = self.node(entry)?;
                    if recorded_parent != Some(value.parent) || recorded_name != value.name {
                        return Err(Error::Changed);
                    }
                    let (_handle, _name, info) = self.open_leaf(entry)?;
                    if kind_of(&info) != Kind::File || info.nlink != 1 {
                        return Err(Error::Changed);
                    }
                    self.check_revision(&info, value.revision.as_deref())?;
                }
                None => {
                    match open_attributes(parent_handle.as_raw_handle(), &component(&value.name)?) {
                        Err(Error::NotFound) => {}
                        Ok(_) => return Err(Error::Changed),
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        Ok(())
    }

    fn open_git_publication_parent(
        &self,
        publication: &GitPublication,
    ) -> Result<(OwnedHandle, Info)> {
        if matches!(
            &publication.final_file.target,
            GitFinalTarget::WorktreeIgnore { .. }
        ) {
            self.open_dir(publication.final_file.parent)
        } else {
            self.open_git_directory(publication.final_file.parent)
        }
    }

    fn check_git_desktop_selected(
        &self,
        repository: EntryRef,
        selected: &GitPullPrecondition,
    ) -> Result<()> {
        if !crate::git::valid_component(&selected.name)
            || is_git_name(&selected.name)
            || is_private_staging_name(&selected.name)
            || selected.entry.is_some() != selected.revision.is_some()
            || selected.entry.is_some() != selected.kind.is_some()
        {
            return Err(Error::Invalid);
        }
        let repository_chain = self.chain(repository)?;
        let parent_chain = self.chain(selected.parent)?;
        if parent_chain.len() < repository_chain.len()
            || parent_chain[..repository_chain.len()] != repository_chain
            || parent_chain.iter().any(|(name, ident)| {
                is_git_name(name)
                    || is_private_staging_name(name)
                    || (*ident != self.root_ident && self.is_protected_ident(ident))
            })
        {
            return Err(Error::Protected);
        }
        let (parent, _) = self.open_dir(selected.parent)?;
        let name = component(&selected.name)?;
        match selected.entry {
            Some(entry) => {
                let (recorded_parent, recorded_name, _) = self.node(entry)?;
                if recorded_parent != Some(selected.parent) || recorded_name != selected.name {
                    return Err(Error::Changed);
                }
                let (_parent, _leaf_name, info) = self.open_leaf(entry)?;
                let actual_kind = match kind_of(&info) {
                    Kind::File => GitPullNodeKind::File,
                    Kind::Directory => GitPullNodeKind::Directory,
                    Kind::Symlink => GitPullNodeKind::Symlink,
                    Kind::Other => return Err(Error::Protected),
                };
                if Some(actual_kind) != selected.kind {
                    return Err(Error::Changed);
                }
                self.check_revision(&info, selected.revision.as_deref())
            }
            None => {
                if selected.kind.is_some() {
                    return Err(Error::Invalid);
                }
                match open_attributes(parent.as_raw_handle(), &name) {
                    Err(Error::NotFound) => Ok(()),
                    Ok(_) => Err(Error::Changed),
                    Err(error) => Err(error),
                }
            }
        }
    }

    fn check_git_desktop_repository(
        &self,
        repository: EntryRef,
        git_dir: EntryRef,
        common_dir: EntryRef,
        preconditions: &[GitPullPrecondition],
        info_guard: Option<&GitInfoCreationGuard>,
    ) -> Result<()> {
        if preconditions.is_empty() || preconditions.len() > 2 {
            return Err(Error::Invalid);
        }
        let marker = &preconditions[0];
        if marker.parent != repository
            || marker.name != b".git"
            || !matches!(
                marker.kind,
                Some(GitPullNodeKind::File | GitPullNodeKind::Directory)
            )
        {
            return Err(Error::Invalid);
        }
        if let Some(guard) = info_guard {
            self.check_git_desktop_marker_after_info_creation(marker, guard)?;
        } else {
            self.check_git_desktop_marker(marker)?;
        }
        if marker.kind == Some(GitPullNodeKind::Directory) {
            let repository_chain = self.chain(repository)?;
            let git_chain = self.chain(git_dir)?;
            if git_chain.len() != repository_chain.len() + 1
                || git_chain[..repository_chain.len()] != repository_chain
                || git_chain.last().map(|(name, _)| name.as_slice()) != Some(b".git")
            {
                return Err(Error::Protected);
            }
        }
        if common_dir == git_dir {
            if preconditions.len() != 1 {
                return Err(Error::Invalid);
            }
        } else {
            let common_marker = preconditions.get(1).ok_or(Error::Invalid)?;
            if common_marker.parent != git_dir
                || common_marker.name != b"commondir"
                || common_marker.kind != Some(GitPullNodeKind::File)
            {
                return Err(Error::Invalid);
            }
            self.check_git_desktop_marker(common_marker)?;
        }
        Ok(())
    }

    fn git_info_creation_baseline(
        &self,
        publication: &GitPublication,
        desktop_selected: Option<(EntryRef, &[GitPullPrecondition], &GitPullPrecondition)>,
        parent: &OwnedHandle,
        parent_identity: Ident,
    ) -> Result<Option<GitInfoCreationBaseline>> {
        let Some((_, repository_preconditions, _)) = desktop_selected else {
            return Ok(None);
        };
        if !matches!(
            publication.final_file.target,
            GitFinalTarget::LocalExclude { .. }
        ) || publication.git_dir != publication.common_dir
            || publication.final_file.parent != publication.common_dir
            || publication.final_file.parent_suffix.as_slice() != [b"info".to_vec()]
        {
            return Ok(None);
        }
        let marker = repository_preconditions.first().ok_or(Error::Invalid)?;
        if marker.kind != Some(GitPullNodeKind::Directory)
            || marker.entry != Some(publication.git_dir)
        {
            return Ok(None);
        }
        self.check_git_desktop_marker(marker)?;
        let (_, _, marker_identity) = self.node(marker.entry.ok_or(Error::Invalid)?)?;
        let parent_info = info_of(parent.as_raw_handle())?;
        if kind_of(&parent_info) != Kind::Directory
            || parent_info.ident != parent_identity
            || parent_identity != marker_identity
        {
            return Err(Error::Changed);
        }
        let entries = git_directory_census(parent.as_raw_handle())?;
        if entries.iter().any(|(name, _)| name == b"info") {
            // Do not adopt a pre-existing or raced-in directory under this
            // narrowly scoped own-create revision allowance.
            return Err(Error::Changed);
        }
        Ok(Some(GitInfoCreationBaseline {
            marker_entry: marker.entry.ok_or(Error::Invalid)?,
            marker_revision: marker.revision.clone().ok_or(Error::Invalid)?,
            parent_identity,
            entries,
        }))
    }

    fn finish_git_info_creation(
        &self,
        parent: &OwnedHandle,
        created: &[CreatedGitDir],
        baseline: GitInfoCreationBaseline,
    ) -> Result<GitInfoCreationGuard> {
        if created.len() != 1 || created[0].name != b"info" || !created[0].created_here {
            return Err(Error::Changed);
        }
        let parent_info = info_of(parent.as_raw_handle())?;
        if kind_of(&parent_info) != Kind::Directory || parent_info.ident != baseline.parent_identity
        {
            return Err(Error::Changed);
        }
        let (info_dir, info_info) =
            open_git_child_dir_for_security(parent.as_raw_handle(), b"info")?;
        if info_info.ident != created[0].identity {
            return Err(Error::Changed);
        }
        verify_native_owner_only_directory_dacl(info_dir.as_raw_handle())?;
        let mut expected_entries = baseline.entries;
        expected_entries.push((b"info".to_vec(), info_info.ident));
        expected_entries.sort_by(|left, right| left.0.cmp(&right.0));
        if git_directory_census(parent.as_raw_handle())? != expected_entries {
            return Err(Error::Changed);
        }
        let (_marker_parent, _marker_name, marker_info) = self.open_leaf(baseline.marker_entry)?;
        if kind_of(&marker_info) != Kind::Directory
            || self.node(baseline.marker_entry)?.2 != baseline.parent_identity
        {
            return Err(Error::Changed);
        }
        Ok(GitInfoCreationGuard {
            marker_entry: baseline.marker_entry,
            marker_revision: baseline.marker_revision,
            parent: parent.try_clone().map_err(map_os)?,
            parent_identity: baseline.parent_identity,
            revision_after_creation: self.revision(&marker_info),
            entries_after_creation: expected_entries,
            info_identity: info_info.ident,
        })
    }

    fn check_git_desktop_marker_after_info_creation(
        &self,
        marker: &GitPullPrecondition,
        guard: &GitInfoCreationGuard,
    ) -> Result<()> {
        if marker.entry != Some(guard.marker_entry)
            || marker.revision.as_deref() != Some(guard.marker_revision.as_str())
            || marker.kind != Some(GitPullNodeKind::Directory)
        {
            return Err(Error::Changed);
        }
        let (recorded_parent, recorded_name, _) = self.node(guard.marker_entry)?;
        if recorded_parent != Some(marker.parent) || recorded_name != marker.name {
            return Err(Error::Changed);
        }
        let (_parent, _name, marker_info) = self.open_leaf(guard.marker_entry)?;
        let parent_info = info_of(guard.parent.as_raw_handle())?;
        if kind_of(&marker_info) != Kind::Directory
            || marker_info.ident != guard.parent_identity
            || parent_info.ident != guard.parent_identity
            || self.revision(&marker_info) != guard.revision_after_creation
        {
            return Err(Error::Changed);
        }
        let (info_dir, info_info) =
            open_git_child_dir_for_security(guard.parent.as_raw_handle(), b"info")?;
        if info_info.ident != guard.info_identity {
            return Err(Error::Changed);
        }
        verify_native_owner_only_directory_dacl(info_dir.as_raw_handle())?;
        if git_directory_census(guard.parent.as_raw_handle())? != guard.entries_after_creation {
            return Err(Error::Changed);
        }
        Ok(())
    }

    fn check_git_desktop_marker(&self, marker: &GitPullPrecondition) -> Result<()> {
        if marker.entry.is_some() != marker.revision.is_some()
            || marker.entry.is_some() != marker.kind.is_some()
        {
            return Err(Error::Invalid);
        }
        let entry = marker.entry.ok_or(Error::Invalid)?;
        let (recorded_parent, recorded_name, _) = self.node(entry)?;
        if recorded_parent != Some(marker.parent) || recorded_name != marker.name {
            return Err(Error::Changed);
        }
        let (_parent, _name, info) = self.open_leaf(entry)?;
        let actual_kind = match kind_of(&info) {
            Kind::File => GitPullNodeKind::File,
            Kind::Directory => GitPullNodeKind::Directory,
            Kind::Symlink => GitPullNodeKind::Symlink,
            Kind::Other => return Err(Error::Protected),
        };
        if Some(actual_kind) != marker.kind {
            return Err(Error::Changed);
        }
        if actual_kind == GitPullNodeKind::File && info.nlink != 1 {
            return Err(Error::Protected);
        }
        self.check_revision(&info, marker.revision.as_deref())
    }

    fn check_git_target_precondition(
        &self,
        publication: &GitPublication,
        preceding: &mut [GitPublishedGuard],
    ) -> Result<()> {
        match &publication.final_file.target {
            GitFinalTarget::WorktreeIgnore { repository } => {
                if !preceding.is_empty()
                    || publication.final_file.parent != *repository
                    || publication.final_file.expected.name != b".gitignore"
                {
                    return Err(Error::Protected);
                }
                let value = &publication.final_file.expected;
                let (parent, _) = self.open_dir(value.parent)?;
                let name = component(&value.name)?;
                match value.entry {
                    Some(entry) => {
                        let (recorded_parent, recorded_name, _) = self.node(entry)?;
                        if recorded_parent != Some(value.parent) || recorded_name != value.name {
                            return Err(Error::Changed);
                        }
                        let (_parent, _leaf_name, info) = self.open_leaf(entry)?;
                        if kind_of(&info) != Kind::File || info.nlink != 1 {
                            return Err(Error::Protected);
                        }
                        self.check_revision(&info, value.revision.as_deref())
                    }
                    None => match open_attributes(parent.as_raw_handle(), &name) {
                        Ok(_) => Err(Error::Changed),
                        Err(Error::NotFound) => Ok(()),
                        Err(error) => Err(error),
                    },
                }
            }
            _ => self
                .check_git_precondition_with_published(&publication.final_file.expected, preceding),
        }
    }

    fn check_git_precondition(&self, value: &GitFilePrecondition) -> Result<()> {
        self.require_git_metadata_parent(value.parent)?;
        let (parent, _) = self.open_dir(value.parent)?;
        let name = component(&value.name)?;
        match value.entry {
            Some(entry) => {
                let (recorded_parent, recorded_name, _) = self.node(entry)?;
                if recorded_parent != Some(value.parent) || recorded_name != value.name {
                    return Err(Error::Changed);
                }
                let (_parent, _name, info) = self.open_leaf(entry)?;
                if kind_of(&info) != Kind::File || info.nlink != 1 {
                    return Err(Error::Protected);
                }
                self.check_revision(&info, value.revision.as_deref())
            }
            None => match open_attributes(parent.as_raw_handle(), &name) {
                Ok(_) => Err(Error::Changed),
                Err(Error::NotFound) => Ok(()),
                Err(error) => Err(error),
            },
        }
    }

    fn read_with_binary_policy(
        &self,
        entry: EntryRef,
        expected_revision: Option<&str>,
        offset: u64,
        max_bytes: usize,
        include_binary: bool,
    ) -> Result<(ReadResult, bool)> {
        if self.entry_has_private_staging_name(entry)? {
            return Err(Error::NotFound);
        }
        let max_bytes = max_bytes.clamp(1, MAX_READ);
        let (parent_handle, name, leaf) = self.open_leaf(entry)?;
        match kind_of(&leaf) {
            Kind::File => {}
            // A link is shown as a link; the engine never reads through it.
            Kind::Symlink | Kind::Directory | Kind::Other => return Err(Error::Invalid),
        }
        // Opened as the entry itself; FILE_OPEN_NO_RECALL never hydrates a
        // cloud placeholder.
        let handle = open_relative(
            parent_handle.as_raw_handle(),
            &component(&name)?,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_OPEN_NO_RECALL | SYNC,
            0,
            false,
        )
        .map_err(|e| match e {
            Error::Io(std::io::ErrorKind::PermissionDenied) => e,
            Error::Io(_) | Error::Invalid => Error::Changed,
            other => other,
        })?;
        let info = info_of(handle.as_raw_handle())?;
        if kind_of(&info) != Kind::File || info.ident != leaf.ident {
            return Err(Error::Changed);
        }
        // Checked on the OPEN handle, so a link created after the open above
        // is still caught.
        if info.nlink > 1 {
            return Err(Error::Protected);
        }
        self.check_revision(&info, expected_revision)?;
        let size = info.size;
        let file = std::fs::File::from(handle);
        let mut buffer = vec![0u8; if offset >= size { 0 } else { max_bytes }];
        let mut filled = 0usize;
        while filled < buffer.len() {
            let n = file
                .seek_read(&mut buffer[filled..], offset + filled as u64)
                .map_err(map_os)?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        buffer.truncate(filled);
        let truncated = offset.saturating_add(filled as u64) < size;
        let (encoding, line_endings) = classify(&buffer, offset, truncated);
        let meta = self.meta(entry, &name, &info);
        let bytes = if encoding == Encoding::Binary && !include_binary {
            Vec::new()
        } else {
            buffer
        };
        Ok((
            ReadResult {
                meta,
                encoding,
                line_endings,
                offset,
                bytes,
                truncated: truncated || (encoding == Encoding::Binary && size > 0),
            },
            false,
        ))
    }

    /// Bounded, deterministic breadth-first name search below `parent`. The
    /// cursor is the number of matches already delivered. Never descends into a
    /// reparse point or a `.git` directory.
    pub fn search_names(
        &self,
        parent: EntryRef,
        query: &str,
        cursor: Option<&[u8]>,
        limit: usize,
    ) -> Result<Page> {
        if self.entry_has_private_staging_name(parent)? {
            return Err(Error::NotFound);
        }
        let limit = limit.clamp(1, MAX_PAGE);
        let needle = query.to_lowercase();
        if needle.is_empty() {
            return Err(Error::Invalid);
        }
        let skip = match cursor {
            None => 0u64,
            Some(bytes) => {
                u64::from_le_bytes(<[u8; 8]>::try_from(bytes).map_err(|_| Error::Invalid)?)
            }
        };
        let mut queue = std::collections::VecDeque::from([(parent, 0usize)]);
        let mut visited = 0usize;
        let mut matched = 0u64;
        let mut entries = Vec::new();
        let mut budget_hit = false;
        let mut more = false;
        'walk: while let Some((dir, depth)) = queue.pop_front() {
            let Ok((handle, _)) = self.open_dir(dir) else {
                continue;
            };
            let mut names = read_dir_names(handle.as_raw_handle())?;
            names.sort();
            for name in names {
                if !std::str::from_utf8(&name).is_ok_and(valid_component) {
                    continue;
                }
                if is_private_staging_name(&name) {
                    continue;
                }
                visited += 1;
                if visited > SEARCH_VISIT_LIMIT {
                    budget_hit = true;
                    break 'walk;
                }
                let wide = component(&name)?;
                let Ok((_leaf, info)) = open_attributes(handle.as_raw_handle(), &wide) else {
                    continue;
                };
                let kind = kind_of(&info);
                let is_match = String::from_utf8_lossy(&name)
                    .to_lowercase()
                    .contains(&needle);
                if is_match {
                    if matched >= skip {
                        if entries.len() == limit {
                            more = true;
                            break 'walk;
                        }
                        let id = self.register(dir, &name, info.ident)?;
                        entries.push(self.meta(id, &name, &info));
                    }
                    matched += 1;
                }
                if kind == Kind::Directory && !is_git_name(&name) && depth + 1 < SEARCH_MAX_DEPTH {
                    let id = self.register(dir, &name, info.ident)?;
                    queue.push_back((id, depth + 1));
                }
            }
        }
        let truncated = more || budget_hit;
        Ok(Page {
            next: more.then(|| (skip + entries.len() as u64).to_le_bytes().to_vec()),
            entries,
            truncated,
        })
    }

    // ---- mutations --------------------------------------------------------

    /// True when the directory chain of `entry` passes through `.git` or a
    /// protected identity.
    fn chain_is_protected(&self, entry: EntryRef) -> Result<bool> {
        let registry = self.registry.lock().map_err(|_| Error::Limit)?;
        let mut cursor = entry;
        loop {
            let node = registry.nodes.get(&cursor).ok_or(Error::NotFound)?;
            if cursor != self.root_entry
                && (is_git_name(&node.name) || self.is_protected_ident(&node.ident))
            {
                return Ok(true);
            }
            match node.parent {
                Some(parent) => cursor = parent,
                None => return Ok(false),
            }
        }
    }

    fn open_mutation_parent(
        &self,
        parent: EntryRef,
        parent_revision: &str,
    ) -> Result<(OwnedHandle, Info)> {
        if self.entry_has_private_staging_name(parent)? {
            return Err(Error::Protected);
        }
        if self.chain_is_protected(parent)? {
            return Err(Error::Protected);
        }
        let (handle, info) = self.open_dir(parent)?;
        self.check_revision(&info, Some(parent_revision))?;
        Ok((handle, info))
    }

    fn validate_new_name(name: &[u8]) -> Result<Vec<u16>> {
        if is_git_name(name) || is_private_staging_name(name) {
            return Err(Error::Protected);
        }
        component(name)
    }

    /// Creates an EMPTY regular file; destination must be absent.
    pub fn create_file(
        &self,
        parent: EntryRef,
        parent_revision: &str,
        name: &[u8],
    ) -> Result<Meta> {
        self.create_file_guarded(parent, parent_revision, name, |_| true)
    }

    /// Creates an empty regular file with an owner-local authorization
    /// checkpoint and a final lock-free publication gate. The callback must
    /// not re-enter this FileRoot.
    pub fn create_file_guarded(
        &self,
        parent: EntryRef,
        parent_revision: &str,
        name: &[u8],
        mut check: impl FnMut(LocalNativeFileCheckPhase) -> bool,
    ) -> Result<Meta> {
        let _guard = self.write.lock().map_err(|_| Error::Limit)?;
        let wide = Self::validate_new_name(name)?;
        let (_initial_parent, initial_info) = self.open_mutation_parent(parent, parent_revision)?;
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::BeforeEffect)?;
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::Validation)?;
        let (parent_handle, parent_info) = self.open_mutation_parent(parent, parent_revision)?;
        if parent_info.ident != initial_info.ident {
            return Err(Error::Changed);
        }
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::Publication)?;
        let file = open_relative(
            parent_handle.as_raw_handle(),
            &wide,
            FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | SYNC,
            FILE_ATTRIBUTE_NORMAL,
            false,
        )?;
        let info = info_of(file.as_raw_handle())?;
        self.touch(parent_info.ident);
        let id = self.register(parent, name, info.ident)?;
        Ok(self.meta(id, name, &info))
    }

    pub fn mkdir(&self, parent: EntryRef, parent_revision: &str, name: &[u8]) -> Result<Meta> {
        self.mkdir_guarded(parent, parent_revision, name, |_| true)
    }

    /// Creates a directory with a final lock-free publication gate. The
    /// callback must not re-enter this FileRoot.
    pub fn mkdir_guarded(
        &self,
        parent: EntryRef,
        parent_revision: &str,
        name: &[u8],
        mut check: impl FnMut(LocalNativeFileCheckPhase) -> bool,
    ) -> Result<Meta> {
        let _guard = self.write.lock().map_err(|_| Error::Limit)?;
        let wide = Self::validate_new_name(name)?;
        let (_initial_parent, initial_info) = self.open_mutation_parent(parent, parent_revision)?;
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::BeforeEffect)?;
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::Validation)?;
        let (parent_handle, parent_info) = self.open_mutation_parent(parent, parent_revision)?;
        if parent_info.ident != initial_info.ident {
            return Err(Error::Changed);
        }
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::Publication)?;
        let created = open_relative(
            parent_handle.as_raw_handle(),
            &wide,
            DIRECTORY_ACCESS,
            FILE_CREATE,
            DIRECTORY_OPTIONS,
            FILE_ATTRIBUTE_NORMAL,
            false,
        )?;
        let info = info_of(created.as_raw_handle())?;
        self.touch(parent_info.ident);
        let id = self.register(parent, name, info.ident)?;
        Ok(self.meta(id, name, &info))
    }

    /// Validates the entry about to be changed. Hard-linked regular files and
    /// repository/host metadata are refused.
    fn check_mutable_leaf(&self, name: &[u8], info: &Info, expected_revision: &str) -> Result<()> {
        if is_git_name(name)
            || is_private_staging_name(name)
            || self.is_protected_ident(&info.ident)
        {
            return Err(Error::Protected);
        }
        if kind_of(info) == Kind::File && info.nlink > 1 {
            return Err(Error::Protected);
        }
        self.check_revision(info, Some(expected_revision))
    }

    /// Opens the entry `name` of `parent_handle` for deletion/rename, as the
    /// entry itself (a link is never followed).
    fn open_for_change(
        &self,
        parent_handle: RawHandle,
        name: &[u8],
        recorded: Ident,
    ) -> Result<(OwnedHandle, Info)> {
        let handle = open_relative(
            parent_handle,
            &component(name)?,
            DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT | SYNC,
            0,
            false,
        )?;
        let info = info_of(handle.as_raw_handle())?;
        if info.ident != recorded {
            return Err(Error::Changed);
        }
        Ok((handle, info))
    }

    /// Removes a file, a link (never its target) or an EMPTY directory.
    pub fn remove(
        &self,
        entry: EntryRef,
        revision: &str,
        parent: EntryRef,
        parent_revision: &str,
    ) -> Result<()> {
        self.remove_guarded(entry, revision, parent, parent_revision, None, |_| true)
    }

    /// Removes the exact registered entry after fresh parent/leaf validation
    /// and a final lock-free publication gate. The callback must not re-enter
    /// FileRoot.
    pub fn remove_guarded(
        &self,
        entry: EntryRef,
        revision: &str,
        parent: EntryRef,
        parent_revision: &str,
        expected_source: Option<&crate::desktop::DesktopSourcePrecondition>,
        mut check: impl FnMut(LocalNativeFileCheckPhase) -> bool,
    ) -> Result<()> {
        let _guard = self.write.lock().map_err(|_| Error::Limit)?;
        if entry == self.root_entry {
            return Err(Error::Protected);
        }
        let (node_parent, name, recorded) = self.node(entry)?;
        if node_parent != Some(parent) {
            return Err(Error::Changed);
        }
        let (initial_parent, initial_parent_info) =
            self.open_mutation_parent(parent, parent_revision)?;
        let (initial_leaf, initial_info) =
            self.open_for_change(initial_parent.as_raw_handle(), &name, recorded)?;
        self.check_mutable_leaf(&name, &initial_info, revision)?;
        check_expected_native_source(expected_source, initial_info.ident, kind_of(&initial_info))?;
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::BeforeEffect)?;
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::Validation)?;

        let (parent_handle, parent_info) = self.open_mutation_parent(parent, parent_revision)?;
        if parent_info.ident != initial_parent_info.ident {
            return Err(Error::Changed);
        }
        let (handle, info) =
            self.open_for_change(parent_handle.as_raw_handle(), &name, recorded)?;
        if info.ident != initial_info.ident {
            return Err(Error::Changed);
        }
        self.check_mutable_leaf(&name, &info, revision)?;
        check_expected_native_source(expected_source, info.ident, kind_of(&info))?;
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::Publication)?;
        delete_entry(handle.as_raw_handle())?;
        drop(handle);
        drop(initial_leaf);
        self.touch(parent_info.ident);
        let mut registry = self.registry.lock().map_err(|_| Error::Limit)?;
        registry.nodes.remove(&entry);
        registry.by_name.remove(&(parent, fold(&name)));
        Ok(())
    }

    /// Renames without ever replacing an existing destination.
    #[allow(clippy::too_many_arguments)]
    pub fn rename(
        &self,
        entry: EntryRef,
        revision: &str,
        source_parent: EntryRef,
        source_parent_revision: &str,
        target_parent: EntryRef,
        target_parent_revision: &str,
        name: &[u8],
    ) -> Result<Meta> {
        self.rename_guarded(
            entry,
            revision,
            source_parent,
            source_parent_revision,
            target_parent,
            target_parent_revision,
            name,
            None,
            |_| true,
        )
    }

    /// Renames the exact registered entry without replacement after fresh
    /// validation and a final lock-free publication gate. The callback must
    /// not re-enter this FileRoot.
    #[allow(clippy::too_many_arguments)]
    pub fn rename_guarded(
        &self,
        entry: EntryRef,
        revision: &str,
        source_parent: EntryRef,
        source_parent_revision: &str,
        target_parent: EntryRef,
        target_parent_revision: &str,
        name: &[u8],
        expected_source: Option<&crate::desktop::DesktopSourcePrecondition>,
        mut check: impl FnMut(LocalNativeFileCheckPhase) -> bool,
    ) -> Result<Meta> {
        let _guard = self.write.lock().map_err(|_| Error::Limit)?;
        let target = Self::validate_new_name(name)?;
        if entry == self.root_entry {
            return Err(Error::Protected);
        }
        let (node_parent, old_name, recorded) = self.node(entry)?;
        if node_parent != Some(source_parent) {
            return Err(Error::Changed);
        }
        let (initial_source_dir, initial_source_info) =
            self.open_mutation_parent(source_parent, source_parent_revision)?;
        let (_initial_target_dir, initial_target_info) =
            self.open_mutation_parent(target_parent, target_parent_revision)?;
        let (initial_handle, initial_info) =
            self.open_for_change(initial_source_dir.as_raw_handle(), &old_name, recorded)?;
        self.check_mutable_leaf(&old_name, &initial_info, revision)?;
        check_expected_native_source(expected_source, initial_info.ident, kind_of(&initial_info))?;
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::BeforeEffect)?;
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::Validation)?;

        let (source_dir, source_info) =
            self.open_mutation_parent(source_parent, source_parent_revision)?;
        if source_info.ident != initial_source_info.ident {
            return Err(Error::Changed);
        }
        let (target_dir, target_info) =
            self.open_mutation_parent(target_parent, target_parent_revision)?;
        if target_info.ident != initial_target_info.ident {
            return Err(Error::Changed);
        }
        let (handle, info) =
            self.open_for_change(source_dir.as_raw_handle(), &old_name, recorded)?;
        if info.ident != initial_info.ident {
            return Err(Error::Changed);
        }
        self.check_mutable_leaf(&old_name, &info, revision)?;
        check_expected_native_source(expected_source, info.ident, kind_of(&info))?;
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::Publication)?;
        rename_no_replace(handle.as_raw_handle(), target_dir.as_raw_handle(), &target)?;
        let moved = info_of(handle.as_raw_handle())?;
        drop(handle);
        drop(initial_handle);
        self.touch(source_info.ident);
        self.touch(target_info.ident);
        self.touch(moved.ident);
        let mut registry = self.registry.lock().map_err(|_| Error::Limit)?;
        registry.by_name.remove(&(source_parent, fold(&old_name)));
        if let Some(node) = registry.nodes.get_mut(&entry) {
            node.parent = Some(target_parent);
            node.name = name.to_vec();
            node.ident = moved.ident;
        }
        registry.by_name.insert((target_parent, fold(name)), entry);
        Ok(self.meta(entry, name, &moved))
    }
}

fn open_git_child_dir(parent: RawHandle, name: &[u8]) -> Result<(OwnedHandle, Info)> {
    let name = component(name)?;
    let handle = open_relative(
        parent,
        &name,
        GIT_DIRECTORY_ACCESS,
        FILE_OPEN,
        DIRECTORY_OPTIONS,
        0,
        true,
    )?;
    let info = info_of(handle.as_raw_handle())?;
    if kind_of(&info) != Kind::Directory {
        return Err(Error::Changed);
    }
    Ok((handle, info))
}

fn open_git_child_dir_for_security(parent: RawHandle, name: &[u8]) -> Result<(OwnedHandle, Info)> {
    let name = component(name)?;
    let handle = open_relative(
        parent,
        &name,
        GIT_DIRECTORY_ACCESS | READ_CONTROL,
        FILE_OPEN,
        DIRECTORY_OPTIONS,
        0,
        true,
    )?;
    let info = info_of(handle.as_raw_handle())?;
    if kind_of(&info) != Kind::Directory {
        return Err(Error::Changed);
    }
    Ok((handle, info))
}

fn open_or_create_git_child_dir(parent: RawHandle, name: &[u8]) -> Result<(OwnedHandle, Info)> {
    let directory = match open_git_child_dir(parent, name) {
        Ok(directory) => directory,
        Err(Error::NotFound) => {
            let wide = component(name)?;
            let handle = match open_relative(
                parent,
                &wide,
                DELETE | GIT_DIRECTORY_ACCESS | READ_CONTROL | WRITE_DAC,
                FILE_CREATE,
                DIRECTORY_OPTIONS,
                FILE_ATTRIBUTE_NORMAL,
                false,
            ) {
                Ok(handle) => handle,
                Err(Error::Exists) => {
                    let directory = open_git_child_dir(parent, name)?;
                    sync_git_directory(parent)?;
                    return Ok(directory);
                }
                Err(error) => return Err(error),
            };
            if let Err(error) = native_owner_only_directory_dacl(handle.as_raw_handle()) {
                let _ = delete_entry(handle.as_raw_handle());
                return Err(error);
            }
            if let Err(error) = sync_git_directory(handle.as_raw_handle()) {
                let _ = delete_entry(handle.as_raw_handle());
                return Err(error);
            }
            let info = info_of(handle.as_raw_handle())?;
            (handle, info)
        }
        Err(error) => return Err(error),
    };
    // Always flush the containing directory. A previous create may have
    // succeeded while this flush failed, and retries must establish durability
    // before installing an object that a final index/ref can reference.
    sync_git_directory(parent)?;
    Ok(directory)
}

#[derive(Clone)]
struct CreatedGitDir {
    name: Vec<u8>,
    identity: Ident,
    created_here: bool,
}

struct GitInfoCreationBaseline {
    marker_entry: EntryRef,
    marker_revision: String,
    parent_identity: Ident,
    entries: Vec<(Vec<u8>, Ident)>,
}

struct GitInfoCreationGuard {
    marker_entry: EntryRef,
    marker_revision: String,
    parent: OwnedHandle,
    parent_identity: Ident,
    revision_after_creation: String,
    entries_after_creation: Vec<(Vec<u8>, Ident)>,
    info_identity: Ident,
}

fn git_directory_census(dir: RawHandle) -> Result<Vec<(Vec<u8>, Ident)>> {
    let mut names = read_dir_names(dir)?;
    names.sort();
    let mut entries = Vec::with_capacity(names.len());
    for name in &names {
        let (child, info) = open_attributes(dir, &component(name)?)?;
        entries.push((name.clone(), info.ident));
        drop(child);
    }
    let mut names_after = read_dir_names(dir)?;
    names_after.sort();
    if names_after != names {
        return Err(Error::Changed);
    }
    Ok(entries)
}

fn create_git_target_parent(
    base: &OwnedHandle,
    suffix: &[Vec<u8>],
    created: &mut Vec<CreatedGitDir>,
    base_entry: EntryRef,
    preceding: &[GitPublishedGuard],
    continue_check: &mut impl FnMut() -> bool,
    mut touch: impl FnMut(Ident),
    mut mark_created: impl FnMut(),
) -> Result<OwnedHandle> {
    let mut current = base.try_clone().map_err(map_os)?;
    let mut prefix = Vec::with_capacity(suffix.len());
    for name in suffix {
        if !continue_check() {
            return Err(Error::Changed);
        }
        let wide = component(name)?;
        prefix.push(name.clone());
        let previously_owned = preceding.iter().find_map(|guard| {
            (guard.base == base_entry
                && guard.parent_suffix.len() >= prefix.len()
                && guard.parent_suffix[..prefix.len()] == prefix)
                .then(|| guard.parent_identities.get(prefix.len() - 1).copied())
                .flatten()
        });
        let (child, created_here) = if let Some(identity) = previously_owned {
            let (child, info) = open_git_child_dir(current.as_raw_handle(), name)?;
            if info.ident != identity {
                return Err(Error::Changed);
            }
            (child, false)
        } else {
            let parent_info = info_of(current.as_raw_handle())?;
            if kind_of(&parent_info) != Kind::Directory {
                return Err(Error::Changed);
            }
            let child = open_relative(
                current.as_raw_handle(),
                &wide,
                DELETE | GIT_DIRECTORY_ACCESS | READ_CONTROL | WRITE_DAC,
                FILE_CREATE,
                DIRECTORY_OPTIONS,
                FILE_ATTRIBUTE_NORMAL,
                false,
            )
            .map_err(|error| {
                if error == Error::Exists {
                    Error::Changed
                } else {
                    error
                }
            })?;
            // FILE_CREATE has made the new directory visible. Record that
            // effect before any fallible info, ACL, or flush operations.
            mark_created();
            touch(parent_info.ident);
            (child, true)
        };
        let info = match info_of(child.as_raw_handle()) {
            Ok(info) => info,
            Err(error) => {
                if created_here {
                    let _ = delete_entry(child.as_raw_handle());
                }
                return Err(error);
            }
        };
        if kind_of(&info) != Kind::Directory {
            if created_here {
                let _ = delete_entry(child.as_raw_handle());
            }
            return Err(Error::Changed);
        }
        created.push(CreatedGitDir {
            name: name.clone(),
            identity: info.ident,
            created_here,
        });
        if created_here {
            if let Err(error) = native_owner_only_directory_dacl(child.as_raw_handle()) {
                let _ = delete_entry(child.as_raw_handle());
                return Err(error);
            }
            if let Err(error) = sync_git_directory(child.as_raw_handle()) {
                let _ = delete_entry(child.as_raw_handle());
                return Err(error);
            }
            if let Err(error) = sync_git_directory(current.as_raw_handle()) {
                let _ = delete_entry(child.as_raw_handle());
                return Err(error);
            }
        }
        current = child;
    }
    Ok(current)
}

fn verify_git_target_parent(
    base: &OwnedHandle,
    suffix: &[Vec<u8>],
    created: &[CreatedGitDir],
) -> Result<OwnedHandle> {
    if suffix.len() != created.len() {
        return Err(Error::Changed);
    }
    let mut current = base.try_clone().map_err(map_os)?;
    for (name, expected) in suffix.iter().zip(created) {
        if name != &expected.name {
            return Err(Error::Changed);
        }
        let (child, info) = open_git_child_dir(current.as_raw_handle(), name)?;
        if info.ident != expected.identity {
            return Err(Error::Changed);
        }
        current = child;
    }
    Ok(current)
}

fn cleanup_created_git_dirs(base: &OwnedHandle, created: &[CreatedGitDir]) {
    for index in (0..created.len()).rev() {
        if !created[index].created_here {
            continue;
        }
        let mut parent = match base.try_clone() {
            Ok(handle) => handle,
            Err(_) => continue,
        };
        let mut valid = true;
        for component_name in &created[..index] {
            let Ok((child, info)) =
                open_git_child_dir(parent.as_raw_handle(), &component_name.name)
            else {
                valid = false;
                break;
            };
            if info.ident != component_name.identity {
                valid = false;
                break;
            }
            parent = child;
        }
        if !valid {
            continue;
        }
        let Ok(name) = component(&created[index].name) else {
            continue;
        };
        let Ok(handle) = open_relative(
            parent.as_raw_handle(),
            &name,
            DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_OPEN,
            DIRECTORY_OPTIONS,
            0,
            false,
        ) else {
            continue;
        };
        if info_of(handle.as_raw_handle()).is_ok_and(|info| {
            info.ident == created[index].identity && kind_of(&info) == Kind::Directory
        }) && delete_entry(handle.as_raw_handle()).is_ok()
        {
            let _ = sync_git_directory(parent.as_raw_handle());
        }
    }
}

fn sync_git_directory(handle: RawHandle) -> Result<()> {
    if unsafe { FlushFileBuffers(handle) } == 0 {
        Err(map_os(std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

const NATIVE_EDITOR_FILE_LIMIT: u64 = 16 * 1024 * 1024;

fn local_native_error(error: Error) -> LocalNativeFileError {
    match error {
        Error::NotFound => LocalNativeFileError::NotFound,
        Error::Changed => LocalNativeFileError::Changed,
        Error::Protected | Error::NotEmpty => LocalNativeFileError::Protected,
        Error::Exists => LocalNativeFileError::Exists,
        Error::Invalid => LocalNativeFileError::Invalid,
        Error::Unsupported => LocalNativeFileError::Unsupported,
        Error::Limit => LocalNativeFileError::Limit,
        Error::Io(kind) if kind == std::io::ErrorKind::PermissionDenied => {
            LocalNativeFileError::Protected
        }
        Error::Io(_) => LocalNativeFileError::Io,
    }
}

fn local_native_io(error: std::io::Error) -> LocalNativeFileError {
    match error.kind() {
        std::io::ErrorKind::NotFound => LocalNativeFileError::NotFound,
        std::io::ErrorKind::AlreadyExists => LocalNativeFileError::Exists,
        std::io::ErrorKind::PermissionDenied => LocalNativeFileError::Protected,
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData => {
            LocalNativeFileError::Invalid
        }
        _ => LocalNativeFileError::Io,
    }
}

fn local_broker_error(error: SecurityBrokerError) -> LocalNativeFileError {
    match error {
        SecurityBrokerError::Invalid => LocalNativeFileError::Invalid,
        SecurityBrokerError::Changed => LocalNativeFileError::Changed,
        SecurityBrokerError::Limit => LocalNativeFileError::Limit,
        SecurityBrokerError::Unsupported => LocalNativeFileError::Unsupported,
        SecurityBrokerError::Io(std::io::ErrorKind::NotFound) => LocalNativeFileError::NotFound,
        SecurityBrokerError::Io(std::io::ErrorKind::AlreadyExists) => LocalNativeFileError::Exists,
        SecurityBrokerError::Io(std::io::ErrorKind::PermissionDenied) => {
            LocalNativeFileError::Protected
        }
        SecurityBrokerError::Io(_) => LocalNativeFileError::Io,
    }
}

fn current_process_user_sid() -> NativeResult<String, LocalNativeFileError> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0
        || token.is_null()
    {
        return Err(LocalNativeFileError::Unsupported);
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut needed = 0u32;
    unsafe {
        GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut needed);
    }
    if needed < size_of::<TOKEN_USER>() as u32 || needed > 64 * 1024 {
        return Err(LocalNativeFileError::Unsupported);
    }
    let mut storage = vec![0u64; (needed as usize).div_ceil(size_of::<u64>())];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            storage.as_mut_ptr().cast::<c_void>(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(LocalNativeFileError::Unsupported);
    }
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    if user.User.Sid.is_null() {
        return Err(LocalNativeFileError::Unsupported);
    }
    let mut text = null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 || text.is_null() {
        return Err(LocalNativeFileError::Unsupported);
    }
    let mut length = 0usize;
    while length < 256 && unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    if length == 256 {
        unsafe { LocalFree(text.cast()) };
        return Err(LocalNativeFileError::Unsupported);
    }
    let sid = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
    unsafe { LocalFree(text.cast()) };
    Ok(sid)
}

fn duplicate_handle_as_file(handle: RawHandle) -> NativeResult<File, LocalNativeFileError> {
    let mut duplicate = null_mut();
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            GetCurrentProcess(),
            &mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
        || duplicate.is_null()
    {
        return Err(local_native_io(std::io::Error::last_os_error()));
    }
    Ok(unsafe { File::from_raw_handle(duplicate) })
}

fn duplicate_handle_as_owned(handle: RawHandle) -> NativeResult<OwnedHandle, LocalNativeFileError> {
    let mut duplicate = null_mut();
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            GetCurrentProcess(),
            &mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
        || duplicate.is_null()
    {
        return Err(local_native_io(std::io::Error::last_os_error()));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(duplicate) })
}

fn same_native_file_info(left: &Info, right: &Info) -> bool {
    left.ident == right.ident
        && left.attributes == right.attributes
        && left.size == right.size
        && left.nlink == right.nlink
        && left.last_write == right.last_write
        && left.change == right.change
}

fn same_native_file_identity(left: &Info, right: &Info) -> bool {
    left.ident == right.ident
        && left.attributes == right.attributes
        && left.size == right.size
        && left.nlink == right.nlink
}

fn native_file_security(
    handle: RawHandle,
) -> NativeResult<NativeFileSecurity, LocalNativeFileError> {
    native_file_security_with_audit_digest(handle, None)
}

fn native_file_security_with_audit_digest(
    handle: RawHandle,
    broker_digest: Option<[u8; 32]>,
) -> NativeResult<NativeFileSecurity, LocalNativeFileError> {
    let mut owner = null_mut();
    let mut group = null_mut();
    let mut dacl = null_mut();
    let mut descriptor = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            &mut group,
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(local_native_io(std::io::Error::from_raw_os_error(
            status as i32,
        )));
    }
    let descriptor = NativeSecurityDescriptor(descriptor);
    if descriptor.0.is_null() || owner.is_null() || group.is_null() {
        return Err(LocalNativeFileError::Unsupported);
    }
    let mut dacl_present = 0;
    let mut descriptor_dacl = null_mut();
    let mut dacl_defaulted = 0;
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor.0,
            &mut dacl_present,
            &mut descriptor_dacl,
            &mut dacl_defaulted,
        )
    } == 0
        || dacl_present == 0
    {
        return Err(LocalNativeFileError::Unsupported);
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
        return Err(LocalNativeFileError::Unsupported);
    }
    let owner_len = unsafe { GetLengthSid(owner) } as usize;
    let group_len = unsafe { GetLengthSid(group) } as usize;
    if owner_len == 0 || group_len == 0 || owner_len > 64 * 1024 || group_len > 64 * 1024 {
        return Err(LocalNativeFileError::Unsupported);
    }
    let owner_bytes = unsafe { std::slice::from_raw_parts(owner.cast::<u8>(), owner_len) }.to_vec();
    let group_bytes = unsafe { std::slice::from_raw_parts(group.cast::<u8>(), group_len) }.to_vec();
    let dacl_bytes = if descriptor_dacl.is_null() {
        None
    } else {
        let length = unsafe { (*descriptor_dacl).AclSize } as usize;
        if length < size_of::<ACL>() || length > 1024 * 1024 {
            return Err(LocalNativeFileError::Unsupported);
        }
        Some(unsafe { std::slice::from_raw_parts(descriptor_dacl.cast::<u8>(), length) }.to_vec())
    };
    let (audit_sacl, label, resource_attributes, scope) = if let Some(digest) = broker_digest {
        (AuditSacl::Broker(digest), None, None, None)
    } else {
        let (present, sacl, protected) = native_audit_sacl(handle)?;
        (
            AuditSacl::Direct {
                present,
                sacl,
                protected,
            },
            native_security_component(handle, LABEL_SECURITY_INFORMATION)?,
            native_security_component(handle, ATTRIBUTE_SECURITY_INFORMATION)?,
            native_security_component(handle, SCOPE_SECURITY_INFORMATION)?,
        )
    };
    Ok(NativeFileSecurity {
        owner: owner_bytes,
        group: group_bytes,
        dacl: dacl_bytes,
        dacl_present: true,
        dacl_protected: control & SE_DACL_PROTECTED != 0,
        label,
        resource_attributes,
        scope,
        audit_sacl,
    })
}

fn capture_native_file_security(
    handle: RawHandle,
) -> NativeResult<CapturedNativeSecurity, LocalNativeFileError> {
    capture_native_file_security_with_session(handle, None)
}

fn capture_native_file_security_with_session(
    handle: RawHandle,
    inherited_session: Option<&BrokerSession>,
) -> NativeResult<CapturedNativeSecurity, LocalNativeFileError> {
    match native_file_security(handle) {
        Ok(security) => Ok(CapturedNativeSecurity {
            security,
            broker_source: None,
        }),
        Err(LocalNativeFileError::Unsupported) => {
            let session = match inherited_session {
                Some(session) => session.clone(),
                None => operation_broker_session()?,
            };
            let file = duplicate_handle_as_file(handle)?;
            let source = session.capture_source(&file)?;
            let digest = source.digest();
            let security = native_file_security_with_audit_digest(handle, Some(digest))?;
            Ok(CapturedNativeSecurity {
                security,
                broker_source: Some(BrokerSourceCapture {
                    session,
                    source: Some(source),
                    _file: file,
                }),
            })
        }
        Err(error) => Err(error),
    }
}

fn native_file_security_matches(
    handle: RawHandle,
    expected: &NativeFileSecurity,
) -> NativeResult<bool, LocalNativeFileError> {
    let actual = match &expected.audit_sacl {
        AuditSacl::Direct { .. } => native_file_security(handle)?,
        AuditSacl::Broker(digest) => native_file_security_with_audit_digest(handle, Some(*digest))?,
    };
    Ok(actual == *expected)
}

fn native_audit_sacl(
    handle: RawHandle,
) -> NativeResult<(bool, Option<Vec<u8>>, bool), LocalNativeFileError> {
    // The retained handle was opened with ACCESS_SYSTEM_SECURITY while the
    // caller's SeSecurityPrivilege was enabled. GetSecurityInfo can query its
    // SACL after that narrow open scope ends (SACL Access Right documentation):
    // https://learn.microsoft.com/en-us/windows/win32/secauthz/sacl-access-right
    let mut sacl = null_mut();
    let mut descriptor = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            SACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sacl,
            &mut descriptor,
        )
    };
    if status != 0 {
        // SACL access is special: failure cannot be interpreted as an empty
        // audit policy because the caller may lack ACCESS_SYSTEM_SECURITY.
        return Err(LocalNativeFileError::Unsupported);
    }
    let descriptor = NativeSecurityDescriptor(descriptor);
    if descriptor.0.is_null() {
        return Err(LocalNativeFileError::Unsupported);
    }
    let mut present = 0;
    let mut descriptor_sacl = null_mut();
    let mut defaulted = 0;
    if unsafe {
        GetSecurityDescriptorSacl(
            descriptor.0,
            &mut present,
            &mut descriptor_sacl,
            &mut defaulted,
        )
    } == 0
    {
        return Err(LocalNativeFileError::Unsupported);
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
        return Err(LocalNativeFileError::Unsupported);
    }
    let bytes = if descriptor_sacl.is_null() {
        None
    } else {
        let length = unsafe { (*descriptor_sacl).AclSize } as usize;
        if length < size_of::<ACL>() || length > 1024 * 1024 {
            return Err(LocalNativeFileError::Unsupported);
        }
        Some(unsafe { std::slice::from_raw_parts(descriptor_sacl.cast::<u8>(), length).to_vec() })
    };
    Ok((present != 0, bytes, control & SE_SACL_PROTECTED != 0))
}

fn native_security_component(
    handle: RawHandle,
    information: u32,
) -> NativeResult<Option<Vec<u8>>, LocalNativeFileError> {
    let mut sacl = null_mut();
    let mut descriptor = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            information,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(local_native_io(std::io::Error::from_raw_os_error(
            status as i32,
        )));
    }
    let _descriptor = NativeSecurityDescriptor(descriptor);
    let mut sacl_present = 0;
    let mut sacl_defaulted = 0;
    if unsafe {
        GetSecurityDescriptorSacl(
            descriptor,
            &mut sacl_present,
            &mut sacl,
            &mut sacl_defaulted,
        )
    } == 0
    {
        return Err(LocalNativeFileError::Unsupported);
    }
    if sacl_present == 0 || sacl.is_null() {
        return Ok(None);
    }
    let length = unsafe { (*sacl).AclSize } as usize;
    if length < size_of::<ACL>() || length > 1024 * 1024 {
        return Err(LocalNativeFileError::Unsupported);
    }
    Ok(Some(
        unsafe { std::slice::from_raw_parts(sacl.cast::<u8>(), length) }.to_vec(),
    ))
}

fn native_set_security_component(
    handle: RawHandle,
    information: u32,
    acl: Option<&Vec<u8>>,
) -> NativeResult<(), LocalNativeFileError> {
    let sacl = acl.map_or(null(), |bytes| bytes.as_ptr().cast::<ACL>());
    let set = || unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            information,
            null_mut(),
            null_mut(),
            null(),
            sacl,
        )
    };
    // SetSecurityInfo requires SeSecurityPrivilege when changing a scoped
    // policy ID. Keep the duplicated caller token installed for this syscall
    // alone; the retained handle already carries ACCESS_SYSTEM_SECURITY.
    // https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo
    let status = if information & SCOPE_SECURITY_INFORMATION != 0 {
        with_system_security_privilege(set).map_err(|_| LocalNativeFileError::Unsupported)?
    } else {
        set()
    };
    if status != 0 {
        return Err(local_native_io(std::io::Error::from_raw_os_error(
            status as i32,
        )));
    }
    Ok(())
}

fn native_apply_audit_sacl(
    handle: RawHandle,
    security: &NativeFileSecurity,
) -> NativeResult<(), LocalNativeFileError> {
    let AuditSacl::Direct {
        present: audit_sacl_present,
        sacl: audit_sacl,
        protected: audit_sacl_protected,
    } = &security.audit_sacl
    else {
        return Ok(());
    };
    let current = native_audit_sacl(handle)?;
    let expected = (
        *audit_sacl_present,
        audit_sacl.clone(),
        *audit_sacl_protected,
    );
    if !*audit_sacl_present {
        return if current == expected {
            Ok(())
        } else {
            Err(LocalNativeFileError::Unsupported)
        };
    }
    let protection = if *audit_sacl_protected {
        PROTECTED_SACL_SECURITY_INFORMATION
    } else {
        UNPROTECTED_SACL_SECURITY_INFORMATION
    };
    let sacl = audit_sacl
        .as_ref()
        .map_or(null(), |bytes| bytes.as_ptr().cast::<ACL>());
    // Microsoft documents that SetSecurityInfo requires SeSecurityPrivilege
    // to set a SACL. The handle was opened with ACCESS_SYSTEM_SECURITY; enable
    // the already-assigned privilege only around this single syscall.
    // https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo
    let status = with_system_security_privilege(|| unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            SACL_SECURITY_INFORMATION | protection,
            null_mut(),
            null_mut(),
            null(),
            sacl,
        )
    })
    .map_err(|_| LocalNativeFileError::Unsupported)?;
    if status != 0 {
        return Err(LocalNativeFileError::Unsupported);
    }
    if native_audit_sacl(handle)? != expected {
        return Err(LocalNativeFileError::Changed);
    }
    Ok(())
}

fn native_apply_file_security(
    handle: RawHandle,
    security: &NativeFileSecurity,
) -> NativeResult<(), LocalNativeFileError> {
    if !security.dacl_present {
        return Err(LocalNativeFileError::Unsupported);
    }
    let dacl_flags = if security.dacl_protected {
        PROTECTED_DACL_SECURITY_INFORMATION
    } else {
        UNPROTECTED_DACL_SECURITY_INFORMATION
    };
    let dacl = security
        .dacl
        .as_ref()
        .map_or(null(), |bytes| bytes.as_ptr().cast::<ACL>());
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | dacl_flags,
            security.owner.as_ptr().cast_mut().cast(),
            security.group.as_ptr().cast_mut().cast(),
            dacl,
            null(),
        )
    };
    if status != 0 {
        return Err(local_native_io(std::io::Error::from_raw_os_error(
            status as i32,
        )));
    }
    if matches!(security.audit_sacl, AuditSacl::Direct { .. }) {
        native_set_security_component(handle, LABEL_SECURITY_INFORMATION, security.label.as_ref())?;
        native_set_security_component(
            handle,
            ATTRIBUTE_SECURITY_INFORMATION,
            security.resource_attributes.as_ref(),
        )?;
        let current_scope = native_security_component(handle, SCOPE_SECURITY_INFORMATION)?;
        if current_scope != security.scope {
            native_set_security_component(
                handle,
                SCOPE_SECURITY_INFORMATION,
                security.scope.as_ref(),
            )
            .map_err(|_| LocalNativeFileError::Unsupported)?;
        }
    }
    native_apply_audit_sacl(handle, security)?;
    if native_file_security_with_audit_digest(
        handle,
        match &security.audit_sacl {
            AuditSacl::Direct { .. } => None,
            AuditSacl::Broker(digest) => Some(*digest),
        },
    )? != *security
    {
        return Err(LocalNativeFileError::Changed);
    }
    Ok(())
}

fn git_native_security_error(error: LocalNativeFileError) -> Error {
    match error {
        LocalNativeFileError::Changed => Error::Changed,
        LocalNativeFileError::Limit => Error::Limit,
        LocalNativeFileError::Invalid => Error::Invalid,
        _ => Error::Unsupported,
    }
}

fn git_file_security(handle: RawHandle) -> Result<GitFileSecurity> {
    let info = info_of(handle)?;
    if kind_of(&info) != Kind::File {
        return Err(Error::Unsupported);
    }
    if info.nlink != 1 {
        return Err(Error::Protected);
    }
    native_default_stream_only(handle).map_err(git_native_security_error)?;
    let extended = capture_native_file_security(handle)
        .map_err(git_native_security_error)?
        .security;
    Ok(GitFileSecurity {
        attributes: info.attributes,
        extended,
    })
}

fn git_file_security_for_expected(
    handle: RawHandle,
    expected: &GitFileSecurity,
) -> Result<GitFileSecurity> {
    let info = info_of(handle)?;
    if kind_of(&info) != Kind::File || info.nlink != 1 {
        return Err(Error::Protected);
    }
    native_default_stream_only(handle).map_err(git_native_security_error)?;
    let extended = match &expected.extended.audit_sacl {
        AuditSacl::Direct { .. } => {
            native_file_security(handle).map_err(git_native_security_error)?
        }
        AuditSacl::Broker(digest) => native_file_security_with_audit_digest(handle, Some(*digest))
            .map_err(git_native_security_error)?,
    };
    Ok(GitFileSecurity {
        attributes: info.attributes,
        extended,
    })
}

fn git_named_file_security(parent: RawHandle, name: &[u16]) -> Result<Option<GitFileSecurity>> {
    capture_git_named_file_security(parent, name).map(|(security, _capture)| security)
}

fn capture_git_named_file_security(
    parent: RawHandle,
    name: &[u16],
) -> Result<(Option<GitFileSecurity>, Option<BrokerSourceCapture>)> {
    match native_open_file(parent, name) {
        Ok((handle, info)) => {
            if kind_of(&info) != Kind::File || info.nlink != 1 {
                return Err(Error::Protected);
            }
            native_default_stream_only(handle.as_raw_handle())
                .map_err(git_native_security_error)?;
            let captured = capture_native_file_security(handle.as_raw_handle())
                .map_err(git_native_security_error)?;
            let security = GitFileSecurity {
                attributes: info.attributes,
                extended: captured.security,
            };
            Ok((Some(security), captured.broker_source))
        }
        Err(LocalNativeFileError::NotFound) => Ok((None, None)),
        Err(LocalNativeFileError::Protected | LocalNativeFileError::Unsupported) => {
            Err(Error::Unsupported)
        }
        Err(error) => Err(git_native_security_error(error)),
    }
}

fn check_git_named_file_security(
    parent: RawHandle,
    name: &[u16],
    expected: Option<&GitFileSecurity>,
) -> Result<()> {
    if git_named_file_security(parent, name)?.as_ref() != expected {
        return Err(Error::Changed);
    }
    Ok(())
}

fn open_git_leaf_metadata(parent: RawHandle, name: &[u16]) -> Result<(OwnedHandle, Info)> {
    let access = FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE;
    let handle = match open_relative(
        parent,
        name,
        access | ACCESS_SYSTEM_SECURITY,
        FILE_OPEN,
        FILE_OPEN_REPARSE_POINT | SYNC,
        0,
        false,
    ) {
        Ok(handle) => handle,
        Err(Error::Unsupported | Error::Io(std::io::ErrorKind::PermissionDenied)) => open_relative(
            parent,
            name,
            access,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT | SYNC,
            0,
            false,
        )?,
        Err(error) => return Err(error),
    };
    let info = info_of(handle.as_raw_handle())?;
    if !matches!(kind_of(&info), Kind::File | Kind::Symlink) || info.nlink != 1 {
        return Err(Error::Protected);
    }
    Ok((handle, info))
}

fn capture_git_leaf_security(handle: OwnedHandle, before: Info) -> Result<CapturedGitLeafSecurity> {
    let kind = match kind_of(&before) {
        Kind::File => GitPullNodeKind::File,
        Kind::Symlink => GitPullNodeKind::Symlink,
        Kind::Directory | Kind::Other => return Err(Error::Protected),
    };
    if kind == GitPullNodeKind::File {
        native_default_stream_only(handle.as_raw_handle()).map_err(git_native_security_error)?;
    }
    let reparse = if kind == GitPullNodeKind::Symlink {
        Some(
            security_broker::read_symlink_reparse_buffer(handle.as_raw_handle())
                .map_err(|_| Error::Unsupported)?,
        )
    } else {
        None
    };
    let eas = native_query_git_eas(handle.as_raw_handle()).map_err(git_native_security_error)?;
    let session = operation_broker_session().map_err(git_native_security_error)?;
    let source_file =
        duplicate_handle_as_file(handle.as_raw_handle()).map_err(git_native_security_error)?;
    let source = session
        .capture_source_pinned(&source_file)
        .map_err(git_native_security_error)?;
    let security =
        native_file_security_with_audit_digest(handle.as_raw_handle(), Some(source.digest()))
            .map_err(git_native_security_error)?;
    let captured = CapturedNativeSecurity {
        security,
        broker_source: Some(BrokerSourceCapture {
            session,
            source: Some(source),
            _file: source_file,
        }),
    };
    let after = info_of(handle.as_raw_handle())?;
    if !same_git_leaf_info(&before, &after)
        || (kind == GitPullNodeKind::Symlink
            && Some(
                security_broker::read_symlink_reparse_buffer(handle.as_raw_handle())
                    .map_err(|_| Error::Changed)?,
            ) != reparse)
        || native_query_git_eas(handle.as_raw_handle()).map_err(git_native_security_error)? != eas
    {
        return Err(Error::Changed);
    }
    let security = GitLeafSecurity {
        info: before,
        kind,
        extended: captured.security,
        eas,
        reparse,
    };
    Ok(CapturedGitLeafSecurity {
        security,
        broker_source: captured.broker_source,
        _file: unsafe { File::from_raw_handle(handle.into_raw_handle()) },
    })
}

fn git_named_leaf_security(
    parent: RawHandle,
    name: &[u16],
) -> Result<Option<CapturedGitLeafSecurity>> {
    match open_git_leaf_metadata(parent, name) {
        Ok((handle, info)) => capture_git_leaf_security(handle, info).map(Some),
        Err(Error::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

fn check_git_named_leaf_security(
    parent: RawHandle,
    name: &[u16],
    expected: Option<&CapturedGitLeafSecurity>,
) -> Result<()> {
    let Some(expected) = expected else {
        return match open_attributes(parent, name) {
            Err(Error::NotFound) => Ok(()),
            Ok(_) => Err(Error::Changed),
            Err(error) => Err(error),
        };
    };
    if let Some(source) = expected.broker_source.as_ref() {
        source.recheck().map_err(git_native_security_error)?;
    }
    let (handle, _) = open_git_leaf_metadata(parent, name)?;
    check_git_leaf_security_handle(handle.as_raw_handle(), expected)
}

/// Compare a held no-follow leaf handle with a previously captured metadata
/// tuple. This variant performs no broker calls and is used only after a
/// stronger share-mode handle has excluded concurrent writers.
fn check_git_leaf_security_handle(
    handle: RawHandle,
    expected: &CapturedGitLeafSecurity,
) -> Result<()> {
    check_git_leaf_security_value(handle, &expected.security)
}

fn check_git_leaf_security_value(handle: RawHandle, expected: &GitLeafSecurity) -> Result<()> {
    let info = info_of(handle)?;
    if !same_git_leaf_info(&expected.info, &info)
        || kind_of(&info)
            != match expected.kind {
                GitPullNodeKind::File => Kind::File,
                GitPullNodeKind::Symlink => Kind::Symlink,
                GitPullNodeKind::Directory => return Err(Error::Changed),
            }
    {
        return Err(Error::Changed);
    }
    let reparse = if expected.kind == GitPullNodeKind::Symlink {
        Some(security_broker::read_symlink_reparse_buffer(handle).map_err(|_| Error::Changed)?)
    } else {
        None
    };
    if reparse != expected.reparse
        || native_query_git_eas(handle).map_err(git_native_security_error)? != expected.eas
    {
        return Err(Error::Changed);
    }
    let extended = match expected.extended.audit_sacl {
        AuditSacl::Direct { .. } => {
            native_file_security(handle).map_err(git_native_security_error)?
        }
        AuditSacl::Broker(digest) => native_file_security_with_audit_digest(handle, Some(digest))
            .map_err(git_native_security_error)?,
    };
    if extended != expected.extended {
        return Err(Error::Changed);
    }
    Ok(())
}

fn apply_git_leaf_security(
    handle: RawHandle,
    source: &GitLeafSecurity,
    destination_kind: GitPullNodeKind,
) -> Result<()> {
    let before = info_of(handle)?;
    let expected_kind = match destination_kind {
        GitPullNodeKind::File => Kind::File,
        GitPullNodeKind::Symlink => Kind::Symlink,
        GitPullNodeKind::Directory => return Err(Error::Invalid),
    };
    if kind_of(&before) != expected_kind || before.nlink != 1 {
        return Err(Error::Changed);
    }
    let settable_attributes = FILE_ATTRIBUTE_READONLY
        | FILE_ATTRIBUTE_ARCHIVE
        | FILE_ATTRIBUTE_HIDDEN
        | FILE_ATTRIBUTE_SYSTEM
        | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
        | FILE_ATTRIBUTE_TEMPORARY;
    // Storage-managed flags such as compressed, sparse, or encrypted describe
    // how the old allocation was stored. They are not settable through
    // FileBasicInfo; preserve the visible/settable flags above and let NTFS
    // apply the destination directory's storage policy.
    // Keep the source DACL protected while the staged object is still named
    // below an owner-private container. The original ACL bytes are retained;
    // the published parent may later restore its exact inherited state.
    let mut staging_security = source.extended.clone();
    staging_security.dacl_protected = true;
    native_apply_file_security(handle, &staging_security).map_err(git_native_security_error)?;
    // Copy extended attributes before applying a source READONLY attribute.
    // The held handle already has FILE_WRITE_EA, but doing this first also
    // preserves behavior on filesystems that enforce readonly at EA writes.
    native_set_git_eas(handle, &source.eas).map_err(git_native_security_error)?;
    let mut basic: FILE_BASIC_INFO = unsafe { zeroed() };
    basic.FileAttributes = source.info.attributes & settable_attributes;
    if basic.FileAttributes == 0 {
        basic.FileAttributes = FILE_ATTRIBUTE_NORMAL;
    }
    if unsafe {
        SetFileInformationByHandle(
            handle,
            FileBasicInfo,
            (&basic as *const FILE_BASIC_INFO).cast::<c_void>(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(git_native_security_error(local_native_io(
            std::io::Error::last_os_error(),
        )));
    }
    let after = info_of(handle)?;
    let actual_extended = match source.extended.audit_sacl {
        AuditSacl::Direct { .. } => {
            native_file_security(handle).map_err(git_native_security_error)?
        }
        AuditSacl::Broker(digest) => native_file_security_with_audit_digest(handle, Some(digest))
            .map_err(git_native_security_error)?,
    };
    if kind_of(&after) != expected_kind
        || after.ident != before.ident
        || after.nlink != 1
        || after.attributes & settable_attributes != source.info.attributes & settable_attributes
        || actual_extended != staging_security
        || native_query_git_eas(handle).map_err(git_native_security_error)? != source.eas
    {
        return Err(Error::Changed);
    }
    if destination_kind == GitPullNodeKind::Symlink {
        let _ = security_broker::read_symlink_reparse_buffer(handle).map_err(|_| Error::Changed)?;
    }
    Ok(())
}

fn finalize_git_leaf_security(
    handle: RawHandle,
    source: &GitLeafSecurity,
    destination_kind: GitPullNodeKind,
    expected_identity: Ident,
    expected_reparse: Option<&[u8]>,
) -> Result<()> {
    let mut staged_security = source.extended.clone();
    staged_security.dacl_protected = true;
    check_git_leaf_metadata(
        handle,
        source,
        destination_kind,
        expected_identity,
        expected_reparse,
        &staged_security,
    )?;
    let dacl_flags = if source.extended.dacl_protected {
        PROTECTED_DACL_SECURITY_INFORMATION
    } else {
        UNPROTECTED_DACL_SECURITY_INFORMATION
    };
    let dacl = source
        .extended
        .dacl
        .as_ref()
        .map_or(null(), |bytes| bytes.as_ptr().cast::<ACL>());
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | dacl_flags,
            null_mut(),
            null_mut(),
            dacl,
            null_mut(),
        )
    };
    if status != 0 {
        return Err(git_native_security_error(local_native_io(
            std::io::Error::from_raw_os_error(status as i32),
        )));
    }
    let actual = match source.extended.audit_sacl {
        AuditSacl::Direct { .. } => native_file_security(handle),
        AuditSacl::Broker(digest) => native_file_security_with_audit_digest(handle, Some(digest)),
    }
    .map_err(git_native_security_error)?;
    if actual != source.extended {
        return Err(Error::Changed);
    }
    check_git_leaf_metadata(
        handle,
        source,
        destination_kind,
        expected_identity,
        expected_reparse,
        &source.extended,
    )
}

fn check_git_leaf_metadata(
    handle: RawHandle,
    source: &GitLeafSecurity,
    destination_kind: GitPullNodeKind,
    expected_identity: Ident,
    expected_reparse: Option<&[u8]>,
    expected_extended: &NativeFileSecurity,
) -> Result<()> {
    let info = info_of(handle)?;
    let expected_kind = match destination_kind {
        GitPullNodeKind::File => Kind::File,
        GitPullNodeKind::Symlink => Kind::Symlink,
        GitPullNodeKind::Directory => return Err(Error::Invalid),
    };
    if kind_of(&info) != expected_kind || info.ident != expected_identity || info.nlink != 1 {
        return Err(Error::Changed);
    }
    const SETTABLE_ATTRIBUTES: u32 = FILE_ATTRIBUTE_READONLY
        | FILE_ATTRIBUTE_ARCHIVE
        | FILE_ATTRIBUTE_HIDDEN
        | FILE_ATTRIBUTE_SYSTEM
        | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
        | FILE_ATTRIBUTE_TEMPORARY;
    if info.attributes & SETTABLE_ATTRIBUTES != source.info.attributes & SETTABLE_ATTRIBUTES {
        return Err(Error::Changed);
    }
    let reparse = match destination_kind {
        GitPullNodeKind::File => None,
        GitPullNodeKind::Symlink => {
            Some(security_broker::read_symlink_reparse_buffer(handle).map_err(|_| Error::Changed)?)
        }
        GitPullNodeKind::Directory => return Err(Error::Invalid),
    };
    if reparse.as_deref() != expected_reparse
        || native_query_git_eas(handle).map_err(git_native_security_error)? != source.eas
    {
        return Err(Error::Changed);
    }
    let extended = match expected_extended.audit_sacl {
        AuditSacl::Direct { .. } => native_file_security(handle),
        AuditSacl::Broker(digest) => native_file_security_with_audit_digest(handle, Some(digest)),
    }
    .map_err(git_native_security_error)?;
    if extended != *expected_extended {
        return Err(Error::Changed);
    }
    Ok(())
}

fn same_git_leaf_info(left: &Info, right: &Info) -> bool {
    left.ident == right.ident
        && left.attributes == right.attributes
        && left.size == right.size
        && left.nlink == right.nlink
        && left.last_write == right.last_write
        && left.change == right.change
}

fn native_query_git_eas(handle: RawHandle) -> NativeResult<Vec<EaRecord>, LocalNativeFileError> {
    let mut storage = vec![0u64; MAX_GIT_EA_BYTES.div_ceil(size_of::<u64>())];
    let mut iosb: IO_STATUS_BLOCK = unsafe { zeroed() };
    let status = unsafe {
        NtQueryEaFile(
            handle,
            &mut iosb,
            storage.as_mut_ptr().cast(),
            MAX_GIT_EA_BYTES as u32,
            false,
            null(),
            0,
            null(),
            true,
        )
    };
    if status == STATUS_NO_EAS_ON_FILE {
        return Ok(Vec::new());
    }
    if status == STATUS_BUFFER_OVERFLOW {
        return Err(LocalNativeFileError::Limit);
    }
    if status < 0 || unsafe { iosb.Anonymous.Status } < 0 {
        return Err(local_native_error(map_status(status, false)));
    }
    let length = usize::try_from(iosb.Information).map_err(|_| LocalNativeFileError::Limit)?;
    if length > MAX_GIT_EA_BYTES {
        return Err(LocalNativeFileError::Limit);
    }
    let bytes = unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), length) };
    parse_git_eas(bytes)
}

fn parse_git_eas(bytes: &[u8]) -> NativeResult<Vec<EaRecord>, LocalNativeFileError> {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        if bytes.len() - offset < 8 {
            return Err(LocalNativeFileError::Changed);
        }
        let next = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let flags = bytes[offset + 4];
        let name_len = usize::from(bytes[offset + 5]);
        let value_len = usize::from(u16::from_le_bytes(
            bytes[offset + 6..offset + 8].try_into().unwrap(),
        ));
        let entry_len = 8usize
            .checked_add(name_len)
            .and_then(|length| length.checked_add(1))
            .and_then(|length| length.checked_add(value_len))
            .ok_or(LocalNativeFileError::Limit)?;
        if name_len == 0
            || name_len >= 255
            || !matches!(flags, 0 | 0x80)
            || entry_len > bytes.len() - offset
        {
            return Err(LocalNativeFileError::Changed);
        }
        let name_start = offset + 8;
        let name_end = name_start + name_len;
        if bytes[name_end] != 0 {
            return Err(LocalNativeFileError::Changed);
        }
        let name = bytes[name_start..name_end].to_vec();
        if !valid_ea_name(&name) {
            return Err(LocalNativeFileError::Changed);
        }
        let value_start = name_end + 1;
        let value = bytes[value_start..value_start + value_len].to_vec();
        if next == 0 {
            if bytes.len() - offset != entry_len {
                return Err(LocalNativeFileError::Changed);
            }
        } else if next < entry_len || next % 4 != 0 || next > bytes.len() - offset {
            return Err(LocalNativeFileError::Changed);
        }
        entries.push(EaRecord { flags, name, value });
        if entries.len() > 4096 {
            return Err(LocalNativeFileError::Limit);
        }
        if next == 0 {
            offset = bytes.len();
        } else {
            offset += next;
        }
    }
    entries.sort_by(|left, right| {
        left.name
            .iter()
            .map(u8::to_ascii_lowercase)
            .cmp(right.name.iter().map(u8::to_ascii_lowercase))
    });
    if entries.windows(2).any(|pair| {
        pair[0]
            .name
            .iter()
            .map(u8::to_ascii_lowercase)
            .eq(pair[1].name.iter().map(u8::to_ascii_lowercase))
    }) {
        return Err(LocalNativeFileError::Changed);
    }
    Ok(entries)
}

fn valid_ea_name(name: &[u8]) -> bool {
    name.is_ascii()
        && !name.is_empty()
        && !name
            .iter()
            .any(|byte| *byte < 0x20 || b"\\/:*?\"<>|,+=[];".contains(byte))
}

fn native_set_git_eas(
    handle: RawHandle,
    entries: &[EaRecord],
) -> NativeResult<(), LocalNativeFileError> {
    if entries.is_empty() {
        return Ok(());
    }
    let mut buffer = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        if !valid_ea_name(&entry.name)
            || entry.name.len() >= 255
            || entry.value.len() > u16::MAX as usize
            || !matches!(entry.flags, 0 | 0x80)
        {
            return Err(LocalNativeFileError::Invalid);
        }
        let entry_start = buffer.len();
        buffer.resize(entry_start + 8, 0);
        buffer[entry_start + 4] = entry.flags;
        buffer[entry_start + 5] = entry.name.len() as u8;
        buffer[entry_start + 6..entry_start + 8]
            .copy_from_slice(&(entry.value.len() as u16).to_le_bytes());
        buffer.extend_from_slice(&entry.name);
        buffer.push(0);
        buffer.extend_from_slice(&entry.value);
        if index + 1 < entries.len() {
            while buffer.len() % 4 != 0 {
                buffer.push(0);
            }
            let next = u32::try_from(buffer.len() - entry_start)
                .map_err(|_| LocalNativeFileError::Limit)?;
            buffer[entry_start..entry_start + 4].copy_from_slice(&next.to_le_bytes());
        }
        if buffer.len() > MAX_GIT_EA_BYTES {
            return Err(LocalNativeFileError::Limit);
        }
    }
    let mut iosb: IO_STATUS_BLOCK = unsafe { zeroed() };
    let status = unsafe {
        NtSetEaFile(
            handle,
            &mut iosb,
            buffer.as_ptr().cast(),
            u32::try_from(buffer.len()).map_err(|_| LocalNativeFileError::Limit)?,
        )
    };
    if status < 0 || unsafe { iosb.Anonymous.Status } < 0 {
        return Err(local_native_error(map_status(status, false)));
    }
    Ok(())
}

fn native_owner_only_dacl(owner: &[u8]) -> NativeResult<Vec<u8>, LocalNativeFileError> {
    if owner.is_empty() || owner.len() > 64 * 1024 {
        return Err(LocalNativeFileError::Unsupported);
    }
    let ace_size = 8usize
        .checked_add(owner.len())
        .ok_or(LocalNativeFileError::Limit)?;
    let acl_size = 8usize
        .checked_add(ace_size)
        .ok_or(LocalNativeFileError::Limit)?;
    if ace_size > u16::MAX as usize || acl_size > u16::MAX as usize {
        return Err(LocalNativeFileError::Limit);
    }
    let mut acl = vec![0u8; acl_size];
    acl[0] = 2; // ACL_REVISION
    acl[2..4].copy_from_slice(&(acl_size as u16).to_le_bytes());
    acl[4..6].copy_from_slice(&1u16.to_le_bytes());
    acl[8] = 0; // ACCESS_ALLOWED_ACE_TYPE
    acl[10..12].copy_from_slice(&(ace_size as u16).to_le_bytes());
    acl[12..16].copy_from_slice(&0x001f_01ffu32.to_le_bytes()); // FILE_ALL_ACCESS
    acl[16..].copy_from_slice(owner);
    Ok(acl)
}

fn native_owner_only_directory_dacl(handle: RawHandle) -> Result<()> {
    let mut owner = null_mut();
    let mut descriptor = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 || owner.is_null() || descriptor.is_null() {
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor) };
        }
        return Err(Error::Unsupported);
    }
    let _descriptor = NativeSecurityDescriptor(descriptor);
    let owner_len = unsafe { GetLengthSid(owner) } as usize;
    if owner_len == 0 || owner_len > 64 * 1024 {
        return Err(Error::Unsupported);
    }
    let owner_bytes = unsafe { std::slice::from_raw_parts(owner.cast::<u8>(), owner_len) };
    let dacl = native_owner_only_dacl(owner_bytes).map_err(git_native_security_error)?;
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl.as_ptr().cast::<ACL>(),
            null_mut(),
        )
    };
    if status != 0 {
        return Err(git_native_security_error(local_native_io(
            std::io::Error::from_raw_os_error(status as i32),
        )));
    }
    let mut actual_dacl = null_mut();
    let mut actual_descriptor = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut actual_dacl,
            null_mut(),
            &mut actual_descriptor,
        )
    };
    if status != 0 || actual_descriptor.is_null() {
        if !actual_descriptor.is_null() {
            unsafe { LocalFree(actual_descriptor) };
        }
        return Err(Error::Unsupported);
    }
    let actual_descriptor = NativeSecurityDescriptor(actual_descriptor);
    let mut present = 0;
    let mut descriptor_dacl = null_mut();
    let mut defaulted = 0;
    if unsafe {
        GetSecurityDescriptorDacl(
            actual_descriptor.0,
            &mut present,
            &mut descriptor_dacl,
            &mut defaulted,
        )
    } == 0
        || present == 0
        || descriptor_dacl.is_null()
    {
        return Err(Error::Unsupported);
    }
    let actual_length = unsafe { (*descriptor_dacl).AclSize } as usize;
    let mut control = 0u16;
    let mut revision = 0u32;
    if actual_length < size_of::<ACL>()
        || actual_length > 64 * 1024
        || unsafe { GetSecurityDescriptorControl(actual_descriptor.0, &mut control, &mut revision) }
            == 0
        || control & SE_DACL_PROTECTED == 0
        || unsafe { std::slice::from_raw_parts(descriptor_dacl.cast::<u8>(), actual_length) }
            != dacl.as_slice()
    {
        return Err(Error::Changed);
    }
    Ok(())
}

fn verify_native_private_stage_directory(handle: RawHandle, expected_owner: &[u8]) -> Result<()> {
    let mut owner = null_mut();
    let mut dacl = null_mut();
    let mut descriptor = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 || owner.is_null() || dacl.is_null() || descriptor.is_null() {
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor) };
        }
        return Err(Error::Unsupported);
    }
    let descriptor = NativeSecurityDescriptor(descriptor);
    let owner_len = unsafe { GetLengthSid(owner) } as usize;
    if owner_len == 0 || owner_len > 64 * 1024 {
        return Err(Error::Unsupported);
    }
    let actual_owner = unsafe { std::slice::from_raw_parts(owner.cast::<u8>(), owner_len) };
    if !expected_owner.is_empty() && actual_owner != expected_owner {
        return Err(Error::Changed);
    }
    let expected_dacl = native_owner_only_dacl(actual_owner).map_err(git_native_security_error)?;
    let actual_len = unsafe { (*dacl).AclSize } as usize;
    let mut control = 0u16;
    let mut revision = 0u32;
    if actual_len < size_of::<ACL>()
        || actual_len > 64 * 1024
        || unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
        || unsafe { std::slice::from_raw_parts(dacl.cast::<u8>(), actual_len) }
            != expected_dacl.as_slice()
    {
        return Err(Error::Changed);
    }
    Ok(())
}

fn verify_native_owner_only_directory_dacl(handle: RawHandle) -> Result<()> {
    let mut owner = null_mut();
    let mut dacl = null_mut();
    let mut descriptor = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 || owner.is_null() || dacl.is_null() || descriptor.is_null() {
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor) };
        }
        return Err(Error::Unsupported);
    }
    let _descriptor = NativeSecurityDescriptor(descriptor);
    let owner_len = unsafe { GetLengthSid(owner) } as usize;
    if owner_len == 0 || owner_len > 64 * 1024 {
        return Err(Error::Unsupported);
    }
    let expected = native_owner_only_dacl(unsafe {
        std::slice::from_raw_parts(owner.cast::<u8>(), owner_len)
    })
    .map_err(git_native_security_error)?;
    let actual_len = unsafe { (*dacl).AclSize } as usize;
    let mut control = 0u16;
    let mut revision = 0u32;
    if actual_len < size_of::<ACL>()
        || actual_len > 64 * 1024
        || unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
        || unsafe { std::slice::from_raw_parts(dacl.cast::<u8>(), actual_len) } != expected
    {
        return Err(Error::Changed);
    }
    Ok(())
}

fn native_owner_only_security(handle: RawHandle) -> Result<NativeFileSecurity> {
    native_owner_only_security_with_session(handle, None)
}

fn native_owner_only_security_with_session(
    handle: RawHandle,
    session: Option<&BrokerSession>,
) -> Result<NativeFileSecurity> {
    let mut security = capture_native_file_security_with_session(handle, session)
        .map_err(git_native_security_error)?
        .security;
    security.dacl =
        Some(native_owner_only_dacl(&security.owner).map_err(git_native_security_error)?);
    security.dacl_present = true;
    security.dacl_protected = true;
    native_apply_file_security(handle, &security).map_err(git_native_security_error)?;
    Ok(security)
}

fn native_owner_only_file_security(handle: RawHandle) -> Result<GitFileSecurity> {
    native_owner_only_security(handle)?;
    git_file_security(handle)
}

fn apply_git_file_security(
    handle: RawHandle,
    source: Option<&GitFileSecurity>,
    owner_only_if_new: bool,
) -> Result<GitFileSecurity> {
    if let Some(source) = source {
        if source.attributes & FILE_ATTRIBUTE_READONLY != 0 {
            return Err(Error::Protected);
        }
        native_apply_file_security(handle, &source.extended).map_err(git_native_security_error)?;
        let info = info_of(handle)?;
        native_apply_file_attributes(
            handle,
            &Info {
                attributes: source.attributes,
                ..info
            },
        )
        .map_err(git_native_security_error)?;
        if source.attributes & FILE_ATTRIBUTE_READONLY != 0 {
            return Err(Error::Protected);
        }
        let actual = git_file_security_for_expected(handle, source)?;
        if actual != *source {
            return Err(Error::Changed);
        }
        Ok(actual)
    } else if owner_only_if_new {
        native_owner_only_file_security(handle)
    } else {
        git_file_security(handle)
    }
}

fn native_default_stream_only(handle: RawHandle) -> NativeResult<(), LocalNativeFileError> {
    let mut buffer = vec![0u64; 8192];
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStreamInfo,
            buffer.as_mut_ptr().cast(),
            (buffer.len() * size_of::<u64>()) as u32,
        )
    } == 0
    {
        return Err(local_native_io(std::io::Error::last_os_error()));
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(
            buffer.as_ptr().cast::<u8>(),
            buffer.len() * size_of::<u64>(),
        )
    };
    let mut offset = 0usize;
    loop {
        if offset + size_of::<FILE_STREAM_INFO>() > bytes.len() {
            return Err(LocalNativeFileError::Changed);
        }
        let entry = unsafe { &*bytes.as_ptr().add(offset).cast::<FILE_STREAM_INFO>() };
        let name_len = entry.StreamNameLength as usize;
        let name_offset = std::mem::offset_of!(FILE_STREAM_INFO, StreamName);
        if name_len % 2 != 0 || offset + name_offset + name_len > bytes.len() {
            return Err(LocalNativeFileError::Changed);
        }
        let name = unsafe {
            std::slice::from_raw_parts(
                bytes.as_ptr().add(offset + name_offset).cast::<u16>(),
                name_len / 2,
            )
        };
        if name != ":$DATA".encode_utf16().collect::<Vec<_>>()
            && name != "::$DATA".encode_utf16().collect::<Vec<_>>()
        {
            return Err(LocalNativeFileError::Unsupported);
        }
        if entry.NextEntryOffset == 0 {
            break;
        }
        if (entry.NextEntryOffset as usize) < name_offset + name_len {
            return Err(LocalNativeFileError::Changed);
        }
        offset = offset
            .checked_add(entry.NextEntryOffset as usize)
            .ok_or(LocalNativeFileError::Changed)?;
    }
    Ok(())
}

fn native_apply_file_attributes(
    handle: RawHandle,
    source: &Info,
) -> NativeResult<(), LocalNativeFileError> {
    let preserved = FILE_ATTRIBUTE_ARCHIVE
        | FILE_ATTRIBUTE_HIDDEN
        | FILE_ATTRIBUTE_SYSTEM
        | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
        | FILE_ATTRIBUTE_TEMPORARY;
    if source.attributes & !(preserved | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_NORMAL) != 0 {
        return Err(LocalNativeFileError::Unsupported);
    }
    let mut basic: FILE_BASIC_INFO = unsafe { zeroed() };
    basic.FileAttributes = source.attributes & preserved;
    if basic.FileAttributes == 0 {
        basic.FileAttributes = FILE_ATTRIBUTE_NORMAL;
    }
    if unsafe {
        SetFileInformationByHandle(
            handle,
            FileBasicInfo,
            (&basic as *const FILE_BASIC_INFO).cast::<c_void>(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(local_native_io(std::io::Error::last_os_error()));
    }
    Ok(())
}

fn native_hash_owned_file(
    file: &mut File,
    handle: RawHandle,
    expected_length: u64,
) -> NativeResult<(String, Info), LocalNativeFileError> {
    let before = info_of(handle).map_err(local_native_error)?;
    if before.size != expected_length {
        return Err(LocalNativeFileError::Changed);
    }
    file.seek(SeekFrom::Start(0)).map_err(local_native_io)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let count = file.read(&mut buffer).map_err(local_native_io)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(LocalNativeFileError::Limit)?;
        if total > expected_length {
            return Err(LocalNativeFileError::Changed);
        }
        digest.update(&buffer[..count]);
    }
    if total != expected_length {
        return Err(LocalNativeFileError::Changed);
    }
    let after = info_of(handle).map_err(local_native_error)?;
    if !same_native_file_info(&before, &after) {
        return Err(LocalNativeFileError::Changed);
    }
    file.seek(SeekFrom::Start(0)).map_err(local_native_io)?;
    Ok((format!("{:x}", digest.finalize()), after))
}

fn verify_native_publication(
    parent_path: &Path,
    parent: RawHandle,
    parent_info: &Info,
    name: &[u16],
    staged: RawHandle,
    expected_length: u64,
    expected_sha256: &str,
    expected_security: &NativeFileSecurity,
) -> NativeResult<String, LocalNativeFileError> {
    let held = info_of(staged).map_err(local_native_error)?;
    if held.nlink != 1 || held.size != expected_length {
        return Err(LocalNativeFileError::Changed);
    }
    let (published, before) = native_open_file(parent, name)?;
    if !same_native_file_identity(&before, &held)
        || before.nlink != 1
        || before.size != expected_length
    {
        return Err(LocalNativeFileError::Changed);
    }
    native_default_stream_only(published.as_raw_handle())?;
    if capture_native_file_security(published.as_raw_handle())?.security != *expected_security {
        return Err(LocalNativeFileError::Changed);
    }
    let file_handle = published.try_clone().map_err(local_native_io)?;
    let mut file = unsafe { File::from_raw_handle(file_handle.into_raw_handle()) };
    let (actual_sha256, hashed_info) =
        native_hash_owned_file(&mut file, published.as_raw_handle(), expected_length)?;
    if actual_sha256 != expected_sha256 || !same_native_file_info(&before, &hashed_info) {
        return Err(LocalNativeFileError::Changed);
    }
    let after = info_of(published.as_raw_handle()).map_err(local_native_error)?;
    let (_named, named) = native_open_file(parent, name)?;
    native_default_stream_only(published.as_raw_handle())?;
    if !same_native_file_info(&before, &after)
        || !same_native_file_info(&after, &named)
        || capture_native_file_security(published.as_raw_handle())?.security != *expected_security
    {
        return Err(LocalNativeFileError::Changed);
    }
    native_check_parent(parent_path, parent, parent_info)?;
    Ok(actual_sha256)
}

fn native_final_path(handle: RawHandle, expected: &Path) -> NativeResult<(), LocalNativeFileError> {
    let mut buffer = vec![0u16; 32_768];
    let length =
        unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0) }
            as usize;
    if length == 0 {
        return Err(local_native_io(std::io::Error::last_os_error()));
    }
    if length >= buffer.len()
        || buffer[..length] != expected.as_os_str().encode_wide().collect::<Vec<_>>()
    {
        return Err(LocalNativeFileError::Changed);
    }
    Ok(())
}

fn native_open_parent(path: &Path) -> NativeResult<(OwnedHandle, Info), LocalNativeFileError> {
    if !path.is_absolute() || path.as_os_str().len() > 32_768 {
        return Err(LocalNativeFileError::Invalid);
    }
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let handle = open_createfilew(GIT_DIRECTORY_ACCESS, |desired_access| {
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                desired_access,
                SHARE_ALL,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        (handle, unsafe { GetLastError() })
    })
    .map_err(local_native_error)?;
    let info = info_of(handle.as_raw_handle()).map_err(local_native_error)?;
    if kind_of(&info) != Kind::Directory {
        return Err(LocalNativeFileError::Changed);
    }
    native_final_path(handle.as_raw_handle(), path)?;
    Ok((handle, info))
}

fn native_open_absolute_directory_no_follow(
    path: &Path,
) -> NativeResult<(OwnedHandle, Info), LocalNativeFileError> {
    if !path.is_absolute()
        || path.as_os_str().len() > 32_768
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(LocalNativeFileError::Invalid);
    }
    let mut components = path.components();
    let prefix = match components.next() {
        Some(Component::Prefix(prefix))
            if matches!(
                prefix.kind(),
                Prefix::Disk(_)
                    | Prefix::VerbatimDisk(_)
                    | Prefix::UNC(_, _)
                    | Prefix::VerbatimUNC(_, _)
            ) =>
        {
            prefix
        }
        _ => return Err(LocalNativeFileError::Invalid),
    };
    let root = match components.next() {
        Some(Component::RootDir) => Component::RootDir,
        _ => return Err(LocalNativeFileError::Invalid),
    };
    let mut root_path = PathBuf::from(prefix.as_os_str());
    root_path.push(root.as_os_str());
    let wide = root_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut current = open_createfilew(DIRECTORY_ACCESS, |desired_access| {
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                desired_access,
                SHARE_ALL,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        (handle, unsafe { GetLastError() })
    })
    .map_err(local_native_error)?;
    let mut current_info = info_of(current.as_raw_handle()).map_err(local_native_error)?;
    if kind_of(&current_info) != Kind::Directory {
        return Err(LocalNativeFileError::Changed);
    }
    let mut count = 0usize;
    for part in components {
        let Component::Normal(name) = part else {
            return Err(LocalNativeFileError::Invalid);
        };
        count += 1;
        if count > 128 {
            return Err(LocalNativeFileError::Limit);
        }
        let name = name
            .to_str()
            .ok_or(LocalNativeFileError::Invalid)?
            .as_bytes();
        let name = component(name).map_err(local_native_error)?;
        let child = open_relative(
            current.as_raw_handle(),
            &name,
            DIRECTORY_ACCESS,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | SYNC,
            0,
            false,
        )
        .map_err(local_native_error)?;
        let child_info = info_of(child.as_raw_handle()).map_err(local_native_error)?;
        if kind_of(&child_info) != Kind::Directory {
            return Err(LocalNativeFileError::Changed);
        }
        current = child;
        current_info = child_info;
    }
    Ok((current, current_info))
}

fn native_open_file(
    parent: RawHandle,
    name: &[u16],
) -> NativeResult<(OwnedHandle, Info), LocalNativeFileError> {
    let base_access =
        FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
    let handle = match open_relative(
        parent,
        name,
        base_access | ACCESS_SYSTEM_SECURITY,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | SYNC,
        0,
        false,
    ) {
        Ok(handle) => handle,
        Err(Error::Unsupported | Error::Io(std::io::ErrorKind::PermissionDenied)) => open_relative(
            parent,
            name,
            base_access,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | SYNC,
            0,
            false,
        )
        .map_err(local_native_error)?,
        Err(error) => return Err(local_native_error(error)),
    };
    let info = info_of(handle.as_raw_handle()).map_err(local_native_error)?;
    if kind_of(&info) != Kind::File {
        return Err(LocalNativeFileError::Changed);
    }
    Ok((handle, info))
}

fn native_check_parent(
    path: &Path,
    pinned: RawHandle,
    expected: &Info,
) -> NativeResult<(), LocalNativeFileError> {
    let pinned_info = info_of(pinned).map_err(local_native_error)?;
    if kind_of(&pinned_info) != Kind::Directory || pinned_info.ident != expected.ident {
        return Err(LocalNativeFileError::Changed);
    }
    let (_current, current_info) = native_open_absolute_directory_no_follow(path)?;
    if current_info.ident != expected.ident {
        return Err(LocalNativeFileError::Changed);
    }
    Ok(())
}

fn native_require_absent(
    parent: RawHandle,
    name: &[u16],
) -> NativeResult<(), LocalNativeFileError> {
    match open_attributes(parent, name) {
        Ok(_) => Err(LocalNativeFileError::Exists),
        Err(Error::NotFound) => Ok(()),
        Err(error) => Err(local_native_error(error)),
    }
}

struct NativeFileTemporary {
    parent: OwnedHandle,
    name: Vec<u16>,
    handle: OwnedHandle,
    publish_handle: Option<OwnedHandle>,
    linked: bool,
    broker_session: Option<BrokerSession>,
    broker_token: Option<TempToken>,
}

impl NativeFileTemporary {
    fn open_publish_handle(&mut self) -> NativeResult<RawHandle, LocalNativeFileError> {
        if self.broker_token.is_some() && self.publish_handle.is_none() {
            let held = info_of(self.handle.as_raw_handle()).map_err(local_native_error)?;
            if kind_of(&held) != Kind::File || held.nlink != 1 {
                return Err(LocalNativeFileError::Changed);
            }
            let (_, named) = open_attributes(self.parent.as_raw_handle(), &self.name)
                .map_err(local_native_error)?;
            if named.ident != held.ident || named.nlink != 1 {
                return Err(LocalNativeFileError::Changed);
            }
            let handle = open_relative(
                self.parent.as_raw_handle(),
                &self.name,
                DELETE
                    | FILE_READ_DATA
                    | FILE_WRITE_DATA
                    | FILE_READ_ATTRIBUTES
                    | FILE_WRITE_ATTRIBUTES
                    | READ_CONTROL
                    | WRITE_DAC
                    | WRITE_OWNER
                    | SYNCHRONIZE,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | SYNC,
                0,
                false,
            )
            .map_err(local_native_error)?;
            let opened = info_of(handle.as_raw_handle()).map_err(local_native_error)?;
            if kind_of(&opened) != Kind::File || opened.ident != held.ident || opened.nlink != 1 {
                return Err(LocalNativeFileError::Changed);
            }
            self.publish_handle = Some(handle);
        }
        Ok(self
            .publish_handle
            .as_ref()
            .unwrap_or(&self.handle)
            .as_raw_handle())
    }

    fn rename_handle(&self) -> RawHandle {
        self.publish_handle
            .as_ref()
            .unwrap_or(&self.handle)
            .as_raw_handle()
    }

    /// Close every client write handle and retain a name-locked publication
    /// handle before copying source ACL/attributes. The new handle allows read
    /// sharing only, so an existing shared-directory temp cannot be modified
    /// through another path between finalization and rename.
    fn seal_for_git_leaf(&mut self) -> NativeResult<RawHandle, LocalNativeFileError> {
        if self.publish_handle.is_some() {
            return Err(LocalNativeFileError::Changed);
        }
        let before = info_of(self.handle.as_raw_handle()).map_err(local_native_error)?;
        if kind_of(&before) != Kind::File || before.nlink != 1 {
            return Err(LocalNativeFileError::Changed);
        }
        native_default_stream_only(self.handle.as_raw_handle())?;
        let readonly = open_relative(
            self.parent.as_raw_handle(),
            &self.name,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | SYNC,
            0,
            false,
        )
        .map_err(local_native_error)?;
        let readonly_info = info_of(readonly.as_raw_handle()).map_err(local_native_error)?;
        if readonly_info.ident != before.ident || readonly_info.nlink != 1 {
            return Err(LocalNativeFileError::Changed);
        }
        let old = std::mem::replace(&mut self.handle, readonly);
        drop(old);

        let publish = open_relative_with_share(
            self.parent.as_raw_handle(),
            &self.name,
            DELETE
                | FILE_READ_ATTRIBUTES
                | FILE_WRITE_ATTRIBUTES
                | FILE_READ_EA
                | FILE_WRITE_EA
                | READ_CONTROL
                | WRITE_DAC
                | WRITE_OWNER
                | SYNCHRONIZE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | SYNC,
            0,
            FILE_SHARE_READ,
            false,
        )
        .map_err(local_native_error)?;
        let publish_info = info_of(publish.as_raw_handle()).map_err(local_native_error)?;
        let named_info = info_of(self.handle.as_raw_handle()).map_err(local_native_error)?;
        if publish_info.ident != before.ident
            || named_info.ident != before.ident
            || publish_info.nlink != 1
            || named_info.nlink != 1
        {
            return Err(LocalNativeFileError::Changed);
        }
        self.publish_handle = Some(publish);
        Ok(self.publish_handle.as_ref().unwrap().as_raw_handle())
    }

    fn detach_published(&mut self) -> NativeResult<(), LocalNativeFileError> {
        if let (Some(session), Some(token)) =
            (self.broker_session.as_ref(), self.broker_token.as_ref())
        {
            session.try_release_temp(token)?;
            self.broker_token = None;
            self.broker_session = None;
        }
        self.linked = false;
        Ok(())
    }

    fn mark_published(&mut self) {
        // Set immediately after the namespace rename succeeds so any later
        // broker/metadata failure cannot make Drop unlink the public entry.
        self.linked = false;
    }

    fn finalize_published_git_leaf(
        &mut self,
        published: &File,
    ) -> NativeResult<(), LocalNativeFileError> {
        self.mark_published();
        if let (Some(session), Some(token)) =
            (self.broker_session.as_ref(), self.broker_token.as_ref())
        {
            session.finalize_published_temp(token, published)?;
            session.try_release_temp(token)?;
            self.broker_token = None;
            self.broker_session = None;
        }
        Ok(())
    }
}

impl Drop for NativeFileTemporary {
    fn drop(&mut self) {
        if self.linked {
            let delete_handle = self
                .publish_handle
                .as_ref()
                .unwrap_or(&self.handle)
                .as_raw_handle();
            if let Ok((named, named_info)) =
                open_attributes(self.parent.as_raw_handle(), &self.name)
                && info_of(delete_handle).is_ok_and(|held| held.ident == named_info.ident)
            {
                drop(named);
                let _ = delete_entry(delete_handle);
            }
            if let (Some(session), Some(token)) =
                (self.broker_session.as_ref(), self.broker_token.as_ref())
            {
                // Broker-created temps use a separate DELETE-capable handle
                // for publication. Close it before client-side cleanup opens
                // the private name with a no-delete sharing guard.
                drop(self.publish_handle.take());
                session.discard_temp(token);
            } else {
                let _ = delete_entry(self.handle.as_raw_handle());
            }
            let _ = sync_git_directory(self.parent.as_raw_handle());
        }
    }
}

fn native_temp(parent: &OwnedHandle) -> NativeResult<NativeFileTemporary, LocalNativeFileError> {
    native_temp_with_broker(parent, None)
}

fn native_temp_with_broker(
    parent: &OwnedHandle,
    inherited_session: Option<&BrokerSession>,
) -> NativeResult<NativeFileTemporary, LocalNativeFileError> {
    let operation_session = inherited_session.cloned().or_else(active_broker_session);
    for _ in 0..100 {
        let name_text = format!("lomi-temp-{}.tmp", uuid::Uuid::new_v4());
        match native_temp_named(parent, &name_text, operation_session.as_ref()) {
            Ok(temp) => return Ok(temp),
            Err(LocalNativeFileError::Exists) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(LocalNativeFileError::Limit)
}

/// Create a protected Git staging file using the active authenticated broker
/// even when this process happens to have local security privileges. Source
/// metadata finalization requires a broker token from the same session.
fn native_temp_from_broker(
    parent: &OwnedHandle,
    session: &BrokerSession,
) -> NativeResult<NativeFileTemporary, LocalNativeFileError> {
    for _ in 0..100 {
        let name_text = format!("lomi-temp-{}.tmp", uuid::Uuid::new_v4());
        let name = name_text.encode_utf16().collect::<Vec<_>>();
        let parent_clone = parent.try_clone().map_err(local_native_io)?;
        match session.create_temp(parent, &name_text) {
            Ok((handle, token, _)) => {
                let info = info_of(handle.as_raw_handle()).map_err(local_native_error)?;
                if kind_of(&info) != Kind::File || info.nlink != 1 {
                    session.discard_temp(&token);
                    return Err(LocalNativeFileError::Changed);
                }
                native_default_stream_only(handle.as_raw_handle())?;
                return Ok(NativeFileTemporary {
                    parent: parent_clone,
                    name,
                    handle,
                    publish_handle: None,
                    linked: true,
                    broker_session: Some(session.clone()),
                    broker_token: Some(token),
                });
            }
            Err(LocalNativeFileError::Exists) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(LocalNativeFileError::Limit)
}

fn native_temp_named(
    parent: &OwnedHandle,
    name_text: &str,
    inherited_session: Option<&BrokerSession>,
) -> NativeResult<NativeFileTemporary, LocalNativeFileError> {
    let operation_session = inherited_session.cloned().or_else(active_broker_session);
    let name = name_text.encode_utf16().collect::<Vec<_>>();
    let direct = open_relative(
        parent.as_raw_handle(),
        &name,
        DELETE
            | FILE_READ_DATA
            | FILE_WRITE_DATA
            | FILE_READ_ATTRIBUTES
            | FILE_WRITE_ATTRIBUTES
            | READ_CONTROL
            | WRITE_DAC
            | WRITE_OWNER
            | ACCESS_SYSTEM_SECURITY
            | SYNCHRONIZE,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | SYNC,
        FILE_ATTRIBUTE_NORMAL,
        false,
    );
    let (handle, broker_session, broker_token) = match direct {
        Ok(handle) => (handle, None, None),
        Err(Error::Exists) => return Err(LocalNativeFileError::Exists),
        Err(Error::Unsupported | Error::Io(std::io::ErrorKind::PermissionDenied)) => {
            let session = match operation_session.as_ref() {
                Some(session) => session.clone(),
                None => operation_broker_session()?,
            };
            let (handle, token, _) = session.create_temp(parent, name_text)?;
            (handle, Some(session), Some(token))
        }
        Err(error) => return Err(local_native_error(error)),
    };
    if kind_of(&info_of(handle.as_raw_handle()).map_err(local_native_error)?) != Kind::File {
        if let (Some(session), Some(token)) = (&broker_session, &broker_token) {
            session.discard_temp(token);
        }
        return Err(LocalNativeFileError::Changed);
    }
    Ok(NativeFileTemporary {
        parent: parent.try_clone().map_err(local_native_io)?,
        name,
        handle,
        publish_handle: None,
        linked: true,
        broker_session,
        broker_token,
    })
}

/// Explicit local editor target with a pinned parent and recorded file identity.
/// This is not part of the remote `FileRoot` API.
pub struct LocalNativeFile {
    path: PathBuf,
    parent_path: PathBuf,
    parent: OwnedHandle,
    parent_info: Info,
    name: Vec<u16>,
    target: Option<Info>,
}

impl LocalNativeFile {
    pub fn open(path: &Path) -> NativeResult<Self, LocalNativeFileError> {
        if !path.is_absolute() {
            return Err(LocalNativeFileError::Invalid);
        }
        let (path, target_exists) = match std::fs::canonicalize(path) {
            Ok(path) => (path, true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let parent = path.parent().ok_or(LocalNativeFileError::Invalid)?;
                let name = path.file_name().ok_or(LocalNativeFileError::Invalid)?;
                (
                    std::fs::canonicalize(parent)
                        .map_err(local_native_io)?
                        .join(name),
                    false,
                )
            }
            Err(error) => return Err(local_native_io(error)),
        };
        let parent_path = path
            .parent()
            .ok_or(LocalNativeFileError::Invalid)?
            .to_path_buf();
        let name_text = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(LocalNativeFileError::Invalid)?;
        let name = component(name_text.as_bytes()).map_err(local_native_error)?;
        let (parent, parent_info) = native_open_parent(&parent_path)?;
        let target = match native_open_file(parent.as_raw_handle(), &name) {
            Ok((_handle, info)) => {
                if !target_exists {
                    return Err(LocalNativeFileError::Exists);
                }
                Some(info)
            }
            Err(LocalNativeFileError::NotFound) if !target_exists => None,
            Err(error) => return Err(error),
        };
        Ok(Self {
            path,
            parent_path,
            parent,
            parent_info,
            name,
            target,
        })
    }

    /// Opens an absolute lexical path without traversing any reparse point in
    /// its parent chain or at its final component.
    pub fn open_no_follow(path: &Path) -> NativeResult<Self, LocalNativeFileError> {
        if !path.is_absolute()
            || path.as_os_str().len() > 32_768
            || path
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        {
            return Err(LocalNativeFileError::Invalid);
        }
        let parent_path = path
            .parent()
            .ok_or(LocalNativeFileError::Invalid)?
            .to_path_buf();
        let name_text = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(LocalNativeFileError::Invalid)?;
        let name = component(name_text.as_bytes()).map_err(local_native_error)?;
        let (parent, parent_info) = native_open_absolute_directory_no_follow(&parent_path)?;
        let target = match native_open_file(parent.as_raw_handle(), &name) {
            Ok((_handle, info)) => Some(info),
            Err(LocalNativeFileError::NotFound) => None,
            Err(error) => return Err(error),
        };
        Ok(Self {
            path: path.to_path_buf(),
            parent_path,
            parent,
            parent_info,
            name,
            target,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn is_new(&self) -> bool {
        self.target.is_none()
    }

    fn snapshot_with_info<E>(
        &self,
        check: &mut impl FnMut(LocalNativeFileCheckPhase) -> NativeResult<(), E>,
    ) -> std::result::Result<
        (
            LocalNativeFileSnapshot,
            Info,
            NativeFileSecurity,
            Option<BrokerSourceCapture>,
        ),
        LocalNativeFileReadError<E>,
    > {
        check(LocalNativeFileCheckPhase::Progress).map_err(LocalNativeFileReadError::Check)?;
        let expected = self.target.ok_or(LocalNativeFileReadError::File(
            LocalNativeFileError::NotFound,
        ))?;
        let (handle, before) = native_open_file(self.parent.as_raw_handle(), &self.name)
            .map_err(LocalNativeFileReadError::File)?;
        if before.ident != expected.ident || before.nlink == 0 {
            return Err(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            ));
        }
        if before.size > NATIVE_EDITOR_FILE_LIMIT {
            return Err(LocalNativeFileReadError::File(LocalNativeFileError::Limit));
        }
        native_default_stream_only(handle.as_raw_handle())
            .map_err(LocalNativeFileReadError::File)?;
        let captured = capture_native_file_security(handle.as_raw_handle())
            .map_err(LocalNativeFileReadError::File)?;
        let security_before = captured.security.clone();
        let file_handle = handle
            .try_clone()
            .map_err(|error| LocalNativeFileReadError::File(local_native_io(error)))?;
        let mut file = unsafe { File::from_raw_handle(file_handle.into_raw_handle()) };
        let mut bytes = Vec::with_capacity(before.size as usize);
        let mut chunk = [0u8; 65_536];
        loop {
            check(LocalNativeFileCheckPhase::Progress).map_err(LocalNativeFileReadError::Check)?;
            let count = file
                .read(&mut chunk)
                .map_err(|error| LocalNativeFileReadError::File(local_native_io(error)))?;
            if count == 0 {
                break;
            }
            if bytes.len() as u64 + count as u64 > NATIVE_EDITOR_FILE_LIMIT {
                return Err(LocalNativeFileReadError::File(LocalNativeFileError::Limit));
            }
            bytes.extend_from_slice(&chunk[..count]);
        }
        let after = info_of(handle.as_raw_handle())
            .map_err(local_native_error)
            .map_err(LocalNativeFileReadError::File)?;
        let (_named_handle, named) = open_attributes(self.parent.as_raw_handle(), &self.name)
            .map_err(local_native_error)
            .map_err(LocalNativeFileReadError::File)?;
        let security_after = if let Some(source) = captured.broker_source.as_ref() {
            source.recheck().map_err(LocalNativeFileReadError::File)?;
            native_file_security_with_audit_digest(
                handle.as_raw_handle(),
                Some(source.digest().map_err(LocalNativeFileReadError::File)?),
            )
            .map_err(LocalNativeFileReadError::File)?
        } else {
            native_file_security(handle.as_raw_handle()).map_err(LocalNativeFileReadError::File)?
        };
        native_default_stream_only(handle.as_raw_handle())
            .map_err(LocalNativeFileReadError::File)?;
        if !same_native_file_info(&before, &after)
            || !same_native_file_info(&before, &named)
            || security_before != security_after
            || bytes.len() as u64 != before.size
        {
            return Err(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            ));
        }
        Ok((
            LocalNativeFileSnapshot {
                sha256: format!("{:x}", Sha256::digest(&bytes)),
                bytes,
                read_only: before.attributes & FILE_ATTRIBUTE_READONLY != 0,
            },
            before,
            security_before,
            captured.broker_source,
        ))
    }

    pub fn snapshot<E>(
        &self,
        mut check: impl FnMut() -> NativeResult<(), E>,
    ) -> std::result::Result<LocalNativeFileSnapshot, LocalNativeFileReadError<E>> {
        let mut phased = |phase| match phase {
            LocalNativeFileCheckPhase::Progress | LocalNativeFileCheckPhase::BeforeEffect => {
                check()
            }
            LocalNativeFileCheckPhase::Validation | LocalNativeFileCheckPhase::Publication => {
                Ok(())
            }
        };
        self.snapshot_with_phase(&mut phased)
    }

    pub fn snapshot_with_phase<E>(
        &self,
        check: &mut impl FnMut(LocalNativeFileCheckPhase) -> NativeResult<(), E>,
    ) -> std::result::Result<LocalNativeFileSnapshot, LocalNativeFileReadError<E>> {
        let _broker_scope = BrokerOperationScope::enter();
        self.snapshot_with_info(check)
            .map(|(snapshot, _, _, _)| snapshot)
    }

    pub fn replace<E>(
        &self,
        expected_sha256: &str,
        bytes: &[u8],
        mut check: impl FnMut() -> NativeResult<(), E>,
    ) -> std::result::Result<String, LocalNativeFilePublishError<E>> {
        let mut phased = |phase| match phase {
            LocalNativeFileCheckPhase::Progress | LocalNativeFileCheckPhase::BeforeEffect => {
                check()
            }
            LocalNativeFileCheckPhase::Validation | LocalNativeFileCheckPhase::Publication => {
                Ok(())
            }
        };
        self.replace_with_phase(expected_sha256, bytes, &mut phased)
    }

    pub fn replace_with_phase<E>(
        &self,
        expected_sha256: &str,
        bytes: &[u8],
        check: &mut impl FnMut(LocalNativeFileCheckPhase) -> NativeResult<(), E>,
    ) -> std::result::Result<String, LocalNativeFilePublishError<E>> {
        let _broker_scope = BrokerOperationScope::enter();
        let before = |error| LocalNativeFilePublishError::Before(error);
        if bytes.len() as u64 > NATIVE_EDITOR_FILE_LIMIT {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Limit,
            )));
        }
        let (snapshot, metadata, security, mut broker_source) =
            self.snapshot_with_info(&mut *check).map_err(before)?;
        if snapshot.sha256 != expected_sha256 {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        if snapshot.read_only || metadata.nlink != 1 {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Protected,
            )));
        }
        let mut temporary = native_temp_with_broker(
            &self.parent,
            broker_source.as_ref().map(|source| &source.session),
        )
        .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        if temporary.broker_token.is_none() {
            native_owner_only_security(temporary.handle.as_raw_handle()).map_err(|error| {
                before(LocalNativeFileReadError::File(local_native_error(error)))
            })?;
        }
        let temp_file_handle = temporary
            .handle
            .try_clone()
            .map_err(|error| before(LocalNativeFileReadError::File(local_native_io(error))))?;
        let mut temp_file = unsafe { File::from_raw_handle(temp_file_handle.into_raw_handle()) };
        for chunk in bytes.chunks(65_536) {
            check(LocalNativeFileCheckPhase::Progress)
                .map_err(|error| before(LocalNativeFileReadError::Check(error)))?;
            temp_file
                .write_all(chunk)
                .map_err(|error| before(LocalNativeFileReadError::File(local_native_io(error))))?;
        }
        let broker_temp = temporary.broker_token.is_some();
        if !broker_temp {
            native_apply_file_security(temporary.handle.as_raw_handle(), &security)
                .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
            native_apply_file_attributes(temporary.handle.as_raw_handle(), &metadata)
                .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        }
        temp_file
            .sync_all()
            .map_err(|error| before(LocalNativeFileReadError::File(local_native_io(error))))?;
        let (staged_hash, held) = native_hash_owned_file(
            &mut temp_file,
            temporary.handle.as_raw_handle(),
            bytes.len() as u64,
        )
        .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        let expected_hash = format!("{:x}", Sha256::digest(bytes));
        if staged_hash != expected_hash {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        if kind_of(&held) != Kind::File
            || held.nlink != 1
            || held.size != bytes.len() as u64
            || (!broker_temp
                && !native_file_security_matches(temporary.handle.as_raw_handle(), &security)
                    .map_err(|error| before(LocalNativeFileReadError::File(error)))?)
        {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        native_default_stream_only(temporary.handle.as_raw_handle())
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        drop(broker_source.take());
        let (current, current_info, current_security, current_broker_source) = self
            .snapshot_with_info(&mut |_| Ok::<(), std::convert::Infallible>(()))
            .map_err(|error| before(native_no_check_read_error(error)))?;
        broker_source = current_broker_source;
        if current.sha256 != expected_sha256
            || !same_native_file_info(&current_info, &metadata)
            || current_security != security
        {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        check(LocalNativeFileCheckPhase::Progress)
            .map_err(|error| before(LocalNativeFileReadError::Check(error)))?;
        let held_after_check = info_of(temporary.handle.as_raw_handle())
            .map_err(local_native_error)
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        if !same_native_file_info(&held, &held_after_check)
            || (!broker_temp
                && !native_file_security_matches(temporary.handle.as_raw_handle(), &security)
                    .map_err(|error| before(LocalNativeFileReadError::File(error)))?)
        {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        native_default_stream_only(temporary.handle.as_raw_handle())
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        let (_temp_named, temp_named_info) =
            native_open_file(self.parent.as_raw_handle(), &temporary.name)
                .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        if !same_native_file_info(&temp_named_info, &held_after_check) {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        let final_target = native_open_file(self.parent.as_raw_handle(), &self.name)
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        if !same_native_file_info(&final_target.1, &current_info)
            || !native_file_security_matches(final_target.0.as_raw_handle(), &security)
                .map_err(|error| before(LocalNativeFileReadError::File(error)))?
        {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        native_default_stream_only(final_target.0.as_raw_handle())
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        native_check_parent(
            &self.parent_path,
            self.parent.as_raw_handle(),
            &self.parent_info,
        )
        .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        if let Some(source) = broker_source.as_ref() {
            source
                .recheck()
                .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
            if let Some(token) = temporary.broker_token.as_ref() {
                source
                    .finalize(token)
                    .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
            } else if matches!(security.audit_sacl, AuditSacl::Broker(_)) {
                return Err(before(LocalNativeFileReadError::File(
                    LocalNativeFileError::Unsupported,
                )));
            }
            if broker_temp {
                let publish_handle = temporary
                    .open_publish_handle()
                    .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
                native_apply_file_security(publish_handle, &security)
                    .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
                native_apply_file_attributes(publish_handle, &metadata)
                    .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
                if capture_native_file_security(publish_handle)
                    .map_err(|error| before(LocalNativeFileReadError::File(error)))?
                    .security
                    != security
                {
                    return Err(before(LocalNativeFileReadError::File(
                        LocalNativeFileError::Changed,
                    )));
                }
                source
                    .recheck()
                    .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
            }
        }
        drop(broker_source.take());
        check(LocalNativeFileCheckPhase::BeforeEffect)
            .map_err(|error| before(LocalNativeFileReadError::Check(error)))?;
        check(LocalNativeFileCheckPhase::Validation)
            .map_err(|error| before(LocalNativeFileReadError::Check(error)))?;
        let (latest, latest_source_info, latest_source_security, latest_broker_source) = self
            .snapshot_with_info(&mut |_| Ok::<(), std::convert::Infallible>(()))
            .map_err(|error| before(native_no_check_read_error(error)))?;
        broker_source = latest_broker_source;
        if latest.sha256 != expected_sha256
            || !same_native_file_info(&latest_source_info, &metadata)
            || latest_source_security != security
        {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        let (final_temp_hash, final_temp_info) = native_hash_owned_file(
            &mut temp_file,
            temporary.handle.as_raw_handle(),
            bytes.len() as u64,
        )
        .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        if final_temp_hash != expected_hash
            || kind_of(&final_temp_info) != Kind::File
            || final_temp_info.ident != held.ident
            || final_temp_info.nlink != 1
            || final_temp_info.size != bytes.len() as u64
        {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        native_default_stream_only(temporary.handle.as_raw_handle())
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        if capture_native_file_security(temporary.rename_handle())
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?
            .security
            != security
        {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        let (_final_temp_named, final_temp_named_info) =
            native_open_file(self.parent.as_raw_handle(), &temporary.name)
                .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        if !same_native_file_info(&final_temp_info, &final_temp_named_info) {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        if let Some(source) = broker_source.as_ref() {
            source
                .recheck()
                .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        }
        let (latest_target, latest_info) =
            native_open_file(self.parent.as_raw_handle(), &self.name)
                .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        if !same_native_file_info(&latest_source_info, &latest_info)
            || !native_file_security_matches(latest_target.as_raw_handle(), &latest_source_security)
                .map_err(|error| before(LocalNativeFileReadError::File(error)))?
        {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        native_check_parent(
            &self.parent_path,
            self.parent.as_raw_handle(),
            &self.parent_info,
        )
        .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        check(LocalNativeFileCheckPhase::Publication)
            .map_err(|error| before(LocalNativeFileReadError::Check(error)))?;
        rename_replace(
            temporary.rename_handle(),
            self.parent.as_raw_handle(),
            &self.name,
        )
        .map_err(|error| before(LocalNativeFileReadError::File(local_native_error(error))))?;
        if temporary.detach_published().is_err() {
            temporary.linked = false;
            return Err(LocalNativeFilePublishError::Uncertain);
        }
        let published = verify_native_publication(
            &self.parent_path,
            self.parent.as_raw_handle(),
            &self.parent_info,
            &self.name,
            temporary.handle.as_raw_handle(),
            bytes.len() as u64,
            &expected_hash,
            &security,
        )
        .map_err(|_| LocalNativeFilePublishError::Uncertain)?;
        sync_git_directory(self.parent.as_raw_handle())
            .map_err(|_| LocalNativeFilePublishError::Uncertain)?;
        Ok(published)
    }

    pub fn create<E>(
        &self,
        bytes: &[u8],
        mut check: impl FnMut() -> NativeResult<(), E>,
    ) -> std::result::Result<String, LocalNativeFilePublishError<E>> {
        let mut phased = |phase| match phase {
            LocalNativeFileCheckPhase::Progress | LocalNativeFileCheckPhase::BeforeEffect => {
                check()
            }
            LocalNativeFileCheckPhase::Validation | LocalNativeFileCheckPhase::Publication => {
                Ok(())
            }
        };
        self.create_with_phase(bytes, &mut phased)
    }

    pub fn create_with_phase<E>(
        &self,
        bytes: &[u8],
        check: &mut impl FnMut(LocalNativeFileCheckPhase) -> NativeResult<(), E>,
    ) -> std::result::Result<String, LocalNativeFilePublishError<E>> {
        let _broker_scope = BrokerOperationScope::enter();
        let before = |error| LocalNativeFilePublishError::Before(error);
        if bytes.len() as u64 > NATIVE_EDITOR_FILE_LIMIT {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Limit,
            )));
        }
        if self.target.is_some() {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Exists,
            )));
        }
        let mut temporary = native_temp(&self.parent)
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        let extended = native_owner_only_security_with_session(
            temporary.handle.as_raw_handle(),
            temporary.broker_session.as_ref(),
        )
        .map_err(|error| before(LocalNativeFileReadError::File(local_native_error(error))))?;
        let security = GitFileSecurity {
            attributes: info_of(temporary.handle.as_raw_handle())
                .map_err(local_native_error)
                .map_err(|error| before(LocalNativeFileReadError::File(error)))?
                .attributes,
            extended,
        };
        let temp_file_handle = temporary
            .handle
            .try_clone()
            .map_err(|error| before(LocalNativeFileReadError::File(local_native_io(error))))?;
        let mut temp_file = unsafe { File::from_raw_handle(temp_file_handle.into_raw_handle()) };
        for chunk in bytes.chunks(65_536) {
            check(LocalNativeFileCheckPhase::Progress)
                .map_err(|error| before(LocalNativeFileReadError::Check(error)))?;
            temp_file
                .write_all(chunk)
                .map_err(|error| before(LocalNativeFileReadError::File(local_native_io(error))))?;
        }
        temp_file
            .sync_all()
            .map_err(|error| before(LocalNativeFileReadError::File(local_native_io(error))))?;
        let expected_hash = format!("{:x}", Sha256::digest(bytes));
        let (staged_hash, held) = native_hash_owned_file(
            &mut temp_file,
            temporary.handle.as_raw_handle(),
            bytes.len() as u64,
        )
        .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        if staged_hash != expected_hash {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        if held.nlink != 1 || held.size != bytes.len() as u64 {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        native_default_stream_only(temporary.handle.as_raw_handle())
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        check(LocalNativeFileCheckPhase::Progress)
            .map_err(|error| before(LocalNativeFileReadError::Check(error)))?;
        let held_after_check = info_of(temporary.handle.as_raw_handle())
            .map_err(local_native_error)
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        if !same_native_file_info(&held, &held_after_check)
            || git_file_security(temporary.handle.as_raw_handle()).map_err(|error| {
                before(LocalNativeFileReadError::File(local_native_error(error)))
            })? != security
        {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        native_default_stream_only(temporary.handle.as_raw_handle())
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        let (_temp_named, temp_named_info) =
            native_open_file(self.parent.as_raw_handle(), &temporary.name)
                .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        if !same_native_file_info(&temp_named_info, &held_after_check) {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        native_check_parent(
            &self.parent_path,
            self.parent.as_raw_handle(),
            &self.parent_info,
        )
        .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        native_require_absent(self.parent.as_raw_handle(), &self.name)
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        let rename_handle = temporary
            .open_publish_handle()
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        check(LocalNativeFileCheckPhase::BeforeEffect)
            .map_err(|error| before(LocalNativeFileReadError::Check(error)))?;
        check(LocalNativeFileCheckPhase::Validation)
            .map_err(|error| before(LocalNativeFileReadError::Check(error)))?;
        let (final_temp_hash, final_temp_info) = native_hash_owned_file(
            &mut temp_file,
            temporary.handle.as_raw_handle(),
            bytes.len() as u64,
        )
        .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        if final_temp_hash != expected_hash
            || kind_of(&final_temp_info) != Kind::File
            || final_temp_info.ident != held.ident
            || final_temp_info.nlink != 1
            || final_temp_info.size != bytes.len() as u64
        {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        native_default_stream_only(temporary.handle.as_raw_handle())
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        if git_file_security(temporary.rename_handle())
            .map_err(|error| before(LocalNativeFileReadError::File(local_native_error(error))))?
            != security
        {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        let (_final_temp_named, final_temp_named_info) =
            native_open_file(self.parent.as_raw_handle(), &temporary.name)
                .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        if !same_native_file_info(&final_temp_info, &final_temp_named_info) {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        native_require_absent(self.parent.as_raw_handle(), &self.name)
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        native_check_parent(
            &self.parent_path,
            self.parent.as_raw_handle(),
            &self.parent_info,
        )
        .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        check(LocalNativeFileCheckPhase::Publication)
            .map_err(|error| before(LocalNativeFileReadError::Check(error)))?;
        rename_no_replace(rename_handle, self.parent.as_raw_handle(), &self.name)
            .map_err(|error| before(LocalNativeFileReadError::File(local_native_error(error))))?;
        if temporary.detach_published().is_err() {
            temporary.linked = false;
            return Err(LocalNativeFilePublishError::Uncertain);
        }
        let published = verify_native_publication(
            &self.parent_path,
            self.parent.as_raw_handle(),
            &self.parent_info,
            &self.name,
            temporary.handle.as_raw_handle(),
            bytes.len() as u64,
            &expected_hash,
            &security.extended,
        )
        .map_err(|_| LocalNativeFilePublishError::Uncertain)?;
        sync_git_directory(self.parent.as_raw_handle())
            .map_err(|_| LocalNativeFilePublishError::Uncertain)?;
        Ok(published)
    }
}

fn git_target_exists(parent: RawHandle, name: &[u16]) -> Result<bool> {
    match open_attributes(parent, name) {
        Ok(_) => Ok(true),
        Err(Error::NotFound) => Ok(false),
        Err(error) => Err(error),
    }
}

fn check_git_lock_identity(
    parent: RawHandle,
    name: &[u16],
    lock: RawHandle,
    expected: Ident,
) -> Result<()> {
    let lock_info = info_of(lock)?;
    if kind_of(&lock_info) != Kind::File || lock_info.nlink != 1 || lock_info.ident != expected {
        return Err(Error::Changed);
    }
    let (_named_handle, named_info) = open_attributes(parent, name).map_err(|error| {
        if error == Error::NotFound {
            Error::Changed
        } else {
            error
        }
    })?;
    if kind_of(&named_info) != Kind::File || named_info.nlink != 1 || named_info.ident != expected {
        return Err(Error::Changed);
    }
    Ok(())
}

fn write_git_bytes(
    file: &mut File,
    bytes: &[u8],
    continue_check: &mut impl FnMut() -> bool,
) -> Result<bool> {
    for chunk in bytes.chunks(64 * 1024) {
        if !continue_check() {
            return Ok(false);
        }
        file.write_all(chunk).map_err(map_os)?;
    }
    Ok(continue_check())
}

fn hash_git_file(file: &mut File, expected_len: usize) -> Result<[u8; 32]> {
    file.seek(SeekFrom::Start(0)).map_err(map_os)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 16 * 1024];
    let mut total = 0usize;
    loop {
        let read = file.read(&mut buffer).map_err(map_os)?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read).ok_or(Error::Limit)?;
        if total > expected_len {
            return Err(Error::Changed);
        }
        digest.update(&buffer[..read]);
    }
    if total != expected_len {
        return Err(Error::Changed);
    }
    file.seek(SeekFrom::Start(0)).map_err(map_os)?;
    Ok(digest.finalize().into())
}

fn install_git_object(
    directory: RawHandle,
    suffix: &[u8],
    bytes: &[u8],
    continue_check: &mut impl FnMut() -> bool,
) -> Result<()> {
    let expected_digest: [u8; 32] = Sha256::digest(bytes).into();
    match verify_existing_git_object(directory, suffix, bytes, continue_check) {
        Ok(()) => {
            sync_git_directory(directory)?;
            return Ok(());
        }
        Err(Error::NotFound) => {}
        Err(error) => return Err(error),
    }

    let parent = duplicate_handle_as_owned(directory).map_err(git_native_security_error)?;
    let mut temporary =
        native_temp_with_broker(&parent, None).map_err(git_native_security_error)?;
    let handle = temporary.handle.try_clone().map_err(map_os)?;
    let write_result = (|| {
        let mut file =
            unsafe { File::from_raw_handle(handle.try_clone().map_err(map_os)?.into_raw_handle()) };
        let security = native_owner_only_file_security(handle.as_raw_handle())?;
        if !write_git_bytes(&mut file, bytes, continue_check)? {
            return Ok(false);
        }
        file.sync_all().map_err(map_os)?;
        if git_file_security(handle.as_raw_handle())?.extended != security.extended
            || hash_git_file(&mut file, bytes.len())? != expected_digest
        {
            return Err(Error::Changed);
        }
        Ok(true)
    })();
    if !matches!(write_result, Ok(true)) {
        return match write_result {
            Ok(false) => Err(Error::Changed),
            Err(error) => Err(error),
            Ok(true) => unreachable!(),
        };
    }
    if !continue_check() {
        return Err(Error::Changed);
    }
    let target = component(suffix)?;
    let published_security = git_file_security(handle.as_raw_handle())?;
    if hash_git_file(
        &mut unsafe {
            File::from_raw_handle(handle.try_clone().map_err(map_os)?.into_raw_handle())
        },
        bytes.len(),
    )? != expected_digest
    {
        return Err(Error::Changed);
    }
    let rename_handle = temporary
        .open_publish_handle()
        .map_err(git_native_security_error)?;
    match rename_no_replace(rename_handle, directory, &target) {
        Ok(()) => {
            temporary
                .detach_published()
                .map_err(git_native_security_error)?;
            let visible = git_named_file_security(directory, &target)?;
            let mut file = unsafe {
                File::from_raw_handle(handle.try_clone().map_err(map_os)?.into_raw_handle())
            };
            if check_git_lock_identity(
                directory,
                &target,
                handle.as_raw_handle(),
                info_of(handle.as_raw_handle())?.ident,
            )
            .is_err()
                || visible.as_ref() != Some(&published_security)
                || hash_git_file(&mut file, bytes.len())? != expected_digest
            {
                return Err(Error::Changed);
            }
            sync_git_directory(directory)
        }
        Err(Error::Exists) => {
            verify_existing_git_object(directory, suffix, bytes, continue_check)?;
            sync_git_directory(directory)
        }
        Err(error) => Err(error),
    }
}

fn verify_existing_git_object(
    directory: RawHandle,
    name: &[u8],
    bytes: &[u8],
    continue_check: &mut impl FnMut() -> bool,
) -> Result<()> {
    let name = component(name)?;
    let handle = open_relative(
        directory,
        &name,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | SYNC,
        0,
        false,
    )?;
    let info = info_of(handle.as_raw_handle())?;
    if kind_of(&info) != Kind::File || info.nlink != 1 || info.size as usize != bytes.len() {
        return Err(Error::Protected);
    }
    let mut file = unsafe { File::from_raw_handle(handle.into_raw_handle()) };
    let mut contents = Vec::with_capacity(bytes.len());
    let mut chunk = [0u8; 64 * 1024];
    loop {
        if !continue_check() {
            return Err(Error::Changed);
        }
        let count = file.read(&mut chunk).map_err(map_os)?;
        if count == 0 {
            break;
        }
        contents.extend_from_slice(&chunk[..count]);
        if contents.len() > bytes.len() {
            return Err(Error::Changed);
        }
    }
    if contents != bytes {
        return Err(Error::Changed);
    }
    Ok(())
}

/// Opaque invalidation source for a directory pinned by `FileRoot`.
pub struct DirectoryWatch {
    handle: OwnedHandle,
    _directory: OwnedHandle,
    // The OS retains pointers to both fields while the request is pending.
    // Pinning the state gives those pointers a stable address; the mutex also
    // serializes polling and prevents simultaneous access to the completion.
    state: Mutex<std::pin::Pin<Box<WatchState>>>,
}

struct WatchState {
    overlapped: OVERLAPPED,
    buffer: Box<[u8]>,
}

impl WatchState {
    fn new() -> Self {
        Self {
            overlapped: unsafe { zeroed() },
            buffer: vec![0; WATCH_BUFFER_SIZE].into_boxed_slice(),
        }
    }
}

fn arm_directory_watch(handle: RawHandle, state: &mut WatchState) -> Result<()> {
    state.overlapped = unsafe { zeroed() };
    let filter = FILE_NOTIFY_CHANGE_FILE_NAME
        | FILE_NOTIFY_CHANGE_DIR_NAME
        | FILE_NOTIFY_CHANGE_ATTRIBUTES
        | FILE_NOTIFY_CHANGE_SIZE
        | FILE_NOTIFY_CHANGE_LAST_WRITE
        | FILE_NOTIFY_CHANGE_CREATION;
    let ok = unsafe {
        ReadDirectoryChangesW(
            handle,
            state.buffer.as_mut_ptr().cast(),
            state.buffer.len() as u32,
            0,
            filter,
            null_mut(),
            &mut state.overlapped,
            None,
        )
    };
    if ok != 0 {
        // With an OVERLAPPED handle, TRUE means the request was accepted; it
        // does not prove the notification is already complete. Poll the
        // OVERLAPPED with GetOverlappedResult on every subsequent check.
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_IO_PENDING) {
        Ok(())
    } else {
        Err(map_watch_error(error))
    }
}

fn map_watch_error(error: std::io::Error) -> Error {
    match error.raw_os_error() {
        Some(ERROR_NOTIFY_ENUM_DIR) => Error::Limit,
        _ => map_os(error),
    }
}

fn validate_notify_records(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        return Err(Error::Changed);
    }
    let mut offset = 0usize;
    loop {
        let header_end = offset.checked_add(12).ok_or(Error::Changed)?;
        if header_end > bytes.len() {
            return Err(Error::Changed);
        }
        let next = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let action = u32::from_ne_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
        let name_bytes =
            u32::from_ne_bytes(bytes[offset + 8..offset + 12].try_into().unwrap()) as usize;
        if !(1..=5).contains(&action) || name_bytes == 0 || name_bytes % 2 != 0 {
            return Err(Error::Changed);
        }
        let end = header_end.checked_add(name_bytes).ok_or(Error::Changed)?;
        if end > bytes.len() {
            return Err(Error::Changed);
        }
        if next == 0 {
            return Ok(());
        }
        if next < 12
            || next % 4 != 0
            || offset
                .checked_add(next)
                .is_none_or(|n| n < end || n > bytes.len())
        {
            return Err(Error::Changed);
        }
        offset += next;
    }
}

impl DirectoryWatch {
    /// Polls the outstanding overlapped request without waiting. Any event
    /// requires reconciliation; malformed/overflow completions fail closed.
    pub fn changed(&self) -> Result<bool> {
        let mut pinned = self.state.lock().map_err(|_| Error::Limit)?;
        let state = pinned.as_mut().get_mut();
        let mut transferred = 0u32;
        let complete = unsafe {
            GetOverlappedResult(
                self.handle.as_raw_handle(),
                &state.overlapped,
                &mut transferred,
                0,
            )
        } != 0;
        if !complete {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.raw_os_error(),
                Some(ERROR_IO_INCOMPLETE | ERROR_IO_PENDING)
            ) {
                return Ok(false);
            }
            return Err(map_watch_error(error));
        }
        if transferred == 0 || transferred as usize > state.buffer.len() {
            return Err(Error::Changed);
        }
        validate_notify_records(&state.buffer[..transferred as usize])?;
        arm_directory_watch(self.handle.as_raw_handle(), state)?;
        Ok(true)
    }
}

impl Drop for DirectoryWatch {
    fn drop(&mut self) {
        let Ok(mut pinned) = self.state.lock() else {
            return;
        };
        let state = pinned.as_mut().get_mut();
        unsafe {
            CancelIoEx(self.handle.as_raw_handle(), &state.overlapped);
        }
        // Keep the OVERLAPPED and its buffer alive until the kernel has
        // completed cancellation. Closing the handle alone is not enough to
        // make those pointers safe to release.
        let mut transferred = 0u32;
        unsafe {
            GetOverlappedResult(
                self.handle.as_raw_handle(),
                &state.overlapped,
                &mut transferred,
                1,
            );
        }
    }
}
