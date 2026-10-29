//! Narrow LocalSystem helper for preserving a user's file SACL on a new temp.
//!
//! The broker only captures SACL state from a handle supplied by the connected
//! owner, creates a new owner-private file relative to a supplied directory
//! handle, and copies the captured SACL state to that file. It never accepts a
//! path or a security descriptor from the client, and it has no publish or
//! rename operation. The ordinary file handle returned to the client has
//! write-data access only; it does not carry ACCESS_SYSTEM_SECURITY.

use super::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;
use windows_sys::Wdk::Foundation::{NtQueryObject, OBJECT_ATTRIBUTES, OBJECT_NAME_INFORMATION};
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_COMPLETE_IF_OPLOCKED, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_DISPOSITION_INFORMATION,
    FILE_FS_ATTRIBUTE_INFORMATION, FILE_ID_INFORMATION, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    FILE_OPEN_BY_FILE_ID, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
    FileDispositionInformation, FileFsAttributeInformation, FileIdInformation, NtCreateFile,
    NtQueryInformationFile, NtQueryVolumeInformationFile, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_IO_PENDING, ERROR_MORE_DATA,
    ERROR_NOT_ALL_ASSIGNED, ERROR_PIPE_CONNECTED, GetLastError, HANDLE, SetLastError, WAIT_FAILED,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, GetSecurityInfo, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AdjustTokenPrivileges,
    DACL_SECURITY_INFORMATION, DuplicateTokenEx, GetAce, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetTokenInformation,
    InitializeSecurityDescriptor, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
    OWNER_SECURITY_INFORMATION, PROTECTED_SACL_SECURITY_INFORMATION, SACL_SECURITY_INFORMATION,
    SE_CREATE_SYMBOLIC_LINK_NAME, SE_DACL_PROTECTED, SE_PRIVILEGE_ENABLED, SECURITY_ATTRIBUTES,
    SECURITY_DESCRIPTOR, SecurityImpersonation, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, SetSecurityDescriptorOwner, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER,
    TokenImpersonation, TokenImpersonationLevel, TokenUser, UNPROTECTED_SACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TEMPORARY, FILE_FLAG_OVERLAPPED,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TYPE_DISK, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, GetFileType,
    PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows_sys::Win32::System::IO::{
    CancelIoEx, DeviceIoControl, GetOverlappedResult, IO_STATUS_BLOCK, OVERLAPPED,
};
use windows_sys::Win32::System::Ioctl::{FSCTL_GET_REPARSE_POINT, FSCTL_SET_REPARSE_POINT};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeServerProcessId, ImpersonateNamedPipeClient, PIPE_READMODE_MESSAGE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_WAIT, SetNamedPipeHandleState,
    WaitNamedPipeW,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken,
    OpenThreadToken, PROCESS_DUP_HANDLE, PROCESS_QUERY_LIMITED_INFORMATION, SetThreadToken,
    WaitForSingleObject,
};

const PROTOCOL_VERSION: u8 = 1;
const MAX_MESSAGE: usize = 32 * 1024;
const MAX_FRAME_BODY: usize = MAX_MESSAGE - size_of::<u32>();
const MAX_ACL_BYTES: usize = 64 * 1024;
const MAX_SOURCE_RECORDS: usize = 32;
// Git pull publication currently admits at most 200 changed files. Leave
// room for metadata locks and a small amount of publication bookkeeping.
const MAX_TEMP_RECORDS: usize = 256;
// The Git validator admits 200,000 objects. Budget 128 broker round trips
// per object, plus 200 changed paths and security metadata requests. 2^25
// leaves headroom for that workload while the one-hour session deadline
// remains the practical bound for a continuously-requesting client.
const MAX_REQUESTS_PER_CONNECTION: usize = 1 << 25;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const SERVER_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const MAX_SESSION_DURATION: Duration = Duration::from_secs(60 * 60);
const IO_POLL_MS: u32 = 50;
const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const SHARE_WITHOUT_DELETE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;
const FILE_ALL_ACCESS_MASK: u32 = 0x001f_01ff;
// FILE_WRITE_ATTRIBUTES permits message-mode configuration. Deliberately omit
// FILE_CREATE_PIPE_INSTANCE (also FILE_APPEND_DATA); GENERIC_WRITE includes it.
const PIPE_OWNER_ACCESS: u32 = 0x0012_0103;
const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const OBJ_DONT_REPARSE: u32 = 0x1000;
const STATUS_OBJECT_NAME_COLLISION: i32 = 0xC000_0035u32 as i32;
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;
const STATUS_OBJECT_PATH_NOT_FOUND: i32 = 0xC000_003Au32 as i32;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
const STATUS_OPLOCK_BREAK_IN_PROGRESS: i32 = 0x0000_0108;
const OBJECT_NAME_INFORMATION_CLASS: i32 = 1;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const MAX_REPARSE_BUFFER: usize = 16 * 1024;
const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
const SYMLINK_FLAG_RELATIVE: u32 = 1;

const OP_CAPTURE_SOURCE: u8 = 1;
const OP_RECHECK_SOURCE: u8 = 2;
const OP_CREATE_TEMP: u8 = 3;
const OP_FINALIZE_TEMP_SECURITY: u8 = 4;
const OP_RELEASE_SOURCE: u8 = 6;
const OP_RELEASE_TEMP: u8 = 7;
const OP_DISCARD_TEMP: u8 = 8;
const OP_CREATE_SYMLINK_TEMP: u8 = 9;
const OP_SET_SYMLINK_TEMP: u8 = 10;
const OP_CAPTURE_SOURCE_PINNED: u8 = 11;
const OP_FINALIZE_PUBLISHED_TEMP: u8 = 12;

const STATUS_OK: u8 = 0;
const STATUS_INVALID: u8 = 1;
const STATUS_CHANGED: u8 = 2;
const STATUS_LIMIT: u8 = 3;
const STATUS_UNSUPPORTED: u8 = 4;
const STATUS_IO: u8 = 5;

/// Result type for the Windows LocalSystem file-security broker.
pub type SecurityBrokerResult<T> = std::result::Result<T, SecurityBrokerError>;

/// A bounded broker failure. Native error text and security data never cross
/// the named-pipe protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityBrokerError {
    Invalid,
    Changed,
    Limit,
    Unsupported,
    Io(io::ErrorKind),
}

impl From<LocalNativeFileError> for SecurityBrokerError {
    fn from(value: LocalNativeFileError) -> Self {
        match value {
            LocalNativeFileError::Changed => Self::Changed,
            LocalNativeFileError::Invalid => Self::Invalid,
            LocalNativeFileError::Limit => Self::Limit,
            LocalNativeFileError::NotFound => Self::Io(io::ErrorKind::NotFound),
            LocalNativeFileError::Exists => Self::Io(io::ErrorKind::AlreadyExists),
            LocalNativeFileError::Protected => Self::Unsupported,
            LocalNativeFileError::Unsupported => Self::Unsupported,
            LocalNativeFileError::Io => Self::Io(io::ErrorKind::Other),
        }
    }
}

fn engine_error(error: Error) -> SecurityBrokerError {
    match error {
        Error::Changed => SecurityBrokerError::Changed,
        Error::Invalid => SecurityBrokerError::Invalid,
        Error::Limit => SecurityBrokerError::Limit,
        Error::Io(kind) => SecurityBrokerError::Io(kind),
        Error::NotFound => SecurityBrokerError::Io(io::ErrorKind::NotFound),
        Error::Exists => SecurityBrokerError::Io(io::ErrorKind::AlreadyExists),
        Error::Protected | Error::NotEmpty | Error::Unsupported => SecurityBrokerError::Unsupported,
    }
}

/// Client-side connection to the configured owner's LocalSystem broker.
///
/// The pipe identity is checked before any request is sent. Each successful
/// response is tied to the session nonce minted by that pipe connection.
pub struct SecurityBrokerClient {
    pipe: Option<OwnedHandle>,
    session: Option<[u8; 16]>,
    owner_sid: Vec<u8>,
}

/// Opaque source-security capture. Only the digest is observable; the SACL and
/// source handle stay in the broker process.
pub struct SourceSnapshot {
    session: [u8; 16],
    id: [u8; 16],
    digest: [u8; 32],
}

impl SourceSnapshot {
    /// Digest of the captured audit SACL, protection state, label, resource
    /// attributes, and scoped-policy component.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Opaque reference to one broker-created temp file.
pub struct TempToken {
    session: [u8; 16],
    id: [u8; 16],
    owner_sid: Vec<u8>,
    parent: File,
    name: String,
    identity: Ident,
    kind: TempKind,
    expected_reparse: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TempKind {
    File,
    PendingSymlink { directory: bool },
    Symlink { directory: bool },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceKind {
    File,
    Symlink { directory: bool },
}

/// New temp and its user-rights content handle. The handle grants no
/// ACCESS_SYSTEM_SECURITY and the broker has no API that publishes it.
pub struct BrokerTemp {
    file: File,
    token: TempToken,
    name: String,
}

/// A broker-created symlink temp. The handle is opened without following its
/// reparse point and grants only ordinary user access. The target bytes remain
/// in the private broker token until publication or discard.
pub struct BrokerSymlinkTemp {
    file: File,
    token: TempToken,
    name: String,
    directory: bool,
}

impl BrokerSymlinkTemp {
    /// The no-follow handle to the newly-created symlink object.
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Opaque identity required by the matching release/discard operation.
    pub fn token(&self) -> &TempToken {
        &self.token
    }

    /// The validated private basename.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the reparse point is backed by a directory object.
    pub fn is_directory(&self) -> bool {
        self.directory
    }

    /// The acknowledged symbolic-link reparse buffer, for a final local
    /// identity/type check after the publisher renames the object.
    pub fn expected_reparse(&self) -> SecurityBrokerResult<&[u8]> {
        self.token
            .expected_reparse
            .as_deref()
            .ok_or(SecurityBrokerError::Changed)
    }

    /// Confirm that a separately opened no-follow handle is still the exact
    /// broker-created link with the acknowledged reparse payload.
    pub fn verify_file(&self, file: &File) -> SecurityBrokerResult<()> {
        let expected = self
            .token
            .expected_reparse
            .as_deref()
            .ok_or(SecurityBrokerError::Changed)?;
        let info = super::info_of(file.as_raw_handle()).map_err(engine_error)?;
        ensure_symlink_temp(
            file.as_raw_handle(),
            &info,
            self.token.identity,
            self.directory,
            expected,
        )?;
        Ok(())
    }

    /// Confirm that an unfinalized symlink temp still has its creation-time
    /// owner-only DACL. Finalized temps are checked against captured source
    /// metadata by the publisher instead.
    pub fn verify_private_dacl(&self, file: &File) -> SecurityBrokerResult<()> {
        self.verify_file(file)?;
        let security = user_dacl_state(file.as_raw_handle())?;
        let expected_dacl = super::native_owner_only_dacl(&self.token.owner_sid)
            .map_err(|_| SecurityBrokerError::Unsupported)?;
        if security.owner != self.token.owner_sid
            || !security.dacl_protected
            || security.dacl.as_deref() != Some(expected_dacl.as_slice())
        {
            return Err(SecurityBrokerError::Changed);
        }
        Ok(())
    }

    /// Take the no-follow handle and opaque token.
    pub fn into_parts(self) -> (File, TempToken, bool) {
        (self.file, self.token, self.directory)
    }
}

impl BrokerTemp {
    /// The ordinary user-rights handle used to write the temp contents.
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Opaque identity required by `finalize_temp_security`.
    pub fn token(&self) -> &TempToken {
        &self.token
    }

    /// The validated private basename. The broker never uses it as a path or
    /// publishes it; callers may use it with their owner-local publisher.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Take ownership of the writable file and opaque broker token.
    pub fn into_parts(self) -> (File, TempToken) {
        (self.file, self.token)
    }
}

impl SecurityBrokerClient {
    /// Connect to the broker configured for `owner_sid` and verify the
    /// connected server's kernel PID plus SYSTEM-owned pipe security.
    pub fn connect(owner_sid: &str) -> SecurityBrokerResult<Self> {
        let owner = canonical_sid(owner_sid)?;
        if process_primary_sid(unsafe { GetCurrentProcess() })? != owner.bytes {
            return Err(SecurityBrokerError::Unsupported);
        }
        let pipe_name = pipe_name(&owner.canonical);
        let deadline = Instant::now() + IO_TIMEOUT;
        let handle = loop {
            let raw = unsafe {
                CreateFileW(
                    pipe_name.as_ptr(),
                    PIPE_OWNER_ACCESS,
                    0,
                    null(),
                    3,                                                // OPEN_EXISTING
                    FILE_FLAG_OVERLAPPED | 0x0010_0000 | 0x0002_0000, // SQOS_PRESENT | SECURITY_IMPERSONATION
                    null_mut(),
                )
            };
            if raw != INVALID_HANDLE_VALUE {
                break unsafe { OwnedHandle::from_raw_handle(raw) };
            }
            if Instant::now() >= deadline {
                return Err(last_io_error());
            }
            unsafe { WaitNamedPipeW(pipe_name.as_ptr(), 250) };
        };

        let mode = PIPE_READMODE_MESSAGE;
        if unsafe { SetNamedPipeHandleState(handle.as_raw_handle(), &mode, null(), null()) } == 0 {
            return Err(last_io_error());
        }
        verify_client_pipe_server(handle.as_raw_handle(), &owner)?;
        Ok(Self {
            pipe: Some(handle),
            session: None,
            owner_sid: owner.bytes,
        })
    }

    /// Capture the source's SACL policy using a source handle opened by the
    /// caller. The handle value crosses the pipe only as a peer-process
    /// handle-table index; authority comes from the kernel peer PID and the
    /// process handle retained for this session.
    pub fn capture_source(&mut self, source: &File) -> SecurityBrokerResult<SourceSnapshot> {
        self.capture_source_with_op(source, OP_CAPTURE_SOURCE)
    }

    /// Capture source policy after the ordinary owner access gate, then retain
    /// a no-follow read/metadata pin that denies later writes. This is used
    /// only by the owner-local Git publisher; the generic capture operation
    /// keeps its historical share behavior for other callers.
    pub fn capture_source_pinned(&mut self, source: &File) -> SecurityBrokerResult<SourceSnapshot> {
        self.capture_source_with_op(source, OP_CAPTURE_SOURCE_PINNED)
    }

    fn capture_source_with_op(
        &mut self,
        source: &File,
        op: u8,
    ) -> SecurityBrokerResult<SourceSnapshot> {
        let mut request = vec![PROTOCOL_VERSION, op];
        request.extend_from_slice(&handle_to_wire(source.as_raw_handle())?.to_le_bytes());
        let response = self.exchange(&request)?;
        expect_status(&response, 1 + 1 + 16 + 16 + 32)?;
        let session = response[2..18]
            .try_into()
            .map_err(|_| SecurityBrokerError::Invalid)?;
        let id: [u8; 16] = response[18..34]
            .try_into()
            .map_err(|_| SecurityBrokerError::Invalid)?;
        let digest = response[34..66]
            .try_into()
            .map_err(|_| SecurityBrokerError::Invalid)?;
        self.accept_session(session)?;
        Ok(SourceSnapshot {
            session,
            id,
            digest,
        })
    }

    /// Re-read the current source security digest. Any file identity or
    /// security change since capture fails with `Changed`.
    pub fn recheck_source(&mut self, source: &SourceSnapshot) -> SecurityBrokerResult<[u8; 32]> {
        self.require_session(source.session)?;
        let mut request = vec![PROTOCOL_VERSION, OP_RECHECK_SOURCE];
        request.extend_from_slice(&source.id);
        let response = self.exchange(&request)?;
        expect_status(&response, 1 + 1 + 16 + 32)?;
        self.accept_session(
            response[2..18]
                .try_into()
                .map_err(|_| SecurityBrokerError::Invalid)?,
        )?;
        let digest: [u8; 32] = response[18..50]
            .try_into()
            .map_err(|_| SecurityBrokerError::Invalid)?;
        if digest != source.digest {
            return Err(SecurityBrokerError::Changed);
        }
        Ok(digest)
    }

    /// Drop the broker's retained source handle and captured policy. The
    /// opaque snapshot cannot be used for another request afterward.
    pub fn release_source(&mut self, source: &SourceSnapshot) -> SecurityBrokerResult<()> {
        self.require_session(source.session)?;
        let mut request = vec![PROTOCOL_VERSION, OP_RELEASE_SOURCE];
        request.extend_from_slice(&source.id);
        let response = self.exchange(&request)?;
        expect_status(&response, 1 + 1 + 16)?;
        self.accept_session(
            response[2..18]
                .try_into()
                .map_err(|_| SecurityBrokerError::Invalid)?,
        )
    }

    /// Create an owner-private file with `FILE_CREATE` relative to a caller
    /// granted directory handle. `name` must be exactly
    /// `lomi-temp-<lowercase-uuid>.tmp` or a safe single-component Git
    /// `*.lock` basename.
    pub fn create_temp(&mut self, parent: &File, name: &str) -> SecurityBrokerResult<BrokerTemp> {
        if !valid_broker_temp_name(name) || name.len() > u8::MAX as usize {
            return Err(SecurityBrokerError::Invalid);
        }
        // Keep a caller-owned directory handle so cleanup remains in the
        // ordinary client process if the broker session ends unexpectedly.
        let cleanup_parent = parent
            .try_clone()
            .map_err(|error| SecurityBrokerError::Io(error.kind()))?;
        let mut request = vec![PROTOCOL_VERSION, OP_CREATE_TEMP];
        request.extend_from_slice(&handle_to_wire(parent.as_raw_handle())?.to_le_bytes());
        request.push(name.len() as u8);
        request.extend_from_slice(name.as_bytes());
        let response = self.exchange(&request)?;
        expect_status(&response, 1 + 1 + 16 + 16 + 8 + 16)?;
        let session = response[2..18]
            .try_into()
            .map_err(|_| SecurityBrokerError::Invalid)?;
        self.accept_session(session)?;
        let id: [u8; 16] = response[18..34]
            .try_into()
            .map_err(|_| SecurityBrokerError::Invalid)?;
        let identity = Ident {
            volume: u64::from_le_bytes(
                response[34..42]
                    .try_into()
                    .map_err(|_| SecurityBrokerError::Invalid)?,
            ),
            id: u128::from_le_bytes(
                response[42..58]
                    .try_into()
                    .map_err(|_| SecurityBrokerError::Invalid)?,
            ),
        };
        // The client obtains its own ordinary handle. Exporting a handle-table
        // index from SYSTEM would require unsafe remote cleanup after a lost
        // acknowledgement: the client could already have closed and reused it.
        let wide: Vec<u16> = name.encode_utf16().collect();
        let handle = super::open_relative(
            parent.as_raw_handle(),
            &wide,
            FILE_READ_DATA
                | FILE_WRITE_DATA
                | FILE_READ_ATTRIBUTES
                | FILE_WRITE_ATTRIBUTES
                | READ_CONTROL
                | WRITE_DAC
                | WRITE_OWNER
                | SYNCHRONIZE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            0,
            false,
        )
        .map_err(engine_error)?;
        let info = super::info_of(handle.as_raw_handle()).map_err(engine_error)?;
        ensure_regular_single_link(handle.as_raw_handle(), &info)?;
        if info.ident != identity {
            return Err(SecurityBrokerError::Changed);
        }
        super::native_default_stream_only(handle.as_raw_handle())
            .map_err(SecurityBrokerError::from)?;
        let file = File::from(handle);
        Ok(BrokerTemp {
            file,
            token: TempToken {
                session,
                id,
                owner_sid: self.owner_sid.clone(),
                parent: cleanup_parent,
                name: name.to_owned(),
                identity,
                kind: TempKind::File,
                expected_reparse: None,
            },
            name: name.to_owned(),
        })
    }

    /// Create a file- or directory-backed symbolic-link temp, set only that
    /// newly-created object's reparse data in the broker, then return an
    /// ordinary no-follow handle. `substitute` and `print` are UTF-16 path
    /// strings already normalized by the owner-local publisher; the broker
    /// never resolves, opens, or stats either target string.
    pub fn create_symlink_temp(
        &mut self,
        parent: &File,
        name: &str,
        substitute: &[u16],
        print: &[u16],
        relative: bool,
        directory: bool,
    ) -> SecurityBrokerResult<BrokerSymlinkTemp> {
        if !valid_broker_symlink_temp_name(name) || name.len() > u8::MAX as usize {
            return Err(SecurityBrokerError::Invalid);
        }
        let cleanup_parent = parent
            .try_clone()
            .map_err(|error| SecurityBrokerError::Io(error.kind()))?;
        let mut create_request = vec![PROTOCOL_VERSION, OP_CREATE_SYMLINK_TEMP];
        create_request.extend_from_slice(&handle_to_wire(parent.as_raw_handle())?.to_le_bytes());
        create_request.push(name.len() as u8);
        create_request.extend_from_slice(name.as_bytes());
        create_request.push(u8::from(directory));
        let created = self.exchange(&create_request)?;
        expect_status(&created, 1 + 1 + 16 + 16 + 8 + 16)?;
        let session = created[2..18]
            .try_into()
            .map_err(|_| SecurityBrokerError::Invalid)?;
        self.accept_session(session)?;
        let id: [u8; 16] = created[18..34]
            .try_into()
            .map_err(|_| SecurityBrokerError::Invalid)?;
        let identity = Ident {
            volume: u64::from_le_bytes(
                created[34..42]
                    .try_into()
                    .map_err(|_| SecurityBrokerError::Invalid)?,
            ),
            id: u128::from_le_bytes(
                created[42..58]
                    .try_into()
                    .map_err(|_| SecurityBrokerError::Invalid)?,
            ),
        };
        let mut token = TempToken {
            session,
            id,
            owner_sid: self.owner_sid.clone(),
            parent: cleanup_parent,
            name: name.to_owned(),
            identity,
            kind: TempKind::PendingSymlink { directory },
            expected_reparse: None,
        };

        let expected_reparse = match build_symlink_reparse_buffer(substitute, print, relative) {
            Ok(buffer) => buffer,
            Err(error) => {
                let _ = self.discard_temp(&token);
                return Err(error);
            }
        };
        // Retain the requested bytes while pending so a failed acknowledgement
        // can still clean up only this exact object if the broker set the
        // reparse point before reporting a later verification failure.
        token.expected_reparse = Some(expected_reparse.clone());
        let set_result = self.set_symlink_temp(&token, substitute, print, relative);
        if let Err(error) = set_result {
            let _ = self.discard_temp(&token);
            return Err(error);
        }
        token.kind = TempKind::Symlink { directory };

        let wide = name.encode_utf16().collect::<Vec<_>>();
        let options = if directory {
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT
        } else {
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT
        };
        let opened = (|| {
            let handle = super::open_relative(
                parent.as_raw_handle(),
                &wide,
                FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
                FILE_OPEN,
                options,
                0,
                false,
            )
            .map_err(engine_error)?;
            let info = super::info_of(handle.as_raw_handle()).map_err(engine_error)?;
            ensure_symlink_temp(
                handle.as_raw_handle(),
                &info,
                identity,
                directory,
                &expected_reparse,
            )?;
            let security = user_dacl_state(handle.as_raw_handle())?;
            let expected_dacl = super::native_owner_only_dacl(&self.owner_sid)
                .map_err(|_| SecurityBrokerError::Unsupported)?;
            if security.owner != self.owner_sid
                || !security.dacl_protected
                || security.dacl.as_deref() != Some(expected_dacl.as_slice())
            {
                return Err(SecurityBrokerError::Changed);
            }
            Ok::<_, SecurityBrokerError>(handle)
        })();
        let handle = match opened {
            Ok(handle) => handle,
            Err(error) => {
                let _ = self.discard_temp(&token);
                return Err(error);
            }
        };
        let file = File::from(handle);
        Ok(BrokerSymlinkTemp {
            file,
            token,
            name: name.to_owned(),
            directory,
        })
    }

    fn set_symlink_temp(
        &mut self,
        temp: &TempToken,
        substitute: &[u16],
        print: &[u16],
        relative: bool,
    ) -> SecurityBrokerResult<()> {
        self.require_session(temp.session)?;
        if !matches!(temp.kind, TempKind::PendingSymlink { .. }) {
            return Err(SecurityBrokerError::Invalid);
        }
        let substitute_bytes = utf16_bytes(substitute)?;
        let print_bytes = utf16_bytes(print)?;
        let mut request = vec![PROTOCOL_VERSION, OP_SET_SYMLINK_TEMP];
        request.extend_from_slice(&temp.id);
        request.push(u8::from(relative));
        request.extend_from_slice(
            &u16::try_from(substitute.len())
                .map_err(|_| SecurityBrokerError::Limit)?
                .to_le_bytes(),
        );
        request.extend_from_slice(
            &u16::try_from(print.len())
                .map_err(|_| SecurityBrokerError::Limit)?
                .to_le_bytes(),
        );
        request.extend_from_slice(&substitute_bytes);
        request.extend_from_slice(&print_bytes);
        let response = self.exchange(&request)?;
        expect_status(&response, 1 + 1 + 16)?;
        self.accept_session(
            response[2..18]
                .try_into()
                .map_err(|_| SecurityBrokerError::Invalid)?,
        )
    }

    /// Revalidate the captured source and newly-created temp, then copy only
    /// source SACL-related components onto that temp.
    pub fn finalize_temp_security(
        &mut self,
        source: &SourceSnapshot,
        temp: &TempToken,
    ) -> SecurityBrokerResult<()> {
        self.require_session(source.session)?;
        self.require_session(temp.session)?;
        if !matches!(temp.kind, TempKind::File | TempKind::Symlink { .. }) {
            return Err(SecurityBrokerError::Invalid);
        }
        let mut request = vec![PROTOCOL_VERSION, OP_FINALIZE_TEMP_SECURITY];
        request.extend_from_slice(&source.id);
        request.extend_from_slice(&temp.id);
        let response = self.exchange(&request)?;
        expect_status(&response, 1 + 1 + 16)?;
        self.accept_session(
            response[2..18]
                .try_into()
                .map_err(|_| SecurityBrokerError::Invalid)?,
        )
    }

    /// Forget a broker temp after the host publisher has renamed it away from
    /// its original private basename. This never deletes the published file.
    pub fn release_temp(&mut self, temp: &TempToken) -> SecurityBrokerResult<()> {
        self.require_session(temp.session)?;
        let mut request = vec![PROTOCOL_VERSION, OP_RELEASE_TEMP];
        request.extend_from_slice(&temp.id);
        let response = self.exchange(&request)?;
        expect_status(&response, 1 + 1 + 16)?;
        self.accept_session(
            response[2..18]
                .try_into()
                .map_err(|_| SecurityBrokerError::Invalid)?,
        )
    }

    /// Restore the original inherited SACL state after the ordinary owner has
    /// published this exact broker-created temp. The supplied handle is used
    /// only to prove that the new object still has the broker-recorded full
    /// identity; it is never used to address an existing target path.
    pub fn finalize_published_temp(
        &mut self,
        temp: &TempToken,
        published: &File,
    ) -> SecurityBrokerResult<()> {
        self.require_session(temp.session)?;
        let mut request = vec![PROTOCOL_VERSION, OP_FINALIZE_PUBLISHED_TEMP];
        request.extend_from_slice(&temp.id);
        request.extend_from_slice(&handle_to_wire(published.as_raw_handle())?.to_le_bytes());
        let response = self.exchange(&request)?;
        expect_status(&response, 1 + 1 + 16)?;
        self.accept_session(
            response[2..18]
                .try_into()
                .map_err(|_| SecurityBrokerError::Invalid)?,
        )
    }

    /// Delete only the exact broker-created private temp from the ordinary
    /// client process, then release the broker's record. If the entry has
    /// already been renamed or removed, this drops the record without
    /// touching another namespace entry. A delete that waits on an oplock can
    /// block this caller, but cannot stall the LocalSystem broker.
    pub fn discard_temp(&mut self, temp: &TempToken) -> SecurityBrokerResult<()> {
        self.require_session(temp.session)?;
        match temp.kind {
            TempKind::File => {
                if let Some(named) = open_private_name_optional(
                    temp.parent.as_raw_handle(),
                    &temp.name.encode_utf16().collect::<Vec<_>>(),
                    true,
                )? {
                    let info = super::info_of(named.as_raw_handle()).map_err(engine_error)?;
                    if info.ident != temp.identity || info.nlink != 1 {
                        return Err(SecurityBrokerError::Changed);
                    }
                    ensure_regular_single_link(named.as_raw_handle(), &info)?;
                    super::native_default_stream_only(named.as_raw_handle())
                        .map_err(SecurityBrokerError::from)?;
                    delete_open_file(named.as_raw_handle())?;
                }
            }
            TempKind::PendingSymlink { directory } | TempKind::Symlink { directory } => {
                if let Some(named) = open_symlink_name_optional(
                    temp.parent.as_raw_handle(),
                    &temp.name.encode_utf16().collect::<Vec<_>>(),
                    directory,
                    true,
                    false,
                )? {
                    let info = super::info_of(named.as_raw_handle()).map_err(engine_error)?;
                    if info.ident != temp.identity || info.nlink != 1 {
                        return Err(SecurityBrokerError::Changed);
                    }
                    match temp.kind {
                        TempKind::PendingSymlink { .. } => {
                            ensure_pending_symlink_temp(
                                named.as_raw_handle(),
                                &info,
                                temp.identity,
                                directory,
                                temp.expected_reparse.as_deref(),
                            )?;
                        }
                        TempKind::Symlink { .. } => {
                            ensure_symlink_object(
                                named.as_raw_handle(),
                                &info,
                                temp.identity,
                                directory,
                                temp.expected_reparse
                                    .as_deref()
                                    .ok_or(SecurityBrokerError::Changed)?,
                            )?;
                        }
                        TempKind::File => unreachable!(),
                    }
                    super::delete_entry(named.as_raw_handle()).map_err(engine_error)?;
                }
            }
        }
        let mut request = vec![PROTOCOL_VERSION, OP_DISCARD_TEMP];
        request.extend_from_slice(&temp.id);
        let response = self.exchange(&request)?;
        expect_status(&response, 1 + 1 + 16)?;
        self.accept_session(
            response[2..18]
                .try_into()
                .map_err(|_| SecurityBrokerError::Invalid)?,
        )
    }

    fn exchange(&mut self, body: &[u8]) -> SecurityBrokerResult<Vec<u8>> {
        if body.len() < 2 || body.len() > MAX_FRAME_BODY {
            return Err(SecurityBrokerError::Limit);
        }
        let mut message = Vec::with_capacity(4 + body.len());
        message.extend_from_slice(&(body.len() as u32).to_le_bytes());
        message.extend_from_slice(body);
        let pipe = self
            .pipe
            .as_ref()
            .ok_or(SecurityBrokerError::Changed)?
            .as_raw_handle();
        let result = (|| {
            write_message(pipe, &message, None)?;
            let response = read_message(pipe, None, IO_TIMEOUT)?;
            let success_len = match body[1] {
                OP_CAPTURE_SOURCE => 66,
                OP_CAPTURE_SOURCE_PINNED => 66,
                OP_RECHECK_SOURCE => 50,
                OP_CREATE_TEMP => 58,
                OP_CREATE_SYMLINK_TEMP => 58,
                OP_FINALIZE_TEMP_SECURITY
                | OP_SET_SYMLINK_TEMP
                | OP_FINALIZE_PUBLISHED_TEMP
                | OP_RELEASE_SOURCE
                | OP_RELEASE_TEMP
                | OP_DISCARD_TEMP => 18,
                _ => return Err(SecurityBrokerError::Invalid),
            };
            if response.len() < 18
                || response[0] != PROTOCOL_VERSION
                || response[1] > STATUS_IO
                || response.len()
                    != if response[1] == STATUS_OK {
                        success_len
                    } else {
                        18
                    }
            {
                return Err(SecurityBrokerError::Invalid);
            }
            self.accept_session(
                response[2..18]
                    .try_into()
                    .map_err(|_| SecurityBrokerError::Invalid)?,
            )?;
            Ok(response)
        })();
        if result.is_err() {
            // A timed-out request may still produce a response. Never let a
            // later operation consume that response as its acknowledgement.
            self.pipe = None;
        }
        result
    }

    fn accept_session(&mut self, session: [u8; 16]) -> SecurityBrokerResult<()> {
        if let Some(existing) = self.session {
            if existing != session {
                return Err(SecurityBrokerError::Changed);
            }
        } else {
            self.session = Some(session);
        }
        Ok(())
    }

    fn require_session(&self, session: [u8; 16]) -> SecurityBrokerResult<()> {
        if self.session != Some(session) {
            return Err(SecurityBrokerError::Invalid);
        }
        Ok(())
    }
}

/// Run the named-pipe broker on a dedicated service thread until `stopping`
/// is set. It creates no worker threads; callers join this function's thread
/// during service shutdown. Each pipe operation has a finite I/O deadline.
pub fn run_security_broker(owner_sid: &str, stopping: &AtomicBool) -> SecurityBrokerResult<()> {
    let owner = canonical_sid(owner_sid)?;
    let system_sid = well_known_sid("S-1-5-18")?;
    if process_primary_sid(unsafe { GetCurrentProcess() })? != system_sid.bytes {
        return Err(SecurityBrokerError::Unsupported);
    }
    let pipe_name = pipe_name(&owner.canonical);

    while !stopping.load(Ordering::Acquire) {
        let pipe = create_server_pipe(&pipe_name, &owner)?;
        match wait_for_client(pipe.as_raw_handle(), stopping) {
            Ok(false) => break,
            Ok(true) => {}
            Err(_) => continue,
        }
        if stopping.load(Ordering::Acquire) {
            break;
        }
        let mut session = match ServerSession::authenticate(pipe.as_raw_handle(), owner.clone()) {
            Ok(session) => session,
            Err(_) => {
                unsafe { DisconnectNamedPipe(pipe.as_raw_handle()) };
                continue;
            }
        };
        let _ = serve_connection(pipe.as_raw_handle(), stopping, &mut session);
        session.cleanup();
        unsafe { DisconnectNamedPipe(pipe.as_raw_handle()) };
    }
    Ok(())
}

#[derive(Clone)]
struct CanonicalSid {
    canonical: String,
    bytes: Vec<u8>,
}

fn canonical_sid(text: &str) -> SecurityBrokerResult<CanonicalSid> {
    if text.is_empty() || text.len() > 184 || !text.starts_with("S-") {
        return Err(SecurityBrokerError::Invalid);
    }
    let mut input: Vec<u16> = text.encode_utf16().collect();
    input.push(0);
    let mut sid = null_mut();
    if unsafe { ConvertStringSidToSidW(input.as_ptr(), &mut sid) } == 0 || sid.is_null() {
        return Err(SecurityBrokerError::Invalid);
    }
    let bytes = unsafe { sid_bytes(sid)? };
    let mut canonical_ptr = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut canonical_ptr) } == 0 || canonical_ptr.is_null() {
        unsafe { LocalFree(sid) };
        return Err(last_io_error());
    }
    let canonical = unsafe { wide_c_string(canonical_ptr) };
    unsafe {
        LocalFree(canonical_ptr.cast());
        LocalFree(sid);
    }
    Ok(CanonicalSid { canonical, bytes })
}

fn well_known_sid(text: &str) -> SecurityBrokerResult<CanonicalSid> {
    canonical_sid(text)
}

unsafe fn sid_bytes(sid: *mut c_void) -> SecurityBrokerResult<Vec<u8>> {
    if sid.is_null() {
        return Err(SecurityBrokerError::Unsupported);
    }
    let len = unsafe { GetLengthSid(sid) } as usize;
    if len == 0 || len > 68 {
        return Err(SecurityBrokerError::Unsupported);
    }
    Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), len) }.to_vec())
}

unsafe fn wide_c_string(value: *mut u16) -> String {
    let mut len = 0usize;
    while len < 256 && unsafe { *value.add(len) } != 0 {
        len += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(value, len) })
}

fn process_primary_sid(process: HANDLE) -> SecurityBrokerResult<Vec<u8>> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 || token.is_null() {
        return Err(last_io_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    token_user_sid(token.as_raw_handle())
}

fn token_user_sid(token: HANDLE) -> SecurityBrokerResult<Vec<u8>> {
    let mut needed = 0u32;
    unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed) };
    if needed < size_of::<TOKEN_USER>() as u32 || needed > 64 * 1024 {
        return Err(SecurityBrokerError::Unsupported);
    }
    let mut storage = vec![0u64; (needed as usize).div_ceil(size_of::<u64>())];
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            storage.as_mut_ptr().cast::<c_void>(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(last_io_error());
    }
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    unsafe { sid_bytes(user.User.Sid) }
}

fn token_impersonation_level(token: HANDLE) -> SecurityBrokerResult<i32> {
    let mut level = SecurityAnonymous;
    let mut needed = 0u32;
    if unsafe {
        GetTokenInformation(
            token,
            TokenImpersonationLevel,
            (&mut level as *mut i32).cast(),
            size_of::<i32>() as u32,
            &mut needed,
        )
    } == 0
        || needed < size_of::<i32>() as u32
        || (level != SecurityImpersonation && level != SecurityDelegation)
    {
        return Err(SecurityBrokerError::Unsupported);
    }
    Ok(level)
}

fn pipe_name(owner_sid: &str) -> Vec<u16> {
    let digest = Sha256::digest(owner_sid.as_bytes());
    let mut name = String::from(r"\\.\pipe\lomi-file-security-v1-");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(name, "{byte:02x}");
    }
    name.encode_utf16().chain(std::iter::once(0)).collect()
}

struct LocalDescriptor(*mut c_void);

impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

fn pipe_security_descriptor(owner: &CanonicalSid) -> SecurityBrokerResult<LocalDescriptor> {
    // The owner SID has already been round-tripped through Windows, so it
    // cannot inject additional SDDL components.
    let sddl = format!(
        "O:SYD:P(A;;GA;;;SY)(A;;0x{PIPE_OWNER_ACCESS:08x};;;{})",
        owner.canonical
    );
    let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
        || descriptor.is_null()
    {
        return Err(last_io_error());
    }
    Ok(LocalDescriptor(descriptor))
}

fn create_server_pipe(name: &[u16], owner: &CanonicalSid) -> SecurityBrokerResult<OwnedHandle> {
    let descriptor = pipe_security_descriptor(owner)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let raw = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            MAX_MESSAGE as u32,
            MAX_MESSAGE as u32,
            0,
            &attributes,
        )
    };
    if raw == INVALID_HANDLE_VALUE || raw.is_null() {
        return Err(last_io_error());
    }
    let pipe = unsafe { OwnedHandle::from_raw_handle(raw) };
    verify_pipe_security(pipe.as_raw_handle(), owner)?;
    Ok(pipe)
}

fn verify_client_pipe_server(pipe: HANDLE, owner: &CanonicalSid) -> SecurityBrokerResult<()> {
    let mut server_pid = 0u32;
    if unsafe { GetNamedPipeServerProcessId(pipe, &mut server_pid) } == 0 || server_pid == 0 {
        return Err(last_io_error());
    }
    verify_pipe_security(pipe, owner)?;

    // Query the server token when the process DACL permits it. Some service
    // hardening policies deny this to an ordinary client; the connected pipe's
    // kernel security descriptor remains the mandatory SYSTEM-owner proof.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, server_pid) };
    if !process.is_null() {
        let process = unsafe { OwnedHandle::from_raw_handle(process) };
        if unsafe { windows_sys::Win32::System::Threading::GetProcessId(process.as_raw_handle()) }
            != server_pid
        {
            return Err(SecurityBrokerError::Changed);
        }
        if let Ok(sid) = process_primary_sid(process.as_raw_handle()) {
            if sid != well_known_sid("S-1-5-18")?.bytes {
                return Err(SecurityBrokerError::Unsupported);
            }
        }
    }
    Ok(())
}

fn verify_pipe_security(pipe: HANDLE, owner: &CanonicalSid) -> SecurityBrokerResult<()> {
    let mut actual_owner = null_mut();
    let mut dacl = null_mut();
    let mut descriptor = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            pipe,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut actual_owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(SecurityBrokerError::Unsupported);
    }
    let descriptor = LocalDescriptor(descriptor);
    let actual_owner = unsafe { sid_bytes(actual_owner)? };
    let system = well_known_sid("S-1-5-18")?;
    if actual_owner != system.bytes || dacl.is_null() {
        return Err(SecurityBrokerError::Unsupported);
    }
    let mut present = 0;
    let mut descriptor_dacl = null_mut();
    let mut defaulted = 0;
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor.0,
            &mut present,
            &mut descriptor_dacl,
            &mut defaulted,
        )
    } == 0
        || present == 0
        || descriptor_dacl.is_null()
    {
        return Err(SecurityBrokerError::Unsupported);
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
    {
        return Err(SecurityBrokerError::Unsupported);
    }
    let mut acl_info: ACL_SIZE_INFORMATION = unsafe { zeroed() };
    if unsafe {
        GetAclInformation(
            descriptor_dacl,
            (&mut acl_info as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            2, // AclSizeInformation
        )
    } == 0
        || acl_info.AceCount != 2
    {
        return Err(SecurityBrokerError::Unsupported);
    }
    let mut system_seen = false;
    let mut owner_seen = false;
    for index in 0..acl_info.AceCount {
        let mut ace_ptr = null_mut();
        if unsafe { GetAce(descriptor_dacl, index, &mut ace_ptr) } == 0 || ace_ptr.is_null() {
            return Err(SecurityBrokerError::Unsupported);
        }
        let ace = unsafe { &*ace_ptr.cast::<ACCESS_ALLOWED_ACE>() };
        if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 {
            return Err(SecurityBrokerError::Unsupported);
        }
        let ace_sid = unsafe { sid_bytes((&ace.SidStart as *const u32).cast_mut().cast())? };
        if ace_sid == system.bytes && ace.Mask == FILE_ALL_ACCESS_MASK && !system_seen {
            system_seen = true;
        } else if ace_sid == owner.bytes && ace.Mask == PIPE_OWNER_ACCESS && !owner_seen {
            owner_seen = true;
        } else {
            return Err(SecurityBrokerError::Unsupported);
        }
    }
    if !system_seen || !owner_seen {
        return Err(SecurityBrokerError::Unsupported);
    }
    Ok(())
}

fn wait_for_client(pipe: HANDLE, stopping: &AtomicBool) -> SecurityBrokerResult<bool> {
    let event = event_handle()?;
    let mut overlapped: OVERLAPPED = unsafe { zeroed() };
    overlapped.hEvent = event.as_raw_handle();
    let connected = unsafe { ConnectNamedPipe(pipe, &mut overlapped) };
    if connected != 0 {
        return Ok(true);
    }
    let error = unsafe { GetLastError() };
    if error == ERROR_PIPE_CONNECTED {
        return Ok(true);
    }
    if error != ERROR_IO_PENDING {
        return Err(last_io_error());
    }
    loop {
        if stopping.load(Ordering::Acquire) {
            unsafe { CancelIoEx(pipe, &overlapped) };
            drain_overlapped(pipe, &mut overlapped);
            return Ok(false);
        }
        match unsafe { WaitForSingleObject(event.as_raw_handle(), IO_POLL_MS) } {
            WAIT_OBJECT_0 => {
                let mut transferred = 0;
                if unsafe { GetOverlappedResult(pipe, &mut overlapped, &mut transferred, 0) } != 0 {
                    return Ok(true);
                }
                if unsafe { GetLastError() } == ERROR_PIPE_CONNECTED {
                    return Ok(true);
                }
                return Err(last_io_error());
            }
            WAIT_TIMEOUT => {}
            WAIT_FAILED => return Err(last_io_error()),
            _ => return Err(SecurityBrokerError::Unsupported),
        }
    }
}

fn event_handle() -> SecurityBrokerResult<OwnedHandle> {
    let raw = unsafe { CreateEventW(null(), 1, 0, null()) };
    if raw.is_null() {
        return Err(last_io_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

fn read_message(
    pipe: HANDLE,
    stopping: Option<&AtomicBool>,
    timeout: Duration,
) -> SecurityBrokerResult<Vec<u8>> {
    let mut buffer = vec![0u8; MAX_MESSAGE];
    let count = overlapped_io(
        pipe,
        stopping,
        |overlapped, bytes| unsafe {
            ReadFile(
                pipe,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                bytes,
                overlapped,
            )
        },
        timeout,
    )?;
    if count < 4 || count > buffer.len() {
        return Err(SecurityBrokerError::Invalid);
    }
    let len = u32::from_le_bytes(
        buffer[..4]
            .try_into()
            .map_err(|_| SecurityBrokerError::Invalid)?,
    ) as usize;
    if len > MAX_FRAME_BODY || len + 4 != count {
        return Err(SecurityBrokerError::Invalid);
    }
    Ok(buffer[4..count].to_vec())
}

fn write_message(
    pipe: HANDLE,
    message: &[u8],
    stopping: Option<&AtomicBool>,
) -> SecurityBrokerResult<()> {
    if message.len() > MAX_MESSAGE {
        return Err(SecurityBrokerError::Limit);
    }
    let count = overlapped_io(
        pipe,
        stopping,
        |overlapped, bytes| unsafe {
            WriteFile(
                pipe,
                message.as_ptr(),
                message.len() as u32,
                bytes,
                overlapped,
            )
        },
        IO_TIMEOUT,
    )?;
    if count != message.len() {
        return Err(SecurityBrokerError::Io(io::ErrorKind::WriteZero));
    }
    Ok(())
}

fn overlapped_io(
    pipe: HANDLE,
    stopping: Option<&AtomicBool>,
    start: impl FnOnce(*mut OVERLAPPED, *mut u32) -> i32,
    timeout: Duration,
) -> SecurityBrokerResult<usize> {
    let event = event_handle()?;
    let mut overlapped: OVERLAPPED = unsafe { zeroed() };
    overlapped.hEvent = event.as_raw_handle();
    let mut transferred = 0u32;
    if start(&mut overlapped, &mut transferred) != 0 {
        return Ok(transferred as usize);
    }
    if unsafe { GetLastError() } != ERROR_IO_PENDING {
        if unsafe { GetLastError() } == ERROR_MORE_DATA {
            return Err(SecurityBrokerError::Limit);
        }
        return Err(last_io_error());
    }
    let deadline = Instant::now() + timeout;
    loop {
        if stopping.is_some_and(|flag| flag.load(Ordering::Acquire)) || Instant::now() >= deadline {
            unsafe { CancelIoEx(pipe, &overlapped) };
            drain_overlapped(pipe, &mut overlapped);
            return Err(
                if stopping.is_some_and(|flag| flag.load(Ordering::Acquire)) {
                    SecurityBrokerError::Io(io::ErrorKind::Interrupted)
                } else {
                    SecurityBrokerError::Io(io::ErrorKind::TimedOut)
                },
            );
        }
        match unsafe { WaitForSingleObject(event.as_raw_handle(), IO_POLL_MS) } {
            WAIT_OBJECT_0 => {
                if unsafe { GetOverlappedResult(pipe, &mut overlapped, &mut transferred, 0) } != 0 {
                    return Ok(transferred as usize);
                }
                if unsafe { GetLastError() } == ERROR_MORE_DATA {
                    return Err(SecurityBrokerError::Limit);
                }
                return Err(last_io_error());
            }
            WAIT_TIMEOUT => {}
            WAIT_FAILED => return Err(last_io_error()),
            _ => return Err(SecurityBrokerError::Unsupported),
        }
    }
}

fn drain_overlapped(pipe: HANDLE, overlapped: &mut OVERLAPPED) {
    // CancelIoEx is asynchronous; retain the OVERLAPPED storage and drain its
    // completion before the event and buffers can go out of scope.
    let mut transferred = 0u32;
    unsafe { GetOverlappedResult(pipe, overlapped, &mut transferred, 1) };
}

fn expect_status(response: &[u8], expected_len: usize) -> SecurityBrokerResult<()> {
    if response.len() < 2 || response[0] != PROTOCOL_VERSION {
        return Err(SecurityBrokerError::Invalid);
    }
    if response[1] != STATUS_OK {
        return Err(match response[1] {
            STATUS_INVALID => SecurityBrokerError::Invalid,
            STATUS_CHANGED => SecurityBrokerError::Changed,
            STATUS_LIMIT => SecurityBrokerError::Limit,
            STATUS_UNSUPPORTED => SecurityBrokerError::Unsupported,
            STATUS_IO => SecurityBrokerError::Io(io::ErrorKind::Other),
            _ => SecurityBrokerError::Invalid,
        });
    }
    if response.len() != expected_len {
        return Err(SecurityBrokerError::Invalid);
    }
    Ok(())
}

fn error_status(error: SecurityBrokerError) -> u8 {
    match error {
        SecurityBrokerError::Invalid => STATUS_INVALID,
        SecurityBrokerError::Changed => STATUS_CHANGED,
        SecurityBrokerError::Limit => STATUS_LIMIT,
        SecurityBrokerError::Unsupported => STATUS_UNSUPPORTED,
        SecurityBrokerError::Io(_) => STATUS_IO,
    }
}

fn last_io_error() -> SecurityBrokerError {
    SecurityBrokerError::Io(io::Error::last_os_error().kind())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuditPolicy {
    present: bool,
    acl: Option<Vec<u8>>,
    protected: bool,
    label: Option<Vec<u8>>,
    resource_attributes: Option<Vec<u8>>,
    scope: Option<Vec<u8>>,
}

impl AuditPolicy {
    fn digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"lomi-windows-audit-policy-v1");
        digest.update([u8::from(self.present), u8::from(self.protected)]);
        hash_option(&mut digest, self.acl.as_deref());
        hash_option(&mut digest, self.label.as_deref());
        hash_option(&mut digest, self.resource_attributes.as_deref());
        hash_option(&mut digest, self.scope.as_deref());
        digest.finalize().into()
    }
}

fn staging_audit_policy(source: &AuditPolicy, defer_inheritance: bool) -> AuditPolicy {
    let mut staged = source.clone();
    if defer_inheritance && staged.present {
        staged.protected = true;
    }
    staged
}

fn hash_option(digest: &mut Sha256, value: Option<&[u8]>) {
    if let Some(value) = value {
        digest.update([1]);
        digest.update((value.len() as u64).to_le_bytes());
        digest.update(value);
    } else {
        digest.update([0]);
    }
}

fn audit_policy(
    audit_handle: RawHandle,
    user_handle: RawHandle,
) -> SecurityBrokerResult<AuditPolicy> {
    let (present, acl, protected) =
        super::native_audit_sacl(audit_handle).map_err(SecurityBrokerError::from)?;
    let label = super::native_security_component(user_handle, LABEL_SECURITY_INFORMATION)
        .map_err(SecurityBrokerError::from)?;
    let resource_attributes =
        super::native_security_component(user_handle, ATTRIBUTE_SECURITY_INFORMATION)
            .map_err(SecurityBrokerError::from)?;
    let scope = super::native_security_component(user_handle, SCOPE_SECURITY_INFORMATION)
        .map_err(SecurityBrokerError::from)?;
    for item in [&acl, &label, &resource_attributes, &scope]
        .into_iter()
        .flatten()
    {
        if item.len() > MAX_ACL_BYTES {
            return Err(SecurityBrokerError::Limit);
        }
    }
    let total: usize = [&acl, &label, &resource_attributes, &scope]
        .into_iter()
        .flatten()
        .map(Vec::len)
        .sum();
    if total > MAX_ACL_BYTES * 4 {
        return Err(SecurityBrokerError::Limit);
    }
    Ok(AuditPolicy {
        present,
        acl,
        protected,
        label,
        resource_attributes,
        scope,
    })
}

fn set_audit_policy(
    audit_handle: RawHandle,
    user_handle: RawHandle,
    policy: &AuditPolicy,
) -> SecurityBrokerResult<()> {
    if !policy.present {
        // SetSecurityInfo(NULL SACL) means a present NULL SACL, not an absent
        // SACL. Preserve absence only when the new temp already matches it.
        let (present, acl, protected) =
            super::native_audit_sacl(audit_handle).map_err(SecurityBrokerError::from)?;
        if present || acl != policy.acl || protected != policy.protected {
            return Err(SecurityBrokerError::Unsupported);
        }
    } else {
        let protection = if policy.protected {
            PROTECTED_SACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_SACL_SECURITY_INFORMATION
        };
        let acl = policy
            .acl
            .as_ref()
            .map_or(null(), |bytes| bytes.as_ptr().cast::<ACL>());
        let result = super::with_system_security_privilege(|| unsafe {
            SetSecurityInfo(
                audit_handle,
                SE_FILE_OBJECT,
                SACL_SECURITY_INFORMATION | protection,
                null_mut(),
                null_mut(),
                null(),
                acl,
            )
        })
        .map_err(engine_error)?;
        if result != 0 {
            return Err(SecurityBrokerError::Unsupported);
        }
    }
    super::native_set_security_component(
        user_handle,
        LABEL_SECURITY_INFORMATION,
        policy.label.as_ref(),
    )
    .map_err(SecurityBrokerError::from)?;
    super::native_set_security_component(
        user_handle,
        ATTRIBUTE_SECURITY_INFORMATION,
        policy.resource_attributes.as_ref(),
    )
    .map_err(SecurityBrokerError::from)?;
    super::native_set_security_component(
        audit_handle,
        SCOPE_SECURITY_INFORMATION,
        policy.scope.as_ref(),
    )
    .map_err(SecurityBrokerError::from)?;
    if audit_policy(audit_handle, user_handle)? != *policy {
        return Err(SecurityBrokerError::Changed);
    }
    Ok(())
}

fn set_published_audit_policy(
    audit_handle: RawHandle,
    user_handle: RawHandle,
    policy: &AuditPolicy,
) -> SecurityBrokerResult<AuditPolicy> {
    // SetSecurityInfo installs the supplied ACL on this handle. Its documented
    // automatic inheritance propagation applies to existing child objects;
    // require exact readback of the moved object's SACL and protection bit
    // instead of normalizing inherited ACEs. See
    // https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo
    if policy.present {
        let protection = if policy.protected {
            PROTECTED_SACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_SACL_SECURITY_INFORMATION
        };
        let acl = policy
            .acl
            .as_ref()
            .map_or(null(), |bytes| bytes.as_ptr().cast::<ACL>());
        let result = super::with_system_security_privilege(|| unsafe {
            SetSecurityInfo(
                audit_handle,
                SE_FILE_OBJECT,
                SACL_SECURITY_INFORMATION | protection,
                null_mut(),
                null_mut(),
                null(),
                acl,
            )
        })
        .map_err(engine_error)?;
        if result != 0 {
            return Err(SecurityBrokerError::Unsupported);
        }
    } else {
        let (present, acl, protected) =
            super::native_audit_sacl(audit_handle).map_err(SecurityBrokerError::from)?;
        if present || acl.is_some() || protected != policy.protected {
            return Err(SecurityBrokerError::Changed);
        }
    }
    super::native_set_security_component(
        user_handle,
        LABEL_SECURITY_INFORMATION,
        policy.label.as_ref(),
    )
    .map_err(SecurityBrokerError::from)?;
    super::native_set_security_component(
        user_handle,
        ATTRIBUTE_SECURITY_INFORMATION,
        policy.resource_attributes.as_ref(),
    )
    .map_err(SecurityBrokerError::from)?;
    super::native_set_security_component(
        audit_handle,
        SCOPE_SECURITY_INFORMATION,
        policy.scope.as_ref(),
    )
    .map_err(SecurityBrokerError::from)?;
    let resulting = audit_policy(audit_handle, user_handle)?;
    if !published_audit_policy_matches(policy, &resulting) {
        return Err(SecurityBrokerError::Changed);
    }
    Ok(resulting)
}

fn published_audit_policy_matches(source: &AuditPolicy, actual: &AuditPolicy) -> bool {
    source == actual
}

fn protect_current_sacl(audit_handle: RawHandle) -> SecurityBrokerResult<()> {
    let (present, acl, protected) =
        super::native_audit_sacl(audit_handle).map_err(SecurityBrokerError::from)?;
    if !present || protected {
        return Ok(());
    }
    let sacl = acl
        .as_ref()
        .map_or(null(), |bytes| bytes.as_ptr().cast::<ACL>());
    let status = super::with_system_security_privilege(|| unsafe {
        SetSecurityInfo(
            audit_handle,
            SE_FILE_OBJECT,
            SACL_SECURITY_INFORMATION | PROTECTED_SACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null(),
            sacl,
        )
    })
    .map_err(engine_error)?;
    if status != 0 {
        return Err(SecurityBrokerError::Unsupported);
    }
    let now = super::native_audit_sacl(audit_handle).map_err(SecurityBrokerError::from)?;
    if !now.0 || !now.2 || now.1 != acl {
        return Err(SecurityBrokerError::Changed);
    }
    Ok(())
}

struct SourceRecord {
    /// Reopened under the authenticated owner. Generic captures retain their
    /// ordinary read/write source handle; owner-local Git captures retain a
    /// read-only handle that denies later writers after the same initial
    /// read/write authorization check.
    handle: OwnedHandle,
    identity: Ident,
    kind: SourceKind,
    reparse: Option<Vec<u8>>,
    user: OwnerDaclState,
    policy: AuditPolicy,
    digest: [u8; 32],
    pin_writes: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OwnerDaclState {
    owner: Vec<u8>,
    group: Vec<u8>,
    dacl: Option<Vec<u8>>,
    dacl_present: bool,
    dacl_protected: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TempSecurityState {
    user: OwnerDaclState,
    audit: AuditPolicy,
}

struct TempRecord {
    parent: OwnedHandle,
    parent_identity: Ident,
    name: Vec<u16>,
    handle: OwnedHandle,
    identity: Ident,
    kind: TempKind,
    expected_reparse: Option<Vec<u8>>,
    expected: Option<TempSecurityState>,
    finalization_started: bool,
    finalized_source: Option<FinalizedSource>,
    published_finalized: bool,
}

#[derive(Clone)]
struct FinalizedSource {
    id: [u8; 16],
    identity: Ident,
    digest: [u8; 32],
    user: OwnerDaclState,
    policy: AuditPolicy,
    defer_sacl_until_published: bool,
}

struct ServerSession {
    owner: CanonicalSid,
    peer_process: OwnedHandle,
    user_token: Option<OwnedHandle>,
    session: [u8; 16],
    sources: HashMap<[u8; 16], SourceRecord>,
    temps: HashMap<[u8; 16], TempRecord>,
    requests: usize,
    started_at: Instant,
}

impl ServerSession {
    fn authenticate(pipe: HANDLE, owner: CanonicalSid) -> SecurityBrokerResult<Self> {
        let mut pid = 0u32;
        if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) } == 0 || pid == 0 {
            return Err(last_io_error());
        }
        let raw_process = unsafe {
            OpenProcess(
                PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                pid,
            )
        };
        if raw_process.is_null() {
            return Err(last_io_error());
        }
        let peer_process = unsafe { OwnedHandle::from_raw_handle(raw_process) };
        if unsafe {
            windows_sys::Win32::System::Threading::GetProcessId(peer_process.as_raw_handle())
        } != pid
            || process_primary_sid(peer_process.as_raw_handle())? != owner.bytes
        {
            return Err(SecurityBrokerError::Unsupported);
        }
        Ok(Self {
            owner,
            peer_process,
            user_token: None,
            session: Uuid::new_v4().into_bytes(),
            sources: HashMap::new(),
            temps: HashMap::new(),
            requests: 0,
            started_at: Instant::now(),
        })
    }

    fn capture_impersonation(&mut self, pipe: HANDLE) -> SecurityBrokerResult<()> {
        ensure_no_thread_token()?;
        if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
            return Err(last_io_error());
        }
        let mut raw_token = null_mut();
        let opened = unsafe {
            OpenThreadToken(
                GetCurrentThread(),
                TOKEN_QUERY | TOKEN_IMPERSONATE,
                1,
                &mut raw_token,
            )
        } != 0;
        if !opened || raw_token.is_null() {
            if unsafe { windows_sys::Win32::Security::RevertToSelf() } == 0 {
                std::process::abort();
            }
            return Err(SecurityBrokerError::Unsupported);
        }
        let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };
        let authenticated = token_impersonation_level(token.as_raw_handle()).is_ok()
            && token_user_sid(token.as_raw_handle()).is_ok_and(|sid| sid == self.owner.bytes);
        if unsafe { windows_sys::Win32::Security::RevertToSelf() } == 0 {
            std::process::abort();
        }
        if !authenticated {
            return Err(SecurityBrokerError::Unsupported);
        }
        if self.user_token.is_none() {
            self.user_token = Some(token);
        }
        Ok(())
    }

    fn handle_request(
        &mut self,
        pipe: HANDLE,
        stopping: &AtomicBool,
    ) -> SecurityBrokerResult<Vec<u8>> {
        if self.requests >= MAX_REQUESTS_PER_CONNECTION
            || self.started_at.elapsed() >= MAX_SESSION_DURATION
        {
            return Err(SecurityBrokerError::Limit);
        }
        self.requests += 1;
        let request = read_message(
            pipe,
            Some(stopping),
            SERVER_IDLE_TIMEOUT.min(MAX_SESSION_DURATION.saturating_sub(self.started_at.elapsed())),
        )?;
        if request.len() < 2 || request[0] != PROTOCOL_VERSION {
            return Err(SecurityBrokerError::Invalid);
        }
        self.capture_impersonation(pipe)?;
        let result = match request[1] {
            OP_CAPTURE_SOURCE if request.len() == 10 => {
                let handle = u64::from_le_bytes(
                    request[2..10]
                        .try_into()
                        .map_err(|_| SecurityBrokerError::Invalid)?,
                );
                self.capture_source(handle)
            }
            OP_CAPTURE_SOURCE_PINNED if request.len() == 10 => {
                let handle = u64::from_le_bytes(
                    request[2..10]
                        .try_into()
                        .map_err(|_| SecurityBrokerError::Invalid)?,
                );
                self.capture_source_pinned(handle)
            }
            OP_RECHECK_SOURCE if request.len() == 18 => {
                let id: [u8; 16] = request[2..18]
                    .try_into()
                    .map_err(|_| SecurityBrokerError::Invalid)?;
                self.recheck_source(id)
            }
            OP_CREATE_TEMP if request.len() >= 11 => {
                let parent = u64::from_le_bytes(
                    request[2..10]
                        .try_into()
                        .map_err(|_| SecurityBrokerError::Invalid)?,
                );
                let name_len = request[10] as usize;
                if request.len() != 11 + name_len {
                    Err(SecurityBrokerError::Invalid)
                } else {
                    let name = std::str::from_utf8(&request[11..])
                        .map_err(|_| SecurityBrokerError::Invalid)?;
                    self.create_temp(pipe, parent, name)
                }
            }
            OP_CREATE_SYMLINK_TEMP if request.len() >= 12 => {
                let parent = u64::from_le_bytes(
                    request[2..10]
                        .try_into()
                        .map_err(|_| SecurityBrokerError::Invalid)?,
                );
                let name_len = request[10] as usize;
                if request.len() != 12 + name_len || request[11 + name_len] > 1 {
                    Err(SecurityBrokerError::Invalid)
                } else {
                    let name = std::str::from_utf8(&request[11..11 + name_len])
                        .map_err(|_| SecurityBrokerError::Invalid)?;
                    self.create_symlink_temp(pipe, parent, name, request[11 + name_len] != 0)
                }
            }
            OP_SET_SYMLINK_TEMP if request.len() >= 23 => {
                let id: [u8; 16] = request[2..18]
                    .try_into()
                    .map_err(|_| SecurityBrokerError::Invalid)?;
                let relative = request[18];
                let substitute_len = u16::from_le_bytes(
                    request[19..21]
                        .try_into()
                        .map_err(|_| SecurityBrokerError::Invalid)?,
                ) as usize;
                let print_len = u16::from_le_bytes(
                    request[21..23]
                        .try_into()
                        .map_err(|_| SecurityBrokerError::Invalid)?,
                ) as usize;
                let payload_len = substitute_len
                    .checked_add(print_len)
                    .and_then(|length| length.checked_mul(size_of::<u16>()))
                    .ok_or(SecurityBrokerError::Limit)?;
                if relative > 1 || request.len() != 23 + payload_len {
                    Err(SecurityBrokerError::Invalid)
                } else {
                    let data = &request[23..];
                    let (substitute_bytes, print_bytes) = data.split_at(
                        substitute_len
                            .checked_mul(size_of::<u16>())
                            .ok_or(SecurityBrokerError::Limit)?,
                    );
                    let substitute = decode_utf16(substitute_bytes)?;
                    let print = decode_utf16(print_bytes)?;
                    self.set_symlink_temp(id, &substitute, &print, relative != 0)
                }
            }
            OP_FINALIZE_TEMP_SECURITY if request.len() == 34 => {
                let source: [u8; 16] = request[2..18]
                    .try_into()
                    .map_err(|_| SecurityBrokerError::Invalid)?;
                let temp: [u8; 16] = request[18..34]
                    .try_into()
                    .map_err(|_| SecurityBrokerError::Invalid)?;
                self.finalize_temp(source, temp)
            }
            OP_FINALIZE_PUBLISHED_TEMP if request.len() == 26 => {
                let id = request[2..18]
                    .try_into()
                    .map_err(|_| SecurityBrokerError::Invalid)?;
                let handle = u64::from_le_bytes(
                    request[18..26]
                        .try_into()
                        .map_err(|_| SecurityBrokerError::Invalid)?,
                );
                self.finalize_published_temp(id, handle)
            }
            OP_RELEASE_SOURCE if request.len() == 18 => {
                let id: [u8; 16] = request[2..18]
                    .try_into()
                    .map_err(|_| SecurityBrokerError::Invalid)?;
                self.release_source(id)
            }
            OP_RELEASE_TEMP if request.len() == 18 => {
                let id: [u8; 16] = request[2..18]
                    .try_into()
                    .map_err(|_| SecurityBrokerError::Invalid)?;
                self.release_temp(id)
            }
            OP_DISCARD_TEMP if request.len() == 18 => {
                let id: [u8; 16] = request[2..18]
                    .try_into()
                    .map_err(|_| SecurityBrokerError::Invalid)?;
                self.discard_temp(id)
            }
            _ => Err(SecurityBrokerError::Invalid),
        };
        match result {
            Ok(mut payload) => {
                let mut response = vec![PROTOCOL_VERSION, STATUS_OK];
                response.extend_from_slice(&self.session);
                response.append(&mut payload);
                let mut frame = Vec::with_capacity(4 + response.len());
                frame.extend_from_slice(&(response.len() as u32).to_le_bytes());
                frame.extend_from_slice(&response);
                write_message(pipe, &frame, Some(stopping))?;
                Ok(Vec::new())
            }
            Err(error) => {
                let mut response = vec![PROTOCOL_VERSION, error_status(error)];
                response.extend_from_slice(&self.session);
                let mut frame = Vec::with_capacity(4 + response.len());
                frame.extend_from_slice(&(response.len() as u32).to_le_bytes());
                frame.extend_from_slice(&response);
                write_message(pipe, &frame, Some(stopping))?;
                Ok(Vec::new())
            }
        }
    }

    fn capture_source(&mut self, wire_handle: u64) -> SecurityBrokerResult<Vec<u8>> {
        self.capture_source_with_pin(wire_handle, false)
    }

    fn capture_source_pinned(&mut self, wire_handle: u64) -> SecurityBrokerResult<Vec<u8>> {
        self.capture_source_with_pin(wire_handle, true)
    }

    fn capture_source_with_pin(
        &mut self,
        wire_handle: u64,
        pin_writes: bool,
    ) -> SecurityBrokerResult<Vec<u8>> {
        if self.sources.len() >= MAX_SOURCE_RECORDS {
            return Err(SecurityBrokerError::Limit);
        }
        let supplied = self.duplicate_peer_handle(wire_handle)?;
        validate_disk_file(supplied.as_raw_handle())?;
        let before = super::info_of(supplied.as_raw_handle())
            .map_err(|_| SecurityBrokerError::Unsupported)?;
        let kind = source_kind(supplied.as_raw_handle(), &before)?;
        let reparse = if matches!(kind, SourceKind::Symlink { .. }) {
            Some(read_symlink_reparse_buffer(supplied.as_raw_handle())?)
        } else {
            None
        };
        let user_token = self
            .user_token
            .as_ref()
            .ok_or(SecurityBrokerError::Unsupported)?;
        // Never let SYSTEM's broader file access authorize a source policy.
        // Reopening by the supplied handle's file ID under the exact
        // authenticated owner must grant the operation's ordinary access
        // before any SACL is read.
        let source = with_user_token(user_token.as_raw_handle(), || {
            reopen_for_user_source(supplied.as_raw_handle())
        })?;
        let user_info =
            super::info_of(source.as_raw_handle()).map_err(|_| SecurityBrokerError::Unsupported)?;
        validate_source_object(source.as_raw_handle(), &user_info, kind, reparse.as_deref())?;
        if !same_source_revision(&user_info, &before) {
            return Err(SecurityBrokerError::Changed);
        }
        if kind == SourceKind::File {
            super::native_default_stream_only(source.as_raw_handle())
                .map_err(SecurityBrokerError::from)?;
        }
        let user = user_dacl_state(source.as_raw_handle())?;
        let system_security = reopen_for_system_security(source.as_raw_handle())?;
        let policy = audit_policy(system_security.as_raw_handle(), source.as_raw_handle())?;
        let after =
            super::info_of(source.as_raw_handle()).map_err(|_| SecurityBrokerError::Unsupported)?;
        validate_source_object(source.as_raw_handle(), &after, kind, reparse.as_deref())?;
        if !same_source_revision(&user_info, &after)
            || after.nlink != 1
            || user_dacl_state(source.as_raw_handle())? != user
        {
            return Err(SecurityBrokerError::Changed);
        }
        let retained = if pin_writes {
            // Drop the temporary RW authorization handle before opening the
            // deny-write pin; otherwise Windows correctly reports a sharing
            // conflict. The peer-supplied handle is metadata-only in this
            // owner-local path, and the new pin denies any concurrent writer.
            drop(system_security);
            drop(source);
            let pinned = with_user_token(user_token.as_raw_handle(), || {
                reopen_for_user_source_pin(supplied.as_raw_handle())
            })?;
            let pinned_info =
                super::info_of(pinned.as_raw_handle()).map_err(|_| SecurityBrokerError::Changed)?;
            validate_source_object(
                pinned.as_raw_handle(),
                &pinned_info,
                kind,
                reparse.as_deref(),
            )?;
            if !same_source_revision(&pinned_info, &after)
                || user_dacl_state(pinned.as_raw_handle())? != user
            {
                return Err(SecurityBrokerError::Changed);
            }
            let pinned_system = reopen_for_system_security(pinned.as_raw_handle())?;
            let pinned_policy =
                audit_policy(pinned_system.as_raw_handle(), pinned.as_raw_handle())?;
            if pinned_policy != policy {
                return Err(SecurityBrokerError::Changed);
            }
            drop(pinned_system);
            pinned
        } else {
            source
        };
        let digest = policy.digest();
        let id = unique_id(self.sources.keys().copied());
        self.sources.insert(
            id,
            SourceRecord {
                handle: retained,
                identity: user_info.ident,
                kind,
                reparse,
                user,
                policy,
                digest,
                pin_writes,
            },
        );
        let mut result = Vec::with_capacity(48);
        result.extend_from_slice(&id);
        result.extend_from_slice(&digest);
        Ok(result)
    }

    fn recheck_source(&self, id: [u8; 16]) -> SecurityBrokerResult<Vec<u8>> {
        let source = self.sources.get(&id).ok_or(SecurityBrokerError::Invalid)?;
        let token = self
            .user_token
            .as_ref()
            .ok_or(SecurityBrokerError::Unsupported)?;
        let digest = recheck_source_record(source, token.as_raw_handle())?;
        let mut result = Vec::with_capacity(32);
        result.extend_from_slice(&digest);
        Ok(result)
    }

    fn release_source(&mut self, id: [u8; 16]) -> SecurityBrokerResult<Vec<u8>> {
        self.sources
            .remove(&id)
            .map(|_| Vec::new())
            .ok_or(SecurityBrokerError::Invalid)
    }

    fn create_temp(
        &mut self,
        _pipe: HANDLE,
        wire_parent: u64,
        name: &str,
    ) -> SecurityBrokerResult<Vec<u8>> {
        if self.temps.len() >= MAX_TEMP_RECORDS {
            return Err(SecurityBrokerError::Limit);
        }
        if !valid_broker_temp_name(name) {
            return Err(SecurityBrokerError::Invalid);
        }
        let user_token = self
            .user_token
            .as_ref()
            .ok_or(SecurityBrokerError::Unsupported)?;
        let supplied_parent = self.duplicate_peer_handle(wire_parent)?;
        validate_disk_directory(supplied_parent.as_raw_handle())?;
        let parent_user = with_user_token(user_token.as_raw_handle(), || {
            reopen_user_directory(supplied_parent.as_raw_handle())
        })?;
        let parent_info = super::info_of(parent_user.as_raw_handle())
            .map_err(|_| SecurityBrokerError::Unsupported)?;
        if super::kind_of(&parent_info) != super::Kind::Directory
            || parent_info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(SecurityBrokerError::Unsupported);
        }
        let name_wide: Vec<u16> = name.encode_utf16().collect();
        let created = with_user_token(user_token.as_raw_handle(), || {
            create_private_temp(parent_user.as_raw_handle(), &name_wide, &self.owner)
        })?;
        let temp_info = super::info_of(created.as_raw_handle())
            .map_err(|_| SecurityBrokerError::Unsupported)?;
        let id = unique_id(self.temps.keys().copied());
        let parent_identity = parent_info.ident;
        self.temps.insert(
            id,
            TempRecord {
                parent: parent_user,
                parent_identity,
                name: name_wide,
                handle: created,
                identity: temp_info.ident,
                kind: TempKind::File,
                expected_reparse: None,
                expected: None,
                finalization_started: false,
                finalized_source: None,
                published_finalized: false,
            },
        );
        let temp = self
            .temps
            .get_mut(&id)
            .ok_or(SecurityBrokerError::Unsupported)?;
        ensure_regular_single_link(temp.handle.as_raw_handle(), &temp_info)?;
        super::native_default_stream_only(temp.handle.as_raw_handle())
            .map_err(SecurityBrokerError::from)?;
        let audit_handle = reopen_for_system_security(temp.handle.as_raw_handle())?;
        let user_state = user_dacl_state(temp.handle.as_raw_handle())?;
        if user_state.owner != self.owner.bytes || !user_state.dacl_protected {
            return Err(SecurityBrokerError::Unsupported);
        }
        let expected_dacl = super::native_owner_only_dacl(&self.owner.bytes)
            .map_err(|_| SecurityBrokerError::Unsupported)?;
        if user_state.dacl.as_deref() != Some(expected_dacl.as_slice()) {
            return Err(SecurityBrokerError::Unsupported);
        }
        let audit = audit_policy(audit_handle.as_raw_handle(), temp.handle.as_raw_handle())?;
        temp.expected = Some(TempSecurityState {
            user: user_state,
            audit,
        });

        // The broker retains only a read handle for the rest of the temp's
        // lifetime. The owner process must later open a DELETE-capable,
        // read-sharing publication handle; retaining broker WRITE_DATA here
        // would make that stricter share mode fail even after the owner closed
        // its writer. The exact name and file ID are revalidated for every
        // privileged operation below.
        let held = with_user_token(user_token.as_raw_handle(), || {
            open_private_name_with_access_and_share(
                temp.parent.as_raw_handle(),
                &temp.name,
                false,
                WRITE_DAC | WRITE_OWNER,
                SHARE_ALL,
            )
        })?;
        let held_info =
            super::info_of(held.as_raw_handle()).map_err(|_| SecurityBrokerError::Changed)?;
        if held_info.ident != temp.identity || held_info.nlink != 1 {
            return Err(SecurityBrokerError::Changed);
        }
        ensure_regular_single_link(held.as_raw_handle(), &held_info)?;
        temp.handle = held;

        // Only public identity bytes cross the pipe. The client opens its
        // own user-granted handle and verifies this exact newly created file.
        let mut response = Vec::with_capacity(40);
        response.extend_from_slice(&id);
        response.extend_from_slice(&temp.identity.volume.to_le_bytes());
        response.extend_from_slice(&temp.identity.id.to_le_bytes());
        Ok(response)
    }

    fn create_symlink_temp(
        &mut self,
        _pipe: HANDLE,
        wire_parent: u64,
        name: &str,
        directory: bool,
    ) -> SecurityBrokerResult<Vec<u8>> {
        if self.temps.len() >= MAX_TEMP_RECORDS {
            return Err(SecurityBrokerError::Limit);
        }
        if !valid_broker_symlink_temp_name(name) {
            return Err(SecurityBrokerError::Invalid);
        }
        let user_token = self
            .user_token
            .as_ref()
            .ok_or(SecurityBrokerError::Unsupported)?;
        let supplied_parent = self.duplicate_peer_handle(wire_parent)?;
        validate_disk_directory(supplied_parent.as_raw_handle())?;
        let parent_user = with_user_token(user_token.as_raw_handle(), || {
            if directory {
                reopen_user_symlink_directory(supplied_parent.as_raw_handle())
            } else {
                reopen_user_directory(supplied_parent.as_raw_handle())
            }
        })?;
        let parent_info = super::info_of(parent_user.as_raw_handle())
            .map_err(|_| SecurityBrokerError::Unsupported)?;
        if super::kind_of(&parent_info) != super::Kind::Directory
            || parent_info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(SecurityBrokerError::Unsupported);
        }
        let name_wide: Vec<u16> = name.encode_utf16().collect();
        let created = with_user_token(user_token.as_raw_handle(), || {
            create_private_symlink_temp(
                parent_user.as_raw_handle(),
                &name_wide,
                &self.owner,
                directory,
            )
        })?;
        let prepared = (|| {
            let info = super::info_of(created.as_raw_handle())
                .map_err(|_| SecurityBrokerError::Unsupported)?;
            let expected_kind = if directory {
                super::Kind::Directory
            } else {
                super::Kind::File
            };
            if info.ident == parent_info.ident
                || super::kind_of(&info) != expected_kind
                || info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || info.nlink != 1
            {
                return Err(SecurityBrokerError::Changed);
            }
            validate_disk_file(created.as_raw_handle())?;
            if !directory {
                super::native_default_stream_only(created.as_raw_handle())
                    .map_err(SecurityBrokerError::from)?;
            }
            if directory
                && !super::read_dir_names(created.as_raw_handle())
                    .map_err(engine_error)?
                    .is_empty()
            {
                return Err(SecurityBrokerError::Changed);
            }
            let state = user_dacl_state(created.as_raw_handle())?;
            let expected_dacl = super::native_owner_only_dacl(&self.owner.bytes)
                .map_err(|_| SecurityBrokerError::Unsupported)?;
            if state.owner != self.owner.bytes
                || !state.dacl_protected
                || state.dacl.as_deref() != Some(expected_dacl.as_slice())
            {
                return Err(SecurityBrokerError::Unsupported);
            }

            // Keep a held identity handle that does not request DELETE. The
            // initial FILE_CREATE handle needs DELETE for exact-object cleanup
            // if validation fails, but retaining that access would conflict
            // with the later SHARE_WITHOUT_DELETE name pin used while setting
            // the reparse point. Reopen with share-all during this transition,
            // verify the name still denotes this exact object, then retain only
            // the no-delete handle.
            let held = with_user_token(user_token.as_raw_handle(), || {
                open_symlink_name_with_access_and_share(
                    parent_user.as_raw_handle(),
                    &name_wide,
                    directory,
                    false,
                    false,
                    WRITE_DAC | WRITE_OWNER,
                    SHARE_ALL,
                )
            })?;
            let held_info =
                super::info_of(held.as_raw_handle()).map_err(|_| SecurityBrokerError::Changed)?;
            if held_info.ident != info.ident
                || super::kind_of(&held_info) != expected_kind
                || held_info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || held_info.nlink != 1
            {
                return Err(SecurityBrokerError::Changed);
            }
            if !directory {
                super::native_default_stream_only(held.as_raw_handle())
                    .map_err(SecurityBrokerError::from)?;
            }
            if directory
                && !super::read_dir_names(held.as_raw_handle())
                    .map_err(engine_error)?
                    .is_empty()
            {
                return Err(SecurityBrokerError::Changed);
            }
            let held_state = user_dacl_state(held.as_raw_handle())?;
            if held_state.owner != self.owner.bytes
                || !held_state.dacl_protected
                || held_state.dacl.as_deref() != Some(expected_dacl.as_slice())
            {
                return Err(SecurityBrokerError::Changed);
            }
            let current_parent = super::info_of(parent_user.as_raw_handle())
                .map_err(|_| SecurityBrokerError::Changed)?;
            if current_parent.ident != parent_info.ident
                || super::kind_of(&current_parent) != super::Kind::Directory
                || current_parent.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                return Err(SecurityBrokerError::Changed);
            }
            let user_state = user_dacl_state(held.as_raw_handle())?;
            let audit_handle = reopen_for_system_security(held.as_raw_handle())?;
            let audit = audit_policy(audit_handle.as_raw_handle(), held.as_raw_handle())?;
            Ok((
                info,
                held,
                TempSecurityState {
                    user: user_state,
                    audit,
                },
            ))
        })();
        let (info, held, expected) = match prepared {
            Ok(result) => result,
            Err(error) => {
                let _ = super::delete_entry(created.as_raw_handle());
                return Err(error);
            }
        };
        drop(created);
        let id = unique_id(self.temps.keys().copied());
        let parent_identity = parent_info.ident;
        self.temps.insert(
            id,
            TempRecord {
                parent: parent_user,
                parent_identity,
                name: name_wide,
                handle: held,
                identity: info.ident,
                kind: TempKind::PendingSymlink { directory },
                expected_reparse: None,
                expected: Some(expected),
                finalization_started: false,
                finalized_source: None,
                published_finalized: false,
            },
        );
        let mut response = Vec::with_capacity(40);
        response.extend_from_slice(&id);
        response.extend_from_slice(&info.ident.volume.to_le_bytes());
        response.extend_from_slice(&info.ident.id.to_le_bytes());
        Ok(response)
    }

    fn set_symlink_temp(
        &mut self,
        id: [u8; 16],
        substitute: &[u16],
        print: &[u16],
        relative: bool,
    ) -> SecurityBrokerResult<Vec<u8>> {
        let buffer = build_symlink_reparse_buffer(substitute, print, relative)?;
        let user_token = self
            .user_token
            .as_ref()
            .ok_or(SecurityBrokerError::Unsupported)?;
        let temp = self
            .temps
            .get_mut(&id)
            .ok_or(SecurityBrokerError::Invalid)?;
        let TempKind::PendingSymlink { directory } = temp.kind else {
            return Err(SecurityBrokerError::Invalid);
        };
        if temp.expected_reparse.is_some()
            || temp.expected.is_some()
            || temp.finalization_started
            || temp.finalized_source.is_some()
        {
            return Err(SecurityBrokerError::Changed);
        }
        let parent_before = super::info_of(temp.parent.as_raw_handle())
            .map_err(|_| SecurityBrokerError::Changed)?;
        if parent_before.ident != temp.parent_identity
            || super::kind_of(&parent_before) != super::Kind::Directory
            || parent_before.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(SecurityBrokerError::Changed);
        }
        let named = with_user_token(user_token.as_raw_handle(), || {
            open_symlink_name(
                temp.parent.as_raw_handle(),
                &temp.name,
                directory,
                false,
                true,
            )
        })?;
        let named_info =
            super::info_of(named.as_raw_handle()).map_err(|_| SecurityBrokerError::Changed)?;
        let held_info = super::info_of(temp.handle.as_raw_handle())
            .map_err(|_| SecurityBrokerError::Changed)?;
        if named_info.ident != temp.identity
            || held_info.ident != temp.identity
            || named_info.nlink != 1
            || held_info.nlink != 1
        {
            return Err(SecurityBrokerError::Changed);
        }
        ensure_pending_symlink_temp(
            named.as_raw_handle(),
            &named_info,
            temp.identity,
            directory,
            None,
        )?;
        ensure_pending_symlink_temp(
            temp.handle.as_raw_handle(),
            &held_info,
            temp.identity,
            directory,
            None,
        )?;
        if !directory {
            super::native_default_stream_only(named.as_raw_handle())
                .map_err(SecurityBrokerError::from)?;
            super::native_default_stream_only(temp.handle.as_raw_handle())
                .map_err(SecurityBrokerError::from)?;
        }
        if directory
            && (!super::read_dir_names(named.as_raw_handle())
                .map_err(engine_error)?
                .is_empty()
                || !super::read_dir_names(temp.handle.as_raw_handle())
                    .map_err(engine_error)?
                    .is_empty())
        {
            return Err(SecurityBrokerError::Changed);
        }
        let expected_dacl = super::native_owner_only_dacl(&self.owner.bytes)
            .map_err(|_| SecurityBrokerError::Unsupported)?;
        for handle in [named.as_raw_handle(), temp.handle.as_raw_handle()] {
            let state = user_dacl_state(handle)?;
            if state.owner != self.owner.bytes
                || !state.dacl_protected
                || state.dacl.as_deref() != Some(expected_dacl.as_slice())
            {
                return Err(SecurityBrokerError::Changed);
            }
        }

        // The only privileged request in this API is FSCTL_SET_REPARSE_POINT
        // on the exact owner-private object created by this session. No target is resolved,
        // opened, statted, or transferred to the SYSTEM side.
        with_system_symlink_privilege(|| {
            set_symlink_reparse_buffer(named.as_raw_handle(), &buffer)
        })?;
        let actual = read_symlink_reparse_buffer(named.as_raw_handle())?;
        if actual != buffer {
            return Err(SecurityBrokerError::Changed);
        }
        let after =
            super::info_of(named.as_raw_handle()).map_err(|_| SecurityBrokerError::Changed)?;
        ensure_symlink_temp(
            named.as_raw_handle(),
            &after,
            temp.identity,
            directory,
            &buffer,
        )?;
        let held_after = super::info_of(temp.handle.as_raw_handle())
            .map_err(|_| SecurityBrokerError::Changed)?;
        ensure_symlink_temp(
            temp.handle.as_raw_handle(),
            &held_after,
            temp.identity,
            directory,
            &buffer,
        )?;
        let updated_security = user_dacl_state(named.as_raw_handle())?;
        if updated_security.owner != self.owner.bytes
            || !updated_security.dacl_protected
            || updated_security.dacl.as_deref() != Some(expected_dacl.as_slice())
        {
            return Err(SecurityBrokerError::Changed);
        }
        let final_parent = super::info_of(temp.parent.as_raw_handle())
            .map_err(|_| SecurityBrokerError::Changed)?;
        if final_parent.ident != temp.parent_identity
            || super::kind_of(&final_parent) != super::Kind::Directory
            || final_parent.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(SecurityBrokerError::Changed);
        }
        let final_named = with_user_token(user_token.as_raw_handle(), || {
            open_symlink_name(
                temp.parent.as_raw_handle(),
                &temp.name,
                directory,
                false,
                true,
            )
        })?;
        let final_named_info = super::info_of(final_named.as_raw_handle())
            .map_err(|_| SecurityBrokerError::Changed)?;
        ensure_symlink_temp(
            final_named.as_raw_handle(),
            &final_named_info,
            temp.identity,
            directory,
            &buffer,
        )?;
        temp.kind = TempKind::Symlink { directory };
        temp.expected_reparse = Some(buffer);
        Ok(Vec::new())
    }

    fn finalize_temp(
        &mut self,
        source_id: [u8; 16],
        temp_id: [u8; 16],
    ) -> SecurityBrokerResult<Vec<u8>> {
        let user_token = self
            .user_token
            .as_ref()
            .ok_or(SecurityBrokerError::Unsupported)?;
        let source = self
            .sources
            .get(&source_id)
            .ok_or(SecurityBrokerError::Invalid)?;
        let source_digest = recheck_source_record(source, user_token.as_raw_handle())?;
        if source_digest != source.digest || source.policy.digest() != source.digest {
            return Err(SecurityBrokerError::Changed);
        }
        let source_identity = source.identity;
        let source_policy = source.policy.clone();
        let defer_sacl_until_published = source.pin_writes;
        // Keep the exact source SACL bytes intact while the object is below
        // the private staging container. Its inherited state is restored only
        // after the ordinary owner publishes this object.
        let staging_policy = staging_audit_policy(&source_policy, defer_sacl_until_published);
        let temp = self
            .temps
            .get_mut(&temp_id)
            .ok_or(SecurityBrokerError::Invalid)?;
        if !matches!(temp.kind, TempKind::File | TempKind::Symlink { .. })
            || temp.finalization_started
            || temp.finalized_source.is_some()
        {
            return Err(SecurityBrokerError::Changed);
        }

        let parent_info = super::info_of(temp.parent.as_raw_handle())
            .map_err(|_| SecurityBrokerError::Unsupported)?;
        if parent_info.ident != temp.parent_identity
            || super::kind_of(&parent_info) != super::Kind::Directory
            || parent_info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(SecurityBrokerError::Changed);
        }
        if source_identity.volume != temp.parent_identity.volume {
            return Err(SecurityBrokerError::Unsupported);
        }
        let name_handle = with_user_token(user_token.as_raw_handle(), || match temp.kind {
            TempKind::File => open_private_name(temp.parent.as_raw_handle(), &temp.name, false),
            TempKind::Symlink { directory } => open_symlink_name(
                temp.parent.as_raw_handle(),
                &temp.name,
                directory,
                false,
                false,
            ),
            TempKind::PendingSymlink { .. } => Err(SecurityBrokerError::Changed),
        })?;
        let named_info = super::info_of(name_handle.as_raw_handle())
            .map_err(|_| SecurityBrokerError::Changed)?;
        let held_info = super::info_of(temp.handle.as_raw_handle())
            .map_err(|_| SecurityBrokerError::Changed)?;
        if named_info.ident != temp.identity
            || held_info.ident != temp.identity
            || named_info.nlink != 1
            || held_info.nlink != 1
        {
            return Err(SecurityBrokerError::Changed);
        }
        match temp.kind {
            TempKind::File => {
                ensure_regular_single_link(name_handle.as_raw_handle(), &named_info)?;
                super::native_default_stream_only(name_handle.as_raw_handle())
                    .map_err(SecurityBrokerError::from)?;
            }
            TempKind::Symlink { directory } => {
                let expected = temp
                    .expected_reparse
                    .as_deref()
                    .ok_or(SecurityBrokerError::Changed)?;
                ensure_symlink_temp(
                    name_handle.as_raw_handle(),
                    &named_info,
                    temp.identity,
                    directory,
                    expected,
                )?;
            }
            TempKind::PendingSymlink { .. } => return Err(SecurityBrokerError::Changed),
        }

        let current_user = user_dacl_state(temp.handle.as_raw_handle())?;
        let temp_security_handle = reopen_for_system_security(temp.handle.as_raw_handle())?;
        let current_audit = audit_policy(
            temp_security_handle.as_raw_handle(),
            temp.handle.as_raw_handle(),
        )?;
        let current = TempSecurityState {
            user: current_user,
            audit: current_audit,
        };
        if temp.expected.as_ref() != Some(&current) {
            return Err(SecurityBrokerError::Changed);
        }

        // Re-read the source immediately before changing the target. Once the
        // operation starts, a failed/partial security write poisons this token
        // so no second source can rewrite its policy.
        let source = self
            .sources
            .get(&source_id)
            .ok_or(SecurityBrokerError::Invalid)?;
        if recheck_source_record(source, user_token.as_raw_handle())? != source.digest {
            return Err(SecurityBrokerError::Changed);
        }
        temp.finalization_started = true;
        set_audit_policy(
            temp_security_handle.as_raw_handle(),
            temp.handle.as_raw_handle(),
            &staging_policy,
        )?;
        let resulting = audit_policy(
            temp_security_handle.as_raw_handle(),
            temp.handle.as_raw_handle(),
        )?;
        if resulting != staging_policy {
            return Err(SecurityBrokerError::Changed);
        }
        let final_named = super::info_of(name_handle.as_raw_handle())
            .map_err(|_| SecurityBrokerError::Changed)?;
        let final_held = super::info_of(temp.handle.as_raw_handle())
            .map_err(|_| SecurityBrokerError::Changed)?;
        match temp.kind {
            TempKind::File => {
                ensure_regular_single_link(name_handle.as_raw_handle(), &final_named)?;
                ensure_regular_single_link(temp.handle.as_raw_handle(), &final_held)?;
            }
            TempKind::Symlink { directory } => {
                let expected = temp
                    .expected_reparse
                    .as_deref()
                    .ok_or(SecurityBrokerError::Changed)?;
                ensure_symlink_temp(
                    name_handle.as_raw_handle(),
                    &final_named,
                    temp.identity,
                    directory,
                    expected,
                )?;
                ensure_symlink_temp(
                    temp.handle.as_raw_handle(),
                    &final_held,
                    temp.identity,
                    directory,
                    expected,
                )?;
            }
            TempKind::PendingSymlink { .. } => return Err(SecurityBrokerError::Changed),
        }
        temp.expected = Some(TempSecurityState {
            user: current.user,
            audit: resulting,
        });
        temp.finalized_source = Some(FinalizedSource {
            id: source_id,
            identity: source_identity,
            digest: source_digest,
            user: source.user.clone(),
            policy: source_policy,
            defer_sacl_until_published,
        });
        temp.published_finalized = !defer_sacl_until_published;
        Ok(Vec::new())
    }

    fn finalize_published_temp(
        &mut self,
        id: [u8; 16],
        wire_published: u64,
    ) -> SecurityBrokerResult<Vec<u8>> {
        let user_token = self
            .user_token
            .as_ref()
            .ok_or(SecurityBrokerError::Unsupported)?;
        let published = self.duplicate_peer_handle(wire_published)?;
        validate_disk_file(published.as_raw_handle())?;
        let temp = self
            .temps
            .get_mut(&id)
            .ok_or(SecurityBrokerError::Invalid)?;
        let finalized = temp
            .finalized_source
            .as_ref()
            .cloned()
            .ok_or(SecurityBrokerError::Changed)?;
        if !temp.finalization_started
            || !finalized.defer_sacl_until_published
            || temp.published_finalized
            || finalized.policy.digest() != finalized.digest
        {
            return Err(SecurityBrokerError::Changed);
        }
        let parent_info = super::info_of(temp.parent.as_raw_handle())
            .map_err(|_| SecurityBrokerError::Changed)?;
        if parent_info.ident != temp.parent_identity
            || super::kind_of(&parent_info) != super::Kind::Directory
            || parent_info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(SecurityBrokerError::Changed);
        }
        let original_name = with_user_token(user_token.as_raw_handle(), || match temp.kind {
            TempKind::File => {
                open_private_name_optional(temp.parent.as_raw_handle(), &temp.name, false)
            }
            TempKind::Symlink { directory } | TempKind::PendingSymlink { directory } => {
                open_symlink_name_optional(
                    temp.parent.as_raw_handle(),
                    &temp.name,
                    directory,
                    false,
                    false,
                )
            }
        })?;
        if original_name.is_some() {
            return Err(SecurityBrokerError::Changed);
        }
        let held_info = super::info_of(temp.handle.as_raw_handle())
            .map_err(|_| SecurityBrokerError::Changed)?;
        let published_info =
            super::info_of(published.as_raw_handle()).map_err(|_| SecurityBrokerError::Changed)?;
        if held_info.ident != temp.identity
            || held_info.nlink != 1
            || published_info.ident != temp.identity
            || published_info.nlink != 1
        {
            return Err(SecurityBrokerError::Changed);
        }
        match temp.kind {
            TempKind::File => {
                ensure_regular_single_link(temp.handle.as_raw_handle(), &held_info)?;
                ensure_regular_single_link(published.as_raw_handle(), &published_info)?;
                super::native_default_stream_only(published.as_raw_handle())
                    .map_err(SecurityBrokerError::from)?;
            }
            TempKind::Symlink { directory } => {
                let expected = temp
                    .expected_reparse
                    .as_deref()
                    .ok_or(SecurityBrokerError::Changed)?;
                ensure_symlink_temp(
                    temp.handle.as_raw_handle(),
                    &held_info,
                    temp.identity,
                    directory,
                    expected,
                )?;
                ensure_symlink_temp(
                    published.as_raw_handle(),
                    &published_info,
                    temp.identity,
                    directory,
                    expected,
                )?;
            }
            TempKind::PendingSymlink { .. } => return Err(SecurityBrokerError::Changed),
        }
        if user_dacl_state(temp.handle.as_raw_handle())? != finalized.user
            || user_dacl_state(published.as_raw_handle())? != finalized.user
        {
            return Err(SecurityBrokerError::Changed);
        }
        let audit_handle = reopen_for_system_security(temp.handle.as_raw_handle())?;
        let before = audit_policy(audit_handle.as_raw_handle(), temp.handle.as_raw_handle())?;
        let expected_stage = staging_audit_policy(&finalized.policy, true);
        if before != expected_stage
            || temp
                .expected
                .as_ref()
                .is_none_or(|expected| expected.audit != expected_stage)
        {
            return Err(SecurityBrokerError::Changed);
        }

        // This post-publication operation changes only the exact broker-created
        // object pinned above. It never resolves the published name or accepts
        // an arbitrary target path. If inherited SACL restoration partially
        // fails, make a best-effort attempt to retain a protected SACL.
        let restored = set_published_audit_policy(
            audit_handle.as_raw_handle(),
            temp.handle.as_raw_handle(),
            &finalized.policy,
        );
        let resulting = match restored {
            Ok(resulting) => resulting,
            Err(error) => {
                let _ = protect_current_sacl(audit_handle.as_raw_handle());
                return Err(error);
            }
        };
        let after = super::info_of(temp.handle.as_raw_handle())
            .map_err(|_| SecurityBrokerError::Changed)?;
        let after_published =
            super::info_of(published.as_raw_handle()).map_err(|_| SecurityBrokerError::Changed)?;
        if after.ident != temp.identity
            || after.nlink != 1
            || after_published.ident != temp.identity
            || after_published.nlink != 1
            || user_dacl_state(temp.handle.as_raw_handle())? != finalized.user
            || user_dacl_state(published.as_raw_handle())? != finalized.user
            || audit_policy(audit_handle.as_raw_handle(), temp.handle.as_raw_handle())? != resulting
            || !published_audit_policy_matches(&finalized.policy, &resulting)
        {
            let _ = protect_current_sacl(audit_handle.as_raw_handle());
            return Err(SecurityBrokerError::Changed);
        }
        let expected = temp.expected.as_mut().ok_or(SecurityBrokerError::Changed)?;
        expected.user = finalized.user;
        expected.audit = resulting;
        temp.published_finalized = true;
        Ok(Vec::new())
    }

    fn release_temp(&mut self, id: [u8; 16]) -> SecurityBrokerResult<Vec<u8>> {
        let user_token = self
            .user_token
            .as_ref()
            .ok_or(SecurityBrokerError::Unsupported)?;
        let temp = self.temps.get(&id).ok_or(SecurityBrokerError::Invalid)?;
        if temp.finalization_started && temp.finalized_source.is_none() {
            return Err(SecurityBrokerError::Changed);
        }
        let parent_info = super::info_of(temp.parent.as_raw_handle())
            .map_err(|_| SecurityBrokerError::Changed)?;
        if parent_info.ident != temp.parent_identity
            || super::kind_of(&parent_info) != super::Kind::Directory
        {
            return Err(SecurityBrokerError::Changed);
        }
        if let Some(finalized) = temp.finalized_source.as_ref() {
            let expected = temp.expected.as_ref().ok_or(SecurityBrokerError::Changed)?;
            if finalized.identity.volume != temp.parent_identity.volume
                || finalized.policy.digest() != finalized.digest
                || (finalized.defer_sacl_until_published && !temp.published_finalized)
                || (!finalized.defer_sacl_until_published && expected.audit != finalized.policy)
            {
                return Err(SecurityBrokerError::Changed);
            }
        }
        let held_info = super::info_of(temp.handle.as_raw_handle())
            .map_err(|_| SecurityBrokerError::Changed)?;
        let held_user = user_dacl_state(temp.handle.as_raw_handle())?;
        let audit_handle = reopen_for_system_security(temp.handle.as_raw_handle())?;
        let held_audit = audit_policy(audit_handle.as_raw_handle(), temp.handle.as_raw_handle())?;
        if let Some(finalized) = temp.finalized_source.as_ref() {
            let _bound_source_id = finalized.id;
            if held_user != finalized.user
                || temp
                    .expected
                    .as_ref()
                    .is_none_or(|expected| expected.audit != held_audit)
                || (!finalized.defer_sacl_until_published && held_audit != finalized.policy)
                || (finalized.defer_sacl_until_published
                    && !published_audit_policy_matches(&finalized.policy, &held_audit))
            {
                return Err(SecurityBrokerError::Changed);
            }
        } else if temp.expected.as_ref()
            != Some(&TempSecurityState {
                user: held_user.clone(),
                audit: held_audit.clone(),
            })
        {
            return Err(SecurityBrokerError::Changed);
        }
        match temp.kind {
            TempKind::File => ensure_regular_single_link(temp.handle.as_raw_handle(), &held_info)?,
            TempKind::PendingSymlink { .. } => return Err(SecurityBrokerError::Changed),
            TempKind::Symlink { directory } => {
                ensure_symlink_temp(
                    temp.handle.as_raw_handle(),
                    &held_info,
                    temp.identity,
                    directory,
                    temp.expected_reparse
                        .as_deref()
                        .ok_or(SecurityBrokerError::Changed)?,
                )?;
            }
        }
        let named = with_user_token(user_token.as_raw_handle(), || match temp.kind {
            TempKind::File => {
                open_private_name_optional(temp.parent.as_raw_handle(), &temp.name, false)
            }
            TempKind::PendingSymlink { directory } | TempKind::Symlink { directory } => {
                open_symlink_name_optional(
                    temp.parent.as_raw_handle(),
                    &temp.name,
                    directory,
                    false,
                    false,
                )
            }
        })?;
        if let Some(named) = named {
            let _ =
                super::info_of(named.as_raw_handle()).map_err(|_| SecurityBrokerError::Changed)?;
            // Never detach while any entry occupies the original basename.
            // This handle omits FILE_SHARE_DELETE, keeping the check stable.
            return Err(SecurityBrokerError::Changed);
        }
        self.temps.remove(&id);
        Ok(Vec::new())
    }

    fn discard_temp(&mut self, id: [u8; 16]) -> SecurityBrokerResult<Vec<u8>> {
        self.temps
            .remove(&id)
            .map(|_| Vec::new())
            .ok_or(SecurityBrokerError::Invalid)
    }

    fn duplicate_peer_handle(&self, wire_handle: u64) -> SecurityBrokerResult<OwnedHandle> {
        let source = wire_to_handle(wire_handle)?;
        let mut duplicate = null_mut();
        if unsafe {
            DuplicateHandle(
                self.peer_process.as_raw_handle(),
                source,
                GetCurrentProcess(),
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
            || duplicate.is_null()
        {
            return Err(last_io_error());
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(duplicate) })
    }

    fn cleanup(&mut self) {
        // Do not probe or delete project files from the LocalSystem process.
        // The client owns private-temp cleanup; records and handles are simply
        // dropped when the authenticated pipe session ends.
        self.temps.clear();
        self.sources.clear();
    }
}

fn serve_connection(
    pipe: HANDLE,
    stopping: &AtomicBool,
    session: &mut ServerSession,
) -> SecurityBrokerResult<()> {
    while !stopping.load(Ordering::Acquire) {
        if session.handle_request(pipe, stopping).is_err() {
            return Err(SecurityBrokerError::Io(io::ErrorKind::UnexpectedEof));
        }
    }
    Ok(())
}

fn recheck_source_record(
    source: &SourceRecord,
    user_token: RawHandle,
) -> SecurityBrokerResult<[u8; 32]> {
    validate_disk_file(source.handle.as_raw_handle())?;
    let held_info =
        super::info_of(source.handle.as_raw_handle()).map_err(|_| SecurityBrokerError::Changed)?;
    validate_source_object(
        source.handle.as_raw_handle(),
        &held_info,
        source.kind,
        source.reparse.as_deref(),
    )?;
    let user_source = with_user_token(user_token, || {
        if source.pin_writes {
            reopen_for_user_source_pin(source.handle.as_raw_handle())
        } else {
            reopen_for_user_source(source.handle.as_raw_handle())
        }
    })?;
    let before =
        super::info_of(user_source.as_raw_handle()).map_err(|_| SecurityBrokerError::Changed)?;
    validate_source_object(
        user_source.as_raw_handle(),
        &before,
        source.kind,
        source.reparse.as_deref(),
    )?;
    if !same_source_revision(&before, &held_info)
        || before.ident != source.identity
        || user_dacl_state(user_source.as_raw_handle())? != source.user
    {
        return Err(SecurityBrokerError::Changed);
    }
    if source.kind == SourceKind::File {
        super::native_default_stream_only(user_source.as_raw_handle())
            .map_err(SecurityBrokerError::from)?;
    }
    let system_security = reopen_for_system_security(user_source.as_raw_handle())?;
    let policy = audit_policy(system_security.as_raw_handle(), user_source.as_raw_handle())?;
    let after =
        super::info_of(user_source.as_raw_handle()).map_err(|_| SecurityBrokerError::Changed)?;
    validate_source_object(
        user_source.as_raw_handle(),
        &after,
        source.kind,
        source.reparse.as_deref(),
    )?;
    if !same_source_revision(&after, &before)
        || after.ident != source.identity
        || after.nlink != 1
        || user_dacl_state(user_source.as_raw_handle())? != source.user
        || policy != source.policy
        || policy.digest() != source.digest
    {
        return Err(SecurityBrokerError::Changed);
    }
    Ok(policy.digest())
}

fn source_kind(handle: RawHandle, info: &super::Info) -> SecurityBrokerResult<SourceKind> {
    validate_disk_file(handle)?;
    if info.nlink != 1 {
        return Err(SecurityBrokerError::Unsupported);
    }
    match super::kind_of(info) {
        super::Kind::File => Ok(SourceKind::File),
        super::Kind::Symlink => {
            // Verify the object itself is an ordinary symbolic-link reparse
            // point. Junctions and other tags are deliberately excluded.
            read_symlink_reparse_buffer(handle)?;
            Ok(SourceKind::Symlink {
                directory: info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0,
            })
        }
        super::Kind::Directory | super::Kind::Other => Err(SecurityBrokerError::Unsupported),
    }
}

fn same_source_revision(left: &super::Info, right: &super::Info) -> bool {
    left.ident == right.ident
        && left.attributes == right.attributes
        && left.size == right.size
        && left.nlink == right.nlink
        && left.last_write == right.last_write
        && left.change == right.change
}

fn validate_source_object(
    handle: RawHandle,
    info: &super::Info,
    kind: SourceKind,
    expected_reparse: Option<&[u8]>,
) -> SecurityBrokerResult<()> {
    validate_disk_file(handle)?;
    if info.nlink != 1 {
        return Err(SecurityBrokerError::Changed);
    }
    match kind {
        SourceKind::File => ensure_regular_single_link(handle, info),
        SourceKind::Symlink { directory } => {
            if super::kind_of(info) != super::Kind::Symlink
                || (info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
            {
                return Err(SecurityBrokerError::Changed);
            }
            let expected = expected_reparse.ok_or(SecurityBrokerError::Changed)?;
            if read_symlink_reparse_buffer(handle)? != expected {
                return Err(SecurityBrokerError::Changed);
            }
            Ok(())
        }
    }
}

fn validate_disk_file(handle: RawHandle) -> SecurityBrokerResult<()> {
    if unsafe { GetFileType(handle) } != FILE_TYPE_DISK {
        return Err(SecurityBrokerError::Unsupported);
    }
    // Do not issue a filesystem query until the kernel object name has ruled
    // out redirectors and device objects. A peer can supply an already-open
    // SMB handle even though GetFileType reports FILE_TYPE_DISK.
    let volume = local_volume_device(handle)?;
    require_supported_filesystem(handle, &volume)?;
    Ok(())
}

fn local_volume_device(handle: RawHandle) -> SecurityBrokerResult<Vec<u16>> {
    let mut needed = 0u32;
    let query_status = unsafe {
        NtQueryObject(
            handle,
            OBJECT_NAME_INFORMATION_CLASS,
            null_mut(),
            0,
            &mut needed,
        )
    };
    if query_status < 0 && query_status != STATUS_INFO_LENGTH_MISMATCH {
        return Err(SecurityBrokerError::Unsupported);
    }
    if needed < size_of::<OBJECT_NAME_INFORMATION>() as u32 || needed > MAX_MESSAGE as u32 {
        return Err(SecurityBrokerError::Unsupported);
    }
    let mut storage = vec![0u64; (needed as usize).div_ceil(size_of::<u64>())];
    let status = unsafe {
        NtQueryObject(
            handle,
            OBJECT_NAME_INFORMATION_CLASS,
            storage.as_mut_ptr().cast(),
            (storage.len() * size_of::<u64>()) as u32,
            &mut needed,
        )
    };
    if status < 0 {
        return Err(SecurityBrokerError::Unsupported);
    }
    let info = unsafe { &*storage.as_ptr().cast::<OBJECT_NAME_INFORMATION>() };
    let name = info.Name;
    let name_len = name.Length as usize;
    let storage_start = storage.as_ptr() as usize;
    let storage_end = storage_start
        .checked_add(storage.len() * size_of::<u64>())
        .ok_or(SecurityBrokerError::Unsupported)?;
    let name_start = name.Buffer as usize;
    let name_end = name_start
        .checked_add(name_len)
        .ok_or(SecurityBrokerError::Unsupported)?;
    if name_len == 0
        || name_len % size_of::<u16>() != 0
        || name_start < storage_start
        || name_end > storage_end
    {
        return Err(SecurityBrokerError::Unsupported);
    }
    let path = unsafe { std::slice::from_raw_parts(name.Buffer, name_len / size_of::<u16>()) };

    // Restrict supported handles to local disk-volume objects. This excludes
    // MUP/LanmanRedirector/WebDav and other remote providers before any query
    // that could contact their servers. The numeric suffix rejects similarly
    // prefixed devices such as HarddiskVolumeShadowCopy.
    const PREFIX: &str = r"\Device\HarddiskVolume";
    let prefix: Vec<u16> = PREFIX.encode_utf16().collect();
    if path.len() <= prefix.len() || !wide_ascii_eq_ignore_case(&path[..prefix.len()], PREFIX) {
        return Err(SecurityBrokerError::Unsupported);
    }
    let mut end = prefix.len();
    while path
        .get(end)
        .is_some_and(|ch| (b'0' as u16..=b'9' as u16).contains(ch))
    {
        end += 1;
    }
    if end == prefix.len() || path.get(end).is_some_and(|ch| *ch != b'\\' as u16) {
        return Err(SecurityBrokerError::Unsupported);
    }
    Ok(path[..end].to_vec())
}

fn require_supported_filesystem(handle: RawHandle, _volume: &[u16]) -> SecurityBrokerResult<()> {
    // This is deliberately reached only after local_volume_device has
    // rejected remote and non-volume object names.
    let mut storage = [0u64; 256];
    let mut iosb: IO_STATUS_BLOCK = unsafe { zeroed() };
    let status = unsafe {
        NtQueryVolumeInformationFile(
            handle,
            &mut iosb,
            storage.as_mut_ptr().cast(),
            (storage.len() * size_of::<u64>()) as u32,
            FileFsAttributeInformation,
        )
    };
    let io_status = unsafe { iosb.Anonymous.Status };
    if status < 0 || io_status < 0 {
        return Err(SecurityBrokerError::Unsupported);
    }
    let info = unsafe { &*storage.as_ptr().cast::<FILE_FS_ATTRIBUTE_INFORMATION>() };
    let name_len = info.FileSystemNameLength as usize;
    let name_offset = std::mem::offset_of!(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName);
    if name_len % size_of::<u16>() != 0
        || name_len > storage.len() * size_of::<u64>() - name_offset
        || iosb.Information < name_offset + name_len
    {
        return Err(SecurityBrokerError::Unsupported);
    }
    let name = unsafe {
        std::slice::from_raw_parts(info.FileSystemName.as_ptr(), name_len / size_of::<u16>())
    };
    if !wide_ascii_eq_ignore_case(name, "NTFS") && !wide_ascii_eq_ignore_case(name, "ReFS") {
        return Err(SecurityBrokerError::Unsupported);
    }
    Ok(())
}

fn wide_ascii_eq_ignore_case(wide: &[u16], ascii: &str) -> bool {
    wide.len() == ascii.len()
        && wide.iter().zip(ascii.bytes()).all(|(&wide, ascii)| {
            let wide = if (b'A' as u16..=b'Z' as u16).contains(&wide) {
                wide + (b'a' - b'A') as u16
            } else {
                wide
            };
            wide == ascii.to_ascii_lowercase() as u16
        })
}

fn validate_disk_directory(handle: RawHandle) -> SecurityBrokerResult<()> {
    validate_disk_file(handle)?;
    let info = super::info_of(handle).map_err(|_| SecurityBrokerError::Unsupported)?;
    if super::kind_of(&info) != super::Kind::Directory
        || info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(SecurityBrokerError::Unsupported);
    }
    Ok(())
}

fn ensure_regular_single_link(handle: RawHandle, info: &Info) -> SecurityBrokerResult<()> {
    if super::kind_of(info) != super::Kind::File
        || info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || info.nlink != 1
    {
        return Err(SecurityBrokerError::Unsupported);
    }
    validate_disk_file(handle)
}

fn reopen_for_system_security(handle: RawHandle) -> SecurityBrokerResult<OwnedHandle> {
    let info = super::info_of(handle).map_err(|_| SecurityBrokerError::Changed)?;
    let options = match super::kind_of(&info) {
        super::Kind::File => FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
        super::Kind::Directory => FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
        super::Kind::Symlink if info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 => {
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT
        }
        super::Kind::Symlink => FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
        super::Kind::Other => return Err(SecurityBrokerError::Unsupported),
    };
    super::with_system_security_privilege(|| {
        reopen_by_file_id(handle, ACCESS_SYSTEM_SECURITY, options)
    })
    .map_err(engine_error)?
}

fn reopen_for_user_source(handle: RawHandle) -> SecurityBrokerResult<OwnedHandle> {
    let info = super::info_of(handle).map_err(|_| SecurityBrokerError::Changed)?;
    let kind = source_kind(handle, &info)?;
    let options = match kind {
        SourceKind::File => FILE_NON_DIRECTORY_FILE,
        SourceKind::Symlink { directory: true } => FILE_DIRECTORY_FILE,
        SourceKind::Symlink { directory: false } => FILE_NON_DIRECTORY_FILE,
    } | FILE_OPEN_REPARSE_POINT
        | FILE_SYNCHRONOUS_IO_NONALERT;
    let access = match kind {
        // Source ACL copying retains the previous ordinary read/write
        // authorization gate for regular files; LocalSystem's privilege alone
        // must not authorize a replacement.
        SourceKind::File => {
            FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
        }
        // Symlinks are inspected through FILE_OPEN_REPARSE_POINT. Their
        // no-follow metadata/reparse contract is distinct from file-content
        // access and never opens or probes the target.
        SourceKind::Symlink { .. } => FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
    };
    reopen_by_file_id(handle, access, options)
}

fn reopen_for_user_source_pin(handle: RawHandle) -> SecurityBrokerResult<OwnedHandle> {
    let info = super::info_of(handle).map_err(|_| SecurityBrokerError::Changed)?;
    let kind = source_kind(handle, &info)?;
    let options = match kind {
        SourceKind::File => FILE_NON_DIRECTORY_FILE,
        SourceKind::Symlink { directory: true } => FILE_DIRECTORY_FILE,
        SourceKind::Symlink { directory: false } => FILE_NON_DIRECTORY_FILE,
    } | FILE_OPEN_REPARSE_POINT
        | FILE_SYNCHRONOUS_IO_NONALERT;
    let access = match kind {
        SourceKind::File => FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
        SourceKind::Symlink { .. } => FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
    };
    reopen_by_file_id_with_share(handle, access, options, FILE_SHARE_READ | FILE_SHARE_DELETE)
}

fn reopen_user_directory(handle: RawHandle) -> SecurityBrokerResult<OwnedHandle> {
    reopen_by_file_id(
        handle,
        FILE_ADD_FILE | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | FILE_TRAVERSE | SYNCHRONIZE,
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
    )
}

fn reopen_user_symlink_directory(handle: RawHandle) -> SecurityBrokerResult<OwnedHandle> {
    reopen_by_file_id(
        handle,
        FILE_ADD_FILE
            | FILE_ADD_SUBDIRECTORY
            | FILE_READ_ATTRIBUTES
            | FILE_LIST_DIRECTORY
            | FILE_TRAVERSE
            | SYNCHRONIZE,
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
    )
}

fn reopen_by_file_id(
    original: RawHandle,
    access: u32,
    options: u32,
) -> SecurityBrokerResult<OwnedHandle> {
    reopen_by_file_id_with_share(original, access, options, SHARE_ALL)
}

fn reopen_by_file_id_with_share(
    original: RawHandle,
    access: u32,
    options: u32,
    share: u32,
) -> SecurityBrokerResult<OwnedHandle> {
    let volume = local_volume_device(original)?;
    require_supported_filesystem(original, &volume)?;
    let original_info = super::info_of(original).map_err(|_| SecurityBrokerError::Changed)?;
    match super::kind_of(&original_info) {
        super::Kind::File => {
            if options & FILE_DIRECTORY_FILE != 0 {
                return Err(SecurityBrokerError::Unsupported);
            }
            ensure_regular_single_link(original, &original_info)?;
        }
        super::Kind::Directory => {
            if options & FILE_DIRECTORY_FILE == 0
                || original_info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                return Err(SecurityBrokerError::Unsupported);
            }
        }
        super::Kind::Symlink => {
            let kind = source_kind(original, &original_info)?;
            if options & FILE_OPEN_REPARSE_POINT == 0
                || (options & FILE_DIRECTORY_FILE != 0)
                    != matches!(kind, SourceKind::Symlink { directory: true })
            {
                return Err(SecurityBrokerError::Unsupported);
            }
        }
        super::Kind::Other => return Err(SecurityBrokerError::Unsupported),
    }
    let file_id = query_file_id_information(original)?;
    let original_identity = file_id_identity(&file_id);
    if original_identity != original_info.ident {
        return Err(SecurityBrokerError::Changed);
    }

    // FILE_OPEN_BY_FILE_ID uses a binary file reference after the device
    // volume name. Use the complete 128-bit identity: ReFS IDs are not
    // necessarily the same as their 64-bit file reference. Build the UTF-16
    // prefix and binary suffix in one aligned allocation for UNICODE_STRING.
    let mut object_name = volume;
    object_name.push(b'\\' as u16);
    for pair in file_id.FileId.Identifier.chunks_exact(2) {
        object_name.push(u16::from_le_bytes([pair[0], pair[1]]));
    }
    let name_len = object_name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|len| u16::try_from(len).ok())
        .ok_or(SecurityBrokerError::Invalid)?;
    let unicode = UNICODE_STRING {
        Length: name_len,
        MaximumLength: name_len,
        Buffer: object_name.as_mut_ptr(),
    };
    let object = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: null_mut(),
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: null_mut(),
        SecurityQualityOfService: null(),
    };
    let mut raw = null_mut();
    let mut iosb: IO_STATUS_BLOCK = unsafe { zeroed() };
    let result = unsafe {
        NtCreateFile(
            &mut raw,
            access,
            &object,
            &mut iosb,
            null(),
            FILE_ATTRIBUTE_NORMAL,
            share,
            FILE_OPEN,
            options | FILE_OPEN_BY_FILE_ID | FILE_COMPLETE_IF_OPLOCKED,
            null(),
            0,
        )
    };
    if result == STATUS_OPLOCK_BREAK_IN_PROGRESS {
        // FILE_COMPLETE_IF_OPLOCKED must never leave a returned handle behind
        // on this no-effect retry result.
        if !raw.is_null() {
            unsafe { CloseHandle(raw) };
        }
        return Err(SecurityBrokerError::Io(io::ErrorKind::WouldBlock));
    }
    if result == STATUS_OBJECT_NAME_NOT_FOUND || result == STATUS_OBJECT_PATH_NOT_FOUND {
        return Err(SecurityBrokerError::Changed);
    }
    if result < 0 || raw.is_null() {
        return Err(SecurityBrokerError::Unsupported);
    }
    let reopened = unsafe { OwnedHandle::from_raw_handle(raw) };
    // The audit-only handle lacks FILE_READ_ATTRIBUTES. FileIdInformation is
    // an access-free identity query; do not call info_of here because it also
    // requests FileBasicInformation and would widen the SACL handle.
    if file_id_identity(&query_file_id_information(reopened.as_raw_handle())?) != original_identity
    {
        return Err(SecurityBrokerError::Changed);
    }
    Ok(reopened)
}

fn query_file_id_information(handle: RawHandle) -> SecurityBrokerResult<FILE_ID_INFORMATION> {
    let mut info: FILE_ID_INFORMATION = unsafe { zeroed() };
    let mut iosb: IO_STATUS_BLOCK = unsafe { zeroed() };
    let status = unsafe {
        NtQueryInformationFile(
            handle,
            &mut iosb,
            (&mut info as *mut FILE_ID_INFORMATION).cast(),
            size_of::<FILE_ID_INFORMATION>() as u32,
            FileIdInformation,
        )
    };
    if status < 0
        || unsafe { iosb.Anonymous.Status } < 0
        || iosb.Information < size_of::<FILE_ID_INFORMATION>()
    {
        return Err(SecurityBrokerError::Unsupported);
    }
    Ok(info)
}

fn file_id_identity(info: &FILE_ID_INFORMATION) -> Ident {
    Ident {
        volume: info.VolumeSerialNumber,
        id: u128::from_le_bytes(info.FileId.Identifier),
    }
}

fn create_private_temp(
    parent: RawHandle,
    name: &[u16],
    owner: &CanonicalSid,
) -> SecurityBrokerResult<OwnedHandle> {
    let dacl = super::native_owner_only_dacl(&owner.bytes)
        .map_err(|_| SecurityBrokerError::Unsupported)?;
    let mut descriptor: SECURITY_DESCRIPTOR = unsafe { zeroed() };
    let mut owner_sid = null_mut();
    let sid_text: Vec<u16> = owner
        .canonical
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    if unsafe { ConvertStringSidToSidW(sid_text.as_ptr(), &mut owner_sid) } == 0
        || owner_sid.is_null()
    {
        return Err(SecurityBrokerError::Unsupported);
    }
    let owner_sid = LocalSid(owner_sid);
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
        return Err(SecurityBrokerError::Unsupported);
    }
    let length = name
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or(SecurityBrokerError::Invalid)?;
    let unicode = UNICODE_STRING {
        Length: u16::try_from(length).map_err(|_| SecurityBrokerError::Invalid)?,
        MaximumLength: u16::try_from(length).map_err(|_| SecurityBrokerError::Invalid)?,
        Buffer: name.as_ptr().cast_mut(),
    };
    let object = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent,
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
        SecurityQualityOfService: null(),
    };
    let mut raw = null_mut();
    let mut status: IO_STATUS_BLOCK = unsafe { zeroed() };
    let result = unsafe {
        NtCreateFile(
            &mut raw,
            FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE,
            &object,
            &mut status,
            null(),
            FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_NORMAL,
            SHARE_ALL,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            null(),
            0,
        )
    };
    if result < 0 || raw.is_null() {
        return Err(if result == STATUS_OBJECT_NAME_COLLISION {
            SecurityBrokerError::Io(io::ErrorKind::AlreadyExists)
        } else {
            SecurityBrokerError::Unsupported
        });
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

fn create_private_symlink_temp(
    parent: RawHandle,
    name: &[u16],
    owner: &CanonicalSid,
    directory: bool,
) -> SecurityBrokerResult<OwnedHandle> {
    let dacl = super::native_owner_only_dacl(&owner.bytes)
        .map_err(|_| SecurityBrokerError::Unsupported)?;
    let mut descriptor: SECURITY_DESCRIPTOR = unsafe { zeroed() };
    let mut owner_sid = null_mut();
    let sid_text: Vec<u16> = owner
        .canonical
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    if unsafe { ConvertStringSidToSidW(sid_text.as_ptr(), &mut owner_sid) } == 0
        || owner_sid.is_null()
    {
        return Err(SecurityBrokerError::Unsupported);
    }
    let owner_sid = LocalSid(owner_sid);
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
        return Err(SecurityBrokerError::Unsupported);
    }
    let length = name
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or(SecurityBrokerError::Invalid)?;
    let unicode = UNICODE_STRING {
        Length: u16::try_from(length).map_err(|_| SecurityBrokerError::Invalid)?,
        MaximumLength: u16::try_from(length).map_err(|_| SecurityBrokerError::Invalid)?,
        Buffer: name.as_ptr().cast_mut(),
    };
    let object = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent,
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
        SecurityQualityOfService: null(),
    };
    let access = FILE_WRITE_DATA
        | FILE_READ_ATTRIBUTES
        | FILE_WRITE_ATTRIBUTES
        | DELETE
        | READ_CONTROL
        | SYNCHRONIZE
        | if directory { FILE_LIST_DIRECTORY } else { 0 };
    let options = if directory {
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT
    } else {
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT
    };
    let mut raw = null_mut();
    let mut status: IO_STATUS_BLOCK = unsafe { zeroed() };
    let result = unsafe {
        NtCreateFile(
            &mut raw,
            access,
            &object,
            &mut status,
            null(),
            FILE_ATTRIBUTE_NORMAL,
            SHARE_ALL,
            FILE_CREATE,
            options,
            null(),
            0,
        )
    };
    if result < 0 || raw.is_null() {
        return Err(if result == STATUS_OBJECT_NAME_COLLISION {
            SecurityBrokerError::Io(io::ErrorKind::AlreadyExists)
        } else {
            SecurityBrokerError::Unsupported
        });
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

struct LocalSid(*mut c_void);

impl Drop for LocalSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

fn user_dacl_state(handle: RawHandle) -> SecurityBrokerResult<OwnerDaclState> {
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
        return Err(SecurityBrokerError::Unsupported);
    }
    let descriptor = LocalDescriptor(descriptor);
    if descriptor.0.is_null() || owner.is_null() || group.is_null() {
        return Err(SecurityBrokerError::Unsupported);
    }
    let owner = unsafe { sid_bytes(owner)? };
    let group = unsafe { sid_bytes(group)? };
    let mut present = 0;
    let mut descriptor_dacl = null_mut();
    let mut defaulted = 0;
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor.0,
            &mut present,
            &mut descriptor_dacl,
            &mut defaulted,
        )
    } == 0
    {
        return Err(SecurityBrokerError::Unsupported);
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
        return Err(SecurityBrokerError::Unsupported);
    }
    let dacl_bytes = if descriptor_dacl.is_null() {
        None
    } else {
        let len = unsafe { (*descriptor_dacl).AclSize } as usize;
        if len < size_of::<ACL>() || len > MAX_ACL_BYTES {
            return Err(SecurityBrokerError::Limit);
        }
        Some(unsafe { std::slice::from_raw_parts(descriptor_dacl.cast::<u8>(), len) }.to_vec())
    };
    Ok(OwnerDaclState {
        owner,
        group,
        dacl: dacl_bytes,
        dacl_present: present != 0,
        dacl_protected: control & SE_DACL_PROTECTED != 0,
    })
}

fn open_private_name(
    parent: RawHandle,
    name: &[u16],
    for_delete: bool,
) -> SecurityBrokerResult<OwnedHandle> {
    open_private_name_optional(parent, name, for_delete)?.ok_or(SecurityBrokerError::Changed)
}

fn open_private_name_optional(
    parent: RawHandle,
    name: &[u16],
    for_delete: bool,
) -> SecurityBrokerResult<Option<OwnedHandle>> {
    open_private_name_optional_with_share(parent, name, for_delete, SHARE_WITHOUT_DELETE)
}

fn open_private_name_with_access_and_share(
    parent: RawHandle,
    name: &[u16],
    for_delete: bool,
    extra_access: u32,
    share: u32,
) -> SecurityBrokerResult<OwnedHandle> {
    open_private_name_optional_with_access_and_share(parent, name, for_delete, extra_access, share)?
        .ok_or(SecurityBrokerError::Changed)
}

fn open_private_name_optional_with_share(
    parent: RawHandle,
    name: &[u16],
    for_delete: bool,
    share: u32,
) -> SecurityBrokerResult<Option<OwnedHandle>> {
    open_private_name_optional_with_access_and_share(parent, name, for_delete, 0, share)
}

fn open_private_name_optional_with_access_and_share(
    parent: RawHandle,
    name: &[u16],
    for_delete: bool,
    extra_access: u32,
    share: u32,
) -> SecurityBrokerResult<Option<OwnedHandle>> {
    let length = name
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or(SecurityBrokerError::Invalid)?;
    let unicode = UNICODE_STRING {
        Length: u16::try_from(length).map_err(|_| SecurityBrokerError::Invalid)?,
        MaximumLength: u16::try_from(length).map_err(|_| SecurityBrokerError::Invalid)?,
        Buffer: name.as_ptr().cast_mut(),
    };
    let object = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent,
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: null(),
        SecurityQualityOfService: null(),
    };
    let access = FILE_READ_ATTRIBUTES
        | READ_CONTROL
        | SYNCHRONIZE
        | extra_access
        | if for_delete { DELETE } else { 0 };
    let mut raw = null_mut();
    let mut status: IO_STATUS_BLOCK = unsafe { zeroed() };
    let result = unsafe {
        NtCreateFile(
            &mut raw,
            access,
            &object,
            &mut status,
            null(),
            FILE_ATTRIBUTE_NORMAL,
            share,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE
                | FILE_OPEN_REPARSE_POINT
                | FILE_SYNCHRONOUS_IO_NONALERT
                | FILE_COMPLETE_IF_OPLOCKED,
            null(),
            0,
        )
    };
    if result == STATUS_OPLOCK_BREAK_IN_PROGRESS {
        if !raw.is_null() {
            unsafe { CloseHandle(raw) };
        }
        return Err(SecurityBrokerError::Io(io::ErrorKind::WouldBlock));
    }
    if result == STATUS_OBJECT_NAME_NOT_FOUND || result == STATUS_OBJECT_PATH_NOT_FOUND {
        return Ok(None);
    }
    if result < 0 || raw.is_null() {
        return Err(SecurityBrokerError::Changed);
    }
    Ok(Some(unsafe { OwnedHandle::from_raw_handle(raw) }))
}

fn open_symlink_name(
    parent: RawHandle,
    name: &[u16],
    directory: bool,
    for_delete: bool,
    for_write: bool,
) -> SecurityBrokerResult<OwnedHandle> {
    open_symlink_name_optional(parent, name, directory, for_delete, for_write)?
        .ok_or(SecurityBrokerError::Changed)
}

fn open_symlink_name_optional(
    parent: RawHandle,
    name: &[u16],
    directory: bool,
    for_delete: bool,
    for_write: bool,
) -> SecurityBrokerResult<Option<OwnedHandle>> {
    open_symlink_name_optional_with_share(
        parent,
        name,
        directory,
        for_delete,
        for_write,
        SHARE_WITHOUT_DELETE,
    )
}

fn open_symlink_name_with_share(
    parent: RawHandle,
    name: &[u16],
    directory: bool,
    for_delete: bool,
    for_write: bool,
    share: u32,
) -> SecurityBrokerResult<OwnedHandle> {
    open_symlink_name_optional_with_share(parent, name, directory, for_delete, for_write, share)?
        .ok_or(SecurityBrokerError::Changed)
}

fn open_symlink_name_with_access_and_share(
    parent: RawHandle,
    name: &[u16],
    directory: bool,
    for_delete: bool,
    for_write: bool,
    extra_access: u32,
    share: u32,
) -> SecurityBrokerResult<OwnedHandle> {
    open_symlink_name_optional_with_access_and_share(
        parent,
        name,
        directory,
        for_delete,
        for_write,
        extra_access,
        share,
    )?
    .ok_or(SecurityBrokerError::Changed)
}

fn open_symlink_name_optional_with_share(
    parent: RawHandle,
    name: &[u16],
    directory: bool,
    for_delete: bool,
    for_write: bool,
    share: u32,
) -> SecurityBrokerResult<Option<OwnedHandle>> {
    open_symlink_name_optional_with_access_and_share(
        parent, name, directory, for_delete, for_write, 0, share,
    )
}

fn open_symlink_name_optional_with_access_and_share(
    parent: RawHandle,
    name: &[u16],
    directory: bool,
    for_delete: bool,
    for_write: bool,
    extra_access: u32,
    share: u32,
) -> SecurityBrokerResult<Option<OwnedHandle>> {
    let length = name
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or(SecurityBrokerError::Invalid)?;
    let unicode = UNICODE_STRING {
        Length: u16::try_from(length).map_err(|_| SecurityBrokerError::Invalid)?,
        MaximumLength: u16::try_from(length).map_err(|_| SecurityBrokerError::Invalid)?,
        Buffer: name.as_ptr().cast_mut(),
    };
    let object = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent,
        ObjectName: &unicode,
        // The parent is an already-pinned non-reparse directory. Permit the
        // final entry itself to be opened with FILE_OPEN_REPARSE_POINT.
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: null(),
        SecurityQualityOfService: null(),
    };
    let mut access = FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
    access |= extra_access;
    if for_delete {
        access |= DELETE;
    }
    if for_write {
        access |= FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES;
    }
    if directory {
        access |= FILE_LIST_DIRECTORY;
    }
    let options = if directory {
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT
    } else {
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT
    };
    let mut raw = null_mut();
    let mut status: IO_STATUS_BLOCK = unsafe { zeroed() };
    let result = unsafe {
        NtCreateFile(
            &mut raw,
            access,
            &object,
            &mut status,
            null(),
            FILE_ATTRIBUTE_NORMAL,
            share,
            FILE_OPEN,
            options | FILE_COMPLETE_IF_OPLOCKED,
            null(),
            0,
        )
    };
    if result == STATUS_OPLOCK_BREAK_IN_PROGRESS {
        if !raw.is_null() {
            unsafe { CloseHandle(raw) };
        }
        return Err(SecurityBrokerError::Io(io::ErrorKind::WouldBlock));
    }
    if result == STATUS_OBJECT_NAME_NOT_FOUND || result == STATUS_OBJECT_PATH_NOT_FOUND {
        return Ok(None);
    }
    if result < 0 || raw.is_null() {
        return Err(SecurityBrokerError::Changed);
    }
    Ok(Some(unsafe { OwnedHandle::from_raw_handle(raw) }))
}

fn delete_open_file(handle: RawHandle) -> SecurityBrokerResult<()> {
    let disposition = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
    let mut status: IO_STATUS_BLOCK = unsafe { zeroed() };
    let result = unsafe {
        NtSetInformationFile(
            handle,
            &mut status,
            (&disposition as *const FILE_DISPOSITION_INFORMATION)
                .cast_mut()
                .cast(),
            size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
            FileDispositionInformation,
        )
    };
    if result < 0 {
        return Err(SecurityBrokerError::Unsupported);
    }
    Ok(())
}

fn ensure_pending_symlink_temp(
    handle: RawHandle,
    info: &super::Info,
    identity: Ident,
    directory: bool,
    expected_reparse: Option<&[u8]>,
) -> SecurityBrokerResult<()> {
    let expected_kind = if directory {
        super::Kind::Directory
    } else {
        super::Kind::File
    };
    if info.ident != identity || info.nlink != 1 {
        return Err(SecurityBrokerError::Changed);
    }
    validate_disk_file(handle)?;
    if info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        // During a failed set acknowledgement the operation may have reached
        // the filesystem. Accept only the exact requested payload for cleanup.
        let Some(expected) = expected_reparse else {
            return Err(SecurityBrokerError::Changed);
        };
        if super::kind_of(info) != super::Kind::Symlink
            || (info.attributes & super::FILE_ATTRIBUTE_DIRECTORY != 0) != directory
            || read_symlink_reparse_buffer(handle)? != expected
        {
            return Err(SecurityBrokerError::Changed);
        }
    } else if super::kind_of(info) != expected_kind {
        return Err(SecurityBrokerError::Changed);
    }
    Ok(())
}

fn ensure_symlink_temp(
    handle: RawHandle,
    info: &super::Info,
    identity: Ident,
    directory: bool,
    expected_reparse: &[u8],
) -> SecurityBrokerResult<()> {
    ensure_symlink_object(handle, info, identity, directory, expected_reparse)?;
    validate_disk_file(handle)?;
    if !directory {
        super::native_default_stream_only(handle).map_err(SecurityBrokerError::from)?;
    }
    Ok(())
}

fn ensure_symlink_object(
    handle: RawHandle,
    info: &super::Info,
    identity: Ident,
    directory: bool,
    expected_reparse: &[u8],
) -> SecurityBrokerResult<()> {
    let directory_bit = info.attributes & super::FILE_ATTRIBUTE_DIRECTORY != 0;
    if info.ident != identity
        || info.nlink != 1
        || super::kind_of(info) != super::Kind::Symlink
        || directory_bit != directory
        || info.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
    {
        return Err(SecurityBrokerError::Changed);
    }
    if read_symlink_reparse_buffer(handle)? != expected_reparse {
        return Err(SecurityBrokerError::Changed);
    }
    Ok(())
}

fn build_symlink_reparse_buffer(
    substitute: &[u16],
    print: &[u16],
    relative: bool,
) -> SecurityBrokerResult<Vec<u8>> {
    for value in [substitute, print] {
        if value.is_empty() || value.contains(&0) || String::from_utf16(value).is_err() {
            return Err(SecurityBrokerError::Invalid);
        }
    }
    let substitute_bytes = substitute
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or(SecurityBrokerError::Limit)?;
    let print_bytes = print
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or(SecurityBrokerError::Limit)?;
    let path_bytes = substitute_bytes
        .checked_add(print_bytes)
        .ok_or(SecurityBrokerError::Limit)?;
    let reparse_data_len = 12usize
        .checked_add(path_bytes)
        .ok_or(SecurityBrokerError::Limit)?;
    let total = 8usize
        .checked_add(reparse_data_len)
        .ok_or(SecurityBrokerError::Limit)?;
    if total > MAX_REPARSE_BUFFER
        || reparse_data_len > u16::MAX as usize
        || substitute_bytes > u16::MAX as usize
        || print_bytes > u16::MAX as usize
    {
        return Err(SecurityBrokerError::Limit);
    }
    let mut output = Vec::with_capacity(total);
    output.extend_from_slice(&IO_REPARSE_TAG_SYMLINK.to_le_bytes());
    output.extend_from_slice(&(reparse_data_len as u16).to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&(substitute_bytes as u16).to_le_bytes());
    output.extend_from_slice(&(substitute_bytes as u16).to_le_bytes());
    output.extend_from_slice(&(print_bytes as u16).to_le_bytes());
    output.extend_from_slice(&(if relative { SYMLINK_FLAG_RELATIVE } else { 0 }).to_le_bytes());
    output.extend_from_slice(&utf16_bytes(substitute)?);
    output.extend_from_slice(&utf16_bytes(print)?);
    if output.len() != total {
        return Err(SecurityBrokerError::Invalid);
    }
    Ok(output)
}

pub(super) fn read_symlink_reparse_buffer(handle: RawHandle) -> SecurityBrokerResult<Vec<u8>> {
    let mut output = vec![0u8; MAX_REPARSE_BUFFER];
    let mut returned = 0u32;
    if unsafe {
        DeviceIoControl(
            handle,
            FSCTL_GET_REPARSE_POINT,
            null(),
            0,
            output.as_mut_ptr().cast(),
            output.len() as u32,
            &mut returned,
            null_mut(),
        )
    } == 0
    {
        return Err(if unsafe { GetLastError() } == ERROR_MORE_DATA {
            SecurityBrokerError::Limit
        } else {
            last_io_error()
        });
    }
    let returned = returned as usize;
    if !(20..=MAX_REPARSE_BUFFER).contains(&returned)
        || u32::from_le_bytes(output[0..4].try_into().unwrap()) != IO_REPARSE_TAG_SYMLINK
        || usize::from(u16::from_le_bytes(output[4..6].try_into().unwrap())) + 8 != returned
        || u16::from_le_bytes(output[6..8].try_into().unwrap()) != 0
    {
        return Err(SecurityBrokerError::Changed);
    }
    output.truncate(returned);
    Ok(output)
}

fn set_symlink_reparse_buffer(handle: RawHandle, buffer: &[u8]) -> SecurityBrokerResult<()> {
    if buffer.len() < 20 || buffer.len() > MAX_REPARSE_BUFFER {
        return Err(SecurityBrokerError::Limit);
    }
    let mut returned = 0u32;
    if unsafe {
        DeviceIoControl(
            handle,
            FSCTL_SET_REPARSE_POINT,
            buffer.as_ptr().cast(),
            u32::try_from(buffer.len()).map_err(|_| SecurityBrokerError::Limit)?,
            null_mut(),
            0,
            &mut returned,
            null_mut(),
        )
    } == 0
    {
        return Err(last_io_error());
    }
    Ok(())
}

fn utf16_bytes(value: &[u16]) -> SecurityBrokerResult<Vec<u8>> {
    let byte_len = value
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or(SecurityBrokerError::Limit)?;
    let mut bytes = Vec::with_capacity(byte_len);
    for unit in value {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(bytes)
}

fn decode_utf16(bytes: &[u8]) -> SecurityBrokerResult<Vec<u16>> {
    if bytes.len() % size_of::<u16>() != 0 {
        return Err(SecurityBrokerError::Invalid);
    }
    let value = bytes
        .chunks_exact(size_of::<u16>())
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    if String::from_utf16(&value).is_err() || value.contains(&0) {
        return Err(SecurityBrokerError::Invalid);
    }
    Ok(value)
}

struct SystemSymlinkPrivilegeScope {
    _token: OwnedHandle,
    active: bool,
}

impl SystemSymlinkPrivilegeScope {
    fn install() -> SecurityBrokerResult<Self> {
        ensure_no_thread_token()?;
        let mut process_raw = null_mut();
        if unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &mut process_raw,
            )
        } == 0
            || process_raw.is_null()
        {
            return Err(SecurityBrokerError::Unsupported);
        }
        let process_token = unsafe { OwnedHandle::from_raw_handle(process_raw) };
        let mut duplicate_raw = null_mut();
        if unsafe {
            DuplicateTokenEx(
                process_token.as_raw_handle(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE | TOKEN_QUERY,
                null(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut duplicate_raw,
            )
        } == 0
            || duplicate_raw.is_null()
        {
            return Err(SecurityBrokerError::Unsupported);
        }
        let token = unsafe { OwnedHandle::from_raw_handle(duplicate_raw) };
        let mut luid = unsafe { zeroed() };
        if unsafe { LookupPrivilegeValueW(null(), SE_CREATE_SYMBOLIC_LINK_NAME, &mut luid) } == 0 {
            return Err(SecurityBrokerError::Unsupported);
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
                token.as_raw_handle(),
                0,
                &privileges,
                0,
                null_mut(),
                null_mut(),
            )
        };
        let adjust_error = unsafe { GetLastError() };
        if adjusted == 0 || adjust_error == ERROR_NOT_ALL_ASSIGNED || adjust_error != 0 {
            return Err(SecurityBrokerError::Unsupported);
        }
        if unsafe { SetThreadToken(null(), token.as_raw_handle()) } == 0 {
            return Err(SecurityBrokerError::Unsupported);
        }
        Ok(Self {
            _token: token,
            active: true,
        })
    }

    fn restore(&mut self) {
        if !self.active {
            return;
        }
        if unsafe { SetThreadToken(null(), null_mut()) } == 0 {
            std::process::abort();
        }
        self.active = false;
    }
}

impl Drop for SystemSymlinkPrivilegeScope {
    fn drop(&mut self) {
        self.restore();
    }
}

fn with_system_symlink_privilege<T>(
    operation: impl FnOnce() -> SecurityBrokerResult<T>,
) -> SecurityBrokerResult<T> {
    let mut scope = SystemSymlinkPrivilegeScope::install()?;
    let result = operation();
    scope.restore();
    result
}

fn with_user_token<T>(
    token: RawHandle,
    operation: impl FnOnce() -> SecurityBrokerResult<T>,
) -> SecurityBrokerResult<T> {
    ensure_no_thread_token()?;
    if unsafe { SetThreadToken(null(), token) } == 0 {
        return Err(last_io_error());
    }
    let result = operation();
    if unsafe { SetThreadToken(null(), null_mut()) } == 0 {
        std::process::abort();
    }
    result
}

fn ensure_no_thread_token() -> SecurityBrokerResult<()> {
    let mut token = null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } != 0 {
        if !token.is_null() {
            unsafe { CloseHandle(token) };
        }
        return Err(SecurityBrokerError::Unsupported);
    }
    if unsafe { GetLastError() } != ERROR_NO_TOKEN {
        return Err(last_io_error());
    }
    Ok(())
}

fn unique_id(existing: impl Iterator<Item = [u8; 16]>) -> [u8; 16] {
    let existing: Vec<_> = existing.collect();
    loop {
        let id = Uuid::new_v4().into_bytes();
        if !existing.contains(&id) {
            return id;
        }
    }
}

fn valid_temp_name(name: &str) -> bool {
    let Some(id) = name
        .strip_prefix("lomi-temp-")
        .and_then(|rest| rest.strip_suffix(".tmp"))
    else {
        return false;
    };
    id.len() == 36
        && id.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn valid_broker_temp_name(name: &str) -> bool {
    valid_temp_name(name) || valid_git_lock_name(name)
}

fn valid_broker_symlink_temp_name(name: &str) -> bool {
    let Some(id) = name
        .strip_prefix("lomi-link-")
        .and_then(|rest| rest.strip_suffix(".tmp"))
    else {
        return false;
    };
    id.len() == 36
        && id.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn valid_git_lock_name(name: &str) -> bool {
    if name.len() > 255 || !name.is_ascii() || !name.ends_with(".lock") {
        return false;
    }
    let Some(stem) = name.strip_suffix(".lock") else {
        return false;
    };
    if stem.is_empty()
        || name == "."
        || name == ".."
        || name.ends_with('.')
        || name.ends_with(' ')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return false;
    }
    let device_stem = stem.split('.').next().unwrap_or(stem).to_ascii_uppercase();
    !matches!(
        device_stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) && !(device_stem.len() == 4
        && (device_stem.starts_with("COM") || device_stem.starts_with("LPT"))
        && matches!(device_stem.as_bytes()[3], b'1'..=b'9'))
}

fn handle_to_wire(handle: RawHandle) -> SecurityBrokerResult<u64> {
    let value = handle as usize;
    u64::try_from(value).map_err(|_| SecurityBrokerError::Invalid)
}

fn wire_to_handle(value: u64) -> SecurityBrokerResult<RawHandle> {
    let value = usize::try_from(value).map_err(|_| SecurityBrokerError::Invalid)?;
    Ok(value as RawHandle)
}
