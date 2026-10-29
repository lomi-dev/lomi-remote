//! A closed macOS capability for invoking the signed Desktop native-evidence
//! entry point. The process path is derived from an authenticated local socket
//! peer and is never supplied by a caller.
#![cfg(target_os = "macos")]

use crate::unix::PrivateProfile;
use core_foundation::{
    base::{CFType, TCFType},
    data::{CFData, CFDataRef},
    dictionary::{CFDictionary, CFDictionaryRef},
    string::{CFString, CFStringRef},
    url::CFURL,
};
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement, SecStaticCode,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::{CStr, CString},
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::fd::{AsRawFd, FromRawFd, RawFd},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    os::unix::net::UnixStream,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use uuid::Uuid;

const DESKTOP_IDENTIFIER: &str = "dev.lomi.desktop";
const HELPER_ARGUMENT: &str = "--internal-native-evidence";
const MAX_FRAME_BYTES: usize = 128 * 1024;
const MAX_MANIFEST_BYTES: u64 = 16 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SNAPSHOT_COUNT: usize = 32;
const MAX_SNAPSHOT_CACHE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const READ_CHUNK_BYTES: usize = 64 * 1024;
const HELPER_FILE_MODE: u32 = 0o500;
const STRICT_FLAGS: Flags = Flags::STRICT_VALIDATE.union(Flags::CHECK_ALL_ARCHITECTURES);
static NEVER_CANCELLED: AtomicBool = AtomicBool::new(false);
static SNAPSHOT_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeEvidenceMode {
    Capture,
    Verify,
}

impl NativeEvidenceMode {
    const fn argument(self) -> &'static str {
        match self {
            Self::Capture => "capture",
            Self::Verify => "verify",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeEvidenceRuntimeError {
    Unsupported,
    InvalidRequest,
    Deadline,
    Unavailable,
}

impl std::fmt::Display for NativeEvidenceRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "trusted native evidence helper is unavailable",
            Self::InvalidRequest => "invalid native evidence helper request",
            Self::Deadline => "native evidence helper deadline elapsed",
            Self::Unavailable => "native evidence helper failed",
        })
    }
}

impl std::error::Error for NativeEvidenceRuntimeError {}

fn check_capture_liveness(
    deadline: Option<Instant>,
    cancelled: &AtomicBool,
) -> Result<(), NativeEvidenceRuntimeError> {
    if cancelled.load(Ordering::Acquire) {
        return Err(NativeEvidenceRuntimeError::Unavailable);
    }
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err(NativeEvidenceRuntimeError::Deadline);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CodeIdentity {
    identifier: String,
    team_identifier: String,
    code_directory_hash: Vec<u8>,
}

#[derive(Clone, Debug)]
struct SigningInformation {
    identity: CodeIdentity,
    main_executable: PathBuf,
}

/// A private, verified snapshot of the installed Desktop executable. The
/// fields are private so callers cannot replace the executable or arguments.
pub struct TrustedNativeRuntime {
    profile: PrivateProfile,
    executable_path: PathBuf,
    executable_name: CString,
    executable_hash: [u8; 32],
    executable_identity: FileIdentity,
    code_identity: CodeIdentity,
}

/// Persistable, closed description of one validated helper snapshot. It carries
/// no caller-selected path: restore accepts only the content-addressed private
/// profile filename and rechecks its identity, hash, Team ID and code signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedNativeRuntimeDescriptor {
    schema: u8,
    abi: u8,
    executable_name: String,
    executable_sha256: String,
    executable_identity: FileIdentity,
    code_identity: CodeIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeCapabilities {
    format: u8,
    #[serde(rename = "nativeEvidence")]
    native_evidence: RuntimeCapability,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeCapability {
    abi: u8,
    max_input_bytes: usize,
    max_output_bytes: usize,
}

/// Establish a native helper capability from the peer of an already accepted
/// macOS local IPC stream. Unsigned, ad-hoc, wrong-team, or ABI-less Desktop
/// builds are unsupported; there is no path or executable override.
pub fn capture_trusted_native_runtime(
    profile: &Path,
    accepted_stream: &std::os::unix::net::UnixStream,
) -> Result<TrustedNativeRuntime, NativeEvidenceRuntimeError> {
    capture_trusted_native_runtime_inner(profile, accepted_stream, None, &NEVER_CANCELLED)
}

/// Deadline- and cancellation-aware form used by the host request path. The
/// same original operation deadline continues through snapshotting and helper
/// execution; no capture-local timeout is added.
pub fn capture_trusted_native_runtime_with_cancellation(
    profile: &Path,
    accepted_stream: &std::os::unix::net::UnixStream,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<TrustedNativeRuntime, NativeEvidenceRuntimeError> {
    capture_trusted_native_runtime_inner(profile, accepted_stream, Some(deadline), cancelled)
}

fn capture_trusted_native_runtime_inner(
    profile: &Path,
    accepted_stream: &std::os::unix::net::UnixStream,
    deadline: Option<Instant>,
    cancelled: &AtomicBool,
) -> Result<TrustedNativeRuntime, NativeEvidenceRuntimeError> {
    check_capture_liveness(deadline, cancelled)?;
    let profile = PrivateProfile::open(profile, false)
        .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
    profile
        .check_current()
        .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;

    let audit_token = peer_audit_token(accepted_stream)?;
    check_capture_liveness(deadline, cancelled)?;
    let audit_bytes = unsafe {
        std::slice::from_raw_parts(
            (&audit_token as *const AuditToken).cast::<u8>(),
            std::mem::size_of::<AuditToken>(),
        )
    };
    let token_data = CFData::from_buffer(audit_bytes);
    let mut attributes = GuestAttributes::new();
    attributes.set_audit_token(token_data.as_concrete_TypeRef());
    let guest = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;

    let apple_requirement: SecRequirement = "anchor apple generic"
        .parse()
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    let self_code =
        SecCode::for_self(Flags::NONE).map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    self_code
        .check_validity(STRICT_FLAGS, &apple_requirement)
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    let self_info = signing_information(self_code.as_CFTypeRef().cast())?;
    require_team(&self_info.identity.team_identifier)?;
    check_capture_liveness(deadline, cancelled)?;

    guest
        .check_validity(STRICT_FLAGS, &apple_requirement)
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    let peer_info = signing_information(guest.as_CFTypeRef().cast())?;
    check_capture_liveness(deadline, cancelled)?;
    if peer_info.identity.identifier != DESKTOP_IDENTIFIER
        || peer_info.identity.team_identifier != self_info.identity.team_identifier
    {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }
    require_team(&peer_info.identity.team_identifier)?;
    let requirement = peer_requirement(&peer_info.identity.team_identifier)?;
    guest
        .check_validity(STRICT_FLAGS, &requirement)
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;

    let bundle_path = guest
        .path(Flags::NONE)
        .ok()
        .and_then(|url| url.to_path())
        .ok_or(NativeEvidenceRuntimeError::Unsupported)?;
    if !bundle_path.is_absolute()
        || bundle_path
            .extension()
            .is_none_or(|extension| extension != "app")
        || bundle_path.canonicalize().ok().as_deref() != Some(bundle_path.as_path())
    {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }
    let bundle_url =
        CFURL::from_path(&bundle_path, true).ok_or(NativeEvidenceRuntimeError::Unsupported)?;
    let bundle = SecStaticCode::from_path(&bundle_url, Flags::NONE)
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    bundle
        .check_validity(STRICT_FLAGS, &requirement)
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    let bundle_info = signing_information(bundle.as_CFTypeRef().cast())?;
    if bundle_info.identity != peer_info.identity {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }

    validate_capability_manifest(&bundle, &bundle_path)?;
    check_capture_liveness(deadline, cancelled)?;

    let executable_path = peer_info.main_executable;
    let expected_macos_dir = bundle_path.join("Contents/MacOS");
    if executable_path.parent() != Some(expected_macos_dir.as_path())
        || executable_path.canonicalize().ok().as_deref() != Some(executable_path.as_path())
    {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }
    let executable_url =
        CFURL::from_path(&executable_path, false).ok_or(NativeEvidenceRuntimeError::Unsupported)?;
    let executable_code = SecStaticCode::from_path(&executable_url, Flags::NONE)
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    executable_code
        .check_validity(STRICT_FLAGS, &requirement)
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    let executable_signing = signing_information(executable_code.as_CFTypeRef().cast())?;
    check_capture_liveness(deadline, cancelled)?;
    if executable_signing.identity != peer_info.identity
        || executable_signing.main_executable != executable_path
    {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }

    let (executable_name, executable_hash, executable_identity) = snapshot_executable(
        &profile,
        &executable_path,
        &requirement,
        &peer_info.identity,
        deadline,
        cancelled,
    )?;
    let executable_path = profile.path().join(
        executable_name
            .to_str()
            .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?,
    );
    profile
        .check_current()
        .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
    check_capture_liveness(deadline, cancelled)?;

    Ok(TrustedNativeRuntime {
        profile,
        executable_path,
        executable_name,
        executable_hash,
        executable_identity,
        code_identity: peer_info.identity,
    })
}

/// Restore a capability from host-owned durable metadata. This never reads an
/// executable path from the descriptor; the filename is reconstructed and
/// validated from its SHA-256 before any launch is possible.
pub fn restore_trusted_native_runtime(
    profile: &Path,
    descriptor_json: &str,
) -> Result<TrustedNativeRuntime, NativeEvidenceRuntimeError> {
    if descriptor_json.len() > 16 * 1024 {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }
    let descriptor: TrustedNativeRuntimeDescriptor = serde_json::from_str(descriptor_json)
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    if descriptor.schema != 1
        || descriptor.abi != 1
        || descriptor.code_identity.identifier != DESKTOP_IDENTIFIER
        || !valid_lower_hex(&descriptor.executable_sha256, 32)
        || !valid_lower_hex_bytes(&descriptor.code_identity.code_directory_hash)
    {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }
    require_team(&descriptor.code_identity.team_identifier)?;
    let expected_name = format!(
        "native-evidence-helper-{}.bin",
        descriptor.executable_sha256
    );
    if descriptor.executable_name != expected_name {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }
    let executable_name = CString::new(descriptor.executable_name.as_bytes())
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    let profile = PrivateProfile::open(profile, false)
        .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
    profile
        .check_current()
        .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;

    let apple_requirement: SecRequirement = "anchor apple generic"
        .parse()
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    let self_code =
        SecCode::for_self(Flags::NONE).map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    self_code
        .check_validity(STRICT_FLAGS, &apple_requirement)
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    let self_info = signing_information(self_code.as_CFTypeRef().cast())?;
    require_team(&self_info.identity.team_identifier)?;
    if self_info.identity.team_identifier != descriptor.code_identity.team_identifier {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }

    let executable_path = profile.path().join(&descriptor.executable_name);
    let snapshot = open_profile_file(&profile, &executable_name, libc::O_RDONLY)
        .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
    validate_snapshot_file(&snapshot, descriptor.executable_identity)?;
    if hex(&hash_file(&snapshot, MAX_EXECUTABLE_BYTES)?) != descriptor.executable_sha256 {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }
    let url =
        CFURL::from_path(&executable_path, false).ok_or(NativeEvidenceRuntimeError::Unsupported)?;
    let code = SecStaticCode::from_path(&url, Flags::NONE)
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    let requirement = peer_requirement(&descriptor.code_identity.team_identifier)?;
    code.check_validity(STRICT_FLAGS, &requirement)
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    let info = signing_information(code.as_CFTypeRef().cast())?;
    if info.identity != descriptor.code_identity || info.main_executable != executable_path {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }
    profile
        .check_current()
        .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;

    Ok(TrustedNativeRuntime {
        profile,
        executable_path,
        executable_name,
        executable_hash: decode_lower_hex_32(&descriptor.executable_sha256)
            .ok_or(NativeEvidenceRuntimeError::Unsupported)?,
        executable_identity: descriptor.executable_identity,
        code_identity: descriptor.code_identity,
    })
}

impl TrustedNativeRuntime {
    pub fn descriptor_json(&self) -> Result<String, NativeEvidenceRuntimeError> {
        let descriptor = TrustedNativeRuntimeDescriptor {
            schema: 1,
            abi: 1,
            executable_name: self
                .executable_name
                .to_str()
                .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?
                .to_owned(),
            executable_sha256: hex(&self.executable_hash),
            executable_identity: self.executable_identity,
            code_identity: self.code_identity.clone(),
        };
        serde_json::to_string(&descriptor).map_err(|_| NativeEvidenceRuntimeError::Unavailable)
    }

    /// Run only the fixed Capture or Verify entry, with bounded JSON pipes and
    /// the caller's absolute monotonic deadline. The caller must keep the host
    /// profile OwnerLock alive until this method returns.
    pub fn run(
        &self,
        mode: NativeEvidenceMode,
        input_json: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, NativeEvidenceRuntimeError> {
        self.run_with_cancellation(mode, input_json, deadline, &NEVER_CANCELLED)
    }

    /// As `run`, while also observing the host's original cancellation latch.
    /// Cancellation kills and reaps the private child before returning.
    pub fn run_with_cancellation(
        &self,
        mode: NativeEvidenceMode,
        input_json: &[u8],
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Vec<u8>, NativeEvidenceRuntimeError> {
        if input_json.len() > MAX_FRAME_BYTES
            || serde_json::from_slice::<serde_json::Value>(input_json).is_err()
        {
            return Err(NativeEvidenceRuntimeError::InvalidRequest);
        }
        if cancelled.load(Ordering::Acquire) {
            return Err(NativeEvidenceRuntimeError::Unavailable);
        }
        if Instant::now() >= deadline {
            return Err(NativeEvidenceRuntimeError::Deadline);
        }
        crate::process::require_child_ownership()
            .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
        self.profile
            .check_current()
            .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
        self.verify_snapshot(deadline, cancelled)?;
        // Signature and content verification may hash a large executable. The
        // original operation deadline still governs launch; validation time
        // must not extend the caller's authority window.
        if cancelled.load(Ordering::Acquire) {
            return Err(NativeEvidenceRuntimeError::Unavailable);
        }
        if Instant::now() >= deadline {
            return Err(NativeEvidenceRuntimeError::Deadline);
        }

        let (lifetime_reader, lifetime_writer) = lifetime_socketpair()?;
        let lifetime_fd = lifetime_reader.as_raw_fd();
        let mut command = Command::new(&self.executable_path);
        command
            .arg(HELPER_ARGUMENT)
            .arg(mode.argument())
            .env_clear()
            .env("HOME", self.profile.path())
            .env("TMPDIR", self.profile.path())
            .env("LC_ALL", "C")
            .current_dir(self.profile.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // FD 3 is the private parent-lifetime socket required by ABI 1. The
        // parent end is CLOEXEC and is retained in OwnedHelperChild until the
        // child has been waited; no message is sent over this channel.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(lifetime_fd, 3) < 0 {
                    return Err(io::Error::last_os_error());
                }
                let flags = libc::fcntl(3, libc::F_GETFD);
                if flags < 0 || libc::fcntl(3, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command
            .spawn()
            .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
        drop(lifetime_reader);
        let mut owned = OwnedHelperChild {
            child,
            _lifetime_writer: lifetime_writer,
            reaped: false,
        };

        let result = drive_child(&mut owned.child, input_json, deadline, cancelled);
        if result.is_err() {
            owned.terminate();
        } else {
            owned.wait()?;
        }
        result
    }

    fn verify_snapshot(
        &self,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<(), NativeEvidenceRuntimeError> {
        self.profile
            .check_current()
            .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
        let file = open_profile_file(&self.profile, &self.executable_name, libc::O_RDONLY)
            .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
        validate_snapshot_file(&file, self.executable_identity)?;
        let actual_hash =
            hash_file_checked(&file, MAX_EXECUTABLE_BYTES, Some(deadline), cancelled)?;
        if actual_hash != self.executable_hash {
            return Err(NativeEvidenceRuntimeError::Unsupported);
        }
        let url = CFURL::from_path(&self.executable_path, false)
            .ok_or(NativeEvidenceRuntimeError::Unsupported)?;
        let code = SecStaticCode::from_path(&url, Flags::NONE)
            .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
        let requirement = peer_requirement(&self.code_identity.team_identifier)?;
        code.check_validity(STRICT_FLAGS, &requirement)
            .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
        let info = signing_information(code.as_CFTypeRef().cast())?;
        if info.identity != self.code_identity || info.main_executable != self.executable_path {
            return Err(NativeEvidenceRuntimeError::Unsupported);
        }
        let after = open_profile_file(&self.profile, &self.executable_name, libc::O_RDONLY)
            .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
        validate_snapshot_file(&after, self.executable_identity)
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
struct AuditToken {
    value: [u32; 8],
}

fn peer_audit_token(
    stream: &std::os::unix::net::UnixStream,
) -> Result<AuditToken, NativeEvidenceRuntimeError> {
    let mut token = AuditToken { value: [0; 8] };
    let mut length = std::mem::size_of::<AuditToken>() as libc::socklen_t;
    // SOL_LOCAL/LOCAL_PEERTOKEN from the macOS sys/un.h SDK header.
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            (&mut token as *mut AuditToken).cast(),
            &mut length,
        )
    };
    if status != 0 || length as usize != std::mem::size_of::<AuditToken>() {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }
    let mut peer_pid: libc::pid_t = 0;
    let mut pid_length = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let pid_status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut peer_pid as *mut libc::pid_t).cast(),
            &mut pid_length,
        )
    };
    if pid_status != 0
        || pid_length as usize != std::mem::size_of::<libc::pid_t>()
        || peer_pid <= 0
        || unsafe { audit_token_to_pid(token) } != peer_pid
    {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }
    Ok(token)
}

fn signing_information(
    code: *const std::ffi::c_void,
) -> Result<SigningInformation, NativeEvidenceRuntimeError> {
    let mut raw: CFDictionaryRef = std::ptr::null();
    let status =
        unsafe { SecCodeCopySigningInformation(code, SEC_CS_SIGNING_INFORMATION, &mut raw) };
    if status != 0 || raw.is_null() {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }
    let dictionary: CFDictionary<*const std::ffi::c_void, CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(raw) };
    let identifier = string_value(&dictionary, unsafe { kSecCodeInfoIdentifier })
        .ok_or(NativeEvidenceRuntimeError::Unsupported)?;
    let team_identifier = string_value(&dictionary, unsafe { kSecCodeInfoTeamIdentifier })
        .ok_or(NativeEvidenceRuntimeError::Unsupported)?;
    let code_directory_hash = data_value(&dictionary, unsafe { kSecCodeInfoUnique })
        .filter(|hash| !hash.is_empty())
        .ok_or(NativeEvidenceRuntimeError::Unsupported)?;
    let main_executable = url_value(&dictionary, unsafe { kSecCodeInfoMainExecutable })
        .and_then(|url| url.to_path())
        .ok_or(NativeEvidenceRuntimeError::Unsupported)?;
    Ok(SigningInformation {
        identity: CodeIdentity {
            identifier,
            team_identifier,
            code_directory_hash,
        },
        main_executable,
    })
}

fn string_value(
    dictionary: &CFDictionary<*const std::ffi::c_void, CFType>,
    key: CFStringRef,
) -> Option<String> {
    let key = unsafe { CFType::wrap_under_get_rule(key.cast()) };
    dictionary
        .find(key.as_CFTypeRef())?
        .downcast::<CFString>()
        .map(|value| value.to_string())
}

fn data_value(
    dictionary: &CFDictionary<*const std::ffi::c_void, CFType>,
    key: CFStringRef,
) -> Option<Vec<u8>> {
    let key = unsafe { CFType::wrap_under_get_rule(key.cast()) };
    dictionary
        .find(key.as_CFTypeRef())?
        .downcast::<CFData>()
        .map(|value| value.bytes().to_vec())
}

fn url_value(
    dictionary: &CFDictionary<*const std::ffi::c_void, CFType>,
    key: CFStringRef,
) -> Option<CFURL> {
    let key = unsafe { CFType::wrap_under_get_rule(key.cast()) };
    dictionary.find(key.as_CFTypeRef())?.downcast::<CFURL>()
}

fn require_team(team: &str) -> Result<(), NativeEvidenceRuntimeError> {
    if team.is_empty() || team.len() > 128 || !team.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(NativeEvidenceRuntimeError::Unsupported);
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

fn valid_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes.saturating_mul(2)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_lower_hex_bytes(value: &[u8]) -> bool {
    matches!(value.len(), 20 | 32)
}

fn decode_lower_hex_32(value: &str) -> Option<[u8; 32]> {
    if !valid_lower_hex(value, 32) {
        return None;
    }
    let mut decoded = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char).to_digit(16)? as u8;
        let low = (pair[1] as char).to_digit(16)? as u8;
        decoded[index] = (high << 4) | low;
    }
    Some(decoded)
}

fn peer_requirement(team: &str) -> Result<SecRequirement, NativeEvidenceRuntimeError> {
    require_team(team)?;
    format!(
        "identifier \"{DESKTOP_IDENTIFIER}\" and anchor apple generic and certificate leaf[subject.OU] = \"{team}\""
    )
    .parse()
    .map_err(|_| NativeEvidenceRuntimeError::Unsupported)
}

fn validate_capability_manifest(
    bundle: &SecStaticCode,
    bundle_path: &Path,
) -> Result<(), NativeEvidenceRuntimeError> {
    let resource = bundle_path.join("Contents/Resources/native-runtime-capabilities.json");
    let bytes = read_bounded_nofollow(&resource, MAX_MANIFEST_BYTES)?;
    let relative = CFString::from_static_string("Resources/native-runtime-capabilities.json");
    let data = CFData::from_buffer(&bytes);
    let status = unsafe {
        SecCodeValidateFileResource(
            bundle.as_CFTypeRef().cast(),
            relative.as_concrete_TypeRef(),
            data.as_concrete_TypeRef(),
            0,
        )
    };
    if status != 0 {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }
    let manifest: RuntimeCapabilities =
        serde_json::from_slice(&bytes).map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    if manifest.format != 1
        || manifest.native_evidence.abi != 1
        || manifest.native_evidence.max_input_bytes != MAX_FRAME_BYTES
        || manifest.native_evidence.max_output_bytes != MAX_FRAME_BYTES
    {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }
    Ok(())
}

fn read_bounded_nofollow(path: &Path, maximum: u64) -> Result<Vec<u8>, NativeEvidenceRuntimeError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    let metadata = file
        .metadata()
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }
    let capacity =
        usize::try_from(metadata.len()).map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > maximum {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }
    Ok(bytes)
}

fn snapshot_executable(
    profile: &PrivateProfile,
    source_path: &Path,
    requirement: &SecRequirement,
    expected_code: &CodeIdentity,
    deadline: Option<Instant>,
    cancelled: &AtomicBool,
) -> Result<(CString, [u8; 32], FileIdentity), NativeEvidenceRuntimeError> {
    check_capture_liveness(deadline, cancelled)?;
    let _snapshot_guard = SNAPSHOT_LOCK
        .try_lock()
        .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
    profile
        .check_current()
        .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
    let mut source_options = OpenOptions::new();
    source_options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let mut source = source_options
        .open(source_path)
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    let source_metadata = source
        .metadata()
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    if !source_metadata.is_file()
        || source_metadata.len() == 0
        || source_metadata.len() > MAX_EXECUTABLE_BYTES
        || source_metadata.mode() & 0o111 == 0
    {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }

    let digest = hash_file_checked(&source, MAX_EXECUTABLE_BYTES, deadline, cancelled)?;
    check_capture_liveness(deadline, cancelled)?;
    let source_after_hash = source
        .metadata()
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    if !same_file_version(&source_metadata, &source_after_hash) {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }
    let digest_hex = hex(&digest);
    let executable_name = CString::new(format!("native-evidence-helper-{digest_hex}.bin"))
        .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
    let executable_name_text = executable_name
        .to_str()
        .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?
        .to_owned();
    let snapshot_path = profile.path().join(&executable_name_text);

    match open_profile_file(profile, &executable_name, libc::O_RDONLY) {
        Ok(snapshot) => {
            let metadata = snapshot
                .metadata()
                .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
            let identity = FileIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
                size: metadata.len(),
            };
            validate_snapshot_file(&snapshot, identity)?;
            if identity.size != source_metadata.len()
                || hash_file_checked(&snapshot, MAX_EXECUTABLE_BYTES, deadline, cancelled)?
                    != digest
            {
                return Err(NativeEvidenceRuntimeError::Unsupported);
            }
            validate_signed_snapshot(&snapshot_path, requirement, expected_code)?;
            return Ok((executable_name, digest, identity));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(NativeEvidenceRuntimeError::Unsupported),
    }
    check_snapshot_cache_capacity(profile, source_metadata.len(), deadline, cancelled)?;
    check_capture_liveness(deadline, cancelled)?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;

    let temp_name = CString::new(format!("native-evidence-{}.tmp", Uuid::new_v4()))
        .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
    let temp_fd = unsafe {
        libc::openat(
            profile.directory().as_raw_fd(),
            temp_name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o700,
        )
    };
    if temp_fd < 0 {
        return Err(NativeEvidenceRuntimeError::Unavailable);
    }
    let mut temp = unsafe { File::from_raw_fd(temp_fd) };
    let mut temp_guard = TempFileGuard {
        directory_fd: profile.directory().as_raw_fd(),
        name: temp_name.clone(),
        published: false,
    };
    let mut copied = 0u64;
    let mut buffer = [0; READ_CHUNK_BYTES];
    loop {
        check_capture_liveness(deadline, cancelled)?;
        let read = source
            .read(&mut buffer)
            .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(read as u64)
            .filter(|size| *size <= MAX_EXECUTABLE_BYTES)
            .ok_or(NativeEvidenceRuntimeError::Unsupported)?;
        temp.write_all(&buffer[..read])
            .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
    }
    let source_after = source
        .metadata()
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    if !same_file_version(&source_metadata, &source_after) || copied != source_metadata.len() {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }
    if hash_file_checked(&temp, MAX_EXECUTABLE_BYTES, deadline, cancelled)? != digest {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }
    check_capture_liveness(deadline, cancelled)?;
    if unsafe { libc::fchmod(temp.as_raw_fd(), HELPER_FILE_MODE as libc::mode_t) } != 0 {
        return Err(NativeEvidenceRuntimeError::Unavailable);
    }
    temp.sync_all()
        .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
    let temp_metadata = temp
        .metadata()
        .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
    validate_snapshot_file(
        &temp,
        FileIdentity {
            device: temp_metadata.dev(),
            inode: temp_metadata.ino(),
            size: copied,
        },
    )?;

    // Publish the content-addressed snapshot as one directory operation. A
    // hard-link followed by unlink leaves a crash window with nlink == 2;
    // restart validation correctly rejects that state, which would strand the
    // cache entry permanently. RENAME_EXCL gives us atomic no-replace
    // semantics and leaves the final file with a single link.
    let rename_result = unsafe {
        libc::renameatx_np(
            profile.directory().as_raw_fd(),
            temp_name.as_ptr(),
            profile.directory().as_raw_fd(),
            executable_name.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if rename_result != 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(NativeEvidenceRuntimeError::Unavailable);
        }
        // A content-addressed name may already be present from an earlier
        // capture. It is reused only after a full private-file, hash, and code
        // signature check below.
        if unsafe { libc::unlinkat(profile.directory().as_raw_fd(), temp_name.as_ptr(), 0) } != 0 {
            return Err(NativeEvidenceRuntimeError::Unavailable);
        }
        temp_guard.published = true;
    } else {
        // The temporary pathname no longer exists after a successful rename.
        temp_guard.published = true;
    }
    drop(temp);
    profile
        .directory()
        .sync_all()
        .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;

    let snapshot = open_profile_file(profile, &executable_name, libc::O_RDONLY)
        .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
    let snapshot_metadata = snapshot
        .metadata()
        .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
    let file_identity = FileIdentity {
        device: snapshot_metadata.dev(),
        inode: snapshot_metadata.ino(),
        size: copied,
    };
    validate_snapshot_file(&snapshot, file_identity)?;
    if hash_file(&snapshot, MAX_EXECUTABLE_BYTES)? != digest {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }
    validate_signed_snapshot(&snapshot_path, requirement, expected_code)?;
    Ok((executable_name, digest, file_identity))
}

fn validate_signed_snapshot(
    snapshot_path: &Path,
    requirement: &SecRequirement,
    expected_code: &CodeIdentity,
) -> Result<(), NativeEvidenceRuntimeError> {
    let url =
        CFURL::from_path(snapshot_path, false).ok_or(NativeEvidenceRuntimeError::Unsupported)?;
    let code = SecStaticCode::from_path(&url, Flags::NONE)
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    code.check_validity(STRICT_FLAGS, requirement)
        .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    let info = signing_information(code.as_CFTypeRef().cast())?;
    if info.identity != *expected_code || info.main_executable != snapshot_path {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }
    Ok(())
}

fn check_snapshot_cache_capacity(
    profile: &PrivateProfile,
    next_size: u64,
    deadline: Option<Instant>,
    cancelled: &AtomicBool,
) -> Result<(), NativeEvidenceRuntimeError> {
    profile
        .check_current()
        .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
    let mut count = 0usize;
    let mut total_bytes = 0u64;
    for entry in
        std::fs::read_dir(profile.path()).map_err(|_| NativeEvidenceRuntimeError::Unavailable)?
    {
        check_capture_liveness(deadline, cancelled)?;
        let entry = entry.map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let is_snapshot = if let Some(digest) = name
            .strip_prefix("native-evidence-helper-")
            .and_then(|name| name.strip_suffix(".bin"))
        {
            if !valid_lower_hex(digest, 32) {
                return Err(NativeEvidenceRuntimeError::Unsupported);
            }
            true
        } else if let Some(id) = name
            .strip_prefix("native-evidence-")
            .and_then(|name| name.strip_suffix(".tmp"))
        {
            if Uuid::parse_str(id).is_err() {
                return Err(NativeEvidenceRuntimeError::Unsupported);
            }
            false
        } else if name.starts_with("native-evidence-") {
            return Err(NativeEvidenceRuntimeError::Unsupported);
        } else {
            continue;
        };
        let name_c = CString::new(name).map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
        let file = open_profile_file(profile, &name_c, libc::O_RDONLY)
            .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
        let metadata = file
            .metadata()
            .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
        let mode = metadata.mode() & 0o777;
        let valid_mode = if is_snapshot {
            mode == HELPER_FILE_MODE
        } else {
            mode == 0o700 || mode == HELPER_FILE_MODE
        };
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || !valid_mode
            || metadata.nlink() != 1
            || metadata.len() > MAX_EXECUTABLE_BYTES
        {
            return Err(NativeEvidenceRuntimeError::Unsupported);
        }
        crate::unix::reject_acl_grants(&file)
            .map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
        count = count
            .checked_add(1)
            .ok_or(NativeEvidenceRuntimeError::Unavailable)?;
        total_bytes = total_bytes
            .checked_add(metadata.len())
            .ok_or(NativeEvidenceRuntimeError::Unavailable)?;
        if count > MAX_SNAPSHOT_COUNT || total_bytes > MAX_SNAPSHOT_CACHE_BYTES {
            return Err(NativeEvidenceRuntimeError::Unavailable);
        }
    }
    let next_count = count
        .checked_add(1)
        .ok_or(NativeEvidenceRuntimeError::Unavailable)?;
    let next_total = total_bytes
        .checked_add(next_size)
        .ok_or(NativeEvidenceRuntimeError::Unavailable)?;
    if next_count > MAX_SNAPSHOT_COUNT || next_total > MAX_SNAPSHOT_CACHE_BYTES {
        return Err(NativeEvidenceRuntimeError::Unavailable);
    }
    profile
        .check_current()
        .map_err(|_| NativeEvidenceRuntimeError::Unavailable)
}

struct TempFileGuard {
    directory_fd: RawFd,
    name: CString,
    published: bool,
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if !self.published {
            unsafe {
                libc::unlinkat(self.directory_fd, self.name.as_ptr(), 0);
            }
        }
    }
}

fn open_profile_file(
    profile: &PrivateProfile,
    name: &CStr,
    flags: libc::c_int,
) -> io::Result<File> {
    profile
        .check_current()
        .map_err(|_| io::ErrorKind::PermissionDenied)?;
    let fd = unsafe {
        libc::openat(
            profile.directory().as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    profile
        .check_current()
        .map_err(|_| io::ErrorKind::PermissionDenied)?;
    Ok(file)
}

fn validate_snapshot_file(
    file: &File,
    expected: FileIdentity,
) -> Result<(), NativeEvidenceRuntimeError> {
    let metadata = file
        .metadata()
        .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != HELPER_FILE_MODE
        || metadata.nlink() != 1
        || metadata.dev() != expected.device
        || metadata.ino() != expected.inode
        || metadata.len() != expected.size
        || metadata.len() > MAX_EXECUTABLE_BYTES
    {
        return Err(NativeEvidenceRuntimeError::Unsupported);
    }
    crate::unix::reject_acl_grants(file).map_err(|_| NativeEvidenceRuntimeError::Unsupported)?;
    Ok(())
}

fn hash_file(file: &File, maximum: u64) -> Result<[u8; 32], NativeEvidenceRuntimeError> {
    hash_file_checked(file, maximum, None, &NEVER_CANCELLED)
}

fn hash_file_checked(
    file: &File,
    maximum: u64,
    deadline: Option<Instant>,
    cancelled: &AtomicBool,
) -> Result<[u8; 32], NativeEvidenceRuntimeError> {
    let mut file = file
        .try_clone()
        .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))
        .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0; READ_CHUNK_BYTES];
    loop {
        check_capture_liveness(deadline, cancelled)?;
        let read = file
            .read(&mut buffer)
            .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .filter(|size| *size <= maximum)
            .ok_or(NativeEvidenceRuntimeError::Unsupported)?;
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn same_file_version(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn drive_child(
    child: &mut Child,
    input: &[u8],
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>, NativeEvidenceRuntimeError> {
    let mut stdin = Some(
        child
            .stdin
            .take()
            .ok_or(NativeEvidenceRuntimeError::Unavailable)?,
    );
    let mut stdout = child
        .stdout
        .take()
        .ok_or(NativeEvidenceRuntimeError::Unavailable)?;
    let stdin_fd = stdin
        .as_ref()
        .map(AsRawFd::as_raw_fd)
        .ok_or(NativeEvidenceRuntimeError::Unavailable)?;
    set_nonblocking(stdin_fd)?;
    set_nonblocking(stdout.as_raw_fd())?;
    let mut written = 0usize;
    let mut output = Vec::with_capacity(MAX_FRAME_BYTES.min(16 * 1024));
    let mut stdout_eof = false;
    let mut status = None;
    let mut buffer = [0u8; READ_CHUNK_BYTES];
    if input.is_empty() {
        drop(stdin.take());
    }

    while !stdout_eof || status.is_none() || written < input.len() {
        if cancelled.load(Ordering::Acquire) {
            return Err(NativeEvidenceRuntimeError::Unavailable);
        }
        if Instant::now() >= deadline {
            return Err(NativeEvidenceRuntimeError::Deadline);
        }
        if written < input.len() {
            let pipe = stdin
                .as_mut()
                .ok_or(NativeEvidenceRuntimeError::Unavailable)?;
            match pipe.write(&input[written..]) {
                Ok(0) => return Err(NativeEvidenceRuntimeError::Unavailable),
                Ok(count) => written = written.saturating_add(count),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(NativeEvidenceRuntimeError::Unavailable),
            }
            if written == input.len() {
                drop(stdin.take());
            }
        }

        loop {
            match stdout.read(&mut buffer) {
                Ok(0) => {
                    stdout_eof = true;
                    break;
                }
                Ok(count) => {
                    if output.len().saturating_add(count) > MAX_FRAME_BYTES {
                        return Err(NativeEvidenceRuntimeError::InvalidRequest);
                    }
                    output.extend_from_slice(&buffer[..count]);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(NativeEvidenceRuntimeError::Unavailable),
            }
        }
        if status.is_none() {
            status = child
                .try_wait()
                .map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
        }
        if !stdout_eof || status.is_none() || written < input.len() {
            poll_pipes(
                stdin.as_ref().map(AsRawFd::as_raw_fd),
                (!stdout_eof).then_some(stdout.as_raw_fd()),
                written < input.len(),
                deadline,
            )?;
        }
    }
    let status = status.ok_or(NativeEvidenceRuntimeError::Unavailable)?;
    if !status.success() || serde_json::from_slice::<serde_json::Value>(&output).is_err() {
        return Err(NativeEvidenceRuntimeError::Unavailable);
    }
    Ok(output)
}

fn set_nonblocking(fd: RawFd) -> Result<(), NativeEvidenceRuntimeError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(NativeEvidenceRuntimeError::Unavailable);
    }
    Ok(())
}

fn poll_pipes(
    stdin_fd: Option<RawFd>,
    stdout_fd: Option<RawFd>,
    need_write: bool,
    deadline: Instant,
) -> Result<(), NativeEvidenceRuntimeError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(NativeEvidenceRuntimeError::Deadline)?;
    let timeout_ms = remaining.as_millis().clamp(1, 25) as libc::c_int;
    let mut descriptors = [
        libc::pollfd {
            fd: stdin_fd.unwrap_or(-1),
            events: if need_write { libc::POLLOUT } else { 0 },
            revents: 0,
        },
        libc::pollfd {
            fd: stdout_fd.unwrap_or(-1),
            events: if stdout_fd.is_some() { libc::POLLIN } else { 0 },
            revents: 0,
        },
    ];
    let ready = unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, timeout_ms) };
    if ready < 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::Interrupted {
            Ok(())
        } else {
            Err(NativeEvidenceRuntimeError::Unavailable)
        };
    }
    Ok(())
}

fn lifetime_socketpair() -> Result<(UnixStream, UnixStream), NativeEvidenceRuntimeError> {
    fn promote(stream: UnixStream) -> io::Result<UnixStream> {
        let fd = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 4) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        drop(stream);
        Ok(unsafe { UnixStream::from_raw_fd(fd) })
    }

    let (reader, writer) =
        UnixStream::pair().map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
    let reader = promote(reader).map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
    let writer = promote(writer).map_err(|_| NativeEvidenceRuntimeError::Unavailable)?;
    Ok((reader, writer))
}

struct OwnedHelperChild {
    child: Child,
    _lifetime_writer: UnixStream,
    reaped: bool,
}

impl OwnedHelperChild {
    fn wait(&mut self) -> Result<ExitStatus, NativeEvidenceRuntimeError> {
        loop {
            match self.child.wait() {
                Ok(status) => {
                    self.reaped = true;
                    return Ok(status);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(NativeEvidenceRuntimeError::Unavailable),
            }
        }
    }

    /// Keep FD 3's writer open until a wait proves the helper is gone. If
    /// private-child ownership has been lost, do not signal a potentially
    /// reused PID or return while the helper could still be live.
    fn terminate(&mut self) {
        while !self.reaped {
            match self.child.try_wait() {
                Ok(Some(_)) => {
                    self.reaped = true;
                    return;
                }
                Ok(None) => {
                    if crate::process::require_unreaped_child(&self.child).is_ok() {
                        let _ = self.child.kill();
                    }
                }
                Err(_) => {}
            }
            match self.child.wait() {
                Ok(_) => {
                    self.reaped = true;
                    return;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
    }
}

impl Drop for OwnedHelperChild {
    fn drop(&mut self) {
        self.terminate();
    }
}

const SEC_CS_SIGNING_INFORMATION: u32 = 1 << 1;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecCodeInfoIdentifier: CFStringRef;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
    static kSecCodeInfoUnique: CFStringRef;
    static kSecCodeInfoMainExecutable: CFStringRef;

    fn SecCodeCopySigningInformation(
        code: *const std::ffi::c_void,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> i32;
    fn SecCodeValidateFileResource(
        code: *const std::ffi::c_void,
        relative_path: CFStringRef,
        data: CFDataRef,
        flags: u32,
    ) -> i32;
}

#[link(name = "bsm")]
unsafe extern "C" {
    fn audit_token_to_pid(token: AuditToken) -> libc::pid_t;
}
