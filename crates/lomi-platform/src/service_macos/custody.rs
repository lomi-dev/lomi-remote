//! Root-owned registration and peer identity for the separate privileged
//! macOS custody LaunchDaemon. This module prepares files and paths only; the
//! caller owns LaunchDaemon load/unload operations and broker runtime.
#![cfg(target_os = "macos")]

use super::{Error, Result, boot::CustodyBinding};
use core_foundation::{
    base::{CFType, TCFType},
    data::CFData,
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
    ffi::{CString, OsStr},
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt, net::UnixStream},
    },
    path::{Component, Path, PathBuf},
};

const CUSTODY_ROOT: &str = "/Library/Application Support/LomiRemote/PrivilegedCustody";
const LAUNCH_DAEMONS: &str = "/Library/LaunchDaemons";
// /private/var/run is group-writable on macOS. Keep the endpoint beneath
// protected root-owned ancestry and within sockaddr_un.sun_path's 103 bytes.
const SOCKET_ROOT: &str = "/private/var/lomi-custody";
const REGISTRATION_FILE: &str = "registration.json";
const UNINSTALLED_FILE: &str = "uninstalled.json";
const PLIST_MODE: u32 = 0o600;
const STATE_MODE: u32 = 0o700;
const SOCKET_DIRECTORY_MODE: u32 = 0o711;
const LIMIT: usize = 16 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const STRICT_FLAGS: Flags = Flags::STRICT_VALIDATE.union(Flags::CHECK_ALL_ARCHITECTURES);
const BROKER_ARGUMENT: &str = "--internal-privileged-pty-broker";
const APPLE_REQUIREMENT: &str = "anchor apple generic";
const REGISTRATION_VERSION: u8 = 1;

#[path = "custody_drain.rs"]
mod drain;
pub use drain::{
    PrivilegedCustodianDrainReceipt, verify_privileged_custodian_drained,
    write_privileged_custodian_drain_receipt,
};

#[path = "custody_release_signing.rs"]
mod release_signing;
pub use release_signing::verify_release_image_team;

/// An immutable, validated registration. Call [`validate_privileged_custodian`]
/// again after an update barrier before using a retained value for a new
/// broker lifetime.
pub struct PrivilegedCustodianRegistration {
    disk: DiskRegistration,
}

impl std::fmt::Debug for PrivilegedCustodianRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivilegedCustodianRegistration")
            .field("owner_uid", &self.disk.owner_uid)
            .field("profile_path", &self.disk.profile_path)
            .field("executable_path", &self.disk.executable_path)
            .field("launch_daemon_label", &self.disk.launch_daemon_label)
            .finish_non_exhaustive()
    }
}

impl PrivilegedCustodianRegistration {
    pub fn registration_key(&self) -> &str {
        &self.disk.registration_key
    }
    pub fn owner_uid(&self) -> u32 {
        self.disk.owner_uid
    }

    pub fn owner_gid(&self) -> u32 {
        self.disk.owner_gid
    }

    pub fn account_name(&self) -> &str {
        &self.disk.account_name
    }

    pub fn account_home(&self) -> &Path {
        Path::new(&self.disk.account_home)
    }

    pub fn profile_path(&self) -> &Path {
        Path::new(&self.disk.profile_path)
    }

    pub fn profile_device(&self) -> u64 {
        self.disk.profile_pin.device
    }

    pub fn profile_inode(&self) -> u64 {
        self.disk.profile_pin.inode
    }

    pub fn executable_path(&self) -> &Path {
        Path::new(&self.disk.executable_path)
    }

    pub fn registration_path(&self) -> &Path {
        Path::new(&self.disk.registration_path)
    }

    pub fn state_directory(&self) -> &Path {
        Path::new(&self.disk.state_directory)
    }

    pub fn socket_parent(&self) -> &Path {
        Path::new(&self.disk.socket_parent)
    }

    pub fn socket_path(&self) -> &Path {
        Path::new(&self.disk.socket_path)
    }

    pub fn launch_daemon_label(&self) -> &str {
        &self.disk.launch_daemon_label
    }

    pub fn launch_daemon_plist_path(&self) -> PathBuf {
        plist_path(&self.disk.launch_daemon_label)
    }

    pub fn signing_identifier(&self) -> &str {
        &self.disk.signing_identity.identifier
    }

    pub fn signing_team_identifier(&self) -> &str {
        &self.disk.signing_identity.team_identifier
    }

    pub fn signing_code_directory_hash(&self) -> &str {
        &self.disk.signing_identity.code_directory_hash
    }

    pub fn executable_device(&self) -> u64 {
        self.disk.executable_pin.device
    }

    pub fn executable_inode(&self) -> u64 {
        self.disk.executable_pin.inode
    }

    pub fn executable_size(&self) -> u64 {
        self.disk.executable_pin.size
    }

    pub fn executable_sha256(&self) -> &str {
        &self.disk.executable_pin.sha256
    }
}

/// Proof that one accepted Unix socket peer has the selected UID and is the
/// exact strict-Apple-signed binary pinned by its root-owned registration.
/// Its fields are intentionally private and it cannot be deserialized.
pub struct PrivilegedCustodianPeerProof {
    registration_key: String,
    peer_uid: u32,
    peer_gid: u32,
    peer_pid: i32,
    code_identifier: String,
    audit_token: [u32; 8],
}

impl std::fmt::Debug for PrivilegedCustodianPeerProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivilegedCustodianPeerProof")
            .field("peer_uid", &self.peer_uid)
            .field("peer_pid", &self.peer_pid)
            .field("code_identifier", &self.code_identifier)
            .finish_non_exhaustive()
    }
}

impl PrivilegedCustodianPeerProof {
    pub fn audit_token(&self) -> [u32; 8] {
        self.audit_token
    }
    pub fn registration_key(&self) -> &str {
        &self.registration_key
    }

    pub fn peer_uid(&self) -> u32 {
        self.peer_uid
    }

    pub fn peer_gid(&self) -> u32 {
        self.peer_gid
    }

    pub fn peer_pid(&self) -> i32 {
        self.peer_pid
    }

    pub fn code_identifier(&self) -> &str {
        &self.code_identifier
    }
}

/// Install or safely update the root-owned registration and exact LaunchDaemon
/// plist. The caller must hold the existing boot maintenance guard; this
/// function does not acquire its own lock. The caller must boot out the root
/// custody job before an executable update and remains responsible for
/// loading the plist after publication.
pub fn install_privileged_custodian(
    guard: &super::BootMaintenanceGuard,
) -> Result<PrivilegedCustodianRegistration> {
    require_root()?;
    let binding = guard.custody_binding()?;
    let disk = registration_for_binding(&binding)?;
    // Prepare the traversable socket directories before publishing any job
    // state. A bad /private/var/run ancestry must not leave a usable plist.
    Directory::open_or_create(Path::new(SOCKET_ROOT), SOCKET_DIRECTORY_MODE, None)?;
    let socket_parent = Directory::open_or_create(
        Path::new(&disk.socket_parent),
        SOCKET_DIRECTORY_MODE,
        Some((disk.owner_uid, disk.owner_gid)),
    )?;
    validate_optional_socket(&socket_parent, disk.owner_uid)?;
    let state = Directory::open_or_create(Path::new(&disk.state_directory), STATE_MODE, None)?;
    let daemons = Directory::open(Path::new(LAUNCH_DAEMONS), None, None)?;
    let registration_name = REGISTRATION_FILE;
    let plist_name = plist_name(&disk.launch_daemon_label);
    let new_registration = encode_registration(&disk)?;
    let new_plist = plist(&disk)?;

    let existing_bytes = state.read(registration_name)?;
    let existing_plist = daemons.read(&plist_name)?;
    match (existing_bytes, existing_plist) {
        (None, None) => {
            state.publish(registration_name, &new_registration)?;
            daemons.publish(&plist_name, &new_plist)?;
        }
        (None, Some(current_plist)) if current_plist == new_plist => {
            state.publish(registration_name, &new_registration)?;
        }
        (Some(old_bytes), None) => {
            let old = decode_registration(&old_bytes)?;
            validate_update_preimage(&old, &disk, &binding)?;
            daemons.publish(&plist_name, &new_plist)?;
            if old_bytes != new_registration {
                state.replace_exact(registration_name, &old_bytes, &new_registration)?;
            }
        }
        (Some(old_bytes), Some(old_plist)) => {
            let old = decode_registration(&old_bytes)?;
            validate_update_preimage(&old, &disk, &binding)?;
            let expected_old_plist = plist(&old)?;
            if old_plist != expected_old_plist && old_plist != new_plist {
                return Err(Error::Conflict);
            }
            if old_plist != new_plist {
                daemons.replace_exact(&plist_name, &old_plist, &new_plist)?;
            }
            if old_bytes != new_registration {
                state.replace_exact(registration_name, &old_bytes, &new_registration)?;
            }
        }
        _ => return Err(Error::Conflict),
    }

    let registration = PrivilegedCustodianRegistration { disk };
    validate_registration_disk(&registration.disk, true)?;
    Ok(registration)
}

/// Read and validate the selected account's registration while the caller
/// holds the boot maintenance guard. No client-provided paths are accepted.
pub fn read_privileged_custodian(
    guard: &super::BootMaintenanceGuard,
) -> Result<PrivilegedCustodianRegistration> {
    let binding = guard.custody_binding()?;
    let expected = registration_paths(&binding)?;
    let registration = load_privileged_custodian(Path::new(&expected.registration_path))?;
    ensure_binding_matches(&registration.disk, &binding)?;
    Ok(registration)
}

/// Distinguish an untouched first installation from corrupt or drifted state.
/// A surviving daemon plist without its registration is never treated as new.
pub fn read_optional_privileged_custodian(
    guard: &super::BootMaintenanceGuard,
) -> Result<Option<PrivilegedCustodianRegistration>> {
    require_root()?;
    let binding = guard.custody_binding()?;
    read_optional_for_binding(&binding)
}

pub(super) fn read_optional_for_binding(
    binding: &super::boot::CustodyBinding,
) -> Result<Option<PrivilegedCustodianRegistration>> {
    require_root()?;
    let paths = registration_paths(&binding)?;
    let state = Directory::open_optional_root(Path::new(&paths.state_directory), Some(STATE_MODE))?;
    let registration_bytes = match &state {
        Some(state) => state.read(REGISTRATION_FILE)?,
        None => None,
    };
    if let Some(bytes) = registration_bytes {
        let disk = decode_registration(&bytes)?;
        ensure_binding_matches(&disk, &binding)?;
        // Interrupted activation can replace the stable executable after a
        // durable drain. Metadata remains readable for recovery; starting or
        // invoking a helper still requires full current-image validation.
        validate_registration_maintenance(&disk)?;
        return Ok(Some(PrivilegedCustodianRegistration { disk }));
    }
    let daemons = Directory::open(Path::new(LAUNCH_DAEMONS), None, None)?;
    if daemons
        .read(&plist_name(&paths.launch_daemon_label))?
        .is_some()
    {
        return Err(Error::Conflict);
    }
    if let Some(state) = state.as_ref()
        && let Some(bytes) = state.read(UNINSTALLED_FILE)?
    {
        let tombstone: UninstallTombstone =
            serde_json::from_slice(&bytes).map_err(|_| Error::Conflict)?;
        if tombstone.version != 1 || !valid_lower_hex(&tombstone.drain_receipt_sha256, 32) {
            return Err(Error::Conflict);
        }
        ensure_binding_matches(&tombstone.registration, &binding)?;
        validate_registration_inner(&tombstone.registration, false, true, false)?;
        let registration = PrivilegedCustodianRegistration {
            disk: tombstone.registration,
        };
        drain::verify_uninstalled(&registration, &tombstone.drain_receipt_sha256)?;
        return Ok(None);
    }
    if Directory::open_optional_root(
        &Path::new(&paths.state_directory).join("generations"),
        Some(STATE_MODE),
    )?
    .is_some_and(|generations| generations.names().map_or(true, |names| !names.is_empty()))
    {
        return Err(Error::Conflict);
    }
    Ok(None)
}

/// Read-only user-side binding. It contains no registration secret and cannot
/// launch a privileged process. The endpoint and root-owned executable must
/// remain pinned before accepting the broker's SCM_RIGHTS descriptor.
pub struct PrivilegedCustodianClientBinding {
    registration_key: String,
    socket_path: PathBuf,
    executable_path: PathBuf,
    executable_pin: ExecutablePin,
    signing_identity: CodeIdentity,
    owner_uid: u32,
    owner_gid: u32,
    profile_path: PathBuf,
    profile_pin: DirectoryPin,
}
impl PrivilegedCustodianClientBinding {
    pub fn registration_key(&self) -> &str {
        &self.registration_key
    }
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

pub fn privileged_custodian_client_binding(
    profile_path: &Path,
    executable_path: &Path,
) -> Result<PrivilegedCustodianClientBinding> {
    let owner_uid = unsafe { libc::geteuid() };
    let owner_gid = unsafe { libc::getegid() };
    if owner_uid == 0 || profile_path.canonicalize().map_err(|_| Error::Conflict)? != profile_path {
        return Err(Error::Conflict);
    }
    let profile = Directory::open_profile(profile_path, owner_uid, owner_gid)?;
    let profile_pin = pin_directory(&profile.0)?;
    let (executable_pin, signing_identity) =
        executable_identity(executable_path, owner_uid, owner_gid)?;
    let registration_key = registration_key(owner_uid, &path_string(profile_path)?);
    let socket_parent = Path::new(SOCKET_ROOT).join(&registration_key);
    let socket_path = socket_parent.join("broker.sock");
    if socket_path.as_os_str().as_bytes().len() > 103 {
        return Err(Error::Conflict);
    }
    let parent = Directory::open(
        &socket_parent,
        Some(SOCKET_DIRECTORY_MODE),
        Some((owner_uid, owner_gid)),
    )?;
    validate_optional_socket(&parent, owner_uid)?;
    Ok(PrivilegedCustodianClientBinding {
        registration_key,
        socket_path,
        executable_path: executable_path.to_path_buf(),
        executable_pin,
        signing_identity,
        owner_uid,
        owner_gid,
        profile_path: profile_path.to_path_buf(),
        profile_pin,
    })
}

/// Resolve the administrator-installed Host for the current local account.
/// Desktop must start this executable rather than its own GUI binary: custody
/// admits only the exact installed Host code at this protected path.
pub fn installed_privileged_host_executable(profile_path: &Path) -> Result<PathBuf> {
    let uid = unsafe { libc::geteuid() };
    if uid == 0 || unsafe { libc::getuid() } != uid {
        return Err(Error::Conflict);
    }
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut storage = vec![0u8; 16 * 1024];
    let mut found = std::ptr::null_mut();
    if unsafe {
        libc::getpwuid_r(
            uid,
            &mut entry,
            storage.as_mut_ptr().cast(),
            storage.len(),
            &mut found,
        )
    } != 0
        || found.is_null()
        || entry.pw_name.is_null()
        || entry.pw_uid != uid
    {
        return Err(Error::Conflict);
    }
    let account = unsafe { std::ffi::CStr::from_ptr(entry.pw_name) }
        .to_str()
        .map_err(|_| Error::Conflict)?;
    let (_, selected_uid) = super::boot::validate_selected_profile(profile_path, account)?;
    if selected_uid != uid {
        return Err(Error::Conflict);
    }
    let executable = super::boot::install_path_for_account(account)?.join("lomiremote");
    executable_identity(&executable, uid, entry.pw_gid)?;
    Ok(executable)
}

/// Prepare the same private account-owned profile used by Desktop and TUI.
/// This creates no Host, shell, service, sharing grant, or administrator state.
pub fn prepare_current_user_host_profile(profile: &Path) -> Result<()> {
    let uid = unsafe { libc::geteuid() };
    if uid == 0 || unsafe { libc::getuid() } != uid {
        return Err(Error::Conflict);
    }
    crate::unix::PrivateProfile::open(profile, true)
        .and_then(|profile| profile.check_current())
        .map_err(|_| Error::Conflict)
}

pub fn capture_privileged_custodian_server_proof(
    binding: &PrivilegedCustodianClientBinding,
    stream: &UnixStream,
) -> Result<PrivilegedCustodianPeerProof> {
    if unsafe { libc::geteuid() } != binding.owner_uid
        || unsafe { libc::getegid() } != binding.owner_gid
    {
        return Err(Error::Conflict);
    }
    let profile =
        Directory::open_profile(&binding.profile_path, binding.owner_uid, binding.owner_gid)?;
    if pin_directory(&profile.0)? != binding.profile_pin {
        return Err(Error::Conflict);
    }
    let (pin, identity) = executable_identity(
        &binding.executable_path,
        binding.owner_uid,
        binding.owner_gid,
    )?;
    if pin != binding.executable_pin || identity != binding.signing_identity {
        return Err(Error::Conflict);
    }
    capture_code_peer(
        &binding.registration_key,
        &binding.executable_path,
        &binding.signing_identity,
        stream,
        0,
        true,
    )
}

pub(crate) fn verify_installed_host_peer(
    profile: &Path,
    executable: &Path,
    stream: &UnixStream,
) -> Result<()> {
    if installed_privileged_host_executable(profile)? != executable {
        return Err(Error::Conflict);
    }
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let (_, identity) = executable_identity(executable, uid, gid)?;
    let key = registration_key(uid, &path_string(profile)?);
    capture_code_peer(&key, executable, &identity, stream, uid, false).map(|_| ())
}

/// Load a registration passed to the root broker by its fixed LaunchDaemon
/// argument. The file's own account/profile data must derive this exact path,
/// and every stored path is recomputed and checked before this returns.
pub fn load_privileged_custodian(
    registration_path: &Path,
) -> Result<PrivilegedCustodianRegistration> {
    require_root()?;
    let parent = registration_path.parent().ok_or(Error::Invalid)?;
    let directory = Directory::open(parent, Some(STATE_MODE), None)?;
    let bytes = directory.read(REGISTRATION_FILE)?.ok_or(Error::Conflict)?;
    let disk = decode_registration(&bytes)?;
    if Path::new(&disk.registration_path) != registration_path {
        return Err(Error::Conflict);
    }
    validate_registration_disk(&disk, true)?;
    Ok(PrivilegedCustodianRegistration { disk })
}

/// Reopen and fully validate the current root-owned record, profile inode,
/// executable inode/hash/signature, plist, and derived socket/state paths.
pub fn validate_privileged_custodian(
    guard: &super::BootMaintenanceGuard,
    registration: &PrivilegedCustodianRegistration,
) -> Result<()> {
    require_root()?;
    let binding = guard.custody_binding()?;
    ensure_binding_matches(&registration.disk, &binding)?;
    validate_registration_disk(&registration.disk, true)
}

pub(super) fn validate_for_binding(
    registration: &PrivilegedCustodianRegistration,
    binding: &super::boot::CustodyBinding,
) -> Result<()> {
    ensure_binding_matches(&registration.disk, binding)?;
    validate_registration_disk(&registration.disk, true)
}

/// Repair only an interrupted plist publication for the same pinned image.
/// This never changes the executable registration beneath a loaded broker.
pub(super) fn repair_privileged_custodian_publication(
    guard: &super::BootMaintenanceGuard,
    registration: &PrivilegedCustodianRegistration,
) -> Result<()> {
    let binding = guard.custody_binding()?;
    ensure_binding_matches(&registration.disk, &binding)?;
    validate_registration_inner(&registration.disk, true, true, true)?;
    let daemons = Directory::open(Path::new(LAUNCH_DAEMONS), None, None)?;
    let name = plist_name(registration.launch_daemon_label());
    let expected = plist(&registration.disk)?;
    match daemons.read(&name)? {
        None => daemons.publish(&name, &expected),
        Some(current) if current == expected => Ok(()),
        _ => Err(Error::Conflict),
    }
}

pub(super) struct PrivilegedCustodianOfflineDrain {
    _instance_lock: File,
}

/// Reconstruct a missing cleanup receipt only behind BOTH actual kernel locks:
/// no account Host can issue work and no broker worker can publish a new
/// generation. Every durable generation must independently be Cleaned.
pub(super) fn certify_offline_privileged_custodian_drained(
    guard: &super::BootMaintenanceGuard,
    registration: &PrivilegedCustodianRegistration,
) -> Result<PrivilegedCustodianOfflineDrain> {
    require_root()?;
    if !guard.profile_owner_lock_held() {
        return Err(Error::Conflict);
    }
    ensure_binding_matches(&registration.disk, &guard.custody_binding()?)?;
    validate_registration_maintenance(&registration.disk)?;
    let state = Directory::open(registration.state_directory(), Some(STATE_MODE), None)?;
    let instance_lock = state.regular("broker.lock", true)?.ok_or(Error::Conflict)?;
    if unsafe { libc::flock(instance_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(Error::NotReady);
    }
    drain::write_offline_receipt(registration)?;
    Ok(PrivilegedCustodianOfflineDrain {
        _instance_lock: instance_lock,
    })
}

/// Remove only this binding's exact root-owned plist and registration. The
/// caller must boot out the root LaunchDaemon before invoking this function;
/// it does not remove profile data, sockets, or the shared runtime directory.
pub fn uninstall_privileged_custodian(guard: &super::BootMaintenanceGuard) -> Result<()> {
    require_root()?;
    let binding = guard.custody_binding()?;
    let paths = registration_paths(&binding)?;
    let state = Directory::open(Path::new(&paths.state_directory), Some(STATE_MODE), None)?;
    let daemons = Directory::open(Path::new(LAUNCH_DAEMONS), None, None)?;
    let Some(bytes) = state.read(REGISTRATION_FILE)? else {
        return Ok(());
    };
    let disk = decode_registration(&bytes)?;
    ensure_binding_matches(&disk, &binding)?;
    if disk.registration_key != paths.registration_key
        || disk.registration_path != paths.registration_path
        || disk.state_directory != paths.state_directory
        || disk.socket_parent != paths.socket_parent
        || disk.socket_path != paths.socket_path
    {
        return Err(Error::Conflict);
    }
    // Keep a positive, exact cleanup tombstone before either removal. It makes
    // a completed uninstall distinguishable from corrupt orphan generations.
    let registration = PrivilegedCustodianRegistration { disk: disk.clone() };
    verify_privileged_custodian_drained(&registration)?;
    let drain_bytes = state.read("drained.json")?.ok_or(Error::Conflict)?;
    let tombstone = UninstallTombstone {
        version: 1,
        registration: disk.clone(),
        drain_receipt_sha256: format!("{:x}", Sha256::digest(&drain_bytes)),
    };
    let tombstone = serde_json::to_vec(&tombstone).map_err(|_| Error::Invalid)?;
    match state.read(UNINSTALLED_FILE)? {
        Some(old) if old == tombstone => {}
        Some(old) => {
            let previous: UninstallTombstone =
                serde_json::from_slice(&old).map_err(|_| Error::Conflict)?;
            ensure_binding_matches(&previous.registration, &binding)?;
            state.replace_exact(UNINSTALLED_FILE, &old, &tombstone)?;
        }
        None => state.publish(UNINSTALLED_FILE, &tombstone)?,
    }
    let name = plist_name(&disk.launch_daemon_label);
    let expected_plist = plist(&disk)?;
    match daemons.read(&name)? {
        Some(current) if current == expected_plist => {
            daemons.remove_exact(&name, &current)?;
        }
        None => {}
        _ => return Err(Error::Conflict),
    }
    state.remove_exact(REGISTRATION_FILE, &bytes)?;
    // Keep state/socket directory scaffolding. The broker owns any live socket
    // inode and may be responsible for its same-UID cleanup.
    Ok(())
}

/// Authenticate an accepted peer from its kernel UID/GID and audit token.
/// This is intended for an accepted connection from the registered socket;
/// the registration must have been loaded and validated when the broker
/// started.
pub fn capture_privileged_custodian_peer_proof(
    registration: &PrivilegedCustodianRegistration,
    accepted_stream: &UnixStream,
) -> Result<PrivilegedCustodianPeerProof> {
    require_root()?;
    capture_custodian_peer(registration, accepted_stream, registration.owner_uid())
}

/// Authenticate a controller, administrative helper or broker from its root
/// socket credentials and the exact installed code identity. Root UID alone
/// does not authorize a different executable or an unpinned release.
pub fn capture_privileged_custodian_root_peer_proof(
    registration: &PrivilegedCustodianRegistration,
    stream: &UnixStream,
) -> Result<PrivilegedCustodianPeerProof> {
    require_root()?;
    capture_custodian_peer(registration, stream, 0)
}

fn capture_custodian_peer(
    registration: &PrivilegedCustodianRegistration,
    accepted_stream: &UnixStream,
    expected_uid: u32,
) -> Result<PrivilegedCustodianPeerProof> {
    capture_code_peer(
        &registration.disk.registration_key,
        registration.executable_path(),
        &registration.disk.signing_identity,
        accepted_stream,
        expected_uid,
        true,
    )
}

fn capture_code_peer(
    registration_key: &str,
    executable_path: &Path,
    signing_identity: &CodeIdentity,
    accepted_stream: &UnixStream,
    expected_uid: u32,
    require_self: bool,
) -> Result<PrivilegedCustodianPeerProof> {
    let (peer_uid, peer_gid) = peer_euid_egid(accepted_stream)?;
    if peer_uid != expected_uid {
        return Err(Error::Conflict);
    }
    let audit_token = peer_audit_token(accepted_stream)?;
    let peer_pid = unsafe { audit_token_to_pid(audit_token) };
    if peer_pid <= 0 {
        return Err(Error::Conflict);
    }

    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&audit_token as *const AuditToken).cast::<u8>(),
            std::mem::size_of::<AuditToken>(),
        )
    };
    let token_data = CFData::from_buffer(bytes);
    let mut attributes = GuestAttributes::new();
    attributes.set_audit_token(token_data.as_concrete_TypeRef());
    let guest = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
        .map_err(|_| Error::Conflict)?;
    let apple_requirement: SecRequirement =
        APPLE_REQUIREMENT.parse().map_err(|_| Error::Invalid)?;

    if require_self {
        let self_code = SecCode::for_self(Flags::NONE).map_err(|_| Error::Conflict)?;
        self_code
            .check_validity(STRICT_FLAGS, &apple_requirement)
            .map_err(|_| Error::Conflict)?;
        let self_info = signing_information(self_code.as_CFTypeRef().cast())?;
        if !same_code_identity(&self_info.identity, signing_identity)
            || self_info.main_executable != executable_path
        {
            return Err(Error::Conflict);
        }
    }

    guest
        .check_validity(STRICT_FLAGS, &apple_requirement)
        .map_err(|_| Error::Conflict)?;
    let peer_info = signing_information(guest.as_CFTypeRef().cast())?;
    if !same_code_identity(&peer_info.identity, signing_identity)
        || peer_info.main_executable != executable_path
    {
        return Err(Error::Conflict);
    }

    Ok(PrivilegedCustodianPeerProof {
        registration_key: registration_key.to_owned(),
        peer_uid,
        peer_gid,
        peer_pid,
        code_identifier: peer_info.identity.identifier,
        audit_token: audit_token.value,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskRegistration {
    version: u8,
    registration_key: String,
    owner_uid: u32,
    owner_gid: u32,
    account_name: String,
    account_home: String,
    profile_path: String,
    profile_pin: DirectoryPin,
    executable_path: String,
    executable_pin: ExecutablePin,
    signing_identity: CodeIdentity,
    launch_daemon_label: String,
    registration_path: String,
    state_directory: String,
    socket_parent: String,
    socket_path: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UninstallTombstone {
    version: u8,
    registration: DiskRegistration,
    drain_receipt_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryPin {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutablePin {
    device: u64,
    inode: u64,
    size: u64,
    sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeIdentity {
    identifier: String,
    team_identifier: String,
    code_directory_hash: String,
}

fn registration_for_binding(binding: &CustodyBinding) -> Result<DiskRegistration> {
    let paths = registration_paths(binding)?;
    let (executable_pin, signing_identity) = executable_identity(
        Path::new(&paths.executable_path),
        binding.owner_uid,
        binding.owner_gid,
    )?;
    let disk = DiskRegistration {
        version: REGISTRATION_VERSION,
        registration_key: paths.registration_key,
        owner_uid: binding.owner_uid,
        owner_gid: binding.owner_gid,
        account_name: binding.account_name.clone(),
        account_home: path_string(&binding.account_home)?,
        profile_path: path_string(&binding.profile_path)?,
        profile_pin: DirectoryPin {
            device: binding.profile_device,
            inode: binding.profile_inode,
            uid: binding.profile_uid,
            gid: binding.profile_gid,
            mode: binding.profile_mode,
        },
        executable_path: paths.executable_path,
        executable_pin,
        signing_identity,
        launch_daemon_label: paths.launch_daemon_label,
        registration_path: paths.registration_path,
        state_directory: paths.state_directory,
        socket_parent: paths.socket_parent,
        socket_path: paths.socket_path,
    };
    validate_derived_fields(&disk)?;
    Ok(disk)
}

struct DerivedPaths {
    registration_key: String,
    launch_daemon_label: String,
    registration_path: String,
    state_directory: String,
    socket_parent: String,
    socket_path: String,
    executable_path: String,
}

fn registration_paths(binding: &CustodyBinding) -> Result<DerivedPaths> {
    let profile = path_string(&binding.profile_path)?;
    let executable_path = path_string(&binding.executable_path)?;
    let registration_key = registration_key(binding.owner_uid, &profile);
    let state_directory = format!("{CUSTODY_ROOT}/{registration_key}");
    let registration_path = format!("{state_directory}/{REGISTRATION_FILE}");
    let socket_parent = format!("{SOCKET_ROOT}/{registration_key}");
    let socket_path = format!("{socket_parent}/broker.sock");
    if socket_path.len() > 103 {
        return Err(Error::Invalid);
    }
    let launch_daemon_label = format!("dev.lomi.remote.privileged-custody.{registration_key}");
    Ok(DerivedPaths {
        registration_key,
        launch_daemon_label,
        registration_path,
        state_directory,
        socket_parent,
        socket_path,
        executable_path,
    })
}

fn registration_key(uid: u32, canonical_profile: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"lomi-privileged-custody-v1\0");
    digest.update(uid.to_be_bytes());
    digest.update([0]);
    digest.update(canonical_profile.as_bytes());
    hex(&digest.finalize())
}

fn validate_derived_fields(disk: &DiskRegistration) -> Result<()> {
    if disk.version != REGISTRATION_VERSION
        || disk.owner_uid == 0
        || disk.owner_gid == 0
        || disk.account_name.is_empty()
        || disk.account_name.len() > 255
        || !disk
            .account_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        || !absolute_canonical_path(&disk.account_home)
        || !absolute_canonical_path(&disk.profile_path)
        || !absolute_canonical_path(&disk.executable_path)
        || disk.profile_pin.uid != disk.owner_uid
        || disk.profile_pin.mode != STATE_MODE
        || disk.executable_pin.size == 0
        || disk.executable_pin.size > MAX_EXECUTABLE_BYTES
        || !valid_lower_hex(&disk.executable_pin.sha256, 32)
        || !valid_identity(&disk.signing_identity)
    {
        return Err(Error::Conflict);
    }
    let key = registration_key(disk.owner_uid, &disk.profile_path);
    let state_directory = format!("{CUSTODY_ROOT}/{key}");
    let paths = DerivedPaths {
        registration_key: key.clone(),
        launch_daemon_label: format!("dev.lomi.remote.privileged-custody.{key}"),
        registration_path: format!("{state_directory}/{REGISTRATION_FILE}"),
        state_directory,
        socket_parent: format!("{SOCKET_ROOT}/{key}"),
        socket_path: format!("{SOCKET_ROOT}/{key}/broker.sock"),
        executable_path: disk.executable_path.clone(),
    };
    if paths.socket_path.len() > 103
        || disk.registration_key != paths.registration_key
        || disk.launch_daemon_label != paths.launch_daemon_label
        || disk.registration_path != paths.registration_path
        || disk.state_directory != paths.state_directory
        || disk.socket_parent != paths.socket_parent
        || disk.socket_path != paths.socket_path
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn ensure_binding_matches(disk: &DiskRegistration, binding: &CustodyBinding) -> Result<()> {
    validate_derived_fields(disk)?;
    if disk.owner_uid != binding.owner_uid
        || disk.owner_gid != binding.owner_gid
        || disk.account_name != binding.account_name
        || disk.account_home != path_string(&binding.account_home)?
        || disk.profile_path != path_string(&binding.profile_path)?
        || disk.profile_pin.device != binding.profile_device
        || disk.profile_pin.inode != binding.profile_inode
        || disk.profile_pin.uid != binding.profile_uid
        || disk.profile_pin.gid != binding.profile_gid
        || disk.profile_pin.mode != binding.profile_mode
        || disk.executable_path != path_string(&binding.executable_path)?
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn validate_update_preimage(
    old: &DiskRegistration,
    new: &DiskRegistration,
    binding: &CustodyBinding,
) -> Result<()> {
    validate_derived_fields(old)?;
    ensure_binding_matches(old, binding)?;
    if old.registration_key != new.registration_key
        || old.owner_uid != new.owner_uid
        || old.owner_gid != new.owner_gid
        || old.account_name != new.account_name
        || old.account_home != new.account_home
        || old.profile_path != new.profile_path
        || old.profile_pin != new.profile_pin
        || old.executable_path != new.executable_path
        || old.launch_daemon_label != new.launch_daemon_label
        || old.registration_path != new.registration_path
        || old.state_directory != new.state_directory
        || old.socket_parent != new.socket_parent
        || old.socket_path != new.socket_path
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn validate_registration_disk(disk: &DiskRegistration, validate_executable: bool) -> Result<()> {
    validate_registration_inner(disk, validate_executable, false, true)
}

fn validate_registration_maintenance(disk: &DiskRegistration) -> Result<()> {
    validate_registration_inner(disk, false, true, true)
}

fn validate_registration_inner(
    disk: &DiskRegistration,
    validate_executable: bool,
    allow_missing_plist: bool,
    require_registration: bool,
) -> Result<()> {
    require_root()?;
    validate_derived_fields(disk)?;
    super::boot::validate_custody_account(
        &disk.account_name,
        disk.owner_uid,
        disk.owner_gid,
        Path::new(&disk.account_home),
    )?;
    let expected_executable =
        super::boot::install_path_for_account(&disk.account_name)?.join("lomiremote");
    if Path::new(&disk.executable_path) != expected_executable {
        return Err(Error::Conflict);
    }
    let (validated_profile, owner_uid) =
        super::boot::validate_selected_profile(Path::new(&disk.profile_path), &disk.account_name)?;
    if validated_profile != Path::new(&disk.profile_path) || owner_uid != disk.owner_uid {
        return Err(Error::Conflict);
    }
    let profile = Directory::open_profile(
        Path::new(&disk.profile_path),
        disk.owner_uid,
        disk.owner_gid,
    )?;
    if pin_directory(&profile.0)? != disk.profile_pin {
        return Err(Error::Conflict);
    }

    let state = Directory::open(Path::new(&disk.state_directory), Some(STATE_MODE), None)?;
    match state.read(REGISTRATION_FILE)? {
        Some(stored) if decode_registration(&stored)? == *disk => {}
        None if !require_registration => {}
        _ => return Err(Error::Conflict),
    }
    let daemons = Directory::open(Path::new(LAUNCH_DAEMONS), None, None)?;
    let expected_plist = plist(disk)?;
    match daemons.read(&plist_name(&disk.launch_daemon_label))? {
        Some(actual) if actual == expected_plist => {}
        None if allow_missing_plist => {}
        _ => return Err(Error::Conflict),
    }
    let socket_parent = Directory::open(
        Path::new(&disk.socket_parent),
        Some(SOCKET_DIRECTORY_MODE),
        Some((disk.owner_uid, disk.owner_gid)),
    )?;
    validate_optional_socket(&socket_parent, disk.owner_uid)?;
    if validate_executable {
        let (pin, identity) = executable_identity(
            Path::new(&disk.executable_path),
            disk.owner_uid,
            disk.owner_gid,
        )?;
        if pin != disk.executable_pin || identity != disk.signing_identity {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}

fn validate_optional_socket(parent: &Directory, owner_uid: u32) -> Result<()> {
    let name = c(OsStr::new("broker.sock"))?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            parent.0.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(())
        } else {
            Err(Error::Conflict)
        };
    }
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || metadata.st_uid != owner_uid
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o777 != 0o600
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn executable_identity(
    path: &Path,
    selected_uid: u32,
    selected_gid: u32,
) -> Result<(ExecutablePin, CodeIdentity)> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        || path.canonicalize().map_err(|_| Error::Invalid)? != path
    {
        return Err(Error::Invalid);
    }
    let parent_path = path.parent().ok_or(Error::Invalid)?;
    let name = path.file_name().ok_or(Error::Invalid)?;
    let parent = Directory::open_executable_parent(parent_path, selected_uid, selected_gid)?;
    let encoded_name = c(name)?;
    let fd = unsafe {
        libc::openat(
            parent.0.as_raw_fd(),
            encoded_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(Error::Invalid);
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let before = file.metadata().map_err(|_| Error::Invalid)?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || access_bits(&before, selected_uid, selected_gid) & 0o5 != 0o5
        || before.len() == 0
        || before.len() > MAX_EXECUTABLE_BYTES
    {
        return Err(Error::Conflict);
    }
    crate::unix::reject_acl_grants(&file).map_err(|_| Error::Conflict)?;
    let mut digest = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|_| Error::Invalid)?;
        if count == 0 {
            break;
        }
        total = total.checked_add(count as u64).ok_or(Error::Invalid)?;
        if total > MAX_EXECUTABLE_BYTES {
            return Err(Error::Invalid);
        }
        digest.update(&buffer[..count]);
    }
    if total != before.len() {
        return Err(Error::Conflict);
    }

    let code_path = CFURL::from_path(path, false).ok_or(Error::Conflict)?;
    let code = SecStaticCode::from_path(&code_path, Flags::NONE).map_err(|_| Error::Conflict)?;
    let apple_requirement: SecRequirement =
        APPLE_REQUIREMENT.parse().map_err(|_| Error::Invalid)?;
    code.check_validity(STRICT_FLAGS, &apple_requirement)
        .map_err(|_| Error::Conflict)?;
    let signing = signing_information(code.as_CFTypeRef().cast())?;
    if signing.main_executable != path {
        return Err(Error::Conflict);
    }
    let identity = signing.identity;
    if !valid_identity(&identity) {
        return Err(Error::Conflict);
    }
    let after = file.metadata().map_err(|_| Error::Conflict)?;
    let current_parent =
        Directory::open_executable_parent(parent_path, selected_uid, selected_gid)?;
    let current_fd = unsafe {
        libc::openat(
            current_parent.0.as_raw_fd(),
            encoded_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if current_fd < 0 {
        return Err(Error::Conflict);
    }
    let current = unsafe { File::from_raw_fd(current_fd) };
    let current_metadata = current.metadata().map_err(|_| Error::Conflict)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.size() != after.size()
        || before.dev() != current_metadata.dev()
        || before.ino() != current_metadata.ino()
        || current_metadata.nlink() != 1
    {
        return Err(Error::Conflict);
    }
    Ok((
        ExecutablePin {
            device: before.dev(),
            inode: before.ino(),
            size: before.len(),
            sha256: hex(&digest.finalize()),
        },
        identity,
    ))
}

fn access_bits(metadata: &std::fs::Metadata, uid: u32, gid: u32) -> u32 {
    let mode = metadata.mode();
    if metadata.uid() == uid {
        (mode >> 6) & 0o7
    } else if metadata.gid() == gid {
        (mode >> 3) & 0o7
    } else {
        mode & 0o7
    }
}

fn encode_registration(disk: &DiskRegistration) -> Result<Vec<u8>> {
    serde_json::to_vec(disk).map_err(|_| Error::Invalid)
}

fn decode_registration(bytes: &[u8]) -> Result<DiskRegistration> {
    if bytes.is_empty() || bytes.len() > LIMIT {
        return Err(Error::Invalid);
    }
    let disk: DiskRegistration = serde_json::from_slice(bytes).map_err(|_| Error::Conflict)?;
    validate_derived_fields(&disk)?;
    Ok(disk)
}

fn plist(disk: &DiskRegistration) -> Result<Vec<u8>> {
    validate_derived_fields(disk)?;
    let binary = super::xml(&disk.executable_path)?;
    let registration = super::xml(&disk.registration_path)?;
    let label = super::xml(&disk.launch_daemon_label)?;
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{label}</string>
<key>ProgramArguments</key><array><string>{binary}</string><string>{BROKER_ARGUMENT}</string><string>{registration}</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ExitTimeOut</key><integer>10</integer>
<key>ThrottleInterval</key><integer>2</integer>
<key>Umask</key><integer>63</integer>
<key>StandardOutPath</key><string>/dev/null</string>
<key>StandardErrorPath</key><string>/dev/null</string>
</dict></plist>
"#
    )
    .into_bytes())
}

fn plist_name(label: &str) -> String {
    format!("{label}.plist")
}

fn plist_path(label: &str) -> PathBuf {
    Path::new(LAUNCH_DAEMONS).join(plist_name(label))
}

fn path_string(path: &Path) -> Result<String> {
    if !path.is_absolute() {
        return Err(Error::Invalid);
    }
    path.to_str().map(str::to_owned).ok_or(Error::Invalid)
}

fn absolute_canonical_path(text: &str) -> bool {
    let path = Path::new(text);
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn valid_identity(identity: &CodeIdentity) -> bool {
    !identity.identifier.is_empty()
        && identity.identifier.len() <= 512
        && !identity.identifier.chars().any(char::is_control)
        && !identity.team_identifier.is_empty()
        && identity.team_identifier.len() <= 128
        && identity
            .team_identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
        && valid_code_hash(&identity.code_directory_hash)
}

fn valid_code_hash(hash: &str) -> bool {
    matches!(hash.len(), 40 | 64)
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_lower_hex(text: &str, bytes: usize) -> bool {
    text.len() == bytes.saturating_mul(2)
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn same_code_identity(left: &CodeIdentity, right: &CodeIdentity) -> bool {
    left.identifier == right.identifier
        && left.team_identifier == right.team_identifier
        && left.code_directory_hash == right.code_directory_hash
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

struct Directory(File);

#[derive(Clone, Copy)]
enum RootLeafGroupPolicy {
    /// Root-owned leaves managed by custody stay root:wheel.
    Wheel,
    /// Protected executable parents may use the installer's existing group.
    Protected,
}

fn valid_directory_component(
    is_directory: bool,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
    final_component: bool,
    final_owner: u32,
    final_mode: Option<u32>,
    accessible_user: Option<(u32, u32)>,
    allow_profile_ancestors: bool,
    root_leaf_group_policy: RootLeafGroupPolicy,
) -> bool {
    let owner_ok = if final_component {
        owner_uid == final_owner
    } else if allow_profile_ancestors {
        owner_uid == 0 || owner_uid == final_owner
    } else {
        owner_uid == 0
    };
    let group_ok = if !final_component || final_owner != 0 {
        true
    } else {
        match root_leaf_group_policy {
            RootLeafGroupPolicy::Wheel => owner_gid == 0,
            RootLeafGroupPolicy::Protected => true,
        }
    };

    is_directory
        && owner_ok
        && group_ok
        && mode & 0o022 == 0
        && (!final_component || final_mode.is_none_or(|expected| mode & 0o777 == expected))
        && accessible_user.is_none_or(|(uid, gid)| {
            access_bits_from_metadata(owner_uid, owner_gid, mode, uid, gid) & 0o1 != 0
        })
}

fn access_bits_from_metadata(owner_uid: u32, owner_gid: u32, mode: u32, uid: u32, gid: u32) -> u32 {
    if owner_uid == uid {
        (mode >> 6) & 0o7
    } else if owner_gid == gid {
        (mode >> 3) & 0o7
    } else {
        mode & 0o7
    }
}

impl Directory {
    fn open_optional_root(path: &Path, final_mode: Option<u32>) -> Result<Option<Self>> {
        if !path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err(Error::Invalid);
        }
        let mut current = File::open("/").map_err(|_| Error::Conflict)?;
        crate::unix::reject_acl_grants(&current).map_err(|_| Error::Conflict)?;
        let components: Vec<_> = path.components().skip(1).collect();
        for (index, component) in components.iter().enumerate() {
            let Component::Normal(name) = component else {
                return Err(Error::Invalid);
            };
            let name = c(name)?;
            let fd = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                    Ok(None)
                } else {
                    Err(Error::Conflict)
                };
            }
            let next = unsafe { File::from_raw_fd(fd) };
            let metadata = next.metadata().map_err(|_| Error::Conflict)?;
            let final_component = index + 1 == components.len();
            if !metadata.is_dir()
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
                || final_component && final_mode.is_some_and(|mode| metadata.mode() & 0o777 != mode)
                || final_component && final_mode.is_some() && metadata.gid() != 0
            {
                return Err(Error::Conflict);
            }
            crate::unix::reject_acl_grants(&next).map_err(|_| Error::Conflict)?;
            current = next;
        }
        if path.canonicalize().map_err(|_| Error::Conflict)? != path {
            return Err(Error::Conflict);
        }
        Ok(Some(Self(current)))
    }

    /// Enumerate the same held directory with an independent open-file offset.
    /// Path replacement cannot redirect the census to another directory.
    fn names(&self) -> Result<Vec<String>> {
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(Error::Conflict);
        }
        let dir = unsafe { libc::fdopendir(fd) };
        if dir.is_null() {
            unsafe {
                libc::close(fd);
            }
            return Err(Error::Conflict);
        }
        struct Census(*mut libc::DIR);
        impl Drop for Census {
            fn drop(&mut self) {
                unsafe {
                    libc::closedir(self.0);
                }
            }
        }
        let guard = Census(dir);
        let mut names = Vec::new();
        loop {
            unsafe {
                *libc::__error() = 0;
            }
            let entry = unsafe { libc::readdir(guard.0) };
            if entry.is_null() {
                if io::Error::last_os_error().raw_os_error() != Some(0) {
                    return Err(Error::Conflict);
                }
                break;
            }
            let entry = unsafe { &*entry };
            let length = entry.d_namlen as usize;
            if length == 0 || length >= entry.d_name.len() || entry.d_name[length] != 0 {
                return Err(Error::Conflict);
            }
            let bytes =
                unsafe { std::slice::from_raw_parts(entry.d_name.as_ptr().cast::<u8>(), length) };
            if bytes == b"." || bytes == b".." {
                continue;
            }
            if names.len() >= 256 {
                return Err(Error::Conflict);
            }
            names.push(
                std::str::from_utf8(bytes)
                    .map_err(|_| Error::Conflict)?
                    .to_owned(),
            );
        }
        names.sort();
        if names.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Error::Conflict);
        }
        Ok(names)
    }

    fn open(
        path: &Path,
        final_mode: Option<u32>,
        accessible_user: Option<(u32, u32)>,
    ) -> Result<Self> {
        Self::open_with_owner(
            path,
            0,
            final_mode,
            accessible_user,
            false,
            RootLeafGroupPolicy::Wheel,
        )
    }

    fn open_executable_parent(path: &Path, selected_uid: u32, selected_gid: u32) -> Result<Self> {
        Self::open_with_owner(
            path,
            0,
            None,
            Some((selected_uid, selected_gid)),
            false,
            RootLeafGroupPolicy::Protected,
        )
    }

    fn open_profile(path: &Path, owner_uid: u32, owner_gid: u32) -> Result<Self> {
        Self::open_with_owner(
            path,
            owner_uid,
            Some(STATE_MODE),
            Some((owner_uid, owner_gid)),
            true,
            RootLeafGroupPolicy::Wheel,
        )
    }

    fn open_with_owner(
        path: &Path,
        final_owner: u32,
        final_mode: Option<u32>,
        accessible_user: Option<(u32, u32)>,
        allow_profile_ancestors: bool,
        root_leaf_group_policy: RootLeafGroupPolicy,
    ) -> Result<Self> {
        if !path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err(Error::Invalid);
        }
        let mut current = File::open("/").map_err(|_| Error::Invalid)?;
        crate::unix::reject_acl_grants(&current).map_err(|_| Error::Invalid)?;
        let components: Vec<_> = path.components().skip(1).collect();
        for (index, component) in components.iter().enumerate() {
            let Component::Normal(name) = component else {
                return Err(Error::Invalid);
            };
            let name = c(name)?;
            let fd = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(Error::Conflict);
            }
            let next = unsafe { File::from_raw_fd(fd) };
            let metadata = next.metadata().map_err(|_| Error::Conflict)?;
            let final_component = index + 1 == components.len();
            // Standard protected ancestors may be root:admin or root:daemon.
            // Custody-owned root leaves still use the exact root:wheel metadata.
            if !valid_directory_component(
                metadata.is_dir(),
                metadata.uid(),
                metadata.gid(),
                metadata.mode(),
                final_component,
                final_owner,
                final_mode,
                accessible_user,
                allow_profile_ancestors,
                root_leaf_group_policy,
            ) {
                return Err(Error::Conflict);
            }
            crate::unix::reject_acl_grants(&next).map_err(|_| Error::Conflict)?;
            current = next;
        }
        if path.canonicalize().map_err(|_| Error::Conflict)? != path {
            return Err(Error::Conflict);
        }
        let metadata = current.metadata().map_err(|_| Error::Conflict)?;
        if !valid_directory_component(
            metadata.is_dir(),
            metadata.uid(),
            metadata.gid(),
            metadata.mode(),
            true,
            final_owner,
            final_mode,
            accessible_user,
            allow_profile_ancestors,
            root_leaf_group_policy,
        ) {
            return Err(Error::Conflict);
        }
        Ok(Self(current))
    }

    fn open_or_create(
        path: &Path,
        final_mode: u32,
        accessible_user: Option<(u32, u32)>,
    ) -> Result<Self> {
        if !path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err(Error::Invalid);
        }
        let mut current = File::open("/").map_err(|_| Error::Invalid)?;
        crate::unix::reject_acl_grants(&current).map_err(|_| Error::Invalid)?;
        let components: Vec<_> = path.components().skip(1).collect();
        for (index, component) in components.iter().enumerate() {
            let Component::Normal(name) = component else {
                return Err(Error::Invalid);
            };
            let name = c(name)?;
            let final_component = index + 1 == components.len();
            let mode = if final_component {
                final_mode
            } else {
                STATE_MODE
            };
            let mut fd = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            let mut created = false;
            if fd < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                if unsafe {
                    libc::mkdirat(current.as_raw_fd(), name.as_ptr(), mode as libc::mode_t)
                } != 0
                {
                    if io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
                        return Err(Error::Invalid);
                    }
                } else {
                    created = true;
                    current.sync_all().map_err(|_| Error::Invalid)?;
                }
                fd = unsafe {
                    libc::openat(
                        current.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
            }
            if fd < 0 {
                return Err(Error::Conflict);
            }
            let next = unsafe { File::from_raw_fd(fd) };
            if created
                && (unsafe { libc::fchown(next.as_raw_fd(), 0, 0) } != 0
                    || unsafe { libc::fchmod(next.as_raw_fd(), mode as libc::mode_t) } != 0)
            {
                return Err(Error::Invalid);
            }
            if created {
                next.sync_all().map_err(|_| Error::Invalid)?;
            }
            let metadata = next.metadata().map_err(|_| Error::Conflict)?;
            if !metadata.is_dir()
                || metadata.uid() != 0
                || (created || final_component) && metadata.gid() != 0
                || metadata.mode() & 0o022 != 0
                || final_component && metadata.mode() & 0o777 != final_mode
                || !final_component && metadata.mode() & 0o022 != 0
                || accessible_user
                    .is_some_and(|(uid, gid)| access_bits(&metadata, uid, gid) & 0o1 == 0)
            {
                return Err(Error::Conflict);
            }
            crate::unix::reject_acl_grants(&next).map_err(|_| Error::Conflict)?;
            current = next;
        }
        if path.canonicalize().map_err(|_| Error::Conflict)? != path {
            return Err(Error::Conflict);
        }
        Ok(Self(current))
    }

    fn regular(&self, name: &str, create: bool) -> Result<Option<File>> {
        let name = c(OsStr::new(name))?;
        let flags = libc::O_RDWR
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | if create { libc::O_CREAT } else { 0 };
        let fd = unsafe { libc::openat(self.0.as_raw_fd(), name.as_ptr(), flags, PLIST_MODE) };
        if fd < 0 {
            return if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                Ok(None)
            } else {
                Err(Error::Conflict)
            };
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(|_| Error::Conflict)?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != PLIST_MODE
        {
            return Err(Error::Conflict);
        }
        crate::unix::reject_acl_grants(&file).map_err(|_| Error::Conflict)?;
        Ok(Some(file))
    }

    fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.regular(name, false)?
            .map(|mut file| {
                let mut bytes = Vec::new();
                (&mut file)
                    .take((LIMIT + 1) as u64)
                    .read_to_end(&mut bytes)
                    .map_err(|_| Error::Invalid)?;
                if bytes.len() > LIMIT {
                    return Err(Error::Invalid);
                }
                Ok(bytes)
            })
            .transpose()
    }

    fn publish(&self, name: &str, bytes: &[u8]) -> Result<()> {
        self.publish_at(name, bytes, libc::RENAME_EXCL)
    }

    fn replace_exact(&self, name: &str, expected: &[u8], bytes: &[u8]) -> Result<()> {
        if self.read(name)?.as_deref() != Some(expected) {
            return Err(Error::Conflict);
        }
        self.publish_at(name, bytes, libc::RENAME_SWAP)
    }

    fn publish_at(&self, name: &str, bytes: &[u8], rename_flag: u32) -> Result<()> {
        if bytes.is_empty() || bytes.len() > LIMIT {
            return Err(Error::Invalid);
        }
        let temporary = format!(".lomi-custody-{}", uuid::Uuid::new_v4());
        let temp = c(OsStr::new(&temporary))?;
        let destination = c(OsStr::new(name))?;
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                temp.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                PLIST_MODE,
            )
        };
        if fd < 0 {
            return Err(Error::Invalid);
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let result = (|| {
            file.write_all(bytes).map_err(|_| Error::Invalid)?;
            if unsafe { libc::fchown(file.as_raw_fd(), 0, 0) } != 0
                || unsafe { libc::fchmod(file.as_raw_fd(), PLIST_MODE as libc::mode_t) } != 0
            {
                return Err(Error::Invalid);
            }
            crate::unix::reject_acl_grants(&file).map_err(|_| Error::Conflict)?;
            file.sync_all().map_err(|_| Error::Invalid)?;
            if unsafe {
                libc::renameatx_np(
                    self.0.as_raw_fd(),
                    temp.as_ptr(),
                    self.0.as_raw_fd(),
                    destination.as_ptr(),
                    rename_flag,
                )
            } != 0
            {
                return Err(Error::Conflict);
            }
            Ok(())
        })();
        unsafe {
            libc::unlinkat(self.0.as_raw_fd(), temp.as_ptr(), 0);
        }
        self.0.sync_all().map_err(|_| Error::Invalid)?;
        result
    }

    fn remove_exact(&self, name: &str, expected: &[u8]) -> Result<()> {
        if self.read(name)?.as_deref() != Some(expected) {
            return Err(Error::Conflict);
        }
        let name = c(OsStr::new(name))?;
        if unsafe { libc::unlinkat(self.0.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(Error::Invalid);
        }
        self.0.sync_all().map_err(|_| Error::Invalid)
    }
}

fn pin_directory(directory: &File) -> Result<DirectoryPin> {
    let metadata = directory.metadata().map_err(|_| Error::Conflict)?;
    if !metadata.is_dir() {
        return Err(Error::Conflict);
    }
    Ok(DirectoryPin {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode() & 0o777,
    })
}

fn peer_euid_egid(stream: &UnixStream) -> Result<(u32, u32)> {
    let mut uid = 0;
    let mut gid = 0;
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(Error::Conflict);
    }
    Ok((uid, gid))
}

#[derive(Clone, Copy)]
#[repr(C)]
struct AuditToken {
    value: [u32; 8],
}

fn peer_audit_token(stream: &UnixStream) -> Result<AuditToken> {
    let mut token = AuditToken { value: [0; 8] };
    let mut length = std::mem::size_of::<AuditToken>() as libc::socklen_t;
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
        return Err(Error::Conflict);
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
        return Err(Error::Conflict);
    }
    Ok(token)
}

struct SigningInformation {
    identity: CodeIdentity,
    main_executable: PathBuf,
}

fn signing_information(code: *const std::ffi::c_void) -> Result<SigningInformation> {
    let mut raw: CFDictionaryRef = std::ptr::null();
    let status =
        unsafe { SecCodeCopySigningInformation(code, SEC_CS_SIGNING_INFORMATION, &mut raw) };
    if status != 0 || raw.is_null() {
        return Err(Error::Conflict);
    }
    let dictionary: CFDictionary<*const std::ffi::c_void, CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(raw) };
    let identifier =
        string_value(&dictionary, unsafe { kSecCodeInfoIdentifier }).ok_or(Error::Conflict)?;
    let team_identifier =
        string_value(&dictionary, unsafe { kSecCodeInfoTeamIdentifier }).ok_or(Error::Conflict)?;
    let code_directory_hash = data_value(&dictionary, unsafe { kSecCodeInfoUnique })
        .map(|hash| hex(&hash))
        .ok_or(Error::Conflict)?;
    let main_executable = url_value(&dictionary, unsafe { kSecCodeInfoMainExecutable })
        .and_then(|url| url.to_path())
        .ok_or(Error::Conflict)?;
    let identity = CodeIdentity {
        identifier,
        team_identifier,
        code_directory_hash,
    };
    if !valid_identity(&identity) {
        return Err(Error::Conflict);
    }
    Ok(SigningInformation {
        identity,
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

fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(Error::Unimplemented);
    }
    Ok(())
}

fn c(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| Error::Invalid)
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
}

#[link(name = "bsm")]
unsafe extern "C" {
    fn audit_token_to_pid(token: AuditToken) -> libc::pid_t;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_parent_accepts_protected_root_admin_directory() {
        assert!(valid_directory_component(
            true,
            0,
            80,
            0o755,
            true,
            0,
            None,
            Some((501, 20)),
            false,
            RootLeafGroupPolicy::Protected,
        ));
    }

    #[test]
    fn custody_root_leaf_still_requires_wheel_group() {
        assert!(!valid_directory_component(
            true,
            0,
            80,
            STATE_MODE,
            true,
            0,
            Some(STATE_MODE),
            None,
            false,
            RootLeafGroupPolicy::Wheel,
        ));
        assert!(valid_directory_component(
            true,
            0,
            0,
            STATE_MODE,
            true,
            0,
            Some(STATE_MODE),
            None,
            false,
            RootLeafGroupPolicy::Wheel,
        ));
    }

    #[test]
    fn executable_parent_rejects_unsafe_metadata_or_missing_traversal() {
        let selected_user = Some((501, 20));
        let protected_policy = RootLeafGroupPolicy::Protected;
        assert!(!valid_directory_component(
            true,
            501,
            80,
            0o755,
            true,
            0,
            None,
            selected_user,
            false,
            protected_policy,
        ));
        assert!(!valid_directory_component(
            true,
            0,
            80,
            0o775,
            true,
            0,
            None,
            selected_user,
            false,
            protected_policy,
        ));
        assert!(!valid_directory_component(
            true,
            0,
            80,
            0o700,
            true,
            0,
            None,
            selected_user,
            false,
            protected_policy,
        ));
    }
}
