//! Explicit user LaunchAgent and administrator-managed system LaunchDaemon.
mod boot;
pub mod custody;
mod custody_lifecycle;
mod profile_setup;

use crate::unix::{LocalClient, OwnerLock};
use lomi_remote_protocol::{
    HostId, LocalIpcVersion,
    ipc::{IpcProfileId, LocalCall, LocalResult},
};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{CString, OsStr},
    fs::{self, File},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const LIMIT: usize = 32 * 1024;
const DEADLINE: Duration = Duration::from_secs(55);
const RECORD: &str = "service-registration-macos.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Conflict,
    Manager,
    Unavailable,
    Deadline,
    NotReady,
    Unimplemented,
    Disabled,
    AdministratorRequired,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "SERVICE_INVALID_CONFIGURATION",
            Self::Conflict => "SERVICE_OWNERSHIP_CONFLICT",
            Self::Manager => "SERVICE_MANAGER_UNAVAILABLE",
            Self::Unavailable => "SERVICE_REGISTRATION_UNAVAILABLE",
            Self::Deadline => "SERVICE_OPERATION_UNCERTAIN",
            Self::NotReady => "SERVICE_NOT_READY",
            Self::Disabled => "SERVICE_DISABLED_BY_OS",
            Self::Unimplemented => "SERVICE_ADAPTER_UNIMPLEMENTED_FOR_MODE_OR_ACCOUNT",
            Self::AdministratorRequired => {
                "SERVICE_ADMINISTRATOR_REQUIRED_FOR_PROTECTED_INSTALL: run the service command as administrator with the existing account and mode"
            }
        })
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
fn uid() -> u32 {
    unsafe { libc::geteuid() }
}

/// Whether this process has administrator credentials. This is only a CLI
/// routing hint; privileged operations still perform their own full checks.
pub fn is_administrator() -> bool {
    uid() == 0
}

fn c(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| Error::Invalid)
}

pub use boot::BootMaintenanceGuard;

/// Explicit Host autostart mode for an administrator-managed protected CLI.
/// The root custodian is independent of this choice and never runs the Host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminHostMode {
    Manual,
    Login,
    Boot,
}

impl AdminHostMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Login => "login",
            Self::Boot => "boot",
        }
    }
}

impl std::str::FromStr for AdminHostMode {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "manual" => Ok(Self::Manual),
            "login" => Ok(Self::Login),
            "boot" => Ok(Self::Boot),
            _ => Err(Error::Invalid),
        }
    }
}

/// Result of checking the root-managed install path for a public identity pin.
/// `Missing` is distinct from `NotManaged`: callers starting the protected
/// system image must fail closed when its projection has not been published.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdminHostIdentityLookup {
    NotManaged,
    Missing,
    Present(AdminHostIdentityBinding),
}

/// Root-published, read-only identity pin for an administrator-managed Host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminHostIdentityBinding {
    account_uid: u32,
    account: String,
    profile: PathBuf,
    mode: AdminHostMode,
    host_id: HostId,
    profile_id: IpcProfileId,
}

impl AdminHostIdentityBinding {
    pub fn account_uid(&self) -> u32 {
        self.account_uid
    }

    pub fn account(&self) -> &str {
        &self.account
    }

    pub fn profile(&self) -> &Path {
        &self.profile
    }

    pub fn mode(&self) -> AdminHostMode {
        self.mode
    }

    pub fn host_id(&self) -> HostId {
        self.host_id
    }

    pub fn profile_id(&self) -> IpcProfileId {
        self.profile_id
    }
}

/// Prior custodian state retained while an administrator-managed release is
/// replaced or rolled back under the selected account's service barrier.
pub struct AdminHostCustodyMaintenanceState(custody_lifecycle::MaintenanceState);

pub fn begin_admin_host_custody_maintenance(
    guard: &BootMaintenanceGuard,
) -> Result<AdminHostCustodyMaintenanceState> {
    custody_lifecycle::begin_maintenance(guard).map(AdminHostCustodyMaintenanceState)
}

pub fn finish_admin_host_custody_maintenance(
    guard: &BootMaintenanceGuard,
    state: AdminHostCustodyMaintenanceState,
) -> Result<()> {
    custody_lifecycle::finish_maintenance(guard, state.0)
}

pub fn uninstall_admin_host_custodian(guard: &BootMaintenanceGuard) -> Result<()> {
    custody_lifecycle::uninstall(guard)
}

pub fn admin_host_was_running(guard: &BootMaintenanceGuard) -> bool {
    guard.service_was_running()
}

/// Acquire the existing selected-account barrier for manual, Aqua login, or
/// boot Host mode. The guard always binds the same protected per-account CLI.
pub fn acquire_admin_maintenance_guard(
    profile: &Path,
    executable: &Path,
    selected_account: &str,
    mode: AdminHostMode,
    recovery: bool,
    uninstall: bool,
) -> Result<BootMaintenanceGuard> {
    if recovery && uninstall {
        return Err(Error::Invalid);
    }
    boot::acquire_admin_maintenance_guard(
        profile,
        executable,
        selected_account,
        mode,
        recovery,
        uninstall,
    )
}

/// Acquire the selected account's maintenance barrier for a genuinely fresh
/// administrator-managed install. No Host registration is stopped, repaired,
/// or adopted on this path. The activation layer must independently recheck
/// that no stable image or pending activation exists while this guard is held.
pub fn acquire_admin_initial_install_guard(
    profile: &Path,
    executable: &Path,
    selected_account: &str,
    mode: AdminHostMode,
) -> Result<BootMaintenanceGuard> {
    boot::acquire_admin_initial_install_guard(profile, executable, selected_account, mode)
}

/// Look up a protected root-published identity using the current native
/// account and the exact installed CLI path. A protected CLI with no public
/// projection returns `Missing`; ordinary application binaries return
/// `NotManaged`.
pub fn lookup_admin_host_identity_binding(
    profile: &Path,
    executable: &Path,
) -> Result<AdminHostIdentityLookup> {
    boot::lookup_admin_host_identity_binding(profile, executable)
}

/// Read the public identity projection for an explicitly selected native
/// account and exact service binding. Root lifecycle operations use this to
/// refuse new registrations until the updater has published a complete pin.
pub fn read_admin_host_identity_binding(
    profile: &Path,
    executable: &Path,
    selected_account: &str,
    mode: AdminHostMode,
) -> Result<AdminHostIdentityBinding> {
    boot::read_admin_host_identity_binding(profile, executable, selected_account, mode)
}

/// Publish the identity only while the selected account/profile and service
/// maintenance locks remain held. The existing root file may be confirmed,
/// but never rebound to different IDs or account context.
pub fn publish_admin_host_identity_binding(
    guard: &BootMaintenanceGuard,
    host_id: &str,
    profile_id: &str,
) -> Result<()> {
    guard.publish_admin_host_identity_binding(host_id, profile_id)
}

/// Check whether an existing public projection is absent or already names the
/// supplied identity. A different or malformed projection is never adopted.
pub fn verify_admin_host_identity_binding(
    guard: &BootMaintenanceGuard,
    host_id: &str,
    profile_id: &str,
) -> Result<()> {
    guard.verify_admin_host_identity_binding(host_id, profile_id)
}

/// Run an administrator-selected Host lifecycle operation without changing
/// the selected account's UID/GID or Keychain context for Host work.
pub fn run_admin_host(
    profile: &Path,
    executable: &Path,
    operation: &str,
    mode: AdminHostMode,
    selected_account: &str,
) -> Result<String> {
    boot::run_admin_host(profile, executable, operation, mode, selected_account)
}

/// Inspect whether the selected administrator-managed Host is active without
/// formatting the native service observation as user-facing status text.
pub fn inspect_admin_host_active(
    profile: &Path,
    executable: &Path,
    selected_account: &str,
    mode: AdminHostMode,
) -> Result<bool> {
    boot::inspect_admin_host_typed(profile, executable, selected_account, mode)
        .map(|inspection| inspection.active)
}

/// Opaque prior custody state retained while the selected boot service's
/// executable is being replaced or rolled back.
pub struct BootCustodyMaintenanceState(custody_lifecycle::MaintenanceState);

/// Positively drain and stop the root custodian while `guard` retains the
/// selected account owner lock and LaunchDaemon adapter lock.
pub fn begin_boot_custody_maintenance(
    guard: &BootMaintenanceGuard,
) -> Result<BootCustodyMaintenanceState> {
    custody_lifecycle::begin_maintenance(guard).map(BootCustodyMaintenanceState)
}

/// Rebind and restore the root custodian to its prior running state after a
/// verified executable update or rollback.
pub fn finish_boot_custody_maintenance(
    guard: &BootMaintenanceGuard,
    state: BootCustodyMaintenanceState,
) -> Result<()> {
    custody_lifecycle::finish_maintenance(guard, state.0)
}

/// Remove the root custody registration after its broker has positively
/// drained all PTY generations.
pub fn uninstall_boot_custodian(guard: &BootMaintenanceGuard) -> Result<()> {
    custody_lifecycle::uninstall(guard)
}

/// Whether the selected-account Host was running before this maintenance
/// guard stopped it.
pub fn boot_host_was_running(guard: &BootMaintenanceGuard) -> bool {
    guard.service_was_running()
}

/// Resolve the standard profile for an explicitly selected local account.
/// No current-user or environment fallback is used.
pub fn boot_profile_path_for_account(name: &str) -> Result<PathBuf> {
    boot::profile_path_for_account(name)
}

/// Return the per-UID system install directory for an explicitly selected
/// account. The account name is resolved natively; it is not used as a path.
pub fn boot_install_path_for_account(name: &str) -> Result<PathBuf> {
    boot::install_path_for_account(name)
}

/// Validate a selected account's existing private profile without changing it.
pub fn validate_boot_profile(profile: &Path, selected_account: &str) -> Result<(PathBuf, u32)> {
    boot::validate_selected_profile(profile, selected_account)
}

/// Prepare the selected account's standard Host profile from a fresh
/// administrator helper process, then permanently continue as that account.
pub fn prepare_boot_profile_in_helper(selected_account: &str, profile: &Path) -> Result<PathBuf> {
    profile_setup::prepare_boot_profile_in_helper(selected_account, profile)
}

/// Initialize or validate the selected user's Host database through the
/// protected installed CLI. Call only after a first release activation has
/// committed, while retaining the initial-install service guard.
pub fn initialize_admin_host_profile_after_activation(
    guard: &mut BootMaintenanceGuard,
) -> Result<()> {
    guard.initialize_profile_after_activation()
}

/// Resume first-profile initialization only after the updater has verified its
/// exact root-private Pending receipt and active signed release.
pub fn initialize_admin_host_profile_after_pending_activation(
    guard: &mut BootMaintenanceGuard,
) -> Result<()> {
    guard.initialize_profile_after_pending_activation()
}

/// Stop a validated account-owned LaunchDaemon and hold its profile owner lock
/// plus the adapter lock across a privileged updater operation.
pub fn acquire_boot_maintenance_guard(
    profile: &Path,
    executable: &Path,
    selected_account: &str,
) -> Result<BootMaintenanceGuard> {
    boot::acquire_maintenance_guard(profile, executable, selected_account, false, false)
}

/// Acquire the selected-account maintenance barrier while permitting the
/// registered stable executable leaf to be absent during authenticated
/// journal recovery. Existing unsafe leaves still fail validation.
pub fn acquire_boot_recovery_guard(
    profile: &Path,
    executable: &Path,
    selected_account: &str,
) -> Result<BootMaintenanceGuard> {
    boot::acquire_maintenance_guard(profile, executable, selected_account, true, false)
}

/// Acquire the selected-account barrier for an explicit uninstall. A missing
/// LaunchDaemon plist is accepted only when the matching registration is
/// authenticated and its manager job is already absent.
pub fn acquire_boot_uninstall_guard(
    profile: &Path,
    executable: &Path,
    selected_account: &str,
) -> Result<BootMaintenanceGuard> {
    boot::acquire_maintenance_guard(profile, executable, selected_account, false, true)
}

// Pin each parent by descriptor. Refuse symlinks and writable ancestors (even
// sticky directories); subsequent mutations are relative to the pinned parent.
struct Directory(File);
impl Directory {
    fn open(path: &Path, create: bool) -> Result<Self> {
        if !path.is_absolute() {
            return Err(Error::Invalid);
        }
        let mut current = File::open("/").map_err(|_| Error::Invalid)?;
        crate::unix::reject_acl_grants(&current).map_err(|_| Error::Invalid)?;
        for component in path.components().skip(1) {
            let Component::Normal(name) = component else {
                return Err(Error::Invalid);
            };
            let name = c(name)?;
            let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            let mut fd = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags) };
            if fd < 0 && create && io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
                if unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), 0o700) } != 0
                    && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
                {
                    return Err(Error::Invalid);
                }
                fd = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags) };
            }
            if fd < 0 {
                return Err(Error::Invalid);
            }
            let next = unsafe { File::from_raw_fd(fd) };
            let m = next.metadata().map_err(|_| Error::Invalid)?;
            if !m.is_dir() || (m.uid() != uid() && m.uid() != 0) || m.mode() & 0o022 != 0 {
                return Err(Error::Invalid);
            }
            crate::unix::reject_acl_grants(&next).map_err(|_| Error::Invalid)?;
            if create {
                current.sync_all().map_err(|_| Error::Invalid)?;
            }
            current = next;
        }
        Ok(Self(current))
    }
    fn sync(&self) -> Result<()> {
        self.0.sync_all().map_err(|_| Error::Invalid)
    }
    fn regular(&self, name: &str, create: bool) -> Result<Option<File>> {
        let name = c(OsStr::new(name))?;
        let flags = libc::O_RDWR
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | if create { libc::O_CREAT } else { 0 };
        let fd = unsafe { libc::openat(self.0.as_raw_fd(), name.as_ptr(), flags, 0o600) };
        if fd < 0 {
            return if io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(Error::Conflict)
            };
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let m = file.metadata().map_err(|_| Error::Invalid)?;
        if !m.is_file() || m.uid() != uid() || m.nlink() != 1 || m.mode() & 0o777 != 0o600 {
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
    fn read_observed(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let name = c(OsStr::new(name))?;
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return if io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(Error::Conflict)
            };
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(|_| Error::Conflict)?;
        if !metadata.is_file()
            || metadata.uid() != uid()
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(Error::Conflict);
        }
        crate::unix::reject_acl_grants(&file).map_err(|_| Error::Conflict)?;
        let mut bytes = Vec::new();
        (&mut file)
            .take((LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Invalid)?;
        if bytes.len() > LIMIT {
            return Err(Error::Invalid);
        }
        Ok(Some(bytes))
    }
    // Publish only absent files. A concurrent or unrelated existing inode is
    // never overwritten, including a symlink inserted during installation.
    fn publish(&self, name: &str, bytes: &[u8]) -> Result<()> {
        self.publish_at_boundary(name, bytes, || {})
    }
    fn publish_at_boundary(
        &self,
        name: &str,
        bytes: &[u8],
        after_publish: impl FnOnce(),
    ) -> Result<()> {
        let temporary = format!(".lomi-service-{}", uuid::Uuid::new_v4());
        let temp = c(OsStr::new(&temporary))?;
        let destination = c(OsStr::new(name))?;
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                temp.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(Error::Invalid);
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let result = (|| {
            file.write_all(bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| Error::Invalid)?;
            // Atomic publication never exposes a second hard link. A crash
            // after publication leaves a private, readable, nlink=1 record.
            let renamed = unsafe {
                libc::renameatx_np(
                    self.0.as_raw_fd(),
                    temp.as_ptr(),
                    self.0.as_raw_fd(),
                    destination.as_ptr(),
                    libc::RENAME_EXCL,
                )
            };
            if renamed != 0 {
                return Err(Error::Conflict);
            }
            after_publish();
            Ok(())
        })();
        unsafe {
            libc::unlinkat(self.0.as_raw_fd(), temp.as_ptr(), 0);
        }
        self.sync()?;
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
        self.sync()
    }
}

fn install_files(
    profile: &Directory,
    agents: &Directory,
    name: &str,
    record: &[u8],
    plist: &[u8],
    record_exists: bool,
    plist_exists: bool,
) -> Result<()> {
    if !record_exists {
        profile.publish(RECORD, record)?;
    }
    // Retry must durably commit a previously published ownership journal before
    // exposing the autoloadable plist, even after the previous fsync failed.
    profile.sync()?;
    if !plist_exists {
        agents.publish(name, plist)?;
    }
    agents.sync()
}
fn uninstall_files(
    profile: &Directory,
    agents: &Directory,
    name: &str,
    record: &[u8],
    plist: &[u8],
    plist_exists: bool,
) -> Result<()> {
    if plist_exists {
        agents.remove_exact(name, plist)?;
    }
    // Commit an already-absent plist too, before discarding its journal.
    agents.sync()?;
    profile.remove_exact(RECORD, record)
}

// No shell. Both output streams are nonblocking and capped; on failure we kill
// and reap the still-owned Child, never a remembered/reused PID.
fn bounded_result(
    command: &mut Command,
    timeout: Duration,
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
    // Reject inherited auto-reaping and custom reapers before creating children.
    // A library must not reset process-global dispositions behind its caller.
    crate::process::require_child_ownership().map_err(|_| Error::Manager)?;
    let mut child = command
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| Error::Manager)?;
    let mut stdout = child.stdout.take().ok_or(Error::Manager)?;
    let mut stderr = child.stderr.take().ok_or(Error::Manager)?;
    let mut reaped = false;
    let result = (|| {
        for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                return Err(Error::Manager);
            }
        }
        let deadline = Instant::now() + timeout;
        let mut output = Vec::new();
        let mut errors = Vec::new();
        loop {
            for (reader, bytes) in [
                (&mut stdout as &mut dyn Read, &mut output),
                (&mut stderr as &mut dyn Read, &mut errors),
            ] {
                let mut chunk = [0; 4096];
                match reader.read(&mut chunk) {
                    Ok(count) => bytes.extend_from_slice(&chunk[..count]),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => return Err(Error::Manager),
                }
                if bytes.len() > LIMIT {
                    return Err(Error::Manager);
                }
            }
            if let Some(status) = child.try_wait().map_err(|_| Error::Manager)? {
                reaped = true;
                // Drain the capped final bytes after exit.
                for (reader, bytes) in [
                    (&mut stdout as &mut dyn Read, &mut output),
                    (&mut stderr as &mut dyn Read, &mut errors),
                ] {
                    let mut chunk = [0; 4096];
                    loop {
                        match reader.read(&mut chunk) {
                            Ok(0) => break,
                            Ok(count) => {
                                bytes.extend_from_slice(&chunk[..count]);
                                if bytes.len() > LIMIT {
                                    return Err(Error::Manager);
                                }
                            }
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                            Err(_) => return Err(Error::Manager),
                        }
                    }
                }
                return Ok((status, output, errors));
            }
            if Instant::now() >= deadline {
                return Err(Error::Deadline);
            }
            thread::sleep(Duration::from_millis(10));
        }
    })();
    if !reaped {
        // Child alone is not proof after ECHILD: Rust may still cache a PID.
        // Require retained kernel ownership immediately before any signal.
        if crate::process::require_unreaped_child(&child).is_err() {
            return Err(Error::Deadline);
        }
        if result.is_err() {
            child.kill().map_err(|_| Error::Deadline)?;
        }
        // Even post-kill reaping has a deadline. An uninterruptible manager
        // command is an uncertain operation, never an unbounded CLI wait.
        let cleanup_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < cleanup_deadline => {
                    thread::sleep(Duration::from_millis(10))
                }
                _ => return Err(Error::Deadline),
            }
        }
    }
    result
}
pub(super) fn bounded(command: &mut Command, timeout: Duration) -> Result<Option<String>> {
    let (status, output, _) = bounded_result(command, timeout)?;
    if status.success() {
        String::from_utf8(output)
            .map(Some)
            .map_err(|_| Error::Manager)
    } else if status.code() == Some(113) {
        Ok(None)
    } else {
        Err(Error::Manager)
    }
}
fn account() -> Result<String> {
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0u8; 16384];
    let mut result = std::ptr::null_mut();
    if unsafe {
        libc::getpwuid_r(
            uid(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    } != 0
        || result.is_null()
    {
        return Err(Error::Invalid);
    }
    let name = unsafe { std::ffi::CStr::from_ptr(entry.pw_name) }
        .to_str()
        .map_err(|_| Error::Invalid)?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        return Err(Error::Invalid);
    }
    Ok(name.to_owned())
}
fn valid_decimal_uid(value: &str) -> bool {
    value
        .parse::<u32>()
        .is_ok_and(|uid| uid.to_string() == value)
}

fn valid_lomi_label(value: &str) -> bool {
    value
        .strip_prefix("dev.lomi.remote.")
        .is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

/// Only the read-only per-user GUI queries used by this adapter may treat
/// launchctl's translated GUI-domain error 125 as an unavailable domain.
fn gui_query_absence_diagnostic(args: &[&str]) -> Option<&'static [u8]> {
    match args {
        ["print", target] => {
            let target = target.strip_prefix("gui/")?;
            let uid = match target.split_once('/') {
                Some((uid, label)) if valid_lomi_label(label) => uid,
                None => target,
                _ => return None,
            };
            valid_decimal_uid(uid).then_some(
                b"Could not print domain: 125: Domain does not support specified action\n",
            )
        }
        ["print-disabled", domain] => {
            let uid = domain.strip_prefix("gui/")?;
            if valid_decimal_uid(uid) {
                Some(b"Could not print cache: 125: Domain does not support specified action\n")
            } else {
                None
            }
        }
        _ => None,
    }
}

fn classify_manager_result(
    args: &[&str],
    success: bool,
    code: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<Option<String>> {
    if success {
        return String::from_utf8(stdout.to_vec())
            .map(Some)
            .map_err(|_| Error::Manager);
    }
    if code == Some(113) {
        return Ok(None);
    }
    if code == Some(125) && stdout.is_empty() && gui_query_absence_diagnostic(args) == Some(stderr)
    {
        return Ok(None);
    }
    Err(Error::Manager)
}

pub(super) fn manager(args: &[&str]) -> Result<Option<String>> {
    let (status, stdout, stderr) = bounded_result(
        Command::new("/bin/launchctl").args(args).current_dir("/"),
        DEADLINE,
    )?;
    classify_manager_result(args, status.success(), status.code(), &stdout, &stderr)
}
pub(super) fn required(args: &[&str]) -> Result<()> {
    manager(args)?.ok_or(Error::Manager).map(|_| ())
}
// launchctl has no per-label API to erase a persistent override. Default is
// enabled, so never create one. Explicitly disabled labels require the operator
// to enable them outside this adapter; no global reset or database edit.
fn disabled_value(text: &str, label: &str) -> Result<Option<bool>> {
    let text = text.trim();
    if !text.starts_with("disabled services = {") || !text.ends_with('}') {
        return Err(Error::Manager);
    }
    let prefix = format!("\"{label}\" => ");
    let mut found = None;
    for line in text.lines().skip(1) {
        if let Some(value) = line.trim().strip_prefix(&prefix) {
            if found.is_some() {
                return Err(Error::Manager);
            }
            found = Some(match value {
                "enabled" => false,
                "disabled" => true,
                _ => return Err(Error::Manager),
            });
        }
    }
    Ok(found)
}
pub(super) fn disabled_override(domain: &str, label: &str) -> Result<Option<bool>> {
    disabled_value(
        &manager(&["print-disabled", domain])?.ok_or(Error::Manager)?,
        label,
    )
}

/// Query a per-user launchd override while distinguishing a logged-out GUI
/// domain (launchctl's exit-113 result or its exact translated exit-125
/// diagnostic) from malformed output or manager failure. `None` means the
/// domain is unavailable; `Some(None)` means its label has no explicit override.
pub(super) fn available_disabled_override(
    domain: &str,
    label: &str,
) -> Result<Option<Option<bool>>> {
    manager(&["print-disabled", domain])?
        .map(|text| disabled_value(&text, label).map(Some))
        .unwrap_or(Ok(None))
}
pub(super) fn label(profile: &str) -> String {
    let mut hash = 0x6c62272e07bb014262b821756295c58du128;
    for byte in profile.bytes() {
        hash ^= byte as u128;
        hash = hash.wrapping_mul(0x1000000000000000000013b);
    }
    format!("dev.lomi.remote.{hash:032x}")
}
fn xml(value: &str) -> Result<String> {
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(Error::Invalid);
    }
    Ok(value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;"))
}

fn launch_arguments<'a>(executable: &'a str, profile: &'a str) -> [&'a str; 6] {
    [
        executable,
        "--profile-dir",
        profile,
        "daemon",
        "run",
        "--existing-profile",
    ]
}

fn launch_arguments_xml(executable: &str, profile: &str) -> Result<String> {
    launch_arguments(executable, profile)
        .iter()
        .map(|argument| xml(argument).map(|argument| format!("<string>{argument}</string>")))
        .collect::<Result<Vec<_>>>()
        .map(|arguments| arguments.join(""))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Registration {
    pub(super) version: u8,
    pub(super) profile: String,
    pub(super) executable: String,
    pub(super) account: String,
    pub(super) label: String,
    pub(super) directory: String,
    pub(super) mode: String,
}
impl Registration {
    pub(super) fn plist(&self) -> Result<Vec<u8>> {
        let arguments = launch_arguments_xml(&self.executable, &self.profile)?;
        let label = xml(&self.label)?;
        Ok(format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{label}</string>
<key>ProgramArguments</key><array>{arguments}</array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>LimitLoadToSessionType</key><string>Aqua</string>
<key>ExitTimeOut</key><integer>45</integer>
<key>ThrottleInterval</key><integer>2</integer>
<key>Umask</key><integer>63</integer>
<key>StandardOutPath</key><string>/dev/null</string>
<key>StandardErrorPath</key><string>/dev/null</string>
</dict></plist>
"#).into_bytes())
    }
}
// Direct fields only; nested environment maps are ignored, never diagnosed.
fn observation(text: &str, target: &str, path: &str, reg: &Registration) -> Result<Option<u32>> {
    if text.lines().last() != Some("}")
        || text
            .lines()
            .skip(1)
            .any(|line| !line.is_empty() && !line.starts_with('\t') && line != "}")
    {
        return Err(Error::Conflict);
    }
    let mut lines = text.lines();
    if lines.next() != Some(format!("{target} = {{").as_str()) {
        return Err(Error::Conflict);
    }
    let (mut seen_path, mut seen_program, mut seen_args) = (false, false, false);
    let mut pid = None;
    let mut state = None;
    while let Some(line) = lines.next() {
        if line.starts_with("\t\t") {
            continue;
        }
        if let Some(value) = line.strip_prefix("\tpath = ") {
            if seen_path || value != path {
                return Err(Error::Conflict);
            }
            seen_path = true;
        } else if let Some(value) = line.strip_prefix("\tprogram = ") {
            if seen_program || value != reg.executable {
                return Err(Error::Conflict);
            }
            seen_program = true;
        } else if line == "\targuments = {" {
            if seen_args {
                return Err(Error::Conflict);
            }
            seen_args = true;
            for argument in launch_arguments(&reg.executable, &reg.profile) {
                if lines.next() != Some(format!("\t\t{argument}").as_str()) {
                    return Err(Error::Conflict);
                }
            }
            if lines.next() != Some("\t}") {
                return Err(Error::Conflict);
            }
        } else if let Some(value) = line.strip_prefix("\tpid = ") {
            if pid.is_some() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::Conflict);
            }
            let value = value.parse::<u32>().map_err(|_| Error::Conflict)?;
            if value == 0 || value > i32::MAX as u32 {
                return Err(Error::Conflict);
            }
            pid = Some(value);
        } else if let Some(value) = line.strip_prefix("\tstate = ")
            && (!matches!(
                value,
                "running"
                    | "not running"
                    | "waiting"
                    | "spawn scheduled"
                    | "spawning"
                    | "xpcproxy"
                    | "SIGTERMed"
            ) || state.replace(value).is_some())
        {
            return Err(Error::Conflict);
        }
    }
    if !seen_path || !seen_program || !seen_args || state.is_none() {
        return Err(Error::Conflict);
    }
    let running = state == Some("running");
    if (running && pid.is_none())
        || (pid.is_some()
            && !matches!(
                state,
                Some("running" | "spawning" | "xpcproxy" | "SIGTERMed")
            ))
    {
        return Err(Error::Conflict);
    }
    Ok(if running { pid } else { None })
}

#[cfg(test)]
mod launchctl_observation_tests {
    use super::*;

    const EXECUTABLE: &str = "/Applications/Lomi.app/Contents/MacOS/lomi";
    const PROFILE: &str = "/Users/alice/Library/Application Support/Lomi/Profile";
    const LABEL: &str = "dev.lomi.remote.test";
    const VALID_LABEL: &str = "dev.lomi.remote.0123456789abcdef0123456789abcdef";
    const PLIST_PATH: &str = "/Users/alice/Library/LaunchAgents/dev.lomi.remote.test.plist";
    const TARGET: &str = "gui/501/dev.lomi.remote.test";

    fn registration() -> Registration {
        Registration {
            version: 1,
            profile: PROFILE.into(),
            executable: EXECUTABLE.into(),
            account: "alice".into(),
            label: LABEL.into(),
            directory: "/Users/alice/Library/LaunchAgents".into(),
            mode: "login".into(),
        }
    }

    fn running_launchctl_output() -> String {
        format!(
            "{TARGET} = {{\n\
\tactive count = 1\n\
\tpath = {PLIST_PATH}\n\
\ttype = LaunchAgent\n\
\tstate = running\n\
\tprogram = {EXECUTABLE}\n\
\targuments = {{\n\
\t\t{EXECUTABLE}\n\
\t\t--profile-dir\n\
\t\t{PROFILE}\n\
\t\tdaemon\n\
\t\trun\n\
\t\t--existing-profile\n\
\t}}\n\
\tpid = 55784\n\
\tlast exit code = 0\n\
\tproperties = {{\n\
\t\tkeepalive = 1\n\
\t}}\n\
}}"
        )
    }

    fn plist_arguments(plist: &[u8]) -> Vec<String> {
        let text = std::str::from_utf8(plist).unwrap();
        let args = text
            .split_once("<key>ProgramArguments</key><array>")
            .unwrap()
            .1
            .split_once("</array>")
            .unwrap()
            .0;
        args.split("<string>")
            .skip(1)
            .map(|argument| argument.split_once("</string>").unwrap().0.to_owned())
            .collect()
    }

    #[test]
    fn login_plist_and_launchctl_arguments_match_exactly() {
        let reg = registration();
        let expected = launch_arguments(&reg.executable, &reg.profile)
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        assert_eq!(plist_arguments(&reg.plist().unwrap()), expected);
        assert_eq!(
            observation(&running_launchctl_output(), TARGET, PLIST_PATH, &reg),
            Ok(Some(55784))
        );
    }

    #[test]
    fn login_observation_rejects_nonmatching_argument_vectors() {
        let reg = registration();
        let fixture = running_launchctl_output();
        let cases = [
            fixture.replace("\t\t--existing-profile\n", ""),
            fixture.replace(
                PROFILE,
                "/Users/alice/Library/Application Support/Lomi/Other",
            ),
            fixture.replace("\t\trun\n", "\t\trun\n\t\t--verbose\n"),
            fixture.replacen(
                &format!("\t\t{EXECUTABLE}\n"),
                "\t\t/Applications/Other.app/Contents/MacOS/lomi\n",
                1,
            ),
            fixture.replace(
                &format!("\tprogram = {EXECUTABLE}\n"),
                "\tprogram = /Applications/Other.app/Contents/MacOS/lomi\n",
            ),
        ];
        for output in cases {
            assert_eq!(
                observation(&output, TARGET, PLIST_PATH, &reg),
                Err(Error::Conflict)
            );
        }
    }

    #[test]
    fn sigtermed_login_job_with_retained_pid_is_not_ready() {
        let reg = registration();
        let output = running_launchctl_output().replace("state = running", "state = SIGTERMed");
        assert_eq!(
            observe_manager_output(Some(output), TARGET, PLIST_PATH, &reg),
            Ok(Some(None))
        );
        assert_eq!(
            observe_manager_output(None, TARGET, PLIST_PATH, &reg),
            Ok(None)
        );
    }

    #[test]
    fn spawning_login_job_with_optional_pid_is_present_but_not_ready() {
        let reg = registration();
        for output in [
            running_launchctl_output().replace("state = running", "state = spawning"),
            running_launchctl_output()
                .replace("state = running", "state = spawning")
                .replace("\tpid = 55784\n", ""),
        ] {
            assert_eq!(
                observe_manager_output(Some(output), TARGET, PLIST_PATH, &reg),
                Ok(Some(None))
            );
        }
    }

    #[test]
    fn xpcproxy_login_job_with_observed_pid_is_present_but_not_ready() {
        let reg = registration();
        let fixture = running_launchctl_output();
        for output in [
            fixture
                .replace("state = running", "state = xpcproxy")
                .replace("pid = 55784", "pid = 22359"),
            fixture
                .replace("state = running", "state = xpcproxy")
                .replace("\tpid = 55784\n", ""),
        ] {
            assert_eq!(
                observe_manager_output(Some(output), TARGET, PLIST_PATH, &reg),
                Ok(Some(None))
            );
        }
    }

    #[test]
    fn login_observation_rejects_other_nonrunning_and_invalid_pids() {
        let reg = registration();
        let fixture = running_launchctl_output();
        let cases = [
            fixture.replace("state = running", "state = waiting"),
            fixture.replace("state = running", "state = new-launchd-state"),
            fixture.replace("pid = 55784", "pid = 0"),
            fixture.replace(
                "\tlast exit code = 0",
                "\tpid = 55785\n\tlast exit code = 0",
            ),
            fixture.replace("\tpid = 55784\n", ""),
        ];
        for output in cases {
            assert!(matches!(
                observation(&output, TARGET, PLIST_PATH, &reg),
                Err(Error::Conflict)
            ));
        }
    }

    #[test]
    fn manager_accepts_exact_gui_domain_unavailable_diagnostics() {
        let print_diagnostic =
            b"Could not print domain: 125: Domain does not support specified action\n";
        let cache_diagnostic =
            b"Could not print cache: 125: Domain does not support specified action\n";

        assert_eq!(
            classify_manager_result(
                &["print", "gui/503"],
                false,
                Some(125),
                b"",
                print_diagnostic,
            ),
            Ok(None)
        );
        assert_eq!(
            classify_manager_result(
                &["print", &format!("gui/503/{VALID_LABEL}")],
                false,
                Some(125),
                b"",
                print_diagnostic,
            ),
            Ok(None)
        );
        assert_eq!(
            classify_manager_result(
                &["print-disabled", "gui/503"],
                false,
                Some(125),
                b"",
                cache_diagnostic,
            ),
            Ok(None)
        );
    }

    #[test]
    fn manager_keeps_exit_113_and_rejects_other_exit_125_results() {
        assert_eq!(
            classify_manager_result(&["print", "system"], false, Some(113), b"", b""),
            Ok(None)
        );

        let print_diagnostic =
            b"Could not print domain: 125: Domain does not support specified action\n";
        let cache_diagnostic =
            b"Could not print cache: 125: Domain does not support specified action\n";
        let cases: &[(&[&str], &[u8], &[u8], i32)] = &[
            // Read-only diagnostics for unrelated launchctl domains stay strict.
            (&["print", "system"], b"", print_diagnostic, 125),
            (&["print", "user/503"], b"", print_diagnostic, 125),
            (&["print-disabled", "system"], b"", cache_diagnostic, 125),
            // Mutating commands are never treated as domain absence.
            (
                &["bootstrap", "system", "/tmp/job.plist"],
                b"",
                print_diagnostic,
                125,
            ),
            // A valid query must also have exact streams and exact diagnostics.
            (&["print", "gui/503"], b"unexpected", print_diagnostic, 125),
            (
                &["print", "gui/503"],
                b"",
                b"Could not print domain: 125",
                125,
            ),
            (
                &["print", "gui/503"],
                b"",
                b"Could not print cache: 125: Domain does not support specified action\n",
                125,
            ),
            (
                &["print", "gui/503/dev.lomi.remote.invalid"],
                b"",
                print_diagnostic,
                125,
            ),
            // Permission errors remain manager failures even for a valid GUI query.
            (&["print", "gui/503"], b"", print_diagnostic, 1),
        ];
        for (args, stdout, stderr, code) in cases {
            assert_eq!(
                classify_manager_result(args, false, Some(*code), stdout, stderr),
                Err(Error::Manager),
                "unexpected result for launchctl arguments {args:?}"
            );
        }
    }
}
pub(super) fn observe(target: &str, path: &str, reg: &Registration) -> Result<Option<Option<u32>>> {
    observe_manager_output(manager(&["print", target])?, target, path, reg)
}

fn observe_manager_output(
    output: Option<String>,
    target: &str,
    path: &str,
    reg: &Registration,
) -> Result<Option<Option<u32>>> {
    output
        .map(|text| observation(&text, target, path, reg))
        .transpose()
}
fn ready(profile: &Path, expected: u32) -> bool {
    LocalClient::connect_with_timeout(profile, Duration::from_millis(200))
        .and_then(|mut client| {
            if client.service_peer_pid()? != expected {
                return Err(crate::unix::Error::PermissionDenied);
            }
            client.request(LocalCall::Status {})
        })
        .is_ok_and(|response| matches!(response.result, Ok(LocalResult::Status(_))))
}

fn unix_identity(uid: u32) -> Result<(String, u32, PathBuf)> {
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0u8; 16384];
    let mut result = std::ptr::null_mut();
    if unsafe {
        libc::getpwuid_r(
            uid,
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    } != 0
        || result.is_null()
    {
        return Err(Error::Invalid);
    }
    let name = unsafe { std::ffi::CStr::from_ptr(entry.pw_name) }
        .to_str()
        .map_err(|_| Error::Invalid)?;
    let home = unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) }
        .to_str()
        .map_err(|_| Error::Invalid)?;
    if name.is_empty()
        || name.len() > 255
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        || !Path::new(home).is_absolute()
    {
        return Err(Error::Invalid);
    }
    Ok((name.to_owned(), entry.pw_gid, PathBuf::from(home)))
}

pub(crate) fn current_service_account() -> std::result::Result<
    crate::service_observation::ServiceAccount,
    crate::service_observation::ServiceError,
> {
    let effective_uid = unsafe { libc::geteuid() };
    let effective_gid = unsafe { libc::getegid() };
    if unsafe { libc::getuid() } != effective_uid {
        return Err(crate::service_observation::ServiceError::Conflict);
    }
    let (name, account_gid, _) = unix_identity(effective_uid).map_err(service_observation_error)?;
    if account_gid != effective_gid {
        return Err(crate::service_observation::ServiceError::Conflict);
    }
    Ok(crate::service_observation::ServiceAccount::Unix {
        uid: effective_uid,
        gid: effective_gid,
        name,
    })
}

pub(crate) fn discover_service_mode(
    profile: &Path,
    installed_executable: &Path,
) -> std::result::Result<
    Option<crate::service_observation::ServiceMode>,
    crate::service_observation::ServiceError,
> {
    use crate::service_observation::{ServiceError, ServiceMode};
    let profile = std::path::absolute(profile).map_err(|_| ServiceError::InvalidBinding)?;
    let profile_text = profile.to_str().ok_or(ServiceError::InvalidBinding)?;
    match fs::symlink_metadata(&profile) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ServiceError::Conflict),
        Ok(_) => {}
    }
    let directory = Directory::open(&profile, false).map_err(|_| ServiceError::Conflict)?;
    let metadata = directory.0.metadata().map_err(|_| ServiceError::Conflict)?;
    if metadata.uid() != uid() || metadata.mode() & 0o777 != 0o700 {
        return Err(ServiceError::Conflict);
    }
    let Some(bytes) = directory
        .read_observed(RECORD)
        .map_err(|_| ServiceError::Conflict)?
    else {
        return Ok(None);
    };
    let registration: Registration =
        serde_json::from_slice(&bytes).map_err(|_| ServiceError::Conflict)?;
    let canonical_name = account().map_err(service_observation_error)?;
    let (_, _, home) = unix_identity(uid()).map_err(service_observation_error)?;
    let expected_directory = match registration.mode.as_str() {
        "login" => home.join("Library/LaunchAgents"),
        "boot" => PathBuf::from(boot::LAUNCH_DAEMONS),
        _ => return Err(ServiceError::Conflict),
    };
    if registration.version != 1
        || registration.profile != profile_text
        || registration.executable
            != installed_executable
                .to_str()
                .ok_or(ServiceError::InvalidBinding)?
        || registration.account != canonical_name
        || registration.label != label(profile_text)
        || registration.directory
            != expected_directory
                .to_str()
                .ok_or(ServiceError::InvalidBinding)?
    {
        return Err(ServiceError::Conflict);
    }
    match registration.mode.as_str() {
        "login" => Ok(Some(ServiceMode::Login)),
        "boot" => Ok(Some(ServiceMode::Boot)),
        _ => Err(ServiceError::Conflict),
    }
}

fn validate_observed_executable(executable: &Path) -> Result<()> {
    if !executable.is_absolute() {
        return Err(Error::Invalid);
    }
    Directory::open(executable.parent().ok_or(Error::Invalid)?, false)?;
    let fd = unsafe {
        libc::open(
            c(executable.as_os_str())?.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(Error::Invalid);
    }
    let file = unsafe { File::from_raw_fd(fd) };
    crate::unix::reject_acl_grants(&file).map_err(|_| Error::Conflict)?;
    let metadata = file.metadata().map_err(|_| Error::Invalid)?;
    if !metadata.is_file()
        || (metadata.uid() != uid() && metadata.uid() != 0)
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn service_observation_error(error: Error) -> crate::service_observation::ServiceError {
    use crate::service_observation::ServiceError as PublicError;
    match error {
        Error::Invalid => PublicError::InvalidBinding,
        Error::Conflict => PublicError::Conflict,
        Error::Manager => PublicError::ManagerUnavailable,
        Error::Unavailable => PublicError::ManagerUnavailable,
        Error::Deadline => PublicError::OperationUncertain,
        Error::NotReady => PublicError::NotReady,
        Error::Disabled => PublicError::Unsupported,
        Error::AdministratorRequired => PublicError::AdministratorRequired,
        Error::Unimplemented => PublicError::Unsupported,
    }
}

pub(crate) fn inspect_read_only(
    binding: &crate::service_observation::ServiceBinding,
) -> std::result::Result<
    crate::service_observation::ServiceObservation,
    crate::service_observation::ServiceError,
> {
    use crate::service_observation::{
        AutostartState, BindingState, IpcReadiness, RegistrationState, RuntimeState,
        ServiceAccount, ServiceError as PublicError, ServiceMode, ServiceObservation,
    };

    let ServiceAccount::Unix {
        uid: selected_uid,
        gid: selected_gid,
        name,
    } = &binding.account
    else {
        return Err(PublicError::InvalidBinding);
    };
    let (canonical_name, actual_gid, home) =
        unix_identity(*selected_uid).map_err(service_observation_error)?;
    if canonical_name != *name || actual_gid != *selected_gid || *selected_uid == 0 {
        return Err(PublicError::Conflict);
    }
    if uid() == 0 {
        let mode = match binding.mode {
            ServiceMode::Manual => AdminHostMode::Manual,
            ServiceMode::Login => AdminHostMode::Login,
            ServiceMode::Boot => AdminHostMode::Boot,
        };
        let inspection = boot::inspect_admin_host_typed(
            &binding.profile,
            &binding.executable,
            &canonical_name,
            mode,
        )
        .map_err(service_observation_error)?;
        return Ok(ServiceObservation {
            binding: BindingState::Matches,
            registration: match inspection.registration {
                boot::AdminRegistrationState::Missing => RegistrationState::Missing,
                boot::AdminRegistrationState::Present
                | boot::AdminRegistrationState::CleanupPending => RegistrationState::Present,
            },
            runtime: if inspection.active {
                RuntimeState::Running
            } else {
                RuntimeState::Stopped
            },
            autostart: match inspection.autostart {
                boot::AdminAutostartState::Enabled => AutostartState::Enabled,
                boot::AdminAutostartState::Disabled | boot::AdminAutostartState::None => {
                    AutostartState::Disabled
                }
                boot::AdminAutostartState::Unknown => AutostartState::Unknown,
            },
            ipc: if inspection.ipc_ready {
                IpcReadiness::Ready
            } else if inspection.active {
                IpcReadiness::NotReady
            } else {
                IpcReadiness::NotReady
            },
        });
    }
    if *selected_uid != uid() || *selected_gid != unsafe { libc::getegid() } {
        return Err(PublicError::Conflict);
    }
    if binding.mode == ServiceMode::Boot {
        let inspection = match boot::inspect_boot_host_public(
            &binding.profile,
            &binding.executable,
            &canonical_name,
        ) {
            Ok(Some(inspection)) => inspection,
            Ok(None) | Err(Error::Unavailable) => {
                return Ok(ServiceObservation {
                    binding: BindingState::Matches,
                    registration: RegistrationState::Unavailable,
                    runtime: RuntimeState::Unknown,
                    autostart: AutostartState::Unknown,
                    ipc: IpcReadiness::Unknown,
                });
            }
            Err(error) => return Err(service_observation_error(error)),
        };
        return Ok(ServiceObservation {
            binding: BindingState::Matches,
            registration: match inspection.registration {
                boot::AdminRegistrationState::Missing => RegistrationState::Missing,
                boot::AdminRegistrationState::Present
                | boot::AdminRegistrationState::CleanupPending => RegistrationState::Present,
            },
            runtime: if inspection.active {
                RuntimeState::Running
            } else {
                RuntimeState::Stopped
            },
            autostart: match inspection.autostart {
                boot::AdminAutostartState::Enabled => AutostartState::Enabled,
                boot::AdminAutostartState::Disabled | boot::AdminAutostartState::None => {
                    AutostartState::Disabled
                }
                boot::AdminAutostartState::Unknown => AutostartState::Unknown,
            },
            ipc: if inspection.ipc_ready {
                IpcReadiness::Ready
            } else {
                IpcReadiness::NotReady
            },
        });
    }
    let profile_text = binding
        .profile
        .to_str()
        .ok_or(PublicError::InvalidBinding)?;
    let executable_text = binding
        .executable
        .to_str()
        .ok_or(PublicError::InvalidBinding)?;
    validate_observed_executable(&binding.executable).map_err(service_observation_error)?;
    if let Err(error) = boot::ensure_no_public_boot_registration(
        &binding.profile,
        &binding.executable,
        &canonical_name,
    ) {
        if error == Error::Unavailable {
            return Ok(ServiceObservation {
                binding: BindingState::Matches,
                registration: RegistrationState::Unavailable,
                runtime: RuntimeState::Unknown,
                autostart: AutostartState::Unknown,
                ipc: IpcReadiness::Unknown,
            });
        }
        return Err(service_observation_error(error));
    }
    let profile_dir =
        Directory::open(&binding.profile, false).map_err(|_| PublicError::Conflict)?;
    let profile_metadata = profile_dir
        .0
        .metadata()
        .map_err(|_| PublicError::Conflict)?;
    if profile_metadata.uid() != uid() || profile_metadata.mode() & 0o777 != 0o700 {
        return Err(PublicError::Conflict);
    }
    let existing = profile_dir
        .read_observed(RECORD)
        .map_err(|_| PublicError::Conflict)?;
    let directory_path = home.join("Library/LaunchAgents");
    let directory_text = directory_path.to_str().ok_or(PublicError::InvalidBinding)?;
    let expected = Registration {
        version: 1,
        profile: profile_text.to_owned(),
        executable: executable_text.to_owned(),
        account: canonical_name.clone(),
        label: label(profile_text),
        directory: directory_text.to_owned(),
        mode: "login".to_owned(),
    };
    let plist_name = format!("{}.plist", expected.label);
    let plist_path = directory_path.join(&plist_name);
    let agents = match fs::symlink_metadata(&directory_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) => return Err(PublicError::Conflict),
        Ok(_) => Some(Directory::open(&directory_path, false).map_err(|_| PublicError::Conflict)?),
    };
    let plist = agents
        .as_ref()
        .map(|directory| directory.read_observed(&plist_name))
        .transpose()
        .map_err(|_| PublicError::Conflict)?
        .flatten();
    let manager = observe(
        &format!("gui/{}/{}", *selected_uid, expected.label),
        plist_path.to_str().ok_or(PublicError::InvalidBinding)?,
        &expected,
    )
    .map_err(service_observation_error)?;
    let Some(bytes) = existing else {
        if plist.is_some() || manager.is_some() {
            return Err(PublicError::Conflict);
        }
        if binding.mode == ServiceMode::Manual {
            return Ok(ServiceObservation {
                binding: BindingState::Matches,
                registration: RegistrationState::Missing,
                runtime: RuntimeState::Unknown,
                autostart: AutostartState::Disabled,
                ipc: IpcReadiness::Unknown,
            });
        }
        return Ok(ServiceObservation {
            binding: BindingState::Matches,
            registration: RegistrationState::Missing,
            runtime: RuntimeState::Unknown,
            autostart: AutostartState::Disabled,
            ipc: IpcReadiness::Unknown,
        });
    };
    let registration: Registration =
        serde_json::from_slice(&bytes).map_err(|_| PublicError::Conflict)?;
    if registration.version != 1
        || registration.profile != profile_text
        || registration.executable != executable_text
        || registration.account != canonical_name
        || registration.label != expected.label
        || registration.directory != directory_text
        || registration.mode != "login"
        || binding.mode != ServiceMode::Login
        || registration.plist().map_err(|_| PublicError::Conflict)?
            != plist.as_deref().unwrap_or_default()
    {
        return Err(PublicError::Conflict);
    }
    let pid = manager.flatten();
    let disabled =
        available_disabled_override(&format!("gui/{}", *selected_uid), &registration.label)
            .map_err(service_observation_error)?;
    let autostart = match disabled {
        Some(Some(true)) => AutostartState::Disabled,
        Some(Some(false)) | Some(None) => AutostartState::Enabled,
        None => AutostartState::Unknown,
    };
    let ipc_ready = pid.is_some_and(|pid| ready(&binding.profile, pid));
    Ok(ServiceObservation {
        binding: BindingState::Matches,
        registration: RegistrationState::Present,
        runtime: if pid.is_some() {
            RuntimeState::Running
        } else {
            RuntimeState::Unknown
        },
        autostart,
        ipc: if ipc_ready {
            IpcReadiness::Ready
        } else {
            IpcReadiness::Unknown
        },
    })
}

pub(crate) fn control_exact(
    binding: &crate::service_observation::ServiceBinding,
    action: crate::service_observation::ServiceAction,
) -> std::result::Result<(), crate::service_observation::ServiceError> {
    use crate::service_observation::{ServiceAccount, ServiceAction, ServiceError, ServiceMode};
    let ServiceAccount::Unix {
        uid: selected_uid,
        gid: selected_gid,
        name,
    } = &binding.account
    else {
        return Err(ServiceError::InvalidBinding);
    };
    let (canonical_name, actual_gid, _) =
        unix_identity(*selected_uid).map_err(service_observation_error)?;
    if canonical_name != *name || actual_gid != *selected_gid || *selected_uid == 0 {
        return Err(ServiceError::Conflict);
    }
    let operation = match action {
        ServiceAction::Install => "install",
        ServiceAction::Start => "start",
        ServiceAction::Stop => "stop",
        ServiceAction::Restart => "restart",
        ServiceAction::Uninstall => "uninstall",
    };
    if uid() == 0 && *selected_uid != 0 {
        let mode = match binding.mode {
            ServiceMode::Manual => AdminHostMode::Manual,
            ServiceMode::Login => AdminHostMode::Login,
            ServiceMode::Boot => AdminHostMode::Boot,
        };
        run_admin_host(&binding.profile, &binding.executable, operation, mode, name)
            .map(|_| ())
            .map_err(service_observation_error)
    } else {
        if *selected_uid != uid() || *selected_gid != unsafe { libc::getegid() } {
            return Err(ServiceError::Conflict);
        }
        run(
            &binding.profile,
            &binding.executable,
            operation,
            Some(binding.mode.as_str()),
            Some(name),
        )
        .map(|_| ())
        .map_err(service_observation_error)
    }
}

/// Internal readiness helper for the privileged boot adapter. The caller must
/// already have dropped to the selected account; LocalClient intentionally
/// authenticates the connected process as its effective UID.
pub fn internal_host_status(profile: &Path, expected_pid: u32) -> i32 {
    if uid() == 0 || expected_pid == 0 || expected_pid > i32::MAX as u32 {
        return 1;
    }
    let response = match LocalClient::connect_with_timeout(profile, Duration::from_secs(3))
        .and_then(|mut client| {
            if client.service_peer_pid()? != expected_pid {
                return Err(crate::unix::Error::PermissionDenied);
            }
            client.request(LocalCall::Status {})
        }) {
        Ok(response)
            if response.version == LocalIpcVersion::CURRENT
                && matches!(response.result, Ok(LocalResult::Status(_))) =>
        {
            response
        }
        _ => return 1,
    };
    let mut stdout = io::stdout().lock();
    if serde_json::to_writer(&mut stdout, &response).is_err()
        || stdout.write_all(b"\n").is_err()
        || stdout.flush().is_err()
    {
        return 1;
    }
    0
}
fn await_cleanup(profile: &Path, mut manual: Option<LocalClient>, deadline: Instant) -> Result<()> {
    loop {
        match OwnerLock::acquire(profile) {
            Ok(owner) => {
                drop(owner);
                return Ok(());
            }
            Err(crate::unix::Error::Busy) => {}
            Err(_) => return Err(Error::Conflict),
        }
        // Only the SAME authenticated connection proven outside the loaded job
        // before bootout may exempt a busy lock. A different runtime could be a
        // new managed generation; failed hello/EOF always remains uncertain.
        if let Some(client) = &mut manual {
            if client
                .request(LocalCall::Status {})
                .is_ok_and(|r| matches!(r.result, Ok(LocalResult::Status(_))))
            {
                return Ok(());
            }
            manual = None;
        }
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        thread::sleep(Duration::from_millis(25));
    }
}
fn stop(profile: &Path, target: &str, path: &str, reg: &Registration) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(48);
    let before = observe(target, path, reg)?;
    // Holding a free lifetime lock prevents a waiting job acquiring this profile
    // between the initial no-PID observation and launchd accepting bootout.
    let free = match OwnerLock::acquire(profile) {
        Ok(owner) => Some(owner),
        Err(crate::unix::Error::Busy) => None,
        Err(_) => return Err(Error::Conflict),
    };
    let mut manual = None;
    if free.is_none()
        && before.is_some()
        && let Ok(mut client) =
            LocalClient::connect_with_timeout(profile, Duration::from_millis(200))
        && let Ok(peer) = client.service_peer_pid()
    {
        // A fresh manager conflict/unavailability must abort before bootout.
        if let Some(current) = observe(target, path, reg)?
            && current != Some(peer)
            && client
                .request(LocalCall::Status {})
                .is_ok_and(|r| matches!(r.result, Ok(LocalResult::Status(_))))
        {
            manual = Some(client);
        }
    }
    if before.is_some() {
        required(&["bootout", target])?;
    }
    while observe(target, path, reg)?.is_some() {
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        thread::sleep(Duration::from_millis(25));
    }
    if let Some(owner) = free {
        drop(owner);
        return Ok(());
    }
    // This is required even when neither observation had a PID, and when a
    // retry observes no job after a previous interrupted bootout.
    await_cleanup(profile, manual, deadline)
}
/// Explicit current-user Aqua login registration only. No before-login or
/// logout/session-escape qualification is implied by this adapter.
pub fn run(
    profile: &Path,
    executable: &Path,
    operation: &str,
    mode: Option<&str>,
    selected_account: Option<&str>,
) -> Result<String> {
    if !matches!(
        operation,
        "install" | "uninstall" | "start" | "restart" | "stop" | "status"
    ) {
        return Err(Error::Invalid);
    }
    // The account-owned profile cannot reveal its root-private mode binding.
    // Do not reinterpret an administrator-installed Manual/Login Host through
    // the legacy per-user LaunchAgent adapter. Root operations validate the
    // existing binding before changing registration or service state.
    if uid() != 0
        && operation != "status"
        && executable
            == Path::new("/Library/Application Support/LomiRemote/Install")
                .join(uid().to_string())
                .join("lomiremote")
    {
        return Err(Error::AdministratorRequired);
    }
    if mode == Some("boot") || boot::is_boot_registration(profile)? {
        return boot::run(profile, executable, operation, mode, selected_account);
    }
    if mode == Some("manual") {
        // Manual mode is an explicit administrator-managed choice. Ordinary
        // per-user service commands must not reinterpret it as an Aqua agent.
        return Err(Error::Unimplemented);
    }
    crate::process::require_child_ownership().map_err(|_| Error::Manager)?;
    if operation == "install" {
        if mode.is_none() || selected_account.is_none() {
            return Err(Error::Invalid);
        }
        if mode != Some("login")
            || ![uid().to_string(), account()?]
                .iter()
                .any(|a| Some(a.as_str()) == selected_account)
        {
            return Err(Error::Unimplemented);
        }
    }
    let profile = std::path::absolute(profile).map_err(|_| Error::Invalid)?;
    if profile
        .components()
        .any(|p| !matches!(p, Component::RootDir | Component::Normal(_)))
    {
        return Err(Error::Invalid);
    }
    let profile_text = profile.to_str().ok_or(Error::Invalid)?;
    xml(profile_text)?;
    if operation == "install" {
        drop(OwnerLock::acquire(&profile).map_err(|_| Error::Conflict)?);
    }
    let profile_dir = Directory::open(&profile, operation == "install")?;
    let m = profile_dir.0.metadata().map_err(|_| Error::Invalid)?;
    if m.uid() != uid() || m.mode() & 0o777 != 0o700 {
        return Err(Error::Invalid);
    }
    let lock = profile_dir
        .regular("service-macos.lock", true)?
        .ok_or(Error::Invalid)?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(Error::Conflict);
    }
    // Account database, not environment HOME, selects standard login location.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0u8; 16384];
    let mut result = std::ptr::null_mut();
    if unsafe {
        libc::getpwuid_r(
            uid(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    } != 0
        || result.is_null()
    {
        return Err(Error::Invalid);
    }
    let home = unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) }
        .to_str()
        .map_err(|_| Error::Invalid)?;
    let directory = Path::new(home).join("Library/LaunchAgents");
    let directory_text = directory.to_str().ok_or(Error::Invalid)?;
    let existing = profile_dir.read(RECORD)?;
    if existing.is_none() && operation == "uninstall" {
        profile_dir.sync()?;
        return Ok("No profile-owned service registration; profile files preserved.".into());
    }
    let reg = if let Some(bytes) = &existing {
        let reg: Registration = serde_json::from_slice(bytes).map_err(|_| Error::Conflict)?;
        if reg.version != 1
            || reg.profile != profile_text
            || reg.label != label(profile_text)
            || reg.directory != directory_text
            || reg.account != account()?
            || reg.mode != "login"
            || !Path::new(&reg.executable).is_absolute()
        {
            return Err(Error::Conflict);
        }
        if operation == "install" && executable.to_str() != Some(&reg.executable) {
            return Err(Error::Conflict);
        }
        reg
    } else {
        if operation != "install" || !executable.is_absolute() {
            return Err(Error::Conflict);
        }
        Directory::open(executable.parent().ok_or(Error::Invalid)?, false)?;
        let fd = unsafe {
            libc::open(
                c(executable.as_os_str())?.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(Error::Invalid);
        }
        let executable_file = unsafe { File::from_raw_fd(fd) };
        crate::unix::reject_acl_grants(&executable_file).map_err(|_| Error::Invalid)?;
        let m = executable_file.metadata().map_err(|_| Error::Invalid)?;
        if !m.is_file()
            || (m.uid() != uid() && m.uid() != 0)
            || m.mode() & 0o022 != 0
            || m.mode() & 0o111 == 0
        {
            return Err(Error::Invalid);
        }
        Registration {
            version: 1,
            profile: profile_text.into(),
            executable: executable.to_str().ok_or(Error::Invalid)?.into(),
            account: account()?,
            label: label(profile_text),
            directory: directory_text.into(),
            mode: "login".into(),
        }
    };
    let expected = reg.plist()?;
    let agents = Directory::open(&directory, operation == "install")?;
    let name = format!("{}.plist", reg.label);
    let path = directory.join(&name);
    let path = path.to_str().ok_or(Error::Invalid)?;
    let domain = format!("gui/{}", uid());
    let target = format!("{domain}/{}", reg.label);
    let current = agents.read(&name)?;
    if let Some(bytes) = &current
        && (bytes != &expected || existing.is_none())
    {
        return Err(Error::Conflict);
    }
    let disabled = disabled_override(&domain, &reg.label)?;
    if matches!(operation, "install" | "start" | "restart") && disabled == Some(true) {
        return Err(Error::Disabled);
    }
    if operation == "install" {
        if existing.is_some() {
            observe(&target, path, &reg)?;
        }
        if existing.is_none() && manager(&["print", &target])?.is_some() {
            return Err(Error::Conflict);
        }
        install_files(
            &profile_dir,
            &agents,
            &name,
            &serde_json::to_vec(&reg).map_err(|_| Error::Invalid)?,
            &expected,
            existing.is_some(),
            current.is_some(),
        )?;
        return Ok(format!(
            "Service installed; account={} mode=login enabled=true (not started)",
            reg.account
        ));
    }
    if current.is_none() && operation != "uninstall" {
        return Err(Error::Conflict);
    }
    let observed = observe(&target, path, &reg)?;
    match operation {
        "status" => Ok(format!(
            "Service: {}\nAccount: {}\nMode: login\nAutostart: {}\nActive: {}\nIPC ready: {}",
            reg.label,
            reg.account,
            if disabled == Some(true) {
                "disabled"
            } else {
                "enabled"
            },
            if observed.flatten().is_some() {
                "active"
            } else {
                "inactive"
            },
            observed.flatten().is_some_and(|pid| ready(&profile, pid))
        )),
        "start" | "restart" => {
            if operation == "restart" {
                stop(&profile, &target, path, &reg)?;
            }
            let now = observe(&target, path, &reg)?;
            if now.flatten().is_none() {
                drop(OwnerLock::acquire(&profile).map_err(|_| Error::Conflict)?);
            }
            if now.is_none() {
                required(&["bootstrap", &domain, path])?;
            } else if now.flatten().is_none() {
                required(&["kickstart", &target])?;
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if observe(&target, path, &reg)?
                    .flatten()
                    .is_some_and(|pid| ready(&profile, pid))
                {
                    return Ok("Service ready.".into());
                }
                if Instant::now() >= deadline {
                    return Err(Error::NotReady);
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
        "stop" | "uninstall" => {
            stop(&profile, &target, path, &reg)?;
            if operation == "uninstall" {
                uninstall_files(
                    &profile_dir,
                    &agents,
                    &name,
                    existing.as_deref().ok_or(Error::Conflict)?,
                    &expected,
                    current.is_some(),
                )?;
                Ok("Service uninstalled; profile and workspace files preserved.".into())
            } else {
                Ok("Service stopped.".into())
            }
        }
        _ => Err(Error::Invalid),
    }
}
