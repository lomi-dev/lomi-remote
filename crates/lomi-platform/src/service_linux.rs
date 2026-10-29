//! Current-account systemd user registration. Does not enroll or share a host.
#[cfg(target_os = "linux")]
use crate::unix::LocalClient;
use crate::unix::OwnerLock;
#[cfg(target_os = "linux")]
use lomi_remote_protocol::ipc::{LocalCall, LocalResult};
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
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const LIMIT: usize = 32 * 1024;
const DEADLINE: Duration = Duration::from_secs(55);
const RECORD: &str = "service-registration.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Conflict,
    Manager,
    Deadline,
    NotReady,
    LingerRequired,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "SERVICE_INVALID_CONFIGURATION",
            Self::Conflict => "SERVICE_OWNERSHIP_CONFLICT",
            Self::Manager => "SERVICE_MANAGER_UNAVAILABLE",
            Self::Deadline => "SERVICE_OPERATION_UNCERTAIN",
            Self::NotReady => "SERVICE_NOT_READY",
            Self::LingerRequired => "SERVICE_BOOT_REQUIRES_VERIFIED_LINGER",
        })
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
fn uid() -> u32 {
    unsafe { libc::geteuid() }
}
fn c(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| Error::Invalid)
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
            current = next;
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
            #[cfg(target_os = "linux")]
            let renamed = unsafe {
                libc::renameat2(
                    self.0.as_raw_fd(),
                    temp.as_ptr(),
                    self.0.as_raw_fd(),
                    destination.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            };
            #[cfg(target_os = "macos")]
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
        self.0.sync_all().map_err(|_| Error::Invalid)?;
        result
    }
    fn check_enable_link(&self, name: &str, absolute: &Path) -> Result<bool> {
        let encoded = c(OsStr::new(name))?;
        let mut target = vec![0u8; 4096];
        let count = unsafe {
            libc::readlinkat(
                self.0.as_raw_fd(),
                encoded.as_ptr(),
                target.as_mut_ptr().cast(),
                target.len(),
            )
        };
        if count < 0 {
            return if io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
                Ok(false)
            } else {
                Err(Error::Conflict)
            };
        }
        target.truncate(count as usize);
        let relative = format!("../{name}");
        if target != absolute.as_os_str().as_bytes() && target != relative.as_bytes() {
            return Err(Error::Conflict);
        }
        Ok(true)
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

// No shell. Both output streams are nonblocking and capped; on failure we kill
// and reap the still-owned Child, never a remembered/reused PID.
fn bounded(command: &mut Command, timeout: Duration) -> Result<String> {
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
                return if status.success() {
                    String::from_utf8(output).map_err(|_| Error::Manager)
                } else {
                    Err(Error::Manager)
                };
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
fn manager(args: &[&str]) -> Result<String> {
    bounded(
        Command::new("/usr/bin/systemctl")
            .args(["--user", "--no-pager", "--no-ask-password"])
            .args(args),
        DEADLINE,
    )
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
fn linger() -> Result<bool> {
    let result = bounded(
        Command::new("/usr/bin/loginctl").args([
            "show-user",
            &uid().to_string(),
            "--property=Linger",
            "--value",
            "--no-pager",
        ]),
        DEADLINE,
    )?;
    match result.trim() {
        "yes" => Ok(true),
        "no" => Ok(false),
        _ => Err(Error::Manager),
    }
}
fn unit_name(profile: &str) -> String {
    let mut hash = 0x6c62272e07bb014262b821756295c58du128;
    for byte in profile.bytes() {
        hash ^= byte as u128;
        hash = hash.wrapping_mul(0x1000000000000000000013b);
    }
    format!("lomiremote-{hash:032x}.service")
}
fn quoted(value: &str) -> Result<String> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(Error::Invalid);
    }
    let mut result = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '%' => result.push_str("%%"),
            '$' => result.push_str("$$"),
            _ => result.push(ch),
        }
    }
    result.push('"');
    Ok(result)
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    version: u8,
    profile: String,
    executable: String,
    account: String,
    mode: String,
    unit: String,
    unit_directory: String,
}
impl Registration {
    fn unit_bytes(&self) -> Result<Vec<u8>> {
        let binary = quoted(&self.executable)?;
        let profile = quoted(&self.profile)?;
        Ok(format!("# Owned by lomiremote service registration v1\n[Unit]\nDescription=Lomi Remote local host\n[Service]\nType=exec\nExecStart={binary} --profile-dir {profile} daemon run --existing-profile\nRestart=on-failure\nRestartSec=2\nTimeoutStartSec=30\nTimeoutStopSec=45\nKillMode=mixed\nKillSignal=SIGTERM\nUMask=0077\n[Install]\nWantedBy=default.target\n").into_bytes())
    }
    fn validate(&self, profile: &str) -> Result<()> {
        if self.version != 1
            || self.profile != profile
            || self.unit != unit_name(profile)
            || self.account != account()?
            || !matches!(self.mode.as_str(), "login" | "boot")
            || !Path::new(&self.executable).is_absolute()
        {
            return Err(Error::Conflict);
        }
        self.unit_bytes()?;
        Ok(())
    }
}
fn validate_executable(executable: &Path) -> Result<()> {
    if !executable.is_absolute() {
        return Err(Error::Invalid);
    }
    // The unit must never execute through a symlink or writable ancestor, even
    // when a private outer run directory happens to restrict traversal today.
    Directory::open(executable.parent().ok_or(Error::Invalid)?, false)?;
    let metadata = fs::symlink_metadata(executable).map_err(|_| Error::Invalid)?;
    if !metadata.is_file()
        || (metadata.uid() != uid() && metadata.uid() != 0)
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn property<'a>(text: &'a str, key: &str) -> Result<&'a str> {
    let prefix = format!("{key}=");
    let mut values = text.lines().filter_map(|line| line.strip_prefix(&prefix));
    let value = values.next().ok_or(Error::Manager)?;
    if values.next().is_some() {
        return Err(Error::Manager);
    }
    Ok(value)
}
fn observation(reg: &Registration, unit_path: &Path) -> Result<String> {
    let output = manager(&[
        "show",
        &reg.unit,
        "--property=LoadState,ActiveState,SubState,UnitFileState,MainPID,FragmentPath,DropInPaths",
    ])?;
    if property(&output, "FragmentPath")? != unit_path.to_str().ok_or(Error::Invalid)?
        || !property(&output, "DropInPaths")?.is_empty()
        || property(&output, "LoadState")? != "loaded"
    {
        return Err(Error::Conflict);
    }
    Ok(output)
}
#[cfg(target_os = "linux")]
fn ready(profile: &Path, expected_pid: &str) -> bool {
    let Ok(expected) = expected_pid.parse::<u32>() else {
        return false;
    };
    if expected == 0 {
        return false;
    }
    LocalClient::connect_with_timeout(profile, Duration::from_millis(200))
        .and_then(|mut client| {
            if client.service_peer_pid()? != expected {
                return Err(crate::unix::Error::PermissionDenied);
            }
            client.request(LocalCall::Status {})
        })
        .is_ok_and(|response| matches!(response.result, Ok(LocalResult::Status(_))))
}
#[cfg(not(target_os = "linux"))]
fn ready(_profile: &Path, _expected_pid: &str) -> bool {
    false
}

fn account_identity() -> Result<(String, u32, u32)> {
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
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    {
        return Err(Error::Invalid);
    }
    Ok((name.to_owned(), entry.pw_uid, entry.pw_gid))
}

pub(crate) fn current_service_account() -> std::result::Result<
    crate::service_observation::ServiceAccount,
    crate::service_observation::ServiceError,
> {
    let (name, account_uid, account_gid) =
        account_identity().map_err(|_| crate::service_observation::ServiceError::Conflict)?;
    if account_uid != uid() || account_gid != unsafe { libc::getegid() } {
        return Err(crate::service_observation::ServiceError::Conflict);
    }
    Ok(crate::service_observation::ServiceAccount::Unix {
        uid: account_uid,
        gid: account_gid,
        name,
    })
}

pub(crate) fn discover_service_binding(
    profile: &Path,
) -> std::result::Result<
    Option<(crate::service_observation::ServiceMode, PathBuf)>,
    crate::service_observation::ServiceError,
> {
    use crate::service_observation::{ServiceError, ServiceMode};

    let profile = std::path::absolute(profile).map_err(|_| ServiceError::InvalidBinding)?;
    let profile_text = profile.to_str().ok_or(ServiceError::InvalidBinding)?;
    let unit_directory = config_directory().map_err(|_| ServiceError::InvalidBinding)?;
    match fs::symlink_metadata(&profile) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            no_registration_artifacts(&unit_directory, &unit_name(profile_text))
                .map_err(|_| ServiceError::Conflict)?;
            return Ok(None);
        }
        Err(_) => return Err(ServiceError::Conflict),
        Ok(_) => {}
    }
    let directory = Directory::open(&profile, false).map_err(|_| ServiceError::Conflict)?;
    let Some(bytes) = directory
        .read_observed(RECORD)
        .map_err(|_| ServiceError::Conflict)?
    else {
        no_registration_artifacts(&unit_directory, &unit_name(profile_text))
            .map_err(|_| ServiceError::Conflict)?;
        return Ok(None);
    };
    let registration: Registration =
        serde_json::from_slice(&bytes).map_err(|_| ServiceError::Conflict)?;
    registration
        .validate(profile_text)
        .map_err(|_| ServiceError::Conflict)?;
    if registration.unit_directory
        != unit_directory
            .to_str()
            .ok_or(ServiceError::InvalidBinding)?
    {
        return Err(ServiceError::Conflict);
    }
    let mode = match registration.mode.as_str() {
        "login" => ServiceMode::Login,
        "boot" => ServiceMode::Boot,
        _ => return Err(ServiceError::Conflict),
    };
    Ok(Some((mode, PathBuf::from(registration.executable))))
}

fn config_directory() -> Result<PathBuf> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .ok_or(Error::Invalid)?;
    if !config.is_absolute() {
        return Err(Error::Invalid);
    }
    Ok(config.join("systemd/user"))
}

fn no_registration_artifacts(units: &Path, unit: &str) -> Result<()> {
    match fs::symlink_metadata(units) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(Error::Conflict),
        Ok(_) => {}
    }
    let directory = Directory::open(units, false)?;
    if directory.read_observed(unit)?.is_some() {
        return Err(Error::Conflict);
    }
    let wants_path = units.join("default.target.wants");
    match fs::symlink_metadata(&wants_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Error::Conflict),
        Ok(_) => {
            let wants = Directory::open(&wants_path, false)?;
            if wants.check_enable_link(unit, &units.join(unit))? {
                Err(Error::Conflict)
            } else {
                Ok(())
            }
        }
    }
}

fn manual_host_ready(profile: &Path, executable: &Path, uid: u32, gid: u32) -> bool {
    let Ok(mut client) = LocalClient::connect_with_timeout(profile, Duration::from_millis(250))
    else {
        return false;
    };
    let Ok(pid) = client.service_peer_pid() else {
        return false;
    };
    if pid == 0 {
        return false;
    }
    let proc_root = PathBuf::from(format!("/proc/{pid}"));
    let Ok(actual_executable) = fs::read_link(proc_root.join("exe")) else {
        return false;
    };
    if actual_executable != executable {
        return false;
    }
    let Ok(status) = fs::read_to_string(proc_root.join("status")) else {
        return false;
    };
    let mut actual_uid = None;
    let mut actual_gid = None;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("Uid:") {
            actual_uid = value
                .split_ascii_whitespace()
                .next()
                .and_then(|value| value.parse::<u32>().ok());
        } else if let Some(value) = line.strip_prefix("Gid:") {
            actual_gid = value
                .split_ascii_whitespace()
                .next()
                .and_then(|value| value.parse::<u32>().ok());
        }
    }
    if actual_uid != Some(uid) || actual_gid != Some(gid) {
        return false;
    }
    client
        .request(LocalCall::Status {})
        .is_ok_and(|response| matches!(response.result, Ok(LocalResult::Status(_))))
}

pub(crate) fn inspect_read_only(
    binding: &crate::service_observation::ServiceBinding,
) -> std::result::Result<
    crate::service_observation::ServiceObservation,
    crate::service_observation::ServiceError,
> {
    use crate::service_observation::{
        AutostartState, BindingState, IpcReadiness, RegistrationState, RuntimeState,
        ServiceAccount, ServiceError, ServiceObservation,
    };

    let ServiceAccount::Unix {
        uid: wanted_uid,
        gid: wanted_gid,
        name: wanted_name,
    } = &binding.account
    else {
        return Err(ServiceError::InvalidBinding);
    };
    let (current_name, current_uid, current_gid) =
        account_identity().map_err(|_| ServiceError::Conflict)?;
    if *wanted_uid != uid()
        || *wanted_gid != unsafe { libc::getegid() }
        || *wanted_uid != current_uid
        || *wanted_gid != current_gid
        || wanted_name != &current_name
    {
        return Err(ServiceError::Conflict);
    }
    validate_executable(&binding.executable).map_err(|_| ServiceError::Conflict)?;
    let profile_text = binding
        .profile
        .to_str()
        .ok_or(ServiceError::InvalidBinding)?;
    let executable_text = binding
        .executable
        .to_str()
        .ok_or(ServiceError::InvalidBinding)?;
    let unit_directory = config_directory().map_err(|_| ServiceError::InvalidBinding)?;
    match fs::symlink_metadata(&binding.profile) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            no_registration_artifacts(&unit_directory, &unit_name(profile_text))
                .map_err(|_| ServiceError::Conflict)?;
            return Ok(ServiceObservation {
                binding: BindingState::Matches,
                registration: RegistrationState::Missing,
                runtime: RuntimeState::Stopped,
                autostart: AutostartState::Disabled,
                ipc: IpcReadiness::NotReady,
            });
        }
        Err(_) => return Err(ServiceError::Conflict),
        Ok(_) => {}
    };
    let profile_dir =
        Directory::open(&binding.profile, false).map_err(|_| ServiceError::Conflict)?;
    let profile_metadata = profile_dir
        .0
        .metadata()
        .map_err(|_| ServiceError::Conflict)?;
    if profile_metadata.uid() != uid() || profile_metadata.mode() & 0o777 != 0o700 {
        return Err(ServiceError::Conflict);
    }
    let record_bytes = profile_dir
        .read_observed(RECORD)
        .map_err(|_| ServiceError::Conflict)?;
    let Some(record_bytes) = record_bytes else {
        let expected_unit = unit_name(profile_text);
        no_registration_artifacts(&unit_directory, &expected_unit)
            .map_err(|_| ServiceError::Conflict)?;
        let manual_running = manual_host_ready(
            &binding.profile,
            &binding.executable,
            current_uid,
            current_gid,
        );
        return Ok(ServiceObservation {
            binding: BindingState::Matches,
            registration: RegistrationState::Missing,
            runtime: if manual_running {
                RuntimeState::Running
            } else {
                RuntimeState::Stopped
            },
            autostart: AutostartState::Disabled,
            ipc: if manual_running {
                IpcReadiness::Ready
            } else {
                IpcReadiness::NotReady
            },
        });
    };
    let registration: Registration =
        serde_json::from_slice(&record_bytes).map_err(|_| ServiceError::Conflict)?;
    registration
        .validate(profile_text)
        .map_err(|_| ServiceError::Conflict)?;
    if registration.executable != executable_text
        || registration.mode != binding.mode.as_str()
        || registration.unit_directory
            != unit_directory
                .to_str()
                .ok_or(ServiceError::InvalidBinding)?
    {
        return Err(ServiceError::Conflict);
    }
    validate_executable(&binding.executable).map_err(|_| ServiceError::Conflict)?;
    let units = Directory::open(&unit_directory, false).map_err(|_| ServiceError::Conflict)?;
    let expected_unit = registration
        .unit_bytes()
        .map_err(|_| ServiceError::Conflict)?;
    if units
        .read_observed(&registration.unit)
        .map_err(|_| ServiceError::Conflict)?
        .as_deref()
        != Some(expected_unit.as_slice())
    {
        return Err(ServiceError::Conflict);
    }
    let unit_path = unit_directory.join(&registration.unit);
    let observed =
        observation(&registration, &unit_path).map_err(|_| ServiceError::ManagerUnavailable)?;
    let enabled = match fs::symlink_metadata(unit_directory.join("default.target.wants")) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(_) => return Err(ServiceError::Conflict),
        Ok(_) => Directory::open(&unit_directory.join("default.target.wants"), false)
            .and_then(|wants| wants.check_enable_link(&registration.unit, &unit_path))
            .map_err(|_| ServiceError::Conflict)?,
    };
    let unit_file_state =
        property(&observed, "UnitFileState").map_err(|_| ServiceError::ManagerUnavailable)?;
    let active =
        property(&observed, "ActiveState").map_err(|_| ServiceError::ManagerUnavailable)?;
    let runtime = match active {
        "active" => RuntimeState::Running,
        "activating" | "reloading" => RuntimeState::Starting,
        "inactive" => RuntimeState::Stopped,
        "failed" => RuntimeState::Failed,
        _ => RuntimeState::Unknown,
    };
    let main_pid = property(&observed, "MainPID").map_err(|_| ServiceError::ManagerUnavailable)?;
    let ipc_ready = runtime == RuntimeState::Running && ready(&binding.profile, main_pid);
    let autostart = match (unit_file_state, enabled) {
        ("enabled" | "enabled-runtime", true) => AutostartState::Enabled,
        ("disabled" | "masked" | "masked-runtime", false) => AutostartState::Disabled,
        ("enabled" | "enabled-runtime", false)
        | ("disabled" | "masked" | "masked-runtime", true) => {
            return Err(ServiceError::Conflict);
        }
        _ => AutostartState::Unknown,
    };
    Ok(ServiceObservation {
        binding: BindingState::Matches,
        registration: RegistrationState::Present,
        runtime,
        autostart,
        ipc: if ipc_ready {
            IpcReadiness::Ready
        } else if runtime == RuntimeState::Unknown {
            IpcReadiness::Unknown
        } else {
            IpcReadiness::NotReady
        },
    })
}

pub(crate) fn control_exact(
    binding: &crate::service_observation::ServiceBinding,
    action: crate::service_observation::ServiceAction,
) -> std::result::Result<(), crate::service_observation::ServiceError> {
    use crate::service_observation::{ServiceAccount, ServiceAction, ServiceError};
    let ServiceAccount::Unix {
        uid: selected_uid,
        gid: selected_gid,
        name,
    } = &binding.account
    else {
        return Err(ServiceError::InvalidBinding);
    };
    if *selected_uid != uid() || *selected_gid != unsafe { libc::getegid() } {
        return Err(ServiceError::Conflict);
    }
    let (current_name, current_uid, current_gid) =
        account_identity().map_err(|_| ServiceError::Conflict)?;
    if current_name != *name || current_uid != *selected_uid || current_gid != *selected_gid {
        return Err(ServiceError::Conflict);
    }
    let operation = match action {
        ServiceAction::Install => "install",
        ServiceAction::Start => "start",
        ServiceAction::Stop => "stop",
        ServiceAction::Restart => "restart",
        ServiceAction::Uninstall => "uninstall",
    };
    run(
        &binding.profile,
        &binding.executable,
        operation,
        Some(binding.mode.as_str()),
        Some(name),
    )
    .map(|_| ())
    .map_err(|error| match error {
        Error::Invalid => ServiceError::InvalidBinding,
        Error::Conflict => ServiceError::Conflict,
        Error::Manager => ServiceError::ManagerUnavailable,
        Error::Deadline => ServiceError::OperationUncertain,
        Error::NotReady => ServiceError::NotReady,
        Error::LingerRequired => ServiceError::Unsupported,
    })
}

/// Operations are serialized per profile. Installation only enables autostart;
/// start/restart additionally verify actual manager state and authenticated IPC.
/// Boot mode never changes linger: an administrator must enable it explicitly.
pub fn run(
    profile: &Path,
    executable: &Path,
    operation: &str,
    mode: Option<&str>,
    selected_account: Option<&str>,
) -> Result<String> {
    crate::process::require_child_ownership().map_err(|_| Error::Manager)?;
    let profile = std::path::absolute(profile).map_err(|_| Error::Invalid)?;
    let profile_text = profile.to_str().ok_or(Error::Invalid)?;
    if profile
        .components()
        .any(|p| !matches!(p, Component::RootDir | Component::Normal(_)))
    {
        return Err(Error::Invalid);
    }
    if operation == "install" {
        if !matches!(mode, Some("login" | "boot")) {
            return Err(Error::Invalid);
        }
        let selected = selected_account.ok_or(Error::Invalid)?;
        if selected != uid().to_string() && selected != account()? {
            return Err(Error::Invalid);
        }
        let owner = OwnerLock::acquire(&profile).map_err(|_| Error::Conflict)?;
        drop(owner);
    }
    let profile_dir = Directory::open(&profile, false)?;
    let metadata = profile_dir.0.metadata().map_err(|_| Error::Invalid)?;
    if metadata.uid() != uid() || metadata.mode() & 0o777 != 0o700 {
        return Err(Error::Invalid);
    }

    let lock = profile_dir
        .regular("service.lock", true)?
        .ok_or(Error::Invalid)?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(Error::Conflict);
    }
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .ok_or(Error::Invalid)?;
    let unit_directory = config.join("systemd/user");
    let unit_directory_text = unit_directory.to_str().ok_or(Error::Invalid)?;
    quoted(unit_directory_text)?;
    let units = Directory::open(&unit_directory, operation == "install")?;
    let existing = profile_dir.read(RECORD)?;
    if existing.is_none() && operation == "uninstall" {
        return Ok("No profile-owned service registration; profile files preserved.".to_owned());
    }

    let reg = if let Some(ref bytes) = existing {
        let reg: Registration = serde_json::from_slice(bytes).map_err(|_| Error::Conflict)?;
        reg.validate(profile_text)?;
        if reg.unit_directory != unit_directory_text {
            return Err(Error::Conflict);
        }
        if operation == "install"
            && (mode != Some(reg.mode.as_str())
                || executable.to_str() != Some(reg.executable.as_str()))
        {
            return Err(Error::Conflict);
        }
        reg
    } else {
        if operation != "install" {
            return Err(Error::Conflict);
        }
        validate_executable(executable)?;
        Registration {
            version: 1,
            profile: profile_text.to_owned(),
            executable: executable.to_str().ok_or(Error::Invalid)?.to_owned(),
            account: account()?,
            mode: mode.ok_or(Error::Invalid)?.to_owned(),
            unit: unit_name(profile_text),
            unit_directory: unit_directory_text.to_owned(),
        }
    };
    let unit_path = unit_directory.join(&reg.unit);
    let wants_path = unit_directory.join("default.target.wants");
    let wants = match fs::symlink_metadata(&wants_path) {
        Ok(_) => Some(Directory::open(&wants_path, false)?),
        Err(error) if error.kind() == io::ErrorKind::NotFound && operation != "install" => None,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Some(Directory::open(&wants_path, true)?)
        }
        Err(_) => return Err(Error::Invalid),
    };
    if let Some(ref directory) = wants {
        directory.check_enable_link(&reg.unit, &unit_path)?;
    }

    let expected = reg.unit_bytes()?;
    if operation == "install" {
        if reg.mode == "boot" && !linger()? {
            return Err(Error::LingerRequired);
        }
        // Do not adopt a unit simply because it matches our name.
        match units.read(&reg.unit)? {
            Some(bytes) if existing.is_some() && bytes == expected => {}
            Some(_) => return Err(Error::Conflict),
            None => {
                if existing.is_none() {
                    profile_dir.publish(
                        RECORD,
                        &serde_json::to_vec(&reg).map_err(|_| Error::Invalid)?,
                    )?;
                }
                units.publish(&reg.unit, &expected)?;
            }
        }
        manager(&["daemon-reload"])?;
        observation(&reg, &unit_path)?;
        manager(&["enable", &reg.unit])?;
        if !wants
            .as_ref()
            .ok_or(Error::Invalid)?
            .check_enable_link(&reg.unit, &unit_path)?
        {
            return Err(Error::Manager);
        }

        let observed = observation(&reg, &unit_path)?;
        if property(&observed, "UnitFileState")? != "enabled" {
            return Err(Error::Manager);
        }
        let lingering = linger()?;
        if reg.mode == "boot" && !lingering {
            return Err(Error::LingerRequired);
        }
        return Ok(format!(
            "Service installed; account={} mode={} enabled=true linger={} (not started)",
            reg.account, reg.mode, lingering
        ));
    }
    let current_unit = units.read(&reg.unit)?;
    if current_unit.is_none() && operation == "uninstall" {
        // Resume an interrupted uninstall after unlink but before reload. The
        // exact private record remains the ownership journal. Reload then prove
        // the manager has no foreign replacement before removing that journal.
        manager(&["daemon-reload"])?;
        let current = manager(&[
            "show",
            &reg.unit,
            "--property=LoadState,ActiveState,MainPID,FragmentPath,DropInPaths",
        ])?;
        if property(&current, "LoadState")? != "not-found"
            || !property(&current, "FragmentPath")?.is_empty()
            || !property(&current, "DropInPaths")?.is_empty()
            || property(&current, "MainPID")? != "0"
            || !matches!(property(&current, "ActiveState")?, "inactive" | "failed")
            || wants
                .as_ref()
                .map(|d| d.check_enable_link(&reg.unit, &unit_path))
                .transpose()?
                .unwrap_or(false)
            || units.read(&reg.unit)?.is_some()
        {
            return Err(Error::Conflict);
        }
        profile_dir.remove_exact(RECORD, existing.as_deref().ok_or(Error::Conflict)?)?;
        return Ok("Service uninstall resumed; profile and workspace files preserved.".to_owned());
    }
    if current_unit.as_deref() != Some(&expected) {
        return Err(Error::Conflict);
    }
    let observed = observation(&reg, &unit_path)?;
    match operation {
        "status" => Ok(format!(
            "Service: {}\nAccount: {}\nMode: {}\nActive: {}\nState: {}\nAutostart: {}\nLinger: {}\nIPC ready: {}",
            reg.unit,
            reg.account,
            reg.mode,
            property(&observed, "ActiveState")?,
            property(&observed, "SubState")?,
            property(&observed, "UnitFileState")?,
            linger()?,
            ready(&profile, property(&observed, "MainPID")?)
        )),
        "start" | "restart" => {
            if reg.mode == "boot" && !linger()? {
                return Err(Error::LingerRequired);
            }
            let active = property(&observed, "ActiveState")?;
            if !matches!(active, "active" | "activating") {
                // Detect a foreground/detached owner before handing off to systemd.
                let owner = OwnerLock::acquire(&profile).map_err(|_| Error::Conflict)?;
                drop(owner);
            }
            manager(&[operation, &reg.unit])?;
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let current = observation(&reg, &unit_path)?;
                if property(&current, "ActiveState")? == "active"
                    && ready(&profile, property(&current, "MainPID")?)
                {
                    return Ok("Service ready.".to_owned());
                }
                if matches!(property(&current, "ActiveState")?, "failed" | "inactive")
                    || Instant::now() >= deadline
                {
                    return Err(Error::NotReady);
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
        "stop" | "uninstall" => {
            manager(&["stop", &reg.unit])?;
            let current = observation(&reg, &unit_path)?;
            if !matches!(property(&current, "ActiveState")?, "inactive" | "failed")
                || property(&current, "MainPID")? != "0"
            {
                return Err(Error::NotReady);
            }
            if operation == "uninstall" {
                manager(&["disable", &reg.unit])?;
                units.remove_exact(&reg.unit, &expected)?;
                manager(&["daemon-reload"])?;
                profile_dir.remove_exact(RECORD, existing.as_deref().ok_or(Error::Conflict)?)?;
                Ok("Service uninstalled; profile and workspace files preserved.".to_owned())
            } else {
                Ok("Service stopped.".to_owned())
            }
        }
        _ => Err(Error::Invalid),
    }
}
