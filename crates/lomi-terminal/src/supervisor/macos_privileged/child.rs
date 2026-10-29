//! Trusted unprivileged command supervisor for a root-launched per-PTY job.
//! User-controlled program data reaches `Command::spawn` only after permanent
//! account credential changes have been verified.
//!
//! Wire contract: the direct root parent writes a bounded version-1 JSON
//! metadata frame containing only `accountName`, `uid`, `gid`, parent identity,
//! and `deadlineNs`. After permanent credential drop and cohort verification,
//! it reads the separate bounded `SpawnProfile` frame, then writes `D`. The
//! root parent must send `E` before this helper spawns the selected user
//! command. The helper reports `S` only after `Command::spawn` confirms the OS
//! exec handshake; a pre-exec refusal reports `N` while no user command has
//! run. `deadlineNs` is an absolute Mach continuous-clock deadline and is not
//! reset across these frames or the E/S handshake.

use super::{Error, capability};
use crate::SpawnProfile;
use std::{
    collections::HashSet,
    ffi::CString,
    io,
    os::{
        fd::FromRawFd,
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    path::PathBuf,
    process::{Child, Command, Stdio},
};

const CONTROL_FD: i32 = 3;
const FRAME_LIMIT: usize = 128 * 1024;
const PROFILE_LIMIT: usize = 64 * 1024;
const ARGUMENT_LIMIT: usize = 256;
const ENVIRONMENT_LIMIT: usize = 256;
const GROUP_LIMIT: usize = 256;
const FD_LIMIT: usize = 65_536;

struct Bootstrap {
    version: u8,
    account_name: String,
    uid: u32,
    gid: u32,
    parent_pid: i32,
    parent_pidversion: u32,
    parent_audit: [u32; 8],
    parent_resource: u64,
    parent_jetsam: u64,
    deadline_ns: u64,
}

struct Profile {
    executable: String,
    args: Vec<String>,
    cwd: String,
    environment: Vec<(String, String)>,
    rows: u16,
    cols: u16,
    history: usize,
}

#[derive(Default)]
struct LaunchState {
    root_authenticated: bool,
    started: bool,
    cancelled: bool,
    deadline_ns: Option<u64>,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct AuditToken {
    values: [u32; 8],
}

#[repr(C)]
struct MachTimebaseInfo {
    numer: u32,
    denom: u32,
}

unsafe extern "C" {
    fn audit_token_to_pid(token: AuditToken) -> libc::pid_t;
    fn mach_continuous_time() -> u64;
    fn mach_timebase_info(info: *mut MachTimebaseInfo) -> i32;
}

pub(super) fn run(control_fd: i32) -> i32 {
    let stream = match take_control_socket(control_fd) {
        Ok(stream) => stream,
        Err(_) => return 1,
    };
    let mut state = LaunchState::default();
    match run_inner(&stream, &mut state) {
        Ok(()) => 0,
        Err(_) => {
            if state.root_authenticated && !state.started && !state.cancelled {
                if let Some(deadline_ns) = state.deadline_ns {
                    // N is a positive pre-exec refusal, never a substitute for
                    // EOF after a successful user-command spawn.
                    if super::wire::write_spawn_outcome(
                        &stream,
                        super::wire::SpawnOutcome::Refused,
                        deadline_ns,
                    )
                    .is_ok()
                    {
                        wait_for_root_close(&stream);
                    }
                }
            }
            1
        }
    }
}

fn wait_for_root_close(stream: &UnixStream) {
    loop {
        let mut descriptor = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, 100) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if result == 0 {
            continue;
        }
        if descriptor.revents & (libc::POLLNVAL | libc::POLLERR) != 0 {
            return;
        }
        if descriptor.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let Ok(deadline) = mach_now_ns()
                .and_then(|now| now.checked_add(1_000_000_000).ok_or(Error::SpawnFailed))
            else {
                return;
            };
            match super::wire::read_byte(stream, deadline) {
                Ok(Some(b'X') | None) | Err(_) => return,
                Ok(Some(_)) => return,
            }
        }
    }
}

fn run_inner(stream: &UnixStream, state: &mut LaunchState) -> Result<(), Error> {
    let connected_parent = peer_identity(stream)?;
    let bootstrap = read_bootstrap(stream)?;
    let profile = validate_bootstrap(bootstrap)?;

    let parent = capability::Identity::from_parts(
        profile.parent_pid,
        profile.parent_pidversion,
        profile.parent_audit,
        profile.parent_resource,
        profile.parent_jetsam,
    )?;
    if !connected_parent.same_identity(parent) {
        return Err(Error::SpawnFailed);
    }
    let deadline = profile.deadline_ns;
    let account = CString::new(profile.account_name.as_bytes()).map_err(|_| Error::SpawnFailed)?;

    validate_root_peer(stream, &parent)?;
    state.root_authenticated = true;
    state.deadline_ns = Some(deadline);
    require_root_credentials()?;
    capability::require_nonprivileged_current()?;
    let before_drop = capability::current_cohorts()?;
    if !before_drop.same_cohorts(parent) {
        return Err(Error::SpawnFailed);
    }
    let expected_groups = account_groups(&account, profile.gid)?;
    ensure_before_deadline(deadline)?;

    // The launchd child receives the user-owned PTY slave as all three standard
    // streams. Establish the terminal session before dropping root so no shell
    // exists until after the account credentials have become permanent.
    if unsafe { libc::setsid() } < 0
        || unsafe { libc::ioctl(0, libc::TIOCSCTTY as libc::c_ulong, 0) } < 0
    {
        return Err(Error::SpawnFailed);
    }

    if unsafe { libc::initgroups(account.as_ptr(), profile.gid as libc::c_int) } != 0
        || unsafe { libc::setgid(profile.gid) } != 0
        || unsafe { libc::setuid(profile.uid) } != 0
    {
        return Err(Error::SpawnFailed);
    }

    verify_account_credentials(profile.uid, profile.gid, &expected_groups)?;
    verify_user_pty(profile.uid)?;
    close_other_descriptors()?;

    capability::require_nonprivileged_current()?;
    let after_drop = capability::current_cohorts()?;
    if !before_drop.same_task_and_cohorts(after_drop) || !after_drop.same_cohorts(parent) {
        return Err(Error::SpawnFailed);
    }
    validate_root_peer(stream, &parent)?;
    ensure_before_deadline(deadline)?;

    // The command profile is a separate bounded frame and remains unread
    // until permanent account credentials and cohort identity are verified.
    let command_profile = read_profile(stream)?;
    let cwd =
        CString::new(command_profile.cwd.as_os_str().as_bytes()).map_err(|_| Error::SpawnFailed)?;
    if unsafe { libc::chdir(cwd.as_ptr()) } != 0 {
        return Err(Error::SpawnFailed);
    }
    verify_account_credentials(profile.uid, profile.gid, &expected_groups)?;
    verify_user_pty(profile.uid)?;
    validate_root_peer(stream, &parent)?;
    ensure_before_deadline(deadline)?;

    super::wire::write_child_dropped(stream, deadline)?;
    match super::wire::read_byte(stream, deadline)? {
        Some(b'E') => {}
        Some(b'X') => {
            state.cancelled = true;
            return Err(Error::SpawnFailed);
        }
        _ => return Err(Error::SpawnFailed),
    }

    validate_root_peer(stream, &parent)?;
    verify_account_credentials(profile.uid, profile.gid, &expected_groups)?;
    verify_user_pty(profile.uid)?;
    capability::require_nonprivileged_current()?;
    let immediately_before_exec = capability::current_cohorts()?;
    if !after_drop.same_task_and_cohorts(immediately_before_exec)
        || !immediately_before_exec.same_cohorts(parent)
    {
        return Err(Error::SpawnFailed);
    }
    ensure_before_deadline(deadline)?;
    close_other_descriptors()?;
    if unsafe { libc::fcntl(CONTROL_FD, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(Error::SpawnFailed);
    }

    let mut command = Command::new(&command_profile.executable);
    command
        .args(&command_profile.args)
        .env_clear()
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    for (name, value) in &command_profile.environment {
        command.env(name, value);
    }

    lomi_platform::process::require_child_ownership().map_err(|_| Error::SpawnFailed)?;
    ensure_before_deadline(deadline)?;
    let mut user_child = command.spawn().map_err(|_| Error::SpawnFailed)?;
    // This flag is monotonic and set before any fallible status I/O. Once
    // true, EOF or a lost S can only mean an unknown startup result.
    state.started = true;
    super::wire::write_spawn_outcome(stream, super::wire::SpawnOutcome::Started, deadline)?;
    supervise_user_child(stream, &mut user_child)
}

struct ValidatedBootstrap {
    account_name: String,
    uid: u32,
    gid: u32,
    parent_pid: i32,
    parent_pidversion: u32,
    parent_audit: [u32; 8],
    parent_resource: u64,
    parent_jetsam: u64,
    deadline_ns: u64,
}

fn validate_bootstrap(bootstrap: Bootstrap) -> Result<ValidatedBootstrap, Error> {
    if bootstrap.version != 1
        || bootstrap.uid == 0
        || bootstrap.gid == 0
        || bootstrap.gid > i32::MAX as u32
        || !valid_account_name(&bootstrap.account_name)
        || bootstrap.parent_pid <= 0
        || bootstrap.parent_pidversion == 0
        || bootstrap.parent_resource == 0
        || bootstrap.parent_jetsam == 0
        || bootstrap.deadline_ns == 0
    {
        return Err(Error::SpawnFailed);
    }
    Ok(ValidatedBootstrap {
        account_name: bootstrap.account_name,
        uid: bootstrap.uid,
        gid: bootstrap.gid,
        parent_pid: bootstrap.parent_pid,
        parent_pidversion: bootstrap.parent_pidversion,
        parent_audit: bootstrap.parent_audit,
        parent_resource: bootstrap.parent_resource,
        parent_jetsam: bootstrap.parent_jetsam,
        deadline_ns: bootstrap.deadline_ns,
    })
}

fn validate_command_profile(profile: Profile) -> Result<SpawnProfile, Error> {
    let executable = PathBuf::from(&profile.executable);
    let cwd = PathBuf::from(&profile.cwd);
    if !executable.is_absolute()
        || !cwd.is_absolute()
        || profile.args.len() > ARGUMENT_LIMIT
        || profile.environment.len() > ENVIRONMENT_LIMIT
        || profile.rows == 0
        || profile.rows > 1000
        || profile.cols == 0
        || profile.cols > 1000
        || profile.history > 1_000_000
    {
        return Err(Error::SpawnFailed);
    }

    let mut total = profile.executable.len() + profile.cwd.len();
    for argument in &profile.args {
        if argument.contains('\0') || argument.len() > PROFILE_LIMIT {
            return Err(Error::SpawnFailed);
        }
        total = total
            .checked_add(argument.len() + 8)
            .ok_or(Error::SpawnFailed)?;
    }
    let mut names = HashSet::with_capacity(profile.environment.len());
    for (name, value) in &profile.environment {
        if name.is_empty()
            || name
                .chars()
                .any(|character| character == '=' || character == '\0')
            || value.contains('\0')
            || name.len() > 256
            || value.len() > PROFILE_LIMIT
            || !names.insert(name)
        {
            return Err(Error::SpawnFailed);
        }
        total = total
            .checked_add(name.len() + value.len() + 8)
            .ok_or(Error::SpawnFailed)?;
    }
    if total > PROFILE_LIMIT || profile.executable.contains('\0') || profile.cwd.contains('\0') {
        return Err(Error::SpawnFailed);
    }

    Ok(SpawnProfile {
        executable,
        args: profile.args,
        cwd,
        environment: profile.environment,
        shell_integration: None,
        rows: profile.rows,
        cols: profile.cols,
        history: profile.history,
    })
}

fn valid_account_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn take_control_socket(fd: i32) -> Result<UnixStream, Error> {
    if fd <= 2 || unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(Error::SpawnFailed);
    }
    if fd != CONTROL_FD && unsafe { libc::dup2(fd, CONTROL_FD) } != CONTROL_FD {
        return Err(Error::SpawnFailed);
    }
    if fd != CONTROL_FD && unsafe { libc::close(fd) } != 0 {
        return Err(Error::SpawnFailed);
    }
    if unsafe { libc::fcntl(CONTROL_FD, libc::F_SETFD, 0) } != 0 {
        return Err(Error::SpawnFailed);
    }
    close_other_descriptors()?;

    let stream = unsafe { UnixStream::from_raw_fd(CONTROL_FD) };
    let mut socket_type: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&socket_type) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut length,
        )
    } != 0
        || socket_type != libc::SOCK_STREAM
        || length as usize != std::mem::size_of_val(&socket_type)
    {
        return Err(Error::SpawnFailed);
    }
    let no_sigpipe: libc::c_int = 1;
    if unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            (&no_sigpipe as *const libc::c_int).cast(),
            std::mem::size_of_val(&no_sigpipe) as libc::socklen_t,
        )
    } != 0
    {
        return Err(Error::SpawnFailed);
    }
    Ok(stream)
}

fn close_other_descriptors() -> Result<(), Error> {
    let fd_size = std::mem::size_of::<libc::proc_fdinfo>();
    let mut capacity = 64usize;
    loop {
        let bytes = capacity.checked_mul(fd_size).ok_or(Error::SpawnFailed)?;
        let mut descriptors =
            Vec::<std::mem::MaybeUninit<libc::proc_fdinfo>>::with_capacity(capacity);
        unsafe { descriptors.set_len(capacity) };
        let written = unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDLISTFDS,
                0,
                descriptors.as_mut_ptr().cast(),
                i32::try_from(bytes).map_err(|_| Error::SpawnFailed)?,
            )
        };
        if written <= 0 || written as usize % fd_size != 0 {
            return Err(Error::SpawnFailed);
        }
        if written as usize == bytes {
            if capacity >= FD_LIMIT {
                return Err(Error::SpawnFailed);
            }
            capacity = (capacity * 2).min(FD_LIMIT);
            continue;
        }

        let count = written as usize / fd_size;
        let mut found_standard = [false; 4];
        for descriptor in descriptors.iter().take(count) {
            let fd = unsafe { descriptor.assume_init_ref() }.proc_fd;
            if fd < 0 {
                return Err(Error::SpawnFailed);
            }
            if !(0..=3).contains(&fd) {
                if unsafe { libc::close(fd) } != 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::EBADF) {
                        return Err(Error::SpawnFailed);
                    }
                }
            } else {
                found_standard[fd as usize] = true;
            }
        }
        if found_standard.iter().any(|found| !found) {
            return Err(Error::SpawnFailed);
        }
        return Ok(());
    }
}

fn read_bootstrap(stream: &UnixStream) -> Result<Bootstrap, Error> {
    parse_bootstrap(read_json_frame(stream)?)
}

fn read_profile(stream: &UnixStream) -> Result<SpawnProfile, Error> {
    validate_command_profile(parse_profile(read_json_frame(stream)?)?)
}

fn read_json_frame(stream: &UnixStream) -> Result<serde_json::Value, Error> {
    let mut length = [0u8; 4];
    read_exact(stream, &mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > FRAME_LIMIT {
        return Err(Error::SpawnFailed);
    }
    let mut bytes = vec![0; length];
    read_exact(stream, &mut bytes)?;
    serde_json::from_slice(&bytes).map_err(|_| Error::SpawnFailed)
}

fn parse_bootstrap(value: serde_json::Value) -> Result<Bootstrap, Error> {
    let object = exact_object(
        &value,
        &[
            "version",
            "accountName",
            "uid",
            "gid",
            "parentPid",
            "parentPidVersion",
            "parentAudit",
            "parentResource",
            "parentJetsam",
            "deadlineNs",
        ],
    )?;
    let audit_values = object
        .get("parentAudit")
        .and_then(serde_json::Value::as_array)
        .filter(|values| values.len() == 8)
        .ok_or(Error::SpawnFailed)?;
    let mut parent_audit = [0; 8];
    for (target, value) in parent_audit.iter_mut().zip(audit_values) {
        *target = value
            .as_u64()
            .and_then(|number| u32::try_from(number).ok())
            .ok_or(Error::SpawnFailed)?;
    }
    Ok(Bootstrap {
        version: number_u8(&object, "version")?,
        account_name: string(&object, "accountName")?,
        uid: number_u32(&object, "uid")?,
        gid: number_u32(&object, "gid")?,
        parent_pid: number_i32(&object, "parentPid")?,
        parent_pidversion: number_u32(&object, "parentPidVersion")?,
        parent_audit,
        parent_resource: number_u64(&object, "parentResource")?,
        parent_jetsam: number_u64(&object, "parentJetsam")?,
        deadline_ns: number_u64(&object, "deadlineNs")?,
    })
}

fn parse_profile(value: serde_json::Value) -> Result<Profile, Error> {
    let profile = exact_object(
        &value,
        &[
            "executable",
            "args",
            "cwd",
            "environment",
            "rows",
            "cols",
            "history",
        ],
    )?;
    let args = profile
        .get("args")
        .and_then(serde_json::Value::as_array)
        .filter(|values| values.len() <= ARGUMENT_LIMIT)
        .ok_or(Error::SpawnFailed)?
        .iter()
        .map(|value| value.as_str().map(str::to_owned).ok_or(Error::SpawnFailed))
        .collect::<Result<Vec<_>, _>>()?;
    let environment = profile
        .get("environment")
        .and_then(serde_json::Value::as_array)
        .filter(|values| values.len() <= ENVIRONMENT_LIMIT)
        .ok_or(Error::SpawnFailed)?
        .iter()
        .map(|entry| {
            let entry = entry.as_array().ok_or(Error::SpawnFailed)?;
            if entry.len() != 2 {
                return Err(Error::SpawnFailed);
            }
            let name = entry[0].as_str().ok_or(Error::SpawnFailed)?.to_owned();
            let value = entry[1].as_str().ok_or(Error::SpawnFailed)?.to_owned();
            Ok((name, value))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(Profile {
        executable: string(profile, "executable")?,
        args,
        cwd: string(profile, "cwd")?,
        environment,
        rows: number_u16(profile, "rows")?,
        cols: number_u16(profile, "cols")?,
        history: usize::try_from(number_u64(profile, "history")?)
            .map_err(|_| Error::SpawnFailed)?,
    })
}

fn exact_object<'a>(
    value: &'a serde_json::Value,
    fields: &[&str],
) -> Result<&'a serde_json::Map<String, serde_json::Value>, Error> {
    let object = value.as_object().ok_or(Error::SpawnFailed)?;
    if object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err(Error::SpawnFailed);
    }
    Ok(object)
}

fn string(
    object: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<String, Error> {
    object
        .get(name)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or(Error::SpawnFailed)
}

fn number_u64(
    object: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<u64, Error> {
    object
        .get(name)
        .and_then(serde_json::Value::as_u64)
        .ok_or(Error::SpawnFailed)
}

fn number_u32(
    object: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<u32, Error> {
    u32::try_from(number_u64(object, name)?).map_err(|_| Error::SpawnFailed)
}

fn number_u16(
    object: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<u16, Error> {
    u16::try_from(number_u64(object, name)?).map_err(|_| Error::SpawnFailed)
}

fn number_u8(object: &serde_json::Map<String, serde_json::Value>, name: &str) -> Result<u8, Error> {
    u8::try_from(number_u64(object, name)?).map_err(|_| Error::SpawnFailed)
}

fn number_i32(
    object: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<i32, Error> {
    object
        .get(name)
        .and_then(serde_json::Value::as_i64)
        .and_then(|number| i32::try_from(number).ok())
        .ok_or(Error::SpawnFailed)
}

fn read_exact(stream: &UnixStream, bytes: &mut [u8]) -> Result<(), Error> {
    let mut offset = 0;
    while offset < bytes.len() {
        let count = unsafe {
            libc::read(
                stream.as_raw_fd(),
                bytes[offset..].as_mut_ptr().cast(),
                bytes.len() - offset,
            )
        };
        if count > 0 {
            offset += count as usize;
            continue;
        }
        if count == 0 {
            return Err(Error::SpawnFailed);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(Error::SpawnFailed);
        }
    }
    Ok(())
}

fn validate_root_peer(stream: &UnixStream, expected: &capability::Identity) -> Result<(), Error> {
    let current = peer_identity(stream)?;
    if !current.same_identity(*expected) {
        return Err(Error::SpawnFailed);
    }
    Ok(())
}

fn peer_identity(stream: &UnixStream) -> Result<capability::Identity, Error> {
    let mut peer_uid = 0;
    let mut peer_gid = 0;
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut peer_uid, &mut peer_gid) } != 0
        || peer_uid != 0
    {
        return Err(Error::SpawnFailed);
    }

    let mut audit = AuditToken { values: [0; 8] };
    let mut token_length = std::mem::size_of::<AuditToken>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            (&mut audit as *mut AuditToken).cast(),
            &mut token_length,
        )
    } != 0
        || token_length as usize != std::mem::size_of::<AuditToken>()
        || audit.values[1] != 0
        || audit.values[2] != peer_gid
    {
        return Err(Error::SpawnFailed);
    }

    let mut peer_pid: libc::pid_t = 0;
    let mut pid_length = std::mem::size_of_val(&peer_pid) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut peer_pid as *mut libc::pid_t).cast(),
            &mut pid_length,
        )
    } != 0
        || pid_length as usize != std::mem::size_of_val(&peer_pid)
        || peer_pid <= 0
        || peer_pid != unsafe { libc::getppid() }
        || peer_pid != unsafe { audit_token_to_pid(audit) }
    {
        return Err(Error::SpawnFailed);
    }

    capability::identity_from_audit(&audit.values)
}

fn require_root_credentials() -> Result<(), Error> {
    if unsafe { libc::geteuid() } != 0 || unsafe { libc::getuid() } != 0 {
        return Err(Error::SpawnFailed);
    }
    let info = process_credentials(unsafe { libc::getpid() })?;
    if info.pbi_uid != 0
        || info.pbi_ruid != 0
        || info.pbi_svuid != 0
        || info.pbi_pid as libc::pid_t != unsafe { libc::getpid() }
    {
        return Err(Error::SpawnFailed);
    }
    Ok(())
}

fn account_groups(account: &CString, gid: u32) -> Result<Vec<libc::gid_t>, Error> {
    let mut groups = vec![0 as libc::c_int; GROUP_LIMIT];
    let mut count = GROUP_LIMIT as libc::c_int;
    if unsafe {
        libc::getgrouplist(
            account.as_ptr(),
            gid as libc::c_int,
            groups.as_mut_ptr(),
            &mut count,
        )
    } < 0
        || count <= 0
        || count as usize > GROUP_LIMIT
    {
        return Err(Error::SpawnFailed);
    }
    groups.truncate(count as usize);
    let mut result = Vec::with_capacity(groups.len());
    for group in groups {
        let group = u32::try_from(group).map_err(|_| Error::SpawnFailed)?;
        if group == 0 {
            return Err(Error::SpawnFailed);
        }
        result.push(group as libc::gid_t);
    }
    result.sort_unstable();
    result.dedup();
    if result.is_empty() || !result.contains(&(gid as libc::gid_t)) {
        return Err(Error::SpawnFailed);
    }
    Ok(result)
}

fn current_groups() -> Result<Vec<libc::gid_t>, Error> {
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count <= 0 || count as usize > GROUP_LIMIT {
        return Err(Error::SpawnFailed);
    }
    let mut groups = vec![0; count as usize];
    let actual = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
    if actual != count {
        return Err(Error::SpawnFailed);
    }
    if groups.iter().any(|group| *group == 0) {
        return Err(Error::SpawnFailed);
    }
    groups.sort_unstable();
    if groups.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(Error::SpawnFailed);
    }
    Ok(groups)
}

fn process_credentials(pid: libc::pid_t) -> Result<libc::proc_bsdinfo, Error> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    if unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    } != size
    {
        return Err(Error::SpawnFailed);
    }
    Ok(unsafe { info.assume_init() })
}

fn verify_account_credentials(
    uid: u32,
    gid: u32,
    expected_groups: &[libc::gid_t],
) -> Result<(), Error> {
    if unsafe { libc::getuid() } != uid
        || unsafe { libc::geteuid() } != uid
        || unsafe { libc::getgid() } != gid
        || unsafe { libc::getegid() } != gid
    {
        return Err(Error::SpawnFailed);
    }
    let info = process_credentials(unsafe { libc::getpid() })?;
    if info.pbi_uid != uid
        || info.pbi_ruid != uid
        || info.pbi_svuid != uid
        || info.pbi_gid != gid
        || info.pbi_rgid != gid
        || info.pbi_svgid != gid
        || info.pbi_pid as libc::pid_t != unsafe { libc::getpid() }
    {
        return Err(Error::SpawnFailed);
    }
    let actual_groups = current_groups()?;
    // macOS may expose only the initial 16-group cache through getgroups();
    // every reported group must be expected and the requested primary group
    // must be present. The full list came from getgrouplist before initgroups.
    if !actual_groups.contains(&(gid as libc::gid_t))
        || actual_groups
            .iter()
            .any(|group| expected_groups.binary_search(group).is_err())
    {
        return Err(Error::SpawnFailed);
    }
    Ok(())
}

fn verify_user_pty(uid: u32) -> Result<(), Error> {
    let mut identity = None;
    for fd in 0..=2 {
        if unsafe { libc::isatty(fd) } != 1 {
            return Err(Error::SpawnFailed);
        }
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return Err(Error::SpawnFailed);
        }
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFCHR
            || stat.st_uid != uid
            || stat.st_mode & 0o777 != 0o600
        {
            return Err(Error::SpawnFailed);
        }
        let current = (stat.st_dev, stat.st_ino, stat.st_rdev);
        if identity.replace(current).is_some_and(|old| old != current) {
            return Err(Error::SpawnFailed);
        }
    }
    Ok(())
}

fn supervise_user_child(stream: &UnixStream, child: &mut Child) -> Result<(), Error> {
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            Err(_) => return Err(Error::SpawnFailed),
        }

        let mut descriptor = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, 100) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::SpawnFailed);
        }
        if result == 0 {
            continue;
        }
        if descriptor.revents & (libc::POLLNVAL | libc::POLLERR) != 0 {
            return Err(Error::SpawnFailed);
        }
        if descriptor.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let deadline = mach_now_ns()?
                .checked_add(1_000_000_000)
                .ok_or(Error::SpawnFailed)?;
            match super::wire::read_byte(stream, deadline)? {
                Some(b'X') | None => return Ok(()),
                _ => return Err(Error::SpawnFailed),
            }
        }
    }
}

fn ensure_before_deadline(deadline_ns: u64) -> Result<(), Error> {
    if mach_now_ns()? >= deadline_ns {
        return Err(Error::SpawnFailed);
    }
    Ok(())
}

fn mach_now_ns() -> Result<u64, Error> {
    let mut timebase = MachTimebaseInfo { numer: 0, denom: 0 };
    if unsafe { mach_timebase_info(&mut timebase) } != 0
        || timebase.numer == 0
        || timebase.denom == 0
    {
        return Err(Error::SpawnFailed);
    }
    let nanos = (u128::from(unsafe { mach_continuous_time() }) * u128::from(timebase.numer))
        / u128::from(timebase.denom);
    u64::try_from(nanos).map_err(|_| Error::SpawnFailed)
}

use std::os::fd::AsRawFd;
