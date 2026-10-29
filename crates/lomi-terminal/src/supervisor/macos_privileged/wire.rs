//! Bounded per-generation root-controller protocol. The authenticated control
//! stream carries setup and lifecycle sentinels only; terminal bytes travel on
//! the PTY master transferred with the single `D` sentinel.

use super::{Error, capability};
use crate::SpawnProfile;
use std::{
    collections::HashSet,
    io,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd},
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    path::{Path, PathBuf},
};
use uuid::Uuid;

const FRAME_LIMIT: usize = 128 * 1024;
const PROFILE_LIMIT: usize = 64 * 1024;
const ARGUMENT_LIMIT: usize = 256;
const ENVIRONMENT_LIMIT: usize = 256;
const ANCILLARY_FD_LIMIT: usize = 16;

#[repr(C)]
struct MachTimebaseInfo {
    numer: u32,
    denom: u32,
}

unsafe extern "C" {
    fn mach_continuous_time() -> u64;
    fn mach_timebase_info(info: *mut MachTimebaseInfo) -> i32;
}

#[derive(Clone)]
pub(super) struct StartRequest {
    pub(super) generation_nonce: String,
    pub(super) deadline_ns: u64,
    pub(super) profile: SpawnProfile,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ControllerHello {
    pub(super) generation_nonce: String,
    pub(super) registration_key: String,
    pub(super) pid: i32,
    pub(super) pidversion: u32,
    pub(super) audit: [u32; 8],
    pub(super) resource: u64,
    pub(super) jetsam: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Decision {
    Commit,
    Cancel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StartIntent {
    Start,
    Cancel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FinalAuthorizationRequest {
    Requested,
    Cancel,
}

#[derive(Debug)]
pub(super) enum ReadyReply {
    Master(OwnedFd),
    Refused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ChildReady {
    Dropped,
    Refused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SpawnOutcome {
    Started,
    Refused,
}

pub(super) fn read_start(
    stream: &UnixStream,
    expected_nonce: &str,
    expected_deadline_ns: u64,
) -> Result<StartRequest, Error> {
    let value = read_json(stream, expected_deadline_ns)?;
    parse_start(value, expected_nonce, expected_deadline_ns)
}

/// Connect to a registered Unix socket without allowing a full listen backlog
/// to block past the caller's original absolute Mach deadline.
pub(super) fn connect(path: &Path, deadline_ns: u64) -> Result<UnixStream, Error> {
    let bytes = path.as_os_str().as_bytes();
    let path_offset = std::mem::offset_of!(libc::sockaddr_un, sun_path);
    let empty_address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let path_capacity = empty_address.sun_path.len();
    if !path.is_absolute() || bytes.is_empty() || bytes.len() + 1 > path_capacity {
        return Err(Error::InvalidArgument);
    }
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(Error::SpawnFailed);
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let descriptor_flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    let status_flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if descriptor_flags < 0
        || status_flags < 0
        || unsafe {
            libc::fcntl(
                fd.as_raw_fd(),
                libc::F_SETFD,
                descriptor_flags | libc::FD_CLOEXEC,
            )
        } != 0
        || unsafe {
            libc::fcntl(
                fd.as_raw_fd(),
                libc::F_SETFL,
                status_flags | libc::O_NONBLOCK,
            )
        } != 0
    {
        return Err(Error::SpawnFailed);
    }

    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as _;
    let address_length = path_offset + bytes.len() + 1;
    address.sun_len = address_length
        .try_into()
        .map_err(|_| Error::InvalidArgument)?;
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            address.sun_path.as_mut_ptr().cast::<u8>(),
            bytes.len(),
        );
    }
    let connected = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            address_length as libc::socklen_t,
        )
    };
    if connected != 0 {
        let error = io::Error::last_os_error();
        if !error.raw_os_error().is_some_and(|code| {
            [libc::EINPROGRESS, libc::EALREADY, libc::EAGAIN, libc::EINTR].contains(&code)
        }) {
            return Err(Error::SpawnFailed);
        }
        wait_fd_ready(fd.as_raw_fd(), libc::POLLOUT, deadline_ns)?;
        let mut socket_error: libc::c_int = 0;
        let mut length = std::mem::size_of_val(&socket_error) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut socket_error as *mut libc::c_int).cast(),
                &mut length,
            )
        } != 0
            || length as usize != std::mem::size_of_val(&socket_error)
            || socket_error != 0
        {
            return Err(Error::SpawnFailed);
        }
    }
    if unsafe {
        libc::fcntl(
            fd.as_raw_fd(),
            libc::F_SETFL,
            status_flags & !libc::O_NONBLOCK,
        )
    } != 0
    {
        return Err(Error::SpawnFailed);
    }
    let stream = unsafe { UnixStream::from_raw_fd(fd.into_raw_fd()) };
    configure_sigpipe_suppression(&stream)?;
    Ok(stream)
}

pub(super) fn write_start(stream: &UnixStream, request: &StartRequest) -> Result<(), Error> {
    validate_nonce(&request.generation_nonce)?;
    validate_profile(&request.profile)?;
    if request.deadline_ns == 0 {
        return Err(Error::InvalidArgument);
    }
    let profile = profile_value(&request.profile)?;
    let value = serde_json::json!({
        "version": 1,
        "kind": "start",
        "generationNonce": request.generation_nonce,
        "deadlineNs": request.deadline_ns,
        "profile": profile,
    });
    write_json(stream, &value, request.deadline_ns)
}

pub(super) fn write_hello(
    stream: &UnixStream,
    generation_nonce: &str,
    registration_key: &str,
    identity: &capability::Identity,
    deadline_ns: u64,
) -> Result<(), Error> {
    validate_nonce(generation_nonce)?;
    validate_registration_key(registration_key)?;
    if identity.audit()[1] != 0
        || identity.audit()[5] as i32 != identity.pid()
        || identity.audit()[7] != identity.pidversion()
    {
        return Err(Error::InvalidArgument);
    }
    let value = serde_json::json!({
        "version": 1,
        "kind": "hello",
        "generationNonce": generation_nonce,
        "registrationKey": registration_key,
        "controller": {
            "pid": identity.pid(),
            "pidVersion": identity.pidversion(),
            "audit": identity.audit(),
            "resource": identity.resource(),
            "jetsam": identity.jetsam(),
        },
    });
    write_json(stream, &value, deadline_ns)
}

pub(super) fn read_hello(stream: &UnixStream, deadline_ns: u64) -> Result<ControllerHello, Error> {
    let value = read_json(stream, deadline_ns)?;
    parse_hello(value)
}

pub(super) fn parse_hello(value: serde_json::Value) -> Result<ControllerHello, Error> {
    let object = exact_object(
        &value,
        &[
            "version",
            "kind",
            "generationNonce",
            "registrationKey",
            "controller",
        ],
    )?;
    if number_u64(object, "version")? != 1 || string(object, "kind")? != "hello" {
        return Err(Error::SpawnFailed);
    }
    let generation_nonce = string(object, "generationNonce")?;
    validate_nonce(&generation_nonce)?;
    let registration_key = string(object, "registrationKey")?;
    validate_registration_key(&registration_key)?;
    let controller = exact_object(
        object.get("controller").ok_or(Error::SpawnFailed)?,
        &["pid", "pidVersion", "audit", "resource", "jetsam"],
    )?;
    let audit_value = controller
        .get("audit")
        .and_then(serde_json::Value::as_array)
        .filter(|values| values.len() == 8)
        .ok_or(Error::SpawnFailed)?;
    let mut audit = [0u32; 8];
    for (target, value) in audit.iter_mut().zip(audit_value) {
        *target = value
            .as_u64()
            .and_then(|number| u32::try_from(number).ok())
            .ok_or(Error::SpawnFailed)?;
    }
    let pid = controller
        .get("pid")
        .and_then(serde_json::Value::as_i64)
        .and_then(|number| i32::try_from(number).ok())
        .filter(|pid| *pid > 0)
        .ok_or(Error::SpawnFailed)?;
    let pidversion = number_u32(controller, "pidVersion")?;
    let resource = number_u64(controller, "resource")?;
    let jetsam = number_u64(controller, "jetsam")?;
    if pidversion == 0
        || resource == 0
        || jetsam == 0
        || audit[1] != 0
        || audit[5] as i32 != pid
        || audit[7] != pidversion
    {
        return Err(Error::SpawnFailed);
    }
    Ok(ControllerHello {
        generation_nonce,
        registration_key,
        pid,
        pidversion,
        audit,
        resource,
        jetsam,
    })
}

pub(super) fn send_json(
    stream: &UnixStream,
    value: &serde_json::Value,
    deadline_ns: u64,
) -> Result<(), Error> {
    write_json(stream, value, deadline_ns)
}

fn write_json(
    stream: &UnixStream,
    value: &serde_json::Value,
    deadline_ns: u64,
) -> Result<(), Error> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::InvalidArgument)?;
    write_frame(stream, &bytes, deadline_ns)
}

pub(super) fn read_json(stream: &UnixStream, deadline_ns: u64) -> Result<serde_json::Value, Error> {
    let bytes = read_frame(stream, deadline_ns)?;
    serde_json::from_slice(&bytes).map_err(|_| Error::SpawnFailed)
}

/// Reject ambiguous administrative frames rather than normalizing duplicate
/// keys, alternate number spellings or whitespace before authorization.
pub(super) fn read_canonical_json(
    stream: &UnixStream,
    deadline_ns: u64,
) -> Result<serde_json::Value, Error> {
    let bytes = read_frame(stream, deadline_ns)?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| Error::SpawnFailed)?;
    if serde_json::to_vec(&value).map_err(|_| Error::SpawnFailed)? != bytes {
        return Err(Error::SpawnFailed);
    }
    Ok(value)
}

/// Transfer the controller's PTY master with the one-byte Host-ready sentinel.
pub(super) fn send_d_with_master(
    stream: &UnixStream,
    master_fd: RawFd,
    deadline_ns: u64,
) -> Result<(), Error> {
    send_fd(stream, b'D', master_fd, deadline_ns)
}

pub(super) fn send_fd(
    stream: &UnixStream,
    marker: u8,
    master_fd: RawFd,
    deadline_ns: u64,
) -> Result<(), Error> {
    if master_fd < 0 || unsafe { libc::fcntl(master_fd, libc::F_GETFD) } < 0 {
        return Err(Error::SpawnFailed);
    }
    disable_sigpipe(stream)?;
    wait_writable(stream, deadline_ns)?;
    let mut byte = marker;
    let mut iovec = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 8];
    let control_len =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as libc::c_uint) as usize };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control_len as _;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null() {
            return Err(Error::SpawnFailed);
        }
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as libc::c_uint) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), master_fd);
    }
    let sent = loop {
        let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_DONTWAIT) };
        if sent >= 0 {
            break sent;
        }
        if !matches!(
            io::Error::last_os_error().kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
        ) {
            return Err(Error::SpawnFailed);
        }
        wait_writable(stream, deadline_ns)?;
    };
    if sent != 1 {
        return Err(Error::SpawnOutcomeUnknown);
    }
    Ok(())
}

/// Receive the sentinel and its single descriptor. The returned fd is CLOEXEC
/// and owned by the caller.
pub(super) fn receive_d_with_master(
    stream: &UnixStream,
    deadline_ns: u64,
) -> Result<OwnedFd, Error> {
    receive_fd(stream, b'D', deadline_ns)
}

/// Initial broker reply: either D with exactly the PTY master descriptor, or
/// N with no descriptor after the controller has durably cleaned a known
/// pre-exec refusal.
pub(super) fn receive_ready(stream: &UnixStream, deadline_ns: u64) -> Result<ReadyReply, Error> {
    let (byte, descriptors) = receive_byte_and_fds(stream, deadline_ns)?;
    match (byte, descriptors.len()) {
        (Some(b'D'), 1) => {
            let descriptor = descriptors.into_iter().next().ok_or(Error::SpawnFailed)?;
            if unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0
            {
                return Err(Error::SpawnFailed);
            }
            Ok(ReadyReply::Master(descriptor))
        }
        (Some(b'N'), 0) => Ok(ReadyReply::Refused),
        _ => {
            close_all(descriptors);
            Err(Error::SpawnFailed)
        }
    }
}

pub(super) fn receive_fd(
    stream: &UnixStream,
    expected_marker: u8,
    deadline_ns: u64,
) -> Result<OwnedFd, Error> {
    let (byte, descriptors) = receive_byte_and_fds(stream, deadline_ns)?;
    if byte != Some(expected_marker) || descriptors.len() != 1 {
        close_all(descriptors);
        return Err(Error::SpawnFailed);
    }
    let fd = descriptors.into_iter().next().ok_or(Error::SpawnFailed)?;
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(Error::SpawnFailed);
    }
    Ok(fd)
}

pub(super) fn read_decision(stream: &UnixStream, deadline_ns: u64) -> Result<Decision, Error> {
    let (byte, descriptors) = receive_byte_and_fds(stream, deadline_ns)?;
    if !descriptors.is_empty() {
        close_all(descriptors);
        return Err(Error::SpawnFailed);
    }
    match byte {
        Some(b'E') => Ok(Decision::Commit),
        Some(b'X') | None => Ok(Decision::Cancel),
        _ => Err(Error::SpawnFailed),
    }
}

pub(super) fn write_child_dropped(stream: &UnixStream, deadline_ns: u64) -> Result<(), Error> {
    send_byte(stream, b'D', deadline_ns)
}

pub(super) fn read_child_ready(stream: &UnixStream, deadline_ns: u64) -> Result<ChildReady, Error> {
    match read_byte(stream, deadline_ns)? {
        Some(b'D') => Ok(ChildReady::Dropped),
        Some(b'N') => Ok(ChildReady::Refused),
        _ => Err(Error::SpawnFailed),
    }
}

pub(super) fn write_spawn_outcome(
    stream: &UnixStream,
    outcome: SpawnOutcome,
    deadline_ns: u64,
) -> Result<(), Error> {
    send_byte(
        stream,
        match outcome {
            SpawnOutcome::Started => b'S',
            SpawnOutcome::Refused => b'N',
        },
        deadline_ns,
    )
}

pub(super) fn read_spawn_outcome(
    stream: &UnixStream,
    deadline_ns: u64,
) -> Result<SpawnOutcome, Error> {
    match read_byte(stream, deadline_ns)? {
        Some(b'S') => Ok(SpawnOutcome::Started),
        Some(b'N') => Ok(SpawnOutcome::Refused),
        _ => Err(Error::SpawnFailed),
    }
}

/// Host intent is only permission to persist the start transition. It does
/// not authorize the trusted child to execute the shell.
pub(super) fn write_start_intent(stream: &UnixStream, deadline_ns: u64) -> Result<(), Error> {
    send_byte(stream, b'I', deadline_ns)
}

pub(super) fn read_start_intent(
    stream: &UnixStream,
    deadline_ns: u64,
) -> Result<StartIntent, Error> {
    match read_byte(stream, deadline_ns)? {
        Some(b'I') => Ok(StartIntent::Start),
        Some(b'X') | None => Ok(StartIntent::Cancel),
        _ => Err(Error::SpawnFailed),
    }
}

/// Sent only after the durable start transition. The Host must perform a new
/// authorization gate after receiving this marker before sending final E.
pub(super) fn write_final_authorization_request(
    stream: &UnixStream,
    deadline_ns: u64,
) -> Result<(), Error> {
    send_byte(stream, b'F', deadline_ns)
}

pub(super) fn read_final_authorization_request(
    stream: &UnixStream,
    deadline_ns: u64,
) -> Result<FinalAuthorizationRequest, Error> {
    match read_byte(stream, deadline_ns)? {
        Some(b'F') => Ok(FinalAuthorizationRequest::Requested),
        Some(b'X') | None => Ok(FinalAuthorizationRequest::Cancel),
        _ => Err(Error::SpawnFailed),
    }
}

pub(super) fn send_byte(stream: &UnixStream, byte: u8, deadline_ns: u64) -> Result<(), Error> {
    write_byte(stream, byte, deadline_ns)
}

/// Make one nonblocking marker attempt. Root broker callers must run their
/// final Host gate immediately before each call and repeat that gate after a
/// `false` (backpressure) result; this helper never waits between the gate and
/// the kernel send.
pub(super) fn try_send_byte_once(stream: &UnixStream, byte: u8) -> Result<bool, Error> {
    let result = unsafe {
        libc::send(
            stream.as_raw_fd(),
            (&byte as *const u8).cast(),
            1,
            libc::MSG_DONTWAIT,
        )
    };
    if result == 1 {
        return Ok(true);
    }
    if result < 0
        && matches!(
            io::Error::last_os_error().kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        )
    {
        return Ok(false);
    }
    Err(Error::SpawnOutcomeUnknown)
}

/// Configure a connected or accepted stream before a final Host gate. This
/// keeps SO_NOSIGPIPE setup out of the one-shot nonblocking E send path.
pub(super) fn configure_sigpipe_suppression(stream: &UnixStream) -> Result<(), Error> {
    disable_sigpipe(stream)
}

pub(super) fn read_byte(stream: &UnixStream, deadline_ns: u64) -> Result<Option<u8>, Error> {
    let (byte, descriptors) = receive_byte_and_fds(stream, deadline_ns)?;
    if !descriptors.is_empty() {
        close_all(descriptors);
        return Err(Error::SpawnFailed);
    }
    Ok(byte)
}

/// Require the original deadline to remain live and both control streams to
/// remain open and quiet after final E. This uses only a zero-time poll, so
/// the controller performs no blocking work between fresh authorization and
/// the one-shot child commit send.
pub(super) fn require_final_commit_window(
    host_stream: &UnixStream,
    child_stream: &UnixStream,
    deadline_ns: u64,
) -> Result<(), Error> {
    if mach_now_ns()? >= deadline_ns {
        return Err(Error::SpawnFailed);
    }
    let mut descriptors = [
        libc::pollfd {
            fd: host_stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: child_stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        descriptors
            .iter_mut()
            .for_each(|descriptor| descriptor.revents = 0);
        let result = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, 0) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                if mach_now_ns()? < deadline_ns {
                    continue;
                }
            }
            return Err(Error::SpawnFailed);
        }
        if result != 0
            || descriptors.iter().any(|descriptor| descriptor.revents != 0)
            || mach_now_ns()? >= deadline_ns
        {
            return Err(Error::SpawnFailed);
        }
        return Ok(());
    }
}

/// Poll both lifecycle sockets without resetting an absolute Mach deadline.
/// When no deadline is supplied this remains a bounded 100 ms poll so the
/// controller can sample direct-child exit state between control messages.
pub(super) fn poll_streams(
    broker_fd: RawFd,
    child_fd: Option<RawFd>,
    deadline_ns: Option<u64>,
) -> Result<(bool, bool), Error> {
    if broker_fd < 0 || child_fd.is_some_and(|fd| fd < 0) {
        return Err(Error::SpawnFailed);
    }
    loop {
        let timeout = if let Some(deadline) = deadline_ns {
            let now = mach_now_ns()?;
            let remaining = deadline.checked_sub(now).ok_or(Error::SpawnFailed)?;
            if remaining == 0 {
                return Err(Error::SpawnFailed);
            }
            remaining.div_ceil(1_000_000).min(100).max(1) as i32
        } else {
            100
        };
        let mut descriptors = [
            libc::pollfd {
                fd: broker_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: child_fd.unwrap_or(-1),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let count = if child_fd.is_some() { 2 } else { 1 };
        let result = unsafe { libc::poll(descriptors.as_mut_ptr(), count, timeout) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::SpawnFailed);
        }
        if descriptors[..count as usize]
            .iter()
            .any(|descriptor| descriptor.revents & libc::POLLNVAL != 0)
        {
            return Err(Error::SpawnFailed);
        }
        let readable = |events: i16| events & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0;
        return Ok((
            readable(descriptors[0].revents),
            readable(descriptors[1].revents),
        ));
    }
}

pub(super) fn write_cancel(stream: &UnixStream, deadline_ns: u64) -> Result<(), Error> {
    write_byte(stream, b'X', deadline_ns)
}

pub(super) fn write_ack_cleaned(stream: &UnixStream) -> Result<(), Error> {
    disable_sigpipe(stream).map_err(|_| Error::CleanupFailed)?;
    let byte = b'A';
    let written = unsafe {
        libc::send(
            stream.as_raw_fd(),
            (&byte as *const u8).cast(),
            1,
            libc::MSG_DONTWAIT,
        )
    };
    (written == 1).then_some(()).ok_or(Error::CleanupFailed)
}

pub(super) fn parse_start(
    value: serde_json::Value,
    expected_nonce: &str,
    expected_deadline_ns: u64,
) -> Result<StartRequest, Error> {
    let object = exact_object(
        &value,
        &[
            "version",
            "kind",
            "generationNonce",
            "deadlineNs",
            "profile",
        ],
    )?;
    if number_u64(object, "version")? != 1 || string(object, "kind")? != "start" {
        return Err(Error::SpawnFailed);
    }
    let nonce = string(object, "generationNonce")?;
    validate_nonce(&nonce)?;
    let deadline_ns = number_u64(object, "deadlineNs")?;
    if nonce != expected_nonce || deadline_ns != expected_deadline_ns || deadline_ns == 0 {
        return Err(Error::SpawnFailed);
    }

    let value = object.get("profile").ok_or(Error::SpawnFailed)?;
    let profile_object = exact_object(
        value,
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
    let args = profile_object
        .get("args")
        .and_then(serde_json::Value::as_array)
        .filter(|args| args.len() <= ARGUMENT_LIMIT)
        .ok_or(Error::SpawnFailed)?
        .iter()
        .map(|value| value.as_str().map(str::to_owned).ok_or(Error::SpawnFailed))
        .collect::<Result<Vec<_>, _>>()?;
    let environment = profile_object
        .get("environment")
        .and_then(serde_json::Value::as_array)
        .filter(|environment| environment.len() <= ENVIRONMENT_LIMIT)
        .ok_or(Error::SpawnFailed)?
        .iter()
        .map(|pair| {
            let pair = pair.as_array().ok_or(Error::SpawnFailed)?;
            if pair.len() != 2 {
                return Err(Error::SpawnFailed);
            }
            Ok((
                pair[0].as_str().ok_or(Error::SpawnFailed)?.to_owned(),
                pair[1].as_str().ok_or(Error::SpawnFailed)?.to_owned(),
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let profile = SpawnProfile {
        executable: PathBuf::from(string(profile_object, "executable")?),
        args,
        cwd: PathBuf::from(string(profile_object, "cwd")?),
        environment,
        shell_integration: None,
        rows: number_u16(profile_object, "rows")?,
        cols: number_u16(profile_object, "cols")?,
        history: usize::try_from(number_u64(profile_object, "history")?)
            .map_err(|_| Error::SpawnFailed)?,
    };
    validate_profile(&profile)?;
    Ok(StartRequest {
        generation_nonce: nonce,
        deadline_ns,
        profile,
    })
}

fn validate_profile(profile: &SpawnProfile) -> Result<(), Error> {
    if !profile.executable.is_absolute()
        || !profile.cwd.is_absolute()
        || profile.args.len() > ARGUMENT_LIMIT
        || profile.environment.len() > ENVIRONMENT_LIMIT
        || profile.rows == 0
        || profile.rows > 1000
        || profile.cols == 0
        || profile.cols > 1000
        || profile.history > 1_000_000
    {
        return Err(Error::InvalidArgument);
    }
    let executable = profile.executable.to_str().ok_or(Error::InvalidArgument)?;
    let cwd = profile.cwd.to_str().ok_or(Error::InvalidArgument)?;
    if executable.contains('\0') || cwd.contains('\0') {
        return Err(Error::InvalidArgument);
    }
    let mut total = executable.len().saturating_add(cwd.len());
    for argument in &profile.args {
        if argument.contains('\0') || argument.len() > PROFILE_LIMIT {
            return Err(Error::InvalidArgument);
        }
        total = total
            .checked_add(argument.len() + 8)
            .ok_or(Error::InvalidArgument)?;
    }
    let mut names = HashSet::with_capacity(profile.environment.len());
    for (name, value) in &profile.environment {
        if name.is_empty()
            || name.contains('=')
            || name.contains('\0')
            || value.contains('\0')
            || name.len() > 256
            || value.len() > PROFILE_LIMIT
            || !names.insert(name)
        {
            return Err(Error::InvalidArgument);
        }
        total = total
            .checked_add(name.len() + value.len() + 8)
            .ok_or(Error::InvalidArgument)?;
    }
    if total > PROFILE_LIMIT {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

pub(super) fn profile_value(profile: &SpawnProfile) -> Result<serde_json::Value, Error> {
    validate_profile(profile)?;
    Ok(serde_json::json!({
        "executable": profile.executable.to_str().ok_or(Error::InvalidArgument)?,
        "args": profile.args,
        "cwd": profile.cwd.to_str().ok_or(Error::InvalidArgument)?,
        "environment": profile.environment,
        "rows": profile.rows,
        "cols": profile.cols,
        "history": profile.history,
    }))
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

fn validate_nonce(nonce: &str) -> Result<(), Error> {
    if nonce.len() != 36
        || nonce.as_bytes()[8] != b'-'
        || nonce.as_bytes()[13] != b'-'
        || nonce.as_bytes()[18] != b'-'
        || nonce.as_bytes()[23] != b'-'
        || !nonce
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 8 | 13 | 18 | 23) || byte.is_ascii_hexdigit())
        || nonce.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(Error::InvalidArgument);
    }
    let parsed = Uuid::parse_str(nonce).map_err(|_| Error::InvalidArgument)?;
    if parsed.to_string() != nonce {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

fn validate_registration_key(key: &str) -> Result<(), Error> {
    if key.len() != 64
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

fn read_frame(stream: &UnixStream, deadline_ns: u64) -> Result<Vec<u8>, Error> {
    let mut header = [0u8; 4];
    read_exact_until(stream, &mut header, deadline_ns)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > FRAME_LIMIT {
        return Err(Error::SpawnFailed);
    }
    let mut bytes = vec![0; length];
    read_exact_until(stream, &mut bytes, deadline_ns)?;
    Ok(bytes)
}

fn write_frame(stream: &UnixStream, bytes: &[u8], deadline_ns: u64) -> Result<(), Error> {
    if bytes.is_empty() || bytes.len() > FRAME_LIMIT || bytes.len() > u32::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    write_exact_until(stream, &(bytes.len() as u32).to_be_bytes(), deadline_ns)?;
    write_exact_until(stream, bytes, deadline_ns)
}

fn write_byte(stream: &UnixStream, byte: u8, deadline_ns: u64) -> Result<(), Error> {
    write_exact_until(stream, &[byte], deadline_ns)
}

fn read_exact_until(stream: &UnixStream, bytes: &mut [u8], deadline_ns: u64) -> Result<(), Error> {
    let mut offset = 0;
    while offset < bytes.len() {
        wait_readable(stream, deadline_ns)?;
        let count = receive_chunk_without_fds(stream, &mut bytes[offset..], deadline_ns)?;
        if count > 0 {
            offset += count as usize;
            continue;
        }
        if count == 0 {
            return Err(Error::SpawnFailed);
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(Error::SpawnFailed);
        }
    }
    Ok(())
}

fn write_exact_until(stream: &UnixStream, bytes: &[u8], deadline_ns: u64) -> Result<(), Error> {
    disable_sigpipe(stream)?;
    let mut offset = 0;
    while offset < bytes.len() {
        wait_writable(stream, deadline_ns)?;
        let count = unsafe {
            libc::send(
                stream.as_raw_fd(),
                bytes[offset..].as_ptr().cast(),
                bytes.len() - offset,
                libc::MSG_DONTWAIT,
            )
        };
        if count > 0 {
            offset += count as usize;
            continue;
        }
        if count == 0 {
            return Err(Error::SpawnOutcomeUnknown);
        }
        if !matches!(
            io::Error::last_os_error().kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
        ) {
            return Err(Error::SpawnOutcomeUnknown);
        }
    }
    Ok(())
}

fn wait_readable(stream: &UnixStream, deadline_ns: u64) -> Result<(), Error> {
    wait_ready(stream, libc::POLLIN, deadline_ns)
}

fn wait_writable(stream: &UnixStream, deadline_ns: u64) -> Result<(), Error> {
    wait_ready(stream, libc::POLLOUT, deadline_ns)
}

fn wait_ready(stream: &UnixStream, events: i16, deadline_ns: u64) -> Result<(), Error> {
    wait_fd_ready(stream.as_raw_fd(), events, deadline_ns)
}

fn wait_fd_ready(fd: RawFd, events: i16, deadline_ns: u64) -> Result<(), Error> {
    loop {
        let now = mach_now_ns()?;
        let remaining = deadline_ns.checked_sub(now).ok_or(Error::SpawnFailed)?;
        if remaining == 0 {
            return Err(Error::SpawnFailed);
        }
        let timeout = remaining.div_ceil(1_000_000).min(i32::MAX as u64) as i32;
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if result > 0 {
            if descriptor.revents & (libc::POLLNVAL | libc::POLLERR) != 0 {
                return Err(Error::SpawnFailed);
            }
            if descriptor.revents & (events | libc::POLLHUP) != 0 {
                return Ok(());
            }
        } else if result < 0 {
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return Err(Error::SpawnFailed);
            }
        }
    }
}

pub(super) fn mach_now_ns() -> Result<u64, Error> {
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

fn receive_byte_and_fds(
    stream: &UnixStream,
    deadline_ns: u64,
) -> Result<(Option<u8>, Vec<OwnedFd>), Error> {
    let mut byte = 0u8;
    let mut iovec = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 64];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control) as _;
    let received = loop {
        wait_readable(stream, deadline_ns)?;
        message.msg_controllen = std::mem::size_of_val(&control) as _;
        message.msg_flags = 0;
        let received =
            unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_DONTWAIT) };
        if received >= 0 {
            break received;
        }
        if !matches!(
            io::Error::last_os_error().kind(),
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
        ) {
            return Err(Error::SpawnFailed);
        }
    };
    let descriptors = collect_rights(&message)?;
    if message.msg_flags & libc::MSG_CTRUNC != 0 {
        close_all(descriptors);
        return Err(Error::SpawnFailed);
    }
    if received == 0 {
        return Ok((None, descriptors));
    }
    if received != 1 {
        close_all(descriptors);
        return Err(Error::SpawnFailed);
    }
    Ok((Some(byte), descriptors))
}

fn collect_rights(message: &libc::msghdr) -> Result<Vec<OwnedFd>, Error> {
    let mut descriptors = Vec::new();
    let mut valid = true;
    let mut rights_headers = 0usize;
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(message);
        while !header.is_null() {
            let length = (*header).cmsg_len as usize;
            let base = libc::CMSG_LEN(0) as usize;
            let control_base = message.msg_control as usize;
            let Some(offset) = (header as usize).checked_sub(control_base) else {
                valid = false;
                break;
            };
            let Some(remaining) = (message.msg_controllen as usize).checked_sub(offset) else {
                valid = false;
                break;
            };
            if length < base || length > remaining {
                valid = false;
                break;
            }
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                rights_headers += 1;
                if rights_headers > 1 {
                    valid = false;
                }
                let data_len = length - base;
                if data_len == 0 || data_len % std::mem::size_of::<RawFd>() != 0 {
                    valid = false;
                } else {
                    for index in 0..data_len / std::mem::size_of::<RawFd>() {
                        let fd = std::ptr::read_unaligned(
                            libc::CMSG_DATA(header).cast::<RawFd>().add(index),
                        );
                        if fd < 0 {
                            valid = false;
                        } else {
                            descriptors.push(OwnedFd::from_raw_fd(fd));
                        }
                    }
                }
            } else {
                valid = false;
            }
            header = libc::CMSG_NXTHDR(message, header);
        }
    }
    if !valid || descriptors.len() > ANCILLARY_FD_LIMIT {
        close_all(descriptors);
        Err(Error::SpawnFailed)
    } else {
        Ok(descriptors)
    }
}

fn receive_chunk_without_fds(
    stream: &UnixStream,
    bytes: &mut [u8],
    deadline_ns: u64,
) -> Result<isize, Error> {
    let mut iovec = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut control = [0usize; 64];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control) as _;
    let received = loop {
        wait_readable(stream, deadline_ns)?;
        message.msg_controllen = std::mem::size_of_val(&control) as _;
        message.msg_flags = 0;
        let received =
            unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_DONTWAIT) };
        if received >= 0 {
            break received;
        }
        match io::Error::last_os_error().kind() {
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock => {}
            _ => return Err(Error::SpawnFailed),
        }
    };
    let descriptors = collect_rights(&message)?;
    if message.msg_flags & libc::MSG_CTRUNC != 0 || !descriptors.is_empty() {
        close_all(descriptors);
        return Err(Error::SpawnFailed);
    }
    Ok(received)
}

fn close_all(descriptors: Vec<OwnedFd>) {
    drop(descriptors);
}

fn disable_sigpipe(stream: &UnixStream) -> Result<(), Error> {
    let enabled: libc::c_int = 1;
    if unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(Error::SpawnFailed)
    }
}
