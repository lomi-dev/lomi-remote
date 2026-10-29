//! Private lifetime protocol. No terminal bytes pass through this socket.
use super::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    path::Path,
    process::{Child, Command, Stdio},
};
const STARTUP: Duration = Duration::from_secs(3);
const PROFILE_LIMIT: usize = 64 * 1024;

static WORKERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
struct Slot;
impl Drop for Slot {
    fn drop(&mut self) {
        WORKERS.fetch_sub(1, Ordering::AcqRel);
    }
}
pub(super) enum Worker {
    #[cfg(target_os = "macos")]
    Privileged(Box<macos_privileged::Worker>),
    Child(ChildWorker),

    #[cfg(all(target_os = "macos", feature = "experimental-macos-coalition-cleanup"))]
    Coalition(Box<macos_coalition::Worker>),
}
impl Worker {
    pub(super) fn finished(&self) -> Result<bool> {
        match self {
            #[cfg(target_os = "macos")]
            Self::Privileged(worker) => worker.finished(),
            Self::Child(worker) => worker.finished(),
            #[cfg(all(target_os = "macos", feature = "experimental-macos-coalition-cleanup"))]
            Self::Coalition(worker) => worker.finished(),
        }
    }
    pub(super) fn stop(&mut self) -> Result<()> {
        match self {
            #[cfg(target_os = "macos")]
            Self::Privileged(worker) => worker.stop(),
            Self::Child(worker) => worker.stop(),
            #[cfg(all(target_os = "macos", feature = "experimental-macos-coalition-cleanup"))]
            Self::Coalition(worker) => worker.stop(),
        }
    }
}
pub(super) struct ChildWorker {
    socket: UnixStream,
    child: Option<Child>,
    stopped: bool,
    reaper: std::sync::mpsc::SyncSender<Child>,
}
impl ChildWorker {
    pub(super) fn finished(&self) -> Result<bool> {
        if self.stopped {
            return Ok(true);
        }
        peek_cleanup(&self.socket)
    }
    pub(super) fn stop(&mut self) -> Result<()> {
        if self.stopped {
            return Ok(());
        }
        let _ = self.socket.shutdown(std::net::Shutdown::Write);
        let mut ack = [0];
        if self.socket.read_exact(&mut ack).is_err() || ack != *b"A" {
            return Err(Error::CleanupFailed);
        }
        let deadline = Instant::now() + STARTUP;
        while let Some(child) = &mut self.child {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => {
                    self.child.take();
                    self.stopped = true;
                    return Ok(());
                }
                Ok(Some(_)) | Err(_) => return Err(Error::CleanupFailed),
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
                Ok(None) => return Err(Error::CleanupFailed),
            }
        }
        Err(Error::CleanupFailed)
    }
}
impl Drop for ChildWorker {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
        if let Some(child) = self.child.take() {
            // Preserve the owned handle when acknowledgement is uncertain. Never
            // kill the watchdog and thereby abandon its shell during cleanup.
            if let Err(error) = self.reaper.send(child) {
                // The reserved reaper has no fallible work before recv. Retain
                // the owned handle even if an unexpected thread failure occurs.
                Box::leak(Box::new(error.0));
            }
        }
    }
}
fn peek_cleanup(socket: &UnixStream) -> Result<bool> {
    let mut ack = [0u8];
    let received = unsafe {
        libc::recv(
            socket.as_raw_fd(),
            ack.as_mut_ptr().cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    match received {
        1 if ack == *b"A" => Ok(true),
        -1 if matches!(
            io::Error::last_os_error().kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) =>
        {
            Ok(false)
        }
        _ => Err(Error::CleanupFailed),
    }
}
fn profile_bytes(profile: &SpawnProfile) -> Result<Vec<u8>> {
    if !profile.executable.is_absolute() || !profile.cwd.is_absolute() {
        return Err(Error::InvalidArgument);
    }
    let mut total = profile
        .executable
        .as_os_str()
        .len()
        .checked_add(profile.cwd.as_os_str().len())
        .ok_or(Error::InvalidArgument)?;
    for value in profile.args.iter().chain(
        profile
            .environment
            .iter()
            .flat_map(|(name, value)| [name, value]),
    ) {
        total = total
            .checked_add(value.len())
            .and_then(|n| n.checked_add(8))
            .filter(|n| *n <= PROFILE_LIMIT)
            .ok_or(Error::InvalidArgument)?;
    }
    if total > PROFILE_LIMIT {
        return Err(Error::InvalidArgument);
    }
    let bytes = serde_json::to_vec(&serde_json::json!({
        "executable": profile.executable.to_str().ok_or(Error::InvalidArgument)?,
        "cwd": profile.cwd.to_str().ok_or(Error::InvalidArgument)?,
        "args": profile.args, "environment": profile.environment,
        "rows": profile.rows, "cols": profile.cols, "history": profile.history,
    }))
    .map_err(|_| Error::InvalidArgument)?;
    if bytes.len() > PROFILE_LIMIT {
        return Err(Error::InvalidArgument);
    }
    Ok(bytes)
}
pub(super) fn spawn(
    executable: &Path,
    profile: &SpawnProfile,
    before_spawn: impl FnOnce() -> bool,
) -> Result<(unix::Pty, Box<dyn Read + Send>)> {
    let bytes = profile_bytes(profile)?;
    let (mut socket, inherited) = UnixStream::pair().map_err(|_| Error::SpawnFailed)?;
    socket
        .set_read_timeout(Some(STARTUP))
        .map_err(|_| Error::SpawnFailed)?;
    socket
        .set_write_timeout(Some(STARTUP))
        .map_err(|_| Error::SpawnFailed)?;
    let lifetime = socket.try_clone().map_err(|_| Error::SpawnFailed)?;
    WORKERS
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            (count < MAX_SESSIONS).then_some(count + 1)
        })
        .map_err(|_| Error::ResourceExhausted)?;
    let slot = Slot;
    let (reaper, receiver) = std::sync::mpsc::sync_channel::<Child>(1);
    thread::Builder::new()
        .name("pty-worker-reap".into())
        .spawn(move || {
            let _slot = slot;
            if let Ok(mut child) = receiver.recv() {
                let _ = child.wait();
            }
        })
        .map_err(|_| Error::SpawnFailed)?;
    let child = Command::new(executable)
        .process_group(0)
        .arg("--internal-pty-worker")
        .stdin(Stdio::from(OwnedFd::from(inherited)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Error::SpawnFailed)?;
    let worker = Worker::Child(ChildWorker {
        socket: lifetime,
        child: Some(child),
        stopped: false,
        reaper,
    });
    // No shell exists until the final G byte, allowing a precise pre-exec fence.
    socket
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| socket.write_all(&bytes))
        .map_err(|_| Error::SpawnFailed)?;
    let mut ready = [0];
    socket
        .read_exact(&mut ready)
        .map_err(|_| Error::SpawnFailed)?;
    if ready != *b"R" || !before_spawn() {
        return Err(Error::SpawnFailed);
    }
    socket
        .write_all(b"G")
        .map_err(|_| Error::SpawnOutcomeUnknown)?;
    let master = receive_fd(&socket).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            Error::SpawnFailed
        } else {
            Error::SpawnOutcomeUnknown
        }
    })?;
    unix::Pty::from_worker(master, worker)
}
fn decode(bytes: &[u8]) -> Option<SpawnProfile> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    Some(SpawnProfile {
        executable: v.get("executable")?.as_str()?.into(),
        cwd: v.get("cwd")?.as_str()?.into(),
        args: serde_json::from_value(v.get("args")?.clone()).ok()?,
        environment: serde_json::from_value(v.get("environment")?.clone()).ok()?,
        shell_integration: None,
        rows: v.get("rows")?.as_u64()?.try_into().ok()?,
        cols: v.get("cols")?.as_u64()?.try_into().ok()?,
        history: v.get("history")?.as_u64()?.try_into().ok()?,
    })
}
pub(super) fn run() -> i32 {
    // The worker is a fresh, single-threaded executable. Reject accidental
    // inheritance from concurrent host FD acquisition before creating any PTY.
    portable_pty::unix::close_random_fds();
    // Linux preserves inherited SIG_IGN across exec. Auto-reaping would destroy
    // the leader's PID/session pin before our final signal, so clear both the
    // disposition and SA_NOCLDWAIT before acquiring any child.
    let mut child_action: libc::sigaction = unsafe { std::mem::zeroed() };
    child_action.sa_sigaction = libc::SIG_DFL;
    if unsafe { libc::sigemptyset(&mut child_action.sa_mask) } < 0
        || unsafe { libc::sigaction(libc::SIGCHLD, &child_action, std::ptr::null_mut()) } < 0
    {
        return 1;
    }
    #[cfg(all(target_os = "macos", feature = "experimental-macos-session-cleanup"))]
    if !macos::available() {
        return 1;
    }

    // stdin is the sole inherited capability; portable-pty replaces shell stdio
    // and closes other descriptors before exec. Keep this endpoint CLOEXEC too.
    let mut socket = unsafe { UnixStream::from_raw_fd(0) };
    if unsafe { libc::fcntl(0, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return 1;
    }
    if socket.set_read_timeout(Some(STARTUP)).is_err()
        || socket.set_write_timeout(Some(STARTUP)).is_err()
    {
        return 1;
    }
    #[cfg(target_os = "linux")]
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } < 0 {
        return 1;
    }
    let mut length = [0; 4];
    if socket.read_exact(&mut length).is_err() {
        return 1;
    }
    let length = u32::from_be_bytes(length) as usize;
    if length > PROFILE_LIMIT {
        return 1;
    }
    let mut bytes = vec![0; length];
    if socket.read_exact(&mut bytes).is_err() {
        return 1;
    }
    let Some(profile) = decode(&bytes) else {
        return 1;
    };
    let before_exec = || {
        if socket.write_all(b"R").is_err() {
            return false;
        }
        let mut go = [0];
        socket.read_exact(&mut go).is_ok() && go == *b"G"
    };
    let acquired = unix::Pty::acquire(&profile, before_exec, true);
    let mut pty = match acquired {
        Ok(pty) => pty,
        Err(error) => {
            let _ = socket.write_all(if error == Error::SpawnFailed {
                b"F"
            } else {
                b"U"
            });
            return 1;
        }
    };
    let fd = pty.worker_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    let nonblocking =
        flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0;
    if nonblocking && send_fd(&socket, fd).is_ok() {
        let _ = socket.set_read_timeout(Some(Duration::from_millis(20)));
        loop {
            let mut byte = [0];
            match socket.read(&mut byte) {
                Ok(_) => break,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => break,
            }
            if pty.leader_exited() {
                break;
            }
        }
    }
    let graceful = pty.begin_worker_shutdown();
    // Observe neither wait/try_wait nor any other reaper during this grace:
    // the original leader must pin the group until stop's final SIGKILL.
    thread::sleep(Duration::from_millis(300));

    loop {
        let cleaned = pty.final_worker_signal();
        #[cfg(all(target_os = "macos", feature = "experimental-macos-session-cleanup"))]
        let cleaned = cleaned.and_then(|_| macos::cleanup_session(pty.worker_group()));

        let cleaned = cleaned.and_then(|_| pty.reap_worker_leader());
        #[cfg(target_os = "linux")]
        let cleaned = cleaned.and_then(|_| linux::reap_descendants());
        #[cfg(not(any(
            target_os = "linux",
            all(target_os = "macos", feature = "experimental-macos-session-cleanup")
        )))]
        let cleaned = cleaned.and(graceful);
        #[cfg(any(
            target_os = "linux",
            all(target_os = "macos", feature = "experimental-macos-session-cleanup")
        ))]
        let _ = graceful; // Platform result supersedes graceful HUP; macOS feature is experimental.
        if cleaned.is_ok() {
            // Default macOS cleanup covers only the owned original group,
            // PTY, and leader. Linux additionally requires kernel ECHILD for
            // all descendants.
            let _ = socket.write_all(b"A");
            return 0;
        }
        thread::sleep(Duration::from_millis(20));
    }
}
fn send_fd(socket: &UnixStream, fd: RawFd) -> io::Result<()> {
    let mut byte = *b"S";
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 8];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as _) } as _;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as _) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), fd);
        if libc::sendmsg(socket.as_raw_fd(), &message, 0) != 1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
fn receive_fd(socket: &UnixStream) -> io::Result<File> {
    let mut byte = [0];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // XNU unp_externalize installs every FD before ancillary copyout, even if
    // MSG_CTRUNC hides their numbers. Its UIPC_MAX_CMSG_FD is 512. Reserve more
    // than that entire kernel maximum plus headers, never a one-FD buffer.
    let mut control = [0usize; 512];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control) as _;
    unsafe {
        #[cfg(target_os = "linux")]
        let flags = libc::MSG_CMSG_CLOEXEC;
        #[cfg(not(target_os = "linux"))]
        let flags = 0;
        let received = libc::recvmsg(socket.as_raw_fd(), &mut message, flags);
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        // recvmsg has already installed every returned rights descriptor. Own
        // all of them before inspecting status/layout so rejection closes them.
        let mut rights: Vec<File> = Vec::new();
        let mut headers = 0;
        let returned = message.msg_controllen as usize;

        let capacity = std::mem::size_of_val(&control);
        let mut valid = message.msg_flags & libc::MSG_CTRUNC == 0 && returned <= capacity;
        message.msg_controllen = returned.min(capacity) as _;
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            headers += 1;
            let offset = (header as usize).checked_sub(control.as_ptr() as usize);
            let Some(remaining) =
                offset.and_then(|offset| (message.msg_controllen as usize).checked_sub(offset))
            else {
                valid = false;
                break;
            };
            if remaining < std::mem::size_of::<libc::cmsghdr>() {
                valid = false;
                break;
            }
            let length = (*header).cmsg_len as usize;
            let base = libc::CMSG_LEN(0) as usize;
            if length < base {
                valid = false;
                break;
            }
            valid &= length <= remaining;
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let bytes = length.min(remaining).saturating_sub(base);
                valid &= bytes % std::mem::size_of::<RawFd>() == 0;
                for index in 0..bytes / std::mem::size_of::<RawFd>() {
                    let fd = std::ptr::read_unaligned(
                        libc::CMSG_DATA(header).cast::<RawFd>().add(index),
                    );
                    if fd < 0 || rights.iter().any(|owned| owned.as_raw_fd() == fd) {
                        valid = false;
                        continue;
                    }
                    let owned = File::from_raw_fd(fd);
                    valid &= libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) == 0;
                    rights.push(owned);
                }
            } else {
                valid = false;
            }
            if length > remaining {
                break;
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
        if received == 1 && byte == *b"F" && valid && headers == 0 && rights.is_empty() {
            return Err(io::ErrorKind::NotFound.into());
        }
        if received != 1 || byte != *b"S" || !valid || headers != 1 || rights.len() != 1 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(rights.pop().unwrap())
    }
}
#[cfg(target_os = "linux")]
mod linux;
#[cfg(all(target_os = "macos", feature = "experimental-macos-session-cleanup"))]
mod macos;
#[cfg(all(target_os = "macos", feature = "experimental-macos-coalition-cleanup"))]
pub(super) mod macos_coalition;
#[cfg(target_os = "macos")]
pub(super) mod macos_privileged;
