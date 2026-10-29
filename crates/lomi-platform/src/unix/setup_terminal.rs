//! Private-terminal supervision for privileged selected-account setup.
//!
//! A selected process must never inherit the administrator's controlling
//! terminal: on Linux that would let it inject input into the still-running
//! administrator shell with TIOCSTI. Every launch therefore gets a fresh
//! controlling PTY. When the caller has an interactive terminal, this module
//! relays bounded input/output through it. Otherwise only non-terminal caller
//! streams are inherited and the private PTY is retained for hangup cleanup.

use std::{
    collections::VecDeque,
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicI32, Ordering},
    time::{Duration, Instant},
};

use std::os::unix::process::CommandExt;

const RELAY_BUFFER_BYTES: usize = 64 * 1024;
const RELAY_CHUNK_BYTES: usize = 8 * 1024;
const POLL_INTERVAL_MS: i32 = 50;
const POST_EXIT_DRAIN: Duration = Duration::from_millis(250);
const MAX_POST_EXIT_DRAIN: Duration = Duration::from_secs(2);
const RELAY_SIGNALS: [libc::c_int; 3] = [libc::SIGHUP, libc::SIGINT, libc::SIGTERM];

static RELAY_SIGNAL_WRITE_FD: AtomicI32 = AtomicI32::new(-1);
static RELAY_SIGNAL_CAUGHT: AtomicI32 = AtomicI32::new(0);

pub(super) enum RunError {
    BeforeSpawn,
    AfterSpawn,
}

#[cfg(target_os = "linux")]
#[link(name = "util")]
unsafe extern "C" {
    fn openpty(
        master: *mut libc::c_int,
        slave: *mut libc::c_int,
        name: *mut libc::c_char,
        termios: *const libc::termios,
        window: *const libc::winsize,
    ) -> libc::c_int;
}

extern "C" fn capture_relay_signal(signal: libc::c_int) {
    let _ = RELAY_SIGNAL_CAUGHT.compare_exchange(0, signal, Ordering::Relaxed, Ordering::Relaxed);
    let fd = RELAY_SIGNAL_WRITE_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = [signal as u8];
        // `write` is async-signal-safe. The atomic preserves the signal even
        // if a full nonblocking pipe cannot accept this wakeup byte.
        unsafe { libc::write(fd, byte.as_ptr().cast(), byte.len()) };
    }
}

struct RelaySignalGuard {
    read: File,
    _write: File,
    watched: libc::sigset_t,
    old_mask: libc::sigset_t,
    old_actions: Vec<(libc::c_int, libc::sigaction)>,
    installed: bool,
}

impl RelaySignalGuard {
    fn install() -> io::Result<Self> {
        let mut pipe_fds = [-1; 2];
        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut read_fd = pipe_fds[0];
        let mut write_fd = pipe_fds[1];
        let moved =
            move_fd_above_stdio(&mut read_fd).and_then(|()| move_fd_above_stdio(&mut write_fd));
        if let Err(error) = moved {
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            return Err(error);
        }
        for fd in [read_fd, write_fd] {
            let status_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if status_flags < 0
                || descriptor_flags < 0
                || unsafe { libc::fcntl(fd, libc::F_SETFL, status_flags | libc::O_NONBLOCK) } != 0
                || unsafe { libc::fcntl(fd, libc::F_SETFD, descriptor_flags | libc::FD_CLOEXEC) }
                    != 0
            {
                let error = io::Error::last_os_error();
                unsafe {
                    libc::close(read_fd);
                    libc::close(write_fd);
                }
                return Err(error);
            }
        }

        let mut watched: libc::sigset_t = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigemptyset(&mut watched) } != 0 {
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            return Err(io::Error::last_os_error());
        }
        for signal in RELAY_SIGNALS {
            if unsafe { libc::sigaddset(&mut watched, signal) } != 0 {
                unsafe {
                    libc::close(read_fd);
                    libc::close(write_fd);
                }
                return Err(io::Error::last_os_error());
            }
        }
        let mut old_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigprocmask(libc::SIG_BLOCK, &watched, &mut old_mask) } != 0 {
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            return Err(io::Error::last_os_error());
        }
        if RELAY_SIGNAL_WRITE_FD
            .compare_exchange(-1, write_fd, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            unsafe { libc::sigprocmask(libc::SIG_SETMASK, &old_mask, std::ptr::null_mut()) };
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            return Err(io::Error::other("another terminal relay is active"));
        }
        RELAY_SIGNAL_CAUGHT.store(0, Ordering::SeqCst);

        let mut old_actions = Vec::with_capacity(RELAY_SIGNALS.len());
        let mut install_error = None;
        for signal in RELAY_SIGNALS {
            let mut old_action: libc::sigaction = unsafe { std::mem::zeroed() };
            if unsafe { libc::sigaction(signal, std::ptr::null(), &mut old_action) } != 0 {
                install_error = Some(io::Error::last_os_error());
                break;
            }
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = capture_relay_signal as *const () as usize;
            action.sa_flags = 0;
            if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0
                || unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0
            {
                install_error = Some(io::Error::last_os_error());
                break;
            }
            old_actions.push((signal, old_action));
        }
        if let Some(error) = install_error {
            for (signal, action) in old_actions.iter().rev() {
                unsafe { libc::sigaction(*signal, action, std::ptr::null_mut()) };
            }
            RELAY_SIGNAL_WRITE_FD.store(-1, Ordering::SeqCst);
            RELAY_SIGNAL_CAUGHT.store(0, Ordering::SeqCst);
            unsafe { libc::sigprocmask(libc::SIG_SETMASK, &old_mask, std::ptr::null_mut()) };
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            return Err(error);
        }

        let mut active_mask = old_mask;
        for signal in RELAY_SIGNALS {
            if unsafe { libc::sigdelset(&mut active_mask, signal) } != 0 {
                for (signal, action) in old_actions.iter().rev() {
                    unsafe { libc::sigaction(*signal, action, std::ptr::null_mut()) };
                }
                RELAY_SIGNAL_WRITE_FD.store(-1, Ordering::SeqCst);
                RELAY_SIGNAL_CAUGHT.store(0, Ordering::SeqCst);
                unsafe { libc::sigprocmask(libc::SIG_SETMASK, &old_mask, std::ptr::null_mut()) };
                unsafe {
                    libc::close(read_fd);
                    libc::close(write_fd);
                }
                return Err(io::Error::last_os_error());
            }
        }
        if unsafe { libc::sigprocmask(libc::SIG_SETMASK, &active_mask, std::ptr::null_mut()) } != 0
        {
            let error = io::Error::last_os_error();
            for (signal, action) in old_actions.iter().rev() {
                unsafe { libc::sigaction(*signal, action, std::ptr::null_mut()) };
            }
            RELAY_SIGNAL_WRITE_FD.store(-1, Ordering::SeqCst);
            RELAY_SIGNAL_CAUGHT.store(0, Ordering::SeqCst);
            unsafe { libc::sigprocmask(libc::SIG_SETMASK, &old_mask, std::ptr::null_mut()) };
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            return Err(error);
        }

        Ok(Self {
            read: unsafe { File::from_raw_fd(read_fd) },
            _write: unsafe { File::from_raw_fd(write_fd) },
            watched,
            old_mask,
            old_actions,
            installed: true,
        })
    }

    fn read_fd(&self) -> RawFd {
        self.read.as_raw_fd()
    }

    fn drain(&self) -> io::Result<()> {
        let mut bytes = [0u8; 64];
        loop {
            let read = unsafe {
                libc::read(
                    self.read.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                )
            };
            if read > 0 {
                continue;
            }
            if read == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EAGAIN)
                || error.raw_os_error() == Some(libc::EWOULDBLOCK)
            {
                return Ok(());
            }
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    fn pending(&self) -> Option<libc::c_int> {
        match RELAY_SIGNAL_CAUGHT.load(Ordering::SeqCst) {
            0 => None,
            signal => Some(signal),
        }
    }

    fn finish(&mut self) -> io::Result<Option<libc::c_int>> {
        if !self.installed {
            return Ok(None);
        }
        if unsafe { libc::sigprocmask(libc::SIG_BLOCK, &self.watched, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let signal = RELAY_SIGNAL_CAUGHT.load(Ordering::SeqCst);
        RELAY_SIGNAL_WRITE_FD.store(-1, Ordering::SeqCst);
        let mut first_error = None;
        for (signal, action) in self.old_actions.iter().rev() {
            if unsafe { libc::sigaction(*signal, action, std::ptr::null_mut()) } != 0
                && first_error.is_none()
            {
                first_error = Some(io::Error::last_os_error());
            }
        }
        if unsafe { libc::sigprocmask(libc::SIG_SETMASK, &self.old_mask, std::ptr::null_mut()) }
            != 0
            && first_error.is_none()
        {
            first_error = Some(io::Error::last_os_error());
        }
        if first_error.is_none() {
            self.installed = false;
            RELAY_SIGNAL_CAUGHT.store(0, Ordering::SeqCst);
        }
        if let Some(error) = first_error {
            Err(error)
        } else if signal == 0 {
            Ok(None)
        } else {
            Ok(Some(signal))
        }
    }
}

impl Drop for RelaySignalGuard {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

enum RelayError {
    Io,
    Signal,
}

impl From<io::Error> for RelayError {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

struct PtyPair {
    master: File,
    slave: File,
    eof_character: u8,
}

impl PtyPair {
    fn open(copy_terminal: bool) -> io::Result<Self> {
        let mut master = -1;
        let mut slave = -1;
        let mut termios = std::mem::MaybeUninit::<libc::termios>::zeroed();
        let mut winsize = std::mem::MaybeUninit::<libc::winsize>::zeroed();
        let mut termios_ptr = std::ptr::null_mut();
        let mut winsize_ptr = std::ptr::null_mut();
        let mut eof_character = 0x04;

        if copy_terminal {
            if unsafe { libc::tcgetattr(libc::STDIN_FILENO, termios.as_mut_ptr()) } != 0
                || unsafe {
                    libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, winsize.as_mut_ptr())
                } != 0
            {
                return Err(io::Error::last_os_error());
            }
            eof_character = unsafe { (*termios.as_ptr()).c_cc[libc::VEOF] };
            termios_ptr = termios.as_mut_ptr();
            winsize_ptr = winsize.as_mut_ptr();
        }

        #[cfg(target_os = "linux")]
        let openpty_result = unsafe {
            openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                termios_ptr,
                winsize_ptr,
            )
        };
        #[cfg(not(target_os = "linux"))]
        let openpty_result = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                termios_ptr,
                winsize_ptr,
            )
        };
        if openpty_result != 0 {
            return Err(io::Error::last_os_error());
        }

        if let Err(error) = move_fd_above_stdio(&mut master) {
            unsafe {
                libc::close(master);
                libc::close(slave);
            }
            return Err(error);
        }
        if let Err(error) = move_fd_above_stdio(&mut slave) {
            unsafe {
                libc::close(master);
                libc::close(slave);
            }
            return Err(error);
        }

        // Keep both descriptors private to this launch. The child needs the
        // slave only until exec has installed its standard descriptors and
        // acquired the controlling-terminal relationship.
        for fd in [master, slave] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0
            {
                let error = io::Error::last_os_error();
                unsafe {
                    libc::close(master);
                    libc::close(slave);
                }
                return Err(error);
            }
        }

        let master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        set_nonblocking(master.as_raw_fd())?;
        Ok(Self {
            master,
            slave,
            eof_character,
        })
    }
}

fn move_fd_above_stdio(fd: &mut RawFd) -> io::Result<()> {
    if *fd > libc::STDERR_FILENO {
        return Ok(());
    }
    let replacement = unsafe { libc::fcntl(*fd, libc::F_DUPFD_CLOEXEC, libc::STDERR_FILENO + 1) };
    if replacement < 0 {
        return Err(io::Error::last_os_error().into());
    }
    unsafe { libc::close(*fd) };
    *fd = replacement;
    Ok(())
}

struct TerminalRestore {
    fd: RawFd,
    saved_termios: libc::termios,
    saved_flags: Vec<(RawFd, libc::c_int)>,
    restored: bool,
}

impl TerminalRestore {
    fn enter() -> io::Result<Self> {
        let mut saved_termios = std::mem::MaybeUninit::<libc::termios>::zeroed();
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, saved_termios.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let saved_termios = unsafe { saved_termios.assume_init() };
        let mut raw = saved_termios;
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) } != 0 {
            return Err(io::Error::last_os_error());
        }

        let mut guard = Self {
            fd: libc::STDIN_FILENO,
            saved_termios,
            saved_flags: Vec::new(),
            restored: false,
        };
        if let Err(error) = guard
            .set_nonblocking(libc::STDIN_FILENO)
            .and_then(|()| guard.set_nonblocking(libc::STDOUT_FILENO))
        {
            let _ = guard.restore();
            return Err(error);
        }
        Ok(guard)
    }

    fn set_nonblocking(&mut self, fd: RawFd) -> io::Result<()> {
        if self.saved_flags.iter().any(|(saved_fd, _)| *saved_fd == fd) {
            return Ok(());
        }
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
            return Err(io::Error::last_os_error());
        }
        self.saved_flags.push((fd, flags));
        Ok(())
    }

    fn restore(&mut self) -> io::Result<()> {
        if self.restored {
            return Ok(());
        }
        let mut first_error = None;
        for (fd, flags) in self.saved_flags.iter().rev().copied() {
            if unsafe { libc::fcntl(fd, libc::F_SETFL, flags) } != 0 && first_error.is_none() {
                first_error = Some(io::Error::last_os_error());
            }
        }
        // TCSAFLUSH makes restoration atomic with discarding type-ahead that
        // arrived while the proxy was in raw mode, including error exits.
        if unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.saved_termios) } != 0
            && first_error.is_none()
        {
            first_error = Some(io::Error::last_os_error());
        }
        self.restored = first_error.is_none();
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for TerminalRestore {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

struct DescriptorFlagsRestore {
    saved: Vec<(RawFd, libc::c_int)>,
    restored: bool,
}

impl DescriptorFlagsRestore {
    fn enter(descriptors: &[RawFd]) -> io::Result<Self> {
        let mut guard = Self {
            saved: Vec::with_capacity(descriptors.len()),
            restored: false,
        };
        for fd in descriptors.iter().copied() {
            if guard.saved.iter().any(|(saved_fd, _)| *saved_fd == fd) {
                continue;
            }
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 {
                let error = io::Error::last_os_error();
                let _ = guard.restore();
                return Err(error);
            }
            if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
                let error = io::Error::last_os_error();
                let _ = guard.restore();
                return Err(error);
            }
            guard.saved.push((fd, flags));
        }
        Ok(guard)
    }

    fn restore(&mut self) -> io::Result<()> {
        if self.restored {
            return Ok(());
        }
        let mut first_error = None;
        for (fd, flags) in self.saved.iter().rev().copied() {
            if unsafe { libc::fcntl(fd, libc::F_SETFL, flags) } != 0 && first_error.is_none() {
                first_error = Some(io::Error::last_os_error());
            }
        }
        self.restored = first_error.is_none();
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for DescriptorFlagsRestore {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn same_terminal(left: RawFd, right: RawFd) -> bool {
    if unsafe { libc::isatty(left) } != 1 || unsafe { libc::isatty(right) } != 1 {
        return false;
    }
    let mut left_stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    let mut right_stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(left, left_stat.as_mut_ptr()) } != 0
        || unsafe { libc::fstat(right, right_stat.as_mut_ptr()) } != 0
    {
        return false;
    }
    let left_stat = unsafe { left_stat.assume_init() };
    let right_stat = unsafe { right_stat.assume_init() };
    left_stat.st_dev == right_stat.st_dev
        && left_stat.st_ino == right_stat.st_ino
        && left_stat.st_rdev == right_stat.st_rdev
}

fn update_window_size(master: RawFd, previous: &mut libc::winsize) -> io::Result<()> {
    let mut current = std::mem::MaybeUninit::<libc::winsize>::zeroed();
    if unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, current.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let current = unsafe { current.assume_init() };
    if current.ws_row != previous.ws_row
        || current.ws_col != previous.ws_col
        || current.ws_xpixel != previous.ws_xpixel
        || current.ws_ypixel != previous.ws_ypixel
    {
        if unsafe { libc::ioctl(master, libc::TIOCSWINSZ, &current) } != 0 {
            return Err(io::Error::last_os_error());
        }
        *previous = current;
    }
    Ok(())
}

fn poll_fds(fds: &mut [libc::pollfd], timeout_ms: i32) -> io::Result<()> {
    loop {
        let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
        if result >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn push_read(fd: RawFd, queue: &mut VecDeque<u8>) -> io::Result<bool> {
    if queue.len() >= RELAY_BUFFER_BYTES {
        return Ok(false);
    }
    let remaining = RELAY_BUFFER_BYTES - queue.len();
    let mut buffer = [0u8; RELAY_CHUNK_BYTES];
    let capacity = remaining.min(buffer.len());
    let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), capacity) };
    if read > 0 {
        queue.extend(&buffer[..read as usize]);
        return Ok(false);
    }
    if read == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EAGAIN) || error.raw_os_error() == Some(libc::EWOULDBLOCK)
    {
        Ok(false)
    } else if matches!(error.raw_os_error(), Some(libc::EIO)) {
        // Linux and Darwin report PTY master EOF as EIO after the final slave
        // descriptor closes.
        Ok(true)
    } else if error.kind() == io::ErrorKind::Interrupted {
        Ok(false)
    } else {
        Err(error)
    }
}

fn flush_write(fd: RawFd, queue: &mut VecDeque<u8>) -> io::Result<()> {
    if queue.is_empty() {
        return Ok(());
    }
    let (first, second) = queue.as_slices();
    let bytes = if !first.is_empty() { first } else { second };
    let written = unsafe {
        libc::write(
            fd,
            bytes.as_ptr().cast(),
            bytes.len().min(RELAY_CHUNK_BYTES),
        )
    };
    if written > 0 {
        queue.drain(..written as usize);
        Ok(())
    } else if written == 0 {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "terminal relay write",
        ))
    } else {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted
            || error.raw_os_error() == Some(libc::EAGAIN)
            || error.raw_os_error() == Some(libc::EWOULDBLOCK)
        {
            Ok(())
        } else {
            Err(error)
        }
    }
}

struct OutputRelay {
    source: File,
    destination: RawFd,
    queue: VecDeque<u8>,
    eof: bool,
}

fn output_relay<T: IntoRawFd>(
    handle: Option<T>,
    destination: RawFd,
) -> io::Result<Option<OutputRelay>> {
    let Some(handle) = handle else {
        return Ok(None);
    };
    let source = unsafe { File::from_raw_fd(handle.into_raw_fd()) };
    set_nonblocking(source.as_raw_fd())?;
    Ok(Some(OutputRelay {
        source,
        destination,
        queue: VecDeque::with_capacity(RELAY_BUFFER_BYTES),
        eof: false,
    }))
}

fn relay_noninteractive_outputs(
    child: &mut Child,
    mut outputs: Vec<OutputRelay>,
    signals: &RelaySignalGuard,
) -> Result<ExitStatus, RelayError> {
    let destinations: Vec<_> = outputs.iter().map(|output| output.destination).collect();
    let mut destination_flags = DescriptorFlagsRestore::enter(&destinations)?;
    let mut status = None;
    let mut exited_at = None;
    loop {
        if signals.pending().is_some() {
            return Err(RelayError::Signal);
        }
        if status.is_none() {
            status = child.try_wait()?;
            if status.is_some() {
                exited_at = Some(Instant::now());
            }
        }
        if status.is_some()
            && outputs
                .iter()
                .all(|output| output.eof && output.queue.is_empty())
        {
            break;
        }
        if let Some(exited_at) = exited_at {
            let pending = outputs.iter().any(|output| !output.queue.is_empty());
            let idle = outputs
                .iter()
                .all(|output| output.queue.is_empty() && output.eof);
            let elapsed = Instant::now().duration_since(exited_at);
            if !pending && elapsed >= POST_EXIT_DRAIN {
                break;
            }
            if pending && elapsed >= MAX_POST_EXIT_DRAIN {
                return Err(
                    io::Error::new(io::ErrorKind::TimedOut, "setup output did not drain").into(),
                );
            }
            if idle {
                break;
            }
        }

        let mut pollfds = Vec::with_capacity(outputs.len() * 2);
        for output in &outputs {
            pollfds.push(libc::pollfd {
                fd: if !output.eof && output.queue.len() < RELAY_BUFFER_BYTES {
                    output.source.as_raw_fd()
                } else {
                    -1
                },
                events: libc::POLLIN,
                revents: 0,
            });
            pollfds.push(libc::pollfd {
                fd: if output.queue.is_empty() {
                    -1
                } else {
                    output.destination
                },
                events: libc::POLLOUT,
                revents: 0,
            });
        }
        let signal_index = pollfds.len();
        pollfds.push(libc::pollfd {
            fd: signals.read_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        poll_fds(&mut pollfds, POLL_INTERVAL_MS)?;
        if pollfds.iter().any(|fd| fd.revents & libc::POLLNVAL != 0) {
            return Err(io::Error::from_raw_os_error(libc::EBADF).into());
        }
        if pollfds[signal_index].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            signals.drain()?;
            if signals.pending().is_some() {
                return Err(RelayError::Signal);
            }
        }
        for (index, output) in outputs.iter_mut().enumerate() {
            let read_events =
                pollfds[index * 2].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR);
            if !output.eof && read_events != 0 {
                output.eof |= push_read(output.source.as_raw_fd(), &mut output.queue)?;
            }
            let write_events =
                pollfds[index * 2 + 1].revents & (libc::POLLOUT | libc::POLLHUP | libc::POLLERR);
            if !output.queue.is_empty() && write_events != 0 {
                flush_write(output.destination, &mut output.queue)?;
            }
        }
    }
    destination_flags.restore()?;
    status.ok_or_else(|| io::Error::other("setup child status lost").into())
}

fn relay(
    child: &mut Child,
    master_file: &File,
    eof_character: u8,
    signals: &RelaySignalGuard,
) -> Result<ExitStatus, RelayError> {
    let mut terminal = TerminalRestore::enter()?;
    let master = master_file.as_raw_fd();
    let mut window = std::mem::MaybeUninit::<libc::winsize>::zeroed();
    if unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, window.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let mut window = unsafe { window.assume_init() };
    let mut input = VecDeque::with_capacity(RELAY_BUFFER_BYTES);
    let mut output = VecDeque::with_capacity(RELAY_BUFFER_BYTES);
    let mut input_eof = false;
    let mut master_eof = false;
    let mut child_status = None;
    let mut exited_at = None;

    loop {
        if signals.pending().is_some() {
            return Err(RelayError::Signal);
        }
        if child_status.is_none() {
            child_status = child.try_wait()?;
            if child_status.is_some() {
                input.clear();
                if unsafe { libc::tcflush(libc::STDIN_FILENO, libc::TCIFLUSH) } != 0 {
                    return Err(io::Error::last_os_error().into());
                }
                exited_at = Some(Instant::now());
            }
        }
        if child_status.is_none() && !input_eof {
            update_window_size(master, &mut window)?;
        }

        let can_read_input =
            child_status.is_none() && !input_eof && input.len() < RELAY_BUFFER_BYTES;
        let can_read_master = !master_eof && output.len() < RELAY_BUFFER_BYTES;
        let can_write_master =
            !master_eof && !input.is_empty() && output.len() < RELAY_BUFFER_BYTES;
        let master_events = (if can_read_master { libc::POLLIN } else { 0 })
            | (if can_write_master { libc::POLLOUT } else { 0 });
        let mut fds = [
            libc::pollfd {
                fd: if can_read_input {
                    libc::STDIN_FILENO
                } else {
                    -1
                },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if master_events != 0 { master } else { -1 },
                events: master_events,
                revents: 0,
            },
            libc::pollfd {
                fd: if !output.is_empty() {
                    libc::STDOUT_FILENO
                } else {
                    -1
                },
                events: libc::POLLOUT,
                revents: 0,
            },
            libc::pollfd {
                fd: signals.read_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        poll_fds(&mut fds, POLL_INTERVAL_MS)?;
        if fds.iter().any(|fd| fd.revents & libc::POLLNVAL != 0) {
            return Err(io::Error::from_raw_os_error(libc::EBADF).into());
        }
        if fds[3].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            signals.drain()?;
            if signals.pending().is_some() {
                return Err(RelayError::Signal);
            }
        }

        if can_read_input && fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            input_eof |= push_read(libc::STDIN_FILENO, &mut input)?;
            if input_eof {
                // A closed caller pipe should deliver a single terminal EOF
                // to the child without reopening or inheriting the root TTY.
                if input.len() < RELAY_BUFFER_BYTES {
                    input.push_back(eof_character);
                }
            }
        }
        if can_write_master && fds[1].revents & libc::POLLOUT != 0 {
            flush_write(master, &mut input)?;
        }
        if can_read_master {
            let events = fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR);
            if events != 0 {
                master_eof |= push_read(master, &mut output)?;
                if master_eof {
                    input.clear();
                    input_eof = true;
                }
            }
        }
        if !output.is_empty()
            && fds[2].revents & (libc::POLLOUT | libc::POLLHUP | libc::POLLERR) != 0
        {
            flush_write(libc::STDOUT_FILENO, &mut output)?;
        }

        if let Some(exited_at) = exited_at {
            if master_eof && output.is_empty() {
                break;
            }
            if Instant::now().duration_since(exited_at) >= MAX_POST_EXIT_DRAIN {
                if !output.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "setup terminal output did not drain",
                    )
                    .into());
                }
                break;
            }
            if output.is_empty() && Instant::now().duration_since(exited_at) >= POST_EXIT_DRAIN {
                break;
            }
        }
    }

    // Do not allow type-ahead left in the root terminal's raw input queue to
    // become a command in the administrator's shell after canonical mode is
    // restored. Output already queued by the child is flushed first.
    while !output.is_empty() {
        let mut fds = [
            libc::pollfd {
                fd: libc::STDOUT_FILENO,
                events: libc::POLLOUT,
                revents: 0,
            },
            libc::pollfd {
                fd: signals.read_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        poll_fds(&mut fds, POLL_INTERVAL_MS)?;
        if fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            signals.drain()?;
            if signals.pending().is_some() {
                return Err(RelayError::Signal);
            }
        }
        if fds[0].revents == 0 {
            continue;
        }
        flush_write(libc::STDOUT_FILENO, &mut output)?;
    }
    if unsafe { libc::tcflush(libc::STDIN_FILENO, libc::TCIFLUSH) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    terminal.restore()?;
    child_status.ok_or_else(|| io::Error::other("setup child status lost").into())
}

fn stop_child(child: &mut Child) -> io::Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    crate::process::require_unreaped_child(child)?;
    child.kill()?;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait()? {
            Some(_) => return Ok(()),
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "setup child cleanup",
                ));
            }
        }
    }
}

fn complete_relay(
    child: &mut Child,
    master: File,
    signals: &mut RelaySignalGuard,
    relayed: Result<ExitStatus, RelayError>,
) -> Result<ExitStatus, RunError> {
    let relay_failed = relayed.is_err();
    let cleanup_ok = if relay_failed {
        drop(master);
        stop_child(child).is_ok()
    } else {
        drop(master);
        true
    };
    let signal = signals.finish().map_err(|_| RunError::AfterSpawn)?;
    if let Some(signal) = signal {
        unsafe { libc::kill(libc::getpid(), signal) };
    }
    if relay_failed || !cleanup_ok {
        return Err(RunError::AfterSpawn);
    }
    match relayed {
        Ok(status) => Ok(status),
        Err(RelayError::Signal) | Err(RelayError::Io) => Err(RunError::AfterSpawn),
    }
}

/// Spawn an already configured selected-account command under a fresh
/// controlling PTY. `configure_child` performs the existing native identity
/// drop and verification after session/terminal isolation is established.
pub(super) fn run_selected(
    command: &mut Command,
    mut configure_child: impl FnMut() -> io::Result<()> + Send + Sync + 'static,
) -> Result<ExitStatus, RunError> {
    crate::process::require_child_ownership().map_err(|_| RunError::BeforeSpawn)?;
    let interactive = same_terminal(libc::STDIN_FILENO, libc::STDOUT_FILENO);
    let stdout_is_tty = unsafe { libc::isatty(libc::STDOUT_FILENO) } == 1;
    let stderr_is_tty = unsafe { libc::isatty(libc::STDERR_FILENO) } == 1;
    let pair = PtyPair::open(interactive).map_err(|_| RunError::BeforeSpawn)?;
    let master = pair.master;
    let slave = pair.slave;
    let eof_character = pair.eof_character;
    let slave_fd = slave.as_raw_fd();
    if interactive {
        command
            .stdin(Stdio::from(
                slave.try_clone().map_err(|_| RunError::BeforeSpawn)?,
            ))
            .stdout(Stdio::from(
                slave.try_clone().map_err(|_| RunError::BeforeSpawn)?,
            ));
        if stderr_is_tty {
            command.stderr(Stdio::from(
                slave.try_clone().map_err(|_| RunError::BeforeSpawn)?,
            ));
        } else {
            command.stderr(Stdio::inherit());
        }
    } else {
        command
            .stdin(if unsafe { libc::isatty(libc::STDIN_FILENO) } == 1 {
                Stdio::null()
            } else {
                Stdio::inherit()
            })
            .stdout(if stdout_is_tty {
                Stdio::piped()
            } else {
                Stdio::inherit()
            })
            .stderr(if stderr_is_tty {
                Stdio::piped()
            } else {
                Stdio::inherit()
            });
    }

    let parent_pid = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0
                || libc::ioctl(slave_fd, libc::TIOCSCTTY as _, 0) < 0
                || libc::tcsetpgrp(slave_fd, libc::getpgrp()) != 0
            {
                return Err(io::Error::last_os_error());
            }

            // Do not inherit a caller's ignored termination dispositions or
            // blocked signals into the setup program.
            for signal in [libc::SIGHUP, libc::SIGINT, libc::SIGTERM] {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = libc::SIG_DFL;
                libc::sigemptyset(&mut action.sa_mask);
                if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            let mut empty_mask: libc::sigset_t = std::mem::zeroed();
            if libc::sigemptyset(&mut empty_mask) != 0
                || libc::sigprocmask(libc::SIG_SETMASK, &empty_mask, std::ptr::null_mut()) != 0
            {
                return Err(io::Error::last_os_error());
            }

            configure_child()?;

            #[cfg(target_os = "linux")]
            {
                // setuid/setgid can clear PDEATHSIG, so arm it only after the
                // selected identity is established, then close the race where
                // the caller exits between fork and arming the signal.
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() != parent_pid {
                    libc::kill(libc::getpid(), libc::SIGKILL);
                    return Err(io::Error::other("setup parent exited"));
                }
            }
            #[cfg(not(target_os = "linux"))]
            let _ = parent_pid;

            Ok(())
        });
    }

    let spawn = command.spawn().map_err(|_| RunError::BeforeSpawn);
    drop(slave);
    let mut child = spawn?;
    if interactive {
        let mut signals = match RelaySignalGuard::install() {
            Ok(signals) => signals,
            Err(_) => {
                drop(master);
                stop_child(&mut child).map_err(|_| RunError::AfterSpawn)?;
                return Err(RunError::AfterSpawn);
            }
        };
        let relayed = relay(&mut child, &master, eof_character, &signals);
        complete_relay(&mut child, master, &mut signals, relayed)
    } else {
        let captured = (|| -> io::Result<Vec<OutputRelay>> {
            let mut outputs = Vec::with_capacity(2);
            if stdout_is_tty {
                let output = output_relay(child.stdout.take(), libc::STDOUT_FILENO)?
                    .ok_or_else(|| io::Error::other("stdout relay pipe missing"))?;
                outputs.push(output);
            }
            if stderr_is_tty {
                let output = output_relay(child.stderr.take(), libc::STDERR_FILENO)?
                    .ok_or_else(|| io::Error::other("stderr relay pipe missing"))?;
                outputs.push(output);
            }
            Ok(outputs)
        })();
        let outputs = match captured {
            Ok(outputs) => outputs,
            Err(_) => {
                drop(master);
                stop_child(&mut child).map_err(|_| RunError::AfterSpawn)?;
                return Err(RunError::AfterSpawn);
            }
        };
        let result = if outputs.is_empty() {
            child.wait()
        } else {
            let mut signals = match RelaySignalGuard::install() {
                Ok(signals) => signals,
                Err(_) => {
                    drop(master);
                    stop_child(&mut child).map_err(|_| RunError::AfterSpawn)?;
                    return Err(RunError::AfterSpawn);
                }
            };
            let relayed = relay_noninteractive_outputs(&mut child, outputs, &signals);
            return complete_relay(&mut child, master, &mut signals, relayed);
        };
        match result {
            Ok(status) => Ok(status),
            Err(_) => {
                drop(master);
                stop_child(&mut child).map_err(|_| RunError::AfterSpawn)?;
                Err(RunError::AfterSpawn)
            }
        }
    }
}
