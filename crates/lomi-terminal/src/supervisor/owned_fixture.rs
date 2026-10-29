//! Source-only proposal. Private test controller; no production fallback.
use super::*;
pub(crate) mod probe;
use std::{
    fs,
    net::Shutdown,
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, PermissionsExt},
        net::UnixListener,
    },
    path::PathBuf,
};
use uuid::Uuid;

const ENDPOINT: &str = "LOMI_OWNED_PTY_ENDPOINT";
const CAPABILITY: &str = "LOMI_OWNED_PTY_CAPABILITY";
const ROOT_PID: &str = "LOMI_OWNED_PTY_ROOT_PID";
const ENDPOINT_ID: &str = "LOMI_OWNED_PTY_ENDPOINT_ID";
const RUN: &str = "LOMI_OWNED_PTY_RUN";
const MAX_WORKERS: usize = 128;
const SESSION: Duration = Duration::from_secs(120);
const RUN_DEADLINE: Duration = Duration::from_secs(900);
pub(super) const CLEAN_EXIT: i32 = 70;
pub(super) const NO_CHILD_EXIT: i32 = 72;
const CLEANUP: Duration = Duration::from_secs(10);
const TICK: Duration = Duration::from_millis(20);

fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}
fn bounded(socket: &UnixStream) -> io::Result<()> {
    socket.set_read_timeout(Some(STARTUP))?;
    socket.set_write_timeout(Some(STARTUP))
}
fn identity(name: &str) -> io::Result<Uuid> {
    std::env::var(name)
        .ok()
        .and_then(|v| Uuid::parse_str(&v).ok())
        .ok_or_else(invalid)
}
fn private(path: &Path, socket: bool) -> io::Result<fs::Metadata> {
    use std::os::unix::fs::FileTypeExt;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || (socket && !metadata.file_type().is_socket())
        || (!socket && !metadata.is_dir())
    {
        return Err(invalid());
    }
    Ok(metadata)
}
fn peer(socket: &UnixStream, expected_pid: Option<u32>) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&credentials) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            )
        } != 0
            || length as usize != std::mem::size_of_val(&credentials)
            || credentials.uid != unsafe { libc::geteuid() }
            || expected_pid.is_some_and(|pid| credentials.pid as u32 != pid)
        {
            return Err(invalid());
        }
    }
    #[cfg(target_os = "macos")]
    {
        let (mut uid, mut gid) = (0, 0);
        if unsafe { libc::getpeereid(socket.as_raw_fd(), &mut uid, &mut gid) } != 0
            || uid != unsafe { libc::geteuid() }
        {
            return Err(invalid());
        }
        if let Some(expected) = expected_pid {
            let mut pid: libc::pid_t = 0;
            let mut length = std::mem::size_of_val(&pid) as libc::socklen_t;
            // Darwin LOCAL_PEERPID is supported for connected local sockets.
            if unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    0,
                    2,
                    (&mut pid as *mut libc::pid_t).cast(),
                    &mut length,
                )
            } != 0
                || length as usize != std::mem::size_of_val(&pid)
                || pid as u32 != expected
            {
                return Err(invalid());
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return Err(io::ErrorKind::Unsupported.into());
    Ok(())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
    NoneYet,
    Closed,
    Data,
}
fn pending(socket: &UnixStream) -> io::Result<Pending> {
    let mut byte = [0];
    match unsafe {
        libc::recv(
            socket.as_raw_fd(),
            byte.as_mut_ptr().cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    } {
        0 => Ok(Pending::Closed),
        1 => Ok(Pending::Data),
        _ => {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                Ok(Pending::NoneYet)
            } else {
                Err(error)
            }
        }
    }
}
fn lifetime_hook_aborts(observed: io::Result<Pending>) -> bool {
    // Data can be the legitimate queued SCM_RIGHTS marker after G. Only an
    // actual closed lifetime or IO error aborts this test pause.
    matches!(observed, Ok(Pending::Closed) | Err(_))
}
fn byte(socket: &mut UnixStream, expected: u8) -> io::Result<()> {
    let mut actual = [0];
    socket.read_exact(&mut actual)?;
    if actual[0] == expected {
        Ok(())
    } else {
        Err(invalid())
    }
}

pub(crate) struct ExternalWorker {
    socket: UnixStream,
    registration: UnixStream,
    stopped: bool,
}
impl ExternalWorker {
    pub(super) fn finished(&self) -> Result<bool> {
        if self.stopped {
            Ok(true)
        } else {
            peek_cleanup(&self.socket)
        }
    }
    pub(super) fn stop(&mut self) -> Result<()> {
        if self.stopped {
            return Ok(());
        }
        self.socket
            .shutdown(Shutdown::Write)
            .map_err(|_| Error::CleanupFailed)?;
        byte(&mut self.socket, b'A').map_err(|_| Error::CleanupFailed)?;
        // C means root independently read A AND reaped a successful actual Child.
        byte(&mut self.registration, b'C').map_err(|_| Error::CleanupFailed)?;
        self.stopped = true;
        Ok(())
    }
}
impl Drop for ExternalWorker {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(Shutdown::Both);
        let _ = self.registration.shutdown(Shutdown::Both);
    }
}

pub(crate) fn spawn(
    profile: &SpawnProfile,
    before_spawn: impl FnOnce() -> bool,
) -> Result<(unix::Pty, Box<dyn Read + Send>)> {
    // Validate before requesting a worker; missing configuration always fails.
    let bytes = profile_bytes(profile)?;
    let connect = || -> io::Result<(UnixStream, UnixStream)> {
        let endpoint = PathBuf::from(std::env::var_os(ENDPOINT).ok_or_else(invalid)?);
        if !endpoint.is_absolute() {
            return Err(invalid());
        }
        let directory = endpoint.parent().ok_or_else(invalid)?;
        private(directory, false)?;
        let before = private(&endpoint, true)?;
        let mut registration = UnixStream::connect(&endpoint)?;
        bounded(&registration)?;
        let root_pid = std::env::var(ROOT_PID)
            .ok()
            .and_then(|v| v.parse().ok())
            .ok_or_else(invalid)?;
        peer(&registration, Some(root_pid))?;
        let expected_id = std::env::var(ENDPOINT_ID).map_err(|_| invalid())?;
        if format!("{}:{}", before.dev(), before.ino()) != expected_id {
            return Err(invalid());
        }
        let after = private(&endpoint, true)?;
        if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
            return Err(invalid());
        }
        let capability = identity(CAPABILITY)?;
        let run = identity(RUN)?;
        registration.write_all(b"LOMI-FH1")?;
        registration.write_all(capability.as_bytes())?;
        registration.write_all(run.as_bytes())?;
        // Both ends prove possession of the run capability before FD transfer.
        let mut proof = [0; 32];
        registration.read_exact(&mut proof)?;
        if &proof[..16] != capability.as_bytes() || &proof[16..] != run.as_bytes() {
            return Err(invalid());
        }
        let mut challenge = [0; 16];
        registration.read_exact(&mut challenge)?;
        let fd = receive_fd(&registration)?;
        let socket = UnixStream::from(OwnedFd::from(fd));
        bounded(&socket)?;
        registration.write_all(&challenge)?;
        byte(&mut registration, b'K')?;
        Ok((socket, registration))
    };
    let (mut socket, registration) = connect().map_err(|_| Error::SpawnFailed)?;
    let lifetime = socket.try_clone().map_err(|_| Error::SpawnFailed)?;
    let worker = Worker::External(ExternalWorker {
        socket: lifetime,
        registration,
        stopped: false,
    });
    socket
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| socket.write_all(&bytes))
        .map_err(|_| Error::SpawnFailed)?;
    if byte(&mut socket, b'R').is_err() || hook("R", Some(&socket)).is_err() || !before_spawn() {
        return Err(Error::SpawnFailed);
    }
    socket
        .write_all(b"G")
        .map_err(|_| Error::SpawnOutcomeUnknown)?;
    hook("G", Some(&socket)).map_err(|_| Error::SpawnOutcomeUnknown)?;
    let master = receive_fd(&socket).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            Error::SpawnFailed
        } else {
            Error::SpawnOutcomeUnknown
        }
    })?;
    hook("PTY_FD", Some(&socket)).map_err(|_| Error::SpawnOutcomeUnknown)?;
    unix::Pty::from_worker(master, worker)
}

static CANCEL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
extern "C" fn cancel_signal(_: libc::c_int) {
    CANCEL.store(true, Ordering::Release);
}
fn install_root_signals() -> io::Result<()> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = libc::SIG_DFL;
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0
        || unsafe { libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // Zero flags deliberately remove inherited SA_NOCLDWAIT/SA_RESETHAND.
    action.sa_sigaction = cancel_signal as *const () as usize;
    for signal in [libc::SIGINT, libc::SIGTERM] {
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
pub(super) fn no_children() -> bool {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    (unsafe {
        libc::waitid(
            libc::P_ALL,
            0,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    }) < 0
        && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
}
fn hook(stage: &str, lifetime: Option<&UnixStream>) -> io::Result<()> {
    if std::env::var("LOMI_OWNED_TEST_HOOK").as_deref() != Ok(stage) {
        return Ok(());
    }
    let directory =
        PathBuf::from(std::env::var_os("LOMI_OWNED_TEST_DIRECTORY").ok_or_else(invalid)?);
    fs::write(directory.join(format!("hook.{stage}")), b"ready")?;
    let deadline = Instant::now() + STARTUP;
    while !directory.join("release").exists() {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if let Some(socket) = lifetime
            && lifetime_hook_aborts(pending(socket))
        {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        thread::sleep(TICK);
    }
    Ok(())
}
fn root_paused(directory: &Path, stage: &str) -> io::Result<bool> {
    if std::env::var("LOMI_OWNED_TEST_HOOK").as_deref() != Ok(stage) {
        return Ok(false);
    }
    fs::write(directory.join(format!("hook.{stage}")), b"ready")?;
    Ok(!directory.join("release").exists())
}
fn read_part(socket: &mut UnixStream, bytes: &mut [u8], position: &mut usize) -> io::Result<bool> {
    // At most one bounded nonblocking syscall each tick; never read_exact here.
    if *position == bytes.len() {
        return Ok(true);
    }
    match socket.read(&mut bytes[*position..]) {
        Ok(0) => Err(io::ErrorKind::UnexpectedEof.into()),
        Ok(n) => {
            *position += n;
            Ok(*position == bytes.len())
        }
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}
fn write_part(socket: &mut UnixStream, bytes: &[u8], position: &mut usize) -> io::Result<bool> {
    if *position == bytes.len() {
        return Ok(true);
    }
    match socket.write(&bytes[*position..]) {
        Ok(0) => Err(io::ErrorKind::WriteZero.into()),
        Ok(n) => {
            *position += n;
            Ok(*position == bytes.len())
        }
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}
struct Admission {
    socket: UnixStream,
    request: [u8; 40],
    position: usize,
    deadline: Instant,
}
#[derive(Clone, Copy, PartialEq)]
enum Stage {
    Created,
    Proof,
    Descriptor,
    Ack,
    Gate,
    Confirm,
    Active,
    Cancelled,
}
struct OwnedWorker {
    child: Child,
    lifetime: UnixStream,
    observer: UnixStream,
    registration: UnixStream,
    id: Uuid,
    started: Instant,
    deadline: Instant,
    cancelling: Option<Instant>,
    stage: Stage,
    output: [u8; 48],
    position: usize,
    response: [u8; 16],
    attestation: Vec<u8>,
    observer_eof: bool,
    malformed: bool,
    violation: bool,
    status: Option<std::process::ExitStatus>,
}
#[derive(Debug, PartialEq)]
enum Drain {
    Pending,
    Qualified,
    RecoveredFailure,
}
impl OwnedWorker {
    fn cancel(&mut self) {
        self.cancelling.get_or_insert_with(Instant::now);
        self.stage = Stage::Cancelled;
        // Explicit shutdown affects the client's duplicate as well.
        let _ = self.lifetime.shutdown(Shutdown::Write);
        // Deny root K if registration was never completed.
        let _ = self.observer.shutdown(Shutdown::Write);
    }
    fn observe(&mut self) -> io::Result<()> {
        if self.observer_eof {
            return Ok(());
        }
        // Drain all attestation bytes THROUGH EOF, bounded per tick. Never
        // decide from just the first A or before the socket reaches EOF.
        for _ in 0..4 {
            let mut bytes = [0; 8];
            match self.observer.read(&mut bytes) {
                Ok(0) => {
                    self.observer_eof = true;
                    break;
                }
                Ok(n) => {
                    append_attestation(&mut self.attestation, &mut self.malformed, &bytes[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    fn admission_tick(&mut self, directory: &Path) -> io::Result<()> {
        if self.stage == Stage::Active || self.stage == Stage::Cancelled {
            return Ok(());
        }
        if Instant::now() >= self.deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        match self.stage {
            Stage::Created => {
                if !root_paused(directory, "created")? {
                    self.stage = Stage::Proof;
                    self.position = 0;
                }
            }
            Stage::Proof => {
                if write_part(&mut self.registration, &self.output, &mut self.position)? {
                    self.stage = Stage::Descriptor;
                }
            }
            Stage::Descriptor => match send_fd(&self.registration, self.lifetime.as_raw_fd()) {
                Ok(()) => {
                    self.stage = Stage::Ack;
                    self.position = 0;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            },
            Stage::Ack => {
                if root_paused(directory, "FD")? {
                    return Ok(());
                }
                if read_part(
                    &mut self.registration,
                    &mut self.response,
                    &mut self.position,
                )? {
                    if &self.response != self.id.as_bytes() {
                        return Err(invalid());
                    }
                    self.stage = Stage::Gate;
                }
            }
            Stage::Gate => {
                if root_paused(directory, "registration_ack")? {
                    return Ok(());
                }
                match self.observer.write(b"K") {
                    Ok(1) => self.stage = Stage::Confirm,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    _ => return Err(invalid()),
                }
            }
            Stage::Confirm => match self.registration.write(b"K") {
                Ok(1) => self.stage = Stage::Active,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                _ => return Err(invalid()),
            },
            _ => {}
        }
        Ok(())
    }
    fn check_registration(&mut self) {
        if self.stage == Stage::Active {
            match pending(&self.registration) {
                Ok(Pending::NoneYet) => {}
                Ok(Pending::Closed) => self.cancel(),
                Ok(Pending::Data) | Err(_) => {
                    self.violation = true;
                    self.cancel();
                }
            }
        }
    }
    fn poll(&mut self, directory: &Path) -> io::Result<Drain> {
        if self.admission_tick(directory).is_err() {
            self.violation = true;
            self.cancel();
        }
        self.observe()?;
        if self.status.is_none() {
            self.status = self.child.try_wait()?;
        }
        if self.status.is_some() {
            self.observe()?;
        }
        if let Some(status) = self.status {
            if !self.observer_eof {
                let observed = self.cancelling.get_or_insert_with(Instant::now);
                if observed.elapsed() >= CLEANUP {
                    return Err(io::Error::other(
                        "attestation EOF deadline; root retains ownership",
                    ));
                }
                return Ok(Drain::Pending);
            }
            // A reaped child and complete attestation do not erase queued
            // registration violations. Check before the terminal classification.
            self.check_registration();
            let result = classify(&self.attestation, self.malformed, status.code())?;
            return Ok(if self.violation {
                Drain::RecoveredFailure
            } else {
                result
            });
        }
        self.check_registration();
        if self.started.elapsed() >= SESSION {
            self.cancel();
        }
        if self.cancelling.is_some_and(|t| t.elapsed() >= CLEANUP) {
            return Err(io::Error::other(
                "cleanup deadline exceeded; root retains ownership",
            ));
        }
        Ok(Drain::Pending)
    }
}
fn append_attestation(stored: &mut Vec<u8>, malformed: &mut bool, bytes: &[u8]) {
    if stored.len() + bytes.len() > 1 {
        *malformed = true;
    }
    let remaining = 2usize.saturating_sub(stored.len());
    stored.extend(bytes.iter().copied().take(remaining));
}
fn classify(bytes: &[u8], malformed: bool, code: Option<i32>) -> io::Result<Drain> {
    if !malformed
        && matches!(
            (bytes, code),
            (b"A", Some(CLEAN_EXIT)) | (b"N", Some(1)) | (b"B", Some(NO_CHILD_EXIT))
        )
    {
        return Ok(Drain::Qualified);
    }
    if code == Some(CLEAN_EXIT) {
        // Actual pinned worker executable's typed exit is emitted ONLY after
        // original group quiet + leader reap + platform cleanup. Physical drain
        // is safe, but ANY absent/malformed A forces qualification failure.
        return Ok(Drain::RecoveredFailure);
    }
    Err(io::Error::other("unknown worker failure; no cleanup proof"))
}
fn spawn_owned(
    socket: UnixStream,
    workers: &mut Vec<OwnedWorker>,
    capability: Uuid,
    run: Uuid,
    executable: &Path,
) -> io::Result<()> {
    let id = Uuid::new_v4();
    let (lifetime, inherited) = UnixStream::pair()?;
    let (observer, attestation) = UnixStream::pair()?;
    observer.set_nonblocking(true)?;
    let child = Command::new(executable)
        .process_group(0)
        .arg("--internal-owned-test-worker")
        .env_remove(ENDPOINT)
        .env_remove(CAPABILITY)
        .env_remove(RUN)
        .stdin(Stdio::from(OwnedFd::from(inherited)))
        .stdout(Stdio::from(OwnedFd::from(attestation)))
        .stderr(Stdio::null())
        .spawn()?;
    let mut output = [0; 48];
    output[..16].copy_from_slice(capability.as_bytes());
    output[16..32].copy_from_slice(run.as_bytes());
    output[32..].copy_from_slice(id.as_bytes());
    // Registry insertion is strictly before descriptor transfer.
    workers.push(OwnedWorker {
        child,
        lifetime,
        observer,
        registration: socket,
        id,
        started: Instant::now(),
        deadline: Instant::now() + STARTUP,
        cancelling: None,
        stage: Stage::Created,
        output,
        position: 0,
        response: [0; 16],
        attestation: Vec::new(),
        observer_eof: false,
        malformed: false,
        violation: false,
        status: None,
    });
    Ok(())
}
fn worker_main() -> i32 {
    let observer = unsafe { UnixStream::from_raw_fd(1) };
    if unsafe { libc::fcntl(1, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 || bounded(&observer).is_err()
    {
        return 1;
    }
    run_with_attestation(Some(observer))
}
// Diagnostics cannot unwind ownership on stderr EIO/ENOSPC. The independent
// summary/attestation is the proof; these messages are best effort only.
fn root_diagnostic(output: &mut impl Write, message: std::fmt::Arguments<'_>) {
    let _ = output.write_fmt(message);
    let _ = output.write_all(b"\n");
}
fn uncertain(
    test: &mut Child,
    workers: &mut [OwnedWorker],
    probes: &mut probe::Registry,
    directory: &Path,
    reason: &str,
) -> ! {
    for worker in workers.iter_mut() {
        worker.cancel();
    }
    let _ = probes.cancel_all();
    // An actual owned handle only. Never kill the root or the watchdog.
    let _ = test.kill();
    let _ = fs::write(directory.join("uncertain"), reason);
    root_diagnostic(
        &mut io::stderr().lock(),
        format_args!(
            "UNCERTAIN: {reason}; root retains {} worker handles",
            workers.len()
        ),
    );
    loop {
        thread::park_timeout(Duration::from_secs(60));
    }
}
pub fn controller_main() -> i32 {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().map(|s| s.as_os_str())
        == Some(std::ffi::OsStr::new("--internal-owned-test-worker"))
    {
        return worker_main();
    }
    if args.first().map(|s| s.as_os_str())
        == Some(std::ffi::OsStr::new("--internal-owned-shell-probe"))
    {
        return probe::exec_worker(&args[1..]);
    }
    if args.first().map(|s| s.as_os_str()) == Some(std::ffi::OsStr::new("--probe")) {
        return probe_main(&args[1..]);
    }
    if args.len() < 3 || args[1] != "--" {
        return 2;
    }
    if install_root_signals().is_err() {
        return 2;
    } // before ANY Child acquisition
    let directory = PathBuf::from(&args[0]);
    if !directory.is_absolute()
        || fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .is_err()
    {
        return 2;
    }
    controller(&directory, &args[2], &args[3..]).unwrap_or_else(|error| {
        eprintln!("controller setup: {error}");
        2
    })
}
fn controller(
    directory: &Path,
    command: &std::ffi::OsStr,
    args: &[std::ffi::OsString],
) -> io::Result<i32> {
    let endpoint = directory.join("pty.sock");
    let listener = UnixListener::bind(&endpoint)?;
    fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let metadata = private(&endpoint, true)?;
    let run = Uuid::new_v4();
    let capability = Uuid::new_v4();
    let executable = std::env::current_exe()?;
    let mut probes = probe::Registry::new(directory, command, &executable, capability, run)?;
    let mut test = Command::new(command)
        .args(args)
        .env(ENDPOINT, &endpoint)
        .env(CAPABILITY, capability.to_string())
        .env(RUN, run.to_string())
        .env(ROOT_PID, std::process::id().to_string())
        .env(
            ENDPOINT_ID,
            format!("{}:{}", metadata.dev(), metadata.ino()),
        )
        .env("LOMI_OWNED_TEST_DIRECTORY", directory)
        .env(probe::ENDPOINT_ID, probes.endpoint_id()?)
        .spawn()?;
    let mut workers: Vec<OwnedWorker> = Vec::new();
    let mut admissions: Vec<Admission> = Vec::new();
    let mut test_status = None;
    let mut failed = false;
    let mut cancelled = false;
    let mut killed = false;
    let mut crash_test_killed = false;
    let mut probe_cancels_before_host_crash = None;
    let mut completed = 0;
    let mut recovered = 0;
    let started = Instant::now();
    let deadline_ms = std::env::var("LOMI_OWNED_TEST_DEADLINE_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok());
    let deadline = started
        + deadline_ms
            .map(Duration::from_millis)
            .unwrap_or(RUN_DEADLINE);
    loop {
        // Deadlines/cancel have priority BEFORE any wait, admission or worker I/O.
        let control = fs::read_to_string(directory.join("control")).unwrap_or_default();
        if CANCEL.load(Ordering::Acquire)
            || Instant::now() >= deadline
            || control.trim() == "cancel"
            || control.trim() == "kill-test"
        {
            cancelled = true;
            failed = true;
        }
        // Fault-only Host death is independent of coordinated root cancel.
        // Do not set cancelled or call any probe/worker cancellation here.
        // The normal actual test reap/client EOF path below must do the drain.
        if !cancelled && control.trim() == "crash-test-only" && !killed && test_status.is_none() {
            let before = probes.cancel_attempts();
            match test.kill() {
                Ok(()) => {
                    killed = true;
                    crash_test_killed = true;
                    failed = true;
                    probe_cancels_before_host_crash = Some(before);
                }
                Err(error) => match test.try_wait() {
                    Ok(Some(status)) => {
                        test_status = Some(status);
                        failed = true;
                    }
                    _ => uncertain(
                        &mut test,
                        &mut workers,
                        &mut probes,
                        directory,
                        &error.to_string(),
                    ),
                },
            }
        }
        if cancelled {
            if let Err(error) = probes.cancel_all() {
                uncertain(
                    &mut test,
                    &mut workers,
                    &mut probes,
                    directory,
                    &error.to_string(),
                );
            }
            admissions.clear();
            for worker in &mut workers {
                worker.cancel();
            }
            if !killed && test_status.is_none() {
                match test.kill() {
                    Ok(()) => killed = true,
                    Err(e) => {
                        // Child may already have exited; try_wait is nonblocking.
                        match test.try_wait() {
                            Ok(Some(status)) => test_status = Some(status),
                            _ => uncertain(
                                &mut test,
                                &mut workers,
                                &mut probes,
                                directory,
                                &e.to_string(),
                            ),
                        }
                    }
                }
            }
        }
        if test_status.is_none() {
            test_status = match test.try_wait() {
                Ok(status) => status,
                Err(e) => uncertain(
                    &mut test,
                    &mut workers,
                    &mut probes,
                    directory,
                    &e.to_string(),
                ),
            };
        }
        if test_status.is_some() {
            admissions.clear();
            for worker in &mut workers {
                worker.cancel();
            }
        }
        if let Err(error) = probes.tick(directory, cancelled || test_status.is_some()) {
            uncertain(
                &mut test,
                &mut workers,
                &mut probes,
                directory,
                &error.to_string(),
            );
        }
        failed |= probes.failed;
        if !cancelled && test_status.is_none() {
            // Fixed accept/read/write budgets; all admission sockets nonblocking.
            for _ in 0..4 {
                if admissions.len() + workers.len() >= MAX_WORKERS {
                    break;
                }
                match listener.accept() {
                    Ok((socket, _)) => {
                        if socket.set_nonblocking(true).is_err() || peer(&socket, None).is_err() {
                            failed = true;
                            continue;
                        }
                        admissions.push(Admission {
                            socket,
                            request: [0; 40],
                            position: 0,
                            deadline: Instant::now() + STARTUP,
                        });
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => uncertain(
                        &mut test,
                        &mut workers,
                        &mut probes,
                        directory,
                        &e.to_string(),
                    ),
                }
            }
            let mut index = 0;
            while index < admissions.len() {
                let admission = &mut admissions[index];
                let ready = if Instant::now() >= admission.deadline {
                    Err(io::ErrorKind::TimedOut.into())
                } else {
                    read_part(
                        &mut admission.socket,
                        &mut admission.request,
                        &mut admission.position,
                    )
                };
                match ready {
                    Ok(false) => index += 1,
                    Ok(true) => {
                        match root_paused(directory, "request") {
                            Ok(true) => {
                                index += 1;
                                continue;
                            }
                            Ok(false) => {}
                            Err(e) => uncertain(
                                &mut test,
                                &mut workers,
                                &mut probes,
                                directory,
                                &e.to_string(),
                            ),
                        }
                        let admission = admissions.swap_remove(index);
                        if &admission.request[..8] != b"LOMI-FH1"
                            || &admission.request[8..24] != capability.as_bytes()
                            || &admission.request[24..] != run.as_bytes()
                        {
                            failed = true;
                            continue;
                        }
                        if spawn_owned(admission.socket, &mut workers, capability, run, &executable)
                            .is_err()
                        {
                            failed = true;
                        }
                    }
                    Err(error) => {
                        let admission = admissions.swap_remove(index);
                        // An unauthenticated peer may close before sending any
                        // frame (e.g. client rejects foreign root/inode). No
                        // capability was accepted and no worker was acquired.
                        if error.kind() != io::ErrorKind::UnexpectedEof || admission.position != 0 {
                            failed = true;
                        }
                    }
                }
            }
        }
        let mut index = 0;
        while index < workers.len() {
            match workers[index].poll(directory) {
                Ok(Drain::Pending) => index += 1,
                Ok(outcome) => {
                    let mut worker = workers.swap_remove(index);
                    completed += 1;
                    if outcome == Drain::RecoveredFailure {
                        failed = true;
                        recovered += 1;
                    }
                    let _ = worker
                        .registration
                        .write_all(if outcome == Drain::Qualified {
                            b"C"
                        } else {
                            b"U"
                        });
                    root_diagnostic(
                        &mut io::stderr().lock(),
                        format_args!(
                            "run={run} worker={} proof={:?} exit={:?} outcome={outcome:?} registry={}",
                            worker.id,
                            worker.attestation,
                            worker.status,
                            workers.len()
                        ),
                    );
                }
                Err(e) => uncertain(
                    &mut test,
                    &mut workers,
                    &mut probes,
                    directory,
                    &e.to_string(),
                ),
            }
        }
        if let Some(status) = test_status
            && workers.is_empty()
            && admissions.is_empty()
            && probes.outstanding() == 0
            && probes.admitted == probes.completed
        {
            let summary = serde_json::json!({"run":run.to_string(),"test_success":status.success(),"cancelled":cancelled,"failed":failed,"completed":completed,"recovered":recovered,"registry":0,"probe_admitted":probes.admitted,"probe_completed":probes.completed,"probe_registry":probes.outstanding(),"crash_test_killed":crash_test_killed,"test_signal":std::os::unix::process::ExitStatusExt::signal(&status),"probe_cancels_before_host_crash":probe_cancels_before_host_crash,"probe_cancel_attempts":probes.cancel_attempts()});
            fs::write(
                directory.join("summary.json"),
                serde_json::to_vec(&summary).map_err(|_| invalid())?,
            )?;
            probes.remove_endpoint()?;
            fs::remove_file(&endpoint)?;
            return Ok(if status.success() && !failed { 0 } else { 1 });
        }
        thread::sleep(TICK);
    }
}

fn probe_main(args: &[std::ffi::OsString]) -> i32 {
    use lomi_remote_protocol::{SessionEpoch, TerminalSessionId};
    let mode = args.first().and_then(|s| s.to_str()).unwrap_or("ordinary");
    let directory = PathBuf::from(std::env::var_os("LOMI_OWNED_TEST_DIRECTORY").unwrap());
    if mode == "slow-drip" || mode == "bad-ack" || mode == "replay-ack" || mode == "startup-eof" {
        let mut registration = UnixStream::connect(std::env::var_os(ENDPOINT).unwrap()).unwrap();
        bounded(&registration).unwrap();
        let mut request = b"LOMI-FH1".to_vec();
        request.extend(identity(CAPABILITY).unwrap().as_bytes());
        request.extend(identity(RUN).unwrap().as_bytes());
        if mode == "slow-drip" {
            fs::write(directory.join("probe.ready"), b"ready").unwrap();
            for byte in request {
                if registration.write_all(&[byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(150));
            }
            return 0;
        }
        registration.write_all(&request).unwrap();
        let mut proof = [0; 48];
        registration.read_exact(&mut proof).unwrap();
        let fd = receive_fd(&registration).unwrap();
        let _lifetime = UnixStream::from(OwnedFd::from(fd));
        if mode == "bad-ack" {
            registration.write_all(&[0; 16]).unwrap();
            let _ = registration.read(&mut [0]);
            return 0;
        }
        registration.write_all(&proof[32..]).unwrap();
        byte(&mut registration, b'K').unwrap();
        if mode == "replay-ack" {
            registration.write_all(&proof[32..]).unwrap();
            let _ = registration.read(&mut [0]);
        }
        return 0; // startup EOF, no profile or G, root's duplicate must shutdown.
    }
    if mode == "foreign-root" {
        unsafe {
            std::env::set_var(ROOT_PID, std::process::id().to_string());
        }
    }
    if mode == "replaced-endpoint" {
        unsafe {
            std::env::set_var(ENDPOINT_ID, "0:0");
        }
    }
    if mode == "wrong-capability" {
        unsafe {
            std::env::set_var(CAPABILITY, Uuid::new_v4().to_string());
        }
    }
    if mode == "wrong-run" {
        unsafe {
            std::env::set_var(RUN, Uuid::new_v4().to_string());
        }
    }
    if mode == "missing-endpoint" {
        unsafe {
            std::env::remove_var(ENDPOINT);
        }
    }
    let service = TerminalService::new();
    let id = TerminalSessionId::from_bytes([41; 16]).unwrap();
    let epoch = SessionEpoch::from_bytes([42; 16]).unwrap();
    let script = if mode == "noisy" {
        "echo started > shell.started; while :; do printf 'continuous-output-0123456789\\n'; done"
    } else if mode == "repeated-cleanup" {
        "echo started > shell.started; exit 0"
    } else {
        "echo started > shell.started; sleep 60 & wait"
    };
    let mut profile = SpawnProfile {
        executable: "/bin/sh".into(),
        args: vec!["-c".into(), script.into()],
        cwd: directory.clone(),
        environment: vec![
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("HOME".into(), directory.to_str().unwrap().into()),
        ],
        shell_integration: None,
        rows: 8,
        cols: 40,
        history: 16,
    };
    if mode == "expected-spawn-failure" {
        profile.executable = directory.join("missing-executable");
    }
    let result = service.spawn(id, epoch, &profile);
    if matches!(
        mode,
        "expected-spawn-failure"
            | "foreign-root"
            | "replaced-endpoint"
            | "wrong-capability"
            | "wrong-run"
            | "missing-endpoint"
    ) {
        return if result == Err(Error::SpawnFailed) {
            0
        } else {
            3
        };
    }
    if result.is_err() {
        return 3;
    }
    fs::write(directory.join("probe.ready"), b"ready").unwrap();
    if mode == "normal" {
        return if service.stop(id).is_ok() { 0 } else { 3 };
    }
    if mode == "repeated-cleanup" {
        let deadline = Instant::now() + STARTUP;
        loop {
            match service.exited_sessions() {
                Ok(exits) if !exits.is_empty() => break,
                Ok(_) => {}
                Err(_) => return 3,
            }
            if Instant::now() >= deadline {
                return 3;
            }
            thread::sleep(TICK);
        }
        for _ in 0..32 {
            if service.exited_sessions().is_err() {
                return 3;
            }
        }
        return 0;
    }
    loop {
        thread::sleep(TICK);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_distinguishes_all_data_bytes_from_eof() {
        let (mut receiver, mut sender) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).unwrap();
        assert_eq!(pending(&receiver).unwrap(), Pending::NoneYet);
        assert!(!lifetime_hook_aborts(pending(&receiver)));
        for value in u8::MIN..=u8::MAX {
            sender.write_all(&[value]).unwrap();
            assert_eq!(pending(&receiver).unwrap(), Pending::Data);
            assert!(!lifetime_hook_aborts(pending(&receiver)));
            let mut actual = [0];
            receiver.read_exact(&mut actual).unwrap();
            assert_eq!(actual, [value]);
            assert_eq!(pending(&receiver).unwrap(), Pending::NoneYet);
        }
        drop(sender);
        assert_eq!(pending(&receiver).unwrap(), Pending::Closed);
        assert!(lifetime_hook_aborts(pending(&receiver)));
        assert!(lifetime_hook_aborts(Err(io::ErrorKind::BrokenPipe.into())));
    }
    #[test]
    fn classification_requires_complete_matching_proof() {
        assert_eq!(
            classify(b"A", false, Some(CLEAN_EXIT)).unwrap(),
            Drain::Qualified
        );
        assert_eq!(classify(b"N", false, Some(1)).unwrap(), Drain::Qualified);
        assert_eq!(
            classify(b"B", false, Some(NO_CHILD_EXIT)).unwrap(),
            Drain::Qualified
        );
        for bytes in [b"".as_slice(), b"AA", b"AX", b"N"] {
            assert_eq!(
                classify(bytes, bytes.len() > 1, Some(CLEAN_EXIT)).unwrap(),
                Drain::RecoveredFailure
            );
        }
        assert!(classify(b"A", false, Some(1)).is_err());
        assert!(classify(b"", false, None).is_err());
    }
    #[test]
    fn stopped_worker_observations_are_idempotent() {
        let (socket, _peer) = UnixStream::pair().unwrap();
        let (registration, _root) = UnixStream::pair().unwrap();
        let mut worker = ExternalWorker {
            socket,
            registration,
            stopped: true,
        };
        for _ in 0..32 {
            assert_eq!(worker.finished(), Ok(true));
            assert_eq!(worker.stop(), Ok(()));
        }
    }
    #[test]
    fn duplicate_shutdown_unblocks_worker() {
        let (root, mut worker) = UnixStream::pair().unwrap();
        let _client = root.try_clone().unwrap();
        root.shutdown(Shutdown::Write).unwrap();
        assert_eq!(worker.read(&mut [0]).unwrap(), 0);
    }
    #[test]
    fn observation_drains_trailing_bytes_through_eof() {
        for suffix in *b"AX" {
            let mut bytes = Vec::new();
            let mut malformed = false;
            append_attestation(&mut bytes, &mut malformed, b"A");
            assert!(!malformed);
            append_attestation(&mut bytes, &mut malformed, &[suffix]);
            assert!(malformed);
            assert_eq!(
                classify(&bytes, malformed, Some(CLEAN_EXIT)).unwrap(),
                Drain::RecoveredFailure
            );
        }
    }
}
