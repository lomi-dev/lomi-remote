//! Feature-only broker for the single persisted-shell subprocess test.
//! No caller-selected command, arguments, environment map or production path.
use super::*;
use std::os::unix::process::ExitStatusExt;

const TAG: &[u8; 8] = b"LOMI-PB1";
pub(super) const ENDPOINT_ID: &str = "LOMI_OWNED_PROBE_ENDPOINT_ID";
const PATH_LIMIT: usize = 16 * 1024;
const MAX_PROBES: usize = 2;
const OUTPUT_LIMIT: usize = 64 * 1024;
static LAST_CHALLENGE: std::sync::Mutex<Option<[u8; 16]>> = std::sync::Mutex::new(None);
const PROBE_TEST: &str = "unix::rpc::tests::persisted_shell_process_probe";
const PROBE_ARGS: [&str; 3] = ["--exact", PROBE_TEST, "--nocapture"];
const ENVIRONMENT: [&str; 10] = [
    "HOME",
    "TMPDIR",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "PATH",
    "LANG",
    "LC_ALL",
    "TZ",
];

fn clean_path(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|part| {
            matches!(
                part,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}
fn paths(bytes: &[u8]) -> io::Result<[PathBuf; 3]> {
    let values: [String; 3] = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    let selected = values.map(PathBuf::from);
    if !selected.iter().all(|path| clean_path(path))
        || selected[0].file_name() != Some(std::ffi::OsStr::new("host.sqlite"))
        || selected[1].file_name() != Some(std::ffi::OsStr::new("selected-shell"))
        || !matches!(
            selected[2].file_name().and_then(|name| name.to_str()),
            Some("selected-shell" | "changed-shell")
        )
        || selected[0].parent() != selected[1].parent()
        || selected[0].parent() != selected[2].parent()
    {
        return Err(invalid());
    }
    let parent = selected[0].parent().ok_or_else(invalid)?;
    private(parent, false)?;
    let temporary =
        PathBuf::from(std::env::var_os("TMPDIR").ok_or_else(invalid)?).canonicalize()?;
    private(&temporary, false)?;
    let canonical = parent.canonicalize()?;
    if canonical == temporary || !canonical.starts_with(&temporary) {
        return Err(invalid());
    }
    for path in &selected[1..] {
        if fs::read_link(path)? != Path::new("/bin/sh") {
            return Err(invalid());
        }
    }
    match fs::symlink_metadata(&selected[0]) {
        Ok(metadata)
            if metadata.is_file()
                && metadata.nlink() == 1
                && metadata.uid() == unsafe { libc::geteuid() } => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        _ => return Err(invalid()),
    }
    Ok(selected)
}

/// Same Output semantics as the default test's Command::output invocation.
pub(crate) fn shell_probe(
    database: &Path,
    expected: &Path,
    shell: &Path,
) -> io::Result<std::process::Output> {
    let values = [database, expected, shell].map(|path| path.to_str().ok_or_else(invalid));
    let [database, expected, shell] = values;
    let bytes = serde_json::to_vec(&[database?, expected?, shell?]).map_err(|_| invalid())?;
    if bytes.len() > PATH_LIMIT {
        return Err(invalid());
    }
    let pty = PathBuf::from(std::env::var_os(super::ENDPOINT).ok_or_else(invalid)?);
    if !pty.is_absolute() {
        return Err(invalid());
    }
    let directory = pty.parent().ok_or_else(invalid)?;
    private(directory, false)?;
    let endpoint = directory.join("probe.sock");
    let before = private(&endpoint, true)?;
    if std::env::var(ENDPOINT_ID).map_err(|_| invalid())?
        != format!("{}:{}", before.dev(), before.ino())
    {
        return Err(invalid());
    }
    let mut socket = UnixStream::connect(&endpoint)?;
    bounded(&socket)?;
    let root = std::env::var(ROOT_PID)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or_else(invalid)?;
    peer(&socket, Some(root))?;
    let after = private(&endpoint, true)?;
    if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
        return Err(invalid());
    }
    let capability = identity(CAPABILITY)?;
    let run = identity(RUN)?;
    socket.write_all(TAG)?;
    socket.write_all(capability.as_bytes())?;
    socket.write_all(run.as_bytes())?;
    socket.write_all(&(bytes.len() as u32).to_be_bytes())?;
    socket.write_all(&bytes)?;
    let mut proof = [0; 49];
    socket.read_exact(&mut proof)?;
    if &proof[..16] != capability.as_bytes()
        || &proof[16..32] != run.as_bytes()
        || proof[48] != b'K'
    {
        return Err(invalid());
    }
    // K means the root already retains the actual gated Child. Only this ACK
    // allows G; disconnect before ACK never execs the Host probe.
    let challenge: [u8; 16] = proof[32..48].try_into().map_err(|_| invalid())?;
    let hook = std::env::var("LOMI_OWNED_TEST_HOOK").unwrap_or_default();
    let mut previous = LAST_CHALLENGE.lock().map_err(|_| invalid())?;
    let ack = if hook == "probe_bad_ack" {
        [0; 16]
    } else if hook == "probe_replay_ack" {
        (*previous).unwrap_or(challenge)
    } else {
        challenge
    };
    *previous = Some(challenge);
    drop(previous);
    socket.write_all(&ack)?;
    socket.set_read_timeout(Some(SESSION))?;
    let mut header = [0; 12];
    socket.read_exact(&mut header)?;
    let status = i32::from_be_bytes(header[..4].try_into().map_err(|_| invalid())?);
    let out = u32::from_be_bytes(header[4..8].try_into().map_err(|_| invalid())?) as usize;
    let err = u32::from_be_bytes(header[8..].try_into().map_err(|_| invalid())?) as usize;
    if out
        .checked_add(err)
        .is_none_or(|length| length > OUTPUT_LIMIT)
    {
        return Err(invalid());
    }
    let mut stdout = vec![0; out];
    let mut stderr = vec![0; err];
    socket.read_exact(&mut stdout)?;
    socket.read_exact(&mut stderr)?;
    let mut eof = [0];
    if socket.read(&mut eof)? != 0 {
        return Err(invalid());
    }
    Ok(std::process::Output {
        status: std::process::ExitStatus::from_raw(status),
        stdout,
        stderr,
    })
}

/// Runs only after exec of the fixed Host test, for authored native fault cases.
pub(crate) fn running_barrier() -> io::Result<()> {
    if std::env::var("LOMI_OWNED_TEST_HOOK").as_deref() != Ok("probe_running") {
        return Ok(());
    }
    let directory =
        PathBuf::from(std::env::var_os("LOMI_OWNED_TEST_DIRECTORY").ok_or_else(invalid)?);
    fs::write(directory.join("hook.probe_running"), b"ready")?;
    let deadline = Instant::now() + STARTUP;
    while !directory.join("release").exists() {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        thread::sleep(TICK);
    }
    Ok(())
}

// Gated exec keeps the same PID/actual root-retained Child through exec. No
// executable selection comes from a client frame; these args are root-built.
pub(super) fn exec_worker(args: &[std::ffi::OsString]) -> i32 {
    if args.len() != 4 {
        return 2;
    }
    let mut gate = unsafe { UnixStream::from_raw_fd(0) };
    if bounded(&gate).is_err() || byte(&mut gate, b'G').is_err() {
        return 2;
    }
    // Drop the lifetime descriptor at exec; this exact Host probe spawns no
    // native children. The root retains its actual Child until actual reap.
    if unsafe { libc::fcntl(0, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return 2;
    }
    let error = Command::new(&args[0])
        .args(PROBE_ARGS)
        .env("LOMI_TEST_SHELL_DATABASE", &args[1])
        .env("LOMI_TEST_EXPECTED_SHELL", &args[2])
        .env("SHELL", &args[3])
        .exec();
    eprintln!("fixed Host probe exec failed: {error}");
    2
}

#[derive(Clone, Copy, PartialEq)]
enum Stage {
    Header,
    Length,
    Paths,
    Retained,
    Ack,
    Gate,
    Active,
    Reply,
}
struct PendingProbe {
    socket: UnixStream,
    header: [u8; 40],
    length: [u8; 4],
    payload: Vec<u8>,
    position: usize,
    stage: Stage,
    deadline: Instant,
    child: Option<Child>,
    gate: Option<UnixStream>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_eof: bool,
    stderr_eof: bool,
    status: Option<std::process::ExitStatus>,
    cancelled: bool,
    response: Vec<u8>,
    challenge: Uuid,
    ack: [u8; 16],
    counted: bool,
    cancel_attempts: usize,
}
impl PendingProbe {
    fn new(socket: UnixStream) -> Self {
        Self {
            socket,
            header: [0; 40],
            length: [0; 4],
            payload: Vec::new(),
            position: 0,
            stage: Stage::Header,
            deadline: Instant::now() + STARTUP,
            child: None,
            gate: None,
            stdout: Vec::with_capacity(OUTPUT_LIMIT),
            stderr: Vec::with_capacity(OUTPUT_LIMIT),
            stdout_eof: false,
            stderr_eof: false,
            status: None,
            cancelled: false,
            response: Vec::with_capacity(OUTPUT_LIMIT + 12),
            challenge: Uuid::new_v4(),
            ack: [0; 16],
            counted: false,
            cancel_attempts: 0,
        }
    }
    fn cancel(&mut self) -> io::Result<()> {
        self.cancel_attempts += 1;
        self.cancelled = true;
        if let Some(gate) = &self.gate {
            let _ = gate.shutdown(Shutdown::Both);
        }
        if self.status.is_none()
            && let Some(child) = &mut self.child
        {
            self.status = child.try_wait()?;
            if self.status.is_none()
                && let Err(error) = child.kill()
            {
                self.status = child.try_wait()?;
                if self.status.is_none() {
                    return Err(error);
                }
            }
        }
        Ok(())
    }
    fn spawn(&mut self, directory: &Path, executable: &Path, host: &Path) -> io::Result<()> {
        let selected = paths(&self.payload)?;
        let (gate, inherited) = UnixStream::pair()?;
        gate.set_nonblocking(true)?;
        let mut command = Command::new(executable);
        command
            .arg("--internal-owned-shell-probe")
            .arg(host)
            .args(&selected)
            .env_clear()
            .env("SHELL", "/bin/sh")
            .env("TERM", "xterm-256color")
            .stdin(Stdio::from(OwnedFd::from(inherited)))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for key in ENVIRONMENT {
            command.env(key, std::env::var_os(key).ok_or_else(invalid)?);
        }
        command.env("LOMI_OWNED_TEST_DIRECTORY", directory);
        if std::env::var("LOMI_OWNED_TEST_HOOK").as_deref() == Ok("probe_running") {
            command.env("LOMI_OWNED_TEST_HOOK", "probe_running");
        }
        self.gate = Some(gate);
        // This entry is already in Registry.pending. Direct assignment retains
        // the returned actual Child before any setup, ACK, G or fallible I/O.
        self.child = Some(command.spawn()?);
        let child = self.child.as_ref().ok_or_else(invalid)?;
        for fd in [
            child.stdout.as_ref().ok_or_else(invalid)?.as_raw_fd(),
            child.stderr.as_ref().ok_or_else(invalid)?.as_raw_fd(),
        ] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        self.stage = Stage::Retained;
        self.position = 0;
        Ok(())
    }
    fn capture(&mut self) -> io::Result<()> {
        let child = self.child.as_mut().ok_or_else(invalid)?;
        for (source, output, eof) in [
            (
                child.stdout.as_mut().map(|stream| stream as &mut dyn Read),
                &mut self.stdout,
                &mut self.stdout_eof,
            ),
            (
                child.stderr.as_mut().map(|stream| stream as &mut dyn Read),
                &mut self.stderr,
                &mut self.stderr_eof,
            ),
        ] {
            if *eof {
                continue;
            }
            let source = source.ok_or_else(invalid)?;
            for _ in 0..2 {
                let mut bytes = [0; 4096];
                match source.read(&mut bytes) {
                    Ok(0) => {
                        *eof = true;
                        break;
                    }
                    Ok(n) => {
                        if output.len() + n > OUTPUT_LIMIT {
                            return Err(io::Error::other("probe output bound exceeded; retained"));
                        }
                        output.extend_from_slice(&bytes[..n]);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
        }
        if self.stdout.len() + self.stderr.len() > OUTPUT_LIMIT {
            return Err(io::Error::other(
                "combined probe output bound exceeded; retained",
            ));
        }
        Ok(())
    }
    fn tick(
        &mut self,
        directory: &Path,
        executable: &Path,
        host: &Path,
        capability: Uuid,
        run: Uuid,
    ) -> io::Result<bool> {
        if Instant::now() >= self.deadline {
            self.cancel()?;
        }
        if self.cancelled && self.child.is_none() {
            return Ok(true);
        }
        if !self.cancelled {
            match self.stage {
                Stage::Header => {
                    if read_part(&mut self.socket, &mut self.header, &mut self.position)? {
                        if &self.header[..8] != TAG
                            || &self.header[8..24] != capability.as_bytes()
                            || &self.header[24..] != run.as_bytes()
                        {
                            return Err(invalid());
                        }
                        self.stage = Stage::Length;
                        self.position = 0;
                    }
                }
                Stage::Length => {
                    if read_part(&mut self.socket, &mut self.length, &mut self.position)? {
                        let length = u32::from_be_bytes(self.length) as usize;
                        if length == 0 || length > PATH_LIMIT {
                            return Err(invalid());
                        }
                        self.payload.resize(length, 0);
                        self.stage = Stage::Paths;
                        self.position = 0;
                    }
                }
                Stage::Paths => {
                    if read_part(&mut self.socket, &mut self.payload, &mut self.position)? {
                        self.spawn(directory, executable, host)?;
                    }
                }
                Stage::Retained => {
                    if root_paused(directory, "probe_acquired")? {
                        return Ok(false);
                    }
                    let mut proof = [0; 49];
                    proof[..16].copy_from_slice(capability.as_bytes());
                    proof[16..32].copy_from_slice(run.as_bytes());
                    proof[32..48].copy_from_slice(self.challenge.as_bytes());
                    proof[48] = b'K';
                    if write_part(&mut self.socket, &proof, &mut self.position)? {
                        self.stage = Stage::Ack;
                        self.position = 0;
                    }
                }
                Stage::Ack => {
                    if read_part(&mut self.socket, &mut self.ack, &mut self.position)? {
                        if &self.ack != self.challenge.as_bytes() {
                            return Err(invalid());
                        }
                        self.stage = Stage::Gate;
                    }
                }
                Stage::Gate => {
                    if !matches!(pending(&self.socket)?, Pending::NoneYet) {
                        self.cancel()?;
                        return Ok(false);
                    }
                    match self.gate.as_mut().ok_or_else(invalid)?.write(b"G") {
                        Ok(1) => {
                            self.stage = Stage::Active;
                            self.deadline = Instant::now() + SESSION;
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        _ => return Err(invalid()),
                    }
                }
                Stage::Active => {
                    if !matches!(pending(&self.socket)?, Pending::NoneYet) {
                        self.cancel()?;
                    }
                }
                Stage::Reply => {}
            }
        }
        if self.child.is_some() && (self.stage == Stage::Active || self.cancelled) {
            self.capture()?;
            if !self.cancelled
                && self.stdout_eof
                && self.stderr_eof
                && root_paused(directory, "probe_draining")?
            {
                return Ok(false);
            }
            if self.status.is_none() {
                self.status = self.child.as_mut().ok_or_else(invalid)?.try_wait()?;
            }
            if let Some(status) = self.status
                && self.stdout_eof
                && self.stderr_eof
            {
                if self.cancelled {
                    return Ok(true);
                }
                self.response
                    .extend_from_slice(&status.into_raw().to_be_bytes());
                self.response
                    .extend_from_slice(&(self.stdout.len() as u32).to_be_bytes());
                self.response
                    .extend_from_slice(&(self.stderr.len() as u32).to_be_bytes());
                self.response.extend_from_slice(&self.stdout);
                self.response.extend_from_slice(&self.stderr);
                self.stage = Stage::Reply;
                self.position = 0;
            }
        }
        if self.stage == Stage::Reply
            && write_part(&mut self.socket, &self.response, &mut self.position)?
        {
            return Ok(true);
        }
        Ok(false)
    }
}

pub(super) struct Registry {
    listener: UnixListener,
    endpoint: PathBuf,
    host: PathBuf,
    executable: PathBuf,
    capability: Uuid,
    run: Uuid,
    pending: Vec<PendingProbe>,
    pub(super) admitted: usize,
    pub(super) completed: usize,
    pub(super) failed: bool,
    completed_cancel_attempts: usize,
}
impl Registry {
    pub(super) fn new(
        directory: &Path,
        host: &std::ffi::OsStr,
        executable: &Path,
        capability: Uuid,
        run: Uuid,
    ) -> io::Result<Self> {
        let host = PathBuf::from(host).canonicalize()?;
        let endpoint = directory.join("probe.sock");
        let listener = UnixListener::bind(&endpoint)?;
        fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            endpoint,
            host,
            executable: executable.to_path_buf(),
            capability,
            run,
            pending: Vec::with_capacity(MAX_PROBES),
            admitted: 0,
            completed: 0,
            failed: false,
            completed_cancel_attempts: 0,
        })
    }
    pub(super) fn endpoint_id(&self) -> io::Result<String> {
        let info = private(&self.endpoint, true)?;
        Ok(format!("{}:{}", info.dev(), info.ino()))
    }
    pub(super) fn outstanding(&self) -> usize {
        self.pending.len()
    }
    pub(super) fn cancel_attempts(&self) -> usize {
        self.completed_cancel_attempts
            + self
                .pending
                .iter()
                .map(|probe| probe.cancel_attempts)
                .sum::<usize>()
    }
    pub(super) fn cancel_all(&mut self) -> io::Result<()> {
        let mut first = None;
        for probe in &mut self.pending {
            if let Err(error) = probe.cancel()
                && first.is_none()
            {
                first = Some(error);
            }
        }
        match first {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    pub(super) fn tick(&mut self, directory: &Path, cancel: bool) -> io::Result<()> {
        if cancel {
            self.cancel_all()?;
        } else {
            for _ in 0..4 {
                if self.pending.len() >= MAX_PROBES {
                    break;
                }
                match self.listener.accept() {
                    Ok((socket, _)) => {
                        socket.set_nonblocking(true)?;
                        peer(&socket, None)?;
                        self.pending.push(PendingProbe::new(socket));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
        }
        let mut index = 0;
        while index < self.pending.len() {
            let result = self.pending[index].tick(
                directory,
                &self.executable,
                &self.host,
                self.capability,
                self.run,
            );
            if self.pending[index].child.is_some() && !self.pending[index].counted {
                self.admitted += 1;
                self.pending[index].counted = true;
            }
            self.failed |= self.pending[index].cancelled;
            let complete = match result {
                Ok(complete) => complete,
                Err(_) if self.pending[index].child.is_none() => {
                    self.failed = true;
                    true
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::BrokenPipe
                            | io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::ConnectionReset
                    ) || (error.kind() == io::ErrorKind::InvalidData
                        && self.pending[index].stage == Stage::Ack) =>
                {
                    self.failed = true;
                    self.pending[index].cancel()?;
                    false
                }
                Err(error) => return Err(error),
            };
            if complete {
                let probe = &self.pending[index];
                if probe.child.is_some()
                    && (probe.status.is_none() || !probe.stdout_eof || !probe.stderr_eof)
                {
                    return Err(io::Error::other(
                        "missing actual probe drain proof; retained",
                    ));
                }
                if probe.child.is_some() {
                    self.completed += 1;
                }
                self.completed_cancel_attempts += probe.cancel_attempts;
                self.pending.swap_remove(index);
            } else {
                index += 1;
            }
        }
        Ok(())
    }
    pub(super) fn remove_endpoint(&self) -> io::Result<()> {
        fs::remove_file(&self.endpoint)
    }
}
