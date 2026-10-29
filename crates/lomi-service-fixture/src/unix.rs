use portable_pty::{CommandBuilder, MasterPty, PtySize, native_pty_system};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const OUTPUT_LIMIT: u64 = 1024 * 1024;
const SCRIPT: &str = r#"
/bin/stty -echo
/bin/sleep 600 & worker=$!
cleanup() { kill "$worker" 2>/dev/null; wait "$worker" 2>/dev/null; }
trap 'cleanup; printf "FIXTURE_CTRL_C\n"; exit 0' INT
trap 'cleanup; printf "FIXTURE_TERM\n"; exit 0' TERM HUP
printf '\033]7;file://localhost%s\007\nFIXTURE_WORKER:%s\nFIXTURE_READY\n' "$PWD" "$worker"
while IFS= read -r command; do
  case "$command" in
    size) size=$(/bin/stty size); if [ "$size" = '37 101' ]; then printf 'FIXTURE_RESIZE_OK\n'; fi ;;
    after_detach) printf 'FIXTURE_DETACH_OK\n' ;;
    exit) cleanup; printf 'FIXTURE_EXIT\n'; exit 0 ;;
  esac
done
cleanup
"#;
fn denied(message: &str) -> Box<dyn std::error::Error + Send + Sync> {
    io::Error::new(io::ErrorKind::PermissionDenied, message).into()
}
fn private_file(file: &File) -> Result<()> {
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o777 != 0o600
        || m.nlink() != 1
    {
        return Err(denied("invalid private fixture file"));
    }
    Ok(())
}
struct Endpoint {
    listener: UnixListener,
    _lock: File,
    socket: PathBuf,
}
impl Endpoint {
    fn open(directory: &Path) -> Result<Self> {
        match fs::DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let m = fs::symlink_metadata(directory)?;
        if !directory.is_absolute()
            || fs::canonicalize(directory)? != directory
            || !m.is_dir()
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o777 != 0o700
        {
            return Err(denied(
                "fixture state must be a canonical private owned directory",
            ));
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join("owner.lock"))?;
        private_file(&lock)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(denied("fixture already has an owner"));
        }
        let socket = directory.join("fixture.sock");
        match fs::symlink_metadata(&socket) {
            Ok(m) => {
                if !m.file_type().is_socket() || m.uid() != unsafe { libc::geteuid() } {
                    return Err(denied("invalid stale fixture socket"));
                }
                fs::remove_file(&socket)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            _lock: lock,
            socket,
        })
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket);
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    version: u8,
    session_epoch: String,
}
fn previous(directory: &Path) -> Result<Option<String>> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join("session.json"))
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    private_file(&file)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file).take(2049).read_to_end(&mut bytes)?;
    if bytes.len() > 2048 {
        return Err(denied("fixture descriptor too large"));
    }
    let d: Descriptor = serde_json::from_slice(&bytes)?;
    if d.version != 1 || Uuid::parse_str(&d.session_epoch).is_err() {
        return Err(denied("invalid fixture descriptor"));
    }
    Ok(Some(d.session_epoch))
}
fn persist(directory: &Path, epoch: &str) -> Result<()> {
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    serde_json::to_writer(
        &mut file,
        &Descriptor {
            version: 1,
            session_epoch: epoch.into(),
        },
    )?;
    file.as_file().sync_all()?;
    file.persist(directory.join("session.json"))?;
    File::open(directory)?.sync_all()?;
    Ok(())
}
#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Counters {
    output_bytes: u64,
    output_chunks: u64,
    model_nonempty_cells: usize,
    ready: bool,
    cwd_detected: bool,
    resize_observed: bool,
    detach_observed: bool,
    ctrl_c_observed: bool,
    worker_pid: Option<i32>,
    input_writes: u64,
    cleanup_complete: bool,
    exit_code: Option<u32>,
}
// Own the direct child immediately after spawn, before any fallible setup.
// Keep it unreaped until all group signals have been sent, preventing PID reuse.
struct StartupChild {
    child: Option<Box<dyn portable_pty::Child + Send + Sync>>,
    pgid: Option<i32>,
    master: Option<Box<dyn MasterPty + Send>>,
    reader: Option<Box<dyn Read + Send>>,
    writer: Option<Box<dyn Write + Send>>,
}
type StartedHandles = (
    Box<dyn portable_pty::Child + Send + Sync>,
    Box<dyn MasterPty + Send>,
    Box<dyn Write + Send>,
);
impl StartupChild {
    fn new(
        child: Box<dyn portable_pty::Child + Send + Sync>,
        master: Box<dyn MasterPty + Send>,
        reader: Box<dyn Read + Send>,
        writer: Box<dyn Write + Send>,
    ) -> Self {
        Self {
            child: Some(child),
            pgid: None,
            master: Some(master),
            reader: Some(reader),
            writer: Some(writer),
        }
    }
    fn capture_group(&mut self) -> Result<i32> {
        let pid = self
            .child
            .as_ref()
            .unwrap()
            .process_id()
            .and_then(|p| i32::try_from(p).ok())
            .filter(|p| *p > 0)
            .ok_or_else(|| denied("fixture child missing native PID"))?;
        if unsafe { libc::getpgid(pid) } != pid {
            return Err(denied("fixture child missing dedicated process group"));
        }
        self.pgid = Some(pid);
        Ok(pid)
    }
    fn release(mut self) -> StartedHandles {
        (
            self.child.take().unwrap(),
            self.master.take().unwrap(),
            self.writer.take().unwrap(),
        )
    }
}
impl Drop for StartupChild {
    fn drop(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        if let Some(group) = self.pgid {
            unsafe {
                libc::kill(-group, libc::SIGTERM);
            }
            thread::sleep(Duration::from_millis(100));
        }
        // Close undrained PTY handles before reaping. Darwin can defer final
        // process teardown while these startup handles still hold the PTY.
        drop(self.reader.take());
        drop(self.writer.take());
        drop(self.master.take());
        if let Some(group) = self.pgid {
            unsafe {
                libc::kill(-group, libc::SIGKILL);
            }
        } else {
            let _ = child.kill();
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Err(error) if error.kind() != io::ErrorKind::Interrupted => break,
                _ => thread::sleep(Duration::from_millis(10)),
            }
        }
    }
}

struct Session {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    pgid: i32,
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    rx: mpsc::Receiver<Vec<u8>>,
    reader: Option<thread::JoinHandle<()>>,
    parser: vt100::Parser,
    tail: Vec<u8>,
    cwd_marker: Vec<u8>,
    stats: Counters,
    _home: tempfile::TempDir,
    exited: bool,
}
impl Session {
    fn start(directory: &Path) -> Result<Self> {
        Self::start_inner(directory, |_| Ok(()))
    }
    fn start_inner(directory: &Path, after_spawn: impl FnOnce(i32) -> Result<()>) -> Result<Self> {
        let home = tempfile::Builder::new()
            .prefix("synthetic-home-")
            .tempdir_in(directory)?;
        let cwd = fs::canonicalize(home.path())?;
        let pair = native_pty_system().openpty(PtySize::default())?;
        let mut command = CommandBuilder::new("/bin/sh");
        command.args(["-f", "-c", SCRIPT]);
        command.cwd(&cwd);
        command.env_clear();
        command.env("HOME", &cwd);
        command.env("PATH", "/usr/bin:/bin");
        command.env("LC_ALL", "C");
        command.env("TERM", "xterm-256color");
        // Complete fallible PTY handle acquisition before a child can exist.
        let reader = pair.master.try_clone_reader()?;
        let writer = pair.master.take_writer()?;
        let mut child = StartupChild::new(
            pair.slave.spawn_command(command)?,
            pair.master,
            reader,
            writer,
        );
        drop(pair.slave);
        let pgid = child.capture_group()?;
        after_spawn(pgid)?;
        let mut reader = child.reader.take().unwrap();
        let (tx, rx) = mpsc::sync_channel(32);
        let worker = thread::Builder::new()
            .name("synthetic-pty-reader".into())
            .spawn(move || {
                let mut chunk = [0u8; 2048];
                loop {
                    match reader.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tx.send(chunk[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                    }
                }
            })?;
        let (child, master, writer) = child.release();
        Ok(Self {
            child,
            pgid,
            master,
            writer,
            rx,
            reader: Some(worker),
            parser: vt100::Parser::new(24, 80, 8),
            tail: Vec::new(),
            cwd_marker: format!("\u{1b}]7;file://localhost{}\u{7}", cwd.display()).into_bytes(),
            stats: Counters::default(),
            _home: home,
            exited: false,
        })
    }
    fn poll(&mut self) -> Result<()> {
        for _ in 0..32 {
            match self.rx.try_recv() {
                Ok(chunk) => {
                    self.stats.output_bytes =
                        self.stats.output_bytes.saturating_add(chunk.len() as u64);
                    self.stats.output_chunks = self.stats.output_chunks.saturating_add(1);
                    if self.stats.output_bytes > OUTPUT_LIMIT {
                        return Err(denied("synthetic fixture output exceeded limit"));
                    }
                    self.parser.process(&chunk);
                    self.tail.extend(chunk);
                    if self.tail.len() > 4096 {
                        self.tail.drain(..self.tail.len() - 4096);
                    }
                    let contains =
                        |needle: &[u8]| self.tail.windows(needle.len()).any(|w| w == needle);
                    self.stats.ready |= contains(b"FIXTURE_READY\r\n");
                    self.stats.cwd_detected |= contains(&self.cwd_marker);
                    self.stats.resize_observed |= contains(b"FIXTURE_RESIZE_OK\r\n");
                    self.stats.detach_observed |= contains(b"FIXTURE_DETACH_OK\r\n");
                    self.stats.ctrl_c_observed |= contains(b"FIXTURE_CTRL_C\r\n");
                    if self.stats.worker_pid.is_none() {
                        let text = String::from_utf8_lossy(&self.tail);
                        if let Some(part) = text.split("FIXTURE_WORKER:").nth(1) {
                            self.stats.worker_pid =
                                part.split_once('\r').and_then(|(v, _)| v.parse().ok());
                        }
                    }
                    let (r, c) = self.parser.screen().size();
                    self.stats.model_nonempty_cells = (0..r)
                        .flat_map(|y| (0..c).map(move |x| (y, x)))
                        .filter(|(r, c)| {
                            self.parser
                                .screen()
                                .cell(*r, *c)
                                .is_some_and(|cell| !cell.contents().is_empty())
                        })
                        .count();
                }
                Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => break,
            }
        }
        if !self.exited
            && let Some(exit) = self.child.try_wait()?
        {
            self.exited = true;
            self.stats.exit_code = Some(exit.exit_code());
        }
        if self.exited {
            self.stats.cleanup_complete = self.stats.worker_pid.is_some_and(|pid| !alive(pid));
        }
        Ok(())
    }
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        if self.exited {
            return Err(denied("synthetic session exited; explicit start required"));
        }
        self.writer.write_all(bytes)?;
        self.writer.flush()?;
        self.stats.input_writes = self.stats.input_writes.saturating_add(1);
        Ok(())
    }
    fn resize(&mut self) -> Result<()> {
        self.master.resize(PtySize {
            rows: 37,
            cols: 101,
            pixel_width: 0,
            pixel_height: 0,
        })?;
        self.parser.screen_mut().set_size(37, 101);
        self.write(b"size\n")
    }
    fn stop(&mut self) -> Result<()> {
        if self.exited && self.stats.cleanup_complete {
            return Ok(());
        }
        unsafe {
            libc::kill(-self.pgid, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(4);
        while Instant::now() < deadline {
            self.poll()?;
            if self.exited && self.stats.cleanup_complete {
                return self.join_reader();
            }
            thread::sleep(Duration::from_millis(10));
        }
        unsafe {
            libc::kill(-self.pgid, libc::SIGKILL);
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            self.poll()?;
            if self.exited && self.stats.cleanup_complete {
                return self.join_reader();
            }
            thread::sleep(Duration::from_millis(10));
        }
        Err(denied("synthetic child cleanup deadline exceeded"))
    }
    fn join_reader(&mut self) -> Result<()> {
        if let Some(reader) = self.reader.take() {
            reader
                .join()
                .map_err(|_| denied("synthetic reader failed"))?;
        }
        Ok(())
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if !self.exited || !self.stats.cleanup_complete {
            unsafe {
                libc::kill(-self.pgid, libc::SIGKILL);
            }
        }
    }
}
fn alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}
#[cfg(target_os = "linux")]
fn same_uid(socket: &UnixStream) -> io::Result<bool> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid == unsafe { libc::geteuid() })
}
#[cfg(not(target_os = "linux"))]
fn same_uid(socket: &UnixStream) -> io::Result<bool> {
    let mut uid = 0;
    let mut gid = 0;
    if unsafe { libc::getpeereid(socket.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(uid == unsafe { libc::geteuid() })
}
fn status(
    owner_epoch: &str,
    epoch: &Option<String>,
    session: &Option<Session>,
) -> serde_json::Value {
    let state = if session.as_ref().is_some_and(|s| !s.exited) {
        "running"
    } else if session.is_some() {
        "exited"
    } else if epoch.is_some() {
        "lost"
    } else {
        "idle"
    };
    serde_json::json!({"fixture":true,"ownerEpoch":owner_epoch,"ownerPid":std::process::id(),"sessionEpoch":epoch,"state":state,"requiresExplicitStart":session.as_ref().is_none_or(|s|s.exited),"childPid":session.as_ref().map(|s|s.pgid),"stats":session.as_ref().map(|s|&s.stats),"modelRows":session.as_ref().map(|s|s.parser.screen().size().0),"modelCols":session.as_ref().map(|s|s.parser.screen().size().1)})
}
fn read_request(client: &mut UnixStream, stop: &AtomicBool) -> Result<String> {
    let deadline = Instant::now() + Duration::from_millis(250);
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    while bytes.len() < 128 && !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        client.set_read_timeout(Some(remaining.min(Duration::from_millis(25))))?;
        match client.read(&mut byte) {
            Ok(1) if byte[0] == b'\n' => {
                if stop.load(Ordering::Relaxed) || Instant::now() >= deadline {
                    break;
                }
                return String::from_utf8(bytes).map_err(Into::into);
            }
            Ok(1) => bytes.push(byte[0]),
            Ok(_) => break,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(denied(
        "incomplete, overlong or interrupted fixture request",
    ))
}
fn owner(directory: &Path) -> Result<()> {
    let endpoint = Endpoint::open(directory)?;
    let mut epoch = previous(directory)?;
    let owner_epoch = Uuid::new_v4().to_string();
    let mut session: Option<Session> = None;
    let stop = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(libc::SIGTERM, stop.clone())?;
    signal_hook::flag::register(libc::SIGINT, stop.clone())?;
    while !stop.load(Ordering::Relaxed) {
        if let Some(s) = &mut session {
            s.poll()?;
        }
        match endpoint.listener.accept() {
            Ok((mut client, _)) => {
                client.set_read_timeout(Some(Duration::from_millis(100)))?;
                client.set_write_timeout(Some(Duration::from_millis(100)))?;
                if !same_uid(&client)? {
                    continue;
                }
                let request = match read_request(&mut client, &stop) {
                    Ok(request) => request,
                    Err(_) => {
                        let _ = client.write_all(b"{\"error\":\"invalid fixture request\"}\n");
                        continue;
                    }
                };
                let result: Result<()> = match request.as_str() {
                    "status" => Ok(()),
                    "start" => {
                        if session.as_ref().is_some_and(|s| !s.exited) {
                            Err(denied("fixture already running"))
                        } else {
                            if let Some(s) = &mut session {
                                s.stop()?;
                            }
                            let new_epoch = Uuid::new_v4().to_string();
                            persist(directory, &new_epoch)?;
                            epoch = Some(new_epoch);
                            session = Some(Session::start(directory)?);
                            Ok(())
                        }
                    }
                    "resize" => session
                        .as_mut()
                        .ok_or_else(|| denied("no synthetic session"))
                        .and_then(Session::resize),
                    "after-detach" => session
                        .as_mut()
                        .ok_or_else(|| denied("no synthetic session"))
                        .and_then(|s| s.write(b"after_detach\n")),
                    "ctrl-c" => session
                        .as_mut()
                        .ok_or_else(|| denied("no synthetic session"))
                        .and_then(|s| s.write(&[3])),
                    "exit" => session
                        .as_mut()
                        .ok_or_else(|| denied("no synthetic session"))
                        .and_then(|s| s.write(b"exit\n")),
                    _ => Err(denied("unsupported synthetic fixture request")),
                };
                let reply = match result {
                    Ok(()) => status(&owner_epoch, &epoch, &session),
                    Err(_) => serde_json::json!({"error":"fixture request rejected"}),
                };
                let _ = serde_json::to_writer(&mut client, &reply);
                let _ = client.write_all(b"\n");
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10))
            }
            Err(e) => return Err(e.into()),
        }
    }
    if let Some(s) = &mut session {
        s.stop()?;
    }
    Ok(())
}
fn client(directory: &Path, request: &str) -> Result<()> {
    if ![
        "status",
        "start",
        "resize",
        "after-detach",
        "ctrl-c",
        "exit",
    ]
    .contains(&request)
    {
        return Err(denied("unsupported synthetic request"));
    }
    let mut socket = UnixStream::connect(directory.join("fixture.sock"))?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    socket.set_write_timeout(Some(Duration::from_secs(3)))?;
    socket.write_all(request.as_bytes())?;
    socket.write_all(b"\n")?;
    let mut bytes = Vec::new();
    socket.take(8193).read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        return Err(denied("fixture reply exceeds bound"));
    }
    let reply: serde_json::Value = serde_json::from_slice(&bytes)?;
    if reply.get("error").is_some() {
        return Err(denied("fixture rejected request"));
    }
    println!("{}", reply);
    Ok(())
}
pub fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("owner") if args.len() == 3 => owner(Path::new(&args[2])),
        Some("client") if args.len() == 4 => client(Path::new(&args[2]), &args[3]),
        _ => Err(denied(
            "usage: lomi-service-fixture owner DIR | client DIR status|start|resize|after-detach|ctrl-c|exit",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn post_spawn_failure_terminates_and_reaps_owned_child_group() {
        let temp = tempfile::tempdir().unwrap();
        let mut process = None;
        let mut worker = None;
        let result = Session::start_inner(temp.path(), |pgid| {
            process = Some(pgid);
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                // Numeric process/group identities only, never argv or PTY text.
                let listing = std::process::Command::new("/bin/ps")
                    .args(["-axo", "pid=,pgid=,comm="])
                    .output()?;
                worker = String::from_utf8(listing.stdout)?.lines().find_map(|line| {
                    let fields: Vec<_> = line.split_whitespace().collect();
                    if fields.len() != 3 {
                        return None;
                    }
                    let pid: i32 = fields[0].parse().ok()?;
                    let group: i32 = fields[1].parse().ok()?;
                    (group == pgid
                        && pid != pgid
                        && Path::new(fields[2])
                            .file_name()
                            .is_some_and(|name| name == "sleep"))
                    .then_some(pid)
                });
                if worker.is_some() {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(denied("injected failure after native spawn"))
        });
        assert!(result.is_err());
        assert!(process.is_some());
        assert!(
            worker.is_some(),
            "synthetic background worker must exist before injection"
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        while alive(process.unwrap()) || alive(worker.unwrap()) {
            if Instant::now() >= deadline {
                let diagnostic = std::process::Command::new("/bin/ps")
                    .args([
                        "-p",
                        &format!("{},{}", process.unwrap(), worker.unwrap()),
                        "-o",
                        "pid=,ppid=,pgid=,stat=,comm=",
                    ])
                    .output()
                    .unwrap();
                panic!(
                    "post-spawn failure cleanup deadline; owned process states: {}",
                    String::from_utf8_lossy(&diagnostic.stdout)
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}
