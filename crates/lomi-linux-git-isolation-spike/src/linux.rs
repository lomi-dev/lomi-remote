//! Bootstrap/seccomp supervision adapted from ../lomi-linux-git-spike; new namespace isolation.
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{self, File},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            net::UnixStream,
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, AtomicI32, Ordering},
    thread,
    time::{Duration, Instant},
};
mod filter;
mod fixtures;
mod setup;
mod snapshot;
const GIT: &str = "/usr/bin/git";
const RUNTIME: &[(&str, &str)] = &[
    (
        GIT,
        "aa6540695d076182256dd6e96c8b302e4d56381e3000bbfd5c71bbdfe94a4942",
    ),
    (
        "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
        "390027e5f45f236bd1838bc54bf464c5ff01d260ab9f8b415ea8276641bce505",
    ),
    (
        "/usr/lib/aarch64-linux-gnu/libpcre2-8.so.0.11.2",
        "aa4e91ff910dbb8e40472ed4fcaaeebfef19ad13fe925d9ed8e22e87d45ce13b",
    ),
    (
        "/usr/lib/aarch64-linux-gnu/libz.so.1.3",
        "e3bc90ee8cce46778c2f46c2a3e580d3b930f7b455910f25ea400a0b797fb9dc",
    ),
    (
        "/usr/lib/aarch64-linux-gnu/libc.so.6",
        "0f1905dc27dbc6715875c70527bc8da846a10084c9c483e9d8ff76dce8d69d0e",
    ),
    (
        "/etc/ld.so.cache",
        "0426562c09ae8b4c46cf1da76d3f563991135b17b7d7ec01baf6c25931f22a0a",
    ),
    (
        "/usr/lib/aarch64-linux-gnu/libgcc_s.so.1",
        "f2d3ad2bf0b61f6bc944cc37d7b6ab7f88d2582b41ff989ca164803f56cc5f20",
    ),
];
static CANCELLED: AtomicBool = AtomicBool::new(false);
static LAST_WORKER: AtomicI32 = AtomicI32::new(0);
static SECOND_DRAINER_FAILURE_OBSERVED: AtomicBool = AtomicBool::new(false);
static CANCEL_FIXTURE: AtomicBool = AtomicBool::new(false);
extern "C" fn cancel(_: i32) {
    CANCELLED.store(true, Ordering::SeqCst);
}
const LIMIT: usize = 2 * 1024 * 1024;
const ERROR_LIMIT: usize = 16 * 1024;
const DEADLINE: Duration = Duration::from_secs(5);
#[derive(Clone, Copy)]
enum Observation {
    Status,
    Diff,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Probe {
    None,
    Hang,
    Syscalls,
    CloseBefore,
    CloseAfter,
    InheritedFd,
    Network,
    Write,
    WrongRuntime,
    SecondDrainerFailure,
    PostflightFifo,
    PostflightFile,
}
impl Probe {
    fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Hang => "hang",
            Self::Syscalls => "syscalls",
            Self::CloseBefore => "close-before",
            Self::CloseAfter => "close-after",
            Self::InheritedFd => "inherited-fd",
            Self::Network => "network",
            Self::Write => "write",
            Self::WrongRuntime => "wrong-runtime",
            Self::SecondDrainerFailure => "second-drainer-failure",
            Self::PostflightFifo => "postflight-fifo",
            Self::PostflightFile => "postflight-file",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "none" => Self::None,
            "hang" => Self::Hang,
            "syscalls" => Self::Syscalls,
            "close-before" => Self::CloseBefore,
            "close-after" => Self::CloseAfter,
            "inherited-fd" => Self::InheritedFd,
            "network" => Self::Network,
            "write" => Self::Write,
            "wrong-runtime" => Self::WrongRuntime,
            "second-drainer-failure" => Self::SecondDrainerFailure,
            "postflight-fifo" => Self::PostflightFifo,
            "postflight-file" => Self::PostflightFile,
            _ => return None,
        })
    }
}
#[derive(Debug, PartialEq, Eq)]
enum Error {
    Unsupported,
    Runtime,
    Repository,
    Setup,
    Rejected,
    Limit,
    Deadline,
    Changed,
    Interrupted,
}
type Result<T> = std::result::Result<T, Error>;
fn identity(f: &File) -> Result<(u64, u64, u64, i64, i64, i64, i64)> {
    let m = f.metadata().map_err(|_| Error::Runtime)?;
    Ok((
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    ))
}
fn runtime() -> Result<Vec<File>> {
    let mut files = Vec::new();
    for (index, &(path, expected)) in RUNTIME.iter().enumerate() {
        for p in Path::new(path).ancestors() {
            let m = fs::symlink_metadata(p).map_err(|_| Error::Runtime)?;
            if m.is_symlink()
                || m.uid() != 0
                || m.mode() & 0o022 != 0
                || (p == Path::new(path)
                    && (!m.is_file()
                        || (index <= 1 && (m.mode() & 0o111 == 0 || m.mode() & 0o6000 != 0))))
                || (p != Path::new(path) && !m.is_dir())
            {
                return Err(Error::Runtime);
            }
        }
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| Error::Runtime)?;
        let mut hash = Sha256::new();
        let mut bytes = [0; 8192];
        loop {
            let n = file.read(&mut bytes).map_err(|_| Error::Runtime)?;
            if n == 0 {
                break;
            }
            hash.update(&bytes[..n]);
        }
        if format!("{:x}", hash.finalize()) != expected {
            return Err(Error::Runtime);
        }
        files.push(file);
    }
    Ok(files)
}
fn abi() -> Result<()> {
    let mut system = unsafe { std::mem::zeroed::<libc::utsname>() };
    if unsafe { libc::uname(&mut system) } != 0
        || unsafe { std::ffi::CStr::from_ptr(system.release.as_ptr()) }.to_bytes()
            != b"6.8.0-146-generic"
        || unsafe { std::ffi::CStr::from_ptr(system.machine.as_ptr()) }.to_bytes() != b"aarch64"
        || unsafe { libc::geteuid() } == 0
        || !fs::read_to_string("/etc/os-release")
            .map_err(|_| Error::Unsupported)?
            .lines()
            .any(|line| line == r#"PRETTY_NAME="Ubuntu 24.04.5 LTS""#)
    {
        return Err(Error::Unsupported);
    }
    // Exact ABI4 only: unknown newer filesystem rights must not be ignored.
    if unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0,
            1,
        )
    } != 4
    {
        return Err(Error::Unsupported);
    }
    Ok(())
}
fn drain(mut reader: impl Read, limit: usize, overflow: &AtomicBool) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut bytes = [0; 8192];
    loop {
        match reader.read(&mut bytes) {
            Ok(0) => return Ok(result),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::Setup),
            Ok(n) => {
                if n > limit.saturating_sub(result.len()) {
                    overflow.store(true, Ordering::SeqCst);
                    return Ok(result);
                }
                result.extend_from_slice(&bytes[..n]);
            }
        }
    }
}
struct OwnedWorker {
    child: std::process::Child,
    armed: bool,
}
impl Drop for OwnedWorker {
    fn drop(&mut self) {
        if self.armed {
            unsafe {
                libc::kill(-(self.child.id() as i32), libc::SIGKILL);
            }
            let _ = self.child.wait();
        }
    }
}
// Both authorization and revalidation must reject a replaced FIFO/device/file
// without opening it in blocking mode. The fd still pins the actual directory.
fn open_root(path: &Path) -> std::io::Result<File> {
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}
fn namespace_prerequisite() -> Result<()> {
    for (path, hash) in [
        (
            "/usr/bin/bwrap",
            "cd6b143283b464baf078ab09ca19dadc5bcc2423b833c4f9dd7e83f9ba1b640b",
        ),
        (
            "/etc/apparmor.d/lomi-git-bwrap-experimental",
            "632d84dbcf93dd242838d3d5090e344fb9ba7c83e3ee935d06f4e055479d7b86",
        ),
    ] {
        let m = fs::symlink_metadata(path).map_err(|_| Error::Runtime)?;
        if !m.is_file()
            || m.uid() != 0
            || m.mode() & 0o6022 != 0
            || format!(
                "{:x}",
                Sha256::digest(fs::read(path).map_err(|_| Error::Runtime)?)
            ) != hash
        {
            return Err(Error::Runtime);
        }
    }
    let m = fs::metadata("/dev/null").map_err(|_| Error::Runtime)?;
    if m.mode() & libc::S_IFMT != libc::S_IFCHR
        || m.uid() != 0
        || libc::major(m.rdev()) != 1
        || libc::minor(m.rdev()) != 3
    {
        return Err(Error::Runtime);
    }
    Ok(())
}
fn read(
    root: &Path,
    observation: Observation,
    probe: Probe,
    extra: Option<RawFd>,
) -> Result<Vec<u8>> {
    abi()?;
    let canonical = root.canonicalize().map_err(|_| Error::Repository)?;
    let directory = open_root(&canonical).map_err(|_| Error::Repository)?;
    let root_id = identity(&directory)?;
    if !directory
        .metadata()
        .map_err(|_| Error::Repository)?
        .is_dir()
    {
        return Err(Error::Repository);
    }
    let mut snapshot = snapshot::Snapshot::capture_pinned(&directory)?;
    let approved = runtime()?;
    namespace_prerequisite()?;
    let initial: Vec<_> = approved.iter().map(identity).collect::<Result<_>>()?;
    let mut sealed_runtime = Vec::new();
    for file in &approved {
        let mut copy = file.try_clone().map_err(|_| Error::Runtime)?;
        use std::io::{Seek, SeekFrom};
        copy.seek(SeekFrom::Start(0)).map_err(|_| Error::Runtime)?;
        let m = file.metadata().map_err(|_| Error::Runtime)?;
        sealed_runtime.push(snapshot::sealed(
            copy,
            m.mode(),
            (m.mtime(), m.mtime_nsec()),
            32 * 1024 * 1024,
        )?);
    }
    let executable = File::open(std::env::current_exe().map_err(|_| Error::Setup)?)
        .map_err(|_| Error::Runtime)?;
    let m = executable.metadata().map_err(|_| Error::Runtime)?;
    let bootstrap = snapshot::sealed(
        executable,
        0o555,
        (m.mtime(), m.mtime_nsec()),
        32 * 1024 * 1024,
    )?;
    let mut command = Command::new("/usr/bin/bwrap");
    command.args([
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--as-pid-1",
        "--die-with-parent",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "CAP_SYS_ADMIN",
        "--cap-add",
        "CAP_SETPCAP",
        "--dir",
        "/repo",
        "--dir",
        "/usr",
        "--dir",
        "/usr/bin",
        "--dir",
        "/usr/lib",
        "--dir",
        "/usr/lib/aarch64-linux-gnu",
        "--dir",
        "/etc",
        "--dir",
        "/dev",
        "--symlink",
        "usr/lib",
        "/lib",
    ]);
    let mut inherited = vec![bootstrap.as_raw_fd()];
    command.args([
        "--perms",
        "0555",
        "--ro-bind-data",
        &bootstrap.as_raw_fd().to_string(),
        "/bootstrap",
    ]);
    for ((path, _), file) in RUNTIME.iter().zip(&sealed_runtime) {
        command.args([
            "--perms",
            &format!(
                "{:o}",
                file.metadata().map_err(|_| Error::Runtime)?.mode() & 0o777
            ),
            "--ro-bind-data",
            &file.as_raw_fd().to_string(),
            path,
        ]);
        inherited.push(file.as_raw_fd());
    }
    command.args([
        "--symlink",
        "aarch64-linux-gnu/ld-linux-aarch64.so.1",
        "/usr/lib/ld-linux-aarch64.so.1",
        "--symlink",
        "libpcre2-8.so.0.11.2",
        "/usr/lib/aarch64-linux-gnu/libpcre2-8.so.0",
        "--symlink",
        "libz.so.1.3",
        "/usr/lib/aarch64-linux-gnu/libz.so.1",
        "--dev-bind",
        "/dev/null",
        "/dev/null",
    ]);
    for entry in &snapshot.entries {
        let dest = Path::new("/repo").join(&entry.path);
        if let Some(file) = &entry.data {
            command
                .arg("--perms")
                .arg(format!("{:o}", entry.mode & 0o777))
                .arg("--bind-data")
                .arg(file.as_raw_fd().to_string())
                .arg(dest);
            inherited.push(file.as_raw_fd());
        } else if let Some(target) = &entry.target {
            use std::os::unix::ffi::OsStrExt;
            command
                .arg("--symlink")
                .arg(std::ffi::OsStr::from_bytes(target))
                .arg(dest);
        } else {
            command
                .arg("--perms")
                .arg(format!("{:o}", entry.mode & 0o777))
                .arg("--dir")
                .arg(dest);
        }
    }
    command.args(["--chdir", "/repo", "--", "/bootstrap", "--worker"]);
    command
        .arg(match observation {
            Observation::Status => "status",
            Observation::Diff => "diff",
        })
        .arg(probe.name());
    let metadata: Vec<_> = snapshot
        .entries
        .iter()
        .filter_map(|e| {
            e.data.as_ref().map(|f| {
                Ok((
                    e.path.to_str().ok_or(Error::Repository)?.to_owned(),
                    e.mode & 0o777,
                    f.metadata().map_err(|_| Error::Setup)?.mtime(),
                    f.metadata().map_err(|_| Error::Setup)?.mtime_nsec(),
                ))
            })
        })
        .collect::<Result<_>>()?;
    let bytes = serde_json::to_vec(&metadata).map_err(|_| Error::Setup)?;
    let manifest = snapshot::sealed(bytes.as_slice(), 0o400, (0, 0), 128 * 1024)?;
    inherited.push(manifest.as_raw_fd());
    command.arg(manifest.as_raw_fd().to_string());
    command.arg(extra.unwrap_or(-1).to_string());
    if let Some(fd) = extra {
        inherited.push(fd);
    }
    snapshot.validate()?;
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("HOME", "/nonexistent")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let owner = std::process::id() as i32;
    // Only async-signal-safe fd flag changes occur in the forked launcher.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                || libc::getppid() != owner
            {
                return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
            }
            for fd in &inherited {
                if libc::fcntl(*fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut worker = OwnedWorker {
        child: command.spawn().map_err(|_| Error::Setup)?,
        armed: true,
    };
    let active = fs::read_to_string(format!("/proc/{}/attr/current", worker.child.id()))
        .map_err(|_| Error::Runtime)?;
    if active.trim() != "lomi-git-bwrap-experimental (unconfined)" {
        return Err(Error::Runtime);
    }
    LAST_WORKER.store(worker.child.id() as i32, Ordering::SeqCst);
    if CANCEL_FIXTURE.load(Ordering::SeqCst) {
        println!("worker-ready:{}", worker.child.id());
        std::io::Write::flush(&mut std::io::stdout()).map_err(|_| Error::Setup)?;
    }
    let stdout = worker.child.stdout.take().ok_or(Error::Setup)?;
    let stderr = worker.child.stderr.take().ok_or(Error::Setup)?;
    let overflow = AtomicBool::new(false);
    let deadline = Instant::now() + DEADLINE;
    let result = thread::scope(|s| {
        // The owned guard is local to the scope body. On startup failure or
        // unwind it kills/reaps before scope automatically joins any drainer.
        let mut worker = worker;
        let out = thread::Builder::new()
            .name("git-stdout".into())
            .spawn_scoped(s, || drain(stdout, LIMIT, &overflow))
            .map_err(|_| Error::Setup)?;
        let err = if probe == Probe::SecondDrainerFailure {
            // Fixture: stdout reader has started while the owned namespace
            // launch still holds its pipe. Inject the second reader failure.
            SECOND_DRAINER_FAILURE_OBSERVED.store(true, Ordering::SeqCst);
            Err(std::io::Error::from_raw_os_error(libc::EAGAIN))
        } else {
            thread::Builder::new()
                .name("git-stderr".into())
                .spawn_scoped(s, || drain(stderr, ERROR_LIMIT, &overflow))
        }
        .map_err(|_| Error::Setup)?;
        let completed = loop {
            if CANCELLED.load(Ordering::SeqCst) {
                break Err(Error::Interrupted);
            }
            if overflow.load(Ordering::SeqCst) {
                break Err(Error::Limit);
            }
            if Instant::now() >= deadline {
                break Err(Error::Deadline);
            }
            let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
            if unsafe {
                libc::waitid(
                    libc::P_PID,
                    worker.child.id(),
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } < 0
            {
                break Err(Error::Setup);
            }
            if unsafe { info.si_pid() } != 0 {
                break Ok(());
            }
            thread::sleep(Duration::from_millis(5));
        };
        // Preserve the unreaped leader until the final group signal, avoiding PID
        // adoption/reuse even when the broker is blocked or a Git child survives it.
        unsafe {
            libc::kill(-(worker.child.id() as i32), libc::SIGKILL);
        }
        let status = worker.child.wait().map_err(|_| Error::Setup)?;
        worker.armed = false;
        let out = out.join().map_err(|_| Error::Setup)??;
        let err = err.join().map_err(|_| Error::Setup)??;
        completed?;
        if overflow.load(Ordering::SeqCst) {
            return Err(Error::Limit);
        }
        if !status.success() || !err.is_empty() {
            return Err(Error::Rejected);
        }
        Ok(out)
    });
    if matches!(probe, Probe::PostflightFifo | Probe::PostflightFile) {
        // Synthetic regression hook: Git and its worker have already finished.
        // Replace this fixture root immediately before the postflight open.
        result.as_ref().map_err(|_| Error::Setup)?;
        fs::rename(&canonical, canonical.with_file_name("detached-fixture"))
            .map_err(|_| Error::Setup)?;
        if probe == Probe::PostflightFifo {
            let path =
                CString::new(canonical.as_os_str().as_encoded_bytes()).map_err(|_| Error::Setup)?;
            if unsafe { libc::mkfifo(path.as_ptr(), 0o600) } != 0 {
                return Err(Error::Setup);
            }
        } else {
            fs::write(&canonical, b"synthetic replacement").map_err(|_| Error::Setup)?;
        }
    }
    snapshot.validate()?;
    let current_root = open_root(&canonical).map_err(|_| Error::Changed)?;
    let current_identity = identity(&current_root)?;
    if (current_identity.0, current_identity.1) != (root_id.0, root_id.1) {
        return Err(Error::Changed);
    }
    let current = runtime()?;
    if current.iter().map(identity).collect::<Result<Vec<_>>>()? != initial {
        return Err(Error::Changed);
    }
    result
}

fn cstrings(values: &[&str]) -> Vec<CString> {
    values.iter().map(|v| CString::new(*v).unwrap()).collect()
}
fn worker(args: &[String]) -> Result<()> {
    if args.len() != 5 {
        return Err(Error::Setup);
    }
    let observation = match args[1].as_str() {
        "status" => Observation::Status,
        "diff" => Observation::Diff,
        _ => return Err(Error::Setup),
    };
    let probe = Probe::parse(&args[2]).ok_or(Error::Setup)?;
    let metadata = args[3].parse::<i32>().map_err(|_| Error::Setup)?;
    setup::finish(metadata)?;
    let extra = args[4].parse::<i32>().map_err(|_| Error::Setup)?;
    let directory = open_root(Path::new("/repo")).map_err(|_| Error::Setup)?;
    let root = directory.as_raw_fd();
    let executable = File::open("/usr/bin/git").map_err(|_| Error::Runtime)?;
    let git = executable.as_raw_fd();
    // bwrap consumes/closes all sealed mount input FDs. No host directory
    // descriptor was inherited. Close all remaining descriptors before fork.
    let max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) }.clamp(64, 65536) as i32;
    for fd in 3..max {
        if fd != root && fd != git && fd != extra {
            unsafe { libc::close(fd) };
        }
    }
    let (parent, child) = UnixStream::pair().map_err(|_| Error::Setup)?;
    let base = [
        "git",
        "--no-pager",
        "--no-optional-locks",
        "--literal-pathspecs",
        "--git-dir=.git",
        "--work-tree=.",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "gc.auto=0",
    ];
    let mut argv = cstrings(&base);
    argv.extend(cstrings(if probe == Probe::Network {
        &["ls-remote", "origin"]
    } else if probe == Probe::Write {
        &["config", "fixture.write", "denied"]
    } else {
        match observation {
            Observation::Status => &[
                "status",
                "--porcelain=v2",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=all",
            ],
            Observation::Diff => &[
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--no-color",
                "--no-renames",
                "--ignore-submodules=all",
                "--",
            ],
        }
    }));
    let argvp: Vec<_> = argv
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let env = cstrings(&[
        "PATH=/usr/bin:/bin",
        "HOME=/nonexistent",
        "LC_ALL=C",
        "GIT_CONFIG_NOSYSTEM=1",
        "GIT_CONFIG_GLOBAL=/dev/null",
        "GIT_CONFIG_SYSTEM=/dev/null",
        "GIT_ATTR_NOSYSTEM=1",
        "GIT_TERMINAL_PROMPT=0",
        "GIT_OPTIONAL_LOCKS=0",
        "GIT_NO_LAZY_FETCH=1",
        "GIT_NO_REPLACE_OBJECTS=1",
    ]);
    let envp: Vec<_> = env
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let empty = c"";
    let program = filter::program(child.as_raw_fd());
    // This broker executable starts single-threaded. After fork the trusted child
    // uses raw syscalls only; repository-controlled data is first read by Git.
    let owner = unsafe { libc::getpid() };
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(Error::Setup);
    }
    if pid == 0 {
        unsafe {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                || libc::getppid() != owner
            {
                libc::_exit(120)
            }
            libc::close(parent.as_raw_fd());
            if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) != 0
                || libc::fchdir(root) != 0
            {
                libc::_exit(120)
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                libc::_exit(121)
            }
            for (resource, value) in [
                (libc::RLIMIT_AS, 256 * 1024 * 1024),
                (libc::RLIMIT_CORE, 0),
                (libc::RLIMIT_FSIZE, 0),
                (libc::RLIMIT_CPU, 3),
                (libc::RLIMIT_NOFILE, 64),
            ] {
                let limit = libc::rlimit {
                    rlim_cur: value,
                    rlim_max: value,
                };
                if libc::setrlimit(resource, &limit) != 0 {
                    libc::_exit(122)
                }
            }
            if !filter::close_unneeded(git, child.as_raw_fd()) {
                libc::_exit(122)
            }
            if probe == Probe::InheritedFd
                && (extra < 3
                    || libc::fcntl(extra, libc::F_GETFD) != -1
                    || *libc::__errno_location() != libc::EBADF)
            {
                libc::_exit(126)
            }
            let descriptor = libc::sock_fprog {
                len: program.len() as u16,
                filter: program.as_ptr().cast_mut(),
            };
            let listener = libc::syscall(libc::SYS_seccomp, 1, 8, &descriptor) as i32;
            if listener < 0 {
                libc::_exit(123)
            }
            if !filter::send_fd(child.as_raw_fd(), listener) {
                libc::_exit(124)
            }
            libc::close(listener);
            libc::close(child.as_raw_fd());
            if probe == Probe::Hang {
                loop {
                    let delay = libc::timespec {
                        tv_sec: 1,
                        tv_nsec: 0,
                    };
                    libc::syscall(
                        libc::SYS_ppoll,
                        std::ptr::null::<u8>(),
                        0,
                        &delay,
                        std::ptr::null::<u8>(),
                        0,
                    );
                }
            }
            if probe == Probe::Syscalls && !filter::syscall_probe() {
                libc::_exit(126)
            }
            let env_ptr = if probe == Probe::CloseAfter {
                std::ptr::dangling::<*const libc::c_char>()
            } else {
                envp.as_ptr()
            };
            let result = libc::syscall(
                libc::SYS_execveat,
                git,
                empty.as_ptr(),
                argvp.as_ptr(),
                env_ptr,
                libc::AT_EMPTY_PATH,
            );
            if probe == Probe::CloseAfter {
                let first = *libc::__errno_location();
                let second = libc::syscall(
                    libc::SYS_execveat,
                    git,
                    empty.as_ptr(),
                    argvp.as_ptr(),
                    envp.as_ptr(),
                    libc::AT_EMPTY_PATH,
                );
                libc::_exit(
                    if result == -1
                        && first == libc::EFAULT
                        && second == -1
                        && *libc::__errno_location() == libc::ENOSYS
                    {
                        0
                    } else {
                        127
                    },
                );
            }
            libc::_exit(125)
        }
    }
    drop(child);
    if probe == Probe::Hang {
        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }
    let broker = filter::approve(
        &parent,
        pid,
        git,
        empty.as_ptr() as u64,
        argvp.as_ptr() as u64,
        if probe == Probe::CloseAfter {
            std::ptr::dangling::<*const libc::c_char>() as u64
        } else {
            envp.as_ptr() as u64
        },
        probe == Probe::CloseBefore,
    );
    if broker.is_err() {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
    let mut status = 0;
    if unsafe { libc::waitpid(pid, &mut status, 0) } != pid {
        return Err(Error::Setup);
    }
    broker?;
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err(Error::Rejected);
    }
    Ok(())
}
pub(super) fn main() -> i32 {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("--worker") {
        unsafe {
            libc::signal(libc::SIGINT, cancel as *const () as libc::sighandler_t);
            libc::signal(libc::SIGTERM, cancel as *const () as libc::sighandler_t);
        }
    }
    let result = if args.first().map(String::as_str) == Some("--worker") {
        worker(&args)
    } else if args.first().map(String::as_str) == Some("cancel") {
        return fixtures::cancel_probe();
    } else if args.first().map(String::as_str) == Some("regression") {
        return fixtures::run();
    } else {
        eprintln!("usage: lomi-linux-git-isolation-spike regression (synthetic, unqualified)");
        return 2;
    };
    if let Err(ref e) = result {
        eprintln!("worker-failure:{e:?}");
    }
    if result.is_ok() { 0 } else { 1 }
}
