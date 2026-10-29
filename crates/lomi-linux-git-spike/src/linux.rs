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
fn wait_for_git_image(worker: u32) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let children = fs::read_to_string(format!("/proc/{worker}/task/{worker}/children"))
            .map_err(|_| Error::Setup)?;
        for child in children.split_whitespace() {
            if child.bytes().all(|b| b.is_ascii_digit())
                && fs::read_link(format!("/proc/{child}/exe")).is_ok_and(|p| p == Path::new(GIT))
            {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(Error::Setup);
        }
        thread::sleep(Duration::from_millis(5));
    }
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
        || !fs::symlink_metadata(canonical.join(".git"))
            .map_err(|_| Error::Repository)?
            .is_dir()
    {
        return Err(Error::Repository);
    }
    let approved = runtime()?;
    let initial: Vec<_> = approved.iter().map(identity).collect::<Result<_>>()?;
    let mut fds = vec![directory.as_raw_fd()];
    fds.extend(approved.iter().map(AsRawFd::as_raw_fd));
    if probe == Probe::WrongRuntime {
        fds[1] = directory.as_raw_fd();
    }
    let mut command = Command::new(std::env::current_exe().map_err(|_| Error::Setup)?);
    command
        .arg("--worker")
        .arg(match observation {
            Observation::Status => "status",
            Observation::Diff => "diff",
        })
        .arg(probe.name());
    for fd in &fds {
        command.arg(fd.to_string());
    }
    command.arg(extra.unwrap_or(-1).to_string());
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("HOME", "/nonexistent")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut inherited = fds.clone();
    if let Some(fd) = extra {
        inherited.push(fd)
    }
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
            // Fixture: stdout's first reader is already blocked while the
            // observed Git image waits on a no-writer configuration FIFO.
            wait_for_git_image(worker.child.id())?;
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

#[repr(C)]
struct Ruleset {
    fs: u64,
    net: u64,
}
#[repr(C, packed)]
struct Beneath {
    access: u64,
    fd: i32,
}
fn ruleset(root: RawFd, runtime: &[RawFd]) -> Result<File> {
    let attr = Ruleset {
        fs: (1 << 15) - 1,
        net: 3,
    };
    let raw = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr,
            std::mem::size_of::<Ruleset>(),
            0,
        )
    } as i32;
    if raw < 0 {
        return Err(Error::Setup);
    }
    let rules = unsafe { File::from_raw_fd(raw) };
    let mut grants = vec![(root, (1 << 2) | (1 << 3))];
    for (i, &fd) in runtime.iter().enumerate() {
        grants.push((fd, (1 << 2) | if i <= 1 { 1 } else { 0 }));
    }
    // Git's explicit inert config/attributes path. Never grant other /dev nodes.
    let null = File::open("/dev/null").map_err(|_| Error::Setup)?;
    let m = null.metadata().map_err(|_| Error::Setup)?;
    if m.uid() != 0
        || m.mode() & libc::S_IFMT != libc::S_IFCHR
        || libc::major(m.rdev()) != 1
        || libc::minor(m.rdev()) != 3
    {
        return Err(Error::Runtime);
    }
    grants.push((null.as_raw_fd(), (1 << 2) | (1 << 1)));
    for (fd, access) in grants {
        let rule = Beneath { access, fd };
        if unsafe { libc::syscall(libc::SYS_landlock_add_rule, raw, 1, &rule, 0) } != 0 {
            return Err(Error::Setup);
        }
    }
    Ok(rules)
}
fn cstrings(values: &[&str]) -> Vec<CString> {
    values.iter().map(|v| CString::new(*v).unwrap()).collect()
}
fn worker(args: &[String]) -> Result<()> {
    abi()?;
    if args.len() != 11 {
        return Err(Error::Setup);
    }
    let observation = match args[1].as_str() {
        "status" => Observation::Status,
        "diff" => Observation::Diff,
        _ => return Err(Error::Setup),
    };
    let probe = Probe::parse(&args[2]).ok_or(Error::Setup)?;
    let fds: Vec<i32> = args[3..]
        .iter()
        .map(|s| s.parse().map_err(|_| Error::Setup))
        .collect::<Result<_>>()?;
    let root = fds[0];
    let git = fds[1];
    let extra = fds[7];
    let opened = runtime()?;
    for (i, file) in opened.iter().enumerate() {
        let duplicated = unsafe { libc::dup(fds[i + 1]) };
        if duplicated < 0 {
            return Err(Error::Setup);
        }
        let actual = unsafe { File::from_raw_fd(duplicated) };
        if identity(&actual)? != identity(file)? {
            return Err(Error::Runtime);
        }
    }
    let rules = ruleset(root, &fds[1..7])?;
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
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::syscall(libc::SYS_landlock_restrict_self, rules.as_raw_fd(), 0) != 0
            {
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
    } else if args.first().map(String::as_str) == Some("review-regressions") {
        return fixtures::review_regressions();
    } else if args.first().map(String::as_str) == Some("regression") {
        return fixtures::run();
    } else {
        eprintln!("usage: lomi-linux-git-spike regression (synthetic, unqualified)");
        return 2;
    };
    if result.is_ok() { 0 } else { 1 }
}
