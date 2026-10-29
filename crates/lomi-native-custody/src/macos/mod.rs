//! Host-pinned native execution boundary for the exact qualified Darwin ABI.
//! A sealed, previously validated coalition's ESRCH is the only retirement
//! receipt. Stream EOF, task counters and PID-list emptiness are not receipts.

use crate::{
    Identity, Member, NativeIo, NativeSpec, Policy, PreviousBootReceipt, Purpose, RetiredReceipt,
    Scope, Transport,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

mod crypto;
mod kernel;
mod pty;
mod registry;
mod sandbox;
pub use kernel::member;
pub use registry::{EffectGuard, EffectScope, registered_scope};

const MAX_RECORD: u64 = 65536;
const MAX_SPEC: usize = 2 * 1024 * 1024;
const WAIT: Duration = Duration::from_secs(30);
const WORKER_FLAG: &str = "--internal-native-custody-worker";
const NATIVE_FLAG: &str = "--internal-native-custody-child";

fn failure() -> String {
    "The native host boundary cannot prove ownership or retirement.".into()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Intent,
    Held,
    ReleaseIntent,
    Released,
    Sealed,
    Retired,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    schema: u32,
    #[serde(default)]
    release_attempted: bool,
    scope: Scope,
    host: kernel::HostWitness,
    label: String,
    domain: String,
    worker: PathBuf,
    worker_digest: String,
    spec_digest: String,
    phase: Phase,
    held: Option<Member>,
    seal_confirmed: bool,
    #[serde(default)]
    native_exit: Option<i32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Held {
    schema: u32,
    operation_id: String,
    spec_digest: String,
    member: Member,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Release {
    operation_id: String,
    spec_digest: String,
}

/// Durable custody lifecycle for one native host process tree.
///
/// A NativeGit Host must keep one boundary over the full prepared plan.
/// Coalition retirement proves process retirement, not plan completion.
pub struct Boundary {
    root: PathBuf,
    record: Record,
    _lock: fs::File,
    transport: Option<Transport>,
    effects: std::sync::Arc<EffectScope>,
    resize_lock: std::sync::Mutex<()>,
}

struct OwnedCommand {
    child: std::process::Child,
    reaped: bool,
}
impl std::ops::Deref for OwnedCommand {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.child
    }
}
impl std::ops::DerefMut for OwnedCommand {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.child
    }
}
impl OwnedCommand {
    fn new(child: std::process::Child) -> Self {
        Self {
            child,
            reaped: false,
        }
    }
    fn stop_and_wait(&mut self) -> Result<std::process::ExitStatus, String> {
        let _ = self.child.kill();
        let status = self.child.wait().map_err(|_| failure())?;
        self.reaped = true;
        Ok(status)
    }
}
impl Drop for OwnedCommand {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

pub(super) fn validate_policy(policy: &Policy) -> Result<(), String> {
    policy.validate()
}

fn private_directory(path: &Path) -> Result<(), String> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| failure())?;
    lomi_platform::unix::reject_acl_grants_readonly(&file).map_err(|_| failure())?;
    let opened = file.metadata().map_err(|_| failure())?;
    let current = fs::symlink_metadata(path).map_err(|_| failure())?;
    if !opened.is_dir()
        || current.file_type().is_symlink()
        || opened.dev() != current.dev()
        || opened.ino() != current.ino()
        || opened.uid() != unsafe { libc::geteuid() }
        || opened.mode() & 0o077 != 0
    {
        return Err(failure());
    }
    Ok(())
}
fn private_file(path: &Path) -> Result<fs::File, String> {
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| failure())?;
    let m = f.metadata().map_err(|_| failure())?;
    lomi_platform::unix::reject_acl_grants_readonly(&f).map_err(|_| failure())?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
        || m.len() > MAX_RECORD
    {
        return Err(failure());
    }
    Ok(f)
}
fn lock_owner(root: &Path) -> Result<fs::File, String> {
    use std::os::fd::AsRawFd;

    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root.join("owner.lock"))
        .map_err(|_| failure())?;
    lomi_platform::unix::reject_acl_grants_readonly(&lock).map_err(|_| failure())?;
    let metadata = lock.metadata().map_err(|_| failure())?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
    {
        return Err(failure());
    }
    Ok(lock)
}
fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let mut bytes = Vec::new();
    private_file(path)?
        .take(MAX_RECORD + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| failure())?;
    if bytes.len() > MAX_RECORD as usize {
        return Err(failure());
    }
    serde_json::from_slice(&bytes).map_err(|_| failure())
}
fn verify_record_binding(
    root: &Path,
    record: &Record,
    expected_scope: &Scope,
    expected_spec: &NativeSpec,
    uid: u32,
) -> Result<(), String> {
    if !root.is_absolute()
        || root.canonicalize().map_err(|_| failure())? != root
        || root.file_name().and_then(|name| name.to_str())
            != Some(expected_scope.operation_id.as_str())
        || !matches!(&expected_scope.purpose, Purpose::NativeGit)
        || !matches!(&expected_spec.policy.mode, crate::PolicyMode::NativeGit(_))
    {
        return Err(failure());
    }
    expected_scope.validate(expected_spec, root.parent().ok_or_else(failure)?)?;
    let expected_scope_bytes = serde_json::to_vec(expected_scope).map_err(|_| failure())?;
    let recorded_scope_bytes = serde_json::to_vec(&record.scope).map_err(|_| failure())?;
    let expected_spec_bytes = serde_json::to_vec(expected_spec).map_err(|_| failure())?;
    let expected_label = format!("dev.lomi.agent.host.{}", expected_scope.operation_id);
    let expected_domain = format!("gui/{uid}");
    if !matches!(record.schema, 1 | 2)
        || record.schema == 1 && record.release_attempted
        || recorded_scope_bytes != expected_scope_bytes
        || record.spec_digest != digest(&expected_spec_bytes)
        || !crate::valid_hash(Some(&record.spec_digest))
        || record.label != expected_label
        || record.domain != expected_domain
        || !record.worker.is_absolute()
        || !crate::valid_hash(Some(&record.worker_digest))
        || record.host.boot.is_empty()
    {
        return Err(failure());
    }
    Ok(())
}
fn previous_boot_held(root: &Path, record: &Record) -> Result<Held, String> {
    let held: Held = read_json(&root.join("held.json"))?;
    if held.schema != 1
        || held.operation_id != record.scope.operation_id
        || held.spec_digest != record.spec_digest
        || record
            .held
            .as_ref()
            .is_some_and(|recorded| recorded != &held.member)
        || held.member.identity.pid == 0
        || held.member.identity.boot != record.host.boot
        || held.member.identity.executable != record.worker
        || held.member.resource_coalition <= 1
    {
        return Err(failure());
    }
    Ok(held)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| failure())?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|_| failure())?;
    fs::File::open(path.parent().ok_or_else(failure)?)
        .and_then(|f| f.sync_all())
        .map_err(|_| failure())
}
fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|_| failure())?;
    if bytes.len() > MAX_RECORD as usize {
        return Err(failure());
    }
    write_new(path, &bytes)
}
fn update(root: &Path, record: &Record) -> Result<(), String> {
    let path = root.join(format!("record-{}.tmp", crate::new_id()?));
    write_json(&path, record)?;
    fs::rename(path, root.join("record.json")).map_err(|_| failure())?;
    fs::File::open(root)
        .and_then(|f| f.sync_all())
        .map_err(|_| failure())
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn binary_digest(path: &Path) -> Result<String, String> {
    let admitted = crate::process_identity::executable_identity(path)?;
    let mut f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&admitted.0)
        .map_err(|_| failure())?;
    if f.metadata().map_err(|_| failure())?.len() > 1024 * 1024 * 1024 {
        return Err(failure());
    }
    let mut h = crypto::Hasher::new()?;
    let mut b = [0u8; 65536];
    loop {
        let n = f.read(&mut b).map_err(|_| failure())?;
        if n == 0 {
            break;
        }
        h.update(&b[..n])?;
    }
    if crate::process_identity::executable_identity(path)? != admitted {
        return Err(failure());
    }
    h.finish()
}
pub fn staged_worker(storage_root: &Path) -> Result<PathBuf, String> {
    private_directory(storage_root)?;
    stage_worker()
}
fn stage_worker() -> Result<PathBuf, String> {
    let source = std::env::current_exe()
        .map_err(|_| failure())?
        .canonicalize()
        .map_err(|_| failure())?;
    let expected = binary_digest(&source)?;
    let base = PathBuf::from(format!("/private/tmp/lomi-host-workers-{}", unsafe {
        libc::geteuid()
    }));
    match fs::DirBuilder::new().mode(0o700).create(&base) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(failure()),
    }
    private_directory(&base)?;
    let published = base.join(&expected);
    let worker = published.join("worker");
    let verify = || -> Result<(), String> {
        private_directory(&published)?;
        let metadata = fs::symlink_metadata(&worker).map_err(|_| failure())?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o277 != 0
            || metadata.nlink() != 1
            || binary_digest(&worker)? != expected
        {
            return Err(failure());
        }
        Ok(())
    };
    if published.try_exists().map_err(|_| failure())? {
        verify()?;
        return Ok(worker);
    }
    let staging = base.join(format!("staging-{}", crate::new_id()?));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&staging)
        .map_err(|_| failure())?;
    let target_path = staging.join("worker");
    let mut source_file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&source)
        .map_err(|_| failure())?;
    let mut target = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&target_path)
        .map_err(|_| failure())?;
    std::io::copy(&mut source_file, &mut target).map_err(|_| failure())?;
    target.sync_all().map_err(|_| failure())?;
    fs::File::open(&staging)
        .and_then(|f| f.sync_all())
        .map_err(|_| failure())?;
    if binary_digest(&source)? != expected || binary_digest(&target_path)? != expected {
        return Err(failure());
    }
    match fs::rename(&staging, &published) {
        Ok(()) => {}
        Err(_) if published.try_exists().map_err(|_| failure())? => {
            verify()?;
            fs::remove_dir_all(&staging).map_err(|_| failure())?;
        }
        Err(_) => return Err(failure()),
    }
    fs::File::open(&base)
        .and_then(|f| f.sync_all())
        .map_err(|_| failure())?;
    verify()?;
    Ok(worker)
}
fn fifo(root: &Path, name: &str, read: bool, write: bool) -> Result<fs::File, String> {
    use std::os::unix::ffi::OsStrExt;
    let path = root.join(name);
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| failure())?;
    if unsafe { libc::mkfifo(c.as_ptr(), 0o600) } != 0 {
        return Err(failure());
    }
    open_fifo(&path, read, write)
}
fn open_fifo(path: &Path, read: bool, write: bool) -> Result<fs::File, String> {
    let f = fs::OpenOptions::new()
        .read(read)
        .write(write)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| failure())?;
    let m = f.metadata().map_err(|_| failure())?;
    if m.mode() & u32::from(libc::S_IFMT) != u32::from(libc::S_IFIFO)
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
    {
        return Err(failure());
    }
    Ok(f)
}

fn native_stdio(file: &fs::File) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) } != 0 {
        return Err(failure());
    }
    Ok(())
}

fn write_stream(file: &mut fs::File, bytes: &[u8]) -> Result<(), String> {
    let deadline = Instant::now() + WAIT;
    let mut at = 0;
    while at < bytes.len() {
        match file.write(&bytes[at..]) {
            Ok(0) => return Err(failure()),
            Ok(n) => at += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(_) => return Err(failure()),
        }
        if Instant::now() > deadline {
            return Err(failure());
        }
    }
    Ok(())
}
fn read_stream(file: &mut fs::File, len: usize) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + WAIT;
    let mut bytes = vec![0; len];
    let mut at = 0;
    while at < len {
        match file.read(&mut bytes[at..]) {
            Ok(0) => std::thread::sleep(Duration::from_millis(5)),
            Ok(n) => at += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(_) => return Err(failure()),
        }
        if Instant::now() > deadline {
            return Err(failure());
        }
    }
    Ok(bytes)
}
fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
fn job_plist(label: &str, worker: &Path, root: &Path) -> String {
    let mut plist = format!(
        "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>Label</key><string>{}</string><key>RunAtLoad</key><true/><key>KeepAlive</key><false/><key>ProcessType</key><string>Background</string><key>ProgramArguments</key><array>",
        xml(label)
    );
    for argument in [
        worker.to_string_lossy().into_owned(),
        WORKER_FLAG.to_owned(),
        root.to_string_lossy().into_owned(),
    ] {
        plist.push_str(&format!("<string>{}</string>", xml(&argument)));
    }
    plist.push_str("</array></dict></plist>");
    plist
}
fn verify_job_plist(root: &Path, record: &Record) -> Result<(), String> {
    let mut bytes = Vec::new();
    private_file(&root.join("job.plist"))?
        .take(MAX_RECORD + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| failure())?;
    let expected = job_plist(&record.label, &record.worker, root);
    if bytes.len() > MAX_RECORD as usize || bytes != expected.as_bytes() {
        return Err(failure());
    }
    Ok(())
}
fn launchctl(args: &[&str]) -> Result<i32, String> {
    use std::process::{Command, Stdio};
    let child = Command::new("/bin/launchctl")
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| failure())?;
    let mut child = OwnedCommand::new(child);
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(status) = child.try_wait().map_err(|_| failure())? {
            return Ok(status.code().unwrap_or(-1));
        }
        if Instant::now() > deadline {
            let _ = child.stop_and_wait();
            return Err(failure());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn drain_launchctl_pipe(
    pipe: &mut impl Read,
    bytes: &mut Vec<u8>,
    other_len: usize,
) -> Result<bool, String> {
    loop {
        let mut chunk = [0; 4096];
        match pipe.read(&mut chunk) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                if bytes.len() + other_len + count > MAX_RECORD as usize {
                    return Err(failure());
                }
                bytes.extend_from_slice(&chunk[..count]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(failure()),
        }
    }
}
fn launchctl_capture(args: &[&str]) -> Result<(i32, Vec<u8>, Vec<u8>), String> {
    use std::os::fd::AsRawFd;

    let child = std::process::Command::new("/bin/launchctl")
        .args(args)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|_| failure())?;
    let mut child = OwnedCommand::new(child);
    let mut stdout = child.stdout.take().ok_or_else(failure)?;
    let mut stderr = child.stderr.take().ok_or_else(failure)?;
    for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(failure());
        }
    }
    let deadline = Instant::now() + WAIT;
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    let mut status = None;
    loop {
        if !stdout_eof {
            stdout_eof = drain_launchctl_pipe(&mut stdout, &mut stdout_bytes, stderr_bytes.len())?;
        }
        if !stderr_eof {
            stderr_eof = drain_launchctl_pipe(&mut stderr, &mut stderr_bytes, stdout_bytes.len())?;
        }
        if status.is_none() {
            status = child.try_wait().map_err(|_| failure())?;
        }
        if stdout_eof && stderr_eof {
            if let Some(status) = status {
                return Ok((status.code().unwrap_or(-1), stdout_bytes, stderr_bytes));
            }
        }
        if Instant::now() >= deadline {
            let _ = child.stop_and_wait();
            return Err(failure());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn verify_launchd_job_absent(domain: &str, label: &str, uid: u32) -> Result<String, String> {
    if launchctl(&["print", domain])? != 0 {
        return Err(failure());
    }

    let job = format!("{domain}/{label}");
    let (code, stdout, stderr) = launchctl_capture(&["print", &job])?;
    let expected = format!("Could not find service \"{label}\" in domain for user gui: {uid}");
    let stderr = String::from_utf8(stderr).map_err(|_| failure())?;
    let lines: Vec<_> = stderr
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if code != 113
        || !stdout.is_empty()
        || !(lines.as_slice() == [expected.as_str()]
            || lines.as_slice() == ["Bad request.", expected.as_str()])
    {
        return Err(failure());
    }
    Ok(job)
}
fn job_status(job: &str) -> Result<String, String> {
    use std::os::fd::AsRawFd;
    let child = std::process::Command::new("/bin/launchctl")
        .args(["print", job])
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|_| failure())?;
    let mut child = OwnedCommand::new(child);
    let mut output = child.stdout.take().ok_or_else(failure)?;
    let flags = unsafe { libc::fcntl(output.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(output.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(failure());
    }
    let deadline = Instant::now() + WAIT;
    let mut bytes = Vec::new();
    let mut status = None;
    loop {
        let mut chunk = [0; 4096];
        match output.read(&mut chunk) {
            Ok(0) if status.is_some() => break,
            Ok(n) => {
                bytes.extend_from_slice(&chunk[..n]);
                if bytes.len() > MAX_RECORD as usize {
                    let _ = child.stop_and_wait();
                    return Err(failure());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return Err(failure()),
        }
        if status.is_none() {
            status = child.try_wait().map_err(|_| failure())?;
        }
        if Instant::now() >= deadline {
            let _ = child.stop_and_wait();
            return Err(failure());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    if !status.ok_or_else(failure)?.success() {
        return Err(failure());
    }
    String::from_utf8(bytes).map_err(|_| failure())
}
fn parse_job_exit(text: &str) -> Result<Option<i32>, String> {
    let field = |name: &str| -> Result<Option<&str>, String> {
        let prefix = format!("{name} = ");
        let mut values = text
            .lines()
            .filter(|line| !line.starts_with("\t\t"))
            .filter_map(|line| line.trim().strip_prefix(&prefix));
        let value = values.next();
        if values.next().is_some() {
            return Err(failure());
        }
        Ok(value)
    };
    if field("state")? == Some("running") {
        return Ok(None);
    }
    if field("runs")? != Some("1") {
        return Ok(None);
    }
    match field("last exit code")? {
        Some(value) => match value.parse::<i32>() {
            Ok(code) if (0..=255).contains(&code) => Ok(Some(code)),
            _ => Err(failure()),
        },
        None => Ok(None),
    }
}
pub fn retire_previous_boot(
    root: &Path,
    expected_scope: &Scope,
    expected_spec: &NativeSpec,
) -> Result<Option<PreviousBootReceipt>, String> {
    // Admit only the currently qualified Darwin ABI before inspecting any
    // durable record or invoking launchctl.
    let current_host = kernel::HostWitness::admitted()?;
    private_directory(root)?;
    if !root.is_absolute() || root.canonicalize().map_err(|_| failure())? != root {
        return Err(failure());
    }
    let _owner_lock = lock_owner(root)?;
    let record: Record = read_json(&root.join("record.json"))?;
    let uid = unsafe { libc::getuid() };
    verify_record_binding(root, &record, expected_scope, expected_spec, uid)?;

    if record.host.boot == current_host.boot {
        return Ok(None);
    }
    if record.schema != 2 || record.host.boot.is_empty() {
        return Err(failure());
    }

    // The recorded coalition belongs to the old kernel and can be reused by
    // the current kernel. Validate its durable old-boot identity, but never
    // query or signal that coalition in this boot.
    let held = previous_boot_held(root, &record)?;
    verify_job_plist(root, &record)?;
    let sealed_job = verify_launchd_job_absent(&record.domain, &record.label, uid)?;
    Ok(Some(PreviousBootReceipt {
        operation_id: record.scope.operation_id,
        old_boot: record.host.boot,
        resource_coalition: held.member.resource_coalition,
        sealed_job,
        release_attempted: record.release_attempted,
    }))
}
impl Boundary {
    pub fn create(base: &Path, scope: Scope, spec: NativeSpec) -> Result<Self, String> {
        private_directory(base)?;
        kernel::HostWitness::admitted()?;
        scope.validate(&spec, base)?;
        spec.validate()
            .map_err(|error| format!("Native specification validation failed: {error}"))?;
        let root = base.join(&scope.operation_id);
        fs::create_dir(&root).map_err(|_| failure())?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(|_| failure())?;
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("owner.lock"))
            .map_err(|_| failure())?;
        if unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&lock),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } != 0
        {
            return Err(failure());
        }
        let worker = stage_worker()?;
        let record = Record {
            schema: 2,
            release_attempted: false,
            scope,
            host: kernel::HostWitness::admitted()?,
            label: String::new(),
            domain: format!("gui/{}", unsafe { libc::getuid() }),
            worker_digest: binary_digest(&worker)?,
            worker,
            spec_digest: digest(&serde_json::to_vec(&spec).map_err(|_| failure())?),
            phase: Phase::Intent,
            held: None,
            seal_confirmed: false,
            native_exit: None,
        };
        let mut result = Self {
            root,
            record,
            _lock: lock,
            transport: None,
            effects: EffectScope::new(),
            resize_lock: std::sync::Mutex::new(()),
        };
        result.record.label = format!("dev.lomi.agent.host.{}", result.record.scope.operation_id);
        write_json(&result.root.join("record.json"), &result.record)?;
        let stdin = fifo(&result.root, "stdin", true, true)?;
        let stdout = fifo(&result.root, "stdout", true, false)?;
        let stderr = fifo(&result.root, "stderr", true, false)?;
        let mut config = fifo(&result.root, "config", true, true)?;
        if matches!(spec.io, NativeIo::Pty { .. }) {
            drop(fifo(&result.root, "resize", true, true)?);
            drop(fifo(&result.root, "resize-ack", true, true)?);
        }
        result.transport = Some(Transport {
            stdin,
            stdout,
            stderr,
        });
        let plist = job_plist(&result.record.label, &result.record.worker, &result.root);
        write_new(&result.root.join("job.plist"), plist.as_bytes())?;
        if launchctl(&[
            "bootstrap",
            &result.record.domain,
            result.root.join("job.plist").to_str().ok_or_else(failure)?,
        ])? != 0
        {
            return Err(failure());
        }
        let mut bytes = serde_json::to_vec(&spec).map_err(|_| failure())?;
        if bytes.len() > MAX_SPEC {
            return Err(failure());
        }
        write_stream(&mut config, &(bytes.len() as u32).to_le_bytes())?;
        let sent = write_stream(&mut config, &bytes);
        bytes.fill(0);
        sent?;
        let deadline = Instant::now() + WAIT;
        let held: Held = loop {
            match read_json(&result.root.join("held.json")) {
                Ok(held) => break held,
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
                Err(_) => {
                    return Err(failure());
                }
            }
        };
        if held.schema != 1
            || held.operation_id != result.record.scope.operation_id
            || held.spec_digest != result.record.spec_digest
        {
            return Err(failure());
        }
        let observed = kernel::member(held.member.identity.pid)?;
        let own = kernel::member(std::process::id())?;
        if observed != held.member
            || observed.identity.executable != result.record.worker
            || observed.resource_coalition <= 1
            || observed.resource_coalition == own.resource_coalition
            || kernel::usage(observed.resource_coalition)? != kernel::Usage::Alive
        {
            return Err(failure());
        }
        result.record.held = Some(observed);
        result.record.phase = Phase::Held;
        update(&result.root, &result.record)?;
        Ok(result)
    }

    pub fn release_with_gate(
        &mut self,
        before_release: impl FnOnce(&Boundary) -> Result<(), String>,
    ) -> Result<(), String> {
        self.ensure_boot()?;
        if self.record.phase != Phase::Held {
            return Err(failure());
        }
        if self.record.schema == 1 {
            // Upgrade legacy Held records before capture. Schema 1 never
            // carried a durable, monotonic release-attempt bit and therefore
            // cannot support a later NoStart proof.
            self.record.schema = 2;
            self.record.release_attempted = false;
            update(&self.root, &self.record)?;
        }
        if self.record.schema != 2 || self.record.release_attempted {
            return Err(failure());
        }
        let held = self.record.held.as_ref().ok_or_else(failure)?;
        if kernel::member(held.identity.pid)? != *held
            || binary_digest(&self.record.worker)? != self.record.worker_digest
        {
            return Err(failure());
        }
        before_release(self)?;
        // This synced monotonic marker is written before the child can be
        // granted execution. Its absence is meaningful only for schema 2.
        self.record.release_attempted = true;
        update(&self.root, &self.record)?;
        self.record.phase = Phase::ReleaseIntent;
        update(&self.root, &self.record)?;
        self.record.phase = Phase::Released;
        update(&self.root, &self.record)?;
        registry::register(
            &self.record.scope,
            self.record.held.as_ref().ok_or_else(failure)?,
            &self.effects,
        )?;
        self.effects.release()?;
        // Native admission is the last publication, after durable ownership and
        // host-effect registration. A failed publication stays recovery-held.
        write_json(
            &self.root.join("release.json"),
            &Release {
                operation_id: self.record.scope.operation_id.clone(),
                spec_digest: self.record.spec_digest.clone(),
            },
        )
    }
    fn ensure_boot(&self) -> Result<(), String> {
        if self.record.host != kernel::HostWitness::admitted()? {
            return Err(failure());
        }
        Ok(())
    }
    pub fn take_transport(&mut self) -> Result<Transport, String> {
        self.transport.take().ok_or_else(failure)
    }
    pub fn stop(&mut self) -> Result<RetiredReceipt, String> {
        self.retire_using(kernel::enumerate)
    }
    fn retire_using(
        &mut self,
        discover: impl Fn() -> Result<Vec<u32>, String>,
    ) -> Result<RetiredReceipt, String> {
        self.ensure_boot()?;
        self.effects.cancel();
        self.recover_held()?;
        let cid = self
            .record
            .held
            .as_ref()
            .ok_or_else(failure)?
            .resource_coalition;
        if cid <= 1 {
            return Err(failure());
        }
        let job = format!("{}/{}", self.record.domain, self.record.label);
        if !self.record.seal_confirmed {
            let code = launchctl(&["bootout", &job])?;
            // A prior successful durable bootout can be retried. Never infer a
            // first seal from unknown launchctl failures or an absent PID.
            if code != 0 {
                return Err(failure());
            }
            self.record.seal_confirmed = true;
            self.record.phase = Phase::Sealed;
            update(&self.root, &self.record)?;
        }
        let deadline = Instant::now() + WAIT;
        loop {
            match kernel::usage(cid)? {
                kernel::Usage::Retired => {
                    self.effects.cancel_and_wait(WAIT)?;
                    self.record.phase = Phase::Retired;
                    update(&self.root, &self.record)?;
                    self.effects.release_resources()?;
                    return Ok(RetiredReceipt {
                        operation_id: self.record.scope.operation_id.clone(),
                        boot: self.record.host.boot.clone(),
                        resource_coalition: cid,
                        sealed_job: job,
                    });
                }
                kernel::Usage::Alive => {}
            }
            for pid in discover()? {
                let member = match kernel::member(pid) {
                    Ok(member) => member,
                    Err(_) if kernel::gone(pid) => continue,
                    Err(error) => return Err(error),
                };
                if member.resource_coalition == cid {
                    kernel::signal_member(&member, cid)?;
                }
            }
            if Instant::now() > deadline {
                return Err(failure());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    pub fn restore(root: &Path) -> Result<Self, String> {
        kernel::HostWitness::admitted()?;
        private_directory(root)?;
        let record: Record = read_json(&root.join("record.json"))?;
        if !matches!(record.schema, 1 | 2)
            || record.schema == 1 && record.release_attempted
            || record.host != kernel::HostWitness::admitted()?
            || root.file_name().and_then(|s| s.to_str()) != Some(record.scope.operation_id.as_str())
            || record.label != format!("dev.lomi.agent.host.{}", record.scope.operation_id)
            || record.domain != format!("gui/{}", unsafe { libc::getuid() })
        {
            return Err(failure());
        }
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(root.join("owner.lock"))
            .map_err(|_| failure())?;
        let m = lock.metadata().map_err(|_| failure())?;
        if !m.is_file()
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o077 != 0
            || m.nlink() != 1
            || unsafe {
                libc::flock(
                    std::os::fd::AsRawFd::as_raw_fd(&lock),
                    libc::LOCK_EX | libc::LOCK_NB,
                )
            } != 0
        {
            return Err(failure());
        }
        let effects = registry::retained_effects(&record.scope)?.unwrap_or_else(EffectScope::new);
        Ok(Self {
            root: root.into(),
            record,
            _lock: lock,
            transport: None,
            effects,
            resize_lock: std::sync::Mutex::new(()),
        })
    }
    pub fn resize(&self, rows: u16, cols: u16) -> Result<(), String> {
        self.ensure_boot()?;
        if rows == 0 || cols == 0 || self.record.phase != Phase::Released {
            return Err(failure());
        }
        let _lock = self.resize_lock.lock().map_err(|_| failure())?;
        let mut ack = open_fifo(&self.root.join("resize-ack"), true, true)?;
        let mut channel = open_fifo(&self.root.join("resize"), false, true)?;
        let bytes = [rows.to_le_bytes(), cols.to_le_bytes()].concat();
        write_stream(&mut channel, &bytes)?;
        if read_stream(&mut ack, 4)? != bytes {
            return Err(failure());
        }
        Ok(())
    }
    pub fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>, String> {
        use std::os::unix::process::ExitStatusExt;
        self.ensure_boot()?;
        if let Some(code) = self.record.native_exit {
            return Ok(Some(std::process::ExitStatus::from_raw(code << 8)));
        }
        if self.record.phase != Phase::Released {
            return Err(failure());
        }
        let held = self.record.held.as_ref().ok_or_else(failure)?;
        match kernel::member(held.identity.pid) {
            Ok(current) if current == *held => return Ok(None),
            Ok(_) => {}
            Err(_) => {}
        }
        let job = format!("{}/{}", self.record.domain, self.record.label);
        let text = job_status(&job)?;

        if let Some(code) = parse_job_exit(&text)? {
            self.record.native_exit = Some(code);
            update(&self.root, &self.record)?;
            return Ok(Some(std::process::ExitStatus::from_raw(code << 8)));
        }
        Ok(None)
    }
    pub fn retain_retirement_resource<T: Send + Sync + 'static>(
        &self,
        resource: std::sync::Arc<T>,
    ) -> Result<(), String> {
        self.ensure_boot()?;
        if self.record.phase != Phase::Held {
            return Err(failure());
        }
        let held = self.record.held.as_ref().ok_or_else(failure)?;
        if kernel::member(held.identity.pid)? != *held {
            return Err(failure());
        }
        // Register while admission is still closed so a failed release can
        // restore the same scope and retained resources after its adapter drops.
        registry::register(&self.record.scope, held, &self.effects)?;
        self.effects.retain_resource(resource)
    }
    pub fn effects(&self) -> std::sync::Arc<EffectScope> {
        self.effects.clone()
    }
    pub fn identity(&self) -> Result<&Identity, String> {
        Ok(&self.record.held.as_ref().ok_or_else(failure)?.identity)
    }
    pub fn signal(&self, signal: i32) -> Result<(), String> {
        self.ensure_boot()?;
        let expected = self.record.held.as_ref().ok_or_else(failure)?;
        if ![libc::SIGKILL, libc::SIGTERM, libc::SIGINT].contains(&signal) {
            return Err(failure());
        }
        for pid in kernel::enumerate()? {
            if pid == expected.identity.pid {
                continue;
            }
            let member = match kernel::member(pid) {
                Ok(member) => member,
                Err(_) if kernel::gone(pid) => continue,
                Err(error) => return Err(error),
            };
            if member.resource_coalition == expected.resource_coalition {
                kernel::signal_member_with(&member, expected.resource_coalition, signal)?;
            }
        }
        Ok(())
    }
    fn recover_held(&mut self) -> Result<(), String> {
        if self.record.held.is_some() {
            return Ok(());
        }
        let held: Held = read_json(&self.root.join("held.json"))?;
        if held.schema != 1
            || held.operation_id != self.record.scope.operation_id
            || held.spec_digest != self.record.spec_digest
        {
            return Err(failure());
        }
        let observed = kernel::member(held.member.identity.pid)?;
        let own = kernel::member(std::process::id())?;
        if observed != held.member
            || observed.resource_coalition == own.resource_coalition
            || observed.identity.executable != self.record.worker
            || binary_digest(&self.record.worker)? != self.record.worker_digest
        {
            return Err(failure());
        }
        self.record.held = Some(observed);
        self.record.phase = Phase::Held;
        update(&self.root, &self.record)
    }
}
impl Drop for Boundary {
    fn drop(&mut self) {
        self.effects.cancel();
    }
}
pub fn entry() -> Option<i32> {
    let args: Vec<_> = std::env::args_os().collect();
    let flag = args.get(1)?.to_str()?;
    if flag != WORKER_FLAG && flag != NATIVE_FLAG {
        return None;
    }
    if kernel::HostWitness::admitted().is_err() {
        return Some(2);
    }
    if args.len() != 3 {
        return Some(2);
    }
    Some(
        if flag == NATIVE_FLAG {
            native_runner(Path::new(&args[2]))
        } else {
            worker(Path::new(&args[2]))
        }
        .unwrap_or(2),
    )
}
fn native_runner(root: &Path) -> Result<i32, String> {
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::process::CommandExt,
    };
    unsafe {
        libc::umask(0o077);
    }
    private_directory(root)?;
    let record: Record = read_json(&root.join("record.json"))?;
    if record.schema != 2
        || !record.release_attempted
        || record.phase != Phase::Released
        || record.host != kernel::HostWitness::admitted()?
    {
        return Err(failure());
    }
    let own = kernel::member(std::process::id())?;
    if own.resource_coalition != record.held.as_ref().ok_or_else(failure)?.resource_coalition
        || own.identity.executable != record.worker
        || binary_digest(&record.worker)? != record.worker_digest
    {
        return Err(failure());
    }
    let mut config = unsafe { fs::File::from_raw_fd(3) };
    let flags = unsafe { libc::fcntl(config.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(config.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(failure());
    }
    let length = u32::from_le_bytes(
        read_stream(&mut config, 4)?
            .try_into()
            .map_err(|_| failure())?,
    ) as usize;
    if length > MAX_SPEC {
        return Err(failure());
    }
    let mut bytes = read_stream(&mut config, length)?;
    if digest(&bytes) != record.spec_digest {
        bytes.fill(0);
        return Err(failure());
    }
    let parsed = serde_json::from_slice::<NativeSpec>(&bytes);
    bytes.fill(0);
    drop(config);
    let spec = parsed.map_err(|_| failure())?;
    spec.validate()?;
    if spec.policy.project_root != record.scope.project_root
        || record
            .scope
            .physical_account_root
            .as_ref()
            .is_some_and(|r| spec.policy.account_root.as_ref() != Some(r))
    {
        return Err(failure());
    }
    let terminal = if matches!(spec.io, NativeIo::Pty { .. }) {
        let mut path = [0i8; 128];
        if unsafe { libc::ttyname_r(0, path.as_mut_ptr(), path.len()) } != 0 {
            return Err(failure());
        }
        Some(PathBuf::from(
            unsafe { std::ffi::CStr::from_ptr(path.as_ptr()) }
                .to_str()
                .map_err(|_| failure())?,
        ))
    } else {
        None
    };
    // The fresh runner applies the sandbox without forking. No Rust allocator,
    // filesystem validation or sandbox library runs inside a pre_exec callback.
    spec.policy.apply_terminal(root, terminal.as_deref())?;
    for fd in 3..unsafe { libc::getdtablesize() } {
        unsafe {
            libc::close(fd);
        }
    }
    let mut command = std::process::Command::new(&spec.program);
    command
        .args(spec.arguments)
        .env_clear()
        .envs(spec.environment)
        .current_dir(spec.cwd);
    Err(format!(
        "Native execution was refused inside its sandbox: {}",
        command.exec().kind()
    ))
}

impl Boundary {
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn verify_binding(
        &self,
        expected_scope: &Scope,
        expected_spec: &NativeSpec,
    ) -> Result<(), String> {
        let current_host = kernel::HostWitness::admitted()?;
        private_directory(&self.root)?;
        let persisted: Record = read_json(&self.root.join("record.json"))?;
        if serde_json::to_vec(&persisted).map_err(|_| failure())?
            != serde_json::to_vec(&self.record).map_err(|_| failure())?
            || persisted.host != current_host
        {
            return Err(failure());
        }
        verify_record_binding(
            &self.root,
            &persisted,
            expected_scope,
            expected_spec,
            unsafe { libc::getuid() },
        )?;
        verify_job_plist(&self.root, &persisted)?;
        if binary_digest(&persisted.worker)? != persisted.worker_digest {
            return Err(failure());
        }
        previous_boot_held(&self.root, &persisted)?;
        Ok(())
    }
    pub fn scope(&self) -> &Scope {
        &self.record.scope
    }
    pub fn member(&self) -> Result<&Member, String> {
        self.record.held.as_ref().ok_or_else(failure)
    }
    pub fn release_attempted(&self) -> bool {
        self.record.release_attempted
    }
    pub fn is_released(&self) -> bool {
        self.record.phase == Phase::Released
    }
}
fn worker(root: &Path) -> Result<i32, String> {
    unsafe {
        libc::umask(0o077);
    }

    use std::os::unix::process::CommandExt;
    private_directory(root)?;
    let record: Record = read_json(&root.join("record.json"))?;
    if record.schema != 2
        || record.release_attempted
        || record.phase != Phase::Intent
        || record.host != kernel::HostWitness::admitted()?
    {
        return Err(failure());
    }

    let observed_digest = binary_digest(&std::env::current_exe().map_err(|_| failure())?)?;

    if observed_digest != record.worker_digest {
        return Err(failure());
    }

    let mut config = open_fifo(&root.join("config"), true, false)?;
    let size = read_stream(&mut config, 4)?;
    let len = u32::from_le_bytes(size.try_into().map_err(|_| failure())?) as usize;
    if len > MAX_SPEC {
        return Err(failure());
    }
    let mut bytes = read_stream(&mut config, len)?;
    if digest(&bytes) != record.spec_digest {
        bytes.fill(0);
        return Err(failure());
    }
    let parsed = serde_json::from_slice::<NativeSpec>(&bytes);
    bytes.fill(0);
    let spec = parsed.map_err(|_| failure())?;
    spec.validate()?;
    drop(config);

    let stdin = open_fifo(&root.join("stdin"), true, false)?;
    let stdout = open_fifo(&root.join("stdout"), false, true)?;
    let stderr = open_fifo(&root.join("stderr"), false, true)?;
    // Bootstrap and parent transport polling need nonblocking opens, but native
    // stdio must backpressure writers rather than lose output with EAGAIN.
    // These worker opens have separate file descriptions from parent readers.
    for file in [&stdin, &stdout, &stderr] {
        native_stdio(file)?;
    }

    let terminal = match spec.io {
        NativeIo::Pipes => None,
        NativeIo::Pty { rows, cols } => Some(pty::Pty::create(root, rows, cols)?),
    };
    let member = kernel::member(std::process::id())?;
    let coalition = member.resource_coalition;
    write_json(
        &root.join("held.json"),
        &Held {
            schema: 1,
            operation_id: record.scope.operation_id.clone(),
            spec_digest: record.spec_digest.clone(),
            member,
        },
    )?;
    let deadline = Instant::now() + WAIT;
    loop {
        if let Ok(release) = read_json::<Release>(&root.join("release.json")) {
            let latest: Record = read_json(&root.join("record.json"))?;
            if latest.schema != 2
                || !latest.release_attempted
                || !matches!(latest.phase, Phase::ReleaseIntent | Phase::Released)
                || release.operation_id != record.scope.operation_id
                || release.spec_digest != record.spec_digest
            {
                return Err(failure());
            }
            break;
        }
        if Instant::now() > deadline {
            return Err(failure());
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    let mut descriptors = [-1; 2];
    if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
        return Err(failure());
    }
    use std::os::fd::{AsRawFd, FromRawFd};
    let control = unsafe { fs::File::from_raw_fd(descriptors[0]) };
    let mut control_writer = unsafe { fs::File::from_raw_fd(descriptors[1]) };
    for file in [&control, &control_writer] {
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(failure());
        }
    }
    let mut command = std::process::Command::new(&record.worker);
    command
        .args([std::ffi::OsStr::new(NATIVE_FLAG), root.as_os_str()])
        .env_clear();

    command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(terminal) = &terminal {
        command
            .stdin(terminal.slave.try_clone().map_err(|_| failure())?)
            .stdout(terminal.slave.try_clone().map_err(|_| failure())?)
            .stderr(terminal.slave.try_clone().map_err(|_| failure())?);
    }
    let control_fd = control.as_raw_fd();
    let use_terminal = terminal.is_some();
    unsafe {
        command.pre_exec(move || {
            kernel::inherited_coalition(coalition)?;
            if use_terminal && (libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY.into(), 0) < 0)
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::dup2(control_fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }

            let max = libc::getdtablesize();

            let first = 4;
            for fd in first..max {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags >= 0 && libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|error| {
        format!(
            "Native spawn failed inside the held boundary: {}",
            error.kind()
        )
    })?;
    drop(command);
    drop(control);
    let mut bytes = serde_json::to_vec(&spec).map_err(|_| failure())?;
    let flags = unsafe { libc::fcntl(control_writer.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe {
            libc::fcntl(
                control_writer.as_raw_fd(),
                libc::F_SETFL,
                flags | libc::O_NONBLOCK,
            )
        } < 0
    {
        return Err(failure());
    }
    write_stream(&mut control_writer, &(bytes.len() as u32).to_le_bytes())?;
    let sent = write_stream(&mut control_writer, &bytes);
    bytes.fill(0);
    sent?;
    drop(control_writer);

    let status = if let Some(terminal) = terminal {
        drop(stderr);
        let output = terminal.relay(stdin, stdout)?;
        let status = child.wait().map_err(|_| failure())?;
        output.join().map_err(|_| failure())??;
        status
    } else {
        let mut child_stdin = child.stdin.take().ok_or_else(failure)?;
        let mut child_stdout = child.stdout.take().ok_or_else(failure)?;
        let mut child_stderr = child.stderr.take().ok_or_else(failure)?;
        std::thread::spawn(move || std::io::copy(&mut { stdin }, &mut child_stdin));
        let output = std::thread::spawn(move || std::io::copy(&mut child_stdout, &mut { stdout }));
        let errors = std::thread::spawn(move || std::io::copy(&mut child_stderr, &mut { stderr }));
        let status = child.wait().map_err(|_| failure())?;
        output
            .join()
            .map_err(|_| failure())?
            .map_err(|_| failure())?;
        errors
            .join()
            .map_err(|_| failure())?
            .map_err(|_| failure())?;
        status
    };
    use std::os::unix::process::ExitStatusExt;

    Ok(status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)))
}
