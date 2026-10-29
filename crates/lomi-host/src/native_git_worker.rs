//! Private, bounded protocol for executing one approved native Git plan.
//!
//! This module is only dispatched by the Host's exact internal command-line
//! entry. It is not an RPC and accepts no executable name or command arguments.

use lomi_native_custody::Member;
use lomi_native_git::{
    ErrorCode,
    types::{NativeGitExecutionOutcome, NativeGitRequest},
};
#[cfg(target_os = "macos")]
use lomi_native_git::{NativeProjectDirectory, PreparedNativeGitPlan};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::{
    io::{self, Write},
    os::fd::RawFd,
    path::{Component, Path},
    time::{Duration, Instant},
};

pub(crate) const MAX_FRAME_BYTES: usize = 131_072;
const MAX_WORKER_BUDGET_MS: u32 = 120_000;
const MAX_CHECKS: u64 = 65_536;
#[cfg(target_os = "macos")]
const IO_CHUNK_BYTES: usize = 512;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WorkerInput {
    pub version: u8,
    pub operation_id: String,
    pub fence_id: String,
    pub request_hash: String,
    pub plan_hash: String,
    pub host_runtime_id: String,
    pub root: PathBuf,
    pub root_device: u64,
    pub root_inode: u64,
    pub controller: Member,
    pub request: NativeGitRequest,
    pub environment: Vec<(String, String)>,
    /// Remaining budget at dispatch. The worker anchors it once at startup.
    pub timeout_ms: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum WorkerFrame {
    Check {
        sequence: u64,
        before_execution: bool,
    },
    Complete {
        outcome: NativeGitExecutionOutcome,
    },
    Failed {
        code: ErrorCode,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum HostReply {
    Decision { sequence: u64, allowed: bool },
}

/// Read one little-endian length-prefixed JSON frame from a raw descriptor.
/// The deadline covers both the header and body and is never renewed.
#[cfg(target_os = "macos")]
pub(crate) fn read_frame<T: DeserializeOwned>(fd: RawFd, deadline: Instant) -> Result<T, String> {
    let mut header = [0u8; 4];
    read_exact_until(fd, &mut header, deadline)?;
    let length = u32::from_le_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err("invalid native Git frame".into());
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| "invalid native Git frame".to_owned())?;
    bytes.resize(length, 0);
    read_exact_until(fd, &mut bytes, deadline)?;
    serde_json::from_slice(&bytes).map_err(|_| "invalid native Git frame".into())
}

/// Write one little-endian length-prefixed JSON frame to a raw descriptor.
/// Serialization and I/O are bounded by `MAX_FRAME_BYTES` and `deadline`.
#[cfg(target_os = "macos")]
pub(crate) fn write_frame<T: Serialize>(
    fd: RawFd,
    value: &T,
    deadline: Instant,
) -> Result<(), String> {
    let mut writer = LimitedBuffer { bytes: Vec::new() };
    serde_json::to_writer(&mut writer, value).map_err(|_| "native Git frame write failed")?;
    let bytes = writer.bytes;
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err("native Git frame write failed".into());
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| "native Git frame write failed".to_owned())?
        .to_le_bytes();
    write_all_until(fd, &length, deadline)?;
    write_all_until(fd, &bytes, deadline)
}

#[cfg(target_os = "macos")]
struct LimitedBuffer {
    bytes: Vec<u8>,
}

#[cfg(target_os = "macos")]
impl Write for LimitedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|length| *length <= MAX_FRAME_BYTES)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;
        self.bytes
            .try_reserve(length - self.bytes.len())
            .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "frame allocation failed"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn wait_ready(fd: RawFd, events: i16, deadline: Instant) -> Result<(), String> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| "native Git frame deadline exceeded".to_owned())?;
        let millis = remaining
            .as_millis()
            .saturating_add(u128::from(remaining.subsec_nanos() % 1_000_000 != 0));
        let timeout = i32::try_from(millis.max(1).min(i32::MAX as u128))
            .map_err(|_| "native Git frame deadline exceeded".to_owned())?;
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if result > 0 {
            if descriptor.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err("native Git frame I/O failed".into());
            }
            if descriptor.revents & (events | libc::POLLHUP) != 0 {
                return Ok(());
            }
            continue;
        }
        if result == 0 {
            return Err("native Git frame deadline exceeded".into());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err("native Git frame I/O failed".into());
        }
    }
}

#[cfg(target_os = "macos")]
fn read_exact_until(fd: RawFd, mut bytes: &mut [u8], deadline: Instant) -> Result<(), String> {
    while !bytes.is_empty() {
        wait_ready(fd, libc::POLLIN, deadline)?;
        let count = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
        if count > 0 {
            let (_, remaining) = bytes.split_at_mut(count as usize);
            bytes = remaining;
            continue;
        }
        if count == 0 {
            return Err("native Git frame ended early".into());
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err("native Git frame I/O failed".into());
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn write_all_until(fd: RawFd, mut bytes: &[u8], deadline: Instant) -> Result<(), String> {
    while !bytes.is_empty() {
        wait_ready(fd, libc::POLLOUT, deadline)?;
        let chunk = bytes.len().min(IO_CHUNK_BYTES);
        let count = unsafe { libc::write(fd, bytes.as_ptr().cast(), chunk) };
        if count > 0 {
            bytes = &bytes[count as usize..];
            continue;
        }
        if count < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err("native Git frame I/O failed".into());
    }
    Ok(())
}

/// Dispatch target for the exact Host-only `--internal-native-git-plan` mode.
/// All errors remain typed frames or silent nonzero exits; no diagnostic text
/// includes request, environment, repository, or Git subprocess data.
pub(crate) fn entry() -> i32 {
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        return 1;
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        let startup = Instant::now();
        let startup_deadline = startup + Duration::from_millis(u64::from(MAX_WORKER_BUDGET_MS));
        // `member` performs the custody kernel's exact Darwin/ARM64 admission
        // before any private process-coalition query.
        let current = match lomi_native_custody::member(std::process::id()) {
            Ok(member) => member,
            Err(_) => return 1,
        };
        let input: WorkerInput = match read_frame(0, startup_deadline) {
            Ok(input) => input,
            Err(_) => return 1,
        };
        let deadline =
            startup + Duration::from_millis(u64::from(input.timeout_ms.min(MAX_WORKER_BUDGET_MS)));
        let result = execute_worker(input, &current, deadline);
        let frame = match result {
            Ok(outcome) => WorkerFrame::Complete { outcome },
            Err(code) => WorkerFrame::Failed { code },
        };
        if write_frame(1, &frame, deadline).is_err() {
            return 1;
        }
        if matches!(&frame, WorkerFrame::Failed { .. }) {
            1
        } else {
            0
        }
    }
}

#[cfg(target_os = "macos")]
fn execute_worker(
    input: WorkerInput,
    current: &Member,
    deadline: Instant,
) -> Result<NativeGitExecutionOutcome, ErrorCode> {
    validate_input(&input)?;
    verify_controller(&input.controller, current)?;
    PreparedNativeGitPlan::validate_request(&input.request)?;
    let environment =
        lomi_native_git::git_execution::Environment::from_unicode_pairs(&input.environment)?;

    let project = NativeProjectDirectory::open(&input.root)?;
    project.check()?;
    let root = project.open_directory("")?;
    use std::os::unix::fs::MetadataExt;
    let metadata = root.metadata().map_err(|_| ErrorCode::StorageUnavailable)?;
    if metadata.dev() != input.root_device || metadata.ino() != input.root_inode {
        return Err(ErrorCode::RevisionConflict);
    }

    let checks = std::sync::Arc::new(std::sync::Mutex::new(CheckProtocol {
        next_sequence: 1,
        emitted: 0,
        revoked: false,
        deadline,
    }));
    let progress_checks = std::sync::Arc::clone(&checks);
    let check = move || {
        progress_checks
            .lock()
            .map_err(|_| ErrorCode::ControlRevoked)?
            .check(false)
    };
    let before_execution_checks = std::sync::Arc::clone(&checks);
    let environment = environment.with_before_execution_authorizer(move || {
        before_execution_checks
            .lock()
            .map_err(|_| ErrorCode::ControlRevoked)?
            .check(true)
    });
    let plan = PreparedNativeGitPlan::prepare_with_environment(
        std::sync::Arc::new(project),
        input.request,
        environment,
        &check,
    )?;
    if plan.revision() != input.plan_hash {
        return Err(ErrorCode::RevisionConflict);
    }
    plan.execute(&input.plan_hash, &check)
}

#[cfg(target_os = "macos")]
struct CheckProtocol {
    next_sequence: u64,
    emitted: u64,
    revoked: bool,
    deadline: Instant,
}

#[cfg(target_os = "macos")]
impl CheckProtocol {
    fn check(&mut self, before_execution: bool) -> Result<(), ErrorCode> {
        if self.revoked {
            return Err(ErrorCode::ControlRevoked);
        }
        if Instant::now() >= self.deadline {
            self.revoked = true;
            return Err(ErrorCode::DeadlineExceeded);
        }
        if self.emitted >= MAX_CHECKS {
            self.revoked = true;
            return Err(ErrorCode::ResourceExhausted);
        }
        let sequence = self.next_sequence;
        let frame = WorkerFrame::Check {
            sequence,
            before_execution,
        };
        if write_frame(1, &frame, self.deadline).is_err() {
            self.revoked = true;
            return Err(ErrorCode::ControlRevoked);
        }
        let reply: HostReply = match read_frame(0, self.deadline) {
            Ok(reply) => reply,
            Err(_) => {
                self.revoked = true;
                return Err(ErrorCode::ControlRevoked);
            }
        };
        match reply {
            HostReply::Decision {
                sequence: received,
                allowed: true,
            } if received == sequence => {
                if Instant::now() >= self.deadline {
                    self.revoked = true;
                    return Err(ErrorCode::DeadlineExceeded);
                }
                self.emitted += 1;
                let Some(next_sequence) = sequence.checked_add(1) else {
                    self.revoked = true;
                    return Err(ErrorCode::ResourceExhausted);
                };
                self.next_sequence = next_sequence;
                Ok(())
            }
            HostReply::Decision { .. } => {
                self.revoked = true;
                Err(ErrorCode::ControlRevoked)
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn validate_input(input: &WorkerInput) -> Result<(), ErrorCode> {
    if input.version != 1
        || !valid_operation_id(&input.operation_id)
        || !valid_text(&input.fence_id, 200)
        || !valid_hash(&input.request_hash)
        || !valid_hash(&input.plan_hash)
        || !valid_text(&input.host_runtime_id, 200)
        || !strict_absolute_path(&input.root)
        || !(1..=MAX_WORKER_BUDGET_MS).contains(&input.timeout_ms)
    {
        return Err(ErrorCode::ScopeDenied);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_controller(controller: &Member, current: &Member) -> Result<(), ErrorCode> {
    let parent_pid = unsafe { libc::getppid() };
    if parent_pid <= 0
        || controller.identity.pid != parent_pid as u32
        || !controller.identity.still_matches().unwrap_or(false)
    {
        return Err(ErrorCode::ControlRevoked);
    }
    let observed = lomi_native_custody::member(controller.identity.pid)
        .map_err(|_| ErrorCode::ControlRevoked)?;
    let executable = std::env::current_exe().map_err(|_| ErrorCode::ControlRevoked)?;
    if &observed != controller
        || current.identity.boot != controller.identity.boot
        || current.resource_coalition != controller.resource_coalition
        || executable != controller.identity.executable
    {
        return Err(ErrorCode::ControlRevoked);
    }
    // `member` verifies the target audit token against this process's real and
    // effective UID, establishing the available same-user parent check.
    Ok(())
}

#[cfg(target_os = "macos")]
fn strict_absolute_path(path: &Path) -> bool {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().contains(&0)
        || path.as_os_str().len() > 4096
    {
        return false;
    }
    path.components()
        .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

#[cfg(target_os = "macos")]
fn valid_operation_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(target_os = "macos")]
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(target_os = "macos")]
fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}
