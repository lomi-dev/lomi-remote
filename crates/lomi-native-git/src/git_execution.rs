//! Native approval snapshots for code-executing Git. Nothing in this module is
//! exposed as a tool; the broker must first authorize git.execute and obtain an
//! exact Host approval decision before a prepared plan can be dispatched.
pub mod commit;
pub mod discard;
pub mod fetch;
pub mod pull;
pub mod push;
use crate::{
    ErrorCode, NativeProjectDirectory as ProjectDirectory,
    git_read::{self, Observation},
    validate_relative,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap, ffi::OsString, fs::File, io::Read, os::unix::fs::MetadataExt, sync::Arc,
};

#[derive(Clone)]
pub struct Environment(
    BTreeMap<OsString, OsString>,
    Option<Arc<dyn Fn() -> Result<(), ErrorCode> + Send + Sync>>,
);
impl Environment {
    /// Caller options can never supply executable names, environment or -c flags.
    pub fn capture() -> Self {
        let mut values: BTreeMap<_, _> = std::env::vars_os()
            .filter(|(name, _)| captured_key_allowed(&name.to_string_lossy()))
            .collect();
        for (key, value) in [
            ("LC_ALL", "C"),
            ("GIT_TERMINAL_PROMPT", "0"),
            ("GIT_NO_LAZY_FETCH", "1"),
            ("GIT_NO_REPLACE_OBJECTS", "1"),
        ] {
            values.insert(key.into(), value.into());
        }
        Self(values, None)
    }

    /// Return the exact bounded Unicode environment that can be transferred to
    /// an isolated native Git worker. Non-Unicode values are not serialized.
    pub fn to_unicode_pairs(&self) -> Result<Vec<(String, String)>, ErrorCode> {
        let mut pairs = Vec::with_capacity(self.0.len());
        for (key, value) in &self.0 {
            let key = key.to_str().ok_or(ErrorCode::ScopeDenied)?;
            let value = value.to_str().ok_or(ErrorCode::ScopeDenied)?;
            pairs.push((key.to_owned(), value.to_owned()));
        }
        validate_unicode_pairs(&pairs)?;
        Ok(pairs)
    }

    /// Rebuild an environment serialized by `to_unicode_pairs` while
    /// reapplying the same Git-variable allowlist and forced values.
    pub fn from_unicode_pairs(pairs: &[(String, String)]) -> Result<Self, ErrorCode> {
        validate_unicode_pairs(pairs)?;
        let mut values = BTreeMap::new();
        for (key, value) in pairs {
            if values
                .insert(OsString::from(key), OsString::from(value))
                .is_some()
            {
                return Err(ErrorCode::ScopeDenied);
            }
        }
        Ok(Self(values, None))
    }

    /// Require fresh Host authorization immediately before each mutating Git
    /// subprocess. The callback is execution control, not environment state,
    /// and is deliberately excluded from the plan fingerprint.
    pub fn with_before_execution_authorizer(
        mut self,
        authorizer: impl Fn() -> Result<(), ErrorCode> + Send + Sync + 'static,
    ) -> Self {
        self.1 = Some(Arc::new(authorizer));
        self
    }

    fn fingerprint(&self) -> String {
        let mut hash = Sha256::new();
        for (key, value) in &self.0 {
            for bytes in [key.as_encoded_bytes(), value.as_encoded_bytes()] {
                hash.update((bytes.len() as u64).to_le_bytes());
                hash.update(bytes);
            }
        }
        format!("{:x}", hash.finalize())
    }
}

const MAX_ENVIRONMENT_ENTRIES: usize = 64;
const MAX_ENVIRONMENT_BYTES: usize = 65_536;

fn captured_key_allowed(key: &str) -> bool {
    (!key.starts_with("GIT_")
        || matches!(
            key,
            "GIT_AUTHOR_NAME"
                | "GIT_AUTHOR_EMAIL"
                | "GIT_AUTHOR_DATE"
                | "GIT_COMMITTER_NAME"
                | "GIT_COMMITTER_EMAIL"
                | "GIT_COMMITTER_DATE"
                | "GIT_CONFIG_GLOBAL"
                | "GIT_CONFIG_SYSTEM"
                | "GIT_CONFIG_NOSYSTEM"
                | "GIT_SSH"
                | "GIT_SSH_COMMAND"
                | "GIT_SSH_VARIANT"
                | "GIT_ASKPASS"
                | "GIT_TERMINAL_PROMPT"
                | "GIT_NO_LAZY_FETCH"
                | "GIT_NO_REPLACE_OBJECTS"
        ))
        && !key.starts_with("DYLD_")
        && key != "LD_PRELOAD"
}

fn validate_unicode_pairs(pairs: &[(String, String)]) -> Result<(), ErrorCode> {
    if pairs.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err(ErrorCode::ResourceExhausted);
    }
    let forced = [
        ("LC_ALL", "C"),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_NO_LAZY_FETCH", "1"),
        ("GIT_NO_REPLACE_OBJECTS", "1"),
    ];
    let mut total_bytes = 0usize;
    let mut seen = std::collections::HashSet::with_capacity(pairs.len());
    for (key, value) in pairs {
        if key.is_empty()
            || key.contains(['=', '\0'])
            || value.contains('\0')
            || !captured_key_allowed(key)
            || !seen.insert(key.as_str())
        {
            return Err(ErrorCode::ScopeDenied);
        }
        total_bytes = total_bytes
            .checked_add(key.len())
            .and_then(|length| length.checked_add(value.len()))
            .ok_or(ErrorCode::ResourceExhausted)?;
        if total_bytes > MAX_ENVIRONMENT_BYTES {
            return Err(ErrorCode::ResourceExhausted);
        }
    }
    if forced.iter().any(|(key, value)| {
        pairs
            .iter()
            .find(|(present, _)| present == key)
            .is_none_or(|(_, present)| present != value)
    }) {
        return Err(ErrorCode::ScopeDenied);
    }
    Ok(())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileIdentity {
    pub relative_path: String,
    pub sha256: Option<String>,
    pub byte_length: u64,
    pub mode: u32,
    device: u64,
    inode: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub head: Option<String>,
    pub branch: Option<String>,
    pub index_revision: String,
    pub configuration_revision: String,
    pub references_revision: String,
    pub status_revision: String,
    pub files: Vec<FileIdentity>,
    repository_identity: (u64, u64),
    environment_revision: String,
}
impl Snapshot {
    pub fn revision(&self) -> Result<String, ErrorCode> {
        Ok(digest(
            &serde_json::to_vec(self).map_err(|_| ErrorCode::ResourceExhausted)?,
        ))
    }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn metadata_bytes(
    directory: &File,
    name: &str,
    check: &dyn Fn() -> Result<(), ErrorCode>,
) -> Result<String, ErrorCode> {
    use rustix::fs::{Mode, OFlags, openat};
    let mut file = match openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => File::from(fd),
        Err(rustix::io::Errno::NOENT) => return Ok(digest(b"missing")),
        Err(_) => return Err(ErrorCode::ScopeDenied),
    };
    let before = file.metadata().map_err(|_| ErrorCode::StorageUnavailable)?;
    if !before.is_file() || before.nlink() != 1 {
        return Err(ErrorCode::ScopeDenied);
    }
    if before.len() > 32 * 1024 * 1024 {
        return Err(ErrorCode::ResourceExhausted);
    }
    let mut hash = Sha256::new();
    hash.update(b"present");
    let mut total = 0;
    let mut bytes = [0; 65536];
    loop {
        check()?;
        let n = file
            .read(&mut bytes)
            .map_err(|_| ErrorCode::StorageUnavailable)?;
        if n == 0 {
            break;
        }
        total += n;
        if total > 32 * 1024 * 1024 {
            return Err(ErrorCode::ResourceExhausted);
        }
        hash.update(&bytes[..n]);
    }
    let after = file.metadata().map_err(|_| ErrorCode::StorageUnavailable)?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) {
        return Err(ErrorCode::RevisionConflict);
    }
    // Physical replacement also invalidates approval, even with identical bytes.
    for value in [
        after.dev(),
        after.ino(),
        after.len(),
        u64::from(after.mode()),
    ] {
        hash.update(value.to_le_bytes());
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn observe_file(
    project: &ProjectDirectory,
    repository: &str,
    relative: &str,
    check: &dyn Fn() -> Result<(), ErrorCode>,
) -> Result<FileIdentity, ErrorCode> {
    use rustix::fs::{AtFlags, FileType, statat};
    validate_relative(relative)?;
    let path = if repository.is_empty() {
        relative.to_string()
    } else {
        format!("{repository}/{relative}")
    };
    // Missing parent directories are a valid absent target. Existing components
    // are still opened individually without following links.
    let missing = || FileIdentity {
        relative_path: relative.into(),
        sha256: None,
        byte_length: 0,
        mode: 0,
        device: 0,
        inode: 0,
        modified: (0, 0),
        changed: (0, 0),
    };
    let (parent, name) = path.rsplit_once('/').unwrap_or(("", &path));
    let mut directory = project.open_directory("")?;
    if !parent.is_empty() {
        for component in parent.split('/') {
            use rustix::fs::{Mode, OFlags, openat};
            check()?;
            directory = match openat(
                &directory,
                component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => File::from(fd),
                Err(rustix::io::Errno::NOENT) => return Ok(missing()),
                Err(_) => return Err(ErrorCode::ScopeDenied),
            };
        }
    }
    let parent = directory;
    let metadata = match statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(m) => m,
        Err(rustix::io::Errno::NOENT) => return Ok(missing()),
        Err(_) => return Err(ErrorCode::ScopeDenied),
    };
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile || metadata.st_nlink != 1
    {
        return Err(ErrorCode::ScopeDenied);
    }
    use rustix::fs::{Mode, OFlags, openat};
    let mut file = File::from(
        openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ErrorCode::ScopeDenied)?,
    );
    let before = file.metadata().map_err(|_| ErrorCode::StorageUnavailable)?;
    if !before.is_file() || before.nlink() != 1 {
        return Err(ErrorCode::ScopeDenied);
    }
    if before.len() > 4 * 1024 * 1024 {
        return Err(ErrorCode::ResourceExhausted);
    }
    let mut hash = Sha256::new();
    let mut total = 0;
    let mut bytes = [0; 65536];
    loop {
        check()?;
        let count = file
            .read(&mut bytes)
            .map_err(|_| ErrorCode::StorageUnavailable)?;
        if count == 0 {
            break;
        }
        total += count;
        if total > 4 * 1024 * 1024 {
            return Err(ErrorCode::ResourceExhausted);
        }
        hash.update(&bytes[..count]);
    }
    let after = file.metadata().map_err(|_| ErrorCode::StorageUnavailable)?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) {
        return Err(ErrorCode::RevisionConflict);
    }
    project.check()?;
    Ok(FileIdentity {
        relative_path: relative.into(),
        sha256: Some(format!("{:x}", hash.finalize())),
        byte_length: after.len(),
        mode: after.mode(),
        device: after.dev(),
        inode: after.ino(),
        modified: (after.mtime(), after.mtime_nsec()),
        changed: (after.ctime(), after.ctime_nsec()),
    })
}
/// Snapshot effective configuration without executing configured helpers. Raw
/// values stay local and are replaced by a hash before returning the snapshot.
pub fn snapshot(
    project: &Arc<ProjectDirectory>,
    repository: &str,
    paths: &[String],
    environment: &Environment,
    check: &dyn Fn() -> Result<(), ErrorCode>,
) -> Result<Snapshot, ErrorCode> {
    crate::require_qualified()?;
    use rustix::fs::{Mode, OFlags, openat};
    if !repository.is_empty() {
        validate_relative(repository)?;
    }
    if paths.len() > 64 {
        return Err(ErrorCode::ResourceExhausted);
    }
    let mut sorted = paths.to_vec();
    sorted.sort();
    sorted.dedup();
    if sorted.len() != paths.len() {
        return Err(ErrorCode::RevisionConflict);
    }
    let executable = git_read::trusted_executable()?;
    if executable.is_empty() {
        return Err(ErrorCode::UnsupportedCapability);
    }
    let directory = project.open_directory(repository)?;
    let metadata = directory
        .metadata()
        .map_err(|_| ErrorCode::StorageUnavailable)?;
    let repo_id = (metadata.dev(), metadata.ino());
    let git_dir = File::from(
        openat(
            &directory,
            ".git",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ErrorCode::UnsupportedCapability)?,
    );
    let index_revision = metadata_bytes(&git_dir, "index", check)?;
    let head_bytes = metadata_bytes(&git_dir, "HEAD", check)?;
    let observe =
        |query| git_read::execution_preview(project, repository, query, &environment.0, check);
    let head = observe(Observation::Head)?;
    let head = std::str::from_utf8(&head)
        .map_err(|_| ErrorCode::UnsupportedCapability)?
        .trim();
    if !head.is_empty()
        && (!matches!(head.len(), 40 | 64) || !head.bytes().all(|c| c.is_ascii_hexdigit()))
    {
        return Err(ErrorCode::UnsupportedCapability);
    }
    let branch = observe(Observation::SymbolicHead)?;
    let branch = std::str::from_utf8(&branch)
        .map_err(|_| ErrorCode::UnsupportedCapability)?
        .trim();
    if !branch.is_empty()
        && (!branch.starts_with("refs/heads/")
            || branch.len() > 1024
            || branch.chars().any(char::is_control))
    {
        return Err(ErrorCode::UnsupportedCapability);
    }
    let configuration_revision = digest(&observe(Observation::Configuration)?);
    let references_revision = digest(&observe(Observation::References)?);
    let status_revision = digest(&observe(Observation::Status)?);
    let mut files = Vec::new();
    let mut bytes = 0;
    for path in sorted {
        let file = observe_file(project, repository, &path, check)?;
        bytes += file.byte_length;
        if bytes > 32 * 1024 * 1024 {
            return Err(ErrorCode::ResourceExhausted);
        }
        files.push(file);
    }
    if metadata_bytes(&git_dir, "index", check)? != index_revision
        || metadata_bytes(&git_dir, "HEAD", check)? != head_bytes
    {
        return Err(ErrorCode::RevisionConflict);
    }
    project.check()?;
    check()?;
    let current = project
        .open_directory(repository)?
        .metadata()
        .map_err(|_| ErrorCode::StorageUnavailable)?;
    if (current.dev(), current.ino()) != repo_id {
        return Err(ErrorCode::RevisionConflict);
    }
    Ok(Snapshot {
        head: (!head.is_empty()).then(|| head.into()),
        branch: (!branch.is_empty()).then(|| branch.into()),
        index_revision,
        configuration_revision,
        references_revision,
        status_revision,
        files,
        repository_identity: repo_id,
        environment_revision: environment.fingerprint(),
    })
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexOperation {
    Stage,
    Unstage,
}
/// Shared argument construction for human Source Control and the approved adapter.
/// This does not authorize or execute the returned arguments.
pub fn index_arguments(paths: &[String], stage: bool, has_head: bool) -> Vec<String> {
    let mut args: Vec<String> = if stage {
        vec!["--literal-pathspecs", "add", "--"]
    } else if has_head {
        vec!["--literal-pathspecs", "restore", "--staged", "--"]
    } else {
        vec!["--literal-pathspecs", "rm", "--cached", "--"]
    }
    .into_iter()
    .map(str::to_string)
    .collect();
    args.extend_from_slice(paths);
    args
}
pub struct IndexPlan {
    project: Arc<ProjectDirectory>,
    repository: String,
    operation: IndexOperation,
    paths: Vec<String>,
    environment: Environment,
    pub observation: Snapshot,
    pub revision: String,
}
impl IndexPlan {
    pub fn prepare(
        project: Arc<ProjectDirectory>,
        repository: String,
        operation: IndexOperation,
        paths: Vec<String>,
        environment: Environment,
        check: &dyn Fn() -> Result<(), ErrorCode>,
    ) -> Result<Self, ErrorCode> {
        crate::require_qualified()?;
        if paths.is_empty() {
            return Err(ErrorCode::ResourceExhausted);
        }
        let observation = snapshot(&project, &repository, &paths, &environment, check)?;
        let repeated = snapshot(&project, &repository, &paths, &environment, check)?;
        if observation != repeated {
            return Err(ErrorCode::RevisionConflict);
        }
        let revision = digest(
            &serde_json::to_vec(&(&repository, operation, &observation))
                .map_err(|_| ErrorCode::ResourceExhausted)?,
        );
        Ok(Self {
            project,
            repository,
            operation,
            paths,
            environment,
            observation,
            revision,
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessSettlement {
    /// The owned process boundary and inherited output pipes were observed
    /// closed. This does not prove trusted code did not escape that boundary.
    ObservedOwnedBoundaryClosed,
    /// Settlement was incomplete; the Host must retain its writer fence until
    /// its own recovery policy resolves the uncertain execution.
    Unproven,
}

#[derive(Debug)]
pub struct IndexOutcome {
    pub exit_code: Option<i32>,
    pub interrupted: Option<ErrorCode>,
    pub abandoned_descendants: bool,
    pub settlement: ProcessSettlement,
    pub after: Option<Snapshot>,
}
impl IndexOutcome {
    /// Whether the Host must keep its repository writer fence after this call.
    /// Unknown operation results require retention even when the child boundary
    /// drained. This observed boundary is not OS containment of trusted helpers.
    pub fn writer_fence_must_be_retained(&self) -> bool {
        let _observed_boundary = self.settlement;
        // The engine has no independent proof that trusted helpers or escaped
        // descendants have stopped writing. Boundary and pipe closure cannot
        // authorize retirement of the Host's repository writer fence.
        true
    }
}
/// Only call after the Host approves this exact revision while retaining its
/// physical repository writer lease. Before spawn, failure has
/// no mutating effect. After spawn, even a nonzero exit may have changed files.
/// The synchronous owner deliberately retains its child and caller's guard until
/// the process group has a confirmed exit; an unconfirmed kill is never forgotten.
pub fn execute_index(
    plan: IndexPlan,
    approved_revision: &str,
    check: &dyn Fn() -> Result<(), ErrorCode>,
) -> Result<IndexOutcome, ErrorCode> {
    crate::require_qualified()?;
    if plan.revision != approved_revision {
        return Err(ErrorCode::ControlRevoked);
    }
    let current = snapshot(
        &plan.project,
        &plan.repository,
        &plan.paths,
        &plan.environment,
        check,
    )?;
    if current != plan.observation {
        return Err(ErrorCode::RevisionConflict);
    }
    let args = index_arguments(
        &plan.paths,
        matches!(plan.operation, IndexOperation::Stage),
        current.head.is_some(),
    );
    let mut outcome = execute_process(
        &plan.project,
        &plan.repository,
        &plan.environment,
        &args,
        check,
    )?;
    if outcome.interrupted.is_none() {
        outcome.after = snapshot(
            &plan.project,
            &plan.repository,
            &plan.paths,
            &plan.environment,
            check,
        )
        .ok();
        if outcome.after.is_none() {
            outcome.interrupted = Some(ErrorCode::OutcomeUnknown);
        }
    }
    Ok(outcome)
}

// Sealed domain plans are the only callers; arguments never originate at IPC.
fn execute_process(
    project: &ProjectDirectory,
    repository: &str,
    environment: &Environment,
    args: &[String],
    check: &dyn Fn() -> Result<(), ErrorCode>,
) -> Result<IndexOutcome, ErrorCode> {
    execute_process_captured(project, repository, environment, args, false, check)
        .map(|(outcome, _)| outcome)
}

// Captured bytes are bounded and remain native; only a domain-specific parser
// may convert them into a receipt. stderr is never returned.
fn execute_process_captured(
    project: &ProjectDirectory,
    repository: &str,
    environment: &Environment,
    args: &[String],
    capture: bool,
    check: &dyn Fn() -> Result<(), ErrorCode>,
) -> Result<(IndexOutcome, Vec<u8>), ErrorCode> {
    use std::{
        io,
        os::{fd::AsRawFd, unix::process::CommandExt},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let program = git_read::trusted_executable()?;
    let directory = project.open_directory(repository)?;
    let directory_metadata = directory.metadata().map_err(|_| ErrorCode::ScopeDenied)?;
    let directory_identity = (directory_metadata.dev(), directory_metadata.ino());
    let mut command = Command::new(program);
    command
        .args(["--no-pager", "--git-dir=.git", "--work-tree=."])
        .args(args)
        .env_clear()
        .envs(&environment.0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            if libc::fchdir(directory.as_raw_fd()) == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }
    check()?;
    project.check()?;
    if let Some(authorize) = &environment.1 {
        authorize()?;
    }
    // Authorization may block on the Host/client exchange. Recheck the
    // physical root and repository after that exchange, while retaining the
    // originally admitted descriptor used by fchdir below. A replaced nested
    // repository must not redirect or detach the approved mutation.
    project.check()?;
    let current_directory = project.open_directory(repository)?;
    let current_metadata = current_directory
        .metadata()
        .map_err(|_| ErrorCode::ScopeDenied)?;
    if (current_metadata.dev(), current_metadata.ino()) != directory_identity {
        return Err(ErrorCode::ScopeDenied);
    }
    let mut child = crate::process_tree::Tree::spawn(&mut command)
        .map_err(|_| ErrorCode::UnsupportedCapability)?;
    let (Some(mut stdout), Some(mut stderr)) =
        (child.child.stdout.take(), child.child.stderr.take())
    else {
        // A started process is never a before-effect error. Retain ownership
        // even if a future platform implementation fails to provide its pipes.
        loop {
            let _ = child.kill();
            if let Ok(Some(status)) = child.try_wait() {
                return Ok((
                    IndexOutcome {
                        exit_code: status.code(),
                        interrupted: Some(ErrorCode::OutcomeUnknown),
                        abandoned_descendants: child.abandoned_descendants,
                        settlement: ProcessSettlement::Unproven,
                        after: None,
                    },
                    Vec::new(),
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut interrupted = None;
    for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
            interrupted = Some(ErrorCode::OutcomeUnknown);
        }
    }
    let mut captured = Vec::new();
    let mut output = 0;
    let mut errors = 0;
    let mut out_done = false;
    let mut err_done = false;
    let mut exited = None;
    let mut exit_seen = None;
    loop {
        if interrupted.is_none() {
            interrupted = check().err();
        }
        if Instant::now() >= deadline {
            interrupted.get_or_insert(ErrorCode::DeadlineExceeded);
        }
        if interrupted.is_some() {
            let _ = child.kill();
        }
        if exited.is_none() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    exited = Some(status);
                    exit_seen = Some(Instant::now());
                }
                Ok(None) => {}
                Err(_) => {
                    interrupted.get_or_insert(ErrorCode::OutcomeUnknown);
                }
            }
        }
        if child.abandoned_descendants {
            interrupted.get_or_insert(ErrorCode::OutcomeUnknown);
        }
        if interrupted.is_some() {
            if exited.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        for (stream, total, done, limit, keep) in [
            (
                &mut stdout as &mut dyn Read,
                &mut output,
                &mut out_done,
                2 * 1024 * 1024,
                capture,
            ),
            (
                &mut stderr as &mut dyn Read,
                &mut errors,
                &mut err_done,
                16 * 1024,
                false,
            ),
        ] {
            if *done {
                continue;
            }
            let mut bytes = [0; 8192];
            // Yield between bounded batches even if a hook continuously writes.
            for _ in 0..8 {
                match stream.read(&mut bytes) {
                    Ok(0) => {
                        *done = true;
                        break;
                    }
                    Ok(n) => {
                        *total += n;
                        if *total > limit {
                            interrupted.get_or_insert(ErrorCode::ResourceExhausted);
                            break;
                        }
                        if keep {
                            captured.extend_from_slice(&bytes[..n]);
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        interrupted.get_or_insert(ErrorCode::OutcomeUnknown);
                        break;
                    }
                }
            }
        }
        if exited.is_some() && out_done && err_done {
            break;
        }
        if exit_seen.is_some_and(|at: Instant| at.elapsed() > Duration::from_millis(100)) {
            // Detached trusted code can escape a process group; never wait on
            // an inherited pipe forever or claim a fully observed completion.
            interrupted.get_or_insert(ErrorCode::OutcomeUnknown);
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let settlement = if interrupted.is_none()
        && exited.is_some()
        && out_done
        && err_done
        && !child.abandoned_descendants
    {
        ProcessSettlement::ObservedOwnedBoundaryClosed
    } else {
        ProcessSettlement::Unproven
    };
    Ok((
        IndexOutcome {
            exit_code: exited.and_then(|s| s.code()),
            interrupted,
            abandoned_descendants: child.abandoned_descendants,
            settlement,
            after: None,
        },
        captured,
    ))
}
