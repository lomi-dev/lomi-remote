//! Owner-local filesystem effects used by the desktop Explorer.
//!
//! These operations preserve local desktop capabilities, including recursive
//! copies and deletion, without expanding the remote v1 or MCP file contract.
//! The Host owns execution, admission, cancellation and durable receipts. An
//! uncertain call is recovered by operation ID; callers must never replay it.

use crate::LocalNativeFileCheckPhase;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

pub const MAX_DESKTOP_CONTROL_ROOTS: usize = 8;
pub const DESKTOP_DUPLICATE_LIMIT: usize = 10_000;

/// Canonical legacy Explorer naming for a newly duplicated file or directory.
/// Both the publisher and receipt consumer use this function.
pub fn desktop_duplicate_name(
    original: &str,
    is_directory: bool,
    number: usize,
) -> Result<String, DesktopFileErrorCode> {
    if number == 0 || number > DESKTOP_DUPLICATE_LIMIT {
        return Err(DesktopFileErrorCode::Limit);
    }
    let path = Path::new(original);
    if original.is_empty()
        || original.contains(['/', '\0'])
        || path.file_name() != Some(std::ffi::OsStr::new(original))
    {
        return Err(DesktopFileErrorCode::Invalid);
    }
    let (stem, extension) = if is_directory {
        (original, None)
    } else {
        (
            path.file_stem()
                .and_then(|value| value.to_str())
                .ok_or(DesktopFileErrorCode::Invalid)?,
            path.extension().and_then(|value| value.to_str()),
        )
    };
    let suffix = if number == 1 {
        " copy".to_owned()
    } else {
        format!(" copy {number}")
    };
    Ok(format!(
        "{stem}{suffix}{}",
        extension
            .map(|value| format!(".{value}"))
            .unwrap_or_default()
    ))
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DesktopMutationRequest {
    pub version: u8,
    pub operation_id: String,
    pub root: PathBuf,
    pub relative_path: String,
    pub expected_path: Option<PathBuf>,
    /// Additional restriction-only roots supplied by the trusted desktop.
    /// The Host always adds its own profile independently.
    pub control_roots: Vec<PathBuf>,
    pub operation: DesktopFileOperation,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum DesktopFileOperation {
    NewFile {
        name: String,
    },
    NewFolder {
        name: String,
    },
    Rename {
        name: String,
    },
    Copy {
        source_root: PathBuf,
        source: String,
    },
    Move {
        source_root: PathBuf,
        source: String,
    },
    Duplicate,
    Trash,
    Delete,
    /// Owner-local Git actions are interpreted by the Host's Git service.
    /// They are never dispatched as generic filesystem mutations.
    GitDiscard {
        context: lomi_remote_protocol::WorkspaceContext,
        repository_relative: String,
        expected: DesktopGitChange,
    },
    GitIgnore {
        context: lomi_remote_protocol::WorkspaceContext,
        repository_relative: String,
        local: bool,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DesktopGitChange {
    pub path: String,
    pub original_path: Option<String>,
    pub index: char,
    pub worktree: char,
}

impl DesktopFileOperation {
    pub fn git_context(&self) -> Option<&lomi_remote_protocol::WorkspaceContext> {
        match self {
            Self::GitDiscard { context, .. } | Self::GitIgnore { context, .. } => Some(context),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopFileKind {
    File,
    Directory,
    Symlink,
    Other,
}

/// Decimal strings preserve Windows' full 128-bit file identifier in JSON.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DesktopFileIdentity {
    pub volume: String,
    pub file_id: String,
}

/// A Host-captured, no-follow identity and kind for one selected desktop
/// source. This is an in-process precondition, not request or wire data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesktopSourcePrecondition {
    pub identity: DesktopFileIdentity,
    pub kind: DesktopFileKind,
}

/// A durable directory identity for owner-coordinated workspace relocation.
/// Creation time supplements the filesystem ID after the original process's
/// descriptors have been lost. An unavailable creation time is not a recovery
/// certificate; the live pinned handle can still be used during one operation.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DesktopDirectoryWitness {
    pub identity: DesktopFileIdentity,
    pub created_unix_ns: Option<String>,
}

impl DesktopDirectoryWitness {
    pub fn is_valid(&self) -> bool {
        self.identity.is_valid()
            && self.created_unix_ns.as_ref().is_none_or(|value| {
                value.len() <= 40
                    && value
                        .parse::<i128>()
                        .is_ok_and(|time| time.to_string() == *value)
            })
    }
}

/// One no-follow directory descriptor kept through a namespace transaction.
/// This read-only capability is not a remote file or workspace API.
pub struct DesktopDirectoryPin {
    path: PathBuf,
    file: std::fs::File,
    witness: DesktopDirectoryWitness,
}

impl DesktopDirectoryPin {
    pub fn open(path: &Path) -> Result<Self, DesktopFileErrorCode> {
        if !valid_absolute(path) {
            return Err(DesktopFileErrorCode::Invalid);
        }
        let (file, identity) = open_namespace_directory(path)?;
        let metadata = file.metadata().map_err(|_| DesktopFileErrorCode::Io)?;
        if !metadata.is_dir() {
            return Err(DesktopFileErrorCode::Changed);
        }
        let witness = DesktopDirectoryWitness {
            identity,
            created_unix_ns: directory_creation_time(&metadata),
        };
        Ok(Self {
            path: path.to_path_buf(),
            file,
            witness,
        })
    }

    pub fn witness(&self) -> &DesktopDirectoryWitness {
        &self.witness
    }

    pub fn verify_named(&self) -> Result<(), DesktopFileErrorCode> {
        self.verify_at(&self.path)
    }

    /// Verify a proposed relocated name against the still-held original
    /// directory. No absence observation or path prefix can satisfy this.
    pub fn verify_at(&self, path: &Path) -> Result<(), DesktopFileErrorCode> {
        let held = self.file.metadata().map_err(|_| DesktopFileErrorCode::Io)?;
        if !held.is_dir() || directory_creation_time(&held) != self.witness.created_unix_ns {
            return Err(DesktopFileErrorCode::Changed);
        }
        let current = Self::open(path)?;
        if current.witness != self.witness {
            return Err(DesktopFileErrorCode::Changed);
        }
        Ok(())
    }

    /// Look up one exact child name through this pin's held directory handle.
    /// The returned identity is captured without following a leaf symlink.
    /// This operation does not grant access to arbitrary paths or expose the
    /// underlying descriptor to callers.
    pub fn exact_child(
        &self,
        name: &std::ffi::OsStr,
        check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
    ) -> Result<Option<DesktopSourcePrecondition>, DesktopFileErrorCode> {
        let component = Path::new(name);
        if name.is_empty()
            || component.file_name() != Some(name)
            || component
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(DesktopFileErrorCode::Invalid);
        }
        check()?;
        let held = self.file.metadata().map_err(|_| DesktopFileErrorCode::Io)?;
        if !held.is_dir() {
            return Err(DesktopFileErrorCode::Changed);
        }
        #[cfg(unix)]
        {
            crate::unix::desktop::namespace_exact_child(&self.file, name, check)
        }
        #[cfg(windows)]
        {
            crate::windows::desktop::namespace_exact_child(&self.file, name, check)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (name, check);
            Err(DesktopFileErrorCode::Unsupported)
        }
    }
}

/// Positive post-restart verification only. Callers must independently prove
/// old-worker retirement and match this witness to the durable operation.
pub fn verify_desktop_directory_witness(
    path: &Path,
    expected: &DesktopDirectoryWitness,
) -> Result<(), DesktopFileErrorCode> {
    if !expected.is_valid() {
        return Err(DesktopFileErrorCode::Invalid);
    }
    if expected.created_unix_ns.is_none() {
        return Err(DesktopFileErrorCode::Unsupported);
    }
    let current = DesktopDirectoryPin::open(path)?;
    if current.witness != *expected {
        return Err(DesktopFileErrorCode::Changed);
    }
    Ok(())
}

fn directory_creation_time(metadata: &std::fs::Metadata) -> Option<String> {
    let created = metadata.created().ok()?;
    let nanos = match created.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => i128::try_from(duration.as_nanos()).ok()?,
        Err(error) => i128::try_from(error.duration().as_nanos())
            .ok()?
            .checked_neg()?,
    };
    Some(nanos.to_string())
}

fn open_namespace_directory(
    path: &Path,
) -> Result<(std::fs::File, DesktopFileIdentity), DesktopFileErrorCode> {
    #[cfg(unix)]
    {
        crate::unix::desktop::pin_namespace_directory(path)
    }
    #[cfg(windows)]
    {
        crate::windows::desktop::pin_namespace_directory(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(DesktopFileErrorCode::Unsupported)
    }
}

impl DesktopFileIdentity {
    pub fn is_valid(&self) -> bool {
        self.volume
            .parse::<u64>()
            .is_ok_and(|value| value.to_string() == self.volume)
            && self
                .file_id
                .parse::<u128>()
                .is_ok_and(|value| value.to_string() == self.file_id)
    }
}

/// A same-volume private staging entry awaiting transfer to the system Trash.
/// A ticket is evidence to validate, never permission to follow its pathname.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DesktopTrashTicket {
    pub version: u8,
    pub operation_id: String,
    pub root: PathBuf,
    pub original_path: PathBuf,
    pub staging_directory: PathBuf,
    pub staged_path: PathBuf,
    pub root_identity: DesktopFileIdentity,
    pub parent_identity: DesktopFileIdentity,
    pub staging_identity: DesktopFileIdentity,
    pub entry_identity: DesktopFileIdentity,
    pub kind: DesktopFileKind,
}

impl DesktopTrashTicket {
    pub fn validate_shape(&self) -> Result<(), DesktopFileErrorCode> {
        validate_desktop_root(&self.root)?;
        let leaf = self
            .original_path
            .file_name()
            .ok_or(DesktopFileErrorCode::Invalid)?;
        let parent = self
            .original_path
            .parent()
            .ok_or(DesktopFileErrorCode::Invalid)?;
        let expected_staging = parent.join(desktop_staging_name(&self.operation_id)?);
        if self.version != 1
            || !valid_absolute(&self.root)
            || !valid_absolute(&self.original_path)
            || self.original_path == self.root
            || !self.original_path.starts_with(&self.root)
            || self.staging_directory != expected_staging
            || self.staged_path != expected_staging.join(leaf)
            || !self.root_identity.is_valid()
            || !self.parent_identity.is_valid()
            || !self.staging_identity.is_valid()
            || !self.entry_identity.is_valid()
        {
            return Err(DesktopFileErrorCode::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DesktopFileChange {
    pub operation_id: String,
    pub old_path: Option<PathBuf>,
    pub new_path: Option<PathBuf>,
    pub trash: Option<DesktopTrashTicket>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DesktopFileErrorCode {
    NotFound,
    Changed,
    Protected,
    Exists,
    NotEmpty,
    Invalid,
    Unsupported,
    Limit,
    Io,
    Revoked,
    DeadlineExceeded,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "code", rename_all = "camelCase")]
pub enum DesktopMutationError {
    Before(DesktopFileErrorCode),
    /// At least one public namespace effect may have occurred. The joined
    /// worker still owns cleanup; a client must query the durable Host result.
    Uncertain,
}

impl From<DesktopFileErrorCode> for DesktopMutationError {
    fn from(value: DesktopFileErrorCode) -> Self {
        Self::Before(value)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DesktopTrashError<E> {
    Before(DesktopFileErrorCode),
    Transfer(E),
    Uncertain,
}

pub fn desktop_staging_name(operation_id: &str) -> Result<String, DesktopFileErrorCode> {
    let id = uuid::Uuid::parse_str(operation_id).map_err(|_| DesktopFileErrorCode::Invalid)?;
    if id.is_nil() {
        return Err(DesktopFileErrorCode::Invalid);
    }
    Ok(format!(".lomi-desktop-{}.tmp", id.simple()))
}

/// Pure contract validation. Platform implementations additionally pin every
/// root and ancestor and validate identities, source state and protected paths.
pub fn validate_desktop_request(
    request: &DesktopMutationRequest,
) -> Result<(), DesktopFileErrorCode> {
    desktop_staging_name(&request.operation_id)?;
    validate_desktop_root(&request.root)?;
    if request.version != 1
        || !valid_absolute(&request.root)
        || request.control_roots.len() > MAX_DESKTOP_CONTROL_ROOTS
        || request
            .control_roots
            .iter()
            .any(|path| !valid_absolute(path))
        || request
            .expected_path
            .as_ref()
            .is_some_and(|path| !valid_absolute(path))
    {
        return Err(DesktopFileErrorCode::Invalid);
    }
    validate_desktop_relative(&request.relative_path, true)?;
    if request.operation.git_context().is_some()
        && request.expected_path.as_deref()
            != Some(request.root.join(&request.relative_path).as_path())
    {
        return Err(DesktopFileErrorCode::Invalid);
    }
    match &request.operation {
        DesktopFileOperation::NewFile { name }
        | DesktopFileOperation::NewFolder { name }
        | DesktopFileOperation::Rename { name } => validate_desktop_name(name)?,
        DesktopFileOperation::Copy {
            source_root,
            source,
        }
        | DesktopFileOperation::Move {
            source_root,
            source,
        } => {
            validate_desktop_root(source_root)?;
            validate_desktop_relative(source, false)?;
        }
        DesktopFileOperation::GitDiscard {
            repository_relative,
            expected,
            ..
        } => {
            validate_desktop_relative(repository_relative, true)?;
            validate_desktop_relative(&expected.path, false)?;
            if let Some(original) = &expected.original_path {
                validate_desktop_relative(original, false)?;
            }
            let valid_status = |value| {
                matches!(
                    value,
                    ' ' | '?' | 'M' | 'D' | 'T' | 'A' | 'R' | 'C' | 'U' | '!'
                )
            };
            if !valid_status(expected.index)
                || !valid_status(expected.worktree)
                || Path::new(repository_relative).join(&expected.path)
                    != Path::new(&request.relative_path)
            {
                return Err(DesktopFileErrorCode::Invalid);
            }
        }
        DesktopFileOperation::GitIgnore {
            repository_relative,
            ..
        } => {
            validate_desktop_relative(repository_relative, true)?;
            let selected = Path::new(&request.relative_path)
                .strip_prefix(repository_relative)
                .map_err(|_| DesktopFileErrorCode::Invalid)?;
            validate_desktop_relative(
                selected.to_str().ok_or(DesktopFileErrorCode::Invalid)?,
                false,
            )?;
        }
        _ => {}
    }
    if Path::new(&request.relative_path)
        .components()
        .all(|part| matches!(part, Component::CurDir))
        && matches!(
            request.operation,
            DesktopFileOperation::Rename { .. }
                | DesktopFileOperation::Duplicate
                | DesktopFileOperation::Trash
                | DesktopFileOperation::Delete
        )
    {
        return Err(DesktopFileErrorCode::Protected);
    }
    Ok(())
}

pub fn validate_desktop_name(name: &str) -> Result<(), DesktopFileErrorCode> {
    if name.is_empty()
        || name.len() > 4096
        || name.contains(['/', '\\', '\0'])
        || name.eq_ignore_ascii_case(".git")
        || crate::is_private_staging_name(name.as_bytes())
        || Path::new(name).components().count() != 1
        || !matches!(
            Path::new(name).components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err(DesktopFileErrorCode::Invalid);
    }
    Ok(())
}

pub fn validate_desktop_relative(
    relative: &str,
    allow_empty: bool,
) -> Result<(), DesktopFileErrorCode> {
    if relative.is_empty() {
        return if allow_empty {
            Ok(())
        } else {
            Err(DesktopFileErrorCode::Invalid)
        };
    }
    if relative.len() > 16_384 || relative.contains('\0') {
        return Err(DesktopFileErrorCode::Invalid);
    }
    let mut count = 0usize;
    for component in Path::new(relative).components() {
        count += 1;
        match component {
            Component::CurDir => {}
            Component::Normal(name) => {
                let name = name.to_str().ok_or(DesktopFileErrorCode::Invalid)?;
                if name.eq_ignore_ascii_case(".git")
                    || crate::is_private_staging_name(name.as_bytes())
                {
                    return Err(DesktopFileErrorCode::Protected);
                }
            }
            _ => return Err(DesktopFileErrorCode::Invalid),
        }
    }
    if count > 128 {
        return Err(DesktopFileErrorCode::Limit);
    }
    if !allow_empty
        && Path::new(relative)
            .components()
            .all(|part| matches!(part, Component::CurDir))
    {
        return Err(DesktopFileErrorCode::Protected);
    }
    Ok(())
}

fn valid_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path.as_os_str().len() <= 16_384
        && !path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
}

/// Public operation roots cannot turn a forbidden relative component into a
/// new root. Restriction-only control roots deliberately do not use this test.
pub fn validate_desktop_root(path: &Path) -> Result<(), DesktopFileErrorCode> {
    if !valid_absolute(path) {
        return Err(DesktopFileErrorCode::Invalid);
    }
    if path.components().any(|part| {
        matches!(part, Component::Normal(name)
        if name.as_encoded_bytes().eq_ignore_ascii_case(b".git")
            || crate::is_private_staging_name(name.as_encoded_bytes()))
    }) {
        return Err(DesktopFileErrorCode::Protected);
    }
    Ok(())
}

pub fn apply_desktop_mutation(
    request: &DesktopMutationRequest,
    check: impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<DesktopFileChange, DesktopMutationError> {
    apply_desktop_mutation_inner(request, None, check)
}

/// Applies a mutation only if the operation's actual source entry matches a
/// Host-captured no-follow identity and kind at the backend's pinned capture.
/// This precondition is Rust-only and is deliberately absent from IPC DTOs.
pub fn apply_desktop_mutation_with_source(
    request: &DesktopMutationRequest,
    expected_source: &DesktopSourcePrecondition,
    check: impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<DesktopFileChange, DesktopMutationError> {
    if !matches!(
        request.operation,
        DesktopFileOperation::Rename { .. }
            | DesktopFileOperation::Move { .. }
            | DesktopFileOperation::Trash
            | DesktopFileOperation::Delete
    ) {
        return Err(DesktopFileErrorCode::Invalid.into());
    }
    if !expected_source.identity.is_valid() {
        return Err(DesktopFileErrorCode::Invalid.into());
    }
    apply_desktop_mutation_inner(request, Some(expected_source), check)
}

fn apply_desktop_mutation_inner(
    request: &DesktopMutationRequest,
    expected_source: Option<&DesktopSourcePrecondition>,
    mut check: impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<DesktopFileChange, DesktopMutationError> {
    validate_desktop_request(request)?;
    if request.operation.git_context().is_some() {
        return Err(DesktopFileErrorCode::Unsupported.into());
    }
    #[cfg(unix)]
    {
        crate::unix::desktop::apply_mutation(request, expected_source, &mut check)
    }
    #[cfg(windows)]
    {
        crate::windows::desktop::apply_mutation(request, expected_source, &mut check)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = check;
        let _ = expected_source;
        Err(DesktopFileErrorCode::Unsupported.into())
    }
}

/// Captures a path's current leaf identity and kind without following any
/// parent or leaf symlink and without opening the leaf for content access.
pub fn desktop_source_precondition(
    path: &Path,
) -> Result<DesktopSourcePrecondition, DesktopFileErrorCode> {
    #[cfg(unix)]
    {
        crate::unix::desktop::source_precondition(path)
    }
    #[cfg(windows)]
    {
        crate::windows::desktop::source_precondition(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(DesktopFileErrorCode::Unsupported)
    }
}

pub fn finish_desktop_trash<E>(
    ticket: &DesktopTrashTicket,
    transfer: impl FnOnce(&Path) -> Result<(), E>,
) -> Result<(), DesktopTrashError<E>> {
    ticket.validate_shape().map_err(DesktopTrashError::Before)?;
    #[cfg(unix)]
    {
        crate::unix::desktop::finish_trash(ticket, transfer)
    }
    #[cfg(windows)]
    {
        crate::windows::desktop::finish_trash(ticket, transfer)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = transfer;
        Err(DesktopTrashError::Before(DesktopFileErrorCode::Unsupported))
    }
}
