use serde::{Deserialize, Serialize};
use std::{ffi::CString, fs::File, path::PathBuf};

/// Platform-independent error codes used by the filesystem engine.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeProjectErrorCode {
    AppUnavailable,
    PairingRequired,
    ScopeDenied,
    UiNotReady,
    AppClosing,
    TargetNotFound,
    StaleGeneration,
    RevisionConflict,
    StaleSnapshot,
    TargetBusy,
    ControlRevoked,
    PromptStateUnknown,
    PanelNotRenderable,
    ProtectedOriginTerminal,
    UnsupportedCapability,
    HostUnqualified,
    DeadlineExceeded,
    CursorExpired,
    ArtifactTooLarge,
    ArtifactInvalid,
    OutcomeUnknown,
    IdempotencyConflict,
    RetryWindowExpired,
    ResourceExhausted,
    StorageUnavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeProjectEntryKind {
    Directory,
    File,
}

/// Serialized field names and representations match the desktop file entry DTO.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeProjectEntry {
    pub name: String,
    pub relative_path: String,
    pub kind: NativeProjectEntryKind,
    /// Decimal bytes preserve the full unsigned 64-bit range in JSON clients.
    pub byte_length: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeProjectDirectorySnapshot {
    pub revision: String,
    pub entries: Vec<NativeProjectEntry>,
}

/// Result of creating one bounded raw project artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeArtifactCreated {
    pub relative_path: String,
    pub byte_length: u64,
    pub disk_revision: String,
}

/// One normalized filesystem mutation. Revisions here describe filesystem
/// state only; request receipts and application scopes belong to the caller.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "operation",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum NativeProjectMutation {
    Create {
        relative_path: String,
        kind: NativeProjectEntryKind,
        expected_parent_revision: String,
    },
    RenameMoveFile {
        relative_path: String,
        target_relative_path: String,
        expected_disk_revision: String,
        expected_parent_revision: String,
    },
    RenameMoveDirectory {
        relative_path: String,
        target_relative_path: String,
        expected_directory_revision: String,
        expected_parent_revision: String,
    },
    TrashStage {
        relative_path: String,
        kind: NativeProjectEntryKind,
        expected_revision: String,
        expected_parent_revision: String,
        recovery_root: PathBuf,
        operation_id: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum NativeProjectMutationResult {
    Created {
        relative_path: String,
    },
    FileMoved {
        relative_path: String,
        target_relative_path: String,
    },
    DirectoryMoved {
        relative_path: String,
        target_relative_path: String,
    },
    TrashStaged {
        ticket: NativeProjectTrashTicket,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum NativeProjectCheckPhase {
    Progress,
    BeforeEffect,
    /// Local-only fresh filesystem checks after authorization.
    Validation,
    /// Local cancellation/deadline/freshness checks immediately before effect.
    Publication,
}

/// Durable identity for a staged entry. IDs remain decimal strings in JSON so
/// every platform preserves the complete device/inode value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeProjectTrashTicket {
    pub recovery_root: PathBuf,
    pub operation_id: String,
    pub staged_path: PathBuf,
    pub project_path: PathBuf,
    pub relative_path: String,
    pub kind: NativeProjectEntryKind,
    pub expected_revision: String,
    pub expected_parent_revision: String,
    pub source_entry_device: String,
    pub source_entry_inode: String,
    pub recovery_device: String,
    pub recovery_inode: String,
    pub operation_device: String,
    pub operation_inode: String,
    pub payload_device: String,
    pub payload_inode: String,
}

impl NativeProjectTrashTicket {
    /// Bind a returned ticket to the exact request that authorized staging.
    pub fn matches_request(
        &self,
        project_root: &std::path::Path,
        mutation: &NativeProjectMutation,
    ) -> bool {
        let NativeProjectMutation::TrashStage {
            relative_path,
            kind,
            expected_revision,
            expected_parent_revision,
            recovery_root,
            operation_id,
        } = mutation
        else {
            return false;
        };
        let Some(leaf) = std::path::Path::new(relative_path).file_name() else {
            return false;
        };
        let expected_staged_path = recovery_root.join(operation_id).join("entry").join(leaf);
        self.project_path == project_root
            && &self.recovery_root == recovery_root
            && &self.operation_id == operation_id
            && &self.relative_path == relative_path
            && &self.kind == kind
            && &self.expected_revision == expected_revision
            && &self.expected_parent_revision == expected_parent_revision
            && &self.staged_path == &expected_staged_path
            && project_root.is_absolute()
            && recovery_root.is_absolute()
            && valid_operation_id(operation_id)
            && crate::validate_relative(relative_path).is_ok()
            && valid_revision(expected_revision)
            && valid_revision(expected_parent_revision)
            && valid_decimal(&self.source_entry_device)
            && valid_decimal(&self.source_entry_inode)
            && valid_decimal(&self.recovery_device)
            && valid_decimal(&self.recovery_inode)
            && valid_decimal(&self.operation_device)
            && valid_decimal(&self.operation_inode)
            && valid_decimal(&self.payload_device)
            && valid_decimal(&self.payload_inode)
            && self.source_entry_device == self.recovery_device
            && self.operation_device == self.recovery_device
            && self.payload_device == self.recovery_device
    }
}

fn valid_operation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_:.".contains(&byte))
}

fn valid_revision(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_decimal(value: &str) -> bool {
    value
        .parse::<u64>()
        .is_ok_and(|number| number.to_string() == value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeProjectMutationError {
    /// The requested mutation did not complete.
    Before(NativeProjectErrorCode),
    /// The mutation completed but durable completion was not confirmed.
    Uncertain,
}

impl From<NativeProjectErrorCode> for NativeProjectMutationError {
    fn from(value: NativeProjectErrorCode) -> Self {
        Self::Before(value)
    }
}

/// A snapshot of one regular file, anchored to the descriptor selected by the
/// project root and pinned to its complete identity/stamp.
pub struct NativeProjectFile {
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) file: std::fs::File,
    pub(crate) stamp: NativeProjectStamp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeProjectStamp {
    pub device: u64,
    pub inode: u64,
    pub bytes: u64,
    pub links: u64,
    pub modified: (i64, i64),
    pub changed: (i64, i64),
}

/// An approved project root with its original path and pinned directory fd.
pub struct NativeProjectDirectory {
    pub(crate) path: PathBuf,
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) directory: std::fs::File,
}

/// A reopened staged entry. Dropping it never removes, restores, or trashes it.
pub struct NativeProjectStagedTrash {
    pub(crate) ticket: NativeProjectTrashTicket,
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) operation_directory: File,
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) payload_directory: File,
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) leaf: CString,
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) source_identity: (u64, u64),
}
