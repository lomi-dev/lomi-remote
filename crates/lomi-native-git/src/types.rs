//! Host-neutral Git approval DTOs shared by the native Git engine.
//!
//! Serde names and enum encodings match the desktop control protocol so the
//! host can translate these values without depending on that protocol crate.
use serde::{Deserialize, Serialize};

/// Git mutations the native engine can prepare for exact approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeGitOperation {
    Stage,
    Unstage,
    Discard,
    Commit,
    Fetch,
    Push,
    Pull,
}

/// Operation-specific, host-neutral request. Workspace authorization,
/// receipts, retries, and pairing policy remain in the caller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "operation",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum NativeGitRequest {
    Stage {
        repository_relative: String,
        paths: Vec<String>,
    },
    Unstage {
        repository_relative: String,
        paths: Vec<String>,
    },
    Discard {
        repository_relative: String,
        paths: Vec<String>,
    },
    Commit {
        repository_relative: String,
        paths: Vec<String>,
        message: String,
    },
    Fetch {
        repository_relative: String,
        remote: String,
        reference: String,
    },
    Push {
        repository_relative: String,
        remote: String,
        reference: String,
        source_commit: String,
        expected_remote_commit: Option<String>,
    },
    Pull {
        repository_relative: String,
        remote: String,
        reference: String,
        source_commit: String,
        expected_remote_commit: String,
        mode: GitPullMode,
    },
}

impl NativeGitRequest {
    pub fn operation(&self) -> NativeGitOperation {
        match self {
            Self::Stage { .. } => NativeGitOperation::Stage,
            Self::Unstage { .. } => NativeGitOperation::Unstage,
            Self::Discard { .. } => NativeGitOperation::Discard,
            Self::Commit { .. } => NativeGitOperation::Commit,
            Self::Fetch { .. } => NativeGitOperation::Fetch,
            Self::Push { .. } => NativeGitOperation::Push,
            Self::Pull { .. } => NativeGitOperation::Pull,
        }
    }

    pub fn repository_relative(&self) -> &str {
        match self {
            Self::Stage {
                repository_relative,
                ..
            }
            | Self::Unstage {
                repository_relative,
                ..
            }
            | Self::Discard {
                repository_relative,
                ..
            }
            | Self::Commit {
                repository_relative,
                ..
            }
            | Self::Fetch {
                repository_relative,
                ..
            }
            | Self::Push {
                repository_relative,
                ..
            }
            | Self::Pull {
                repository_relative,
                ..
            } => repository_relative,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitDiscardFile {
    pub relative_path: String,
    pub index_object: String,
    pub index_mode: String,
    pub patch: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitPushTarget {
    pub remote: String,
    pub reference: String,
    pub source_commit: String,
    pub expected_remote_commit: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitPushApproval {
    pub target: GitPushTarget,
    pub location: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitFetchApproval {
    pub remote: String,
    pub reference: String,
    pub destination: String,
    pub location: String,
    pub previous_commit: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitStagedChange {
    pub relative_path: String,
    pub old_mode: String,
    pub new_mode: String,
    pub old_object: String,
    pub new_object: String,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitCommitIdentity {
    pub name: String,
    pub email: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitCommitApproval {
    pub message: String,
    pub final_newline_added: bool,
    pub author: GitCommitIdentity,
    pub committer: GitCommitIdentity,
    pub changes: Vec<GitStagedChange>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitPullMode {
    FfOnly,
    Rebase,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitPullTarget {
    pub remote: String,
    pub reference: String,
    pub source_commit: String,
    pub expected_remote_commit: String,
    pub mode: GitPullMode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitPullApproval {
    pub target: GitPullTarget,
    pub network: GitFetchApproval,
    pub replay_commits: Vec<String>,
    pub affected_paths: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitPullOutcome {
    Applied,
    RemoteChanged,
    Conflicted,
}

/// File evidence in the existing desktop mutation-plan/result shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitMutationFile {
    pub relative_path: String,
    pub sha256: Option<String>,
    pub byte_length: u64,
}

/// Complete approval preview serialized with the current desktop UI fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeGitPlanPreview {
    pub plan_hash: String,
    pub repository_path: String,
    pub operation: NativeGitOperation,
    pub head: Option<String>,
    pub branch: Option<String>,
    pub files: Vec<GitMutationFile>,
    pub commit: Option<GitCommitApproval>,
    pub network: Option<GitFetchApproval>,
    pub push: Option<GitPushApproval>,
    pub discard: Option<Vec<GitDiscardFile>>,
    pub pull: Option<GitPullApproval>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitPushVerification {
    ServerAcknowledgement,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitPushed {
    pub target: GitPushTarget,
    pub changed: bool,
    pub verification: GitPushVerification,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitFetched {
    pub remote: String,
    pub reference: String,
    pub destination: String,
    pub commit: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitCommitCreated {
    pub message_sha256: String,
    pub author: GitCommitIdentity,
    pub committer: GitCommitIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitPulled {
    pub target: GitPullTarget,
    pub fetched_commit: String,
    pub outcome: GitPullOutcome,
}

/// The native process boundary observation is not proof that trusted helpers
/// or escaped descendants have stopped writing. The Host retains its writer
/// fence regardless of this value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeGitProcessSettlement {
    ObservedOwnedBoundaryClosed,
    Unproven,
}

/// Result data from a started operation. An unknown result remains explicit;
/// only the Host can decide when its repository writer fence may be retired.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeGitExecutionOutcome {
    pub plan_hash: String,
    pub operation: NativeGitOperation,
    pub repository_path: String,
    pub before_revision: String,
    pub after_revision: Option<String>,
    pub head: Option<String>,
    pub index_revision: Option<String>,
    pub files: Option<Vec<GitMutationFile>>,
    pub selected_files_changed: Option<bool>,
    pub commit: Option<GitCommitCreated>,
    pub fetch: Option<GitFetched>,
    pub push: Option<GitPushed>,
    pub pull: Option<GitPulled>,
    pub exit_code: Option<i32>,
    pub interrupted: Option<crate::ErrorCode>,
    pub abandoned_descendants: bool,
    pub settlement: NativeGitProcessSettlement,
    pub outcome_unknown: bool,
    pub writer_fence_must_be_retained: bool,
}
