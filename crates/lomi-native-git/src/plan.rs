//! Typed adapter from host-neutral Git requests to the sealed native plans.
//!
//! The Host may acquire its writer lease using `repository_path()`, but must
//! keep this prepared plan (and therefore its descriptor-backed project root)
//! alive through execution. Git subprocesses use the repository descriptor as
//! their cwd; this adapter never reopens the approved root by pathname.
use crate::{
    ErrorCode, NativeProjectDirectory, git_execution, git_read,
    types::{
        GitCommitApproval, GitCommitCreated, GitDiscardFile, GitFetchApproval, GitFetched,
        GitMutationFile, GitPullApproval, GitPullMode, GitPulled, GitPushApproval, GitPushTarget,
        GitPushVerification, GitPushed, NativeGitExecutionOutcome, NativeGitPlanPreview,
        NativeGitProcessSettlement, NativeGitRequest,
    },
    validate_relative,
};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::Arc};

enum SealedPlan {
    Index(git_execution::IndexPlan),
    Discard(git_execution::discard::Plan),
    Commit(git_execution::commit::Plan),
    Fetch(git_execution::fetch::Plan),
    Push(git_execution::push::Plan),
    Pull(Box<git_execution::pull::Plan>),
}

struct Executed {
    process: git_execution::IndexOutcome,
    fetch: Option<GitFetched>,
    push: Option<GitPushed>,
    pull: Option<GitPulled>,
}

impl SealedPlan {
    fn revision(&self) -> &str {
        match self {
            Self::Index(plan) => &plan.revision,
            Self::Discard(plan) => &plan.revision,
            Self::Commit(plan) => &plan.preview.revision,
            Self::Fetch(plan) => &plan.revision,
            Self::Push(plan) => &plan.revision,
            Self::Pull(plan) => &plan.revision,
        }
    }

    fn observation(&self) -> &git_execution::Snapshot {
        match self {
            Self::Index(plan) => &plan.observation,
            Self::Discard(plan) => &plan.observation,
            Self::Commit(plan) => &plan.preview.observation,
            Self::Fetch(plan) => &plan.observation,
            Self::Push(plan) => &plan.observation,
            Self::Pull(plan) => &plan.observation,
        }
    }

    fn commit_preview(&self) -> Option<GitCommitApproval> {
        let Self::Commit(plan) = self else {
            return None;
        };
        Some(GitCommitApproval {
            message: plan.preview.stored_message.clone(),
            final_newline_added: plan.preview.final_newline_added,
            author: plan.preview.author.clone(),
            committer: plan.preview.committer.clone(),
            changes: plan.preview.changes.clone(),
        })
    }

    fn commit_result(&self) -> Option<GitCommitCreated> {
        let Self::Commit(plan) = self else {
            return None;
        };
        Some(GitCommitCreated {
            message_sha256: format!(
                "{:x}",
                Sha256::digest(plan.preview.stored_message.as_bytes())
            ),
            author: plan.preview.author.clone(),
            committer: plan.preview.committer.clone(),
        })
    }

    fn network_preview(&self) -> Option<GitFetchApproval> {
        match self {
            Self::Fetch(plan) => Some(plan.preview.clone()),
            _ => None,
        }
    }

    fn push_preview(&self) -> Option<GitPushApproval> {
        match self {
            Self::Push(plan) => Some(plan.preview.clone()),
            _ => None,
        }
    }

    fn pull_preview(&self) -> Option<GitPullApproval> {
        match self {
            Self::Pull(plan) => Some(plan.preview.clone()),
            _ => None,
        }
    }

    fn discard_preview(&self) -> Option<Vec<GitDiscardFile>> {
        match self {
            Self::Discard(plan) => Some(plan.files.clone()),
            _ => None,
        }
    }

    fn execute(
        self,
        exact_approved_hash: &str,
        check: &dyn Fn() -> Result<(), ErrorCode>,
    ) -> Result<Executed, ErrorCode> {
        match self {
            Self::Discard(plan) => {
                git_execution::discard::execute(plan, exact_approved_hash, check).map(|process| {
                    Executed {
                        process,
                        fetch: None,
                        push: None,
                        pull: None,
                    }
                })
            }
            Self::Index(plan) => git_execution::execute_index(plan, exact_approved_hash, check)
                .map(|process| Executed {
                    process,
                    fetch: None,
                    push: None,
                    pull: None,
                }),
            Self::Commit(plan) => git_execution::commit::execute(plan, exact_approved_hash, check)
                .map(|process| Executed {
                    process,
                    fetch: None,
                    push: None,
                    pull: None,
                }),
            Self::Fetch(plan) => {
                let preview = plan.preview.clone();
                let result = git_execution::fetch::execute(plan, exact_approved_hash, check)?;
                Ok(Executed {
                    process: result.execution,
                    fetch: result.fetched_commit.map(|commit| GitFetched {
                        remote: preview.remote,
                        reference: preview.reference,
                        destination: preview.destination,
                        commit,
                    }),
                    push: None,
                    pull: None,
                })
            }
            Self::Pull(plan) => {
                let target = plan.preview.target.clone();
                let result = git_execution::pull::execute(*plan, exact_approved_hash, check)?;
                Ok(Executed {
                    process: result.execution,
                    fetch: None,
                    push: None,
                    pull: result.status.zip(result.fetched_commit).map(
                        |(outcome, fetched_commit)| GitPulled {
                            target,
                            fetched_commit,
                            outcome,
                        },
                    ),
                })
            }
            Self::Push(plan) => {
                let target = plan.preview.target.clone();
                let result = git_execution::push::execute(plan, exact_approved_hash, check)?;
                Ok(Executed {
                    process: result.execution,
                    fetch: None,
                    push: result.changed.map(|changed| GitPushed {
                        target,
                        changed,
                        verification: GitPushVerification::ServerAcknowledgement,
                    }),
                    pull: None,
                })
            }
        }
    }
}

/// A prepared plan owns both the sealed native operation and its original
/// descriptor-backed project directory. The Host approves `revision()` and
/// must hold its physical repository writer lease for `repository_path()`
/// until `execute` returns. The engine never reconstructs command arguments
/// from IPC and does not retire the Host's writer fence.
pub struct PreparedNativeGitPlan {
    sealed: SealedPlan,
    preview: NativeGitPlanPreview,
    repository_relative: String,
    project_root: PathBuf,
}

impl PreparedNativeGitPlan {
    /// Validate the typed request and prepare its immutable native plan.
    /// Qualification is checked before request validation, callbacks, or any
    /// filesystem access.
    pub fn prepare(
        project: Arc<NativeProjectDirectory>,
        request: NativeGitRequest,
        check: &dyn Fn() -> Result<(), ErrorCode>,
    ) -> Result<Self, ErrorCode> {
        crate::require_qualified()?;
        validate_request(&request)?;
        Self::prepare_validated(project, request, git_execution::Environment::capture, check)
    }

    /// Prepare the exact approved plan using a previously captured, bounded
    /// environment. A worker must not recapture ambient variables after Host
    /// approval.
    pub fn prepare_with_environment(
        project: Arc<NativeProjectDirectory>,
        request: NativeGitRequest,
        environment: git_execution::Environment,
        check: &dyn Fn() -> Result<(), ErrorCode>,
    ) -> Result<Self, ErrorCode> {
        crate::require_qualified()?;
        validate_request(&request)?;
        Self::prepare_validated(project, request, || environment, check)
    }

    /// Pure request validation for worker admission before opening the root.
    pub fn validate_request(request: &NativeGitRequest) -> Result<(), ErrorCode> {
        validate_request(request)
    }

    fn prepare_validated(
        project: Arc<NativeProjectDirectory>,
        request: NativeGitRequest,
        environment: impl FnOnce() -> git_execution::Environment,
        check: &dyn Fn() -> Result<(), ErrorCode>,
    ) -> Result<Self, ErrorCode> {
        validate_request(&request)?;

        let operation = request.operation();
        let repository_relative = request.repository_relative().to_owned();
        let project_root = project.canonical_path().to_path_buf();
        let repository_path = if repository_relative.is_empty() {
            project_root.clone()
        } else {
            project_root.join(&repository_relative)
        }
        .to_str()
        .ok_or(ErrorCode::ScopeDenied)?
        .to_owned();

        check()?;
        let environment = environment();
        let sealed = match request {
            NativeGitRequest::Stage {
                repository_relative,
                paths,
            } => SealedPlan::Index(git_execution::IndexPlan::prepare(
                project,
                repository_relative,
                git_execution::IndexOperation::Stage,
                paths,
                environment,
                check,
            )?),
            NativeGitRequest::Unstage {
                repository_relative,
                paths,
            } => SealedPlan::Index(git_execution::IndexPlan::prepare(
                project,
                repository_relative,
                git_execution::IndexOperation::Unstage,
                paths,
                environment,
                check,
            )?),
            NativeGitRequest::Discard {
                repository_relative,
                paths,
            } => SealedPlan::Discard(git_execution::discard::Plan::prepare(
                project,
                repository_relative,
                paths,
                environment,
                check,
            )?),
            NativeGitRequest::Commit {
                repository_relative,
                paths,
                message,
            } => SealedPlan::Commit(git_execution::commit::Plan::prepare(
                project,
                repository_relative,
                paths,
                &message,
                environment,
                check,
            )?),
            NativeGitRequest::Fetch {
                repository_relative,
                remote,
                reference,
            } => SealedPlan::Fetch(git_execution::fetch::Plan::prepare(
                project,
                repository_relative,
                &remote,
                &reference,
                environment,
                check,
            )?),
            NativeGitRequest::Push {
                repository_relative,
                remote,
                reference,
                source_commit,
                expected_remote_commit,
            } => SealedPlan::Push(git_execution::push::Plan::prepare(
                project,
                repository_relative,
                GitPushTarget {
                    remote,
                    reference,
                    source_commit,
                    expected_remote_commit,
                },
                environment,
                check,
            )?),
            NativeGitRequest::Pull {
                repository_relative,
                remote,
                reference,
                source_commit,
                expected_remote_commit,
                mode,
            } => SealedPlan::Pull(Box::new(git_execution::pull::Plan::prepare(
                project,
                repository_relative,
                git_execution::pull::Target {
                    remote,
                    reference,
                    source_commit,
                    expected_remote_commit,
                    mode,
                },
                environment,
                check,
            )?)),
        };

        let observation = sealed.observation();
        let preview = NativeGitPlanPreview {
            plan_hash: sealed.revision().to_owned(),
            repository_path,
            operation,
            head: observation.head.clone(),
            branch: observation.branch.clone(),
            files: files(observation),
            commit: sealed.commit_preview(),
            network: sealed.network_preview(),
            push: sealed.push_preview(),
            discard: sealed.discard_preview(),
            pull: sealed.pull_preview(),
        };
        if serde_json::to_vec(&preview)
            .map_err(|_| ErrorCode::ResourceExhausted)?
            .len()
            > 32 * 1024
        {
            return Err(ErrorCode::ResourceExhausted);
        }

        Ok(Self {
            sealed,
            preview,
            repository_relative,
            project_root,
        })
    }

    /// Exact hash of the sealed plan which must be explicitly approved.
    pub fn revision(&self) -> &str {
        self.sealed.revision()
    }

    /// Snapshot used to prepare this plan. It includes the bound repository
    /// identity and can be serialized by a future Host adapter.
    pub fn observation(&self) -> &git_execution::Snapshot {
        self.sealed.observation()
    }

    /// Complete approval DTO with the current desktop UI field names.
    pub fn preview(&self) -> &NativeGitPlanPreview {
        &self.preview
    }

    /// The canonical path the Host must use when acquiring its writer lease.
    /// The plan retains the descriptor-backed project root for its lifetime.
    pub fn repository_path(&self) -> &str {
        &self.preview.repository_path
    }

    pub fn repository_relative(&self) -> &str {
        &self.repository_relative
    }

    /// Root identity captured from the original NativeProjectDirectory.
    pub fn project_root(&self) -> &std::path::Path {
        &self.project_root
    }

    /// Execute only the exact approved sealed plan. A returned outcome always
    /// requires the Host to retain its repository writer fence; this engine
    /// has no custodian proof that would permit retiring it.
    pub fn execute(
        self,
        exact_approved_hash: &str,
        check: &dyn Fn() -> Result<(), ErrorCode>,
    ) -> Result<NativeGitExecutionOutcome, ErrorCode> {
        crate::require_qualified()?;
        if self.revision() != exact_approved_hash {
            return Err(ErrorCode::ControlRevoked);
        }

        let before = self.observation().clone();
        let before_revision = before.revision()?;
        let commit = self.sealed.commit_result();
        let plan_hash = self.revision().to_owned();
        let operation = self.preview.operation;
        let repository_path = self.preview.repository_path.clone();
        let executed = self.sealed.execute(exact_approved_hash, check)?;
        let git_execution::IndexOutcome {
            exit_code,
            interrupted,
            abandoned_descendants,
            settlement,
            after,
        } = executed.process;
        let pull_conflicted = executed
            .pull
            .as_ref()
            .is_some_and(|result| result.outcome == crate::types::GitPullOutcome::Conflicted);
        let process_complete = (exit_code == Some(0) || pull_conflicted)
            && interrupted.is_none()
            && !abandoned_descendants
            && settlement == git_execution::ProcessSettlement::ObservedOwnedBoundaryClosed
            && after.is_some();
        let (after_revision, head, index_revision, result_files, selected_files_changed) =
            if let Some(after) = after {
                (
                    after.revision().ok(),
                    after.head.clone(),
                    Some(after.index_revision.clone()),
                    Some(files(&after)),
                    Some(before.files != after.files),
                )
            } else {
                (None, None, None, None, None)
            };
        let outcome_unknown = !process_complete || after_revision.is_none();

        Ok(NativeGitExecutionOutcome {
            plan_hash,
            operation,
            repository_path,
            before_revision,
            after_revision,
            head,
            index_revision,
            files: result_files,
            selected_files_changed,
            commit,
            fetch: executed.fetch,
            push: executed.push,
            pull: executed.pull,
            exit_code,
            interrupted,
            abandoned_descendants,
            settlement: match settlement {
                git_execution::ProcessSettlement::ObservedOwnedBoundaryClosed => {
                    NativeGitProcessSettlement::ObservedOwnedBoundaryClosed
                }
                git_execution::ProcessSettlement::Unproven => NativeGitProcessSettlement::Unproven,
            },
            outcome_unknown,
            writer_fence_must_be_retained: true,
        })
    }
}

fn files(snapshot: &git_execution::Snapshot) -> Vec<GitMutationFile> {
    snapshot
        .files
        .iter()
        .map(|file| GitMutationFile {
            relative_path: file.relative_path.clone(),
            sha256: file.sha256.clone(),
            byte_length: file.byte_length,
        })
        .collect()
}

fn validate_request(request: &NativeGitRequest) -> Result<(), ErrorCode> {
    if !request.repository_relative().is_empty() {
        validate_relative(request.repository_relative())?;
    }

    let validate_paths = |paths: &[String]| -> Result<(), ErrorCode> {
        if paths.is_empty() {
            return Err(ErrorCode::ScopeDenied);
        }
        if paths.len() > 64 {
            return Err(ErrorCode::ResourceExhausted);
        }
        for path in paths {
            validate_relative(path)?;
        }
        let mut unique = std::collections::HashSet::with_capacity(paths.len());
        if paths.iter().any(|path| !unique.insert(path)) {
            return Err(ErrorCode::RevisionConflict);
        }
        Ok(())
    };
    let validate_network = |remote: &str, reference: &str| -> Result<(), ErrorCode> {
        if !git_read::valid_remote_name(remote)
            || !reference.starts_with("refs/heads/")
            || !git_execution::fetch::reference(reference)
        {
            return Err(ErrorCode::ScopeDenied);
        }
        Ok(())
    };
    let validate_oid = |value: &str| -> Result<(), ErrorCode> {
        if !git_execution::push::oid(value) {
            return Err(ErrorCode::ScopeDenied);
        }
        Ok(())
    };

    match request {
        NativeGitRequest::Stage { paths, .. }
        | NativeGitRequest::Unstage { paths, .. }
        | NativeGitRequest::Discard { paths, .. } => validate_paths(paths),
        NativeGitRequest::Commit { paths, message, .. } => {
            validate_paths(paths)?;
            if message.trim().is_empty() || message.contains('\0') {
                return Err(ErrorCode::ScopeDenied);
            }
            if message.len() > 16 * 1024 {
                return Err(ErrorCode::ResourceExhausted);
            }
            Ok(())
        }
        NativeGitRequest::Fetch {
            remote, reference, ..
        } => validate_network(remote, reference),
        NativeGitRequest::Push {
            remote,
            reference,
            source_commit,
            expected_remote_commit,
            ..
        } => {
            validate_network(remote, reference)?;
            validate_oid(source_commit)?;
            if let Some(commit) = expected_remote_commit.as_deref() {
                validate_oid(commit)?;
            }
            Ok(())
        }
        NativeGitRequest::Pull {
            remote,
            reference,
            source_commit,
            expected_remote_commit,
            mode: GitPullMode::FfOnly | GitPullMode::Rebase,
            ..
        } => {
            validate_network(remote, reference)?;
            validate_oid(source_commit)?;
            validate_oid(expected_remote_commit)
        }
    }
}
