//! Host-root-bound Git repository discovery and read admission.
//!
//! Repository metadata is inspected through `lomi-files::FileRoot`, which
//! pins the host-selected workspace and refuses links while traversing it.
//! Status runs in an embedded, policy-checked WASI worker over a private copy.
//! All Git reads run in the embedded, policy-checked WASI worker. Mutations are
//! prepared against a private copy and published by descriptor-confined code.

use base64::Engine as _;
use lomi_files::{
    EntryRef, Error as FileError, FileRoot, GitFilePrecondition, GitFinalFile, GitFinalTarget,
    GitObjectFile, GitPublication, GitPublishOutcome, GitPullFile, GitPullNodeKind,
    GitPullPrecondition, GitPullPublication, GitWorktreePrecondition, Kind, Meta,
};
use lomi_remote_protocol::rpc::{
    BoundedList, DiffLineKind, DiffLineText, DiffView, DisplayText, EncodedPathId, GitChange,
    GitCommitParams, GitCommitSummary, GitDiffFile, GitDiffHunk, GitDiffLine, GitDiffParams,
    GitDiffResult, GitLogParams, GitLogResult, GitNetworkParams, GitPreconditions, GitPullParams,
    GitRemote, GitRemoteSelector, GitRemoteSelectorKind, GitRepositoriesResult, GitRepository,
    GitShowParams, GitShowResult, GitStageParams, GitStatusEntry, GitStatusParams, GitStatusResult,
    GitUnstageParams, ObjectId, RefId, RemoteId, WorkspaceReadParams,
};
use lomi_remote_protocol::{
    DecimalU64, EntryId, EventCursor, FileRevision, RepoStateToken, RepositoryId, WorkspaceContext,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

mod desktop;
mod network;
mod worker;
pub use network::{
    GitPushOutcome, PreparedGitFetch, PreparedGitPull, PreparedGitPullMutation, PreparedGitPush,
    canonical_credential_url, internal_network_worker, validate_credential_url,
};

const MAX_DISCOVERY_DEPTH: usize = 64;
const MAX_DISCOVERY_ENTRIES: usize = 100_000;
const MAX_PAGE_SIZE: usize = 200;
const MAX_GIT_POINTER_BYTES: usize = 4096;
const MAX_SNAPSHOT_ENTRIES: usize = 100_000;
const MAX_SNAPSHOT_DEPTH: usize = 64;
const MAX_SNAPSHOT_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SNAPSHOT_SYMLINK_BYTES: usize = 64 * 1024;
const MAX_SNAPSHOT_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const SNAPSHOT_READ_CHUNK: usize = 1024 * 1024;
const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MISSING_EXECUTOR: &str = "Embedded isolated WASI Git worker is unavailable";

/// Read-only artifact availability observation for local diagnostics. This
/// checks the exact bundled worker, not a repository or its executable config.
pub fn embedded_read_worker_integrity() -> bool {
    worker::embedded_integrity()
}

/// Cancellation shared by an RPC handler and its Git operation.
#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Per-request cancellation and absolute deadline. Callers must supply this
/// control object for discovery and read operations.
#[derive(Clone)]
pub struct RequestControl {
    cancellation: CancellationToken,
    deadline: Instant,
}

impl RequestControl {
    pub fn with_timeout(
        cancellation: CancellationToken,
        timeout: Duration,
    ) -> Result<Self, GitServiceError> {
        if timeout.is_zero() || timeout > Duration::from_secs(120) {
            return Err(GitServiceError::InvalidDeadline);
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(GitServiceError::InvalidDeadline)?;
        Ok(Self {
            cancellation,
            deadline,
        })
    }

    pub fn with_deadline(cancellation: CancellationToken, deadline: Instant) -> Self {
        Self {
            cancellation,
            deadline,
        }
    }

    fn check(&self) -> Result<(), GitServiceError> {
        if self.cancellation.is_cancelled() {
            return Err(GitServiceError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(GitServiceError::DeadlineExceeded);
        }
        Ok(())
    }

    fn wait_duration(&self) -> Result<Duration, GitServiceError> {
        self.check()?;
        Ok(self
            .deadline
            .saturating_duration_since(Instant::now())
            .min(LOCK_POLL_INTERVAL))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitServiceError {
    Cancelled,
    DeadlineExceeded,
    InvalidDeadline,
    ContextMismatch,
    RepositoryNotFound,
    RepositoryChanged,
    UnsafeRepository,
    ResourceLimit,
    DiscoveryFailed,
    ExecutorUnavailable,
    ExecutorFailed,
    InvalidObjectId,
    StaleState,
    InvalidCursor,
    MutationConflict,
    IdentityRequired,
    MutationOutcomeUnknown,
    MutationFailed,
    CredentialsRequired,
    UnsupportedCapability,
    NetworkFailed,
    PushRejected,
    NetworkOutcomeUnknown,
}

impl GitServiceError {
    /// Safe, stable diagnostic suitable for mapping to a host error response.
    /// It never includes a host path or an environment/configuration value.
    pub fn public_message(self) -> &'static str {
        match self {
            Self::Cancelled => "Git operation cancelled",
            Self::DeadlineExceeded => "Git operation deadline exceeded",
            Self::InvalidDeadline => "Invalid Git operation deadline",
            Self::ContextMismatch => "Git workspace context mismatch",
            Self::RepositoryNotFound => "Repository unavailable",
            Self::RepositoryChanged => "Repository changed during discovery",
            Self::UnsafeRepository => "Repository metadata uses an unsupported or unsafe path",
            Self::ResourceLimit => "Git repository discovery resource limit reached",
            Self::DiscoveryFailed => "Repository discovery failed",
            Self::ExecutorUnavailable => MISSING_EXECUTOR,
            Self::ExecutorFailed => "Isolated Git read worker failed",
            Self::InvalidObjectId => "Invalid Git object identifier",
            Self::StaleState => "Repository state changed since the requested snapshot",
            Self::InvalidCursor => "Invalid Git status page cursor",
            Self::MutationConflict => "Git repository changed before the mutation was published",
            Self::IdentityRequired => {
                "Repository-local Git user.name and user.email are required to commit"
            }
            Self::MutationOutcomeUnknown => "Git mutation outcome is unknown",
            Self::MutationFailed => "Git mutation failed",
            Self::CredentialsRequired => "Credentials are required for this Git remote",
            Self::UnsupportedCapability => "This Git remote configuration is not supported",
            Self::NetworkFailed => "Git network operation failed",
            Self::PushRejected => "The Git server rejected the requested reference update",
            Self::NetworkOutcomeUnknown => "Git remote operation outcome is unknown",
        }
    }
}

/// Credential lookup key for an explicitly selected, validated HTTPS remote.
/// The raw URL is available only to the host-owned credential provider and is
/// always redacted from Debug output.
pub struct RemoteCredentialBinding {
    pub remote_id: RemoteId,
    pub validated_https_url: String,
    pub config_fingerprint: RepoStateToken,
}

impl std::fmt::Debug for RemoteCredentialBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteCredentialBinding")
            .field("remote_id", &self.remote_id)
            .field("validated_https_url", &"[REDACTED]")
            .field("config_fingerprint", &self.config_fingerprint)
            .finish()
    }
}

/// Ephemeral HTTPS credentials supplied by the host's secret store.
pub struct GitCredentials {
    pub username: Zeroizing<Vec<u8>>,
    pub password: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for GitCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GitCredentials([REDACTED])")
    }
}

/// The host owns credential storage and selects values using this binding.
pub trait GitCredentialProvider: Send + Sync {
    fn credentials(&self, binding: &RemoteCredentialBinding) -> Option<GitCredentials>;
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct RelPath(Vec<Vec<u8>>);

impl RelPath {
    fn root() -> Self {
        Self(Vec::new())
    }

    fn joined(&self, name: &[u8]) -> Self {
        let mut components = self.0.clone();
        components.push(name.to_vec());
        Self(components)
    }

    fn resolve_relative(&self, path: &str) -> Result<Self, GitServiceError> {
        if path.is_empty() || path.starts_with('/') || path.starts_with('\\') {
            return Err(GitServiceError::UnsafeRepository);
        }
        let mut components = self.0.clone();
        for piece in path.split('/') {
            match piece {
                "" | "." => {}
                ".." => {
                    if components.pop().is_none() {
                        return Err(GitServiceError::UnsafeRepository);
                    }
                }
                value if value.contains('\\') || value.contains(':') || value.contains('\0') => {
                    return Err(GitServiceError::UnsafeRepository);
                }
                value => components.push(value.as_bytes().to_vec()),
            }
        }
        if components.is_empty() {
            return Err(GitServiceError::UnsafeRepository);
        }
        Ok(Self(components))
    }

    fn to_host_path(&self, root: &Path) -> Result<PathBuf, GitServiceError> {
        let mut path = root.to_path_buf();
        for component in &self.0 {
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStrExt;
                path.push(std::ffi::OsStr::from_bytes(component));
            }
            #[cfg(windows)]
            {
                let text = std::str::from_utf8(component)
                    .map_err(|_| GitServiceError::UnsafeRepository)?;
                path.push(text);
            }
            #[cfg(not(any(unix, windows)))]
            {
                let text = std::str::from_utf8(component)
                    .map_err(|_| GitServiceError::UnsafeRepository)?;
                path.push(text);
            }
        }
        Ok(path)
    }

    fn last_display_name(&self) -> String {
        self.0
            .last()
            .and_then(|name| std::str::from_utf8(name).ok())
            .map(sanitize_display_name)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "Repository".to_owned())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct FileIdentity(Vec<u8>);

#[derive(Clone)]
struct Repository {
    id: RepositoryId,
    entry: EntryRef,
    root_meta: Meta,
    path: RelPath,
    git_marker: Meta,
    gitdir_path: RelPath,
    gitdir: Meta,
    commondir_marker: Option<Meta>,
    common_path: RelPath,
    commondir: Meta,
    gitdir_identity: FileIdentity,
    common_identity: FileIdentity,
}

/// The same physical common-directory lease used by canonical Host Git calls,
/// retained for an approved native Git job. This is admission and exclusion,
/// not proof that Git or a hook has finished. The Host must retain this lease
/// and its durable writer fence until independent process custody has settled.
#[must_use]
pub struct NativeRepositoryMutationLease {
    verifier: GitService,
    repository: Repository,
    repository_path: PathBuf,
    worktree_directory: fs::File,
    request_control: RequestControl,
    _repository_lock: RepoLockGuard,
}

impl NativeRepositoryMutationLease {
    /// Host-selected worktree, resolved through the pinned workspace. This path
    /// is never accepted from a remote request or used to choose another lock.
    pub fn repository_path(&self) -> &Path {
        &self.repository_path
    }

    /// Descriptor for native cwd. Keep it held through process settlement;
    /// never replace it with a fresh pathname-based process launch.
    pub fn worktree_directory(&self) -> &fs::File {
        &self.worktree_directory
    }

    /// Recheck admission after waiting for approval and immediately before
    /// native launch. The caller cannot renew the original request deadline.
    /// Mutable Git metadata is re-read; physical worktree/gitdir/common-dir
    /// replacement or redirection cannot silently change the held lease.
    pub fn revalidate(&self, control: &RequestControl) -> Result<(), GitServiceError> {
        self.request_control.check()?;
        control.check()?;
        let current = self
            .verifier
            .refresh_repository(self.repository.id, &self.request_control)?;
        if current.path != self.repository.path
            || current.entry != self.repository.entry
            || current.gitdir_identity != self.repository.gitdir_identity
            || current.common_identity != self.repository.common_identity
        {
            return Err(GitServiceError::RepositoryChanged);
        }
        // EntryRef(root) can stay constant while the root's former pathname
        // is renamed/replaced. Bind that name to FileRoot's actual descriptor,
        // including the workspace-root case and all no-follow ancestors.
        let _named = self
            .verifier
            .files
            .pin_native_directory(current.entry, &self.repository_path)
            .map_err(map_file_error)?;
        self.request_control.check()?;
        control.check()
    }
}

struct SnapshotEntry {
    path: RelPath,
    meta: Meta,
}

struct PrivateSnapshot {
    directory: tempfile::TempDir,
    state_token: String,
    root: Meta,
    files: HashMap<RelPath, Meta>,
    executable: HashMap<RelPath, bool>,
}

/// A prepared Git index update retaining the physical repository lock until
/// the host actor publishes it inside the live owner/revoke barrier.
pub struct PreparedGitMutation {
    files: Arc<FileRoot>,
    publication: GitPublication,
    request_control: RequestControl,
    post_state: PostStateReader,
    _repository_lock: RepoLockGuard,
}

/// A visible Git mutation whose actual post-publication state token has not
/// yet been captured. It retains the physical-repository lease during that
/// bounded metadata pass.
pub struct PublishedGitMutation {
    post_state: PostStateReader,
    request_control: RequestControl,
    _repository_lock: RepoLockGuard,
}

impl PublishedGitMutation {
    pub fn capture_state_token(
        self,
        control: &RequestControl,
    ) -> Result<RepoStateToken, GitServiceError> {
        self.request_control
            .check()
            .and_then(|()| control.check())
            .map_err(|_| GitServiceError::MutationOutcomeUnknown)?;
        let token = self
            .post_state
            .read(&self.request_control)
            .map_err(|_| GitServiceError::MutationOutcomeUnknown)?;
        self.request_control
            .check()
            .and_then(|()| control.check())
            .map_err(|_| GitServiceError::MutationOutcomeUnknown)?;
        Ok(token)
    }
}

impl PreparedGitMutation {
    /// Publish a prepared index after the host actor rechecks owner authority.
    pub fn publish(self, control: &RequestControl) -> Result<(), GitServiceError> {
        self.publish_guarded(control, || true).map(drop)
    }

    /// Publish and then capture the actual host repository token while the
    /// same physical-repository lease remains held. The capture is metadata
    /// only and does not run Git or WASI. Failure after publication is unknown.
    pub fn publish_for_receipt(
        self,
        control: &RequestControl,
    ) -> Result<RepoStateToken, GitServiceError> {
        self.publish_for_receipt_guarded(control, || true)
    }

    pub fn publish_guarded(
        self,
        control: &RequestControl,
        current_gate: impl Fn() -> bool,
    ) -> Result<PublishedGitMutation, GitServiceError> {
        // Keep the original operation's cancellation and absolute deadline
        // attached to the prepared mutation. A host publication gate may
        // supply an additional control, but it cannot renew this request.
        self.request_control.check()?;
        control.check()?;
        let request_control = self.request_control.clone();
        let outcome = self
            .files
            .publish_git(&self.publication, || {
                request_control.check().is_ok() && control.check().is_ok() && current_gate()
            })
            .map_err(map_mutation_file_error)?;
        match outcome {
            GitPublishOutcome::Published => Ok(PublishedGitMutation {
                post_state: self.post_state,
                request_control: self.request_control,
                _repository_lock: self._repository_lock,
            }),
            GitPublishOutcome::AbortedBeforeFinalRename => {
                Err(control.check().err().unwrap_or(GitServiceError::Cancelled))
            }
            GitPublishOutcome::UncertainAfterFinalRename => {
                Err(GitServiceError::MutationOutcomeUnknown)
            }
        }
    }

    pub fn publish_for_receipt_guarded(
        self,
        control: &RequestControl,
        current_gate: impl Fn() -> bool,
    ) -> Result<RepoStateToken, GitServiceError> {
        self.publish_guarded(control, current_gate)?
            .capture_state_token(control)
    }
}

struct PostStateReader {
    root_path: PathBuf,
    files: Arc<FileRoot>,
    context: WorkspaceContext,
    repository: Repository,
}

impl PostStateReader {
    fn new(service: &GitService, repository: Repository) -> Self {
        Self {
            root_path: service.root_path.clone(),
            files: service.files.clone(),
            context: service.context.clone(),
            repository,
        }
    }

    fn read(&self, control: &RequestControl) -> Result<RepoStateToken, GitServiceError> {
        control.check()?;
        let service = GitService {
            root_path: self.root_path.clone(),
            files: self.files.clone(),
            context: self.context.clone(),
            repositories: Mutex::new(HashMap::new()),
        };
        let snapshot = service.create_snapshot(&self.repository, control)?;
        control.check()?;
        snapshot_token(&snapshot.state_token)
    }
}

impl PrivateSnapshot {
    fn path(&self) -> &Path {
        self.directory.path()
    }
}

/// Git service pinned to one host-selected workspace and a full RPC context.
/// The constructor accepts host paths only; client DTOs never carry paths.
pub struct GitService {
    root_path: PathBuf,
    files: Arc<FileRoot>,
    context: WorkspaceContext,
    repositories: Mutex<HashMap<RepositoryId, Repository>>,
}

impl GitService {
    pub fn open(
        host_workspace_root: &Path,
        host_protected_paths: &[&Path],
        context: WorkspaceContext,
    ) -> Result<Self, GitServiceError> {
        let files =
            FileRoot::open(host_workspace_root, host_protected_paths).map_err(map_file_error)?;
        // This path is retained only to derive process-wide alias identities
        // and protect validated metadata. Traversal and admission use FileRoot.
        let root_path = host_workspace_root
            .canonicalize()
            .map_err(|_| GitServiceError::DiscoveryFailed)?;
        Ok(Self {
            root_path,
            files: Arc::new(files),
            context,
            repositories: Mutex::new(HashMap::new()),
        })
    }

    /// Discover repositories below this service's pinned workspace.
    pub fn repositories(
        &self,
        params: WorkspaceReadParams,
        control: &RequestControl,
    ) -> Result<GitRepositoriesResult, GitServiceError> {
        self.check_context(&params.context)?;
        let found = self.scan_repositories(control)?;
        let mut repositories = Vec::with_capacity(found.len());
        let mut cache = HashMap::with_capacity(found.len());
        for repo in found {
            control.check()?;
            let display_name = DisplayText::try_from(repo.path.last_display_name())
                .map_err(|_| GitServiceError::UnsafeRepository)?;
            let remotes = self.remote_descriptions(&repo, control)?;
            repositories.push(GitRepository {
                repository_id: repo.id,
                display_name,
                remotes: BoundedList(remotes),
            });
            cache.insert(repo.id, repo);
        }
        *self
            .repositories
            .lock()
            .map_err(|_| GitServiceError::DiscoveryFailed)? = cache;
        Ok(GitRepositoriesResult {
            repositories: BoundedList(repositories),
        })
    }

    /// Resolve an exact repository directory inside the pinned workspace.
    /// This uses the same FileRoot-backed discovery and gitdir/common-dir
    /// identity calculation as normal RPC requests, without spawning Git or
    /// exposing repository paths over the wire.
    pub fn repository_id_for_path(
        &self,
        repository_path: &Path,
        control: &RequestControl,
    ) -> Result<RepositoryId, GitServiceError> {
        control.check()?;
        let repository_path = repository_path
            .canonicalize()
            .map_err(|_| GitServiceError::RepositoryNotFound)?;
        if !repository_path.starts_with(&self.root_path) || !repository_path.is_dir() {
            return Err(GitServiceError::RepositoryNotFound);
        }

        let mut matching = self
            .scan_repositories(control)?
            .into_iter()
            .filter_map(|repository| {
                (repository.path.to_host_path(&self.root_path).ok()? == repository_path)
                    .then_some(repository.id)
            });
        let repository_id = matching.next().ok_or(GitServiceError::RepositoryNotFound)?;
        if matching.next().is_some() {
            return Err(GitServiceError::UnsafeRepository);
        }
        control.check()?;
        Ok(repository_id)
    }

    /// Admit an owner-local native Git job under the exact physical lock used
    /// by status, diff, index publication and network operations. Resolving a
    /// second workspace or linked worktree cannot create an independent lock
    /// for the same Git common directory. This API neither spawns a process nor
    /// grants permission to execute hooks; approval remains the Host's duty.
    pub fn acquire_native_repository_lease(
        &self,
        repository_id: RepositoryId,
        control: &RequestControl,
    ) -> Result<NativeRepositoryMutationLease, GitServiceError> {
        control.check()?;
        let repository = self.refresh_repository(repository_id, control)?;
        let repository_lock =
            common_repository_lock(&repository.common_identity).acquire(control)?;
        let repository_path = repository.path.to_host_path(&self.root_path)?;
        let worktree_directory = self
            .files
            .pin_native_directory(repository.entry, &repository_path)
            .map_err(map_file_error)?;
        let lease = NativeRepositoryMutationLease {
            verifier: Self {
                root_path: self.root_path.clone(),
                files: self.files.clone(),
                context: self.context.clone(),
                repositories: Mutex::new(HashMap::new()),
            },
            repository,
            repository_path,
            worktree_directory,
            request_control: control.clone(),
            _repository_lock: repository_lock,
        };
        lease.revalidate(control)?;
        Ok(lease)
    }

    pub fn status(
        &self,
        params: GitStatusParams,
        control: &RequestControl,
    ) -> Result<GitStatusResult, GitServiceError> {
        self.check_context(&params.context)?;
        control.check()?;
        let repository = self.refresh_repository(params.repository_id, control)?;
        let _lock = common_repository_lock(&repository.common_identity).acquire(control)?;
        let snapshot = self.create_snapshot(&repository, control)?;
        if params
            .state_token
            .as_ref()
            .is_some_and(|token| token.as_str() != snapshot.state_token)
        {
            return Err(GitServiceError::StaleState);
        }
        let offset = parse_status_cursor(
            params.cursor.as_ref(),
            params.state_token.as_ref(),
            &snapshot.state_token,
        )?;
        let page_limit = params.limit.0 as usize;
        let worker = worker::run_status(snapshot.path(), offset, page_limit + 1, control)?;
        control.check()?;
        if worker.total > MAX_SNAPSHOT_ENTRIES || worker.entries.len() > page_limit + 1 {
            return Err(GitServiceError::ResourceLimit);
        }
        if offset > worker.total {
            return Err(GitServiceError::InvalidCursor);
        }

        let head = state_token(worker.head.as_bytes());
        let index = index_token(snapshot.path())?;
        let page_len = worker.entries.len().min(page_limit);
        let has_more = worker.entries.len() > page_limit || worker.truncated;
        let mut entries = Vec::with_capacity(page_len);
        for row in worker.entries.into_iter().take(page_limit) {
            control.check()?;
            entries.push(map_status_entry(
                repository.id,
                row,
                &snapshot.files,
                &snapshot.state_token,
            )?);
        }
        let next_offset = offset
            .checked_add(page_len)
            .ok_or(GitServiceError::ResourceLimit)?;
        let next_cursor = if has_more {
            if next_offset > MAX_SNAPSHOT_ENTRIES {
                return Err(GitServiceError::ResourceLimit);
            }
            Some(
                EventCursor::try_from(format!("{next_offset}_{}", snapshot.state_token))
                    .map_err(|_| GitServiceError::ResourceLimit)?,
            )
        } else {
            None
        };
        Ok(GitStatusResult {
            state_token: RepoStateToken::try_from(snapshot.state_token.clone())
                .map_err(|_| GitServiceError::ExecutorFailed)?,
            head,
            index,
            entries: BoundedList(entries),
            next_cursor,
            truncated: has_more,
        })
    }

    pub fn diff(
        &self,
        params: GitDiffParams,
        control: &RequestControl,
    ) -> Result<GitDiffResult, GitServiceError> {
        self.check_context(&params.context)?;
        control.check()?;
        let repository = self.refresh_repository(params.repository_id, control)?;
        let _lock = common_repository_lock(&repository.common_identity).acquire(control)?;
        let snapshot = self.create_snapshot(&repository, control)?;
        check_snapshot_token(&params.state_token, &snapshot.state_token)?;

        let view = match params.view {
            DiffView::Index => "index",
            DiffView::Worktree => "worktree",
        };
        let entry_id = params.entry_id.as_ref();
        let path_filter_hex = entry_id
            .and_then(|entry_id| snapshot_path_for_entry(&snapshot, entry_id))
            .map(|path| encode_hex(&path));
        let entry_filter_hex = entry_id.map(|entry_id| encode_hex(&entry_id.to_bytes()));
        let repository_id_hex = encode_hex(&repository.id.to_bytes());
        let binding = cursor_binding(
            "diff",
            &snapshot.state_token,
            &[view, entry_filter_hex.as_deref().unwrap_or("")],
        );
        let offset = parse_bound_cursor(params.cursor.as_ref(), &binding)?;
        let page_limit = params.limit.0 as usize;
        let worker = worker::run_diff(
            snapshot.path(),
            view,
            offset,
            page_limit + 1,
            path_filter_hex.as_deref(),
            entry_filter_hex.as_deref(),
            &repository_id_hex,
            control,
        )?;
        control.check()?;
        if worker.total > MAX_SNAPSHOT_ENTRIES || worker.files.len() > page_limit + 1 {
            return Err(GitServiceError::ResourceLimit);
        }
        if offset > worker.total {
            return Err(GitServiceError::InvalidCursor);
        }
        let page_len = worker.files.len().min(page_limit);
        let has_more = worker.files.len() > page_limit || worker.truncated;
        let files = worker
            .files
            .into_iter()
            .take(page_limit)
            .map(|row| map_diff_file(repository.id, &snapshot, row))
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = if has_more {
            Some(make_bound_cursor(
                offset
                    .checked_add(page_len)
                    .ok_or(GitServiceError::ResourceLimit)?,
                &binding,
            )?)
        } else {
            None
        };
        Ok(GitDiffResult {
            state_token: snapshot_token(&snapshot.state_token)?,
            files: BoundedList(files),
            next_cursor,
            truncated: has_more,
        })
    }

    pub fn log(
        &self,
        params: GitLogParams,
        control: &RequestControl,
    ) -> Result<GitLogResult, GitServiceError> {
        self.check_context(&params.context)?;
        control.check()?;
        let repository = self.refresh_repository(params.repository_id, control)?;
        let _lock = common_repository_lock(&repository.common_identity).acquire(control)?;
        let snapshot = self.create_snapshot(&repository, control)?;
        check_snapshot_token(&params.state_token, &snapshot.state_token)?;

        let binding = cursor_binding("log", &snapshot.state_token, &[]);
        let offset = parse_bound_cursor(params.cursor.as_ref(), &binding)?;
        let page_limit = params.limit.0 as usize;
        let worker = worker::run_log(snapshot.path(), offset, page_limit + 1, control)?;
        control.check()?;
        if worker.total > MAX_SNAPSHOT_ENTRIES || worker.commits.len() > page_limit + 1 {
            return Err(GitServiceError::ResourceLimit);
        }
        if offset > worker.total {
            return Err(GitServiceError::InvalidCursor);
        }
        let page_len = worker.commits.len().min(page_limit);
        let has_more = worker.commits.len() > page_limit || worker.truncated;
        let commits = worker
            .commits
            .into_iter()
            .take(page_limit)
            .map(map_commit_summary)
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = if has_more {
            Some(make_bound_cursor(
                offset
                    .checked_add(page_len)
                    .ok_or(GitServiceError::ResourceLimit)?,
                &binding,
            )?)
        } else {
            None
        };
        Ok(GitLogResult {
            state_token: snapshot_token(&snapshot.state_token)?,
            commits: BoundedList(commits),
            next_cursor,
            truncated: has_more,
        })
    }

    pub fn show(
        &self,
        params: GitShowParams,
        control: &RequestControl,
    ) -> Result<GitShowResult, GitServiceError> {
        self.check_context(&params.context)?;
        control.check()?;
        let repository = self.refresh_repository(params.repository_id, control)?;
        let _lock = common_repository_lock(&repository.common_identity).acquire(control)?;
        let snapshot = self.create_snapshot(&repository, control)?;
        check_snapshot_token(&params.state_token, &snapshot.state_token)?;
        let object_id = validate_object_id(params.object_id.as_str())?;
        let binding = cursor_binding("show", &snapshot.state_token, &[params.object_id.as_str()]);
        let offset = parse_bound_cursor(params.cursor.as_ref(), &binding)?;
        let page_limit = params.limit.0 as usize;
        let (commit, worker) =
            worker::run_show(snapshot.path(), &object_id, offset, page_limit + 1, control)?;
        control.check()?;
        if worker.total > MAX_SNAPSHOT_ENTRIES || worker.files.len() > page_limit + 1 {
            return Err(GitServiceError::ResourceLimit);
        }
        if offset > worker.total {
            return Err(GitServiceError::InvalidCursor);
        }
        let page_len = worker.files.len().min(page_limit);
        let has_more = worker.files.len() > page_limit || worker.truncated;
        let files = worker
            .files
            .into_iter()
            .take(page_limit)
            .map(|row| map_diff_file(repository.id, &snapshot, row))
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = if has_more {
            Some(make_bound_cursor(
                offset
                    .checked_add(page_len)
                    .ok_or(GitServiceError::ResourceLimit)?,
                &binding,
            )?)
        } else {
            None
        };
        Ok(GitShowResult {
            commit: map_commit_summary(commit)?,
            diff: GitDiffResult {
                state_token: snapshot_token(&snapshot.state_token)?,
                files: BoundedList(files),
                next_cursor,
                truncated: has_more,
            },
        })
    }

    /// Prepare stage from the exact worktree revisions named by the request.
    /// The returned value retains the physical repository lock and must be
    /// published by the host inside its current owner/revoke write barrier.
    pub fn prepare_stage(
        &self,
        params: GitStageParams,
        control: &RequestControl,
    ) -> Result<PreparedGitMutation, GitServiceError> {
        self.check_context(&params.mutation.context)?;
        control.check()?;
        if params.paths.0.is_empty() || params.paths.0.len() > 200 {
            return Err(GitServiceError::ResourceLimit);
        }
        let repository = self.refresh_repository(params.repository_id, control)?;
        let repository_lock =
            common_repository_lock(&repository.common_identity).acquire(control)?;
        let snapshot = self.create_snapshot(&repository, control)?;
        let first_status = worker::run_status(snapshot.path(), 0, 201, control)?;
        check_mutation_preconditions(&params.expected, &snapshot, &first_status.head)?;

        let mut requested = HashMap::<[u8; 16], String>::with_capacity(params.paths.0.len());
        for path in params.paths.0 {
            if requested
                .insert(
                    path.entry_id.to_bytes(),
                    path.file_revision.as_str().to_owned(),
                )
                .is_some()
            {
                return Err(GitServiceError::MutationConflict);
            }
        }
        let mut resolved = HashMap::<[u8; 16], (Vec<u8>, Option<Meta>, String)>::new();
        let mut unresolved = HashSet::new();
        for entry_id in requested.keys() {
            if let Some((path, meta)) = find_snapshot_entry(&snapshot, entry_id) {
                if meta.kind != Kind::File {
                    return Err(GitServiceError::MutationConflict);
                }
                resolved.insert(
                    *entry_id,
                    (
                        encode_relative_path(path),
                        Some(meta.clone()),
                        meta.revision.clone(),
                    ),
                );
            } else {
                unresolved.insert(*entry_id);
            }
        }

        let mut status_page = first_status;
        let mut offset = 0usize;
        loop {
            for row in status_page.entries {
                let path = decode_path_hex(&row.path_hex)?;
                let relative = git_relative_path(&path)?;
                let meta = snapshot.files.get(&relative).cloned();
                let entry_id = match &meta {
                    Some(meta) => meta.entry.to_bytes(),
                    None => path_entry_id(repository.id, &path).to_bytes(),
                };
                if !unresolved.contains(&entry_id) {
                    continue;
                }
                if meta.as_ref().is_some_and(|meta| meta.kind != Kind::File)
                    || row.worktree.as_deref() != Some("deleted")
                {
                    return Err(GitServiceError::MutationConflict);
                }
                let revision = token_hex(
                    Sha256::digest([snapshot.state_token.as_bytes(), &path].concat()).as_slice(),
                );
                resolved.insert(entry_id, (path, meta, revision));
                unresolved.remove(&entry_id);
            }
            if unresolved.is_empty() || !status_page.truncated {
                break;
            }
            offset = offset
                .checked_add(201)
                .ok_or(GitServiceError::ResourceLimit)?;
            if offset > MAX_SNAPSHOT_ENTRIES {
                return Err(GitServiceError::ResourceLimit);
            }
            status_page = worker::run_status(snapshot.path(), offset, 201, control)?;
        }
        if !unresolved.is_empty() {
            return Err(GitServiceError::MutationConflict);
        }

        let mut worktree_preconditions = Vec::with_capacity(requested.len());
        let mut stage_paths = Vec::with_capacity(requested.len());
        let mut seen_paths = HashSet::with_capacity(requested.len());
        for (entry_id, expected_revision) in requested {
            let (path, meta, revision) = resolved
                .remove(&entry_id)
                .ok_or(GitServiceError::MutationConflict)?;
            if revision != expected_revision {
                return Err(GitServiceError::MutationConflict);
            }
            if !allowed_git_path(&path) || !seen_paths.insert(path.clone()) {
                return Err(GitServiceError::MutationConflict);
            }
            let relative = git_relative_path(&path)?;
            let executable = snapshot.executable.get(&relative).copied().unwrap_or(false);
            worktree_preconditions.push(worktree_path_precondition(&snapshot, &relative, meta)?);
            stage_paths.push((path, executable));
        }

        let guest = worker::run_stage(snapshot.path(), &stage_paths, control)?;
        control.check()?;
        let publication = make_index_publication(&repository, &snapshot, guest.object_ids)?;
        Ok(PreparedGitMutation {
            files: self.files.clone(),
            publication: GitPublication {
                worktree_preconditions,
                ..publication
            },
            request_control: control.clone(),
            post_state: PostStateReader::new(self, repository.clone()),
            _repository_lock: repository_lock,
        })
    }

    /// Prepare unstage by restoring the selected index paths from HEAD.
    pub fn prepare_unstage(
        &self,
        params: GitUnstageParams,
        control: &RequestControl,
    ) -> Result<PreparedGitMutation, GitServiceError> {
        self.check_context(&params.mutation.context)?;
        control.check()?;
        if params.paths.0.is_empty() || params.paths.0.len() > 200 {
            return Err(GitServiceError::ResourceLimit);
        }
        let repository = self.refresh_repository(params.repository_id, control)?;
        let repository_lock =
            common_repository_lock(&repository.common_identity).acquire(control)?;
        let snapshot = self.create_snapshot(&repository, control)?;
        let first_status = worker::run_status(snapshot.path(), 0, 201, control)?;
        check_mutation_preconditions(&params.expected, &snapshot, &first_status.head)?;

        let requested: HashSet<[u8; 16]> = params
            .paths
            .0
            .iter()
            .map(|entry_id| entry_id.to_bytes())
            .collect();
        if requested.len() != params.paths.0.len() {
            return Err(GitServiceError::MutationConflict);
        }
        let mut resolved = HashMap::<[u8; 16], Vec<u8>>::with_capacity(requested.len());
        let mut unresolved = HashSet::new();
        for entry_id in &requested {
            if let Some((path, meta)) = find_snapshot_entry(&snapshot, entry_id) {
                if meta.kind != Kind::File {
                    return Err(GitServiceError::MutationConflict);
                }
                resolved.insert(*entry_id, encode_relative_path(path));
            } else {
                unresolved.insert(*entry_id);
            }
        }
        let mut status_page = first_status;
        let mut offset = 0usize;
        loop {
            for row in status_page.entries {
                let path = decode_path_hex(&row.path_hex)?;
                let relative = git_relative_path(&path)?;
                let meta = snapshot.files.get(&relative);
                let entry_id = match meta {
                    Some(meta) => meta.entry.to_bytes(),
                    None => path_entry_id(repository.id, &path).to_bytes(),
                };
                if unresolved.remove(&entry_id) {
                    resolved.insert(entry_id, path);
                }
            }
            if unresolved.is_empty() || !status_page.truncated {
                break;
            }
            offset = offset
                .checked_add(201)
                .ok_or(GitServiceError::ResourceLimit)?;
            if offset > MAX_SNAPSHOT_ENTRIES {
                return Err(GitServiceError::ResourceLimit);
            }
            status_page = worker::run_status(snapshot.path(), offset, 201, control)?;
        }
        if !unresolved.is_empty() {
            return Err(GitServiceError::MutationConflict);
        }
        let paths = requested
            .iter()
            .map(|entry_id| {
                let path = resolved
                    .get(entry_id)
                    .ok_or(GitServiceError::MutationConflict)?;
                if path.len() > 3072 || !allowed_git_path(path) {
                    return Err(GitServiceError::MutationConflict);
                }
                Ok(path.clone())
            })
            .collect::<Result<Vec<_>, GitServiceError>>()?;
        let guest = worker::run_unstage(snapshot.path(), &paths, control)?;
        control.check()?;
        let publication = make_index_publication(&repository, &snapshot, guest.object_ids)?;
        Ok(PreparedGitMutation {
            files: self.files.clone(),
            publication,
            request_control: control.clone(),
            post_state: PostStateReader::new(self, repository.clone()),
            _repository_lock: repository_lock,
        })
    }

    /// Prepare a commit from the private index and publish it by advancing
    /// the current branch reference (or detached HEAD). The returned
    /// mutation retains the physical repository lock until the host actor
    /// publishes it under the live owner/revoke barrier.
    pub fn prepare_commit(
        &self,
        params: GitCommitParams,
        control: &RequestControl,
    ) -> Result<PreparedGitMutation, GitServiceError> {
        self.check_context(&params.mutation.context)?;
        control.check()?;
        let repository = self.refresh_repository(params.repository_id, control)?;
        let repository_lock =
            common_repository_lock(&repository.common_identity).acquire(control)?;
        let snapshot = self.create_snapshot(&repository, control)?;
        let status = worker::run_status(snapshot.path(), 0, 1, control)?;
        check_mutation_preconditions(&params.expected, &snapshot, &status.head)?;

        let timestamp_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| GitServiceError::MutationFailed)?
            .as_secs()
            .try_into()
            .map_err(|_| GitServiceError::MutationFailed)?;
        let guest = worker::run_commit(
            snapshot.path(),
            params.message.as_str(),
            timestamp_seconds,
            control,
        )?;
        control.check()?;
        let commit_id = guest
            .commit_id
            .as_deref()
            .ok_or(GitServiceError::ExecutorFailed)?;
        let commit_id = validate_object_id(commit_id)?;
        if !guest
            .object_ids
            .iter()
            .any(|object_id| object_id == &commit_id)
        {
            return Err(GitServiceError::ExecutorFailed);
        }
        let publication =
            make_commit_publication(&repository, &snapshot, guest.object_ids, &commit_id)?;
        Ok(PreparedGitMutation {
            files: self.files.clone(),
            publication,
            request_control: control.clone(),
            post_state: PostStateReader::new(self, repository.clone()),
            _repository_lock: repository_lock,
        })
    }

    fn refresh_repository(
        &self,
        repository_id: RepositoryId,
        control: &RequestControl,
    ) -> Result<Repository, GitServiceError> {
        let found = self.scan_repositories(control)?;
        let mut cache = HashMap::with_capacity(found.len());
        for repository in found {
            cache.insert(repository.id, repository);
        }
        let repository = cache
            .get(&repository_id)
            .cloned()
            .ok_or(GitServiceError::RepositoryNotFound)?;
        *self
            .repositories
            .lock()
            .map_err(|_| GitServiceError::DiscoveryFailed)? = cache;
        Ok(repository)
    }

    fn create_snapshot(
        &self,
        repository: &Repository,
        control: &RequestControl,
    ) -> Result<PrivateSnapshot, GitServiceError> {
        control.check()?;
        if repository.git_marker.kind != Kind::Directory
            || repository.gitdir_identity != repository.common_identity
        {
            return Err(GitServiceError::UnsafeRepository);
        }
        self.revalidate_entry(&repository.root_meta, control)?;
        self.revalidate_entry(&repository.git_marker, control)?;
        self.revalidate_entry(&repository.gitdir, control)?;
        self.revalidate_entry(&repository.commondir, control)?;

        let mut entries = Vec::new();
        let mut entry_count = 0usize;
        let mut total_bytes = 0u64;
        self.collect_snapshot_entries(
            repository.entry,
            RelPath::root(),
            0,
            &mut entry_count,
            &mut total_bytes,
            &mut entries,
            control,
        )?;
        entries.sort_by(|a, b| {
            a.path
                .0
                .len()
                .cmp(&b.path.0.len())
                .then_with(|| a.path.cmp(&b.path))
        });
        for entry in &entries {
            control.check()?;
            if entry.path.0.len() > 1 && entry.path.0[1..].iter().any(|part| part == b".git") {
                return Err(GitServiceError::UnsafeRepository);
            }
            // Never reinterpret a link anywhere in Git metadata as an
            // ordinary private file. Repository discovery already rejects a
            // linked .git marker; this also protects config/objects/ref paths.
            if entry.path.0.first().is_some_and(|part| part == b".git")
                && entry.meta.kind == Kind::Symlink
            {
                return Err(GitServiceError::UnsafeRepository);
            }
        }

        let directory = tempfile::Builder::new()
            .prefix("lomi-git-read-")
            .tempdir()
            .map_err(|_| GitServiceError::DiscoveryFailed)?;
        for entry in &entries {
            if entry.meta.kind == Kind::Directory {
                let destination = entry.path.to_host_path(directory.path())?;
                fs::create_dir(&destination).map_err(|_| GitServiceError::DiscoveryFailed)?;
            }
        }

        let mut executable = HashMap::<RelPath, bool>::new();
        for entry in entries.iter().filter(|entry| entry.meta.kind == Kind::File) {
            control.check()?;
            if entry.meta.size > MAX_SNAPSHOT_FILE_BYTES {
                return Err(GitServiceError::ResourceLimit);
            }
            let destination = entry.path.to_host_path(directory.path())?;
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&destination)
                .map_err(|_| GitServiceError::DiscoveryFailed)?;
            let mut offset = 0u64;
            let mut mode = None;
            while offset < entry.meta.size || (entry.meta.size == 0 && mode.is_none()) {
                control.check()?;
                let chunk = self
                    .files
                    .read_snapshot_chunk(
                        entry.meta.entry,
                        &entry.meta.revision,
                        offset,
                        SNAPSHOT_READ_CHUNK,
                    )
                    .map_err(map_file_error)?;
                if chunk.meta.revision != entry.meta.revision
                    || chunk.offset != offset
                    || chunk.bytes.len() > SNAPSHOT_READ_CHUNK
                {
                    return Err(GitServiceError::RepositoryChanged);
                }
                match mode {
                    Some(previous) if previous != chunk.executable => {
                        return Err(GitServiceError::RepositoryChanged);
                    }
                    None => mode = Some(chunk.executable),
                    _ => {}
                }
                if chunk.bytes.is_empty() && offset < entry.meta.size {
                    return Err(GitServiceError::RepositoryChanged);
                }
                output
                    .write_all(&chunk.bytes)
                    .map_err(|_| GitServiceError::DiscoveryFailed)?;
                offset = offset
                    .checked_add(chunk.bytes.len() as u64)
                    .ok_or(GitServiceError::ResourceLimit)?;
                if offset > entry.meta.size {
                    return Err(GitServiceError::RepositoryChanged);
                }
                if entry.meta.size == 0 {
                    break;
                }
            }
            if offset != entry.meta.size {
                return Err(GitServiceError::RepositoryChanged);
            }
            output
                .flush()
                .map_err(|_| GitServiceError::DiscoveryFailed)?;
            let is_executable = mode.unwrap_or(false);
            set_snapshot_executable(&destination, is_executable)?;
            executable.insert(entry.path.clone(), is_executable);
        }

        let mut has_symlinks = false;
        for entry in entries
            .iter()
            .filter(|entry| entry.meta.kind == Kind::Symlink)
        {
            control.check()?;
            let target = self
                .files
                .readlink_snapshot(
                    entry.meta.entry,
                    &entry.meta.revision,
                    MAX_SNAPSHOT_SYMLINK_BYTES,
                )
                .map_err(|error| match error {
                    FileError::Unsupported => GitServiceError::UnsupportedCapability,
                    other => map_file_error(other),
                })?;
            if target.is_empty() || target.contains(&0) {
                return Err(GitServiceError::UnsafeRepository);
            }
            total_bytes = total_bytes
                .checked_add(target.len() as u64)
                .ok_or(GitServiceError::ResourceLimit)?;
            if total_bytes > MAX_SNAPSHOT_TOTAL_BYTES {
                return Err(GitServiceError::ResourceLimit);
            }
            let destination = entry.path.to_host_path(directory.path())?;
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&destination)
                .map_err(|_| GitServiceError::DiscoveryFailed)?;
            output
                .write_all(&target)
                .and_then(|_| output.flush())
                .map_err(|_| GitServiceError::DiscoveryFailed)?;
            executable.insert(entry.path.clone(), false);
            has_symlinks = true;
        }
        if has_symlinks {
            // Keep link targets as ordinary private files. gix's
            // core.symlinks=false mode compares mode-120000 index entries to
            // regular files containing the link bytes without resolving any
            // target in the private snapshot.
            let config = directory.path().join(".git").join("config");
            let mut output = OpenOptions::new()
                .create(true)
                .append(true)
                .open(config)
                .map_err(|_| GitServiceError::DiscoveryFailed)?;
            output
                .write_all(b"\n[core]\n\tsymlinks = false\n")
                .and_then(|_| output.flush())
                .map_err(|_| GitServiceError::DiscoveryFailed)?;
        }

        let mut after = Vec::new();
        let mut after_count = 0usize;
        let mut after_bytes = 0u64;
        self.collect_snapshot_entries(
            repository.entry,
            RelPath::root(),
            0,
            &mut after_count,
            &mut after_bytes,
            &mut after,
            control,
        )?;
        if !same_manifest(&entries, &after) {
            return Err(GitServiceError::RepositoryChanged);
        }
        self.revalidate_entry(&repository.root_meta, control)?;
        self.revalidate_entry(&repository.git_marker, control)?;
        self.revalidate_entry(&repository.gitdir, control)?;
        self.revalidate_entry(&repository.commondir, control)?;

        let mut digest = Sha256::new();
        digest.update(b"lomi-git-snapshot-v1\0");
        digest.update(repository.id.to_bytes());
        digest.update(repository.root_meta.revision.as_bytes());
        let mut files = HashMap::with_capacity(entries.len());
        for entry in &entries {
            update_path_hash(&mut digest, &entry.path);
            digest.update([kind_tag(entry.meta.kind)]);
            digest.update(entry.meta.size.to_le_bytes());
            digest.update(entry.meta.nlink.to_le_bytes());
            digest.update(entry.meta.revision.as_bytes());
            digest.update([u8::from(
                executable.get(&entry.path).copied().unwrap_or(false),
            )]);
            files.insert(entry.path.clone(), entry.meta.clone());
        }
        let state_token = token_hex(digest.finalize().as_slice());
        Ok(PrivateSnapshot {
            directory,
            state_token,
            root: repository.root_meta.clone(),
            files,
            executable,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn collect_snapshot_entries(
        &self,
        directory: EntryRef,
        relative: RelPath,
        depth: usize,
        count: &mut usize,
        total_bytes: &mut u64,
        entries: &mut Vec<SnapshotEntry>,
        control: &RequestControl,
    ) -> Result<(), GitServiceError> {
        control.check()?;
        if depth > MAX_SNAPSHOT_DEPTH {
            return Err(GitServiceError::ResourceLimit);
        }
        let mut cursor: Option<Vec<u8>> = None;
        let mut cursors = HashSet::new();
        loop {
            control.check()?;
            let page = self
                .files
                .list(directory, cursor.as_deref(), MAX_PAGE_SIZE)
                .map_err(map_file_error)?;
            for meta in page.entries {
                control.check()?;
                *count = count.saturating_add(1);
                if *count > MAX_SNAPSHOT_ENTRIES {
                    return Err(GitServiceError::ResourceLimit);
                }
                if meta.kind == Kind::Other {
                    return Err(GitServiceError::UnsafeRepository);
                }
                if meta.kind == Kind::Symlink && meta.nlink != 1 {
                    return Err(GitServiceError::UnsafeRepository);
                }
                if meta.kind == Kind::File {
                    if meta.nlink != 1 || meta.size > MAX_SNAPSHOT_FILE_BYTES {
                        return Err(if meta.nlink != 1 {
                            GitServiceError::UnsafeRepository
                        } else {
                            GitServiceError::ResourceLimit
                        });
                    }
                    *total_bytes = total_bytes
                        .checked_add(meta.size)
                        .ok_or(GitServiceError::ResourceLimit)?;
                    if *total_bytes > MAX_SNAPSHOT_TOTAL_BYTES {
                        return Err(GitServiceError::ResourceLimit);
                    }
                }
                let path = relative.joined(&meta.name);
                entries.push(SnapshotEntry {
                    path: path.clone(),
                    meta: meta.clone(),
                });
                if meta.kind == Kind::Directory {
                    self.collect_snapshot_entries(
                        meta.entry,
                        path,
                        depth + 1,
                        count,
                        total_bytes,
                        entries,
                        control,
                    )?;
                }
            }
            match page.next {
                Some(next) if page.truncated => {
                    if !cursors.insert(next.clone()) {
                        return Err(GitServiceError::DiscoveryFailed);
                    }
                    cursor = Some(next);
                }
                Some(_) | None if page.truncated => {
                    return Err(GitServiceError::DiscoveryFailed);
                }
                None => break,
                Some(_) => return Err(GitServiceError::DiscoveryFailed),
            }
        }
        Ok(())
    }

    fn check_context(&self, context: &WorkspaceContext) -> Result<(), GitServiceError> {
        if context == &self.context {
            Ok(())
        } else {
            Err(GitServiceError::ContextMismatch)
        }
    }

    fn scan_repositories(
        &self,
        control: &RequestControl,
    ) -> Result<Vec<Repository>, GitServiceError> {
        let mut directories = Vec::new();
        let mut entries_seen = 0usize;
        self.scan_dirs(
            self.files.root_entry(),
            RelPath::root(),
            0,
            &mut entries_seen,
            &mut directories,
            control,
        )?;

        let mut repositories = Vec::with_capacity(directories.len());
        for (repo_entry, repo_path, marker) in directories {
            control.check()?;
            let (gitdir_path, gitdir_meta) = match marker.kind {
                Kind::Directory => (repo_path.joined(b".git"), marker.clone()),
                Kind::File => {
                    if marker.nlink != 1 {
                        return Err(GitServiceError::UnsafeRepository);
                    }
                    let text = self.read_pointer(&marker)?;
                    let target = parse_pointer(&text, "gitdir: ")?;
                    let path = repo_path.resolve_relative(target)?;
                    let metadata = self.lookup_path(&path, control)?;
                    if metadata.kind != Kind::Directory {
                        return Err(GitServiceError::UnsafeRepository);
                    }
                    (path, metadata)
                }
                Kind::Symlink | Kind::Other => return Err(GitServiceError::UnsafeRepository),
            };

            let gitdir_entry = if marker.kind == Kind::Directory {
                marker.entry
            } else {
                gitdir_meta.entry
            };
            let mut common_path = gitdir_path.clone();
            let mut common_meta = gitdir_meta.clone();
            let commondir_marker =
                self.lookup_optional_child(gitdir_entry, &gitdir_path, b"commondir", control)?;
            if let Some(common_marker) = commondir_marker.as_ref() {
                if common_marker.kind != Kind::File || common_marker.nlink != 1 {
                    return Err(GitServiceError::UnsafeRepository);
                }
                let text = self.read_pointer(&common_marker)?;
                let target = parse_pointer(&text, "")?;
                common_path = gitdir_path.resolve_relative(target)?;
                common_meta = self.lookup_path(&common_path, control)?;
                if common_meta.kind != Kind::Directory {
                    return Err(GitServiceError::UnsafeRepository);
                }
            }

            let marker_path = repo_path.joined(b".git").to_host_path(&self.root_path)?;
            let gitdir_host_path = gitdir_path.to_host_path(&self.root_path)?;
            let common_host_path = common_path.to_host_path(&self.root_path)?;
            // FileRoot's entry/revision checks establish admission. These
            // filesystem IDs only unify advisory locks for stable aliases.
            self.revalidate_entry(&marker, control)?;
            self.revalidate_entry(&gitdir_meta, control)?;
            self.revalidate_entry(&common_meta, control)?;
            self.files.protect(&marker_path).map_err(map_file_error)?;
            self.files
                .protect(&gitdir_host_path)
                .map_err(map_file_error)?;
            self.files
                .protect(&common_host_path)
                .map_err(map_file_error)?;

            let gitdir_identity = path_identity(&gitdir_host_path)?;
            let common_identity = path_identity(&common_host_path)?;
            let id = repository_id(&gitdir_identity, &common_identity);
            let root_meta = self.files.stat(repo_entry, None).map_err(map_file_error)?;
            repositories.push(Repository {
                id,
                entry: repo_entry,
                root_meta,
                path: repo_path,
                git_marker: marker,
                gitdir_path,
                gitdir: gitdir_meta,
                commondir_marker,
                common_path,
                commondir: common_meta,
                gitdir_identity,
                common_identity,
            });
        }
        if repositories.len() > 32 {
            return Err(GitServiceError::ResourceLimit);
        }
        repositories.sort_by_key(|repo| repo.id);
        Ok(repositories)
    }

    fn scan_dirs(
        &self,
        directory: EntryRef,
        path: RelPath,
        depth: usize,
        entries_seen: &mut usize,
        found: &mut Vec<(EntryRef, RelPath, Meta)>,
        control: &RequestControl,
    ) -> Result<(), GitServiceError> {
        control.check()?;
        if depth > MAX_DISCOVERY_DEPTH {
            return Err(GitServiceError::ResourceLimit);
        }
        let mut cursor: Option<Vec<u8>> = None;
        let mut cursors = HashSet::new();
        loop {
            control.check()?;
            let page = self
                .files
                .list(directory, cursor.as_deref(), MAX_PAGE_SIZE)
                .map_err(map_file_error)?;
            for item in page.entries {
                control.check()?;
                *entries_seen = entries_seen.saturating_add(1);
                if *entries_seen > MAX_DISCOVERY_ENTRIES {
                    return Err(GitServiceError::ResourceLimit);
                }
                let child_path = path.joined(&item.name);
                if item.name == b".git" {
                    found.push((directory, path.clone(), item));
                    if found.len() > 32 {
                        return Err(GitServiceError::ResourceLimit);
                    }
                } else if item.kind == Kind::Directory {
                    self.scan_dirs(
                        item.entry,
                        child_path,
                        depth + 1,
                        entries_seen,
                        found,
                        control,
                    )?;
                }
            }
            match page.next {
                Some(next) if page.truncated => {
                    if !cursors.insert(next.clone()) {
                        return Err(GitServiceError::DiscoveryFailed);
                    }
                    cursor = Some(next);
                }
                Some(_) => return Err(GitServiceError::DiscoveryFailed),
                None if page.truncated => return Err(GitServiceError::DiscoveryFailed),
                None => break,
            }
        }
        Ok(())
    }

    fn lookup_path(
        &self,
        path: &RelPath,
        control: &RequestControl,
    ) -> Result<Meta, GitServiceError> {
        let mut parent = self.files.root_entry();
        let mut found = None;
        for (index, component) in path.0.iter().enumerate() {
            control.check()?;
            let item = self.lookup_child(parent, component, control)?;
            let last = index + 1 == path.0.len();
            if !last && item.kind != Kind::Directory {
                return Err(GitServiceError::UnsafeRepository);
            }
            parent = item.entry;
            found = Some(item);
        }
        found.ok_or(GitServiceError::UnsafeRepository)
    }

    fn lookup_optional_child(
        &self,
        parent: EntryRef,
        parent_path: &RelPath,
        name: &[u8],
        control: &RequestControl,
    ) -> Result<Option<Meta>, GitServiceError> {
        let _ = parent_path;
        match self.lookup_child(parent, name, control) {
            Ok(meta) => Ok(Some(meta)),
            Err(GitServiceError::RepositoryNotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn lookup_child(
        &self,
        parent: EntryRef,
        name: &[u8],
        control: &RequestControl,
    ) -> Result<Meta, GitServiceError> {
        let mut cursor: Option<Vec<u8>> = None;
        let mut cursors = HashSet::new();
        loop {
            control.check()?;
            let page = self
                .files
                .list(parent, cursor.as_deref(), MAX_PAGE_SIZE)
                .map_err(map_file_error)?;
            if let Some(meta) = page.entries.into_iter().find(|meta| meta.name == name) {
                return Ok(meta);
            }
            match page.next {
                Some(next) if page.truncated => {
                    if !cursors.insert(next.clone()) {
                        return Err(GitServiceError::DiscoveryFailed);
                    }
                    cursor = Some(next);
                }
                Some(_) | None if page.truncated => {
                    return Err(GitServiceError::DiscoveryFailed);
                }
                None => return Err(GitServiceError::RepositoryNotFound),
                Some(_) => return Err(GitServiceError::DiscoveryFailed),
            }
        }
    }

    fn read_pointer(&self, meta: &Meta) -> Result<String, GitServiceError> {
        if meta.kind != Kind::File || meta.size == 0 || meta.size > MAX_GIT_POINTER_BYTES as u64 {
            return Err(GitServiceError::UnsafeRepository);
        }
        let read = self
            .files
            .read(meta.entry, Some(&meta.revision), 0, MAX_GIT_POINTER_BYTES)
            .map_err(map_file_error)?;
        if read.meta.revision != meta.revision || read.truncated || read.bytes.is_empty() {
            return Err(GitServiceError::RepositoryChanged);
        }
        String::from_utf8(read.bytes).map_err(|_| GitServiceError::UnsafeRepository)
    }

    fn revalidate_entry(
        &self,
        expected: &Meta,
        control: &RequestControl,
    ) -> Result<(), GitServiceError> {
        control.check()?;
        let current = self
            .files
            .stat(expected.entry, Some(&expected.revision))
            .map_err(map_file_error)?;
        if current.kind != expected.kind
            || current.name != expected.name
            || current.size != expected.size
            || current.nlink != expected.nlink
        {
            return Err(GitServiceError::RepositoryChanged);
        }
        Ok(())
    }
}

fn parse_pointer<'a>(contents: &'a str, prefix: &str) -> Result<&'a str, GitServiceError> {
    let mut text = contents.strip_suffix('\n').unwrap_or(contents);
    if let Some(without_cr) = text.strip_suffix('\r') {
        text = without_cr;
    }
    if text.contains('\n') || text.contains('\r') || text.contains('\0') {
        return Err(GitServiceError::UnsafeRepository);
    }
    text.strip_prefix(prefix)
        .filter(|value| !value.is_empty())
        .ok_or(GitServiceError::UnsafeRepository)
}

fn parse_status_cursor(
    cursor: Option<&EventCursor>,
    requested_state: Option<&RepoStateToken>,
    current_state: &str,
) -> Result<usize, GitServiceError> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let requested_state = requested_state.ok_or(GitServiceError::InvalidCursor)?;
    if requested_state.as_str() != current_state {
        return Err(GitServiceError::StaleState);
    }
    let (offset, state) = cursor
        .as_str()
        .split_once('_')
        .ok_or(GitServiceError::InvalidCursor)?;
    if state != current_state
        || offset.is_empty()
        || !offset.bytes().all(|byte| byte.is_ascii_digit())
        || (offset.len() > 1 && offset.starts_with('0'))
    {
        return Err(GitServiceError::InvalidCursor);
    }
    let offset = offset
        .parse::<usize>()
        .map_err(|_| GitServiceError::InvalidCursor)?;
    if offset > MAX_SNAPSHOT_ENTRIES {
        return Err(GitServiceError::InvalidCursor);
    }
    Ok(offset)
}

fn check_snapshot_token(requested: &RepoStateToken, current: &str) -> Result<(), GitServiceError> {
    if requested.as_str() == current {
        Ok(())
    } else {
        Err(GitServiceError::StaleState)
    }
}

fn cursor_binding(operation: &str, state: &str, query: &[&str]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"lomi-git-page-v1\0");
    for part in std::iter::once(operation)
        .chain(std::iter::once(state))
        .chain(query.iter().copied())
    {
        digest.update((part.len() as u64).to_le_bytes());
        digest.update(part.as_bytes());
    }
    token_hex(digest.finalize().as_slice())
}

fn parse_bound_cursor(
    cursor: Option<&EventCursor>,
    binding: &str,
) -> Result<usize, GitServiceError> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let (offset, supplied_binding) = cursor
        .as_str()
        .split_once('_')
        .ok_or(GitServiceError::InvalidCursor)?;
    if supplied_binding != binding
        || offset.is_empty()
        || !offset.bytes().all(|byte| byte.is_ascii_digit())
        || (offset.len() > 1 && offset.starts_with('0'))
    {
        return Err(GitServiceError::InvalidCursor);
    }
    let offset = offset
        .parse::<usize>()
        .map_err(|_| GitServiceError::InvalidCursor)?;
    if offset > MAX_SNAPSHOT_ENTRIES {
        return Err(GitServiceError::InvalidCursor);
    }
    Ok(offset)
}

fn make_bound_cursor(offset: usize, binding: &str) -> Result<EventCursor, GitServiceError> {
    EventCursor::try_from(format!("{offset}_{binding}")).map_err(|_| GitServiceError::ResourceLimit)
}

fn snapshot_token(state: &str) -> Result<RepoStateToken, GitServiceError> {
    RepoStateToken::try_from(state.to_owned()).map_err(|_| GitServiceError::ExecutorFailed)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn encode_relative_path(path: &RelPath) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (index, component) in path.0.iter().enumerate() {
        if index != 0 {
            bytes.push(b'/');
        }
        bytes.extend_from_slice(component);
    }
    bytes
}

fn snapshot_path_for_entry(snapshot: &PrivateSnapshot, entry_id: &EntryId) -> Option<Vec<u8>> {
    snapshot.files.iter().find_map(|(path, meta)| {
        (meta.entry.to_bytes() == entry_id.to_bytes()).then(|| encode_relative_path(path))
    })
}

fn find_snapshot_entry<'a>(
    snapshot: &'a PrivateSnapshot,
    entry_id: &[u8; 16],
) -> Option<(&'a RelPath, &'a Meta)> {
    snapshot
        .files
        .iter()
        .find(|(_, meta)| &meta.entry.to_bytes() == entry_id)
}

fn check_mutation_preconditions(
    expected: &GitPreconditions,
    snapshot: &PrivateSnapshot,
    head: &str,
) -> Result<(), GitServiceError> {
    if expected.head.as_str() != state_token(head.as_bytes()).as_str()
        || expected.index != index_token(snapshot.path())?
    {
        return Err(GitServiceError::StaleState);
    }
    Ok(())
}

fn make_index_publication(
    repository: &Repository,
    snapshot: &PrivateSnapshot,
    object_ids: Vec<String>,
) -> Result<GitPublication, GitServiceError> {
    let git_dir_path = snapshot.path().join(".git");
    let index_bytes =
        fs::read(git_dir_path.join("index")).map_err(|_| GitServiceError::MutationFailed)?;
    if index_bytes.len() > 64 * 1024 * 1024 {
        return Err(GitServiceError::ResourceLimit);
    }
    let (preconditions, index_expected) = git_index_preconditions(snapshot)?;
    let mut objects = Vec::new();
    let mut seen = HashSet::new();
    for object_id in object_ids {
        let object_id = validate_object_id(&object_id)?;
        if !seen.insert(object_id.clone()) {
            continue;
        }
        let object_path = git_dir_path
            .join("objects")
            .join(&object_id[..2])
            .join(&object_id[2..]);
        match fs::metadata(&object_path) {
            Ok(meta) if meta.is_file() && meta.len() <= 64 * 1024 * 1024 => {
                let bytes = fs::read(object_path).map_err(|_| GitServiceError::MutationFailed)?;
                if bytes.is_empty() {
                    return Err(GitServiceError::MutationFailed);
                }
                objects.push(GitObjectFile { object_id, bytes });
            }
            Ok(_) => return Err(GitServiceError::UnsafeRepository),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // The object may already be available from a pack. Such an
                // object is already present in the host repository.
            }
            Err(_) => return Err(GitServiceError::MutationFailed),
        }
    }
    Ok(GitPublication {
        git_dir: repository.git_marker.entry,
        common_dir: repository.commondir.entry,
        preconditions,
        worktree_preconditions: Vec::new(),
        objects,
        final_file: GitFinalFile {
            target: GitFinalTarget::Index,
            parent: repository.git_marker.entry,
            parent_suffix: Vec::new(),
            expected: index_expected,
            bytes: index_bytes,
        },
    })
}

fn make_commit_publication(
    repository: &Repository,
    snapshot: &PrivateSnapshot,
    object_ids: Vec<String>,
    commit_id: &str,
) -> Result<GitPublication, GitServiceError> {
    let git_dir_path = snapshot.path().join(".git");
    let index_expected = metadata_precondition(
        snapshot,
        &RelPath(vec![b".git".to_vec(), b"index".to_vec()]),
    )?;
    let head_path = RelPath(vec![b".git".to_vec(), b"HEAD".to_vec()]);
    let head_expected = metadata_precondition(snapshot, &head_path)?;
    let head_bytes =
        fs::read(git_dir_path.join("HEAD")).map_err(|_| GitServiceError::UnsafeRepository)?;
    if head_bytes.len() > MAX_GIT_POINTER_BYTES {
        return Err(GitServiceError::UnsafeRepository);
    }
    let head_text =
        std::str::from_utf8(&head_bytes).map_err(|_| GitServiceError::UnsafeRepository)?;

    let mut preconditions = vec![index_expected];
    let (target, expected, parent_suffix) = if head_text.starts_with("ref: ") {
        preconditions.push(head_expected);
        let mut current_ref = reference_rel_path(parse_pointer(head_text, "ref: ")?)?;
        let mut seen = HashSet::new();
        let mut terminal_expected = None;
        let mut terminal_ref = None;
        for _ in 0..8 {
            if !seen.insert(current_ref.clone()) {
                return Err(GitServiceError::UnsafeRepository);
            }
            let current_expected = metadata_precondition(snapshot, &current_ref)?;
            let host_path = current_ref.to_host_path(snapshot.path())?;
            let bytes = match fs::read(host_path) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    terminal_expected = Some(current_expected);
                    terminal_ref = Some(current_ref);
                    break;
                }
                Err(_) => return Err(GitServiceError::UnsafeRepository),
            };
            if bytes.len() > MAX_GIT_POINTER_BYTES {
                return Err(GitServiceError::UnsafeRepository);
            }
            let text =
                std::str::from_utf8(&bytes).map_err(|_| GitServiceError::UnsafeRepository)?;
            if text.starts_with("ref: ") {
                // Every symbolic hop before the terminal target must remain
                // unchanged while the private commit is prepared.
                preconditions.push(current_expected);
                current_ref = reference_rel_path(parse_pointer(text, "ref: ")?)?;
                continue;
            }
            parse_git_object_pointer(text)?;
            terminal_expected = Some(current_expected);
            terminal_ref = Some(current_ref);
            break;
        }
        let terminal_ref = terminal_ref.ok_or(GitServiceError::UnsafeRepository)?;
        let expected = terminal_expected.ok_or(GitServiceError::UnsafeRepository)?;
        let reference = terminal_ref
            .0
            .get(1..)
            .ok_or(GitServiceError::UnsafeRepository)?
            .to_vec();
        validate_commit_branch_reference(&reference)?;
        let packed_refs_path = RelPath(vec![b".git".to_vec(), b"packed-refs".to_vec()]);
        preconditions.push(metadata_precondition(snapshot, &packed_refs_path)?);
        let parent_components = terminal_ref
            .0
            .split_last()
            .map(|(_, parents)| parents)
            .ok_or(GitServiceError::UnsafeRepository)?;
        let mut nearest_parent = None;
        for existing_len in (1..=parent_components.len()).rev() {
            let path = RelPath(parent_components[..existing_len].to_vec());
            if let Some(parent) = snapshot_directory(snapshot, &path) {
                if parent.kind != Kind::Directory {
                    return Err(GitServiceError::UnsafeRepository);
                }
                nearest_parent = Some((parent.entry, existing_len));
                break;
            }
        }
        let (parent_entry, existing_len) =
            nearest_parent.ok_or(GitServiceError::UnsafeRepository)?;
        if parent_entry != expected.parent {
            return Err(GitServiceError::UnsafeRepository);
        }
        let parent_suffix = reference[..reference.len() - 1]
            .get(existing_len.saturating_sub(1)..)
            .ok_or(GitServiceError::UnsafeRepository)?
            .to_vec();
        (
            GitFinalTarget::BranchHead { reference },
            expected,
            parent_suffix,
        )
    } else {
        parse_git_object_pointer(head_text)?;
        (GitFinalTarget::DetachedHead, head_expected, Vec::new())
    };

    let commit_id = validate_object_id(commit_id)?;
    let objects = collect_loose_objects(snapshot, object_ids)?;
    if !objects.iter().any(|object| object.object_id == commit_id) {
        return Err(GitServiceError::MutationFailed);
    }
    let bytes = format!("{commit_id}\n").into_bytes();
    Ok(GitPublication {
        git_dir: repository.git_marker.entry,
        common_dir: repository.commondir.entry,
        preconditions,
        worktree_preconditions: Vec::new(),
        objects,
        final_file: GitFinalFile {
            target,
            parent: expected.parent,
            parent_suffix,
            expected,
            bytes,
        },
    })
}

fn collect_loose_objects(
    snapshot: &PrivateSnapshot,
    object_ids: Vec<String>,
) -> Result<Vec<GitObjectFile>, GitServiceError> {
    let git_dir_path = snapshot.path().join(".git");
    let object_dir = git_dir_path.join("objects");
    let mut objects = Vec::new();
    let mut seen = HashSet::new();
    for object_id in object_ids {
        let object_id = validate_object_id(&object_id)?;
        if !seen.insert(object_id.clone()) {
            continue;
        }
        let prefix_path = object_dir.join(&object_id[..2]);
        let object_path = prefix_path.join(&object_id[2..]);
        match fs::symlink_metadata(&object_dir) {
            Ok(meta) if meta.file_type().is_dir() && !meta.file_type().is_symlink() => {}
            Ok(_) => return Err(GitServiceError::UnsafeRepository),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(GitServiceError::MutationFailed),
        }
        match fs::symlink_metadata(&prefix_path) {
            Ok(meta) if meta.file_type().is_dir() && !meta.file_type().is_symlink() => {}
            Ok(_) => return Err(GitServiceError::UnsafeRepository),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(GitServiceError::MutationFailed),
        }
        match fs::symlink_metadata(&object_path) {
            Ok(meta) if meta.file_type().is_file() && meta.len() <= 64 * 1024 * 1024 => {
                let bytes = fs::read(object_path).map_err(|_| GitServiceError::MutationFailed)?;
                if bytes.is_empty() {
                    return Err(GitServiceError::MutationFailed);
                }
                objects.push(GitObjectFile { object_id, bytes });
            }
            Ok(_) => return Err(GitServiceError::UnsafeRepository),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Packed objects already exist in the host repository and do
                // not need to be copied from the private snapshot.
            }
            Err(_) => return Err(GitServiceError::MutationFailed),
        }
    }
    Ok(objects)
}

fn parse_git_object_pointer(contents: &str) -> Result<String, GitServiceError> {
    let mut value = contents.strip_suffix('\n').unwrap_or(contents);
    if let Some(without_cr) = value.strip_suffix('\r') {
        value = without_cr;
    }
    if value.contains(['\n', '\r', '\0']) {
        return Err(GitServiceError::UnsafeRepository);
    }
    validate_object_id(value).map_err(|_| GitServiceError::UnsafeRepository)
}

fn validate_commit_branch_reference(reference: &[Vec<u8>]) -> Result<(), GitServiceError> {
    if reference.len() < 3
        || reference.len() > 64
        || reference[0] != b"refs"
        || reference[1] != b"heads"
        || reference.iter().map(Vec::len).sum::<usize>() + reference.len() - 1 > 2048
        || reference.iter().any(|part| {
            part.is_empty()
                || part.len() > 255
                || part.starts_with(b".")
                || part.ends_with(b".")
                || part.ends_with(b".lock")
                || part.windows(2).any(|pair| pair == b".." || pair == b"@{")
                || part.iter().any(|byte| {
                    *byte <= 0x20
                        || *byte == 0x7f
                        || matches!(*byte, b'~' | b'^' | b'?' | b'*' | b'[' | b'\\' | b':')
                })
        })
        || (reference.len() == 3 && reference[2] == b"@")
        || reference.last().is_some_and(|leaf| leaf.len() > 250)
    {
        return Err(GitServiceError::UnsafeRepository);
    }
    Ok(())
}

fn git_index_preconditions(
    snapshot: &PrivateSnapshot,
) -> Result<(Vec<GitFilePrecondition>, GitFilePrecondition), GitServiceError> {
    let index_path = RelPath(vec![b".git".to_vec(), b"index".to_vec()]);
    let index_expected = metadata_precondition(snapshot, &index_path)?;
    let head_path = RelPath(vec![b".git".to_vec(), b"HEAD".to_vec()]);
    let head_precondition = metadata_precondition(snapshot, &head_path)?;
    let head_bytes = fs::read(snapshot.path().join(".git").join("HEAD"))
        .map_err(|_| GitServiceError::UnsafeRepository)?;
    if head_bytes.len() > MAX_GIT_POINTER_BYTES {
        return Err(GitServiceError::UnsafeRepository);
    }
    let mut preconditions = vec![head_precondition];
    let head_text =
        std::str::from_utf8(&head_bytes).map_err(|_| GitServiceError::UnsafeRepository)?;
    if head_text.starts_with("ref: ") {
        let mut current_ref = reference_rel_path(parse_pointer(head_text, "ref: ")?)?;
        let mut seen = HashSet::new();
        let mut terminated = false;
        for _ in 0..8 {
            if !seen.insert(current_ref.clone()) {
                return Err(GitServiceError::UnsafeRepository);
            }
            preconditions.push(metadata_precondition(snapshot, &current_ref)?);
            let host_path = current_ref.to_host_path(snapshot.path())?;
            let bytes = match fs::read(host_path) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    terminated = true;
                    break;
                }
                Err(_) => return Err(GitServiceError::UnsafeRepository),
            };
            if bytes.len() > MAX_GIT_POINTER_BYTES {
                return Err(GitServiceError::UnsafeRepository);
            }
            let text =
                std::str::from_utf8(&bytes).map_err(|_| GitServiceError::UnsafeRepository)?;
            if text.starts_with("ref: ") {
                current_ref = reference_rel_path(parse_pointer(text, "ref: ")?)?;
            } else {
                terminated = true;
                break;
            }
        }
        if !terminated {
            return Err(GitServiceError::UnsafeRepository);
        }
        preconditions.push(metadata_precondition(
            snapshot,
            &RelPath(vec![b".git".to_vec(), b"packed-refs".to_vec()]),
        )?);
    }
    Ok((preconditions, index_expected))
}

fn reference_rel_path(reference: &str) -> Result<RelPath, GitServiceError> {
    if !reference.starts_with("refs/") || reference.len() > 2048 {
        return Err(GitServiceError::UnsafeRepository);
    }
    let components = reference
        .split('/')
        .map(|component| component.as_bytes().to_vec())
        .collect::<Vec<_>>();
    if components.iter().any(|component| {
        component.is_empty()
            || component.len() > 255
            || component == b"."
            || component == b".."
            || component.contains(&0)
            || component.contains(&b'\\')
            || component.contains(&b':')
    }) {
        return Err(GitServiceError::UnsafeRepository);
    }
    let mut path = vec![b".git".to_vec()];
    path.extend(components);
    Ok(RelPath(path))
}

fn metadata_precondition(
    snapshot: &PrivateSnapshot,
    path: &RelPath,
) -> Result<GitFilePrecondition, GitServiceError> {
    let (target_name, parent_path) = path
        .0
        .split_last()
        .ok_or(GitServiceError::UnsafeRepository)?;
    if target_name.is_empty() || target_name.len() > 255 {
        return Err(GitServiceError::UnsafeRepository);
    }

    for existing_len in (0..=parent_path.len()).rev() {
        let existing_path = RelPath(parent_path[..existing_len].to_vec());
        let Some(parent) = snapshot_directory(snapshot, &existing_path) else {
            continue;
        };
        if parent.kind != Kind::Directory {
            return Err(GitServiceError::UnsafeRepository);
        }
        if existing_len == parent_path.len() {
            let target = snapshot.files.get(path);
            if target.is_some_and(|meta| meta.kind != Kind::File) {
                return Err(GitServiceError::UnsafeRepository);
            }
            return Ok(GitFilePrecondition {
                parent: parent.entry,
                name: target_name.clone(),
                entry: target.map(|meta| meta.entry),
                revision: target.map(|meta| meta.revision.clone()),
            });
        }
        // Guard the first absent directory below the nearest existing parent.
        // If it appears, the whole previously absent reference path changed.
        let missing_component = &parent_path[existing_len];
        if missing_component.is_empty() || missing_component.len() > 255 {
            return Err(GitServiceError::UnsafeRepository);
        }
        return Ok(GitFilePrecondition {
            parent: parent.entry,
            name: missing_component.clone(),
            entry: None,
            revision: None,
        });
    }
    Err(GitServiceError::UnsafeRepository)
}

fn worktree_path_precondition(
    snapshot: &PrivateSnapshot,
    path: &RelPath,
    expected: Option<Meta>,
) -> Result<GitWorktreePrecondition, GitServiceError> {
    let (name, parent_path) = path
        .0
        .split_last()
        .ok_or(GitServiceError::UnsafeRepository)?;
    let current = snapshot.files.get(path);
    match (expected, current) {
        (Some(expected), Some(current)) => {
            if expected.entry != current.entry
                || expected.revision != current.revision
                || expected.kind != Kind::File
                || current.kind != Kind::File
            {
                return Err(GitServiceError::MutationConflict);
            }
            let parent = snapshot_directory(snapshot, &RelPath(parent_path.to_vec()))
                .filter(|parent| parent.kind == Kind::Directory)
                .ok_or(GitServiceError::MutationConflict)?;
            Ok(GitWorktreePrecondition {
                parent: parent.entry,
                name: name.clone(),
                entry: Some(current.entry),
                revision: Some(current.revision.clone()),
            })
        }
        (None, None) => {
            // A deleted file may have lost one or more parent directories as
            // well. Pin the nearest existing directory and the first absent
            // child so re-creation conflicts before the index is published.
            for existing_len in (0..=parent_path.len()).rev() {
                let existing_path = RelPath(parent_path[..existing_len].to_vec());
                let Some(parent) = snapshot_directory(snapshot, &existing_path) else {
                    continue;
                };
                if parent.kind != Kind::Directory {
                    return Err(GitServiceError::MutationConflict);
                }
                let missing_component = if existing_len == parent_path.len() {
                    name
                } else {
                    &parent_path[existing_len]
                };
                if missing_component.is_empty() || missing_component.len() > 255 {
                    return Err(GitServiceError::UnsafeRepository);
                }
                return Ok(GitWorktreePrecondition {
                    parent: parent.entry,
                    name: missing_component.clone(),
                    entry: None,
                    revision: None,
                });
            }
            let parent = snapshot_directory(snapshot, &RelPath::root())
                .filter(|parent| parent.kind == Kind::Directory)
                .ok_or(GitServiceError::MutationConflict)?;
            Ok(GitWorktreePrecondition {
                parent: parent.entry,
                name: name.clone(),
                entry: None,
                revision: None,
            })
        }
        _ => Err(GitServiceError::MutationConflict),
    }
}

fn snapshot_directory<'a>(snapshot: &'a PrivateSnapshot, path: &RelPath) -> Option<&'a Meta> {
    if path.0.is_empty() {
        Some(&snapshot.root)
    } else {
        snapshot.files.get(path)
    }
}

fn allowed_git_path(path: &[u8]) -> bool {
    !path.is_empty()
        && path.len() <= 3072
        && !path.starts_with(b"/")
        && path.split(|byte| *byte == b'/').all(|component| {
            !component.is_empty()
                && component != b"."
                && component != b".."
                && !component.contains(&0)
                && !component.contains(&b'\\')
                && !component.contains(&b':')
                && !is_git_metadata_component(component)
        })
}

fn is_git_metadata_component(component: &[u8]) -> bool {
    let mut end = component.len();
    while end > 0 && matches!(component[end - 1], b'.' | b' ') {
        end -= 1;
    }
    let trimmed = &component[..end];
    if trimmed.eq_ignore_ascii_case(b".git") {
        return true;
    }
    let lowercase = trimmed
        .iter()
        .map(u8::to_ascii_lowercase)
        .collect::<Vec<_>>();
    lowercase
        .strip_prefix(b"git~")
        .is_some_and(|digits| !digits.is_empty() && digits.iter().all(u8::is_ascii_digit))
}

fn map_mutation_file_error(error: FileError) -> GitServiceError {
    match error {
        FileError::Changed | FileError::Exists | FileError::NotFound | FileError::NotEmpty => {
            GitServiceError::MutationConflict
        }
        FileError::Protected | FileError::Invalid | FileError::Unsupported => {
            GitServiceError::UnsafeRepository
        }
        FileError::Limit => GitServiceError::ResourceLimit,
        FileError::Io(_) => GitServiceError::MutationFailed,
    }
}

fn validate_object_id(value: &str) -> Result<String, GitServiceError> {
    if !matches!(value.len(), 40 | 64) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(GitServiceError::InvalidObjectId);
    }
    Ok(value.to_ascii_lowercase())
}

fn map_commit_summary(row: worker::GuestCommit) -> Result<GitCommitSummary, GitServiceError> {
    let object_id = ObjectId::try_from(validate_object_id(&row.object_id)?)
        .map_err(|_| GitServiceError::ExecutorFailed)?;
    let subject =
        DisplayText::try_from(row.subject).map_err(|_| GitServiceError::ExecutorFailed)?;
    let author = DisplayText::try_from(row.author).map_err(|_| GitServiceError::ExecutorFailed)?;
    Ok(GitCommitSummary {
        object_id,
        subject,
        author,
        timestamp_seconds: DecimalU64(row.timestamp_seconds),
    })
}

fn map_diff_file(
    repository_id: RepositoryId,
    snapshot: &PrivateSnapshot,
    row: worker::GuestDiffFile,
) -> Result<GitDiffFile, GitServiceError> {
    if row.hunks.len() > 200 {
        return Err(GitServiceError::ResourceLimit);
    }
    let path = decode_path_hex(&row.path_hex)?;
    if path.len() > 3072 {
        return Err(GitServiceError::ResourceLimit);
    }
    let relative = git_relative_path(&path)?;
    let entry_id = match snapshot.files.get(&relative) {
        Some(meta) => EntryId::from_bytes(meta.entry.to_bytes())
            .map_err(|_| GitServiceError::ExecutorFailed)?,
        None => path_entry_id(repository_id, &path),
    };
    let display_name =
        DisplayText::try_from(display_path(&path)).map_err(|_| GitServiceError::ResourceLimit)?;
    let mut hunks = Vec::with_capacity(row.hunks.len());
    for hunk in row.hunks {
        if hunk.lines.len() > 200 {
            return Err(GitServiceError::ResourceLimit);
        }
        let lines = hunk
            .lines
            .into_iter()
            .map(|line| {
                let kind = match line.kind.as_str() {
                    "context" => DiffLineKind::Context,
                    "added" => DiffLineKind::Added,
                    "removed" => DiffLineKind::Removed,
                    _ => return Err(GitServiceError::ExecutorFailed),
                };
                let text = DiffLineText::try_from(line.text)
                    .map_err(|_| GitServiceError::ExecutorFailed)?;
                Ok(GitDiffLine { kind, text })
            })
            .collect::<Result<Vec<_>, GitServiceError>>()?;
        hunks.push(GitDiffHunk {
            old_start: DecimalU64(hunk.old_start),
            new_start: DecimalU64(hunk.new_start),
            lines: BoundedList(lines),
        });
    }
    Ok(GitDiffFile {
        entry_id,
        display_name,
        binary: row.binary,
        hunks: BoundedList(hunks),
        truncated: row.truncated,
    })
}

fn index_token(snapshot: &Path) -> Result<RepoStateToken, GitServiceError> {
    use std::io::Read;
    let path = snapshot.join(".git").join("index");
    let mut file = match std::fs::File::open(path) {
        Ok(file) => Some(file),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(GitServiceError::ExecutorFailed),
    };
    let mut digest = Sha256::new();
    if let Some(file) = file.as_mut() {
        let mut bytes = [0u8; 64 * 1024];
        loop {
            let count = file
                .read(&mut bytes)
                .map_err(|_| GitServiceError::ExecutorFailed)?;
            if count == 0 {
                break;
            }
            digest.update(&bytes[..count]);
        }
    }
    RepoStateToken::try_from(token_hex(digest.finalize().as_slice()))
        .map_err(|_| GitServiceError::ExecutorFailed)
}

fn state_token(bytes: &[u8]) -> RepoStateToken {
    RepoStateToken::try_from(token_hex(Sha256::digest(bytes).as_slice()))
        .expect("SHA-256 state token is a valid bounded protocol token")
}

fn map_status_entry(
    repository_id: RepositoryId,
    row: worker::GuestStatusEntry,
    files: &HashMap<RelPath, Meta>,
    snapshot_state: &str,
) -> Result<GitStatusEntry, GitServiceError> {
    let path = decode_path_hex(&row.path_hex)?;
    if path.len() > 3072 {
        return Err(GitServiceError::ResourceLimit);
    }
    let relative = git_relative_path(&path)?;
    let meta = files.get(&relative);
    let entry_id = match meta {
        Some(meta) => EntryId::from_bytes(meta.entry.to_bytes())
            .map_err(|_| GitServiceError::ExecutorFailed)?,
        None => path_entry_id(repository_id, &path),
    };
    let path_id =
        EncodedPathId::try_from(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&path))
            .map_err(|_| GitServiceError::ResourceLimit)?;
    let display_name =
        DisplayText::try_from(display_path(&path)).map_err(|_| GitServiceError::ResourceLimit)?;
    let file_revision = match meta {
        Some(meta) => FileRevision::try_from(meta.revision.clone()),
        None => FileRevision::try_from(token_hex(
            Sha256::digest([snapshot_state.as_bytes(), &path].concat()).as_slice(),
        )),
    }
    .map_err(|_| GitServiceError::ExecutorFailed)?;
    Ok(GitStatusEntry {
        entry_id,
        path_id,
        display_name,
        index: parse_change(row.index.as_deref())?,
        worktree: parse_change(row.worktree.as_deref())?,
        file_revision,
    })
}

fn parse_change(value: Option<&str>) -> Result<GitChange, GitServiceError> {
    match value {
        None => Ok(GitChange::Unchanged),
        Some("added") => Ok(GitChange::Added),
        Some("modified") => Ok(GitChange::Modified),
        Some("deleted") => Ok(GitChange::Deleted),
        Some("renamed") => Ok(GitChange::Renamed),
        Some("copied") => Ok(GitChange::Copied),
        Some("unmerged") => Ok(GitChange::Unmerged),
        Some("untracked") => Ok(GitChange::Untracked),
        _ => Err(GitServiceError::ExecutorFailed),
    }
}

fn decode_path_hex(hex: &str) -> Result<Vec<u8>, GitServiceError> {
    if hex.len() > 8192 || !hex.len().is_multiple_of(2) {
        return Err(GitServiceError::ResourceLimit);
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        let digit = |value: u8| match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            _ => None,
        };
        let high = digit(pair[0]).ok_or(GitServiceError::ExecutorFailed)?;
        let low = digit(pair[1]).ok_or(GitServiceError::ExecutorFailed)?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn git_relative_path(path: &[u8]) -> Result<RelPath, GitServiceError> {
    if path.is_empty() || path.starts_with(b"/") {
        return Err(GitServiceError::UnsafeRepository);
    }
    let components = path
        .split(|byte| *byte == b'/')
        .map(|component| component.to_vec())
        .collect::<Vec<_>>();
    if components
        .iter()
        .any(|component| component.is_empty() || component == b"." || component == b"..")
    {
        return Err(GitServiceError::UnsafeRepository);
    }
    Ok(RelPath(components))
}

fn path_entry_id(repository: RepositoryId, path: &[u8]) -> EntryId {
    let mut digest = Sha256::new();
    digest.update(b"lomi-git-entry-v1\0");
    digest.update(repository.to_bytes());
    digest.update((path.len() as u64).to_le_bytes());
    digest.update(path);
    let digest = digest.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    EntryId::from_bytes(bytes).expect("versioned hash cannot be nil")
}

fn display_path(path: &[u8]) -> String {
    let text = String::from_utf8_lossy(path);
    let mut output = String::with_capacity(text.len().min(4096));
    for character in text.chars() {
        let character = if character.is_control() {
            '\u{fffd}'
        } else {
            character
        };
        if output.len() + character.len_utf8() > 4096 {
            break;
        }
        output.push(character);
    }
    output
}

fn sanitize_display_name(input: &str) -> String {
    let mut output = String::with_capacity(input.len().min(128));
    for character in input.chars() {
        if output.len() >= 128 {
            break;
        }
        output.push(if character.is_control() {
            '_'
        } else {
            character
        });
    }
    output
}

fn path_identity(path: &Path) -> Result<FileIdentity, GitServiceError> {
    let metadata = std::fs::metadata(path).map_err(|_| GitServiceError::RepositoryChanged)?;
    if !metadata.is_dir() {
        return Err(GitServiceError::UnsafeRepository);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(&metadata.dev().to_le_bytes());
        bytes.extend_from_slice(&metadata.ino().to_le_bytes());
        Ok(FileIdentity(bytes))
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let volume = metadata
            .volume_serial_number()
            .ok_or(GitServiceError::RepositoryChanged)?;
        let index = metadata
            .file_index()
            .ok_or(GitServiceError::RepositoryChanged)?;
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&volume.to_le_bytes());
        bytes.extend_from_slice(&index.to_le_bytes());
        Ok(FileIdentity(bytes))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let canonical = path
            .canonicalize()
            .map_err(|_| GitServiceError::RepositoryChanged)?;
        Ok(FileIdentity(
            canonical.to_string_lossy().to_lowercase().into_bytes(),
        ))
    }
}

fn repository_id(gitdir: &FileIdentity, common: &FileIdentity) -> RepositoryId {
    let mut digest = Sha256::new();
    digest.update(b"lomi-git-repository-id-v1\0");
    digest.update((gitdir.0.len() as u64).to_le_bytes());
    digest.update(&gitdir.0);
    digest.update((common.0.len() as u64).to_le_bytes());
    digest.update(&common.0);
    let hash = digest.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    RepositoryId::from_bytes(bytes).expect("versioned hash cannot be nil")
}

fn same_manifest(before: &[SnapshotEntry], after: &[SnapshotEntry]) -> bool {
    let mut before = before.iter().collect::<Vec<_>>();
    let mut after = after.iter().collect::<Vec<_>>();
    let by_path = |left: &&SnapshotEntry, right: &&SnapshotEntry| left.path.cmp(&right.path);
    before.sort_by(by_path);
    after.sort_by(by_path);
    before.iter().zip(after.iter()).all(|(old, new)| {
        old.path == new.path
            && old.meta.entry == new.meta.entry
            && old.meta.kind == new.meta.kind
            && old.meta.size == new.meta.size
            && old.meta.revision == new.meta.revision
            && old.meta.nlink == new.meta.nlink
    }) && before.len() == after.len()
}

fn set_snapshot_executable(path: &Path, executable: bool) -> Result<(), GitServiceError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if executable { 0o755 } else { 0o644 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|_| GitServiceError::DiscoveryFailed)?;
    }
    #[cfg(windows)]
    {
        let _ = (path, executable);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, executable);
    }
    Ok(())
}

fn update_path_hash(digest: &mut Sha256, path: &RelPath) {
    digest.update((path.0.len() as u64).to_le_bytes());
    for component in &path.0 {
        digest.update((component.len() as u64).to_le_bytes());
        digest.update(component);
    }
}

fn kind_tag(kind: Kind) -> u8 {
    match kind {
        Kind::File => 1,
        Kind::Directory => 2,
        Kind::Symlink => 3,
        Kind::Other => 4,
    }
}

fn token_hex(bytes: &[u8]) -> String {
    let mut token = String::with_capacity(1 + bytes.len() * 2);
    token.push('r');
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(token, "{byte:02x}");
    }
    token
}

fn map_file_error(error: FileError) -> GitServiceError {
    match error {
        FileError::Changed => GitServiceError::RepositoryChanged,
        FileError::Protected | FileError::Invalid | FileError::Unsupported => {
            GitServiceError::UnsafeRepository
        }
        FileError::Limit => GitServiceError::ResourceLimit,
        FileError::NotFound => GitServiceError::RepositoryNotFound,
        FileError::Io(_) | FileError::NotEmpty | FileError::Exists => {
            GitServiceError::DiscoveryFailed
        }
    }
}

struct RepoLock {
    held: Mutex<bool>,
    released: Condvar,
}

struct RepoLockGuard(Arc<RepoLock>);

impl Drop for RepoLockGuard {
    fn drop(&mut self) {
        if let Ok(mut held) = self.0.held.lock() {
            *held = false;
            self.0.released.notify_one();
        }
    }
}

impl RepoLock {
    fn acquire(
        self: &Arc<Self>,
        control: &RequestControl,
    ) -> Result<RepoLockGuard, GitServiceError> {
        let mut held = self
            .held
            .lock()
            .map_err(|_| GitServiceError::DiscoveryFailed)?;
        loop {
            control.check()?;
            if !*held {
                *held = true;
                return Ok(RepoLockGuard(self.clone()));
            }
            let (next, _) = self
                .released
                .wait_timeout(held, control.wait_duration()?)
                .map_err(|_| GitServiceError::DiscoveryFailed)?;
            held = next;
        }
    }
}

fn common_repository_lock(identity: &FileIdentity) -> Arc<RepoLock> {
    static LOCKS: OnceLock<Mutex<HashMap<FileIdentity, Weak<RepoLock>>>> = OnceLock::new();
    let locks = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut locks = locks.lock().unwrap_or_else(|poison| poison.into_inner());
    if let Some(existing) = locks.get(identity).and_then(Weak::upgrade) {
        return existing;
    }
    locks.retain(|_, lock| lock.strong_count() != 0);
    let lock = Arc::new(RepoLock {
        held: Mutex::new(false),
        released: Condvar::new(),
    });
    locks.insert(identity.clone(), Arc::downgrade(&lock));
    lock
}

#[cfg(test)]
mod tests {
    use super::*;
    use lomi_remote_protocol::{
        DecimalU64, OperationId, RuntimeId, WorkspaceEpoch, WorkspaceId,
        rpc::{GitMutationContext, GitStagePath},
    };
    use std::fs;
    use std::process::Command;
    use std::thread;

    fn context() -> WorkspaceContext {
        WorkspaceContext {
            workspace_id: WorkspaceId::from_bytes([1; 16]).unwrap(),
            workspace_epoch: WorkspaceEpoch::from_bytes([2; 16]).unwrap(),
            runtime_id: RuntimeId::from_bytes([3; 16]).unwrap(),
            runtime_generation: DecimalU64(1),
            host_access_epoch: DecimalU64(1),
            grant_revision: DecimalU64(1),
        }
    }

    fn control() -> RequestControl {
        RequestControl::with_timeout(CancellationToken::new(), Duration::from_secs(2)).unwrap()
    }

    fn long_control() -> RequestControl {
        RequestControl::with_timeout(CancellationToken::new(), Duration::from_secs(30)).unwrap()
    }

    fn mutation_control() -> RequestControl {
        RequestControl::with_timeout(CancellationToken::new(), Duration::from_secs(15)).unwrap()
    }

    fn service(root: &Path) -> GitService {
        GitService::open(root, &[], context()).unwrap()
    }

    fn git(root: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args(args)
            .current_dir(root)
            .env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .expect("test fixture requires git");
        assert!(status.success(), "git fixture command failed: {args:?}");
    }

    fn git_output(root: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(root)
            .env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("test fixture requires git");
        assert!(
            output.status.success(),
            "git fixture command failed: {args:?}"
        );
        String::from_utf8(output.stdout)
            .expect("git fixture output is utf8")
            .trim()
            .to_owned()
    }

    fn git_with_stdin(root: &Path, args: &[&str], input: &[u8]) {
        use std::io::Write as _;
        use std::process::Stdio;

        let mut child = Command::new("git")
            .args(args)
            .current_dir(root)
            .env_clear()
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("test fixture requires git");
        child.stdin.take().unwrap().write_all(input).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "git fixture command failed: {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn mutation_fixture() -> (tempfile::TempDir, Arc<GitService>, RepositoryId) {
        let workspace = tempfile::tempdir().unwrap();
        git(workspace.path(), &["init", "--quiet"]);
        git(
            workspace.path(),
            &["config", "user.name", "Git Mutation Fixture"],
        );
        git(
            workspace.path(),
            &["config", "user.email", "git-mutation@example.invalid"],
        );
        fs::write(workspace.path().join("tracked.txt"), "initial contents\n").unwrap();
        git(workspace.path(), &["add", "tracked.txt"]);
        git(
            workspace.path(),
            &["commit", "--quiet", "--message", "initial fixture"],
        );
        let service = Arc::new(service(workspace.path()));
        let repository_id = service
            .repositories(
                WorkspaceReadParams { context: context() },
                &mutation_control(),
            )
            .unwrap()
            .repositories
            .0[0]
            .repository_id;
        (workspace, service, repository_id)
    }

    fn stage_params(
        repository_id: RepositoryId,
        status: &GitStatusResult,
        entry: &GitStatusEntry,
        operation_id: u8,
    ) -> GitStageParams {
        GitStageParams {
            mutation: GitMutationContext {
                operation_id: OperationId::from_bytes([operation_id; 16]).unwrap(),
                context: context(),
            },
            repository_id,
            expected: GitPreconditions {
                head: status.head.clone(),
                index: status.index.clone(),
            },
            paths: BoundedList(vec![GitStagePath {
                entry_id: entry.entry_id,
                file_revision: entry.file_revision.clone(),
            }]),
        }
    }

    fn mutation_status(service: &GitService, repository_id: RepositoryId) -> GitStatusResult {
        service
            .status(
                GitStatusParams {
                    context: context(),
                    repository_id,
                    state_token: None,
                    cursor: None,
                    limit: 200u32.try_into().unwrap(),
                },
                &mutation_control(),
            )
            .unwrap()
    }

    #[test]
    fn discovers_regular_and_linked_worktree_metadata_without_client_paths() {
        let workspace = tempfile::tempdir().unwrap();
        fs::create_dir_all(workspace.path().join("project/.git")).unwrap();
        fs::write(
            workspace.path().join("project/.git/HEAD"),
            "ref: refs/heads/main\n",
        )
        .unwrap();
        fs::create_dir_all(workspace.path().join("shared/worktrees/wt")).unwrap();
        fs::write(
            workspace.path().join("project/.git/commondir"),
            "../../shared\n",
        )
        .unwrap();

        let gitdir = workspace.path().join("shared/worktrees/wt");
        fs::create_dir_all(&gitdir).unwrap();
        fs::write(gitdir.join("HEAD"), "ref: refs/heads/linked\n").unwrap();
        fs::write(gitdir.join("commondir"), "../..\n").unwrap();
        fs::create_dir_all(workspace.path().join("linked")).unwrap();
        fs::write(
            workspace.path().join("linked/.git"),
            "gitdir: ../shared/worktrees/wt\n",
        )
        .unwrap();

        let service = service(workspace.path());
        let result = service
            .repositories(WorkspaceReadParams { context: context() }, &control())
            .unwrap();
        assert_eq!(result.repositories.0.len(), 2);
        assert_ne!(
            result.repositories.0[0].repository_id,
            result.repositories.0[1].repository_id
        );
    }

    #[test]
    fn rejects_symlinked_git_marker_and_out_of_workspace_pointer() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir(workspace.path().join("repo")).unwrap();
        fs::create_dir(outside.path().join("gitdir")).unwrap();
        fs::write(outside.path().join("gitdir/HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(
            workspace.path().join("repo/.git"),
            format!("gitdir: {}\n", outside.path().join("gitdir").display()),
        )
        .unwrap();

        let instance = service(workspace.path());
        let error = instance
            .repositories(WorkspaceReadParams { context: context() }, &control())
            .unwrap_err();
        assert_eq!(error, GitServiceError::UnsafeRepository);

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let link_root = tempfile::tempdir().unwrap();
            fs::create_dir(outside.path().join("realrepo")).unwrap();
            fs::create_dir(outside.path().join("realrepo/.git")).unwrap();
            fs::create_dir(link_root.path().join("repo")).unwrap();
            symlink(
                outside.path().join("realrepo/.git"),
                link_root.path().join("repo/.git"),
            )
            .unwrap();
            let instance = service(link_root.path());
            assert_eq!(
                instance
                    .repositories(WorkspaceReadParams { context: context() }, &control(),)
                    .unwrap_err(),
                GitServiceError::UnsafeRepository
            );
        }
    }

    #[test]
    fn status_reads_real_fixture_through_read_only_wasi_with_paging_and_no_hooks() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        git(workspace.path(), &["init", "--quiet"]);
        git(workspace.path(), &["config", "user.name", "Lomi Test"]);
        git(
            workspace.path(),
            &["config", "user.email", "lomi-test@example.invalid"],
        );
        git(workspace.path(), &["config", "core.filemode", "false"]);
        fs::write(workspace.path().join("tracked.txt"), "base\n").unwrap();
        git(workspace.path(), &["add", "tracked.txt"]);
        git(workspace.path(), &["commit", "--quiet", "-m", "fixture"]);

        fs::write(workspace.path().join("staged.txt"), "staged\n").unwrap();
        git(workspace.path(), &["add", "staged.txt"]);
        fs::write(workspace.path().join("staged.txt"), "worktree\n").unwrap();
        fs::write(workspace.path().join("tracked.txt"), "modified\n").unwrap();
        fs::write(workspace.path().join("untracked.txt"), "new\n").unwrap();

        let outside_config = outside.path().join("external-config");
        fs::write(
            &outside_config,
            "[core]\n\texcludesFile = /outside/secret-ignore\n",
        )
        .unwrap();
        git(
            workspace.path(),
            &[
                "config",
                "--local",
                "--add",
                "include.path",
                outside_config.to_str().unwrap(),
            ],
        );
        git(
            workspace.path(),
            &[
                "remote",
                "add",
                "unreachable",
                "https://127.0.0.1:1/no-network",
            ],
        );
        let hook_marker = outside.path().join("hook-ran");
        fs::create_dir_all(workspace.path().join(".git/hooks")).unwrap();
        let hook = workspace.path().join(".git/hooks/pre-commit");
        fs::write(
            &hook,
            format!("#!/bin/sh\nprintf ran > '{}'\n", hook_marker.display()),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let service = service(workspace.path());
        let found = service
            .repositories(WorkspaceReadParams { context: context() }, &control())
            .unwrap();
        assert_eq!(found.repositories.0.len(), 1);
        let repo_id = found.repositories.0[0].repository_id;
        let first = service
            .status(
                GitStatusParams {
                    context: context(),
                    repository_id: repo_id,
                    state_token: None,
                    cursor: None,
                    limit: 2u32.try_into().unwrap(),
                },
                &control(),
            )
            .unwrap();
        assert_eq!(first.entries.0.len(), 2);
        assert!(first.truncated);
        let cursor = first.next_cursor.clone().expect("more status entries");
        let second = service
            .status(
                GitStatusParams {
                    context: context(),
                    repository_id: repo_id,
                    state_token: Some(first.state_token.clone()),
                    cursor: Some(cursor),
                    limit: 2u32.try_into().unwrap(),
                },
                &control(),
            )
            .unwrap();
        assert_eq!(second.entries.0.len(), 1);
        assert!(!second.truncated);

        let mut rows = first.entries.0;
        rows.extend(second.entries.0);
        let mut by_name = rows
            .into_iter()
            .map(|row| (row.display_name.as_str().to_owned(), row))
            .collect::<HashMap<_, _>>();
        let staged = by_name.remove("staged.txt").unwrap();
        assert_eq!(staged.index, GitChange::Added);
        assert_eq!(staged.worktree, GitChange::Modified);
        let tracked = by_name.remove("tracked.txt").unwrap();
        assert_eq!(tracked.index, GitChange::Unchanged);
        assert_eq!(tracked.worktree, GitChange::Modified);
        let untracked = by_name.remove("untracked.txt").unwrap();
        assert_eq!(untracked.worktree, GitChange::Untracked);
        assert!(by_name.is_empty());
        assert!(!hook_marker.exists(), "read operation must not run hooks");

        fs::write(workspace.path().join("later.txt"), "later\n").unwrap();
        let stale = service
            .status(
                GitStatusParams {
                    context: context(),
                    repository_id: repo_id,
                    state_token: Some(first.state_token),
                    cursor: None,
                    limit: 2u32.try_into().unwrap(),
                },
                &control(),
            )
            .unwrap_err();
        assert_eq!(stale, GitServiceError::StaleState);
    }

    #[test]
    fn diff_log_and_show_use_bounded_typed_wasi_results() {
        let workspace = tempfile::tempdir().unwrap();
        git(workspace.path(), &["init", "--quiet"]);
        git(workspace.path(), &["config", "user.name", "Lomi Test"]);
        git(
            workspace.path(),
            &["config", "user.email", "lomi-test@example.invalid"],
        );

        fs::write(
            workspace.path().join("tracked.txt"),
            "first line\nsecond line\nthird line\n",
        )
        .unwrap();
        fs::write(workspace.path().join("stage-a.txt"), "old staged a\n").unwrap();
        fs::write(workspace.path().join("stage-b.txt"), "old staged b\n").unwrap();
        git(
            workspace.path(),
            &["add", "tracked.txt", "stage-a.txt", "stage-b.txt"],
        );
        git(
            workspace.path(),
            &["commit", "--quiet", "-m", "first commit"],
        );

        fs::write(workspace.path().join("show-a.txt"), "show one\n").unwrap();
        fs::write(workspace.path().join("show-b.txt"), "show two\n").unwrap();
        git(workspace.path(), &["add", "show-a.txt", "show-b.txt"]);
        git(
            workspace.path(),
            &["commit", "--quiet", "-m", "show fixture"],
        );
        let show_object = git_output(workspace.path(), &["rev-parse", "HEAD"]);

        fs::write(workspace.path().join("history.txt"), "third commit\n").unwrap();
        git(workspace.path(), &["add", "history.txt"]);
        git(
            workspace.path(),
            &["commit", "--quiet", "-m", "third commit"],
        );

        fs::write(workspace.path().join("stage-a.txt"), "new staged a\n").unwrap();
        fs::write(workspace.path().join("stage-b.txt"), "new staged b\n").unwrap();
        git(workspace.path(), &["add", "stage-a.txt", "stage-b.txt"]);
        fs::write(workspace.path().join("stage-a.txt"), "worktree staged a\n").unwrap();
        fs::write(
            workspace.path().join("tracked.txt"),
            format!("first line\n{}\nthird line\n", "x".repeat(1800)),
        )
        .unwrap();

        let service = service(workspace.path());
        let repository_id = service
            .repositories(WorkspaceReadParams { context: context() }, &long_control())
            .unwrap()
            .repositories
            .0[0]
            .repository_id;
        let status = service
            .status(
                GitStatusParams {
                    context: context(),
                    repository_id,
                    state_token: None,
                    cursor: None,
                    limit: 200u32.try_into().unwrap(),
                },
                &long_control(),
            )
            .unwrap();
        let status_by_name = status
            .entries
            .0
            .iter()
            .map(|entry| (entry.display_name.as_str(), entry.entry_id))
            .collect::<HashMap<_, _>>();

        let first_index_page = service
            .diff(
                GitDiffParams {
                    context: context(),
                    repository_id,
                    state_token: status.state_token.clone(),
                    entry_id: None,
                    view: DiffView::Index,
                    cursor: None,
                    limit: 1u32.try_into().unwrap(),
                },
                &long_control(),
            )
            .unwrap();
        assert_eq!(first_index_page.files.0.len(), 1);
        assert_eq!(
            first_index_page.files.0[0].display_name.as_str(),
            "stage-a.txt"
        );
        assert!(first_index_page.truncated);
        let first_file = &first_index_page.files.0[0];
        let first_lines = first_file.hunks.0.iter().flat_map(|hunk| &hunk.lines.0);
        assert!(
            first_lines
                .clone()
                .any(|line| line.kind == DiffLineKind::Removed)
        );
        assert!(
            first_lines
                .clone()
                .any(|line| line.kind == DiffLineKind::Added)
        );
        assert!(
            first_file
                .hunks
                .0
                .iter()
                .all(|hunk| hunk.lines.0.len() <= 200)
        );
        let second_index_page = service
            .diff(
                GitDiffParams {
                    context: context(),
                    repository_id,
                    state_token: status.state_token.clone(),
                    entry_id: None,
                    view: DiffView::Index,
                    cursor: first_index_page.next_cursor.clone(),
                    limit: 1u32.try_into().unwrap(),
                },
                &long_control(),
            )
            .unwrap();
        assert_eq!(second_index_page.files.0.len(), 1);
        assert_eq!(
            second_index_page.files.0[0].display_name.as_str(),
            "stage-b.txt"
        );
        assert!(!second_index_page.truncated);

        let tracked_id = status_by_name["tracked.txt"];
        let worktree_diff = service
            .diff(
                GitDiffParams {
                    context: context(),
                    repository_id,
                    state_token: status.state_token.clone(),
                    entry_id: Some(tracked_id),
                    view: DiffView::Worktree,
                    cursor: None,
                    limit: 5u32.try_into().unwrap(),
                },
                &long_control(),
            )
            .unwrap();
        assert_eq!(worktree_diff.files.0.len(), 1);
        assert_eq!(
            worktree_diff.files.0[0].display_name.as_str(),
            "tracked.txt"
        );
        assert!(!worktree_diff.files.0[0].binary);
        assert!(worktree_diff.files.0[0].truncated);
        assert!(
            worktree_diff.files.0[0]
                .hunks
                .0
                .iter()
                .flat_map(|hunk| &hunk.lines.0)
                .all(|line| line.text.as_str().len() <= 4096)
        );

        let first_log = service
            .log(
                GitLogParams {
                    context: context(),
                    repository_id,
                    state_token: status.state_token.clone(),
                    cursor: None,
                    limit: 2u32.try_into().unwrap(),
                },
                &long_control(),
            )
            .unwrap();
        assert_eq!(first_log.commits.0.len(), 2);
        assert_eq!(first_log.commits.0[0].subject.as_str(), "third commit");
        assert!(first_log.truncated);
        let next_log = service
            .log(
                GitLogParams {
                    context: context(),
                    repository_id,
                    state_token: status.state_token.clone(),
                    cursor: first_log.next_cursor,
                    limit: 2u32.try_into().unwrap(),
                },
                &long_control(),
            )
            .unwrap();
        assert_eq!(next_log.commits.0.len(), 1);
        assert_eq!(next_log.commits.0[0].subject.as_str(), "first commit");
        assert!(!next_log.truncated);

        let first_show_page = service
            .show(
                GitShowParams {
                    context: context(),
                    repository_id,
                    state_token: status.state_token.clone(),
                    object_id: ObjectId::try_from(show_object.clone()).unwrap(),
                    cursor: None,
                    limit: 1u32.try_into().unwrap(),
                },
                &long_control(),
            )
            .unwrap();
        assert_eq!(first_show_page.commit.subject.as_str(), "show fixture");
        assert_eq!(first_show_page.diff.files.0.len(), 1);
        assert_eq!(
            first_show_page.diff.files.0[0].display_name.as_str(),
            "show-a.txt"
        );
        assert!(first_show_page.diff.truncated);
        let second_show_page = service
            .show(
                GitShowParams {
                    context: context(),
                    repository_id,
                    state_token: status.state_token,
                    object_id: ObjectId::try_from(show_object).unwrap(),
                    cursor: first_show_page.diff.next_cursor,
                    limit: 1u32.try_into().unwrap(),
                },
                &long_control(),
            )
            .unwrap();
        assert_eq!(second_show_page.diff.files.0.len(), 1);
        assert_eq!(
            second_show_page.diff.files.0[0].display_name.as_str(),
            "show-b.txt"
        );
        assert!(!second_show_page.diff.truncated);
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_admission_rejects_symlinks_hardlinks_special_files_and_cancellation() {
        use std::os::unix::fs::symlink;
        use std::os::unix::net::UnixListener;

        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir_all(workspace.path().join("repo/.git")).unwrap();
        fs::write(
            workspace.path().join("repo/.git/HEAD"),
            "ref: refs/heads/main\n",
        )
        .unwrap();
        fs::write(outside.path().join("secret"), "outside-data\n").unwrap();
        let link = workspace.path().join("repo/link");
        symlink(outside.path().join("secret"), &link).unwrap();
        let service = service(workspace.path());
        let repo_id = service
            .repositories(WorkspaceReadParams { context: context() }, &control())
            .unwrap()
            .repositories
            .0[0]
            .repository_id;

        let request = |cancellation: CancellationToken| {
            service.status(
                GitStatusParams {
                    context: context(),
                    repository_id: repo_id,
                    state_token: None,
                    cursor: None,
                    limit: 10u32.try_into().unwrap(),
                },
                &RequestControl::with_timeout(cancellation, Duration::from_secs(2)).unwrap(),
            )
        };
        assert_eq!(
            request(CancellationToken::new()).unwrap_err(),
            GitServiceError::UnsafeRepository
        );

        fs::remove_file(&link).unwrap();
        fs::hard_link(
            outside.path().join("secret"),
            workspace.path().join("repo/hardlink"),
        )
        .unwrap();
        assert_eq!(
            request(CancellationToken::new()).unwrap_err(),
            GitServiceError::UnsafeRepository
        );

        fs::remove_file(workspace.path().join("repo/hardlink")).unwrap();
        let socket_path = workspace.path().join("repo/socket");
        let _socket = UnixListener::bind(&socket_path).unwrap();
        assert_eq!(
            request(CancellationToken::new()).unwrap_err(),
            GitServiceError::UnsafeRepository
        );

        drop(_socket);
        fs::remove_file(socket_path).unwrap();
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert_eq!(request(cancelled), Err(GitServiceError::Cancelled));
        assert_eq!(
            fs::read(outside.path().join("secret")).unwrap(),
            b"outside-data\n"
        );
    }

    #[test]
    fn aliases_of_one_common_directory_share_cancellation_aware_lock() {
        let identity = FileIdentity(vec![7, 8, 9]);
        let lock_a = common_repository_lock(&identity);
        let lock_b = common_repository_lock(&identity);
        let waiter_lock = lock_b.clone();
        let held = lock_a.acquire(&control()).unwrap();
        let cancellation = CancellationToken::new();
        let waiter_control =
            RequestControl::with_timeout(cancellation.clone(), Duration::from_secs(2)).unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let waiter = thread::spawn(move || {
            started_tx.send(()).unwrap();
            waiter_lock.acquire(&waiter_control).map(|_guard| ())
        });
        started_rx.recv().unwrap();
        cancellation.cancel();
        assert_eq!(waiter.join().unwrap(), Err(GitServiceError::Cancelled));
        drop(held);
        assert!(lock_b.acquire(&control()).is_ok());
    }

    #[test]
    fn linked_common_directory_alias_has_same_repository_lock_identity() {
        let workspace = tempfile::tempdir().unwrap();
        fs::create_dir_all(workspace.path().join("common/worktrees/one")).unwrap();
        fs::create_dir_all(workspace.path().join("common/worktrees/two")).unwrap();
        for name in ["one", "two"] {
            let gitdir = workspace.path().join("common/worktrees").join(name);
            fs::write(gitdir.join("HEAD"), "ref: refs/heads/branch\n").unwrap();
            fs::write(gitdir.join("commondir"), "../..\n").unwrap();
            let worktree = workspace.path().join(name);
            fs::create_dir_all(&worktree).unwrap();
            fs::write(
                worktree.join(".git"),
                format!("gitdir: ../common/worktrees/{name}\n"),
            )
            .unwrap();
        }
        let service = service(workspace.path());
        let found = service
            .repositories(WorkspaceReadParams { context: context() }, &control())
            .unwrap();
        assert_eq!(found.repositories.0.len(), 2);
        let repositories = service.repositories.lock().unwrap();
        let mut common_ids: Vec<_> = repositories
            .values()
            .map(|repo| repo.common_identity.clone())
            .collect();
        common_ids.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(common_ids[0], common_ids[1]);
    }

    #[test]
    fn stage_unstage_and_stage_deletion_publish_real_index_updates() {
        let (workspace, service, repository_id) = mutation_fixture();
        fs::write(workspace.path().join("tracked.txt"), "staged contents\n").unwrap();

        let status = mutation_status(&service, repository_id);
        let entry = status
            .entries
            .0
            .iter()
            .find(|entry| entry.display_name.as_str() == "tracked.txt")
            .unwrap();
        let prepared = service
            .prepare_stage(
                stage_params(repository_id, &status, entry, 20),
                &mutation_control(),
            )
            .unwrap();
        // Preparation runs only against the private snapshot.
        assert_eq!(
            git_output(workspace.path(), &["show", ":tracked.txt"]),
            "initial contents"
        );
        prepared.publish(&mutation_control()).unwrap();
        assert_eq!(
            git_output(workspace.path(), &["show", ":tracked.txt"]),
            "staged contents"
        );

        let staged = mutation_status(&service, repository_id);
        let staged_entry = staged
            .entries
            .0
            .iter()
            .find(|entry| entry.display_name.as_str() == "tracked.txt")
            .unwrap();
        assert_eq!(staged_entry.index, GitChange::Modified);
        let unstage = lomi_remote_protocol::rpc::GitUnstageParams {
            mutation: GitMutationContext {
                operation_id: OperationId::from_bytes([21; 16]).unwrap(),
                context: context(),
            },
            repository_id,
            expected: GitPreconditions {
                head: staged.head.clone(),
                index: staged.index.clone(),
            },
            paths: BoundedList(vec![staged_entry.entry_id]),
        };
        service
            .prepare_unstage(unstage, &mutation_control())
            .unwrap()
            .publish(&mutation_control())
            .unwrap();
        assert_eq!(
            git_output(workspace.path(), &["show", ":tracked.txt"]),
            "initial contents"
        );

        fs::write(workspace.path().join("deleted.txt"), "delete me\n").unwrap();
        git(workspace.path(), &["add", "deleted.txt"]);
        git(
            workspace.path(),
            &["commit", "--quiet", "--message", "add deletable fixture"],
        );
        fs::remove_file(workspace.path().join("deleted.txt")).unwrap();
        let deleted_status = mutation_status(&service, repository_id);
        let deleted_entry = deleted_status
            .entries
            .0
            .iter()
            .find(|entry| entry.display_name.as_str() == "deleted.txt")
            .unwrap();
        assert_eq!(deleted_entry.worktree, GitChange::Deleted);
        service
            .prepare_stage(
                stage_params(repository_id, &deleted_status, deleted_entry, 22),
                &mutation_control(),
            )
            .unwrap()
            .publish(&mutation_control())
            .unwrap();
        assert!(
            git_output(workspace.path(), &["diff", "--cached", "--name-status"])
                .contains("D\tdeleted.txt")
        );
    }

    #[test]
    fn staging_deleted_parent_and_absent_nested_branch_checks_the_nearest_existing_directory() {
        let (workspace, service, repository_id) = mutation_fixture();
        let nested = workspace.path().join("nested/child");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("deleted.txt"), "delete with parents\n").unwrap();
        git(workspace.path(), &["add", "nested/child/deleted.txt"]);
        git(
            workspace.path(),
            &["commit", "--quiet", "--message", "add nested fixture"],
        );
        fs::remove_dir_all(workspace.path().join("nested")).unwrap();

        let status = mutation_status(&service, repository_id);
        let deleted_entry = status
            .entries
            .0
            .iter()
            .find(|entry| {
                entry
                    .display_name
                    .as_str()
                    .ends_with("nested/child/deleted.txt")
            })
            .unwrap();
        let prepared = service
            .prepare_stage(
                stage_params(repository_id, &status, deleted_entry, 23),
                &mutation_control(),
            )
            .unwrap();
        fs::create_dir(workspace.path().join("nested")).unwrap();
        assert_eq!(
            prepared.publish(&mutation_control()),
            Err(GitServiceError::MutationConflict)
        );
        fs::remove_dir(workspace.path().join("nested")).unwrap();

        let status = mutation_status(&service, repository_id);
        let deleted_entry = status
            .entries
            .0
            .iter()
            .find(|entry| {
                entry
                    .display_name
                    .as_str()
                    .ends_with("nested/child/deleted.txt")
            })
            .unwrap();
        service
            .prepare_stage(
                stage_params(repository_id, &status, deleted_entry, 24),
                &mutation_control(),
            )
            .unwrap()
            .publish(&mutation_control())
            .unwrap();
        assert!(
            git_output(workspace.path(), &["diff", "--cached", "--name-status"])
                .contains("D\tnested/child/deleted.txt")
        );

        // A valid packed-only nested branch may have no loose `feature/`
        // directory. Stage still guards its absence from the nearest existing
        // refs directory rather than rejecting the repository.
        fs::write(workspace.path().join("tracked.txt"), "branch edit\n").unwrap();
        fs::write(
            workspace.path().join(".git/HEAD"),
            "ref: refs/heads/feature/x\n",
        )
        .unwrap();
        let status = mutation_status(&service, repository_id);
        let entry = status
            .entries
            .0
            .iter()
            .find(|entry| entry.display_name.as_str() == "tracked.txt")
            .unwrap();
        let prepared = service
            .prepare_stage(
                stage_params(repository_id, &status, entry, 25),
                &mutation_control(),
            )
            .unwrap();
        fs::create_dir(workspace.path().join(".git/refs/heads/feature")).unwrap();
        assert_eq!(
            prepared.publish(&mutation_control()),
            Err(GitServiceError::MutationConflict)
        );
        fs::remove_dir(workspace.path().join(".git/refs/heads/feature")).unwrap();

        let status = mutation_status(&service, repository_id);
        let entry = status
            .entries
            .0
            .iter()
            .find(|entry| entry.display_name.as_str() == "tracked.txt")
            .unwrap();
        service
            .prepare_stage(
                stage_params(repository_id, &status, entry, 26),
                &mutation_control(),
            )
            .unwrap()
            .publish(&mutation_control())
            .unwrap();
        assert_eq!(
            git_output(workspace.path(), &["show", ":tracked.txt"]),
            "branch edit"
        );
    }

    #[test]
    fn chained_symbolic_head_leaf_advancement_conflicts_with_prepared_stage() {
        let (workspace, service, repository_id) = mutation_fixture();
        let reference = git_output(workspace.path(), &["symbolic-ref", "HEAD"]);
        let tree = git_output(workspace.path(), &["rev-parse", "HEAD^{tree}"]);
        let commit = git_output(
            workspace.path(),
            &["commit-tree", &tree, "-m", "advance chained head"],
        );
        fs::write(
            workspace.path().join(".git/HEAD"),
            "ref: refs/heads/alias\n",
        )
        .unwrap();
        fs::write(
            workspace.path().join(".git/refs/heads/alias"),
            format!("ref: {reference}\n"),
        )
        .unwrap();
        let control = mutation_control();
        let repository = service.refresh_repository(repository_id, &control).unwrap();
        let repository_lock = common_repository_lock(&repository.common_identity)
            .acquire(&control)
            .unwrap();
        let snapshot = service.create_snapshot(&repository, &control).unwrap();
        let publication = make_index_publication(&repository, &snapshot, Vec::new()).unwrap();
        let prepared = PreparedGitMutation {
            files: service.files.clone(),
            publication,
            request_control: control.clone(),
            post_state: PostStateReader::new(&service, repository.clone()),
            _repository_lock: repository_lock,
        };
        git(workspace.path(), &["update-ref", &reference, &commit]);
        assert_eq!(
            prepared.publish(&mutation_control()),
            Err(GitServiceError::MutationConflict)
        );
    }

    #[test]
    fn stage_rejects_git_metadata_paths_and_windows_alias_spellings() {
        for path in [
            b".git/config".as_slice(),
            b".Git/index".as_slice(),
            b"dir/.GIT/objects".as_slice(),
            b"GIT~1/config".as_slice(),
            b".git./config".as_slice(),
        ] {
            assert!(!allowed_git_path(path), "unsafe mutation path: {path:?}");
        }

        let (workspace, service, repository_id) = mutation_fixture();
        let status = mutation_status(&service, repository_id);
        let repository = service
            .refresh_repository(repository_id, &mutation_control())
            .unwrap();
        let snapshot = service
            .create_snapshot(&repository, &mutation_control())
            .unwrap();
        let config = snapshot
            .files
            .get(&RelPath(vec![b".git".to_vec(), b"config".to_vec()]))
            .unwrap();
        let params = GitStageParams {
            mutation: GitMutationContext {
                operation_id: OperationId::from_bytes([28; 16]).unwrap(),
                context: context(),
            },
            repository_id,
            expected: GitPreconditions {
                head: status.head.clone(),
                index: status.index.clone(),
            },
            paths: BoundedList(vec![GitStagePath {
                entry_id: EntryId::from_bytes(config.entry.to_bytes()).unwrap(),
                file_revision: FileRevision::try_from(config.revision.clone()).unwrap(),
            }]),
        };
        assert!(matches!(
            service.prepare_stage(params, &mutation_control()),
            Err(GitServiceError::MutationConflict)
        ));
        assert!(workspace.path().join(".git/config").is_file());
    }

    #[test]
    fn stage_accepts_200_paths_with_a_long_valid_path_and_rejects_201() {
        let (workspace, service, repository_id) = mutation_fixture();
        let mut long_components = Vec::new();
        for index in 0..9 {
            let component = format!("segment-{index}-{}", "x".repeat(210));
            long_components.push(component);
        }
        long_components.push("long-file.txt".to_owned());
        let long_relative = long_components.join("/");
        assert!(long_relative.len() > 1800 && long_relative.len() < 3072);
        assert!(allowed_git_path(long_relative.as_bytes()));

        fs::write(
            workspace.path().join("blob-source.txt"),
            "shared staged blob\n",
        )
        .unwrap();
        let blob_id = git_output(workspace.path(), &["hash-object", "-w", "blob-source.txt"]);
        fs::remove_file(workspace.path().join("blob-source.txt")).unwrap();
        let mut index_info = String::new();
        for index in 0..199 {
            use std::fmt::Write as _;
            let _ = writeln!(index_info, "100644 {blob_id} 0\tbatch-{index:03}.txt");
        }
        use std::fmt::Write as _;
        let _ = writeln!(index_info, "100644 {blob_id} 0\t{long_relative}");
        git_with_stdin(
            workspace.path(),
            &["update-index", "--index-info"],
            index_info.as_bytes(),
        );
        git(
            workspace.path(),
            &[
                "commit",
                "--quiet",
                "--message",
                "add bounded batch fixture",
            ],
        );

        let status = mutation_status(&service, repository_id);
        assert_eq!(status.entries.0.len(), 200);
        let mut params = stage_params(repository_id, &status, &status.entries.0[0], 29);
        params.paths = BoundedList(
            status
                .entries
                .0
                .iter()
                .map(|entry| GitStagePath {
                    entry_id: entry.entry_id,
                    file_revision: entry.file_revision.clone(),
                })
                .collect(),
        );
        let mut too_many = params.clone();
        too_many.paths.0.push(too_many.paths.0[0].clone());
        assert!(matches!(
            service.prepare_stage(too_many, &mutation_control()),
            Err(GitServiceError::ResourceLimit)
        ));
        service
            .prepare_stage(params, &mutation_control())
            .unwrap()
            .publish(&mutation_control())
            .unwrap();
        assert_eq!(
            git_output(workspace.path(), &["diff", "--cached", "--name-only"])
                .lines()
                .count(),
            200
        );
        assert!(
            git_output(workspace.path(), &["diff", "--cached", "--name-only"])
                .contains(&long_relative)
        );
    }

    #[test]
    fn prepared_mutations_recheck_file_index_and_head_and_honor_cancellation() {
        let (workspace, service, repository_id) = mutation_fixture();
        fs::write(workspace.path().join("tracked.txt"), "first edit\n").unwrap();

        let status = mutation_status(&service, repository_id);
        let entry = status
            .entries
            .0
            .iter()
            .find(|entry| entry.display_name.as_str() == "tracked.txt")
            .unwrap();
        let prepared = service
            .prepare_stage(
                stage_params(repository_id, &status, entry, 30),
                &mutation_control(),
            )
            .unwrap();
        fs::write(workspace.path().join("tracked.txt"), "raced edit\n").unwrap();
        assert_eq!(
            prepared.publish(&mutation_control()),
            Err(GitServiceError::MutationConflict)
        );
        assert_eq!(
            git_output(workspace.path(), &["show", ":tracked.txt"]),
            "initial contents"
        );

        let status = mutation_status(&service, repository_id);
        let entry = status
            .entries
            .0
            .iter()
            .find(|entry| entry.display_name.as_str() == "tracked.txt")
            .unwrap();
        let prepared = service
            .prepare_stage(
                stage_params(repository_id, &status, entry, 31),
                &mutation_control(),
            )
            .unwrap();
        fs::write(workspace.path().join("external.txt"), "external change\n").unwrap();
        git(workspace.path(), &["add", "external.txt"]);
        assert_eq!(
            prepared.publish(&mutation_control()),
            Err(GitServiceError::MutationConflict)
        );
        assert_eq!(
            git_output(workspace.path(), &["show", ":tracked.txt"]),
            "initial contents"
        );

        let status = mutation_status(&service, repository_id);
        let entry = status
            .entries
            .0
            .iter()
            .find(|entry| entry.display_name.as_str() == "tracked.txt")
            .unwrap();
        let prepared = service
            .prepare_stage(
                stage_params(repository_id, &status, entry, 32),
                &mutation_control(),
            )
            .unwrap();
        let tree = git_output(workspace.path(), &["rev-parse", "HEAD^{tree}"]);
        let commit = git_output(
            workspace.path(),
            &["commit-tree", &tree, "-m", "advance head during prepare"],
        );
        let reference = git_output(workspace.path(), &["symbolic-ref", "HEAD"]);
        git(workspace.path(), &["update-ref", &reference, &commit]);
        assert_eq!(
            prepared.publish(&mutation_control()),
            Err(GitServiceError::MutationConflict)
        );

        let status = mutation_status(&service, repository_id);
        let entry = status
            .entries
            .0
            .iter()
            .find(|entry| entry.display_name.as_str() == "tracked.txt")
            .unwrap();
        let cancellation = CancellationToken::new();
        let original_control =
            RequestControl::with_timeout(cancellation.clone(), Duration::from_secs(15)).unwrap();
        let prepared = service
            .prepare_stage(
                stage_params(repository_id, &status, entry, 33),
                &original_control,
            )
            .unwrap();
        cancellation.cancel();
        assert_eq!(
            prepared.publish(&mutation_control()),
            Err(GitServiceError::Cancelled)
        );
        assert_eq!(
            git_output(workspace.path(), &["show", ":tracked.txt"]),
            "initial contents"
        );

        let status = mutation_status(&service, repository_id);
        let entry = status
            .entries
            .0
            .iter()
            .find(|entry| entry.display_name.as_str() == "tracked.txt")
            .unwrap();
        let original_control = long_control();
        let mut prepared = service
            .prepare_stage(
                stage_params(repository_id, &status, entry, 34),
                &original_control,
            )
            .unwrap();
        prepared.request_control.deadline = Instant::now() - Duration::from_millis(1);
        assert_eq!(
            prepared.publish(&mutation_control()),
            Err(GitServiceError::DeadlineExceeded)
        );
        assert_eq!(
            git_output(workspace.path(), &["show", ":tracked.txt"]),
            "initial contents"
        );
    }

    #[test]
    fn prepared_mutation_holds_the_shared_repository_lock_until_publish_or_drop() {
        let (workspace, service, repository_id) = mutation_fixture();
        fs::write(workspace.path().join("tracked.txt"), "pending edit\n").unwrap();
        let status = mutation_status(&service, repository_id);
        let entry = status
            .entries
            .0
            .iter()
            .find(|entry| entry.display_name.as_str() == "tracked.txt")
            .unwrap();
        let prepared = service
            .prepare_stage(
                stage_params(repository_id, &status, entry, 40),
                &mutation_control(),
            )
            .unwrap();

        let read_service = service.clone();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let reader = thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = mutation_status(&read_service, repository_id);
            finished_tx.send(result).unwrap();
        });
        started_rx.recv().unwrap();
        assert!(finished_rx.recv_timeout(Duration::from_millis(50)).is_err());
        drop(prepared);
        assert!(finished_rx.recv_timeout(Duration::from_secs(15)).is_ok());
        reader.join().unwrap();
    }
}
