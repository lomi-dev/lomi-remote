//! Local, network-free remote metadata admission.
//!
//! This module deliberately discovers remotes from the repository's own
//! `.git/config` through `FileRoot`. It never asks libgit2 to enumerate a
//! remote and never contacts a server.

use super::*;
use git2::{
    Config, Cred, CredentialType, Delta, DiffOptions, Direction, FetchOptions, ObjectType, Oid,
    ProxyOptions, PushOptions, RemoteCallbacks, RemoteRedirect, RemoteUpdateFlags,
    Repository as NativeRepository,
};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use url::Url;
use zeroize::Zeroizing;

const MAX_REMOTE_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_REMOTE_REF_BYTES: u64 = 16 * 1024 * 1024;
const MAX_REMOTE_REF_ENTRIES: usize = 100_000;
const MAX_REMOTE_OBJECTS: usize = 200_000;
const MAX_REMOTE_OBJECT_BYTES: usize = 64 * 1024 * 1024;
const NETWORK_WORKER_MAGIC: &[u8; 4] = b"LGNW";
const NETWORK_WORKER_VERSION: u8 = 1;
const MAX_NETWORK_WORKER_INPUT: usize = 2 * 1024 * 1024;
const MAX_NETWORK_WORKER_OUTPUT: usize = 8192;
const MAX_NETWORK_CREDENTIAL_BYTES: usize = 16 * 1024;
const NETWORK_WORKER_POLL: Duration = Duration::from_millis(10);

#[derive(Clone)]
pub(super) struct RemoteBinding {
    pub remote_id: RemoteId,
    pub name: String,
    pub url: String,
    pub config_fingerprint: RepoStateToken,
    pub refs_state_token: RepoStateToken,
    pub selectors: Vec<RemoteSelector>,
}

#[derive(Clone)]
pub(super) struct RemoteSelector {
    pub ref_id: RefId,
    pub kind: SelectorKind,
    pub value: String,
    pub pull_refspec: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SelectorKind {
    Head,
    Fetch,
    Push,
}

/// A prepared fetch holds the repository lock and a private writable copy.
/// The supplied start callback is called once, immediately before network
/// dispatch, so the host can durably record authorization first.
pub struct PreparedGitFetch {
    files: Arc<FileRoot>,
    repository: Repository,
    remote: RemoteBinding,
    selector: RemoteSelector,
    snapshot: PrivateSnapshot,
    request_control: RequestControl,
    post_state: PostStateReader,
    _repository_lock: RepoLockGuard,
}

/// A prepared push holds the same physical repository lock through the
/// one-shot external operation.
pub struct PreparedGitPush {
    files: Arc<FileRoot>,
    remote: RemoteBinding,
    selector: RemoteSelector,
    snapshot: PrivateSnapshot,
    request_control: RequestControl,
    post_state: PostStateReader,
    _repository_lock: RepoLockGuard,
}

/// A pull request whose clean worktree and HEAD/index tokens were checked
/// before its one-shot remote fetch.
pub struct PreparedGitPull {
    fetch: PreparedGitFetch,
    expected: GitPreconditions,
    expected_worktree: RepoStateToken,
}

/// A prepared pull retains the physical-repository lease until publication
/// occurs inside the host's owner/revoke barrier.
pub struct PreparedGitPullMutation {
    files: Arc<FileRoot>,
    publication: GitPullPublication,
    request_control: RequestControl,
    post_state: PostStateReader,
    _repository_lock: RepoLockGuard,
}

/// The remote side's push receipt. `PossibleRemoteEffect` must be journaled as
/// unknown and must never be retried automatically.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitPushOutcome {
    NoEffect,
    FailedNoEffect(GitServiceError),
    Rejected,
    Committed,
    PossibleRemoteEffect,
}

/// Entry point selected by the host executable before starting its UI or
/// service runtime. The worker accepts one bounded request on stdin and emits
/// one bounded result on stdout. It never reads ambient Git configuration.
pub fn internal_network_worker() -> i32 {
    match network_worker_main() {
        Ok(()) => 0,
        Err(()) => 70,
    }
}

struct NetworkWorkerRequest {
    bytes: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for NetworkWorkerRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NetworkWorkerRequest([REDACTED])")
    }
}

#[derive(Debug)]
enum NetworkWorkerResult {
    Fetch {
        source: String,
        destination: String,
        tip: String,
    },
    Push(GitPushOutcome),
    Failed(GitServiceError),
}

#[derive(Clone, Copy)]
enum WorkerKind {
    Fetch = 1,
    Push = 2,
}

enum WorkerRunError {
    Spawn(GitServiceError),
    Running(GitServiceError),
}

#[derive(Default)]
struct RemoteConfig {
    urls: Vec<String>,
    push_urls: Vec<String>,
    fetch: Vec<String>,
    push: Vec<String>,
}

#[derive(Default)]
struct BranchConfig {
    remote: Option<String>,
    merge: Option<String>,
    push_remote: Option<String>,
}

#[derive(Default)]
struct LocalConfig {
    remotes: BTreeMap<String, RemoteConfig>,
    branches: BTreeMap<String, BranchConfig>,
    push_default: Option<String>,
}

impl GitService {
    pub(super) fn remote_descriptions(
        &self,
        repository: &Repository,
        control: &RequestControl,
    ) -> Result<Vec<GitRemote>, GitServiceError> {
        let bindings = self.read_remote_bindings(repository, control)?;
        bindings
            .into_iter()
            .map(|binding| {
                let display_name = DisplayText::try_from(sanitize_display_name(&binding.name))
                    .map_err(|_| GitServiceError::UnsupportedCapability)?;
                let selectors = binding
                    .selectors
                    .iter()
                    .map(|selector| {
                        let display_name =
                            selector_display_name(selector.kind, &selector.value, &binding.name)?;
                        let (fetch, pull, push) = match selector.kind {
                            SelectorKind::Head => (true, false, false),
                            SelectorKind::Fetch => (true, selector.pull_refspec.is_some(), false),
                            SelectorKind::Push => (false, false, true),
                        };
                        Ok(GitRemoteSelector {
                            kind: match selector.kind {
                                SelectorKind::Head => GitRemoteSelectorKind::Head,
                                SelectorKind::Fetch => GitRemoteSelectorKind::Fetch,
                                SelectorKind::Push => GitRemoteSelectorKind::Push,
                            },
                            ref_id: selector.ref_id.clone(),
                            display_name,
                            fetch,
                            pull,
                            push,
                        })
                    })
                    .collect::<Result<Vec<_>, GitServiceError>>()?;
                Ok(GitRemote {
                    remote_id: binding.remote_id,
                    display_name,
                    refs_state_token: binding.refs_state_token,
                    refs: BoundedList(
                        binding
                            .selectors
                            .iter()
                            .map(|selector| selector.ref_id.clone())
                            .collect(),
                    ),
                    selectors: BoundedList(selectors),
                })
            })
            .collect()
    }

    pub(super) fn read_remote_bindings(
        &self,
        repository: &Repository,
        control: &RequestControl,
    ) -> Result<Vec<RemoteBinding>, GitServiceError> {
        control.check()?;
        self.revalidate_entry(&repository.root_meta, control)?;
        self.revalidate_entry(&repository.git_marker, control)?;
        self.revalidate_entry(&repository.gitdir, control)?;
        self.revalidate_entry(&repository.commondir, control)?;

        let config_path = vec![b"config".as_slice()];
        let config_bytes = self.read_git_metadata_file(
            repository.git_marker.entry,
            &config_path,
            MAX_REMOTE_CONFIG_BYTES,
            control,
        )?;
        let config_bytes = config_bytes.unwrap_or_default();
        if contains_config_include(&config_bytes) {
            return Err(GitServiceError::UnsupportedCapability);
        }
        let config = parse_local_config(&config_bytes)?;
        let current_branch = self.read_current_branch(repository, control)?;

        let mut refs_state = Sha256::new();
        refs_state.update(b"lomi-git-remote-state-v1\0");
        refs_state.update((config_bytes.len() as u64).to_le_bytes());
        refs_state.update(&config_bytes);
        refs_state.update(b"current-branch\0");
        if let Some(branch) = current_branch.as_deref() {
            refs_state.update((branch.len() as u64).to_le_bytes());
            refs_state.update(branch.as_bytes());
        } else {
            refs_state.update(0u64.to_le_bytes());
        }
        self.hash_optional_git_file(
            repository.commondir.entry,
            &[b"packed-refs"],
            MAX_REMOTE_REF_BYTES,
            &mut refs_state,
            control,
        )?;
        self.hash_remote_ref_tree(repository.commondir.entry, &mut refs_state, control)?;
        let refs_state_token =
            RepoStateToken::try_from(token_hex(refs_state.finalize().as_slice()))
                .map_err(|_| GitServiceError::DiscoveryFailed)?;
        let config_fingerprint =
            RepoStateToken::try_from(token_hex(Sha256::digest(&config_bytes).as_slice()))
                .map_err(|_| GitServiceError::DiscoveryFailed)?;

        let mut out = Vec::with_capacity(config.remotes.len());
        for (name, mut values) in config.remotes {
            control.check()?;
            if !git2::Remote::is_valid_name(&name)
                || values.urls.len() != 1
                || !values.push_urls.is_empty()
            {
                return Err(GitServiceError::UnsupportedCapability);
            }
            let url = validate_https_remote(&values.urls[0])?;
            let remote_id = remote_id(repository, &name, &url)?;
            let upstream_fetch = current_branch
                .as_deref()
                .and_then(|branch_name| config.branches.get(branch_name))
                .and_then(|branch| pull_fetch_spec(&name, branch, &values.fetch));
            let mut raw_selectors = vec![(SelectorKind::Head, String::from("HEAD"))];
            for spec in values.fetch.drain(..) {
                validate_fetch_refspec(&spec, &name)?;
                raw_selectors.push((SelectorKind::Fetch, spec));
            }
            for spec in values.push.drain(..) {
                validate_push_refspec(&spec)?;
                raw_selectors.push((SelectorKind::Push, spec));
            }
            if !raw_selectors
                .iter()
                .any(|(kind, _)| *kind == SelectorKind::Push)
                && let Some(branch_name) = current_branch.as_deref()
                && let Some(branch) = config.branches.get(branch_name)
            {
                let push_remote = branch.push_remote.as_deref().or(branch.remote.as_deref());
                let push_default = config.push_default.as_deref().unwrap_or("simple");
                let source = format!("refs/heads/{branch_name}");
                let destination = match push_default {
                    "simple" if push_remote == Some(name.as_str()) => branch
                        .merge
                        .as_deref()
                        .filter(|merge| merge.strip_prefix("refs/heads/") == Some(branch_name))
                        .and_then(|merge| merge.strip_prefix("refs/heads/")),
                    "upstream" if push_remote == Some(name.as_str()) => branch
                        .merge
                        .as_deref()
                        .and_then(|merge| merge.strip_prefix("refs/heads/")),
                    "current"
                        if branch
                            .push_remote
                            .as_deref()
                            .is_none_or(|remote| remote == name) =>
                    {
                        Some(branch_name)
                    }
                    _ => None,
                };
                if let Some(destination) = destination {
                    let spec = format!("{source}:refs/heads/{destination}");
                    validate_push_refspec(&spec)?;
                    raw_selectors.push((SelectorKind::Push, spec));
                }
            }
            if let Some((configured_spec, exact_spec)) = &upstream_fetch
                && configured_spec != exact_spec
                && raw_selectors.len() < 200
            {
                validate_fetch_refspec(exact_spec, &name)?;
                raw_selectors.push((SelectorKind::Fetch, exact_spec.clone()));
            }
            raw_selectors.sort_by(|a, b| (a.0 as u8, &a.1).cmp(&(b.0 as u8, &b.1)));
            raw_selectors.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
            if raw_selectors.len() > 200 {
                return Err(GitServiceError::ResourceLimit);
            }
            let selectors = raw_selectors
                .into_iter()
                .map(|(kind, value)| {
                    let pull_refspec = upstream_fetch
                        .as_ref()
                        .filter(|(_, exact_spec)| {
                            kind == SelectorKind::Fetch && exact_spec == &value
                        })
                        .map(|(_, exact_spec)| exact_spec.clone());
                    let selector_kind = match kind {
                        SelectorKind::Head => "head:",
                        SelectorKind::Fetch => "fetch:",
                        SelectorKind::Push => "push:",
                    };
                    let mut digest = Sha256::new();
                    digest.update(b"lomi-git-ref-id-v1\0");
                    digest.update(remote_id.as_str().as_bytes());
                    digest.update(selector_kind.as_bytes());
                    digest.update(value.as_bytes());
                    let ref_id = RefId::try_from(token_hex(digest.finalize().as_slice()))
                        .map_err(|_| GitServiceError::DiscoveryFailed)?;
                    Ok(RemoteSelector {
                        ref_id,
                        kind,
                        value,
                        pull_refspec,
                    })
                })
                .collect::<Result<Vec<_>, GitServiceError>>()?;
            out.push(RemoteBinding {
                remote_id,
                name,
                url,
                config_fingerprint: config_fingerprint.clone(),
                refs_state_token: refs_state_token.clone(),
                selectors,
            });
        }
        if out.len() > 32 {
            return Err(GitServiceError::ResourceLimit);
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn read_current_branch(
        &self,
        repository: &Repository,
        control: &RequestControl,
    ) -> Result<Option<String>, GitServiceError> {
        let head = self
            .read_git_metadata_file(
                repository.git_marker.entry,
                &[b"HEAD"],
                MAX_GIT_POINTER_BYTES as u64,
                control,
            )?
            .ok_or(GitServiceError::UnsafeRepository)?;
        if head.len() > MAX_GIT_POINTER_BYTES {
            return Err(GitServiceError::UnsafeRepository);
        }
        let head_text =
            std::str::from_utf8(&head).map_err(|_| GitServiceError::UnsafeRepository)?;
        let head = head_text.strip_suffix('\n').unwrap_or(head_text);
        let head = head.strip_suffix('\r').unwrap_or(head);
        let Some(reference) = head.strip_prefix("ref: ") else {
            return Ok(None);
        };
        let Some(branch) = reference.strip_prefix("refs/heads/") else {
            return Err(GitServiceError::UnsafeRepository);
        };
        if !git2::Reference::is_valid_name(reference) {
            return Err(GitServiceError::UnsafeRepository);
        }
        Ok(Some(branch.to_owned()))
    }

    pub fn prepare_fetch(
        &self,
        params: GitNetworkParams,
        control: &RequestControl,
    ) -> Result<PreparedGitFetch, GitServiceError> {
        self.prepare_fetch_internal(params, control, false)
    }

    fn prepare_fetch_internal(
        &self,
        params: GitNetworkParams,
        control: &RequestControl,
        for_pull: bool,
    ) -> Result<PreparedGitFetch, GitServiceError> {
        self.check_context(&params.mutation.context)?;
        control.check()?;
        let repository = self.refresh_repository(params.repository_id, control)?;
        let repository_lock =
            common_repository_lock(&repository.common_identity).acquire(control)?;
        let bindings = self.read_remote_bindings(&repository, control)?;
        let remote = find_remote(&bindings, &params.remote_id)?;
        if remote.refs_state_token != params.expected_refs {
            return Err(GitServiceError::StaleState);
        }
        let selector = find_selector(remote, &params.ref_id)?;
        if !matches!(selector.kind, SelectorKind::Head | SelectorKind::Fetch) {
            return Err(GitServiceError::UnsupportedCapability);
        }
        let pull_refspec = selector.pull_refspec.clone();
        let mut selector = selector.clone();
        if for_pull {
            selector.value = selector
                .pull_refspec
                .clone()
                .ok_or(GitServiceError::UnsupportedCapability)?;
        }
        let snapshot = self.create_snapshot(&repository, control)?;
        let current = self.read_remote_bindings(&repository, control)?;
        let current_remote = find_remote(&current, &params.remote_id)?;
        if current_remote.refs_state_token != params.expected_refs
            || current_remote.config_fingerprint != remote.config_fingerprint
        {
            return Err(GitServiceError::MutationConflict);
        }
        if for_pull && find_selector(current_remote, &params.ref_id)?.pull_refspec != pull_refspec {
            return Err(GitServiceError::MutationConflict);
        }
        Ok(PreparedGitFetch {
            files: self.files.clone(),
            post_state: PostStateReader::new(self, repository.clone()),
            repository,
            remote: remote.clone(),
            selector,
            snapshot,
            request_control: control.clone(),
            _repository_lock: repository_lock,
        })
    }

    pub fn prepare_push(
        &self,
        params: GitNetworkParams,
        control: &RequestControl,
    ) -> Result<PreparedGitPush, GitServiceError> {
        self.check_context(&params.mutation.context)?;
        control.check()?;
        let repository = self.refresh_repository(params.repository_id, control)?;
        let repository_lock =
            common_repository_lock(&repository.common_identity).acquire(control)?;
        let bindings = self.read_remote_bindings(&repository, control)?;
        let remote = find_remote(&bindings, &params.remote_id)?;
        if remote.refs_state_token != params.expected_refs {
            return Err(GitServiceError::StaleState);
        }
        let selector = find_selector(remote, &params.ref_id)?;
        if selector.kind != SelectorKind::Push {
            return Err(GitServiceError::UnsupportedCapability);
        }
        let snapshot = self.create_snapshot(&repository, control)?;
        let current = self.read_remote_bindings(&repository, control)?;
        let current_remote = find_remote(&current, &params.remote_id)?;
        if current_remote.refs_state_token != params.expected_refs
            || current_remote.config_fingerprint != remote.config_fingerprint
        {
            return Err(GitServiceError::MutationConflict);
        }
        Ok(PreparedGitPush {
            files: self.files.clone(),
            remote: remote.clone(),
            selector: selector.clone(),
            snapshot,
            request_control: control.clone(),
            post_state: PostStateReader::new(self, repository),
            _repository_lock: repository_lock,
        })
    }

    pub fn prepare_pull(
        &self,
        params: GitPullParams,
        control: &RequestControl,
    ) -> Result<PreparedGitPull, GitServiceError> {
        let fetch = self.prepare_fetch_internal(
            GitNetworkParams {
                mutation: params.mutation,
                repository_id: params.repository_id,
                remote_id: params.remote_id,
                ref_id: params.ref_id,
                expected_refs: params.expected_refs,
            },
            control,
            true,
        )?;
        let status = worker::run_status(fetch.snapshot.path(), 0, 1, control)?;
        check_mutation_preconditions(&params.expected, &fetch.snapshot, &status.head)?;
        if params.expected_worktree.as_str() != fetch.snapshot.state_token
            || !status.entries.is_empty()
            || status.truncated
        {
            return Err(GitServiceError::MutationConflict);
        }
        Ok(PreparedGitPull {
            fetch,
            expected: params.expected,
            expected_worktree: params.expected_worktree,
        })
    }

    fn read_git_metadata_file(
        &self,
        root: EntryRef,
        path: &[&[u8]],
        max_bytes: u64,
        control: &RequestControl,
    ) -> Result<Option<Vec<u8>>, GitServiceError> {
        let mut parent = root;
        let mut path_so_far = RelPath::root();
        let mut found = None;
        for (index, component) in path.iter().enumerate() {
            control.check()?;
            path_so_far = path_so_far.joined(component);
            let last = index + 1 == path.len();
            let meta = if last {
                match self.lookup_optional_child(parent, &path_so_far, component, control)? {
                    Some(meta) => meta,
                    None => return Ok(None),
                }
            } else {
                self.lookup_child(parent, component, control)?
            };
            if (!last && meta.kind != Kind::Directory) || (last && meta.kind != Kind::File) {
                return Err(GitServiceError::UnsafeRepository);
            }
            found = Some(meta.clone());
            parent = meta.entry;
        }
        let Some(meta) = found else {
            return Err(GitServiceError::UnsafeRepository);
        };
        if meta.nlink != 1 || meta.size > max_bytes {
            return Err(if meta.nlink != 1 {
                GitServiceError::UnsafeRepository
            } else {
                GitServiceError::ResourceLimit
            });
        }
        let mut bytes = Vec::with_capacity(meta.size as usize);
        let mut offset = 0u64;
        loop {
            control.check()?;
            let chunk = self
                .files
                .read_snapshot_chunk(meta.entry, &meta.revision, offset, SNAPSHOT_READ_CHUNK)
                .map_err(map_file_error)?;
            if chunk.meta.revision != meta.revision || chunk.offset != offset {
                return Err(GitServiceError::RepositoryChanged);
            }
            if chunk.bytes.is_empty() {
                break;
            }
            offset = offset
                .checked_add(chunk.bytes.len() as u64)
                .ok_or(GitServiceError::ResourceLimit)?;
            if offset > meta.size || offset > max_bytes {
                return Err(GitServiceError::RepositoryChanged);
            }
            bytes.extend_from_slice(&chunk.bytes);
        }
        if offset != meta.size {
            return Err(GitServiceError::RepositoryChanged);
        }
        self.revalidate_entry(&meta, control)?;
        Ok(Some(bytes))
    }

    fn hash_optional_git_file(
        &self,
        root: EntryRef,
        path: &[&[u8]],
        max_bytes: u64,
        digest: &mut Sha256,
        control: &RequestControl,
    ) -> Result<(), GitServiceError> {
        let bytes = self.read_git_metadata_file(root, path, max_bytes, control)?;
        match bytes {
            Some(bytes) => {
                digest.update([1]);
                digest.update((bytes.len() as u64).to_le_bytes());
                digest.update(bytes);
            }
            None => digest.update([0]),
        }
        Ok(())
    }

    fn hash_remote_ref_tree(
        &self,
        common_dir: EntryRef,
        digest: &mut Sha256,
        control: &RequestControl,
    ) -> Result<(), GitServiceError> {
        let refs =
            match self.lookup_optional_child(common_dir, &RelPath::root(), b"refs", control)? {
                Some(meta) if meta.kind == Kind::Directory => meta,
                Some(_) => return Err(GitServiceError::UnsafeRepository),
                None => return Ok(()),
            };
        let remotes =
            match self.lookup_optional_child(refs.entry, &RelPath::root(), b"remotes", control)? {
                Some(meta) if meta.kind == Kind::Directory => meta,
                Some(_) => return Err(GitServiceError::UnsafeRepository),
                None => return Ok(()),
            };
        let mut count = 0usize;
        let mut total = 0u64;
        self.hash_directory(remotes, Vec::new(), digest, control, &mut count, &mut total)?;
        Ok(())
    }

    fn hash_directory(
        &self,
        directory: Meta,
        path: Vec<Vec<u8>>,
        digest: &mut Sha256,
        control: &RequestControl,
        count: &mut usize,
        total: &mut u64,
    ) -> Result<(), GitServiceError> {
        control.check()?;
        if path.len() > 64 {
            return Err(GitServiceError::ResourceLimit);
        }
        let mut cursor = None;
        let mut seen = HashSet::new();
        loop {
            let page = self
                .files
                .list(directory.entry, cursor.as_deref(), MAX_PAGE_SIZE)
                .map_err(map_file_error)?;
            for item in page.entries {
                control.check()?;
                *count += 1;
                if *count > MAX_REMOTE_REF_ENTRIES {
                    return Err(GitServiceError::ResourceLimit);
                }
                let mut child_path = path.clone();
                child_path.push(item.name.clone());
                digest.update((child_path.len() as u64).to_le_bytes());
                for part in &child_path {
                    digest.update((part.len() as u64).to_le_bytes());
                    digest.update(part);
                }
                match item.kind {
                    Kind::Directory => {
                        digest.update([b'd']);
                        self.hash_directory(item, child_path, digest, control, count, total)?;
                    }
                    Kind::File if item.nlink == 1 && item.size <= MAX_REMOTE_REF_BYTES => {
                        *total = total
                            .checked_add(item.size)
                            .ok_or(GitServiceError::ResourceLimit)?;
                        if *total > MAX_REMOTE_REF_BYTES {
                            return Err(GitServiceError::ResourceLimit);
                        }
                        digest.update([b'f']);
                        let bytes = self
                            .read_git_metadata_file(
                                directory.entry,
                                &[item.name.as_slice()],
                                MAX_REMOTE_REF_BYTES,
                                control,
                            )?
                            .ok_or(GitServiceError::RepositoryChanged)?;
                        digest.update((bytes.len() as u64).to_le_bytes());
                        digest.update(bytes);
                    }
                    Kind::File => return Err(GitServiceError::UnsafeRepository),
                    Kind::Symlink | Kind::Other => return Err(GitServiceError::UnsafeRepository),
                }
            }
            match page.next {
                Some(next) if page.truncated => {
                    if !seen.insert(next.clone()) {
                        return Err(GitServiceError::DiscoveryFailed);
                    }
                    cursor = Some(next);
                }
                Some(_) | None if page.truncated => return Err(GitServiceError::DiscoveryFailed),
                None => break,
                Some(_) => return Err(GitServiceError::DiscoveryFailed),
            }
        }
        self.revalidate_entry(&directory, control)?;
        Ok(())
    }
}

fn parse_local_config(bytes: &[u8]) -> Result<LocalConfig, GitServiceError> {
    let temp = tempfile::Builder::new()
        .prefix("lomi-git-config-")
        .tempfile()
        .map_err(|_| GitServiceError::DiscoveryFailed)?;
    let (mut file, path) = temp.into_parts();
    file.write_all(bytes)
        .and_then(|_| file.flush())
        .map_err(|_| GitServiceError::DiscoveryFailed)?;
    drop(file);
    let git_config = Config::open(&path).map_err(|_| GitServiceError::UnsupportedCapability)?;
    let mut config = LocalConfig::default();
    let entries = git_config
        .entries(None)
        .map_err(|_| GitServiceError::UnsupportedCapability)?;
    let mut unsupported = false;
    entries
        .for_each(|entry| {
            let Ok(name) = entry.name() else {
                unsupported = true;
                return;
            };
            let lower_name = name.to_ascii_lowercase();
            let Ok(value) = entry.value() else {
                if lower_name.starts_with("remote.") || lower_name.starts_with("branch.") {
                    unsupported = true;
                }
                return;
            };
            if lower_name.starts_with("url.")
                && (lower_name.ends_with(".insteadof") || lower_name.ends_with(".pushinsteadof"))
            {
                unsupported = true;
                return;
            }
            if lower_name.starts_with("remote.") {
                let rest = &name["remote.".len()..];
                let Some((remote_name, key)) = rest.rsplit_once('.') else {
                    unsupported = true;
                    return;
                };
                let remote = config.remotes.entry(remote_name.to_owned()).or_default();
                match key.to_ascii_lowercase().as_str() {
                    "url" => remote.urls.push(value.to_owned()),
                    "pushurl" => remote.push_urls.push(value.to_owned()),
                    "fetch" => remote.fetch.push(value.to_owned()),
                    "push" => remote.push.push(value.to_owned()),
                    _ => {}
                }
            } else if lower_name.starts_with("branch.") {
                let rest = &name["branch.".len()..];
                let Some((branch_name, key)) = rest.rsplit_once('.') else {
                    unsupported = true;
                    return;
                };
                let branch = config.branches.entry(branch_name.to_owned()).or_default();
                match key.to_ascii_lowercase().as_str() {
                    "remote" => branch.remote = Some(value.to_owned()),
                    "merge" => branch.merge = Some(value.to_owned()),
                    "pushremote" => branch.push_remote = Some(value.to_owned()),
                    _ => {}
                }
            } else if lower_name == "push.default" {
                config.push_default = Some(value.to_ascii_lowercase());
            }
        })
        .map_err(|_| GitServiceError::UnsupportedCapability)?;
    drop(git_config);
    if unsupported {
        return Err(GitServiceError::UnsupportedCapability);
    }
    config.remotes.retain(|_, remote| !remote.urls.is_empty());
    Ok(config)
}

fn contains_config_include(bytes: &[u8]) -> bool {
    for line in bytes.split(|byte| *byte == b'\n') {
        let line = line
            .split(|byte| *byte == b'#' || *byte == b';')
            .next()
            .unwrap_or_default();
        let line = line
            .iter()
            .copied()
            .skip_while(|byte| byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        if line.first() != Some(&b'[') {
            continue;
        }
        let section = line[1..]
            .split(|byte| byte.is_ascii_whitespace() || *byte == b']')
            .next()
            .unwrap_or_default();
        if section.eq_ignore_ascii_case(b"include") || section.eq_ignore_ascii_case(b"includeif") {
            return true;
        }
    }
    false
}

fn validate_https_remote(value: &str) -> Result<String, GitServiceError> {
    if value.len() > 4096 || value.contains('\0') {
        return Err(GitServiceError::UnsupportedCapability);
    }
    let url = Url::parse(value).map_err(|_| GitServiceError::UnsupportedCapability)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url
            .as_str()
            .strip_prefix("https://")
            .and_then(|rest| rest.split('/').next())
            .is_some_and(|authority| authority.contains('@'))
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(GitServiceError::UnsupportedCapability);
    }
    Ok(url.to_string())
}

/// Validate a URL supplied to the native host credential store using the same
/// closed HTTPS policy that protects Git remote dispatch.
pub fn validate_credential_url(value: &str) -> Result<(), GitServiceError> {
    validate_https_remote(value).map(|_| ())
}

/// Native secret stores must key the same canonical URL used for dispatch.
pub fn canonical_credential_url(value: &str) -> Result<String, GitServiceError> {
    validate_https_remote(value)
}

fn remote_id(repository: &Repository, name: &str, url: &str) -> Result<RemoteId, GitServiceError> {
    let mut digest = Sha256::new();
    digest.update(b"lomi-git-remote-id-v1\0");
    digest.update(repository.common_identity.0.as_slice());
    digest.update((name.len() as u64).to_le_bytes());
    digest.update(name.as_bytes());
    digest.update(Sha256::digest(url.as_bytes()));
    RemoteId::try_from(token_hex(digest.finalize().as_slice()))
        .map_err(|_| GitServiceError::DiscoveryFailed)
}

fn validate_fetch_refspec(value: &str, remote_name: &str) -> Result<(), GitServiceError> {
    let value = value.strip_prefix('+').unwrap_or(value);
    let (source, destination) = value
        .split_once(':')
        .ok_or(GitServiceError::UnsupportedCapability)?;
    let wildcard = source.ends_with("*") && destination.ends_with("*");
    if source.is_empty()
        || !source.starts_with("refs/heads/")
        || !destination.starts_with(&format!("refs/remotes/{remote_name}/"))
        || destination.contains(':')
        || source.contains('^')
        || source.matches('*').count() != usize::from(wildcard)
        || destination.matches('*').count() != usize::from(wildcard)
        || source.contains('\0')
        || destination.contains('\0')
    {
        return Err(GitServiceError::UnsupportedCapability);
    }
    let source_check = source.replace('*', "branch");
    let destination_check = destination.replace('*', "branch");
    if !git2::Reference::is_valid_name(&source_check)
        || !git2::Reference::is_valid_name(&destination_check)
    {
        return Err(GitServiceError::UnsupportedCapability);
    }
    Ok(())
}

fn validate_push_refspec(value: &str) -> Result<(), GitServiceError> {
    if value.starts_with('+') {
        return Err(GitServiceError::UnsupportedCapability);
    }
    let (source, destination) = value
        .split_once(':')
        .ok_or(GitServiceError::UnsupportedCapability)?;
    if !source.starts_with("refs/heads/")
        || !destination.starts_with("refs/heads/")
        || destination.contains(':')
        || source.contains('*')
        || destination.contains('*')
        || source.contains('\0')
        || destination.contains('\0')
        || !git2::Reference::is_valid_name(source)
        || !git2::Reference::is_valid_name(destination)
    {
        return Err(GitServiceError::UnsupportedCapability);
    }
    Ok(())
}

fn find_remote<'a>(
    remotes: &'a [RemoteBinding],
    remote_id: &RemoteId,
) -> Result<&'a RemoteBinding, GitServiceError> {
    remotes
        .iter()
        .find(|remote| &remote.remote_id == remote_id)
        .ok_or(GitServiceError::RepositoryChanged)
}

fn find_selector<'a>(
    remote: &'a RemoteBinding,
    ref_id: &RefId,
) -> Result<&'a RemoteSelector, GitServiceError> {
    remote
        .selectors
        .iter()
        .find(|selector| &selector.ref_id == ref_id)
        .ok_or(GitServiceError::StaleState)
}

fn credential_binding(remote: &RemoteBinding) -> RemoteCredentialBinding {
    RemoteCredentialBinding {
        remote_id: remote.remote_id.clone(),
        validated_https_url: remote.url.clone(),
        config_fingerprint: remote.config_fingerprint.clone(),
    }
}

fn validate_credentials(
    credentials: Option<GitCredentials>,
) -> Result<Option<GitCredentials>, GitServiceError> {
    if let Some(credentials) = &credentials {
        for value in [&credentials.username, &credentials.password] {
            if value.is_empty()
                || value.contains(&0)
                || value.len() > MAX_NETWORK_CREDENTIAL_BYTES
                || std::str::from_utf8(value).is_err()
            {
                return Err(GitServiceError::CredentialsRequired);
            }
        }
    }
    Ok(credentials)
}

fn check_controls(
    original: &RequestControl,
    current: &RequestControl,
) -> Result<(), GitServiceError> {
    original.check()?;
    current.check()
}

fn remote_callbacks<'a>(
    remote_url: &'a str,
    credentials: Option<&'a GitCredentials>,
    original_control: &'a RequestControl,
    current_control: &'a RequestControl,
    missing_credentials: &'a AtomicBool,
    unsupported_credentials: &'a AtomicBool,
) -> RemoteCallbacks<'a> {
    let mut callbacks = RemoteCallbacks::new();
    callbacks.credentials(move |url, _username, allowed| {
        if !same_https_origin(remote_url, url) {
            unsupported_credentials.store(true, Ordering::Release);
            return Err(git2::Error::from_str("unsupported credential target"));
        }
        if !allowed.contains(CredentialType::USER_PASS_PLAINTEXT) {
            unsupported_credentials.store(true, Ordering::Release);
            return Err(git2::Error::from_str("unsupported credential type"));
        }
        let Some(credentials) = credentials else {
            missing_credentials.store(true, Ordering::Release);
            return Err(git2::Error::from_str("host credentials required"));
        };
        let username = std::str::from_utf8(&credentials.username)
            .map_err(|_| git2::Error::from_str("invalid host credential"))?;
        let password = std::str::from_utf8(&credentials.password)
            .map_err(|_| git2::Error::from_str("invalid host credential"))?;
        Cred::userpass_plaintext(username, password)
    });
    callbacks.transfer_progress(move |_| {
        original_control.check().is_ok() && current_control.check().is_ok()
    });
    callbacks.sideband_progress(move |_| {
        original_control.check().is_ok() && current_control.check().is_ok()
    });
    callbacks
}

#[allow(clippy::too_many_arguments)]
fn push_callbacks<'a>(
    remote_url: &'a str,
    credentials: Option<&'a GitCredentials>,
    original_control: &'a RequestControl,
    current_control: &'a RequestControl,
    missing_credentials: &'a AtomicBool,
    unsupported_credentials: &'a AtomicBool,
    expected_destination: &'a str,
    expected_source: &'a str,
    expected_source_oid: Oid,
    update_will_be_sent: &'a std::cell::Cell<bool>,
    confirmed: &'a std::cell::Cell<bool>,
    rejected: &'a std::cell::Cell<bool>,
) -> RemoteCallbacks<'a> {
    let mut callbacks = RemoteCallbacks::new();
    callbacks.credentials(move |url, _username, allowed| {
        if !same_https_origin(remote_url, url) {
            unsupported_credentials.store(true, Ordering::Release);
            return Err(git2::Error::from_str("unsupported credential target"));
        }
        if !allowed.contains(CredentialType::USER_PASS_PLAINTEXT) {
            unsupported_credentials.store(true, Ordering::Release);
            return Err(git2::Error::from_str("unsupported credential type"));
        }
        let Some(credentials) = credentials else {
            missing_credentials.store(true, Ordering::Release);
            return Err(git2::Error::from_str("host credentials required"));
        };
        let username = std::str::from_utf8(&credentials.username)
            .map_err(|_| git2::Error::from_str("invalid host credential"))?;
        let password = std::str::from_utf8(&credentials.password)
            .map_err(|_| git2::Error::from_str("invalid host credential"))?;
        Cred::userpass_plaintext(username, password)
    });
    callbacks.sideband_progress(move |_| {
        original_control.check().is_ok() && current_control.check().is_ok()
    });
    callbacks.push_negotiation(move |updates| {
        check_controls(original_control, current_control)
            .map_err(|_| git2::Error::from_str("Git operation cancelled"))?;
        if updates.is_empty() {
            update_will_be_sent.set(false);
            return Ok(());
        }
        if updates.len() != 1
            || updates[0].dst_refname().ok() != Some(expected_destination)
            || updates[0].src_refname().ok() != Some(expected_source)
            || updates[0].src().to_string() != expected_source_oid.to_string()
        {
            return Err(git2::Error::from_str("unexpected push reference update"));
        }
        update_will_be_sent.set(true);
        Ok(())
    });
    callbacks.push_update_reference(move |reference, status| {
        if reference != expected_destination {
            return Err(git2::Error::from_str("unexpected push reference receipt"));
        }
        if status.is_some() {
            rejected.set(true);
        } else {
            confirmed.set(true);
        }
        Ok(())
    });
    callbacks
}

fn same_https_origin(expected: &str, actual: &str) -> bool {
    let (Ok(expected), Ok(actual)) = (Url::parse(expected), Url::parse(actual)) else {
        return false;
    };
    expected.scheme() == "https"
        && actual.scheme() == "https"
        && expected.origin() == actual.origin()
}

fn map_network_error(
    error: git2::Error,
    control: &RequestControl,
    missing_credentials: &AtomicBool,
    unsupported_credentials: &AtomicBool,
) -> GitServiceError {
    if let Err(control_error) = control.check() {
        return control_error;
    }
    if unsupported_credentials.load(Ordering::Acquire) {
        GitServiceError::UnsupportedCapability
    } else if missing_credentials.load(Ordering::Acquire) || error.code() == git2::ErrorCode::Auth {
        GitServiceError::CredentialsRequired
    } else {
        GitServiceError::NetworkFailed
    }
}

fn open_network_repository(
    snapshot: &PrivateSnapshot,
    control: &RequestControl,
) -> Result<NativeRepository, GitServiceError> {
    open_network_repository_at(snapshot.path(), control)
}

fn open_network_repository_at(
    snapshot_path: &Path,
    control: &RequestControl,
) -> Result<NativeRepository, GitServiceError> {
    control.check()?;
    let git_dir = snapshot_path.join(".git");
    let config_path = git_dir.join("config");
    let original_config =
        Config::open(&config_path).map_err(|_| GitServiceError::UnsupportedCapability)?;
    let format = match original_config.get_i32("core.repositoryformatversion") {
        Ok(format) => format,
        Err(_) => 0,
    };
    if format != 0
        || original_config
            .get_string("extensions.objectformat")
            .ok()
            .is_some_and(|format| !format.eq_ignore_ascii_case("sha1"))
    {
        return Err(GitServiceError::UnsupportedCapability);
    }
    let entries = original_config
        .entries(None)
        .map_err(|_| GitServiceError::UnsupportedCapability)?;
    let mut unsupported_extension = false;
    entries
        .for_each(|entry| {
            if entry
                .name()
                .ok()
                .is_some_and(|name| name.to_ascii_lowercase().starts_with("extensions."))
            {
                let is_object_format = entry
                    .name()
                    .ok()
                    .is_some_and(|name| name.eq_ignore_ascii_case("extensions.objectformat"));
                if !is_object_format {
                    unsupported_extension = true;
                }
            }
        })
        .map_err(|_| GitServiceError::UnsupportedCapability)?;
    if unsupported_extension {
        return Err(GitServiceError::UnsupportedCapability);
    }
    for path in [
        git_dir.join("objects/info/alternates"),
        git_dir.join("objects/info/http-alternates"),
    ] {
        match fs::symlink_metadata(&path) {
            Ok(_) => return Err(GitServiceError::UnsupportedCapability),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(GitServiceError::MutationFailed),
        }
    }
    drop(original_config);
    fs::write(
        &config_path,
        // WASI status still reads this private snapshot after fetch. Keep its
        // worktree visible and represent links as their staged target bytes.
        // The native handle below receives a separate, bare isolated Config.
        b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tsymlinks = false\n",
    )
    .map_err(|_| GitServiceError::MutationFailed)?;
    let repo =
        NativeRepository::open_bare(&git_dir).map_err(|_| GitServiceError::MutationFailed)?;
    let mut isolated = Config::new().map_err(|_| GitServiceError::ExecutorUnavailable)?;
    isolated
        .set_i32("core.repositoryformatversion", 0)
        .and_then(|_| isolated.set_bool("core.bare", true))
        .and_then(|_| isolated.set_bool("http.followRedirects", false))
        .map_err(|_| GitServiceError::ExecutorUnavailable)?;
    repo.set_config(&isolated)
        .map_err(|_| GitServiceError::ExecutorUnavailable)?;
    control.check()?;
    Ok(repo)
}

fn collect_object_inventory(
    repository: &NativeRepository,
) -> Result<HashSet<Oid>, GitServiceError> {
    let odb = repository
        .odb()
        .map_err(|_| GitServiceError::MutationFailed)?;
    let mut objects = HashSet::new();
    let mut over_limit = false;
    odb.foreach(|oid| {
        if objects.len() == MAX_REMOTE_OBJECTS {
            over_limit = true;
            return false;
        }
        objects.insert(*oid);
        true
    })
    .map_err(|_| {
        if over_limit {
            GitServiceError::ResourceLimit
        } else {
            GitServiceError::MutationFailed
        }
    })?;
    if over_limit {
        return Err(GitServiceError::ResourceLimit);
    }
    Ok(objects)
}

fn materialize_new_reachable_objects(
    repository: &NativeRepository,
    start: Oid,
    existing: &HashSet<Oid>,
) -> Result<Vec<String>, GitServiceError> {
    let odb = repository
        .odb()
        .map_err(|_| GitServiceError::MutationFailed)?;
    let mut pending = vec![start];
    let mut visited = HashSet::new();
    let mut new_objects = Vec::new();
    let mut total_bytes = 0usize;
    while let Some(oid) = pending.pop() {
        if !visited.insert(oid) {
            continue;
        }
        if visited.len() > MAX_REMOTE_OBJECTS {
            return Err(GitServiceError::ResourceLimit);
        }
        let (kind, data) = {
            let object = odb.read(oid).map_err(|_| GitServiceError::MutationFailed)?;
            if object.data().len() > MAX_REMOTE_OBJECT_BYTES {
                return Err(GitServiceError::ResourceLimit);
            }
            (object.kind(), object.data().to_vec())
        };
        if !existing.contains(&oid) {
            total_bytes = total_bytes
                .checked_add(data.len())
                .ok_or(GitServiceError::ResourceLimit)?;
            if total_bytes > MAX_SNAPSHOT_TOTAL_BYTES as usize {
                return Err(GitServiceError::ResourceLimit);
            }
            let written = odb
                .write(kind, &data)
                .map_err(|_| GitServiceError::MutationFailed)?;
            if written != oid {
                return Err(GitServiceError::MutationFailed);
            }
            new_objects.push(oid.to_string());
        }
        match kind {
            ObjectType::Commit => {
                let commit = repository
                    .find_commit(oid)
                    .map_err(|_| GitServiceError::MutationFailed)?;
                pending.push(commit.tree_id());
                pending.extend(commit.parent_ids());
            }
            ObjectType::Tree => {
                let tree = repository
                    .find_tree(oid)
                    .map_err(|_| GitServiceError::MutationFailed)?;
                for entry in tree.iter() {
                    if entry.filemode() != 0o160000 {
                        pending.push(entry.id());
                    }
                }
            }
            ObjectType::Tag => {
                let tag = repository
                    .find_tag(oid)
                    .map_err(|_| GitServiceError::MutationFailed)?;
                pending.push(tag.target_id());
            }
            ObjectType::Blob => {}
            _ => return Err(GitServiceError::MutationFailed),
        }
    }
    Ok(new_objects)
}

fn make_fetch_publication(
    repository: &Repository,
    snapshot: &PrivateSnapshot,
    remote: &RemoteBinding,
    source: &str,
    destination: &str,
    tip: Oid,
    object_ids: Vec<String>,
) -> Result<GitPublication, GitServiceError> {
    validate_server_default_branch(source)?;
    validate_tracking_destination(destination, &remote.name)?;
    let reference = destination
        .split('/')
        .map(|component| component.as_bytes().to_vec())
        .collect::<Vec<_>>();
    let path = RelPath(
        std::iter::once(b".git".to_vec())
            .chain(reference.iter().cloned())
            .collect(),
    );
    let expected = metadata_precondition(snapshot, &path)?;
    let parent_components = path
        .0
        .split_last()
        .map(|(_, parents)| parents)
        .ok_or(GitServiceError::UnsafeRepository)?;
    let mut nearest_parent = None;
    for existing_len in (1..=parent_components.len()).rev() {
        let parent_path = RelPath(parent_components[..existing_len].to_vec());
        if let Some(parent) = snapshot_directory(snapshot, &parent_path) {
            if parent.kind != Kind::Directory {
                return Err(GitServiceError::UnsafeRepository);
            }
            nearest_parent = Some((parent.entry, existing_len));
            break;
        }
    }
    let (parent, existing_len) = nearest_parent.ok_or(GitServiceError::UnsafeRepository)?;
    if parent != expected.parent {
        return Err(GitServiceError::UnsafeRepository);
    }
    let parent_suffix = reference[..reference.len() - 1]
        .get(existing_len.saturating_sub(1)..)
        .ok_or(GitServiceError::UnsafeRepository)?
        .to_vec();
    let config_precondition = metadata_precondition(
        snapshot,
        &RelPath(vec![b".git".to_vec(), b"config".to_vec()]),
    )?;
    let packed_refs_precondition = metadata_precondition(
        snapshot,
        &RelPath(vec![b".git".to_vec(), b"packed-refs".to_vec()]),
    )?;
    let objects = collect_loose_objects(snapshot, object_ids)?;
    if tip.to_string().is_empty() {
        return Err(GitServiceError::InvalidObjectId);
    }
    Ok(GitPublication {
        git_dir: repository.git_marker.entry,
        common_dir: repository.commondir.entry,
        preconditions: vec![config_precondition, packed_refs_precondition],
        worktree_preconditions: Vec::new(),
        objects,
        final_file: GitFinalFile {
            target: GitFinalTarget::RemoteTrackingHead { reference },
            parent: expected.parent,
            parent_suffix,
            expected,
            bytes: format!("{tip}\n").into_bytes(),
        },
    })
}

fn make_pull_publication(
    repository: &Repository,
    snapshot: &PrivateSnapshot,
    remote: &RemoteBinding,
    source: &str,
    destination: &str,
    native: &NativeRepository,
    tip: Oid,
    object_ids: Vec<String>,
    expected: &GitPreconditions,
    control: &RequestControl,
) -> Result<GitPullPublication, GitServiceError> {
    validate_server_default_branch(source)?;
    validate_tracking_destination(destination, &remote.name)?;
    control.check()?;
    let status = worker::run_status(snapshot.path(), 0, 1, control)?;
    check_mutation_preconditions(expected, snapshot, &status.head)?;
    if !status.entries.is_empty() || status.truncated {
        return Err(GitServiceError::MutationConflict);
    }
    let local_head = Oid::from_str(&status.head).map_err(|_| GitServiceError::MutationConflict)?;
    if local_head != tip
        && !native
            .graph_descendant_of(tip, local_head)
            .map_err(|_| GitServiceError::MutationConflict)?
    {
        return Err(GitServiceError::MutationConflict);
    }
    let old_commit = native
        .find_commit(local_head)
        .map_err(|_| GitServiceError::UnsafeRepository)?;
    let new_commit = native
        .find_commit(tip)
        .map_err(|_| GitServiceError::UnsafeRepository)?;
    let old_tree = old_commit
        .tree()
        .map_err(|_| GitServiceError::UnsafeRepository)?;
    let new_tree = new_commit
        .tree()
        .map_err(|_| GitServiceError::UnsafeRepository)?;
    let files = make_pull_worktree_files(snapshot, native, &old_tree, &new_tree, control)?;

    let mut index = native
        .index()
        .map_err(|_| GitServiceError::MutationFailed)?;
    index.clear().map_err(|_| GitServiceError::MutationFailed)?;
    index
        .read_tree(&new_tree)
        .map_err(|_| GitServiceError::MutationFailed)?;
    index.write().map_err(|_| GitServiceError::MutationFailed)?;
    drop(index);

    // Ensure the fast-forward target has a private loose representation so
    // the existing HEAD publisher can validate and encode its pointer. The
    // host receives the complete reachable object set from the index update.
    let odb = native.odb().map_err(|_| GitServiceError::MutationFailed)?;
    let target = odb.read(tip).map_err(|_| GitServiceError::MutationFailed)?;
    if odb
        .write(target.kind(), target.data())
        .map_err(|_| GitServiceError::MutationFailed)?
        != tip
    {
        return Err(GitServiceError::MutationFailed);
    }

    let mut index_publication = make_index_publication(repository, snapshot, object_ids.clone())?;
    let mut tracking_publication = make_fetch_publication(
        repository,
        snapshot,
        remote,
        source,
        destination,
        tip,
        Vec::new(),
    )?;
    let tip_text = tip.to_string();
    let mut head_publication =
        super::make_commit_publication(repository, snapshot, vec![tip_text.clone()], &tip_text)?;
    head_publication.objects.clear();
    let mut preconditions = Vec::<GitFilePrecondition>::new();
    for publication in [&index_publication, &tracking_publication, &head_publication] {
        for precondition in publication
            .preconditions
            .iter()
            .chain(std::iter::once(&publication.final_file.expected))
        {
            if preconditions.iter().any(|existing| {
                existing.parent == precondition.parent && existing.name == precondition.name
            }) {
                if !preconditions
                    .iter()
                    .any(|existing| existing == precondition)
                {
                    return Err(GitServiceError::MutationConflict);
                }
                continue;
            }
            preconditions.push(precondition.clone());
        }
    }
    index_publication.preconditions = preconditions.clone();
    tracking_publication.preconditions = preconditions.clone();
    head_publication.preconditions = preconditions;
    Ok(GitPullPublication {
        metadata: vec![index_publication, tracking_publication, head_publication],
        files,
    })
}

fn make_pull_worktree_files(
    snapshot: &PrivateSnapshot,
    repository: &NativeRepository,
    old_tree: &git2::Tree<'_>,
    new_tree: &git2::Tree<'_>,
    control: &RequestControl,
) -> Result<Vec<GitPullFile>, GitServiceError> {
    let mut options = DiffOptions::new();
    // File/link mode changes must retain their original occupant in one CAS
    // entry. Directory transitions remain decomposed into tracked leaf edits.
    options.include_typechange(true);
    let diff = repository
        .diff_tree_to_tree(Some(old_tree), Some(new_tree), Some(&mut options))
        .map_err(|_| GitServiceError::MutationFailed)?;
    let mut files = Vec::new();
    let mut total = 0usize;
    let mut changed_paths = 0usize;
    for delta in diff.deltas() {
        control.check()?;
        changed_paths += 1;
        if changed_paths > 200 {
            return Err(GitServiceError::ResourceLimit);
        }
        let (path, target_file, deleted) = match delta.status() {
            Delta::Added => (
                delta
                    .new_file()
                    .path_bytes()
                    .ok_or(GitServiceError::UnsupportedCapability)?,
                Some(delta.new_file()),
                false,
            ),
            Delta::Deleted => (
                delta
                    .old_file()
                    .path_bytes()
                    .ok_or(GitServiceError::UnsupportedCapability)?,
                None,
                true,
            ),
            Delta::Modified | Delta::Typechange => {
                let old_path = delta
                    .old_file()
                    .path_bytes()
                    .ok_or(GitServiceError::UnsupportedCapability)?;
                let new_path = delta
                    .new_file()
                    .path_bytes()
                    .ok_or(GitServiceError::UnsupportedCapability)?;
                if old_path != new_path {
                    return Err(GitServiceError::UnsupportedCapability);
                }
                (new_path, Some(delta.new_file()), false)
            }
            _ => return Err(GitServiceError::UnsupportedCapability),
        };
        if !allowed_git_path(path) {
            return Err(GitServiceError::UnsafeRepository);
        }
        let relative = git_relative_path(path)?;
        let existing = snapshot.files.get(&relative);
        let (kind, contents, executable) = if deleted {
            if target_file.is_some() {
                return Err(GitServiceError::ExecutorFailed);
            }
            let old = delta.old_file();
            if old.mode() == git2::FileMode::Commit {
                // Gitlinks are not checked out recursively and never trigger
                // helpers or nested network operations.
                return Err(GitServiceError::UnsupportedCapability);
            }
            let kind = git_mode_node_kind(old.mode())?;
            if existing.map(|meta| pull_node_kind(meta.kind)).transpose()? != Some(kind) {
                return Err(GitServiceError::MutationConflict);
            }
            (kind, None, false)
        } else {
            let target_file = target_file.ok_or(GitServiceError::ExecutorFailed)?;
            let kind = git_mode_node_kind(target_file.mode())?;
            match delta.status() {
                Delta::Added if existing.is_some_and(|meta| meta.kind != Kind::Directory) => {
                    // Git must not overwrite an ignored/untracked occupant of
                    // a newly added path.
                    return Err(GitServiceError::MutationConflict);
                }
                Delta::Modified | Delta::Typechange => {
                    let old_kind = git_mode_node_kind(delta.old_file().mode())?;
                    if existing.map(|meta| pull_node_kind(meta.kind)).transpose()? != Some(old_kind)
                    {
                        return Err(GitServiceError::MutationConflict);
                    }
                }
                _ => {}
            }
            let blob = repository
                .find_blob(target_file.id())
                .map_err(|_| GitServiceError::MutationFailed)?;
            if kind == GitPullNodeKind::Symlink
                && (blob.content().is_empty()
                    || blob.content().len() > 64 * 1024
                    || blob.content().contains(&0))
            {
                return Err(GitServiceError::UnsupportedCapability);
            }
            if blob.content().len() > MAX_SNAPSHOT_FILE_BYTES as usize {
                return Err(GitServiceError::ResourceLimit);
            }
            total = total
                .checked_add(blob.content().len())
                .ok_or(GitServiceError::ResourceLimit)?;
            if total > MAX_SNAPSHOT_TOTAL_BYTES as usize {
                return Err(GitServiceError::ResourceLimit);
            }
            (
                kind,
                Some(blob.content().to_vec()),
                kind == GitPullNodeKind::File
                    && target_file.mode() == git2::FileMode::BlobExecutable,
            )
        };
        let expected = pull_worktree_precondition(snapshot, &relative, existing.cloned())?;
        let (parent, parent_suffix) = pull_worktree_parent(snapshot, &relative)?;
        if parent != expected.parent {
            return Err(GitServiceError::UnsafeRepository);
        }
        files.push(GitPullFile {
            path: relative.0.clone(),
            parent,
            parent_suffix,
            name: relative
                .0
                .last()
                .cloned()
                .ok_or(GitServiceError::UnsafeRepository)?,
            expected,
            contents,
            kind,
            executable,
        });
    }

    // A directory replaced by a blob must be removed only after every tracked
    // descendant that Git deletes. Refuse the transition if any ignored or
    // otherwise unaccounted entry remains below it.
    let deletions: HashSet<RelPath> = files
        .iter()
        .filter(|file| file.contents.is_none() && file.kind != GitPullNodeKind::Directory)
        .map(|file| RelPath(file.path.clone()))
        .collect();
    let replacements: Vec<RelPath> = files
        .iter()
        .filter(|file| file.contents.is_some())
        .filter(|file| {
            snapshot
                .files
                .get(&RelPath(file.path.clone()))
                .is_some_and(|meta| meta.kind == Kind::Directory)
        })
        .map(|file| RelPath(file.path.clone()))
        .collect();
    let mut directory_removals = HashSet::<RelPath>::new();
    for replaced in replacements {
        control.check()?;
        for (path, meta) in &snapshot.files {
            if !path_has_prefix(path, &replaced) || meta.kind == Kind::Directory {
                continue;
            }
            if !deletions.contains(path) {
                return Err(GitServiceError::MutationConflict);
            }
        }
        for (path, meta) in &snapshot.files {
            if !path_has_prefix(path, &replaced) || meta.kind != Kind::Directory {
                continue;
            }
            directory_removals.insert(path.clone());
        }
    }
    let mut directory_removals: Vec<_> = directory_removals.into_iter().collect();
    directory_removals.sort_by(|left, right| {
        right
            .0
            .len()
            .cmp(&left.0.len())
            .then_with(|| right.cmp(left))
    });
    for path in directory_removals {
        control.check()?;
        let meta = snapshot
            .files
            .get(&path)
            .filter(|meta| meta.kind == Kind::Directory)
            .ok_or(GitServiceError::MutationConflict)?;
        let expected = pull_worktree_precondition(snapshot, &path, Some(meta.clone()))?;
        let (parent, parent_suffix) = pull_worktree_parent(snapshot, &path)?;
        files.push(GitPullFile {
            path: path.0.clone(),
            parent,
            parent_suffix,
            name: path
                .0
                .last()
                .cloned()
                .ok_or(GitServiceError::UnsafeRepository)?,
            expected,
            contents: None,
            kind: GitPullNodeKind::Directory,
            executable: false,
        });
    }
    files.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| (left.kind as u8).cmp(&(right.kind as u8)))
    });
    Ok(files)
}

fn path_has_prefix(path: &RelPath, prefix: &RelPath) -> bool {
    path.0.len() >= prefix.0.len() && path.0[..prefix.0.len()] == prefix.0
}

fn pull_node_kind(kind: Kind) -> Result<GitPullNodeKind, GitServiceError> {
    match kind {
        Kind::File => Ok(GitPullNodeKind::File),
        Kind::Symlink => Ok(GitPullNodeKind::Symlink),
        Kind::Directory => Ok(GitPullNodeKind::Directory),
        Kind::Other => Err(GitServiceError::UnsafeRepository),
    }
}

fn git_mode_node_kind(mode: git2::FileMode) -> Result<GitPullNodeKind, GitServiceError> {
    match mode {
        git2::FileMode::Blob | git2::FileMode::BlobExecutable => Ok(GitPullNodeKind::File),
        git2::FileMode::Link => Ok(GitPullNodeKind::Symlink),
        git2::FileMode::Commit => {
            // Submodules are never updated recursively or through helpers.
            Err(GitServiceError::UnsupportedCapability)
        }
        _ => Err(GitServiceError::UnsupportedCapability),
    }
}

fn pull_worktree_precondition(
    snapshot: &PrivateSnapshot,
    path: &RelPath,
    expected: Option<Meta>,
) -> Result<GitPullPrecondition, GitServiceError> {
    let (name, parent_path) = path
        .0
        .split_last()
        .ok_or(GitServiceError::UnsafeRepository)?;
    match expected {
        Some(expected) => {
            let current = snapshot
                .files
                .get(path)
                .ok_or(GitServiceError::MutationConflict)?;
            if expected.entry != current.entry || expected.revision != current.revision {
                return Err(GitServiceError::MutationConflict);
            }
            let parent = snapshot_directory(snapshot, &RelPath(parent_path.to_vec()))
                .filter(|parent| parent.kind == Kind::Directory)
                .ok_or(GitServiceError::MutationConflict)?;
            Ok(GitPullPrecondition {
                parent: parent.entry,
                name: name.clone(),
                entry: Some(current.entry),
                revision: Some(current.revision.clone()),
                kind: Some(pull_node_kind(current.kind)?),
            })
        }
        None => {
            // Pin the nearest existing directory. If the first missing
            // component is occupied by a non-directory, retain that exact
            // identity so file-to-directory transitions can delete only the
            // expected blocker before creating nested paths.
            for existing_len in (0..=parent_path.len()).rev() {
                let existing_path = RelPath(parent_path[..existing_len].to_vec());
                let Some(parent) = snapshot_directory(snapshot, &existing_path) else {
                    continue;
                };
                if parent.kind != Kind::Directory {
                    continue;
                }
                let (missing_name, blocker_path) = if existing_len == parent_path.len() {
                    (name, None)
                } else {
                    let missing = &parent_path[existing_len];
                    (
                        missing,
                        Some(RelPath(parent_path[..=existing_len].to_vec())),
                    )
                };
                if missing_name.is_empty() || missing_name.len() > 255 {
                    return Err(GitServiceError::UnsafeRepository);
                }
                let blocker = blocker_path.and_then(|path| snapshot.files.get(&path));
                let kind = blocker.map(|meta| pull_node_kind(meta.kind)).transpose()?;
                if kind.is_some_and(|kind| kind == GitPullNodeKind::Directory) {
                    return Err(GitServiceError::MutationConflict);
                }
                return Ok(GitPullPrecondition {
                    parent: parent.entry,
                    name: missing_name.clone(),
                    entry: blocker.map(|meta| meta.entry),
                    revision: blocker.map(|meta| meta.revision.clone()),
                    kind,
                });
            }
            Err(GitServiceError::UnsafeRepository)
        }
    }
}

fn pull_worktree_parent(
    snapshot: &PrivateSnapshot,
    path: &RelPath,
) -> Result<(EntryRef, Vec<Vec<u8>>), GitServiceError> {
    let (_, parent_path) = path
        .0
        .split_last()
        .ok_or(GitServiceError::UnsafeRepository)?;
    for existing_len in (0..=parent_path.len()).rev() {
        let existing_path = RelPath(parent_path[..existing_len].to_vec());
        let Some(parent) = snapshot_directory(snapshot, &existing_path) else {
            continue;
        };
        if parent.kind != Kind::Directory {
            continue;
        }
        return Ok((parent.entry, parent_path[existing_len..].to_vec()));
    }
    Err(GitServiceError::UnsafeRepository)
}

fn revalidate_snapshot_git_metadata(
    files: &FileRoot,
    snapshot: &PrivateSnapshot,
    control: &RequestControl,
) -> Result<(), GitServiceError> {
    for (path, meta) in &snapshot.files {
        control.check()?;
        if path.0.first().is_some_and(|component| component == b".git") {
            files
                .stat(meta.entry, Some(&meta.revision))
                .map_err(map_file_error)?;
        }
    }
    Ok(())
}

fn selector_display_name(
    kind: SelectorKind,
    value: &str,
    remote_name: &str,
) -> Result<DisplayText, GitServiceError> {
    let label = match kind {
        SelectorKind::Head => "Remote HEAD".to_owned(),
        SelectorKind::Fetch => {
            let (source, destination) = split_fetch_spec(value)?;
            format!(
                "Fetch {} → {}",
                friendly_ref_name(source, remote_name),
                friendly_ref_name(destination, remote_name)
            )
        }
        SelectorKind::Push => {
            let (source, destination) = split_push_spec(value)?;
            format!(
                "Push {} → {}",
                friendly_ref_name(source, remote_name),
                friendly_ref_name(destination, remote_name)
            )
        }
    };
    let mut sanitized = String::with_capacity(label.len().min(128));
    for character in label.chars() {
        let character = if character.is_control() {
            '_'
        } else {
            character
        };
        if sanitized.len() + character.len_utf8() > 128 {
            break;
        }
        sanitized.push(character);
    }
    DisplayText::try_from(sanitized).map_err(|_| GitServiceError::UnsupportedCapability)
}

fn friendly_ref_name(value: &str, remote_name: &str) -> String {
    if let Some(name) = value.strip_prefix("refs/heads/") {
        format!("branch {name}")
    } else if let Some(name) = value.strip_prefix("refs/tags/") {
        format!("tag {name}")
    } else if let Some(name) = value.strip_prefix(&format!("refs/remotes/{remote_name}/")) {
        format!("tracking branch {name}")
    } else {
        value.to_owned()
    }
}

fn pull_fetch_spec(
    remote_name: &str,
    branch: &BranchConfig,
    fetch_specs: &[String],
) -> Option<(String, String)> {
    if branch.remote.as_deref() != Some(remote_name) {
        return None;
    }
    let upstream = branch.merge.as_deref()?;
    if !upstream.starts_with("refs/heads/") || !git2::Reference::is_valid_name(upstream) {
        return None;
    }

    let mut matching_specs = BTreeMap::new();
    for spec in fetch_specs {
        if validate_fetch_refspec(spec, remote_name).is_err() {
            continue;
        }
        let Ok((source, destination)) = split_fetch_spec(spec) else {
            continue;
        };
        let destination = if source == upstream {
            destination.to_owned()
        } else if let Some(source_prefix) = source.strip_suffix('*') {
            let Some(suffix) = upstream.strip_prefix(source_prefix) else {
                continue;
            };
            let Some(destination_prefix) = destination.strip_suffix('*') else {
                continue;
            };
            format!("{destination_prefix}{suffix}")
        } else {
            continue;
        };
        if validate_tracking_destination(&destination, remote_name).is_err() {
            continue;
        }
        let force = if spec.starts_with('+') { "+" } else { "" };
        let exact_spec = format!("{force}{upstream}:{destination}");
        matching_specs.entry(spec.clone()).or_insert(exact_spec);
    }
    if matching_specs.len() != 1 {
        return None;
    }
    matching_specs.into_iter().next()
}

fn selected_fetch_refspec(
    remote_name: &str,
    selector_kind: SelectorKind,
    selector_value: &str,
    fetch_specs: &[String],
    default_branch: &str,
) -> Result<String, GitServiceError> {
    validate_server_default_branch(default_branch)?;
    match selector_kind {
        SelectorKind::Fetch => {
            let forced = selector_value.starts_with('+');
            let value = selector_value.strip_prefix('+').unwrap_or(selector_value);
            let (source, destination) = value
                .split_once(':')
                .ok_or(GitServiceError::UnsupportedCapability)?;
            if source.contains('*') {
                let source_prefix = source
                    .strip_suffix('*')
                    .ok_or(GitServiceError::UnsupportedCapability)?;
                let destination_prefix = destination
                    .strip_suffix('*')
                    .ok_or(GitServiceError::UnsupportedCapability)?;
                let suffix = default_branch
                    .strip_prefix(source_prefix)
                    .ok_or(GitServiceError::UnsupportedCapability)?;
                let resolved_source = default_branch;
                let resolved_destination = format!("{destination_prefix}{suffix}");
                validate_tracking_destination(&resolved_destination, remote_name)?;
                Ok(format!(
                    "{}{resolved_source}:{resolved_destination}",
                    if forced { "+" } else { "" }
                ))
            } else {
                validate_tracking_destination(destination, remote_name)?;
                Ok(selector_value.to_owned())
            }
        }
        SelectorKind::Head => {
            for spec in fetch_specs {
                let value = spec.strip_prefix('+').unwrap_or(spec);
                let (source, destination) = value
                    .split_once(':')
                    .ok_or(GitServiceError::UnsupportedCapability)?;
                let forced = spec.starts_with('+');
                if source == default_branch {
                    validate_tracking_destination(destination, remote_name)?;
                    return Ok(format!(
                        "{}{default_branch}:{destination}",
                        if forced { "+" } else { "" }
                    ));
                }
                if let Some(source_prefix) = source.strip_suffix('*') {
                    let Some(suffix) = default_branch.strip_prefix(source_prefix) else {
                        continue;
                    };
                    let destination_prefix = destination
                        .strip_suffix('*')
                        .ok_or(GitServiceError::UnsupportedCapability)?;
                    let destination = format!("{destination_prefix}{suffix}");
                    validate_tracking_destination(&destination, remote_name)?;
                    return Ok(format!(
                        "{}{default_branch}:{destination}",
                        if forced { "+" } else { "" }
                    ));
                }
            }
            if !fetch_specs.is_empty() {
                return Err(GitServiceError::UnsupportedCapability);
            }
            let suffix = default_branch
                .strip_prefix("refs/heads/")
                .ok_or(GitServiceError::UnsupportedCapability)?;
            let destination = format!("refs/remotes/{remote_name}/{suffix}");
            validate_tracking_destination(&destination, remote_name)?;
            Ok(format!("{default_branch}:{destination}"))
        }
        SelectorKind::Push => Err(GitServiceError::UnsupportedCapability),
    }
}

fn split_fetch_spec(spec: &str) -> Result<(&str, &str), GitServiceError> {
    spec.strip_prefix('+')
        .unwrap_or(spec)
        .split_once(':')
        .ok_or(GitServiceError::UnsupportedCapability)
}

fn split_push_spec(spec: &str) -> Result<(&str, &str), GitServiceError> {
    if spec.starts_with('+') {
        return Err(GitServiceError::UnsupportedCapability);
    }
    spec.split_once(':')
        .ok_or(GitServiceError::UnsupportedCapability)
}

fn validate_server_default_branch(branch: &str) -> Result<(), GitServiceError> {
    if !branch.starts_with("refs/heads/")
        || !git2::Reference::is_valid_name(branch)
        || branch.len() > 2048
    {
        return Err(GitServiceError::UnsupportedCapability);
    }
    Ok(())
}

fn validate_tracking_destination(destination: &str, remote: &str) -> Result<(), GitServiceError> {
    if !destination.starts_with(&format!("refs/remotes/{remote}/"))
        || !git2::Reference::is_valid_name(destination)
        || destination.len() > 2048
    {
        return Err(GitServiceError::UnsupportedCapability);
    }
    Ok(())
}

struct ParsedWorkerRequest {
    kind: WorkerKind,
    snapshot_path: std::path::PathBuf,
    remote_url: String,
    remote_name: String,
    selector_kind: SelectorKind,
    selector_value: String,
    fetch_specs: Vec<String>,
    credentials: Option<GitCredentials>,
}

fn build_worker_request(
    kind: WorkerKind,
    snapshot: &PrivateSnapshot,
    remote: &RemoteBinding,
    selector: &RemoteSelector,
    credentials: Option<GitCredentials>,
) -> Result<NetworkWorkerRequest, GitServiceError> {
    let credentials = validate_credentials(credentials)?;
    let mut body = Zeroizing::new(Vec::with_capacity(4096));
    body.extend_from_slice(&[
        NETWORK_WORKER_VERSION,
        kind as u8,
        1, // The durable external-operation permit was granted by the caller.
        selector.kind as u8,
    ]);
    append_worker_field(&mut body, &encode_worker_path(snapshot.path())?)?;
    append_worker_field(&mut body, remote.url.as_bytes())?;
    append_worker_field(&mut body, remote.name.as_bytes())?;
    append_worker_field(&mut body, selector.value.as_bytes())?;
    let fetch_specs = remote
        .selectors
        .iter()
        .filter(|value| value.kind == SelectorKind::Fetch)
        .map(|value| value.value.as_str())
        .collect::<Vec<_>>();
    let count = u16::try_from(fetch_specs.len()).map_err(|_| GitServiceError::ResourceLimit)?;
    body.extend_from_slice(&count.to_be_bytes());
    for spec in fetch_specs {
        append_worker_field(&mut body, spec.as_bytes())?;
    }
    append_worker_field(
        &mut body,
        credentials
            .as_ref()
            .map(|value| value.username.as_slice())
            .unwrap_or_default(),
    )?;
    append_worker_field(
        &mut body,
        credentials
            .as_ref()
            .map(|value| value.password.as_slice())
            .unwrap_or_default(),
    )?;
    let total = body
        .len()
        .checked_add(8)
        .ok_or(GitServiceError::ResourceLimit)?;
    if total > MAX_NETWORK_WORKER_INPUT {
        return Err(GitServiceError::ResourceLimit);
    }
    let mut frame = Zeroizing::new(Vec::with_capacity(total));
    frame.extend_from_slice(NETWORK_WORKER_MAGIC);
    frame.extend_from_slice(
        &u32::try_from(body.len())
            .map_err(|_| GitServiceError::ResourceLimit)?
            .to_be_bytes(),
    );
    frame.extend_from_slice(&body);
    Ok(NetworkWorkerRequest { bytes: frame })
}

fn append_worker_field(body: &mut Vec<u8>, value: &[u8]) -> Result<(), GitServiceError> {
    let length = u32::try_from(value.len()).map_err(|_| GitServiceError::ResourceLimit)?;
    body.extend_from_slice(&length.to_be_bytes());
    body.extend_from_slice(value);
    if body.len() > MAX_NETWORK_WORKER_INPUT {
        return Err(GitServiceError::ResourceLimit);
    }
    Ok(())
}

#[cfg(unix)]
fn encode_worker_path(path: &Path) -> Result<Vec<u8>, GitServiceError> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() > 16 * 1024 || bytes.contains(&0) {
        return Err(GitServiceError::ResourceLimit);
    }
    Ok(bytes.to_vec())
}

#[cfg(windows)]
fn encode_worker_path(path: &Path) -> Result<Vec<u8>, GitServiceError> {
    use std::os::windows::ffi::OsStrExt;
    let bytes = path
        .as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    if bytes.is_empty() || bytes.len() > 16 * 1024 {
        return Err(GitServiceError::ResourceLimit);
    }
    Ok(bytes)
}

#[cfg(not(any(unix, windows)))]
fn encode_worker_path(path: &Path) -> Result<Vec<u8>, GitServiceError> {
    let value = path
        .to_str()
        .ok_or(GitServiceError::UnsupportedCapability)?;
    if value.is_empty() || value.len() > 16 * 1024 {
        return Err(GitServiceError::ResourceLimit);
    }
    Ok(value.as_bytes().to_vec())
}

fn decode_worker_path(value: &[u8]) -> Result<std::path::PathBuf, GitServiceError> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        if value.is_empty() || value.contains(&0) {
            return Err(GitServiceError::ExecutorFailed);
        }
        let path = std::path::PathBuf::from(std::ffi::OsString::from_vec(value.to_vec()));
        if !path.is_absolute() {
            return Err(GitServiceError::ExecutorFailed);
        }
        return Ok(path);
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        if value.is_empty() || value.len() % 2 != 0 {
            return Err(GitServiceError::ExecutorFailed);
        }
        let wide = value
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        if wide.contains(&0) {
            return Err(GitServiceError::ExecutorFailed);
        }
        let path = std::path::PathBuf::from(std::ffi::OsString::from_wide(&wide));
        if !path.is_absolute() {
            return Err(GitServiceError::ExecutorFailed);
        }
        return Ok(path);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let value = std::str::from_utf8(value).map_err(|_| GitServiceError::ExecutorFailed)?;
        let path = std::path::PathBuf::from(value);
        if !path.is_absolute() {
            return Err(GitServiceError::ExecutorFailed);
        }
        Ok(path)
    }
}

fn validate_private_worker_snapshot(path: &Path) -> Result<(), GitServiceError> {
    let name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or(GitServiceError::ExecutorFailed)?;
    if !path.is_absolute() || !name.starts_with("lomi-git-read-") {
        return Err(GitServiceError::ExecutorFailed);
    }
    let root = fs::symlink_metadata(path).map_err(|_| GitServiceError::ExecutorFailed)?;
    let git_dir =
        fs::symlink_metadata(path.join(".git")).map_err(|_| GitServiceError::ExecutorFailed)?;
    let config = fs::symlink_metadata(path.join(".git").join("config"))
        .map_err(|_| GitServiceError::ExecutorFailed)?;
    if !root.file_type().is_dir()
        || root.file_type().is_symlink()
        || !git_dir.file_type().is_dir()
        || git_dir.file_type().is_symlink()
        || !config.file_type().is_file()
        || config.file_type().is_symlink()
    {
        return Err(GitServiceError::ExecutorFailed);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if root.mode() & 0o077 != 0 {
            return Err(GitServiceError::ExecutorFailed);
        }
    }
    Ok(())
}

fn worker_take_field<'a>(
    body: &'a [u8],
    cursor: &mut usize,
    max_length: usize,
) -> Result<&'a [u8], GitServiceError> {
    let length_bytes = body
        .get(*cursor..cursor.saturating_add(4))
        .ok_or(GitServiceError::ExecutorFailed)?;
    *cursor += 4;
    let length = u32::from_be_bytes(
        length_bytes
            .try_into()
            .map_err(|_| GitServiceError::ExecutorFailed)?,
    ) as usize;
    if length > max_length {
        return Err(GitServiceError::ResourceLimit);
    }
    let end = cursor
        .checked_add(length)
        .ok_or(GitServiceError::ExecutorFailed)?;
    let field = body
        .get(*cursor..end)
        .ok_or(GitServiceError::ExecutorFailed)?;
    *cursor = end;
    Ok(field)
}

fn parse_worker_request(body: &[u8]) -> Result<ParsedWorkerRequest, GitServiceError> {
    let mut cursor = 0usize;
    if body.get(cursor) != Some(&NETWORK_WORKER_VERSION) {
        return Err(GitServiceError::ExecutorFailed);
    }
    cursor += 1;
    let kind = match body.get(cursor) {
        Some(1) => WorkerKind::Fetch,
        Some(2) => WorkerKind::Push,
        _ => return Err(GitServiceError::ExecutorFailed),
    };
    cursor += 1;
    if body.get(cursor) != Some(&1) {
        return Err(GitServiceError::ExecutorFailed);
    }
    cursor += 1;
    let selector_kind = match body.get(cursor) {
        Some(0) => SelectorKind::Head,
        Some(1) => SelectorKind::Fetch,
        Some(2) => SelectorKind::Push,
        _ => return Err(GitServiceError::ExecutorFailed),
    };
    cursor += 1;
    let path = decode_worker_path(worker_take_field(body, &mut cursor, 16 * 1024)?)?;
    validate_private_worker_snapshot(&path)?;
    let remote_url = std::str::from_utf8(worker_take_field(body, &mut cursor, 4096)?)
        .map_err(|_| GitServiceError::ExecutorFailed)?
        .to_owned();
    let remote_url = validate_https_remote(&remote_url)?;
    let remote_name = std::str::from_utf8(worker_take_field(body, &mut cursor, 255)?)
        .map_err(|_| GitServiceError::ExecutorFailed)?
        .to_owned();
    if !git2::Remote::is_valid_name(&remote_name) {
        return Err(GitServiceError::ExecutorFailed);
    }
    let selector_value = std::str::from_utf8(worker_take_field(body, &mut cursor, 4096)?)
        .map_err(|_| GitServiceError::ExecutorFailed)?
        .to_owned();
    let count_bytes = body
        .get(cursor..cursor.saturating_add(2))
        .ok_or(GitServiceError::ExecutorFailed)?;
    cursor += 2;
    let count = u16::from_be_bytes(
        count_bytes
            .try_into()
            .map_err(|_| GitServiceError::ExecutorFailed)?,
    ) as usize;
    if count > 200 {
        return Err(GitServiceError::ResourceLimit);
    }
    let mut fetch_specs = Vec::with_capacity(count);
    for _ in 0..count {
        let spec = std::str::from_utf8(worker_take_field(body, &mut cursor, 4096)?)
            .map_err(|_| GitServiceError::ExecutorFailed)?
            .to_owned();
        validate_fetch_refspec(&spec, &remote_name)?;
        fetch_specs.push(spec);
    }
    let username = worker_take_field(body, &mut cursor, MAX_NETWORK_CREDENTIAL_BYTES)?;
    let password = worker_take_field(body, &mut cursor, MAX_NETWORK_CREDENTIAL_BYTES)?;
    if cursor != body.len() {
        return Err(GitServiceError::ExecutorFailed);
    }
    let credentials = if username.is_empty() && password.is_empty() {
        None
    } else {
        Some(GitCredentials {
            username: Zeroizing::new(username.to_vec()),
            password: Zeroizing::new(password.to_vec()),
        })
    };
    let credentials = validate_credentials(credentials)?;
    match kind {
        WorkerKind::Fetch if selector_kind == SelectorKind::Push => {
            return Err(GitServiceError::ExecutorFailed);
        }
        WorkerKind::Push if selector_kind != SelectorKind::Push => {
            return Err(GitServiceError::ExecutorFailed);
        }
        _ => {}
    }
    match selector_kind {
        SelectorKind::Head if selector_value != "HEAD" => {
            return Err(GitServiceError::ExecutorFailed);
        }
        SelectorKind::Fetch => validate_fetch_refspec(&selector_value, &remote_name)?,
        SelectorKind::Push => validate_push_refspec(&selector_value)?,
        SelectorKind::Head => {}
    }
    Ok(ParsedWorkerRequest {
        kind,
        snapshot_path: path,
        remote_url,
        remote_name,
        selector_kind,
        selector_value,
        fetch_specs,
        credentials,
    })
}

fn write_worker_result(
    mut output: impl Write,
    result: NetworkWorkerResult,
    kind: WorkerKind,
) -> Result<(), GitServiceError> {
    let mut body = Vec::with_capacity(128);
    body.extend_from_slice(&[NETWORK_WORKER_VERSION, kind as u8]);
    match result {
        NetworkWorkerResult::Fetch {
            source,
            destination,
            tip,
        } => {
            body.push(1);
            append_worker_field(&mut body, source.as_bytes())?;
            append_worker_field(&mut body, destination.as_bytes())?;
            append_worker_field(&mut body, tip.as_bytes())?;
        }
        NetworkWorkerResult::Push(outcome) => match outcome {
            GitPushOutcome::NoEffect => body.push(2),
            GitPushOutcome::FailedNoEffect(error) => {
                body.push(3);
                body.push(worker_error_code(error));
            }
            GitPushOutcome::Rejected => body.push(4),
            GitPushOutcome::Committed => body.push(5),
            GitPushOutcome::PossibleRemoteEffect => body.push(6),
        },
        NetworkWorkerResult::Failed(error) => {
            body.push(0);
            body.push(worker_error_code(error));
        }
    }
    if body.len() + 8 > MAX_NETWORK_WORKER_OUTPUT {
        return Err(GitServiceError::ResourceLimit);
    }
    output
        .write_all(NETWORK_WORKER_MAGIC)
        .and_then(|_| output.write_all(&(body.len() as u32).to_be_bytes()))
        .and_then(|_| output.write_all(&body))
        .and_then(|_| output.flush())
        .map_err(|_| GitServiceError::ExecutorFailed)
}

fn worker_error_code(error: GitServiceError) -> u8 {
    match error {
        GitServiceError::Cancelled => 1,
        GitServiceError::DeadlineExceeded => 2,
        GitServiceError::CredentialsRequired => 3,
        GitServiceError::UnsupportedCapability => 4,
        GitServiceError::NetworkFailed => 5,
        GitServiceError::PushRejected => 6,
        GitServiceError::MutationConflict | GitServiceError::StaleState => 7,
        GitServiceError::ResourceLimit => 8,
        _ => 9,
    }
}

fn worker_error_from_code(code: u8) -> Result<GitServiceError, GitServiceError> {
    match code {
        1 => Ok(GitServiceError::Cancelled),
        2 => Ok(GitServiceError::DeadlineExceeded),
        3 => Ok(GitServiceError::CredentialsRequired),
        4 => Ok(GitServiceError::UnsupportedCapability),
        5 => Ok(GitServiceError::NetworkFailed),
        6 => Ok(GitServiceError::PushRejected),
        7 => Ok(GitServiceError::MutationConflict),
        8 => Ok(GitServiceError::ResourceLimit),
        _ => Err(GitServiceError::ExecutorFailed),
    }
}

fn network_worker_main() -> Result<(), ()> {
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut header = [0u8; 8];
    input.read_exact(&mut header).map_err(|_| ())?;
    if &header[..4] != NETWORK_WORKER_MAGIC {
        return Err(());
    }
    let body_length = u32::from_be_bytes(header[4..].try_into().map_err(|_| ())?) as usize;
    if body_length > MAX_NETWORK_WORKER_INPUT - 8 {
        return Err(());
    }
    let mut body = Zeroizing::new(vec![0u8; body_length]);
    input.read_exact(&mut body).map_err(|_| ())?;
    let mut trailing = [0u8; 1];
    if input.read(&mut trailing).map_err(|_| ())? != 0 {
        return Err(());
    }
    let request = parse_worker_request(&body).map_err(|_| ())?;
    let kind = request.kind;
    let cancellation = CancellationToken::new();
    let control =
        RequestControl::with_timeout(cancellation, Duration::from_secs(120)).map_err(|_| ())?;
    let result = match kind {
        WorkerKind::Fetch => run_fetch_worker(&request, &control),
        WorkerKind::Push => run_push_worker(&request, &control),
    }
    .unwrap_or_else(NetworkWorkerResult::Failed);
    let stdout = std::io::stdout();
    write_worker_result(stdout.lock(), result, kind).map_err(|_| ())
}

fn run_fetch_worker(
    request: &ParsedWorkerRequest,
    control: &RequestControl,
) -> Result<NetworkWorkerResult, GitServiceError> {
    let repo = open_network_repository_at(&request.snapshot_path, control)?;
    let before_objects = collect_object_inventory(&repo)?;
    let mut remote = repo
        .remote_anonymous(&request.remote_url)
        .map_err(|_| GitServiceError::NetworkFailed)?;
    let missing_credentials = AtomicBool::new(false);
    let unsupported_credentials = AtomicBool::new(false);
    let callbacks = remote_callbacks(
        &request.remote_url,
        request.credentials.as_ref(),
        control,
        control,
        &missing_credentials,
        &unsupported_credentials,
    );
    let proxy = ProxyOptions::new();
    let mut connection = remote
        .connect_auth(Direction::Fetch, Some(callbacks), Some(proxy))
        .map_err(|error| {
            map_network_error(
                error,
                control,
                &missing_credentials,
                &unsupported_credentials,
            )
        })?;
    let branch = connection
        .default_branch()
        .map_err(|error| {
            map_network_error(
                error,
                control,
                &missing_credentials,
                &unsupported_credentials,
            )
        })?
        .as_str()
        .map_err(|_| GitServiceError::UnsupportedCapability)?
        .to_owned();
    validate_server_default_branch(&branch)?;
    let fetch_spec = selected_fetch_refspec(
        &request.remote_name,
        request.selector_kind,
        &request.selector_value,
        &request.fetch_specs,
        &branch,
    )?;
    let fetch_callbacks = remote_callbacks(
        &request.remote_url,
        request.credentials.as_ref(),
        control,
        control,
        &missing_credentials,
        &unsupported_credentials,
    );
    let mut options = FetchOptions::new();
    options
        .remote_callbacks(fetch_callbacks)
        .follow_redirects(RemoteRedirect::None)
        .download_tags(git2::AutotagOption::None)
        .update_fetchhead(false)
        .proxy_options(ProxyOptions::new());
    connection
        .remote()
        .download(&[fetch_spec.as_str()], Some(&mut options))
        .map_err(|error| {
            map_network_error(
                error,
                control,
                &missing_credentials,
                &unsupported_credentials,
            )
        })?;
    control.check()?;
    connection
        .remote()
        .update_tips(
            None,
            RemoteUpdateFlags::empty(),
            git2::AutotagOption::None,
            None,
        )
        .map_err(|_| GitServiceError::NetworkFailed)?;
    drop(connection);
    drop(options);
    let (source, destination) = split_fetch_spec(&fetch_spec)?;
    validate_server_default_branch(source)?;
    validate_tracking_destination(destination, &request.remote_name)?;
    let reference = repo
        .find_reference(destination)
        .map_err(|_| GitServiceError::NetworkFailed)?;
    let tip = reference.target().ok_or(GitServiceError::NetworkFailed)?;
    // Confirm the exact ref update is backed by a bounded, parseable object
    // graph before returning success to the parent.
    let _ = materialize_new_reachable_objects(&repo, tip, &before_objects)?;
    Ok(NetworkWorkerResult::Fetch {
        source: source.to_owned(),
        destination: destination.to_owned(),
        tip: tip.to_string(),
    })
}

fn run_push_worker(
    request: &ParsedWorkerRequest,
    control: &RequestControl,
) -> Result<NetworkWorkerResult, GitServiceError> {
    let (source, destination) = split_push_spec(&request.selector_value)?;
    if !git2::Reference::is_valid_name(source) || !git2::Reference::is_valid_name(destination) {
        return Err(GitServiceError::UnsupportedCapability);
    }
    let repo = open_network_repository_at(&request.snapshot_path, control)?;
    let source_ref = repo
        .find_reference(source)
        .map_err(|_| GitServiceError::MutationConflict)?;
    let source_oid = source_ref
        .target()
        .ok_or(GitServiceError::MutationConflict)?;
    let update_will_be_sent = std::cell::Cell::new(false);
    let confirmed = std::cell::Cell::new(false);
    let rejected = std::cell::Cell::new(false);
    let missing_credentials = AtomicBool::new(false);
    let unsupported_credentials = AtomicBool::new(false);
    let callbacks = push_callbacks(
        &request.remote_url,
        request.credentials.as_ref(),
        control,
        control,
        &missing_credentials,
        &unsupported_credentials,
        destination,
        source,
        source_oid,
        &update_will_be_sent,
        &confirmed,
        &rejected,
    );
    let mut options = PushOptions::new();
    options
        .remote_callbacks(callbacks)
        .follow_redirects(RemoteRedirect::None)
        .proxy_options(ProxyOptions::new())
        .packbuilder_parallelism(1);
    let mut remote = repo
        .remote_anonymous(&request.remote_url)
        .map_err(|_| GitServiceError::NetworkFailed)?;
    let outcome = match remote.push(&[request.selector_value.as_str()], Some(&mut options)) {
        Ok(()) if confirmed.get() => GitPushOutcome::Committed,
        Ok(()) if rejected.get() => GitPushOutcome::Rejected,
        Ok(()) if !update_will_be_sent.get() => GitPushOutcome::NoEffect,
        Ok(()) => GitPushOutcome::PossibleRemoteEffect,
        Err(_error) if confirmed.get() => GitPushOutcome::Committed,
        Err(_) if rejected.get() => GitPushOutcome::Rejected,
        Err(error)
            if !update_will_be_sent.get()
                && error.code() != git2::ErrorCode::Auth
                && !missing_credentials.load(Ordering::Acquire) =>
        {
            GitPushOutcome::FailedNoEffect(map_network_error(
                error,
                control,
                &missing_credentials,
                &unsupported_credentials,
            ))
        }
        Err(error) => {
            let mapped = map_network_error(
                error,
                control,
                &missing_credentials,
                &unsupported_credentials,
            );
            if matches!(
                mapped,
                GitServiceError::CredentialsRequired | GitServiceError::UnsupportedCapability
            ) || !update_will_be_sent.get()
            {
                GitPushOutcome::FailedNoEffect(mapped)
            } else {
                GitPushOutcome::PossibleRemoteEffect
            }
        }
    };
    Ok(NetworkWorkerResult::Push(outcome))
}

fn read_worker_result(mut input: impl Read) -> Result<NetworkWorkerResult, GitServiceError> {
    let mut header = [0u8; 8];
    input
        .read_exact(&mut header)
        .map_err(|_| GitServiceError::ExecutorFailed)?;
    if &header[..4] != NETWORK_WORKER_MAGIC {
        return Err(GitServiceError::ExecutorFailed);
    }
    let length = u32::from_be_bytes(
        header[4..]
            .try_into()
            .map_err(|_| GitServiceError::ExecutorFailed)?,
    ) as usize;
    if length > MAX_NETWORK_WORKER_OUTPUT - 8 {
        return Err(GitServiceError::ResourceLimit);
    }
    let mut body = vec![0u8; length];
    input
        .read_exact(&mut body)
        .map_err(|_| GitServiceError::ExecutorFailed)?;
    let mut trailing = [0u8; 1];
    if input
        .read(&mut trailing)
        .map_err(|_| GitServiceError::ExecutorFailed)?
        != 0
        || body.len() < 3
        || body[0] != NETWORK_WORKER_VERSION
    {
        return Err(GitServiceError::ExecutorFailed);
    }
    let kind = match body[1] {
        1 => WorkerKind::Fetch,
        2 => WorkerKind::Push,
        _ => return Err(GitServiceError::ExecutorFailed),
    };
    let mut cursor = 3usize;
    let result = match (kind, body[2]) {
        (WorkerKind::Fetch, 1) => {
            let source = std::str::from_utf8(worker_take_field(&body, &mut cursor, 2048)?)
                .map_err(|_| GitServiceError::ExecutorFailed)?
                .to_owned();
            let destination = std::str::from_utf8(worker_take_field(&body, &mut cursor, 2048)?)
                .map_err(|_| GitServiceError::ExecutorFailed)?
                .to_owned();
            let tip = std::str::from_utf8(worker_take_field(&body, &mut cursor, 64)?)
                .map_err(|_| GitServiceError::ExecutorFailed)?
                .to_owned();
            if !git2::Reference::is_valid_name(&source)
                || !git2::Reference::is_valid_name(&destination)
                || validate_object_id(&tip).is_err()
            {
                return Err(GitServiceError::ExecutorFailed);
            }
            NetworkWorkerResult::Fetch {
                source,
                destination,
                tip,
            }
        }
        (WorkerKind::Push, 2) => NetworkWorkerResult::Push(GitPushOutcome::NoEffect),
        (WorkerKind::Push, 3) => {
            let code = *body.get(cursor).ok_or(GitServiceError::ExecutorFailed)?;
            cursor += 1;
            NetworkWorkerResult::Push(GitPushOutcome::FailedNoEffect(worker_error_from_code(
                code,
            )?))
        }
        (WorkerKind::Push, 4) => NetworkWorkerResult::Push(GitPushOutcome::Rejected),
        (WorkerKind::Push, 5) => NetworkWorkerResult::Push(GitPushOutcome::Committed),
        (WorkerKind::Push, 6) => NetworkWorkerResult::Push(GitPushOutcome::PossibleRemoteEffect),
        (_, 0) => {
            let code = *body.get(cursor).ok_or(GitServiceError::ExecutorFailed)?;
            cursor += 1;
            NetworkWorkerResult::Failed(worker_error_from_code(code)?)
        }
        _ => return Err(GitServiceError::ExecutorFailed),
    };
    if cursor != body.len() {
        return Err(GitServiceError::ExecutorFailed);
    }
    Ok(result)
}

fn run_network_worker(
    request: NetworkWorkerRequest,
    original: &RequestControl,
    current: &RequestControl,
) -> Result<NetworkWorkerResult, WorkerRunError> {
    check_controls(original, current).map_err(WorkerRunError::Spawn)?;
    let executable = std::env::current_exe()
        .map_err(|_| WorkerRunError::Spawn(GitServiceError::ExecutorUnavailable))?;
    let mut command = Command::new(executable);
    command
        .arg("--internal-git-worker")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", system_root);
    }
    let mut child = command
        .spawn()
        .map_err(|_| WorkerRunError::Spawn(GitServiceError::ExecutorUnavailable))?;
    let stdin = match child.stdin.take() {
        Some(stdin) => stdin,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(WorkerRunError::Spawn(GitServiceError::ExecutorFailed));
        }
    };
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(WorkerRunError::Spawn(GitServiceError::ExecutorFailed));
        }
    };
    let io = match std::thread::Builder::new()
        .name("lomi-git-network-io".to_owned())
        .spawn(move || {
            let mut stdin = stdin;
            stdin
                .write_all(&request.bytes)
                .map_err(|_| GitServiceError::ExecutorFailed)?;
            drop(stdin);
            read_worker_result(stdout)
        }) {
        Ok(io) => io,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(WorkerRunError::Spawn(GitServiceError::ExecutorUnavailable));
        }
    };

    let mut control_error = None;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(_) => {
                let _ = child.kill();
                break child.wait().ok();
            }
        }
        if let Err(error) = check_controls(original, current) {
            control_error = Some(error);
            let _ = child.kill();
            break child.wait().ok();
        }
        std::thread::sleep(NETWORK_WORKER_POLL);
    };
    let read_result = io
        .join()
        .map_err(|_| GitServiceError::ExecutorFailed)
        .and_then(|result| result);
    if let Some(error) = control_error {
        return Err(WorkerRunError::Running(error));
    }
    if !status.is_some_and(|status| status.success()) {
        return Err(WorkerRunError::Running(GitServiceError::ExecutorFailed));
    }
    read_result.map_err(WorkerRunError::Running)
}

impl PreparedGitFetch {
    fn fetch_private(
        &self,
        control: &RequestControl,
        credentials: &dyn GitCredentialProvider,
        start_network: impl FnOnce() -> Result<(), GitServiceError>,
    ) -> Result<(HashSet<Oid>, String, String, Oid), GitServiceError> {
        check_controls(&self.request_control, control)?;
        revalidate_snapshot_git_metadata(&self.files, &self.snapshot, control)?;
        let binding = credential_binding(&self.remote);
        let secret = validate_credentials(credentials.credentials(&binding))?;
        let repo = open_network_repository(&self.snapshot, control)?;
        let before_objects = collect_object_inventory(&repo)?;
        let request = build_worker_request(
            WorkerKind::Fetch,
            &self.snapshot,
            &self.remote,
            &self.selector,
            secret,
        )?;
        check_controls(&self.request_control, control)?;
        start_network()?;
        if let Err(error) = check_controls(&self.request_control, control) {
            return Err(error);
        }
        let worker_result = match run_network_worker(request, &self.request_control, control) {
            Ok(result) => result,
            Err(WorkerRunError::Spawn(error) | WorkerRunError::Running(error)) => {
                return Err(error);
            }
        };
        let NetworkWorkerResult::Fetch {
            source,
            destination,
            tip,
        } = worker_result
        else {
            return Err(match worker_result {
                NetworkWorkerResult::Failed(error) => error,
                _ => GitServiceError::ExecutorFailed,
            });
        };
        validate_server_default_branch(&source)?;
        validate_tracking_destination(&destination, &self.remote.name)?;
        let tip = validate_object_id(&tip)?;
        let tip = Oid::from_str(&tip).map_err(|_| GitServiceError::ExecutorFailed)?;
        let reference = repo
            .find_reference(&destination)
            .map_err(|_| GitServiceError::ExecutorFailed)?;
        if reference.target() != Some(tip) {
            return Err(GitServiceError::ExecutorFailed);
        }
        Ok((before_objects, source, destination, tip))
    }

    pub fn dispatch(
        self,
        control: &RequestControl,
        credentials: &dyn GitCredentialProvider,
        start_network: impl FnOnce() -> Result<(), GitServiceError>,
    ) -> Result<PreparedGitMutation, GitServiceError> {
        let (before_objects, source, destination, tip) =
            self.fetch_private(control, credentials, start_network)?;
        let repo = open_network_repository(&self.snapshot, control)?;
        let reference = repo
            .find_reference(&destination)
            .map_err(|_| GitServiceError::ExecutorFailed)?;
        if reference.target() != Some(tip) {
            return Err(GitServiceError::ExecutorFailed);
        }
        let new_object_ids = materialize_new_reachable_objects(&repo, tip, &before_objects)?;
        check_controls(&self.request_control, control)?;
        let publication = make_fetch_publication(
            &self.repository,
            &self.snapshot,
            &self.remote,
            &source,
            &destination,
            tip,
            new_object_ids,
        )?;
        Ok(PreparedGitMutation {
            files: self.files,
            publication,
            request_control: self.request_control,
            post_state: self.post_state,
            _repository_lock: self._repository_lock,
        })
    }
}

impl PreparedGitPull {
    pub fn dispatch(
        self,
        control: &RequestControl,
        credentials: &dyn GitCredentialProvider,
        start_network: impl FnOnce() -> Result<(), GitServiceError>,
    ) -> Result<PreparedGitPullMutation, GitServiceError> {
        check_mutation_preconditions(
            &self.expected,
            &self.fetch.snapshot,
            &worker::run_status(self.fetch.snapshot.path(), 0, 1, control)?.head,
        )?;
        if self.expected_worktree.as_str() != self.fetch.snapshot.state_token {
            return Err(GitServiceError::StaleState);
        }
        let status = worker::run_status(self.fetch.snapshot.path(), 0, 1, control)?;
        if !status.entries.is_empty() || status.truncated {
            return Err(GitServiceError::MutationConflict);
        }
        let (before_objects, source, destination, tip) =
            self.fetch
                .fetch_private(control, credentials, start_network)?;
        let repository = open_network_repository(&self.fetch.snapshot, control)?;
        let object_ids = materialize_new_reachable_objects(&repository, tip, &before_objects)?;
        let publication = make_pull_publication(
            &self.fetch.repository,
            &self.fetch.snapshot,
            &self.fetch.remote,
            &source,
            &destination,
            &repository,
            tip,
            object_ids,
            &self.expected,
            control,
        )?;
        Ok(PreparedGitPullMutation {
            files: self.fetch.files,
            publication,
            request_control: self.fetch.request_control,
            post_state: self.fetch.post_state,
            _repository_lock: self.fetch._repository_lock,
        })
    }
}

impl PreparedGitPullMutation {
    pub fn publish(self, control: &RequestControl) -> Result<(), GitServiceError> {
        self.publish_guarded(control, || true).map(drop)
    }

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
        self.request_control.check()?;
        control.check()?;
        let request_control = self.request_control.clone();
        let outcome = self
            .files
            .publish_git_pull(&self.publication, || {
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

impl PreparedGitPush {
    pub fn dispatch_for_receipt(
        self,
        control: &RequestControl,
        credentials: &dyn GitCredentialProvider,
        start_network: impl FnOnce() -> Result<(), GitServiceError>,
    ) -> Result<(GitPushOutcome, RepoStateToken), GitServiceError> {
        // Push does not change local repository state. Capture its exact local
        // snapshot token while the same physical-repository lease is held and
        // before network dispatch; never invent a token from remote refs.
        let state_token = self.post_state.read(control)?;
        let outcome = self.dispatch(control, credentials, start_network)?;
        Ok((outcome, state_token))
    }

    pub fn dispatch(
        self,
        control: &RequestControl,
        credentials: &dyn GitCredentialProvider,
        start_network: impl FnOnce() -> Result<(), GitServiceError>,
    ) -> Result<GitPushOutcome, GitServiceError> {
        check_controls(&self.request_control, control)?;
        revalidate_snapshot_git_metadata(&self.files, &self.snapshot, control)?;
        let binding = credential_binding(&self.remote);
        let secret = validate_credentials(credentials.credentials(&binding))?;
        let (source, destination) = split_push_spec(&self.selector.value)?;
        if !git2::Reference::is_valid_name(source) || !git2::Reference::is_valid_name(destination) {
            return Err(GitServiceError::UnsupportedCapability);
        }
        let request = build_worker_request(
            WorkerKind::Push,
            &self.snapshot,
            &self.remote,
            &self.selector,
            secret,
        )?;
        check_controls(&self.request_control, control)?;
        start_network()?;
        if let Err(error) = check_controls(&self.request_control, control) {
            return Ok(GitPushOutcome::FailedNoEffect(error));
        }
        match run_network_worker(request, &self.request_control, control) {
            Err(WorkerRunError::Spawn(_)) => Ok(GitPushOutcome::FailedNoEffect(
                GitServiceError::NetworkFailed,
            )),
            Err(WorkerRunError::Running(_)) => Ok(GitPushOutcome::PossibleRemoteEffect),
            Ok(NetworkWorkerResult::Push(outcome)) => Ok(outcome),
            Ok(NetworkWorkerResult::Failed(error)) => Ok(GitPushOutcome::FailedNoEffect(error)),
            Ok(NetworkWorkerResult::Fetch { .. }) => Ok(GitPushOutcome::PossibleRemoteEffect),
        }
    }
}
