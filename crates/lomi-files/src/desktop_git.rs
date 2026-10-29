//! Narrow owner-local publication targets used only by Desktop Git actions.
//!
//! These are deliberately separate from remote file mutation and Git index
//! publication. A Git discard can replace one selected worktree leaf; an
//! ignore action can append only the repository-root `.gitignore` or the
//! common Git directory's `info/exclude` file.

use crate::{
    EntryRef, GitFilePrecondition, GitFinalFile, GitFinalTarget, GitPublication, GitPublishOutcome,
    GitPullFile, GitPullNodeKind, GitPullPrecondition, LocalNativeFileCheckPhase,
    OwnerGitMetadataCondition, OwnerGitMetadataRoot, Result,
};

const MAX_DESKTOP_GIT_IGNORE_BYTES: usize = 1024 * 1024;
const MAX_DESKTOP_GIT_FILE_BYTES: usize = 256 * 1024 * 1024;
const MAX_DESKTOP_GIT_LINK_BYTES: usize = 64 * 1024;

/// One descriptor-relative worktree leaf restored from the current index.
/// The path is workspace-relative and the publisher verifies that it remains
/// below the registered repository root before touching the namespace.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct GitDesktopFilePublication {
    pub repository: EntryRef,
    pub git_dir: EntryRef,
    pub common_dir: EntryRef,
    /// The repository's `.git` marker and optional linked-worktree
    /// `commondir` marker, captured during repository discovery.
    pub repository_preconditions: Vec<GitPullPrecondition>,
    /// Freshly captured `.git` marker, gitdir, common-dir, HEAD and index
    /// conditions. The platform publisher rechecks these after authorization
    /// and immediately before replacing the worktree leaf.
    pub metadata_preconditions: Vec<GitFilePrecondition>,
    pub file: GitPullFile,
}

/// The worktree half of an owner-local one-leaf publication. It contains no
/// Git metadata `EntryRef`s, so it can be paired with an explicitly pinned
/// external metadata root without mixing root-local entry namespaces.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct GitDesktopFileTarget {
    pub repository: EntryRef,
    pub repository_preconditions: Vec<GitPullPrecondition>,
    /// Additional selected worktree nodes guarded by an owner ignore action.
    pub worktree_preconditions: Vec<GitPullPrecondition>,
    pub file: GitPullFile,
}

impl GitDesktopFilePublication {
    pub(crate) fn target(&self) -> GitDesktopFileTarget {
        GitDesktopFileTarget {
            repository: self.repository,
            repository_preconditions: self.repository_preconditions.clone(),
            worktree_preconditions: Vec::new(),
            file: self.file.clone(),
        }
    }
}

/// Paired worktree/Git-metadata publication used only by Desktop Git when
/// validated metadata lives outside the workspace FileRoot.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct OwnerGitDesktopFilePublication {
    pub target: GitDesktopFileTarget,
    pub metadata_preconditions: Vec<OwnerGitMetadataCondition>,
}

/// The only two targets accepted by an external-metadata owner ignore action.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub enum OwnerGitIgnoreTarget {
    Worktree { expected: GitPullPrecondition },
    CommonExclude { expected: OwnerGitMetadataCondition },
}

/// Paired, selected-entry-guarded owner-local ignore update.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct OwnerGitIgnorePublication {
    pub repository: EntryRef,
    /// Repository-root path from the workspace root, used to form a valid
    /// workspace-relative `.gitignore` publication path.
    pub repository_path: Vec<Vec<u8>>,
    pub repository_preconditions: Vec<GitPullPrecondition>,
    pub selected: GitPullPrecondition,
    pub metadata_preconditions: Vec<OwnerGitMetadataCondition>,
    pub target: OwnerGitIgnoreTarget,
    pub bytes: Vec<u8>,
}

impl OwnerGitIgnorePublication {
    fn validate(&self) -> Result<()> {
        if self.repository_preconditions.len() != 1
            || self.repository_path.len() > 255
            || self.repository_path.iter().any(|part| {
                !crate::git::valid_component(part)
                    || part.eq_ignore_ascii_case(b".git")
                    || crate::is_private_staging_name(part)
            })
            || self.selected.entry.is_some() != self.selected.revision.is_some()
            || self.selected.entry.is_some() != self.selected.kind.is_some()
            || self.metadata_preconditions.is_empty()
            || self.metadata_preconditions.len() > 32
            || self.bytes.len() > MAX_DESKTOP_GIT_IGNORE_BYTES
        {
            return Err(crate::Error::Invalid);
        }
        validate_owner_git_metadata_conditions(&self.metadata_preconditions)?;
        let marker = &self.repository_preconditions[0];
        if marker.parent != self.repository
            || marker.name != b".git"
            || !matches!(
                marker.kind,
                Some(GitPullNodeKind::File | GitPullNodeKind::Directory)
            )
            || marker.entry.is_none()
            || marker.revision.is_none()
        {
            return Err(crate::Error::Invalid);
        }
        match &self.target {
            OwnerGitIgnoreTarget::Worktree { expected } => {
                let mut expected_path = self.repository_path.clone();
                expected_path.push(b".gitignore".to_vec());
                if expected.parent != self.repository
                    || expected.name != b".gitignore"
                    || expected_path
                        .iter()
                        .any(|part| !crate::git::valid_component(part))
                    || expected.entry.is_some() != expected.revision.is_some()
                    || expected.entry.is_some() != expected.kind.is_some()
                    || expected
                        .kind
                        .is_some_and(|kind| kind != GitPullNodeKind::File)
                {
                    return Err(crate::Error::Invalid);
                }
            }
            OwnerGitIgnoreTarget::CommonExclude { expected } => {
                if expected.role != crate::OwnerGitMetadataRole::CommonDir
                    || expected.path.components() != [b"info".to_vec(), b"exclude".to_vec()]
                    || expected.expected.as_ref().is_some_and(|version| {
                        version.kind != crate::Kind::File || version.nlink != 1
                    })
                {
                    return Err(crate::Error::Invalid);
                }
            }
        }
        Ok(())
    }
}

impl GitDesktopFilePublication {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_repository_preconditions(
            self.repository,
            self.git_dir,
            self.common_dir,
            &self.repository_preconditions,
        )?;
        validate_git_desktop_leaf(&self.file)?;
        if self.metadata_preconditions.is_empty()
            || self.metadata_preconditions.len() > 16
            || self.metadata_preconditions.iter().any(|condition| {
                condition.name.is_empty()
                    || condition.name.len() > 255
                    || condition.name.contains(&b'/')
                    || condition.name.contains(&b'\\')
                    || condition.name.contains(&0)
                    || condition.entry.is_some() != condition.revision.is_some()
                    || (condition.parent == self.repository && condition.name == b".git")
                    || condition.entry == Some(self.git_dir)
                    || condition.entry == Some(self.common_dir)
                    || condition
                        .revision
                        .as_ref()
                        .is_some_and(|revision| revision.is_empty() || revision.len() > 256)
            })
        {
            return Err(crate::Error::Invalid);
        }
        Ok(())
    }
}

impl GitDesktopFileTarget {
    pub(crate) fn validate_owner_local(&self) -> Result<()> {
        if self.repository_preconditions.len() != 1 {
            return Err(crate::Error::Invalid);
        }
        let marker = &self.repository_preconditions[0];
        if marker.parent != self.repository
            || marker.name != b".git"
            || marker.entry.is_none()
            || marker
                .revision
                .as_ref()
                .is_none_or(|revision| revision.is_empty() || revision.len() > 256)
            || !matches!(
                marker.kind,
                Some(GitPullNodeKind::File | GitPullNodeKind::Directory)
            )
        {
            return Err(crate::Error::Invalid);
        }
        if self.worktree_preconditions.len() > 16
            || self.worktree_preconditions.iter().any(|condition| {
                condition.entry.is_some() != condition.revision.is_some()
                    || condition.entry.is_some() != condition.kind.is_some()
                    || condition.name.is_empty()
                    || condition.name.len() > 255
                    || condition.name.contains(&b'/')
                    || condition.name.contains(&b'\\')
                    || condition.name.contains(&0)
                    || condition
                        .revision
                        .as_ref()
                        .is_some_and(|revision| revision.is_empty() || revision.len() > 256)
            })
        {
            return Err(crate::Error::Invalid);
        }
        validate_git_desktop_leaf(&self.file)
    }
}

fn validate_git_desktop_leaf(file: &GitPullFile) -> Result<()> {
    if file.path.is_empty()
        || file.path.len() > 256
        || file
            .path
            .iter()
            .any(|part| !crate::git::valid_component(part) || part.eq_ignore_ascii_case(b".git"))
        || file.parent_suffix.len() > 64
        || file
            .parent_suffix
            .iter()
            .any(|part| !crate::git::valid_component(part))
        || !crate::git::valid_component(&file.name)
        || file.expected.parent != file.parent
        || file.expected.entry.is_some() != file.expected.revision.is_some()
        || file.expected.entry.is_some() != file.expected.kind.is_some()
        || (file.parent_suffix.is_empty() && file.expected.name != file.name)
        || (!file.parent_suffix.is_empty()
            && (file.expected.entry.is_some()
                || file.expected.revision.is_some()
                || file.expected.kind.is_some()
                || file.expected.name != file.parent_suffix[0]))
        || file.contents.is_none()
        || file
            .contents
            .as_ref()
            .is_some_and(|contents| contents.len() > MAX_DESKTOP_GIT_FILE_BYTES)
        || !matches!(file.kind, GitPullNodeKind::File | GitPullNodeKind::Symlink)
        || (file.kind == GitPullNodeKind::Symlink
            && (file.executable
                || file.contents.as_ref().is_some_and(|contents| {
                    contents.is_empty()
                        || contents.len() > MAX_DESKTOP_GIT_LINK_BYTES
                        || contents.contains(&0)
                })))
        || file
            .expected
            .revision
            .as_ref()
            .is_some_and(|revision| revision.is_empty() || revision.len() > 256)
    {
        return Err(crate::Error::Invalid);
    }
    let parent_prefix_len = file
        .path
        .len()
        .checked_sub(file.parent_suffix.len() + 1)
        .ok_or(crate::Error::Invalid)?;
    if file.path.last() != Some(&file.name)
        || file.path[parent_prefix_len..file.path.len() - 1] != file.parent_suffix
    {
        return Err(crate::Error::Invalid);
    }
    Ok(())
}

/// The only two paths a Desktop Git Ignore action is allowed to update.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub enum GitIgnoreTarget {
    /// `<repository-root>/.gitignore`.
    Worktree { repository: EntryRef },
    /// `<common-git-dir>/info/exclude` (shared by linked worktrees).
    LocalExclude { common_dir: EntryRef },
}

/// An atomic compare-and-swap update to one fixed ignore file.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct GitIgnorePublication {
    /// Repository containing the selected entry, including when the ignore
    /// rule is stored in the linked worktree's common Git directory.
    pub repository: EntryRef,
    pub target: GitIgnoreTarget,
    pub git_dir: EntryRef,
    pub common_dir: EntryRef,
    /// The repository's `.git` marker and optional linked-worktree
    /// `commondir` marker, captured during repository discovery.
    pub repository_preconditions: Vec<GitPullPrecondition>,
    /// Repository metadata identity and content revisions captured before
    /// authorization and rechecked directly by the platform publisher.
    pub metadata_preconditions: Vec<GitFilePrecondition>,
    /// The selected worktree entry being ignored. This is revalidated by
    /// identity and revision after authorization; it is never followed.
    pub selected: GitPullPrecondition,
    /// Only the fixed `info` component may be created for a fresh common Git
    /// directory. A non-empty suffix is exactly `[b"info"]`.
    pub parent_suffix: Vec<Vec<u8>>,
    pub expected: GitFilePrecondition,
    pub bytes: Vec<u8>,
}

impl GitIgnorePublication {
    pub(crate) fn validate(&self) -> Result<()> {
        validate_repository_preconditions(
            self.repository,
            self.git_dir,
            self.common_dir,
            &self.repository_preconditions,
        )?;
        let (expected_parent, expected_name) = match &self.target {
            GitIgnoreTarget::Worktree { repository } => (*repository, b".gitignore".as_slice()),
            GitIgnoreTarget::LocalExclude { common_dir } => (
                if self.parent_suffix.is_empty() {
                    self.expected.parent
                } else {
                    *common_dir
                },
                if self.parent_suffix.is_empty() {
                    b"exclude".as_slice()
                } else {
                    b"info".as_slice()
                },
            ),
        };
        let local_target_valid = match &self.target {
            GitIgnoreTarget::Worktree { repository } => {
                self.parent_suffix.is_empty()
                    && self.repository == *repository
                    && self.expected.parent == *repository
                    && self.expected.name == b".gitignore"
            }
            GitIgnoreTarget::LocalExclude { common_dir } => {
                self.parent_suffix.len() <= 1
                    && self
                        .parent_suffix
                        .first()
                        .is_none_or(|part| part.as_slice() == b"info")
                    && if self.parent_suffix.is_empty() {
                        self.expected.name == b"exclude"
                    } else {
                        self.expected.parent == *common_dir
                            && self.expected.entry.is_none()
                            && self.expected.revision.is_none()
                            && self.expected.name == b"info"
                    }
            }
        };
        if !local_target_valid
            || self.expected.parent != expected_parent
            || self.expected.name != expected_name
            || self.expected.entry.is_some() != self.expected.revision.is_some()
            || self.bytes.len() > MAX_DESKTOP_GIT_IGNORE_BYTES
            || self.metadata_preconditions.is_empty()
            || self.metadata_preconditions.len() > 16
            || self.metadata_preconditions.iter().any(|condition| {
                condition.name.is_empty()
                    || condition.name.len() > 255
                    || condition.name.contains(&b'/')
                    || condition.name.contains(&b'\\')
                    || condition.name.contains(&0)
                    || condition.entry.is_some() != condition.revision.is_some()
                    || (condition.parent == self.repository && condition.name == b".git")
                    || condition.entry == Some(self.git_dir)
                    || condition.entry == Some(self.common_dir)
                    || condition
                        .revision
                        .as_ref()
                        .is_some_and(|revision| revision.is_empty() || revision.len() > 256)
            })
            || self.selected.name.is_empty()
            || self.selected.name.len() > 255
            || self.selected.name.contains(&b'/')
            || self.selected.name.contains(&b'\\')
            || self.selected.name.contains(&0)
            || self.selected.entry.is_some() != self.selected.revision.is_some()
            || self.selected.entry.is_some() != self.selected.kind.is_some()
            || self
                .selected
                .revision
                .as_ref()
                .is_some_and(|revision| revision.is_empty() || revision.len() > 256)
            || self
                .expected
                .revision
                .as_ref()
                .is_some_and(|revision| revision.is_empty() || revision.len() > 256)
        {
            return Err(crate::Error::Invalid);
        }
        Ok(())
    }
}

fn validate_repository_preconditions(
    repository: EntryRef,
    git_dir: EntryRef,
    common_dir: EntryRef,
    preconditions: &[GitPullPrecondition],
) -> Result<()> {
    if preconditions.is_empty() || preconditions.len() > 2 {
        return Err(crate::Error::Invalid);
    }
    let marker = &preconditions[0];
    if marker.parent != repository
        || marker.name != b".git"
        || marker.entry.is_none()
        || marker
            .revision
            .as_ref()
            .is_none_or(|revision| revision.is_empty() || revision.len() > 256)
        || !matches!(
            marker.kind,
            Some(GitPullNodeKind::File | GitPullNodeKind::Directory)
        )
        || (marker.kind == Some(GitPullNodeKind::Directory) && marker.entry != Some(git_dir))
    {
        return Err(crate::Error::Invalid);
    }
    if common_dir == git_dir {
        if preconditions.len() != 1 {
            return Err(crate::Error::Invalid);
        }
    } else {
        let common_marker = preconditions.get(1).ok_or(crate::Error::Invalid)?;
        if preconditions.len() != 2
            || common_marker.parent != git_dir
            || common_marker.name != b"commondir"
            || common_marker.entry.is_none()
            || common_marker
                .revision
                .as_ref()
                .is_none_or(|revision| revision.is_empty() || revision.len() > 256)
            || common_marker.kind != Some(GitPullNodeKind::File)
        {
            return Err(crate::Error::Invalid);
        }
    }
    Ok(())
}

/// Publish the selected tracked leaf under the platform's handle-relative
/// FileRoot barrier.
#[doc(hidden)]
pub fn publish_git_desktop_file(
    root: &crate::FileRoot,
    publication: &GitDesktopFilePublication,
    check: impl FnMut(LocalNativeFileCheckPhase) -> bool,
) -> Result<GitPublishOutcome> {
    publication.validate()?;
    #[cfg(unix)]
    {
        crate::unix::desktop_git::publish_file(root, publication, check)
    }
    #[cfg(windows)]
    {
        crate::windows::desktop_git::publish_file(root, publication, check)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (root, publication, check);
        Err(crate::Error::Unsupported)
    }
}

/// Publish one worktree leaf while also validating typed Git metadata roots
/// that live outside the workspace root. Only owner-local Git callers receive
/// this capability; ordinary FileRoot mutation remains workspace-confined.
#[doc(hidden)]
pub fn publish_git_desktop_file_owner_local(
    workspace: &crate::FileRoot,
    git_dir: &OwnerGitMetadataRoot,
    common_dir: &OwnerGitMetadataRoot,
    publication: &OwnerGitDesktopFilePublication,
    check: impl FnMut(LocalNativeFileCheckPhase) -> bool,
) -> Result<GitPublishOutcome> {
    publication.target.validate_owner_local()?;
    validate_owner_git_metadata_conditions(&publication.metadata_preconditions)?;
    #[cfg(unix)]
    {
        crate::unix::owner_git::publish_file(workspace, git_dir, common_dir, publication, check)
    }
    #[cfg(windows)]
    {
        crate::windows::owner_git::publish_file(workspace, git_dir, common_dir, publication, check)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (workspace, git_dir, common_dir, publication, check);
        Err(crate::Error::Unsupported)
    }
}

pub(crate) fn validate_owner_git_metadata_conditions(
    conditions: &[OwnerGitMetadataCondition],
) -> Result<()> {
    if conditions.is_empty() || conditions.len() > 32 {
        return Err(crate::Error::Invalid);
    }
    for condition in conditions {
        if condition.path.components().is_empty()
            || condition.path.components().len() > 128
            || condition.expected.as_ref().is_some_and(|version| {
                version.revision.is_empty()
                    || version.revision.len() > 256
                    || version.kind == crate::Kind::Other
                    || matches!(version.kind, crate::Kind::File | crate::Kind::Symlink)
                        && version.nlink != 1
            })
        {
            return Err(crate::Error::Invalid);
        }
    }
    for (role, name) in [
        (crate::OwnerGitMetadataRole::GitDir, b"commondir".as_slice()),
        (crate::OwnerGitMetadataRole::GitDir, b"HEAD".as_slice()),
        (crate::OwnerGitMetadataRole::GitDir, b"index".as_slice()),
        (
            crate::OwnerGitMetadataRole::GitDir,
            b"config.worktree".as_slice(),
        ),
        (crate::OwnerGitMetadataRole::CommonDir, b"config".as_slice()),
    ] {
        if !conditions.iter().any(|condition| {
            condition.role == role
                && condition.path.components().len() == 1
                && condition.path.components()[0].as_slice() == name
        }) {
            return Err(crate::Error::Invalid);
        }
    }
    let commondir = conditions
        .iter()
        .find(|condition| {
            condition.role == crate::OwnerGitMetadataRole::GitDir
                && condition.path.components() == [b"commondir".to_vec()]
        })
        .ok_or(crate::Error::Invalid)?;
    if commondir
        .expected
        .as_ref()
        .is_some_and(|version| version.kind != crate::Kind::File || version.nlink != 1)
    {
        return Err(crate::Error::Invalid);
    }
    let head = conditions
        .iter()
        .find(|condition| {
            condition.role == crate::OwnerGitMetadataRole::GitDir
                && condition.path.components() == [b"HEAD".to_vec()]
        })
        .and_then(|condition| condition.expected.as_ref())
        .ok_or(crate::Error::Invalid)?;
    if head.kind != crate::Kind::File || head.nlink != 1 {
        return Err(crate::Error::Invalid);
    }
    Ok(())
}

/// Publish one external-metadata Desktop Ignore action. Worktree `.gitignore`
/// reuses the paired leaf publisher; local `info/exclude` is constrained to
/// that exact common-dir path by the platform owner publisher.
#[doc(hidden)]
pub fn publish_git_ignore_owner_local(
    workspace: &crate::FileRoot,
    git_dir: &OwnerGitMetadataRoot,
    common_dir: &OwnerGitMetadataRoot,
    publication: &OwnerGitIgnorePublication,
    check: impl FnMut(LocalNativeFileCheckPhase) -> bool,
) -> Result<GitPublishOutcome> {
    publication.validate()?;
    match &publication.target {
        OwnerGitIgnoreTarget::Worktree { expected } => {
            let mut path = publication.repository_path.clone();
            path.push(b".gitignore".to_vec());
            let file = GitPullFile {
                path,
                parent: publication.repository,
                parent_suffix: Vec::new(),
                name: b".gitignore".to_vec(),
                expected: expected.clone(),
                contents: Some(publication.bytes.clone()),
                kind: GitPullNodeKind::File,
                executable: false,
            };
            let target = GitDesktopFileTarget {
                repository: publication.repository,
                repository_preconditions: publication.repository_preconditions.clone(),
                worktree_preconditions: vec![publication.selected.clone()],
                file,
            };
            publish_git_desktop_file_owner_local(
                workspace,
                git_dir,
                common_dir,
                &OwnerGitDesktopFilePublication {
                    target,
                    metadata_preconditions: publication.metadata_preconditions.clone(),
                },
                check,
            )
        }
        OwnerGitIgnoreTarget::CommonExclude { expected } => {
            let expected_file = common_exclude_file(common_dir, expected, &publication.bytes)?;
            let worktree_target = GitDesktopFileTarget {
                repository: publication.repository,
                repository_preconditions: publication.repository_preconditions.clone(),
                worktree_preconditions: Vec::new(),
                file: expected_file.clone(),
            };
            #[cfg(unix)]
            {
                crate::unix::owner_git::publish_common_exclude(
                    workspace,
                    git_dir,
                    common_dir,
                    &worktree_target,
                    &publication.selected,
                    &publication.metadata_preconditions,
                    &expected_file,
                    check,
                )
            }
            #[cfg(windows)]
            {
                crate::windows::owner_git::publish_common_exclude(
                    workspace,
                    git_dir,
                    common_dir,
                    &worktree_target,
                    &publication.selected,
                    &publication.metadata_preconditions,
                    &expected_file,
                    check,
                )
            }
            #[cfg(not(any(unix, windows)))]
            {
                let _ = (
                    workspace,
                    git_dir,
                    common_dir,
                    worktree_target,
                    expected_file,
                    check,
                );
                Err(crate::Error::Unsupported)
            }
        }
    }
}

fn common_exclude_file(
    common_dir: &OwnerGitMetadataRoot,
    expected: &OwnerGitMetadataCondition,
    bytes: &[u8],
) -> Result<GitPullFile> {
    if expected.role != crate::OwnerGitMetadataRole::CommonDir
        || expected.path.components() != [b"info".to_vec(), b"exclude".to_vec()]
    {
        return Err(crate::Error::Invalid);
    }
    let root = common_dir.file_root();
    let root_entry = root.root_entry();
    let info = crate::OwnerGitMetadataPath::from_components(vec![b"info".to_vec()])?;
    let entries = common_dir.list(&crate::OwnerGitMetadataPath::root())?;
    let info_entry = entries.into_iter().find(|entry| entry.path == info);
    let path = expected.path.components().to_vec();
    let (parent, parent_suffix, expected_condition) = match info_entry {
        Some(info_entry) if info_entry.kind == crate::Kind::Directory => {
            let resolved = common_dir.resolve_condition(expected)?;
            let expected_condition = GitPullPrecondition {
                parent: resolved.parent,
                name: resolved.name,
                entry: resolved.entry,
                revision: resolved.revision,
                kind: expected
                    .expected
                    .as_ref()
                    .map(|version| match version.kind {
                        crate::Kind::File => GitPullNodeKind::File,
                        crate::Kind::Symlink => GitPullNodeKind::Symlink,
                        crate::Kind::Directory => GitPullNodeKind::Directory,
                        crate::Kind::Other => GitPullNodeKind::File,
                    }),
            };
            (resolved.parent, Vec::new(), expected_condition)
        }
        Some(_) => return Err(crate::Error::Protected),
        None => {
            if expected.expected.is_some() {
                return Err(crate::Error::Changed);
            }
            (
                root_entry,
                vec![b"info".to_vec()],
                GitPullPrecondition {
                    parent: root_entry,
                    name: b"info".to_vec(),
                    entry: None,
                    revision: None,
                    kind: None,
                },
            )
        }
    };
    Ok(GitPullFile {
        path,
        parent,
        parent_suffix,
        name: b"exclude".to_vec(),
        expected: expected_condition,
        contents: Some(bytes.to_vec()),
        kind: GitPullNodeKind::File,
        executable: false,
    })
}

/// Compare-and-swap one of the two fixed ignore targets, preserving the
/// target's existing owner security when replacing it.
#[doc(hidden)]
pub fn publish_git_ignore(
    root: &crate::FileRoot,
    publication: &GitIgnorePublication,
    mut check: impl FnMut(LocalNativeFileCheckPhase) -> bool,
) -> Result<GitPublishOutcome> {
    publication.validate()?;
    let target = match publication.target {
        GitIgnoreTarget::Worktree { repository } => GitFinalTarget::WorktreeIgnore { repository },
        GitIgnoreTarget::LocalExclude { common_dir } => GitFinalTarget::LocalExclude { common_dir },
    };
    let publisher = GitPublication {
        git_dir: publication.git_dir,
        common_dir: publication.common_dir,
        preconditions: publication.metadata_preconditions.clone(),
        worktree_preconditions: Vec::new(),
        objects: Vec::new(),
        final_file: GitFinalFile {
            target,
            parent: publication.expected.parent,
            parent_suffix: publication.parent_suffix.clone(),
            expected: publication.expected.clone(),
            bytes: publication.bytes.clone(),
        },
    };
    if !check(LocalNativeFileCheckPhase::Progress)
        || !check(LocalNativeFileCheckPhase::BeforeEffect)
        || !check(LocalNativeFileCheckPhase::Validation)
    {
        return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
    }
    let newly_created_info = matches!(&publication.target, GitIgnoreTarget::LocalExclude { .. })
        && publication.parent_suffix.len() == 1;
    let result = root.publish_git_desktop_ignore(
        &publisher,
        publication.repository,
        &publication.repository_preconditions,
        &publication.selected,
        || check(LocalNativeFileCheckPhase::Publication),
    );
    if newly_created_info
        && match &result {
            Err(_) | Ok(GitPublishOutcome::AbortedBeforeFinalRename) => true,
            Ok(GitPublishOutcome::Published | GitPublishOutcome::UncertainAfterFinalRename) => {
                false
            }
        }
    {
        let common_dir = match &publication.target {
            GitIgnoreTarget::LocalExclude { common_dir } => *common_dir,
            GitIgnoreTarget::Worktree { .. } => unreachable!(),
        };
        if fixed_child_exists(root, common_dir, b"info").unwrap_or(true) {
            return Ok(GitPublishOutcome::UncertainAfterFinalRename);
        }
    }
    result
}

fn fixed_child_exists(root: &crate::FileRoot, parent: EntryRef, name: &[u8]) -> Result<bool> {
    let mut cursor = None;
    let mut seen = std::collections::HashSet::new();
    loop {
        let page = root.list(parent, cursor.as_deref(), 200)?;
        if page.entries.iter().any(|entry| entry.name == name) {
            return Ok(true);
        }
        match page.next {
            Some(next) if page.truncated && seen.insert(next.clone()) => cursor = Some(next),
            Some(_) | None if page.truncated => return Err(crate::Error::Changed),
            None => return Ok(false),
            Some(_) => return Err(crate::Error::Changed),
        }
    }
}
