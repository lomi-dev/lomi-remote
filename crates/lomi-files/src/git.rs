//! Host-internal publication primitives for Git metadata.
//!
//! These operations are intentionally separate from Explorer file mutations:
//! they can write only below a validated `.git` directory and expose no
//! client-controlled filesystem path.

use crate::EntryRef;

const MAX_GIT_OBJECTS: usize = 200_000;
const MAX_GIT_OBJECT_BYTES: usize = 64 * 1024 * 1024;
const MAX_GIT_PUBLICATION_BYTES: usize = 512 * 1024 * 1024;
const MAX_GIT_PRECONDITIONS: usize = 16;
const MAX_GIT_WORKTREE_PRECONDITIONS: usize = 200;
const MAX_GIT_PULL_FILES: usize = 200;
const MAX_GIT_PULL_NODES: usize = 20_000;
const MAX_GIT_PULL_FILE_BYTES: usize = 256 * 1024 * 1024;
const MAX_GIT_PULL_BYTES: usize = 512 * 1024 * 1024;
const MAX_GIT_PULL_LINK_BYTES: usize = 64 * 1024;
const MAX_GIT_REF_PATH_BYTES: usize = 2048;
const MAX_GIT_REF_COMPONENTS: usize = 64;

/// A file identity/revision condition below one pinned Git metadata directory.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitFilePrecondition {
    pub parent: EntryRef,
    pub name: Vec<u8>,
    /// `None` means the file must be absent.
    pub entry: Option<EntryRef>,
    /// Present exactly when `entry` is present.
    pub revision: Option<String>,
}

/// A pinned worktree file whose exact bytes were used to prepare an index.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct GitWorktreePrecondition {
    pub parent: EntryRef,
    pub name: Vec<u8>,
    pub entry: Option<EntryRef>,
    pub revision: Option<String>,
}

/// A compressed loose Git object, named by its canonical lowercase object ID.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct GitObjectFile {
    pub object_id: String,
    pub bytes: Vec<u8>,
}

/// The only Git metadata targets the publisher is allowed to replace.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GitFinalTarget {
    /// Replace the repository index.
    Index,
    /// Replace detached `.git/HEAD`.
    DetachedHead,
    /// Replace a fully resolved branch reference relative to the common dir.
    BranchHead { reference: Vec<Vec<u8>> },
    /// Replace a fully resolved remote-tracking reference relative to the
    /// common dir. The host may publish only below `refs/remotes`.
    RemoteTrackingHead { reference: Vec<Vec<u8>> },
    /// Replace only the selected repository root's `.gitignore`.
    WorktreeIgnore { repository: EntryRef },
    /// Replace only `<common-dir>/info/exclude`.
    LocalExclude { common_dir: EntryRef },
}

impl GitFinalTarget {
    pub(crate) fn name(&self) -> &[u8] {
        match self {
            Self::Index => b"index",
            Self::DetachedHead => b"HEAD",
            Self::BranchHead { reference } | Self::RemoteTrackingHead { reference } => {
                reference.last().map(Vec::as_slice).unwrap_or_default()
            }
            Self::WorktreeIgnore { .. } => b".gitignore",
            Self::LocalExclude { .. } => b"exclude",
        }
    }
}

/// One Git metadata file to atomically replace after publishing its objects.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct GitFinalFile {
    pub target: GitFinalTarget,
    /// Nearest existing protected directory above the target's parent.
    pub parent: EntryRef,
    /// Missing target-parent components below `parent`, in order. Branch
    /// publication creates only these components while holding the FileRoot
    /// write barrier and records their filesystem identities.
    pub parent_suffix: Vec<Vec<u8>>,
    /// The identity/revision of the target, or the first missing parent when
    /// `parent_suffix` is non-empty. In that case it must describe absence.
    pub expected: GitFilePrecondition,
    pub bytes: Vec<u8>,
}

/// An owned, bounded Git metadata publication prepared from a private snapshot.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct GitPublication {
    /// Git directory containing `index` and `HEAD`.
    pub git_dir: EntryRef,
    /// Common directory containing the object database.
    pub common_dir: EntryRef,
    /// Conditions checked before and immediately before the final rename.
    pub preconditions: Vec<GitFilePrecondition>,
    /// Worktree identities and revisions checked with the final metadata.
    pub worktree_preconditions: Vec<GitWorktreePrecondition>,
    /// New objects are installed before the final metadata file becomes visible.
    pub objects: Vec<GitObjectFile>,
    /// The index or a loose reference; this is the publication point.
    pub final_file: GitFinalFile,
}

/// The worktree node type that a Git pull installs or removes.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GitPullNodeKind {
    File,
    Symlink,
    Directory,
}

/// A descriptor-confined worktree precondition for a fast-forward pull.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitPullPrecondition {
    pub parent: EntryRef,
    pub name: Vec<u8>,
    pub entry: Option<EntryRef>,
    pub revision: Option<String>,
    /// `None` describes an absent name; present entries carry their no-follow
    /// node type so links and directories cannot be mistaken for regular files.
    pub kind: Option<GitPullNodeKind>,
}

/// One descriptor-confined worktree node change in a fast-forward pull.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct GitPullFile {
    /// Worktree path relative to the pinned workspace root.
    pub path: Vec<Vec<u8>>,
    /// Nearest existing worktree directory before any missing parents.
    pub parent: EntryRef,
    /// Missing containing-directory components below `parent`.
    pub parent_suffix: Vec<Vec<u8>>,
    pub name: Vec<u8>,
    /// For nested additions this guards the first missing directory; otherwise
    /// it guards the target file itself.
    pub expected: GitPullPrecondition,
    /// `None` removes this node; `Some` installs file bytes or a symlink target.
    pub contents: Option<Vec<u8>>,
    pub kind: GitPullNodeKind,
    pub executable: bool,
}

/// Ordered publication for a fast-forward pull. The index is first, the
/// optional remote-tracking ref follows, and the local HEAD/branch ref is the
/// final commit point. A failure after any worktree or metadata change is an
/// uncertain partial result and must be reconciled by the host.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct GitPullPublication {
    pub metadata: Vec<GitPublication>,
    pub files: Vec<GitPullFile>,
}

/// Result of a Git publication that noticed cancellation before its final rename.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitPublishOutcome {
    Published,
    AbortedBeforeFinalRename,
    UncertainAfterFinalRename,
}

impl GitPublication {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.preconditions.len() > MAX_GIT_PRECONDITIONS
            || self.worktree_preconditions.len() > MAX_GIT_WORKTREE_PRECONDITIONS
            || self.objects.len() > MAX_GIT_OBJECTS
            || self.final_file.bytes.len() > MAX_GIT_OBJECT_BYTES
        {
            return Err("Git publication resource limit");
        }
        let name = self.final_file.target.name();
        if name.is_empty()
            || self.final_file.expected.parent != self.final_file.parent
            || self.final_file.parent_suffix.len() > MAX_GIT_REF_COMPONENTS
            || self
                .final_file
                .parent_suffix
                .iter()
                .any(|part| !valid_component(part))
        {
            return Err("inconsistent Git publication target");
        }
        match &self.final_file.target {
            GitFinalTarget::Index | GitFinalTarget::DetachedHead => {
                if !self.final_file.parent_suffix.is_empty()
                    || self.final_file.expected.name != name
                {
                    return Err("invalid Git publication target");
                }
            }
            GitFinalTarget::BranchHead { reference } => {
                validate_branch_reference(reference)?;
                let expected_name = self
                    .final_file
                    .parent_suffix
                    .first()
                    .map(Vec::as_slice)
                    .unwrap_or(name);
                if self.final_file.expected.name != expected_name
                    || (!self.final_file.parent_suffix.is_empty()
                        && self.final_file.expected.entry.is_some())
                {
                    return Err("invalid Git publication target");
                }
            }
            GitFinalTarget::RemoteTrackingHead { reference } => {
                validate_remote_tracking_reference(reference)?;
                let expected_name = self
                    .final_file
                    .parent_suffix
                    .first()
                    .map(Vec::as_slice)
                    .unwrap_or(name);
                if self.final_file.expected.name != expected_name
                    || (!self.final_file.parent_suffix.is_empty()
                        && self.final_file.expected.entry.is_some())
                {
                    return Err("invalid Git publication target");
                }
            }
            GitFinalTarget::WorktreeIgnore { repository } => {
                if self.final_file.parent != *repository
                    || !self.final_file.parent_suffix.is_empty()
                    || self.final_file.expected.name != b".gitignore"
                    || !self.objects.is_empty()
                {
                    return Err("invalid Git worktree ignore target");
                }
            }
            GitFinalTarget::LocalExclude { common_dir } => {
                if *common_dir != self.common_dir
                    || self.final_file.parent_suffix.len() > 1
                    || self
                        .final_file
                        .parent_suffix
                        .first()
                        .is_some_and(|part| part.as_slice() != b"info")
                    || (self.final_file.parent_suffix.is_empty()
                        && self.final_file.expected.name != b"exclude")
                    || (!self.final_file.parent_suffix.is_empty()
                        && (self.final_file.parent != *common_dir
                            || self.final_file.expected.name != b"info"
                            || self.final_file.expected.entry.is_some()))
                    || !self.objects.is_empty()
                {
                    return Err("invalid Git local exclude target");
                }
            }
        }
        validate_precondition(&self.final_file.expected)?;

        let mut total = self.final_file.bytes.len();
        for precondition in &self.preconditions {
            validate_precondition(precondition)?;
        }
        for precondition in &self.worktree_preconditions {
            if precondition.name.is_empty()
                || precondition.name.len() > 255
                || precondition.name.contains(&b'/')
                || precondition.name.contains(&b'\\')
                || precondition.name.contains(&0)
                || precondition.name == b"."
                || precondition.name == b".."
                || precondition.entry.is_some() != precondition.revision.is_some()
                || precondition
                    .revision
                    .as_ref()
                    .is_some_and(|revision| revision.is_empty() || revision.len() > 256)
            {
                return Err("invalid Git worktree precondition");
            }
        }
        let mut seen = std::collections::HashSet::with_capacity(self.objects.len());
        for object in &self.objects {
            let oid = object.object_id.as_bytes();
            if !matches!(oid.len(), 40 | 64)
                || !oid.iter().all(u8::is_ascii_hexdigit)
                || object
                    .object_id
                    .bytes()
                    .any(|byte| byte.is_ascii_uppercase())
                || object.bytes.is_empty()
                || object.bytes.len() > MAX_GIT_OBJECT_BYTES
                || !seen.insert(object.object_id.as_str())
            {
                return Err("invalid Git loose object");
            }
            total = total
                .checked_add(object.bytes.len())
                .ok_or("Git publication resource limit")?;
            if total > MAX_GIT_PUBLICATION_BYTES {
                return Err("Git publication resource limit");
            }
        }
        Ok(())
    }
}

impl GitPullPublication {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.metadata.len() < 2
            || self.metadata.len() > 3
            || self.files.len() > MAX_GIT_PULL_NODES
        {
            return Err("invalid Git pull publication size");
        }
        let first = &self.metadata[0];
        if first.final_file.target != GitFinalTarget::Index
            || self.metadata.last().is_none_or(|publication| {
                !matches!(
                    publication.final_file.target,
                    GitFinalTarget::BranchHead { .. } | GitFinalTarget::DetachedHead
                )
            })
        {
            return Err("invalid Git pull publication order");
        }
        if self.metadata.len() == 3
            && !matches!(
                self.metadata[1].final_file.target,
                GitFinalTarget::RemoteTrackingHead { .. }
            )
        {
            return Err("invalid Git pull tracking ref");
        }
        let mut total = 0usize;
        for (index, publication) in self.metadata.iter().enumerate() {
            if publication.git_dir != first.git_dir
                || publication.common_dir != first.common_dir
                || !publication.worktree_preconditions.is_empty()
                || (index != 0 && !publication.objects.is_empty())
            {
                return Err("inconsistent Git pull metadata");
            }
            publication.validate()?;
            if index != 0 && publication.preconditions != first.preconditions {
                return Err("inconsistent Git pull preconditions");
            }
            total = total
                .checked_add(publication.final_file.bytes.len())
                .ok_or("Git pull publication resource limit")?;
            if index == 0 {
                for object in &publication.objects {
                    total = total
                        .checked_add(object.bytes.len())
                        .ok_or("Git pull publication resource limit")?;
                }
            }
            if total > MAX_GIT_PULL_BYTES {
                return Err("Git pull publication resource limit");
            }
        }
        let mut seen = std::collections::HashSet::with_capacity(self.files.len());
        for file in &self.files {
            if file.path.is_empty()
                || file.path.len() > 256
                || file.path.iter().any(|part| !valid_component(part))
                || file
                    .path
                    .iter()
                    .any(|part| part.eq_ignore_ascii_case(b".git"))
                || file.parent_suffix.len() > 64
                || file.parent_suffix.iter().any(|part| !valid_component(part))
                || !valid_component(&file.name)
                || file.expected.parent != file.parent
                || !valid_component(&file.expected.name)
                || file.expected.entry.is_some() != file.expected.revision.is_some()
                || file.expected.entry.is_some() != file.expected.kind.is_some()
                || !seen.insert((&file.path, file.kind))
                || file
                    .contents
                    .as_ref()
                    .is_some_and(|contents| contents.len() > MAX_GIT_PULL_FILE_BYTES)
                || (file.kind == GitPullNodeKind::Symlink
                    && file.contents.as_ref().is_some_and(|contents| {
                        contents.is_empty()
                            || contents.len() > MAX_GIT_PULL_LINK_BYTES
                            || contents.contains(&0)
                    }))
                || (file.kind == GitPullNodeKind::Directory
                    && (file.contents.is_some() || file.executable))
                || (file.kind == GitPullNodeKind::Symlink && file.executable)
            {
                return Err("invalid Git pull worktree entry");
            }
            let containing_len = file.path.len() - 1;
            if file.parent_suffix.len() > containing_len
                || file.path[containing_len - file.parent_suffix.len()..containing_len]
                    != file.parent_suffix
                || file.path.last() != Some(&file.name)
            {
                return Err("inconsistent Git pull worktree path");
            }
            if file.parent_suffix.is_empty() {
                if file.expected.name != file.name {
                    return Err("invalid Git pull target precondition");
                }
            } else if file.expected.name != file.parent_suffix[0]
                || file
                    .expected
                    .kind
                    .is_some_and(|kind| kind == GitPullNodeKind::Directory)
            {
                return Err("invalid Git pull missing-parent precondition");
            }
            if file
                .expected
                .revision
                .as_ref()
                .is_some_and(|revision| revision.is_empty() || revision.len() > 256)
            {
                return Err("invalid Git pull worktree revision");
            }
            total = total
                .checked_add(file.contents.as_ref().map_or(0, Vec::len))
                .ok_or("Git pull publication resource limit")?;
            if total > MAX_GIT_PULL_BYTES {
                return Err("Git pull publication resource limit");
            }
        }
        let changed_paths: std::collections::HashSet<_> = self
            .files
            .iter()
            .filter(|file| file.kind != GitPullNodeKind::Directory)
            .map(|file| &file.path)
            .collect();
        if changed_paths.len() > MAX_GIT_PULL_FILES {
            return Err("Git pull file count limit");
        }
        for file in &self.files {
            match (file.kind, file.contents.is_some(), file.expected.kind) {
                (GitPullNodeKind::Directory, false, Some(GitPullNodeKind::Directory)) => {}
                (GitPullNodeKind::Directory, _, _) => {
                    return Err("invalid Git pull directory operation");
                }
                (kind, false, Some(expected)) if kind == expected => {}
                (_, false, _) => return Err("invalid Git pull removal precondition"),
                (_kind, true, Some(GitPullNodeKind::Directory)) => {
                    let directory_removed = self.files.iter().any(|remove| {
                        remove.path == file.path
                            && remove.kind == GitPullNodeKind::Directory
                            && remove.contents.is_none()
                            && remove.expected == file.expected
                    });
                    if !directory_removed {
                        return Err("Git pull install would replace a directory");
                    }
                }
                (_, true, _) => {}
            }
            if !file.parent_suffix.is_empty()
                && let Some(expected_kind) = file.expected.kind
            {
                let prefix_len = file.path.len() - file.parent_suffix.len() - 1;
                let blocker_path = [&file.path[..prefix_len], &file.parent_suffix[..1]].concat();
                let blocker_removed = self.files.iter().any(|remove| {
                    remove.path == blocker_path
                        && remove.kind == expected_kind
                        && remove.contents.is_none()
                        && remove.expected.entry == file.expected.entry
                        && remove.expected.revision == file.expected.revision
                });
                if !blocker_removed {
                    return Err("Git pull missing parent is not removed");
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn valid_component(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value != b"."
        && value != b".."
        && !value.contains(&b'/')
        && !value.contains(&b'\\')
        && !value.contains(&0)
        && !value.contains(&b':')
}

pub(crate) fn validate_branch_reference(reference: &[Vec<u8>]) -> Result<(), &'static str> {
    if reference.len() < 3
        || reference.len() > MAX_GIT_REF_COMPONENTS
        || reference[0] != b"refs"
        || reference[1] != b"heads"
        || reference.iter().map(Vec::len).sum::<usize>() + reference.len() - 1
            > MAX_GIT_REF_PATH_BYTES
        || reference.iter().any(|part| !valid_component(part))
        || reference.iter().any(|part| {
            part.starts_with(b".")
                || part.ends_with(b".")
                || part.ends_with(b".lock")
                || part.windows(2).any(|pair| pair == b".." || pair == b"@{")
                || part.iter().any(|byte| {
                    *byte <= 0x20
                        || *byte == 0x7f
                        || matches!(*byte, b'~' | b'^' | b'?' | b'*' | b'[')
                })
        })
        || (reference.len() == 3 && reference[2] == b"@")
    {
        return Err("invalid branch reference");
    }
    // Git's lock file appends `.lock` to the leaf. Keep that name within the
    // filesystem's component limit before reserving it.
    if reference.last().is_some_and(|leaf| leaf.len() > 250) {
        return Err("branch reference component too long");
    }
    Ok(())
}

pub(crate) fn validate_remote_tracking_reference(
    reference: &[Vec<u8>],
) -> Result<(), &'static str> {
    if reference.len() < 4
        || reference.len() > MAX_GIT_REF_COMPONENTS
        || reference[0] != b"refs"
        || reference[1] != b"remotes"
        || reference.iter().map(Vec::len).sum::<usize>() + reference.len() - 1
            > MAX_GIT_REF_PATH_BYTES
        || reference.iter().any(|part| !valid_component(part))
        || reference.iter().any(|part| {
            part.starts_with(b".")
                || part.ends_with(b".")
                || part.ends_with(b".lock")
                || part.windows(2).any(|pair| pair == b".." || pair == b"@{")
                || part.iter().any(|byte| {
                    *byte <= 0x20
                        || *byte == 0x7f
                        || matches!(*byte, b'~' | b'^' | b'?' | b'*' | b'[')
                })
        })
        || reference.last().is_some_and(|leaf| leaf.len() > 250)
    {
        return Err("invalid remote-tracking reference");
    }
    Ok(())
}

fn validate_precondition(value: &GitFilePrecondition) -> Result<(), &'static str> {
    if value.name.is_empty()
        || value.name.len() > 255
        || value.name.contains(&b'/')
        || value.name.contains(&b'\\')
        || value.name.contains(&0)
        || value.name == b"."
        || value.name == b".."
        || value.entry.is_some() != value.revision.is_some()
        || value
            .revision
            .as_ref()
            .is_some_and(|revision| revision.is_empty() || revision.len() > 256)
    {
        return Err("invalid Git file precondition");
    }
    Ok(())
}
