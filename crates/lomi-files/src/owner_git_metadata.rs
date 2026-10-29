//! Owner-only access to Git metadata roots outside a selected workspace.
//!
//! This capability is intentionally separate from `FileRoot`'s public file
//! surface. It exposes bounded metadata reads and typed conditions, but never
//! exposes its pinned `FileRoot` or an `EntryRef` that could be confused with
//! one from another root.

use crate::{EntryRef, Error, FileRoot, GitPullPrecondition, Kind, Meta, SnapshotChunk};
use std::path::{Path, PathBuf};

const MAX_OWNER_METADATA_PATH_DEPTH: usize = 128;
const MAX_OWNER_METADATA_COMPONENT_BYTES: usize = 1024;
const MAX_OWNER_METADATA_PAGE: usize = 200;

/// The physical Git metadata tree whose paths a condition names.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerGitMetadataRole {
    GitDir,
    CommonDir,
}

/// A root-relative Git metadata path. Components are raw Unix name bytes and
/// UTF-8 Windows names, matching `FileRoot`'s platform path contract.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OwnerGitMetadataPath(Vec<Vec<u8>>);

impl OwnerGitMetadataPath {
    pub fn root() -> Self {
        Self(Vec::new())
    }

    pub fn from_components(components: Vec<Vec<u8>>) -> crate::Result<Self> {
        validate_components(&components)?;
        Ok(Self(components))
    }

    pub fn components(&self) -> &[Vec<u8>] {
        &self.0
    }

    pub fn joined(&self, name: &[u8]) -> crate::Result<Self> {
        let mut components = self.0.clone();
        components.push(name.to_vec());
        Self::from_components(components)
    }
}

/// A metadata identity and revision bound to one owner metadata root.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerGitMetadataVersion {
    pub kind: Kind,
    pub revision: String,
    pub size: u64,
    pub nlink: u64,
}

/// A closed compare-and-swap condition. `expected: None` means the named leaf
/// must remain absent. The role is part of the condition so a path cannot be
/// checked against the other root in a linked-worktree pair.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerGitMetadataCondition {
    pub role: OwnerGitMetadataRole,
    pub path: OwnerGitMetadataPath,
    pub expected: Option<OwnerGitMetadataVersion>,
}

/// One bounded child returned by a metadata-root directory listing.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerGitMetadataEntry {
    pub path: OwnerGitMetadataPath,
    pub kind: Kind,
    pub size: u64,
    pub revision: String,
    pub nlink: u64,
}

/// A binary-preserving file chunk with no root-local `EntryRef` in its shape.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerGitMetadataChunk {
    pub kind: Kind,
    pub revision: String,
    pub size: u64,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub truncated: bool,
    pub executable: bool,
}

/// A pinned Git metadata root admitted only for owner-local Desktop Git.
///
/// The contained `FileRoot` is private and this type deliberately has no
/// `Deref` or conversion back to `FileRoot`. Normal Explorer and remote Git
/// code continue to use the workspace-rooted capability.
#[doc(hidden)]
pub struct OwnerGitMetadataRoot {
    files: FileRoot,
    role: OwnerGitMetadataRole,
    canonical_path: PathBuf,
    physical_identity: Vec<u8>,
}

impl OwnerGitMetadataRoot {
    /// Open the exact Git metadata directory without following any component.
    /// The root is rejected if it overlaps the workspace or a host-protected
    /// root by path or file identity.
    pub fn open(
        path: &Path,
        role: OwnerGitMetadataRole,
        workspace_root: &Path,
        host_protected_roots: &[&Path],
    ) -> crate::Result<Self> {
        let files = FileRoot::open_owner_git_metadata(path, workspace_root, host_protected_roots)?;
        let canonical_path = files.owner_git_metadata_path()?;
        let physical_identity = files.owner_git_metadata_identity()?;
        Ok(Self {
            files,
            role,
            canonical_path,
            physical_identity,
        })
    }

    /// Open a metadata root named by a no-follow `.git` marker beneath a
    /// workspace. The FileRoot verifies the marker, pointer target, and target
    /// directory identity before admitting a strict workspace descendant.
    #[doc(hidden)]
    pub fn open_from_workspace_git_marker(
        path: &Path,
        role: OwnerGitMetadataRole,
        workspace_files: &FileRoot,
        workspace_root: &Path,
        repository: EntryRef,
        repository_path: &Path,
        marker: &GitPullPrecondition,
        expected_entry: Option<EntryRef>,
        host_protected_roots: &[&Path],
    ) -> crate::Result<Self> {
        let files = workspace_files.open_owner_git_metadata_from_workspace_marker(
            path,
            workspace_root,
            host_protected_roots,
            repository,
            repository_path,
            marker,
            expected_entry,
        )?;
        Self::from_file_root(files, role)
    }

    /// Open a common metadata root named by a pinned Git `commondir` file.
    /// The condition is checked before and after reading the pointer, and the
    /// resolved target path is opened without following any ancestor link.
    #[doc(hidden)]
    pub fn open_from_commondir_pointer(
        path: &Path,
        workspace_root: &Path,
        host_protected_roots: &[&Path],
        git_dir: &OwnerGitMetadataRoot,
        condition: &OwnerGitMetadataCondition,
    ) -> crate::Result<Self> {
        if git_dir.role != OwnerGitMetadataRole::GitDir
            || condition.role != OwnerGitMetadataRole::GitDir
            || condition.path.components() != [b"commondir".to_vec()]
        {
            return Err(Error::Invalid);
        }
        let expected = condition.expected.as_ref().ok_or(Error::Invalid)?;
        if expected.kind != Kind::File
            || expected.nlink != 1
            || expected.size == 0
            || expected.size > 4096
        {
            return Err(Error::Protected);
        }
        git_dir.check(condition)?;
        let pointer_path = OwnerGitMetadataPath::from_components(vec![b"commondir".to_vec()])?;
        let pointer = git_dir.read_chunk(&pointer_path, &expected.revision, 0, 4096)?;
        if pointer.kind != Kind::File || pointer.size != expected.size || pointer.truncated {
            return Err(Error::Changed);
        }
        pointer_resolves_to(&pointer.bytes, "", git_dir.canonical_path(), path)?;
        let files = FileRoot::open_owner_git_metadata_from_verified_pointer(
            path,
            workspace_root,
            host_protected_roots,
        )?;
        git_dir.check(condition)?;
        Self::from_file_root(files, OwnerGitMetadataRole::CommonDir)
    }

    fn from_file_root(files: FileRoot, role: OwnerGitMetadataRole) -> crate::Result<Self> {
        let canonical_path = files.owner_git_metadata_path()?;
        let physical_identity = files.owner_git_metadata_identity()?;
        Ok(Self {
            files,
            role,
            canonical_path,
            physical_identity,
        })
    }

    pub fn role(&self) -> OwnerGitMetadataRole {
        self.role
    }

    /// Opaque stable physical identity used to share the existing common-dir
    /// repository lease across workspace aliases and metadata-root instances.
    pub fn physical_identity(&self) -> &[u8] {
        &self.physical_identity
    }

    /// Canonical host path retained for owner-local identity bookkeeping.
    /// This value is never included in an Explorer/RPC response.
    pub fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    /// Recheck the named root and every pinned ancestor against the original
    /// no-follow path walk.
    pub fn revalidate_binding(&self) -> crate::Result<()> {
        self.files.check_owner_git_metadata_binding()
    }

    /// List one directory in the metadata tree, with the same page ceiling as
    /// `FileRoot` and paths relative to this typed root.
    pub fn list(&self, path: &OwnerGitMetadataPath) -> crate::Result<Vec<OwnerGitMetadataEntry>> {
        self.revalidate_binding()?;
        let directory = self.resolve(path, true)?.ok_or(Error::NotFound)?;
        let mut entries = Vec::new();
        let mut cursor = None;
        loop {
            let page = self
                .files
                .list(directory, cursor.as_deref(), MAX_OWNER_METADATA_PAGE)?;
            for meta in page.entries {
                entries.push(OwnerGitMetadataEntry {
                    path: path.joined(&meta.name)?,
                    kind: meta.kind,
                    size: meta.size,
                    revision: meta.revision,
                    nlink: meta.nlink,
                });
            }
            match page.next {
                Some(next) if page.truncated => cursor = Some(next),
                Some(_) | None if page.truncated => return Err(Error::Changed),
                None => break,
                Some(_) => return Err(Error::Changed),
            }
        }
        self.revalidate_binding()?;
        Ok(entries)
    }

    /// Read one raw file chunk through the pinned root, preserving binary
    /// bytes and the native Git executable bit where the platform provides it.
    pub fn read_chunk(
        &self,
        path: &OwnerGitMetadataPath,
        expected_revision: &str,
        offset: u64,
        max_bytes: usize,
    ) -> crate::Result<OwnerGitMetadataChunk> {
        self.revalidate_binding()?;
        let entry = self.resolve(path, false)?.ok_or(Error::NotFound)?;
        let chunk: SnapshotChunk =
            self.files
                .read_snapshot_chunk(entry, expected_revision, offset, max_bytes)?;
        self.revalidate_binding()?;
        Ok(OwnerGitMetadataChunk {
            kind: chunk.meta.kind,
            revision: chunk.meta.revision,
            size: chunk.meta.size,
            offset: chunk.offset,
            bytes: chunk.bytes,
            truncated: chunk.truncated,
            executable: chunk.executable,
        })
    }

    /// Read a symlink target without following it. Platform support remains
    /// explicit; unsupported platforms return `Error::Unsupported`.
    pub fn readlink(
        &self,
        path: &OwnerGitMetadataPath,
        expected_revision: &str,
        max_bytes: usize,
    ) -> crate::Result<Vec<u8>> {
        self.revalidate_binding()?;
        let entry = self.resolve(path, false)?.ok_or(Error::NotFound)?;
        let bytes = self
            .files
            .readlink_snapshot(entry, expected_revision, max_bytes)?;
        self.revalidate_binding()?;
        Ok(bytes)
    }

    /// Resolve and compare one root-relative condition. Used by paired
    /// publishers only after their owner authorization phase.
    pub fn check(&self, condition: &OwnerGitMetadataCondition) -> crate::Result<()> {
        if condition.role != self.role {
            return Err(Error::Protected);
        }
        self.revalidate_binding()?;
        let actual = self.resolve(&condition.path, false)?;
        match (&condition.expected, actual) {
            (None, None) => Ok(()),
            (Some(expected), Some(entry)) => {
                let actual = self.files.stat(entry, Some(&expected.revision))?;
                if metadata_version(&actual) == *expected {
                    Ok(())
                } else {
                    Err(Error::Changed)
                }
            }
            _ => Err(Error::Changed),
        }
    }

    pub(crate) fn file_root(&self) -> &FileRoot {
        &self.files
    }

    /// Resolve a typed leaf condition to a root-local precondition for the
    /// platform publication core. The returned `EntryRef` stays crate-local.
    pub(crate) fn resolve_condition(
        &self,
        condition: &OwnerGitMetadataCondition,
    ) -> crate::Result<OwnerGitMetadataResolvedCondition> {
        if condition.role != self.role {
            return Err(Error::Protected);
        }
        self.revalidate_binding()?;
        let path = &condition.path.0;
        let (parent_path, name) = path.split_at(path.len().checked_sub(1).ok_or(Error::Invalid)?);
        let parent = self
            .resolve(&OwnerGitMetadataPath(parent_path.to_vec()), true)?
            .ok_or(Error::NotFound)?;
        let actual = self.resolve(&condition.path, false)?;
        match (&condition.expected, actual) {
            (None, None) => Ok(OwnerGitMetadataResolvedCondition {
                parent,
                name: name[0].clone(),
                entry: None,
                revision: None,
            }),
            (Some(expected), Some(entry)) => {
                let actual = self.files.stat(entry, Some(&expected.revision))?;
                if metadata_version(&actual) != *expected {
                    return Err(Error::Changed);
                }
                Ok(OwnerGitMetadataResolvedCondition {
                    parent,
                    name: name[0].clone(),
                    entry: Some(entry),
                    revision: Some(expected.revision.clone()),
                })
            }
            _ => Err(Error::Changed),
        }
    }

    fn resolve(
        &self,
        path: &OwnerGitMetadataPath,
        directory: bool,
    ) -> crate::Result<Option<EntryRef>> {
        let mut entry = self.files.root_entry();
        if path.0.is_empty() {
            return if directory {
                Ok(Some(entry))
            } else {
                Err(Error::Invalid)
            };
        }
        for (index, component) in path.0.iter().enumerate() {
            let mut cursor = None;
            let found = loop {
                let page = self
                    .files
                    .list(entry, cursor.as_deref(), MAX_OWNER_METADATA_PAGE)?;
                if let Some(meta) = page
                    .entries
                    .into_iter()
                    .find(|meta| &meta.name == component)
                {
                    break Some(meta);
                }
                if !page.truncated {
                    break None;
                }
                match page.next {
                    Some(next) => cursor = Some(next),
                    None => return Err(Error::Changed),
                }
            };
            let Some(meta) = found else {
                return Ok(None);
            };
            let last = index + 1 == path.0.len();
            if !last && meta.kind != Kind::Directory {
                return Ok(None);
            }
            if last && directory && meta.kind != Kind::Directory {
                return Ok(None);
            }
            entry = meta.entry;
        }
        Ok(Some(entry))
    }
}

/// Root-local resolved condition for platform publishers. It is deliberately
/// not exported from the crate.
#[derive(Clone, Debug)]
pub(crate) struct OwnerGitMetadataResolvedCondition {
    pub parent: EntryRef,
    pub name: Vec<u8>,
    pub entry: Option<EntryRef>,
    pub revision: Option<String>,
}

fn metadata_version(meta: &Meta) -> OwnerGitMetadataVersion {
    OwnerGitMetadataVersion {
        kind: meta.kind,
        revision: meta.revision.clone(),
        size: meta.size,
        nlink: meta.nlink,
    }
}

pub(crate) fn pointer_resolves_to(
    contents: &[u8],
    prefix: &str,
    base: &Path,
    expected: &Path,
) -> crate::Result<()> {
    let contents = std::str::from_utf8(contents).map_err(|_| Error::Protected)?;
    let mut text = contents.strip_suffix('\n').unwrap_or(contents);
    if let Some(without_cr) = text.strip_suffix('\r') {
        text = without_cr;
    }
    if text.contains(['\n', '\r', '\0']) {
        return Err(Error::Protected);
    }
    let target = text
        .strip_prefix(prefix)
        .filter(|target| !target.is_empty())
        .ok_or(Error::Protected)?;
    let target = Path::new(target);
    let resolved = if target.is_absolute() {
        target.to_path_buf()
    } else {
        base.join(target)
    };
    if normalize_absolute_path(&resolved)? != normalize_absolute_path(expected)? {
        return Err(Error::Changed);
    }
    Ok(())
}

fn normalize_absolute_path(path: &Path) -> crate::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(Error::Invalid);
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            std::path::Component::RootDir => normalized.push(component.as_os_str()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    return Err(Error::Invalid);
                }
            }
            std::path::Component::Normal(name) => normalized.push(name),
        }
    }
    Ok(normalized)
}

fn validate_components(components: &[Vec<u8>]) -> crate::Result<()> {
    if components.len() > MAX_OWNER_METADATA_PATH_DEPTH
        || components.iter().any(|component| {
            component.is_empty()
                || component.len() > MAX_OWNER_METADATA_COMPONENT_BYTES
                || component == b"."
                || component == b".."
                || component.contains(&b'/')
                || cfg!(windows) && component.contains(&b'\\')
                || component.contains(&0)
        })
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
