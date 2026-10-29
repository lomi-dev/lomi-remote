//! Placeholder engine for platforms without a handle-relative implementation.
//!
//! `open` always fails, so a host can never hold a `FileRoot` here and every
//! Explorer request is answered with `UNSUPPORTED_CAPABILITY`. The remaining
//! methods exist only so shared host code compiles unchanged.

use crate::{
    EntryRef, Error, GitPublication, GitPublishOutcome, GitPullPublication,
    LocalNativeFileCheckPhase, LocalNativeFileError, LocalNativeFilePublishError,
    LocalNativeFileReadError, LocalNativeFileSnapshot, Meta, Page, ReadResult, Result,
    SnapshotChunk,
};
use std::path::{Path, PathBuf};

pub struct LocalNativeFile {
    path: PathBuf,
}

impl LocalNativeFile {
    pub fn open(path: &Path) -> std::result::Result<Self, LocalNativeFileError> {
        let _ = path;
        Err(LocalNativeFileError::Unsupported)
    }

    pub fn open_no_follow(path: &Path) -> std::result::Result<Self, LocalNativeFileError> {
        let _ = path;
        Err(LocalNativeFileError::Unsupported)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn is_new(&self) -> bool {
        false
    }

    pub fn snapshot<E>(
        &self,
        _check: impl FnMut() -> std::result::Result<(), E>,
    ) -> std::result::Result<LocalNativeFileSnapshot, LocalNativeFileReadError<E>> {
        Err(LocalNativeFileReadError::File(
            LocalNativeFileError::Unsupported,
        ))
    }

    pub fn snapshot_with_phase<E>(
        &self,
        _check: &mut impl FnMut(LocalNativeFileCheckPhase) -> std::result::Result<(), E>,
    ) -> std::result::Result<LocalNativeFileSnapshot, LocalNativeFileReadError<E>> {
        Err(LocalNativeFileReadError::File(
            LocalNativeFileError::Unsupported,
        ))
    }

    pub fn replace<E>(
        &self,
        _expected_sha256: &str,
        _bytes: &[u8],
        _check: impl FnMut() -> std::result::Result<(), E>,
    ) -> std::result::Result<String, LocalNativeFilePublishError<E>> {
        Err(LocalNativeFilePublishError::Before(
            LocalNativeFileReadError::File(LocalNativeFileError::Unsupported),
        ))
    }

    pub fn replace_with_phase<E>(
        &self,
        _expected_sha256: &str,
        _bytes: &[u8],
        _check: &mut impl FnMut(LocalNativeFileCheckPhase) -> std::result::Result<(), E>,
    ) -> std::result::Result<String, LocalNativeFilePublishError<E>> {
        Err(LocalNativeFilePublishError::Before(
            LocalNativeFileReadError::File(LocalNativeFileError::Unsupported),
        ))
    }

    pub fn create<E>(
        &self,
        _bytes: &[u8],
        _check: impl FnMut() -> std::result::Result<(), E>,
    ) -> std::result::Result<String, LocalNativeFilePublishError<E>> {
        Err(LocalNativeFilePublishError::Before(
            LocalNativeFileReadError::File(LocalNativeFileError::Unsupported),
        ))
    }

    pub fn create_with_phase<E>(
        &self,
        _bytes: &[u8],
        _check: &mut impl FnMut(LocalNativeFileCheckPhase) -> std::result::Result<(), E>,
    ) -> std::result::Result<String, LocalNativeFilePublishError<E>> {
        Err(LocalNativeFilePublishError::Before(
            LocalNativeFileReadError::File(LocalNativeFileError::Unsupported),
        ))
    }
}

#[derive(Debug)]
pub struct FileRoot {
    root_entry: EntryRef,
}

impl FileRoot {
    pub fn open(_root: &Path, _host_protected: &[&Path]) -> Result<Self> {
        Err(Error::Unsupported)
    }
    pub fn open_with_root_entry(
        _root: &Path,
        _host_protected: &[&Path],
        _root_entry: EntryRef,
    ) -> Result<Self> {
        Err(Error::Unsupported)
    }
    pub fn root_entry(&self) -> EntryRef {
        self.root_entry
    }
    pub fn protect(&self, _path: &Path) -> Result<()> {
        Err(Error::Unsupported)
    }
    pub fn stat(&self, _entry: EntryRef, _expected_revision: Option<&str>) -> Result<Meta> {
        Err(Error::Unsupported)
    }
    pub fn pin_native_directory(
        &self,
        _entry: EntryRef,
        _absolute_path: &Path,
    ) -> Result<std::fs::File> {
        Err(Error::Unsupported)
    }
    #[doc(hidden)]
    pub fn native_entry_binding(
        &self,
        _absolute_root: &Path,
        _entry: EntryRef,
    ) -> Result<(PathBuf, crate::desktop::DesktopSourcePrecondition)> {
        Err(Error::Unsupported)
    }
    pub fn list(&self, _parent: EntryRef, _cursor: Option<&[u8]>, _limit: usize) -> Result<Page> {
        Err(Error::Unsupported)
    }
    pub fn read(
        &self,
        _entry: EntryRef,
        _expected_revision: Option<&str>,
        _offset: u64,
        _max_bytes: usize,
    ) -> Result<ReadResult> {
        Err(Error::Unsupported)
    }

    /// Raw Git snapshot reads are unsupported without a pinned platform file
    /// engine, just like ordinary Explorer reads.
    pub fn read_snapshot_chunk(
        &self,
        _entry: EntryRef,
        _expected_revision: &str,
        _offset: u64,
        _max_bytes: usize,
    ) -> Result<SnapshotChunk> {
        Err(Error::Unsupported)
    }
    #[doc(hidden)]
    pub fn publish_git(
        &self,
        _publication: &GitPublication,
        _continue_check: impl FnMut() -> bool,
    ) -> Result<GitPublishOutcome> {
        Err(Error::Unsupported)
    }
    #[doc(hidden)]
    pub fn publish_git_pull(
        &self,
        _publication: &GitPullPublication,
        _continue_check: impl FnMut() -> bool,
    ) -> Result<GitPublishOutcome> {
        Err(Error::Unsupported)
    }
    pub fn search_names(
        &self,
        _parent: EntryRef,
        _query: &str,
        _cursor: Option<&[u8]>,
        _limit: usize,
    ) -> Result<Page> {
        Err(Error::Unsupported)
    }
    pub fn create_file(
        &self,
        _parent: EntryRef,
        _parent_revision: &str,
        _name: &[u8],
    ) -> Result<Meta> {
        Err(Error::Unsupported)
    }
    pub fn create_file_guarded(
        &self,
        _parent: EntryRef,
        _parent_revision: &str,
        _name: &[u8],
        _check: impl FnMut(LocalNativeFileCheckPhase) -> bool,
    ) -> Result<Meta> {
        Err(Error::Unsupported)
    }
    pub fn mkdir(&self, _parent: EntryRef, _parent_revision: &str, _name: &[u8]) -> Result<Meta> {
        Err(Error::Unsupported)
    }
    pub fn mkdir_guarded(
        &self,
        _parent: EntryRef,
        _parent_revision: &str,
        _name: &[u8],
        _check: impl FnMut(LocalNativeFileCheckPhase) -> bool,
    ) -> Result<Meta> {
        Err(Error::Unsupported)
    }
    pub fn remove(
        &self,
        _entry: EntryRef,
        _revision: &str,
        _parent: EntryRef,
        _parent_revision: &str,
    ) -> Result<()> {
        Err(Error::Unsupported)
    }
    pub fn remove_guarded(
        &self,
        _entry: EntryRef,
        _revision: &str,
        _parent: EntryRef,
        _parent_revision: &str,
        _expected_source: Option<&crate::desktop::DesktopSourcePrecondition>,
        _check: impl FnMut(LocalNativeFileCheckPhase) -> bool,
    ) -> Result<()> {
        Err(Error::Unsupported)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn rename(
        &self,
        _entry: EntryRef,
        _revision: &str,
        _source_parent: EntryRef,
        _source_parent_revision: &str,
        _target_parent: EntryRef,
        _target_parent_revision: &str,
        _name: &[u8],
    ) -> Result<Meta> {
        Err(Error::Unsupported)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn rename_guarded(
        &self,
        _entry: EntryRef,
        _revision: &str,
        _source_parent: EntryRef,
        _source_parent_revision: &str,
        _target_parent: EntryRef,
        _target_parent_revision: &str,
        _name: &[u8],
        _expected_source: Option<&crate::desktop::DesktopSourcePrecondition>,
        _check: impl FnMut(LocalNativeFileCheckPhase) -> bool,
    ) -> Result<Meta> {
        Err(Error::Unsupported)
    }
}
