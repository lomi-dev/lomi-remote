//! Root-confined Explorer engine for the shared workspace host.
//!
//! `FileRoot` never follows a symbolic link, resolves every operation relative
//! to a pinned root descriptor, validates the recorded file identity of every
//! ancestor on every call, refuses regular files with several hard links, and
//! never writes content. Entry identifiers and revision tokens are opaque to
//! clients; a changed identity or revision is reported as [`Error::Changed`].
//! `LocalNativeFile` is a separate owner-local editor publication surface and
//! must not be exposed through remote file RPCs.
//!
//! The Unix engine is descriptor-relative (`openat`, `O_NOFOLLOW`). The Windows
//! engine is handle-relative: every component is opened with `NtCreateFile`
//! relative to the parent directory handle and never through a reparse point;
//! device names, alternate data streams and 8.3 aliases of `.git` are refused.
//! Other platforms have no engine and refuse to open any root with
//! [`Error::Unsupported`], so no host can claim the capability by accident.

mod common;
/// Closed owner-local Explorer operations. Never expose this surface through
/// remote file RPCs or MCP's narrower project-file mutation contract.
pub mod desktop;
#[doc(hidden)]
pub mod desktop_git;
mod git;
#[doc(hidden)]
pub mod owner_git_metadata;
mod types;
#[doc(hidden)]
pub use desktop_git::{
    GitDesktopFilePublication, GitDesktopFileTarget, GitIgnorePublication, GitIgnoreTarget,
    OwnerGitDesktopFilePublication, OwnerGitIgnorePublication, OwnerGitIgnoreTarget,
    publish_git_desktop_file, publish_git_desktop_file_owner_local, publish_git_ignore,
    publish_git_ignore_owner_local,
};
#[doc(hidden)]
pub use git::{
    GitFilePrecondition, GitFinalFile, GitFinalTarget, GitObjectFile, GitPublication,
    GitPublishOutcome, GitPullFile, GitPullNodeKind, GitPullPrecondition, GitPullPublication,
    GitWorktreePrecondition,
};
pub use lomi_fs_policy::is_private_staging_name;
#[doc(hidden)]
pub use owner_git_metadata::{
    OwnerGitMetadataChunk, OwnerGitMetadataCondition, OwnerGitMetadataEntry, OwnerGitMetadataPath,
    OwnerGitMetadataRole, OwnerGitMetadataRoot, OwnerGitMetadataVersion,
};
pub use types::*;

#[cfg(unix)]
mod unix;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use unix::DirectoryWatch;
#[cfg(unix)]
pub use unix::{FileRoot, LocalNativeFile};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
#[doc(hidden)]
pub use windows::{
    BrokerTemp, SecurityBrokerClient, SecurityBrokerError, SecurityBrokerResult, SourceSnapshot,
    TempToken, run_security_broker,
};
#[cfg(windows)]
pub use windows::{DirectoryWatch, FileRoot, LocalNativeFile};

#[cfg(not(any(unix, windows)))]
mod unsupported;
#[cfg(not(any(unix, windows)))]
pub use unsupported::{FileRoot, LocalNativeFile};
