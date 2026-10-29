/// Opaque, host-minted identifier of one entry in one [`crate::FileRoot`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct EntryRef([u8; 16]);
impl EntryRef {
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    pub fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Meta {
    pub entry: EntryRef,
    /// Raw OS name bytes (not necessarily UTF-8 on Unix).
    pub name: Vec<u8>,
    pub kind: Kind,
    pub size: u64,
    /// Opaque `[A-Za-z0-9]` token that changes whenever the entry changes.
    pub revision: String,
    pub nlink: u64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Page {
    pub entries: Vec<Meta>,
    /// Opaque cursor for the next page; `None` when the listing is complete.
    pub next: Option<Vec<u8>>,
    pub truncated: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Encoding {
    Utf8,
    Utf16Le,
    Utf16Be,
    Binary,
    Unknown,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LineEndings {
    Lf,
    CrLf,
    Cr,
    Mixed,
    None,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReadResult {
    pub meta: Meta,
    pub encoding: Encoding,
    pub line_endings: LineEndings,
    pub offset: u64,
    /// Empty for binary content: only metadata is disclosed.
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

/// A bounded, race-resistant raw chunk for constructing a private Git input
/// snapshot. This is a host-internal primitive, never a remote DTO.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SnapshotChunk {
    pub meta: Meta,
    pub offset: u64,
    pub encoding: Encoding,
    pub bytes: Vec<u8>,
    pub truncated: bool,
    /// Whether the opened file has any execute bit set. Windows filesystems do
    /// not expose Git's executable bit and report `false`.
    pub executable: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// Entry or directory no longer exists / is unknown.
    NotFound,
    /// Identity or revision precondition failed (`FILE_CHANGED`).
    Changed,
    /// Repository metadata, host data, a multi-link file or the root itself.
    Protected,
    NotEmpty,
    Exists,
    Invalid,
    Unsupported,
    /// A bounded resource (directory size, registry, search budget) was hit.
    Limit,
    Io(std::io::ErrorKind),
}
pub type Result<T> = std::result::Result<T, Error>;

/// A bounded, owner-local target for editor saves. This surface is separate
/// from [`FileRoot`] and must never be exposed through remote file RPCs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalNativeFileError {
    NotFound,
    Changed,
    Protected,
    Exists,
    Invalid,
    Unsupported,
    Limit,
    Io,
}

/// Checkpoint in the local native editor file publication lifecycle.
///
/// `Progress` may run repeatedly while preparing or copying data.
/// `BeforeEffect` is the fresh authorization checkpoint immediately before
/// final filesystem revalidation. `Validation` and `Publication` are local
/// checkpoints used after authorization; callbacks at those phases must not
/// perform remote authorization or other blocking IPC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalNativeFileCheckPhase {
    Progress,
    /// May obtain fresh authorization from the owner. All final filesystem
    /// checks run after this callback returns.
    BeforeEffect,
    /// Local-only caller validation immediately after authorization, before
    /// the publisher rechecks source, temporary file and destination names.
    Validation,
    /// Fast local cancellation/deadline/approval-age check immediately before
    /// publication. Must not perform IPC, filesystem scans or other blocking
    /// work that would invalidate the publisher's final identity checks.
    Publication,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LocalNativeFileReadError<E> {
    File(LocalNativeFileError),
    Check(E),
}

#[derive(Debug, PartialEq, Eq)]
pub enum LocalNativeFilePublishError<E> {
    Before(LocalNativeFileReadError<E>),
    /// The final namespace change succeeded, but durable completion failed.
    Uncertain,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalNativeFileSnapshot {
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub read_only: bool,
}

pub const MAX_DIR_ENTRIES: usize = 100_000;
pub const MAX_REGISTERED_ENTRIES: usize = 200_000;
pub const MAX_PAGE: usize = 200;
pub const MAX_READ: usize = 1_048_576;
pub const SEARCH_VISIT_LIMIT: usize = 50_000;
pub const SEARCH_MAX_DEPTH: usize = 32;
