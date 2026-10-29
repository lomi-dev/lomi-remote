//! Remote Explorer reads: `files.list`, `files.stat`, `files.read`,
//! `files.searchNames`.
//!
//! The root is resolved on the host from the workspace's own project record, never
//! from client input. The workspace id doubles as the root entry id, so a client
//! needs no extra lookup. All path confinement lives in `lomi-files`; this module
//! only maps protocol DTOs to the engine and engine errors to safe wire errors.
//! The caller has already consumed the queued request and dropped every owner
//! turn; the response is then sent through the ordinary gated response path.
use lomi_files::{self as engine, EntryRef, FileRoot};
use lomi_remote_protocol::{
    DecimalU64, Effect, EntryId, ErrorCode, ErrorDetails, EventCursor, FileRevision, RemoteError,
    WorkspaceEpoch, WorkspaceId,
    rpc::{
        BoundedList, DisplayText, EncodedPathId, EntryKind, FileEncoding, FileMetadata,
        FilesListResult, FilesReadResult, LineEndings, RpcCall, RpcResult,
    },
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

struct Slot {
    epoch: WorkspaceEpoch,
    root: PathBuf,
    files: Arc<FileRoot>,
}

/// One pinned `FileRoot` per workspace. Re-opened when the workspace epoch or
/// the project root changes; entry ids of the old root then stop resolving.
#[derive(Default)]
pub(super) struct Roots {
    map: Mutex<BTreeMap<WorkspaceId, Slot>>,
    /// Host data (profile directory, SQLite, credentials). A root that contains
    /// or lies inside any of these is refused by identity.
    host_protected: Mutex<Vec<PathBuf>>,
}

impl Roots {
    pub(super) fn protect_host(&self, path: &Path) {
        if let Ok(mut protected) = self.host_protected.lock() {
            protected.push(path.to_owned());
        }
    }

    pub(super) fn get(
        &self,
        workspace: WorkspaceId,
        epoch: WorkspaceEpoch,
        local_root: &Path,
    ) -> Result<Arc<FileRoot>, RemoteError> {
        self.get_engine(workspace, epoch, local_root)
            .map_err(map_error)
    }

    pub(super) fn get_engine(
        &self,
        workspace: WorkspaceId,
        epoch: WorkspaceEpoch,
        local_root: &Path,
    ) -> Result<Arc<FileRoot>, engine::Error> {
        let mut map = self.map.lock().map_err(|_| engine::Error::Limit)?;
        if let Some(slot) = map.get(&workspace)
            && slot.epoch == epoch
            && slot.root == local_root
        {
            return Ok(slot.files.clone());
        }
        let root_entry = EntryRef::from_bytes(workspace.to_bytes());
        let protected = self
            .host_protected
            .lock()
            .map_err(|_| engine::Error::Limit)?
            .clone();
        let protected: Vec<&Path> = protected.iter().map(PathBuf::as_path).collect();
        let files = Arc::new(FileRoot::open_with_root_entry(
            local_root, &protected, root_entry,
        )?);
        map.insert(
            workspace,
            Slot {
                epoch,
                root: local_root.to_owned(),
                files: files.clone(),
            },
        );
        Ok(files)
    }
}

fn fault(code: ErrorCode) -> RemoteError {
    RemoteError::new(code, false, Effect::None, ErrorDetails::empty(), None)
        .expect("static safe error")
}

pub(super) fn map_error(error: engine::Error) -> RemoteError {
    fault(match error {
        engine::Error::NotFound => ErrorCode::ResourceNotFound,
        engine::Error::Changed | engine::Error::Exists => ErrorCode::FileChanged,
        engine::Error::Protected => ErrorCode::ProtectedPath,
        engine::Error::NotEmpty => ErrorCode::DirectoryNotEmpty,
        engine::Error::Invalid => ErrorCode::InvalidArgument,
        engine::Error::Unsupported => ErrorCode::UnsupportedCapability,
        engine::Error::Limit => ErrorCode::HostBusy,
        engine::Error::Io(std::io::ErrorKind::PermissionDenied) => ErrorCode::ProtectedPath,
        engine::Error::Io(_) => ErrorCode::ResourceNotFound,
    })
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64url; the wire tokens only allow `[A-Za-z0-9_-]`.
fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..=chunk.len() {
            out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

fn b64_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 4 == 1 {
        return None; // a single trailing sextet cannot encode a byte
    }
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for byte in text.bytes() {
        let value = B64.iter().position(|b| *b == byte)? as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // Unused trailing bits must be zero (canonical encoding).
    (acc == 0).then_some(out)
}

fn cursor(token: &Option<EventCursor>) -> Result<Option<Vec<u8>>, RemoteError> {
    token
        .as_ref()
        .map(|t| b64_decode(t.as_str()).ok_or_else(|| fault(ErrorCode::InvalidArgument)))
        .transpose()
}

fn cursor_token(bytes: &Option<Vec<u8>>) -> Result<Option<EventCursor>, RemoteError> {
    bytes
        .as_ref()
        .map(|b| EventCursor::try_from(b64_encode(b)).map_err(|_| fault(ErrorCode::HostBusy)))
        .transpose()
}

fn display(name: &[u8], root: bool) -> String {
    if root {
        return "workspace".to_owned();
    }
    let text: String = String::from_utf8_lossy(name)
        .chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect();
    if text.is_empty() {
        "(unnamed)".to_owned()
    } else {
        text
    }
}

fn entry(id: &EntryId) -> EntryRef {
    EntryRef::from_bytes(id.to_bytes())
}

fn metadata(m: &engine::Meta, root: EntryRef) -> Result<FileMetadata, RemoteError> {
    let is_root = m.entry == root;
    let internal = |_| fault(ErrorCode::HostBusy);
    Ok(FileMetadata {
        entry_id: EntryId::from_bytes(m.entry.to_bytes()).map_err(internal)?,
        path_id: EncodedPathId::try_from(b64_encode(if is_root { b"." } else { &m.name }))
            .map_err(internal)?,
        display_name: DisplayText::try_from(display(&m.name, is_root)).map_err(internal)?,
        kind: match m.kind {
            engine::Kind::File => EntryKind::File,
            engine::Kind::Directory => EntryKind::Directory,
            engine::Kind::Symlink => EntryKind::Symlink,
            engine::Kind::Other => EntryKind::Other,
        },
        file_revision: FileRevision::try_from(m.revision.clone()).map_err(internal)?,
        size: DecimalU64(m.size),
    })
}

fn page(page: engine::Page, root: EntryRef) -> Result<FilesListResult, RemoteError> {
    Ok(FilesListResult {
        entries: BoundedList(
            page.entries
                .iter()
                .map(|m| metadata(m, root))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        next_cursor: cursor_token(&page.next)?,
        truncated: page.truncated,
    })
}

fn revision(token: &Option<FileRevision>) -> Option<&str> {
    token.as_ref().map(FileRevision::as_str)
}

/// Runs one read-only Explorer call against the pinned root.
pub(super) fn execute_read(files: &FileRoot, call: &RpcCall) -> Result<RpcResult, RemoteError> {
    let root = files.root_entry();
    match call {
        RpcCall::FilesList(p) => files
            .list(
                entry(&p.parent_entry_id),
                cursor(&p.cursor)?.as_deref(),
                u32::from(p.limit) as usize,
            )
            .map_err(map_error)
            .and_then(|found| page(found, root))
            .map(RpcResult::FilesList),
        RpcCall::FilesSearchNames(p) => files
            .search_names(
                entry(&p.parent_entry_id),
                p.query.as_str(),
                cursor(&p.cursor)?.as_deref(),
                u32::from(p.limit) as usize,
            )
            .map_err(map_error)
            .and_then(|found| page(found, root))
            .map(RpcResult::FilesSearchNames),
        RpcCall::FilesStat(p) => files
            .stat(entry(&p.entry_id), revision(&p.file_revision))
            .map_err(map_error)
            .and_then(|m| metadata(&m, root))
            .map(RpcResult::FilesStat),
        RpcCall::FilesRead(p) => {
            let read = files
                .read(
                    entry(&p.entry_id),
                    revision(&p.file_revision),
                    p.offset.0,
                    u32::from(p.max_bytes) as usize,
                )
                .map_err(map_error)?;
            Ok(RpcResult::FilesRead(FilesReadResult {
                metadata: metadata(&read.meta, root)?,
                encoding: match read.encoding {
                    engine::Encoding::Utf8 => FileEncoding::Utf8,
                    engine::Encoding::Utf16Le => FileEncoding::Utf16Le,
                    engine::Encoding::Utf16Be => FileEncoding::Utf16Be,
                    engine::Encoding::Binary => FileEncoding::Binary,
                    engine::Encoding::Unknown => FileEncoding::Unknown,
                },
                line_endings: match read.line_endings {
                    engine::LineEndings::Lf => LineEndings::Lf,
                    engine::LineEndings::CrLf => LineEndings::CrLf,
                    engine::LineEndings::Cr => LineEndings::Cr,
                    engine::LineEndings::Mixed => LineEndings::Mixed,
                    engine::LineEndings::None => LineEndings::None,
                },
                offset: DecimalU64(read.offset),
                bytes: BoundedList(read.bytes),
                truncated: read.truncated,
            }))
        }
        _ => Err(fault(ErrorCode::UnsupportedCapability)),
    }
}
