//! Synchronous owner-local editor saves for native effect execution.
//!
//! This crate has no GUI, process, IPC, or host-store dependencies. It accepts
//! file text separately from the typed request so native IPC can stage large
//! inputs without placing them in a bounded control frame.

pub use lomi_files::LocalNativeFileCheckPhase as NativeFileCheckPhase;
use lomi_files::{
    LocalNativeFile, LocalNativeFileError, LocalNativeFilePublishError, LocalNativeFileReadError,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Component, Path, PathBuf},
};

const FILE_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum NativeFileErrorKind {
    Io,
    Unsupported,
    TooLarge,
    Conflict,
    ReadOnly,
    OpenFile,
    Uncertain,
}

/// Serializable error shape matching the desktop editor's existing error DTO.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeFileError {
    pub kind: NativeFileErrorKind,
    pub message: String,
}

impl NativeFileError {
    pub fn new(kind: NativeFileErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    fn io(message: impl Into<String>) -> Self {
        Self::new(NativeFileErrorKind::Io, message)
    }

    fn unsupported(message: impl Into<String>) -> Self {
        Self::new(NativeFileErrorKind::Unsupported, message)
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self::new(NativeFileErrorKind::Conflict, message)
    }

    fn too_large(message: impl Into<String>) -> Self {
        Self::new(NativeFileErrorKind::TooLarge, message)
    }

    fn read_only(message: impl Into<String>) -> Self {
        Self::new(NativeFileErrorKind::ReadOnly, message)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeSaveFile {
    pub root: String,
    pub relative: String,
    pub expected_revision: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeFileLocation {
    pub root: String,
    pub relative: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeSaveNew {
    pub absolute_path: PathBuf,
    pub open_files: Vec<NativeFileLocation>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeSaveNewChecked {
    pub request: NativeSaveNew,
    pub expected_revision: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "request", rename_all = "camelCase")]
pub enum NativeSaveRequest {
    File(NativeSaveFile),
    FileNoFollow(NativeSaveFile),
    New(NativeSaveNew),
    NewChecked(NativeSaveNewChecked),
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeFileEncoding {
    Utf8,
    Utf8Bom,
    Utf16Le,
    Utf16Be,
}

/// Serializable metadata shape matching the desktop `EditorFile` result.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeEditorFile {
    pub path: String,
    pub relative: String,
    pub content: Option<String>,
    pub revision: String,
    pub encoding: NativeFileEncoding,
    pub read_only: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeSavedEditorFile {
    pub location: NativeFileLocation,
    pub file: NativeEditorFile,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum NativeSaveResult {
    File(NativeEditorFile),
    New(NativeSavedEditorFile),
}

/// Save an existing editor file or save text to a native-selected absolute
/// path. The caller supplies the text independently of the request DTO.
pub fn save(
    request: NativeSaveRequest,
    content: &str,
    mut check: impl FnMut() -> Result<(), NativeFileError>,
) -> Result<NativeSaveResult, NativeFileError> {
    let mut phased = |phase| match phase {
        NativeFileCheckPhase::Progress | NativeFileCheckPhase::BeforeEffect => check(),
        NativeFileCheckPhase::Validation | NativeFileCheckPhase::Publication => Ok(()),
    };
    save_with_phase(request, content, &mut phased)
}

/// Save an editor file while exposing the distinct local publication phases.
/// The caller must reserve remote authorization for `BeforeEffect`; later
/// phases are local deadline/cancellation checks only.
pub fn save_with_phase(
    request: NativeSaveRequest,
    content: &str,
    check: &mut impl FnMut(NativeFileCheckPhase) -> Result<(), NativeFileError>,
) -> Result<NativeSaveResult, NativeFileError> {
    check(NativeFileCheckPhase::Progress)?;
    match request {
        NativeSaveRequest::File(request) => save_file(request, content, false, check),
        NativeSaveRequest::FileNoFollow(request) => save_file(request, content, true, check),
        NativeSaveRequest::New(request) => save_new_inner(request, content, None, check),
        NativeSaveRequest::NewChecked(request) => save_new_inner(
            request.request,
            content,
            Some(request.expected_revision.as_deref()),
            check,
        ),
    }
}

fn save_file(
    request: NativeSaveFile,
    content: &str,
    no_follow: bool,
    check: &mut impl FnMut(NativeFileCheckPhase) -> Result<(), NativeFileError>,
) -> Result<NativeSaveResult, NativeFileError> {
    check(NativeFileCheckPhase::Progress)?;
    let (path, root, relative) = if no_follow {
        resolve_no_follow(&request.root, &request.relative)?
    } else {
        resolve(&request.root, &request.relative)?
    };
    check(NativeFileCheckPhase::Progress)?;
    let target = if no_follow {
        LocalNativeFile::open_no_follow(&path)
    } else {
        LocalNativeFile::open(&path)
    }
    .map_err(read_error)?;
    check(NativeFileCheckPhase::Progress)?;
    if !target.path().starts_with(Path::new(&root)) {
        return Err(NativeFileError::unsupported(
            "This symbolic link points outside the project.",
        ));
    }
    if target.path() != path {
        return Err(NativeFileError::conflict(
            "The file path changed while opening. Try again.",
        ));
    }
    if target.is_new() {
        return Err(NativeFileError::conflict(
            "The file changed on disk. Reload it or explicitly overwrite the disk version.",
        ));
    }
    let snapshot = target.snapshot_with_phase(check).map_err(read_failure)?;
    if snapshot.sha256 != request.expected_revision {
        return Err(NativeFileError::conflict(
            "The file changed on disk. Reload it or explicitly overwrite the disk version.",
        ));
    }
    if snapshot.read_only {
        return Err(NativeFileError::read_only(
            "This file is read-only. Your changes are still in the editor.",
        ));
    }
    check(NativeFileCheckPhase::Progress)?;
    let (_, encoding) = decode(&snapshot.bytes)?;
    check(NativeFileCheckPhase::Progress)?;
    let bytes = encode(content, encoding)?;
    check(NativeFileCheckPhase::Progress)?;
    let revision = target
        .replace_with_phase(&snapshot.sha256, &bytes, check)
        .map_err(publish_failure)?;
    Ok(NativeSaveResult::File(NativeEditorFile {
        path: path
            .to_str()
            .ok_or_else(|| NativeFileError::unsupported("This filename is not valid Unicode."))?
            .to_owned(),
        relative,
        content: None,
        revision,
        encoding,
        read_only: false,
    }))
}

fn save_new_inner(
    request: NativeSaveNew,
    content: &str,
    expected_revision: Option<Option<&str>>,
    check: &mut impl FnMut(NativeFileCheckPhase) -> Result<(), NativeFileError>,
) -> Result<NativeSaveResult, NativeFileError> {
    check(NativeFileCheckPhase::Progress)?;
    let path = resolve_new_path(&request.absolute_path)?;
    check(NativeFileCheckPhase::Progress)?;
    let target = LocalNativeFile::open(&path).map_err(read_error)?;
    for file in &request.open_files {
        check(NativeFileCheckPhase::Progress)?;
        if resolve(&file.root, &file.relative)
            .ok()
            .is_some_and(|(open, _, _)| open == path)
        {
            return Err(NativeFileError::new(
                NativeFileErrorKind::OpenFile,
                "This file is already open. Close its editor tabs before replacing it.",
            ));
        }
    }

    let target_is_new = target.is_new();
    if let Some(expected_revision) = expected_revision {
        match (expected_revision, target_is_new) {
            (None, false) | (Some(_), true) => {
                return Err(NativeFileError::conflict(
                    "The file changed on disk. Reload it or explicitly overwrite the disk version.",
                ));
            }
            _ => {}
        }
    }

    let (revision, encoding) = if target_is_new {
        check(NativeFileCheckPhase::Progress)?;
        let bytes = encode(content, NativeFileEncoding::Utf8)?;
        let revision = target
            .create_with_phase(&bytes, check)
            .map_err(publish_failure)?;
        (revision, NativeFileEncoding::Utf8)
    } else {
        let snapshot = target.snapshot_with_phase(check).map_err(read_failure)?;
        if let Some(Some(expected_revision)) = expected_revision {
            if expected_revision != snapshot.sha256.as_str() {
                return Err(NativeFileError::conflict(
                    "The file changed on disk. Reload it or explicitly overwrite the disk version.",
                ));
            }
        }
        if snapshot.read_only {
            return Err(NativeFileError::read_only(
                "This file is read-only. Your changes are still in the editor.",
            ));
        }
        check(NativeFileCheckPhase::Progress)?;
        let (_, encoding) = decode(&snapshot.bytes)?;
        check(NativeFileCheckPhase::Progress)?;
        let encoded = encode(content, encoding)?;
        check(NativeFileCheckPhase::Progress)?;
        let revision = target
            .replace_with_phase(&snapshot.sha256, &encoded, check)
            .map_err(publish_failure)?;
        (revision, encoding)
    };

    let parent = path
        .parent()
        .ok_or_else(|| NativeFileError::io("The file has no parent directory."))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| NativeFileError::unsupported("This filename is not valid Unicode."))?;
    let parent = parent
        .to_str()
        .ok_or_else(|| NativeFileError::unsupported("This filename is not valid Unicode."))?
        .to_owned();
    let file_path = path
        .to_str()
        .ok_or_else(|| NativeFileError::unsupported("This filename is not valid Unicode."))?
        .to_owned();
    Ok(NativeSaveResult::New(NativeSavedEditorFile {
        location: NativeFileLocation {
            root: parent,
            relative: file_name.to_owned(),
        },
        file: NativeEditorFile {
            path: file_path,
            relative: file_name.to_owned(),
            content: None,
            revision,
            encoding,
            read_only: false,
        },
    }))
}

fn resolve(root: &str, relative: &str) -> Result<(PathBuf, String, String), NativeFileError> {
    let root = fs::canonicalize(root)
        .map_err(|error| NativeFileError::io(format!("Cannot open directory: {error}")))?;
    if !root.is_dir() {
        return Err(NativeFileError::unsupported(
            "The selected path is not a directory.",
        ));
    }
    let relative_path = Path::new(relative);
    if relative_path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(NativeFileError::unsupported(
            "The path must stay inside the project.",
        ));
    }
    let path = fs::canonicalize(root.join(relative_path))
        .map_err(|error| NativeFileError::io(format!("The file could not be opened: {error}")))?;
    if !path.starts_with(&root) {
        return Err(NativeFileError::unsupported(
            "This symbolic link points outside the project.",
        ));
    }
    if !path.is_file() {
        return Err(NativeFileError::unsupported(
            "Only regular files can be opened in the editor.",
        ));
    }
    let relative = path
        .strip_prefix(&root)
        .map_err(|error| NativeFileError::io(error.to_string()))?
        .to_str()
        .ok_or_else(|| NativeFileError::unsupported("This filename is not valid Unicode."))?
        .to_owned();
    let root = root
        .to_str()
        .ok_or_else(|| NativeFileError::unsupported("This filename is not valid Unicode."))?
        .to_owned();
    Ok((path, root, relative))
}

fn resolve_no_follow(
    root: &str,
    relative: &str,
) -> Result<(PathBuf, String, String), NativeFileError> {
    let root_path = Path::new(root);
    if !root_path.is_absolute()
        || root_path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(NativeFileError::unsupported(
            "The project folder path is invalid.",
        ));
    }
    let relative_path = Path::new(relative);
    if relative_path.as_os_str().is_empty()
        || relative_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(NativeFileError::unsupported(
            "The path must stay inside the project.",
        ));
    }
    let path = root_path.join(relative_path);
    let root = root_path
        .to_str()
        .ok_or_else(|| NativeFileError::unsupported("The project folder path is invalid."))?
        .to_owned();
    let relative = relative_path
        .to_str()
        .ok_or_else(|| NativeFileError::unsupported("The editor file path is invalid."))?
        .to_owned();
    Ok((path, root, relative))
}

fn resolve_new_path(path: &Path) -> Result<PathBuf, NativeFileError> {
    if !path.is_absolute() {
        return Err(NativeFileError::unsupported(
            "Choose an absolute file path.",
        ));
    }
    match fs::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .ok_or_else(|| NativeFileError::io("The file has no parent directory."))?;
            let name = path
                .file_name()
                .ok_or_else(|| NativeFileError::unsupported("Choose a filename."))?;
            Ok(fs::canonicalize(parent)
                .map_err(|error| NativeFileError::io(error.to_string()))?
                .join(name))
        }
        Err(error) => Err(NativeFileError::io(error.to_string())),
    }
}

fn decode(bytes: &[u8]) -> Result<(String, NativeFileEncoding), NativeFileError> {
    let invalid = || {
        NativeFileError::unsupported(
            "This file is not supported text. Use UTF-8 or UTF-16 with a byte order mark.",
        )
    };
    let (text, encoding) = if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        if !bytes.len().is_multiple_of(2) {
            return Err(invalid());
        }
        let little = bytes[0] == 0xff;
        let units = bytes[2..]
            .chunks_exact(2)
            .map(|pair| {
                if little {
                    u16::from_le_bytes([pair[0], pair[1]])
                } else {
                    u16::from_be_bytes([pair[0], pair[1]])
                }
            })
            .collect::<Vec<_>>();
        (
            String::from_utf16(&units).map_err(|_| invalid())?,
            if little {
                NativeFileEncoding::Utf16Le
            } else {
                NativeFileEncoding::Utf16Be
            },
        )
    } else {
        let (data, encoding) = if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
            (&bytes[3..], NativeFileEncoding::Utf8Bom)
        } else {
            (bytes, NativeFileEncoding::Utf8)
        };
        (
            std::str::from_utf8(data).map_err(|_| invalid())?.to_owned(),
            encoding,
        )
    };
    if text
        .chars()
        .any(|ch| ch == '\0' || (ch < ' ' && !matches!(ch, '\n' | '\r' | '\t' | '\u{000c}')))
    {
        return Err(NativeFileError::unsupported(
            "Binary files cannot be edited as text.",
        ));
    }
    Ok((text, encoding))
}

fn encode(text: &str, encoding: NativeFileEncoding) -> Result<Vec<u8>, NativeFileError> {
    let utf8_limit_exceeded = match encoding {
        NativeFileEncoding::Utf8 => text.len() > FILE_LIMIT,
        NativeFileEncoding::Utf8Bom => text.len() > FILE_LIMIT - 3,
        NativeFileEncoding::Utf16Le | NativeFileEncoding::Utf16Be => false,
    };
    if utf8_limit_exceeded {
        return Err(NativeFileError::too_large(
            "The edited file exceeds the 16 MiB save limit. Your changes are still in the editor.",
        ));
    }
    let mut bytes = match encoding {
        NativeFileEncoding::Utf8 => Vec::with_capacity(text.len()),
        NativeFileEncoding::Utf8Bom => Vec::with_capacity(text.len() + 3),
        NativeFileEncoding::Utf16Le | NativeFileEncoding::Utf16Be => Vec::new(),
    };
    match encoding {
        NativeFileEncoding::Utf8 => bytes.extend_from_slice(text.as_bytes()),
        NativeFileEncoding::Utf8Bom => {
            bytes.extend_from_slice(&[0xef, 0xbb, 0xbf]);
            bytes.extend_from_slice(text.as_bytes());
        }
        NativeFileEncoding::Utf16Le | NativeFileEncoding::Utf16Be => {
            bytes.extend_from_slice(if encoding == NativeFileEncoding::Utf16Le {
                &[0xff, 0xfe]
            } else {
                &[0xfe, 0xff]
            });
            for unit in text.encode_utf16() {
                bytes.extend_from_slice(&if encoding == NativeFileEncoding::Utf16Le {
                    unit.to_le_bytes()
                } else {
                    unit.to_be_bytes()
                });
                if bytes.len() > FILE_LIMIT {
                    return Err(NativeFileError::too_large(
                        "The edited file exceeds the 16 MiB save limit. Your changes are still in the editor.",
                    ));
                }
            }
        }
    }
    if bytes.len() > FILE_LIMIT {
        return Err(NativeFileError::too_large(
            "The edited file exceeds the 16 MiB save limit. Your changes are still in the editor.",
        ));
    }
    Ok(bytes)
}

fn read_error(error: LocalNativeFileError) -> NativeFileError {
    match error {
        LocalNativeFileError::NotFound => {
            NativeFileError::io("The file could not be opened: file not found.")
        }
        LocalNativeFileError::Changed => {
            NativeFileError::conflict("The file changed while reading. Try again.")
        }
        LocalNativeFileError::Protected => {
            NativeFileError::read_only("This file cannot be safely opened for editing.")
        }
        LocalNativeFileError::Exists => NativeFileError::conflict(
            "The file changed while saving. Your changes are still in the editor.",
        ),
        LocalNativeFileError::Invalid => {
            NativeFileError::unsupported("The file path is not valid.")
        }
        LocalNativeFileError::Unsupported => {
            NativeFileError::unsupported("Only regular text files can be edited.")
        }
        LocalNativeFileError::Limit => {
            NativeFileError::too_large("This file exceeds the 16 MiB editor limit.")
        }
        LocalNativeFileError::Io => NativeFileError::io("The file could not be opened."),
    }
}

fn read_failure(error: LocalNativeFileReadError<NativeFileError>) -> NativeFileError {
    match error {
        LocalNativeFileReadError::File(error) => read_error(error),
        LocalNativeFileReadError::Check(error) => error,
    }
}

fn publish_failure(error: LocalNativeFilePublishError<NativeFileError>) -> NativeFileError {
    match error {
        LocalNativeFilePublishError::Before(LocalNativeFileReadError::File(error)) => match error {
            LocalNativeFileError::Changed | LocalNativeFileError::Exists => {
                NativeFileError::conflict(
                    "The file changed while saving. Your changes are still in the editor.",
                )
            }
            LocalNativeFileError::Protected => NativeFileError::read_only(
                "This file cannot be safely replaced. Your changes are still in the editor.",
            ),
            LocalNativeFileError::Limit => NativeFileError::too_large(
                "The edited file exceeds the 16 MiB save limit. Your changes are still in the editor.",
            ),
            other => read_error(other),
        },
        LocalNativeFilePublishError::Before(LocalNativeFileReadError::Check(error)) => error,
        LocalNativeFilePublishError::Uncertain => NativeFileError::new(
            NativeFileErrorKind::Uncertain,
            "The file was replaced, but durable completion could not be confirmed. Check the disk version before saving again.",
        ),
    }
}
