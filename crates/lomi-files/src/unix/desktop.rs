//! Descriptor-relative implementation of owner-local Explorer mutations.
//!
//! This deliberately does not use `FileRoot`: Explorer paths are local paths,
//! may refer to a separate OS drop directory, and have different copy/trash
//! semantics from the remote file API.

use super::*;
use crate::LocalNativeFileCheckPhase;
use crate::desktop::{
    DesktopFileChange, DesktopFileErrorCode, DesktopFileIdentity, DesktopFileKind,
    DesktopFileOperation, DesktopMutationError, DesktopMutationRequest, DesktopSourcePrecondition,
    DesktopTrashError, DesktopTrashTicket, desktop_staging_name,
};
use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;

const COPY_BUFFER: usize = 64 * 1024;
const COPY_NODE_LIMIT: usize = 65_536;
const COPY_PATH_BUDGET: usize = 16 * 1024 * 1024;
const STAGE_PATH_BUDGET: usize = 16 * 1024 * 1024;
const DESKTOP_DIR_ENTRY_LIMIT: usize = 2_048;
const DESKTOP_DIR_NAME_BYTES: usize = 256 * 1024;
type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone)]
struct ComponentPath(Vec<CString>);

impl ComponentPath {
    fn parse(value: &str, allow_empty: bool) -> Result<Self, DesktopFileErrorCode> {
        crate::desktop::validate_desktop_relative(value, allow_empty)?;
        let mut names = Vec::new();
        for component in Path::new(value).components() {
            match component {
                Component::CurDir => {}
                Component::Normal(name) => names.push(
                    CString::new(name.as_bytes()).map_err(|_| DesktopFileErrorCode::Invalid)?,
                ),
                _ => return Err(DesktopFileErrorCode::Invalid),
            }
        }
        Ok(Self(names))
    }

    fn parent_and_leaf(&self) -> Result<(Vec<CString>, CString), DesktopFileErrorCode> {
        let (leaf, parent) = self.0.split_last().ok_or(DesktopFileErrorCode::Protected)?;
        Ok((parent.to_vec(), leaf.clone()))
    }

    fn as_path(&self) -> PathBuf {
        let mut path = PathBuf::new();
        for component in &self.0 {
            path.push(OsStr::from_bytes(component.as_bytes()));
        }
        path
    }
}

struct RootPin {
    path: PathBuf,
    fd: OwnedFd,
    identity: Ident,
}

pub(crate) fn pin_namespace_directory(
    path: &Path,
) -> Result<(std::fs::File, DesktopFileIdentity), DesktopFileErrorCode> {
    let pin = RootPin::open(path).map_err(desktop_error)?;
    pin.validate().map_err(desktop_error)?;
    let directory_identity = identity(pin.identity);
    Ok((std::fs::File::from(pin.fd), directory_identity))
}

pub(crate) fn namespace_exact_child(
    parent: &std::fs::File,
    name: &OsStr,
    check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
) -> Result<Option<DesktopSourcePrecondition>, DesktopFileErrorCode> {
    let name = CString::new(name.as_bytes()).map_err(|_| DesktopFileErrorCode::Invalid)?;
    check()?;
    let directory_fd: std::os::fd::OwnedFd = parent
        .try_clone()
        .map_err(|_| DesktopFileErrorCode::Io)?
        .into();
    let names = super::read_dir_names(&directory_fd).map_err(desktop_error)?;
    check()?;
    let mut found = false;
    for entry in names {
        check()?;
        if entry == name.as_bytes() {
            if found {
                return Err(DesktopFileErrorCode::Changed);
            }
            found = true;
        }
    }
    if !found {
        return Ok(None);
    }
    check()?;
    let parent_fd = std::os::fd::AsRawFd::as_raw_fd(parent);
    let stat = fstatat_nofollow(parent_fd, &name).map_err(desktop_error)?;
    let entry_identity = ident_at(parent_fd, &name, &stat).map_err(desktop_error)?;
    check()?;
    Ok(Some(DesktopSourcePrecondition {
        identity: identity(entry_identity),
        kind: file_kind(kind_of(&stat)),
    }))
}

pub(crate) fn source_precondition(
    path: &Path,
) -> Result<DesktopSourcePrecondition, DesktopFileErrorCode> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(DesktopFileErrorCode::Invalid);
    }
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(DesktopFileErrorCode::Protected)?;
    let leaf = path.file_name().ok_or(DesktopFileErrorCode::Protected)?;
    let name = cstring(leaf.as_bytes()).map_err(desktop_error)?;
    let parent = PinnedDir::open(parent_path, &[]).map_err(desktop_error)?;
    let stat = fstatat_nofollow(parent.fd.as_raw_fd(), &name).map_err(desktop_error)?;
    let result = DesktopSourcePrecondition {
        identity: identity(ident_at(parent.fd.as_raw_fd(), &name, &stat).map_err(desktop_error)?),
        kind: file_kind(kind_of(&stat)),
    };
    parent.validate().map_err(desktop_error)?;
    Ok(result)
}

impl RootPin {
    fn open(path: &Path) -> Result<Self, Error> {
        let directory = native_open_absolute_directory(path).map_err(local_native_to_error)?;
        let fd: OwnedFd = directory.into();
        let stat = fstat(fd.as_raw_fd())?;
        if kind_of(&stat) != Kind::Directory {
            return Err(Error::Changed);
        }
        let identity = ident_fd(fd.as_raw_fd(), &stat)?;
        Ok(Self {
            path: path.to_path_buf(),
            fd,
            identity,
        })
    }

    fn validate(&self) -> Result<(), Error> {
        let stat = fstat(self.fd.as_raw_fd())?;
        if kind_of(&stat) != Kind::Directory
            || ident_fd(self.fd.as_raw_fd(), &stat)? != self.identity
        {
            return Err(Error::Changed);
        }
        let current = native_open_absolute_directory(&self.path).map_err(local_native_to_error)?;
        let current_stat = fstat(current.as_raw_fd())?;
        if ident_fd(current.as_raw_fd(), &current_stat)? != self.identity {
            return Err(Error::Changed);
        }
        Ok(())
    }
}

fn local_native_to_error(error: LocalNativeFileError) -> Error {
    match error {
        LocalNativeFileError::NotFound => Error::NotFound,
        LocalNativeFileError::Changed => Error::Changed,
        LocalNativeFileError::Protected => Error::Protected,
        LocalNativeFileError::Exists => Error::Exists,
        LocalNativeFileError::Invalid => Error::Invalid,
        LocalNativeFileError::Unsupported => Error::Unsupported,
        LocalNativeFileError::Limit => Error::Limit,
        LocalNativeFileError::Io => Error::Io(std::io::ErrorKind::Other),
    }
}

struct PinnedDir {
    root: RootPin,
    relative: Vec<CString>,
    fd: OwnedFd,
    identity: Ident,
    chain: Vec<Ident>,
}

impl PinnedDir {
    fn open(root: &Path, relative: &[CString]) -> Result<Self, Error> {
        let root = RootPin::open(root)?;
        let mut current = dup(root.fd.as_raw_fd())?;
        let mut chain = vec![root.identity];
        for component in relative {
            let named = fstatat_nofollow(current.as_raw_fd(), component)?;
            if kind_of(&named) != Kind::Directory {
                return Err(Error::Changed);
            }
            let next = openat(
                current.as_raw_fd(),
                component,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                0,
                true,
            )?;
            let held = fstat(next.as_raw_fd())?;
            let identity = ident_fd(next.as_raw_fd(), &held)?;
            if identity != ident_at(current.as_raw_fd(), component, &named)?
                || kind_of(&held) != Kind::Directory
            {
                return Err(Error::Changed);
            }
            chain.push(identity);
            current = next;
        }
        let stat = fstat(current.as_raw_fd())?;
        let identity = ident_fd(current.as_raw_fd(), &stat)?;
        Ok(Self {
            root,
            relative: relative.to_vec(),
            fd: current,
            identity,
            chain,
        })
    }

    fn path(&self) -> PathBuf {
        self.root
            .path
            .join(ComponentPath(self.relative.clone()).as_path())
    }

    fn validate(&self) -> Result<(), Error> {
        self.root.validate()?;
        let current = Self::open(&self.root.path, &self.relative)?;
        if current.identity != self.identity || current.chain != self.chain {
            return Err(Error::Changed);
        }
        let held = fstat(self.fd.as_raw_fd())?;
        if ident_fd(self.fd.as_raw_fd(), &held)? != self.identity {
            return Err(Error::Changed);
        }
        Ok(())
    }
}

struct EntryPin {
    parent: PinnedDir,
    name: CString,
    absolute: PathBuf,
    identity: Ident,
    stamp: NativeFileStamp,
    kind: Kind,
}

impl EntryPin {
    fn open(root: &Path, path: &ComponentPath) -> Result<Self, Error> {
        let (parent, name) = path.parent_and_leaf().map_err(|_| Error::Protected)?;
        let parent = PinnedDir::open(root, &parent)?;
        let stat = fstatat_nofollow(parent.fd.as_raw_fd(), &name)?;
        let identity = ident_at(parent.fd.as_raw_fd(), &name, &stat)?;
        Ok(Self {
            absolute: parent.path().join(OsStr::from_bytes(name.as_bytes())),
            parent,
            name,
            identity,
            stamp: NativeFileStamp::read(&stat),
            kind: kind_of(&stat),
        })
    }

    fn validate(&self) -> Result<(), Error> {
        self.parent.validate()?;
        let stat = fstatat_nofollow(self.parent.fd.as_raw_fd(), &self.name)?;
        if ident_at(self.parent.fd.as_raw_fd(), &self.name, &stat)? != self.identity
            || NativeFileStamp::read(&stat) != self.stamp
        {
            return Err(Error::Changed);
        }
        Ok(())
    }
}

struct ControlPin {
    path: PathBuf,
    parent: Option<PinnedDir>,
    name: Option<CString>,
    identity: Ident,
}

impl ControlPin {
    fn open(path: &Path) -> Result<Self, Error> {
        if path == Path::new("/") {
            let root = RootPin::open(path)?;
            return Ok(Self {
                path: path.to_path_buf(),
                identity: root.identity,
                parent: None,
                name: None,
            });
        }
        let parent_path = path.parent().ok_or(Error::Invalid)?;
        let leaf = path.file_name().ok_or(Error::Invalid)?;
        let name = cstring(leaf.as_bytes())?;
        let parent = PinnedDir::open(parent_path, &[])?;
        let stat = fstatat_nofollow(parent.fd.as_raw_fd(), &name).map_err(|_| Error::Protected)?;
        let kind = kind_of(&stat);
        if kind == Kind::Symlink || kind == Kind::Other {
            return Err(Error::Protected);
        }
        Ok(Self {
            path: path.to_path_buf(),
            identity: ident_at(parent.fd.as_raw_fd(), &name, &stat)?,
            parent: Some(parent),
            name: Some(name),
        })
    }

    fn validate(&self) -> Result<(), Error> {
        match (&self.parent, &self.name) {
            (Some(parent), Some(name)) => {
                parent.validate()?;
                let stat = fstatat_nofollow(parent.fd.as_raw_fd(), name)?;
                if ident_at(parent.fd.as_raw_fd(), name, &stat)? != self.identity {
                    return Err(Error::Changed);
                }
            }
            (None, None) => {
                let root = RootPin::open(&self.path)?;
                if root.identity != self.identity {
                    return Err(Error::Changed);
                }
            }
            _ => return Err(Error::Changed),
        }
        Ok(())
    }
}

fn file_kind(kind: Kind) -> DesktopFileKind {
    match kind {
        Kind::File => DesktopFileKind::File,
        Kind::Directory => DesktopFileKind::Directory,
        Kind::Symlink => DesktopFileKind::Symlink,
        Kind::Other => DesktopFileKind::Other,
    }
}

fn read_desktop_dir_names(fd: RawFd) -> Result<Vec<Vec<u8>>, Error> {
    let duplicate = dup(fd)?;
    let raw = duplicate.as_raw_fd();
    let directory = unsafe { libc::fdopendir(raw) };
    if directory.is_null() {
        return Err(map_errno(last_errno(), false));
    }
    std::mem::forget(duplicate);
    unsafe { libc::rewinddir(directory) };
    let mut names = Vec::new();
    let mut total = 0usize;
    let result = loop {
        unsafe { *errno_location() = 0 };
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            break match unsafe { *errno_location() } {
                0 => Ok(()),
                error => Err(map_errno(error, false)),
            };
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let Some(next_total) = total.checked_add(name.len()) else {
            break Err(Error::Limit);
        };
        total = next_total;
        if names.len() >= DESKTOP_DIR_ENTRY_LIMIT || total > DESKTOP_DIR_NAME_BYTES {
            break Err(Error::Limit);
        }
        names.push(name.to_vec());
    };
    unsafe { libc::closedir(directory) };
    result.map(|()| names)
}

fn identity(identity: Ident) -> DesktopFileIdentity {
    DesktopFileIdentity {
        volume: identity.dev.to_string(),
        file_id: identity.ino.to_string(),
    }
}

fn desktop_error(error: Error) -> DesktopFileErrorCode {
    match error {
        Error::NotFound => DesktopFileErrorCode::NotFound,
        Error::Changed => DesktopFileErrorCode::Changed,
        Error::Protected => DesktopFileErrorCode::Protected,
        Error::Exists => DesktopFileErrorCode::Exists,
        Error::NotEmpty => DesktopFileErrorCode::NotEmpty,
        Error::Invalid => DesktopFileErrorCode::Invalid,
        Error::Unsupported => DesktopFileErrorCode::Unsupported,
        Error::Limit => DesktopFileErrorCode::Limit,
        Error::Io(_) => DesktopFileErrorCode::Io,
    }
}

fn overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn selected_is_controlled(
    path: &Path,
    identity: Ident,
    ancestors: &[Ident],
    controls: &[ControlPin],
    tree: bool,
) -> Result<(), Error> {
    for control in controls {
        control.validate()?;
        if identity == control.identity
            || ancestors.contains(&control.identity)
            || path.starts_with(&control.path)
            || (tree && control.path.starts_with(path))
        {
            return Err(Error::Protected);
        }
    }
    Ok(())
}

fn parent_is_controlled(parent: &PinnedDir, controls: &[ControlPin]) -> Result<(), Error> {
    for control in controls {
        control.validate()?;
        if parent.chain.contains(&control.identity) {
            return Err(Error::Protected);
        }
    }
    Ok(())
}

fn target_is_controlled(path: &Path, controls: &[ControlPin]) -> Result<(), Error> {
    for control in controls {
        control.validate()?;
        if overlap(path, &control.path) {
            return Err(Error::Protected);
        }
    }
    Ok(())
}

fn open_controls(request: &DesktopMutationRequest) -> Result<Vec<ControlPin>, Error> {
    let mut controls = Vec::with_capacity(request.control_roots.len());
    for path in &request.control_roots {
        controls.push(ControlPin::open(path)?);
    }
    Ok(controls)
}

fn expected_path_matches(
    request: &DesktopMutationRequest,
    relative: &ComponentPath,
) -> Result<(), DesktopFileErrorCode> {
    if let Some(expected) = &request.expected_path {
        if expected != &request.root.join(relative.as_path()) {
            return Err(DesktopFileErrorCode::Changed);
        }
    }
    Ok(())
}

fn phase<E>(
    check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), E>,
    phase: LocalNativeFileCheckPhase,
) -> Result<(), E> {
    check(phase)
}

fn require_absent(parent: RawFd, name: &CStr) -> Result<(), Error> {
    match fstatat_nofollow(parent, name) {
        Ok(_) => Err(Error::Exists),
        Err(Error::NotFound) => Ok(()),
        Err(error) => Err(error),
    }
}

fn mkdir_at(parent: RawFd, name: &CStr, mode: u32) -> Result<(), Error> {
    if unsafe { libc::mkdirat(parent, name.as_ptr(), mode as libc::mode_t) } != 0 {
        return Err(map_errno(last_errno(), false));
    }
    Ok(())
}

fn remove_at(parent: RawFd, name: &CStr, directory: bool) -> Result<(), Error> {
    let flags = if directory { libc::AT_REMOVEDIR } else { 0 };
    if unsafe { libc::unlinkat(parent, name.as_ptr(), flags) } != 0 {
        return Err(map_errno(last_errno(), false));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_symlink_pin(parent: RawFd, name: &CStr) -> Result<OwnedFd, Error> {
    openat(parent, name, libc::O_PATH | libc::O_NOFOLLOW, 0, false)
}

#[cfg(target_os = "macos")]
fn open_symlink_pin(parent: RawFd, name: &CStr) -> Result<OwnedFd, Error> {
    openat(
        parent,
        name,
        libc::O_RDONLY | libc::O_SYMLINK | libc::O_NOFOLLOW,
        0,
        false,
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn open_symlink_pin(_parent: RawFd, _name: &CStr) -> Result<OwnedFd, Error> {
    Err(Error::Unsupported)
}

fn create_file_at(parent: RawFd, name: &CStr, mode: u32) -> Result<OwnedFd, Error> {
    openat(
        parent,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
        mode,
        false,
    )
}

fn check_parent_and_controls(parent: &PinnedDir, controls: &[ControlPin]) -> Result<(), Error> {
    parent.validate()?;
    parent_is_controlled(parent, controls)?;
    for control in controls {
        control.validate()?;
    }
    Ok(())
}

fn mutation_change(
    request: &DesktopMutationRequest,
    old_path: Option<PathBuf>,
    new_path: Option<PathBuf>,
    trash: Option<DesktopTrashTicket>,
) -> DesktopFileChange {
    DesktopFileChange {
        operation_id: request.operation_id.clone(),
        old_path,
        new_path,
        trash,
    }
}

fn check_source_precondition(
    expected: Option<&DesktopSourcePrecondition>,
    actual_identity: Ident,
    actual_kind: Kind,
) -> Result<(), DesktopMutationError> {
    if let Some(expected) = expected {
        if identity(actual_identity) != expected.identity || file_kind(actual_kind) != expected.kind
        {
            return Err(DesktopFileErrorCode::Changed.into());
        }
    }
    Ok(())
}

pub(crate) fn apply_mutation(
    request: &DesktopMutationRequest,
    expected_source: Option<&DesktopSourcePrecondition>,
    check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<DesktopFileChange, DesktopMutationError> {
    crate::desktop::validate_desktop_request(request).map_err(DesktopMutationError::Before)?;
    phase(check, LocalNativeFileCheckPhase::Progress).map_err(DesktopMutationError::Before)?;
    let controls = open_controls(request)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;

    let relative =
        ComponentPath::parse(&request.relative_path, true).map_err(DesktopMutationError::Before)?;
    expected_path_matches(request, &relative).map_err(DesktopMutationError::Before)?;

    match &request.operation {
        DesktopFileOperation::NewFile { name } => {
            create_entry(request, &relative, name, false, &controls, check)
        }
        DesktopFileOperation::NewFolder { name } => {
            create_entry(request, &relative, name, true, &controls, check)
        }
        DesktopFileOperation::Rename { name } => {
            rename_entry(request, &relative, name, expected_source, &controls, check)
        }
        DesktopFileOperation::Copy {
            source_root,
            source,
        } => copy_or_move(
            request,
            &relative,
            source_root,
            source,
            false,
            None,
            &controls,
            check,
        ),
        DesktopFileOperation::Move {
            source_root,
            source,
        } => copy_or_move(
            request,
            &relative,
            source_root,
            source,
            true,
            expected_source,
            &controls,
            check,
        ),
        DesktopFileOperation::Duplicate => duplicate_entry(request, &relative, &controls, check),
        DesktopFileOperation::Trash => {
            trash_entry(request, &relative, expected_source, &controls, check)
        }
        DesktopFileOperation::Delete => {
            delete_entry(request, &relative, expected_source, &controls, check)
        }
        DesktopFileOperation::GitDiscard { .. } | DesktopFileOperation::GitIgnore { .. } => {
            Err(DesktopFileErrorCode::Unsupported.into())
        }
    }
}

fn create_entry(
    request: &DesktopMutationRequest,
    parent_relative: &ComponentPath,
    name: &str,
    directory: bool,
    controls: &[ControlPin],
    check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<DesktopFileChange, DesktopMutationError> {
    let parent = PinnedDir::open(&request.root, &parent_relative.0)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    parent_is_controlled(&parent, controls)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    let leaf = CString::new(name)
        .map_err(|_| DesktopMutationError::Before(DesktopFileErrorCode::Invalid))?;
    let target = parent.path().join(name);
    target_is_controlled(&target, controls)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    require_absent(parent.fd.as_raw_fd(), &leaf)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    phase(check, LocalNativeFileCheckPhase::BeforeEffect).map_err(DesktopMutationError::Before)?;
    phase(check, LocalNativeFileCheckPhase::Validation).map_err(DesktopMutationError::Before)?;
    phase(check, LocalNativeFileCheckPhase::Publication).map_err(DesktopMutationError::Before)?;
    check_parent_and_controls(&parent, controls)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    require_absent(parent.fd.as_raw_fd(), &leaf)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    let created = if directory {
        mkdir_at(parent.fd.as_raw_fd(), &leaf, 0o777)
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        openat(
            parent.fd.as_raw_fd(),
            &leaf,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
            true,
        )
        .map_err(|_| DesktopMutationError::Uncertain)?
    } else {
        create_file_at(parent.fd.as_raw_fd(), &leaf, 0o666)
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?
    };
    let held_stat = fstat(created.as_raw_fd()).map_err(|_| DesktopMutationError::Uncertain)?;
    let held_identity =
        ident_fd(created.as_raw_fd(), &held_stat).map_err(|_| DesktopMutationError::Uncertain)?;
    let named_stat = fstatat_nofollow(parent.fd.as_raw_fd(), &leaf)
        .map_err(|_| DesktopMutationError::Uncertain)?;
    if ident_at(parent.fd.as_raw_fd(), &leaf, &named_stat)
        .map_err(|_| DesktopMutationError::Uncertain)?
        != held_identity
    {
        return Err(DesktopMutationError::Uncertain);
    }
    Ok(mutation_change(request, None, Some(target), None))
}

fn rename_entry(
    request: &DesktopMutationRequest,
    relative: &ComponentPath,
    new_name: &str,
    expected_source: Option<&DesktopSourcePrecondition>,
    controls: &[ControlPin],
    check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<DesktopFileChange, DesktopMutationError> {
    let source = EntryPin::open(&request.root, relative)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    check_source_precondition(expected_source, source.identity, source.kind)?;
    selected_is_controlled(
        &source.absolute,
        source.identity,
        &source.parent.chain,
        controls,
        source.kind == Kind::Directory,
    )
    .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    if let Some(expected) = &request.expected_path {
        if expected != &source.absolute {
            return Err(DesktopFileErrorCode::Changed.into());
        }
    }
    let destination_name = CString::new(new_name)
        .map_err(|_| DesktopMutationError::Before(DesktopFileErrorCode::Invalid))?;
    let destination = source.parent.path().join(new_name);
    target_is_controlled(&destination, controls)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    if source.name.as_bytes() == destination_name.as_bytes() {
        source
            .validate()
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        return Ok(mutation_change(
            request,
            Some(source.absolute),
            Some(destination),
            None,
        ));
    }
    let case_only = case_only_alias(
        source.parent.fd.as_raw_fd(),
        &source.name,
        &destination_name,
        source.identity,
    )
    .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    if !case_only {
        require_absent(source.parent.fd.as_raw_fd(), &destination_name)
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    }
    phase(check, LocalNativeFileCheckPhase::BeforeEffect).map_err(DesktopMutationError::Before)?;
    phase(check, LocalNativeFileCheckPhase::Validation).map_err(DesktopMutationError::Before)?;
    source
        .validate()
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    check_parent_and_controls(&source.parent, controls)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    if case_only {
        let stage = CString::new(
            desktop_staging_name(&request.operation_id).map_err(DesktopMutationError::Before)?,
        )
        .map_err(|_| DesktopMutationError::Before(DesktopFileErrorCode::Invalid))?;
        require_absent(source.parent.fd.as_raw_fd(), &stage)
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        phase(check, LocalNativeFileCheckPhase::Publication)
            .map_err(DesktopMutationError::Before)?;
        source
            .validate()
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        check_parent_and_controls(&source.parent, controls)
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        require_absent(source.parent.fd.as_raw_fd(), &stage)
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        no_replace_rename(
            source.parent.fd.as_raw_fd(),
            &source.name,
            source.parent.fd.as_raw_fd(),
            &stage,
        )
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        phase(check, LocalNativeFileCheckPhase::BeforeEffect)
            .map_err(|_| DesktopMutationError::Uncertain)?;
        phase(check, LocalNativeFileCheckPhase::Validation)
            .map_err(|_| DesktopMutationError::Uncertain)?;
        phase(check, LocalNativeFileCheckPhase::Publication)
            .map_err(|_| DesktopMutationError::Uncertain)?;
        check_parent_and_controls(&source.parent, controls)
            .map_err(|_| DesktopMutationError::Uncertain)?;
        let staged = fstatat_nofollow(source.parent.fd.as_raw_fd(), &stage)
            .map_err(|_| DesktopMutationError::Uncertain)?;
        if ident_at(source.parent.fd.as_raw_fd(), &stage, &staged)
            .map_err(|_| DesktopMutationError::Uncertain)?
            != source.identity
        {
            return Err(DesktopMutationError::Uncertain);
        }
        require_absent(source.parent.fd.as_raw_fd(), &destination_name)
            .map_err(|_| DesktopMutationError::Uncertain)?;
        if no_replace_rename(
            source.parent.fd.as_raw_fd(),
            &stage,
            source.parent.fd.as_raw_fd(),
            &destination_name,
        )
        .is_err()
        {
            return Err(DesktopMutationError::Uncertain);
        }
        let published = fstatat_nofollow(source.parent.fd.as_raw_fd(), &destination_name)
            .map_err(|_| DesktopMutationError::Uncertain)?;
        if ident_at(source.parent.fd.as_raw_fd(), &destination_name, &published)
            .map_err(|_| DesktopMutationError::Uncertain)?
            != source.identity
        {
            return Err(DesktopMutationError::Uncertain);
        }
        Ok(mutation_change(
            request,
            Some(source.absolute),
            Some(destination),
            None,
        ))
    } else {
        require_absent(source.parent.fd.as_raw_fd(), &destination_name)
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        phase(check, LocalNativeFileCheckPhase::Publication)
            .map_err(DesktopMutationError::Before)?;
        source
            .validate()
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        check_parent_and_controls(&source.parent, controls)
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        require_absent(source.parent.fd.as_raw_fd(), &destination_name)
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        no_replace_rename(
            source.parent.fd.as_raw_fd(),
            &source.name,
            source.parent.fd.as_raw_fd(),
            &destination_name,
        )
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        let published = fstatat_nofollow(source.parent.fd.as_raw_fd(), &destination_name)
            .map_err(|_| DesktopMutationError::Uncertain)?;
        if ident_at(source.parent.fd.as_raw_fd(), &destination_name, &published)
            .map_err(|_| DesktopMutationError::Uncertain)?
            != source.identity
        {
            return Err(DesktopMutationError::Uncertain);
        }
        Ok(mutation_change(
            request,
            Some(source.absolute),
            Some(destination),
            None,
        ))
    }
}

#[derive(Clone)]
struct CopyNodeSnapshot {
    path: Vec<Vec<u8>>,
    identity: Ident,
    stamp: NativeFileStamp,
}

struct CopySnapshot {
    nodes: Vec<CopyNodeSnapshot>,
    index: HashMap<Vec<u8>, usize>,
    children: HashMap<Vec<u8>, Vec<Vec<u8>>>,
    path_bytes: usize,
}

struct DeleteAliasState {
    expected: NativeFileStamp,
    remaining_nodes: HashSet<usize>,
}

struct DeleteAliasLedger {
    by_identity: HashMap<Ident, DeleteAliasState>,
}

impl DeleteAliasLedger {
    fn from_snapshot(snapshot: &CopySnapshot) -> Result<Self, Error> {
        let mut by_identity: HashMap<Ident, DeleteAliasState> = HashMap::new();
        for (index, node) in snapshot.nodes.iter().enumerate() {
            if node.stamp.directory() {
                continue;
            }
            let state = by_identity
                .entry(node.identity)
                .or_insert_with(|| DeleteAliasState {
                    expected: node.stamp,
                    remaining_nodes: HashSet::new(),
                });
            if state.expected != node.stamp || !state.remaining_nodes.insert(index) {
                return Err(Error::Changed);
            }
        }
        Ok(Self { by_identity })
    }

    fn expected_stamp(&self, identity: Ident) -> Result<NativeFileStamp, Error> {
        self.by_identity
            .get(&identity)
            .map(|state| state.expected)
            .ok_or(Error::Changed)
    }

    fn validate_stat(&self, identity: Ident, stat: &libc::stat) -> Result<(), Error> {
        if self.expected_stamp(identity)? != NativeFileStamp::read(stat) {
            return Err(Error::Changed);
        }
        Ok(())
    }

    fn record_removed(
        &mut self,
        root_parent: &PinnedDir,
        snapshot: &CopySnapshot,
        relative: &[Vec<u8>],
        identity: Ident,
    ) -> Result<(), Error> {
        let key = snapshot_key(relative)?;
        let node_index = *snapshot.index.get(&key).ok_or(Error::Changed)?;
        let node = snapshot.nodes.get(node_index).ok_or(Error::Changed)?;
        if node.identity != identity || node.stamp.directory() {
            return Err(Error::Changed);
        }
        let state = self.by_identity.get_mut(&identity).ok_or(Error::Changed)?;
        if !state.remaining_nodes.remove(&node_index) {
            return Err(Error::Changed);
        }
        state.expected.links = state.expected.links.checked_sub(1).ok_or(Error::Changed)?;
        let next_index = state.remaining_nodes.iter().next().copied();
        if let Some(next_index) = next_index {
            let next_node = snapshot.nodes.get(next_index).ok_or(Error::Changed)?;
            let stat = snapshot_path_stat(root_parent, snapshot, &next_node.path)?;
            let observed = NativeFileStamp::read(&stat);
            let mut expected = state.expected;
            expected.changed = observed.changed;
            if observed != expected {
                return Err(Error::Changed);
            }
            state.expected.changed = observed.changed;
        }
        Ok(())
    }
}

impl CopySnapshot {
    fn record(
        &mut self,
        path: &[Vec<u8>],
        stat: &libc::stat,
        identity: Ident,
    ) -> Result<(), Error> {
        if self.nodes.len() >= COPY_NODE_LIMIT {
            return Err(Error::Limit);
        }
        let path_data = path.iter().map(Vec::len).sum::<usize>();
        let added = path_data
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(
                    path.len() * std::mem::size_of::<Vec<u8>>()
                        + std::mem::size_of::<CopyNodeSnapshot>()
                        + 128,
                )
            })
            .ok_or(Error::Limit)?;
        self.path_bytes = self.path_bytes.checked_add(added).ok_or(Error::Limit)?;
        if self.path_bytes > COPY_PATH_BUDGET {
            return Err(Error::Limit);
        }
        let key = snapshot_key(path)?;
        let index = self.nodes.len();
        if self.index.insert(key, index).is_some() {
            return Err(Error::Changed);
        }
        self.nodes.push(CopyNodeSnapshot {
            path: path.to_vec(),
            identity,
            stamp: NativeFileStamp::read(stat),
        });
        Ok(())
    }

    fn get(&self, path: &[Vec<u8>]) -> Result<&CopyNodeSnapshot, Error> {
        let key = snapshot_key(path)?;
        self.index
            .get(&key)
            .and_then(|index| self.nodes.get(*index))
            .ok_or(Error::Changed)
    }
}

fn snapshot_key(path: &[Vec<u8>]) -> Result<Vec<u8>, Error> {
    let length = path
        .iter()
        .map(Vec::len)
        .sum::<usize>()
        .checked_add(path.len().saturating_sub(1))
        .ok_or(Error::Limit)?;
    let mut key = Vec::with_capacity(length);
    for (index, component) in path.iter().enumerate() {
        if index > 0 {
            key.push(b'/');
        }
        key.extend_from_slice(component);
    }
    Ok(key)
}

struct StageDir<'a> {
    parent: &'a PinnedDir,
    name: CString,
    fd: OwnedFd,
    identity: Ident,
    created: Vec<StagedEntry>,
    created_path_bytes: usize,
    active: bool,
}

struct StagedEntry {
    relative_path: Vec<u8>,
    parent_identity: Ident,
    identity: Ident,
    directory: bool,
}

fn track_staged_entry(
    parent: RawFd,
    name: &CStr,
    parent_relative: &[Vec<u8>],
    identity: Ident,
    directory: bool,
    created: &mut Vec<StagedEntry>,
    path_bytes: &mut usize,
) -> Result<(), Error> {
    let mut relative_path = Vec::new();
    for component in parent_relative {
        if !relative_path.is_empty() {
            relative_path.push(b'/');
        }
        relative_path.extend_from_slice(component);
    }
    if !relative_path.is_empty() {
        relative_path.push(b'/');
    }
    relative_path.extend_from_slice(name.to_bytes());
    let next_bytes = path_bytes
        .checked_add(relative_path.len())
        .ok_or(Error::Limit)?;
    if next_bytes > STAGE_PATH_BUDGET {
        remove_owned_new_entry(parent, name, identity, directory);
        return Err(Error::Limit);
    }
    let parent_stat = match fstat(parent) {
        Ok(stat) => stat,
        Err(error) => {
            remove_owned_new_entry(parent, name, identity, directory);
            return Err(error);
        }
    };
    let parent_identity = match ident_fd(parent, &parent_stat) {
        Ok(identity) => identity,
        Err(error) => {
            remove_owned_new_entry(parent, name, identity, directory);
            return Err(error);
        }
    };
    created.push(StagedEntry {
        relative_path,
        parent_identity,
        identity,
        directory,
    });
    *path_bytes = next_bytes;
    Ok(())
}

fn remove_owned_new_entry(parent: RawFd, name: &CStr, identity: Ident, directory: bool) {
    if let Ok(stat) = fstatat_nofollow(parent, name) {
        if ident_at(parent, name, &stat).ok() == Some(identity) {
            let _ = remove_at(parent, name, directory);
        }
    }
}

fn open_stage_parent(stage: RawFd, components: &[&[u8]]) -> Result<OwnedFd, Error> {
    let mut parent = dup(stage)?;
    for component in components {
        let name = cstring(component)?;
        parent = openat(
            parent.as_raw_fd(),
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
            true,
        )?;
    }
    Ok(parent)
}

fn remove_named_empty_dir_if_identity(parent: RawFd, name: &CStr, identity: Ident) {
    if let Ok(stat) = fstatat_nofollow(parent, name) {
        if kind_of(&stat) == Kind::Directory && ident_at(parent, name, &stat).ok() == Some(identity)
        {
            let _ = remove_at(parent, name, true);
        }
    }
}

impl<'a> StageDir<'a> {
    fn create(parent: &'a PinnedDir, operation_id: &str) -> Result<Self, Error> {
        let name = CString::new(desktop_staging_name(operation_id).map_err(|_| Error::Invalid)?)
            .map_err(|_| Error::Invalid)?;
        mkdir_at(parent.fd.as_raw_fd(), &name, 0o700)?;
        let named = match fstatat_nofollow(parent.fd.as_raw_fd(), &name) {
            Ok(stat) => stat,
            Err(error) => return Err(error),
        };
        let identity = ident_at(parent.fd.as_raw_fd(), &name, &named)?;
        let fd = match openat(
            parent.fd.as_raw_fd(),
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
            true,
        ) {
            Ok(fd) => fd,
            Err(error) => {
                remove_named_empty_dir_if_identity(parent.fd.as_raw_fd(), &name, identity);
                return Err(error);
            }
        };
        let stat = match fstat(fd.as_raw_fd()) {
            Ok(stat) => stat,
            Err(error) => {
                remove_named_empty_dir_if_identity(parent.fd.as_raw_fd(), &name, identity);
                return Err(error);
            }
        };
        if ident_fd(fd.as_raw_fd(), &stat)? != identity {
            remove_named_empty_dir_if_identity(parent.fd.as_raw_fd(), &name, identity);
            return Err(Error::Changed);
        }
        Ok(Self {
            parent,
            name,
            fd,
            identity,
            created: Vec::new(),
            created_path_bytes: 0,
            active: true,
        })
    }

    fn path(&self) -> PathBuf {
        self.parent
            .path()
            .join(OsStr::from_bytes(self.name.as_bytes()))
    }

    fn validate(&self) -> Result<(), Error> {
        self.parent.validate()?;
        let held = fstat(self.fd.as_raw_fd())?;
        let named = fstatat_nofollow(self.parent.fd.as_raw_fd(), &self.name)?;
        if kind_of(&held) != Kind::Directory
            || ident_fd(self.fd.as_raw_fd(), &held)? != self.identity
            || ident_at(self.parent.fd.as_raw_fd(), &self.name, &named)? != self.identity
        {
            return Err(Error::Changed);
        }
        Ok(())
    }

    fn publish(
        &mut self,
        destination: &PinnedDir,
        target: &CStr,
    ) -> Result<(), DesktopMutationError> {
        self.validate()
            .and_then(|()| destination.validate())
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        require_absent(destination.fd.as_raw_fd(), target)
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        let payload = cstring(b"payload")
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        let staged_stat = fstatat_nofollow(self.fd.as_raw_fd(), &payload)
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        let staged_identity = ident_at(self.fd.as_raw_fd(), &payload, &staged_stat)
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        no_replace_rename(
            self.fd.as_raw_fd(),
            &payload,
            destination.fd.as_raw_fd(),
            target,
        )
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        // The stage tree is now public. From here on, never let Drop remove
        // any of its recorded descendants, even if later evidence is unclear.
        self.active = false;
        let published_stat = fstatat_nofollow(destination.fd.as_raw_fd(), target)
            .map_err(|_| DesktopMutationError::Uncertain)?;
        if ident_at(destination.fd.as_raw_fd(), target, &published_stat)
            .map_err(|_| DesktopMutationError::Uncertain)?
            != staged_identity
        {
            return Err(DesktopMutationError::Uncertain);
        }
        let _ = self.remove_empty();
        Ok(())
    }

    fn remove_empty(&mut self) -> Result<(), Error> {
        let held = fstat(self.fd.as_raw_fd())?;
        if ident_fd(self.fd.as_raw_fd(), &held)? != self.identity {
            return Err(Error::Changed);
        }
        let named = fstatat_nofollow(self.parent.fd.as_raw_fd(), &self.name)?;
        if ident_at(self.parent.fd.as_raw_fd(), &self.name, &named)? != self.identity {
            return Err(Error::Changed);
        }
        remove_at(self.parent.fd.as_raw_fd(), &self.name, true)?;
        self.active = false;
        Ok(())
    }

    fn retain(&mut self) {
        self.active = false;
    }
}

impl Drop for StageDir<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        for entry in self.created.iter().rev() {
            let mut parts = entry
                .relative_path
                .split(|byte| *byte == b'/')
                .collect::<Vec<_>>();
            let Some(name_bytes) = parts.pop() else {
                continue;
            };
            let Ok(name) = cstring(name_bytes) else {
                continue;
            };
            let Ok(parent) = open_stage_parent(self.fd.as_raw_fd(), &parts) else {
                continue;
            };
            let Ok(parent_stat) = fstat(parent.as_raw_fd()) else {
                continue;
            };
            if ident_fd(parent.as_raw_fd(), &parent_stat).ok() != Some(entry.parent_identity) {
                continue;
            }
            if let Ok(stat) = fstatat_nofollow(parent.as_raw_fd(), &name) {
                if ident_at(parent.as_raw_fd(), &name, &stat).ok() == Some(entry.identity) {
                    let _ = remove_at(parent.as_raw_fd(), &name, entry.directory);
                }
            }
        }
        if let Ok(named) = fstatat_nofollow(self.parent.fd.as_raw_fd(), &self.name) {
            if ident_at(self.parent.fd.as_raw_fd(), &self.name, &named).ok() == Some(self.identity)
            {
                let _ = remove_at(self.parent.fd.as_raw_fd(), &self.name, true);
            }
        }
    }
}

fn copy_node(
    source_parent: RawFd,
    source_name: &CStr,
    destination_parent: RawFd,
    destination_name: &CStr,
    relative: &mut Vec<Vec<u8>>,
    snapshot: &mut CopySnapshot,
    created: &mut Vec<StagedEntry>,
    created_path_bytes: &mut usize,
    destination_relative: &mut Vec<Vec<u8>>,
    buffer: &mut [u8; COPY_BUFFER],
    check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<(), DesktopFileErrorCode> {
    if relative.len() > 128 {
        return Err(DesktopFileErrorCode::Limit);
    }
    let before = fstatat_nofollow(source_parent, source_name).map_err(desktop_error)?;
    let source_identity = ident_at(source_parent, source_name, &before).map_err(desktop_error)?;
    let kind = kind_of(&before);
    if is_private_staging_name(source_name.to_bytes()) {
        return Err(DesktopFileErrorCode::Protected);
    }
    snapshot
        .record(relative, &before, source_identity)
        .map_err(desktop_error)?;
    match kind {
        Kind::File => {
            let source = openat(
                source_parent,
                source_name,
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                0,
                false,
            )
            .map_err(desktop_error)?;
            let opened = fstat(source.as_raw_fd()).map_err(desktop_error)?;
            if ident_fd(source.as_raw_fd(), &opened).map_err(desktop_error)? != source_identity
                || NativeFileStamp::read(&opened) != NativeFileStamp::read(&before)
            {
                return Err(DesktopFileErrorCode::Changed);
            }
            let destination = create_file_at(destination_parent, destination_name, 0o600)
                .map_err(desktop_error)?;
            let destination_stat = fstat(destination.as_raw_fd()).map_err(desktop_error)?;
            let destination_identity =
                ident_fd(destination.as_raw_fd(), &destination_stat).map_err(desktop_error)?;
            track_staged_entry(
                destination_parent,
                destination_name,
                destination_relative,
                destination_identity,
                false,
                created,
                created_path_bytes,
            )
            .map_err(desktop_error)?;
            let mut input = File::from(source);
            let mut output = File::from(destination);
            loop {
                check(LocalNativeFileCheckPhase::Progress)?;
                let count = input.read(&mut buffer[..]).map_err(|error| {
                    desktop_error(map_errno(error.raw_os_error().unwrap_or(0), false))
                })?;
                if count == 0 {
                    break;
                }
                output.write_all(&buffer[..count]).map_err(|error| {
                    desktop_error(map_errno(error.raw_os_error().unwrap_or(0), false))
                })?;
            }
            let after_fd = fstat(input.as_raw_fd()).map_err(desktop_error)?;
            let after_name = fstatat_nofollow(source_parent, source_name).map_err(desktop_error)?;
            if NativeFileStamp::read(&after_fd) != NativeFileStamp::read(&before)
                || ident_at(source_parent, source_name, &after_name).map_err(desktop_error)?
                    != source_identity
                || NativeFileStamp::read(&after_name) != NativeFileStamp::read(&before)
            {
                return Err(DesktopFileErrorCode::Changed);
            }
            if unsafe {
                libc::fchmod(
                    output.as_raw_fd(),
                    (before.st_mode as u32 & 0o777) as libc::mode_t,
                )
            } != 0
            {
                return Err(desktop_error(map_errno(last_errno(), false)));
            }
            output.flush().map_err(|error| {
                desktop_error(map_errno(error.raw_os_error().unwrap_or(0), false))
            })?;
            Ok(())
        }
        Kind::Directory => {
            let source = openat(
                source_parent,
                source_name,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                0,
                true,
            )
            .map_err(desktop_error)?;
            let opened = fstat(source.as_raw_fd()).map_err(desktop_error)?;
            if ident_fd(source.as_raw_fd(), &opened).map_err(desktop_error)? != source_identity {
                return Err(DesktopFileErrorCode::Changed);
            }
            mkdir_at(destination_parent, destination_name, 0o700).map_err(desktop_error)?;
            let destination_stat =
                fstatat_nofollow(destination_parent, destination_name).map_err(desktop_error)?;
            let destination_identity =
                ident_at(destination_parent, destination_name, &destination_stat)
                    .map_err(desktop_error)?;
            track_staged_entry(
                destination_parent,
                destination_name,
                destination_relative,
                destination_identity,
                true,
                created,
                created_path_bytes,
            )
            .map_err(desktop_error)?;
            let destination = openat(
                destination_parent,
                destination_name,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                0,
                true,
            )
            .map_err(desktop_error)?;
            destination_relative.push(destination_name.to_bytes().to_vec());
            let children = read_desktop_dir_names(source.as_raw_fd()).map_err(desktop_error)?;
            snapshot.children.insert(
                snapshot_key(relative).map_err(desktop_error)?,
                children.clone(),
            );
            for child_bytes in children {
                check(LocalNativeFileCheckPhase::Progress)?;
                let child_name = cstring(&child_bytes).map_err(desktop_error)?;
                relative.push(child_bytes.clone());
                let result = copy_node(
                    source.as_raw_fd(),
                    &child_name,
                    destination.as_raw_fd(),
                    &child_name,
                    relative,
                    snapshot,
                    created,
                    created_path_bytes,
                    destination_relative,
                    buffer,
                    check,
                );
                relative.pop();
                result?;
            }
            destination_relative.pop();
            let after_fd = fstat(source.as_raw_fd()).map_err(desktop_error)?;
            let after_name = fstatat_nofollow(source_parent, source_name).map_err(desktop_error)?;
            if NativeFileStamp::read(&after_fd) != NativeFileStamp::read(&before)
                || ident_at(source_parent, source_name, &after_name).map_err(desktop_error)?
                    != source_identity
                || NativeFileStamp::read(&after_name) != NativeFileStamp::read(&before)
            {
                return Err(DesktopFileErrorCode::Changed);
            }
            if unsafe {
                libc::fchmod(
                    destination.as_raw_fd(),
                    (before.st_mode as u32 & 0o777) as libc::mode_t,
                )
            } != 0
            {
                return Err(desktop_error(map_errno(last_errno(), false)));
            }
            Ok(())
        }
        Kind::Symlink | Kind::Other => Err(DesktopFileErrorCode::Unsupported),
    }
}

fn validate_copy_snapshot(source: &PinnedDir, snapshots: &CopySnapshot) -> Result<(), Error> {
    source.validate()?;
    let root = snapshots.nodes.first().ok_or(Error::Changed)?;
    let root_name = cstring(root.path.first().ok_or(Error::Changed)?)?;
    validate_snapshot_node(
        source.fd.as_raw_fd(),
        &root_name,
        &mut vec![root_name.as_bytes().to_vec()],
        snapshots,
    )
}

fn validate_snapshot_node(
    parent: RawFd,
    name: &CStr,
    relative: &mut Vec<Vec<u8>>,
    snapshots: &CopySnapshot,
) -> Result<(), Error> {
    let before = fstatat_nofollow(parent, name)?;
    let identity = ident_at(parent, name, &before)?;
    let expected = snapshots.get(relative)?;
    if identity != expected.identity || NativeFileStamp::read(&before) != expected.stamp {
        return Err(Error::Changed);
    }
    if kind_of(&before) != Kind::Directory {
        return Ok(());
    }
    let directory = openat(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        0,
        true,
    )?;
    let opened = fstat(directory.as_raw_fd())?;
    if ident_fd(directory.as_raw_fd(), &opened)? != identity {
        return Err(Error::Changed);
    }
    let mut current_names = read_desktop_dir_names(directory.as_raw_fd())?;
    let mut expected_names = snapshots
        .children
        .get(&snapshot_key(relative)?)
        .cloned()
        .ok_or(Error::Changed)?;
    current_names.sort();
    expected_names.sort();
    if current_names != expected_names {
        return Err(Error::Changed);
    }
    for child in expected_names {
        let child_name = cstring(&child)?;
        relative.push(child);
        let result =
            validate_snapshot_node(directory.as_raw_fd(), &child_name, relative, snapshots);
        relative.pop();
        result?;
    }
    let after_fd = fstat(directory.as_raw_fd())?;
    let after_named = fstatat_nofollow(parent, name)?;
    if ident_fd(directory.as_raw_fd(), &after_fd)? != identity
        || ident_at(parent, name, &after_named)? != identity
        || NativeFileStamp::read(&after_fd) != expected.stamp
        || NativeFileStamp::read(&after_named) != expected.stamp
    {
        return Err(Error::Changed);
    }
    Ok(())
}

fn dev(fd: RawFd) -> Result<u64, Error> {
    Ok(fstat(fd)?.st_dev as u64)
}

fn case_only_alias(
    parent: RawFd,
    source_name: &CStr,
    target_name: &CStr,
    source_identity: Ident,
) -> Result<bool, Error> {
    if source_name.to_bytes() == target_name.to_bytes() {
        return Ok(false);
    }
    let (Ok(source_text), Ok(target_text)) = (
        std::str::from_utf8(source_name.to_bytes()),
        std::str::from_utf8(target_name.to_bytes()),
    ) else {
        return Ok(false);
    };
    if source_text.to_lowercase() != target_text.to_lowercase() {
        return Ok(false);
    }
    let target_stat = match fstatat_nofollow(parent, target_name) {
        Ok(stat) => stat,
        Err(Error::NotFound) => return Ok(false),
        Err(error) => return Err(error),
    };
    if ident_at(parent, target_name, &target_stat)? != source_identity {
        return Ok(false);
    }
    Ok(!read_desktop_dir_names(parent)?
        .iter()
        .any(|name| name.as_slice() == target_name.to_bytes()))
}

fn move_entry(
    source: &EntryPin,
    destination_parent: &PinnedDir,
    target_name: &CStr,
    target: &Path,
    request: &DesktopMutationRequest,
    controls: &[ControlPin],
    check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<(), DesktopMutationError> {
    parent_is_controlled(destination_parent, controls)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    let tree =
        scan_selected_directory(source, controls, check).map_err(DesktopMutationError::Before)?;
    let same_parent = source.parent.identity == destination_parent.identity;
    let case_alias = same_parent
        && case_only_alias(
            source.parent.fd.as_raw_fd(),
            &source.name,
            target_name,
            source.identity,
        )
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    if !case_alias {
        require_absent(destination_parent.fd.as_raw_fd(), target_name)
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    }
    if source.kind == Kind::Directory
        && (target.starts_with(&source.absolute)
            || destination_parent.chain.contains(&source.identity))
    {
        return Err(DesktopFileErrorCode::Invalid.into());
    }
    if dev(source.parent.fd.as_raw_fd())
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?
        != dev(destination_parent.fd.as_raw_fd())
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?
    {
        return Err(DesktopFileErrorCode::Unsupported.into());
    }
    phase(check, LocalNativeFileCheckPhase::BeforeEffect).map_err(DesktopMutationError::Before)?;
    phase(check, LocalNativeFileCheckPhase::Validation).map_err(DesktopMutationError::Before)?;
    source
        .validate()
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    if let Some(snapshot) = &tree {
        validate_copy_snapshot(&source.parent, snapshot)
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    }
    check_parent_and_controls(&destination_parent, controls)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    if case_alias {
        if !case_only_alias(
            source.parent.fd.as_raw_fd(),
            &source.name,
            target_name,
            source.identity,
        )
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?
        {
            return Err(DesktopFileErrorCode::Changed.into());
        }
    } else {
        require_absent(destination_parent.fd.as_raw_fd(), target_name)
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    }
    phase(check, LocalNativeFileCheckPhase::Publication).map_err(DesktopMutationError::Before)?;
    source
        .validate()
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    check_parent_and_controls(destination_parent, controls)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    if case_alias {
        let target_stat = fstatat_nofollow(destination_parent.fd.as_raw_fd(), target_name)
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        if ident_at(destination_parent.fd.as_raw_fd(), target_name, &target_stat)
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?
            != source.identity
        {
            return Err(DesktopFileErrorCode::Changed.into());
        }
    } else {
        require_absent(destination_parent.fd.as_raw_fd(), target_name)
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    }
    if case_alias {
        let stage = CString::new(
            desktop_staging_name(&request.operation_id).map_err(DesktopMutationError::Before)?,
        )
        .map_err(|_| DesktopMutationError::Before(DesktopFileErrorCode::Invalid))?;
        require_absent(source.parent.fd.as_raw_fd(), &stage)
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        source
            .validate()
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        no_replace_rename(
            source.parent.fd.as_raw_fd(),
            &source.name,
            source.parent.fd.as_raw_fd(),
            &stage,
        )
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        phase(check, LocalNativeFileCheckPhase::BeforeEffect)
            .map_err(|_| DesktopMutationError::Uncertain)?;
        phase(check, LocalNativeFileCheckPhase::Validation)
            .map_err(|_| DesktopMutationError::Uncertain)?;
        phase(check, LocalNativeFileCheckPhase::Publication)
            .map_err(|_| DesktopMutationError::Uncertain)?;
        check_parent_and_controls(destination_parent, controls)
            .map_err(|_| DesktopMutationError::Uncertain)?;
        let staged = fstatat_nofollow(source.parent.fd.as_raw_fd(), &stage)
            .map_err(|_| DesktopMutationError::Uncertain)?;
        if ident_at(source.parent.fd.as_raw_fd(), &stage, &staged)
            .map_err(|_| DesktopMutationError::Uncertain)?
            != source.identity
        {
            return Err(DesktopMutationError::Uncertain);
        }
        require_absent(destination_parent.fd.as_raw_fd(), target_name)
            .map_err(|_| DesktopMutationError::Uncertain)?;
        if no_replace_rename(
            source.parent.fd.as_raw_fd(),
            &stage,
            destination_parent.fd.as_raw_fd(),
            target_name,
        )
        .is_err()
        {
            return Err(DesktopMutationError::Uncertain);
        }
        let published = fstatat_nofollow(destination_parent.fd.as_raw_fd(), target_name)
            .map_err(|_| DesktopMutationError::Uncertain)?;
        if ident_at(destination_parent.fd.as_raw_fd(), target_name, &published)
            .map_err(|_| DesktopMutationError::Uncertain)?
            != source.identity
        {
            return Err(DesktopMutationError::Uncertain);
        }
    } else {
        source
            .validate()
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        no_replace_rename(
            source.parent.fd.as_raw_fd(),
            &source.name,
            destination_parent.fd.as_raw_fd(),
            target_name,
        )
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        let published = fstatat_nofollow(destination_parent.fd.as_raw_fd(), target_name)
            .map_err(|_| DesktopMutationError::Uncertain)?;
        if ident_at(destination_parent.fd.as_raw_fd(), target_name, &published)
            .map_err(|_| DesktopMutationError::Uncertain)?
            != source.identity
        {
            return Err(DesktopMutationError::Uncertain);
        }
    }
    Ok(())
}

fn copy_or_move(
    request: &DesktopMutationRequest,
    destination_relative: &ComponentPath,
    source_root: &Path,
    source_relative: &str,
    moving: bool,
    expected_source: Option<&DesktopSourcePrecondition>,
    controls: &[ControlPin],
    check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<DesktopFileChange, DesktopMutationError> {
    let destination_parent = PinnedDir::open(&request.root, &destination_relative.0)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    parent_is_controlled(&destination_parent, controls)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    if let Some(expected) = &request.expected_path {
        if expected != &destination_parent.path() {
            return Err(DesktopFileErrorCode::Changed.into());
        }
    }
    let source_path =
        ComponentPath::parse(source_relative, false).map_err(DesktopMutationError::Before)?;
    let source = EntryPin::open(source_root, &source_path)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    check_source_precondition(
        if moving { expected_source } else { None },
        source.identity,
        source.kind,
    )?;
    let source_name = source_path
        .0
        .last()
        .ok_or(DesktopFileErrorCode::Protected)?;
    selected_is_controlled(
        &source.absolute,
        source.identity,
        &source.parent.chain,
        controls,
        source.kind == Kind::Directory,
    )
    .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    let target_name = source_name.clone();
    let target = destination_parent
        .path()
        .join(OsStr::from_bytes(target_name.as_bytes()));
    target_is_controlled(&target, controls)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;

    if moving {
        move_entry(
            &source,
            &destination_parent,
            &target_name,
            &target,
            request,
            controls,
            check,
        )?;
        return Ok(mutation_change(
            request,
            Some(source.absolute),
            Some(target),
            None,
        ));
    }

    if source.kind == Kind::Symlink || source.kind == Kind::Other {
        return Err(DesktopFileErrorCode::Unsupported.into());
    }
    if source.kind == Kind::Directory && target.starts_with(&source.absolute) {
        return Err(DesktopFileErrorCode::Invalid.into());
    }
    require_absent(destination_parent.fd.as_raw_fd(), &target_name)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    let mut stage = StageDir::create(&destination_parent, &request.operation_id)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    let payload =
        cstring(b"payload").map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    let mut snapshots = CopySnapshot {
        nodes: Vec::new(),
        index: HashMap::new(),
        children: HashMap::new(),
        path_bytes: 0,
    };
    let mut copy_buffer = Box::new([0u8; COPY_BUFFER]);
    let mut destination_relative = Vec::new();
    copy_node(
        source.parent.fd.as_raw_fd(),
        &source.name,
        stage.fd.as_raw_fd(),
        &payload,
        &mut vec![source.name.as_bytes().to_vec()],
        &mut snapshots,
        &mut stage.created,
        &mut stage.created_path_bytes,
        &mut destination_relative,
        &mut copy_buffer,
        check,
    )
    .map_err(DesktopMutationError::Before)?;
    if snapshots.nodes.iter().any(|node| {
        controls
            .iter()
            .any(|control| control.identity == node.identity)
    }) {
        return Err(DesktopFileErrorCode::Protected.into());
    }

    phase(check, LocalNativeFileCheckPhase::BeforeEffect).map_err(DesktopMutationError::Before)?;
    phase(check, LocalNativeFileCheckPhase::Validation).map_err(DesktopMutationError::Before)?;
    source
        .parent
        .validate()
        .and_then(|()| validate_copy_snapshot(&source.parent, &snapshots))
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    check_parent_and_controls(&destination_parent, controls)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    require_absent(destination_parent.fd.as_raw_fd(), &target_name)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    phase(check, LocalNativeFileCheckPhase::Publication).map_err(DesktopMutationError::Before)?;
    source
        .validate()
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    check_parent_and_controls(&destination_parent, controls)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    require_absent(destination_parent.fd.as_raw_fd(), &target_name)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    stage.publish(&destination_parent, &target_name)?;
    Ok(mutation_change(request, None, Some(target), None))
}

fn duplicate_entry(
    request: &DesktopMutationRequest,
    relative: &ComponentPath,
    controls: &[ControlPin],
    check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<DesktopFileChange, DesktopMutationError> {
    let source = EntryPin::open(&request.root, relative)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    parent_is_controlled(&source.parent, controls)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    if source.kind == Kind::Symlink || source.kind == Kind::Other {
        return Err(DesktopFileErrorCode::Unsupported.into());
    }
    selected_is_controlled(
        &source.absolute,
        source.identity,
        &source.parent.chain,
        controls,
        source.kind == Kind::Directory,
    )
    .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    let basename = source
        .name
        .to_str()
        .map_err(|_| DesktopMutationError::Before(DesktopFileErrorCode::Invalid))?;
    let mut destination_name = None;
    for index in 1..=crate::desktop::DESKTOP_DUPLICATE_LIMIT {
        let candidate =
            crate::desktop::desktop_duplicate_name(basename, source.kind == Kind::Directory, index)
                .map_err(DesktopMutationError::Before)?;
        crate::desktop::validate_desktop_name(&candidate).map_err(DesktopMutationError::Before)?;
        let candidate = CString::new(candidate)
            .map_err(|_| DesktopMutationError::Before(DesktopFileErrorCode::Invalid))?;
        let path = source
            .parent
            .path()
            .join(OsStr::from_bytes(candidate.as_bytes()));
        target_is_controlled(&path, controls)
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
        match require_absent(source.parent.fd.as_raw_fd(), &candidate) {
            Ok(()) => {
                destination_name = Some(candidate);
                break;
            }
            Err(Error::Exists) => {}
            Err(error) => {
                return Err(DesktopMutationError::Before(desktop_error(error)));
            }
        }
    }
    let destination_name = destination_name.ok_or(DesktopFileErrorCode::Limit)?;
    let destination = source
        .parent
        .path()
        .join(OsStr::from_bytes(destination_name.as_bytes()));
    let mut stage = StageDir::create(&source.parent, &request.operation_id)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    let payload =
        cstring(b"payload").map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    let mut snapshots = CopySnapshot {
        nodes: Vec::new(),
        index: HashMap::new(),
        children: HashMap::new(),
        path_bytes: 0,
    };
    let mut copy_buffer = Box::new([0u8; COPY_BUFFER]);
    let mut destination_relative = Vec::new();
    copy_node(
        source.parent.fd.as_raw_fd(),
        &source.name,
        stage.fd.as_raw_fd(),
        &payload,
        &mut vec![source.name.as_bytes().to_vec()],
        &mut snapshots,
        &mut stage.created,
        &mut stage.created_path_bytes,
        &mut destination_relative,
        &mut copy_buffer,
        check,
    )
    .map_err(DesktopMutationError::Before)?;
    if snapshots.nodes.iter().any(|node| {
        controls
            .iter()
            .any(|control| control.identity == node.identity)
    }) {
        return Err(DesktopFileErrorCode::Protected.into());
    }
    phase(check, LocalNativeFileCheckPhase::BeforeEffect).map_err(DesktopMutationError::Before)?;
    phase(check, LocalNativeFileCheckPhase::Validation).map_err(DesktopMutationError::Before)?;
    source
        .parent
        .validate()
        .and_then(|()| validate_copy_snapshot(&source.parent, &snapshots))
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    check_parent_and_controls(&source.parent, controls)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    require_absent(source.parent.fd.as_raw_fd(), &destination_name)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    phase(check, LocalNativeFileCheckPhase::Publication).map_err(DesktopMutationError::Before)?;
    source
        .validate()
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    check_parent_and_controls(&source.parent, controls)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    require_absent(source.parent.fd.as_raw_fd(), &destination_name)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    stage.publish(&source.parent, &destination_name)?;
    Ok(mutation_change(request, None, Some(destination), None))
}

fn scan_delete_node(
    parent: RawFd,
    name: &CStr,
    relative: &mut Vec<Vec<u8>>,
    snapshot: &mut CopySnapshot,
    check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<(), DesktopFileErrorCode> {
    if relative.len() > 128 {
        return Err(DesktopFileErrorCode::Limit);
    }
    check(LocalNativeFileCheckPhase::Progress)?;
    if is_private_staging_name(name.to_bytes()) {
        return Err(DesktopFileErrorCode::Protected);
    }
    let before = fstatat_nofollow(parent, name).map_err(desktop_error)?;
    let identity = ident_at(parent, name, &before).map_err(desktop_error)?;
    snapshot
        .record(relative, &before, identity)
        .map_err(desktop_error)?;
    if kind_of(&before) == Kind::Directory {
        let directory = openat(
            parent,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
            true,
        )
        .map_err(desktop_error)?;
        let opened = fstat(directory.as_raw_fd()).map_err(desktop_error)?;
        if ident_fd(directory.as_raw_fd(), &opened).map_err(desktop_error)? != identity {
            return Err(DesktopFileErrorCode::Changed);
        }
        let children = read_desktop_dir_names(directory.as_raw_fd()).map_err(desktop_error)?;
        snapshot.children.insert(
            snapshot_key(relative).map_err(desktop_error)?,
            children.clone(),
        );
        for child in children {
            let child_name = cstring(&child).map_err(desktop_error)?;
            relative.push(child);
            let result = scan_delete_node(
                directory.as_raw_fd(),
                &child_name,
                relative,
                snapshot,
                check,
            );
            relative.pop();
            result?;
        }
        let after_fd = fstat(directory.as_raw_fd()).map_err(desktop_error)?;
        let after_name = fstatat_nofollow(parent, name).map_err(desktop_error)?;
        if ident_fd(directory.as_raw_fd(), &after_fd).map_err(desktop_error)? != identity
            || ident_at(parent, name, &after_name).map_err(desktop_error)? != identity
            || NativeFileStamp::read(&after_fd) != NativeFileStamp::read(&before)
            || NativeFileStamp::read(&after_name) != NativeFileStamp::read(&before)
        {
            return Err(DesktopFileErrorCode::Changed);
        }
    }
    Ok(())
}

fn scan_selected_directory(
    entry: &EntryPin,
    controls: &[ControlPin],
    check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<Option<CopySnapshot>, DesktopFileErrorCode> {
    if entry.kind != Kind::Directory {
        return Ok(None);
    }
    let mut snapshot = CopySnapshot {
        nodes: Vec::new(),
        index: HashMap::new(),
        children: HashMap::new(),
        path_bytes: 0,
    };
    scan_delete_node(
        entry.parent.fd.as_raw_fd(),
        &entry.name,
        &mut vec![entry.name.as_bytes().to_vec()],
        &mut snapshot,
        check,
    )?;
    if snapshot.nodes.iter().any(|node| {
        controls
            .iter()
            .any(|control| control.identity == node.identity)
    }) {
        return Err(DesktopFileErrorCode::Protected);
    }
    Ok(Some(snapshot))
}

fn snapshot_path_stat(
    root_parent: &PinnedDir,
    snapshot: &CopySnapshot,
    path: &[Vec<u8>],
) -> Result<libc::stat, Error> {
    if path.is_empty() {
        return Err(Error::Changed);
    }
    root_parent.validate()?;
    let mut parent = dup(root_parent.fd.as_raw_fd())?;
    let mut prefix = Vec::with_capacity(path.len());
    for (index, component) in path.iter().enumerate() {
        let name = cstring(component)?;
        let stat = fstatat_nofollow(parent.as_raw_fd(), &name)?;
        let identity = ident_at(parent.as_raw_fd(), &name, &stat)?;
        prefix.push(component.clone());
        let expected = snapshot.get(&prefix)?;
        if identity != expected.identity {
            return Err(Error::Changed);
        }
        if index + 1 == path.len() {
            return Ok(stat);
        }
        if kind_of(&stat) != Kind::Directory {
            return Err(Error::Changed);
        }
        let next = openat(
            parent.as_raw_fd(),
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
            true,
        )?;
        let held = fstat(next.as_raw_fd())?;
        if ident_fd(next.as_raw_fd(), &held)? != identity {
            return Err(Error::Changed);
        }
        parent = next;
    }
    Err(Error::Changed)
}

fn validate_snapshot_path(
    root_parent: &PinnedDir,
    snapshot: &CopySnapshot,
    path: &[Vec<u8>],
    expected_stamp: Option<NativeFileStamp>,
) -> Result<(), Error> {
    root_parent.validate()?;
    let mut parent = dup(root_parent.fd.as_raw_fd())?;
    let mut prefix = Vec::with_capacity(path.len());
    for (index, component) in path.iter().enumerate() {
        let name = cstring(component)?;
        let stat = fstatat_nofollow(parent.as_raw_fd(), &name)?;
        let identity = ident_at(parent.as_raw_fd(), &name, &stat)?;
        prefix.push(component.clone());
        let expected = snapshot.get(&prefix)?;
        if identity != expected.identity
            || (index + 1 == path.len()
                && expected_stamp.is_some_and(|stamp| NativeFileStamp::read(&stat) != stamp))
        {
            return Err(Error::Changed);
        }
        if index + 1 < path.len() {
            if kind_of(&stat) != Kind::Directory {
                return Err(Error::Changed);
            }
            let next = openat(
                parent.as_raw_fd(),
                &name,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                0,
                true,
            )?;
            let held = fstat(next.as_raw_fd())?;
            if ident_fd(next.as_raw_fd(), &held)? != identity {
                return Err(Error::Changed);
            }
            parent = next;
        }
    }
    Ok(())
}

fn remove_node(
    root_parent: &PinnedDir,
    controls: &[ControlPin],
    parent: RawFd,
    name: &CStr,
    relative: &mut Vec<Vec<u8>>,
    snapshot: &CopySnapshot,
    aliases: &mut DeleteAliasLedger,
    changed: &mut bool,
    check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<(), DesktopFileErrorCode> {
    let node = snapshot.get(relative).map_err(desktop_error)?;
    let stat = fstatat_nofollow(parent, name).map_err(desktop_error)?;
    let identity = ident_at(parent, name, &stat).map_err(desktop_error)?;
    if identity != node.identity {
        return Err(DesktopFileErrorCode::Changed);
    }
    let directory = kind_of(&stat) == Kind::Directory;
    if directory {
        let child_dir = openat(
            parent,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
            true,
        )
        .map_err(desktop_error)?;
        let opened = fstat(child_dir.as_raw_fd()).map_err(desktop_error)?;
        if ident_fd(child_dir.as_raw_fd(), &opened).map_err(desktop_error)? != node.identity {
            return Err(DesktopFileErrorCode::Changed);
        }
        let mut current_names =
            read_desktop_dir_names(child_dir.as_raw_fd()).map_err(desktop_error)?;
        let mut expected_names = snapshot
            .children
            .get(&snapshot_key(relative).map_err(desktop_error)?)
            .cloned()
            .ok_or(DesktopFileErrorCode::Changed)?;
        current_names.sort();
        expected_names.sort();
        if current_names != expected_names {
            return Err(DesktopFileErrorCode::Changed);
        }
        for child in expected_names {
            let child_name = cstring(&child).map_err(desktop_error)?;
            relative.push(child);
            let result = remove_node(
                root_parent,
                controls,
                child_dir.as_raw_fd(),
                &child_name,
                relative,
                snapshot,
                aliases,
                changed,
                check,
            );
            relative.pop();
            result?;
        }
    } else {
        aliases
            .validate_stat(identity, &stat)
            .map_err(desktop_error)?;
    }
    check(LocalNativeFileCheckPhase::BeforeEffect)?;
    check(LocalNativeFileCheckPhase::Validation)?;
    check_parent_and_controls(root_parent, controls).map_err(desktop_error)?;
    let expected_stamp = if directory {
        None
    } else {
        Some(aliases.expected_stamp(identity).map_err(desktop_error)?)
    };
    validate_snapshot_path(root_parent, snapshot, relative, expected_stamp)
        .map_err(desktop_error)?;
    check(LocalNativeFileCheckPhase::Publication)?;
    validate_snapshot_path(root_parent, snapshot, relative, expected_stamp)
        .map_err(desktop_error)?;
    let final_stat = fstatat_nofollow(parent, name).map_err(desktop_error)?;
    if ident_at(parent, name, &final_stat).map_err(desktop_error)? != node.identity
        || kind_of(&final_stat) != kind_of(&stat)
        || (!directory && aliases.validate_stat(identity, &final_stat).is_err())
    {
        return Err(DesktopFileErrorCode::Changed);
    }
    if directory {
        let final_directory = openat(
            parent,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
            true,
        )
        .map_err(desktop_error)?;
        let mut current_names =
            read_desktop_dir_names(final_directory.as_raw_fd()).map_err(desktop_error)?;
        current_names.sort();
        if !current_names.is_empty() {
            return Err(DesktopFileErrorCode::Changed);
        }
    }
    if remove_at(parent, name, directory).is_err() {
        return Err(DesktopFileErrorCode::Io);
    }
    *changed = true;
    if !directory {
        aliases
            .record_removed(root_parent, snapshot, relative, identity)
            .map_err(desktop_error)?;
    }
    Ok(())
}

fn delete_entry(
    request: &DesktopMutationRequest,
    relative: &ComponentPath,
    expected_source: Option<&DesktopSourcePrecondition>,
    controls: &[ControlPin],
    check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<DesktopFileChange, DesktopMutationError> {
    let target = EntryPin::open(&request.root, relative)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    check_source_precondition(expected_source, target.identity, target.kind)?;
    selected_is_controlled(
        &target.absolute,
        target.identity,
        &target.parent.chain,
        controls,
        target.kind == Kind::Directory,
    )
    .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    if let Some(expected) = &request.expected_path {
        if expected != &target.absolute {
            return Err(DesktopFileErrorCode::Changed.into());
        }
    }
    let mut snapshot = CopySnapshot {
        nodes: Vec::new(),
        index: HashMap::new(),
        children: HashMap::new(),
        path_bytes: 0,
    };
    scan_delete_node(
        target.parent.fd.as_raw_fd(),
        &target.name,
        &mut vec![target.name.as_bytes().to_vec()],
        &mut snapshot,
        check,
    )
    .map_err(DesktopMutationError::Before)?;
    if snapshot.nodes.iter().any(|node| {
        controls
            .iter()
            .any(|control| control.identity == node.identity)
    }) {
        return Err(DesktopFileErrorCode::Protected.into());
    }
    let mut aliases = DeleteAliasLedger::from_snapshot(&snapshot)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    target
        .validate()
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    validate_copy_snapshot(&target.parent, &snapshot)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    check_parent_and_controls(&target.parent, controls)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    let mut changed = false;
    match remove_node(
        &target.parent,
        controls,
        target.parent.fd.as_raw_fd(),
        &target.name,
        &mut vec![target.name.as_bytes().to_vec()],
        &snapshot,
        &mut aliases,
        &mut changed,
        check,
    ) {
        Ok(()) => Ok(mutation_change(request, Some(target.absolute), None, None)),
        Err(_code) if changed => Err(DesktopMutationError::Uncertain),
        Err(code) => Err(DesktopMutationError::Before(code)),
    }
}

fn trash_entry(
    request: &DesktopMutationRequest,
    relative: &ComponentPath,
    expected_source: Option<&DesktopSourcePrecondition>,
    controls: &[ControlPin],
    check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
) -> Result<DesktopFileChange, DesktopMutationError> {
    let target = EntryPin::open(&request.root, relative)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    check_source_precondition(expected_source, target.identity, target.kind)?;
    selected_is_controlled(
        &target.absolute,
        target.identity,
        &target.parent.chain,
        controls,
        target.kind == Kind::Directory,
    )
    .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    if let Some(expected) = &request.expected_path {
        if expected != &target.absolute {
            return Err(DesktopFileErrorCode::Changed.into());
        }
    }
    let tree =
        scan_selected_directory(&target, controls, check).map_err(DesktopMutationError::Before)?;
    let mut stage = StageDir::create(&target.parent, &request.operation_id)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    let staged_path = stage.path().join(OsStr::from_bytes(target.name.as_bytes()));
    phase(check, LocalNativeFileCheckPhase::BeforeEffect).map_err(DesktopMutationError::Before)?;
    phase(check, LocalNativeFileCheckPhase::Validation).map_err(DesktopMutationError::Before)?;
    target
        .validate()
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    if let Some(snapshot) = &tree {
        validate_copy_snapshot(&target.parent, snapshot)
            .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    }
    check_parent_and_controls(&target.parent, controls)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    stage
        .validate()
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    require_absent(stage.fd.as_raw_fd(), &target.name)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    phase(check, LocalNativeFileCheckPhase::Publication).map_err(DesktopMutationError::Before)?;
    target
        .validate()
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    check_parent_and_controls(&target.parent, controls)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    stage
        .validate()
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    require_absent(stage.fd.as_raw_fd(), &target.name)
        .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    no_replace_rename(
        target.parent.fd.as_raw_fd(),
        &target.name,
        stage.fd.as_raw_fd(),
        &target.name,
    )
    .map_err(|error| DesktopMutationError::Before(desktop_error(error)))?;
    // The original entry has moved. From this point on, retain it on every
    // error; cleanup must never turn an uncertain Trash handoff into deletion.
    stage.retain();
    let entry_stat = fstatat_nofollow(stage.fd.as_raw_fd(), &target.name)
        .map_err(|_| DesktopMutationError::Uncertain)?;
    let entry_identity = ident_at(stage.fd.as_raw_fd(), &target.name, &entry_stat)
        .map_err(|_| DesktopMutationError::Uncertain)?;
    if entry_identity != target.identity {
        return Err(DesktopMutationError::Uncertain);
    }
    let parent_stat =
        fstat(target.parent.fd.as_raw_fd()).map_err(|_| DesktopMutationError::Uncertain)?;
    let parent_identity = ident_fd(target.parent.fd.as_raw_fd(), &parent_stat)
        .map_err(|_| DesktopMutationError::Uncertain)?;
    let ticket = DesktopTrashTicket {
        version: 1,
        operation_id: request.operation_id.clone(),
        root: request.root.clone(),
        original_path: target.absolute.clone(),
        staging_directory: stage.path(),
        staged_path,
        root_identity: identity(target.parent.root.identity),
        parent_identity: identity(parent_identity),
        staging_identity: identity(stage.identity),
        entry_identity: identity(entry_identity),
        kind: file_kind(target.kind),
    };
    Ok(mutation_change(
        request,
        Some(target.absolute),
        None,
        Some(ticket),
    ))
}

pub(crate) fn finish_trash<E>(
    ticket: &DesktopTrashTicket,
    transfer: impl FnOnce(&Path) -> Result<(), E>,
) -> Result<(), DesktopTrashError<E>> {
    ticket.validate_shape().map_err(DesktopTrashError::Before)?;
    let relative = ticket
        .original_path
        .strip_prefix(&ticket.root)
        .map_err(|_| DesktopTrashError::Before(DesktopFileErrorCode::Invalid))?;
    let relative = ComponentPath::parse(
        relative
            .to_str()
            .ok_or(DesktopTrashError::Before(DesktopFileErrorCode::Invalid))?,
        false,
    )
    .map_err(DesktopTrashError::Before)?;
    let target_parent_relative = relative
        .0
        .split_last()
        .ok_or(DesktopTrashError::Before(DesktopFileErrorCode::Invalid))?
        .1
        .to_vec();
    let parent = PinnedDir::open(&ticket.root, &target_parent_relative)
        .map_err(|error| DesktopTrashError::Before(desktop_error(error)))?;
    let parent_stat = fstat(parent.fd.as_raw_fd())
        .map_err(|error| DesktopTrashError::Before(desktop_error(error)))?;
    if identity(
        ident_fd(parent.fd.as_raw_fd(), &parent_stat)
            .map_err(|error| DesktopTrashError::Before(desktop_error(error)))?,
    ) != ticket.parent_identity
        || identity(parent.root.identity) != ticket.root_identity
    {
        return Err(DesktopTrashError::Before(DesktopFileErrorCode::Changed));
    }
    let staging_name = ticket
        .staging_directory
        .file_name()
        .and_then(OsStr::to_str)
        .and_then(|value| CString::new(value).ok())
        .ok_or(DesktopTrashError::Before(DesktopFileErrorCode::Invalid))?;
    let staging_fd = openat(
        parent.fd.as_raw_fd(),
        &staging_name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        0,
        true,
    )
    .map_err(|error| DesktopTrashError::Before(desktop_error(error)))?;
    let staging_stat = fstat(staging_fd.as_raw_fd())
        .map_err(|error| DesktopTrashError::Before(desktop_error(error)))?;
    let staging_identity = ident_fd(staging_fd.as_raw_fd(), &staging_stat)
        .map_err(|error| DesktopTrashError::Before(desktop_error(error)))?;
    if identity(staging_identity) != ticket.staging_identity {
        return Err(DesktopTrashError::Before(DesktopFileErrorCode::Changed));
    }
    let staged_name = ticket
        .staged_path
        .file_name()
        .and_then(OsStr::to_str)
        .and_then(|value| CString::new(value).ok())
        .ok_or(DesktopTrashError::Before(DesktopFileErrorCode::Invalid))?;
    let staged_stat = fstatat_nofollow(staging_fd.as_raw_fd(), &staged_name)
        .map_err(|error| DesktopTrashError::Before(desktop_error(error)))?;
    let staged_identity = ident_at(staging_fd.as_raw_fd(), &staged_name, &staged_stat)
        .map_err(|error| DesktopTrashError::Before(desktop_error(error)))?;
    if identity(staged_identity) != ticket.entry_identity
        || file_kind(kind_of(&staged_stat)) != ticket.kind
    {
        return Err(DesktopTrashError::Before(DesktopFileErrorCode::Changed));
    }
    // Hold an additional leaf handle when the kernel can open it without
    // following links. Parent and staging descriptors always remain pinned.
    let leaf_pin = match kind_of(&staged_stat) {
        Kind::Directory => openat(
            staging_fd.as_raw_fd(),
            &staged_name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
            true,
        )
        .ok(),
        Kind::File => openat(
            staging_fd.as_raw_fd(),
            &staged_name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0,
            false,
        )
        .ok(),
        Kind::Symlink => Some(
            open_symlink_pin(staging_fd.as_raw_fd(), &staged_name)
                .map_err(|error| DesktopTrashError::Before(desktop_error(error)))?,
        ),
        _ => None,
    };
    if let Some(leaf) = &leaf_pin {
        let held = fstat(leaf.as_raw_fd())
            .map_err(|error| DesktopTrashError::Before(desktop_error(error)))?;
        if ident_fd(leaf.as_raw_fd(), &held)
            .map_err(|error| DesktopTrashError::Before(desktop_error(error)))?
            != staged_identity
        {
            return Err(DesktopTrashError::Before(DesktopFileErrorCode::Changed));
        }
    }
    let result = transfer(&ticket.staged_path);
    if result.is_ok() {
        if read_desktop_dir_names(staging_fd.as_raw_fd()).is_ok_and(|names| names.is_empty()) {
            if let Ok(named) = fstatat_nofollow(parent.fd.as_raw_fd(), &staging_name) {
                if ident_at(parent.fd.as_raw_fd(), &staging_name, &named).ok()
                    == Some(staging_identity)
                {
                    let _ = remove_at(parent.fd.as_raw_fd(), &staging_name, true);
                }
            }
        }
    }
    result.map_err(DesktopTrashError::Transfer)
}
