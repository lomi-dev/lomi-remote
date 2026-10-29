//! Handle-relative owner-local Explorer mutations for Windows.
//!
//! Roots and every relative ancestor are opened without following reparse
//! points. Public results are staged beside the destination and published by
//! a no-replace handle-relative rename. The UI callback is never invoked after
//! the final local validation/publication checkpoint.

use super::*;
use crate::LocalNativeFileCheckPhase;
use crate::desktop::{
    DesktopFileChange, DesktopFileErrorCode, DesktopFileKind, DesktopMutationError,
    DesktopMutationRequest, DesktopSourcePrecondition, DesktopTrashError, DesktopTrashTicket,
    desktop_staging_name, validate_desktop_request,
};
use std::collections::VecDeque;
use std::ffi::c_void;
use std::io::{Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;

type DResult<T> = std::result::Result<T, DesktopFileErrorCode>;

const DESKTOP_MAX_NODES: usize = 200_000;
const DESKTOP_MAX_DEPTH: usize = 128;
const DESKTOP_MAX_METADATA_BYTES: usize = 32 * 1024 * 1024;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const FILE_ATTRIBUTE_COPY_MASK: u32 = FILE_ATTRIBUTE_ARCHIVE
    | FILE_ATTRIBUTE_HIDDEN
    | FILE_ATTRIBUTE_SYSTEM
    | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
    | FILE_ATTRIBUTE_TEMPORARY
    | FILE_ATTRIBUTE_READONLY
    | FILE_ATTRIBUTE_NORMAL;
const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x0000_0200;
const FILE_ATTRIBUTE_COMPRESSED: u32 = 0x0000_0800;
const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x0000_4000;
const FILE_ATTRIBUTE_COPY_STORAGE_MASK: u32 =
    FILE_ATTRIBUTE_SPARSE_FILE | FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_ENCRYPTED;

#[derive(Clone, Debug)]
struct PathNode {
    name: Vec<u16>,
    ident: Option<Ident>,
}

struct PinnedRoot {
    input_path: PathBuf,
    canonical_path: PathBuf,
    directory_access: u32,
    handle: OwnedHandle,
    info: Info,
    nodes: Vec<PathNode>,
}

pub(crate) fn pin_namespace_directory(
    path: &Path,
) -> DResult<(File, crate::desktop::DesktopFileIdentity)> {
    let pin = PinnedRoot::open(path, false)?;
    let directory_identity = identity_dto(pin.info.ident);
    Ok((File::from(pin.handle), directory_identity))
}

pub(crate) fn namespace_exact_child(
    parent: &File,
    name: &std::ffi::OsStr,
    check: &mut impl FnMut() -> std::result::Result<(), DesktopFileErrorCode>,
) -> std::result::Result<Option<DesktopSourcePrecondition>, DesktopFileErrorCode> {
    let text = name.to_str().ok_or(DesktopFileErrorCode::Invalid)?;
    if !super::valid_component(text) {
        return Err(DesktopFileErrorCode::Invalid);
    }
    let name_bytes = text.as_bytes();
    let name_wide: Vec<u16> = text.encode_utf16().collect();
    check()?;
    let names = read_dir_names(parent.as_raw_handle()).map_err(desktop_error)?;
    check()?;
    let mut found = false;
    for entry in names {
        check()?;
        if entry == name_bytes {
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
    let handle = open_relative(
        parent.as_raw_handle(),
        &name_wide,
        ATTRIBUTE_ACCESS,
        FILE_OPEN,
        FILE_OPEN_REPARSE_POINT | FILE_OPEN_NO_RECALL | SYNC,
        0,
        false,
    )
    .map_err(desktop_error)?;
    let info = info(handle.as_raw_handle())?;
    let result = DesktopSourcePrecondition {
        identity: identity_dto(info.ident),
        kind: desktop_kind(&info),
    };
    check()?;
    Ok(Some(result))
}

struct PinnedDir {
    handle: OwnedHandle,
    info: Info,
    path: PathBuf,
    relative: Vec<Vec<u8>>,
    nodes: Vec<PathNode>,
}

struct ResolvedEntry {
    parent: PinnedDir,
    name: Vec<u8>,
    handle: OwnedHandle,
    info: Info,
    path: PathBuf,
    nodes: Vec<PathNode>,
}

struct ControlRoot {
    root: PinnedRoot,
}

impl ControlRoot {
    fn nodes(&self) -> &[PathNode] {
        &self.root.nodes
    }
}

struct StageEntry {
    relative: Vec<Vec<u16>>,
    ident: Ident,
    directory: bool,
}

struct StageGuard {
    parent: OwnedHandle,
    parent_info: Info,
    name: Vec<u16>,
    handle: OwnedHandle,
    info: Info,
    directory: bool,
    entries: Vec<StageEntry>,
    cleanup_bytes: usize,
    published: bool,
    cleaned: bool,
}

#[derive(Clone)]
struct SnapshotEntry {
    relative: Vec<Vec<u8>>,
    info: Info,
    kind: Kind,
}

#[derive(Default)]
struct TreeSnapshot {
    entries: Vec<SnapshotEntry>,
    total_bytes: u64,
    metadata_bytes: usize,
}

impl TreeSnapshot {
    fn record(&mut self, relative: Vec<Vec<u8>>, info: Info, kind: Kind) -> DResult<()> {
        if self.entries.len() >= DESKTOP_MAX_NODES {
            return Err(DesktopFileErrorCode::Limit);
        }
        let mut cost = size_of::<SnapshotEntry>()
            .checked_add(size_of::<Vec<Vec<u8>>>())
            .and_then(|value| {
                relative
                    .len()
                    .checked_mul(size_of::<Vec<u8>>())
                    .and_then(|items| value.checked_add(items))
            })
            .ok_or(DesktopFileErrorCode::Limit)?;
        for name in &relative {
            cost = cost
                .checked_add(name.len())
                .ok_or(DesktopFileErrorCode::Limit)?;
        }
        let next = self
            .metadata_bytes
            .checked_add(cost)
            .ok_or(DesktopFileErrorCode::Limit)?;
        if next > DESKTOP_MAX_METADATA_BYTES {
            return Err(DesktopFileErrorCode::Limit);
        }
        self.entries.push(SnapshotEntry {
            relative,
            info,
            kind,
        });
        self.metadata_bytes = next;
        Ok(())
    }
}

struct DeleteEntry {
    parent: OwnedHandle,
    parent_path: PathBuf,
    name: Vec<u16>,
    handle: OwnedHandle,
    info: Info,
    directory: bool,
    directory_handle: Option<OwnedHandle>,
    path_nodes: Vec<PathNode>,
}

struct DeletePlan {
    entries: Vec<DeleteEntry>,
}

struct StageSecurityDescriptor(*mut c_void);

impl Drop for StageSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

struct PrivateStageSecurity {
    descriptor: StageSecurityDescriptor,
    owner_sid: String,
}

impl PrivateStageSecurity {
    fn current_user_and_system() -> DResult<Self> {
        let owner_sid =
            super::current_process_user_sid().map_err(|_| DesktopFileErrorCode::Protected)?;
        let sddl = format!("O:{owner_sid}D:P(A;;FA;;;SY)(A;;FA;;;{owner_sid})");
        let wide = sddl
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
            || descriptor.is_null()
        {
            if !descriptor.is_null() {
                unsafe { LocalFree(descriptor) };
            }
            return Err(DesktopFileErrorCode::Protected);
        }
        Ok(Self {
            descriptor: StageSecurityDescriptor(descriptor),
            owner_sid,
        })
    }

    fn verify_new_object(&self, handle: RawHandle) -> DResult<()> {
        let mut owner = null_mut();
        let mut dacl = null_mut();
        let mut descriptor = null_mut();
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 || owner.is_null() || dacl.is_null() || descriptor.is_null() {
            if !descriptor.is_null() {
                unsafe { LocalFree(descriptor) };
            }
            return Err(DesktopFileErrorCode::Protected);
        }
        let actual_descriptor = StageSecurityDescriptor(descriptor);
        let mut owner_text = null_mut();
        if unsafe { ConvertSidToStringSidW(owner, &mut owner_text) } == 0 || owner_text.is_null() {
            if !owner_text.is_null() {
                unsafe { LocalFree(owner_text.cast()) };
            }
            return Err(DesktopFileErrorCode::Protected);
        }
        let mut owner_len = 0usize;
        while owner_len < 256 && unsafe { *owner_text.add(owner_len) } != 0 {
            owner_len += 1;
        }
        let actual_owner = if owner_len < 256 {
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(owner_text, owner_len) })
        } else {
            String::new()
        };
        unsafe { LocalFree(owner_text.cast()) };
        let mut actual_present = 0;
        let mut actual_dacl = null_mut();
        let mut defaulted = 0;
        let mut actual_control = 0u16;
        let mut revision = 0u32;
        let mut expected_present = 0;
        let mut expected_dacl = null_mut();
        let mut expected_defaulted = 0;
        if unsafe {
            GetSecurityDescriptorDacl(
                actual_descriptor.0,
                &mut actual_present,
                &mut actual_dacl,
                &mut defaulted,
            )
        } == 0
            || unsafe {
                GetSecurityDescriptorControl(
                    actual_descriptor.0,
                    &mut actual_control,
                    &mut revision,
                )
            } == 0
            || unsafe {
                GetSecurityDescriptorDacl(
                    self.descriptor.0,
                    &mut expected_present,
                    &mut expected_dacl,
                    &mut expected_defaulted,
                )
            } == 0
            || actual_present == 0
            || expected_present == 0
            || actual_dacl.is_null()
            || expected_dacl.is_null()
            || actual_control & SE_DACL_PROTECTED == 0
            || actual_owner != self.owner_sid
            || unsafe { (*actual_dacl).AclSize } != unsafe { (*expected_dacl).AclSize }
            || unsafe {
                std::slice::from_raw_parts(
                    actual_dacl.cast::<u8>(),
                    (*actual_dacl).AclSize as usize,
                )
            } != unsafe {
                std::slice::from_raw_parts(
                    expected_dacl.cast::<u8>(),
                    (*expected_dacl).AclSize as usize,
                )
            }
        {
            return Err(DesktopFileErrorCode::Protected);
        }
        Ok(())
    }
}

fn unprotect_stage_dacl(handle: RawHandle) -> DResult<()> {
    let mut dacl = null_mut();
    let mut descriptor = null_mut();
    let query_status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if query_status != 0 || dacl.is_null() || descriptor.is_null() {
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor) };
        }
        return Err(DesktopFileErrorCode::Protected);
    }
    let descriptor = StageSecurityDescriptor(descriptor);
    let set_status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null_mut(),
        )
    };
    drop(descriptor);
    if set_status != 0 {
        return Err(DesktopFileErrorCode::Protected);
    }
    let mut updated_descriptor = null_mut();
    let query_status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut updated_descriptor,
        )
    };
    if query_status != 0 || updated_descriptor.is_null() {
        if !updated_descriptor.is_null() {
            unsafe { LocalFree(updated_descriptor) };
        }
        return Err(DesktopFileErrorCode::Protected);
    }
    let updated_descriptor = StageSecurityDescriptor(updated_descriptor);
    let mut control = 0u16;
    let mut revision = 0u32;
    if unsafe { GetSecurityDescriptorControl(updated_descriptor.0, &mut control, &mut revision) }
        == 0
        || control & SE_DACL_PROTECTED != 0
    {
        return Err(DesktopFileErrorCode::Protected);
    }
    Ok(())
}

fn desktop_error(error: Error) -> DesktopFileErrorCode {
    match error {
        Error::NotFound => DesktopFileErrorCode::NotFound,
        Error::Changed => DesktopFileErrorCode::Changed,
        Error::Protected => DesktopFileErrorCode::Protected,
        Error::NotEmpty => DesktopFileErrorCode::NotEmpty,
        Error::Exists => DesktopFileErrorCode::Exists,
        Error::Invalid => DesktopFileErrorCode::Invalid,
        Error::Unsupported => DesktopFileErrorCode::Unsupported,
        Error::Limit => DesktopFileErrorCode::Limit,
        Error::Io(_) => DesktopFileErrorCode::Io,
    }
}

fn d<T>(result: Result<T>) -> DResult<T> {
    result.map_err(desktop_error)
}

fn io_code(error: std::io::Error) -> DesktopFileErrorCode {
    match error.kind() {
        std::io::ErrorKind::NotFound => DesktopFileErrorCode::NotFound,
        std::io::ErrorKind::AlreadyExists => DesktopFileErrorCode::Exists,
        std::io::ErrorKind::PermissionDenied => DesktopFileErrorCode::Protected,
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData => {
            DesktopFileErrorCode::Invalid
        }
        _ => DesktopFileErrorCode::Io,
    }
}

fn same_info(a: &Info, b: &Info) -> bool {
    a.ident == b.ident
        && a.attributes == b.attributes
        && a.size == b.size
        && a.nlink == b.nlink
        && a.last_write == b.last_write
        && a.change == b.change
}

fn same_directory(a: &Info, b: &Info) -> bool {
    a.ident == b.ident
        && kind_of(a) == Kind::Directory
        && kind_of(b) == Kind::Directory
        && a.attributes == b.attributes
}

fn info(handle: RawHandle) -> DResult<Info> {
    d(info_of(handle))
}

fn utf8_name(name: &std::ffi::OsStr) -> DResult<Vec<u8>> {
    let text = name.to_str().ok_or(DesktopFileErrorCode::Invalid)?;
    component(text.as_bytes()).map_err(desktop_error)?;
    Ok(text.as_bytes().to_vec())
}

fn relative_names(relative: &str) -> DResult<Vec<Vec<u8>>> {
    let mut names = Vec::new();
    for part in Path::new(relative).components() {
        match part {
            Component::CurDir => {}
            Component::Normal(name) => names.push(utf8_name(name)?),
            _ => return Err(DesktopFileErrorCode::Invalid),
        }
        if names.len() > DESKTOP_MAX_DEPTH {
            return Err(DesktopFileErrorCode::Limit);
        }
    }
    Ok(names)
}

fn open_volume_root(prefix: &std::ffi::OsStr, access: u32) -> DResult<(OwnedHandle, Info)> {
    let mut path = PathBuf::from(prefix);
    path.push(std::path::MAIN_SEPARATOR.to_string());
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let handle = open_createfilew(access, |access| {
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                access,
                SHARE_ALL,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        (raw, unsafe { GetLastError() })
    })
    .map_err(desktop_error)?;
    let info = info(handle.as_raw_handle())?;
    if kind_of(&info) != Kind::Directory {
        return Err(DesktopFileErrorCode::Changed);
    }
    Ok((handle, info))
}

impl PinnedRoot {
    fn open(path: &Path, writable: bool) -> DResult<Self> {
        if !path.is_absolute()
            || path.as_os_str().len() > 32_768
            || path
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        {
            return Err(DesktopFileErrorCode::Invalid);
        }
        let canonical_path = std::fs::canonicalize(path).map_err(io_code)?;
        let directory_access = if writable {
            GIT_DIRECTORY_ACCESS
        } else {
            DIRECTORY_ACCESS
        };
        let mut components = path.components();
        let prefix = match components.next() {
            Some(Component::Prefix(prefix))
                if matches!(
                    prefix.kind(),
                    Prefix::Disk(_)
                        | Prefix::VerbatimDisk(_)
                        | Prefix::UNC(_, _)
                        | Prefix::VerbatimUNC(_, _)
                ) =>
            {
                prefix
            }
            _ => return Err(DesktopFileErrorCode::Invalid),
        };
        if !matches!(components.next(), Some(Component::RootDir)) {
            return Err(DesktopFileErrorCode::Invalid);
        }
        let (mut handle, root_info) = open_volume_root(prefix.as_os_str(), directory_access)?;
        let mut nodes = vec![PathNode {
            name: Vec::new(),
            ident: Some(root_info.ident),
        }];
        for part in components {
            let Component::Normal(name) = part else {
                return Err(DesktopFileErrorCode::Invalid);
            };
            let name = utf8_name(name)?;
            let next = open_relative(
                handle.as_raw_handle(),
                &component(&name).map_err(desktop_error)?,
                directory_access,
                FILE_OPEN,
                DIRECTORY_OPTIONS,
                0,
                true,
            )
            .map_err(desktop_error)?;
            let next_info = info(next.as_raw_handle())?;
            if kind_of(&next_info) != Kind::Directory {
                return Err(DesktopFileErrorCode::Changed);
            }
            nodes.push(PathNode {
                name: String::from_utf8(name.clone())
                    .map_err(|_| DesktopFileErrorCode::Invalid)?
                    .encode_utf16()
                    .collect(),
                ident: Some(next_info.ident),
            });
            handle = next;
        }
        let info = info(handle.as_raw_handle())?;
        if kind_of(&info) != Kind::Directory {
            return Err(DesktopFileErrorCode::Changed);
        }
        native_final_path(handle.as_raw_handle(), &canonical_path).map_err(
            |error| match error {
                LocalNativeFileError::Changed => DesktopFileErrorCode::Changed,
                LocalNativeFileError::Invalid => DesktopFileErrorCode::Invalid,
                _ => DesktopFileErrorCode::Io,
            },
        )?;
        Ok(Self {
            input_path: path.to_path_buf(),
            canonical_path,
            directory_access,
            handle,
            info,
            nodes,
        })
    }

    fn revalidate(&self) -> DResult<()> {
        let reopened = Self::open(
            &self.input_path,
            self.directory_access == GIT_DIRECTORY_ACCESS,
        )?;
        if reopened.canonical_path != self.canonical_path
            || reopened.nodes.len() != self.nodes.len()
            || !reopened
                .nodes
                .iter()
                .zip(&self.nodes)
                .all(|(actual, expected)| {
                    actual.ident == expected.ident
                        && fold_wide(&actual.name) == fold_wide(&expected.name)
                })
            || !same_directory(&reopened.info, &self.info)
        {
            return Err(DesktopFileErrorCode::Changed);
        }
        Ok(())
    }

    fn open_dir(&self, relative: &[Vec<u8>]) -> DResult<PinnedDir> {
        let mut handle = self
            .handle
            .try_clone()
            .map_err(|_| DesktopFileErrorCode::Io)?;
        let mut nodes = self.nodes.clone();
        let mut path = self.canonical_path.clone();
        let mut current_info = info(handle.as_raw_handle())?;
        for name in relative {
            let wide = component(name).map_err(desktop_error)?;
            let next = open_relative(
                handle.as_raw_handle(),
                &wide,
                self.directory_access,
                FILE_OPEN,
                DIRECTORY_OPTIONS,
                0,
                true,
            )
            .map_err(desktop_error)?;
            let next_info = info(next.as_raw_handle())?;
            if kind_of(&next_info) != Kind::Directory {
                return Err(DesktopFileErrorCode::Changed);
            }
            nodes.push(PathNode {
                name: wide,
                ident: Some(next_info.ident),
            });
            path.push(String::from_utf8(name.clone()).map_err(|_| DesktopFileErrorCode::Invalid)?);
            current_info = next_info;
            handle = next;
        }
        Ok(PinnedDir {
            handle,
            info: current_info,
            path,
            relative: relative.to_vec(),
            nodes,
        })
    }

    fn target_path(&self, relative: &[Vec<u8>]) -> DResult<PathBuf> {
        let mut path = self.canonical_path.clone();
        for name in relative {
            path.push(String::from_utf8(name.clone()).map_err(|_| DesktopFileErrorCode::Invalid)?);
        }
        Ok(path)
    }
}

impl PinnedDir {
    fn revalidate(&self, root: &PinnedRoot) -> DResult<()> {
        root.revalidate()?;
        let reopened = root.open_dir(&self.relative)?;
        if !same_directory(&reopened.info, &self.info)
            || reopened.nodes.len() != self.nodes.len()
            || !reopened
                .nodes
                .iter()
                .zip(&self.nodes)
                .all(|(actual, expected)| {
                    actual.ident == expected.ident
                        && fold_wide(&actual.name) == fold_wide(&expected.name)
                })
        {
            return Err(DesktopFileErrorCode::Changed);
        }
        Ok(())
    }

    fn child_path(&self, name: &[u8]) -> DResult<PathBuf> {
        let mut path = self.path.clone();
        path.push(String::from_utf8(name.to_vec()).map_err(|_| DesktopFileErrorCode::Invalid)?);
        Ok(path)
    }

    fn child_nodes(&self, name: &[u8], ident: Option<Ident>) -> DResult<Vec<PathNode>> {
        let wide = component(name).map_err(desktop_error)?;
        let mut nodes = self.nodes.clone();
        nodes.push(PathNode { name: wide, ident });
        Ok(nodes)
    }

    fn resolve_entry(&self, name: &[u8]) -> DResult<ResolvedEntry> {
        let wide = component(name).map_err(desktop_error)?;
        let (handle, info) =
            open_attributes(self.handle.as_raw_handle(), &wide).map_err(desktop_error)?;
        Ok(ResolvedEntry {
            parent: self.clone_for_use()?,
            name: name.to_vec(),
            path: self.child_path(name)?,
            nodes: self.child_nodes(name, Some(info.ident))?,
            handle,
            info,
        })
    }

    fn clone_for_use(&self) -> DResult<Self> {
        Ok(Self {
            handle: self
                .handle
                .try_clone()
                .map_err(|_| DesktopFileErrorCode::Io)?,
            info: self.info,
            path: self.path.clone(),
            relative: self.relative.clone(),
            nodes: self.nodes.clone(),
        })
    }
}

impl ResolvedEntry {
    fn revalidate(&self, root: &PinnedRoot) -> DResult<()> {
        self.parent.revalidate(root)?;
        let (_current, current_info) = open_attributes(
            self.parent.handle.as_raw_handle(),
            &component(&self.name).map_err(desktop_error)?,
        )
        .map_err(desktop_error)?;
        let held = info(self.handle.as_raw_handle())?;
        if !same_info(&current_info, &self.info)
            || !same_info(&held, &self.info)
            || current_info.ident != held.ident
        {
            return Err(DesktopFileErrorCode::Changed);
        }
        Ok(())
    }

    fn path_nodes(&self) -> &[PathNode] {
        &self.nodes
    }
}

fn fold_wide(name: &[u16]) -> Vec<u16> {
    String::from_utf16_lossy(name)
        .to_lowercase()
        .encode_utf16()
        .collect()
}

fn path_prefix(prefix: &[PathNode], full: &[PathNode]) -> bool {
    prefix.len() <= full.len()
        && prefix.iter().zip(full).all(|(left, right)| {
            fold_wide(&left.name) == fold_wide(&right.name)
                && match (left.ident, right.ident) {
                    (Some(a), Some(b)) => a == b,
                    _ => true,
                }
        })
}

fn ensure_not_control_overlap(candidate: &[PathNode], controls: &[ControlRoot]) -> DResult<()> {
    if controls.iter().any(|control| {
        path_prefix(candidate, control.nodes()) || path_prefix(control.nodes(), candidate)
    }) {
        Err(DesktopFileErrorCode::Protected)
    } else {
        Ok(())
    }
}

fn open_controls(paths: &[PathBuf]) -> DResult<Vec<ControlRoot>> {
    let mut controls = Vec::with_capacity(paths.len());
    for path in paths {
        controls.push(ControlRoot {
            root: PinnedRoot::open(path, false)?,
        });
    }
    Ok(controls)
}

fn revalidate_controls(controls: &[ControlRoot]) -> DResult<()> {
    for control in controls {
        control.root.revalidate()?;
    }
    Ok(())
}

fn parse_relative(path: &str) -> DResult<(Vec<Vec<u8>>, Option<Vec<u8>>)> {
    let mut names = relative_names(path)?;
    let leaf = names.pop();
    Ok((names, leaf))
}

fn expected_directory_path(request: &DesktopMutationRequest, root: &PinnedRoot) -> DResult<()> {
    let Some(expected) = request.expected_path.as_deref() else {
        return Ok(());
    };
    if !expected.is_absolute()
        || expected.as_os_str().len() > 32_768
        || expected
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(DesktopFileErrorCode::Invalid);
    }
    let relative = relative_names(&request.relative_path)?;
    let actual = root.target_path(&relative)?;
    if normalized_path(expected) != normalized_path(&actual) {
        return Err(DesktopFileErrorCode::Changed);
    }
    Ok(())
}

fn normalized_path(path: &Path) -> String {
    let mut text = path.to_string_lossy().replace('/', "\\");
    if let Some(rest) = text.strip_prefix("\\\\?\\UNC\\") {
        text = format!("\\\\{rest}");
    } else if let Some(rest) = text.strip_prefix("\\\\?\\") {
        text = rest.to_string();
    }
    while text.len() > 3 && text.ends_with('\\') {
        text.pop();
    }
    text.to_lowercase()
}

fn check_phase(
    check: &mut dyn FnMut(LocalNativeFileCheckPhase) -> DResult<()>,
    phase: LocalNativeFileCheckPhase,
) -> DResult<()> {
    check(phase)
}

fn check_before_publish(
    check: &mut dyn FnMut(LocalNativeFileCheckPhase) -> DResult<()>,
) -> DResult<()> {
    check_phase(check, LocalNativeFileCheckPhase::BeforeEffect)?;
    check_phase(check, LocalNativeFileCheckPhase::Validation)
}

fn absent(parent: RawHandle, name: &[u16]) -> DResult<()> {
    match open_attributes(parent, name) {
        Ok(_) => Err(DesktopFileErrorCode::Exists),
        Err(Error::NotFound) => Ok(()),
        Err(error) => Err(desktop_error(error)),
    }
}

fn open_for_change(
    parent: RawHandle,
    name: &[u16],
    expected: Ident,
) -> DResult<(OwnedHandle, Info)> {
    let handle = open_relative(
        parent,
        name,
        DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_OPEN,
        FILE_OPEN_REPARSE_POINT | SYNC,
        0,
        false,
    )
    .map_err(desktop_error)?;
    let info = info(handle.as_raw_handle())?;
    if info.ident != expected {
        return Err(DesktopFileErrorCode::Changed);
    }
    Ok((handle, info))
}

fn create_stage_file(
    parent: &PinnedDir,
    stage_name: &str,
    security: &PrivateStageSecurity,
) -> DResult<StageGuard> {
    let wide = component(stage_name.as_bytes()).map_err(desktop_error)?;
    let parent_handle = parent
        .handle
        .try_clone()
        .map_err(|_| DesktopFileErrorCode::Io)?;
    let handle = open_relative_with_security(
        parent.handle.as_raw_handle(),
        &wide,
        DELETE
            | FILE_READ_DATA
            | FILE_WRITE_DATA
            | FILE_READ_ATTRIBUTES
            | FILE_WRITE_ATTRIBUTES
            | READ_CONTROL
            | WRITE_DAC
            | SYNCHRONIZE,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | SYNC,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY,
        false,
        security.descriptor.0,
    )
    .map_err(desktop_error)?;
    let info = match info(handle.as_raw_handle()) {
        Ok(info) => info,
        Err(error) => {
            let _ = delete_entry(handle.as_raw_handle());
            return Err(error);
        }
    };
    if kind_of(&info) != Kind::File {
        let _ = delete_entry(handle.as_raw_handle());
        return Err(DesktopFileErrorCode::Changed);
    }
    if let Err(error) = security.verify_new_object(handle.as_raw_handle()) {
        let _ = delete_entry(handle.as_raw_handle());
        return Err(error);
    }
    Ok(StageGuard {
        parent: parent_handle,
        parent_info: parent.info,
        name: wide,
        handle,
        info,
        directory: false,
        entries: Vec::new(),
        cleanup_bytes: 0,
        published: false,
        cleaned: false,
    })
}

fn create_stage_directory(
    parent: &PinnedDir,
    stage_name: &str,
    security: &PrivateStageSecurity,
) -> DResult<StageGuard> {
    let wide = component(stage_name.as_bytes()).map_err(desktop_error)?;
    let parent_handle = parent
        .handle
        .try_clone()
        .map_err(|_| DesktopFileErrorCode::Io)?;
    let handle = open_relative_with_security(
        parent.handle.as_raw_handle(),
        &wide,
        DELETE
            | GIT_DIRECTORY_ACCESS
            | FILE_WRITE_ATTRIBUTES
            | READ_CONTROL
            | WRITE_DAC
            | SYNCHRONIZE,
        FILE_CREATE,
        DIRECTORY_OPTIONS,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY,
        false,
        security.descriptor.0,
    )
    .map_err(desktop_error)?;
    let info = match info(handle.as_raw_handle()) {
        Ok(info) => info,
        Err(error) => {
            let _ = delete_entry(handle.as_raw_handle());
            return Err(error);
        }
    };
    if kind_of(&info) != Kind::Directory {
        let _ = delete_entry(handle.as_raw_handle());
        return Err(DesktopFileErrorCode::Changed);
    }
    if let Err(error) = security.verify_new_object(handle.as_raw_handle()) {
        let _ = delete_entry(handle.as_raw_handle());
        return Err(error);
    }
    Ok(StageGuard {
        parent: parent_handle,
        parent_info: parent.info,
        name: wide,
        handle,
        info,
        directory: true,
        entries: Vec::new(),
        cleanup_bytes: 0,
        published: false,
        cleaned: false,
    })
}

impl StageGuard {
    fn record_cost(&self, relative: &[Vec<u16>]) -> DResult<usize> {
        let mut cost = size_of::<StageEntry>()
            .checked_add(size_of::<Vec<Vec<u16>>>())
            .and_then(|value| {
                relative
                    .len()
                    .checked_mul(size_of::<Vec<u16>>())
                    .and_then(|items| value.checked_add(items))
            })
            .ok_or(DesktopFileErrorCode::Limit)?;
        for name in relative {
            cost = cost
                .checked_add(
                    name.len()
                        .checked_mul(size_of::<u16>())
                        .ok_or(DesktopFileErrorCode::Limit)?,
                )
                .ok_or(DesktopFileErrorCode::Limit)?;
        }
        let next = self
            .cleanup_bytes
            .checked_add(cost)
            .ok_or(DesktopFileErrorCode::Limit)?;
        if next > DESKTOP_MAX_METADATA_BYTES {
            return Err(DesktopFileErrorCode::Limit);
        }
        Ok(cost)
    }

    fn record(&mut self, relative: Vec<Vec<u16>>, info: Info, directory: bool, cost: usize) {
        self.entries.push(StageEntry {
            relative,
            ident: info.ident,
            directory,
        });
        self.cleanup_bytes += cost;
    }

    fn mark_published(&mut self) {
        self.published = true;
    }

    fn disarm(&mut self) {
        self.published = true;
    }

    fn cleanup(&mut self) -> DResult<()> {
        if self.published || self.cleaned {
            return Ok(());
        }
        let parent_info = info(self.parent.as_raw_handle())?;
        if parent_info.ident != self.parent_info.ident {
            return Err(DesktopFileErrorCode::Changed);
        }
        let (named, named_info) =
            open_attributes(self.parent.as_raw_handle(), &self.name).map_err(desktop_error)?;
        if named_info.ident != self.info.ident
            || info(self.handle.as_raw_handle())?.ident != self.info.ident
        {
            return Err(DesktopFileErrorCode::Changed);
        }
        if self.directory {
            let mut entries: Vec<_> = self.entries.iter().collect();
            entries.sort_by_key(|entry| std::cmp::Reverse(entry.relative.len()));
            for entry in entries {
                if entry.relative.is_empty() {
                    return Err(DesktopFileErrorCode::Changed);
                }
                let parent_names = &entry.relative[..entry.relative.len() - 1];
                let mut parent = self
                    .handle
                    .try_clone()
                    .map_err(|_| DesktopFileErrorCode::Io)?;
                for name in parent_names {
                    let child = open_relative(
                        parent.as_raw_handle(),
                        name,
                        DIRECTORY_ACCESS,
                        FILE_OPEN,
                        DIRECTORY_OPTIONS,
                        0,
                        true,
                    )
                    .map_err(desktop_error)?;
                    parent = child;
                }
                let (child, child_info) = open_for_change(
                    parent.as_raw_handle(),
                    entry.relative.last().unwrap(),
                    entry.ident,
                )?;
                if (kind_of(&child_info) == Kind::Directory) != entry.directory {
                    return Err(DesktopFileErrorCode::Changed);
                }
                delete_entry(child.as_raw_handle()).map_err(desktop_error)?;
            }
            if !read_dir_names(self.handle.as_raw_handle())
                .map_err(desktop_error)?
                .is_empty()
            {
                return Err(DesktopFileErrorCode::Changed);
            }
        }
        delete_entry(self.handle.as_raw_handle()).map_err(desktop_error)?;
        drop(named);
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for StageGuard {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn set_copy_attributes(handle: RawHandle, source: &Info, staged: bool) -> DResult<()> {
    // A logical byte copy does not preserve NTFS storage encoding. Preserve
    // visible/basic attributes while allowing the filesystem to choose the
    // destination's compression, sparse and encryption representation.
    if source.attributes
        & !(FILE_ATTRIBUTE_COPY_MASK | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_COPY_STORAGE_MASK)
        != 0
    {
        return Err(DesktopFileErrorCode::Unsupported);
    }
    let mut basic: FILE_BASIC_INFO = unsafe { zeroed() };
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            (&mut basic as *mut FILE_BASIC_INFO).cast::<c_void>(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(DesktopFileErrorCode::Io);
    }
    basic.FileAttributes = source.attributes & (FILE_ATTRIBUTE_COPY_MASK & !FILE_ATTRIBUTE_NORMAL);
    if staged {
        basic.FileAttributes |= FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY;
    }
    if basic.FileAttributes == 0 {
        basic.FileAttributes = FILE_ATTRIBUTE_NORMAL;
    }
    if unsafe {
        SetFileInformationByHandle(
            handle,
            FileBasicInfo,
            (&basic as *const FILE_BASIC_INFO).cast::<c_void>(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(DesktopFileErrorCode::Io);
    }
    Ok(())
}

fn set_plain_attributes(handle: RawHandle, attributes: u32) -> DResult<()> {
    let source = Info {
        attributes: attributes & !FILE_ATTRIBUTE_DIRECTORY,
        ..info(handle)?
    };
    set_copy_attributes(handle, &source, false)
}

fn create_child_file(
    parent: RawHandle,
    name: &[u8],
    security: &PrivateStageSecurity,
) -> DResult<(OwnedHandle, Info)> {
    let handle = open_relative_with_security(
        parent,
        &component(name).map_err(desktop_error)?,
        DELETE
            | FILE_READ_DATA
            | FILE_WRITE_DATA
            | FILE_READ_ATTRIBUTES
            | FILE_WRITE_ATTRIBUTES
            | READ_CONTROL
            | WRITE_DAC
            | SYNCHRONIZE,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | SYNC,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY,
        false,
        security.descriptor.0,
    )
    .map_err(desktop_error)?;
    let info = match info(handle.as_raw_handle()) {
        Ok(info) => info,
        Err(error) => {
            let _ = delete_entry(handle.as_raw_handle());
            return Err(error);
        }
    };
    if kind_of(&info) != Kind::File {
        let _ = delete_entry(handle.as_raw_handle());
        return Err(DesktopFileErrorCode::Changed);
    }
    if let Err(error) = security.verify_new_object(handle.as_raw_handle()) {
        let _ = delete_entry(handle.as_raw_handle());
        return Err(error);
    }
    if let Err(error) = unprotect_stage_dacl(handle.as_raw_handle()) {
        let _ = delete_entry(handle.as_raw_handle());
        return Err(error);
    }
    Ok((handle, info))
}

fn create_child_dir(
    parent: RawHandle,
    name: &[u8],
    security: &PrivateStageSecurity,
) -> DResult<(OwnedHandle, Info)> {
    let handle = open_relative_with_security(
        parent,
        &component(name).map_err(desktop_error)?,
        DELETE
            | GIT_DIRECTORY_ACCESS
            | FILE_WRITE_ATTRIBUTES
            | READ_CONTROL
            | WRITE_DAC
            | SYNCHRONIZE,
        FILE_CREATE,
        DIRECTORY_OPTIONS,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY,
        false,
        security.descriptor.0,
    )
    .map_err(desktop_error)?;
    let info = match info(handle.as_raw_handle()) {
        Ok(info) => info,
        Err(error) => {
            let _ = delete_entry(handle.as_raw_handle());
            return Err(error);
        }
    };
    if kind_of(&info) != Kind::Directory {
        let _ = delete_entry(handle.as_raw_handle());
        return Err(DesktopFileErrorCode::Changed);
    }
    if let Err(error) = security.verify_new_object(handle.as_raw_handle()) {
        let _ = delete_entry(handle.as_raw_handle());
        return Err(error);
    }
    if let Err(error) = unprotect_stage_dacl(handle.as_raw_handle()) {
        let _ = delete_entry(handle.as_raw_handle());
        return Err(error);
    }
    Ok((handle, info))
}

fn open_source_file(parent: RawHandle, name: &[u8], expected: Ident) -> DResult<(File, Info)> {
    let handle = open_relative(
        parent,
        &component(name).map_err(desktop_error)?,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | SYNC,
        0,
        false,
    )
    .map_err(desktop_error)?;
    let info = info(handle.as_raw_handle())?;
    if info.ident != expected || kind_of(&info) != Kind::File {
        return Err(DesktopFileErrorCode::Changed);
    }
    Ok((File::from(handle), info))
}

fn open_directory(parent: RawHandle, name: &[u8]) -> DResult<(OwnedHandle, Info)> {
    let handle = open_relative(
        parent,
        &component(name).map_err(desktop_error)?,
        DIRECTORY_ACCESS,
        FILE_OPEN,
        DIRECTORY_OPTIONS,
        0,
        true,
    )
    .map_err(desktop_error)?;
    let info = info(handle.as_raw_handle())?;
    if kind_of(&info) != Kind::Directory {
        return Err(DesktopFileErrorCode::Changed);
    }
    Ok((handle, info))
}

fn is_private_name(name: &[u8]) -> bool {
    is_private_staging_name(name) || is_git_name(name)
}

fn validate_public_root(path: &Path) -> DResult<()> {
    let mut components = 0usize;
    for part in path.components() {
        if let Component::Normal(name) = part {
            components += 1;
            if components > DESKTOP_MAX_DEPTH {
                return Err(DesktopFileErrorCode::Limit);
            }
            let name = utf8_name(name)?;
            if is_private_name(&name) {
                return Err(DesktopFileErrorCode::Protected);
            }
        }
    }
    Ok(())
}

fn validate_destination_name(name: &[u8]) -> DResult<()> {
    component(name).map_err(desktop_error)?;
    if is_private_name(name) {
        return Err(DesktopFileErrorCode::Protected);
    }
    Ok(())
}

fn copy_file_contents(
    source_parent: RawHandle,
    source_name: &[u8],
    source_info: &Info,
    target: RawHandle,
    target_info: &Info,
    snapshot: &mut TreeSnapshot,
    staged_root: bool,
    check: &mut dyn FnMut(LocalNativeFileCheckPhase) -> DResult<()>,
) -> DResult<()> {
    let (mut source, before) = open_source_file(source_parent, source_name, source_info.ident)?;
    if !same_info(&before, source_info) || kind_of(target_info) != Kind::File {
        return Err(DesktopFileErrorCode::Changed);
    }
    let mut duplicate = null_mut();
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            target,
            GetCurrentProcess(),
            &mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(DesktopFileErrorCode::Io);
    }
    let mut target_file = unsafe { File::from_raw_handle(duplicate) };
    let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
    let mut copied = 0u64;
    loop {
        check_phase(check, LocalNativeFileCheckPhase::Progress)?;
        let count = source.read(&mut buffer).map_err(io_code)?;
        if count == 0 {
            break;
        }
        target_file.write_all(&buffer[..count]).map_err(io_code)?;
        copied = copied
            .checked_add(count as u64)
            .ok_or(DesktopFileErrorCode::Limit)?;
        if copied > source_info.size {
            return Err(DesktopFileErrorCode::Changed);
        }
    }
    target_file.flush().map_err(io_code)?;
    if copied != source_info.size || !same_info(&info(source.as_raw_handle())?, source_info) {
        return Err(DesktopFileErrorCode::Changed);
    }
    set_copy_attributes(target, source_info, staged_root)?;
    snapshot.total_bytes = snapshot
        .total_bytes
        .checked_add(copied)
        .ok_or(DesktopFileErrorCode::Limit)?;
    Ok(())
}

fn copy_tree_contents(
    source_dir: RawHandle,
    source_info: &Info,
    target_dir: RawHandle,
    stage: &mut StageGuard,
    stage_prefix: Vec<Vec<u16>>,
    relative_prefix: Vec<Vec<u8>>,
    path_nodes: Vec<PathNode>,
    security: &PrivateStageSecurity,
    controls: &[ControlRoot],
    snapshot: &mut TreeSnapshot,
    check: &mut dyn FnMut(LocalNativeFileCheckPhase) -> DResult<()>,
) -> DResult<()> {
    if relative_prefix.len() > DESKTOP_MAX_DEPTH {
        return Err(DesktopFileErrorCode::Limit);
    }
    let before = info(source_dir)?;
    if !same_info(&before, source_info) || kind_of(&before) != Kind::Directory {
        return Err(DesktopFileErrorCode::Changed);
    }
    let mut names = read_dir_names(source_dir).map_err(desktop_error)?;
    names.sort();
    for child_name in &names {
        if relative_prefix.len() >= DESKTOP_MAX_DEPTH
            || snapshot.entries.len() >= DESKTOP_MAX_NODES
            || stage.entries.len() >= DESKTOP_MAX_NODES
        {
            return Err(DesktopFileErrorCode::Limit);
        }
        check_phase(check, LocalNativeFileCheckPhase::Progress)?;
        if is_private_staging_name(child_name) {
            return Err(DesktopFileErrorCode::Protected);
        }
        let child_wide = component(child_name).map_err(desktop_error)?;
        let (source_child, child_info) =
            open_attributes(source_dir, &child_wide).map_err(desktop_error)?;
        let kind = kind_of(&child_info);
        if !matches!(kind, Kind::File | Kind::Directory) {
            return Err(DesktopFileErrorCode::Unsupported);
        }
        let mut child_nodes = path_nodes.clone();
        child_nodes.push(PathNode {
            name: child_wide.clone(),
            ident: Some(child_info.ident),
        });
        ensure_not_control_overlap(&child_nodes, controls)?;
        let mut relative = relative_prefix.clone();
        relative.push(child_name.clone());
        let mut stage_relative = stage_prefix.clone();
        stage_relative.push(child_wide.clone());
        snapshot.record(relative.clone(), child_info, kind)?;
        let cleanup_cost = stage.record_cost(&stage_relative)?;
        match kind {
            Kind::File => {
                let (target_child, target_info) =
                    create_child_file(target_dir, child_name, security)?;
                stage.record(stage_relative, target_info, false, cleanup_cost);
                copy_file_contents(
                    source_dir,
                    child_name,
                    &child_info,
                    target_child.as_raw_handle(),
                    &target_info,
                    snapshot,
                    false,
                    check,
                )?;
            }
            Kind::Directory => {
                let (source_child_dir, source_dir_info) = open_directory(source_dir, child_name)?;
                if !same_info(&source_dir_info, &child_info) {
                    return Err(DesktopFileErrorCode::Changed);
                }
                let (target_child_dir, target_info) =
                    create_child_dir(target_dir, child_name, security)?;
                stage.record(stage_relative.clone(), target_info, true, cleanup_cost);
                copy_tree_contents(
                    source_child_dir.as_raw_handle(),
                    &child_info,
                    target_child_dir.as_raw_handle(),
                    stage,
                    stage_relative,
                    relative,
                    child_nodes,
                    security,
                    controls,
                    snapshot,
                    check,
                )?;
                set_copy_attributes(target_child_dir.as_raw_handle(), &child_info, false)?;
            }
            Kind::Symlink | Kind::Other => unreachable!(),
        }
        drop(source_child);
    }
    let mut after_names = read_dir_names(source_dir).map_err(desktop_error)?;
    after_names.sort();
    let after = info(source_dir)?;
    if names != after_names || !same_info(&after, source_info) {
        return Err(DesktopFileErrorCode::Changed);
    }
    Ok(())
}

fn copy_tree_to_stage(
    source: &ResolvedEntry,
    stage: &mut StageGuard,
    security: &PrivateStageSecurity,
    controls: &[ControlRoot],
    snapshot: &mut TreeSnapshot,
    check: &mut dyn FnMut(LocalNativeFileCheckPhase) -> DResult<()>,
) -> DResult<()> {
    let kind = kind_of(&source.info);
    if !matches!(kind, Kind::File | Kind::Directory) {
        return Err(DesktopFileErrorCode::Unsupported);
    }
    snapshot.record(Vec::new(), source.info, kind)?;
    if kind == Kind::File {
        copy_file_contents(
            source.parent.handle.as_raw_handle(),
            &source.name,
            &source.info,
            stage.handle.as_raw_handle(),
            &stage.info,
            snapshot,
            true,
            check,
        )?;
        return Ok(());
    }
    let (source_dir, before) = open_directory(source.parent.handle.as_raw_handle(), &source.name)?;
    if !same_info(&before, &source.info) {
        return Err(DesktopFileErrorCode::Changed);
    }
    copy_tree_contents(
        source_dir.as_raw_handle(),
        &source.info,
        stage.handle.as_raw_handle(),
        stage,
        Vec::new(),
        Vec::new(),
        source.path_nodes().to_vec(),
        security,
        controls,
        snapshot,
        check,
    )
}

fn scan_snapshot(
    parent: RawHandle,
    name: &[u8],
    node_info: &Info,
    relative: Vec<Vec<u8>>,
    path_nodes: Vec<PathNode>,
    controls: &[ControlRoot],
    snapshot: &mut TreeSnapshot,
    check: &mut dyn FnMut(LocalNativeFileCheckPhase) -> DResult<()>,
    depth: usize,
    allow_git: bool,
    allow_symlink: bool,
    report_progress: bool,
) -> DResult<()> {
    if depth > DESKTOP_MAX_DEPTH || snapshot.entries.len() >= DESKTOP_MAX_NODES {
        return Err(DesktopFileErrorCode::Limit);
    }
    ensure_not_control_overlap(&path_nodes, controls)?;
    let kind = kind_of(node_info);
    if kind == Kind::Symlink && allow_symlink {
        return snapshot.record(relative, *node_info, kind);
    }
    if !matches!(kind, Kind::File | Kind::Directory) {
        return Err(DesktopFileErrorCode::Unsupported);
    }
    snapshot.record(relative.clone(), *node_info, kind)?;
    if kind == Kind::Directory {
        let (directory, before) = open_directory(parent, name)?;
        if !same_info(&before, node_info) {
            return Err(DesktopFileErrorCode::Changed);
        }
        let mut names = read_dir_names(directory.as_raw_handle()).map_err(desktop_error)?;
        names.sort();
        for child_name in &names {
            if report_progress {
                check_phase(check, LocalNativeFileCheckPhase::Progress)?;
            }
            if is_private_staging_name(child_name) || (!allow_git && is_git_name(child_name)) {
                return Err(DesktopFileErrorCode::Protected);
            }
            let child_info = open_attributes(
                directory.as_raw_handle(),
                &component(child_name).map_err(desktop_error)?,
            )
            .map_err(desktop_error)?
            .1;
            let mut child_path = path_nodes.clone();
            child_path.push(PathNode {
                name: component(child_name).map_err(desktop_error)?,
                ident: Some(child_info.ident),
            });
            let mut child_relative = relative.clone();
            child_relative.push(child_name.clone());
            scan_snapshot(
                directory.as_raw_handle(),
                child_name,
                &child_info,
                child_relative,
                child_path,
                controls,
                snapshot,
                check,
                depth + 1,
                allow_git,
                allow_symlink,
                report_progress,
            )?;
        }
        let mut after_names = read_dir_names(directory.as_raw_handle()).map_err(desktop_error)?;
        after_names.sort();
        if names != after_names || !same_info(&info(directory.as_raw_handle())?, node_info) {
            return Err(DesktopFileErrorCode::Changed);
        }
    }
    Ok(())
}

fn revalidate_snapshot(
    source: &ResolvedEntry,
    snapshot: &TreeSnapshot,
    controls: &[ControlRoot],
    check: &mut dyn FnMut(LocalNativeFileCheckPhase) -> DResult<()>,
    allow_git: bool,
    allow_symlink: bool,
) -> DResult<()> {
    source.revalidate_rootless()?;
    let mut current = TreeSnapshot::default();
    scan_snapshot(
        source.parent.handle.as_raw_handle(),
        &source.name,
        &source.info,
        Vec::new(),
        source.path_nodes().to_vec(),
        controls,
        &mut current,
        check,
        0,
        allow_git,
        allow_symlink,
        false,
    )?;
    if current.entries.len() != snapshot.entries.len()
        || current.entries.iter().zip(&snapshot.entries).any(|(a, b)| {
            a.relative != b.relative || a.kind != b.kind || !same_info(&a.info, &b.info)
        })
    {
        return Err(DesktopFileErrorCode::Changed);
    }
    Ok(())
}

impl ResolvedEntry {
    fn revalidate_rootless(&self) -> DResult<()> {
        let (named, current) = open_attributes(
            self.parent.handle.as_raw_handle(),
            &component(&self.name).map_err(desktop_error)?,
        )
        .map_err(desktop_error)?;
        let held = info(self.handle.as_raw_handle())?;
        if current.ident != self.info.ident
            || held.ident != self.info.ident
            || !same_info(&current, &self.info)
            || !same_info(&held, &self.info)
        {
            return Err(DesktopFileErrorCode::Changed);
        }
        drop(named);
        Ok(())
    }
}

fn collect_delete_plan(
    parent: &PinnedDir,
    name: &[u8],
    node_info: Info,
    controls: &[ControlRoot],
    entries: &mut Vec<DeleteEntry>,
    path_nodes: Vec<PathNode>,
    check: &mut dyn FnMut(LocalNativeFileCheckPhase) -> DResult<()>,
    depth: usize,
) -> DResult<()> {
    if depth > DESKTOP_MAX_DEPTH || entries.len() >= DESKTOP_MAX_NODES {
        return Err(DesktopFileErrorCode::Limit);
    }
    if is_private_staging_name(name) {
        return Err(DesktopFileErrorCode::Protected);
    }
    ensure_not_control_overlap(&path_nodes, controls)?;
    let (handle, opened_info) = open_for_change(
        parent.handle.as_raw_handle(),
        &component(name).map_err(desktop_error)?,
        node_info.ident,
    )?;
    if !same_info(&opened_info, &node_info) {
        return Err(DesktopFileErrorCode::Changed);
    }
    let kind = kind_of(&node_info);
    if kind == Kind::Other {
        return Err(DesktopFileErrorCode::Unsupported);
    }
    if kind == Kind::Directory {
        let (directory, dir_info) = open_directory(parent.handle.as_raw_handle(), name)?;
        if !same_info(&dir_info, &node_info) {
            return Err(DesktopFileErrorCode::Changed);
        }
        let mut names = read_dir_names(directory.as_raw_handle()).map_err(desktop_error)?;
        names.sort();
        for child_name in &names {
            check_phase(check, LocalNativeFileCheckPhase::Progress)?;
            if is_private_staging_name(child_name) {
                return Err(DesktopFileErrorCode::Protected);
            }
            let child_info = open_attributes(
                directory.as_raw_handle(),
                &component(child_name).map_err(desktop_error)?,
            )
            .map_err(desktop_error)?
            .1;
            let mut child_nodes = path_nodes.clone();
            child_nodes.push(PathNode {
                name: component(child_name).map_err(desktop_error)?,
                ident: Some(child_info.ident),
            });
            let child_parent = PinnedDir {
                handle: directory
                    .try_clone()
                    .map_err(|_| DesktopFileErrorCode::Io)?,
                info: dir_info,
                path: parent.child_path(name)?,
                relative: parent
                    .relative
                    .iter()
                    .cloned()
                    .chain(std::iter::once(name.to_vec()))
                    .collect(),
                nodes: path_nodes.clone(),
            };
            collect_delete_plan(
                &child_parent,
                child_name,
                child_info,
                controls,
                entries,
                child_nodes,
                check,
                depth + 1,
            )?;
        }
        let mut after_names = read_dir_names(directory.as_raw_handle()).map_err(desktop_error)?;
        after_names.sort();
        if names != after_names || !same_info(&info(directory.as_raw_handle())?, &node_info) {
            return Err(DesktopFileErrorCode::Changed);
        }
        // Keep a listable handle for final namespace validation. The change
        // handle below has DELETE access but intentionally lacks list access.
        entries.push(DeleteEntry {
            parent: parent
                .handle
                .try_clone()
                .map_err(|_| DesktopFileErrorCode::Io)?,
            parent_path: parent.path.clone(),
            name: component(name).map_err(desktop_error)?,
            handle,
            info: node_info,
            directory: true,
            directory_handle: Some(directory),
            path_nodes,
        });
        return Ok(());
    }
    entries.push(DeleteEntry {
        parent: parent
            .handle
            .try_clone()
            .map_err(|_| DesktopFileErrorCode::Io)?,
        parent_path: parent.path.clone(),
        name: component(name).map_err(desktop_error)?,
        handle,
        info: node_info,
        directory: false,
        directory_handle: None,
        path_nodes,
    });
    Ok(())
}

fn verify_delete_entry(entry: &DeleteEntry, controls: &[ControlRoot]) -> DResult<()> {
    ensure_not_control_overlap(&entry.path_nodes, controls)?;
    let held = info(entry.handle.as_raw_handle())?;
    let held_matches = if entry.directory {
        same_directory(&held, &entry.info)
    } else {
        same_info(&held, &entry.info)
    };
    if !held_matches {
        return Err(DesktopFileErrorCode::Changed);
    }
    let (named, named_info) =
        open_attributes(entry.parent.as_raw_handle(), &entry.name).map_err(desktop_error)?;
    let named_matches = if entry.directory {
        same_directory(&named_info, &entry.info)
    } else {
        same_info(&named_info, &entry.info)
    };
    if !named_matches {
        return Err(DesktopFileErrorCode::Changed);
    }
    let parent_info = info(entry.parent.as_raw_handle())?;
    let parent_ident = entry
        .path_nodes
        .get(entry.path_nodes.len().saturating_sub(2))
        .and_then(|node| node.ident)
        .ok_or(DesktopFileErrorCode::Changed)?;
    if parent_info.ident != parent_ident || kind_of(&parent_info) != Kind::Directory {
        return Err(DesktopFileErrorCode::Changed);
    }
    native_final_path(entry.parent.as_raw_handle(), &entry.parent_path)
        .map_err(|_| DesktopFileErrorCode::Changed)?;
    if entry.directory {
        let directory = entry
            .directory_handle
            .as_ref()
            .ok_or(DesktopFileErrorCode::Changed)?;
        if !same_directory(&info(directory.as_raw_handle())?, &entry.info)
            || !read_dir_names(directory.as_raw_handle())
                .map_err(desktop_error)?
                .is_empty()
        {
            return Err(DesktopFileErrorCode::Changed);
        }
    }
    drop(named);
    Ok(())
}

fn refresh_remaining_hardlinks(
    entries: &mut VecDeque<DeleteEntry>,
    deleted_ident: Ident,
) -> DResult<()> {
    for alias in entries
        .iter_mut()
        .filter(|entry| !entry.directory && entry.info.ident == deleted_ident)
    {
        let expected_nlink = alias
            .info
            .nlink
            .checked_sub(1)
            .ok_or(DesktopFileErrorCode::Changed)?;
        let current = info(alias.handle.as_raw_handle())?;
        if current.ident != alias.info.ident
            || current.attributes != alias.info.attributes
            || current.size != alias.info.size
            || current.last_write != alias.info.last_write
            || current.nlink != expected_nlink
        {
            return Err(DesktopFileErrorCode::Changed);
        }
        let (_named, named_info) =
            open_attributes(alias.parent.as_raw_handle(), &alias.name).map_err(desktop_error)?;
        if !same_info(&named_info, &current) {
            return Err(DesktopFileErrorCode::Changed);
        }
        alias.info = current;
    }
    Ok(())
}

fn make_delete_plan(
    entry: &ResolvedEntry,
    controls: &[ControlRoot],
    check: &mut dyn FnMut(LocalNativeFileCheckPhase) -> DResult<()>,
) -> DResult<DeletePlan> {
    let mut entries = Vec::new();
    collect_delete_plan(
        &entry.parent,
        &entry.name,
        entry.info,
        controls,
        &mut entries,
        entry.path_nodes().to_vec(),
        check,
        0,
    )?;
    Ok(DeletePlan { entries })
}

fn guarded_tree_snapshot(
    entry: &ResolvedEntry,
    controls: &[ControlRoot],
    check: &mut dyn FnMut(LocalNativeFileCheckPhase) -> DResult<()>,
) -> DResult<Option<TreeSnapshot>> {
    if kind_of(&entry.info) != Kind::Directory {
        ensure_not_control_overlap(entry.path_nodes(), controls)?;
        return Ok(None);
    }
    let mut snapshot = TreeSnapshot::default();
    scan_snapshot(
        entry.parent.handle.as_raw_handle(),
        &entry.name,
        &entry.info,
        Vec::new(),
        entry.path_nodes().to_vec(),
        controls,
        &mut snapshot,
        check,
        0,
        true,
        true,
        true,
    )?;
    Ok(Some(snapshot))
}

fn verify_guarded_tree(
    entry: &ResolvedEntry,
    snapshot: Option<&TreeSnapshot>,
    controls: &[ControlRoot],
    check: &mut dyn FnMut(LocalNativeFileCheckPhase) -> DResult<()>,
) -> DResult<()> {
    if let Some(snapshot) = snapshot {
        revalidate_snapshot(entry, snapshot, controls, check, true, true)
    } else {
        ensure_not_control_overlap(entry.path_nodes(), controls)
    }
}

fn target_candidate_nodes(parent: &PinnedDir, name: &[u8]) -> DResult<Vec<PathNode>> {
    let mut nodes = parent.nodes.clone();
    nodes.push(PathNode {
        name: component(name).map_err(desktop_error)?,
        ident: None,
    });
    Ok(nodes)
}

fn case_only_rename(
    entry: &ResolvedEntry,
    target_parent: &PinnedDir,
    target_name: &[u8],
    request: &DesktopMutationRequest,
    source_root: &PinnedRoot,
    target_root: &PinnedRoot,
    controls: &[ControlRoot],
    tree_snapshot: Option<&TreeSnapshot>,
    check: &mut dyn FnMut(LocalNativeFileCheckPhase) -> DResult<()>,
) -> std::result::Result<DesktopFileChange, DesktopMutationError> {
    let old_fold = fold(&entry.name);
    let new_fold = fold(target_name);
    if old_fold != new_fold || entry.name == target_name {
        return Err(DesktopFileErrorCode::Exists.into());
    }
    let exact_names = read_dir_names(target_parent.handle.as_raw_handle())
        .map_err(desktop_error)
        .map_err(DesktopMutationError::Before)?;
    if exact_names
        .iter()
        .any(|name| name.as_slice() == target_name)
    {
        return Err(DesktopFileErrorCode::Exists.into());
    }
    let name = component(target_name).map_err(desktop_error)?;
    let (_, existing) =
        open_attributes(target_parent.handle.as_raw_handle(), &name).map_err(desktop_error)?;
    if existing.ident != entry.info.ident {
        return Err(DesktopFileErrorCode::Exists.into());
    }
    let stage_name =
        desktop_staging_name(&request.operation_id).map_err(DesktopMutationError::Before)?;
    let stage_wide = component(stage_name.as_bytes())
        .map_err(desktop_error)
        .map_err(DesktopMutationError::Before)?;
    absent(entry.parent.handle.as_raw_handle(), &stage_wide)
        .map_err(DesktopMutationError::Before)?;
    let (change, current) = open_for_change(
        entry.parent.handle.as_raw_handle(),
        &component(&entry.name)
            .map_err(desktop_error)
            .map_err(DesktopMutationError::Before)?,
        entry.info.ident,
    )
    .map_err(DesktopMutationError::Before)?;
    if !same_info(&current, &entry.info) {
        return Err(DesktopFileErrorCode::Changed.into());
    }
    check_before_publish(check).map_err(DesktopMutationError::Before)?;
    source_root
        .revalidate()
        .map_err(DesktopMutationError::Before)?;
    target_root
        .revalidate()
        .map_err(DesktopMutationError::Before)?;
    entry
        .parent
        .revalidate(source_root)
        .map_err(DesktopMutationError::Before)?;
    target_parent
        .revalidate(target_root)
        .map_err(DesktopMutationError::Before)?;
    entry
        .revalidate(source_root)
        .map_err(DesktopMutationError::Before)?;
    revalidate_controls(controls).map_err(DesktopMutationError::Before)?;
    verify_guarded_tree(entry, tree_snapshot, controls, check)
        .map_err(DesktopMutationError::Before)?;
    absent(entry.parent.handle.as_raw_handle(), &stage_wide)
        .map_err(DesktopMutationError::Before)?;
    check_phase(check, LocalNativeFileCheckPhase::Publication)
        .map_err(DesktopMutationError::Before)?;
    if let Err(error) = rename_no_replace(
        change.as_raw_handle(),
        entry.parent.handle.as_raw_handle(),
        &stage_wide,
    ) {
        return Err(desktop_error(error).into());
    }
    let staged = open_relative(
        entry.parent.handle.as_raw_handle(),
        &stage_wide,
        DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_OPEN,
        FILE_OPEN_REPARSE_POINT | SYNC,
        0,
        false,
    )
    .map_err(desktop_error)
    .map_err(|_| DesktopMutationError::Uncertain)?;
    if info(staged.as_raw_handle())
        .map_err(|_| DesktopMutationError::Uncertain)?
        .ident
        != entry.info.ident
    {
        return Err(DesktopMutationError::Uncertain);
    }
    if rename_no_replace(
        staged.as_raw_handle(),
        target_parent.handle.as_raw_handle(),
        &name,
    )
    .is_err()
    {
        return Err(DesktopMutationError::Uncertain);
    }
    Ok(DesktopFileChange {
        operation_id: request.operation_id.clone(),
        old_path: Some(entry.path.clone()),
        new_path: Some(
            target_parent
                .child_path(target_name)
                .map_err(DesktopMutationError::Before)?,
        ),
        trash: None,
    })
}

fn duplicate_name(parent: RawHandle, original: &[u8], is_directory: bool) -> DResult<Vec<u8>> {
    let name = String::from_utf8(original.to_vec()).map_err(|_| DesktopFileErrorCode::Invalid)?;
    for number in 1..=crate::desktop::DESKTOP_DUPLICATE_LIMIT {
        let candidate = crate::desktop::desktop_duplicate_name(&name, is_directory, number)?;
        crate::desktop::validate_desktop_name(&candidate)?;
        let bytes = candidate.into_bytes();
        let wide = component(&bytes).map_err(desktop_error)?;
        match open_attributes(parent, &wide) {
            Ok(_) => continue,
            Err(Error::NotFound) => return Ok(bytes),
            Err(error) => return Err(desktop_error(error)),
        }
    }
    Err(DesktopFileErrorCode::Limit)
}

fn make_ticket(
    request: &DesktopMutationRequest,
    root: &PinnedRoot,
    entry: &ResolvedEntry,
    stage: &StageGuard,
) -> DResult<DesktopTrashTicket> {
    let staging_name =
        String::from_utf16(&stage.name).map_err(|_| DesktopFileErrorCode::Invalid)?;
    let staging_directory = entry.parent.path.join(staging_name);
    let original_path = entry.path.clone();
    let staged_path = staging_directory.join(
        entry
            .path
            .file_name()
            .ok_or(DesktopFileErrorCode::Invalid)?,
    );
    let ticket = DesktopTrashTicket {
        version: 1,
        operation_id: request.operation_id.clone(),
        root: root.canonical_path.clone(),
        original_path,
        staging_directory,
        staged_path,
        root_identity: identity_dto(root.info.ident),
        parent_identity: identity_dto(entry.parent.info.ident),
        staging_identity: identity_dto(stage.info.ident),
        entry_identity: identity_dto(entry.info.ident),
        kind: desktop_kind(&entry.info),
    };
    ticket.validate_shape()?;
    Ok(ticket)
}

fn identity_dto(ident: Ident) -> crate::desktop::DesktopFileIdentity {
    crate::desktop::DesktopFileIdentity {
        volume: ident.volume.to_string(),
        file_id: ident.id.to_string(),
    }
}

fn desktop_kind(info: &Info) -> DesktopFileKind {
    match kind_of(info) {
        Kind::File => DesktopFileKind::File,
        Kind::Directory => DesktopFileKind::Directory,
        Kind::Symlink => DesktopFileKind::Symlink,
        Kind::Other => DesktopFileKind::Other,
    }
}

pub(crate) fn source_precondition(path: &Path) -> DResult<DesktopSourcePrecondition> {
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
    let name = utf8_name(leaf)?;
    let root = PinnedRoot::open(parent_path, false)?;
    let parent = root.open_dir(&[])?;
    let wide = component(&name).map_err(desktop_error)?;
    let handle = open_relative(
        parent.handle.as_raw_handle(),
        &wide,
        ATTRIBUTE_ACCESS,
        FILE_OPEN,
        FILE_OPEN_REPARSE_POINT | FILE_OPEN_NO_RECALL | SYNC,
        0,
        false,
    )
    .map_err(desktop_error)?;
    let leaf_info = info(handle.as_raw_handle())?;
    let result = DesktopSourcePrecondition {
        identity: identity_dto(leaf_info.ident),
        kind: desktop_kind(&leaf_info),
    };
    parent.revalidate(&root)?;
    Ok(result)
}

fn check_source_precondition(
    expected: Option<&DesktopSourcePrecondition>,
    actual: &Info,
) -> std::result::Result<(), DesktopMutationError> {
    if let Some(expected) = expected {
        if identity_dto(actual.ident) != expected.identity || desktop_kind(actual) != expected.kind
        {
            return Err(DesktopFileErrorCode::Changed.into());
        }
    }
    Ok(())
}

fn parse_identity(identity: &crate::desktop::DesktopFileIdentity) -> DResult<Ident> {
    if !identity.is_valid() {
        return Err(DesktopFileErrorCode::Invalid);
    }
    Ok(Ident {
        volume: identity
            .volume
            .parse()
            .map_err(|_| DesktopFileErrorCode::Invalid)?,
        id: identity
            .file_id
            .parse()
            .map_err(|_| DesktopFileErrorCode::Invalid)?,
    })
}

fn apply_create(
    request: &DesktopMutationRequest,
    root: &PinnedRoot,
    target_parent: &PinnedDir,
    target_name: &[u8],
    directory: bool,
    controls: &[ControlRoot],
    check: &mut dyn FnMut(LocalNativeFileCheckPhase) -> DResult<()>,
) -> std::result::Result<DesktopFileChange, DesktopMutationError> {
    validate_destination_name(target_name).map_err(DesktopMutationError::Before)?;
    let candidate =
        target_candidate_nodes(target_parent, target_name).map_err(DesktopMutationError::Before)?;
    ensure_not_control_overlap(&candidate, controls).map_err(DesktopMutationError::Before)?;
    let target = component(target_name)
        .map_err(desktop_error)
        .map_err(DesktopMutationError::Before)?;
    absent(target_parent.handle.as_raw_handle(), &target).map_err(DesktopMutationError::Before)?;
    let stage_name =
        desktop_staging_name(&request.operation_id).map_err(DesktopMutationError::Before)?;
    let security =
        PrivateStageSecurity::current_user_and_system().map_err(DesktopMutationError::Before)?;
    let mut stage = if directory {
        create_stage_directory(target_parent, &stage_name, &security)
    } else {
        create_stage_file(target_parent, &stage_name, &security)
    }
    .map_err(DesktopMutationError::Before)?;
    let result = (|| -> DResult<()> {
        check_before_publish(check)?;
        root.revalidate()?;
        target_parent.revalidate(root)?;
        revalidate_controls(controls)?;
        ensure_not_control_overlap(&candidate, controls)?;
        absent(target_parent.handle.as_raw_handle(), &target)?;
        check_phase(check, LocalNativeFileCheckPhase::Publication)?;
        rename_no_replace(
            stage.handle.as_raw_handle(),
            target_parent.handle.as_raw_handle(),
            &target,
        )
        .map_err(desktop_error)?;
        stage.mark_published();
        set_plain_attributes(
            stage.handle.as_raw_handle(),
            if directory {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_NORMAL
            },
        )?;
        unprotect_stage_dacl(stage.handle.as_raw_handle())?;
        Ok(())
    })();
    if let Err(error) = result {
        if stage.published || stage.cleanup().is_err() {
            return Err(DesktopMutationError::Uncertain);
        }
        return Err(error.into());
    }
    Ok(DesktopFileChange {
        operation_id: request.operation_id.clone(),
        old_path: None,
        new_path: Some(
            target_parent
                .child_path(target_name)
                .map_err(DesktopMutationError::Before)?,
        ),
        trash: None,
    })
}

fn apply_rename(
    request: &DesktopMutationRequest,
    root: &PinnedRoot,
    entry: &ResolvedEntry,
    new_name: &[u8],
    expected_source: Option<&DesktopSourcePrecondition>,
    controls: &[ControlRoot],
    check: &mut dyn FnMut(LocalNativeFileCheckPhase) -> DResult<()>,
) -> std::result::Result<DesktopFileChange, DesktopMutationError> {
    check_source_precondition(expected_source, &entry.info)?;
    validate_destination_name(new_name).map_err(DesktopMutationError::Before)?;
    ensure_not_control_overlap(entry.path_nodes(), controls)
        .map_err(DesktopMutationError::Before)?;
    if entry.name == new_name {
        return Ok(DesktopFileChange {
            operation_id: request.operation_id.clone(),
            old_path: Some(entry.path.clone()),
            new_path: Some(entry.path.clone()),
            trash: None,
        });
    }
    let tree_snapshot =
        guarded_tree_snapshot(entry, controls, check).map_err(DesktopMutationError::Before)?;
    let candidate =
        target_candidate_nodes(&entry.parent, new_name).map_err(DesktopMutationError::Before)?;
    ensure_not_control_overlap(&candidate, controls).map_err(DesktopMutationError::Before)?;
    let target = component(new_name)
        .map_err(desktop_error)
        .map_err(DesktopMutationError::Before)?;
    let target_is_same_entry = match open_attributes(entry.parent.handle.as_raw_handle(), &target) {
        Ok((_, other)) if other.ident != entry.info.ident => {
            return Err(DesktopFileErrorCode::Exists.into());
        }
        Ok(_) if fold(&entry.name) != fold(new_name) => {
            return Err(DesktopFileErrorCode::Exists.into());
        }
        Err(Error::NotFound) => false,
        Ok(_) => true,
        Err(error) => return Err(desktop_error(error).into()),
    };
    if target_is_same_entry && fold(&entry.name) == fold(new_name) && entry.name != new_name {
        return case_only_rename(
            entry,
            &entry.parent,
            new_name,
            request,
            root,
            root,
            controls,
            tree_snapshot.as_ref(),
            check,
        );
    }
    let (change, current) = open_for_change(
        entry.parent.handle.as_raw_handle(),
        &component(&entry.name)
            .map_err(desktop_error)
            .map_err(DesktopMutationError::Before)?,
        entry.info.ident,
    )
    .map_err(DesktopMutationError::Before)?;
    if !same_info(&current, &entry.info) {
        return Err(DesktopFileErrorCode::Changed.into());
    }
    check_before_publish(check).map_err(DesktopMutationError::Before)?;
    root.revalidate().map_err(DesktopMutationError::Before)?;
    entry
        .revalidate(root)
        .map_err(DesktopMutationError::Before)?;
    entry
        .parent
        .revalidate(root)
        .map_err(DesktopMutationError::Before)?;
    revalidate_controls(controls).map_err(DesktopMutationError::Before)?;
    verify_guarded_tree(entry, tree_snapshot.as_ref(), controls, check)
        .map_err(DesktopMutationError::Before)?;
    match open_attributes(entry.parent.handle.as_raw_handle(), &target) {
        Err(Error::NotFound) => {}
        Ok((_, existing)) if existing.ident == entry.info.ident => {}
        Ok(_) => return Err(DesktopFileErrorCode::Exists.into()),
        Err(error) => return Err(desktop_error(error).into()),
    }
    check_phase(check, LocalNativeFileCheckPhase::Publication)
        .map_err(DesktopMutationError::Before)?;
    rename_no_replace(
        change.as_raw_handle(),
        entry.parent.handle.as_raw_handle(),
        &target,
    )
    .map_err(desktop_error)
    .map_err(DesktopMutationError::Before)?;
    Ok(DesktopFileChange {
        operation_id: request.operation_id.clone(),
        old_path: Some(entry.path.clone()),
        new_path: Some(
            entry
                .parent
                .child_path(new_name)
                .map_err(DesktopMutationError::Before)?,
        ),
        trash: None,
    })
}

fn apply_delete(
    request: &DesktopMutationRequest,
    root: &PinnedRoot,
    entry: &ResolvedEntry,
    expected_source: Option<&DesktopSourcePrecondition>,
    controls: &[ControlRoot],
    check: &mut dyn FnMut(LocalNativeFileCheckPhase) -> DResult<()>,
) -> std::result::Result<DesktopFileChange, DesktopMutationError> {
    check_source_precondition(expected_source, &entry.info)?;
    ensure_not_control_overlap(entry.path_nodes(), controls)
        .map_err(DesktopMutationError::Before)?;
    let plan = make_delete_plan(entry, controls, check).map_err(DesktopMutationError::Before)?;
    let mut remaining = VecDeque::from(plan.entries);
    let mut changed = false;
    while let Some(item) = remaining.pop_front() {
        let step = (|| -> DResult<()> {
            check_before_publish(check)?;
            root.revalidate()?;
            entry.parent.revalidate(root)?;
            revalidate_controls(controls)?;
            verify_delete_entry(&item, controls)?;
            check_phase(check, LocalNativeFileCheckPhase::Publication)?;
            delete_entry(item.handle.as_raw_handle()).map_err(desktop_error)
        })();
        if let Err(error) = step {
            return Err(if changed {
                DesktopMutationError::Uncertain
            } else {
                DesktopMutationError::Before(error)
            });
        }
        changed = true;
        let was_directory = item.directory;
        let identity = item.info.ident;
        drop(item);
        if !was_directory {
            if refresh_remaining_hardlinks(&mut remaining, identity).is_err() {
                return Err(DesktopMutationError::Uncertain);
            }
        }
    }
    Ok(DesktopFileChange {
        operation_id: request.operation_id.clone(),
        old_path: Some(entry.path.clone()),
        new_path: None,
        trash: None,
    })
}

fn apply_trash(
    request: &DesktopMutationRequest,
    root: &PinnedRoot,
    entry: &ResolvedEntry,
    expected_source: Option<&DesktopSourcePrecondition>,
    controls: &[ControlRoot],
    check: &mut dyn FnMut(LocalNativeFileCheckPhase) -> DResult<()>,
) -> std::result::Result<DesktopFileChange, DesktopMutationError> {
    check_source_precondition(expected_source, &entry.info)?;
    ensure_not_control_overlap(entry.path_nodes(), controls)
        .map_err(DesktopMutationError::Before)?;
    let tree_snapshot =
        guarded_tree_snapshot(entry, controls, check).map_err(DesktopMutationError::Before)?;
    let stage_name =
        desktop_staging_name(&request.operation_id).map_err(DesktopMutationError::Before)?;
    let security =
        PrivateStageSecurity::current_user_and_system().map_err(DesktopMutationError::Before)?;
    let mut stage = create_stage_directory(&entry.parent, &stage_name, &security)
        .map_err(DesktopMutationError::Before)?;
    let result = (|| -> DResult<DesktopTrashTicket> {
        check_before_publish(check)?;
        root.revalidate()?;
        entry.parent.revalidate(root)?;
        entry.revalidate(root)?;
        revalidate_controls(controls)?;
        verify_guarded_tree(entry, tree_snapshot.as_ref(), controls, check)?;
        ensure_not_control_overlap(entry.path_nodes(), controls)?;
        let name = component(&entry.name).map_err(desktop_error)?;
        absent(stage.handle.as_raw_handle(), &name)?;
        let (change, info) =
            open_for_change(entry.parent.handle.as_raw_handle(), &name, entry.info.ident)?;
        if !same_info(&info, &entry.info) {
            return Err(DesktopFileErrorCode::Changed);
        }
        let ticket = make_ticket(request, root, entry, &stage)?;
        check_phase(check, LocalNativeFileCheckPhase::Publication)?;
        rename_no_replace(change.as_raw_handle(), stage.handle.as_raw_handle(), &name)
            .map_err(desktop_error)?;
        stage.disarm();
        Ok(ticket)
    })();
    let ticket = match result {
        Ok(ticket) => ticket,
        Err(error) => {
            if stage.cleanup().is_err() {
                return Err(DesktopMutationError::Uncertain);
            }
            return Err(error.into());
        }
    };
    Ok(DesktopFileChange {
        operation_id: request.operation_id.clone(),
        old_path: Some(entry.path.clone()),
        new_path: None,
        trash: Some(ticket),
    })
}

fn apply_copy_or_move(
    request: &DesktopMutationRequest,
    root: &PinnedRoot,
    destination: &PinnedDir,
    source_root: &PinnedRoot,
    source: &ResolvedEntry,
    target_name: &[u8],
    is_move: bool,
    expected_source: Option<&DesktopSourcePrecondition>,
    controls: &[ControlRoot],
    check: &mut dyn FnMut(LocalNativeFileCheckPhase) -> DResult<()>,
) -> std::result::Result<DesktopFileChange, DesktopMutationError> {
    check_source_precondition(if is_move { expected_source } else { None }, &source.info)?;
    validate_destination_name(target_name).map_err(DesktopMutationError::Before)?;
    let target_candidate =
        target_candidate_nodes(destination, target_name).map_err(DesktopMutationError::Before)?;
    ensure_not_control_overlap(&target_candidate, controls)
        .map_err(DesktopMutationError::Before)?;
    ensure_not_control_overlap(source.path_nodes(), controls)
        .map_err(DesktopMutationError::Before)?;
    let target_wide = component(target_name)
        .map_err(desktop_error)
        .map_err(DesktopMutationError::Before)?;

    if is_move && source.info.ident.volume != destination.info.ident.volume {
        return Err(DesktopFileErrorCode::Unsupported.into());
    }

    if is_move {
        if kind_of(&source.info) == Kind::Directory
            && path_prefix(source.path_nodes(), &destination.nodes)
        {
            return Err(DesktopFileErrorCode::Protected.into());
        }
        let tree_snapshot =
            guarded_tree_snapshot(source, controls, check).map_err(DesktopMutationError::Before)?;
        if destination.info.ident == source.parent.info.ident
            && fold(&source.name) == fold(target_name)
        {
            if source.name == target_name {
                return Ok(DesktopFileChange {
                    operation_id: request.operation_id.clone(),
                    old_path: Some(source.path.clone()),
                    new_path: Some(source.path.clone()),
                    trash: None,
                });
            }
            match open_attributes(destination.handle.as_raw_handle(), &target_wide) {
                Ok((_, existing)) if existing.ident == source.info.ident => {
                    return case_only_rename(
                        source,
                        destination,
                        target_name,
                        request,
                        source_root,
                        root,
                        controls,
                        tree_snapshot.as_ref(),
                        check,
                    );
                }
                Ok(_) => return Err(DesktopFileErrorCode::Exists.into()),
                Err(Error::NotFound) => {}
                Err(error) => return Err(desktop_error(error).into()),
            }
        }
        absent(destination.handle.as_raw_handle(), &target_wide)
            .map_err(DesktopMutationError::Before)?;
        let (change, current) = open_for_change(
            source.parent.handle.as_raw_handle(),
            &component(&source.name)
                .map_err(desktop_error)
                .map_err(DesktopMutationError::Before)?,
            source.info.ident,
        )
        .map_err(DesktopMutationError::Before)?;
        if !same_info(&current, &source.info) {
            return Err(DesktopFileErrorCode::Changed.into());
        }
        check_before_publish(check).map_err(DesktopMutationError::Before)?;
        root.revalidate().map_err(DesktopMutationError::Before)?;
        source_root
            .revalidate()
            .map_err(DesktopMutationError::Before)?;
        destination
            .revalidate(root)
            .map_err(DesktopMutationError::Before)?;
        source
            .revalidate(source_root)
            .map_err(DesktopMutationError::Before)?;
        revalidate_controls(controls).map_err(DesktopMutationError::Before)?;
        verify_guarded_tree(source, tree_snapshot.as_ref(), controls, check)
            .map_err(DesktopMutationError::Before)?;
        ensure_not_control_overlap(source.path_nodes(), controls)
            .map_err(DesktopMutationError::Before)?;
        ensure_not_control_overlap(&target_candidate, controls)
            .map_err(DesktopMutationError::Before)?;
        absent(destination.handle.as_raw_handle(), &target_wide)
            .map_err(DesktopMutationError::Before)?;
        check_phase(check, LocalNativeFileCheckPhase::Publication)
            .map_err(DesktopMutationError::Before)?;
        rename_no_replace(
            change.as_raw_handle(),
            destination.handle.as_raw_handle(),
            &target_wide,
        )
        .map_err(desktop_error)
        .map_err(DesktopMutationError::Before)?;
        return Ok(DesktopFileChange {
            operation_id: request.operation_id.clone(),
            old_path: Some(source.path.clone()),
            new_path: Some(
                destination
                    .child_path(target_name)
                    .map_err(DesktopMutationError::Before)?,
            ),
            trash: None,
        });
    }

    if kind_of(&source.info) == Kind::Symlink {
        return Err(DesktopFileErrorCode::Unsupported.into());
    }
    if !matches!(kind_of(&source.info), Kind::File | Kind::Directory) {
        return Err(DesktopFileErrorCode::Unsupported.into());
    }
    absent(destination.handle.as_raw_handle(), &target_wide)
        .map_err(DesktopMutationError::Before)?;

    let stage_name =
        desktop_staging_name(&request.operation_id).map_err(DesktopMutationError::Before)?;
    let security =
        PrivateStageSecurity::current_user_and_system().map_err(DesktopMutationError::Before)?;
    let directory = kind_of(&source.info) == Kind::Directory;
    let mut stage = if directory {
        create_stage_directory(destination, &stage_name, &security)
    } else {
        create_stage_file(destination, &stage_name, &security)
    }
    .map_err(DesktopMutationError::Before)?;
    let mut snapshot = TreeSnapshot::default();
    if let Err(error) = copy_tree_to_stage(
        source,
        &mut stage,
        &security,
        controls,
        &mut snapshot,
        check,
    ) {
        if stage.cleanup().is_err() {
            return Err(DesktopMutationError::Uncertain);
        }
        return Err(error.into());
    }
    let result = (|| -> DResult<()> {
        check_before_publish(check)?;
        root.revalidate()?;
        source_root.revalidate()?;
        destination.revalidate(root)?;
        source.revalidate(source_root)?;
        revalidate_controls(controls)?;
        revalidate_snapshot(source, &snapshot, controls, check, true, false)?;
        ensure_not_control_overlap(&target_candidate, controls)?;
        absent(destination.handle.as_raw_handle(), &target_wide)?;
        check_phase(check, LocalNativeFileCheckPhase::Publication)?;
        rename_no_replace(
            stage.handle.as_raw_handle(),
            destination.handle.as_raw_handle(),
            &target_wide,
        )
        .map_err(desktop_error)?;
        stage.mark_published();
        set_copy_attributes(stage.handle.as_raw_handle(), &source.info, false)?;
        unprotect_stage_dacl(stage.handle.as_raw_handle())?;
        Ok(())
    })();
    if let Err(error) = result {
        if stage.published {
            return Err(DesktopMutationError::Uncertain);
        }
        if stage.cleanup().is_err() {
            return Err(DesktopMutationError::Uncertain);
        }
        return Err(error.into());
    }
    Ok(DesktopFileChange {
        operation_id: request.operation_id.clone(),
        old_path: Some(source.path.clone()),
        new_path: Some(
            destination
                .child_path(target_name)
                .map_err(DesktopMutationError::Before)?,
        ),
        trash: None,
    })
}

pub(crate) fn apply_mutation(
    request: &DesktopMutationRequest,
    expected_source: Option<&DesktopSourcePrecondition>,
    check: &mut dyn FnMut(LocalNativeFileCheckPhase) -> DResult<()>,
) -> std::result::Result<DesktopFileChange, DesktopMutationError> {
    validate_desktop_request(request)?;
    validate_public_root(&request.root).map_err(DesktopMutationError::Before)?;
    let root = PinnedRoot::open(&request.root, true).map_err(DesktopMutationError::Before)?;
    expected_directory_path(request, &root).map_err(DesktopMutationError::Before)?;
    let controls = open_controls(&request.control_roots).map_err(DesktopMutationError::Before)?;
    let (parent_names, leaf) = match &request.operation {
        crate::desktop::DesktopFileOperation::NewFile { .. }
        | crate::desktop::DesktopFileOperation::NewFolder { .. }
        | crate::desktop::DesktopFileOperation::Copy { .. }
        | crate::desktop::DesktopFileOperation::Move { .. } => (
            relative_names(&request.relative_path).map_err(DesktopMutationError::Before)?,
            None,
        ),
        crate::desktop::DesktopFileOperation::Rename { .. }
        | crate::desktop::DesktopFileOperation::Duplicate
        | crate::desktop::DesktopFileOperation::Trash
        | crate::desktop::DesktopFileOperation::Delete => {
            parse_relative(&request.relative_path).map_err(DesktopMutationError::Before)?
        }
        crate::desktop::DesktopFileOperation::GitDiscard { .. }
        | crate::desktop::DesktopFileOperation::GitIgnore { .. } => {
            return Err(DesktopFileErrorCode::Unsupported.into());
        }
    };
    if relative_names(&request.relative_path)
        .map_err(DesktopMutationError::Before)?
        .iter()
        .any(|name| is_private_name(name))
    {
        return Err(DesktopFileErrorCode::Protected.into());
    }
    let target_parent = root
        .open_dir(&parent_names)
        .map_err(DesktopMutationError::Before)?;
    match &request.operation {
        crate::desktop::DesktopFileOperation::NewFile { name } => apply_create(
            request,
            &root,
            &target_parent,
            name.as_bytes(),
            false,
            &controls,
            check,
        ),
        crate::desktop::DesktopFileOperation::NewFolder { name } => apply_create(
            request,
            &root,
            &target_parent,
            name.as_bytes(),
            true,
            &controls,
            check,
        ),
        crate::desktop::DesktopFileOperation::Copy {
            source_root,
            source,
        }
        | crate::desktop::DesktopFileOperation::Move {
            source_root,
            source,
        } => {
            validate_public_root(source_root).map_err(DesktopMutationError::Before)?;
            let source_root =
                PinnedRoot::open(source_root, false).map_err(DesktopMutationError::Before)?;
            let source_names = relative_names(source).map_err(DesktopMutationError::Before)?;
            let (source_parent_names, source_leaf) = source_names
                .split_last()
                .map(|(leaf, parents)| (parents.to_vec(), leaf.clone()))
                .ok_or(DesktopMutationError::Before(
                    DesktopFileErrorCode::Protected,
                ))?;
            if source_names.iter().any(|name| is_private_name(name)) {
                return Err(DesktopFileErrorCode::Protected.into());
            }
            let source_parent = source_root
                .open_dir(&source_parent_names)
                .map_err(DesktopMutationError::Before)?;
            let source = source_parent
                .resolve_entry(&source_leaf)
                .map_err(DesktopMutationError::Before)?;
            let is_move = matches!(
                request.operation,
                crate::desktop::DesktopFileOperation::Move { .. }
            );
            apply_copy_or_move(
                request,
                &root,
                &target_parent,
                &source_root,
                &source,
                &source.name,
                is_move,
                if is_move { expected_source } else { None },
                &controls,
                check,
            )
        }
        crate::desktop::DesktopFileOperation::Rename { name } => {
            let leaf = leaf.ok_or(DesktopMutationError::Before(
                DesktopFileErrorCode::Protected,
            ))?;
            if is_private_name(&leaf) {
                return Err(DesktopFileErrorCode::Protected.into());
            }
            let entry = target_parent
                .resolve_entry(&leaf)
                .map_err(DesktopMutationError::Before)?;
            apply_rename(
                request,
                &root,
                &entry,
                name.as_bytes(),
                expected_source,
                &controls,
                check,
            )
        }
        crate::desktop::DesktopFileOperation::Duplicate => {
            let leaf = leaf.ok_or(DesktopMutationError::Before(
                DesktopFileErrorCode::Protected,
            ))?;
            if is_private_name(&leaf) {
                return Err(DesktopFileErrorCode::Protected.into());
            }
            let entry = target_parent
                .resolve_entry(&leaf)
                .map_err(DesktopMutationError::Before)?;
            let name = duplicate_name(
                target_parent.handle.as_raw_handle(),
                &leaf,
                kind_of(&entry.info) == Kind::Directory,
            )
            .map_err(DesktopMutationError::Before)?;
            // Duplicate is a copy within the same pinned parent.
            apply_copy_or_move(
                request,
                &root,
                &target_parent,
                &root,
                &entry,
                &name,
                false,
                None,
                &controls,
                check,
            )
        }
        crate::desktop::DesktopFileOperation::Trash => {
            let leaf = leaf.ok_or(DesktopMutationError::Before(
                DesktopFileErrorCode::Protected,
            ))?;
            if is_private_name(&leaf) {
                return Err(DesktopFileErrorCode::Protected.into());
            }
            let entry = target_parent
                .resolve_entry(&leaf)
                .map_err(DesktopMutationError::Before)?;
            apply_trash(request, &root, &entry, expected_source, &controls, check)
        }
        crate::desktop::DesktopFileOperation::Delete => {
            let leaf = leaf.ok_or(DesktopMutationError::Before(
                DesktopFileErrorCode::Protected,
            ))?;
            if is_private_name(&leaf) {
                return Err(DesktopFileErrorCode::Protected.into());
            }
            let entry = target_parent
                .resolve_entry(&leaf)
                .map_err(DesktopMutationError::Before)?;
            apply_delete(request, &root, &entry, expected_source, &controls, check)
        }
        crate::desktop::DesktopFileOperation::GitDiscard { .. }
        | crate::desktop::DesktopFileOperation::GitIgnore { .. } => {
            Err(DesktopFileErrorCode::Unsupported.into())
        }
    }
}

fn open_ticket_entry(
    ticket: &DesktopTrashTicket,
) -> DResult<(
    PinnedRoot,
    PinnedDir,
    OwnedHandle,
    OwnedHandle,
    Info,
    Vec<u16>,
)> {
    ticket.validate_shape()?;
    validate_public_root(&ticket.root)?;
    let root = PinnedRoot::open(&ticket.root, false)?;
    let root_id = parse_identity(&ticket.root_identity)?;
    if root.info.ident != root_id {
        return Err(DesktopFileErrorCode::Changed);
    }
    let relative = ticket
        .original_path
        .strip_prefix(&ticket.root)
        .map_err(|_| DesktopFileErrorCode::Invalid)?;
    let names = relative_names(relative.to_str().ok_or(DesktopFileErrorCode::Invalid)?)?;
    if names.iter().any(|name| is_private_name(name)) {
        return Err(DesktopFileErrorCode::Protected);
    }
    let (parents, leaf) = parse_names_leaf(&names)?;
    let parent = root.open_dir(&parents)?;
    if parent.info.ident != parse_identity(&ticket.parent_identity)? {
        return Err(DesktopFileErrorCode::Changed);
    }
    native_final_path(
        parent.handle.as_raw_handle(),
        ticket
            .original_path
            .parent()
            .ok_or(DesktopFileErrorCode::Invalid)?,
    )
    .map_err(|_| DesktopFileErrorCode::Changed)?;
    let staging_name = desktop_staging_name(&ticket.operation_id)?;
    let staging_wide = component(staging_name.as_bytes()).map_err(desktop_error)?;
    let staging = open_relative(
        parent.handle.as_raw_handle(),
        &staging_wide,
        DELETE | GIT_DIRECTORY_ACCESS | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
        FILE_OPEN,
        DIRECTORY_OPTIONS,
        0,
        true,
    )
    .map_err(desktop_error)?;
    let staging_info = info(staging.as_raw_handle())?;
    if staging_info.ident != parse_identity(&ticket.staging_identity)?
        || kind_of(&staging_info) != Kind::Directory
    {
        return Err(DesktopFileErrorCode::Changed);
    }
    let entry = open_relative(
        staging.as_raw_handle(),
        &component(&leaf).map_err(desktop_error)?,
        DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_OPEN,
        FILE_OPEN_REPARSE_POINT | SYNC,
        0,
        false,
    )
    .map_err(desktop_error)?;
    let entry_info = info(entry.as_raw_handle())?;
    if entry_info.ident != parse_identity(&ticket.entry_identity)?
        || desktop_kind(&entry_info) != ticket.kind
    {
        return Err(DesktopFileErrorCode::Changed);
    }
    native_final_path(entry.as_raw_handle(), &ticket.staged_path)
        .map_err(|_| DesktopFileErrorCode::Changed)?;
    native_final_path(staging.as_raw_handle(), &ticket.staging_directory)
        .map_err(|_| DesktopFileErrorCode::Changed)?;
    Ok((root, parent, staging, entry, entry_info, staging_wide))
}

fn parse_names_leaf(names: &[Vec<u8>]) -> DResult<(Vec<Vec<u8>>, Vec<u8>)> {
    let (leaf, parents) = names.split_last().ok_or(DesktopFileErrorCode::Invalid)?;
    Ok((parents.to_vec(), leaf.clone()))
}

pub(crate) fn finish_trash<E>(
    ticket: &DesktopTrashTicket,
    transfer: impl FnOnce(&Path) -> std::result::Result<(), E>,
) -> std::result::Result<(), DesktopTrashError<E>> {
    let opened = open_ticket_entry(ticket).map_err(DesktopTrashError::Before)?;
    let (root, parent, staging, entry, expected_entry, entry_wide) = opened;
    // Keep all path-chain and leaf handles live for the entire shell transfer.
    let staging_info = info(staging.as_raw_handle()).map_err(DesktopTrashError::Before)?;
    if !same_info(
        &info(entry.as_raw_handle()).map_err(DesktopTrashError::Before)?,
        &expected_entry,
    ) {
        return Err(DesktopTrashError::Before(DesktopFileErrorCode::Changed));
    }
    root.revalidate().map_err(DesktopTrashError::Before)?;
    parent
        .revalidate(&root)
        .map_err(DesktopTrashError::Before)?;
    if staging_info.ident
        != parse_identity(&ticket.staging_identity).map_err(DesktopTrashError::Before)?
    {
        return Err(DesktopTrashError::Before(DesktopFileErrorCode::Changed));
    }
    transfer(&ticket.staged_path).map_err(DesktopTrashError::Transfer)?;
    root.revalidate()
        .map_err(|_| DesktopTrashError::Uncertain)?;
    parent
        .revalidate(&root)
        .map_err(|_| DesktopTrashError::Uncertain)?;
    let (staging_named, staging_named_info) = open_attributes(
        parent.handle.as_raw_handle(),
        &component(
            desktop_staging_name(&ticket.operation_id)
                .map_err(|_| DesktopTrashError::Uncertain)?
                .as_bytes(),
        )
        .map_err(desktop_error)
        .map_err(|_| DesktopTrashError::Uncertain)?,
    )
    .map_err(desktop_error)
    .map_err(|_| DesktopTrashError::Uncertain)?;
    if staging_named_info.ident != staging_info.ident {
        return Err(DesktopTrashError::Uncertain);
    }
    match open_attributes(staging.as_raw_handle(), &entry_wide) {
        Err(Error::NotFound) => {}
        Ok((_, remaining)) if remaining.ident == expected_entry.ident => {
            return Err(DesktopTrashError::Uncertain);
        }
        _ => return Err(DesktopTrashError::Uncertain),
    }
    if !read_dir_names(staging.as_raw_handle())
        .map_err(desktop_error)
        .map_err(|_| DesktopTrashError::Uncertain)?
        .is_empty()
    {
        return Err(DesktopTrashError::Uncertain);
    }
    let after_transfer = info(staging.as_raw_handle()).map_err(|_| DesktopTrashError::Uncertain)?;
    if kind_of(&after_transfer) != Kind::Directory || after_transfer.ident != staging_info.ident {
        return Err(DesktopTrashError::Uncertain);
    }
    drop(staging_named);
    // The system transfer is already known to have consumed the staged entry.
    // Removing the now-empty private container is best effort; a cleanup
    // failure must not turn that completed transfer into a replayable result.
    let _ = delete_entry(staging.as_raw_handle());
    Ok(())
}
