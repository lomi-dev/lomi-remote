// Field widths of `libc::stat` differ between Unix targets; the casts keep one
// portable implementation.
#![allow(clippy::unnecessary_cast)]

use crate::common::{classify, is_private_staging_name, mint};
use crate::types::*;
use crate::{
    GitFilePrecondition, GitFinalTarget, GitPublication, GitPublishOutcome, GitPullFile,
    GitPullNodeKind, GitPullPrecondition, GitPullPublication, GitWorktreePrecondition,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

pub(crate) mod desktop;
pub(crate) mod desktop_git;
pub(crate) mod owner_git;

#[cfg(target_os = "linux")]
const MAX_CHILD_WATCHES: usize = 256;
#[cfg(target_os = "macos")]
const MAX_CHILD_WATCHES: usize = 64;
#[cfg(target_os = "macos")]
const WATCH_RESERVED_DESCRIPTORS: libc::rlim_t = 16;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct Ident {
    dev: u64,
    ino: u64,
    birth_sec: i64,
    birth_nsec: i64,
}

struct Node {
    parent: Option<EntryRef>,
    name: Vec<u8>,
    ident: Ident,
}

struct PullCreatedDir {
    parent: OwnedFd,
    name: CString,
    identity: Ident,
}

struct StagedPullFile {
    source: GitPullFile,
    target_parent: OwnedFd,
    target_parent_identity: Ident,
    target_name: CString,
    temp_name: Option<CString>,
    temp_identity: Option<Ident>,
    temp_file: Option<File>,
    source_security: Option<GitFileSecurity>,
    published_security: Option<GitFileSecurity>,
}

struct GitPublishedGuard {
    base: EntryRef,
    parent_suffix: Vec<Vec<u8>>,
    parent_identities: Vec<Ident>,
    target_name: Vec<u8>,
    file_identity: Ident,
    revision: String,
    content_digest: [u8; 32],
    content_len: usize,
    security: GitFileSecurity,
    file: File,
}

static NEXT_GIT_PULL_TEMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
static NEXT_NATIVE_FILE_TEMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
type NativeResult<T, E> = std::result::Result<T, E>;

#[derive(Default)]
struct Registry {
    nodes: HashMap<EntryRef, Node>,
    by_name: HashMap<(EntryRef, Vec<u8>), EntryRef>,
}

pub struct FileRoot {
    root_fd: OwnedFd,
    root_ident: Ident,
    root_entry: EntryRef,
    owner_metadata: Option<OwnerMetadataBinding>,
    salt: [u8; 16],
    protected: Mutex<Vec<Ident>>,
    registry: Mutex<Registry>,
    /// Serializes mutations so identity/revision checks and the syscall that
    /// follows them cannot interleave with another mutation of this root.
    write: Mutex<()>,
}

struct OwnerMetadataBinding {
    path: PathBuf,
    components: Vec<Vec<u8>>,
    identities: Vec<Ident>,
    protected_paths: Vec<PathBuf>,
    allow_workspace_descendant: bool,
    /// Retain every named ancestor descriptor as well as the root descriptor.
    _ancestor_handles: Vec<OwnedFd>,
}

struct OpenedOwnerMetadataPath {
    root: OwnedFd,
    path: PathBuf,
    components: Vec<Vec<u8>>,
    identities: Vec<Ident>,
    ancestor_handles: Vec<OwnedFd>,
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Maps an errno to the closed engine error set. `ancestor` selects the
/// meaning of "something on the path is no longer what we recorded".
fn map_errno(errno: i32, ancestor: bool) -> Error {
    match errno {
        libc::ENOENT => Error::NotFound,
        libc::ELOOP | libc::ENOTDIR if ancestor => Error::Changed,
        libc::ENOTDIR => Error::NotFound,
        libc::ELOOP => Error::Changed,
        libc::EEXIST => Error::Exists,
        libc::ENOTEMPTY => Error::NotEmpty,
        libc::EXDEV | libc::ENOSYS | libc::ENOTSUP => Error::Unsupported,
        libc::EINVAL | libc::ENAMETOOLONG => Error::Invalid,
        libc::EMFILE | libc::ENFILE => Error::Limit,
        libc::EACCES | libc::EPERM | libc::EROFS => Error::Io(std::io::ErrorKind::PermissionDenied),
        other => Error::Io(std::io::Error::from_raw_os_error(other).kind()),
    }
}

fn cstring(name: &[u8]) -> Result<CString> {
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') {
        return Err(Error::Invalid);
    }
    CString::new(name).map_err(|_| Error::Invalid)
}

fn fstat(fd: RawFd) -> Result<libc::stat> {
    let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(map_errno(last_errno(), false));
    }
    Ok(st)
}

fn check_git_lock_identity(
    parent: RawFd,
    name: &CStr,
    lock_fd: RawFd,
    expected: Ident,
) -> Result<()> {
    check_git_fd_name_identity(parent, name, lock_fd, expected, Some(1))
}

fn check_git_fd_name_identity(
    parent: RawFd,
    name: &CStr,
    file_fd: RawFd,
    expected: Ident,
    expected_nlink: Option<u64>,
) -> Result<()> {
    let file_stat = fstat(file_fd)?;
    if kind_of(&file_stat) != Kind::File
        || expected_nlink.is_some_and(|nlink| file_stat.st_nlink as u64 != nlink)
        || ident_fd(file_fd, &file_stat)? != expected
    {
        return Err(Error::Changed);
    }
    let name_stat = fstatat_nofollow(parent, name).map_err(|error| {
        if error == Error::NotFound {
            Error::Changed
        } else {
            error
        }
    })?;
    if kind_of(&name_stat) != Kind::File
        || expected_nlink.is_some_and(|nlink| name_stat.st_nlink as u64 != nlink)
        || ident_at(parent, name, &name_stat)? != expected
    {
        return Err(Error::Changed);
    }
    Ok(())
}

fn check_git_entry_identity(parent: RawFd, name: &CStr, expected: Ident) -> Result<()> {
    let name_stat = fstatat_nofollow(parent, name).map_err(|error| {
        if error == Error::NotFound {
            Error::Changed
        } else {
            error
        }
    })?;
    if kind_of(&name_stat) != Kind::File || ident_at(parent, name, &name_stat)? != expected {
        return Err(Error::Changed);
    }
    Ok(())
}

fn unlink_owned_git_file(parent: RawFd, name: &CStr, expected: Ident) -> Result<()> {
    match check_git_entry_identity(parent, name, expected) {
        Ok(()) => {}
        Err(Error::Changed) => return Ok(()),
        Err(error) => return Err(error),
    }
    if unsafe { libc::unlinkat(parent, name.as_ptr(), 0) } != 0 {
        return Err(map_errno(last_errno(), false));
    }
    Ok(())
}

fn unlink_owned_git_lock(parent: RawFd, name: &CStr, expected: Ident) {
    let _ = unlink_owned_git_file(parent, name, expected);
}

fn fstatat_nofollow(dir: RawFd, name: &CStr) -> Result<libc::stat> {
    let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(map_errno(last_errno(), false));
    }
    Ok(st)
}

fn openat(dir: RawFd, name: &CStr, flags: i32, mode: u32, ancestor: bool) -> Result<OwnedFd> {
    let fd = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            flags | libc::O_CLOEXEC,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(map_errno(last_errno(), ancestor));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn dup(fd: RawFd) -> Result<OwnedFd> {
    let new = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if new < 0 {
        return Err(map_errno(last_errno(), false));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(new) })
}

#[cfg(target_os = "macos")]
fn ident_of(st: &libc::stat) -> Ident {
    Ident {
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
        birth_sec: st.st_birthtime as i64,
        birth_nsec: st.st_birthtime_nsec as i64,
    }
}

#[cfg(target_os = "linux")]
fn statx_ident(dir: RawFd, name: &CStr, flags: i32, expected: &libc::stat) -> Result<Ident> {
    let mut st = unsafe { std::mem::zeroed::<libc::statx>() };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_statx,
            dir,
            name.as_ptr(),
            flags,
            libc::STATX_BASIC_STATS | libc::STATX_BTIME,
            &mut st,
        )
    };
    if rc != 0 {
        return Err(map_errno(last_errno(), false));
    }
    if st.stx_mask & libc::STATX_BTIME == 0 {
        return Err(Error::Unsupported);
    }
    let expected_ino = expected.st_ino as u64;
    if st.stx_ino != expected_ino
        || st.stx_dev_major as u64 != libc::major(expected.st_dev) as u64
        || st.stx_dev_minor as u64 != libc::minor(expected.st_dev) as u64
    {
        return Err(Error::Changed);
    }
    Ok(Ident {
        dev: ((st.stx_dev_major as u64) << 32) | st.stx_dev_minor as u64,
        ino: st.stx_ino,
        birth_sec: st.stx_btime.tv_sec as i64,
        birth_nsec: st.stx_btime.tv_nsec as i64,
    })
}

#[cfg(target_os = "linux")]
fn ident_fd(fd: RawFd, expected: &libc::stat) -> Result<Ident> {
    statx_ident(
        fd,
        c"",
        libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
        expected,
    )
}

#[cfg(target_os = "linux")]
fn ident_at(dir: RawFd, name: &CStr, expected: &libc::stat) -> Result<Ident> {
    statx_ident(dir, name, libc::AT_SYMLINK_NOFOLLOW, expected)
}

#[cfg(target_os = "macos")]
fn ident_fd(_fd: RawFd, expected: &libc::stat) -> Result<Ident> {
    Ok(ident_of(expected))
}
#[cfg(target_os = "macos")]
fn ident_at(_dir: RawFd, _name: &CStr, expected: &libc::stat) -> Result<Ident> {
    Ok(ident_of(expected))
}

fn kind_of(st: &libc::stat) -> Kind {
    match st.st_mode as u32 & libc::S_IFMT as u32 {
        m if m == libc::S_IFREG as u32 => Kind::File,
        m if m == libc::S_IFDIR as u32 => Kind::Directory,
        m if m == libc::S_IFLNK as u32 => Kind::Symlink,
        _ => Kind::Other,
    }
}

fn is_git_name(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(b".git")
}

fn native_source_precondition(
    identity: Ident,
    kind: Kind,
) -> crate::desktop::DesktopSourcePrecondition {
    let kind = match kind {
        Kind::File => crate::desktop::DesktopFileKind::File,
        Kind::Directory => crate::desktop::DesktopFileKind::Directory,
        Kind::Symlink => crate::desktop::DesktopFileKind::Symlink,
        Kind::Other => crate::desktop::DesktopFileKind::Other,
    };
    crate::desktop::DesktopSourcePrecondition {
        identity: crate::desktop::DesktopFileIdentity {
            volume: identity.dev.to_string(),
            file_id: identity.ino.to_string(),
        },
        kind,
    }
}

fn check_expected_native_source(
    expected: Option<&crate::desktop::DesktopSourcePrecondition>,
    identity: Ident,
    kind: Kind,
) -> Result<()> {
    if let Some(expected) = expected {
        if !expected.identity.is_valid() || *expected != native_source_precondition(identity, kind)
        {
            return Err(Error::Changed);
        }
    }
    Ok(())
}

fn check_native_mutation_phase(
    check: &mut impl FnMut(LocalNativeFileCheckPhase) -> bool,
    phase: LocalNativeFileCheckPhase,
) -> Result<()> {
    if check(phase) {
        Ok(())
    } else {
        Err(Error::Changed)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct NativeFileStamp {
    device: u64,
    inode: u64,
    length: u64,
    links: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NativeFileSecurity {
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
    #[cfg(target_os = "macos")]
    acl: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GitFileSecurity {
    uid: u32,
    gid: u32,
    mode: u32,
    extended: NativeFileSecurity,
}

const NATIVE_XATTR_LIMIT: usize = 1024 * 1024;

#[cfg(target_os = "macos")]
#[link(name = "System")]
unsafe extern "C" {
    fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut libc::c_void;
    fn acl_to_text(acl: *mut libc::c_void, length: *mut libc::ssize_t) -> *mut libc::c_char;
    fn acl_from_text(text: *const libc::c_char) -> *mut libc::c_void;
    fn acl_set_fd_np(fd: libc::c_int, acl: *mut libc::c_void, kind: libc::c_int) -> libc::c_int;
    fn acl_delete_fd_np(fd: libc::c_int, kind: libc::c_int) -> libc::c_int;
    fn acl_free(value: *mut libc::c_void) -> libc::c_int;
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn native_xattrs(fd: RawFd) -> NativeResult<Vec<(Vec<u8>, Vec<u8>)>, LocalNativeFileError> {
    #[cfg(target_os = "linux")]
    let list_size = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0) };
    #[cfg(target_os = "macos")]
    let list_size = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0, 0) };
    if list_size < 0 {
        return Err(local_native_io(std::io::Error::last_os_error()));
    }
    if list_size as usize > NATIVE_XATTR_LIMIT {
        return Err(LocalNativeFileError::Limit);
    }
    let mut names = vec![0u8; list_size as usize];
    if list_size > 0 {
        #[cfg(target_os = "linux")]
        let actual = unsafe { libc::flistxattr(fd, names.as_mut_ptr().cast(), names.len()) };
        #[cfg(target_os = "macos")]
        let actual = unsafe { libc::flistxattr(fd, names.as_mut_ptr().cast(), names.len(), 0) };
        if actual < 0 || actual as usize != names.len() {
            return Err(LocalNativeFileError::Changed);
        }
    }
    let mut values = Vec::new();
    let mut total = names.len();
    for name in names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        let c_name = CString::new(name).map_err(|_| LocalNativeFileError::Invalid)?;
        #[cfg(target_os = "linux")]
        let value_size = unsafe { libc::fgetxattr(fd, c_name.as_ptr(), std::ptr::null_mut(), 0) };
        #[cfg(target_os = "macos")]
        let value_size =
            unsafe { libc::fgetxattr(fd, c_name.as_ptr(), std::ptr::null_mut(), 0, 0, 0) };
        if value_size < 0 {
            return Err(local_native_io(std::io::Error::last_os_error()));
        }
        total = total
            .checked_add(value_size as usize)
            .ok_or(LocalNativeFileError::Limit)?;
        if total > NATIVE_XATTR_LIMIT {
            return Err(LocalNativeFileError::Limit);
        }
        let mut value = vec![0u8; value_size as usize];
        if value_size > 0 {
            #[cfg(target_os = "linux")]
            let actual = unsafe {
                libc::fgetxattr(fd, c_name.as_ptr(), value.as_mut_ptr().cast(), value.len())
            };
            #[cfg(target_os = "macos")]
            let actual = unsafe {
                libc::fgetxattr(
                    fd,
                    c_name.as_ptr(),
                    value.as_mut_ptr().cast(),
                    value.len(),
                    0,
                    0,
                )
            };
            if actual < 0 || actual as usize != value.len() {
                return Err(LocalNativeFileError::Changed);
            }
        }
        values.push((name.to_vec(), value));
    }
    Ok(values)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn native_xattrs(_fd: RawFd) -> NativeResult<Vec<(Vec<u8>, Vec<u8>)>, LocalNativeFileError> {
    Err(LocalNativeFileError::Unsupported)
}

#[cfg(target_os = "macos")]
fn native_acl(fd: RawFd) -> NativeResult<Option<Vec<u8>>, LocalNativeFileError> {
    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    let acl = unsafe { acl_get_fd_np(fd, ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINVAL) || error.raw_os_error() == Some(libc::ENOENT)
        {
            return Ok(None);
        }
        return Err(local_native_io(error));
    }
    let mut length = 0;
    let text = unsafe { acl_to_text(acl, &mut length) };
    unsafe { acl_free(acl) };
    if text.is_null() || length < 0 || length as usize > NATIVE_XATTR_LIMIT {
        if !text.is_null() {
            unsafe { acl_free(text.cast()) };
        }
        return Err(LocalNativeFileError::Unsupported);
    }
    let bytes = unsafe { std::slice::from_raw_parts(text.cast::<u8>(), length as usize) }.to_vec();
    unsafe { acl_free(text.cast()) };
    Ok(Some(bytes))
}

fn native_file_security(fd: RawFd) -> NativeResult<NativeFileSecurity, LocalNativeFileError> {
    Ok(NativeFileSecurity {
        xattrs: native_xattrs(fd)?,
        #[cfg(target_os = "macos")]
        acl: native_acl(fd)?,
    })
}

fn native_apply_file_security(
    fd: RawFd,
    security: &NativeFileSecurity,
) -> NativeResult<(), LocalNativeFileError> {
    let existing = native_xattrs(fd)?;
    for (name, _) in existing
        .iter()
        .filter(|(name, _)| !security.xattrs.iter().any(|(wanted, _)| wanted == name))
    {
        let name = CString::new(name.as_slice()).map_err(|_| LocalNativeFileError::Invalid)?;
        #[cfg(target_os = "linux")]
        let result = unsafe { libc::fremovexattr(fd, name.as_ptr()) };
        #[cfg(target_os = "macos")]
        let result = unsafe { libc::fremovexattr(fd, name.as_ptr(), 0) };
        if result != 0 {
            return Err(local_native_io(std::io::Error::last_os_error()));
        }
    }
    for (name, value) in &security.xattrs {
        let name = CString::new(name.as_slice()).map_err(|_| LocalNativeFileError::Invalid)?;
        #[cfg(target_os = "linux")]
        let result =
            unsafe { libc::fsetxattr(fd, name.as_ptr(), value.as_ptr().cast(), value.len(), 0) };
        #[cfg(target_os = "macos")]
        let result =
            unsafe { libc::fsetxattr(fd, name.as_ptr(), value.as_ptr().cast(), value.len(), 0, 0) };
        if result != 0 {
            return Err(local_native_io(std::io::Error::last_os_error()));
        }
    }
    #[cfg(target_os = "macos")]
    {
        match security.acl.as_ref() {
            Some(bytes) => {
                let text =
                    CString::new(bytes.as_slice()).map_err(|_| LocalNativeFileError::Invalid)?;
                let acl = unsafe { acl_from_text(text.as_ptr()) };
                if acl.is_null() {
                    return Err(LocalNativeFileError::Unsupported);
                }
                let result = unsafe { acl_set_fd_np(fd, acl, 0x0000_0100) };
                unsafe { acl_free(acl) };
                if result != 0 {
                    return Err(local_native_io(std::io::Error::last_os_error()));
                }
            }
            None => clear_git_new_file_acl(fd).map_err(|error| match error {
                Error::Unsupported => LocalNativeFileError::Unsupported,
                Error::Changed => LocalNativeFileError::Changed,
                Error::Limit => LocalNativeFileError::Limit,
                _ => LocalNativeFileError::Io,
            })?,
        }
    }
    if &native_file_security(fd)? != security {
        return Err(LocalNativeFileError::Changed);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn clear_git_new_file_acl(fd: RawFd) -> Result<()> {
    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    if unsafe { acl_delete_fd_np(fd, ACL_TYPE_EXTENDED) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENOENT) {
            return Err(Error::Unsupported);
        }
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn clear_git_new_file_acl(_fd: RawFd) -> Result<()> {
    Ok(())
}

fn git_native_security_error(error: LocalNativeFileError) -> Error {
    match error {
        LocalNativeFileError::NotFound => Error::NotFound,
        LocalNativeFileError::Changed => Error::Changed,
        LocalNativeFileError::Exists => Error::Exists,
        LocalNativeFileError::Invalid => Error::Invalid,
        LocalNativeFileError::Unsupported => Error::Unsupported,
        LocalNativeFileError::Limit => Error::Limit,
        LocalNativeFileError::Protected | LocalNativeFileError::Io => Error::Unsupported,
    }
}

fn git_file_security(fd: RawFd) -> Result<GitFileSecurity> {
    let stat = fstat(fd)?;
    if kind_of(&stat) != Kind::File {
        return Err(Error::Unsupported);
    }
    if stat.st_nlink != 1 {
        return Err(Error::Protected);
    }
    Ok(GitFileSecurity {
        uid: stat.st_uid,
        gid: stat.st_gid,
        mode: stat.st_mode as u32 & 0o7777,
        extended: native_file_security(fd).map_err(git_native_security_error)?,
    })
}

fn git_named_file_security(parent: RawFd, name: &CStr) -> Result<Option<GitFileSecurity>> {
    let named_stat = match fstatat_nofollow(parent, name) {
        Ok(stat) => stat,
        Err(Error::NotFound) => return Ok(None),
        Err(error) => return Err(error),
    };
    if kind_of(&named_stat) != Kind::File {
        return Err(Error::Unsupported);
    }
    if named_stat.st_nlink != 1 {
        return Err(Error::Protected);
    }
    let fd = openat(
        parent,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        0,
        false,
    )?;
    let held_stat = fstat(fd.as_raw_fd())?;
    if kind_of(&held_stat) != Kind::File
        || held_stat.st_nlink != 1
        || ident_fd(fd.as_raw_fd(), &held_stat)? != ident_at(parent, name, &named_stat)?
    {
        return Err(Error::Changed);
    }
    git_file_security(fd.as_raw_fd()).map(Some)
}

fn check_git_named_file_security(
    parent: RawFd,
    name: &CStr,
    expected: Option<&GitFileSecurity>,
) -> Result<()> {
    if git_named_file_security(parent, name)?.as_ref() != expected {
        return Err(Error::Changed);
    }
    Ok(())
}

fn apply_git_file_security(
    fd: RawFd,
    source: Option<&GitFileSecurity>,
    executable: Option<bool>,
) -> Result<GitFileSecurity> {
    let (uid, gid, mode, extended) = match source {
        Some(source) => {
            let mode = match executable {
                Some(true) => (source.mode & !0o111) | (source.mode & 0o111) | 0o100,
                Some(false) => source.mode & !0o111,
                None => source.mode,
            };
            (source.uid, source.gid, mode, &source.extended)
        }
        None => {
            let mode = 0o600 | if executable == Some(true) { 0o100 } else { 0 };
            // New Git metadata uses owner-only permissions. A new worktree
            // file inherits only the requested owner execute bit.
            if unsafe { libc::fchmod(fd, mode) } != 0 {
                return Err(map_errno(last_errno(), false));
            }
            clear_git_new_file_acl(fd)?;
            let security = git_file_security(fd)?;
            if security.mode != mode as u32 {
                return Err(Error::Unsupported);
            }
            return Ok(security);
        }
    };
    if unsafe { libc::fchown(fd, uid, gid) } != 0 {
        return Err(Error::Unsupported);
    }
    if unsafe { libc::fchmod(fd, mode as libc::mode_t) } != 0 {
        return Err(Error::Unsupported);
    }
    native_apply_file_security(fd, extended).map_err(git_native_security_error)?;
    git_file_security(fd)
}

fn native_hash_owned_file(
    file: &mut File,
    expected_length: u64,
) -> NativeResult<(String, NativeFileStamp), LocalNativeFileError> {
    let before = stat_from_metadata(&file.metadata().map_err(local_native_io)?);
    let before = NativeFileStamp::read(&before);
    if before.length != expected_length {
        return Err(LocalNativeFileError::Changed);
    }
    file.seek(SeekFrom::Start(0)).map_err(local_native_io)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let count = file.read(&mut buffer).map_err(local_native_io)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(LocalNativeFileError::Limit)?;
        if total > expected_length {
            return Err(LocalNativeFileError::Changed);
        }
        digest.update(&buffer[..count]);
    }
    if total != expected_length {
        return Err(LocalNativeFileError::Changed);
    }
    let after = stat_from_metadata(&file.metadata().map_err(local_native_io)?);
    let after = NativeFileStamp::read(&after);
    if after != before {
        return Err(LocalNativeFileError::Changed);
    }
    file.seek(SeekFrom::Start(0)).map_err(local_native_io)?;
    Ok((format!("{:x}", digest.finalize()), after))
}

fn verify_native_publication(
    parent: &File,
    parent_path: &Path,
    parent_identity: (u64, u64),
    name: &CStr,
    staged: &File,
    expected_length: u64,
    expected_sha256: &str,
    expected_security: Option<&NativeFileSecurity>,
) -> NativeResult<String, LocalNativeFileError> {
    let held = stat_from_metadata(&staged.metadata().map_err(local_native_io)?);
    let held_stamp = NativeFileStamp::read(&held);
    if held_stamp.links != 1 || held_stamp.length != expected_length {
        return Err(LocalNativeFileError::Changed);
    }
    let (mut published, published_stamp) = native_open_file(parent, name)?;
    if published_stamp.identity() != held_stamp.identity()
        || published_stamp.links != 1
        || published_stamp.length != expected_length
    {
        return Err(LocalNativeFileError::Changed);
    }
    let (actual_sha256, hashed_stamp) = native_hash_owned_file(&mut published, expected_length)?;
    if actual_sha256 != expected_sha256 || hashed_stamp != published_stamp {
        return Err(LocalNativeFileError::Changed);
    }
    if let Some(expected_security) = expected_security {
        if &native_file_security(published.as_raw_fd())? != expected_security {
            return Err(LocalNativeFileError::Changed);
        }
    }
    let named_stat = fstatat_nofollow(parent.as_raw_fd(), name).map_err(local_native_error)?;
    if NativeFileStamp::read(&named_stat) != published_stamp {
        return Err(LocalNativeFileError::Changed);
    }
    native_check_parent(parent_path, parent, parent_identity)?;
    Ok(actual_sha256)
}

fn no_check_read_error<E>(
    error: LocalNativeFileReadError<std::convert::Infallible>,
) -> LocalNativeFileReadError<E> {
    match error {
        LocalNativeFileReadError::File(error) => LocalNativeFileReadError::File(error),
        LocalNativeFileReadError::Check(never) => match never {},
    }
}

impl NativeFileStamp {
    fn read(st: &libc::stat) -> Self {
        Self {
            device: st.st_dev as u64,
            inode: st.st_ino as u64,
            length: st.st_size as u64,
            links: st.st_nlink as u64,
            mode: st.st_mode as u32,
            uid: st.st_uid as u32,
            gid: st.st_gid as u32,
            modified: (st.st_mtime as i64, st.st_mtime_nsec as i64),
            changed: (st.st_ctime as i64, st.st_ctime_nsec as i64),
        }
    }
    fn identity(self) -> (u64, u64) {
        (self.device, self.inode)
    }
    fn regular(self) -> bool {
        self.mode & libc::S_IFMT as u32 == libc::S_IFREG as u32
    }
    fn directory(self) -> bool {
        self.mode & libc::S_IFMT as u32 == libc::S_IFDIR as u32
    }
    fn read_only(self) -> bool {
        self.mode & 0o222 == 0
    }
}

fn local_native_error(error: Error) -> LocalNativeFileError {
    match error {
        Error::NotFound => LocalNativeFileError::NotFound,
        Error::Changed => LocalNativeFileError::Changed,
        Error::Protected | Error::NotEmpty => LocalNativeFileError::Protected,
        Error::Exists => LocalNativeFileError::Exists,
        Error::Invalid => LocalNativeFileError::Invalid,
        Error::Unsupported => LocalNativeFileError::Unsupported,
        Error::Limit => LocalNativeFileError::Limit,
        Error::Io(kind) if kind == std::io::ErrorKind::PermissionDenied => {
            LocalNativeFileError::Protected
        }
        Error::Io(_) => LocalNativeFileError::Io,
    }
}

fn local_native_io(error: std::io::Error) -> LocalNativeFileError {
    match error.kind() {
        std::io::ErrorKind::NotFound => LocalNativeFileError::NotFound,
        std::io::ErrorKind::AlreadyExists => LocalNativeFileError::Exists,
        std::io::ErrorKind::PermissionDenied => LocalNativeFileError::Protected,
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData => {
            LocalNativeFileError::Invalid
        }
        _ => LocalNativeFileError::Io,
    }
}

fn native_open_absolute_directory(path: &Path) -> NativeResult<File, LocalNativeFileError> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err(LocalNativeFileError::Invalid);
    }
    let mut directory = File::open("/").map_err(local_native_io)?;
    let mut count = 0;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                count += 1;
                if count > 128 {
                    return Err(LocalNativeFileError::Limit);
                }
                let name =
                    CString::new(name.as_bytes()).map_err(|_| LocalNativeFileError::Invalid)?;
                let next = openat(
                    directory.as_raw_fd(),
                    &name,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                    0,
                    true,
                )
                .map_err(local_native_error)?;
                directory = File::from(next);
            }
            _ => return Err(LocalNativeFileError::Invalid),
        }
    }
    let metadata = directory.metadata().map_err(local_native_io)?;
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(directory.as_raw_fd(), &mut stat) } != 0 {
        return Err(local_native_io(std::io::Error::last_os_error()));
    }
    if !NativeFileStamp::read(&stat).directory() || metadata.is_file() {
        return Err(LocalNativeFileError::Changed);
    }
    Ok(directory)
}

fn native_open_file(
    parent: &File,
    name: &CStr,
) -> NativeResult<(File, NativeFileStamp), LocalNativeFileError> {
    let owned = openat(
        parent.as_raw_fd(),
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        0,
        false,
    )
    .map_err(local_native_error)?;
    let file = File::from(owned);
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut stat) } != 0 {
        return Err(local_native_io(std::io::Error::last_os_error()));
    }
    let stamp = NativeFileStamp::read(&stat);
    if !stamp.regular() {
        return Err(LocalNativeFileError::Unsupported);
    }
    let named = fstatat_nofollow(parent.as_raw_fd(), name).map_err(local_native_error)?;
    if NativeFileStamp::read(&named) != stamp {
        return Err(LocalNativeFileError::Changed);
    }
    Ok((file, stamp))
}

fn native_check_parent(
    path: &Path,
    parent: &File,
    expected: (u64, u64),
) -> NativeResult<(), LocalNativeFileError> {
    let current = native_open_absolute_directory(path)?;
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    let pinned = unsafe { libc::fstat(parent.as_raw_fd(), &mut stat) } == 0;
    if !pinned || NativeFileStamp::read(&stat).identity() != expected {
        return Err(LocalNativeFileError::Changed);
    }
    let mut current_stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(current.as_raw_fd(), &mut current_stat) } != 0
        || NativeFileStamp::read(&current_stat).identity() != expected
    {
        return Err(LocalNativeFileError::Changed);
    }
    Ok(())
}

fn native_require_absent(parent: &File, name: &CStr) -> NativeResult<(), LocalNativeFileError> {
    match fstatat_nofollow(parent.as_raw_fd(), name) {
        Ok(_) => Err(LocalNativeFileError::Exists),
        Err(Error::NotFound) => Ok(()),
        Err(error) => Err(local_native_error(error)),
    }
}

fn native_temp(parent: &File) -> NativeResult<NativeFileTemporary<'_>, LocalNativeFileError> {
    for _ in 0..100 {
        let suffix = NEXT_NATIVE_FILE_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let name =
            CString::new(format!(".lomi-native-{suffix}")).map_err(|_| LocalNativeFileError::Io)?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd >= 0 {
            return Ok(NativeFileTemporary {
                parent,
                name,
                file: unsafe { File::from_raw_fd(fd) },
                linked: true,
            });
        }
        if last_errno() != libc::EEXIST {
            return Err(local_native_io(std::io::Error::last_os_error()));
        }
    }
    Err(LocalNativeFileError::Limit)
}

struct NativeFileTemporary<'a> {
    parent: &'a File,
    name: CString,
    file: File,
    linked: bool,
}
impl Drop for NativeFileTemporary<'_> {
    fn drop(&mut self) {
        if self.linked {
            unsafe {
                libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0);
            }
        }
    }
}

const NATIVE_EDITOR_FILE_LIMIT: u64 = 16 * 1024 * 1024;

/// Explicit local editor target with a pinned parent and recorded file identity.
/// This is not part of the remote `FileRoot` API.
pub struct LocalNativeFile {
    path: PathBuf,
    parent_path: PathBuf,
    parent: File,
    parent_identity: (u64, u64),
    name: CString,
    target: Option<NativeFileStamp>,
}

impl LocalNativeFile {
    pub fn open(path: &Path) -> NativeResult<Self, LocalNativeFileError> {
        if !path.is_absolute() {
            return Err(LocalNativeFileError::Invalid);
        }
        let (path, target_exists) = match std::fs::canonicalize(path) {
            Ok(path) => (path, true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let parent = path.parent().ok_or(LocalNativeFileError::Invalid)?;
                let name = path.file_name().ok_or(LocalNativeFileError::Invalid)?;
                (
                    std::fs::canonicalize(parent)
                        .map_err(local_native_io)?
                        .join(name),
                    false,
                )
            }
            Err(error) => return Err(local_native_io(error)),
        };
        let parent_path = path
            .parent()
            .ok_or(LocalNativeFileError::Invalid)?
            .to_path_buf();
        let name = CString::new(
            path.file_name()
                .ok_or(LocalNativeFileError::Invalid)?
                .as_bytes(),
        )
        .map_err(|_| LocalNativeFileError::Invalid)?;
        let parent = native_open_absolute_directory(&parent_path)?;
        let parent_stat = fstat(parent.as_raw_fd()).map_err(local_native_error)?;
        let parent_identity = NativeFileStamp::read(&parent_stat).identity();
        let target = match native_open_file(&parent, &name) {
            Ok((_, stamp)) => {
                if !target_exists {
                    return Err(LocalNativeFileError::Exists);
                }
                Some(stamp)
            }
            Err(LocalNativeFileError::NotFound) if !target_exists => None,
            Err(error) => return Err(error),
        };
        Ok(Self {
            path,
            parent_path,
            parent,
            parent_identity,
            name,
            target,
        })
    }

    /// Opens an absolute lexical path without following any symbolic link in
    /// its parent chain or at its final component.
    pub fn open_no_follow(path: &Path) -> NativeResult<Self, LocalNativeFileError> {
        if !path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    Component::CurDir | Component::ParentDir | Component::Prefix(_)
                )
            })
        {
            return Err(LocalNativeFileError::Invalid);
        }
        let parent_path = path
            .parent()
            .ok_or(LocalNativeFileError::Invalid)?
            .to_path_buf();
        let name = CString::new(
            path.file_name()
                .ok_or(LocalNativeFileError::Invalid)?
                .as_bytes(),
        )
        .map_err(|_| LocalNativeFileError::Invalid)?;
        let parent = native_open_absolute_directory(&parent_path)?;
        let parent_stat = fstat(parent.as_raw_fd()).map_err(local_native_error)?;
        let parent_identity = NativeFileStamp::read(&parent_stat).identity();
        let target = match native_open_file(&parent, &name) {
            Ok((_, stamp)) => Some(stamp),
            Err(LocalNativeFileError::NotFound) => None,
            Err(error) => return Err(error),
        };
        Ok(Self {
            path: path.to_path_buf(),
            parent_path,
            parent,
            parent_identity,
            name,
            target,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn is_new(&self) -> bool {
        self.target.is_none()
    }

    fn snapshot_with_stamp<E>(
        &self,
        check: &mut impl FnMut(LocalNativeFileCheckPhase) -> NativeResult<(), E>,
    ) -> NativeResult<
        (LocalNativeFileSnapshot, NativeFileStamp, NativeFileSecurity),
        LocalNativeFileReadError<E>,
    > {
        check(LocalNativeFileCheckPhase::Progress).map_err(LocalNativeFileReadError::Check)?;
        let expected = self.target.ok_or(LocalNativeFileReadError::File(
            LocalNativeFileError::NotFound,
        ))?;
        let (mut file, before) =
            native_open_file(&self.parent, &self.name).map_err(LocalNativeFileReadError::File)?;
        if before.identity() != expected.identity() || before.links == 0 {
            return Err(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            ));
        }
        if before.length > NATIVE_EDITOR_FILE_LIMIT {
            return Err(LocalNativeFileReadError::File(LocalNativeFileError::Limit));
        }
        let security_before =
            native_file_security(file.as_raw_fd()).map_err(LocalNativeFileReadError::File)?;
        let mut bytes = Vec::with_capacity(before.length as usize);
        let mut chunk = [0u8; 65_536];
        loop {
            check(LocalNativeFileCheckPhase::Progress).map_err(LocalNativeFileReadError::Check)?;
            let count = file
                .read(&mut chunk)
                .map_err(|error| LocalNativeFileReadError::File(local_native_io(error)))?;
            if count == 0 {
                break;
            }
            if bytes.len() as u64 + count as u64 > NATIVE_EDITOR_FILE_LIMIT {
                return Err(LocalNativeFileReadError::File(LocalNativeFileError::Limit));
            }
            bytes.extend_from_slice(&chunk[..count]);
        }
        let after = file
            .metadata()
            .map_err(|error| LocalNativeFileReadError::File(local_native_io(error)))?;
        let after_stat = stat_from_metadata(&after);
        let named = fstatat_nofollow(self.parent.as_raw_fd(), &self.name)
            .map_err(local_native_error)
            .map_err(LocalNativeFileReadError::File)?;
        let security_after =
            native_file_security(file.as_raw_fd()).map_err(LocalNativeFileReadError::File)?;
        if NativeFileStamp::read(&after_stat) != before
            || NativeFileStamp::read(&named) != before
            || security_before != security_after
            || bytes.len() as u64 != before.length
        {
            return Err(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            ));
        }
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        Ok((
            LocalNativeFileSnapshot {
                bytes,
                sha256,
                read_only: before.read_only(),
            },
            before,
            security_before,
        ))
    }

    pub fn snapshot<E>(
        &self,
        mut check: impl FnMut() -> NativeResult<(), E>,
    ) -> NativeResult<LocalNativeFileSnapshot, LocalNativeFileReadError<E>> {
        let mut phased = |phase| match phase {
            LocalNativeFileCheckPhase::Progress | LocalNativeFileCheckPhase::BeforeEffect => {
                check()
            }
            LocalNativeFileCheckPhase::Validation | LocalNativeFileCheckPhase::Publication => {
                Ok(())
            }
        };
        self.snapshot_with_phase(&mut phased)
    }

    pub fn snapshot_with_phase<E>(
        &self,
        check: &mut impl FnMut(LocalNativeFileCheckPhase) -> NativeResult<(), E>,
    ) -> NativeResult<LocalNativeFileSnapshot, LocalNativeFileReadError<E>> {
        self.snapshot_with_stamp(check)
            .map(|(snapshot, _, _)| snapshot)
    }

    pub fn replace<E>(
        &self,
        expected_sha256: &str,
        bytes: &[u8],
        mut check: impl FnMut() -> NativeResult<(), E>,
    ) -> NativeResult<String, LocalNativeFilePublishError<E>> {
        let mut phased = |phase| match phase {
            LocalNativeFileCheckPhase::Progress | LocalNativeFileCheckPhase::BeforeEffect => {
                check()
            }
            LocalNativeFileCheckPhase::Validation | LocalNativeFileCheckPhase::Publication => {
                Ok(())
            }
        };
        self.replace_with_phase(expected_sha256, bytes, &mut phased)
    }

    pub fn replace_with_phase<E>(
        &self,
        expected_sha256: &str,
        bytes: &[u8],
        check: &mut impl FnMut(LocalNativeFileCheckPhase) -> NativeResult<(), E>,
    ) -> NativeResult<String, LocalNativeFilePublishError<E>> {
        let before = |error| LocalNativeFilePublishError::Before(error);
        if bytes.len() as u64 > NATIVE_EDITOR_FILE_LIMIT {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Limit,
            )));
        }
        let (snapshot, metadata, security) =
            self.snapshot_with_stamp(&mut *check).map_err(before)?;
        if snapshot.sha256 != expected_sha256 {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        if snapshot.read_only || metadata.links != 1 || metadata.mode & 0o7000 != 0 {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Protected,
            )));
        }
        let mut temporary = native_temp(&self.parent)
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        let temporary_metadata = temporary
            .file
            .metadata()
            .map_err(|error| before(LocalNativeFileReadError::File(local_native_io(error))))?;
        let temporary_stat = stat_from_metadata(&temporary_metadata);
        if (temporary_stat.st_uid as u32, temporary_stat.st_gid as u32)
            != (metadata.uid, metadata.gid)
            && unsafe { libc::fchown(temporary.file.as_raw_fd(), metadata.uid, metadata.gid) } != 0
        {
            return Err(before(LocalNativeFileReadError::File(local_native_io(
                std::io::Error::last_os_error(),
            ))));
        }
        native_apply_file_security(temporary.file.as_raw_fd(), &security)
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        if unsafe {
            libc::fchmod(
                temporary.file.as_raw_fd(),
                (metadata.mode & 0o777) as libc::mode_t,
            )
        } != 0
        {
            return Err(before(LocalNativeFileReadError::File(local_native_io(
                std::io::Error::last_os_error(),
            ))));
        }
        native_apply_file_security(temporary.file.as_raw_fd(), &security)
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        for chunk in bytes.chunks(65_536) {
            check(LocalNativeFileCheckPhase::Progress)
                .map_err(|error| before(LocalNativeFileReadError::Check(error)))?;
            temporary
                .file
                .write_all(chunk)
                .map_err(|error| before(LocalNativeFileReadError::File(local_native_io(error))))?;
        }
        let expected_hash = format!("{:x}", Sha256::digest(bytes));
        temporary
            .file
            .sync_all()
            .map_err(|error| before(LocalNativeFileReadError::File(local_native_io(error))))?;
        let (current, current_stamp, current_security) = self
            .snapshot_with_stamp(&mut |_| Ok::<(), std::convert::Infallible>(()))
            .map_err(|error| before(no_check_read_error(error)))?;
        if current.sha256 != expected_sha256
            || current_stamp != metadata
            || current_security != security
        {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        let (staged_hash, held_stamp) =
            native_hash_owned_file(&mut temporary.file, bytes.len() as u64)
                .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        if staged_hash != expected_hash {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        let held_stat = stat_from_metadata(
            &temporary
                .file
                .metadata()
                .map_err(|error| before(LocalNativeFileReadError::File(local_native_io(error))))?,
        );
        if NativeFileStamp::read(&held_stat) != held_stamp
            || held_stamp.links != 1
            || held_stamp.length != bytes.len() as u64
            || native_file_security(temporary.file.as_raw_fd())
                .map_err(|error| before(LocalNativeFileReadError::File(error)))?
                != security
        {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        check(LocalNativeFileCheckPhase::BeforeEffect)
            .map_err(|error| before(LocalNativeFileReadError::Check(error)))?;
        check(LocalNativeFileCheckPhase::Validation)
            .map_err(|error| before(LocalNativeFileReadError::Check(error)))?;
        let (latest, latest_stamp, latest_security) = self
            .snapshot_with_stamp(&mut |_| Ok::<(), std::convert::Infallible>(()))
            .map_err(|error| before(no_check_read_error(error)))?;
        if latest.sha256 != expected_sha256
            || latest_stamp != metadata
            || latest_security != security
        {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        let temp_after_check = temporary
            .file
            .metadata()
            .map_err(|error| before(LocalNativeFileReadError::File(local_native_io(error))))?;
        if NativeFileStamp::read(&stat_from_metadata(&temp_after_check)) != held_stamp {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        let temp_named = native_open_file(&self.parent, &temporary.name)
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        if temp_named.1 != held_stamp {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        let final_named = native_open_file(&self.parent, &self.name)
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        if final_named.1 != latest_stamp {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        if native_file_security(final_named.0.as_raw_fd())
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?
            != latest_security
        {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        let final_metadata = final_named
            .0
            .metadata()
            .map_err(|error| before(LocalNativeFileReadError::File(local_native_io(error))))?;
        let final_named_stat = fstatat_nofollow(self.parent.as_raw_fd(), &self.name)
            .map_err(local_native_error)
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        if NativeFileStamp::read(&stat_from_metadata(&final_metadata)) != latest_stamp
            || NativeFileStamp::read(&final_named_stat) != latest_stamp
        {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        native_check_parent(&self.parent_path, &self.parent, self.parent_identity)
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        check(LocalNativeFileCheckPhase::Publication)
            .map_err(|error| before(LocalNativeFileReadError::Check(error)))?;
        if unsafe {
            libc::renameat(
                self.parent.as_raw_fd(),
                temporary.name.as_ptr(),
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
            )
        } != 0
        {
            return Err(before(LocalNativeFileReadError::File(local_native_io(
                std::io::Error::last_os_error(),
            ))));
        }
        temporary.linked = false;
        let published = verify_native_publication(
            &self.parent,
            &self.parent_path,
            self.parent_identity,
            &self.name,
            &temporary.file,
            bytes.len() as u64,
            &expected_hash,
            Some(&security),
        )
        .map_err(|_| LocalNativeFilePublishError::Uncertain)?;
        self.parent
            .sync_all()
            .map_err(|_| LocalNativeFilePublishError::Uncertain)?;
        Ok(published)
    }

    pub fn create<E>(
        &self,
        bytes: &[u8],
        mut check: impl FnMut() -> NativeResult<(), E>,
    ) -> NativeResult<String, LocalNativeFilePublishError<E>> {
        let mut phased = |phase| match phase {
            LocalNativeFileCheckPhase::Progress | LocalNativeFileCheckPhase::BeforeEffect => {
                check()
            }
            LocalNativeFileCheckPhase::Validation | LocalNativeFileCheckPhase::Publication => {
                Ok(())
            }
        };
        self.create_with_phase(bytes, &mut phased)
    }

    pub fn create_with_phase<E>(
        &self,
        bytes: &[u8],
        check: &mut impl FnMut(LocalNativeFileCheckPhase) -> NativeResult<(), E>,
    ) -> NativeResult<String, LocalNativeFilePublishError<E>> {
        let before = |error| LocalNativeFilePublishError::Before(error);
        if bytes.len() as u64 > NATIVE_EDITOR_FILE_LIMIT {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Limit,
            )));
        }
        if self.target.is_some() {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Exists,
            )));
        }
        let mut temporary = native_temp(&self.parent)
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        for chunk in bytes.chunks(65_536) {
            check(LocalNativeFileCheckPhase::Progress)
                .map_err(|error| before(LocalNativeFileReadError::Check(error)))?;
            temporary
                .file
                .write_all(chunk)
                .map_err(|error| before(LocalNativeFileReadError::File(local_native_io(error))))?;
        }
        temporary
            .file
            .sync_all()
            .map_err(|error| before(LocalNativeFileReadError::File(local_native_io(error))))?;
        let expected_hash = format!("{:x}", Sha256::digest(bytes));
        let (staged_hash, staged_stamp) =
            native_hash_owned_file(&mut temporary.file, bytes.len() as u64)
                .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        if staged_hash != expected_hash || staged_stamp.links != 1 {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        check(LocalNativeFileCheckPhase::BeforeEffect)
            .map_err(|error| before(LocalNativeFileReadError::Check(error)))?;
        check(LocalNativeFileCheckPhase::Validation)
            .map_err(|error| before(LocalNativeFileReadError::Check(error)))?;
        let temp_after_check = temporary
            .file
            .metadata()
            .map_err(|error| before(LocalNativeFileReadError::File(local_native_io(error))))?;
        if NativeFileStamp::read(&stat_from_metadata(&temp_after_check)) != staged_stamp {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        let temp_named = native_open_file(&self.parent, &temporary.name)
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        if temp_named.1 != staged_stamp {
            return Err(before(LocalNativeFileReadError::File(
                LocalNativeFileError::Changed,
            )));
        }
        native_check_parent(&self.parent_path, &self.parent, self.parent_identity)
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        native_require_absent(&self.parent, &self.name)
            .map_err(|error| before(LocalNativeFileReadError::File(error)))?;
        check(LocalNativeFileCheckPhase::Publication)
            .map_err(|error| before(LocalNativeFileReadError::Check(error)))?;
        if unsafe {
            libc::linkat(
                self.parent.as_raw_fd(),
                temporary.name.as_ptr(),
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                0,
            )
        } != 0
        {
            return Err(before(LocalNativeFileReadError::File(local_native_io(
                std::io::Error::last_os_error(),
            ))));
        }
        if unsafe { libc::unlinkat(self.parent.as_raw_fd(), temporary.name.as_ptr(), 0) } != 0 {
            return Err(LocalNativeFilePublishError::Uncertain);
        }
        temporary.linked = false;
        let published = verify_native_publication(
            &self.parent,
            &self.parent_path,
            self.parent_identity,
            &self.name,
            &temporary.file,
            bytes.len() as u64,
            &expected_hash,
            None,
        )
        .map_err(|_| LocalNativeFilePublishError::Uncertain)?;
        self.parent
            .sync_all()
            .map_err(|_| LocalNativeFilePublishError::Uncertain)?;
        Ok(published)
    }
}

fn stat_from_metadata(metadata: &std::fs::Metadata) -> libc::stat {
    use std::os::unix::fs::MetadataExt;
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    stat.st_dev = metadata.dev() as _;
    stat.st_ino = metadata.ino() as _;
    stat.st_mode = metadata.mode() as _;
    stat.st_nlink = metadata.nlink() as _;
    stat.st_uid = metadata.uid() as _;
    stat.st_gid = metadata.gid() as _;
    stat.st_size = metadata.len() as _;
    stat.st_mtime = metadata.mtime() as _;
    stat.st_mtime_nsec = metadata.mtime_nsec() as _;
    stat.st_ctime = metadata.ctime() as _;
    stat.st_ctime_nsec = metadata.ctime_nsec() as _;
    stat
}

impl FileRoot {
    /// Registers Linux inotify watches for a validated directory and up to
    /// `MAX_CHILD_WATCHES` current regular-file children. The returned handle
    /// owns the inotify instance and pinned directory descriptor.
    #[cfg(target_os = "linux")]
    pub fn watch_directory(&self, entry: EntryRef) -> Result<DirectoryWatch> {
        let (directory, st) = self.open_dir(entry)?;
        let identity = ident_fd(directory.as_raw_fd(), &st)?;
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        if fd < 0 {
            return Err(map_errno(last_errno(), false));
        }
        let inotify = unsafe { OwnedFd::from_raw_fd(fd) };
        // Linux exposes inotify_add_watch by pathname only. procfs's fd link
        // resolves the held descriptor itself, rather than a workspace path.
        let wd = add_inotify_watch(inotify.as_raw_fd(), directory.as_raw_fd());
        if wd < 0 {
            return Err(map_errno(last_errno(), false));
        }
        let current = fstat(directory.as_raw_fd())?;
        if ident_fd(directory.as_raw_fd(), &current)? != identity {
            return Err(Error::Changed);
        }
        let mut watch_descriptors = vec![wd];
        let mut child_watches = 0;

        // A watch on a directory reports child creation/removal, but not
        // writes or attribute changes to its existing children. Watch regular
        // files too so a same-size write with restored mtime is reconciled
        // immediately rather than waiting for the periodic fingerprint poll.
        // Keep direct child watches bounded; the full directory is still
        // reconciled periodically by the remote watch.
        let mut cursor = None;
        for _ in 0..5 {
            let page = self.list(entry, cursor.as_deref(), 200)?;
            for meta in page.entries {
                if child_watches == MAX_CHILD_WATCHES {
                    break;
                }
                if meta.kind != Kind::File {
                    continue;
                }
                let Ok((parent_fd, name, _, listed)) = self.open_leaf(meta.entry) else {
                    // The parent watch and reconciliation cover entries that
                    // disappear or are replaced while their watches are added.
                    continue;
                };
                if kind_of(&listed) != Kind::File {
                    continue;
                }
                let Ok(file) = openat(
                    parent_fd.as_raw_fd(),
                    &name,
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                    0,
                    false,
                ) else {
                    continue;
                };
                let opened = fstat(file.as_raw_fd())?;
                if ident_fd(file.as_raw_fd(), &opened)?
                    != ident_at(parent_fd.as_raw_fd(), &name, &listed)?
                {
                    continue;
                }
                let child_wd = add_inotify_watch(inotify.as_raw_fd(), file.as_raw_fd());
                if child_wd < 0 {
                    // A concurrent unlink can make procfs resolution fail;
                    // the directory watch still records that namespace change.
                    if last_errno() == libc::ENOENT {
                        continue;
                    }
                    return Err(map_errno(last_errno(), false));
                }
                watch_descriptors.push(child_wd);
                child_watches += 1;
            }
            if child_watches == MAX_CHILD_WATCHES {
                break;
            }
            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        Ok(DirectoryWatch {
            inotify,
            _directory: directory,
            watch_descriptors,
        })
    }

    /// Registers bounded vnode filters for a pinned directory and its current
    /// regular-file children. The descriptors remain owned by the watch so
    /// kqueue never has to resolve workspace paths after registration.
    #[cfg(target_os = "macos")]
    pub fn watch_directory(&self, entry: EntryRef) -> Result<DirectoryWatch> {
        let (directory, st) = self.open_dir(entry)?;
        let identity = ident_fd(directory.as_raw_fd(), &st)?;
        let queue = unsafe { libc::kqueue() };
        if queue < 0 {
            return Err(map_errno(last_errno(), false));
        }
        let queue = unsafe { OwnedFd::from_raw_fd(queue) };
        let directory_filter = libc::NOTE_WRITE
            | libc::NOTE_ATTRIB
            | libc::NOTE_DELETE
            | libc::NOTE_RENAME
            | libc::NOTE_REVOKE;
        register_vnode(queue.as_raw_fd(), directory.as_raw_fd(), directory_filter)?;
        let current = fstat(directory.as_raw_fd())?;
        if ident_fd(directory.as_raw_fd(), &current)? != identity {
            return Err(Error::Changed);
        }

        let child_watch_budget = macos_child_watch_budget();
        let mut children = Vec::new();
        let mut cursor = None;
        'pages: for _ in 0..5 {
            let page = match self.list(entry, cursor.as_deref(), 200) {
                Ok(page) => page,
                Err(Error::Limit) => break 'pages,
                Err(error) => return Err(error),
            };
            for meta in page.entries {
                if children.len() == child_watch_budget {
                    break 'pages;
                }
                if meta.kind != Kind::File {
                    continue;
                }
                let (parent_fd, name, _, listed) = match self.open_leaf(meta.entry) {
                    Ok(leaf) => leaf,
                    // Keep the directory watch and already-registered child
                    // watches. Periodic reconciliation still covers files
                    // beyond the descriptor budget.
                    Err(Error::Limit) => break 'pages,
                    Err(error) => return Err(error),
                };
                if kind_of(&listed) != Kind::File {
                    return Err(Error::Changed);
                }
                let file = match openat(
                    parent_fd.as_raw_fd(),
                    &name,
                    libc::O_EVTONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                    0,
                    false,
                ) {
                    Ok(file) => file,
                    Err(Error::Limit) => break 'pages,
                    Err(error) => return Err(error),
                };
                let opened = fstat(file.as_raw_fd())?;
                if ident_fd(file.as_raw_fd(), &opened)?
                    != ident_at(parent_fd.as_raw_fd(), &name, &listed)?
                {
                    return Err(Error::Changed);
                }
                match register_vnode(
                    queue.as_raw_fd(),
                    file.as_raw_fd(),
                    directory_filter | libc::NOTE_EXTEND,
                ) {
                    Ok(()) => children.push(file),
                    Err(Error::Limit) => break 'pages,
                    Err(error) => return Err(error),
                }
            }
            if children.len() == MAX_CHILD_WATCHES {
                break;
            }
            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        Ok(DirectoryWatch {
            queue,
            _directory: directory,
            _children: children,
        })
    }
    /// Pins `root`. Refuses a root that contains, or lies inside, any of the
    /// `host_protected` paths (host data/secrets), by identity and not text.
    pub fn open(root: &Path, host_protected: &[&Path]) -> Result<Self> {
        Self::open_with_root_entry(root, host_protected, mint())
    }

    /// Like [`FileRoot::open`] but with a caller-chosen identifier for the root
    /// entry (the host uses the workspace id, so clients need no extra lookup).
    pub fn open_with_root_entry(
        root: &Path,
        host_protected: &[&Path],
        root_entry: EntryRef,
    ) -> Result<Self> {
        let canonical = root
            .canonicalize()
            .map_err(|e| map_errno(e.raw_os_error().unwrap_or(0), false))?;
        let path = CString::new(canonical.as_os_str().as_bytes()).map_err(|_| Error::Invalid)?;
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(map_errno(last_errno(), false));
        }
        let root_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let st = fstat(root_fd.as_raw_fd())?;
        let root_ident = ident_fd(root_fd.as_raw_fd(), &st)?;
        let mut protected = Vec::new();
        for path in host_protected {
            let canonical_protected = path
                .canonicalize()
                .map_err(|error| map_errno(error.raw_os_error().unwrap_or(0), false))?;
            if canonical_protected.starts_with(&canonical)
                || canonical.starts_with(&canonical_protected)
            {
                return Err(Error::Protected);
            }
            let ident = path_ident(&canonical_protected)?;
            // Identity guard too: bind mounts and renamed ancestors. Failure
            // to identify any configured protected path must fail closed.
            if ident == root_ident || ancestor_idents(&canonical)?.contains(&ident) {
                return Err(Error::Protected);
            }
            if ancestor_idents(&canonical_protected)?.contains(&root_ident) {
                return Err(Error::Protected);
            }
            protected.push(ident);
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        let mut registry = Registry::default();
        registry.nodes.insert(
            root_entry,
            Node {
                parent: None,
                name: Vec::new(),
                ident: root_ident,
            },
        );
        Ok(Self {
            root_fd,
            root_ident,
            root_entry,
            owner_metadata: None,
            salt,
            protected: Mutex::new(protected),
            registry: Mutex::new(registry),
            write: Mutex::new(()),
        })
    }

    /// Opens one exact owner-local Git metadata directory by walking every
    /// component with `O_NOFOLLOW`. This constructor is crate-internal and its
    /// result is held only by `OwnerGitMetadataRoot`, never exposed as an
    /// Explorer `FileRoot`.
    pub(crate) fn open_owner_git_metadata(
        root: &Path,
        workspace_root: &Path,
        host_protected: &[&Path],
    ) -> Result<Self> {
        Self::open_owner_git_metadata_scoped(root, workspace_root, host_protected, false)
    }

    pub(crate) fn open_owner_git_metadata_from_verified_pointer(
        root: &Path,
        workspace_root: &Path,
        host_protected: &[&Path],
    ) -> Result<Self> {
        Self::open_owner_git_metadata_scoped(root, workspace_root, host_protected, true)
    }

    fn open_owner_git_metadata_scoped(
        root: &Path,
        workspace_root: &Path,
        host_protected: &[&Path],
        allow_workspace_descendant: bool,
    ) -> Result<Self> {
        let mut opened = open_owner_metadata_path(root)?;
        let root_st = fstat(opened.root.as_raw_fd())?;
        let root_ident = ident_fd(opened.root.as_raw_fd(), &root_st)?;
        let mut protected_paths = Vec::with_capacity(host_protected.len() + 1);
        protected_paths.push(workspace_root.to_path_buf());
        protected_paths.extend(host_protected.iter().map(|path| path.to_path_buf()));
        check_owner_metadata_protection(
            &opened.path,
            &opened.identities,
            &protected_paths,
            allow_workspace_descendant,
        )?;

        let mut protected = Vec::with_capacity(host_protected.len());
        for path in host_protected {
            let canonical = path
                .canonicalize()
                .map_err(|error| map_errno(error.raw_os_error().unwrap_or(0), false))?;
            protected.push(path_ident(&canonical)?);
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        let root_entry = mint();
        let mut registry = Registry::default();
        registry.nodes.insert(
            root_entry,
            Node {
                parent: None,
                name: Vec::new(),
                ident: root_ident,
            },
        );
        let binding = OwnerMetadataBinding {
            path: opened.path,
            components: opened.components,
            identities: opened.identities,
            protected_paths,
            allow_workspace_descendant,
            _ancestor_handles: std::mem::take(&mut opened.ancestor_handles),
        };
        Ok(Self {
            root_fd: opened.root,
            root_ident,
            root_entry,
            owner_metadata: Some(binding),
            salt,
            protected: Mutex::new(protected),
            registry: Mutex::new(registry),
            write: Mutex::new(()),
        })
    }

    pub(crate) fn open_owner_git_metadata_from_workspace_marker(
        &self,
        root: &Path,
        workspace_root: &Path,
        host_protected: &[&Path],
        repository: EntryRef,
        repository_path: &Path,
        marker: &GitPullPrecondition,
        expected_entry: Option<EntryRef>,
    ) -> Result<Self> {
        self.pin_native_directory(self.root_entry, workspace_root)?;
        self.pin_native_directory(repository, repository_path)?;
        if marker.parent != repository
            || marker.name != b".git"
            || !matches!(
                marker.kind,
                Some(GitPullNodeKind::File | GitPullNodeKind::Directory)
            )
        {
            return Err(Error::Invalid);
        }
        self.check_git_desktop_marker(marker)?;
        match marker.kind {
            Some(GitPullNodeKind::Directory) => {
                crate::owner_git_metadata::pointer_resolves_to(b".git", "", repository_path, root)?;
                if expected_entry != marker.entry {
                    return Err(Error::Changed);
                }
            }
            Some(GitPullNodeKind::File) => {
                let revision = marker.revision.as_deref().ok_or(Error::Invalid)?;
                let pointer = self.read_snapshot_chunk(
                    marker.entry.ok_or(Error::Invalid)?,
                    revision,
                    0,
                    4096,
                )?;
                if pointer.meta.size > 4096 || pointer.truncated {
                    return Err(Error::Limit);
                }
                crate::owner_git_metadata::pointer_resolves_to(
                    &pointer.bytes,
                    "gitdir: ",
                    repository_path,
                    root,
                )?;
            }
            _ => return Err(Error::Invalid),
        }
        self.check_git_desktop_marker(marker)?;
        let opened = Self::open_owner_git_metadata_from_verified_pointer(
            root,
            workspace_root,
            host_protected,
        )?;
        if let Some(expected_entry) = expected_entry {
            let (expected_fd, expected_stat) = self.open_dir(expected_entry)?;
            let expected_ident = ident_fd(expected_fd.as_raw_fd(), &expected_stat)?;
            if expected_ident != opened.root_ident {
                return Err(Error::Changed);
            }
        } else if opened.owner_metadata.as_ref().is_some_and(|binding| {
            binding.identities.len() > 1
                && binding.identities[..binding.identities.len() - 1].contains(&self.root_ident)
        }) {
            return Err(Error::Changed);
        }
        self.check_git_desktop_marker(marker)?;
        self.pin_native_directory(self.root_entry, workspace_root)?;
        Ok(opened)
    }

    pub(crate) fn owner_git_metadata_path(&self) -> Result<PathBuf> {
        self.owner_metadata
            .as_ref()
            .map(|binding| binding.path.clone())
            .ok_or(Error::Protected)
    }

    /// Identity byte layout intentionally matches lomi-git's existing
    /// `path_identity`: device/volume id followed by file index/inode.
    pub(crate) fn owner_git_metadata_identity(&self) -> Result<Vec<u8>> {
        let mut identity = Vec::with_capacity(16);
        identity.extend_from_slice(&self.root_ident.dev.to_le_bytes());
        identity.extend_from_slice(&self.root_ident.ino.to_le_bytes());
        Ok(identity)
    }

    pub(crate) fn check_owner_git_metadata_binding(&self) -> Result<()> {
        let binding = self.owner_metadata.as_ref().ok_or(Error::Protected)?;
        let current = open_owner_metadata_path(&binding.path)?;
        if current.path != binding.path
            || current.components != binding.components
            || current.identities != binding.identities
        {
            return Err(Error::Changed);
        }
        check_owner_metadata_protection(
            &binding.path,
            &binding.identities,
            &binding.protected_paths,
            binding.allow_workspace_descendant,
        )
    }

    pub fn root_entry(&self) -> EntryRef {
        self.root_entry
    }

    /// Registers an approved git directory (gitdir/commondir) as protected from
    /// File API mutation. Identity based; the caller has already validated it.
    pub fn protect(&self, path: &Path) -> Result<()> {
        let ident = path_ident(path)?;
        let mut protected = self.protected.lock().map_err(|_| Error::Limit)?;
        if !protected.contains(&ident) {
            protected.push(ident);
        }
        Ok(())
    }

    fn is_protected_ident(&self, ident: &Ident) -> bool {
        *ident == self.root_ident
            || self
                .protected
                .lock()
                .map(|p| p.contains(ident))
                .unwrap_or(true)
    }

    fn revision(&self, st: &libc::stat) -> String {
        let mut hash = Sha256::new();
        hash.update(self.salt);
        for value in [
            st.st_dev as u64,
            st.st_ino as u64,
            st.st_size as u64,
            st.st_mtime as u64,
            st.st_mtime_nsec as u64,
            st.st_ctime as u64,
            st.st_ctime_nsec as u64,
            st.st_mode as u64,
        ] {
            hash.update(value.to_le_bytes());
        }
        let digest = hash.finalize();
        let mut out = String::from("r");
        for byte in &digest[..16] {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    fn meta(&self, entry: EntryRef, name: &[u8], st: &libc::stat) -> Meta {
        Meta {
            entry,
            name: name.to_vec(),
            kind: kind_of(st),
            size: if kind_of(st) == Kind::File {
                st.st_size as u64
            } else {
                0
            },
            revision: self.revision(st),
            nlink: st.st_nlink as u64,
        }
    }

    /// Records (or reuses) the entry for `(parent, name)` with this identity.
    fn register(&self, parent: EntryRef, name: &[u8], ident: Ident) -> Result<EntryRef> {
        let mut registry = self.registry.lock().map_err(|_| Error::Limit)?;
        let key = (parent, name.to_vec());
        if let Some(existing) = registry.by_name.get(&key).copied() {
            if registry
                .nodes
                .get(&existing)
                .is_some_and(|n| n.ident == ident)
            {
                return Ok(existing);
            }
            registry.nodes.remove(&existing);
            registry.by_name.remove(&key);
        }
        if registry.nodes.len() >= MAX_REGISTERED_ENTRIES {
            // Generation reset: every previously issued id (but the root)
            // becomes NotFound and clients resync by listing again.
            registry.nodes.retain(|id, _| *id == self.root_entry);
            registry.by_name.clear();
        }
        let id = mint();
        registry.nodes.insert(
            id,
            Node {
                parent: Some(parent),
                name: name.to_vec(),
                ident,
            },
        );
        registry.by_name.insert(key, id);
        Ok(id)
    }

    fn chain(&self, entry: EntryRef) -> Result<Vec<(Vec<u8>, Ident)>> {
        let registry = self.registry.lock().map_err(|_| Error::Limit)?;
        let mut chain = Vec::new();
        let mut cursor = entry;
        while cursor != self.root_entry {
            let node = registry.nodes.get(&cursor).ok_or(Error::NotFound)?;
            chain.push((node.name.clone(), node.ident));
            cursor = node.parent.ok_or(Error::NotFound)?;
            if chain.len() > 4096 {
                return Err(Error::Limit);
            }
        }
        chain.reverse();
        Ok(chain)
    }

    fn entry_has_private_staging_name(&self, entry: EntryRef) -> Result<bool> {
        Ok(self
            .chain(entry)?
            .iter()
            .any(|(name, _)| is_private_staging_name(name)))
    }

    fn node(&self, entry: EntryRef) -> Result<(Option<EntryRef>, Vec<u8>, Ident)> {
        let registry = self.registry.lock().map_err(|_| Error::Limit)?;
        let node = registry.nodes.get(&entry).ok_or(Error::NotFound)?;
        Ok((node.parent, node.name.clone(), node.ident))
    }

    /// Opens the directory `entry`, validating the recorded identity of every
    /// ancestor. Never follows a symbolic link.
    fn open_dir(&self, entry: EntryRef) -> Result<(OwnedFd, libc::stat)> {
        let chain = self.chain(entry)?;
        let root_st = fstat(self.root_fd.as_raw_fd())?;
        if ident_fd(self.root_fd.as_raw_fd(), &root_st)? != self.root_ident {
            return Err(Error::Changed);
        }
        let mut fd = dup(self.root_fd.as_raw_fd())?;
        for (name, ident) in chain {
            let c = cstring(&name)?;
            let next = openat(
                fd.as_raw_fd(),
                &c,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                0,
                true,
            )
            .map_err(|e| match e {
                Error::NotFound => Error::NotFound,
                Error::Io(_) | Error::Changed | Error::Invalid => Error::Changed,
                other => other,
            })?;
            let next_st = fstat(next.as_raw_fd())?;
            if ident_fd(next.as_raw_fd(), &next_st)? != ident {
                return Err(Error::Changed);
            }
            fd = next;
        }
        let st = fstat(fd.as_raw_fd())?;
        Ok((fd, st))
    }

    /// Parent directory fd plus the validated (not followed) leaf stat.
    fn open_leaf(&self, entry: EntryRef) -> Result<(OwnedFd, CString, Vec<u8>, libc::stat)> {
        let (parent, name, ident) = self.node(entry)?;
        let parent = parent.ok_or(Error::Invalid)?;
        let (parent_fd, _) = self.open_dir(parent)?;
        let c = cstring(&name)?;
        let st = fstatat_nofollow(parent_fd.as_raw_fd(), &c)?;
        if ident_at(parent_fd.as_raw_fd(), &c, &st)? != ident {
            return Err(Error::Changed);
        }
        Ok((parent_fd, c, name, st))
    }

    fn check_revision(&self, st: &libc::stat, expected: Option<&str>) -> Result<()> {
        match expected {
            Some(expected) if self.revision(st) != expected => Err(Error::Changed),
            _ => Ok(()),
        }
    }

    pub fn stat(&self, entry: EntryRef, expected_revision: Option<&str>) -> Result<Meta> {
        if self.entry_has_private_staging_name(entry)? {
            return Err(Error::NotFound);
        }
        if entry == self.root_entry {
            let st = fstat(self.root_fd.as_raw_fd())?;
            if ident_fd(self.root_fd.as_raw_fd(), &st)? != self.root_ident {
                return Err(Error::Changed);
            }
            self.check_revision(&st, expected_revision)?;
            return Ok(self.meta(entry, b"", &st));
        }
        let (_fd, _c, name, st) = self.open_leaf(entry)?;
        self.check_revision(&st, expected_revision)?;
        Ok(self.meta(entry, &name, &st))
    }

    /// Host-only native launch binding. Return the descriptor admitted through
    /// FileRoot only if the absolute no-follow pathname still names that exact
    /// directory. The held descriptor, rather than a pathname, must govern cwd.
    #[doc(hidden)]
    pub fn pin_native_directory(&self, entry: EntryRef, absolute_path: &Path) -> Result<File> {
        if self.entry_has_private_staging_name(entry)? {
            return Err(Error::NotFound);
        }
        let (held, held_stat) = self.open_dir(entry)?;
        let named = native_open_absolute_directory(absolute_path).map_err(|_| Error::Changed)?;
        let named_stat = fstat(named.as_raw_fd())?;
        if ident_fd(held.as_raw_fd(), &held_stat)? != ident_fd(named.as_raw_fd(), &named_stat)? {
            return Err(Error::Changed);
        }
        Ok(File::from(held))
    }

    /// Return a desktop-only native identity for the exact leaf admitted by
    /// this FileRoot registry entry. The identity is read from the pinned
    /// parent and no-follow leaf, never reconstructed from an absolute path.
    #[doc(hidden)]
    pub fn desktop_source_precondition(
        &self,
        entry: EntryRef,
    ) -> Result<crate::desktop::DesktopSourcePrecondition> {
        let (parent, name, _, stat) = self.open_leaf(entry)?;
        let identity = ident_at(parent.as_raw_fd(), &name, &stat)?;
        let kind = match kind_of(&stat) {
            Kind::File => crate::desktop::DesktopFileKind::File,
            Kind::Directory => crate::desktop::DesktopFileKind::Directory,
            Kind::Symlink => crate::desktop::DesktopFileKind::Symlink,
            Kind::Other => crate::desktop::DesktopFileKind::Other,
        };
        Ok(crate::desktop::DesktopSourcePrecondition {
            identity: crate::desktop::DesktopFileIdentity {
                volume: identity.dev.to_string(),
                file_id: identity.ino.to_string(),
            },
            kind,
        })
    }

    /// Resolve a registered entry to its current absolute path while retaining
    /// FileRoot's no-follow identity binding. The supplied root must still name
    /// this exact root directory; path components come only from the registry.
    #[doc(hidden)]
    pub fn native_entry_binding(
        &self,
        absolute_root: &Path,
        entry: EntryRef,
    ) -> Result<(PathBuf, crate::desktop::DesktopSourcePrecondition)> {
        let _guard = self.write.lock().map_err(|_| Error::Limit)?;
        if self.entry_has_private_staging_name(entry)? || self.chain_is_protected(entry)? {
            return Err(Error::Protected);
        }

        let held_root_stat = fstat(self.root_fd.as_raw_fd())?;
        if ident_fd(self.root_fd.as_raw_fd(), &held_root_stat)? != self.root_ident {
            return Err(Error::Changed);
        }
        let named_root =
            native_open_absolute_directory(absolute_root).map_err(|_| Error::Changed)?;
        let named_root_stat = fstat(named_root.as_raw_fd())?;
        if ident_fd(named_root.as_raw_fd(), &named_root_stat)? != self.root_ident {
            return Err(Error::Changed);
        }

        let mut path = absolute_root.to_path_buf();
        let (identity, kind) = if entry == self.root_entry {
            (self.root_ident, Kind::Directory)
        } else {
            for (name, _) in self.chain(entry)? {
                path.push(std::ffi::OsStr::from_bytes(&name));
            }
            let (parent, name, _, stat) = self.open_leaf(entry)?;
            (ident_at(parent.as_raw_fd(), &name, &stat)?, kind_of(&stat))
        };
        Ok((path, native_source_precondition(identity, kind)))
    }

    pub fn list(&self, parent: EntryRef, cursor: Option<&[u8]>, limit: usize) -> Result<Page> {
        if self.entry_has_private_staging_name(parent)? {
            return Err(Error::NotFound);
        }
        let limit = limit.clamp(1, MAX_PAGE);
        let (fd, _) = self.open_dir(parent)?;
        let mut names = read_dir_names(&fd)?;
        names.retain(|name| !is_private_staging_name(name));
        names.sort();
        let start = match cursor {
            Some(cursor) => names.partition_point(|n| n.as_slice() <= cursor),
            None => 0,
        };
        let mut entries = Vec::new();
        let mut last = None;
        let mut index = start;
        while index < names.len() && entries.len() < limit {
            let name = &names[index];
            index += 1;
            last = Some(name.clone());
            let c = cstring(name)?;
            // A name that vanished or became unreadable mid-listing is skipped.
            let Ok(st) = fstatat_nofollow(fd.as_raw_fd(), &c) else {
                continue;
            };
            let id = self.register(parent, name, ident_at(fd.as_raw_fd(), &c, &st)?)?;
            entries.push(self.meta(id, name, &st));
        }
        let truncated = index < names.len();
        Ok(Page {
            entries,
            next: if truncated { last } else { None },
            truncated,
        })
    }

    pub fn read(
        &self,
        entry: EntryRef,
        expected_revision: Option<&str>,
        offset: u64,
        max_bytes: usize,
    ) -> Result<ReadResult> {
        self.read_with_binary_policy(entry, expected_revision, offset, max_bytes, false)
            .map(|(result, _)| result)
    }

    /// Read one bounded raw chunk for a private Git snapshot. Unlike Explorer
    /// reads, this host-internal API preserves binary bytes. It retains the
    /// same pinned-entry, no-follow, hard-link, and revision checks as `read`.
    /// Do not expose this result through a remote file-read DTO.
    #[doc(hidden)]
    pub fn read_snapshot_chunk(
        &self,
        entry: EntryRef,
        expected_revision: &str,
        offset: u64,
        max_bytes: usize,
    ) -> Result<SnapshotChunk> {
        let (read, executable) =
            self.read_with_binary_policy(entry, Some(expected_revision), offset, max_bytes, true)?;
        let truncated = offset.saturating_add(read.bytes.len() as u64) < read.meta.size;
        Ok(SnapshotChunk {
            meta: read.meta,
            offset: read.offset,
            encoding: read.encoding,
            bytes: read.bytes,
            truncated,
            executable,
        })
    }

    /// Read a symlink's target bytes without following the link. This is an
    /// internal Git snapshot primitive; the pinned parent, link identity and
    /// revision are checked both before and after `readlinkat`.
    #[doc(hidden)]
    pub fn readlink_snapshot(
        &self,
        entry: EntryRef,
        expected_revision: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>> {
        if self.entry_has_private_staging_name(entry)? {
            return Err(Error::NotFound);
        }
        if max_bytes == 0 || max_bytes > 1024 * 1024 {
            return Err(Error::Invalid);
        }
        let (parent, name, _, before) = self.open_leaf(entry)?;
        if kind_of(&before) != Kind::Symlink || before.st_nlink != 1 {
            return Err(Error::Protected);
        }
        self.check_revision(&before, Some(expected_revision))?;
        if usize::try_from(before.st_size).is_ok_and(|size| size > max_bytes) {
            return Err(Error::Limit);
        }
        let mut bytes = vec![0u8; max_bytes + 1];
        let read = unsafe {
            libc::readlinkat(
                parent.as_raw_fd(),
                name.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if read < 0 {
            return Err(map_errno(last_errno(), false));
        }
        let read = read as usize;
        if read > max_bytes {
            return Err(Error::Limit);
        }
        bytes.truncate(read);
        let after = fstatat_nofollow(parent.as_raw_fd(), &name)?;
        if kind_of(&after) != Kind::Symlink
            || ident_at(parent.as_raw_fd(), &name, &after)?
                != ident_at(parent.as_raw_fd(), &name, &before)?
        {
            return Err(Error::Changed);
        }
        self.check_revision(&after, Some(expected_revision))?;
        Ok(bytes)
    }

    /// Publishes a Git index prepared from a private snapshot. This is the only
    /// write path allowed below protected Git metadata; it installs loose
    /// objects first and atomically renames `index.lock` as the visible commit.
    #[doc(hidden)]
    pub fn publish_git(
        &self,
        publication: &GitPublication,
        continue_check: impl FnMut() -> bool,
    ) -> Result<GitPublishOutcome> {
        publication.validate().map_err(|_| Error::Invalid)?;
        if matches!(
            publication.final_file.target,
            GitFinalTarget::WorktreeIgnore { .. } | GitFinalTarget::LocalExclude { .. }
        ) {
            return Err(Error::Invalid);
        }
        let _guard = self.write.lock().map_err(|_| Error::Limit)?;
        self.publish_git_locked(publication, continue_check)
    }

    /// Publishes a fixed Desktop Ignore target while rechecking the selected
    /// worktree entry under the same write barrier immediately before rename.
    #[doc(hidden)]
    pub fn publish_git_desktop_ignore(
        &self,
        publication: &GitPublication,
        repository: EntryRef,
        repository_preconditions: &[GitPullPrecondition],
        selected: &GitPullPrecondition,
        continue_check: impl FnMut() -> bool,
    ) -> Result<GitPublishOutcome> {
        publication.validate().map_err(|_| Error::Invalid)?;
        if !matches!(
            publication.final_file.target,
            GitFinalTarget::WorktreeIgnore { .. } | GitFinalTarget::LocalExclude { .. }
        ) || !publication.objects.is_empty()
            || !publication.worktree_preconditions.is_empty()
        {
            return Err(Error::Invalid);
        }
        let _guard = self.write.lock().map_err(|_| Error::Limit)?;
        let mut preceding = Vec::new();
        self.publish_git_locked_batch(
            publication,
            continue_check,
            &mut preceding,
            false,
            Some((repository, repository_preconditions, selected)),
        )
        .map(|(outcome, _)| outcome)
    }

    fn publish_git_locked(
        &self,
        publication: &GitPublication,
        continue_check: impl FnMut() -> bool,
    ) -> Result<GitPublishOutcome> {
        let mut preceding = Vec::new();
        self.publish_git_locked_batch(publication, continue_check, &mut preceding, false, None)
            .map(|(outcome, _)| outcome)
    }

    fn publish_git_locked_batch(
        &self,
        publication: &GitPublication,
        mut continue_check: impl FnMut() -> bool,
        preceding: &mut [GitPublishedGuard],
        capture_guard: bool,
        desktop_selected: Option<(EntryRef, &[GitPullPrecondition], &GitPullPrecondition)>,
    ) -> Result<(GitPublishOutcome, Option<GitPublishedGuard>)> {
        publication.validate().map_err(|_| Error::Invalid)?;
        let desktop_ignore_target = matches!(
            &publication.final_file.target,
            GitFinalTarget::WorktreeIgnore { .. } | GitFinalTarget::LocalExclude { .. }
        );
        if desktop_ignore_target != desktop_selected.is_some() {
            return Err(Error::Protected);
        }
        let mut info_creation_guard: Option<GitInfoCreationGuard> = None;
        self.require_git_dir(publication.git_dir)?;
        self.require_git_dir(publication.common_dir)?;
        self.validate_git_target(publication)?;
        self.check_git_preconditions_with_published(&publication.preconditions, preceding)?;
        self.check_git_worktree_preconditions(&publication.worktree_preconditions)?;
        if let Some((repository, repository_preconditions, selected)) = desktop_selected {
            self.check_git_desktop_repository(
                repository,
                publication.git_dir,
                publication.common_dir,
                repository_preconditions,
                info_creation_guard.as_ref(),
            )?;
            self.check_git_desktop_selected(repository, selected)?;
        }
        self.check_git_target_precondition(publication, preceding)?;
        if !continue_check() {
            return Ok((GitPublishOutcome::AbortedBeforeFinalRename, None));
        }

        let (base_fd, base_stat) = self.open_dir(publication.final_file.parent)?;
        let base_identity = ident_fd(base_fd.as_raw_fd(), &base_stat)?;
        let info_creation_baseline = self.git_info_creation_baseline(
            publication,
            desktop_selected,
            &base_fd,
            base_identity,
        )?;
        let mut created_dirs = Vec::new();
        let target_parent = if publication.final_file.parent_suffix.is_empty() {
            dup(base_fd.as_raw_fd())?
        } else {
            match create_git_target_parent(
                &base_fd,
                &publication.final_file.parent_suffix,
                &mut created_dirs,
                publication.final_file.parent,
                preceding,
                &mut continue_check,
            ) {
                Ok(parent) => parent,
                Err(error) => {
                    cleanup_created_git_dirs(&base_fd, &created_dirs);
                    return Err(error);
                }
            }
        };
        if let Some(baseline) = info_creation_baseline {
            info_creation_guard =
                Some(self.finish_git_info_creation(&base_fd, &created_dirs, baseline)?);
        }
        let target_parent_identity = ident_fd(
            target_parent.as_raw_fd(),
            &fstat(target_parent.as_raw_fd())?,
        )?;
        let target_name = cstring(publication.final_file.target.name())?;
        let source_security = match git_named_file_security(target_parent.as_raw_fd(), &target_name)
        {
            Ok(security) => security,
            Err(error) => {
                cleanup_created_git_dirs(&base_fd, &created_dirs);
                return Err(error);
            }
        };
        if source_security.is_some() != publication.final_file.expected.entry.is_some() {
            cleanup_created_git_dirs(&base_fd, &created_dirs);
            return Err(Error::Changed);
        }
        let mut lock_name_bytes = publication.final_file.target.name().to_vec();
        lock_name_bytes.extend_from_slice(b".lock");
        let lock_name = cstring(&lock_name_bytes)?;
        // Git writers reserve the final file's sibling lock name. The target
        // is published only by renaming the exact inode we created here.
        let lock_fd = match openat(
            target_parent.as_raw_fd(),
            &lock_name,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            0o600,
            false,
        ) {
            Ok(fd) => fd,
            Err(error) => {
                cleanup_created_git_dirs(&base_fd, &created_dirs);
                return Err(error);
            }
        };
        let lock_stat = fstat(lock_fd.as_raw_fd())?;
        if kind_of(&lock_stat) != Kind::File || lock_stat.st_nlink != 1 {
            cleanup_created_git_dirs(&base_fd, &created_dirs);
            return Err(Error::Protected);
        }
        let lock_identity = ident_fd(lock_fd.as_raw_fd(), &lock_stat)?;
        let mut lock_file = File::from(lock_fd);
        let mut lock_exists = true;
        let mut publication_visible = false;
        let mut guard_file = None;
        let mut published_security = None;
        let publication_digest: [u8; 32] = Sha256::digest(&publication.final_file.bytes).into();
        let content_digest = if capture_guard {
            publication_digest
        } else {
            [0; 32]
        };
        let work = (|| -> Result<GitPublishOutcome> {
            // Clear inherited ACLs and keep the named lock private while its
            // content is incomplete. Target security is applied after writing.
            apply_git_file_security(lock_file.as_raw_fd(), None, None)?;
            if !write_git_bytes(
                &mut lock_file,
                &publication.final_file.bytes,
                &mut continue_check,
            )? {
                return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
            }
            lock_file.sync_all().map_err(map_io)?;

            let security =
                apply_git_file_security(lock_file.as_raw_fd(), source_security.as_ref(), None)?;
            lock_file.sync_all().map_err(map_io)?;
            if hash_git_file(&mut lock_file, publication.final_file.bytes.len())?
                != publication_digest
            {
                return Err(Error::Changed);
            }
            published_security = Some(security);

            // Keep a read-only descriptor for this exact private lock inode.
            // It becomes the post-publication guard only if the rename below
            // is confirmed to have installed the same identity.
            if capture_guard {
                let verification_fd = openat(
                    target_parent.as_raw_fd(),
                    &lock_name,
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                    0,
                    false,
                )?;
                let verification_stat = fstat(verification_fd.as_raw_fd())?;
                if kind_of(&verification_stat) != Kind::File
                    || verification_stat.st_nlink != 1
                    || ident_fd(verification_fd.as_raw_fd(), &verification_stat)? != lock_identity
                {
                    return Err(Error::Changed);
                }
                let mut verification_file = File::from(verification_fd);
                if hash_git_file(&mut verification_file, publication.final_file.bytes.len())?
                    != content_digest
                {
                    return Err(Error::Changed);
                }
                guard_file = Some(verification_file);
            }

            let (common_fd, _) = self.open_dir(publication.common_dir)?;
            let (objects_fd, _) = open_git_child_dir(&common_fd, b"objects")?;
            for object in &publication.objects {
                if !continue_check() {
                    return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
                }
                let hex = object.object_id.as_bytes();
                let (prefix, suffix) = hex.split_at(2);
                let (prefix_fd, _) = open_or_create_git_child_dir(&objects_fd, prefix)?;
                if let Err(error) =
                    install_git_object(&prefix_fd, suffix, &object.bytes, &mut continue_check)
                {
                    if error == Error::Changed && !continue_check() {
                        return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
                    }
                    return Err(error);
                }
            }

            // Repeat all identity/revision checks after object publication and
            // immediately before the index rename.
            self.check_git_preconditions_with_current(
                &publication.preconditions,
                preceding,
                Some((publication, &base_fd, &created_dirs)),
            )?;
            self.check_git_worktree_preconditions(&publication.worktree_preconditions)?;
            if let Some((repository, repository_preconditions, selected)) = desktop_selected {
                self.check_git_desktop_repository(
                    repository,
                    publication.git_dir,
                    publication.common_dir,
                    repository_preconditions,
                    info_creation_guard.as_ref(),
                )?;
                self.check_git_desktop_selected(repository, selected)?;
            }
            if publication.final_file.parent_suffix.is_empty() {
                self.check_git_target_precondition(publication, preceding)?;
            } else {
                verify_git_target_parent(
                    &base_fd,
                    &publication.final_file.parent_suffix,
                    &created_dirs,
                )?;
                match fstatat_nofollow(target_parent.as_raw_fd(), &target_name) {
                    Err(Error::NotFound) => {}
                    Ok(_) => return Err(Error::Changed),
                    Err(error) => return Err(error),
                }
            }
            if !continue_check() {
                return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
            }
            let verified_base = self.open_dir(publication.final_file.parent)?;
            if ident_fd(verified_base.0.as_raw_fd(), &verified_base.1).ok() != Some(base_identity) {
                return Err(Error::Changed);
            }
            if verify_git_target_parent(
                &verified_base.0,
                &publication.final_file.parent_suffix,
                &created_dirs,
            )
            .is_err()
            {
                return Err(Error::Changed);
            }
            // The lock file name is replaceable by another process even while
            // this descriptor remains open. Publish only the inode we created.
            check_git_lock_identity(
                target_parent.as_raw_fd(),
                &lock_name,
                lock_file.as_raw_fd(),
                lock_identity,
            )?;
            self.check_git_preconditions_with_current(
                &publication.preconditions,
                preceding,
                Some((publication, &base_fd, &created_dirs)),
            )?;
            if !continue_check() {
                return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
            }
            self.check_git_preconditions_with_current(
                &publication.preconditions,
                preceding,
                Some((publication, &base_fd, &created_dirs)),
            )?;
            self.check_git_worktree_preconditions(&publication.worktree_preconditions)?;
            if let Some((repository, repository_preconditions, selected)) = desktop_selected {
                self.check_git_desktop_repository(
                    repository,
                    publication.git_dir,
                    publication.common_dir,
                    repository_preconditions,
                    info_creation_guard.as_ref(),
                )?;
                self.check_git_desktop_selected(repository, selected)?;
            }
            let final_base = self.open_dir(publication.final_file.parent)?;
            if ident_fd(final_base.0.as_raw_fd(), &final_base.1)? != base_identity {
                return Err(Error::Changed);
            }
            let final_parent = verify_git_target_parent(
                &final_base.0,
                &publication.final_file.parent_suffix,
                &created_dirs,
            )?;
            if ident_fd(final_parent.as_raw_fd(), &fstat(final_parent.as_raw_fd())?)?
                != target_parent_identity
            {
                return Err(Error::Changed);
            }
            if publication.final_file.parent_suffix.is_empty() {
                self.check_git_target_precondition(publication, preceding)?;
            } else {
                match fstatat_nofollow(final_parent.as_raw_fd(), &target_name) {
                    Err(Error::NotFound) => {}
                    Ok(_) => return Err(Error::Changed),
                    Err(error) => return Err(error),
                }
            }
            check_git_named_file_security(
                target_parent.as_raw_fd(),
                &target_name,
                source_security.as_ref(),
            )?;
            let lock_security = git_file_security(lock_file.as_raw_fd())?;
            if published_security.as_ref() != Some(&lock_security)
                || hash_git_file(&mut lock_file, publication.final_file.bytes.len())?
                    != publication_digest
            {
                return Err(Error::Changed);
            }
            self.check_git_target_precondition(publication, preceding)?;
            if let Some((repository, repository_preconditions, selected)) = desktop_selected {
                self.check_git_desktop_repository(
                    repository,
                    publication.git_dir,
                    publication.common_dir,
                    repository_preconditions,
                    info_creation_guard.as_ref(),
                )?;
                self.check_git_desktop_selected(repository, selected)?;
            }
            if unsafe {
                libc::renameat(
                    target_parent.as_raw_fd(),
                    lock_name.as_ptr(),
                    target_parent.as_raw_fd(),
                    target_name.as_ptr(),
                )
            } != 0
            {
                // The OS did not provide a definitive visibility receipt.
                // Keep any created parent directories for manual resolution.
                publication_visible = true;
                return Ok(GitPublishOutcome::UncertainAfterFinalRename);
            }
            lock_exists = false;
            publication_visible = true;
            let Ok(current_base) = self.open_dir(publication.final_file.parent) else {
                return Ok(GitPublishOutcome::UncertainAfterFinalRename);
            };
            if ident_fd(current_base.0.as_raw_fd(), &current_base.1).ok() != Some(base_identity) {
                return Ok(GitPublishOutcome::UncertainAfterFinalRename);
            }
            let Ok(current_target_parent) = verify_git_target_parent(
                &current_base.0,
                &publication.final_file.parent_suffix,
                &created_dirs,
            ) else {
                return Ok(GitPublishOutcome::UncertainAfterFinalRename);
            };
            let current_target_identity = fstat(current_target_parent.as_raw_fd())
                .and_then(|stat| ident_fd(current_target_parent.as_raw_fd(), &stat))
                .ok();
            if current_target_identity != Some(target_parent_identity) {
                return Ok(GitPublishOutcome::UncertainAfterFinalRename);
            }
            if check_git_lock_identity(
                current_target_parent.as_raw_fd(),
                &target_name,
                lock_file.as_raw_fd(),
                lock_identity,
            )
            .is_err()
            {
                return Ok(GitPublishOutcome::UncertainAfterFinalRename);
            }
            if git_file_security(lock_file.as_raw_fd()).ok().as_ref() != published_security.as_ref()
                || hash_git_file(&mut lock_file, publication.final_file.bytes.len()).ok()
                    != Some(publication_digest)
            {
                return Ok(GitPublishOutcome::UncertainAfterFinalRename);
            }
            if sync_git_directory(current_target_parent.as_raw_fd()).is_err() {
                return Ok(GitPublishOutcome::UncertainAfterFinalRename);
            }
            Ok(GitPublishOutcome::Published)
        })();
        let mut work = match work {
            Err(_) if publication_visible => Ok(GitPublishOutcome::UncertainAfterFinalRename),
            other => other,
        };
        let mut produced_guard = None;
        if matches!(&work, Ok(GitPublishOutcome::Published)) && capture_guard {
            let captured = guard_file.take().map_or(Err(Error::Changed), |file| {
                self.capture_git_published_guard(
                    publication,
                    target_parent.as_raw_fd(),
                    file,
                    content_digest,
                )
            });
            match captured {
                Ok(guard) => produced_guard = Some(guard),
                Err(_) => work = Ok(GitPublishOutcome::UncertainAfterFinalRename),
            }
        }
        drop(lock_file);
        if lock_exists {
            unlink_owned_git_lock(target_parent.as_raw_fd(), &lock_name, lock_identity);
        }
        if !publication_visible {
            cleanup_created_git_dirs(&base_fd, &created_dirs);
        }
        work.map(|outcome| (outcome, produced_guard))
    }

    /// Publishes a prepared fast-forward worktree/index/ref update while
    /// holding the same FileRoot mutation barrier used by Explorer writes.
    #[doc(hidden)]
    pub fn publish_git_pull(
        &self,
        publication: &GitPullPublication,
        mut continue_check: impl FnMut() -> bool,
    ) -> Result<GitPublishOutcome> {
        publication.validate().map_err(|_| Error::Invalid)?;
        let _guard = self.write.lock().map_err(|_| Error::Limit)?;
        let first = &publication.metadata[0];
        for metadata in &publication.metadata {
            metadata.validate().map_err(|_| Error::Invalid)?;
            self.require_git_dir(metadata.git_dir)?;
            self.require_git_dir(metadata.common_dir)?;
            self.validate_git_target(metadata)?;
            self.check_git_preconditions(&metadata.preconditions)?;
            self.check_git_precondition(&metadata.final_file.expected)?;
        }
        let mut pull_security = HashMap::<Vec<Vec<u8>>, Option<GitFileSecurity>>::new();
        for file in &publication.files {
            self.validate_pull_worktree_path(file)?;
            self.check_git_pull_precondition(&file.expected, true)?;
            if file.contents.is_some() {
                let security = self.capture_git_pull_file_security(file)?;
                pull_security.insert(file.path.clone(), security);
            }
        }
        if !continue_check() {
            return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
        }

        // Make every referenced object durable before changing the worktree.
        // The metadata publishers repeat these checks when they atomically
        // replace the index and refs later in the batch.
        let (common_fd, _) = self.open_dir(first.common_dir)?;
        let (objects_fd, _) = open_git_child_dir(&common_fd, b"objects")?;
        for object in &first.objects {
            if !continue_check() {
                return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
            }
            let hex = object.object_id.as_bytes();
            let (prefix, suffix) = hex.split_at(2);
            let (prefix_fd, _) = open_or_create_git_child_dir(&objects_fd, prefix)?;
            if let Err(error) =
                install_git_object(&prefix_fd, suffix, &object.bytes, &mut continue_check)
            {
                if error == Error::Changed && !continue_check() {
                    return Ok(GitPublishOutcome::AbortedBeforeFinalRename);
                }
                return Err(error);
            }
        }

        let mut created_directories = Vec::<PullCreatedDir>::new();
        let mut created_identities = HashMap::<Vec<Vec<u8>>, Ident>::new();
        let mut staged = Vec::<StagedPullFile>::with_capacity(publication.files.len());
        let mut visible = false;
        let work = (|| -> Result<GitPublishOutcome> {
            self.check_git_preconditions(&first.preconditions)?;
            for source in publication
                .files
                .iter()
                .filter(|file| file.contents.is_none() && file.kind != GitPullNodeKind::Directory)
            {
                if !continue_check() {
                    return Ok(if visible {
                        GitPublishOutcome::UncertainAfterFinalRename
                    } else {
                        GitPublishOutcome::AbortedBeforeFinalRename
                    });
                }
                if !source.parent_suffix.is_empty() {
                    return Err(Error::Invalid);
                }
                self.check_git_pull_precondition(&source.expected, true)?;
                let parent_prefix_len = source.path.len().checked_sub(1).ok_or(Error::Invalid)?;
                let parent_chain = self.chain(source.parent)?;
                if parent_chain
                    .iter()
                    .map(|(name, _)| name)
                    .ne(source.path[..parent_prefix_len].iter())
                {
                    return Err(Error::Protected);
                }
                let (base_fd, base_stat) = self.open_dir(source.parent)?;
                if kind_of(&base_stat) != Kind::Directory {
                    return Err(Error::Changed);
                }
                let name = cstring(&source.name)?;
                if !continue_check() {
                    return Ok(if visible {
                        GitPublishOutcome::UncertainAfterFinalRename
                    } else {
                        GitPublishOutcome::AbortedBeforeFinalRename
                    });
                }
                if unsafe { libc::unlinkat(base_fd.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                    return Err(map_errno(last_errno(), false));
                }
                visible = true;
                if sync_git_directory(base_fd.as_raw_fd()).is_err() {
                    return Ok(GitPublishOutcome::UncertainAfterFinalRename);
                }
            }

            let mut directories: Vec<_> = publication
                .files
                .iter()
                .filter(|file| file.kind == GitPullNodeKind::Directory)
                .collect();
            directories.sort_by(|left, right| {
                right
                    .path
                    .len()
                    .cmp(&left.path.len())
                    .then_with(|| right.path.cmp(&left.path))
            });
            for source in directories {
                if !continue_check() {
                    return Ok(if visible {
                        GitPublishOutcome::UncertainAfterFinalRename
                    } else {
                        GitPublishOutcome::AbortedBeforeFinalRename
                    });
                }
                if !source.parent_suffix.is_empty() {
                    return Err(Error::Invalid);
                }
                self.check_git_pull_precondition(&source.expected, false)?;
                let parent_prefix_len = source.path.len().checked_sub(1).ok_or(Error::Invalid)?;
                let parent_chain = self.chain(source.parent)?;
                if parent_chain
                    .iter()
                    .map(|(name, _)| name)
                    .ne(source.path[..parent_prefix_len].iter())
                {
                    return Err(Error::Protected);
                }
                let (parent_fd, _) = self.open_dir(source.parent)?;
                let name = cstring(&source.name)?;
                if !continue_check() {
                    return Ok(if visible {
                        GitPublishOutcome::UncertainAfterFinalRename
                    } else {
                        GitPublishOutcome::AbortedBeforeFinalRename
                    });
                }
                if unsafe {
                    libc::unlinkat(parent_fd.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR)
                } != 0
                {
                    return Err(map_errno(last_errno(), false));
                }
                visible = true;
                if sync_git_directory(parent_fd.as_raw_fd()).is_err() {
                    return Ok(GitPublishOutcome::UncertainAfterFinalRename);
                }
            }

            for source in publication
                .files
                .iter()
                .filter(|file| file.contents.is_some())
            {
                if !continue_check() {
                    return Ok(if visible {
                        GitPublishOutcome::UncertainAfterFinalRename
                    } else {
                        GitPublishOutcome::AbortedBeforeFinalRename
                    });
                }
                let parent_prefix_len = source
                    .path
                    .len()
                    .checked_sub(source.parent_suffix.len() + 1)
                    .ok_or(Error::Invalid)?;
                let parent_chain = self.chain(source.parent)?;
                if parent_chain
                    .iter()
                    .map(|(name, _)| name)
                    .ne(source.path[..parent_prefix_len].iter())
                {
                    return Err(Error::Protected);
                }
                let (base_fd, base_stat) = self.open_dir(source.parent)?;
                if kind_of(&base_stat) != Kind::Directory {
                    return Err(Error::Changed);
                }
                let mut parent_fd = dup(base_fd.as_raw_fd())?;
                let mut full_parent_path = source.path[..parent_prefix_len].to_vec();
                for component in &source.parent_suffix {
                    if !continue_check() {
                        return Ok(if visible {
                            GitPublishOutcome::UncertainAfterFinalRename
                        } else {
                            GitPublishOutcome::AbortedBeforeFinalRename
                        });
                    }
                    let component_name = cstring(component)?;
                    full_parent_path.push(component.clone());
                    if let Some(expected_identity) = created_identities.get(&full_parent_path) {
                        let (child, stat) = open_git_child_dir(&parent_fd, component)?;
                        if ident_fd(child.as_raw_fd(), &stat)? != *expected_identity {
                            return Err(Error::Changed);
                        }
                        parent_fd = child;
                        continue;
                    }
                    if unsafe {
                        libc::mkdirat(parent_fd.as_raw_fd(), component_name.as_ptr(), 0o700)
                    } != 0
                    {
                        return Err(if last_errno() == libc::EEXIST {
                            Error::Changed
                        } else {
                            map_errno(last_errno(), false)
                        });
                    }
                    visible = true;
                    let stat = fstatat_nofollow(parent_fd.as_raw_fd(), &component_name)?;
                    if kind_of(&stat) != Kind::Directory {
                        return Err(Error::Changed);
                    }
                    let identity = ident_at(parent_fd.as_raw_fd(), &component_name, &stat)?;
                    created_directories.push(PullCreatedDir {
                        parent: dup(parent_fd.as_raw_fd())?,
                        name: component_name,
                        identity,
                    });
                    created_identities.insert(full_parent_path.clone(), identity);
                    if sync_git_directory(parent_fd.as_raw_fd()).is_err() {
                        return Ok(GitPublishOutcome::UncertainAfterFinalRename);
                    }
                    let (child, child_stat) = open_git_child_dir(&parent_fd, component)?;
                    if ident_fd(child.as_raw_fd(), &child_stat)? != identity {
                        return Err(Error::Changed);
                    }
                    parent_fd = child;
                }
                let target_name = cstring(&source.name)?;
                let target_parent_identity =
                    ident_fd(parent_fd.as_raw_fd(), &fstat(parent_fd.as_raw_fd())?)?;
                let mut staged_file = StagedPullFile {
                    source: source.clone(),
                    target_parent: parent_fd,
                    target_parent_identity,
                    target_name,
                    temp_name: None,
                    temp_identity: None,
                    temp_file: None,
                    source_security: pull_security.get(&source.path).cloned().flatten(),
                    published_security: None,
                };
                let contents = source.contents.as_ref().ok_or(Error::Changed)?;
                match source.kind {
                    GitPullNodeKind::File => {
                        let suffix =
                            NEXT_GIT_PULL_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let temp_name = cstring(
                            format!(".lomi-pull-{}-{suffix}.tmp", std::process::id()).as_bytes(),
                        )?;
                        let temp_fd = openat(
                            staged_file.target_parent.as_raw_fd(),
                            &temp_name,
                            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
                            0o600,
                            false,
                        )?;
                        let temp_stat = fstat(temp_fd.as_raw_fd())?;
                        if kind_of(&temp_stat) != Kind::File || temp_stat.st_nlink != 1 {
                            return Err(Error::Protected);
                        }
                        let temp_identity = ident_fd(temp_fd.as_raw_fd(), &temp_stat)?;
                        staged_file.temp_name = Some(temp_name);
                        staged_file.temp_identity = Some(temp_identity);
                        staged_file.temp_file = Some(File::from(temp_fd));
                        staged.push(staged_file);
                        let item = staged.last_mut().ok_or(Error::Changed)?;
                        apply_git_file_security(
                            item.temp_file.as_ref().ok_or(Error::Changed)?.as_raw_fd(),
                            None,
                            None,
                        )?;
                        if !write_git_bytes(
                            item.temp_file.as_mut().ok_or(Error::Changed)?,
                            contents,
                            &mut continue_check,
                        )? {
                            return Ok(if visible {
                                GitPublishOutcome::UncertainAfterFinalRename
                            } else {
                                GitPublishOutcome::AbortedBeforeFinalRename
                            });
                        }
                        item.temp_file
                            .as_ref()
                            .ok_or(Error::Changed)?
                            .sync_all()
                            .map_err(map_io)?;
                        let output_security = apply_git_file_security(
                            item.temp_file.as_ref().ok_or(Error::Changed)?.as_raw_fd(),
                            item.source_security.as_ref(),
                            Some(item.source.executable),
                        )?;
                        item.temp_file
                            .as_ref()
                            .ok_or(Error::Changed)?
                            .sync_all()
                            .map_err(map_io)?;
                        item.published_security = Some(output_security);
                        let expected_digest: [u8; 32] = Sha256::digest(contents).into();
                        if hash_git_file(
                            item.temp_file.as_mut().ok_or(Error::Changed)?,
                            contents.len(),
                        )? != expected_digest
                        {
                            return Err(Error::Changed);
                        }
                    }
                    GitPullNodeKind::Symlink => {
                        if contents.is_empty() || contents.contains(&0) {
                            return Err(Error::Invalid);
                        }
                        let target =
                            CString::new(contents.as_slice()).map_err(|_| Error::Invalid)?;
                        let mut created = None;
                        for _ in 0..8 {
                            let suffix = NEXT_GIT_PULL_TEMP
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let name = cstring(
                                format!(".lomi-pull-{}-{suffix}.tmp", std::process::id())
                                    .as_bytes(),
                            )?;
                            if !continue_check() {
                                return Ok(if visible {
                                    GitPublishOutcome::UncertainAfterFinalRename
                                } else {
                                    GitPublishOutcome::AbortedBeforeFinalRename
                                });
                            }
                            if unsafe {
                                libc::symlinkat(
                                    target.as_ptr(),
                                    staged_file.target_parent.as_raw_fd(),
                                    name.as_ptr(),
                                )
                            } == 0
                            {
                                created = Some(name);
                                break;
                            }
                            if last_errno() != libc::EEXIST {
                                return Err(map_errno(last_errno(), false));
                            }
                        }
                        let temp_name = created.ok_or(Error::Exists)?;
                        staged_file.temp_name = Some(temp_name.clone());
                        staged.push(staged_file);
                        let item = staged.last_mut().ok_or(Error::Changed)?;
                        let stat = fstatat_nofollow(item.target_parent.as_raw_fd(), &temp_name)?;
                        if kind_of(&stat) != Kind::Symlink {
                            return Err(Error::Changed);
                        }
                        item.temp_identity =
                            Some(ident_at(item.target_parent.as_raw_fd(), &temp_name, &stat)?);
                    }
                    GitPullNodeKind::Directory => return Err(Error::Invalid),
                }
            }

            for item in &staged {
                self.recheck_pull_install_target(item, &created_identities)?;
            }
            for item in &mut staged {
                if !continue_check() {
                    return Ok(if visible {
                        GitPublishOutcome::UncertainAfterFinalRename
                    } else {
                        GitPublishOutcome::AbortedBeforeFinalRename
                    });
                }
                self.recheck_pull_install_target(item, &created_identities)?;
                let temp_name = item.temp_name.as_ref().ok_or(Error::Changed)?;
                let temp_identity = item.temp_identity.ok_or(Error::Changed)?;
                match item.source.kind {
                    GitPullNodeKind::File => check_git_lock_identity(
                        item.target_parent.as_raw_fd(),
                        temp_name,
                        item.temp_file.as_ref().ok_or(Error::Changed)?.as_raw_fd(),
                        temp_identity,
                    )?,
                    GitPullNodeKind::Symlink => {
                        let stat = fstatat_nofollow(item.target_parent.as_raw_fd(), temp_name)?;
                        if kind_of(&stat) != Kind::Symlink
                            || ident_at(item.target_parent.as_raw_fd(), temp_name, &stat)?
                                != temp_identity
                        {
                            return Err(Error::Changed);
                        }
                    }
                    GitPullNodeKind::Directory => return Err(Error::Invalid),
                }
                if !continue_check() {
                    return Ok(if visible {
                        GitPublishOutcome::UncertainAfterFinalRename
                    } else {
                        GitPublishOutcome::AbortedBeforeFinalRename
                    });
                }
                self.recheck_pull_install_target(item, &created_identities)?;
                if item.source.kind == GitPullNodeKind::File {
                    let contents = item.source.contents.as_ref().ok_or(Error::Changed)?;
                    let expected_digest: [u8; 32] = Sha256::digest(contents).into();
                    let temp_file = item.temp_file.as_mut().ok_or(Error::Changed)?;
                    let temp_security = git_file_security(temp_file.as_raw_fd())?;
                    if item.published_security.as_ref() != Some(&temp_security)
                        || hash_git_file(temp_file, contents.len())? != expected_digest
                    {
                        return Err(Error::Changed);
                    }
                }
                check_git_named_file_security(
                    item.target_parent.as_raw_fd(),
                    &item.target_name,
                    item.source_security.as_ref(),
                )?;
                if unsafe {
                    libc::renameat(
                        item.target_parent.as_raw_fd(),
                        temp_name.as_ptr(),
                        item.target_parent.as_raw_fd(),
                        item.target_name.as_ptr(),
                    )
                } != 0
                {
                    return Ok(GitPublishOutcome::UncertainAfterFinalRename);
                }
                item.temp_name = None;
                visible = true;
                let expected_digest: [u8; 32] = item
                    .source
                    .contents
                    .as_ref()
                    .map(|contents| Sha256::digest(contents).into())
                    .unwrap_or([0; 32]);
                if item.source.kind == GitPullNodeKind::File
                    && (check_git_named_file_security(
                        item.target_parent.as_raw_fd(),
                        &item.target_name,
                        item.published_security.as_ref(),
                    )
                    .is_err()
                        || hash_git_file(
                            item.temp_file.as_mut().ok_or(Error::Changed)?,
                            item.source.contents.as_ref().ok_or(Error::Changed)?.len(),
                        )
                        .ok()
                            != Some(expected_digest))
                {
                    return Ok(GitPublishOutcome::UncertainAfterFinalRename);
                }
                if sync_git_directory(item.target_parent.as_raw_fd()).is_err() {
                    return Ok(GitPublishOutcome::UncertainAfterFinalRename);
                }
            }

            let mut published_guards = Vec::with_capacity(publication.metadata.len());
            for metadata in &publication.metadata {
                match self.publish_git_locked_batch(
                    metadata,
                    &mut continue_check,
                    &mut published_guards,
                    true,
                    None,
                ) {
                    Ok((GitPublishOutcome::Published, Some(guard))) => {
                        visible = true;
                        published_guards.push(guard);
                    }
                    Ok((GitPublishOutcome::Published, None)) => {
                        visible = true;
                        return Ok(GitPublishOutcome::UncertainAfterFinalRename);
                    }
                    Ok((GitPublishOutcome::AbortedBeforeFinalRename, _)) => {
                        return Ok(if visible {
                            GitPublishOutcome::UncertainAfterFinalRename
                        } else {
                            GitPublishOutcome::AbortedBeforeFinalRename
                        });
                    }
                    Ok((GitPublishOutcome::UncertainAfterFinalRename, _)) => {
                        visible = true;
                        return Ok(GitPublishOutcome::UncertainAfterFinalRename);
                    }
                    Err(error) => {
                        return if visible {
                            Ok(GitPublishOutcome::UncertainAfterFinalRename)
                        } else {
                            Err(error)
                        };
                    }
                }
            }
            Ok(GitPublishOutcome::Published)
        })();
        let work = match work {
            Err(_) if visible => Ok(GitPublishOutcome::UncertainAfterFinalRename),
            other => other,
        };

        for item in &staged {
            if let (Some(name), Some(identity)) = (&item.temp_name, item.temp_identity) {
                if let Ok(stat) = fstatat_nofollow(item.target_parent.as_raw_fd(), name) {
                    let expected_kind = match item.source.kind {
                        GitPullNodeKind::File => Kind::File,
                        GitPullNodeKind::Symlink => Kind::Symlink,
                        GitPullNodeKind::Directory => Kind::Directory,
                    };
                    if kind_of(&stat) == expected_kind
                        && ident_at(item.target_parent.as_raw_fd(), name, &stat).ok()
                            == Some(identity)
                    {
                        unsafe {
                            libc::unlinkat(item.target_parent.as_raw_fd(), name.as_ptr(), 0);
                        }
                    }
                }
            }
        }
        if !visible {
            for created in created_directories.iter().rev() {
                if let Ok(stat) = fstatat_nofollow(created.parent.as_raw_fd(), &created.name) {
                    if kind_of(&stat) == Kind::Directory
                        && ident_at(created.parent.as_raw_fd(), &created.name, &stat).ok()
                            == Some(created.identity)
                    {
                        unsafe {
                            libc::unlinkat(
                                created.parent.as_raw_fd(),
                                created.name.as_ptr(),
                                libc::AT_REMOVEDIR,
                            );
                        }
                        let _ = sync_git_directory(created.parent.as_raw_fd());
                    }
                }
            }
        }
        work
    }

    fn validate_pull_worktree_path(&self, file: &GitPullFile) -> Result<()> {
        if file.path.iter().any(|component| is_git_name(component)) {
            return Err(Error::Protected);
        }
        let parent_prefix_len = file
            .path
            .len()
            .checked_sub(file.parent_suffix.len() + 1)
            .ok_or(Error::Invalid)?;
        let chain = self.chain(file.parent)?;
        if chain
            .iter()
            .map(|(name, _)| name)
            .ne(file.path[..parent_prefix_len].iter())
        {
            return Err(Error::Protected);
        }
        Ok(())
    }

    fn capture_git_pull_file_security(
        &self,
        file: &GitPullFile,
    ) -> Result<Option<GitFileSecurity>> {
        let Some(entry) = file.expected.entry else {
            return Ok(None);
        };
        if file.parent_suffix.len() != 0 {
            return Err(Error::Changed);
        }
        let kind = file.expected.kind.ok_or(Error::Changed)?;
        if kind != GitPullNodeKind::File || file.kind != GitPullNodeKind::File {
            // Replacing a symlink or another node cannot preserve its
            // no-follow metadata through the regular-file staging path.
            return Err(Error::Unsupported);
        }
        let (recorded_parent, recorded_name, _) = self.node(entry)?;
        if recorded_parent != Some(file.parent) || recorded_name != file.name {
            return Err(Error::Changed);
        }
        let (parent, _) = self.open_dir(file.parent)?;
        let name = cstring(&file.name)?;
        let named = fstatat_nofollow(parent.as_raw_fd(), &name)?;
        if kind_of(&named) != Kind::File || named.st_nlink != 1 {
            return Err(Error::Protected);
        }
        let fd = openat(
            parent.as_raw_fd(),
            &name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0,
            false,
        )?;
        let held = fstat(fd.as_raw_fd())?;
        if kind_of(&held) != Kind::File
            || held.st_nlink != 1
            || ident_fd(fd.as_raw_fd(), &held)? != ident_at(parent.as_raw_fd(), &name, &named)?
        {
            return Err(Error::Changed);
        }
        git_file_security(fd.as_raw_fd()).map(Some)
    }

    fn recheck_pull_install_target(
        &self,
        item: &StagedPullFile,
        created: &HashMap<Vec<Vec<u8>>, Ident>,
    ) -> Result<()> {
        let prefix_len = item
            .source
            .path
            .len()
            .checked_sub(item.source.parent_suffix.len() + 1)
            .ok_or(Error::Invalid)?;
        let (base, _) = self.open_dir(item.source.parent)?;
        let mut current = dup(base.as_raw_fd())?;
        let mut full_path = item.source.path[..prefix_len].to_vec();
        for component in &item.source.parent_suffix {
            full_path.push(component.clone());
            let expected = created.get(&full_path).ok_or(Error::Changed)?;
            let (child, stat) = open_git_child_dir(&current, component)?;
            if ident_fd(child.as_raw_fd(), &stat)? != *expected {
                return Err(Error::Changed);
            }
            current = child;
        }
        let current_parent_identity = ident_fd(current.as_raw_fd(), &fstat(current.as_raw_fd())?)?;
        if current_parent_identity != item.target_parent_identity {
            return Err(Error::Changed);
        }
        if item.source.parent_suffix.is_empty()
            && matches!(
                item.source.expected.kind,
                Some(GitPullNodeKind::File | GitPullNodeKind::Symlink)
            )
        {
            self.check_git_pull_precondition(&item.source.expected, true)?;
        } else {
            match fstatat_nofollow(item.target_parent.as_raw_fd(), &item.target_name) {
                Err(Error::NotFound) => {}
                Ok(_) => return Err(Error::Changed),
                Err(error) => return Err(error),
            }
        }
        check_git_named_file_security(
            item.target_parent.as_raw_fd(),
            &item.target_name,
            item.source_security.as_ref(),
        )?;
        Ok(())
    }

    fn check_git_pull_precondition(
        &self,
        value: &GitPullPrecondition,
        check_revision: bool,
    ) -> Result<()> {
        let (parent_fd, _) = self.open_dir(value.parent)?;
        let name = cstring(&value.name)?;
        match (value.entry, value.kind) {
            (Some(entry), Some(expected_kind)) => {
                let (recorded_parent, recorded_name, _) = self.node(entry)?;
                if recorded_parent != Some(value.parent) || recorded_name != value.name {
                    return Err(Error::Changed);
                }
                let (_leaf_parent, _leaf_name, _leaf_path, stat) = self.open_leaf(entry)?;
                let actual_kind = match kind_of(&stat) {
                    Kind::File => GitPullNodeKind::File,
                    Kind::Symlink => GitPullNodeKind::Symlink,
                    Kind::Directory => GitPullNodeKind::Directory,
                    Kind::Other => return Err(Error::Changed),
                };
                if actual_kind != expected_kind
                    || (actual_kind != GitPullNodeKind::Directory && stat.st_nlink != 1)
                {
                    return Err(Error::Changed);
                }
                if check_revision {
                    self.check_revision(&stat, value.revision.as_deref())?;
                }
                Ok(())
            }
            (None, None) if value.revision.is_none() => {
                match fstatat_nofollow(parent_fd.as_raw_fd(), &name) {
                    Err(Error::NotFound) => Ok(()),
                    Ok(_) => Err(Error::Changed),
                    Err(error) => Err(error),
                }
            }
            _ => Err(Error::Invalid),
        }
    }

    fn validate_git_target(&self, publication: &GitPublication) -> Result<()> {
        let final_file = &publication.final_file;
        match &final_file.target {
            GitFinalTarget::Index | GitFinalTarget::DetachedHead => {
                if final_file.parent != publication.git_dir || !final_file.parent_suffix.is_empty()
                {
                    return Err(Error::Protected);
                }
            }
            GitFinalTarget::BranchHead { reference }
            | GitFinalTarget::RemoteTrackingHead { reference } => {
                match &final_file.target {
                    GitFinalTarget::BranchHead { .. } => {
                        crate::git::validate_branch_reference(reference)
                    }
                    GitFinalTarget::RemoteTrackingHead { .. } => {
                        crate::git::validate_remote_tracking_reference(reference)
                    }
                    _ => unreachable!(),
                }
                .map_err(|_| Error::Invalid)?;
                let common_chain = self.chain(publication.common_dir)?;
                let parent_chain = self.chain(final_file.parent)?;
                if parent_chain.len() < common_chain.len()
                    || parent_chain[..common_chain.len()] != common_chain
                {
                    return Err(Error::Protected);
                }
                let prefix_len = parent_chain.len() - common_chain.len();
                let reference_parent_len = reference.len() - 1;
                if prefix_len + final_file.parent_suffix.len() != reference_parent_len
                    || parent_chain[common_chain.len()..]
                        .iter()
                        .map(|(name, _)| name)
                        .ne(reference[..prefix_len].iter())
                    || final_file
                        .parent_suffix
                        .iter()
                        .ne(reference[prefix_len..reference_parent_len].iter())
                {
                    return Err(Error::Protected);
                }
            }
            GitFinalTarget::WorktreeIgnore { repository } => {
                if final_file.parent != *repository || !final_file.parent_suffix.is_empty() {
                    return Err(Error::Protected);
                }
                let chain = self.chain(*repository)?;
                if chain.iter().any(|(name, ident)| {
                    is_git_name(name)
                        || (*ident != self.root_ident && self.is_protected_ident(ident))
                }) {
                    return Err(Error::Protected);
                }
                let (_, stat) = self.open_dir(*repository)?;
                if kind_of(&stat) != Kind::Directory {
                    return Err(Error::Changed);
                }
            }
            GitFinalTarget::LocalExclude { common_dir } => {
                if *common_dir != publication.common_dir {
                    return Err(Error::Protected);
                }
                let common_chain = self.chain(*common_dir)?;
                if final_file.parent_suffix.is_empty() {
                    let info_chain = self.chain(final_file.parent)?;
                    if info_chain.len() != common_chain.len() + 1
                        || info_chain[..common_chain.len()] != common_chain
                        || info_chain.last().map(|(name, _)| name.as_slice()) != Some(b"info")
                    {
                        return Err(Error::Protected);
                    }
                    self.require_git_metadata_parent(final_file.parent)?;
                } else if final_file.parent != *common_dir
                    || final_file.parent_suffix.len() != 1
                    || final_file.parent_suffix.first().map(Vec::as_slice) != Some(b"info")
                    || final_file.expected.entry.is_some()
                {
                    return Err(Error::Protected);
                } else {
                    self.require_git_metadata_parent(*common_dir)?;
                }
            }
        }
        Ok(())
    }

    fn require_git_dir(&self, entry: EntryRef) -> Result<()> {
        if self.owner_metadata.is_some() {
            self.check_owner_git_metadata_binding()?;
            if entry != self.root_entry {
                return Err(Error::Protected);
            }
            let (fd, st) = self.open_dir(entry)?;
            if kind_of(&st) != Kind::Directory || ident_fd(fd.as_raw_fd(), &st)? != self.root_ident
            {
                return Err(Error::Changed);
            }
            return Ok(());
        }
        let chain = self.chain(entry)?;
        if !chain.iter().any(|(name, _)| is_git_name(name)) {
            return Err(Error::Protected);
        }
        let (fd, st) = self.open_dir(entry)?;
        if kind_of(&st) != Kind::Directory {
            return Err(Error::Invalid);
        }
        let ident = ident_fd(fd.as_raw_fd(), &st)?;
        if !self.is_protected_ident(&ident) {
            return Err(Error::Protected);
        }
        Ok(())
    }

    fn require_git_metadata_parent(&self, entry: EntryRef) -> Result<()> {
        if self.owner_metadata.is_some() {
            self.check_owner_git_metadata_binding()?;
            let chain = self.chain(entry)?;
            if !(chain.is_empty() || (chain.len() == 1 && chain[0].0.as_slice() == b"info")) {
                return Err(Error::Protected);
            }
            let (_fd, st) = self.open_dir(entry)?;
            if kind_of(&st) != Kind::Directory {
                return Err(Error::Changed);
            }
            return Ok(());
        }
        let chain = self.chain(entry)?;
        let Some(git_index) = chain.iter().position(|(name, _)| is_git_name(name)) else {
            return Err(Error::Protected);
        };
        if !chain[..=git_index]
            .iter()
            .any(|(_, ident)| self.is_protected_ident(ident))
        {
            return Err(Error::Protected);
        }
        let (fd, st) = self.open_dir(entry)?;
        if kind_of(&st) != Kind::Directory {
            return Err(Error::Invalid);
        }
        let _ = fd;
        Ok(())
    }

    fn check_git_preconditions(&self, values: &[GitFilePrecondition]) -> Result<()> {
        for value in values {
            self.check_git_precondition(value)?;
        }
        Ok(())
    }

    fn check_git_preconditions_with_published(
        &self,
        values: &[GitFilePrecondition],
        preceding: &mut [GitPublishedGuard],
    ) -> Result<()> {
        self.check_git_preconditions_with_current(values, preceding, None)
    }

    fn check_git_preconditions_with_current(
        &self,
        values: &[GitFilePrecondition],
        preceding: &mut [GitPublishedGuard],
        current: Option<(&GitPublication, &OwnedFd, &[CreatedGitDir])>,
    ) -> Result<()> {
        let check_current = || -> Result<()> {
            if let Some((publication, base, directories)) = current {
                if !publication.final_file.parent_suffix.is_empty() {
                    let (fresh, stat) = self.open_dir(publication.final_file.parent)?;
                    if ident_fd(fresh.as_raw_fd(), &stat)?
                        != ident_fd(base.as_raw_fd(), &fstat(base.as_raw_fd())?)?
                    {
                        return Err(Error::Changed);
                    }
                    verify_git_target_parent(
                        &fresh,
                        &publication.final_file.parent_suffix,
                        directories,
                    )?;
                }
            }
            Ok(())
        };
        check_current()?;
        for value in values {
            // The original absence condition is consumed only by this exact
            // stage's pinned directory chain; the actual target stays absent.
            let current_prefix = current.is_some_and(|(publication, _, _)| {
                !publication.final_file.parent_suffix.is_empty()
                    && value == &publication.final_file.expected
                    && value.entry.is_none()
                    && value.revision.is_none()
            });
            let replaced = preceding.iter().any(|guard| {
                if guard.parent_suffix.is_empty() {
                    value.parent == guard.base && value.name == guard.target_name
                } else {
                    value.parent == guard.base
                        && value.entry.is_none()
                        && value.revision.is_none()
                        && value.name == guard.parent_suffix[0]
                }
            });
            if !replaced && !current_prefix {
                self.check_git_precondition(value)?;
            }
        }
        for guard in preceding {
            self.check_git_published_guard(guard)?;
        }
        check_current()
    }

    fn check_git_precondition_with_published(
        &self,
        value: &GitFilePrecondition,
        preceding: &mut [GitPublishedGuard],
    ) -> Result<()> {
        let replaced = preceding.iter().any(|guard| {
            if guard.parent_suffix.is_empty() {
                value.parent == guard.base && value.name == guard.target_name
            } else {
                value.parent == guard.base
                    && value.entry.is_none()
                    && value.revision.is_none()
                    && value.name == guard.parent_suffix[0]
            }
        });
        if replaced {
            for guard in preceding {
                self.check_git_published_guard(guard)?;
            }
            Ok(())
        } else {
            self.check_git_precondition(value)
        }
    }

    fn check_git_published_guard(&self, guard: &mut GitPublishedGuard) -> Result<()> {
        if guard.parent_suffix.len() != guard.parent_identities.len() {
            return Err(Error::Changed);
        }
        let (mut parent, _) = self.open_dir(guard.base)?;
        for (component, expected) in guard
            .parent_suffix
            .iter()
            .zip(guard.parent_identities.iter())
        {
            let (next, stat) = open_git_child_dir(&parent, component)?;
            if ident_fd(next.as_raw_fd(), &stat)? != *expected {
                return Err(Error::Changed);
            }
            parent = next;
        }

        let name = cstring(&guard.target_name)?;
        let path_stat = fstatat_nofollow(parent.as_raw_fd(), &name)?;
        let handle_stat = fstat(guard.file.as_raw_fd())?;
        let path_identity = ident_at(parent.as_raw_fd(), &name, &path_stat)?;
        let handle_identity = ident_fd(guard.file.as_raw_fd(), &handle_stat)?;
        if kind_of(&path_stat) != Kind::File
            || kind_of(&handle_stat) != Kind::File
            || path_stat.st_nlink != 1
            || handle_stat.st_nlink != 1
            || path_identity != guard.file_identity
            || handle_identity != guard.file_identity
            || self.revision(&path_stat) != guard.revision
            || self.revision(&handle_stat) != guard.revision
            || git_named_file_security(parent.as_raw_fd(), &name)?.as_ref() != Some(&guard.security)
            || git_file_security(guard.file.as_raw_fd())? != guard.security
            || hash_git_file(&mut guard.file, guard.content_len)? != guard.content_digest
        {
            return Err(Error::Changed);
        }
        Ok(())
    }

    fn capture_git_published_guard(
        &self,
        publication: &GitPublication,
        target_parent_fd: RawFd,
        mut file: File,
        content_digest: [u8; 32],
    ) -> Result<GitPublishedGuard> {
        let final_file = &publication.final_file;
        let (mut parent, _) = self.open_dir(final_file.parent)?;
        let mut parent_identities = Vec::with_capacity(final_file.parent_suffix.len());
        for component in &final_file.parent_suffix {
            let (next, stat) = open_git_child_dir(&parent, component)?;
            parent_identities.push(ident_fd(next.as_raw_fd(), &stat)?);
            parent = next;
        }
        let target_parent_identity = ident_fd(parent.as_raw_fd(), &fstat(parent.as_raw_fd())?)?;
        let installed_parent_identity = ident_fd(target_parent_fd, &fstat(target_parent_fd)?)?;
        if target_parent_identity != installed_parent_identity {
            return Err(Error::Changed);
        }

        let target_name = final_file.target.name().to_vec();
        let name = cstring(&target_name)?;
        let path_stat = fstatat_nofollow(parent.as_raw_fd(), &name)?;
        let handle_stat = fstat(file.as_raw_fd())?;
        let file_identity = ident_fd(file.as_raw_fd(), &handle_stat)?;
        if kind_of(&path_stat) != Kind::File
            || kind_of(&handle_stat) != Kind::File
            || path_stat.st_nlink != 1
            || handle_stat.st_nlink != 1
            || ident_at(parent.as_raw_fd(), &name, &path_stat)? != file_identity
            || self.revision(&path_stat) != self.revision(&handle_stat)
            || git_named_file_security(parent.as_raw_fd(), &name)?.as_ref()
                != Some(&git_file_security(file.as_raw_fd())?)
            || hash_git_file(&mut file, final_file.bytes.len())? != content_digest
        {
            return Err(Error::Changed);
        }
        let revision = self.revision(&handle_stat);
        let security = git_file_security(file.as_raw_fd())?;
        Ok(GitPublishedGuard {
            base: final_file.parent,
            parent_suffix: final_file.parent_suffix.clone(),
            parent_identities,
            target_name,
            file_identity,
            revision,
            content_digest,
            content_len: final_file.bytes.len(),
            security,
            file,
        })
    }

    fn check_git_worktree_preconditions(&self, values: &[GitWorktreePrecondition]) -> Result<()> {
        for value in values {
            let (parent_fd, _) = self.open_dir(value.parent)?;
            let name = cstring(&value.name)?;
            match value.entry {
                Some(entry) => {
                    let (recorded_parent, recorded_name, _) = self.node(entry)?;
                    if recorded_parent != Some(value.parent) || recorded_name != value.name {
                        return Err(Error::Changed);
                    }
                    let (_fd, _leaf_name, _path, st) = self.open_leaf(entry)?;
                    if kind_of(&st) != Kind::File || st.st_nlink != 1 {
                        return Err(Error::Changed);
                    }
                    self.check_revision(&st, value.revision.as_deref())?;
                }
                None => match fstatat_nofollow(parent_fd.as_raw_fd(), &name) {
                    Err(Error::NotFound) => {}
                    Ok(_) => return Err(Error::Changed),
                    Err(error) => return Err(error),
                },
            }
        }
        Ok(())
    }

    fn check_git_desktop_selected(
        &self,
        repository: EntryRef,
        selected: &GitPullPrecondition,
    ) -> Result<()> {
        if !crate::git::valid_component(&selected.name)
            || is_git_name(&selected.name)
            || is_private_staging_name(&selected.name)
            || selected.entry.is_some() != selected.revision.is_some()
            || selected.entry.is_some() != selected.kind.is_some()
        {
            return Err(Error::Invalid);
        }
        let repository_chain = self.chain(repository)?;
        let parent_chain = self.chain(selected.parent)?;
        if parent_chain.len() < repository_chain.len()
            || parent_chain[..repository_chain.len()] != repository_chain
            || parent_chain.iter().any(|(name, ident)| {
                is_git_name(name)
                    || is_private_staging_name(name)
                    || (*ident != self.root_ident && self.is_protected_ident(ident))
            })
        {
            return Err(Error::Protected);
        }
        let (parent, _) = self.open_dir(selected.parent)?;
        let name = cstring(&selected.name)?;
        match selected.entry {
            Some(entry) => {
                let (recorded_parent, recorded_name, _) = self.node(entry)?;
                if recorded_parent != Some(selected.parent) || recorded_name != selected.name {
                    return Err(Error::Changed);
                }
                let (_parent, _leaf_name, _path, stat) = self.open_leaf(entry)?;
                let actual_kind = match kind_of(&stat) {
                    Kind::File => GitPullNodeKind::File,
                    Kind::Directory => GitPullNodeKind::Directory,
                    Kind::Symlink => GitPullNodeKind::Symlink,
                    Kind::Other => return Err(Error::Protected),
                };
                if Some(actual_kind) != selected.kind {
                    return Err(Error::Changed);
                }
                self.check_revision(&stat, selected.revision.as_deref())
            }
            None => {
                if selected.kind.is_some() {
                    return Err(Error::Invalid);
                }
                match fstatat_nofollow(parent.as_raw_fd(), &name) {
                    Err(Error::NotFound) => Ok(()),
                    Ok(_) => Err(Error::Changed),
                    Err(error) => Err(error),
                }
            }
        }
    }

    fn check_git_desktop_repository(
        &self,
        repository: EntryRef,
        git_dir: EntryRef,
        common_dir: EntryRef,
        preconditions: &[GitPullPrecondition],
        info_guard: Option<&GitInfoCreationGuard>,
    ) -> Result<()> {
        if preconditions.is_empty() || preconditions.len() > 2 {
            return Err(Error::Invalid);
        }
        let marker = &preconditions[0];
        if marker.parent != repository
            || marker.name != b".git"
            || !matches!(
                marker.kind,
                Some(GitPullNodeKind::File | GitPullNodeKind::Directory)
            )
        {
            return Err(Error::Invalid);
        }
        if let Some(guard) = info_guard {
            self.check_git_desktop_marker_after_info_creation(marker, guard)?;
        } else {
            self.check_git_desktop_marker(marker)?;
        }
        if marker.kind == Some(GitPullNodeKind::Directory) {
            let repository_chain = self.chain(repository)?;
            let git_chain = self.chain(git_dir)?;
            if git_chain.len() != repository_chain.len() + 1
                || git_chain[..repository_chain.len()] != repository_chain
                || git_chain.last().map(|(name, _)| name.as_slice()) != Some(b".git")
            {
                return Err(Error::Protected);
            }
        }
        if common_dir == git_dir {
            if preconditions.len() != 1 {
                return Err(Error::Invalid);
            }
        } else {
            let common_marker = preconditions.get(1).ok_or(Error::Invalid)?;
            if common_marker.parent != git_dir
                || common_marker.name != b"commondir"
                || common_marker.kind != Some(GitPullNodeKind::File)
            {
                return Err(Error::Invalid);
            }
            self.check_git_desktop_marker(common_marker)?;
        }
        Ok(())
    }

    fn git_info_creation_baseline(
        &self,
        publication: &GitPublication,
        desktop_selected: Option<(EntryRef, &[GitPullPrecondition], &GitPullPrecondition)>,
        parent: &OwnedFd,
        parent_identity: Ident,
    ) -> Result<Option<GitInfoCreationBaseline>> {
        let Some((_, repository_preconditions, _)) = desktop_selected else {
            return Ok(None);
        };
        if !matches!(
            publication.final_file.target,
            GitFinalTarget::LocalExclude { .. }
        ) || publication.git_dir != publication.common_dir
            || publication.final_file.parent != publication.common_dir
            || publication.final_file.parent_suffix.as_slice() != [b"info".to_vec()]
        {
            return Ok(None);
        }
        let marker = repository_preconditions.first().ok_or(Error::Invalid)?;
        if marker.kind != Some(GitPullNodeKind::Directory)
            || marker.entry != Some(publication.git_dir)
        {
            return Ok(None);
        }
        self.check_git_desktop_marker(marker)?;
        let (_, _, marker_identity) = self.node(marker.entry.ok_or(Error::Invalid)?)?;
        let parent_stat = fstat(parent.as_raw_fd())?;
        if kind_of(&parent_stat) != Kind::Directory
            || ident_fd(parent.as_raw_fd(), &parent_stat)? != parent_identity
            || parent_identity != marker_identity
        {
            return Err(Error::Changed);
        }
        let entries = git_directory_census(parent)?;
        if entries.iter().any(|(name, _)| name == b"info") {
            // This special allowance is only for the exact directory created
            // by this call; an existing or raced-in `info` is not adopted.
            return Err(Error::Changed);
        }
        Ok(Some(GitInfoCreationBaseline {
            marker_entry: marker.entry.ok_or(Error::Invalid)?,
            marker_revision: marker.revision.clone().ok_or(Error::Invalid)?,
            parent_identity,
            entries,
        }))
    }

    fn finish_git_info_creation(
        &self,
        parent: &OwnedFd,
        created: &[CreatedGitDir],
        baseline: GitInfoCreationBaseline,
    ) -> Result<GitInfoCreationGuard> {
        if created.len() != 1 || created[0].name != b"info" || !created[0].created_here {
            return Err(Error::Changed);
        }
        let parent_stat = fstat(parent.as_raw_fd())?;
        if kind_of(&parent_stat) != Kind::Directory
            || ident_fd(parent.as_raw_fd(), &parent_stat)? != baseline.parent_identity
        {
            return Err(Error::Changed);
        }
        let (info_dir, info_stat) = open_git_child_dir(parent, b"info")?;
        let info_identity = ident_fd(info_dir.as_raw_fd(), &info_stat)?;
        if info_identity != created[0].identity
            || info_stat.st_uid != unsafe { libc::geteuid() }
            || info_stat.st_mode as u32 & 0o077 != 0
        {
            return Err(Error::Protected);
        }
        let mut expected_entries = baseline.entries;
        expected_entries.push((b"info".to_vec(), info_identity));
        expected_entries.sort_by(|left, right| left.0.cmp(&right.0));
        if git_directory_census(parent)? != expected_entries {
            return Err(Error::Changed);
        }
        let (_marker_parent, _marker_name, _marker_path, marker_stat) =
            self.open_leaf(baseline.marker_entry)?;
        if kind_of(&marker_stat) != Kind::Directory
            || self.node(baseline.marker_entry)?.2 != baseline.parent_identity
        {
            return Err(Error::Changed);
        }
        Ok(GitInfoCreationGuard {
            marker_entry: baseline.marker_entry,
            marker_revision: baseline.marker_revision,
            parent: dup(parent.as_raw_fd())?,
            parent_identity: baseline.parent_identity,
            revision_after_creation: self.revision(&marker_stat),
            entries_after_creation: expected_entries,
            info_identity,
        })
    }

    fn check_git_desktop_marker_after_info_creation(
        &self,
        marker: &GitPullPrecondition,
        guard: &GitInfoCreationGuard,
    ) -> Result<()> {
        if marker.entry != Some(guard.marker_entry)
            || marker.revision.as_deref() != Some(guard.marker_revision.as_str())
            || marker.kind != Some(GitPullNodeKind::Directory)
        {
            return Err(Error::Changed);
        }
        let (recorded_parent, recorded_name, _) = self.node(guard.marker_entry)?;
        if recorded_parent != Some(marker.parent) || recorded_name != marker.name {
            return Err(Error::Changed);
        }
        let (_parent, _name, _path, marker_stat) = self.open_leaf(guard.marker_entry)?;
        if kind_of(&marker_stat) != Kind::Directory
            || ident_fd(guard.parent.as_raw_fd(), &fstat(guard.parent.as_raw_fd())?)?
                != guard.parent_identity
            || ident_fd(guard.parent.as_raw_fd(), &marker_stat)? != guard.parent_identity
            || self.revision(&marker_stat) != guard.revision_after_creation
        {
            return Err(Error::Changed);
        }
        let (info_dir, info_stat) = open_git_child_dir(&guard.parent, b"info")?;
        if ident_fd(info_dir.as_raw_fd(), &info_stat)? != guard.info_identity
            || info_stat.st_uid != unsafe { libc::geteuid() }
            || info_stat.st_mode as u32 & 0o077 != 0
            || git_directory_census(&guard.parent)? != guard.entries_after_creation
        {
            return Err(Error::Changed);
        }
        Ok(())
    }

    fn check_git_desktop_marker(&self, marker: &GitPullPrecondition) -> Result<()> {
        if marker.entry.is_some() != marker.revision.is_some()
            || marker.entry.is_some() != marker.kind.is_some()
        {
            return Err(Error::Invalid);
        }
        let entry = marker.entry.ok_or(Error::Invalid)?;
        let (recorded_parent, recorded_name, _) = self.node(entry)?;
        if recorded_parent != Some(marker.parent) || recorded_name != marker.name {
            return Err(Error::Changed);
        }
        let (_parent, _name, _path, stat) = self.open_leaf(entry)?;
        let actual_kind = match kind_of(&stat) {
            Kind::File => GitPullNodeKind::File,
            Kind::Directory => GitPullNodeKind::Directory,
            Kind::Symlink => GitPullNodeKind::Symlink,
            Kind::Other => return Err(Error::Protected),
        };
        if Some(actual_kind) != marker.kind {
            return Err(Error::Changed);
        }
        if actual_kind == GitPullNodeKind::File && stat.st_nlink != 1 {
            return Err(Error::Protected);
        }
        self.check_revision(&stat, marker.revision.as_deref())
    }

    fn check_git_target_precondition(
        &self,
        publication: &GitPublication,
        preceding: &mut [GitPublishedGuard],
    ) -> Result<()> {
        match &publication.final_file.target {
            GitFinalTarget::WorktreeIgnore { repository } => {
                if !preceding.is_empty()
                    || publication.final_file.parent != *repository
                    || publication.final_file.expected.name != b".gitignore"
                {
                    return Err(Error::Protected);
                }
                let value = &publication.final_file.expected;
                let (parent, _) = self.open_dir(value.parent)?;
                let name = cstring(&value.name)?;
                match value.entry {
                    Some(entry) => {
                        let (recorded_parent, recorded_name, _) = self.node(entry)?;
                        if recorded_parent != Some(value.parent) || recorded_name != value.name {
                            return Err(Error::Changed);
                        }
                        let (_parent, _leaf_name, _path, stat) = self.open_leaf(entry)?;
                        if kind_of(&stat) != Kind::File || stat.st_nlink != 1 {
                            return Err(Error::Protected);
                        }
                        self.check_revision(&stat, value.revision.as_deref())
                    }
                    None => match fstatat_nofollow(parent.as_raw_fd(), &name) {
                        Err(Error::NotFound) => Ok(()),
                        Ok(_) => Err(Error::Changed),
                        Err(error) => Err(error),
                    },
                }
            }
            _ => self
                .check_git_precondition_with_published(&publication.final_file.expected, preceding),
        }
    }

    fn check_git_precondition(&self, value: &GitFilePrecondition) -> Result<()> {
        self.require_git_metadata_parent(value.parent)?;
        let (parent_fd, _) = self.open_dir(value.parent)?;
        let name = cstring(&value.name)?;
        match value.entry {
            Some(entry) => {
                let (recorded_parent, recorded_name, _) = self.node(entry)?;
                if recorded_parent != Some(value.parent) || recorded_name != value.name {
                    return Err(Error::Changed);
                }
                let (_fd, _leaf, _name, st) = self.open_leaf(entry)?;
                if kind_of(&st) != Kind::File || st.st_nlink != 1 {
                    return Err(Error::Protected);
                }
                self.check_revision(&st, value.revision.as_deref())
            }
            None => match fstatat_nofollow(parent_fd.as_raw_fd(), &name) {
                Err(Error::NotFound) => Ok(()),
                Ok(_) => Err(Error::Changed),
                Err(error) => Err(error),
            },
        }
    }

    fn read_with_binary_policy(
        &self,
        entry: EntryRef,
        expected_revision: Option<&str>,
        offset: u64,
        max_bytes: usize,
        include_binary: bool,
    ) -> Result<(ReadResult, bool)> {
        if self.entry_has_private_staging_name(entry)? {
            return Err(Error::NotFound);
        }
        let max_bytes = max_bytes.clamp(1, MAX_READ);
        let (parent_fd, c, name, lstat) = self.open_leaf(entry)?;
        match kind_of(&lstat) {
            Kind::File => {}
            // A link is shown as a link; the engine never reads through it.
            Kind::Symlink | Kind::Directory | Kind::Other => return Err(Error::Invalid),
        }
        // O_NONBLOCK so that a path swapped for a FIFO cannot block the host.
        let fd = openat(
            parent_fd.as_raw_fd(),
            &c,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0,
            false,
        )
        .map_err(|e| match e {
            Error::Io(_) | Error::Invalid => Error::Changed,
            other => other,
        })?;
        let st = fstat(fd.as_raw_fd())?;
        if kind_of(&st) != Kind::File
            || ident_fd(fd.as_raw_fd(), &st)? != ident_at(parent_fd.as_raw_fd(), &c, &lstat)?
        {
            return Err(Error::Changed);
        }
        // Checked on the OPEN handle, so a link created after the lstat above
        // is still caught.
        if st.st_nlink as u64 > 1 {
            return Err(Error::Protected);
        }
        self.check_revision(&st, expected_revision)?;
        let size = st.st_size as u64;
        let mut buffer = vec![0u8; if offset >= size { 0 } else { max_bytes }];
        let mut filled = 0usize;
        while filled < buffer.len() {
            let n = unsafe {
                libc::pread(
                    fd.as_raw_fd(),
                    buffer[filled..].as_mut_ptr().cast(),
                    buffer.len() - filled,
                    (offset + filled as u64) as libc::off_t,
                )
            };
            if n < 0 {
                let errno = last_errno();
                if errno == libc::EINTR {
                    continue;
                }
                return Err(map_errno(errno, false));
            }
            if n == 0 {
                break;
            }
            filled += n as usize;
        }
        buffer.truncate(filled);
        let truncated = offset.saturating_add(filled as u64) < size;
        let (encoding, line_endings) = classify(&buffer, offset, truncated);
        let meta = self.meta(entry, &name, &st);
        let bytes = if encoding == Encoding::Binary && !include_binary {
            Vec::new()
        } else {
            buffer
        };
        Ok((
            ReadResult {
                meta,
                encoding,
                line_endings,
                offset,
                bytes,
                truncated: truncated || (encoding == Encoding::Binary && size > 0),
            },
            st.st_mode & 0o111 != 0,
        ))
    }

    /// Bounded, deterministic breadth-first name search below `parent`. The
    /// cursor is the number of matches already delivered. Never descends into a
    /// symbolic link or a `.git` directory.
    pub fn search_names(
        &self,
        parent: EntryRef,
        query: &str,
        cursor: Option<&[u8]>,
        limit: usize,
    ) -> Result<Page> {
        if self.entry_has_private_staging_name(parent)? {
            return Err(Error::NotFound);
        }
        let limit = limit.clamp(1, MAX_PAGE);
        let needle = query.to_lowercase();
        if needle.is_empty() {
            return Err(Error::Invalid);
        }
        let skip = match cursor {
            None => 0u64,
            Some(bytes) => {
                u64::from_le_bytes(<[u8; 8]>::try_from(bytes).map_err(|_| Error::Invalid)?)
            }
        };
        let mut queue = std::collections::VecDeque::from([(parent, 0usize)]);
        let mut visited = 0usize;
        let mut matched = 0u64;
        let mut entries = Vec::new();
        let mut budget_hit = false;
        let mut more = false;
        'walk: while let Some((dir, depth)) = queue.pop_front() {
            let Ok((fd, _)) = self.open_dir(dir) else {
                continue;
            };
            let mut names = read_dir_names(&fd)?;
            names.sort();
            for name in names {
                if is_private_staging_name(&name) {
                    continue;
                }
                visited += 1;
                if visited > SEARCH_VISIT_LIMIT {
                    budget_hit = true;
                    break 'walk;
                }
                let c = cstring(&name)?;
                let Ok(st) = fstatat_nofollow(fd.as_raw_fd(), &c) else {
                    continue;
                };
                let kind = kind_of(&st);
                let is_match = String::from_utf8_lossy(&name)
                    .to_lowercase()
                    .contains(&needle);
                if is_match {
                    if matched >= skip {
                        if entries.len() == limit {
                            more = true;
                            break 'walk;
                        }
                        let id = self.register(dir, &name, ident_at(fd.as_raw_fd(), &c, &st)?)?;
                        entries.push(self.meta(id, &name, &st));
                    }
                    matched += 1;
                }
                if kind == Kind::Directory && !is_git_name(&name) && depth + 1 < SEARCH_MAX_DEPTH {
                    let id = self.register(dir, &name, ident_at(fd.as_raw_fd(), &c, &st)?)?;
                    queue.push_back((id, depth + 1));
                }
            }
        }
        let truncated = more || budget_hit;
        Ok(Page {
            next: more.then(|| (skip + entries.len() as u64).to_le_bytes().to_vec()),
            entries,
            truncated,
        })
    }

    // ---- mutations --------------------------------------------------------

    /// True when the directory chain of `entry` passes through `.git` or a
    /// protected identity.
    fn chain_is_protected(&self, entry: EntryRef) -> Result<bool> {
        let registry = self.registry.lock().map_err(|_| Error::Limit)?;
        let mut cursor = entry;
        loop {
            let node = registry.nodes.get(&cursor).ok_or(Error::NotFound)?;
            if cursor != self.root_entry
                && (is_git_name(&node.name) || self.is_protected_ident(&node.ident))
            {
                return Ok(true);
            }
            match node.parent {
                Some(parent) => cursor = parent,
                None => return Ok(false),
            }
        }
    }

    fn open_mutation_parent(
        &self,
        parent: EntryRef,
        parent_revision: &str,
    ) -> Result<(OwnedFd, libc::stat)> {
        if self.entry_has_private_staging_name(parent)? {
            return Err(Error::Protected);
        }
        if self.chain_is_protected(parent)? {
            return Err(Error::Protected);
        }
        let (fd, st) = self.open_dir(parent)?;
        self.check_revision(&st, Some(parent_revision))?;
        Ok((fd, st))
    }

    fn validate_new_name(name: &[u8]) -> Result<CString> {
        if is_git_name(name) || is_private_staging_name(name) {
            return Err(Error::Protected);
        }
        cstring(name)
    }

    /// Creates an EMPTY regular file; destination must be absent. The mode never
    /// carries execute bits.
    pub fn create_file(
        &self,
        parent: EntryRef,
        parent_revision: &str,
        name: &[u8],
    ) -> Result<Meta> {
        self.create_file_guarded(parent, parent_revision, name, |_| true)
    }

    /// Creates an empty file with an optional owner-local authorization
    /// checkpoint and a final lock-free publication gate. The callback must
    /// not re-enter this FileRoot.
    pub fn create_file_guarded(
        &self,
        parent: EntryRef,
        parent_revision: &str,
        name: &[u8],
        mut check: impl FnMut(LocalNativeFileCheckPhase) -> bool,
    ) -> Result<Meta> {
        let _guard = self.write.lock().map_err(|_| Error::Limit)?;
        let c = Self::validate_new_name(name)?;
        let (initial_parent, initial_stat) = self.open_mutation_parent(parent, parent_revision)?;
        let initial_ident = ident_fd(initial_parent.as_raw_fd(), &initial_stat)?;
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::BeforeEffect)?;
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::Validation)?;
        let (parent_fd, parent_stat) = self.open_mutation_parent(parent, parent_revision)?;
        if ident_fd(parent_fd.as_raw_fd(), &parent_stat)? != initial_ident {
            return Err(Error::Changed);
        }
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::Publication)?;
        let file = openat(
            parent_fd.as_raw_fd(),
            &c,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            0o644,
            false,
        )?;
        let st = fstat(file.as_raw_fd())?;
        let id = self.register(parent, name, ident_fd(file.as_raw_fd(), &st)?)?;
        Ok(self.meta(id, name, &st))
    }

    pub fn mkdir(&self, parent: EntryRef, parent_revision: &str, name: &[u8]) -> Result<Meta> {
        self.mkdir_guarded(parent, parent_revision, name, |_| true)
    }

    /// Creates a directory with a final lock-free publication gate. The
    /// callback must not re-enter this FileRoot.
    pub fn mkdir_guarded(
        &self,
        parent: EntryRef,
        parent_revision: &str,
        name: &[u8],
        mut check: impl FnMut(LocalNativeFileCheckPhase) -> bool,
    ) -> Result<Meta> {
        let _guard = self.write.lock().map_err(|_| Error::Limit)?;
        let c = Self::validate_new_name(name)?;
        let (initial_parent, initial_stat) = self.open_mutation_parent(parent, parent_revision)?;
        let initial_ident = ident_fd(initial_parent.as_raw_fd(), &initial_stat)?;
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::BeforeEffect)?;
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::Validation)?;
        let (parent_fd, parent_stat) = self.open_mutation_parent(parent, parent_revision)?;
        if ident_fd(parent_fd.as_raw_fd(), &parent_stat)? != initial_ident {
            return Err(Error::Changed);
        }
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::Publication)?;
        if unsafe { libc::mkdirat(parent_fd.as_raw_fd(), c.as_ptr(), 0o755) } != 0 {
            return Err(map_errno(last_errno(), false));
        }
        let st = fstatat_nofollow(parent_fd.as_raw_fd(), &c)?;
        let id = self.register(parent, name, ident_at(parent_fd.as_raw_fd(), &c, &st)?)?;
        Ok(self.meta(id, name, &st))
    }

    /// Validates the entry about to be changed. Hard-linked regular files and
    /// repository/host metadata are refused.
    fn check_mutable_leaf(
        &self,
        name: &[u8],
        st: &libc::stat,
        ident: &Ident,
        expected_revision: &str,
    ) -> Result<()> {
        if is_git_name(name) || is_private_staging_name(name) || self.is_protected_ident(ident) {
            return Err(Error::Protected);
        }
        if kind_of(st) == Kind::File && st.st_nlink as u64 > 1 {
            return Err(Error::Protected);
        }
        self.check_revision(st, Some(expected_revision))
    }

    /// Removes a file, a link (never its target) or an EMPTY directory.
    pub fn remove(
        &self,
        entry: EntryRef,
        revision: &str,
        parent: EntryRef,
        parent_revision: &str,
    ) -> Result<()> {
        self.remove_guarded(entry, revision, parent, parent_revision, None, |_| true)
    }

    /// Removes an entry after fresh parent/leaf validation and a final
    /// lock-free publication gate. The callback must not re-enter FileRoot.
    pub fn remove_guarded(
        &self,
        entry: EntryRef,
        revision: &str,
        parent: EntryRef,
        parent_revision: &str,
        expected_source: Option<&crate::desktop::DesktopSourcePrecondition>,
        mut check: impl FnMut(LocalNativeFileCheckPhase) -> bool,
    ) -> Result<()> {
        let _guard = self.write.lock().map_err(|_| Error::Limit)?;
        if entry == self.root_entry {
            return Err(Error::Protected);
        }
        let (node_parent, name, _) = self.node(entry)?;
        if node_parent != Some(parent) {
            return Err(Error::Changed);
        }
        let (initial_parent_fd, initial_parent_stat) =
            self.open_mutation_parent(parent, parent_revision)?;
        let initial_parent_ident = ident_fd(initial_parent_fd.as_raw_fd(), &initial_parent_stat)?;
        let c = cstring(&name)?;
        let initial_st = fstatat_nofollow(initial_parent_fd.as_raw_fd(), &c)?;
        let initial_ident = ident_at(initial_parent_fd.as_raw_fd(), &c, &initial_st)?;
        if initial_ident != self.node(entry)?.2 {
            return Err(Error::Changed);
        }
        self.check_mutable_leaf(&name, &initial_st, &initial_ident, revision)?;
        check_expected_native_source(expected_source, initial_ident, kind_of(&initial_st))?;
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::BeforeEffect)?;
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::Validation)?;

        let (parent_fd, parent_stat) = self.open_mutation_parent(parent, parent_revision)?;
        if ident_fd(parent_fd.as_raw_fd(), &parent_stat)? != initial_parent_ident {
            return Err(Error::Changed);
        }
        let st = fstatat_nofollow(parent_fd.as_raw_fd(), &c)?;
        let ident = ident_at(parent_fd.as_raw_fd(), &c, &st)?;
        if ident != initial_ident || ident != self.node(entry)?.2 {
            return Err(Error::Changed);
        }
        self.check_mutable_leaf(&name, &st, &ident, revision)?;
        check_expected_native_source(expected_source, ident, kind_of(&st))?;
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::Publication)?;

        let flags = if kind_of(&st) == Kind::Directory {
            libc::AT_REMOVEDIR
        } else {
            0
        };
        if unsafe { libc::unlinkat(parent_fd.as_raw_fd(), c.as_ptr(), flags) } != 0 {
            let errno = last_errno();
            return Err(match errno {
                // Linux reports a non-empty directory as ENOTEMPTY, some
                // systems as EEXIST.
                libc::ENOTEMPTY | libc::EEXIST => Error::NotEmpty,
                other => map_errno(other, false),
            });
        }
        let mut registry = self.registry.lock().map_err(|_| Error::Limit)?;
        registry.nodes.remove(&entry);
        registry.by_name.remove(&(parent, name));
        Ok(())
    }

    /// Renames without ever replacing an existing destination.
    #[allow(clippy::too_many_arguments)]
    pub fn rename(
        &self,
        entry: EntryRef,
        revision: &str,
        source_parent: EntryRef,
        source_parent_revision: &str,
        target_parent: EntryRef,
        target_parent_revision: &str,
        name: &[u8],
    ) -> Result<Meta> {
        self.rename_guarded(
            entry,
            revision,
            source_parent,
            source_parent_revision,
            target_parent,
            target_parent_revision,
            name,
            None,
            |_| true,
        )
    }

    /// Renames an entry without replacement after fresh validation and a
    /// final lock-free publication gate. The callback must not re-enter root.
    #[allow(clippy::too_many_arguments)]
    pub fn rename_guarded(
        &self,
        entry: EntryRef,
        revision: &str,
        source_parent: EntryRef,
        source_parent_revision: &str,
        target_parent: EntryRef,
        target_parent_revision: &str,
        name: &[u8],
        expected_source: Option<&crate::desktop::DesktopSourcePrecondition>,
        mut check: impl FnMut(LocalNativeFileCheckPhase) -> bool,
    ) -> Result<Meta> {
        let _guard = self.write.lock().map_err(|_| Error::Limit)?;
        let target = Self::validate_new_name(name)?;
        if entry == self.root_entry {
            return Err(Error::Protected);
        }
        let (node_parent, old_name, node_ident) = self.node(entry)?;
        if node_parent != Some(source_parent) {
            return Err(Error::Changed);
        }
        let (initial_source_fd, initial_source_stat) =
            self.open_mutation_parent(source_parent, source_parent_revision)?;
        let initial_source_parent_ident =
            ident_fd(initial_source_fd.as_raw_fd(), &initial_source_stat)?;
        let (initial_target_fd, initial_target_stat) =
            self.open_mutation_parent(target_parent, target_parent_revision)?;
        let initial_target_parent_ident =
            ident_fd(initial_target_fd.as_raw_fd(), &initial_target_stat)?;
        let old = cstring(&old_name)?;
        let initial_st = fstatat_nofollow(initial_source_fd.as_raw_fd(), &old)?;
        let initial_source_ident = ident_at(initial_source_fd.as_raw_fd(), &old, &initial_st)?;
        if initial_source_ident != node_ident {
            return Err(Error::Changed);
        }
        self.check_mutable_leaf(&old_name, &initial_st, &initial_source_ident, revision)?;
        check_expected_native_source(expected_source, initial_source_ident, kind_of(&initial_st))?;
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::BeforeEffect)?;
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::Validation)?;

        let (source_fd, source_stat) =
            self.open_mutation_parent(source_parent, source_parent_revision)?;
        if ident_fd(source_fd.as_raw_fd(), &source_stat)? != initial_source_parent_ident {
            return Err(Error::Changed);
        }
        let (target_fd, target_stat) =
            self.open_mutation_parent(target_parent, target_parent_revision)?;
        if ident_fd(target_fd.as_raw_fd(), &target_stat)? != initial_target_parent_ident {
            return Err(Error::Changed);
        }
        let st = fstatat_nofollow(source_fd.as_raw_fd(), &old)?;
        let source_ident = ident_at(source_fd.as_raw_fd(), &old, &st)?;
        if source_ident != initial_source_ident || source_ident != node_ident {
            return Err(Error::Changed);
        }
        self.check_mutable_leaf(&old_name, &st, &source_ident, revision)?;
        check_expected_native_source(expected_source, source_ident, kind_of(&st))?;
        check_native_mutation_phase(&mut check, LocalNativeFileCheckPhase::Publication)?;
        no_replace_rename(source_fd.as_raw_fd(), &old, target_fd.as_raw_fd(), &target)?;
        let moved = fstatat_nofollow(target_fd.as_raw_fd(), &target)?;
        let mut registry = self.registry.lock().map_err(|_| Error::Limit)?;
        registry.by_name.remove(&(source_parent, old_name));
        if let Some(node) = registry.nodes.get_mut(&entry) {
            node.parent = Some(target_parent);
            node.name = name.to_vec();
            node.ident = ident_at(target_fd.as_raw_fd(), &target, &moved)?;
        }
        registry
            .by_name
            .insert((target_parent, name.to_vec()), entry);
        Ok(self.meta(entry, name, &moved))
    }
}

fn open_git_child_dir(parent: &OwnedFd, name: &[u8]) -> Result<(OwnedFd, libc::stat)> {
    let name = cstring(name)?;
    let fd = openat(
        parent.as_raw_fd(),
        &name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        0,
        true,
    )?;
    let st = fstat(fd.as_raw_fd())?;
    if kind_of(&st) != Kind::Directory {
        return Err(Error::Changed);
    }
    Ok((fd, st))
}

fn open_or_create_git_child_dir(parent: &OwnedFd, name: &[u8]) -> Result<(OwnedFd, libc::stat)> {
    let directory = match open_git_child_dir(parent, name) {
        Ok(directory) => directory,
        Err(Error::NotFound) => {
            let name = cstring(name)?;
            if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                let error = last_errno();
                if error != libc::EEXIST {
                    return Err(map_errno(error, false));
                }
            }
            open_git_child_dir(parent, name.as_bytes())?
        }
        Err(error) => return Err(error),
    };
    // Sync even when the directory already exists. A previous mkdir may have
    // succeeded while its parent fsync failed, so retrying must not assume the
    // directory entry is durable.
    sync_git_directory(parent.as_raw_fd())?;
    Ok(directory)
}

#[cfg(test)]
static FAIL_GIT_DIRECTORY_FSYNC_AFTER: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn sync_git_directory(fd: RawFd) -> Result<()> {
    #[cfg(test)]
    {
        use std::sync::atomic::Ordering;
        let mut remaining = FAIL_GIT_DIRECTORY_FSYNC_AFTER.load(Ordering::SeqCst);
        while remaining != 0 {
            match FAIL_GIT_DIRECTORY_FSYNC_AFTER.compare_exchange(
                remaining,
                remaining - 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) if remaining == 1 => return Err(Error::Io(std::io::ErrorKind::Other)),
                Ok(_) => break,
                Err(actual) => remaining = actual,
            }
        }
    }
    if unsafe { libc::fsync(fd) } != 0 {
        return Err(map_errno(last_errno(), false));
    }
    Ok(())
}

#[derive(Clone)]
struct CreatedGitDir {
    name: Vec<u8>,
    identity: Ident,
    created_here: bool,
}

struct GitInfoCreationBaseline {
    marker_entry: EntryRef,
    marker_revision: String,
    parent_identity: Ident,
    entries: Vec<(Vec<u8>, Ident)>,
}

struct GitInfoCreationGuard {
    marker_entry: EntryRef,
    marker_revision: String,
    parent: OwnedFd,
    parent_identity: Ident,
    revision_after_creation: String,
    entries_after_creation: Vec<(Vec<u8>, Ident)>,
    info_identity: Ident,
}

fn git_directory_census(dir: &OwnedFd) -> Result<Vec<(Vec<u8>, Ident)>> {
    let mut names = read_dir_names(dir)?;
    names.sort();
    let mut entries = Vec::with_capacity(names.len());
    for name in &names {
        let c_name = cstring(name)?;
        let stat = fstatat_nofollow(dir.as_raw_fd(), &c_name)?;
        entries.push((name.clone(), ident_at(dir.as_raw_fd(), &c_name, &stat)?));
    }
    let mut names_after = read_dir_names(dir)?;
    names_after.sort();
    if names_after != names {
        return Err(Error::Changed);
    }
    Ok(entries)
}

fn create_git_target_parent(
    base: &OwnedFd,
    suffix: &[Vec<u8>],
    created: &mut Vec<CreatedGitDir>,
    base_entry: EntryRef,
    preceding: &[GitPublishedGuard],
    continue_check: &mut impl FnMut() -> bool,
) -> Result<OwnedFd> {
    let mut current = dup(base.as_raw_fd())?;
    let mut prefix = Vec::with_capacity(suffix.len());
    for component in suffix {
        if !continue_check() {
            return Err(Error::Changed);
        }
        prefix.push(component.clone());
        let name = cstring(component)?;
        let previously_owned = preceding.iter().find_map(|guard| {
            (guard.base == base_entry
                && guard.parent_suffix.len() >= prefix.len()
                && guard.parent_suffix[..prefix.len()] == prefix)
                .then(|| guard.parent_identities.get(prefix.len() - 1).copied())
                .flatten()
        });
        let (child, stat) = if let Some(identity) = previously_owned {
            let (child, stat) = open_git_child_dir(&current, component)?;
            if ident_fd(child.as_raw_fd(), &stat)? != identity {
                return Err(Error::Changed);
            }
            (child, stat)
        } else {
            if unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                return Err(if last_errno() == libc::EEXIST {
                    Error::Changed
                } else {
                    map_errno(last_errno(), false)
                });
            }
            let stat = fstatat_nofollow(current.as_raw_fd(), &name)?;
            if kind_of(&stat) != Kind::Directory {
                return Err(Error::Changed);
            }
            let identity = ident_at(current.as_raw_fd(), &name, &stat)?;
            created.push(CreatedGitDir {
                name: component.clone(),
                identity,
                created_here: true,
            });
            let (child, stat) = open_git_child_dir(&current, component)?;
            if ident_fd(child.as_raw_fd(), &stat)? != identity {
                return Err(Error::Changed);
            }
            sync_git_directory(current.as_raw_fd())?;
            (child, stat)
        };
        if kind_of(&stat) != Kind::Directory {
            return Err(Error::Changed);
        }
        let identity = ident_fd(child.as_raw_fd(), &stat)?;
        if previously_owned.is_some() {
            created.push(CreatedGitDir {
                name: component.clone(),
                identity,
                created_here: false,
            });
        }
        current = child;
    }
    Ok(current)
}

fn verify_git_target_parent(
    base: &OwnedFd,
    suffix: &[Vec<u8>],
    created: &[CreatedGitDir],
) -> Result<OwnedFd> {
    if suffix.len() != created.len() {
        return Err(Error::Changed);
    }
    let mut current = dup(base.as_raw_fd())?;
    for (component, expected) in suffix.iter().zip(created) {
        if component != &expected.name {
            return Err(Error::Changed);
        }
        let (child, stat) = open_git_child_dir(&current, component)?;
        if ident_fd(child.as_raw_fd(), &stat)? != expected.identity {
            return Err(Error::Changed);
        }
        current = child;
    }
    Ok(current)
}

fn cleanup_created_git_dirs(base: &OwnedFd, created: &[CreatedGitDir]) {
    for index in (0..created.len()).rev() {
        if !created[index].created_here {
            continue;
        }
        let mut parent = match dup(base.as_raw_fd()) {
            Ok(fd) => fd,
            Err(_) => continue,
        };
        let mut valid = true;
        for component in &created[..index] {
            let Ok((child, stat)) = open_git_child_dir(&parent, &component.name) else {
                valid = false;
                break;
            };
            if ident_fd(child.as_raw_fd(), &stat).ok() != Some(component.identity) {
                valid = false;
                break;
            }
            parent = child;
        }
        if !valid {
            continue;
        }
        let Ok(name) = cstring(&created[index].name) else {
            continue;
        };
        let Ok(stat) = fstatat_nofollow(parent.as_raw_fd(), &name) else {
            continue;
        };
        if kind_of(&stat) != Kind::Directory
            || ident_at(parent.as_raw_fd(), &name, &stat).ok() != Some(created[index].identity)
        {
            continue;
        }
        if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } == 0 {
            let _ = sync_git_directory(parent.as_raw_fd());
        }
    }
}

fn write_git_bytes(
    file: &mut File,
    bytes: &[u8],
    continue_check: &mut impl FnMut() -> bool,
) -> Result<bool> {
    for chunk in bytes.chunks(64 * 1024) {
        if !continue_check() {
            return Ok(false);
        }
        file.write_all(chunk).map_err(map_io)?;
    }
    Ok(continue_check())
}

fn hash_git_file(file: &mut File, expected_len: usize) -> Result<[u8; 32]> {
    file.seek(SeekFrom::Start(0)).map_err(map_io)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 16 * 1024];
    let mut total = 0usize;
    loop {
        let read = file.read(&mut buffer).map_err(map_io)?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read).ok_or(Error::Limit)?;
        if total > expected_len {
            return Err(Error::Changed);
        }
        digest.update(&buffer[..read]);
    }
    if total != expected_len {
        return Err(Error::Changed);
    }
    file.seek(SeekFrom::Start(0)).map_err(map_io)?;
    Ok(digest.finalize().into())
}

fn map_io(error: std::io::Error) -> Error {
    match error.raw_os_error() {
        Some(errno) => map_errno(errno, false),
        None => Error::Io(error.kind()),
    }
}

fn install_git_object(
    directory: &OwnedFd,
    suffix: &[u8],
    bytes: &[u8],
    continue_check: &mut impl FnMut() -> bool,
) -> Result<()> {
    let expected_digest: [u8; 32] = Sha256::digest(bytes).into();
    let target = cstring(suffix)?;
    match verify_existing_git_object(directory, &target, bytes, continue_check) {
        Ok(()) => {
            // A previous writer may have linked this object but failed to
            // durably sync its fanout directory. Make retries re-establish
            // that durability before a later index/ref can point at it.
            sync_git_directory(directory.as_raw_fd())?;
            return Ok(());
        }
        Err(Error::NotFound) => {}
        Err(error) => return Err(error),
    }

    let temporary = format!(".lomi-object-{}.tmp", uuid::Uuid::new_v4().simple());
    let temporary = cstring(temporary.as_bytes())?;
    let temporary_fd = openat(
        directory.as_raw_fd(),
        &temporary,
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
        0o600,
        false,
    )?;
    let mut temporary_file = File::from(temporary_fd);
    let temporary_stat = fstat(temporary_file.as_raw_fd())?;
    if kind_of(&temporary_stat) != Kind::File || temporary_stat.st_nlink != 1 {
        return Err(Error::Protected);
    }
    let temporary_identity = ident_fd(temporary_file.as_raw_fd(), &temporary_stat)?;
    apply_git_file_security(temporary_file.as_raw_fd(), None, None)?;
    let write_result = (|| {
        if !write_git_bytes(&mut temporary_file, bytes, continue_check)? {
            return Ok(false);
        }
        temporary_file.sync_all().map_err(map_io)?;
        apply_git_file_security(temporary_file.as_raw_fd(), None, None)?;
        temporary_file.sync_all().map_err(map_io)?;
        if hash_git_file(&mut temporary_file, bytes.len())? != expected_digest {
            return Err(Error::Changed);
        }
        Ok(true)
    })();
    match write_result {
        Ok(false) => {
            unlink_owned_git_file(directory.as_raw_fd(), &temporary, temporary_identity)?;
            return Err(Error::Changed);
        }
        Err(error) => {
            unlink_owned_git_file(directory.as_raw_fd(), &temporary, temporary_identity)?;
            return Err(error);
        }
        Ok(true) => {}
    }
    if !continue_check() {
        unlink_owned_git_file(directory.as_raw_fd(), &temporary, temporary_identity)?;
        return Err(Error::Changed);
    }
    check_git_fd_name_identity(
        directory.as_raw_fd(),
        &temporary,
        temporary_file.as_raw_fd(),
        temporary_identity,
        Some(1),
    )?;
    if unsafe {
        libc::linkat(
            directory.as_raw_fd(),
            temporary.as_ptr(),
            directory.as_raw_fd(),
            target.as_ptr(),
            0,
        )
    } != 0
    {
        let errno = last_errno();
        unlink_owned_git_file(directory.as_raw_fd(), &temporary, temporary_identity)?;
        if errno == libc::EEXIST {
            verify_existing_git_object(directory, &target, bytes, continue_check)?;
            sync_git_directory(directory.as_raw_fd())?;
            return Ok(());
        }
        return Err(map_errno(errno, false));
    }
    if check_git_fd_name_identity(
        directory.as_raw_fd(),
        &target,
        temporary_file.as_raw_fd(),
        temporary_identity,
        Some(2),
    )
    .is_err()
        || hash_git_file(&mut temporary_file, bytes.len()).ok() != Some(expected_digest)
    {
        return Err(Error::Changed);
    }
    if check_git_entry_identity(directory.as_raw_fd(), &target, temporary_identity).is_err() {
        let _ = unlink_owned_git_file(directory.as_raw_fd(), &temporary, temporary_identity);
        return Err(Error::Changed);
    }
    unlink_owned_git_file(directory.as_raw_fd(), &temporary, temporary_identity)?;
    drop(temporary_file);
    sync_git_directory(directory.as_raw_fd())?;
    Ok(())
}

fn verify_existing_git_object(
    directory: &OwnedFd,
    target: &CStr,
    bytes: &[u8],
    continue_check: &mut impl FnMut() -> bool,
) -> Result<()> {
    let existing = openat(
        directory.as_raw_fd(),
        target,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        0,
        false,
    )?;
    let st = fstat(existing.as_raw_fd())?;
    if kind_of(&st) != Kind::File || st.st_nlink != 1 || st.st_size as usize != bytes.len() {
        return Err(Error::Protected);
    }
    let mut existing = File::from(existing);
    let mut contents = Vec::with_capacity(bytes.len());
    let mut chunk = [0u8; 64 * 1024];
    loop {
        if !continue_check() {
            return Err(Error::Changed);
        }
        let count = existing.read(&mut chunk).map_err(map_io)?;
        if count == 0 {
            break;
        }
        contents.extend_from_slice(&chunk[..count]);
        if contents.len() > bytes.len() {
            return Err(Error::Changed);
        }
    }
    if contents != bytes {
        return Err(Error::Changed);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_child_watch_budget() -> usize {
    let mut limits: libc::rlimit = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) } != 0 {
        return 0;
    }
    // /dev/fd includes the descriptor used to enumerate it; it is closed
    // before we use the count below. Keep headroom for host connections,
    // reconciliation and unrelated application work.
    let Ok(open_fds) = std::fs::read_dir("/dev/fd") else {
        return 0;
    };
    let open_count = open_fds.count().saturating_sub(1) as libc::rlim_t;
    let available = limits
        .rlim_cur
        .saturating_sub(open_count)
        .saturating_sub(WATCH_RESERVED_DESCRIPTORS);
    MAX_CHILD_WATCHES.min(available.min(usize::MAX as libc::rlim_t) as usize)
}

/// Opaque invalidation source for a directory pinned by `FileRoot`.
#[cfg(target_os = "linux")]
pub struct DirectoryWatch {
    inotify: OwnedFd,
    _directory: OwnedFd,
    watch_descriptors: Vec<i32>,
}

#[cfg(target_os = "macos")]
pub struct DirectoryWatch {
    queue: OwnedFd,
    _directory: OwnedFd,
    _children: Vec<OwnedFd>,
}

#[cfg(target_os = "macos")]
fn register_vnode(queue: RawFd, target: RawFd, notes: u32) -> Result<()> {
    let event = libc::kevent {
        ident: target as usize,
        filter: libc::EVFILT_VNODE,
        flags: libc::EV_ADD | libc::EV_CLEAR,
        fflags: notes,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    let rc = unsafe { libc::kevent(queue, &event, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
    if rc < 0 {
        return Err(map_errno(last_errno(), false));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
impl DirectoryWatch {
    /// Drains vnode invalidations. Any event requires reconciliation. A queue
    /// error is surfaced so callers fail closed instead of trusting stale
    /// state.
    pub fn changed(&self) -> Result<bool> {
        let mut changed = false;
        let mut events = [unsafe { std::mem::zeroed::<libc::kevent>() }; 257];
        loop {
            let timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let count = unsafe {
                libc::kevent(
                    self.queue.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    events.as_mut_ptr(),
                    events.len() as i32,
                    &timeout,
                )
            };
            if count < 0 {
                let errno = last_errno();
                if errno == libc::EINTR {
                    continue;
                }
                return Err(map_errno(errno, false));
            }
            if count == 0 {
                return Ok(changed);
            }
            changed = true;
            for event in &events[..count as usize] {
                if event.flags & libc::EV_ERROR != 0 {
                    return Err(if event.data == 0 {
                        Error::Changed
                    } else {
                        map_errno(event.data as i32, false)
                    });
                }
                if event.flags & libc::EV_EOF != 0 {
                    return Err(Error::Changed);
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn add_inotify_watch(inotify: RawFd, target: RawFd) -> i32 {
    let procfd = CString::new(format!("/proc/self/fd/{target}")).unwrap();
    let mask = libc::IN_ATTRIB
        | libc::IN_CREATE
        | libc::IN_DELETE
        | libc::IN_DELETE_SELF
        | libc::IN_MODIFY
        | libc::IN_MOVE_SELF
        | libc::IN_MOVED_FROM
        | libc::IN_MOVED_TO;
    unsafe { libc::inotify_add_watch(inotify, procfd.as_ptr(), mask) }
}

#[cfg(target_os = "linux")]
impl DirectoryWatch {
    /// Drains pending events. `true` means reconcile; any event (including
    /// IN_Q_OVERFLOW) is surfaced, so callers never silently drop changes.
    pub fn changed(&self) -> Result<bool> {
        let mut buffer = [0u8; 4096];
        let mut changed = false;
        loop {
            let n = unsafe {
                libc::read(
                    self.inotify.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if n < 0 {
                let errno = last_errno();
                if errno == libc::EINTR {
                    continue;
                }
                if errno == libc::EAGAIN {
                    return Ok(changed);
                }
                return Err(map_errno(errno, false));
            }
            if n == 0 {
                return Err(Error::Changed);
            }
            changed = true;
            scan_inotify_events(&buffer[..n as usize])?;
        }
    }
}

#[cfg(target_os = "linux")]
fn scan_inotify_events(buffer: &[u8]) -> Result<()> {
    let mut offset = 0usize;
    while offset + std::mem::size_of::<libc::inotify_event>() <= buffer.len() {
        let event = unsafe {
            std::ptr::read_unaligned(buffer.as_ptr().add(offset).cast::<libc::inotify_event>())
        };
        if event.mask & libc::IN_Q_OVERFLOW != 0 {
            return Err(Error::Limit);
        }
        offset += std::mem::size_of::<libc::inotify_event>() + event.len as usize;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
impl Drop for DirectoryWatch {
    fn drop(&mut self) {
        for wd in &self.watch_descriptors {
            unsafe {
                libc::inotify_rm_watch(self.inotify.as_raw_fd(), *wd);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn path_ident(path: &Path) -> Result<Ident> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::Invalid)?;
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(map_errno(last_errno(), false));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let st = fstat(fd.as_raw_fd())?;
    ident_fd(fd.as_raw_fd(), &st)
}

#[cfg(target_os = "macos")]
fn path_ident(path: &Path) -> Result<Ident> {
    use std::os::macos::fs::MetadataExt as MacMetadataExt;
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path)
        .map_err(|error| map_errno(error.raw_os_error().unwrap_or(0), false))?;
    Ok(Ident {
        dev: metadata.dev(),
        ino: metadata.ino(),
        birth_sec: metadata.st_birthtime() as i64,
        birth_nsec: metadata.st_birthtime_nsec() as i64,
    })
}

fn ancestor_idents(path: &Path) -> Result<Vec<Ident>> {
    path.ancestors().map(path_ident).collect()
}

fn open_owner_metadata_path(path: &Path) -> Result<OpenedOwnerMetadataPath> {
    if !path.is_absolute() {
        return Err(Error::Invalid);
    }
    let root_name = CString::new(b"/").map_err(|_| Error::Invalid)?;
    let root_fd = unsafe {
        libc::open(
            root_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if root_fd < 0 {
        return Err(map_errno(last_errno(), false));
    }
    let root_fd = unsafe { OwnedFd::from_raw_fd(root_fd) };
    let root_stat = fstat(root_fd.as_raw_fd())?;
    let mut handles = vec![root_fd];
    let mut components = Vec::new();
    let mut identities = vec![ident_fd(handles[0].as_raw_fd(), &root_stat)?];

    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                if components.pop().is_some() {
                    identities.pop();
                    handles.pop();
                }
            }
            Component::Normal(name) => {
                let bytes = name.as_bytes();
                if bytes.is_empty() || bytes.contains(&0) || bytes.contains(&b'/') {
                    return Err(Error::Invalid);
                }
                let name = cstring(bytes)?;
                let child = openat(
                    handles.last().ok_or(Error::Changed)?.as_raw_fd(),
                    &name,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                    0,
                    true,
                )?;
                let stat = fstat(child.as_raw_fd())?;
                if kind_of(&stat) != Kind::Directory {
                    return Err(Error::Changed);
                }
                identities.push(ident_fd(child.as_raw_fd(), &stat)?);
                components.push(bytes.to_vec());
                handles.push(child);
            }
            Component::Prefix(_) => return Err(Error::Invalid),
        }
    }
    if components.is_empty() {
        return Err(Error::Protected);
    }

    let mut canonical = PathBuf::from("/");
    for component in &components {
        canonical.push(std::ffi::OsStr::from_bytes(component));
    }
    let root = handles.pop().ok_or(Error::Changed)?;
    Ok(OpenedOwnerMetadataPath {
        root,
        path: canonical,
        components,
        identities,
        ancestor_handles: handles,
    })
}

fn check_owner_metadata_protection(
    metadata_path: &Path,
    metadata_identities: &[Ident],
    protected_paths: &[PathBuf],
    allow_workspace_descendant: bool,
) -> Result<()> {
    let metadata_identity = *metadata_identities.last().ok_or(Error::Changed)?;
    for (index, protected_path) in protected_paths.iter().enumerate() {
        let canonical_protected = protected_path
            .canonicalize()
            .map_err(|error| map_errno(error.raw_os_error().unwrap_or(0), false))?;
        let protected_id = path_ident(&canonical_protected)?;
        let verified_workspace_descendant = allow_workspace_descendant
            && index == 0
            && metadata_path != canonical_protected
            && metadata_path.starts_with(&canonical_protected)
            && metadata_identities[..metadata_identities.len().saturating_sub(1)]
                .contains(&protected_id);
        if verified_workspace_descendant {
            continue;
        }
        if canonical_protected.starts_with(metadata_path)
            || metadata_path.starts_with(&canonical_protected)
        {
            return Err(Error::Protected);
        }
        let protected_ancestors = ancestor_idents(&canonical_protected)?;
        if metadata_identities.contains(&protected_id)
            || protected_ancestors.contains(&metadata_identity)
        {
            return Err(Error::Protected);
        }
    }
    Ok(())
}

fn read_dir_names(fd: &OwnedFd) -> Result<Vec<Vec<u8>>> {
    let duplicate = dup(fd.as_raw_fd())?;
    let raw = duplicate.as_raw_fd();
    let dir = unsafe { libc::fdopendir(raw) };
    if dir.is_null() {
        return Err(map_errno(last_errno(), false));
    }
    // fdopendir took ownership of the descriptor; closedir releases it.
    std::mem::forget(duplicate);
    unsafe { libc::rewinddir(dir) };
    let mut names = Vec::new();
    let result = loop {
        unsafe { *errno_location() = 0 };
        let entry = unsafe { libc::readdir(dir) };
        if entry.is_null() {
            break match unsafe { *errno_location() } {
                0 => Ok(()),
                e => Err(map_errno(e, false)),
            };
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if names.len() >= MAX_DIR_ENTRIES {
            break Err(Error::Limit);
        }
        names.push(name.to_vec());
    };
    unsafe { libc::closedir(dir) };
    result.map(|()| names)
}

#[cfg(target_os = "linux")]
unsafe fn errno_location() -> *mut i32 {
    unsafe { libc::__errno_location() }
}
#[cfg(target_os = "macos")]
unsafe fn errno_location() -> *mut i32 {
    unsafe { libc::__error() }
}

#[cfg(target_os = "linux")]
fn no_replace_rename(from_dir: RawFd, from: &CStr, to_dir: RawFd, to: &CStr) -> Result<()> {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            from_dir,
            from.as_ptr(),
            to_dir,
            to.as_ptr(),
            1 as libc::c_uint, // RENAME_NOREPLACE
        )
    };
    if rc != 0 {
        return Err(map_errno(last_errno(), false));
    }
    Ok(())
}
#[cfg(target_os = "macos")]
fn no_replace_rename(from_dir: RawFd, from: &CStr, to_dir: RawFd, to: &CStr) -> Result<()> {
    let rc = unsafe {
        libc::renameatx_np(
            from_dir,
            from.as_ptr(),
            to_dir,
            to.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if rc != 0 {
        return Err(map_errno(last_errno(), false));
    }
    Ok(())
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn no_replace_rename(_: RawFd, _: &CStr, _: RawFd, _: &CStr) -> Result<()> {
    // No race-free no-replace rename is qualified on this platform.
    Err(Error::Unsupported)
}

#[cfg(test)]
mod tests;
