//! Explicit system LaunchDaemon for a selected existing non-root account.
//!
//! Installation and lifecycle operations are administrator-only. The daemon
//! itself runs with the selected account's UID/GID so its profile, IPC peer
//! identity, and macOS Keychain access stay in that account's context.

use super::{Error, Result};
use crate::unix::{LocalClient, LocalDiscovery};
use lomi_remote_protocol::{
    LocalIpcVersion,
    ipc::{LocalCall, LocalResult, LocalStatus},
};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{CStr, CString, OsStr},
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt, process::CommandExt},
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const RECORD: &str = "service-registration-macos.json";
const ADMIN_OWNER_BINDING: &str = "admin-owner.json";
const ADMIN_HOST_IDENTITY_BINDING: &str = "host-identity.json";
pub(super) const LAUNCH_DAEMONS: &str = "/Library/LaunchDaemons";
const PROFILE_OWNER_LOCK: &str = "owner.lock";
const ADMIN_LOCK: &str = ".lomi-remote-service.lock";
const DISCOVERY: &str = "discovery.json";
const LIMIT: usize = 32 * 1024;

fn root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
fn c(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| Error::Invalid)
}

#[derive(Clone, Debug)]
struct Account {
    name: String,
    uid: u32,
    gid: u32,
    group: String,
    home: PathBuf,
}

fn valid_account_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

fn account(name: &str) -> Result<Account> {
    if !valid_account_name(name) {
        return Err(Error::Invalid);
    }
    let encoded = CString::new(name).map_err(|_| Error::Invalid)?;
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0u8; 16 * 1024];
    let mut result = std::ptr::null_mut();
    if unsafe {
        libc::getpwnam_r(
            encoded.as_ptr(),
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    } != 0
        || result.is_null()
    {
        return Err(Error::Invalid);
    }
    let canonical_name = unsafe { CStr::from_ptr(entry.pw_name) }
        .to_str()
        .map_err(|_| Error::Invalid)?;
    let home = unsafe { CStr::from_ptr(entry.pw_dir) }
        .to_str()
        .map_err(|_| Error::Invalid)?;
    let uid = entry.pw_uid;
    let gid = entry.pw_gid;
    if canonical_name != name || uid == 0 || !Path::new(home).is_absolute() {
        return Err(Error::Invalid);
    }

    let mut group_entry: libc::group = unsafe { std::mem::zeroed() };
    let mut group_buffer = vec![0u8; 16 * 1024];
    let mut group_result = std::ptr::null_mut();
    if unsafe {
        libc::getgrgid_r(
            gid,
            &mut group_entry,
            group_buffer.as_mut_ptr().cast(),
            group_buffer.len(),
            &mut group_result,
        )
    } != 0
        || group_result.is_null()
    {
        return Err(Error::Invalid);
    }
    let group_name = unsafe { CStr::from_ptr(group_entry.gr_name) }
        .to_str()
        .map_err(|_| Error::Invalid)?;
    if !valid_account_name(group_name) {
        return Err(Error::Invalid);
    }
    let account = Account {
        name: canonical_name.to_owned(),
        uid,
        gid,
        group: group_name.to_owned(),
        home: PathBuf::from(home),
    };
    Directory::open(
        &account.home,
        account.uid,
        false,
        None,
        Some((account.uid, account.gid)),
    )?;
    Ok(account)
}

/// A pinned directory chain. Ancestors may be root- or profile-account-owned;
/// all must be non-writable by group/world and contain no ACL allow entries.
struct Directory(File, PathBuf);
struct RootPlist {
    bytes: Vec<u8>,
    mode: u32,
    device: u64,
    inode: u64,
}

impl Directory {
    fn open(
        path: &Path,
        owner: u32,
        create: bool,
        final_mode: Option<u32>,
        accessible_user: Option<(u32, u32)>,
    ) -> Result<Self> {
        if !path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err(Error::Invalid);
        }
        let mut current = File::open("/").map_err(|_| Error::Invalid)?;
        crate::unix::reject_acl_grants(&current).map_err(|_| Error::Invalid)?;
        for (index, component) in path.components().enumerate().skip(1) {
            let Component::Normal(name) = component else {
                return Err(Error::Invalid);
            };
            let encoded = c(name)?;
            let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            let mut fd = unsafe { libc::openat(current.as_raw_fd(), encoded.as_ptr(), flags) };
            if fd < 0 && create && io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
                if unsafe { libc::mkdirat(current.as_raw_fd(), encoded.as_ptr(), 0o700) } != 0
                    && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
                {
                    return Err(Error::Invalid);
                }
                fd = unsafe { libc::openat(current.as_raw_fd(), encoded.as_ptr(), flags) };
            }
            if fd < 0 {
                return Err(Error::Invalid);
            }
            let next = unsafe { File::from_raw_fd(fd) };
            let metadata = next.metadata().map_err(|_| Error::Invalid)?;
            let final_component = index + 1 == path.components().count();
            if !metadata.is_dir()
                || if final_component {
                    metadata.uid() != owner
                        || final_mode.is_some_and(|mode| metadata.mode() & 0o777 != mode)
                } else {
                    !matches!(metadata.uid(), 0) && metadata.uid() != owner
                }
                || metadata.mode() & 0o022 != 0
                || accessible_user
                    .is_some_and(|(uid, gid)| access_bits(&metadata, uid, gid) & 0o1 == 0)
            {
                return Err(Error::Invalid);
            }
            crate::unix::reject_acl_grants(&next).map_err(|_| Error::Invalid)?;
            if create {
                current.sync_all().map_err(|_| Error::Invalid)?;
            }
            current = next;
        }
        let metadata = current.metadata().map_err(|_| Error::Invalid)?;
        if !metadata.is_dir()
            || metadata.uid() != owner
            || final_mode.is_some_and(|mode| metadata.mode() & 0o777 != mode)
            || metadata.mode() & 0o022 != 0
            || accessible_user.is_some_and(|(uid, gid)| access_bits(&metadata, uid, gid) & 0o1 == 0)
            || path.canonicalize().map_err(|_| Error::Invalid)? != path
        {
            return Err(Error::Invalid);
        }
        crate::unix::reject_acl_grants(&current).map_err(|_| Error::Invalid)?;
        Ok(Self(current, path.to_path_buf()))
    }

    fn regular(&self, name: &str, owner: u32, mode: u32, create: bool) -> Result<Option<File>> {
        let name = c(OsStr::new(name))?;
        let access = if create { libc::O_RDWR } else { libc::O_RDONLY };
        let flags = access
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | if create { libc::O_CREAT } else { 0 };
        let fd = unsafe { libc::openat(self.0.as_raw_fd(), name.as_ptr(), flags, mode) };
        if fd < 0 {
            return if io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(Error::Conflict)
            };
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(|_| Error::Invalid)?;
        if !metadata.is_file()
            || metadata.uid() != owner
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != mode
        {
            return Err(Error::Conflict);
        }
        crate::unix::reject_acl_grants(&file).map_err(|_| Error::Conflict)?;
        Ok(Some(file))
    }

    fn read(&self, name: &str, owner: u32, mode: u32) -> Result<Option<Vec<u8>>> {
        self.regular(name, owner, mode, false)?
            .map(|mut file| {
                let mut bytes = Vec::new();
                (&mut file)
                    .take((LIMIT + 1) as u64)
                    .read_to_end(&mut bytes)
                    .map_err(|_| Error::Invalid)?;
                if bytes.len() > LIMIT {
                    return Err(Error::Invalid);
                }
                Ok(bytes)
            })
            .transpose()
    }

    /// Read the exact root-owned system plist in either the legacy private
    /// mode or the current public-configuration mode. This is used only by
    /// root lifecycle code, which already holds the system service locks.
    fn read_root_plist(&self, name: &str) -> Result<Option<RootPlist>> {
        let encoded = c(OsStr::new(name))?;
        let mut before = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                self.0.as_raw_fd(),
                encoded.as_ptr(),
                before.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                Ok(None)
            } else {
                Err(Error::Conflict)
            };
        }
        let before = unsafe { before.assume_init() };
        let before_mode = (before.st_mode as u32) & 0o7777;
        if (before.st_mode as u32) & libc::S_IFMT as u32 != libc::S_IFREG as u32
            || before.st_uid != 0
            || before.st_nlink != 1
            || !matches!(before_mode, 0o600 | 0o644)
        {
            return Err(Error::Conflict);
        }

        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                encoded.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return if io::Error::last_os_error().kind() == io::ErrorKind::PermissionDenied {
                Err(Error::Unavailable)
            } else {
                Err(Error::Conflict)
            };
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(|_| Error::Conflict)?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != before_mode
            || metadata.dev() != before.st_dev as u64
            || metadata.ino() != before.st_ino as u64
        {
            return Err(Error::Conflict);
        }
        crate::unix::reject_acl_grants(&file).map_err(|_| Error::Conflict)?;
        let mut bytes = Vec::new();
        (&mut file)
            .take((LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Conflict)?;
        if bytes.len() > LIMIT {
            return Err(Error::Conflict);
        }
        Ok(Some(RootPlist {
            bytes,
            mode: before_mode,
            device: before.st_dev as u64,
            inode: before.st_ino as u64,
        }))
    }

    fn read_root_plist_bytes(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.read_root_plist(name)
            .map(|plist| plist.map(|plist| plist.bytes))
    }

    /// User-side observation accepts only the root-protected public plist.
    /// Legacy 0600 installs remain indeterminate to the selected account
    /// until an administrator repairs them under the maintenance barrier.
    fn read_public_root_plist(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let Some(plist) = self.read_root_plist(name)? else {
            return Ok(None);
        };
        if plist.mode == 0o600 {
            return Err(Error::Unavailable);
        }
        if plist.mode != 0o644 {
            return Err(Error::Conflict);
        }
        Ok(Some(plist.bytes))
    }

    fn publish_public_root_plist(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let temporary = format!(".lomi-service-{}", uuid::Uuid::new_v4());
        let temp = c(OsStr::new(&temporary))?;
        let destination = c(OsStr::new(name))?;
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                temp.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o644,
            )
        };
        if fd < 0 {
            return Err(Error::Invalid);
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let result = (|| {
            file.write_all(bytes).map_err(|_| Error::Invalid)?;
            if unsafe { libc::fchown(file.as_raw_fd(), 0, 0) } != 0
                || unsafe { libc::fchmod(file.as_raw_fd(), 0o644) } != 0
            {
                return Err(Error::Invalid);
            }
            let metadata = file.metadata().map_err(|_| Error::Invalid)?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.nlink() != 1
                || metadata.mode() & 0o7777 != 0o644
            {
                return Err(Error::Conflict);
            }
            crate::unix::reject_acl_grants(&file).map_err(|_| Error::Conflict)?;
            file.sync_all().map_err(|_| Error::Invalid)?;
            if unsafe {
                libc::renameatx_np(
                    self.0.as_raw_fd(),
                    temp.as_ptr(),
                    self.0.as_raw_fd(),
                    destination.as_ptr(),
                    libc::RENAME_EXCL,
                )
            } != 0
            {
                return Err(Error::Conflict);
            }
            self.0.sync_all().map_err(|_| Error::Invalid)
        })();
        unsafe {
            libc::unlinkat(self.0.as_raw_fd(), temp.as_ptr(), 0);
        }
        self.0.sync_all().map_err(|_| Error::Invalid)?;
        result
    }

    /// Atomically replace only the exact legacy plist while the caller holds
    /// the existing root LaunchDaemon maintenance locks. A changed or public
    /// plist is never silently adopted as a repair target.
    fn upgrade_root_plist(&self, name: &str, expected: &[u8]) -> Result<()> {
        let Some(current) = self.read_root_plist(name)? else {
            return Err(Error::Conflict);
        };
        if current.bytes != expected {
            return Err(Error::Conflict);
        }
        if current.mode == 0o644 {
            return Ok(());
        }
        if current.mode != 0o600 {
            return Err(Error::Conflict);
        }

        let temporary = format!(".lomi-service-{}", uuid::Uuid::new_v4());
        let temp = c(OsStr::new(&temporary))?;
        let destination = c(OsStr::new(name))?;
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                temp.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o644,
            )
        };
        if fd < 0 {
            return Err(Error::Invalid);
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let result = (|| {
            file.write_all(expected).map_err(|_| Error::Invalid)?;
            if unsafe { libc::fchown(file.as_raw_fd(), 0, 0) } != 0
                || unsafe { libc::fchmod(file.as_raw_fd(), 0o644) } != 0
            {
                return Err(Error::Invalid);
            }
            let metadata = file.metadata().map_err(|_| Error::Invalid)?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.nlink() != 1
                || metadata.mode() & 0o7777 != 0o644
            {
                return Err(Error::Conflict);
            }
            crate::unix::reject_acl_grants(&file).map_err(|_| Error::Conflict)?;
            file.sync_all().map_err(|_| Error::Invalid)?;

            let Some(latest) = self.read_root_plist(name)? else {
                return Err(Error::Conflict);
            };
            if latest.bytes != expected
                || latest.mode != 0o600
                || latest.device != current.device
                || latest.inode != current.inode
            {
                return Err(Error::Conflict);
            }
            if unsafe {
                libc::renameat(
                    self.0.as_raw_fd(),
                    temp.as_ptr(),
                    self.0.as_raw_fd(),
                    destination.as_ptr(),
                )
            } != 0
            {
                return Err(Error::Conflict);
            }
            self.0.sync_all().map_err(|_| Error::Invalid)?;
            let Some(repaired) = self.read_root_plist(name)? else {
                return Err(Error::Conflict);
            };
            if repaired.mode != 0o644 || repaired.bytes != expected {
                return Err(Error::Conflict);
            }
            Ok(())
        })();
        unsafe {
            libc::unlinkat(self.0.as_raw_fd(), temp.as_ptr(), 0);
        }
        self.0.sync_all().map_err(|_| Error::Invalid)?;
        result
    }

    fn remove_root_plist_exact(&self, name: &str, expected: &[u8]) -> Result<()> {
        let Some(current) = self.read_root_plist(name)? else {
            return Err(Error::Conflict);
        };
        if current.bytes != expected {
            return Err(Error::Conflict);
        }
        let latest = self.read_root_plist(name)?.ok_or(Error::Conflict)?;
        if latest.device != current.device || latest.inode != current.inode {
            return Err(Error::Conflict);
        }
        let encoded = c(OsStr::new(name))?;
        if unsafe { libc::unlinkat(self.0.as_raw_fd(), encoded.as_ptr(), 0) } != 0 {
            return Err(Error::Conflict);
        }
        self.0.sync_all().map_err(|_| Error::Invalid)
    }

    fn publish(&self, name: &str, bytes: &[u8], owner: u32, group: u32, mode: u32) -> Result<()> {
        let temporary = format!(".lomi-service-{}", uuid::Uuid::new_v4());
        let temp = c(OsStr::new(&temporary))?;
        let destination = c(OsStr::new(name))?;
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                temp.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode,
            )
        };
        if fd < 0 {
            return Err(Error::Invalid);
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let result = (|| {
            file.write_all(bytes).map_err(|_| Error::Invalid)?;
            if unsafe { libc::fchown(file.as_raw_fd(), owner, group) } != 0
                || unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0
            {
                return Err(Error::Invalid);
            }
            if owner == 0 && mode == 0o644 {
                let metadata = file.metadata().map_err(|_| Error::Conflict)?;
                if !metadata.is_file()
                    || metadata.uid() != 0
                    || metadata.nlink() != 1
                    || metadata.mode() & 0o7777 != 0o644
                {
                    return Err(Error::Conflict);
                }
                crate::unix::reject_acl_grants(&file).map_err(|_| Error::Conflict)?;
            }
            file.sync_all().map_err(|_| Error::Invalid)?;
            let renamed = unsafe {
                libc::renameatx_np(
                    self.0.as_raw_fd(),
                    temp.as_ptr(),
                    self.0.as_raw_fd(),
                    destination.as_ptr(),
                    libc::RENAME_EXCL,
                )
            };
            if renamed != 0 {
                return Err(Error::Conflict);
            }
            Ok(())
        })();
        unsafe {
            libc::unlinkat(self.0.as_raw_fd(), temp.as_ptr(), 0);
        }
        self.0.sync_all().map_err(|_| Error::Invalid)?;
        result
    }

    fn remove_exact(&self, name: &str, expected: &[u8], owner: u32, mode: u32) -> Result<()> {
        if self.read(name, owner, mode)?.as_deref() != Some(expected) {
            return Err(Error::Conflict);
        }
        let name = c(OsStr::new(name))?;
        if unsafe { libc::unlinkat(self.0.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(Error::Invalid);
        }
        self.0.sync_all().map_err(|_| Error::Invalid)
    }
}

fn access_bits(metadata: &std::fs::Metadata, uid: u32, gid: u32) -> u32 {
    let mode = metadata.mode();
    if metadata.uid() == uid {
        (mode >> 6) & 0o7
    } else if metadata.gid() == gid {
        (mode >> 3) & 0o7
    } else {
        mode & 0o7
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    version: u8,
    profile: String,
    executable: String,
    account: String,
    label: String,
    directory: String,
    mode: String,
}
impl Registration {
    fn validate(&self, profile: &str, account: &Account) -> Result<()> {
        if self.version != 1
            || self.profile != profile
            || self.account != account.name
            || self.label != super::label(profile)
            || self.directory != LAUNCH_DAEMONS
            || self.mode != "boot"
            || !Path::new(&self.executable).is_absolute()
        {
            return Err(Error::Conflict);
        }
        self.plist(account)?;
        Ok(())
    }

    fn plist(&self, account: &Account) -> Result<Vec<u8>> {
        let binary = super::xml(&self.executable)?;
        let profile = super::xml(&self.profile)?;
        let label = super::xml(&self.label)?;
        let user = super::xml(&account.name)?;
        let group = super::xml(&account.group)?;
        Ok(format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{label}</string>
<key>ProgramArguments</key><array><string>{binary}</string><string>--profile-dir</string><string>{profile}</string><string>daemon</string><string>run</string><string>--existing-profile</string></array>
<key>UserName</key><string>{user}</string>
<key>GroupName</key><string>{group}</string>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ExitTimeOut</key><integer>45</integer>
<key>ThrottleInterval</key><integer>2</integer>
<key>Umask</key><integer>63</integer>
<key>StandardOutPath</key><string>/dev/null</string>
<key>StandardErrorPath</key><string>/dev/null</string>
</dict></plist>
"#
        )
        .into_bytes())
    }
}

fn validate_profile(path: &Path, account: &Account) -> Result<PathBuf> {
    let absolute = std::path::absolute(path).map_err(|_| Error::Invalid)?;
    if absolute
        .components()
        .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        || absolute.canonicalize().map_err(|_| Error::Invalid)? != absolute
    {
        return Err(Error::Invalid);
    }
    let profile = Directory::open(
        &absolute,
        account.uid,
        false,
        Some(0o700),
        Some((account.uid, account.gid)),
    )?;
    let metadata = profile.0.metadata().map_err(|_| Error::Invalid)?;
    if metadata.uid() != account.uid || metadata.mode() & 0o777 != 0o700 {
        return Err(Error::Invalid);
    }
    Ok(absolute)
}

fn validate_executable_state(path: &Path, account: &Account, allow_missing: bool) -> Result<bool> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(Error::Invalid);
    }
    let parent_path = path.parent().ok_or(Error::Invalid)?;
    if parent_path.canonicalize().map_err(|_| Error::Invalid)? != parent_path
        || parent_path.join(path.file_name().ok_or(Error::Invalid)?) != path
    {
        return Err(Error::Invalid);
    }
    let parent = Directory::open(
        parent_path,
        0,
        false,
        None,
        Some((account.uid, account.gid)),
    )?;
    let name = path.file_name().ok_or(Error::Invalid)?;
    let encoded = c(name)?;
    let fd = unsafe {
        libc::openat(
            parent.0.as_raw_fd(),
            encoded.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        if allow_missing && io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
            let result = unsafe {
                libc::fstatat(
                    parent.0.as_raw_fd(),
                    encoded.as_ptr(),
                    metadata.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if result != 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                return Ok(false);
            }
        }
        return Err(Error::Invalid);
    }
    let file = unsafe { File::from_raw_fd(fd) };
    crate::unix::reject_acl_grants(&file).map_err(|_| Error::Invalid)?;
    let metadata = file.metadata().map_err(|_| Error::Invalid)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || access_bits(&metadata, account.uid, account.gid) & 0o5 != 0o5
    {
        return Err(Error::Invalid);
    }
    Ok(true)
}

fn validate_executable(path: &Path, account: &Account) -> Result<PathBuf> {
    validate_executable_state(path, account, false)?;
    Ok(path.to_path_buf())
}

enum ProfileLock {
    Missing,
    Busy,
    Acquired(File),
}
fn open_profile_lock(profile: &Directory, account: &Account, create: bool) -> Result<ProfileLock> {
    let name = c(OsStr::new(PROFILE_OWNER_LOCK))?;
    let flags = libc::O_RDWR
        | libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | libc::O_NONBLOCK
        | if create { libc::O_CREAT } else { 0 };
    let fd = unsafe { libc::openat(profile.0.as_raw_fd(), name.as_ptr(), flags, 0o600) };
    if fd < 0 {
        return if io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
            Ok(ProfileLock::Missing)
        } else {
            Err(Error::Conflict)
        };
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let mut metadata = file.metadata().map_err(|_| Error::Invalid)?;
    if create && metadata.uid() == 0 && metadata.nlink() == 1 && metadata.mode() & 0o777 == 0o600 {
        // The profile is owned by the selected account. If root had to create
        // the long-lived host lock, hand its inode to that account before use.
        if unsafe { libc::fchown(file.as_raw_fd(), account.uid, account.gid) } != 0 {
            return Err(Error::Invalid);
        }
        metadata = file.metadata().map_err(|_| Error::Invalid)?;
    }
    if !metadata.is_file()
        || metadata.uid() != account.uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(Error::Conflict);
    }
    crate::unix::reject_acl_grants(&file).map_err(|_| Error::Conflict)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            Ok(ProfileLock::Busy)
        } else {
            Err(Error::Conflict)
        }
    } else {
        Ok(ProfileLock::Acquired(file))
    }
}

fn lock_admin(launch_daemons: &Directory) -> Result<File> {
    let file = launch_daemons
        .regular(ADMIN_LOCK, 0, 0o600, true)?
        .ok_or(Error::Invalid)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(Error::Conflict);
    }
    Ok(file)
}

fn lock_login_adapter(profile: &Directory, account: &Account) -> Result<File> {
    const NAME: &str = "service-macos.lock";
    let name = c(OsStr::new(NAME))?;
    let flags = libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    let mut created = false;
    let mut fd = unsafe {
        libc::openat(
            profile.0.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )
    };
    if fd >= 0 {
        created = true;
    } else if io::Error::last_os_error().kind() == io::ErrorKind::AlreadyExists {
        fd = unsafe { libc::openat(profile.0.as_raw_fd(), name.as_ptr(), flags) };
    }
    if fd < 0 {
        return Err(Error::Conflict);
    }
    let file = unsafe { File::from_raw_fd(fd) };
    if created {
        if unsafe { libc::fchown(file.as_raw_fd(), account.uid, account.gid) } != 0 {
            return Err(Error::Conflict);
        }
    }
    let metadata = file.metadata().map_err(|_| Error::Conflict)?;
    if !metadata.is_file()
        || metadata.uid() != account.uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(Error::Conflict);
    }
    crate::unix::reject_acl_grants(&file).map_err(|_| Error::Conflict)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(Error::Conflict);
    }
    Ok(file)
}

fn login_agents_directory(account: &Account) -> Result<Option<Directory>> {
    fn child(
        parent: &Directory,
        name: &str,
        path: PathBuf,
        account: &Account,
    ) -> Result<Option<Directory>> {
        let name = c(OsStr::new(name))?;
        let fd = unsafe {
            libc::openat(
                parent.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return if io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(Error::Conflict)
            };
        }
        let directory = unsafe { File::from_raw_fd(fd) };
        let metadata = directory.metadata().map_err(|_| Error::Conflict)?;
        if !metadata.is_dir()
            || metadata.uid() != account.uid
            || metadata.mode() & 0o022 != 0
            || path.canonicalize().map_err(|_| Error::Conflict)? != path
        {
            return Err(Error::Conflict);
        }
        crate::unix::reject_acl_grants(&directory).map_err(|_| Error::Conflict)?;
        Ok(Some(Directory(directory, path)))
    }

    let home = Directory::open(
        &account.home,
        account.uid,
        false,
        None,
        Some((account.uid, account.gid)),
    )?;
    let Some(library) = child(&home, "Library", account.home.join("Library"), account)? else {
        return Ok(None);
    };
    child(
        &library,
        "LaunchAgents",
        account.home.join("Library/LaunchAgents"),
        account,
    )
}

fn ensure_login_agents_directory(account: &Account) -> Result<Directory> {
    let path = account.home.join("Library/LaunchAgents");
    match login_agents_directory(account)? {
        Some(directory) => Ok(directory),
        None => {
            let library = Directory::open(
                &account.home.join("Library"),
                account.uid,
                false,
                None,
                Some((account.uid, account.gid)),
            )?;
            let name = c(OsStr::new("LaunchAgents"))?;
            let fd = unsafe {
                libc::openat(
                    library.0.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd >= 0 {
                return Err(Error::Conflict);
            }
            if io::Error::last_os_error().kind() != io::ErrorKind::NotFound
                || unsafe { libc::mkdirat(library.0.as_raw_fd(), name.as_ptr(), 0o700) } != 0
            {
                return Err(Error::Conflict);
            }
            let fd = unsafe {
                libc::openat(
                    library.0.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(Error::Conflict);
            }
            let directory = unsafe { File::from_raw_fd(fd) };
            if unsafe { libc::fchown(directory.as_raw_fd(), account.uid, account.gid) } != 0
                || unsafe { libc::fchmod(directory.as_raw_fd(), 0o755) } != 0
            {
                return Err(Error::Conflict);
            }
            directory.sync_all().map_err(|_| Error::Conflict)?;
            library.0.sync_all().map_err(|_| Error::Conflict)?;
            let metadata = directory.metadata().map_err(|_| Error::Conflict)?;
            if !metadata.is_dir()
                || metadata.uid() != account.uid
                || metadata.mode() & 0o022 != 0
                || path.canonicalize().map_err(|_| Error::Conflict)? != path
            {
                return Err(Error::Conflict);
            }
            crate::unix::reject_acl_grants(&directory).map_err(|_| Error::Conflict)?;
            Ok(Directory(directory, path))
        }
    }
}

fn service_name(reg: &Registration) -> String {
    format!("{}.plist", reg.label)
}
fn target(reg: &Registration) -> String {
    format!("system/{}", reg.label)
}
fn plist_directory() -> Result<Directory> {
    Directory::open(Path::new(LAUNCH_DAEMONS), 0, false, None, None)
}

fn disabled_value(text: &str, label: &str) -> Result<Option<bool>> {
    let text = text.trim();
    if !text.starts_with("disabled services = {") || !text.ends_with('}') {
        return Err(Error::Manager);
    }
    let prefix = format!("\"{label}\" => ");
    let mut found = None;
    for line in text.lines().skip(1) {
        if let Some(value) = line.trim().strip_prefix(&prefix) {
            if found.is_some() {
                return Err(Error::Manager);
            }
            found = Some(match value {
                "enabled" => false,
                "disabled" => true,
                _ => return Err(Error::Manager),
            });
        }
    }
    Ok(found)
}
fn disabled_override(label: &str) -> Result<Option<bool>> {
    disabled_value(
        &super::manager(&["print-disabled", "system"])?.ok_or(Error::Manager)?,
        label,
    )
}

#[derive(Debug, Clone, Copy)]
struct Observation {
    pid: Option<u32>,
    running: bool,
}
fn observation(
    text: &str,
    requested_target: &str,
    path: &str,
    reg: &Registration,
) -> Result<Observation> {
    if text.lines().last() != Some("}")
        || text
            .lines()
            .skip(1)
            .any(|line| !line.is_empty() && !line.starts_with('\t') && line != "}")
    {
        return Err(Error::Conflict);
    }
    let mut lines = text.lines();
    if lines.next() != Some(format!("{requested_target} = {{").as_str()) {
        return Err(Error::Conflict);
    }
    let (mut seen_path, mut seen_program, mut seen_args) = (false, false, false);
    let mut pid = None;
    let mut state = None;
    while let Some(line) = lines.next() {
        if line.starts_with("\t\t") {
            continue;
        }
        if let Some(value) = line.strip_prefix("\tpath = ") {
            if seen_path || value != path {
                return Err(Error::Conflict);
            }
            seen_path = true;
        } else if let Some(value) = line.strip_prefix("\tprogram = ") {
            if seen_program || value != reg.executable {
                return Err(Error::Conflict);
            }
            seen_program = true;
        } else if line == "\targuments = {" {
            if seen_args {
                return Err(Error::Conflict);
            }
            seen_args = true;
            for argument in [
                &reg.executable,
                "--profile-dir",
                &reg.profile,
                "daemon",
                "run",
            ] {
                if lines.next() != Some(format!("\t\t{argument}").as_str()) {
                    return Err(Error::Conflict);
                }
            }
            if lines.next() != Some("\t}") {
                return Err(Error::Conflict);
            }
        } else if let Some(value) = line.strip_prefix("\tpid = ") {
            if pid.is_some() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::Conflict);
            }
            let value = value.parse::<u32>().map_err(|_| Error::Conflict)?;
            if value == 0 || value > i32::MAX as u32 {
                return Err(Error::Conflict);
            }
            pid = Some(value);
        } else if let Some(value) = line.strip_prefix("\tstate = ")
            && (!matches!(
                value,
                "running" | "not running" | "waiting" | "spawn scheduled" | "SIGTERMed"
            ) || state.replace(value).is_some())
        {
            return Err(Error::Conflict);
        }
    }
    if !seen_path || !seen_program || !seen_args || state.is_none() {
        return Err(Error::Conflict);
    }
    let running = state == Some("running");
    if running != pid.is_some() {
        return Err(Error::Conflict);
    }
    Ok(Observation { pid, running })
}

fn observe(reg: &Registration, path: &str) -> Result<Option<Observation>> {
    super::manager(&["print", &target(reg)])?
        .map(|text| observation(&text, &target(reg), path, reg))
        .transpose()
}

fn read_discovery(profile: &Directory, account: &Account) -> Result<LocalDiscovery> {
    let bytes = profile
        .read(DISCOVERY, account.uid, 0o600)?
        .ok_or(Error::NotReady)?;
    let discovery: LocalDiscovery = serde_json::from_slice(&bytes).map_err(|_| Error::NotReady)?;
    if discovery.version.major != LocalIpcVersion::CURRENT.major
        || discovery.build_id.is_empty()
        || discovery.build_id.len() > 128
        || !discovery
            .build_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-+".contains(&b))
    {
        return Err(Error::NotReady);
    }
    Ok(discovery)
}

fn bounded_status(reg: &Registration, account: &Account, expected_pid: u32) -> Result<LocalStatus> {
    crate::process::require_child_ownership().map_err(|_| Error::Manager)?;
    let mut command = Command::new(&reg.executable);
    command
        .arg("--internal-host-status")
        .arg(&reg.profile)
        .arg(expected_pid.to_string())
        .env_clear()
        .env("HOME", &account.home)
        .env("USER", &account.name)
        .env("LOGNAME", &account.name)
        .env("SHELL", "/bin/sh")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let uid = account.uid;
    let gid = account.gid;
    unsafe {
        command.pre_exec(move || {
            // The service probe must carry only the target account's primary
            // group and UID. Clear inherited root supplementary groups before
            // dropping the primary group and UID.
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(gid) != 0
                || libc::setuid(uid) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    bounded_response(&mut command)
}

fn bounded_response(command: &mut Command) -> Result<LocalStatus> {
    let mut child = command.spawn().map_err(|_| Error::Manager)?;
    let mut stdout = child.stdout.take().ok_or(Error::Manager)?;
    let mut stderr = child.stderr.take().ok_or(Error::Manager)?;
    let mut reaped = false;
    let result = (|| {
        for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                return Err(Error::Manager);
            }
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut output = Vec::new();
        let mut errors = Vec::new();
        loop {
            for (reader, bytes) in [
                (&mut stdout as &mut dyn Read, &mut output),
                (&mut stderr as &mut dyn Read, &mut errors),
            ] {
                let mut chunk = [0; 4096];
                match reader.read(&mut chunk) {
                    Ok(count) => bytes.extend_from_slice(&chunk[..count]),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => return Err(Error::Manager),
                }
                if bytes.len() > LIMIT {
                    return Err(Error::Manager);
                }
            }
            if let Some(status) = child.try_wait().map_err(|_| Error::Manager)? {
                reaped = true;
                for (reader, bytes) in [
                    (&mut stdout as &mut dyn Read, &mut output),
                    (&mut stderr as &mut dyn Read, &mut errors),
                ] {
                    let mut chunk = [0; 4096];
                    loop {
                        match reader.read(&mut chunk) {
                            Ok(0) => break,
                            Ok(count) => {
                                bytes.extend_from_slice(&chunk[..count]);
                                if bytes.len() > LIMIT {
                                    return Err(Error::Manager);
                                }
                            }
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                            Err(_) => return Err(Error::Manager),
                        }
                    }
                }
                if !status.success() || !errors.is_empty() {
                    return Err(Error::NotReady);
                }
                let Some(body) = output.strip_suffix(b"\n") else {
                    return Err(Error::NotReady);
                };
                if body.is_empty() || body.contains(&b'\n') || body.contains(&b'\r') {
                    return Err(Error::NotReady);
                }
                let response: lomi_remote_protocol::ipc::LocalResponse =
                    serde_json::from_slice(body).map_err(|_| Error::NotReady)?;
                if serde_json::to_vec(&response).map_err(|_| Error::NotReady)? != body
                    || response.version != LocalIpcVersion::CURRENT
                {
                    return Err(Error::NotReady);
                }
                return match response.result {
                    Ok(LocalResult::Status(status)) => Ok(status),
                    _ => Err(Error::NotReady),
                };
            }
            if Instant::now() >= deadline {
                return Err(Error::Deadline);
            }
            thread::sleep(Duration::from_millis(10));
        }
    })();
    if !reaped {
        if crate::process::require_unreaped_child(&child).is_err() {
            return Err(Error::Deadline);
        }
        if result.is_err() {
            child.kill().map_err(|_| Error::Deadline)?;
        }
        let cleanup_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < cleanup_deadline => {
                    thread::sleep(Duration::from_millis(10))
                }
                _ => return Err(Error::Deadline),
            }
        }
    }
    result
}

fn ready(
    profile: &Directory,
    reg: &Registration,
    path: &str,
    account: &Account,
    expected_pid: u32,
) -> bool {
    let Ok(discovery) = read_discovery(profile, account) else {
        return false;
    };
    let Ok(status) = bounded_status(reg, account, expected_pid) else {
        return false;
    };
    status.host_id == discovery.host_id
        && status.runtime_id == discovery.runtime_id
        && observe(reg, path).is_ok_and(|current| {
            current.is_some_and(|value| value.running && value.pid == Some(expected_pid))
        })
}

fn await_owner_cleanup(profile: &Directory, account: &Account, deadline: Instant) -> Result<File> {
    loop {
        match open_profile_lock(profile, account, false)? {
            ProfileLock::Acquired(owner) => return Ok(owner),
            ProfileLock::Busy => {}
            ProfileLock::Missing => return Err(Error::Conflict),
        }
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn run_as_account(
    profile: &Path,
    executable: &Path,
    account: &Account,
    args: &[&str],
) -> Result<String> {
    crate::process::require_child_ownership().map_err(|_| Error::Manager)?;
    let mut command = Command::new("/usr/bin/sudo");
    command
        .args(["-n", "-H", "-u"])
        .arg(&account.name)
        .arg("--")
        .arg(executable)
        .arg("--profile-dir")
        .arg(profile)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C");
    super::bounded(&mut command, Duration::from_secs(48))?.ok_or(Error::Manager)
}

fn run_profile_initializer_as_account(
    profile: &Path,
    executable: &Path,
    account: &Account,
) -> Result<()> {
    crate::process::require_child_ownership().map_err(|_| Error::Manager)?;
    let mut command = Command::new("/usr/bin/sudo");
    command
        .args(["-n", "-H", "-u"])
        .arg(&account.name)
        .arg("--")
        .arg(executable)
        .arg("--internal-initialize-profile")
        .arg(profile)
        .current_dir("/")
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C");
    let _output = super::bounded(&mut command, Duration::from_secs(48))?.ok_or(Error::Manager)?;
    Ok(())
}

fn confirm_host_ready(profile: &Path, executable: &Path, account: &Account) -> Result<()> {
    let response = run_as_account(
        profile,
        executable,
        account,
        &["maintenance", "prepare", "--json"],
    )?;
    if response.trim().is_empty() {
        return Err(Error::Manager);
    }
    Ok(())
}

fn stop_manual_with_owner_lock(
    profile: &Directory,
    account: &Account,
    executable: &Path,
) -> Result<(bool, File)> {
    let free_owner = open_profile_lock(profile, account, true)?;
    match free_owner {
        ProfileLock::Acquired(owner) => Ok((false, owner)),
        ProfileLock::Missing => Err(Error::Conflict),
        ProfileLock::Busy => {
            // The command is launched as the selected account through the
            // installed protected CLI; no remembered PID is signalled.
            run_as_account(
                &profile.1,
                executable,
                account,
                &["daemon", "stop", "--confirm"],
            )?;
            let deadline = Instant::now() + Duration::from_secs(48);
            await_owner_cleanup(profile, account, deadline).map(|owner| (true, owner))
        }
    }
}

fn stop_login_with_owner_lock(
    profile: &Directory,
    account: &Account,
    executable: &Path,
    plist_path: &Path,
    registration: &super::Registration,
) -> Result<(bool, File)> {
    let deadline = Instant::now() + Duration::from_secs(48);
    let free_owner = open_profile_lock(profile, account, true)?;
    let target = format!("gui/{}/{}", account.uid, registration.label);
    let path = plist_path.to_str().ok_or(Error::Invalid)?;
    let before = super::observe(&target, path, registration)?;
    let was_running = before.is_some_and(|pid| pid.is_some());
    if before.is_some() {
        super::required(&["bootout", &target])?;
    }
    while super::observe(&target, path, registration)?.is_some() {
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        thread::sleep(Duration::from_millis(25));
    }
    match free_owner {
        ProfileLock::Acquired(owner) => return Ok((was_running, owner)),
        ProfileLock::Missing => return Err(Error::Conflict),
        ProfileLock::Busy => {}
    }
    if !was_running {
        // The loaded GUI job may have been an inactive registration while a
        // manually-started Host owns the same selected profile. Stop only via
        // its authenticated local IPC using the protected CLI as that account.
        run_as_account(
            &profile.1,
            executable,
            account,
            &["daemon", "stop", "--confirm"],
        )?;
    }
    await_owner_cleanup(profile, account, deadline)
        .map(|owner| (was_running || before.is_some(), owner))
}

fn stop_with_owner_lock(
    profile: &Directory,
    reg: &Registration,
    path: &str,
    account: &Account,
) -> Result<(bool, File)> {
    let deadline = Instant::now() + Duration::from_secs(48);
    // Create and retain the existing host lifetime lock before inspecting the
    // manager, closing the no-PID gap in which a foreground host could start.
    let free_owner = open_profile_lock(profile, account, true)?;
    let before = observe(reg, path)?;
    let was_running = before.is_some_and(|value| value.running);
    if before.is_some() {
        // bootout is addressed only to the exact manager registration already
        // verified by path, program, and argv. Never signal its reported PID.
        super::required(&["bootout", &target(reg)])?;
    }
    while observe(reg, path)?.is_some() {
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        thread::sleep(Duration::from_millis(25));
    }
    match free_owner {
        ProfileLock::Acquired(owner) => return Ok((was_running, owner)),
        ProfileLock::Missing => return Err(Error::Conflict),
        ProfileLock::Busy => {}
    }
    let (manual_was_running, owner) =
        stop_manual_with_owner_lock(profile, account, Path::new(&reg.executable))?;
    Ok((was_running || manual_was_running, owner))
}

/// A root-held barrier for an explicitly selected account's Host mode.
/// The account-owned profile and `owner.lock` are validated without changing
/// their ownership or permissions. The system and login adapter locks and
/// profile owner lock stay held until this value is dropped.
pub struct BootMaintenanceGuard {
    profile: Directory,
    _owner_lock: Option<File>,
    _admin_lock: File,
    _login_adapter_lock: File,
    uid: u32,
    account: Account,
    executable_path: PathBuf,
    registration: Option<Registration>,
    registration_bytes: Option<Vec<u8>>,
    expected_plist: Option<Vec<u8>>,
    plist_exists: bool,
    host_mode: super::AdminHostMode,
    login_registration: Option<super::Registration>,
    login_registration_bytes: Option<Vec<u8>>,
    login_expected_plist: Option<Vec<u8>>,
    login_plist_exists: bool,
    login_agents: Option<Directory>,
    service_was_running: bool,
    allow_missing_executable: bool,
    initial_install: bool,
}

impl BootMaintenanceGuard {
    pub fn profile_path(&self) -> &Path {
        &self.profile.1
    }

    pub fn owner_uid(&self) -> u32 {
        self.uid
    }

    pub fn host_mode(&self) -> super::AdminHostMode {
        self.host_mode
    }

    pub(super) fn service_was_running(&self) -> bool {
        self.service_was_running
    }

    pub(super) fn has_service_registration(&self) -> bool {
        self.registration.is_some() || self.login_registration_bytes.is_some()
    }

    pub(super) fn profile_owner_lock_held(&self) -> bool {
        self._owner_lock.is_some()
    }

    /// Publish the root-owned, account-readable identity projection only while
    /// the selected profile owner lock and the service-adapter lock are held.
    /// A prior projection is immutable: an exact retry is idempotent, while a
    /// changed identity or binding is a conflict.
    pub(super) fn publish_admin_host_identity_binding(
        &self,
        host_id: &str,
        profile_id: &str,
    ) -> Result<()> {
        if !root() || self._owner_lock.is_none() {
            return Err(Error::Conflict);
        }
        let host_id = lomi_remote_protocol::HostId::try_from(host_id.to_owned())
            .map_err(|_| Error::Conflict)?;
        let profile_id = lomi_remote_protocol::ipc::IpcProfileId::try_from(profile_id.to_owned())
            .map_err(|_| Error::Conflict)?;
        let account = account(&self.account.name)?;
        if account.uid != self.uid
            || account.gid != self.account.gid
            || account.home != self.account.home
            || self.profile_path() != validate_profile(self.profile_path(), &account)?
            || self.executable_path != install_path_for_account(&account.name)?.join("lomiremote")
        {
            return Err(Error::Conflict);
        }
        validate_admin_owner_binding(
            &install_path_for_account(&account.name)?,
            self.profile_path(),
            &account,
            self.host_mode,
        )?;
        let install_dir = Directory::open(
            &install_path_for_account(&account.name)?,
            0,
            false,
            Some(0o755),
            Some((account.uid, account.gid)),
        )?;
        let expected = admin_host_identity_binding_bytes(
            &account,
            self.profile_path(),
            self.host_mode,
            host_id,
            profile_id,
        )?;
        match install_dir.read(ADMIN_HOST_IDENTITY_BINDING, 0, 0o644)? {
            Some(current) if current == expected => Ok(()),
            Some(_) => Err(Error::Conflict),
            None => {
                install_dir.publish(ADMIN_HOST_IDENTITY_BINDING, &expected, 0, 0, 0o644)?;
                if install_dir
                    .read(ADMIN_HOST_IDENTITY_BINDING, 0, 0o644)?
                    .as_deref()
                    != Some(expected.as_slice())
                {
                    return Err(Error::Conflict);
                }
                install_dir.0.sync_all().map_err(|_| Error::Invalid)
            }
        }
    }

    pub(super) fn verify_admin_host_identity_binding(
        &self,
        host_id: &str,
        profile_id: &str,
    ) -> Result<()> {
        if !root() || self._owner_lock.is_none() {
            return Err(Error::Conflict);
        }
        let account = account(&self.account.name)?;
        let host_id = lomi_remote_protocol::HostId::try_from(host_id.to_owned())
            .map_err(|_| Error::Conflict)?;
        let profile_id = lomi_remote_protocol::ipc::IpcProfileId::try_from(profile_id.to_owned())
            .map_err(|_| Error::Conflict)?;
        let install_dir = install_path_for_account(&account.name)?;
        if account.uid != self.uid
            || account.gid != self.account.gid
            || account.home != self.account.home
            || self.profile_path() != validate_profile(self.profile_path(), &account)?
            || self.executable_path != install_dir.join("lomiremote")
        {
            return Err(Error::Conflict);
        }
        validate_admin_owner_binding(&install_dir, self.profile_path(), &account, self.host_mode)?;
        let directory = Directory::open(
            &install_dir,
            0,
            false,
            Some(0o755),
            Some((account.uid, account.gid)),
        )?;
        let expected = admin_host_identity_binding_bytes(
            &account,
            self.profile_path(),
            self.host_mode,
            host_id,
            profile_id,
        )?;
        match directory.read(ADMIN_HOST_IDENTITY_BINDING, 0, 0o644)? {
            None => Ok(()),
            Some(current) if current == expected => Ok(()),
            Some(_) => Err(Error::Conflict),
        }
    }

    /// Release the profile owner lock only after the root custodian is ready
    /// and immediately before launchd starts the account Host.
    pub(super) fn release_profile_owner_lock(&mut self) {
        self._owner_lock.take();
    }

    /// Initialize or validate the selected account's Host database through
    /// the newly installed, root-protected CLI. The caller must invoke this
    /// only after its verified initial release activation is durable.
    pub(super) fn initialize_profile_after_activation(&mut self) -> Result<()> {
        if !self.initial_install {
            return Err(Error::Conflict);
        }
        self.initialize_profile_after_verified_activation()
    }

    /// Resume an initialization whose exact root-private Pending receipt and
    /// active signed image were verified by the updater. The ordinary
    /// maintenance guard still requires no service, Host, or custodian.
    pub(super) fn initialize_profile_after_pending_activation(&mut self) -> Result<()> {
        if self.initial_install {
            return Err(Error::Conflict);
        }
        self.initialize_profile_after_verified_activation()
    }

    fn initialize_profile_after_verified_activation(&mut self) -> Result<()> {
        if self._owner_lock.is_none()
            || self.service_was_running
            || self.has_service_registration()
            || self.profile.read(RECORD, self.uid, 0o600)?.is_some()
            || super::custody::read_optional_privileged_custodian(self)?.is_some()
        {
            return Err(Error::Conflict);
        }
        let install_dir = install_path_for_account(&self.account.name)?;
        if self.executable_path != install_dir.join("lomiremote") {
            return Err(Error::Conflict);
        }
        validate_admin_owner_binding(&install_dir, &self.profile.1, &self.account, self.host_mode)?;
        validate_executable_state(&self.executable_path, &self.account, false)?;

        let before = self.profile.0.metadata().map_err(|_| Error::Conflict)?;
        let current_profile = validate_profile(&self.profile.1, &self.account)?;
        let current = Directory::open(
            &current_profile,
            self.uid,
            false,
            Some(0o700),
            Some((self.uid, self.account.gid)),
        )?;
        let after = current.0.metadata().map_err(|_| Error::Conflict)?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(Error::Conflict);
        }

        // The updater's completed activation is the durable intent that
        // permits this one selected-account initializer to acquire OwnerLock.
        self.release_profile_owner_lock();
        let initialization = run_profile_initializer_as_account(
            &self.profile.1,
            &self.executable_path,
            &self.account,
        );
        let owner_lock = await_owner_cleanup(
            &self.profile,
            &self.account,
            Instant::now() + Duration::from_secs(48),
        )?;
        self._owner_lock = Some(owner_lock);
        initialization?;

        validate_executable_state(&self.executable_path, &self.account, false)?;
        drop(
            self.open_database_component("host.sqlite3")?
                .ok_or(Error::Conflict)?,
        );
        for name in [
            "host.sqlite3-wal",
            "host.sqlite3-shm",
            "host.sqlite3-journal",
        ] {
            drop(self.open_database_component(name)?);
        }
        self.initial_install = false;
        Ok(())
    }

    fn install_login_service_registration(&mut self) -> Result<()> {
        if self.host_mode != super::AdminHostMode::Login {
            return Err(Error::Conflict);
        }
        let registration = self.login_registration.clone().ok_or(Error::Conflict)?;
        let expected_plist = self
            .login_expected_plist
            .as_deref()
            .ok_or(Error::Conflict)?
            .to_vec();
        let registration_bytes = serde_json::to_vec(&registration).map_err(|_| Error::Invalid)?;
        let current_record = self.profile.read(RECORD, self.uid, 0o600)?;
        match self.login_registration_bytes.as_deref() {
            Some(expected) if current_record.as_deref() == Some(expected) => {}
            None if current_record.is_none() => {}
            _ => return Err(Error::Conflict),
        }
        if let Some(current) = self.login_registration_bytes.as_deref()
            && current != registration_bytes
        {
            return Err(Error::Conflict);
        }

        let agents = match self.login_agents.take() {
            Some(directory) => directory,
            None => ensure_login_agents_directory(&self.account)?,
        };
        let name = format!("{}.plist", registration.label);
        let path = registration.directory.clone() + "/" + &name;
        let current_plist = agents.read(&name, self.uid, 0o600)?;
        if if self.login_plist_exists {
            current_plist.as_deref() != Some(expected_plist.as_slice())
        } else {
            current_plist.is_some()
        } || super::observe(
            &format!("gui/{}/{}", self.uid, registration.label),
            &path,
            &registration,
        )?
        .is_some()
        {
            return Err(Error::Conflict);
        }

        if self.login_registration_bytes.is_none() {
            self.profile.publish(
                RECORD,
                &registration_bytes,
                self.uid,
                self.account.gid,
                0o600,
            )?;
            self.profile.0.sync_all().map_err(|_| Error::Invalid)?;
        }
        if current_plist.is_none() {
            agents.publish(&name, &expected_plist, self.uid, self.account.gid, 0o600)?;
            agents.0.sync_all().map_err(|_| Error::Invalid)?;
        }
        self.login_agents = Some(agents);
        self.login_registration_bytes = Some(registration_bytes);
        self.login_plist_exists = true;
        Ok(())
    }

    fn start_login_service(&mut self) -> Result<()> {
        if self.host_mode != super::AdminHostMode::Login {
            return Err(Error::Conflict);
        }
        if self.login_registration_bytes.is_none() {
            return Err(Error::Conflict);
        }
        let registration = self.login_registration.clone().ok_or(Error::Conflict)?;
        let expected_plist = self
            .login_expected_plist
            .as_deref()
            .ok_or(Error::Conflict)?
            .to_vec();
        let name = format!("{}.plist", registration.label);
        let path = registration.directory.clone() + "/" + &name;
        let target = format!("gui/{}/{}", self.uid, registration.label);
        let agents = self.login_agents.as_ref().ok_or(Error::Conflict)?;
        if self.profile.read(RECORD, self.uid, 0o600)?.as_deref()
            != self.login_registration_bytes.as_deref()
            || agents.read(&name, self.uid, 0o600)?.as_deref() != Some(expected_plist.as_slice())
        {
            return Err(Error::Conflict);
        }
        if super::disabled_override(
            &target.split('/').take(2).collect::<Vec<_>>().join("/"),
            &registration.label,
        )? == Some(true)
        {
            return Err(Error::Disabled);
        }
        let now = super::observe(&target, &path, &registration)?;
        if now
            .flatten()
            .is_some_and(|pid| super::ready(&self.profile.1, pid))
        {
            return Ok(());
        }
        self.release_profile_owner_lock();
        if now.is_none() {
            super::required(&[
                "bootstrap",
                &target[..target.rfind('/').ok_or(Error::Invalid)?],
                &path,
            ])?;
        } else if now.flatten().is_none() {
            super::required(&["kickstart", &target])?;
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if super::observe(&target, &path, &registration)?
                .flatten()
                .is_some_and(|pid| super::ready(&self.profile.1, pid))
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Error::NotReady);
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    /// Resolve the selected account, profile inode, and root-installed
    /// executable for the separate root custody service. This is available
    /// only while this guard retains both the profile owner lock and the
    /// LaunchDaemon administration lock.
    pub(super) fn custody_binding(&self) -> Result<CustodyBinding> {
        let account = account(&self.account.name)?;
        if account.uid != self.account.uid
            || account.gid != self.account.gid
            || account.home != self.account.home
        {
            return Err(Error::Conflict);
        }
        let profile_path = validate_profile(&self.profile.1, &account)?;
        let current_profile = Directory::open(
            &profile_path,
            account.uid,
            false,
            Some(0o700),
            Some((account.uid, account.gid)),
        )?;
        let pinned_metadata = self.profile.0.metadata().map_err(|_| Error::Conflict)?;
        let current_metadata = current_profile.0.metadata().map_err(|_| Error::Conflict)?;
        if pinned_metadata.dev() != current_metadata.dev()
            || pinned_metadata.ino() != current_metadata.ino()
            || pinned_metadata.uid() != current_metadata.uid()
            || pinned_metadata.gid() != current_metadata.gid()
            || pinned_metadata.mode() & 0o777 != current_metadata.mode() & 0o777
        {
            return Err(Error::Conflict);
        }
        if let Some(registration) = self.registration.as_ref()
            && (registration.profile != profile_path.to_str().ok_or(Error::Invalid)?
                || registration.account != account.name
                || registration.executable
                    != self.executable_path.to_str().ok_or(Error::Invalid)?)
        {
            return Err(Error::Conflict);
        }
        if let Some(registration) = self.login_registration.as_ref()
            && (registration.profile != profile_path.to_str().ok_or(Error::Invalid)?
                || registration.account != account.name
                || registration.executable
                    != self.executable_path.to_str().ok_or(Error::Invalid)?)
        {
            return Err(Error::Conflict);
        }
        let executable_path = self.executable_path.clone();
        let expected_executable = install_path_for_account(&account.name)?.join("lomiremote");
        if executable_path != expected_executable {
            return Err(Error::Conflict);
        }
        validate_executable_state(&executable_path, &account, self.allow_missing_executable)?;
        let metadata = current_metadata;
        Ok(CustodyBinding {
            account_name: account.name,
            account_home: account.home,
            owner_uid: account.uid,
            owner_gid: account.gid,
            profile_path,
            profile_device: metadata.dev(),
            profile_inode: metadata.ino(),
            profile_uid: metadata.uid(),
            profile_gid: metadata.gid(),
            profile_mode: metadata.mode() & 0o777,
            executable_path,
        })
    }

    /// Open only a database or SQLite sidecar relative to the retained profile
    /// directory descriptor. Symlinks, aliases and non-private files fail.
    pub fn open_database_component(&self, name: &str) -> Result<Option<File>> {
        if !matches!(
            name,
            "host.sqlite3" | "host.sqlite3-wal" | "host.sqlite3-shm" | "host.sqlite3-journal"
        ) {
            return Err(Error::Invalid);
        }
        let name = c(OsStr::new(name))?;
        let fd = unsafe {
            libc::openat(
                self.profile.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return if io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(Error::Conflict)
            };
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(|_| Error::Conflict)?;
        if !metadata.is_file()
            || metadata.uid() != self.uid
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(Error::Conflict);
        }
        crate::unix::reject_acl_grants(&file).map_err(|_| Error::Conflict)?;
        Ok(Some(file))
    }

    /// Remove only the exact authenticated boot registration after this guard
    /// has stopped its job and retained the account owner and adapter locks.
    pub fn uninstall_service_registration(&mut self) -> Result<()> {
        if self.host_mode == super::AdminHostMode::Login {
            return self.uninstall_login_service_registration();
        }
        let Some(registration) = self.registration.as_ref() else {
            return Ok(());
        };
        let record = self.registration_bytes.as_deref().ok_or(Error::Conflict)?;
        let expected_plist = self.expected_plist.as_deref().ok_or(Error::Conflict)?;
        let daemons = plist_directory()?;
        let name = service_name(registration);
        let path = format!("{LAUNCH_DAEMONS}/{name}");
        let current_plist = daemons.read_root_plist_bytes(&name)?;
        if self.profile.read(RECORD, self.uid, 0o600)?.as_deref() != Some(record)
            || if self.plist_exists {
                current_plist.as_deref() != Some(expected_plist)
            } else {
                current_plist.is_some()
            }
            || observe(registration, &path)?.is_some()
        {
            return Err(Error::Conflict);
        }
        uninstall_files(
            &self.profile,
            &daemons,
            registration,
            record,
            expected_plist,
            &self.account,
            self.plist_exists,
        )?;
        self.registration = None;
        self.registration_bytes = None;
        self.expected_plist = None;
        Ok(())
    }

    fn uninstall_login_service_registration(&mut self) -> Result<()> {
        if self.login_registration_bytes.is_none() {
            if self.login_plist_exists {
                return Err(Error::Conflict);
            }
            return Ok(());
        }
        let Some(registration) = self.login_registration.as_ref() else {
            return Ok(());
        };
        let record = self
            .login_registration_bytes
            .as_deref()
            .ok_or(Error::Conflict)?;
        let expected_plist = self
            .login_expected_plist
            .as_deref()
            .ok_or(Error::Conflict)?;
        let agents = self.login_agents.as_ref();
        let name = format!("{}.plist", registration.label);
        let path = registration.directory.clone() + "/" + &name;
        let current_plist = match agents {
            Some(agents) => agents.read(&name, self.uid, 0o600)?,
            None => None,
        };
        if self.profile.read(RECORD, self.uid, 0o600)?.as_deref() != Some(record)
            || if self.login_plist_exists {
                current_plist.as_deref() != Some(expected_plist)
            } else {
                current_plist.is_some()
            }
            || super::observe(
                &format!("gui/{}/{}", self.uid, registration.label),
                &path,
                registration,
            )?
            .is_some()
        {
            return Err(Error::Conflict);
        }
        if self.login_plist_exists {
            let agents = agents.ok_or(Error::Conflict)?;
            agents.remove_exact(&name, expected_plist, self.uid, 0o600)?;
            agents.0.sync_all().map_err(|_| Error::Invalid)?;
        }
        self.profile.remove_exact(RECORD, record, self.uid, 0o600)?;
        self.login_registration = None;
        self.login_registration_bytes = None;
        self.login_expected_plist = None;
        self.login_plist_exists = false;
        Ok(())
    }
}

fn admin_host_identity_binding_bytes(
    account: &Account,
    profile: &Path,
    mode: super::AdminHostMode,
    host_id: lomi_remote_protocol::HostId,
    profile_id: lomi_remote_protocol::ipc::IpcProfileId,
) -> Result<Vec<u8>> {
    let profile = profile.to_str().ok_or(Error::Invalid)?;
    Ok(serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "accountUid": account.uid,
        "account": account.name,
        "profilePath": profile,
        "hostMode": mode.as_str(),
        "hostId": String::from(host_id),
        "profileId": String::from(profile_id),
    }))
    .map_err(|_| Error::Invalid)?)
}

fn parse_admin_host_identity_binding(
    bytes: &[u8],
    account: &Account,
    profile: &Path,
    expected_mode: Option<super::AdminHostMode>,
) -> Result<super::AdminHostIdentityBinding> {
    if bytes.is_empty() || bytes.len() > 16 * 1024 {
        return Err(Error::Conflict);
    }
    let wire: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| Error::Conflict)?;
    if serde_json::to_vec(&wire).map_err(|_| Error::Conflict)? != bytes {
        return Err(Error::Conflict);
    }
    let object = wire.as_object().ok_or(Error::Conflict)?;
    if object.len() != 7 || object.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(Error::Conflict);
    }
    let string = |name: &str| {
        object
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::Conflict)
    };
    let account_uid = object
        .get("accountUid")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(Error::Conflict)?;
    let profile_text = profile.to_str().ok_or(Error::Conflict)?;
    let account_name = string("account")?;
    let profile_path = string("profilePath")?;
    let mode = string("hostMode")?
        .parse::<super::AdminHostMode>()
        .map_err(|_| Error::Conflict)?;
    let host_id = lomi_remote_protocol::HostId::try_from(string("hostId")?.to_owned())
        .map_err(|_| Error::Conflict)?;
    let profile_id =
        lomi_remote_protocol::ipc::IpcProfileId::try_from(string("profileId")?.to_owned())
            .map_err(|_| Error::Conflict)?;
    if account_uid != account.uid
        || account_name != account.name
        || profile_path != profile_text
        || expected_mode.is_some_and(|expected| expected != mode)
    {
        return Err(Error::Conflict);
    }
    Ok(super::AdminHostIdentityBinding {
        account_uid,
        account: account.name.clone(),
        profile: profile.to_path_buf(),
        mode,
        host_id,
        profile_id,
    })
}

fn read_admin_host_identity_binding_for(
    profile: &Path,
    account: &Account,
    mode: Option<super::AdminHostMode>,
) -> Result<Option<super::AdminHostIdentityBinding>> {
    let profile = validate_profile(profile, account)?;
    let install_dir = install_path_for_account(&account.name)?;
    let directory = Directory::open(
        &install_dir,
        0,
        false,
        Some(0o755),
        Some((account.uid, account.gid)),
    )?;
    directory
        .read(ADMIN_HOST_IDENTITY_BINDING, 0, 0o644)?
        .map(|bytes| parse_admin_host_identity_binding(&bytes, account, &profile, mode))
        .transpose()
}

pub(super) fn read_admin_host_identity_binding(
    profile: &Path,
    executable: &Path,
    selected_account: &str,
    mode: super::AdminHostMode,
) -> Result<super::AdminHostIdentityBinding> {
    let account = account(selected_account)?;
    let profile = validate_profile(profile, &account)?;
    let install_dir = install_path_for_account(&account.name)?;
    if executable != install_dir.join("lomiremote") {
        return Err(Error::Conflict);
    }
    validate_admin_owner_binding(&install_dir, &profile, &account, mode)?;
    read_admin_host_identity_binding_for(&profile, &account, Some(mode))?.ok_or(Error::Conflict)
}

pub(super) fn lookup_admin_host_identity_binding(
    profile: &Path,
    executable: &Path,
) -> Result<super::AdminHostIdentityLookup> {
    if super::uid() == 0 {
        return Err(Error::Conflict);
    }
    let (name, gid, _) = super::unix_identity(super::uid())?;
    if gid != unsafe { libc::getegid() } {
        return Err(Error::Conflict);
    }
    let account = account(&name)?;
    let profile = validate_profile(profile, &account)?;
    let expected_executable = install_path_for_account(&account.name)?.join("lomiremote");
    if !executable.is_absolute() {
        return Err(Error::Invalid);
    }
    let actual_executable = executable.canonicalize().map_err(|_| Error::Conflict)?;
    if actual_executable != expected_executable {
        return Ok(super::AdminHostIdentityLookup::NotManaged);
    }
    match read_admin_host_identity_binding_for(&profile, &account, None)? {
        Some(binding) => Ok(super::AdminHostIdentityLookup::Present(binding)),
        None => Ok(super::AdminHostIdentityLookup::Missing),
    }
}

/// Narrow immutable identity copied from a live boot maintenance barrier.
/// Fields are visible only to the macOS service adapter and its children.
pub(super) struct CustodyBinding {
    pub(super) account_name: String,
    pub(super) account_home: PathBuf,
    pub(super) owner_uid: u32,
    pub(super) owner_gid: u32,
    pub(super) profile_path: PathBuf,
    pub(super) profile_device: u64,
    pub(super) profile_inode: u64,
    pub(super) profile_uid: u32,
    pub(super) profile_gid: u32,
    pub(super) profile_mode: u32,
    pub(super) executable_path: PathBuf,
}

pub(super) fn custody_binding_for_identity(
    profile_path: &Path,
    executable: &Path,
    selected_name: &str,
) -> Result<CustodyBinding> {
    if !root() || !executable.is_absolute() {
        return Err(Error::Unimplemented);
    }
    let account = account(selected_name)?;
    let profile_path = validate_profile(profile_path, &account)?;
    let expected_executable = install_path_for_account(&account.name)?.join("lomiremote");
    if executable != expected_executable {
        return Err(Error::Conflict);
    }
    validate_executable_state(executable, &account, false)?;
    let profile = Directory::open(
        &profile_path,
        account.uid,
        false,
        Some(0o700),
        Some((account.uid, account.gid)),
    )?;
    let metadata = profile.0.metadata().map_err(|_| Error::Conflict)?;
    Ok(CustodyBinding {
        account_name: account.name,
        account_home: account.home,
        owner_uid: account.uid,
        owner_gid: account.gid,
        profile_path,
        profile_device: metadata.dev(),
        profile_inode: metadata.ino(),
        profile_uid: metadata.uid(),
        profile_gid: metadata.gid(),
        profile_mode: metadata.mode() & 0o777,
        executable_path: executable.to_path_buf(),
    })
}

/// Re-resolve a persisted account identity before a root custody service uses
/// registration data that was loaded from disk without a maintenance guard.
pub(super) fn validate_custody_account(
    name: &str,
    expected_uid: u32,
    expected_gid: u32,
    expected_home: &Path,
) -> Result<()> {
    let account = account(name)?;
    if account.uid != expected_uid || account.gid != expected_gid || account.home != expected_home {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Resolve only the supplied account name. This intentionally has no HOME or
/// current-user fallback, so admin installers cannot select an account by
/// inheriting an environment value.
pub(super) fn profile_path_for_account(name: &str) -> Result<PathBuf> {
    let selected = account(name)?;
    Ok(selected
        .home
        .join("Library")
        .join("Application Support")
        .join("LomiRemote"))
}

pub(super) fn install_path_for_account(name: &str) -> Result<PathBuf> {
    let selected = account(name)?;
    Ok(Path::new("/Library/Application Support/LomiRemote/Install").join(selected.uid.to_string()))
}

pub(super) fn validate_selected_profile(
    profile_path: &Path,
    selected_name: &str,
) -> Result<(PathBuf, u32)> {
    let account = account(selected_name)?;
    let profile_path = validate_profile(profile_path, &account)?;
    Ok((profile_path, account.uid))
}

fn validate_admin_owner_binding(
    install_dir: &Path,
    profile_path: &Path,
    account: &Account,
    mode: super::AdminHostMode,
) -> Result<()> {
    if !root()
        || install_dir != install_path_for_account(&account.name)?
        || !profile_path.is_absolute()
        || profile_path.canonicalize().map_err(|_| Error::Conflict)? != profile_path
    {
        return Err(Error::Conflict);
    }
    let directory = Directory::open(
        install_dir,
        0,
        false,
        Some(0o755),
        Some((account.uid, account.gid)),
    )?;
    let stored = directory
        .read(ADMIN_OWNER_BINDING, 0, 0o600)?
        .ok_or(Error::Conflict)?;
    let profile = profile_path.to_str().ok_or(Error::Conflict)?;
    let expected = serde_json::to_vec(&serde_json::json!({
        "format": 2,
        "accountUid": account.uid,
        "hostMode": mode.as_str(),
        "profilePath": profile,
    }))
    .map_err(|_| Error::Conflict)?;
    if stored == expected {
        return Ok(());
    }
    if mode == super::AdminHostMode::Boot {
        let legacy = serde_json::to_vec(&serde_json::json!({
            "format": 1,
            "accountUid": account.uid,
            "profilePath": profile,
        }))
        .map_err(|_| Error::Conflict)?;
        if stored == legacy {
            return Ok(());
        }
    }
    Err(Error::Conflict)
}

/// Stop the exact selected-account LaunchDaemon, then retain both the system
/// service-adapter lock and that user's existing profile OwnerLock. A missing
/// profile owner lock is created using the existing boot-adapter ownership
/// rule; an existing profile directory is never chmodded or chowned.
pub(super) fn acquire_maintenance_guard(
    profile_path: &Path,
    executable: &Path,
    selected_name: &str,
    allow_missing_executable: bool,
    allow_missing_plist: bool,
) -> Result<BootMaintenanceGuard> {
    crate::process::require_child_ownership().map_err(|_| Error::Manager)?;
    if !root() || !executable.is_absolute() {
        return Err(Error::Unimplemented);
    }
    let account = account(selected_name)?;
    if executable != install_path_for_account(&account.name)?.join("lomiremote") {
        return Err(Error::Conflict);
    }
    validate_executable_state(executable, &account, allow_missing_executable)?;
    let profile_path = validate_profile(profile_path, &account)?;
    validate_admin_owner_binding(
        &install_path_for_account(&account.name)?,
        &profile_path,
        &account,
        super::AdminHostMode::Boot,
    )?;
    let profile = Directory::open(
        &profile_path,
        account.uid,
        false,
        Some(0o700),
        Some((account.uid, account.gid)),
    )?;
    let launch_daemons = plist_directory()?;
    let admin_lock = lock_admin(&launch_daemons)?;
    let login_adapter_lock = lock_login_adapter(&profile, &account)?;
    let profile_text = profile_path.to_str().ok_or(Error::Invalid)?;
    let executable_text = executable.to_str().ok_or(Error::Invalid)?;
    let registration_bytes = profile.read(RECORD, account.uid, 0o600)?;
    let record_exists = registration_bytes.is_some();
    let registration = if let Some(bytes) = &registration_bytes {
        let registration =
            serde_json::from_slice::<Registration>(bytes).map_err(|_| Error::Conflict)?;
        registration.validate(profile_text, &account)?;
        if registration.executable != executable_text {
            return Err(Error::Conflict);
        }
        validate_executable_state(
            Path::new(&registration.executable),
            &account,
            allow_missing_executable,
        )?;
        Some(registration)
    } else {
        // Before the first LaunchDaemon record exists, the caller must still
        // provide the selected account explicitly. Validate its chosen system
        // install directory and reject any orphaned manager registration.
        if executable
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
            || executable.parent().is_none()
        {
            return Err(Error::Invalid);
        }
        Directory::open(
            executable.parent().ok_or(Error::Invalid)?,
            0,
            false,
            None,
            Some((account.uid, account.gid)),
        )?;
        None
    };
    let reg = registration.clone().unwrap_or_else(|| Registration {
        version: 1,
        profile: profile_text.to_owned(),
        executable: executable_text.to_owned(),
        account: account.name.clone(),
        label: super::label(profile_text),
        directory: LAUNCH_DAEMONS.to_owned(),
        mode: "boot".to_owned(),
    });
    let expected_plist = reg.plist(&account)?;
    let plist_name = service_name(&reg);
    let plist_path = format!("{LAUNCH_DAEMONS}/{plist_name}");
    let current_plist = launch_daemons.read_root_plist_bytes(&plist_name)?;
    let observed = observe(&reg, &plist_path)?;
    let login_agents = login_agents_directory(&account)?;
    let login_directory_path = account.home.join("Library/LaunchAgents");
    let login_registration = super::Registration {
        version: 1,
        profile: profile_text.to_owned(),
        executable: executable_text.to_owned(),
        account: account.name.clone(),
        label: super::label(profile_text),
        directory: login_directory_path
            .to_str()
            .ok_or(Error::Invalid)?
            .to_owned(),
        mode: "login".to_owned(),
    };
    let login_name = format!("{}.plist", login_registration.label);
    let login_path = login_directory_path.join(&login_name);
    let login_current_plist = match login_agents.as_ref() {
        Some(agents) => agents.read(&login_name, account.uid, 0o600)?,
        None => None,
    };
    let login_observed = super::observe(
        &format!("gui/{}/{}", account.uid, login_registration.label),
        login_path.to_str().ok_or(Error::Invalid)?,
        &login_registration,
    )?;
    if login_current_plist.is_some() || login_observed.is_some() {
        return Err(Error::Conflict);
    }
    let (service_was_running, owner_lock) = if record_exists {
        let exact_plist = current_plist.as_deref() == Some(expected_plist.as_slice());
        let allowed_partial_uninstall =
            allow_missing_plist && current_plist.is_none() && observed.is_none();
        if !exact_plist && !allowed_partial_uninstall {
            return Err(Error::Conflict);
        }
        let (was_running, owner) = stop_with_owner_lock(&profile, &reg, &plist_path, &account)?;
        (was_running, Some(owner))
    } else if current_plist.is_some() || observed.is_some() {
        return Err(Error::Conflict);
    } else {
        let owner = match open_profile_lock(&profile, &account, false)? {
            ProfileLock::Acquired(lock) => lock,
            ProfileLock::Missing | ProfileLock::Busy => return Err(Error::Conflict),
        };
        (false, Some(owner))
    };
    Ok(BootMaintenanceGuard {
        profile,
        _owner_lock: owner_lock,
        _admin_lock: admin_lock,
        _login_adapter_lock: login_adapter_lock,
        uid: account.uid,
        account,
        executable_path: executable.to_path_buf(),
        registration,
        registration_bytes,
        expected_plist: record_exists.then_some(expected_plist),
        plist_exists: record_exists && current_plist.is_some(),
        host_mode: super::AdminHostMode::Boot,
        login_registration: None,
        login_registration_bytes: None,
        login_expected_plist: Some(login_registration.plist()?),
        login_plist_exists: false,
        login_agents,
        service_was_running,
        allow_missing_executable,
        initial_install: false,
    })
}

pub(super) fn acquire_admin_maintenance_guard(
    profile_path: &Path,
    executable: &Path,
    selected_name: &str,
    mode: super::AdminHostMode,
    recovery: bool,
    uninstall: bool,
) -> Result<BootMaintenanceGuard> {
    if recovery && uninstall {
        return Err(Error::Invalid);
    }
    if mode == super::AdminHostMode::Boot {
        return acquire_maintenance_guard(
            profile_path,
            executable,
            selected_name,
            recovery,
            uninstall,
        );
    }
    acquire_login_or_manual_maintenance_guard(
        profile_path,
        executable,
        selected_name,
        mode,
        recovery,
        uninstall,
        true,
    )
}

pub(super) fn acquire_admin_initial_install_guard(
    profile_path: &Path,
    executable: &Path,
    selected_name: &str,
    mode: super::AdminHostMode,
) -> Result<BootMaintenanceGuard> {
    crate::process::require_child_ownership().map_err(|_| Error::Manager)?;
    if !root() || !executable.is_absolute() {
        return Err(Error::Unimplemented);
    }
    let account = account(selected_name)?;
    let expected_executable = install_path_for_account(&account.name)?.join("lomiremote");
    if executable != expected_executable {
        return Err(Error::Conflict);
    }
    let profile_path = validate_profile(profile_path, &account)?;
    validate_admin_owner_binding(
        &install_path_for_account(&account.name)?,
        &profile_path,
        &account,
        mode,
    )?;
    if validate_executable_state(executable, &account, true)? {
        return Err(Error::Conflict);
    }

    let profile = Directory::open(
        &profile_path,
        account.uid,
        false,
        Some(0o700),
        Some((account.uid, account.gid)),
    )?;
    let daemons = plist_directory()?;
    let admin_lock = lock_admin(&daemons)?;
    let login_adapter_lock = lock_login_adapter(&profile, &account)?;
    let owner_lock = match open_profile_lock(&profile, &account, true)? {
        ProfileLock::Acquired(owner) => owner,
        ProfileLock::Busy | ProfileLock::Missing => return Err(Error::Conflict),
    };
    if profile.read(RECORD, account.uid, 0o600)?.is_some() {
        return Err(Error::Conflict);
    }

    let profile_text = profile_path.to_str().ok_or(Error::Invalid)?.to_owned();
    let executable_text = executable.to_str().ok_or(Error::Invalid)?.to_owned();
    let boot_registration = Registration {
        version: 1,
        profile: profile_text.clone(),
        executable: executable_text.clone(),
        account: account.name.clone(),
        label: super::label(&profile_text),
        directory: LAUNCH_DAEMONS.to_owned(),
        mode: "boot".to_owned(),
    };
    let boot_name = service_name(&boot_registration);
    let boot_path = format!("{LAUNCH_DAEMONS}/{boot_name}");
    if daemons.read_root_plist_bytes(&boot_name)?.is_some()
        || observe(&boot_registration, &boot_path)?.is_some()
    {
        return Err(Error::Conflict);
    }

    let login_directory_path = account.home.join("Library/LaunchAgents");
    let login_registration = super::Registration {
        version: 1,
        profile: profile_text,
        executable: executable_text,
        account: account.name.clone(),
        label: super::label(profile_path.to_str().ok_or(Error::Invalid)?),
        directory: login_directory_path
            .to_str()
            .ok_or(Error::Invalid)?
            .to_owned(),
        mode: "login".to_owned(),
    };
    let login_name = format!("{}.plist", login_registration.label);
    let login_path = login_directory_path.join(&login_name);
    let login_agents = login_agents_directory(&account)?;
    if match login_agents.as_ref() {
        Some(agents) => agents.read(&login_name, account.uid, 0o600)?.is_some(),
        None => false,
    } || super::observe(
        &format!("gui/{}/{}", account.uid, login_registration.label),
        login_path.to_str().ok_or(Error::Invalid)?,
        &login_registration,
    )?
    .is_some()
    {
        return Err(Error::Conflict);
    }

    let guard = BootMaintenanceGuard {
        profile,
        _owner_lock: Some(owner_lock),
        _admin_lock: admin_lock,
        _login_adapter_lock: login_adapter_lock,
        uid: account.uid,
        account,
        executable_path: executable.to_path_buf(),
        registration: None,
        registration_bytes: None,
        expected_plist: None,
        plist_exists: false,
        host_mode: mode,
        login_registration: (mode == super::AdminHostMode::Login)
            .then_some(login_registration.clone()),
        login_registration_bytes: None,
        login_expected_plist: (mode == super::AdminHostMode::Login)
            .then(|| login_registration.plist())
            .transpose()?,
        login_plist_exists: false,
        login_agents,
        service_was_running: false,
        allow_missing_executable: true,
        initial_install: true,
    };
    if super::custody::read_optional_privileged_custodian(&guard)?.is_some() {
        return Err(Error::Conflict);
    }
    Ok(guard)
}

pub(super) fn run_admin_host(
    profile_path: &Path,
    executable: &Path,
    operation: &str,
    mode: super::AdminHostMode,
    selected_name: &str,
) -> Result<String> {
    crate::process::require_child_ownership().map_err(|_| Error::Manager)?;
    if !root()
        || !matches!(
            operation,
            "install" | "uninstall" | "start" | "restart" | "stop" | "status"
        )
    {
        return Err(Error::Invalid);
    }
    let account = account(selected_name)?;
    let profile_path = validate_profile(profile_path, &account)?;
    let expected_executable = install_path_for_account(&account.name)?.join("lomiremote");
    if executable != expected_executable {
        return Err(Error::Conflict);
    }
    validate_admin_owner_binding(
        &install_path_for_account(&account.name)?,
        &profile_path,
        &account,
        mode,
    )?;
    if mode != super::AdminHostMode::Boot
        && matches!(operation, "install" | "start" | "restart" | "status")
    {
        read_admin_host_identity_binding_for(&profile_path, &account, Some(mode))?
            .ok_or(Error::Conflict)?;
    }
    if operation == "status" {
        return inspect_admin_host(&profile_path, executable, selected_name, mode);
    }
    validate_executable_state(executable, &account, operation == "uninstall")?;
    if mode == super::AdminHostMode::Boot {
        if operation == "start" {
            let status = inspect_admin_host(&profile_path, executable, selected_name, mode)?;
            if status_field(&status, "Registration")? != "registered" {
                return Err(Error::Conflict);
            }
            if status_field(&status, "Active")? == "active" {
                if status_field(&status, "Custodian ready")? != "yes" {
                    return Err(Error::Conflict);
                }
                confirm_host_ready(&profile_path, executable, &account)?;
                return Ok("Service ready.".into());
            }
        }
        return run(
            &profile_path,
            executable,
            operation,
            Some("boot"),
            Some(selected_name),
        );
    }

    if operation == "start" {
        let status = inspect_admin_host(&profile_path, executable, selected_name, mode)?;
        if mode == super::AdminHostMode::Login
            && status_field(&status, "Registration")? != "registered"
        {
            return Err(Error::Conflict);
        }
        if status_field(&status, "Active")? == "active" {
            // A start request is idempotent. In particular, do not stop a
            // running Host merely to refresh its already installed companion.
            if status_field(&status, "Custodian ready")? != "yes" {
                return Err(Error::Conflict);
            }
            confirm_host_ready(&profile_path, executable, &account)?;
            return Ok("Service ready.".into());
        }
    }

    let mut guard = match acquire_login_or_manual_maintenance_guard(
        &profile_path,
        executable,
        selected_name,
        mode,
        operation == "install",
        operation == "uninstall",
        operation != "start",
    ) {
        Ok(guard) => guard,
        Err(Error::Conflict) if operation == "start" => {
            let status = inspect_admin_host(&profile_path, executable, selected_name, mode)?;
            if status_field(&status, "Active")? == "active"
                && status_field(&status, "Custodian ready")? == "yes"
            {
                confirm_host_ready(&profile_path, executable, &account)?;
                return Ok("Service ready.".into());
            }
            return Err(Error::Conflict);
        }
        Err(error) => return Err(error),
    };
    match operation {
        "install" => {
            super::custody_lifecycle::install_and_start(&guard)?;
            if mode == super::AdminHostMode::Login {
                guard.install_login_service_registration()?;
            }
            Ok(format!(
                "Service installed; account={} mode={} enabled={} (not started)",
                selected_name,
                mode.as_str(),
                mode == super::AdminHostMode::Login
            ))
        }
        "start" => {
            super::custody_lifecycle::ensure_ready_for_host(&guard)?;
            match mode {
                super::AdminHostMode::Login => guard
                    .start_login_service()
                    .map(|()| "Service ready.".into()),
                super::AdminHostMode::Manual => {
                    guard.release_profile_owner_lock();
                    run_as_account(&profile_path, executable, &account, &["daemon", "start"])?;
                    Ok("Service ready.".into())
                }
                super::AdminHostMode::Boot => unreachable!(),
            }
        }
        "stop" => {
            super::custody_lifecycle::begin_maintenance(&guard)?;
            Ok("Service stopped.".into())
        }
        "restart" => {
            super::custody_lifecycle::begin_maintenance(&guard)?;
            super::custody_lifecycle::ensure_ready_for_host(&guard)?;
            match mode {
                super::AdminHostMode::Login => guard
                    .start_login_service()
                    .map(|()| "Service ready.".into()),
                super::AdminHostMode::Manual => {
                    guard.release_profile_owner_lock();
                    run_as_account(&profile_path, executable, &account, &["daemon", "start"])?;
                    Ok("Service ready.".into())
                }
                super::AdminHostMode::Boot => unreachable!(),
            }
        }
        "uninstall" => {
            super::custody_lifecycle::begin_maintenance(&guard)?;
            guard.uninstall_service_registration()?;
            super::custody_lifecycle::uninstall(&guard)?;
            Ok("Service uninstalled; profile and workspace files preserved.".into())
        }
        _ => Err(Error::Invalid),
    }
}

fn status_field<'a>(status: &'a str, field: &str) -> Result<&'a str> {
    let prefix = format!("{field}: ");
    let mut matching = status.lines().filter_map(|line| line.strip_prefix(&prefix));
    let value = matching.next().ok_or(Error::Conflict)?;
    if matching.next().is_some() {
        return Err(Error::Conflict);
    }
    Ok(value)
}

fn acquire_login_or_manual_maintenance_guard(
    profile_path: &Path,
    executable: &Path,
    selected_name: &str,
    mode: super::AdminHostMode,
    recovery: bool,
    uninstall: bool,
    stop_host: bool,
) -> Result<BootMaintenanceGuard> {
    crate::process::require_child_ownership().map_err(|_| Error::Manager)?;
    if !root() || !executable.is_absolute() || mode == super::AdminHostMode::Boot {
        return Err(Error::Unimplemented);
    }
    let account = account(selected_name)?;
    let profile_path = validate_profile(profile_path, &account)?;
    validate_admin_owner_binding(
        &install_path_for_account(&account.name)?,
        &profile_path,
        &account,
        mode,
    )?;
    let profile = Directory::open(
        &profile_path,
        account.uid,
        false,
        Some(0o700),
        Some((account.uid, account.gid)),
    )?;
    let daemons = plist_directory()?;
    let admin_lock = lock_admin(&daemons)?;
    let login_adapter_lock = lock_login_adapter(&profile, &account)?;
    let profile_text = profile_path.to_str().ok_or(Error::Invalid)?;
    let executable_text = executable.to_str().ok_or(Error::Invalid)?;
    let expected_executable = install_path_for_account(&account.name)?.join("lomiremote");
    if executable != expected_executable {
        return Err(Error::Conflict);
    }
    validate_executable_state(executable, &account, recovery || uninstall)?;

    let registration_bytes = profile.read(RECORD, account.uid, 0o600)?;
    let registration = match (mode, registration_bytes.as_deref()) {
        (super::AdminHostMode::Login, Some(bytes)) => {
            let value: super::Registration =
                serde_json::from_slice(bytes).map_err(|_| Error::Conflict)?;
            let expected_directory = account.home.join("Library/LaunchAgents");
            if value.version != 1
                || value.profile != profile_text
                || value.executable != executable_text
                || value.account != account.name
                || value.label != super::label(profile_text)
                || value.directory != expected_directory.to_str().ok_or(Error::Invalid)?
                || value.mode != "login"
            {
                return Err(Error::Conflict);
            }
            validate_executable_state(
                Path::new(&value.executable),
                &account,
                recovery || uninstall,
            )?;
            Some(value)
        }
        (super::AdminHostMode::Login, None) => None,
        (super::AdminHostMode::Manual, None) => None,
        (super::AdminHostMode::Manual, Some(_)) => return Err(Error::Conflict),
        (super::AdminHostMode::Boot, _) => unreachable!(),
    };
    if registration.is_none() {
        Directory::open(
            executable.parent().ok_or(Error::Invalid)?,
            0,
            false,
            None,
            Some((account.uid, account.gid)),
        )?;
    }

    let agents = login_agents_directory(&account)?;
    let login_directory_path = account.home.join("Library/LaunchAgents");
    let login_directory_text = login_directory_path.to_str().ok_or(Error::Invalid)?;
    let login_registration = registration.clone().unwrap_or_else(|| super::Registration {
        version: 1,
        profile: profile_text.to_owned(),
        executable: executable_text.to_owned(),
        account: account.name.clone(),
        label: super::label(profile_text),
        directory: login_directory_text.to_owned(),
        mode: "login".to_owned(),
    });
    let login_name = format!("{}.plist", login_registration.label);
    let login_path = login_directory_path.join(&login_name);
    let login_path_text = login_path.to_str().ok_or(Error::Invalid)?;
    let login_plist = match agents.as_ref() {
        Some(directory) => directory.read(&login_name, account.uid, 0o600)?,
        None => None,
    };
    let login_observed = super::observe(
        &format!("gui/{}/{}", account.uid, login_registration.label),
        login_path_text,
        &login_registration,
    )?;
    let expected_login_plist = login_registration.plist()?;

    // A login or manual registration must never coexist with the same account's
    // boot LaunchDaemon, including a loaded orphan whose plist was removed.
    let boot_registration = Registration {
        version: 1,
        profile: profile_text.to_owned(),
        executable: executable_text.to_owned(),
        account: account.name.clone(),
        label: super::label(profile_text),
        directory: LAUNCH_DAEMONS.to_owned(),
        mode: "boot".to_owned(),
    };
    let boot_name = service_name(&boot_registration);
    let boot_path = format!("{LAUNCH_DAEMONS}/{boot_name}");
    let boot_plist = daemons.read_root_plist_bytes(&boot_name)?;
    let boot_observed = observe(&boot_registration, &boot_path)?;
    if boot_plist.is_some() || boot_observed.is_some() {
        return Err(Error::Conflict);
    }

    let service_was_running;
    let owner_lock;
    if mode == super::AdminHostMode::Login {
        if let Some(registration) = registration.as_ref() {
            let exact = login_plist.as_deref() == Some(expected_login_plist.as_slice());
            let recover_missing_plist =
                (uninstall || recovery) && login_plist.is_none() && login_observed.is_none();
            if !exact && !recover_missing_plist {
                return Err(Error::Conflict);
            }
            if stop_host {
                let (was_running, owner) = stop_login_with_owner_lock(
                    &profile,
                    &account,
                    executable,
                    &login_path,
                    registration,
                )?;
                service_was_running = was_running;
                owner_lock = Some(owner);
            } else {
                owner_lock = Some(match open_profile_lock(&profile, &account, true)? {
                    ProfileLock::Acquired(owner) => owner,
                    ProfileLock::Busy | ProfileLock::Missing => return Err(Error::Conflict),
                });
                service_was_running = false;
            }
        } else {
            if login_plist.is_some() || login_observed.is_some() {
                return Err(Error::Conflict);
            }
            if stop_host {
                let (was_running, owner) =
                    stop_manual_with_owner_lock(&profile, &account, executable)?;
                service_was_running = was_running;
                owner_lock = Some(owner);
            } else {
                owner_lock = Some(match open_profile_lock(&profile, &account, true)? {
                    ProfileLock::Acquired(owner) => owner,
                    ProfileLock::Busy | ProfileLock::Missing => return Err(Error::Conflict),
                });
                service_was_running = false;
            }
        }
    } else {
        if registration_bytes.is_some() || login_plist.is_some() || login_observed.is_some() {
            return Err(Error::Conflict);
        }
        if stop_host {
            let (was_running, owner) = stop_manual_with_owner_lock(&profile, &account, executable)?;
            service_was_running = was_running;
            owner_lock = Some(owner);
        } else {
            owner_lock = Some(match open_profile_lock(&profile, &account, true)? {
                ProfileLock::Acquired(owner) => owner,
                ProfileLock::Busy | ProfileLock::Missing => return Err(Error::Conflict),
            });
            service_was_running = false;
        }
    }

    Ok(BootMaintenanceGuard {
        profile,
        _owner_lock: owner_lock,
        _admin_lock: admin_lock,
        _login_adapter_lock: login_adapter_lock,
        uid: account.uid,
        account,
        executable_path: executable.to_path_buf(),
        registration: None,
        registration_bytes: None,
        expected_plist: None,
        plist_exists: false,
        host_mode: mode,
        login_registration: (mode == super::AdminHostMode::Login).then_some(login_registration),
        login_registration_bytes: registration_bytes,
        login_expected_plist: Some(expected_login_plist),
        login_plist_exists: login_plist.is_some(),
        login_agents: agents,
        service_was_running,
        allow_missing_executable: recovery || uninstall,
        initial_install: false,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AdminRegistrationState {
    Missing,
    Present,
    CleanupPending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AdminAutostartState {
    Enabled,
    Disabled,
    Unknown,
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AdminHostInspection {
    pub(super) registration: AdminRegistrationState,
    pub(super) active: bool,
    pub(super) autostart: AdminAutostartState,
    pub(super) ipc_ready: bool,
    pub(super) custodian_ready: bool,
}

fn inspect_admin_host(
    profile_path: &Path,
    executable: &Path,
    selected_name: &str,
    mode: super::AdminHostMode,
) -> Result<String> {
    let status = inspect_admin_host_typed(profile_path, executable, selected_name, mode)?;
    Ok(format!(
        "Account: {}\nMode: {}\nRegistration: {}\nActive: {}\nAutostart: {}\nCustodian ready: {}",
        account(selected_name)?.name,
        mode.as_str(),
        match status.registration {
            AdminRegistrationState::Missing => "absent",
            AdminRegistrationState::Present => "registered",
            AdminRegistrationState::CleanupPending => "cleanup-pending",
        },
        if status.active { "active" } else { "inactive" },
        match status.autostart {
            AdminAutostartState::Enabled => "enabled",
            AdminAutostartState::Disabled => "disabled",
            AdminAutostartState::Unknown => "unavailable",
            AdminAutostartState::None => "none",
        },
        if status.custodian_ready { "yes" } else { "no" },
    ))
}

pub(super) fn inspect_admin_host_typed(
    profile_path: &Path,
    executable: &Path,
    selected_name: &str,
    mode: super::AdminHostMode,
) -> Result<AdminHostInspection> {
    crate::process::require_child_ownership().map_err(|_| Error::Manager)?;
    if !root() || !executable.is_absolute() {
        return Err(Error::Unimplemented);
    }
    let account = account(selected_name)?;
    let profile_path = validate_profile(profile_path, &account)?;
    let profile = Directory::open(
        &profile_path,
        account.uid,
        false,
        Some(0o700),
        Some((account.uid, account.gid)),
    )?;
    let expected_executable = install_path_for_account(&account.name)?.join("lomiremote");
    if executable != expected_executable {
        return Err(Error::Conflict);
    }
    validate_admin_owner_binding(
        &install_path_for_account(&account.name)?,
        &profile_path,
        &account,
        mode,
    )?;
    let profile_text = profile_path.to_str().ok_or(Error::Invalid)?;
    let executable_text = executable.to_str().ok_or(Error::Invalid)?;
    let record = profile.read(RECORD, account.uid, 0o600)?;
    validate_executable_state(executable, &account, false)?;
    let boot_registration = Registration {
        version: 1,
        profile: profile_text.to_owned(),
        executable: executable_text.to_owned(),
        account: account.name.clone(),
        label: super::label(profile_text),
        directory: LAUNCH_DAEMONS.to_owned(),
        mode: "boot".to_owned(),
    };
    let login_directory_path = account.home.join("Library/LaunchAgents");
    let login_registration = super::Registration {
        version: 1,
        profile: profile_text.to_owned(),
        executable: executable_text.to_owned(),
        account: account.name.clone(),
        label: super::label(profile_text),
        directory: login_directory_path
            .to_str()
            .ok_or(Error::Invalid)?
            .to_owned(),
        mode: "login".to_owned(),
    };
    let (registration, active, autostart, ipc_ready) = match mode {
        super::AdminHostMode::Boot => {
            let (registration, has_record) = if let Some(record) = record.as_deref() {
                let registration: Registration =
                    serde_json::from_slice(record).map_err(|_| Error::Conflict)?;
                registration.validate(profile_text, &account)?;
                if registration.executable != executable_text {
                    return Err(Error::Conflict);
                }
                (registration, true)
            } else {
                (boot_registration.clone(), false)
            };
            let daemons = plist_directory()?;
            let name = service_name(&registration);
            let path = format!("{LAUNCH_DAEMONS}/{name}");
            let expected = registration.plist(&account)?;
            let plist = daemons.read_root_plist_bytes(&name)?;
            let observed = observe(&registration, &path)?;
            let agents = login_agents_directory(&account)?;
            let login_name = format!("{}.plist", login_registration.label);
            let login_path = login_directory_path.join(&login_name);
            let login_plist = match agents.as_ref() {
                Some(agents) => agents.read(&login_name, account.uid, 0o600)?,
                None => None,
            };
            let login_observed = super::observe(
                &format!("gui/{}/{}", account.uid, login_registration.label),
                login_path.to_str().ok_or(Error::Invalid)?,
                &login_registration,
            )?;
            if plist
                .as_deref()
                .is_some_and(|value| value != expected.as_slice())
                || !has_record && plist.is_some()
                || plist.is_none() && observed.is_some()
                || login_plist.is_some()
                || login_observed.is_some()
            {
                return Err(Error::Conflict);
            }
            let disabled = disabled_override(&registration.label)? == Some(true);
            let (owner_active, owner_ready) = profile_lock_status(&profile, &account, executable)?;
            let ipc_ready = observed
                .filter(|job| job.running)
                .and_then(|job| job.pid)
                .is_some_and(|pid| ready(&profile, &registration, &path, &account, pid));
            (
                if !has_record {
                    AdminRegistrationState::Missing
                } else if plist.is_none() {
                    AdminRegistrationState::CleanupPending
                } else {
                    AdminRegistrationState::Present
                },
                observed.is_some_and(|job| job.running) || owner_active,
                if disabled || !has_record {
                    AdminAutostartState::Disabled
                } else {
                    AdminAutostartState::Enabled
                },
                ipc_ready || owner_ready,
            )
        }
        super::AdminHostMode::Login => {
            let registration = if let Some(bytes) = record.as_deref() {
                let registration: super::Registration =
                    serde_json::from_slice(bytes).map_err(|_| Error::Conflict)?;
                if registration.version != 1
                    || registration.profile != profile_text
                    || registration.executable != executable_text
                    || registration.account != account.name
                    || registration.label != super::label(profile_text)
                    || registration.directory != login_registration.directory
                    || registration.mode != "login"
                {
                    return Err(Error::Conflict);
                }
                Some(registration)
            } else {
                None
            };
            let daemons = plist_directory()?;
            let boot_name = service_name(&boot_registration);
            let boot_path = format!("{LAUNCH_DAEMONS}/{boot_name}");
            let boot_plist = daemons.read_root_plist_bytes(&boot_name)?;
            let boot_observed = observe(&boot_registration, &boot_path)?;
            let agents = login_agents_directory(&account)?;
            let login_name = format!("{}.plist", login_registration.label);
            let login_path = login_directory_path.join(&login_name);
            let login_plist = match agents.as_ref() {
                Some(agents) => agents.read(&login_name, account.uid, 0o600)?,
                None => None,
            };
            let login_observed = match registration.as_ref() {
                Some(registration) => super::observe(
                    &format!("gui/{}/{}", account.uid, registration.label),
                    login_path.to_str().ok_or(Error::Invalid)?,
                    registration,
                )?,
                None => super::observe(
                    &format!("gui/{}/{}", account.uid, login_registration.label),
                    login_path.to_str().ok_or(Error::Invalid)?,
                    &login_registration,
                )?,
            };
            if boot_plist.is_some() || boot_observed.is_some() {
                return Err(Error::Conflict);
            }
            let (registration_state, expected) = if let Some(registration) = registration.as_ref() {
                validate_executable_state(executable, &account, false)?;
                (
                    if login_plist.is_none() {
                        "cleanup-pending"
                    } else {
                        "registered"
                    },
                    registration.plist()?,
                )
            } else {
                if login_plist.is_some() || login_observed.is_some() {
                    return Err(Error::Conflict);
                }
                ("absent", Vec::new())
            };
            if login_plist
                .as_deref()
                .is_some_and(|value| value != expected.as_slice())
                || login_plist.is_none() && login_observed.is_some()
            {
                return Err(Error::Conflict);
            }
            let autostart = if let Some(registration) = registration.as_ref() {
                match super::available_disabled_override(
                    &format!("gui/{}", account.uid),
                    &registration.label,
                )? {
                    None if login_observed.is_some() => return Err(Error::Conflict),
                    None => AdminAutostartState::Unknown,
                    Some(Some(true)) => AdminAutostartState::Disabled,
                    Some(Some(false)) | Some(None) => AdminAutostartState::Enabled,
                }
            } else {
                AdminAutostartState::Disabled
            };
            let (owner_active, owner_ready) = profile_lock_status(&profile, &account, executable)?;
            let ipc_ready = login_observed
                .flatten()
                .is_some_and(|pid| super::ready(&profile_path, pid));
            (
                if registration_state == "absent" {
                    AdminRegistrationState::Missing
                } else if registration_state == "cleanup-pending" {
                    AdminRegistrationState::CleanupPending
                } else {
                    AdminRegistrationState::Present
                },
                login_observed.is_some_and(|pid| pid.is_some()) || owner_active,
                autostart,
                ipc_ready || owner_ready,
            )
        }
        super::AdminHostMode::Manual => {
            if record.is_some() {
                return Err(Error::Conflict);
            }
            let daemons = plist_directory()?;
            let boot_name = service_name(&boot_registration);
            if daemons.read_root_plist_bytes(&boot_name)?.is_some()
                || observe(&boot_registration, &format!("{LAUNCH_DAEMONS}/{boot_name}"))?.is_some()
            {
                return Err(Error::Conflict);
            }
            let agents = login_agents_directory(&account)?;
            let login_name = format!("{}.plist", login_registration.label);
            let login_path = login_directory_path.join(&login_name);
            let login_plist = match agents.as_ref() {
                Some(agents) => agents.read(&login_name, account.uid, 0o600)?,
                None => None,
            };
            let login_observed = super::observe(
                &format!("gui/{}/{}", account.uid, login_registration.label),
                login_path.to_str().ok_or(Error::Invalid)?,
                &login_registration,
            )?;
            if login_plist.is_some() || login_observed.is_some() {
                return Err(Error::Conflict);
            }
            let (active, ipc_ready) = profile_lock_status(&profile, &account, executable)?;
            (
                AdminRegistrationState::Missing,
                active,
                AdminAutostartState::None,
                ipc_ready,
            )
        }
    };
    let custodian_ready =
        super::custody_lifecycle::is_ready_for_identity(&profile_path, executable, &account.name)?;
    Ok(AdminHostInspection {
        registration,
        active,
        autostart,
        ipc_ready,
        custodian_ready,
    })
}

/// Inspect the root-owned public LaunchDaemon configuration as the selected
/// account. The private admin-owner record remains exclusively a root
/// mutation/update authority; this read path derives every plist field from
/// the native account and exact installed signed Host binary.
pub(super) fn inspect_boot_host_public(
    profile_path: &Path,
    executable: &Path,
    selected_name: &str,
) -> Result<Option<AdminHostInspection>> {
    crate::process::require_child_ownership().map_err(|_| Error::Manager)?;
    if root() {
        return Err(Error::Conflict);
    }
    let account = account(selected_name)?;
    if account.uid != unsafe { libc::geteuid() }
        || account.gid != unsafe { libc::getegid() }
        || unsafe { libc::getuid() } != account.uid
    {
        return Err(Error::Conflict);
    }
    let profile_path = validate_profile(profile_path, &account)?;
    let expected_executable = install_path_for_account(&account.name)?.join("lomiremote");
    if executable != expected_executable
        || super::custody::installed_privileged_host_executable(&profile_path)?
            != expected_executable
    {
        return Err(Error::Conflict);
    }
    let _custody_binding =
        super::custody::privileged_custodian_client_binding(&profile_path, &expected_executable)
            .map_err(|_| Error::Conflict)?;
    validate_executable_state(&expected_executable, &account, false)?;

    let profile = Directory::open(
        &profile_path,
        account.uid,
        false,
        Some(0o700),
        Some((account.uid, account.gid)),
    )?;
    let profile_text = profile_path.to_str().ok_or(Error::Invalid)?;
    let executable_text = expected_executable.to_str().ok_or(Error::Invalid)?;
    let expected_registration = Registration {
        version: 1,
        profile: profile_text.to_owned(),
        executable: executable_text.to_owned(),
        account: account.name.clone(),
        label: super::label(profile_text),
        directory: LAUNCH_DAEMONS.to_owned(),
        mode: "boot".to_owned(),
    };
    let expected_record = profile
        .read(RECORD, account.uid, 0o600)?
        .map(|bytes| {
            let registration: Registration =
                serde_json::from_slice(&bytes).map_err(|_| Error::Conflict)?;
            registration.validate(profile_text, &account)?;
            if registration.executable != executable_text {
                return Err(Error::Conflict);
            }
            Ok(registration)
        })
        .transpose()?;
    if expected_record
        .as_ref()
        .is_some_and(|registration| registration.mode != "boot")
    {
        return Err(Error::Conflict);
    }

    let daemons = plist_directory()?;
    let name = service_name(&expected_registration);
    let path = format!("{LAUNCH_DAEMONS}/{name}");
    let expected_plist = expected_registration.plist(&account)?;
    let Some(public_plist) = daemons.read_public_root_plist(&name)? else {
        let manager_entry = match observe(&expected_registration, &path) {
            Ok(entry) => entry,
            Err(Error::Manager) => return Ok(None),
            Err(error) => return Err(error),
        };
        if expected_record.is_none() && manager_entry.is_some() {
            return Err(Error::Conflict);
        }
        match ensure_no_login_registration(&profile, &account, &expected_registration) {
            Ok(()) => {}
            Err(Error::Manager) => return Ok(None),
            Err(error) => return Err(error),
        }
        // Missing root-visible registration is intentionally indeterminate.
        // In particular, do not treat the selected user's private record as
        // sufficient evidence that launchd owns a Boot job.
        return Ok(None);
    };
    if public_plist != expected_plist {
        return Err(Error::Conflict);
    }
    if expected_record.is_none() {
        return Err(Error::Conflict);
    }
    match ensure_no_login_registration(&profile, &account, &expected_registration) {
        Ok(()) => {}
        Err(Error::Manager) => return Ok(None),
        Err(error) => return Err(error),
    }

    let manager_entry = match observe(&expected_registration, &path) {
        Ok(entry) => entry,
        Err(Error::Manager) => return Ok(None),
        Err(error) => return Err(error),
    };
    let disabled = match disabled_override(&expected_registration.label) {
        Ok(disabled) => disabled == Some(true),
        Err(Error::Manager) => return Ok(None),
        Err(error) => return Err(error),
    };
    let active = manager_entry.is_some_and(|entry| entry.running);
    let ipc_ready = manager_entry
        .filter(|entry| entry.running)
        .and_then(|entry| entry.pid)
        .is_some_and(|pid| {
            ready_as_account(&profile, &expected_registration, &path, &account, pid)
        });
    Ok(Some(AdminHostInspection {
        registration: AdminRegistrationState::Present,
        active,
        autostart: if disabled {
            AdminAutostartState::Disabled
        } else {
            AdminAutostartState::Enabled
        },
        ipc_ready,
        custodian_ready: false,
    }))
}

/// Reject a competing selected-account LaunchAgent before reporting or
/// selecting Boot mode. The user registration and launchd definition are
/// checked independently; neither is used as authority for the system plist.
fn ensure_no_login_registration(
    profile: &Directory,
    account: &Account,
    boot_registration: &Registration,
) -> Result<()> {
    let login_directory_path = account.home.join("Library/LaunchAgents");
    let login_registration = super::Registration {
        version: 1,
        profile: boot_registration.profile.clone(),
        executable: boot_registration.executable.clone(),
        account: account.name.clone(),
        label: super::label(&boot_registration.profile),
        directory: login_directory_path
            .to_str()
            .ok_or(Error::Invalid)?
            .to_owned(),
        mode: "login".to_owned(),
    };
    let name = format!("{}.plist", login_registration.label);
    let path = login_directory_path.join(&name);
    let agents = login_agents_directory(account)?;
    let plist = match agents.as_ref() {
        Some(directory) => directory.read(&name, account.uid, 0o600)?,
        None => None,
    };
    let observed = super::observe(
        &format!("gui/{}/{}", account.uid, login_registration.label),
        path.to_str().ok_or(Error::Invalid)?,
        &login_registration,
    )?;
    if plist.is_some() || observed.is_some() {
        return Err(Error::Conflict);
    }
    let stored = profile.read(RECORD, account.uid, 0o600)?;
    if stored.as_deref().is_some_and(|bytes| {
        serde_json::from_slice::<Registration>(bytes)
            .is_ok_and(|registration| registration.mode == "login")
    }) {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Check the system-domain Boot registration before selecting Manual or
/// Login. A private legacy plist is intentionally surfaced as unavailable to
/// ordinary users, so it cannot be mistaken for absence.
pub(super) fn ensure_no_public_boot_registration(
    profile_path: &Path,
    executable: &Path,
    selected_name: &str,
) -> Result<()> {
    if root() {
        return Ok(());
    }
    let account = account(selected_name)?;
    let profile_path = validate_profile(profile_path, &account)?;
    let profile_text = profile_path.to_str().ok_or(Error::Invalid)?;
    let executable_text = executable.to_str().ok_or(Error::Invalid)?;
    let registration = Registration {
        version: 1,
        profile: profile_text.to_owned(),
        executable: executable_text.to_owned(),
        account: account.name,
        label: super::label(profile_text),
        directory: LAUNCH_DAEMONS.to_owned(),
        mode: "boot".to_owned(),
    };
    let name = service_name(&registration);
    let path = format!("{LAUNCH_DAEMONS}/{name}");
    let daemons = plist_directory()?;
    let plist = daemons.read_public_root_plist(&name)?;
    let observed = observe(&registration, &path).map_err(|error| {
        if error == Error::Manager {
            Error::Unavailable
        } else {
            error
        }
    })?;
    if plist.is_some() || observed.is_some() {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn ready_as_account(
    profile: &Directory,
    registration: &Registration,
    path: &str,
    account: &Account,
    expected_pid: u32,
) -> bool {
    let Ok(discovery) = read_discovery(profile, account) else {
        return false;
    };
    LocalClient::connect_with_timeout(&profile.1, Duration::from_millis(200))
        .and_then(|mut client| {
            if client.service_peer_pid()? != expected_pid {
                return Err(crate::unix::Error::PermissionDenied);
            }
            client.request(LocalCall::Status {})
        })
        .is_ok_and(|response| {
            matches!(
                response.result,
                Ok(LocalResult::Status(status))
                    if status.host_id == discovery.host_id
                        && status.runtime_id == discovery.runtime_id
            ) && observe(registration, path).is_ok_and(|current| {
                current.is_some_and(|entry| entry.running && entry.pid == Some(expected_pid))
            })
        })
}

fn profile_lock_status(
    profile: &Directory,
    account: &Account,
    executable: &Path,
) -> Result<(bool, bool)> {
    match open_profile_lock(profile, account, false)? {
        ProfileLock::Busy => {
            // The fixed installed CLI queries the profile's authenticated local
            // IPC as the selected account; an arbitrary PID or lock alone is
            // never reported as a live Host.
            run_as_account(
                &profile.1,
                executable,
                account,
                &["maintenance", "prepare", "--json"],
            )?;
            Ok((true, true))
        }
        ProfileLock::Acquired(owner) => {
            drop(owner);
            Ok((false, false))
        }
        ProfileLock::Missing => Ok((false, false)),
    }
}

fn install_files(
    guard: &BootMaintenanceGuard,
    daemons: &Directory,
    account: &Account,
    name: &str,
    registration: &[u8],
    plist: &[u8],
    registration_exists: bool,
    plist_exists: bool,
) -> Result<()> {
    if !root()
        || guard.host_mode != super::AdminHostMode::Boot
        || guard.uid != account.uid
        || guard.account.name != account.name
        || guard._owner_lock.is_none()
    {
        return Err(Error::Conflict);
    }
    let profile = &guard.profile;
    if !registration_exists {
        profile.publish(RECORD, registration, account.uid, account.gid, 0o600)?;
    }
    profile.0.sync_all().map_err(|_| Error::Invalid)?;
    if plist_exists {
        daemons.upgrade_root_plist(name, plist)?;
    } else {
        daemons.publish_public_root_plist(name, plist)?;
    }
    daemons.0.sync_all().map_err(|_| Error::Invalid)
}

fn uninstall_files(
    profile: &Directory,
    daemons: &Directory,
    reg: &Registration,
    registration: &[u8],
    plist: &[u8],
    account: &Account,
    plist_exists: bool,
) -> Result<()> {
    if plist_exists {
        daemons.remove_root_plist_exact(&service_name(reg), plist)?;
    }
    daemons.0.sync_all().map_err(|_| Error::Invalid)?;
    profile.remove_exact(RECORD, registration, account.uid, 0o600)
}

fn routing_registration(profile: &Path) -> Result<Option<Registration>> {
    // This read is only a routing hint; boot::run reopens and validates every
    // component and the record owner before it authorizes any manager action.
    let path = profile.join(RECORD);
    let fd = unsafe {
        libc::open(
            c(path.as_os_str())?.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return if io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(Error::Conflict)
        };
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|_| Error::Conflict)?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
        return Err(Error::Conflict);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Conflict)?;
    if bytes.len() > LIMIT {
        return Err(Error::Conflict);
    }
    let registration =
        serde_json::from_slice::<Registration>(&bytes).map_err(|_| Error::Conflict)?;
    if registration.mode == "boot" {
        Ok(Some(registration))
    } else {
        Ok(None)
    }
}

pub(super) fn is_boot_registration(profile: &Path) -> Result<bool> {
    Ok(routing_registration(profile)?.is_some())
}

/// Handles the explicit system-domain adapter. Calls with a persisted boot
/// record are routed here even when no mode was passed (for updater recovery).
pub(super) fn run(
    profile_path: &Path,
    executable: &Path,
    operation: &str,
    mode: Option<&str>,
    selected_account: Option<&str>,
) -> Result<String> {
    crate::process::require_child_ownership().map_err(|_| Error::Manager)?;
    if !root() {
        return Err(Error::Unimplemented);
    }
    if !matches!(
        operation,
        "install" | "uninstall" | "start" | "restart" | "stop" | "status"
    ) {
        return Err(Error::Invalid);
    }
    let hint = if mode == Some("boot") {
        None
    } else {
        routing_registration(profile_path)?
    };
    if mode != Some("boot") && hint.is_none() {
        return Err(Error::Conflict);
    }
    if operation == "install" && mode != Some("boot") {
        return Err(Error::Conflict);
    }
    let selected_name = if operation == "install" || mode == Some("boot") {
        selected_account
            .or_else(|| {
                hint.as_ref()
                    .map(|registration| registration.account.as_str())
            })
            .ok_or(Error::Invalid)?
            .to_owned()
    } else {
        hint.as_ref().ok_or(Error::Conflict)?.account.clone()
    };
    if hint
        .as_ref()
        .is_some_and(|registration| registration.account != selected_name)
    {
        return Err(Error::Conflict);
    }
    let account = account(&selected_name)?;
    let profile_path = validate_profile(profile_path, &account)?;
    let expected_executable = install_path_for_account(&account.name)?.join("lomiremote");
    if executable != expected_executable {
        return Err(Error::Conflict);
    }
    validate_admin_owner_binding(
        &install_path_for_account(&account.name)?,
        &profile_path,
        &account,
        super::AdminHostMode::Boot,
    )?;
    if matches!(operation, "install" | "start" | "restart" | "status") {
        read_admin_host_identity_binding_for(
            &profile_path,
            &account,
            Some(super::AdminHostMode::Boot),
        )?
        .ok_or(Error::Conflict)?;
    }
    if operation == "status" {
        return inspect_admin_host(
            &profile_path,
            executable,
            &selected_name,
            super::AdminHostMode::Boot,
        );
    }
    let profile = Directory::open(
        &profile_path,
        account.uid,
        false,
        Some(0o700),
        Some((account.uid, account.gid)),
    )?;
    let launch_daemons = plist_directory()?;
    let admin_lock = lock_admin(&launch_daemons)?;
    let login_adapter_lock = lock_login_adapter(&profile, &account)?;
    let existing = profile.read(RECORD, account.uid, 0o600)?;
    let reg = if let Some(bytes) = &existing {
        let reg: Registration = serde_json::from_slice(bytes).map_err(|_| Error::Conflict)?;
        reg.validate(profile_path.to_str().ok_or(Error::Invalid)?, &account)?;
        if operation == "install"
            && (mode != Some("boot")
                || selected_account != Some(reg.account.as_str())
                || executable.to_str() != Some(reg.executable.as_str()))
        {
            return Err(Error::Conflict);
        }
        reg
    } else {
        if !matches!(operation, "install" | "uninstall") || mode != Some("boot") {
            return Err(Error::Conflict);
        }
        let expected_executable = install_path_for_account(&account.name)?.join("lomiremote");
        if executable != expected_executable {
            return Err(Error::Conflict);
        }
        let executable = if operation == "uninstall" {
            validate_executable_state(executable, &account, true)?;
            executable.to_path_buf()
        } else {
            validate_executable(executable, &account)?
        };
        Registration {
            version: 1,
            profile: profile_path.to_str().ok_or(Error::Invalid)?.to_owned(),
            executable: executable.to_str().ok_or(Error::Invalid)?.to_owned(),
            account: account.name.clone(),
            label: super::label(profile_path.to_str().ok_or(Error::Invalid)?),
            directory: LAUNCH_DAEMONS.to_owned(),
            mode: "boot".to_owned(),
        }
    };
    if operation == "uninstall" && existing.is_none() {
        validate_executable_state(Path::new(&reg.executable), &account, true)?;
    } else {
        validate_executable(Path::new(&reg.executable), &account)?;
    }
    let expected_plist = reg.plist(&account)?;
    let name = service_name(&reg);
    let path = format!("{LAUNCH_DAEMONS}/{name}");
    let current_plist = launch_daemons.read_root_plist_bytes(&name)?;
    if let Some(bytes) = &current_plist
        && (bytes != &expected_plist || existing.is_none())
    {
        return Err(Error::Conflict);
    }
    let disabled = disabled_override(&reg.label)?;
    if matches!(operation, "install" | "start" | "restart") && disabled == Some(true) {
        return Err(Error::Disabled);
    }
    let observed = observe(&reg, &path)?;
    let login_agents = login_agents_directory(&account)?;
    let login_directory_path = account.home.join("Library/LaunchAgents");
    let login_registration = super::Registration {
        version: 1,
        profile: profile_path.to_str().ok_or(Error::Invalid)?.to_owned(),
        executable: reg.executable.clone(),
        account: account.name.clone(),
        label: super::label(profile_path.to_str().ok_or(Error::Invalid)?),
        directory: login_directory_path
            .to_str()
            .ok_or(Error::Invalid)?
            .to_owned(),
        mode: "login".to_owned(),
    };
    let login_name = format!("{}.plist", login_registration.label);
    let login_path = login_directory_path.join(&login_name);
    let login_current_plist = match login_agents.as_ref() {
        Some(agents) => agents.read(&login_name, account.uid, 0o600)?,
        None => None,
    };
    let login_observed = super::observe(
        &format!("gui/{}/{}", account.uid, login_registration.label),
        login_path.to_str().ok_or(Error::Invalid)?,
        &login_registration,
    )?;
    if login_current_plist.is_some() || login_observed.is_some() {
        return Err(Error::Conflict);
    }
    // Registration is published before its plist. A retry may repair that
    // exact authenticated partial install, but never adopt a loaded orphan.
    if current_plist.is_none()
        && !matches!(operation, "uninstall" | "status")
        && !(operation == "install" && observed.is_none())
    {
        return Err(Error::Conflict);
    }
    let (service_was_running, owner_lock) = match operation {
        "install" if existing.is_some() => {
            let (was_running, owner) = stop_with_owner_lock(&profile, &reg, &path, &account)?;
            (was_running, Some(owner))
        }
        "install" => {
            if observed.is_some() {
                return Err(Error::Conflict);
            }
            let owner = match open_profile_lock(&profile, &account, true)? {
                ProfileLock::Acquired(owner) => owner,
                ProfileLock::Missing | ProfileLock::Busy => return Err(Error::Conflict),
            };
            (false, Some(owner))
        }
        "stop" | "restart" | "uninstall" => {
            let (was_running, owner) = stop_with_owner_lock(&profile, &reg, &path, &account)?;
            (was_running, Some(owner))
        }
        "start" | "status" => {
            let reported_running = observed.is_some_and(|value| value.running);
            match open_profile_lock(&profile, &account, false)? {
                ProfileLock::Acquired(owner) if reported_running => {
                    // Launchd has published the job but Host has not acquired
                    // its lifetime lock yet. Do not hold that lock over start.
                    drop(owner);
                    (true, None)
                }
                ProfileLock::Acquired(owner) => (false, Some(owner)),
                ProfileLock::Busy if reported_running => (true, None),
                ProfileLock::Busy if operation == "status" => (true, None),
                ProfileLock::Busy => return Err(Error::Conflict),
                ProfileLock::Missing => return Err(Error::Conflict),
            }
        }
        _ => return Err(Error::Invalid),
    };
    let mut guard = BootMaintenanceGuard {
        profile,
        _owner_lock: owner_lock,
        _admin_lock: admin_lock,
        _login_adapter_lock: login_adapter_lock,
        uid: account.uid,
        account: account.clone(),
        executable_path: PathBuf::from(&reg.executable),
        registration: existing.as_ref().map(|_| reg.clone()),
        registration_bytes: existing.clone(),
        expected_plist: existing.as_ref().map(|_| expected_plist.clone()),
        plist_exists: existing.is_some() && current_plist.is_some(),
        host_mode: super::AdminHostMode::Boot,
        login_registration: None,
        login_registration_bytes: None,
        login_expected_plist: Some(login_registration.plist()?),
        login_plist_exists: login_current_plist.is_some(),
        login_agents,
        service_was_running,
        allow_missing_executable: operation == "uninstall" && existing.is_none(),
        initial_install: false,
    };
    match operation {
        "install" => {
            super::custody_lifecycle::install_and_start(&guard)?;
            install_files(
                &guard,
                &launch_daemons,
                &account,
                &name,
                &serde_json::to_vec(&reg).map_err(|_| Error::Invalid)?,
                &expected_plist,
                existing.is_some(),
                current_plist.is_some(),
            )?;
            Ok(format!(
                "Service installed; account={} mode=boot enabled=true (not started)",
                reg.account
            ))
        }
        "status" => {
            let partial_cleanup = current_plist.is_none();
            let profile_owner_active = service_was_running && observed.is_none();
            let ipc_ready = observed.is_some_and(|value| {
                value.running
                    && value
                        .pid
                        .is_some_and(|pid| ready(&guard.profile, &reg, &path, &account, pid))
            });
            let custody_ready = super::custody_lifecycle::is_ready(&guard)?;
            Ok(format!(
                "Service: {}\nAccount: {}\nMode: boot\nRegistration: {}\nAutostart: {}\nActive: {}\nIPC ready: {}\nCustody ready: {}",
                reg.label,
                reg.account,
                if partial_cleanup {
                    "cleanup-pending"
                } else {
                    "registered"
                },
                if disabled == Some(true) {
                    "disabled"
                } else {
                    "enabled"
                },
                if observed.is_some_and(|value| value.running) || profile_owner_active {
                    "active"
                } else {
                    "inactive"
                },
                ipc_ready,
                custody_ready
            ))
        }
        "start" => {
            super::custody_lifecycle::ensure_ready_for_host(&guard)?;
            let now = observe(&reg, &path)?;
            if now.is_some_and(|value| {
                value.running
                    && value
                        .pid
                        .is_some_and(|pid| ready(&guard.profile, &reg, &path, &account, pid))
            }) {
                return Ok("Service ready.".into());
            }
            if now.is_none() {
                guard.release_profile_owner_lock();
                super::required(&["bootstrap", "system", &path])?;
            } else if now.is_some_and(|value| !value.running) {
                guard.release_profile_owner_lock();
                super::required(&["kickstart", &target(&reg)])?;
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(current) = observe(&reg, &path)?
                    && current.running
                    && current
                        .pid
                        .is_some_and(|pid| ready(&guard.profile, &reg, &path, &account, pid))
                {
                    super::custody_lifecycle::is_ready(&guard)?
                        .then_some(())
                        .ok_or(Error::NotReady)?;
                    return Ok("Service ready.".into());
                }
                if Instant::now() >= deadline {
                    return Err(Error::NotReady);
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
        "restart" => {
            super::custody_lifecycle::begin_maintenance(&guard)?;
            super::custody_lifecycle::ensure_ready_for_host(&guard)?;
            guard.release_profile_owner_lock();
            match observe(&reg, &path)? {
                None => super::required(&["bootstrap", "system", &path])?,
                Some(observation) if !observation.running => {
                    super::required(&["kickstart", &target(&reg)])?;
                }
                Some(_) => {}
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(current) = observe(&reg, &path)?
                    && current.running
                    && current
                        .pid
                        .is_some_and(|pid| ready(&guard.profile, &reg, &path, &account, pid))
                {
                    if !super::custody_lifecycle::is_ready(&guard)? {
                        return Err(Error::NotReady);
                    }
                    return Ok("Service ready.".into());
                }
                if Instant::now() >= deadline {
                    return Err(Error::NotReady);
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
        "stop" => {
            super::custody_lifecycle::begin_maintenance(&guard)?;
            Ok("Service stopped.".into())
        }
        "uninstall" => {
            // Drain custody before removing either registration. Removing the
            // Host record first leaves a retryable state if custody removal
            // later encounters a filesystem error.
            super::custody_lifecycle::begin_maintenance(&guard)?;
            guard.uninstall_service_registration()?;
            super::custody_lifecycle::uninstall(&guard)?;
            Ok("Service uninstalled; profile and workspace files preserved.".into())
        }
        _ => Err(Error::Invalid),
    }
}
