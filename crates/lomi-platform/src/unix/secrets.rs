//! Explicit Unix plaintext protected-file provider, scoped to one private profile.
use super::{PrivateProfile, object, private_regular};
use crate::secrets::{
    Error, MAX_BUNDLE_BYTES, ProviderKind, ProviderStatus, SecretBundle, SecretStorage, Selection,
    StorageState,
};
use std::{
    ffi::CStr,
    fs::File,
    io::{self, Read, Write},
    os::fd::{AsRawFd, FromRawFd},
};
use zeroize::Zeroizing;

const BUNDLE: &CStr = c"host-secrets.bundle";
const LOCK: &CStr = c"host-secrets.lock";
const MAGIC: &[u8; 8] = b"LMSECRET";
const HEADER: usize = 12;

fn io_error(_: io::Error) -> Error {
    Error::Io
}
fn validate(file: &File) -> Result<(), Error> {
    private_regular(file).map_err(|_| Error::InvalidStorage)?;
    no_posix_acl(file)
}
#[cfg(target_os = "linux")]
fn no_posix_acl(file: &File) -> Result<(), Error> {
    for name in [c"system.posix_acl_access", c"system.posix_acl_default"] {
        let n =
            unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
        if n >= 0 {
            return Err(Error::InvalidStorage);
        }
        match io::Error::last_os_error().raw_os_error() {
            Some(libc::ENODATA) | Some(libc::ENOTSUP) => {}
            _ => return Err(Error::InvalidStorage),
        }
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn no_posix_acl(_: &File) -> Result<(), Error> {
    Ok(())
}

// Retain the normal ancestry validation and additionally reject Linux POSIX
// ACLs, including inheritable default entries, on every pinned ancestor.
fn check_acl_ancestry(profile: &PrivateProfile) -> Result<(), Error> {
    let mut directory = File::open("/").map_err(io_error)?;
    no_posix_acl(&directory)?;
    for part in profile.path.components().skip(1) {
        let std::path::Component::Normal(name) = part else {
            return Err(Error::InvalidStorage);
        };
        let name =
            std::ffi::CString::new(name.as_encoded_bytes()).map_err(|_| Error::InvalidStorage)?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(Error::InvalidStorage);
        }
        directory = unsafe { File::from_raw_fd(fd) };
        super::trusted_directory(&directory, false).map_err(|_| Error::InvalidStorage)?;
        no_posix_acl(&directory)?;
    }
    if object(&directory.metadata().map_err(io_error)?) != profile.identity {
        return Err(Error::InvalidStorage);
    }
    Ok(())
}

/// Holds a separate persistent exclusive storage lock for its entire lifetime.
/// Same-UID malicious processes and privileged administrators remain trusted.
/// No paths, names or directories are accepted from secret bundle input.
pub struct ProtectedFile<'a> {
    profile: &'a PrivateProfile,
    lock: File,
    kind: GuardKind,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum GuardKind {
    Plaintext,
    #[cfg(target_os = "macos")]
    Keychain,
    #[cfg(target_os = "linux")]
    SecretService,
}
impl<'a> ProtectedFile<'a> {
    pub fn open(profile: &'a PrivateProfile, selection: Selection) -> Result<Self, Error> {
        match selection {
            Selection::ProtectedFile(_) => {}
            Selection::Unconfigured => return Err(Error::Unconfigured),
            _ => return Err(Error::Unavailable),
        }
        Self::open_internal(profile, GuardKind::Plaintext)
    }
    /// Reuse only the validated persistent lock, never the plaintext reader.
    #[cfg(target_os = "macos")]
    pub(super) fn open_keychain_guard(profile: &'a PrivateProfile) -> Result<Self, Error> {
        absent(profile, c"host-secrets.bundle")?;
        Self::open_internal(profile, GuardKind::Keychain)
    }
    #[cfg(target_os = "linux")]
    pub(super) fn open_secret_service_guard(profile: &'a PrivateProfile) -> Result<Self, Error> {
        Self::open_internal(profile, GuardKind::SecretService)
    }
    fn open_internal(profile: &'a PrivateProfile, kind: GuardKind) -> Result<Self, Error> {
        profile.check_current().map_err(|_| Error::InvalidStorage)?;
        check_acl_ancestry(profile)?;
        let lock = open_at(profile, LOCK, libc::O_RDWR | libc::O_CREAT)?;
        validate(&lock)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return if io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
                Err(Error::Locked)
            } else {
                Err(Error::Io)
            };
        }
        let this = Self {
            profile,
            lock,
            kind,
        };
        this.check()?;
        // Validate an existing bundle before declaring this provider available.
        if kind == GuardKind::Plaintext {
            drop(this.load()?);
        }
        Ok(this)
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        self.profile
            .check_current()
            .map_err(|_| Error::InvalidStorage)?;
        check_acl_ancestry(self.profile)?;
        validate(&self.lock)?;
        let current = open_at(self.profile, LOCK, libc::O_RDONLY)?;
        validate(&current)?;
        if object(&current.metadata().map_err(io_error)?)
            != object(&self.lock.metadata().map_err(io_error)?)
        {
            return Err(Error::InvalidStorage);
        }
        // Provider transitions are explicit. Check presence under the common
        // lock without reading either provider's foreign payload, even symlinks.
        if self.kind != GuardKind::Plaintext {
            absent(self.profile, c"host-secrets.bundle")?;
        } else {
            absent(self.profile, c"host-secrets.keychain.bundle")?;
        }
        #[cfg(target_os = "linux")]
        if self.kind == GuardKind::SecretService {
            absent(self.profile, c"host-secrets.keychain.bundle")?;
        } else {
            absent(self.profile, c"host-secrets.secret-service")?;
        }
        #[cfg(not(target_os = "linux"))]
        absent(self.profile, c"host-secrets.secret-service")?;
        Ok(())
    }
    fn existing(&self) -> Result<Option<File>, Error> {
        match open_at_io(self.profile, BUNDLE, libc::O_RDONLY) {
            Ok(file) => {
                validate(&file)?;
                Ok(Some(file))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(Error::InvalidStorage),
        }
    }
    fn confirm_cleared(&self) -> Result<(), Error> {
        // A retry may observe absence after an earlier unlink whose directory
        // sync failed. Establish durability on this path as well.
        self.profile
            .directory
            .sync_all()
            .map_err(|_| Error::CommitUncertain)?;
        self.check().map_err(|_| Error::CommitUncertain)?;
        if self
            .existing()
            .map_err(|_| Error::CommitUncertain)?
            .is_some()
        {
            return Err(Error::CommitUncertain);
        }
        Ok(())
    }
    fn write(
        &mut self,
        bundle: &SecretBundle,
        before_publish: impl FnOnce() -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.check()?;
        drop(self.existing()?);
        // O_EXCL never opens/reuses a crash remnant or colliding entry. Crash
        // remnants remain private and are never automatically restored/published.
        let name = std::ffi::CString::new(format!(".host-secrets-{}.tmp", uuid::Uuid::new_v4()))
            .map_err(|_| Error::Io)?;
        let file = open_at(
            self.profile,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        let mut temp = Temporary {
            profile: self.profile,
            name: &name,
            file,
            published: false,
        };
        validate(&temp.file)?;
        temp.file.write_all(MAGIC).map_err(io_error)?;
        temp.file
            .write_all(&(bundle.expose().len() as u32).to_be_bytes())
            .map_err(io_error)?;
        temp.file.write_all(bundle.expose()).map_err(io_error)?;
        temp.file.sync_all().map_err(io_error)?;
        before_publish()?;
        self.check()?;
        drop(self.existing()?);
        validate(&temp.file)?;
        let current = open_at(self.profile, &name, libc::O_RDONLY)?;
        validate(&current)?;
        if object(&current.metadata().map_err(io_error)?)
            != object(&temp.file.metadata().map_err(io_error)?)
        {
            return Err(Error::InvalidStorage);
        }
        if unsafe {
            libc::renameat(
                self.profile.directory.as_raw_fd(),
                name.as_ptr(),
                self.profile.directory.as_raw_fd(),
                BUNDLE.as_ptr(),
            )
        } != 0
        {
            return Err(Error::Io);
        }
        temp.published = true;
        self.profile
            .directory
            .sync_all()
            .map_err(|_| Error::CommitUncertain)
    }
}
fn absent(profile: &PrivateProfile, name: &CStr) -> Result<(), Error> {
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            profile.directory.as_raw_fd(),
            name.as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
        && io::Error::last_os_error().kind() == io::ErrorKind::NotFound
    {
        Ok(())
    } else {
        Err(Error::InvalidStorage)
    }
}
impl SecretStorage for ProtectedFile<'_> {
    fn status(&self) -> ProviderStatus {
        ProviderStatus {
            kind: Some(ProviderKind::ProtectedFile),
            state: match self.load() {
                Ok(_) => StorageState::Available,
                Err(error) => error.state(),
            },
        }
    }
    fn load(&self) -> Result<Option<SecretBundle>, Error> {
        self.check()?;
        let Some(mut file) = self.existing()? else {
            return Ok(None);
        };
        let size = file.metadata().map_err(io_error)?.len();
        if !(HEADER as u64 + 1..=HEADER as u64 + MAX_BUNDLE_BYTES as u64).contains(&size) {
            return Err(Error::InvalidBundle);
        }
        let mut header = Zeroizing::new([0; HEADER]);
        file.read_exact(&mut header[..])
            .map_err(|_| Error::InvalidBundle)?;
        let length = u32::from_be_bytes(header[8..12].try_into().map_err(|_| Error::InvalidBundle)?)
            as usize;
        if &header[..8] != MAGIC
            || length == 0
            || length > MAX_BUNDLE_BYTES
            || size != (HEADER + length) as u64
        {
            return Err(Error::InvalidBundle);
        }
        let mut bytes = Zeroizing::new(vec![0; length]);
        file.read_exact(&mut bytes)
            .map_err(|_| Error::InvalidBundle)?;
        let mut extra = Zeroizing::new([0; 1]);
        if file.read(&mut extra[..]).map_err(io_error)? != 0 {
            return Err(Error::InvalidBundle);
        }
        validate(&file)?;
        self.check()?;
        // Move the already zeroizing allocation without making a secret copy.
        Ok(Some(SecretBundle::from_zeroizing(bytes)))
    }
    fn replace(&mut self, bundle: &SecretBundle) -> Result<(), Error> {
        self.write(bundle, || Ok(()))
    }
    fn clear(&mut self) -> Result<(), Error> {
        drop(self.load()?);
        self.check()?;
        let Some(file) = self.existing()? else {
            return self.confirm_cleared();
        };
        let identity = object(&file.metadata().map_err(io_error)?);
        drop(file);
        self.check()?;
        let Some(current) = self.existing()? else {
            return self.confirm_cleared();
        };
        if object(&current.metadata().map_err(io_error)?) != identity {
            return Err(Error::InvalidStorage);
        }
        drop(current);
        if unsafe { libc::unlinkat(self.profile.directory.as_raw_fd(), BUNDLE.as_ptr(), 0) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::NotFound {
                return Err(io_error(error));
            }
        }
        self.confirm_cleared()
    }
}
fn open_at_io(profile: &PrivateProfile, name: &CStr, flags: i32) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            profile.directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn open_at(profile: &PrivateProfile, name: &CStr, flags: i32) -> Result<File, Error> {
    open_at_io(profile, name, flags).map_err(io_error)
}
struct Temporary<'a> {
    profile: &'a PrivateProfile,
    name: &'a CStr,
    file: File,
    published: bool,
}
impl Drop for Temporary<'_> {
    fn drop(&mut self) {
        if !self.published {
            // Fixed pinned directory; remove only our still-owned temporary inode.
            if let Ok(current) = open_at(self.profile, self.name, libc::O_RDONLY)
                && current
                    .metadata()
                    .ok()
                    .zip(self.file.metadata().ok())
                    .is_some_and(|(a, b)| object(&a) == object(&b))
            {
                unsafe {
                    libc::unlinkat(self.profile.directory.as_raw_fd(), self.name.as_ptr(), 0);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{secrets::ProtectedFileAcknowledgement, unix::OwnerLock};
    use std::{fs, os::unix::fs::PermissionsExt};
    #[test]
    fn failed_atomic_update_keeps_previous_bundle() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let owner = OwnerLock::acquire(&root.path().canonicalize().unwrap()).unwrap();
        let mut store = ProtectedFile::open(
            owner.profile(),
            Selection::ProtectedFile(ProtectedFileAcknowledgement::OsPermissionsOnly),
        )
        .unwrap();
        store
            .replace(&SecretBundle::new(b"old-fixture".to_vec()).unwrap())
            .unwrap();
        let before = fs::read(root.path().join("host-secrets.bundle")).unwrap();
        assert_eq!(
            store.write(
                &SecretBundle::new(b"new-fixture".to_vec()).unwrap(),
                || Err(Error::Io)
            ),
            Err(Error::Io)
        );
        assert_eq!(
            fs::read(root.path().join("host-secrets.bundle")).unwrap(),
            before
        );
        assert_eq!(store.load().unwrap().unwrap().expose(), b"old-fixture");
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 3);
    }
}
