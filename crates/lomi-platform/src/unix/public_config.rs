//! Pinned-directory atomic replacement under the caller's lifetime OwnerLock.
//! One owner and one writer are required; this is not a same-UID attacker CAS.
use super::{PrivateProfile, object, private_regular};
use crate::public_config::{self, Configuration, Error};
use std::{
    ffi::CStr,
    fs::File,
    io::{self, Write},
    os::fd::{AsRawFd, FromRawFd},
};

const NAME: &CStr = c"host-public.toml";

/// Bounded exact bytes avoid accepting same-revision edits or inode substitution.
/// No Debug implementation exposes manually inserted unknown TOML values.
#[derive(Clone, PartialEq, Eq)]
pub struct Snapshot {
    identity: super::Object,
    bytes: Vec<u8>,
    configuration: Configuration,
}
impl Snapshot {
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }
    pub fn source(&self) -> &[u8] {
        &self.bytes
    }
}
pub enum CommitOutcome {
    Committed(Snapshot),
    /// Rename happened. Reconcile this revision; never blindly roll back/retry.
    Uncertain(Snapshot),
}
pub struct PublicFile<'a> {
    profile: &'a PrivateProfile,
}
impl<'a> PublicFile<'a> {
    /// The profile must belong to the host's still-held OwnerLock.
    pub fn new(profile: &'a PrivateProfile) -> Result<Self, Error> {
        let this = Self { profile };
        this.check()?;
        Ok(this)
    }
    fn check(&self) -> Result<(), Error> {
        self.profile
            .check_current()
            .map_err(|_| Error::InvalidStorage)?;
        check_acl_ancestry(self.profile)
    }
    pub fn load(&self) -> Result<Option<Snapshot>, Error> {
        self.check()?;
        let mut file = match open_at(self.profile, NAME, libc::O_RDONLY) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(Error::InvalidStorage),
        };
        validate(&file)?;
        let before = file.metadata().map_err(|_| Error::Io)?;
        let bytes = public_config::read_bytes(&mut file)?;
        let configuration = public_config::decode(&bytes)?;
        validate(&file)?;
        let after = file.metadata().map_err(|_| Error::Io)?;
        use std::os::unix::fs::MetadataExt;
        if before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err(Error::Stale);
        }
        let current =
            open_at(self.profile, NAME, libc::O_RDONLY).map_err(|_| Error::InvalidStorage)?;
        validate(&current)?;
        if object(&after) != object(&current.metadata().map_err(|_| Error::Io)?) {
            return Err(Error::Stale);
        }
        self.check()?;
        Ok(Some(Snapshot {
            identity: object(&after),
            bytes,
            configuration,
        }))
    }
    /// Confirm exact already-published bytes and metadata, then sync file and
    /// directory. Required when reconciling an earlier uncertain rename.
    pub fn confirm(&self, expected: &Snapshot) -> Result<(), Error> {
        if self.load()?.as_ref() != Some(expected) {
            return Err(Error::Stale);
        }
        let file =
            open_at(self.profile, NAME, libc::O_RDONLY).map_err(|_| Error::InvalidStorage)?;
        validate(&file)?;
        if object(&file.metadata().map_err(|_| Error::Io)?) != expected.identity {
            return Err(Error::Stale);
        }
        file.sync_all().map_err(|_| Error::Io)?;
        self.profile.directory.sync_all().map_err(|_| Error::Io)?;
        if self.load()?.as_ref() != Some(expected) {
            return Err(Error::Stale);
        }
        Ok(())
    }
    /// None means expected absence. Replacements require the exact loaded token.
    /// This primitive does not authorize an auth/provider/endpoint transition.
    pub fn replace(
        &mut self,
        expected: Option<&Snapshot>,
        next: &Configuration,
    ) -> Result<CommitOutcome, Error> {
        self.replace_with(expected, next, |_| Ok(()))
    }
    fn replace_with(
        &mut self,
        expected: Option<&Snapshot>,
        next: &Configuration,
        mut checkpoint: impl FnMut(Step) -> Result<(), Error>,
    ) -> Result<CommitOutcome, Error> {
        let bytes = public_config::encode(next)?;
        let revision = expected.map_or(0, |old| old.configuration.revision);
        if revision.checked_add(1) != Some(next.revision) {
            return Err(Error::Stale);
        }
        if self.load()?.as_ref() != expected {
            return Err(Error::Stale);
        }
        let name = std::ffi::CString::new(format!(".host-public-{}.tmp", uuid::Uuid::new_v4()))
            .map_err(|_| Error::Io)?;
        let file = open_at(
            self.profile,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
        .map_err(|_| Error::Io)?;
        let mut temp = Temporary {
            profile: self.profile,
            name: &name,
            file,
            published: false,
        };
        validate(&temp.file)?;
        checkpoint(Step::AfterTemp)?;
        temp.file.write_all(&bytes).map_err(|_| Error::Io)?;
        temp.file.sync_all().map_err(|_| Error::Io)?;
        checkpoint(Step::BeforeRename)?;
        if self.load()?.as_ref() != expected {
            return Err(Error::Stale);
        }
        validate(&temp.file)?;
        let current =
            open_at(self.profile, &name, libc::O_RDONLY).map_err(|_| Error::InvalidStorage)?;
        validate(&current)?;
        let identity = object(&temp.file.metadata().map_err(|_| Error::Io)?);
        if object(&current.metadata().map_err(|_| Error::Io)?) != identity {
            return Err(Error::Stale);
        }
        self.check()?;
        if unsafe {
            libc::renameat(
                self.profile.directory.as_raw_fd(),
                name.as_ptr(),
                self.profile.directory.as_raw_fd(),
                NAME.as_ptr(),
            )
        } != 0
        {
            return Err(Error::Io);
        }
        temp.published = true;
        let snapshot = Snapshot {
            identity,
            bytes,
            configuration: next.clone(),
        };
        if checkpoint(Step::AfterRename).is_err() || self.profile.directory.sync_all().is_err() {
            return Ok(CommitOutcome::Uncertain(snapshot));
        }
        Ok(CommitOutcome::Committed(snapshot))
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    AfterTemp,
    BeforeRename,
    AfterRename,
}
fn open_at(profile: &PrivateProfile, name: &CStr, flags: i32) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            profile.directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn validate(file: &File) -> Result<(), Error> {
    private_regular(file).map_err(|_| Error::InvalidStorage)?;
    no_posix_acl(file)
}
#[cfg(target_os = "linux")]
fn no_posix_acl(file: &File) -> Result<(), Error> {
    for name in [c"system.posix_acl_access", c"system.posix_acl_default"] {
        if unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) } >= 0
        {
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
fn check_acl_ancestry(profile: &PrivateProfile) -> Result<(), Error> {
    let mut directory = File::open("/").map_err(|_| Error::Io)?;
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
    if object(&directory.metadata().map_err(|_| Error::Io)?) != profile.identity {
        return Err(Error::InvalidStorage);
    }
    Ok(())
}
struct Temporary<'a> {
    profile: &'a PrivateProfile,
    name: &'a CStr,
    file: File,
    published: bool,
}
impl Drop for Temporary<'_> {
    fn drop(&mut self) {
        if !self.published
            && let Ok(current) = open_at(self.profile, self.name, libc::O_RDONLY)
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
