//! Public bytes under a held OwnerLock and pinned, private Windows ancestry.
//! One trusted owner/writer, not a hostile same-account name-substitution CAS.
//! Durability uses documented write-through same-volume rename plus file flush
//! and exact readback. No Unix directory-fsync equivalence is claimed.
use super::{
    Handle, Object, PrivateProfile, information, object, security, validate_security, wide,
};
use crate::public_config::{self, Configuration, Error};
use std::{
    fs::File,
    io::Write,
    mem,
    os::windows::io::{AsRawHandle, FromRawHandle},
    path::PathBuf,
    ptr,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use windows_sys::Win32::{
    Foundation::*, Security::*, Storage::FileSystem::*, System::Threading::*,
};

const NAME: &str = "host-public.toml";

// Opaque, non-Clone token. Confirmation can republish the exact same bytes to
// establish a new write-through namespace barrier and refresh only its private
// identity. No handle, guard or mutable source/configuration leaves this type.
pub struct Snapshot {
    identity: Mutex<Object>,
    bytes: Vec<u8>,
    configuration: Configuration,
    confirmed: AtomicBool,
}
impl Snapshot {
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }
    pub fn source(&self) -> &[u8] {
        &self.bytes
    }
    fn identity(&self) -> Result<Object, Error> {
        self.identity
            .lock()
            .map(|identity| *identity)
            .map_err(|_| Error::InvalidStorage)
    }
}
impl PartialEq for Snapshot {
    fn eq(&self, other: &Self) -> bool {
        // Copy one scalar at a time; comparing a token with itself cannot nest
        // the same mutex acquisition. Poison never compares as a valid token.
        matches!((self.identity(), other.identity()), (Ok(a), Ok(b)) if a == b)
            && self.bytes == other.bytes
            && self.configuration == other.configuration
    }
}
impl Eq for Snapshot {}
pub enum CommitOutcome {
    Committed(Snapshot),
    /// Publication was attempted. Token describes intended bytes/identity, not
    /// proof that the final name changed. Reload durable intent before recovery.
    Uncertain(Snapshot),
}
pub struct PublicFile<'a> {
    profile: &'a PrivateProfile,
}
impl<'a> PublicFile<'a> {
    pub fn new(profile: &'a PrivateProfile) -> Result<Self, Error> {
        let this = Self { profile };
        this.check()?;
        Ok(this)
    }
    fn check(&self) -> Result<(), Error> {
        // File operations must run under the same process account whose entire
        // ancestry is pinned. An impersonation token cannot select another ACL.
        let mut token = ptr::null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } != 0 {
            drop(Handle::new(token).map_err(|_| Error::InvalidStorage)?);
            return Err(Error::InvalidStorage);
        }
        if unsafe { GetLastError() } != ERROR_NO_TOKEN {
            return Err(Error::InvalidStorage);
        }
        if super::current_sid().map_err(|_| Error::InvalidStorage)? != self.profile.sid {
            return Err(Error::InvalidStorage);
        }
        self.profile
            .check_current()
            .map_err(|_| Error::InvalidStorage)?;
        for (index, directory) in self.profile._directories.iter().enumerate() {
            validate_security(
                directory.0,
                &self.profile.sid,
                index + 1 == self.profile._directories.len(),
                true,
            )
            .map_err(|_| Error::InvalidStorage)?;
        }
        let current =
            PrivateProfile::open(&self.profile.path, false).map_err(|_| Error::InvalidStorage)?;
        if current.identity != self.profile.identity {
            return Err(Error::InvalidStorage);
        }
        Ok(())
    }
    pub fn load(&self) -> Result<Option<Snapshot>, Error> {
        self.check()?;
        let path = self.profile.path.join(NAME);
        let mut file = match open_file(self.profile, &path, false, OPEN_EXISTING) {
            Ok(file) => file,
            Err(OpenError::Io(error))
                if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        let before = validate(&file, &self.profile.sid)?;
        let bytes = public_config::read_bytes(&mut file)?;
        let configuration = public_config::decode(&bytes)?;
        let after = validate(&file, &self.profile.sid)?;
        if !same_version(&before, &after) {
            return Err(Error::Stale);
        }
        let current = open_file(self.profile, &path, false, OPEN_EXISTING).map_err(Error::from)?;
        if !same_version(&after, &validate(&current, &self.profile.sid)?) {
            return Err(Error::Stale);
        }
        self.check()?;
        Ok(Some(Snapshot {
            identity: Mutex::new(object(&after)),
            bytes,
            configuration,
            confirmed: AtomicBool::new(false),
        }))
    }
    /// A loaded token has no proof of a previous namespace flush. Republish its
    /// exact bytes at the SAME revision via a new write-through rename, then
    /// refresh its private identity. This is recovery, never a new auth revision.
    pub fn confirm(&self, expected: &Snapshot) -> Result<(), Error> {
        if self.load()?.as_ref() != Some(expected) {
            return Err(Error::Stale);
        }
        if !expected.confirmed.load(Ordering::Acquire) {
            match self.publish_exact(
                Some(expected),
                &expected.configuration,
                expected.bytes.clone(),
                |_| Ok(()),
            )? {
                CommitOutcome::Committed(next) => {
                    *expected
                        .identity
                        .lock()
                        .map_err(|_| Error::InvalidStorage)? = next.identity()?;
                    expected.confirmed.store(true, Ordering::Release);
                }
                CommitOutcome::Uncertain(_) => return Err(Error::Io),
            }
        }
        let file = open_file(
            self.profile,
            &self.profile.path.join(NAME),
            true,
            OPEN_EXISTING,
        )
        .map_err(Error::from)?;
        if object(&validate(&file, &self.profile.sid)?) != expected.identity()? {
            return Err(Error::Stale);
        }
        flush(&file)?;
        if self.load()?.as_ref() != Some(expected) {
            return Err(Error::Stale);
        }
        Ok(())
    }
    pub fn replace(
        &mut self,
        expected: Option<&Snapshot>,
        next: &Configuration,
    ) -> Result<CommitOutcome, Error> {
        self.replace_with(expected, next, |_| Ok(()))
    }
    fn replace_with(
        &self,
        expected: Option<&Snapshot>,
        next: &Configuration,
        checkpoint: impl FnMut(Step) -> Result<(), Error>,
    ) -> Result<CommitOutcome, Error> {
        let revision = expected.map_or(0, |old| old.configuration.revision);
        if revision.checked_add(1) != Some(next.revision) {
            return Err(Error::Stale);
        }
        self.publish_exact(expected, next, public_config::encode(next)?, checkpoint)
    }
    fn publish_exact(
        &self,
        expected: Option<&Snapshot>,
        next: &Configuration,
        bytes: Vec<u8>,
        mut checkpoint: impl FnMut(Step) -> Result<(), Error>,
    ) -> Result<CommitOutcome, Error> {
        if self.load()?.as_ref() != expected {
            return Err(Error::Stale);
        }
        let path = self
            .profile
            .path
            .join(format!(".host-public-{}.tmp", uuid::Uuid::new_v4()));
        let file = open_file(self.profile, &path, true, CREATE_NEW).map_err(Error::from)?;
        let identity = object(&validate(&file, &self.profile.sid)?);
        let mut temp = Temporary {
            profile: self.profile,
            path,
            file: Some(file),
            identity,
            attempted: false,
        };
        checkpoint(Step::AfterTemp)?;
        let file = temp.file.as_mut().ok_or(Error::Io)?;
        file.write_all(&bytes).map_err(|_| Error::Io)?;
        flush(file)?;
        checkpoint(Step::BeforeRename)?;
        if self.load()?.as_ref() != expected {
            return Err(Error::Stale);
        }
        let current =
            open_file(self.profile, &temp.path, false, OPEN_EXISTING).map_err(Error::from)?;
        if object(&validate(&current, &self.profile.sid)?) != identity {
            return Err(Error::Stale);
        }
        drop(current);
        self.check()?;
        // No DELETE sharing: close only the fully flushed private temporary at
        // the boundary. Ancestry/OwnerLock remain held through rename/readback.
        drop(temp.file.take());
        temp.attempted = true;
        let snapshot = Snapshot {
            identity: Mutex::new(identity),
            bytes,
            configuration: next.clone(),
            confirmed: AtomicBool::new(false),
        };
        let flags = MOVEFILE_WRITE_THROUGH
            | if expected.is_some() {
                MOVEFILE_REPLACE_EXISTING
            } else {
                0
            };
        // Same parent/volume, never COPY_ALLOWED, never truncate the previous
        // file. Even a zero return is uncertain after this syscall is invoked.
        if unsafe {
            MoveFileExW(
                wide(&temp.path).as_ptr(),
                wide(self.profile.path.join(NAME)).as_ptr(),
                flags,
            )
        } == 0
        {
            return Ok(CommitOutcome::Uncertain(snapshot));
        }
        if checkpoint(Step::AfterRename).is_err() {
            return Ok(CommitOutcome::Uncertain(snapshot));
        }
        let committed = match open_file(
            self.profile,
            &self.profile.path.join(NAME),
            true,
            OPEN_EXISTING,
        ) {
            Ok(file) => file,
            Err(_) => return Ok(CommitOutcome::Uncertain(snapshot)),
        };
        if validate(&committed, &self.profile.sid).is_err()
            || information(committed.as_raw_handle())
                .ok()
                .map(|info| object(&info))
                != Some(identity)
            || flush(&committed).is_err()
        {
            return Ok(CommitOutcome::Uncertain(snapshot));
        }
        drop(committed);
        if self.load().ok().flatten().as_ref() != Some(&snapshot) {
            return Ok(CommitOutcome::Uncertain(snapshot));
        }
        snapshot.confirmed.store(true, Ordering::Release);
        Ok(CommitOutcome::Committed(snapshot))
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    AfterTemp,
    BeforeRename,
    AfterRename,
}
enum OpenError {
    Io(std::io::Error),
    Invalid,
}
impl From<OpenError> for Error {
    fn from(error: OpenError) -> Self {
        match error {
            OpenError::Io(_) => Error::Io,
            OpenError::Invalid => Error::InvalidStorage,
        }
    }
}
fn open_file(
    profile: &PrivateProfile,
    path: &std::path::Path,
    write: bool,
    creation: u32,
) -> Result<File, OpenError> {
    let descriptor = security(&profile.sid, false).map_err(|_| OpenError::Invalid)?;
    let handle = Handle::new(unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            GENERIC_READ | READ_CONTROL | if write { GENERIC_WRITE } else { 0 },
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &descriptor.attributes,
            creation,
            FILE_FLAG_OPEN_REPARSE_POINT | if write { FILE_FLAG_WRITE_THROUGH } else { 0 },
            ptr::null_mut(),
        )
    })
    .map_err(OpenError::Io)?;
    let raw = handle.0;
    mem::forget(handle);
    let file = unsafe { File::from_raw_handle(raw) };
    validate(&file, &profile.sid).map_err(|_| OpenError::Invalid)?;
    Ok(file)
}
fn validate(file: &File, sid: &str) -> Result<BY_HANDLE_FILE_INFORMATION, Error> {
    let info = information(file.as_raw_handle()).map_err(|_| Error::InvalidStorage)?;
    if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
        || info.nNumberOfLinks != 1
    {
        return Err(Error::InvalidStorage);
    }
    validate_security(file.as_raw_handle(), sid, true, false).map_err(|_| Error::InvalidStorage)?;
    Ok(info)
}
fn same_version(a: &BY_HANDLE_FILE_INFORMATION, b: &BY_HANDLE_FILE_INFORMATION) -> bool {
    object(a) == object(b)
        && a.nNumberOfLinks == b.nNumberOfLinks
        && a.nFileSizeHigh == b.nFileSizeHigh
        && a.nFileSizeLow == b.nFileSizeLow
        && a.ftLastWriteTime.dwHighDateTime == b.ftLastWriteTime.dwHighDateTime
        && a.ftLastWriteTime.dwLowDateTime == b.ftLastWriteTime.dwLowDateTime
        && a.dwFileAttributes == b.dwFileAttributes
}
fn flush(file: &File) -> Result<(), Error> {
    if unsafe { FlushFileBuffers(file.as_raw_handle()) } == 0 {
        Err(Error::Io)
    } else {
        Ok(())
    }
}
struct Temporary<'a> {
    profile: &'a PrivateProfile,
    path: PathBuf,
    file: Option<File>,
    identity: Object,
    attempted: bool,
}
impl Drop for Temporary<'_> {
    fn drop(&mut self) {
        if self.attempted {
            return;
        }
        drop(self.file.take());
        let same = open_file(self.profile, &self.path, false, OPEN_EXISTING)
            .ok()
            .and_then(|file| information(file.as_raw_handle()).ok())
            .is_some_and(|info| object(&info) == self.identity);
        if same && self.profile.check_current().is_ok() {
            unsafe {
                DeleteFileW(wide(&self.path).as_ptr());
            }
        }
    }
}
