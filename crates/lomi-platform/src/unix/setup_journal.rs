use super::{Error as PlatformError, PrivateProfile, private_regular};
use crate::setup_journal::{Error, MAX_BYTES};
use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    path::Path,
};

const LOCK_FILE: &str = "setup.lock";
const JOURNAL_FILE: &str = "setup.journal";
const TEMP_FILE: &str = "setup.journal.tmp";

pub(crate) struct NativeStore {
    profile: PrivateProfile,
    _lock: File,
}

impl NativeStore {
    pub(crate) fn open(path: &Path) -> Result<Self, Error> {
        let profile = PrivateProfile::open(path, true).map_err(map_profile_error)?;
        let lock = open_profile_file(&profile, LOCK_FILE, libc::O_RDWR | libc::O_CREAT, true)
            .map_err(OpenFileError::into_platform)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock {
                Err(Error::Busy)
            } else {
                Err(Error::Storage)
            };
        }
        profile.check_current().map_err(map_profile_error)?;
        Ok(Self {
            profile,
            _lock: lock,
        })
    }

    pub(crate) fn read(&self) -> Result<Option<Vec<u8>>, Error> {
        read_profile(&self.profile)
    }

    pub(crate) fn replace_atomic(&self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        self.profile.check_current().map_err(map_profile_error)?;
        validate_existing(&self.profile, JOURNAL_FILE)?;
        remove_validated_temp(&self.profile)?;

        let mut temp = open_profile_file(
            &self.profile,
            TEMP_FILE,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            true,
        )
        .map_err(OpenFileError::into_platform)?;
        let outcome = (|| {
            temp.write_all(bytes).map_err(|_| Error::Storage)?;
            temp.sync_all().map_err(|_| Error::Storage)?;
            private_regular(&temp).map_err(map_profile_error)?;
            let metadata = temp.metadata().map_err(|_| Error::Storage)?;
            if metadata.len() != bytes.len() as u64 {
                return Err(Error::Storage);
            }
            self.profile.check_current().map_err(map_profile_error)?;
            let from = name(TEMP_FILE)?;
            let to = name(JOURNAL_FILE)?;
            if unsafe {
                libc::renameat(
                    self.profile.directory.as_raw_fd(),
                    from.as_ptr(),
                    self.profile.directory.as_raw_fd(),
                    to.as_ptr(),
                )
            } != 0
            {
                return Err(Error::Storage);
            }
            self.profile
                .directory
                .sync_all()
                .map_err(|_| Error::Storage)?;
            self.profile.check_current().map_err(map_profile_error)
        })();
        drop(temp);
        if outcome.is_err() {
            remove_validated_temp(&self.profile)?;
        }
        outcome
    }
}

fn name(value: &str) -> Result<CString, Error> {
    CString::new(value).map_err(|_| Error::Storage)
}

fn open_profile_file(
    profile: &PrivateProfile,
    file_name: &str,
    flags: i32,
    create: bool,
) -> Result<File, OpenFileError> {
    profile
        .check_current()
        .map_err(map_profile_error)
        .map_err(OpenFileError::Platform)?;
    let name = name(file_name).map_err(OpenFileError::Platform)?;
    let flags = flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    let fd = unsafe {
        libc::openat(
            profile.directory.as_raw_fd(),
            name.as_ptr(),
            flags,
            if create { 0o600 } else { 0 },
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return if error.kind() == std::io::ErrorKind::NotFound {
            Err(OpenFileError::NotFound)
        } else {
            Err(OpenFileError::Platform(Error::Storage))
        };
    }
    let file = unsafe { File::from_raw_fd(fd) };
    private_regular(&file)
        .map_err(map_profile_error)
        .map_err(OpenFileError::Platform)?;
    profile
        .check_current()
        .map_err(map_profile_error)
        .map_err(OpenFileError::Platform)?;
    Ok(file)
}

fn validate_existing(profile: &PrivateProfile, file_name: &str) -> Result<(), Error> {
    match open_profile_file(profile, file_name, libc::O_RDONLY, false) {
        Ok(file) => {
            private_regular(&file).map_err(map_profile_error)?;
            if file.metadata().map_err(|_| Error::Storage)?.len() > MAX_BYTES as u64 {
                return Err(Error::TooLarge);
            }
            Ok(())
        }
        Err(OpenFileError::NotFound) => Ok(()),
        Err(OpenFileError::Platform(error)) => Err(error),
    }
}

fn remove_validated_temp(profile: &PrivateProfile) -> Result<(), Error> {
    match open_profile_file(profile, TEMP_FILE, libc::O_RDONLY, false) {
        Ok(file) => {
            private_regular(&file).map_err(map_profile_error)?;
            drop(file);
            let name = name(TEMP_FILE)?;
            if unsafe { libc::unlinkat(profile.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(Error::Storage);
            }
            profile.check_current().map_err(map_profile_error)
        }
        Err(OpenFileError::NotFound) => Ok(()),
        Err(OpenFileError::Platform(error)) => Err(error),
    }
}

enum OpenFileError {
    NotFound,
    Platform(Error),
}

impl OpenFileError {
    fn into_platform(self) -> Error {
        match self {
            Self::NotFound => Error::Storage,
            Self::Platform(error) => error,
        }
    }
}

fn map_profile_error(error: PlatformError) -> Error {
    match error {
        PlatformError::Busy => Error::Busy,
        PlatformError::InvalidProfile | PlatformError::PermissionDenied => Error::InvalidProfile,
        _ => Error::Storage,
    }
}

/// Startup reads only an already-existing atomic journal. It must not take
/// setup.lock: an interactive wizard can be waiting for this Host to start.
pub(crate) fn read_existing(path: &Path) -> Result<Option<Vec<u8>>, Error> {
    let profile = PrivateProfile::open(path, false).map_err(map_profile_error)?;
    read_profile(&profile)
}

fn read_profile(profile: &PrivateProfile) -> Result<Option<Vec<u8>>, Error> {
    profile.check_current().map_err(map_profile_error)?;
    let file = match open_profile_file(&profile, JOURNAL_FILE, libc::O_RDONLY, false) {
        Ok(file) => file,
        Err(OpenFileError::NotFound) => return Ok(None),
        Err(OpenFileError::Platform(error)) => return Err(error),
    };
    private_regular(&file).map_err(map_profile_error)?;
    let length = file.metadata().map_err(|_| Error::Storage)?.len();
    if length > MAX_BYTES as u64 {
        return Err(Error::TooLarge);
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Storage)?;
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(Error::TooLarge);
    }
    profile.check_current().map_err(map_profile_error)?;
    Ok(Some(bytes))
}
