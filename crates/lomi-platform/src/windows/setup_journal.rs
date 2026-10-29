use super::{Error as PlatformError, PrivateProfile, open_regular};
use crate::setup_journal::{Error, MAX_BYTES};
use std::{
    fs,
    io::{Read, Write},
    os::windows::io::AsRawHandle,
    path::Path,
};
use windows_sys::Win32::{
    Foundation::*,
    Storage::FileSystem::{
        LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, MOVEFILE_REPLACE_EXISTING,
        MOVEFILE_WRITE_THROUGH, MoveFileExW,
    },
    System::IO::OVERLAPPED,
};

const LOCK_FILE: &str = "setup.lock";
const JOURNAL_FILE: &str = "setup.journal";
const TEMP_FILE: &str = "setup.journal.tmp";

pub(crate) struct NativeStore {
    profile: PrivateProfile,
    _lock: fs::File,
    sid: String,
}

impl NativeStore {
    pub(crate) fn open(path: &Path) -> Result<Self, Error> {
        let profile = PrivateProfile::open(path, true).map_err(map_profile_error)?;
        let sid = profile.sid.clone();
        let lock_path = profile.path.join(LOCK_FILE);
        let lock = open_regular(&lock_path, true, true, &sid).map_err(map_profile_error)?;
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        if unsafe {
            LockFileEx(
                lock.as_raw_handle(),
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        } == 0
        {
            return if unsafe { GetLastError() } == ERROR_LOCK_VIOLATION {
                Err(Error::Busy)
            } else {
                Err(Error::Storage)
            };
        }
        profile.check_current().map_err(map_profile_error)?;
        Ok(Self {
            profile,
            _lock: lock,
            sid,
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
        validate_existing(&self.profile, &self.sid, JOURNAL_FILE)?;
        remove_validated_temp(&self.profile, &self.sid)?;

        let temporary = self.profile.path.join(TEMP_FILE);
        let output = self.profile.path.join(JOURNAL_FILE);
        let mut file =
            open_regular(&temporary, true, true, &self.sid).map_err(map_profile_error)?;
        file.set_len(0).map_err(|_| Error::Storage)?;
        let outcome = (|| {
            file.write_all(bytes).map_err(|_| Error::Storage)?;
            file.sync_all().map_err(|_| Error::Storage)?;
            let metadata = file.metadata().map_err(|_| Error::Storage)?;
            if metadata.len() != bytes.len() as u64 {
                return Err(Error::Storage);
            }
            self.profile.check_current().map_err(map_profile_error)?;
            drop(file);
            if unsafe {
                MoveFileExW(
                    wide(&temporary).as_ptr(),
                    wide(&output).as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            } == 0
            {
                return Err(Error::Storage);
            }
            self.profile.check_current().map_err(map_profile_error)
        })();
        if outcome.is_err() {
            remove_validated_temp(&self.profile, &self.sid)?;
        }
        outcome
    }
}

fn validate_existing(profile: &PrivateProfile, sid: &str, file_name: &str) -> Result<(), Error> {
    match open_regular(&profile.path.join(file_name), false, false, sid) {
        Ok(file) => {
            if file.metadata().map_err(|_| Error::Storage)?.len() > MAX_BYTES as u64 {
                return Err(Error::TooLarge);
            }
            Ok(())
        }
        Err(PlatformError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(map_profile_error(error)),
    }
}

fn remove_validated_temp(profile: &PrivateProfile, sid: &str) -> Result<(), Error> {
    let path = profile.path.join(TEMP_FILE);
    match open_regular(&path, false, false, sid) {
        Ok(file) => {
            drop(file);
            fs::remove_file(&path).map_err(|_| Error::Storage)?;
            profile.check_current().map_err(map_profile_error)
        }
        Err(PlatformError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(map_profile_error(error)),
    }
}

fn wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str().encode_wide().chain(Some(0)).collect()
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
    let path = profile.path.join(JOURNAL_FILE);
    let file = match open_regular(&path, false, false, &profile.sid) {
        Ok(file) => file,
        Err(PlatformError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(map_profile_error(error)),
    };
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
