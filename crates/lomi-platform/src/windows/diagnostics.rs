//! Windows read-only diagnostics built on the same handle and DACL checks used
//! by local IPC. These helpers never create a profile or acquire a host lock.

use super::{Error, PrivateProfile, current_sid, information, open_path, validate_security};
use crate::diagnostics::{ExecutableObservation, ProfileObservation};
use std::{io, path::Path};
use windows_sys::Win32::{
    Foundation::HANDLE,
    Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_BEGIN, ReadFile,
        SetFilePointerEx,
    },
};

pub(crate) fn can_execute(path: &Path) -> bool {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_EXECUTE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    };
    let Ok(file) = std::fs::OpenOptions::new()
        .access_mode(FILE_EXECUTE | FILE_READ_ATTRIBUTES)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    else {
        return false;
    };
    file.metadata().is_ok_and(|info| {
        info.is_file() && info.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
    })
}

pub(crate) fn canonical_profile_path(path: &Path) -> Option<std::path::PathBuf> {
    super::normalized(&path.canonicalize().ok()?).ok()
}

fn profile_error(error: Error) -> ProfileObservation {
    match error {
        Error::Io(error) if error.kind() == io::ErrorKind::NotFound => ProfileObservation::Missing,
        Error::Io(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            ProfileObservation::PermissionDenied
        }
        Error::PermissionDenied => ProfileObservation::PermissionDenied,
        Error::InvalidProfile => ProfileObservation::Invalid,
        Error::Busy
        | Error::InvalidEndpoint
        | Error::InvalidFrame
        | Error::Incompatible
        | Error::Deadline
        | Error::Io(_) => ProfileObservation::Unavailable,
    }
}

pub(crate) fn inspect_profile(path: &Path) -> ProfileObservation {
    match PrivateProfile::open(path, false) {
        Ok(profile) => match profile.check_current() {
            Ok(()) => ProfileObservation::Private,
            Err(error) => profile_error(error),
        },
        Err(error) => profile_error(error),
    }
}

fn executable_error(error: Error) -> ExecutableObservation {
    match error {
        Error::Io(error) if error.kind() == io::ErrorKind::NotFound => {
            ExecutableObservation::Missing
        }
        Error::Io(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            ExecutableObservation::PermissionDenied
        }
        Error::PermissionDenied => ExecutableObservation::PermissionDenied,
        Error::InvalidProfile => ExecutableObservation::Invalid,
        Error::Busy
        | Error::InvalidEndpoint
        | Error::InvalidFrame
        | Error::Incompatible
        | Error::Deadline
        | Error::Io(_) => ExecutableObservation::Unavailable,
    }
}

pub(crate) fn inspect_executable(path: &Path) -> ExecutableObservation {
    let path = match super::normalized(path) {
        Ok(path) => path,
        Err(error) => return executable_error(error),
    };
    let sid = match current_sid() {
        Ok(sid) => sid,
        Err(error) => return executable_error(error),
    };
    let handle = match open_path(&path, false, false, false, &sid) {
        Ok(handle) => handle,
        Err(error) => return executable_error(error),
    };
    let info = match information(handle.0) {
        Ok(info) => info,
        Err(error) => return executable_error(error.into()),
    };
    if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        return ExecutableObservation::Invalid;
    }
    let size = ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64;
    match has_pe_signature(handle.0, size) {
        Ok(true) => {}
        Ok(false) => return ExecutableObservation::Invalid,
        Err(error) => return executable_error(error),
    }
    match validate_security(handle.0, &sid, false, false) {
        Ok(()) => ExecutableObservation::ProtectedFile,
        Err(Error::PermissionDenied) => ExecutableObservation::PermissionDenied,
        Err(_) => ExecutableObservation::Invalid,
    }
}

fn has_pe_signature(handle: HANDLE, size: u64) -> std::result::Result<bool, Error> {
    if size < 64 {
        return Ok(false);
    }
    let mut dos_header = [0_u8; 64];
    let mut read = 0_u32;
    super::check(unsafe {
        ReadFile(
            handle,
            dos_header.as_mut_ptr(),
            dos_header.len() as u32,
            &mut read,
            std::ptr::null_mut(),
        )
    })?;
    if read as usize != dos_header.len() || &dos_header[..2] != b"MZ" {
        return Ok(false);
    }
    let pe_offset = u32::from_le_bytes(dos_header[0x3c..0x40].try_into().unwrap()) as u64;
    if pe_offset < 64
        || pe_offset > 1024 * 1024
        || pe_offset.checked_add(4).map_or(true, |end| end > size)
    {
        return Ok(false);
    }
    super::check(unsafe {
        SetFilePointerEx(handle, pe_offset as i64, std::ptr::null_mut(), FILE_BEGIN)
    })?;
    let mut signature = [0_u8; 4];
    let mut read = 0_u32;
    super::check(unsafe {
        ReadFile(
            handle,
            signature.as_mut_ptr(),
            signature.len() as u32,
            &mut read,
            std::ptr::null_mut(),
        )
    })?;
    Ok(read == signature.len() as u32 && signature == *b"PE\0\0")
}
