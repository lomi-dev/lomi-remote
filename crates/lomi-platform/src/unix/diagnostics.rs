//! Unix read-only diagnostics built on the same descriptor validation used by
//! local IPC. This module intentionally does not acquire `owner.lock`.

use super::{Error, PrivateProfile, reject_acl_grants_readonly};
use crate::diagnostics::{ExecutableObservation, ProfileObservation};
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::{fs::MetadataExt, fs::OpenOptionsExt},
    path::Path,
};

fn profile_error(error: Error) -> ProfileObservation {
    match error {
        Error::Io(error) if error.kind() == io::ErrorKind::NotFound => ProfileObservation::Missing,
        Error::Io(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            ProfileObservation::PermissionDenied
        }
        Error::InvalidProfile => ProfileObservation::Invalid,
        Error::PermissionDenied => ProfileObservation::PermissionDenied,
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

fn executable_error(error: io::Error) -> ExecutableObservation {
    match error.kind() {
        io::ErrorKind::NotFound => ExecutableObservation::Missing,
        io::ErrorKind::PermissionDenied => ExecutableObservation::PermissionDenied,
        _ => ExecutableObservation::Unavailable,
    }
}

pub(crate) fn inspect_executable(path: &Path) -> ExecutableObservation {
    if !path.is_absolute() {
        return ExecutableObservation::Invalid;
    }
    let canonical = match path.canonicalize() {
        Ok(path) => path,
        Err(error) => return executable_error(error),
    };
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&canonical)
    {
        Ok(file) => file,
        Err(error) => return executable_error(error),
    };
    inspect_open_executable(&canonical, &file)
}

fn inspect_open_executable(path: &Path, file: &File) -> ExecutableObservation {
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => return executable_error(error),
    };
    let named = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return executable_error(error),
    };
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || !named.is_file()
        || metadata.dev() != named.dev()
        || metadata.ino() != named.ino()
        || metadata.nlink() == 0
        || (metadata.uid() != 0 && metadata.uid() != uid)
        || metadata.mode() & 0o111 == 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o6000 != 0
    {
        return ExecutableObservation::Invalid;
    }
    match reject_acl_grants_readonly(file) {
        Ok(()) => ExecutableObservation::ProtectedFile,
        Err(Error::PermissionDenied) => ExecutableObservation::PermissionDenied,
        Err(_) => ExecutableObservation::Invalid,
    }
}
