//! Verify staged release executables before the activation journal or service
//! executable changes. This is independent of the installed custodian's peer
//! identity: a replacement must satisfy the release's compiled Team pin.

use super::{
    Error, File, FromRawFd, MAX_EXECUTABLE_BYTES, MetadataExt, Path, Result, STRICT_FLAGS,
    SecRequirement, SecStaticCode, TCFType, c, signing_information,
};
use core_foundation::url::CFURL;
use security_framework::os::macos::code_signing::Flags;
use std::os::fd::AsRawFd;

/// Require an Apple Developer ID Application signature from the exact pinned
/// Team on an owned, private staged executable. No install/profile is created.
pub fn verify_release_image_team(path: &Path, expected_team: &str) -> Result<()> {
    if expected_team.len() != 10
        || !expected_team
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        || !path.is_absolute()
        || path.canonicalize().map_err(|_| Error::Invalid)? != path
    {
        return Err(Error::Invalid);
    }
    let parent_path = path.parent().ok_or(Error::Invalid)?;
    let name = c(path.file_name().ok_or(Error::Invalid)?)?;
    let parent =
        crate::unix::PrivateProfile::open(parent_path, false).map_err(|_| Error::Conflict)?;
    let open = || -> Result<File> {
        let fd = unsafe {
            libc::openat(
                parent.directory().as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(Error::Conflict);
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    };
    let file = open()?;
    let before = file.metadata().map_err(|_| Error::Conflict)?;
    if !before.is_file()
        || before.uid() != unsafe { libc::geteuid() }
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || before.mode() & 0o500 != 0o500
        || before.len() == 0
        || before.len() > MAX_EXECUTABLE_BYTES
    {
        return Err(Error::Conflict);
    }
    crate::unix::reject_acl_grants(&file).map_err(|_| Error::Conflict)?;
    // Apple TN3127: the intermediate and leaf extensions distinguish Developer
    // ID Application from development, App Store and installer certificates.
    let requirement = format!(
        "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists \
         and certificate leaf[field.1.2.840.113635.100.6.1.13] exists \
         and certificate leaf[subject.OU] = \"{expected_team}\""
    );
    let requirement: SecRequirement = requirement.parse().map_err(|_| Error::Conflict)?;
    let code_path = CFURL::from_path(path, false).ok_or(Error::Conflict)?;
    let code = SecStaticCode::from_path(&code_path, Flags::NONE).map_err(|_| Error::Conflict)?;
    code.check_validity(STRICT_FLAGS, &requirement)
        .map_err(|_| Error::Conflict)?;
    let information = signing_information(code.as_CFTypeRef().cast())?;
    if information.identity.team_identifier != expected_team || information.main_executable != path
    {
        return Err(Error::Conflict);
    }
    parent.check_current().map_err(|_| Error::Conflict)?;
    let after = file.metadata().map_err(|_| Error::Conflict)?;
    let named = open()?.metadata().map_err(|_| Error::Conflict)?;
    let pin = |metadata: &std::fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.uid(),
            metadata.gid(),
            metadata.mode(),
            metadata.nlink(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    if pin(&before) != pin(&after) || pin(&before) != pin(&named) {
        return Err(Error::Conflict);
    }
    parent.check_current().map_err(|_| Error::Conflict)
}
