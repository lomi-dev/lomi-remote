//! Startup barrier shared by installed host entrypoints. The updater journals
//! an activation before replacing any member of the signed executable set.
//! A crash leaves the journal in place; only verified recovery may remove it.
use std::{fmt, io, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationError {
    Incomplete,
    Unavailable,
}

impl fmt::Display for ActivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Incomplete => "INSTALLATION_ACTIVATION_INCOMPLETE",
            Self::Unavailable => "INSTALLATION_STATE_UNAVAILABLE",
        })
    }
}
impl std::error::Error for ActivationError {}

/// Never read, adopt, or repair a journal from a running host. Even a malformed
/// file, directory or symlink at this name blocks startup. No cached absence is
/// retained: each executable entrypoint checks before opening its profile or
/// starting a process. The updater separately holds the private profile owner
/// lock across activation, preventing a check/start race from reaching effects.
pub fn check_executable(executable: &Path) -> Result<(), ActivationError> {
    let directory = executable.parent().ok_or(ActivationError::Unavailable)?;
    match std::fs::symlink_metadata(directory.join("activation.pending")) {
        Ok(_) => Err(ActivationError::Incomplete),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ActivationError::Unavailable),
    }
}

pub fn check_current_executable() -> Result<(), ActivationError> {
    let executable = std::env::current_exe().map_err(|_| ActivationError::Unavailable)?;
    check_executable(&executable)
}
