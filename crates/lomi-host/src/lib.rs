//! Headless host coordinator shared by manual and operating-system service modes.
pub use lomi_host_store::{Identity, PROFILE_SCHEMA_VERSION, SetupInspection, SetupObservation};
#[cfg(any(unix, windows))]
pub mod git_credentials;
#[cfg(any(unix, windows))]
mod profile_purge;
pub use lomi_git::GitCredentials;
#[cfg(any(unix, windows))]
pub use lomi_host_store::MaintenanceProfileObservation;
#[cfg(any(unix, windows))]
pub use profile_purge::{
    ProfilePurgeError, ProfilePurgeOutcome, fence_maintenance_profile, inspect_maintenance_profile,
    purge_host_profile,
};

/// Observe an existing profile without creating it or recovering SQLite. Live
/// owners are reported separately and must be queried through authenticated IPC.
#[cfg(any(unix, windows))]
pub fn inspect_setup(profile: &std::path::Path) -> SetupInspection {
    lomi_host_store::HostStore::inspect_setup(&profile.join("host.sqlite3"))
}
#[cfg(not(any(unix, windows)))]
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostError {
    Unavailable,
    Busy,
    InvalidProfile,
    Storage,
    Cleanup,
    Unsupported,
    NonRootAccountRequired,
    IdentityMismatch,
}

/// Internal same-binary Git network executor. The native parent owns the
/// process and the bounded private stdin/stdout grant; this is never a remote
/// RPC or a path/credential-bearing command-line interface.
pub fn internal_git_worker() -> i32 {
    lomi_git::internal_network_worker()
}

/// Dispatch only exact private custody/helper modes before normal Host or
/// desktop argument parsing. Helpers accept their grants on inherited pipes;
/// this entry never accepts a repository, command, or environment in argv.
pub fn internal_native_entry() -> Option<i32> {
    if let Some(code) = lomi_native_custody::entry() {
        return Some(code);
    }
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--internal-native-git-plan")) {
        return None;
    }
    Some(if arguments.next().is_none() {
        native_git_worker::entry()
    } else {
        2
    })
}

mod native_git_worker;
impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "HOST_UNAVAILABLE",
            Self::Busy => "HOST_BUSY",
            Self::InvalidProfile => "INVALID_PROFILE",
            Self::Storage => "HOST_STORAGE_ERROR",
            Self::Cleanup => "HOST_CLEANUP_INCOMPLETE",
            Self::Unsupported => "UNSUPPORTED_PLATFORM",
            Self::NonRootAccountRequired => "NONROOT_HOST_ACCOUNT_REQUIRED",
            Self::IdentityMismatch => "HOST_IDENTITY_MISMATCH",
        })
    }
}
impl std::error::Error for HostError {}

#[cfg(test)]
mod testsupport;
#[cfg(any(unix, windows))]
mod unix;
#[cfg(windows)]
mod windows_launch;
#[cfg(windows)]
pub mod windows_service;
#[cfg(windows)]
pub mod windows_task;
#[cfg(any(unix, windows))]
pub use unix::{
    initialize_profile, run, run_bound, run_bound_identity, run_existing, start, start_bound,
    start_existing, start_identity_bound, stop, stop_bound,
};
#[cfg(any(unix, windows))]
pub fn suggested_host_display_name(
    host_id: Option<lomi_remote_protocol::HostId>,
) -> lomi_remote_protocol::ipc::LocalHostName {
    unix::suggested_host_display_name(host_id)
}
#[cfg(not(any(unix, windows)))]
pub fn initialize_profile(_profile: &Path) -> Result<lomi_host_store::Identity, HostError> {
    Err(HostError::Unsupported)
}
#[cfg(not(any(unix, windows)))]
pub fn run(_profile: &Path) -> Result<(), HostError> {
    Err(HostError::Unsupported)
}
#[cfg(not(any(unix, windows)))]
pub fn run_existing(_profile: &Path) -> Result<(), HostError> {
    Err(HostError::Unsupported)
}
#[cfg(not(any(unix, windows)))]
pub fn run_bound(
    _profile: &Path,
    _expected_host_id: lomi_remote_protocol::HostId,
) -> Result<(), HostError> {
    Err(HostError::Unsupported)
}
#[cfg(not(any(unix, windows)))]
pub fn start(_executable: &Path, _profile: &Path) -> Result<(), HostError> {
    Err(HostError::Unsupported)
}
#[cfg(not(any(unix, windows)))]
pub fn start_existing(_executable: &Path, _profile: &Path) -> Result<(), HostError> {
    Err(HostError::Unsupported)
}
#[cfg(not(any(unix, windows)))]
pub fn start_bound(
    _executable: &Path,
    _profile: &Path,
    _expected_host_id: lomi_remote_protocol::HostId,
) -> Result<(), HostError> {
    Err(HostError::Unsupported)
}
#[cfg(not(any(unix, windows)))]
pub fn stop(_profile: &Path) -> Result<(), HostError> {
    Err(HostError::Unsupported)
}
#[cfg(not(any(unix, windows)))]
pub fn stop_bound(
    _profile: &Path,
    _expected_host_id: lomi_remote_protocol::HostId,
) -> Result<(), HostError> {
    Err(HostError::Unsupported)
}
