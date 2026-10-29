//! Native account selection and fresh selected-account process launch.
//!
//! These helpers do not resolve or create a profile. Callers must choose and
//! validate the account before deriving profile paths or opening Host state.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::ExitStatus,
};

#[cfg(unix)]
#[path = "unix/setup_context.rs"]
mod native;
#[cfg(windows)]
#[path = "windows/setup_context.rs"]
mod native;

#[cfg(windows)]
pub use native::WindowsLogonCredential;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnixAccount {
    uid: u32,
    gid: u32,
    name: String,
    home: PathBuf,
}

impl UnixAccount {
    pub fn uid(&self) -> u32 {
        self.uid
    }

    pub fn gid(&self) -> u32 {
        self.gid
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn home(&self) -> &Path {
        &self.home
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsAccount {
    sid: String,
    name: String,
    home: PathBuf,
}

impl WindowsAccount {
    pub fn sid(&self) -> &str {
        &self.sid
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn home(&self) -> &Path {
        &self.home
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectedAccount {
    Unix(UnixAccount),
    Windows(WindowsAccount),
}

impl SelectedAccount {
    pub fn name(&self) -> &str {
        match self {
            Self::Unix(account) => account.name(),
            Self::Windows(account) => account.name(),
        }
    }

    pub fn home(&self) -> &Path {
        match self {
            Self::Unix(account) => account.home(),
            Self::Windows(account) => account.home(),
        }
    }

    pub fn unix(&self) -> Option<&UnixAccount> {
        match self {
            Self::Unix(account) => Some(account),
            Self::Windows(_) => None,
        }
    }

    pub fn windows(&self) -> Option<&WindowsAccount> {
        match self {
            Self::Windows(account) => Some(account),
            Self::Unix(_) => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentAccount {
    is_root: bool,
    selected: Option<SelectedAccount>,
}

impl CurrentAccount {
    pub fn is_root(&self) -> bool {
        self.is_root
    }

    /// Root is observable as the current principal, but never returned as a
    /// selectable Host account.
    pub fn selected(&self) -> Option<&SelectedAccount> {
        self.selected.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountCreationConsent {
    Confirmed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidAccount,
    AccountNotFound,
    RootCannotBeSelected,
    DifferentAccountRequiresFreshProcess,
    DifferentAccountRequiresNativeLogon,
    AccountProfileRequired,
    AdministratorRequired,
    NativeIdentityUnavailable,
    ProcessOwnershipUnavailable,
    InvalidExecutable,
    SpawnFailed,
    AccountCreationFailed,
    OperationUncertain,
    Unsupported,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidAccount => "SETUP_ACCOUNT_INVALID",
            Self::AccountNotFound => "SETUP_ACCOUNT_NOT_FOUND",
            Self::RootCannotBeSelected => "SETUP_ROOT_CANNOT_OWN_HOST",
            Self::DifferentAccountRequiresFreshProcess => {
                "SETUP_ACCOUNT_REQUIRES_FRESH_SELECTED_ACCOUNT_PROCESS"
            }
            Self::DifferentAccountRequiresNativeLogon => {
                "SETUP_ACCOUNT_REQUIRES_NATIVE_LOGON_CREDENTIALS"
            }
            Self::AccountProfileRequired => "SETUP_ACCOUNT_PROFILE_REQUIRED",
            Self::AdministratorRequired => "SETUP_ACCOUNT_ADMINISTRATOR_REQUIRED",
            Self::NativeIdentityUnavailable => "SETUP_NATIVE_ACCOUNT_IDENTITY_UNAVAILABLE",
            Self::ProcessOwnershipUnavailable => "SETUP_CHILD_PROCESS_OWNERSHIP_UNAVAILABLE",
            Self::InvalidExecutable => "SETUP_EXECUTABLE_INVALID",
            Self::SpawnFailed => "SETUP_SELECTED_ACCOUNT_PROCESS_FAILED",
            Self::AccountCreationFailed => "SETUP_DEDICATED_ACCOUNT_CREATION_FAILED",
            Self::OperationUncertain => "SETUP_ACCOUNT_OPERATION_UNCERTAIN",
            Self::Unsupported => "SETUP_ACCOUNT_CONTEXT_UNSUPPORTED",
        })
    }
}

impl std::error::Error for Error {}

/// Capture native process identity. Unix root is represented by `is_root`
/// with no Host-selectable account; no environment variable supplies identity.
pub fn current_account() -> Result<CurrentAccount, Error> {
    native::current_account()
}

/// Resolve an explicitly selected Unix login name through the native account
/// database. UID 0 is never a valid selected Host account.
#[cfg(unix)]
pub fn select_unix_account(name: &str) -> Result<SelectedAccount, Error> {
    native::select_unix_account(name)
}

/// Resolve an explicitly selected Windows account name through native SID
/// lookup and its SID-bound profile registration.
#[cfg(windows)]
pub fn select_windows_account(account_name: &str) -> Result<SelectedAccount, Error> {
    native::select_windows_account(account_name)
}

/// Select the current principal when it is an ordinary Host account.
pub fn select_current_account() -> Result<SelectedAccount, Error> {
    current_account()?
        .selected
        .ok_or(Error::RootCannotBeSelected)
}

/// Re-resolve a selected identity immediately before profile work or spawn.
/// A non-root Unix caller may continue only as its own real/effective/saved
/// identity. Windows accepts only the current native SID.
pub fn validate_selection(account: &SelectedAccount) -> Result<(), Error> {
    native::validate_selection(account)
}

/// Start a fresh process with a cleared, bounded environment under the
/// selected account. Unix callers must be root; ordinary users selecting
/// themselves continue in their current process.
pub fn reexec_as_selected(
    account: &SelectedAccount,
    executable: &Path,
    arguments: &[OsString],
) -> Result<ExitStatus, Error> {
    native::reexec_as_selected(account, executable, arguments)
}

/// On Linux, copy this running executable into a sealed root-owned memfd and
/// start it under an explicitly selected account. This is intended for a
/// short first-install continuation when the current executable lives in a
/// root-only directory; the child receives no root authority after exec.
#[cfg(target_os = "linux")]
pub fn reexec_sealed_current_as_selected(
    account: &SelectedAccount,
    arguments: &[OsString],
) -> Result<ExitStatus, Error> {
    native::reexec_sealed_current_as_selected(account, arguments)
}

/// Validate the root-created sealed executable descriptor used by the Linux
/// selected-account first-install continuation. The descriptor must refer to
/// the current executable image and is marked close-on-exec after validation.
#[cfg(target_os = "linux")]
pub fn validate_sealed_selected_executable(fd: i32) -> Result<(), Error> {
    native::validate_sealed_selected_executable(fd)
}

/// Create a fresh Windows process under an explicitly selected account using
/// native credential logon. The caller must obtain credentials through an
/// explicit secure prompt; credentials are never persisted or inherited.
#[cfg(windows)]
pub fn reexec_windows_as_selected(
    account: &SelectedAccount,
    credential: &WindowsLogonCredential,
    executable: &Path,
    arguments: &[OsString],
) -> Result<ExitStatus, Error> {
    native::reexec_windows_as_selected(account, credential, executable, arguments)
}

/// Create a dedicated Linux account only after an explicit user confirmation.
/// The platform chooses the native home path and never chowns a project path.
#[cfg(target_os = "linux")]
pub fn create_dedicated_account(
    name: &str,
    consent: AccountCreationConsent,
) -> Result<SelectedAccount, Error> {
    native::create_dedicated_account(name, consent)
}
