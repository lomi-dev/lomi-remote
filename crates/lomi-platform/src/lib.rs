//! Native local transport, process/service adapters and explicit host-secret stores.
//! No network listener or GUI runtime.
//!
//! The owner lock is held for the entire host lifetime, including SQLite shutdown.
//! Peers are authenticated by the operating system before any JSON is accepted.
#[cfg(target_os = "macos")]
pub mod native_evidence_runtime;
#[cfg(unix)]
pub mod process;
#[cfg(target_os = "linux")]
pub mod service_linux;
#[cfg(target_os = "macos")]
pub mod service_macos;
#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
mod windows_login_start_policy;
#[cfg(windows)]
pub mod windows_password;
#[cfg(windows)]
pub use windows::service as service_windows;
#[cfg(windows)]
pub use windows::task as service_windows_login;

mod ipc_result;
pub mod secrets;
#[cfg(target_os = "linux")]
pub use unix::secret_service;

pub mod diagnostics;
#[cfg(any(unix, windows))]
pub mod empty_profile;
pub mod installation;
pub mod noexec_process;
pub mod public_config;
pub mod service_observation;
pub mod setup_context;
pub mod setup_journal;

/// Shared profile location for the TUI, desktop and headless host. Callers must
/// use the same native user context; a GUI-specific profile creates a second
/// owner and cannot recover the canonical workspace identities.
pub fn default_profile() -> Option<std::path::PathBuf> {
    use std::{env, path::PathBuf};
    #[cfg(target_os = "windows")]
    {
        env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .map(|path| path.join(".lomiRemote"))
    }
    #[cfg(target_os = "macos")]
    {
        env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .map(|path| path.join("Library/Application Support/LomiRemote"))
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .map(|path| path.join("lomiremote"))
            .or_else(|| {
                env::var_os("HOME")
                    .map(PathBuf::from)
                    .filter(|path| path.is_absolute())
                    .map(|path| path.join(".local/share/lomiremote"))
            })
    }
}
