//! Read-only, redacted observations used by the local doctor.
//!
//! These helpers do not create a profile, acquire the host lifetime lock, or
//! return the inspected path. A successful profile observation means only that
//! the profile directory currently passes the native ownership/ACL checks; it
//! does not claim that the database or service is healthy.

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileObservation {
    Private,
    Missing,
    PermissionDenied,
    Invalid,
    Unavailable,
}

/// An executable-shaped file which passes the platform's read-only path and
/// ownership checks. This does not launch it or prove its runtime behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutableObservation {
    ProtectedFile,
    Missing,
    PermissionDenied,
    Invalid,
    Unavailable,
}

pub fn inspect_profile(path: &Path) -> ProfileObservation {
    #[cfg(unix)]
    {
        crate::unix::diagnostics::inspect_profile(path)
    }
    #[cfg(windows)]
    {
        crate::windows::diagnostics::inspect_profile(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        ProfileObservation::Unavailable
    }
}

pub fn inspect_executable(path: &Path) -> ExecutableObservation {
    #[cfg(unix)]
    {
        crate::unix::diagnostics::inspect_executable(path)
    }
    #[cfg(windows)]
    {
        crate::windows::diagnostics::inspect_executable(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        ExecutableObservation::Unavailable
    }
}

/// Native standard shell candidates for an explicit setup choice. This does
/// not search an inherited PATH or execute any candidate.
pub fn standard_shell_candidates() -> Vec<std::path::PathBuf> {
    #[cfg(unix)]
    let paths: Vec<std::path::PathBuf> = ["/bin/bash", "/bin/zsh", "/bin/sh", "/usr/bin/fish"]
        .iter()
        .map(std::path::PathBuf::from)
        .collect();
    #[cfg(windows)]
    let paths: Vec<std::path::PathBuf> = {
        let mut directory = vec![0u16; 32768];
        let length = unsafe {
            windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
                directory.as_mut_ptr(),
                directory.len() as u32,
            )
        } as usize;
        if length == 0 || length >= directory.len() {
            return Vec::new();
        }
        let Ok(directory) = String::from_utf16(&directory[..length]) else {
            return Vec::new();
        };
        vec![std::path::PathBuf::from(directory).join(r"WindowsPowerShell\v1.0\powershell.exe")]
    };
    #[cfg(not(any(unix, windows)))]
    let paths: Vec<std::path::PathBuf> = Vec::new();
    paths
        .into_iter()
        .filter(|path| {
            inspect_executable(path) == ExecutableObservation::ProtectedFile
                && can_execute_as_current_account(path)
        })
        .collect()
}

/// Current-account execute access is separate from immutable-file protection.
/// This never executes a shell or changes the process token.
pub fn can_execute_as_current_account(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        if unsafe { libc::getuid() != libc::geteuid() || libc::getgid() != libc::getegid() } {
            return false;
        }
        let Ok(path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        unsafe { libc::access(path.as_ptr(), libc::X_OK) == 0 }
    }
    #[cfg(windows)]
    {
        crate::windows::diagnostics::can_execute(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        false
    }
}

/// Canonical profile spelling used by native profile/journal/service bindings.
/// Windows extended-path prefixes are normalized by the same native policy as
/// PrivateProfile, rather than compared to a different Rust path spelling.
pub fn canonical_profile_path(path: &Path) -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    {
        crate::windows::diagnostics::canonical_profile_path(path)
    }
    #[cfg(not(windows))]
    {
        path.canonicalize().ok()
    }
}
