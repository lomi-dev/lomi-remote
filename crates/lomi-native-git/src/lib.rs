//! Native, approval-bound Git execution for qualified desktop hosts.
//!
//! Execution is currently qualified only on macOS ARM64. Other hosts can use
//! the neutral approval DTOs and query the qualification flag, but must not
//! treat the engine as available there.

pub mod types;
pub use lomi_native_project_files::{
    NativeProjectDirectory, NativeProjectErrorCode as ErrorCode, validate_relative,
};

#[cfg(unix)]
mod plan;
#[cfg(unix)]
pub use plan::PreparedNativeGitPlan;

/// Whether this target has the pinned native Git execution implementation.
pub const fn qualified() -> bool {
    cfg!(all(target_os = "macos", target_arch = "aarch64"))
}

#[cfg(unix)]
pub(crate) fn require_qualified() -> Result<(), ErrorCode> {
    if qualified() {
        Ok(())
    } else {
        Err(ErrorCode::HostUnqualified)
    }
}

#[cfg(unix)]
pub mod git_execution;
#[cfg(unix)]
pub mod git_read;

#[cfg(any(unix, windows))]
#[cfg_attr(windows, allow(dead_code))]
mod process_tree;
