//! Owned Windows ConPTY backend. Unsupported targets deliberately expose no backend.
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;
