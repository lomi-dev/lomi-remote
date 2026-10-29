//! Descriptor-relative filesystem operations for native project files.
//!
//! This crate contains no application protocol, GUI, or host-service types.

mod types;
pub use types::*;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{
    open_absolute_directory, open_file_at, rename_exclusive, snapshot_file, stamp_file,
    validate_relative,
};
#[cfg(unix)]
mod trash;
#[cfg(unix)]
pub use trash::from_ticket;

#[cfg(not(unix))]
mod unsupported;
#[cfg(not(unix))]
pub use unsupported::from_ticket;
#[cfg(not(unix))]
pub use unsupported::{
    open_absolute_directory, open_file_at, rename_exclusive, snapshot_file, stamp_file,
    validate_relative,
};
