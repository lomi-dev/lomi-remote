//! Managed logon entry; markers are published under the actual host owner lock.
use crate::HostError;
use lomi_platform::service_windows_login::ManagedRun;
use std::{cell::RefCell, path::Path};
use uuid::Uuid;
pub fn run_registered(registration: &Path, installation: Uuid) -> Result<(), HostError> {
    let managed =
        ManagedRun::prepare(registration, installation).map_err(|_| HostError::InvalidProfile)?;
    let profile = managed.profile().to_path_buf();
    let managed = RefCell::new(managed);
    super::unix::run_with_managed_callbacks(
        &profile,
        |runtime| {
            managed
                .borrow_mut()
                .ready(runtime)
                .map_err(|_| HostError::Unavailable)
        },
        |result| {
            managed
                .borrow_mut()
                .finish(result.is_ok())
                .map_err(|_| HostError::Cleanup)
        },
    )
}
