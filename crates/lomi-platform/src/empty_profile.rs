//! Affine proof of an empty private Host reservation. A missing database alone
//! never establishes this state, and acquiring the proof creates no files.
#[cfg(unix)]
use crate::unix as native;
#[cfg(windows)]
use crate::windows as native;
use std::{fmt, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Unavailable,
    NotEmpty,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "EMPTY_HOST_RESERVATION_UNAVAILABLE",
            Self::NotEmpty => "HOST_PROFILE_NOT_EMPTY",
        })
    }
}
impl std::error::Error for Error {}

/// Keeps the exact native account/profile owner lock until image removal has
/// finished. There is no constructor from a path assertion, identity UUID,
/// serialized record, missing-file observation, or caller-supplied boolean.
pub struct EmptyHostProfile {
    owner: native::OwnerLock,
}
impl EmptyHostProfile {
    pub fn acquire(path: &Path) -> Result<Self, Error> {
        let owner = native::OwnerLock::acquire_existing(path).map_err(|_| Error::Unavailable)?;
        owner
            .check_empty_reservation()
            .map_err(|_| Error::NotEmpty)?;
        Ok(Self { owner })
    }
    pub fn profile_path(&self) -> &Path {
        self.owner.profile().path()
    }
    /// The exact native directory object held by this proof. A resumed worker
    /// must acquire its own proof and compare this observation; these numbers
    /// alone never establish that a profile is empty or currently locked.
    pub fn profile_identity(&self) -> (u64, u64) {
        self.owner.profile_identity()
    }
    pub fn recheck(&self) -> Result<(), Error> {
        self.owner
            .check_empty_reservation()
            .map_err(|_| Error::NotEmpty)
    }
}
impl fmt::Debug for EmptyHostProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EmptyHostProfile([native owner lock held])")
    }
}
