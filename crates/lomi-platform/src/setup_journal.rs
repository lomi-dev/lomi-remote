//! Private, bounded storage for the resumable first-run coordinator.
//!
//! The caller owns the versioned journal schema. This layer only provides a
//! single fixed file, a per-profile lock, and durable replacement.
use std::path::Path;

#[cfg(unix)]
use crate::unix::setup_journal::NativeStore;
#[cfg(windows)]
use crate::windows::setup_journal::NativeStore;

pub const MAX_BYTES: usize = 16 * 1024;
pub const JOURNAL_VERSION: u64 = 1;

/// Attenuation only: once first-run setup records a Host ID, every native
/// startup mode must refuse replacing it with a freshly initialized identity.
/// The atomic owner-private journal is read without taking setup.lock. This
/// value grants no credential, consent, or Cloud authority.
pub fn read_expected_host_id(
    profile: &Path,
) -> Result<Option<lomi_remote_protocol::HostId>, Error> {
    #[cfg(unix)]
    let bytes = crate::unix::setup_journal::read_existing(profile)?;
    #[cfg(windows)]
    let bytes = crate::windows::setup_journal::read_existing(profile)?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    #[derive(serde::Deserialize)]
    struct Expectation {
        version: u64,
        #[serde(rename = "hostId")]
        host_id: serde_json::Value,
    }
    // Required fields and duplicate known fields are checked by serde. Other
    // setup fields belong to the coordinator and convey no startup authority.
    let record: Expectation = serde_json::from_slice(&bytes).map_err(|_| Error::Storage)?;
    if record.version != JOURNAL_VERSION {
        return Err(Error::Storage);
    }
    match record.host_id {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(value) => value.try_into().map(Some).map_err(|_| Error::Storage),
        _ => Err(Error::Storage),
    }
}

/// Closed diagnostics avoid exposing profile paths or OS error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidProfile,
    Busy,
    TooLarge,
    Storage,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidProfile => "SETUP_JOURNAL_PROFILE_INVALID",
            Self::Busy => "SETUP_JOURNAL_BUSY",
            Self::TooLarge => "SETUP_JOURNAL_TOO_LARGE",
            Self::Storage => "SETUP_JOURNAL_STORAGE_UNAVAILABLE",
        })
    }
}

impl std::error::Error for Error {}

/// A private setup record store with its independent lock held until drop.
pub struct SetupJournalStore {
    inner: NativeStore,
}

impl SetupJournalStore {
    /// Observe an existing atomic setup record without creating a profile or
    /// taking setup.lock. No setup transition may be based on this alone.
    pub fn read_existing(profile: &Path) -> Result<Option<Vec<u8>>, Error> {
        #[cfg(unix)]
        { crate::unix::setup_journal::read_existing(profile) }
        #[cfg(windows)]
        { crate::windows::setup_journal::read_existing(profile) }
    }
    /// Create or open the already-selected account's private Host profile.
    /// The platform implementation rejects foreign ownership and unsafe paths.
    pub fn open(profile: &Path) -> Result<Self, Error> {
        Ok(Self {
            inner: NativeStore::open(profile)?,
        })
    }

    /// Read the complete bounded journal, or return `None` on first run.
    pub fn read(&self) -> Result<Option<Vec<u8>>, Error> {
        self.inner.read()
    }

    /// Atomically replace the journal and durably flush file and directory.
    pub fn replace_atomic(&self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        self.inner.replace_atomic(bytes)
    }
}
