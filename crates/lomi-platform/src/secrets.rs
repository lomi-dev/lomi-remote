//! Host-only secret storage boundary. No enrollment, transport or local terminal effects.
use zeroize::Zeroizing;

pub const MAX_BUNDLE_BYTES: usize = 32 * 1024;

/// One opaque host-secret bundle. No serialization or implicit string conversion.
/// The caller must also protect and erase any original input or exposed copies.
pub struct SecretBundle(Zeroizing<Vec<u8>>);
impl SecretBundle {
    pub fn new(bytes: Vec<u8>) -> Result<Self, Error> {
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty() || bytes.len() > MAX_BUNDLE_BYTES {
            return Err(Error::InvalidBundle);
        }
        Ok(Self(bytes))
    }
    #[cfg(any(unix, windows))]
    pub(crate) fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}
impl std::fmt::Debug for SecretBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBundle([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    ProtectedFile,
    MacOsKeychain,
    WindowsDpapi,
    SecretService,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageState {
    Unconfigured,
    Available,
    Locked,
    Unavailable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderStatus {
    pub kind: Option<ProviderKind>,
    pub state: StorageState,
}
/// Construct only after a trusted setup choice explains that OS permissions
/// protect plaintext bytes; administrators and disk backups can read them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedFileAcknowledgement {
    OsPermissionsOnly,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    Unconfigured,
    MacOsKeychain,
    WindowsDpapi,
    SecretService,
    ProtectedFile(ProtectedFileAcknowledgement),
}
impl Selection {
    /// Selection alone never probes or creates files. Only opening a concrete
    /// provider can qualify its availability in the current account context.
    pub fn status(self) -> ProviderStatus {
        let kind = match self {
            Self::Unconfigured => None,
            Self::MacOsKeychain => Some(ProviderKind::MacOsKeychain),
            Self::WindowsDpapi => Some(ProviderKind::WindowsDpapi),
            Self::SecretService => Some(ProviderKind::SecretService),
            Self::ProtectedFile(_) => Some(ProviderKind::ProtectedFile),
        };
        ProviderStatus {
            kind,
            state: if kind.is_none() {
                StorageState::Unconfigured
            } else {
                StorageState::Unavailable
            },
        }
    }
}
/// Closed diagnostics: no paths, provider messages, input bytes or IO payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Unconfigured,
    Locked,
    Unavailable,
    InvalidBundle,
    InvalidStorage,
    Io,
    /// Publication may have completed without confirmed durability: inspect
    /// before retrying. No provider automatically retries an uncertain commit.
    CommitUncertain,
}
impl Error {
    pub fn state(self) -> StorageState {
        match self {
            Self::Unconfigured => StorageState::Unconfigured,
            Self::Locked => StorageState::Locked,
            _ => StorageState::Unavailable,
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unconfigured => "SECRET_STORAGE_UNCONFIGURED",
            Self::Locked => "SECRET_STORAGE_LOCKED",
            Self::Unavailable => "SECRET_STORAGE_UNAVAILABLE",
            Self::InvalidBundle => "INVALID_SECRET_BUNDLE",
            Self::InvalidStorage => "INVALID_SECRET_STORAGE",
            Self::Io => "SECRET_STORAGE_IO_ERROR",
            Self::CommitUncertain => "SECRET_STORAGE_COMMIT_UNCERTAIN",
        })
    }
}
impl std::error::Error for Error {}

pub trait SecretStorage {
    fn status(&self) -> ProviderStatus;
    fn load(&self) -> Result<Option<SecretBundle>, Error>;
    fn replace(&mut self, bundle: &SecretBundle) -> Result<(), Error>;
    /// Remove only this selected provider's exact bundle while preserving its
    /// persistent lock and encryption identity. Implementations must validate
    /// the provider and return CommitUncertain if removal durability is unknown.
    fn clear(&mut self) -> Result<(), Error> {
        Err(Error::Unavailable)
    }
}
