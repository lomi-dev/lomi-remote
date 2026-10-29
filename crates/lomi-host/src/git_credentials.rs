//! Native, URL-scoped Git credentials. Nothing in this module is a remote RPC.
//! A credential has its own private provider profile, so replacing it cannot
//! overwrite the host enrollment/rotation bundle. Provider failure never falls
//! back to an ambient Git helper, environment variable, or plaintext store.
use lomi_git::{GitCredentialProvider, GitCredentials, RemoteCredentialBinding};
use lomi_platform::secrets::{self, SecretBundle, SecretStorage, Selection};
use lomi_remote_protocol::ipc::{IpcProfileId, LocalAuthConfiguration, LocalAuthProvider};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use lomi_platform::unix as platform;
#[cfg(windows)]
use lomi_platform::windows as platform;

const MAGIC: &[u8; 8] = b"LMGIT001";
const CLEARED: &[u8; 8] = b"LMGITDEL";
const MAX_ENTRIES: usize = 128;
const MAX_FIELD: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitCredentialPurgeError {
    Uncertain,
}

fn valid_slot_name(name: &str) -> bool {
    name.len() == 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_slot_key(name: &str) -> Result<[u8; 32], secrets::Error> {
    if !valid_slot_name(name) {
        return Err(secrets::Error::InvalidStorage);
    }
    let mut key = [0u8; 32];
    for (index, pair) in name.as_bytes().chunks_exact(2).enumerate() {
        let digit = |value: u8| match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            _ => None,
        };
        let high = digit(pair[0]).ok_or(secrets::Error::InvalidStorage)?;
        let low = digit(pair[1]).ok_or(secrets::Error::InvalidStorage)?;
        key[index] = (high << 4) | low;
    }
    Ok(key)
}

pub struct HostGitCredentials {
    profile: PathBuf,
    configuration: LocalAuthConfiguration,
}

impl HostGitCredentials {
    /// Pure construction: native provider access happens on the Git worker,
    /// after the caller has dropped its owner/domain turns.
    pub fn new(
        profile: PathBuf,
        configuration: LocalAuthConfiguration,
    ) -> Result<Self, secrets::Error> {
        if !profile.is_absolute() || configuration.validate().is_err() {
            return Err(secrets::Error::InvalidStorage);
        }
        Ok(Self {
            profile,
            configuration,
        })
    }

    /// Clear exact, recognized URL-slot bundles after the profile purge has
    /// excluded the Host and all writer ledgers. The namespace lock blocks
    /// concurrent credential writes; slot directories and persistent owner
    /// locks are retained. Unknown entries are never removed.
    pub fn clear_profile_credentials(
        owner: &platform::OwnerLock,
        configuration: Option<&LocalAuthConfiguration>,
    ) -> Result<(), GitCredentialPurgeError> {
        let profile = owner.profile().path();
        let namespace_path = profile.join("git-credentials");
        match fs::symlink_metadata(&namespace_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            _ => return Err(GitCredentialPurgeError::Uncertain),
        }
        let namespace = platform::OwnerLock::acquire_existing(&namespace_path)
            .map_err(|_| GitCredentialPurgeError::Uncertain)?;
        if namespace.profile().path() != namespace_path {
            return Err(GitCredentialPurgeError::Uncertain);
        }

        let mut slots = Vec::new();
        let mut uncertain = false;
        let mut entries = fs::read_dir(namespace.profile().path())
            .map_err(|_| GitCredentialPurgeError::Uncertain)?;
        let mut entry_count = 0usize;
        for entry in entries.by_ref().take(MAX_ENTRIES + 2) {
            entry_count = entry_count.saturating_add(1);
            if entry_count > MAX_ENTRIES + 1 {
                uncertain = true;
            }
            let entry = entry.map_err(|_| GitCredentialPurgeError::Uncertain)?;
            let name = entry.file_name();
            if name == "owner.lock" {
                let metadata = fs::symlink_metadata(entry.path())
                    .map_err(|_| GitCredentialPurgeError::Uncertain)?;
                if !metadata.file_type().is_file() {
                    uncertain = true;
                }
                continue;
            }
            let Some(name) = name.to_str() else {
                uncertain = true;
                continue;
            };
            if !valid_slot_name(name) {
                uncertain = true;
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|_| GitCredentialPurgeError::Uncertain)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                uncertain = true;
                continue;
            }
            if slots.len() == MAX_ENTRIES {
                uncertain = true;
                continue;
            }
            slots.push(name.to_owned());
        }
        if slots.len() > MAX_ENTRIES {
            return Err(GitCredentialPurgeError::Uncertain);
        }

        if slots.is_empty() {
            return if uncertain {
                Err(GitCredentialPurgeError::Uncertain)
            } else {
                Ok(())
            };
        }
        let Some(configuration) = configuration else {
            return Err(GitCredentialPurgeError::Uncertain);
        };
        let credentials = Self::new(profile.to_path_buf(), configuration.clone())
            .map_err(|_| GitCredentialPurgeError::Uncertain)?;
        for slot in slots {
            match credentials.clear_slot(&slot) {
                Ok(()) => {}
                Err(_) => uncertain = true,
            }
        }
        if uncertain {
            Err(GitCredentialPurgeError::Uncertain)
        } else {
            Ok(())
        }
    }

    /// Read-only completed-attempt replay check. A prior purge may be replayed
    /// as complete only while every recognized slot remains logically empty.
    pub fn profile_has_live_credentials(
        owner: &platform::OwnerLock,
        configuration: &LocalAuthConfiguration,
    ) -> Result<bool, GitCredentialPurgeError> {
        let profile = owner.profile().path();
        let namespace_path = profile.join("git-credentials");
        match fs::symlink_metadata(&namespace_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            _ => return Err(GitCredentialPurgeError::Uncertain),
        }
        let namespace = platform::OwnerLock::acquire_existing(&namespace_path)
            .map_err(|_| GitCredentialPurgeError::Uncertain)?;
        if namespace.profile().path() != namespace_path {
            return Err(GitCredentialPurgeError::Uncertain);
        }

        let mut slots = Vec::new();
        let mut entries = fs::read_dir(namespace.profile().path())
            .map_err(|_| GitCredentialPurgeError::Uncertain)?;
        let mut entry_count = 0usize;
        for entry in entries.by_ref().take(MAX_ENTRIES + 2) {
            entry_count = entry_count.saturating_add(1);
            if entry_count > MAX_ENTRIES + 1 {
                return Err(GitCredentialPurgeError::Uncertain);
            }
            let entry = entry.map_err(|_| GitCredentialPurgeError::Uncertain)?;
            let name = entry.file_name();
            if name == "owner.lock" {
                let metadata = fs::symlink_metadata(entry.path())
                    .map_err(|_| GitCredentialPurgeError::Uncertain)?;
                if !metadata.file_type().is_file() {
                    return Err(GitCredentialPurgeError::Uncertain);
                }
                continue;
            }
            let Some(name) = name.to_str() else {
                return Err(GitCredentialPurgeError::Uncertain);
            };
            if !valid_slot_name(name) {
                return Err(GitCredentialPurgeError::Uncertain);
            }
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|_| GitCredentialPurgeError::Uncertain)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(GitCredentialPurgeError::Uncertain);
            }
            if slots.len() == MAX_ENTRIES {
                return Err(GitCredentialPurgeError::Uncertain);
            }
            slots.push(name.to_owned());
        }
        let credentials = Self::new(profile.to_path_buf(), configuration.clone())
            .map_err(|_| GitCredentialPurgeError::Uncertain)?;
        for slot in slots {
            if credentials
                .slot_has_live_credential(&slot)
                .map_err(|_| GitCredentialPurgeError::Uncertain)?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn clear_slot(&self, name: &str) -> Result<(), secrets::Error> {
        if !valid_slot_name(name) {
            return Err(secrets::Error::InvalidStorage);
        }
        let key = decode_slot_key(name)?;
        let path = self.profile.join("git-credentials").join(name);
        let lock = platform::OwnerLock::acquire_existing(&path)
            .map_err(|_| secrets::Error::Unavailable)?;
        self.with_provider(&lock, key, |store| store.clear())
    }

    fn slot_has_live_credential(&self, name: &str) -> Result<bool, secrets::Error> {
        if !valid_slot_name(name) {
            return Err(secrets::Error::InvalidStorage);
        }
        let key = decode_slot_key(name)?;
        let path = self.profile.join("git-credentials").join(name);
        let lock = platform::OwnerLock::acquire_existing(&path)
            .map_err(|_| secrets::Error::Unavailable)?;
        self.with_provider(&lock, key, |store| {
            let Some(bundle) = store.load()? else {
                return Ok(false);
            };
            let bytes = bundle.expose();
            if bytes.len() == 40 && &bytes[..8] == CLEARED && bytes[8..40] == key {
                return Ok(false);
            }
            if bytes.len() >= 48 && &bytes[..8] == MAGIC && bytes[8..40] == key {
                return Ok(true);
            }
            Err(secrets::Error::InvalidBundle)
        })
    }

    fn key(url: &str) -> Result<([u8; 32], String), secrets::Error> {
        let url =
            lomi_git::canonical_credential_url(url).map_err(|_| secrets::Error::InvalidBundle)?;
        let mut hash = Sha256::new();
        hash.update(b"lomi.git.credentials.https.v1\0");
        hash.update(url.as_bytes());
        let digest: [u8; 32] = hash.finalize().into();
        let name = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok((digest, name))
    }

    fn with_provider<T>(
        &self,
        lock: &platform::OwnerLock,
        key: [u8; 32],
        run: impl FnOnce(&mut dyn SecretStorage) -> Result<T, secrets::Error>,
    ) -> Result<T, secrets::Error> {
        match self.configuration.provider {
            LocalAuthProvider::ProtectedFile => {
                #[cfg(unix)]
                {
                    let selection = Selection::ProtectedFile(
                        secrets::ProtectedFileAcknowledgement::OsPermissionsOnly,
                    );
                    let mut store =
                        platform::secrets::ProtectedFile::open(lock.profile(), selection)?;
                    run(&mut store)
                }
                #[cfg(windows)]
                {
                    let _ = (lock, key, run);
                    Err(secrets::Error::Unavailable)
                }
            }
            LocalAuthProvider::MacOsKeychain => {
                #[cfg(target_os = "macos")]
                {
                    // The keychain account is a domain-separated, URL-scoped
                    // UUID, independent from the enrollment profile identity.
                    let mut uuid = [0u8; 16];
                    uuid.copy_from_slice(&key[..16]);
                    uuid[6] = (uuid[6] & 0x0f) | 0x40;
                    uuid[8] = (uuid[8] & 0x3f) | 0x80;
                    let id = IpcProfileId::from_bytes(uuid)
                        .map_err(|_| secrets::Error::InvalidStorage)?;
                    let path = self
                        .configuration
                        .keychain_path
                        .as_ref()
                        .ok_or(secrets::Error::InvalidStorage)?;
                    let mut store = platform::keychain::MacOsKeychain::open(
                        lock.profile(),
                        Selection::MacOsKeychain,
                        id,
                        Path::new(path.as_str()),
                    )?;
                    run(&mut store)
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = (lock, key, run);
                    Err(secrets::Error::Unavailable)
                }
            }
            LocalAuthProvider::WindowsDpapi => {
                #[cfg(windows)]
                {
                    let mut store = platform::secrets::WindowsDpapi::open(
                        lock.profile(),
                        Selection::WindowsDpapi,
                    )?;
                    run(&mut store)
                }
                #[cfg(not(windows))]
                {
                    let _ = (lock, key, run);
                    Err(secrets::Error::Unavailable)
                }
            }
            LocalAuthProvider::LinuxSecretService => {
                #[cfg(target_os = "linux")]
                {
                    let mut uuid = [0u8; 16];
                    uuid.copy_from_slice(&key[..16]);
                    uuid[6] = (uuid[6] & 0x0f) | 0x40;
                    uuid[8] = (uuid[8] & 0x3f) | 0x80;
                    let id = IpcProfileId::from_bytes(uuid)
                        .map_err(|_| secrets::Error::InvalidStorage)?;
                    let mut store = lomi_platform::secret_service::SecretService::open(
                        lock.profile(),
                        Selection::SecretService,
                        id,
                    )?;
                    run(&mut store)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (lock, key, run);
                    Err(secrets::Error::Unavailable)
                }
            }
        }
    }

    fn read(&self, url: &str) -> Result<Option<GitCredentials>, secrets::Error> {
        let (key, name) = Self::key(url)?;
        let path = self.profile.join("git-credentials").join(name);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => (),
            _ => return Err(secrets::Error::InvalidStorage),
        }
        let lock = platform::OwnerLock::acquire(&path).map_err(|_| secrets::Error::Unavailable)?;
        self.with_provider(&lock, key, |store| {
            let Some(bundle) = store.load()? else {
                return Ok(None);
            };
            let bytes = bundle.expose();
            if bytes.len() == 40 && &bytes[..8] == CLEARED && bytes[8..40] == key {
                return Ok(None);
            }
            if bytes.len() < 48 || &bytes[..8] != MAGIC || bytes[8..40] != key {
                return Err(secrets::Error::InvalidBundle);
            }
            let username = u32::from_be_bytes(
                bytes[40..44]
                    .try_into()
                    .map_err(|_| secrets::Error::InvalidBundle)?,
            ) as usize;
            let password = u32::from_be_bytes(
                bytes[44..48]
                    .try_into()
                    .map_err(|_| secrets::Error::InvalidBundle)?,
            ) as usize;
            if username == 0
                || password == 0
                || username > MAX_FIELD
                || password > MAX_FIELD
                || bytes.len() != 48 + username + password
            {
                return Err(secrets::Error::InvalidBundle);
            }
            Ok(Some(GitCredentials {
                username: bytes[48..48 + username].to_vec().into(),
                password: bytes[48 + username..].to_vec().into(),
            }))
        })
    }

    /// Explicit native setup only. `None` replaces the bundle with a tombstone
    /// instead of deleting an OS keychain item belonging to another context.
    pub fn replace(
        &self,
        url: &str,
        credentials: Option<GitCredentials>,
    ) -> Result<(), secrets::Error> {
        let (key, name) = Self::key(url)?;
        if let Some(value) = credentials.as_ref() {
            for field in [&value.username, &value.password] {
                if field.is_empty()
                    || field.len() > MAX_FIELD
                    || field.iter().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
                {
                    return Err(secrets::Error::InvalidBundle);
                }
                std::str::from_utf8(field).map_err(|_| secrets::Error::InvalidBundle)?;
            }
        }
        // The namespace lock serializes bounded slot creation, not Git work.
        // Its ancestry and every final leaf are validated by native profiles.
        let namespace = platform::OwnerLock::acquire(&self.profile.join("git-credentials"))
            .map_err(|_| secrets::Error::InvalidStorage)?;
        let path = namespace.profile().path().join(name);
        if !path
            .try_exists()
            .map_err(|_| secrets::Error::InvalidStorage)?
        {
            let count = fs::read_dir(namespace.profile().path())
                .map_err(|_| secrets::Error::Io)?
                .take(MAX_ENTRIES + 2)
                .count();
            if count > MAX_ENTRIES {
                return Err(secrets::Error::Unavailable);
            }
        }
        let lock = platform::OwnerLock::acquire(&path).map_err(|_| secrets::Error::Unavailable)?;
        let mut bytes = Vec::with_capacity(
            48 + credentials
                .as_ref()
                .map_or(0, |value| value.username.len() + value.password.len()),
        );
        bytes.extend_from_slice(if credentials.is_some() {
            MAGIC
        } else {
            CLEARED
        });
        bytes.extend_from_slice(&key);
        if let Some(value) = credentials.as_ref() {
            bytes.extend_from_slice(&(value.username.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&(value.password.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&value.username);
            bytes.extend_from_slice(&value.password);
        }
        let bundle = SecretBundle::new(bytes)?;
        self.with_provider(&lock, key, |store| store.replace(&bundle))
    }
}

impl GitCredentialProvider for HostGitCredentials {
    fn credentials(&self, binding: &RemoteCredentialBinding) -> Option<GitCredentials> {
        // No credential bytes or native provider diagnostics cross this trait.
        // Missing/locked/unavailable storage is an ordinary CredentialsRequired.
        self.read(&binding.validated_https_url).ok().flatten()
    }
}
