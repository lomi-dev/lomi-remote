//! Explicit, identity-bound local profile purge.
//!
//! This removes only the reviewed mutable Host state. It never removes the
//! profile directory, Store identity, HostAuth signing identity, provider KEK,
//! initialization receipt, TUF state, project roots, or unknown files.

use crate::git_credentials::HostGitCredentials;
use lomi_host_auth::{Config as AuthConfig, HostAuth, Status as AuthStatus};
use lomi_host_store::{
    HostStore, Identity, Limits, ProfilePurgeAuthority, ProfilePurgePhase, ProfilePurgeStore,
    StoreError,
};
use lomi_platform::{
    secrets::{SecretStorage, Selection},
    setup_context,
};
use lomi_remote_protocol::{HostId, OperationId, ipc::*};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use lomi_platform::unix as platform;
#[cfg(windows)]
use lomi_platform::windows as platform;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfilePurgeOutcome {
    Complete,
    RevocationPending,
    CleanupUncertain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfilePurgeError {
    Busy,
    InvalidProfile,
    IdentityMismatch,
    HistoryExhausted,
    Storage,
    Unsupported,
}

impl std::fmt::Display for ProfilePurgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Busy => "PROFILE_PURGE_BUSY",
            Self::InvalidProfile => "PROFILE_PURGE_INVALID_PROFILE",
            Self::IdentityMismatch => "PROFILE_PURGE_IDENTITY_MISMATCH",
            Self::HistoryExhausted => "PROFILE_PURGE_HISTORY_EXHAUSTED",
            Self::Storage => "PROFILE_PURGE_STORAGE_ERROR",
            Self::Unsupported => "PROFILE_PURGE_UNSUPPORTED",
        })
    }
}
impl std::error::Error for ProfilePurgeError {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
enum InitializationBinding {
    #[cfg(unix)]
    Unix {
        uid: u32,
        gid: u32,
        device: u64,
        inode: u64,
    },
    #[cfg(windows)]
    Windows {
        sid: String,
        volume: u64,
        file_index: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InitializationState {
    Creating,
    Complete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InitializationReceipt {
    version: u8,
    state: InitializationState,
    profile_path: String,
    owner: InitializationBinding,
    host_id: Option<String>,
    profile_id: Option<String>,
}

fn receipt_identity(owner: &platform::OwnerLock) -> Result<Identity, ProfilePurgeError> {
    let bytes = owner
        .read_host_initialization_receipt()
        .map_err(|_| ProfilePurgeError::InvalidProfile)?
        .ok_or(ProfilePurgeError::InvalidProfile)?;
    let receipt: InitializationReceipt =
        serde_json::from_slice(&bytes).map_err(|_| ProfilePurgeError::InvalidProfile)?;
    let encoded = serde_json::to_vec(&receipt).map_err(|_| ProfilePurgeError::InvalidProfile)?;
    if encoded != bytes
        || receipt.version != 1
        || receipt.state != InitializationState::Complete
        || receipt.profile_path
            != owner
                .profile()
                .path()
                .to_str()
                .ok_or(ProfilePurgeError::InvalidProfile)?
    {
        return Err(ProfilePurgeError::InvalidProfile);
    }

    let selected =
        setup_context::select_current_account().map_err(|_| ProfilePurgeError::IdentityMismatch)?;
    let (first, second) = owner.profile_identity();
    #[cfg(unix)]
    let binding_matches = {
        let account = selected.unix().ok_or(ProfilePurgeError::IdentityMismatch)?;
        matches!(
            receipt.owner,
            InitializationBinding::Unix { uid, gid, device, inode }
                if uid == account.uid()
                    && gid == account.gid()
                    && device == first
                    && inode == second
        )
    };
    #[cfg(windows)]
    let binding_matches = {
        let account = selected
            .windows()
            .ok_or(ProfilePurgeError::IdentityMismatch)?;
        matches!(
            &receipt.owner,
            InitializationBinding::Windows { sid, volume, file_index }
                if sid == account.sid() && *volume == first && *file_index == second
        )
    };
    if !binding_matches {
        return Err(ProfilePurgeError::IdentityMismatch);
    }

    let host_id: HostId = receipt
        .host_id
        .ok_or(ProfilePurgeError::InvalidProfile)?
        .try_into()
        .map_err(|_| ProfilePurgeError::InvalidProfile)?;
    let profile_id: IpcProfileId = receipt
        .profile_id
        .ok_or(ProfilePurgeError::InvalidProfile)?
        .try_into()
        .map_err(|_| ProfilePurgeError::InvalidProfile)?;
    Ok(Identity {
        host_id,
        profile_id,
    })
}

fn validate_receipt(
    owner: &platform::OwnerLock,
    expected_host_id: HostId,
    expected_profile_id: IpcProfileId,
) -> Result<Identity, ProfilePurgeError> {
    let identity = receipt_identity(owner)?;
    if identity.host_id != expected_host_id || identity.profile_id != expected_profile_id {
        return Err(ProfilePurgeError::IdentityMismatch);
    }
    Ok(identity)
}

/// Observe an existing Host in its actual native owner context, including a
/// committed WAL that setup's immutable reader deliberately does not consume.
/// This creates no Host/profile identity and does not migrate or start runtime.
pub fn inspect_maintenance_profile(
    profile: &Path,
) -> Result<lomi_host_store::MaintenanceProfileObservation, ProfilePurgeError> {
    let owner = maintenance_owner(profile)?;
    let identity = receipt_identity(&owner)?;
    lomi_host_store::MaintenanceProfileStore::open_existing(&owner, &identity)
        .and_then(|store| store.observation())
        .map_err(store_error)
}

/// Persist a stopped Host's local logout fence without launching a runtime.
/// The same initialized profile and both durable IDs must still be present.
pub fn fence_maintenance_profile(
    profile: &Path,
    host_id: HostId,
    profile_id: IpcProfileId,
) -> Result<lomi_host_store::MaintenanceProfileObservation, ProfilePurgeError> {
    let owner = maintenance_owner(profile)?;
    let identity = validate_receipt(&owner, host_id, profile_id)?;
    lomi_host_store::MaintenanceProfileStore::open_existing(&owner, &identity)
        .and_then(|mut store| store.ensure_logout_fenced())
        .map_err(store_error)
}

fn maintenance_owner(profile: &Path) -> Result<platform::OwnerLock, ProfilePurgeError> {
    if !profile.is_absolute() {
        return Err(ProfilePurgeError::InvalidProfile);
    }
    let owner = platform::OwnerLock::acquire_existing(profile).map_err(|error| match error {
        platform::Error::Busy => ProfilePurgeError::Busy,
        platform::Error::InvalidProfile => ProfilePurgeError::InvalidProfile,
        _ => ProfilePurgeError::IdentityMismatch,
    })?;
    if profile.canonicalize().ok().as_deref() != Some(owner.profile().path()) {
        return Err(ProfilePurgeError::InvalidProfile);
    }
    Ok(owner)
}

fn store_error(error: StoreError) -> ProfilePurgeError {
    match error {
        StoreError::Busy | StoreError::NativeWriterBusy => ProfilePurgeError::Busy,
        StoreError::Invalid | StoreError::NotFound | StoreError::SchemaVersion => {
            ProfilePurgeError::InvalidProfile
        }
        StoreError::Fenced | StoreError::PurgeInProgress => ProfilePurgeError::IdentityMismatch,
        StoreError::IdempotencyConflict => ProfilePurgeError::Busy,
        StoreError::ResourceExhausted => ProfilePurgeError::HistoryExhausted,
        _ => ProfilePurgeError::Storage,
    }
}

fn open_provider<'a>(
    owner: &'a platform::OwnerLock,
    profile_id: IpcProfileId,
    configuration: &LocalAuthConfiguration,
) -> Result<Box<dyn SecretStorage + 'a>, ProfilePurgeError> {
    configuration
        .validate()
        .map_err(|_| ProfilePurgeError::InvalidProfile)?;
    match configuration.provider {
        LocalAuthProvider::ProtectedFile => {
            #[cfg(unix)]
            {
                let selection = Selection::ProtectedFile(
                    lomi_platform::secrets::ProtectedFileAcknowledgement::OsPermissionsOnly,
                );
                platform::secrets::ProtectedFile::open(owner.profile(), selection)
                    .map(|provider| Box::new(provider) as Box<dyn SecretStorage>)
                    .map_err(|_| ProfilePurgeError::Busy)
            }
            #[cfg(not(unix))]
            {
                let _ = (owner, profile_id);
                Err(ProfilePurgeError::Unsupported)
            }
        }
        LocalAuthProvider::MacOsKeychain => {
            #[cfg(target_os = "macos")]
            {
                let keychain_path = configuration
                    .keychain_path
                    .as_ref()
                    .ok_or(ProfilePurgeError::InvalidProfile)?;
                platform::keychain::MacOsKeychain::open(
                    owner.profile(),
                    Selection::MacOsKeychain,
                    profile_id,
                    Path::new(keychain_path.as_str()),
                )
                .map(|provider| Box::new(provider) as Box<dyn SecretStorage>)
                .map_err(|_| ProfilePurgeError::Busy)
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = (owner, profile_id);
                Err(ProfilePurgeError::Unsupported)
            }
        }
        LocalAuthProvider::WindowsDpapi => {
            #[cfg(windows)]
            {
                platform::secrets::WindowsDpapi::open(owner.profile(), Selection::WindowsDpapi)
                    .map(|provider| Box::new(provider) as Box<dyn SecretStorage>)
                    .map_err(|_| ProfilePurgeError::Busy)
            }
            #[cfg(not(windows))]
            {
                let _ = (owner, profile_id);
                Err(ProfilePurgeError::Unsupported)
            }
        }
        LocalAuthProvider::LinuxSecretService => {
            #[cfg(target_os = "linux")]
            {
                lomi_platform::secret_service::SecretService::open(
                    owner.profile(),
                    Selection::SecretService,
                    profile_id,
                )
                .map(|provider| Box::new(provider) as Box<dyn SecretStorage>)
                .map_err(|_| ProfilePurgeError::Busy)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (owner, profile_id);
                Err(ProfilePurgeError::Unsupported)
            }
        }
    }
}

fn auth_config(
    identity: &Identity,
    configuration: &LocalAuthConfiguration,
) -> Result<AuthConfig, ProfilePurgeError> {
    let client = configuration
        .client_id
        .as_str()
        .to_owned()
        .try_into()
        .map_err(|_| ProfilePurgeError::InvalidProfile)?;
    AuthConfig::new(
        identity.host_id,
        identity.profile_id,
        configuration.origin.as_str().to_owned(),
        client,
    )
    .map_err(|_| ProfilePurgeError::InvalidProfile)
}

fn reset_host_auth(
    owner: &platform::OwnerLock,
    identity: &Identity,
    configuration: &LocalAuthConfiguration,
    clock_floor: u64,
) -> Result<(), ProfilePurgeError> {
    let mut provider = open_provider(owner, identity.profile_id, configuration)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProfilePurgeError::Storage)?
        .as_secs()
        .max(clock_floor);
    let trusted = auth_config(identity, configuration)?;
    let mut auth =
        HostAuth::open(provider.as_mut(), trusted, now).map_err(|_| ProfilePurgeError::Busy)?;
    match auth.status() {
        AuthStatus::Empty | AuthStatus::PendingInit => Ok(()),
        AuthStatus::AwaitingApproval | AuthStatus::Approved => auth
            .cancel_pending_login(now)
            .map_err(|_| ProfilePurgeError::Busy),
        AuthStatus::Revoked => auth
            .reset_after_acknowledged_revocation(now)
            .map_err(|_| ProfilePurgeError::Busy),
        AuthStatus::ExchangePrepared
        | AuthStatus::Unconfirmed
        | AuthStatus::Ready
        | AuthStatus::Rotating
        | AuthStatus::Sealed => Err(ProfilePurgeError::Busy),
    }
}

fn completed_host_auth_is_reset(
    owner: &platform::OwnerLock,
    identity: &Identity,
    configuration: &LocalAuthConfiguration,
    clock_floor: u64,
) -> Result<bool, ProfilePurgeError> {
    let mut provider = open_provider(owner, identity.profile_id, configuration)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProfilePurgeError::Storage)?
        .as_secs()
        .max(clock_floor);
    let trusted = auth_config(identity, configuration)?;
    let auth =
        HostAuth::open(provider.as_mut(), trusted, now).map_err(|_| ProfilePurgeError::Busy)?;
    Ok(matches!(
        auth.status(),
        AuthStatus::Empty | AuthStatus::PendingInit
    ))
}

fn mark_uncertain(store: &mut ProfilePurgeStore, authority: &ProfilePurgeAuthority) {
    let _ = store.mark_uncertain(authority);
}

/// Purge the selected native account's existing Host profile after logout.
///
/// The call acquires the real persistent OwnerLock, validates its immutable
/// initialization receipt and Store identity, and performs no network or
/// project-root filesystem effects. A pending logout remains available to the
/// normal Host revoke worker; no purge marker is installed before ACK.
pub fn purge_host_profile(
    profile: &Path,
    expected_host_id: HostId,
    expected_profile_id: IpcProfileId,
    operation_id: OperationId,
) -> Result<ProfilePurgeOutcome, ProfilePurgeError> {
    if !profile.is_absolute() {
        return Err(ProfilePurgeError::InvalidProfile);
    }
    let owner = platform::OwnerLock::acquire_existing(profile).map_err(|error| match error {
        platform::Error::Busy => ProfilePurgeError::Busy,
        platform::Error::InvalidProfile => ProfilePurgeError::InvalidProfile,
        _ => ProfilePurgeError::IdentityMismatch,
    })?;
    let canonical = profile
        .canonicalize()
        .map_err(|_| ProfilePurgeError::InvalidProfile)?;
    if canonical != owner.profile().path() {
        return Err(ProfilePurgeError::InvalidProfile);
    }
    let identity = validate_receipt(&owner, expected_host_id, expected_profile_id)?;
    let profile_identity = owner.profile_identity();
    let db_path = owner.profile().path().join("host.sqlite3");
    let mut store = HostStore::open_existing_for_profile_purge(
        &db_path,
        Limits::default(),
        &identity,
        profile_identity,
    )
    .map_err(store_error)?;

    let authorization = store.ensure_revocation_fenced().map_err(store_error)?;
    if authorization.pending_cloud_revoke {
        return Ok(ProfilePurgeOutcome::RevocationPending);
    }

    let configuration = store.auth_configuration().map_err(store_error)?;
    let Some(configuration) = configuration.as_ref() else {
        // Without the exact retained provider selection, a secret bundle may
        // exist in an unknown provider and cannot be claimed purged.
        return Ok(ProfilePurgeOutcome::CleanupUncertain);
    };
    let begin = store
        .begin(operation_id, profile_identity)
        .map_err(store_error)?;
    if begin.record.phase == ProfilePurgePhase::Complete {
        if !completed_host_auth_is_reset(
            &owner,
            &identity,
            configuration,
            authorization.clock_floor,
        )? || HostGitCredentials::profile_has_live_credentials(&owner, configuration)
            .map_err(|_| ProfilePurgeError::Busy)?
        {
            return Err(ProfilePurgeError::Busy);
        }
        return Ok(ProfilePurgeOutcome::Complete);
    }
    let Some(authority) = begin.authority else {
        return Ok(ProfilePurgeOutcome::CleanupUncertain);
    };

    if begin.record.phase == ProfilePurgePhase::Started {
        if reset_host_auth(&owner, &identity, configuration, authorization.clock_floor).is_err() {
            mark_uncertain(&mut store, &authority);
            return Ok(ProfilePurgeOutcome::CleanupUncertain);
        }
        if store.mark_host_auth_reset(&authority).is_err() {
            mark_uncertain(&mut store, &authority);
            return Ok(ProfilePurgeOutcome::CleanupUncertain);
        }
    }

    let phase = match store.status() {
        Ok(phase) => phase,
        Err(_) => {
            mark_uncertain(&mut store, &authority);
            return Ok(ProfilePurgeOutcome::CleanupUncertain);
        }
    };
    if phase.is_some_and(|record| record.phase == ProfilePurgePhase::HostAuthReset) {
        if HostGitCredentials::clear_profile_credentials(&owner, Some(configuration)).is_err() {
            mark_uncertain(&mut store, &authority);
            return Ok(ProfilePurgeOutcome::CleanupUncertain);
        }
        if store.mark_git_credentials_cleared(&authority).is_err() {
            mark_uncertain(&mut store, &authority);
            return Ok(ProfilePurgeOutcome::CleanupUncertain);
        }
    }

    let phase = match store.status() {
        Ok(phase) => phase,
        Err(_) => {
            mark_uncertain(&mut store, &authority);
            return Ok(ProfilePurgeOutcome::CleanupUncertain);
        }
    };
    if phase.is_some_and(|record| record.phase == ProfilePurgePhase::GitCredentialsCleared) {
        if store.clear_mutable_store(&authority).is_err() {
            mark_uncertain(&mut store, &authority);
            return Ok(ProfilePurgeOutcome::CleanupUncertain);
        }
    }

    let phase = match store.status() {
        Ok(phase) => phase,
        Err(_) => {
            mark_uncertain(&mut store, &authority);
            return Ok(ProfilePurgeOutcome::CleanupUncertain);
        }
    };
    if phase.is_some_and(|record| record.phase == ProfilePurgePhase::StoreCleared) {
        if store.complete(&authority).is_err() {
            mark_uncertain(&mut store, &authority);
            return Ok(ProfilePurgeOutcome::CleanupUncertain);
        }
    }
    match store.status() {
        Ok(Some(record)) if record.phase == ProfilePurgePhase::Complete => {
            Ok(ProfilePurgeOutcome::Complete)
        }
        Ok(_) => Ok(ProfilePurgeOutcome::CleanupUncertain),
        Err(_) => {
            mark_uncertain(&mut store, &authority);
            Ok(ProfilePurgeOutcome::CleanupUncertain)
        }
    }
}

#[cfg(not(any(unix, windows)))]
pub fn purge_host_profile(
    _profile: &Path,
    _expected_host_id: HostId,
    _expected_profile_id: IpcProfileId,
    _operation_id: OperationId,
) -> Result<ProfilePurgeOutcome, ProfilePurgeError> {
    Err(ProfilePurgeError::Unsupported)
}
