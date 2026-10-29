//! Single-owner durable local domain coordinator. No IPC, credentials, processes,
//! shell execution or authority verification live here. Callers authenticate and
//! authorize independently before constructing trusted operation bindings.
use lomi_remote_protocol::{ipc::IpcProfileId, rpc::*, *};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
#[cfg(any(unix, windows))]
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;

#[cfg(any(unix, windows))]
mod maintenance_profile;
#[cfg(any(unix, windows))]
mod public_configuration;
#[cfg(any(unix, windows))]
pub use maintenance_profile::{MaintenanceProfileObservation, MaintenanceProfileStore};
#[cfg(any(unix, windows))]
pub use public_configuration::*;

mod terminal_move;
pub use terminal_move::{TerminalMoveError, TerminalMoveLayout, plan_terminal_move};

mod host_metadata;

mod cloud_publication;
pub use cloud_publication::*;
mod cloud_peer_intents;
pub use cloud_peer_intents::*;
mod cloud_channel_intents;
pub use cloud_channel_intents::*;
#[cfg(any(unix, windows))]
mod native_git;
#[cfg(any(unix, windows))]
pub use native_git::*;
#[cfg(any(unix, windows))]
mod desktop_namespace;
#[cfg(any(unix, windows))]
pub use desktop_namespace::*;
#[cfg(any(unix, windows))]
mod workspace_binding_lookup;
#[cfg(any(unix, windows))]
mod workspace_removal;
#[cfg(any(unix, windows))]
pub use workspace_removal::*;
#[cfg(any(unix, windows))]
mod profile_purge;
#[cfg(any(unix, windows))]
pub use profile_purge::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginIntent {
    pub operation_id: OperationId,
    pub generation: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifiedGeneration {
    version: u32,
    generation: u64,
}

const AUTHORIZATION_REJECTION_KEY: &str = "authorization_rejection";
const DEFERRED_LOGIN_KEY: &str = "deferred_login_intent";
const MAX_SHELL_PROFILE_CWD_SUFFIX_BYTES: usize = 4096;
const MAX_REGISTERED_SHELL_PROFILES_PER_WORKSPACE: usize = 31;
const MAX_SHELL_PROFILES_PER_WORKSPACE: usize = 32;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationRejection {
    version: u32,
    generation: u64,
    configuration: ipc::LocalAuthConfiguration,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeferredLoginRecord {
    version: u32,
    intent: LoginIntent,
}

fn metadata_value(db: &Connection, key: &str) -> Result<Option<String>> {
    db.query_row("SELECT value FROM metadata WHERE key=?1", [key], |row| {
        row.get(0)
    })
    .optional()
    .map_err(Into::into)
}

fn verify_expected_identity(
    db: &Connection,
    expected_host_id: Option<HostId>,
    expected_profile_id: Option<IpcProfileId>,
) -> Result<()> {
    let version: i64 = db.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if !(1..=VERSION).contains(&version) {
        return Err(StoreError::SchemaVersion);
    }
    let metadata_exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='metadata')",
        [],
        |row| row.get(0),
    )?;
    if !metadata_exists {
        return Err(StoreError::SchemaVersion);
    }
    let identity_length: Option<i64> = db
        .query_row(
            "SELECT length(CAST(value AS BLOB)) FROM metadata WHERE key='identity'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let Some(identity_length) = identity_length else {
        return Err(StoreError::Fenced);
    };
    if !(1..=4096).contains(&identity_length) {
        return Err(StoreError::Storage);
    }
    let wire: String = db.query_row(
        "SELECT value FROM metadata WHERE key='identity'",
        [],
        |row| row.get(0),
    )?;
    let identity: Identity = decode(&wire)?;
    if expected_host_id.is_some_and(|expected| identity.host_id != expected)
        || expected_profile_id.is_some_and(|expected| identity.profile_id != expected)
    {
        return Err(StoreError::Fenced);
    }
    Ok(())
}

fn verify_existing_identity(db: &Connection) -> Result<()> {
    let version: i64 = db.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if !(1..=VERSION).contains(&version) {
        return Err(StoreError::SchemaVersion);
    }
    let metadata_exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='metadata')",
        [],
        |row| row.get(0),
    )?;
    if !metadata_exists {
        return Err(StoreError::SchemaVersion);
    }
    let identity_length: Option<i64> = db
        .query_row(
            "SELECT length(CAST(value AS BLOB)) FROM metadata WHERE key='identity'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let Some(identity_length) = identity_length else {
        return Err(StoreError::Fenced);
    };
    if !(1..=4096).contains(&identity_length) {
        return Err(StoreError::Storage);
    }
    let wire: String = db.query_row(
        "SELECT value FROM metadata WHERE key='identity'",
        [],
        |row| row.get(0),
    )?;
    let _: Identity = decode(&wire)?;
    Ok(())
}

fn immutable_setup_uri(path: &Path) -> Option<String> {
    if !path.is_absolute() {
        return None;
    }
    let path_text = path.to_str()?;
    #[cfg(windows)]
    let path = {
        let mut path = path_text.to_owned();
        path = path.replace('\\', "/");
        if path.as_bytes().get(1) == Some(&b':') {
            path.insert(0, '/');
        }
        path
    };
    #[cfg(not(windows))]
    let path = path_text.to_owned();
    let mut uri = String::from("file:");
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'-' | b'_' | b'.' | b'~') {
            uri.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut uri, "%{byte:02X}").ok()?;
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    Some(uri)
}

fn shell_profile_cwd_key(workspace_id: WorkspaceId, profile_id: &HostProfileId) -> String {
    format!(
        "shell_profile_cwd/{}/{}",
        key(workspace_id),
        profile_id.as_str()
    )
}

fn validate_shell_profile_cwd_override(path: &Path) -> Result<()> {
    let Some(text) = path.to_str() else {
        return Err(StoreError::Invalid);
    };
    if text.len() > MAX_SHELL_PROFILE_CWD_SUFFIX_BYTES || text.contains('\0') || path.is_absolute()
    {
        return Err(StoreError::Invalid);
    }
    if text.is_empty() {
        return Ok(());
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(name) => normalized.push(name),
            _ => return Err(StoreError::Invalid),
        }
    }
    if normalized.as_os_str() != path.as_os_str() {
        return Err(StoreError::Invalid);
    }
    Ok(())
}

fn read_shell_profile_cwd_override(db: &Connection, key: &str) -> Result<Option<PathBuf>> {
    metadata_value(db, key)?
        .map(|wire| -> Result<PathBuf> {
            let path: PathBuf = decode(&wire)?;
            validate_shell_profile_cwd_override(&path)?;
            Ok(path)
        })
        .transpose()
}

fn read_authorization_rejection(db: &Connection) -> Result<Option<AuthorizationRejection>> {
    metadata_value(db, AUTHORIZATION_REJECTION_KEY)?
        .map(|value| {
            let rejection: AuthorizationRejection =
                serde_json::from_str(&value).map_err(|_| StoreError::Storage)?;
            if rejection.version != 1 {
                return Err(StoreError::Storage);
            }
            rejection
                .configuration
                .validate()
                .map_err(|_| StoreError::Storage)?;
            Ok(rejection)
        })
        .transpose()
}

fn read_deferred_login_record(db: &Connection) -> Result<Option<DeferredLoginRecord>> {
    metadata_value(db, DEFERRED_LOGIN_KEY)?
        .map(|value| {
            let record: DeferredLoginRecord =
                serde_json::from_str(&value).map_err(|_| StoreError::Storage)?;
            if record.version != 1 {
                return Err(StoreError::Storage);
            }
            Ok(record)
        })
        .transpose()
}

fn read_login_intent_record(db: &Connection) -> Result<Option<LoginIntent>> {
    metadata_value(db, "login_generation")?
        .map(|value| serde_json::from_str(&value).map_err(|_| StoreError::Storage))
        .transpose()
}

fn save_authorization_rejection(
    tx: &Transaction<'_>,
    generation: u64,
    configuration: &ipc::LocalAuthConfiguration,
) -> Result<()> {
    let value = json(&AuthorizationRejection {
        version: 1,
        generation,
        configuration: configuration.clone(),
    })?;
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![AUTHORIZATION_REJECTION_KEY, value],
    )?;
    Ok(())
}

fn save_deferred_login(tx: &Transaction<'_>, intent: LoginIntent) -> Result<()> {
    let value = json(&DeferredLoginRecord { version: 1, intent })?;
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![DEFERRED_LOGIN_KEY, value],
    )?;
    Ok(())
}

/// Validate the strict rejection/deferred pair against the fenced generation.
/// A supplied configuration is the caller's effective trusted setup snapshot;
/// omission is used only by paths that reject every unresolved marker anyway.
fn validate_rejection_metadata(
    db: &Connection,
    state: AuthorizationState,
    configuration: Option<&ipc::LocalAuthConfiguration>,
) -> Result<(Option<AuthorizationRejection>, Option<LoginIntent>)> {
    let rejection = read_authorization_rejection(db)?;
    let deferred = read_deferred_login_record(db)?;
    let active = read_login_intent_record(db)?;
    match rejection {
        None => {
            if deferred.is_some() || (state.pending_cloud_revoke && active.is_some()) {
                return Err(StoreError::Storage);
            }
            Ok((None, None))
        }
        Some(rejection) => {
            if rejection.generation != state.generation {
                return Err(StoreError::Fenced);
            }
            if configuration.is_none()
                || configuration.is_some_and(|value| value != &rejection.configuration)
            {
                return Err(StoreError::Fenced);
            }
            if !state.locked
                || active.is_some()
                || metadata_value(db, "authorization_verified_generation")?.is_some()
            {
                return Err(StoreError::Storage);
            }
            let deferred_intent = match (state.pending_cloud_revoke, deferred) {
                (false, None) => None,
                (true, Some(record)) => {
                    if record.intent.generation != rejection.generation {
                        return Err(StoreError::Fenced);
                    }
                    Some(record.intent)
                }
                _ => return Err(StoreError::Storage),
            };
            Ok((Some(rejection), deferred_intent))
        }
    }
}

fn save_verified_generation(tx: &Transaction<'_>, generation: u64) -> Result<()> {
    tx.execute("INSERT INTO metadata(key,value) VALUES('authorization_verified_generation',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [serde_json::to_string(&VerifiedGeneration { version: 1, generation }).map_err(|_| StoreError::Storage)?])?;
    Ok(())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudAuthorizationHistory {
    version: u32,
    may_exist: bool,
}
fn save_cloud_history(tx: &Transaction<'_>, may_exist: bool) -> Result<()> {
    tx.execute("INSERT INTO metadata(key,value) VALUES('cloud_authorization_history',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [serde_json::to_string(&CloudAuthorizationHistory { version: 1, may_exist }).map_err(|_| StoreError::Storage)?])?;
    Ok(())
}
fn read_cloud_history(db: &Connection) -> Result<Option<bool>> {
    let text: Option<String> = db
        .query_row(
            "SELECT value FROM metadata WHERE key='cloud_authorization_history'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    text.map(|text| {
        if !text.trim_start().starts_with('{') {
            return Err(StoreError::Storage);
        }
        let value: CloudAuthorizationHistory =
            serde_json::from_str(&text).map_err(|_| StoreError::Storage)?;
        if value.version != 1 {
            return Err(StoreError::Storage);
        }
        Ok(value.may_exist)
    })
    .transpose()
}
#[cfg(any(unix, windows))]
const VERSION: i64 = 14;
#[cfg(any(unix, windows))]
const MAX_NATIVE_INTENT_ROWS: usize = 16_384;
#[cfg(not(any(unix, windows)))]
const VERSION: i64 = 3;
/// Native release metadata and entrypoints derive their schema compatibility
/// from the Store implementation instead of maintaining another version pin.
pub const PROFILE_SCHEMA_VERSION: u64 = VERSION as u64;
const AUTHORIZATION_SCHEMA: &str = "CREATE TABLE authorization_state(id INTEGER PRIMARY KEY CHECK(id=1),generation TEXT NOT NULL,locked INTEGER NOT NULL CHECK(locked IN(0,1)),pending_cloud_revoke INTEGER NOT NULL CHECK(pending_cloud_revoke IN(0,1)),clock_floor TEXT NOT NULL); INSERT INTO authorization_state VALUES(1,'0',1,0,'0'); PRAGMA user_version=3;";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    Storage,
    Busy,
    Invalid,
    NotFound,
    RevisionConflict,
    IdempotencyConflict,
    ResourceExhausted,
    /// A live native writer excludes this remote/native effect, but does not
    /// indicate stale authority or an invalid consumer generation.
    NativeWriterBusy,
    Fenced,
    AlreadyStarted,
    SchemaVersion,
    Backup,
    PurgeInProgress,
}
pub type Result<T> = std::result::Result<T, StoreError>;

/// Minimal setup data read from an already-existing, supported Store without
/// opening HostStore or running migrations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupObservation {
    pub identity: Identity,
    pub auth_configuration: Option<ipc::LocalAuthConfiguration>,
    pub workspace_present: bool,
}

/// Read-only setup inspection distinguishes absent or malformed local state
/// from a valid Store and never attempts to repair it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupInspection {
    Ready(SetupObservation),
    MissingDatabase,
    InvalidSchema,
    MissingIdentity,
    InvalidIdentity,
    InvalidConfiguration,
    OwnerRunning,
    NeedsRecovery,
    Unavailable,
}

/// An owned canonical, UTF-8 directory root prepared without a Store borrow.
/// This records the existing root checks; it is not a filesystem sandbox or a
/// guarantee that the directory cannot change after preparation.
#[derive(Debug)]
pub struct ValidatedProjectRoot {
    canonical: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceImportAlias {
    workspace_id: WorkspaceId,
    canonical_root: String,
}

fn remember_workspace_import(
    tx: &Transaction<'_>,
    import_id: WorkspaceId,
    workspace_id: WorkspaceId,
    canonical_root: &str,
    limit: usize,
) -> Result<()> {
    if count(
        tx,
        "SELECT count(*) FROM metadata WHERE key LIKE 'workspace_import/%'",
    )? >= limit
    {
        return Err(StoreError::ResourceExhausted);
    }
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2)",
        params![
            format!("workspace_import/{}", key(import_id)),
            json(&WorkspaceImportAlias {
                workspace_id,
                canonical_root: canonical_root.to_owned()
            })?,
        ],
    )?;
    Ok(())
}

/// Perform project-root filesystem I/O before entering owner synchronization.
pub fn prepare_project_root(root: &Path) -> Result<ValidatedProjectRoot> {
    let canonical = root.canonicalize().map_err(|_| StoreError::Invalid)?;
    if !canonical.is_dir() || canonical.to_str().is_none() {
        return Err(StoreError::Invalid);
    }
    Ok(ValidatedProjectRoot { canonical })
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        match error.sqlite_error_code() {
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
                Self::Busy
            }
            _ => Self::Storage,
        }
    }
}
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub events: usize,
    pub operations: usize,
    pub workspaces: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            events: 4096,
            operations: 4096,
            workspaces: 200,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    pub host_id: HostId,
    pub profile_id: IpcProfileId,
}
/// Trusted local configuration only. Never constructed from remote RPC parameters.
/// CWD and inherited environment are deliberately not durable profile data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DefaultShellProfile {
    pub executable: PathBuf,
    pub args: Vec<String>,
}
impl DefaultShellProfile {
    fn validate(&self) -> Result<()> {
        let executable = self.executable.to_str().ok_or(StoreError::Invalid)?;
        if !self.executable.is_absolute()
            || executable.len() > 32768
            || executable.contains('\0')
            || self.args.len() > 32
            || self
                .args
                .iter()
                .any(|arg| arg.len() > 4096 || arg.contains('\0'))
        {
            return Err(StoreError::Invalid);
        }
        Ok(())
    }
}
#[derive(Debug, Clone)]
pub struct ProjectRecord {
    pub local_root: PathBuf,
    pub state: WorkspaceState,
    pub consent: bool,
    pub fence: u64,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TerminalStatus {
    Stopped,
    Running,
    Lost,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalDescriptor {
    pub pane_id: PaneId,
    pub status: TerminalStatus,
}
/// Already authenticated actor and actually required rights, not caller JSON.
#[derive(Debug, Clone)]
pub struct OperationBinding {
    pub rights: StoredOperationRights,
    pub parameter_hash: OperationParameterHash,
}
#[derive(Debug, Clone)]
pub struct Admission {
    pub receipt: OperationReceipt,
    pub newly_admitted: bool,
}
/// One-shot permission returned only on accepted -> running. It carries no PID.
#[derive(Debug)]
pub struct ExternalPermit {
    binding: OperationBinding,
    fence: u64,
    runtime: RuntimeId,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Publication {
    pub workspace_id: WorkspaceId,
    pub fence: u64,
    pub domain_revision: DecimalU64,
    pub enabled: bool,
    pub token: String,
}
#[derive(Debug, Clone)]
pub struct Event {
    pub sequence: u64,
    pub workspace_id: WorkspaceId,
    pub operation_id: Option<OperationId>,
    pub domain_revision: DecimalU64,
}
#[derive(Debug)]
pub struct EventPage {
    pub resync_required: bool,
    pub low_watermark: u64,
    pub events: Vec<Event>,
}

/// Nonsecret remote-access gate. Local terminal admission is independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationState {
    pub generation: u64,
    pub locked: bool,
    pub pending_cloud_revoke: bool,
    pub clock_floor: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationFenceReason {
    LocalLogout,
    AuthorityRejected,
}

#[cfg(any(unix, windows))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeEditorJobState {
    Running,
    Succeeded,
    Failed,
    OutcomeUnknown,
}

#[cfg(any(unix, windows))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeEditorCompletionProof {
    Joined,
    NotStarted,
}

#[cfg(any(unix, windows))]
#[derive(Debug, Clone)]
pub struct NativeEditorJobRecord {
    pub operation_id: ipc::NativeIntentId,
    pub state: NativeEditorJobState,
    pub result_json: Option<String>,
}

#[cfg(any(unix, windows))]
#[derive(Debug, Clone)]
pub struct NativeEvidenceBinding {
    pub intent_id: ipc::NativeIntentId,
    pub store_root: String,
    pub parent_operation_id: String,
    pub binding_json: String,
    pub runtime_descriptor_json: String,
    pub binding_sha256: String,
}

#[cfg(any(unix, windows))]
#[derive(Debug, Clone, Copy)]
pub struct NativeEditorStageRegistration {
    /// Consumed input IDs retain their fixed path for idempotency but cannot
    /// be recreated or rewritten after an Execute has been journaled.
    pub writable: bool,
}

#[cfg(any(unix, windows))]
pub enum NativeEditorBegin {
    Started {
        operation_id: ipc::NativeIntentId,
        fence_id: ipc::NativeIntentId,
    },
    Existing(NativeEditorJobRecord),
}

pub struct HostStore {
    db: Connection,
    identity: Identity,
    runtime: RuntimeId,
    generation: u64,
    limits: Limits,
    authorization_sealed: std::cell::Cell<bool>,
    #[cfg(any(unix, windows))]
    native_clock_anchor: Instant,
    #[cfg(any(unix, windows))]
    native_clock_anchor_ms: u64,
    #[cfg(any(unix, windows))]
    public_configuration: Option<PublicDocument>,
}
fn json(value: &impl Serialize) -> Result<String> {
    serde_json::to_string(value).map_err(|_| StoreError::Invalid)
}
fn decode<T: DeserializeOwned>(value: &str) -> Result<T> {
    serde_json::from_str(value).map_err(|_| StoreError::Storage)
}
fn increment(value: u64) -> Result<u64> {
    value.checked_add(1).ok_or(StoreError::ResourceExhausted)
}
fn key<T: Into<String>>(value: T) -> String {
    value.into()
}
fn count(db: &Connection, sql: &str) -> Result<usize> {
    let n: i64 = db.query_row(sql, [], |r| r.get(0))?;
    usize::try_from(n).map_err(|_| StoreError::Storage)
}
/// Hash a caller-defined canonical admission record including method, targets,
/// parameters and preconditions. Do not include connection request IDs/timeouts.
pub fn parameter_hash(canonical: &impl Serialize) -> Result<OperationParameterHash> {
    OperationParameterHash::try_from(format!("{:x}", Sha256::digest(json(canonical)?.as_bytes())))
        .map_err(|_| StoreError::Invalid)
}
impl HostStore {
    /// Inspect setup while holding the existing native owner lock. If another
    /// Host owns the profile, the caller should use authenticated local IPC.
    /// This path never creates profile, database, or journal files.
    pub fn inspect_setup(path: &Path) -> SetupInspection {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() && metadata.len() > 0 => {}
            Ok(_) => return SetupInspection::InvalidSchema,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return SetupInspection::MissingDatabase;
            }
            Err(_) => return SetupInspection::Unavailable,
        }
        let Some(profile) = path.parent() else {
            return SetupInspection::Unavailable;
        };
        #[cfg(unix)]
        {
            return match lomi_platform::unix::OwnerLock::acquire_existing(profile) {
                Ok(lock) => Self::inspect_setup_under_owner_lock(path, &lock),
                Err(lomi_platform::unix::Error::Busy) => SetupInspection::OwnerRunning,
                Err(_) => SetupInspection::Unavailable,
            };
        }
        #[cfg(windows)]
        {
            return match lomi_platform::windows::OwnerLock::acquire_existing(profile) {
                Ok(lock) => Self::inspect_setup_under_owner_lock(path, &lock),
                Err(lomi_platform::windows::Error::Busy) => SetupInspection::OwnerRunning,
                Err(_) => SetupInspection::Unavailable,
            };
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = profile;
            SetupInspection::Unavailable
        }
    }

    #[cfg(unix)]
    pub fn inspect_setup_under_owner_lock(
        path: &Path,
        lock: &lomi_platform::unix::OwnerLock,
    ) -> SetupInspection {
        if lock.profile().path().join("host.sqlite3") != path {
            return SetupInspection::Unavailable;
        }
        Self::inspect_setup_snapshot(path)
    }

    #[cfg(windows)]
    pub fn inspect_setup_under_owner_lock(
        path: &Path,
        lock: &lomi_platform::windows::OwnerLock,
    ) -> SetupInspection {
        if lock.profile().path().join("host.sqlite3") != path {
            return SetupInspection::Unavailable;
        }
        Self::inspect_setup_snapshot(path)
    }

    fn inspect_setup_snapshot(path: &Path) -> SetupInspection {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() && metadata.len() > 0 => {}
            Ok(_) => return SetupInspection::InvalidSchema,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return SetupInspection::MissingDatabase;
            }
            Err(_) => return SetupInspection::Unavailable,
        }
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut sidecar = path.as_os_str().to_owned();
            sidecar.push(suffix);
            match fs::symlink_metadata(Path::new(&sidecar)) {
                Ok(metadata) if metadata.file_type().is_file() => {
                    if matches!(suffix, "-wal" | "-journal") && metadata.len() > 0 {
                        return SetupInspection::NeedsRecovery;
                    }
                }
                Ok(_) => return SetupInspection::Unavailable,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return SetupInspection::Unavailable,
            }
        }
        let Some(uri) = immutable_setup_uri(path) else {
            return SetupInspection::Unavailable;
        };
        let db = match Connection::open_with_flags(
            uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_URI
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        ) {
            Ok(db) => db,
            Err(_) => return SetupInspection::Unavailable,
        };
        if db.busy_timeout(Duration::ZERO).is_err() {
            return SetupInspection::Unavailable;
        }
        match db.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0)) {
            Ok(version) if (1..=VERSION).contains(&version) => {}
            _ => return SetupInspection::InvalidSchema,
        }
        for table in ["metadata", "projects"] {
            let exists: rusqlite::Result<bool> = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                [table],
                |row| row.get(0),
            );
            if !matches!(exists, Ok(true)) {
                return SetupInspection::InvalidSchema;
            }
        }

        let identity_length: Option<i64> = match db
            .query_row(
                "SELECT length(CAST(value AS BLOB)) FROM metadata WHERE key='identity'",
                [],
                |row| row.get(0),
            )
            .optional()
        {
            Ok(length) => length,
            Err(_) => return SetupInspection::InvalidSchema,
        };
        let Some(identity_length) = identity_length else {
            return SetupInspection::MissingIdentity;
        };
        if !(1..=4096).contains(&identity_length) {
            return SetupInspection::InvalidIdentity;
        }
        let identity_wire: String = match db.query_row(
            "SELECT value FROM metadata WHERE key='identity'",
            [],
            |row| row.get(0),
        ) {
            Ok(value) => value,
            Err(_) => return SetupInspection::InvalidIdentity,
        };
        let identity: Identity = match decode(&identity_wire) {
            Ok(identity) => identity,
            Err(_) => return SetupInspection::InvalidIdentity,
        };

        let auth_length: Option<i64> = match db
            .query_row(
                "SELECT length(CAST(value AS BLOB)) FROM metadata WHERE key='auth_configuration'",
                [],
                |row| row.get(0),
            )
            .optional()
        {
            Ok(length) => length,
            Err(_) => return SetupInspection::InvalidSchema,
        };
        let auth_configuration = match auth_length {
            None => None,
            Some(length) if (1..=16_384).contains(&length) => {
                let wire: String = match db.query_row(
                    "SELECT value FROM metadata WHERE key='auth_configuration'",
                    [],
                    |row| row.get(0),
                ) {
                    Ok(value) => value,
                    Err(_) => return SetupInspection::InvalidConfiguration,
                };
                let configuration: ipc::LocalAuthConfiguration =
                    match decode::<ipc::LocalAuthConfiguration>(&wire) {
                        Ok(configuration) if configuration.validate().is_ok() => configuration,
                        _ => return SetupInspection::InvalidConfiguration,
                    };
                Some(configuration)
            }
            Some(_) => return SetupInspection::InvalidConfiguration,
        };
        let workspace_present = match db.query_row(
            "SELECT EXISTS(SELECT 1 FROM projects WHERE removed=0)",
            [],
            |row| row.get(0),
        ) {
            Ok(present) => present,
            Err(_) => return SetupInspection::InvalidSchema,
        };

        SetupInspection::Ready(SetupObservation {
            identity,
            auth_configuration,
            workspace_present,
        })
    }

    /// Requires a local filesystem with correct SQLite locking. Persistent SQLite
    /// EXCLUSIVE locking is the independent owner guard, in addition to the native
    /// profile lock held by the platform adapter. A second owner returns Busy.
    pub fn open(path: &Path, limits: Limits) -> Result<Self> {
        Self::open_bound(path, limits, None)
    }

    /// Open only an existing, initialized Host Store. This never creates the
    /// database and verifies its durable identity on the opened SQLite
    /// connection before any pragma, migration, recovery, or runtime write.
    pub fn open_existing(path: &Path, limits: Limits) -> Result<Self> {
        Self::open_internal(path, limits, None, None, true, false, false, None)
    }

    /// Open or finish initializing the database only after the caller has
    /// durably written its exact profile-bound Creating receipt. Existing
    /// supported databases retain their identity, including a committed WAL
    /// transaction recovered by this same SQLite connection. A zero-schema
    /// database is initialized only when it has no application objects or
    /// application ID and no expected Host ID is pinned.
    pub fn initialize_after_receipt(
        path: &Path,
        limits: Limits,
        expected_host_id: Option<HostId>,
    ) -> Result<Self> {
        Self::open_internal(
            path,
            limits,
            expected_host_id,
            None,
            false,
            true,
            false,
            None,
        )
    }

    /// Open an existing initialized Store while requiring its pinned Host ID
    /// on the same SQLite connection before schema migration or recovery.
    pub fn open_existing_bound(
        path: &Path,
        limits: Limits,
        expected_host_id: HostId,
    ) -> Result<Self> {
        Self::open_internal(
            path,
            limits,
            Some(expected_host_id),
            None,
            true,
            false,
            false,
            None,
        )
    }

    /// Open an existing Store while requiring both durable identity fields on
    /// the same SQLite connection before schema migration or recovery.
    pub fn open_existing_identity_bound(
        path: &Path,
        limits: Limits,
        expected_identity: &Identity,
    ) -> Result<Self> {
        Self::open_internal(
            path,
            limits,
            Some(expected_identity.host_id),
            Some(expected_identity.profile_id),
            true,
            false,
            false,
            None,
        )
    }

    /// Open a Store only if its durable Host identity matches the caller's
    /// already-pinned identity. The check is made on this SQLite connection
    /// before changing journal mode or applying any schema/runtime mutation.
    /// With an expected ID, the database is never created if it is absent.
    pub fn open_bound(
        path: &Path,
        limits: Limits,
        expected_host_id: Option<HostId>,
    ) -> Result<Self> {
        Self::open_internal(
            path,
            limits,
            expected_host_id,
            None,
            false,
            false,
            false,
            None,
        )
    }

    fn open_internal(
        path: &Path,
        limits: Limits,
        expected_host_id: Option<HostId>,
        expected_profile_id: Option<IpcProfileId>,
        existing_only: bool,
        new_only: bool,
        allow_profile_purge: bool,
        profile_identity: Option<(u64, u64)>,
    ) -> Result<Self> {
        if limits.events < 3
            || limits.events > 4096
            || limits.operations == 0
            || limits.operations > 4096
            || limits.workspaces == 0
            || limits.workspaces > 200
        {
            return Err(StoreError::Invalid);
        }
        let existed = if existing_only {
            let metadata = fs::symlink_metadata(path).map_err(|_| StoreError::Storage)?;
            if !metadata.file_type().is_file() || metadata.len() == 0 {
                return Err(StoreError::SchemaVersion);
            }
            true
        } else if new_only {
            let metadata = fs::symlink_metadata(path).map_err(|_| StoreError::Storage)?;
            if !metadata.file_type().is_file() {
                return Err(StoreError::SchemaVersion);
            }
            metadata.len() > 0
        } else {
            path.metadata().is_ok_and(|metadata| metadata.len() > 0)
        };
        let mut db = if existing_only || expected_host_id.is_some() || new_only {
            Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_WRITE
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )?
        } else {
            Connection::open(path)?
        };
        db.busy_timeout(Duration::ZERO)?;
        // Opening the same SQLite connection first lets it recover a committed
        // WAL transaction before classifying the schema. Do not change journal
        // mode, migrate, or create a Host identity until the durable identity
        // and any caller pin have been checked on this connection.
        let initial_version: i64 = db.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if initial_version == 0 {
            let application_objects = count(
                &db,
                "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
            )?;
            let application_id: i64 =
                db.pragma_query_value(None, "application_id", |row| row.get(0))?;
            if application_objects != 0
                || application_id != 0
                || expected_host_id.is_some()
                || expected_profile_id.is_some()
                || (existed && !new_only)
            {
                return Err(StoreError::SchemaVersion);
            }
        } else {
            if !(1..=VERSION).contains(&initial_version) {
                return Err(StoreError::SchemaVersion);
            }
            verify_existing_identity(&db)?;
            if expected_host_id.is_some() || expected_profile_id.is_some() {
                verify_expected_identity(&db, expected_host_id, expected_profile_id)?;
            }
        }
        db.execute_batch("PRAGMA locking_mode=EXCLUSIVE; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")?;
        let version: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if !(0..=VERSION).contains(&version) {
            return Err(StoreError::SchemaVersion);
        }
        if version == 0 {
            // The receipt-gated initializer and a brand-new in-memory/test
            // store may start only from a schema-free, object-free database.
            if count(
                &db,
                "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
            )? != 0
            {
                return Err(StoreError::SchemaVersion);
            }
            let application_id: i64 =
                db.pragma_query_value(None, "application_id", |row| row.get(0))?;
            if application_id != 0 || (existed && !new_only) {
                return Err(StoreError::SchemaVersion);
            }
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch("CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE projects(workspace TEXT PRIMARY KEY,root TEXT NOT NULL,state TEXT NOT NULL,consent INTEGER NOT NULL CHECK(consent IN(0,1)),fence TEXT NOT NULL,removed INTEGER NOT NULL DEFAULT 0 CHECK(removed IN(0,1)));
CREATE UNIQUE INDEX active_project_root ON projects(root) WHERE removed=0;
CREATE TABLE terminals(workspace TEXT NOT NULL REFERENCES projects(workspace),pane TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN('Stopped','Running','Lost')),PRIMARY KEY(workspace,pane));
CREATE TABLE operations(actor TEXT NOT NULL,workspace TEXT NOT NULL REFERENCES projects(workspace),id TEXT NOT NULL,method TEXT NOT NULL,hash TEXT NOT NULL,receipt TEXT NOT NULL,fence TEXT NOT NULL,revision TEXT NOT NULL,reserved INTEGER NOT NULL CHECK(reserved>=0),PRIMARY KEY(actor,workspace,id));
CREATE TABLE events(sequence INTEGER PRIMARY KEY AUTOINCREMENT,workspace TEXT NOT NULL REFERENCES projects(workspace),operation TEXT,revision TEXT NOT NULL);
CREATE TABLE outbox(workspace TEXT PRIMARY KEY REFERENCES projects(workspace),publication TEXT NOT NULL);
CREATE TABLE default_shell(id INTEGER PRIMARY KEY CHECK(id=1),config TEXT NOT NULL);
INSERT INTO metadata VALUES('low_watermark','0'); INSERT INTO metadata VALUES('owner_generation','0'); PRAGMA user_version=2;")?;
            tx.execute_batch(AUTHORIZATION_SCHEMA)?;
            #[cfg(any(unix, windows))]
            tx.execute_batch("PRAGMA user_version=4;")?;
            let identity = Identity {
                host_id: HostId::from_bytes(Uuid::new_v4().into_bytes())
                    .map_err(|_| StoreError::Invalid)?,
                profile_id: IpcProfileId::from_bytes(Uuid::new_v4().into_bytes())
                    .map_err(|_| StoreError::Invalid)?,
            };
            tx.execute(
                "INSERT INTO metadata VALUES('identity',?1)",
                [json(&identity)?],
            )?;
            save_cloud_history(&tx, false)?;
            tx.commit()?;
        }
        if version == 1 {
            migration_backup(&db, &path.with_extension("before-v2.sqlite"), 1)?;
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch("CREATE TABLE default_shell(id INTEGER PRIMARY KEY CHECK(id=1),config TEXT NOT NULL); PRAGMA user_version=2;")?;
            tx.commit()?;
        }
        if version == 1 || version == 2 {
            migration_backup(&db, &path.with_extension("before-v3.sqlite"), 2)?;
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(AUTHORIZATION_SCHEMA)?;
            // Previous schemas have no verified account binding. Invalidate old
            // sharing intent atomically with the schema compatibility boundary.
            tx.execute("UPDATE authorization_state SET generation='1'", [])?;
            fence_workspaces_before_removal_schema(&tx, limits)?;
            tx.commit()?;
        }
        #[cfg(any(unix, windows))]
        if version != 0 && version < 4 {
            // All v1/v2 paths have reached v3 by this point. Backup precedes
            // the rollback barrier and is reused only for an exact v3 state.
            migration_backup(&db, &path.with_extension("before-v4.sqlite"), 3)?;
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch("PRAGMA user_version=4;")?;
            tx.commit()?;
        }
        #[cfg(any(unix, windows))]
        if version < 5 {
            // A project folder may have several explicitly imported named
            // workspaces. Their IDs, policies, operation journals and terminal
            // trees remain independent; repository locking is physical-root
            // based in the file/Git services. Older hosts must reject v5.
            if version != 0 {
                migration_backup(&db, &path.with_extension("before-v5.sqlite"), 4)?;
            }
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(
                "DROP INDEX active_project_root;
CREATE INDEX active_project_root ON projects(root) WHERE removed=0;
PRAGMA user_version=5;",
            )?;
            tx.commit()?;
        }
        #[cfg(any(unix, windows))]
        if version < 6 {
            if version != 0 {
                migration_backup(&db, &path.with_extension("before-v6.sqlite"), 5)?;
            }
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(
                "CREATE TABLE native_intents(id TEXT PRIMARY KEY,connection TEXT NOT NULL,scope TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN('registered','active','quarantine','finished')),fence TEXT NOT NULL,expires_at_ms TEXT NOT NULL);
CREATE INDEX native_intents_state ON native_intents(state);
CREATE TABLE native_clock(id INTEGER PRIMARY KEY CHECK(id=1),floor_ms TEXT NOT NULL);
INSERT INTO native_clock VALUES(1,'0');
CREATE TABLE native_file_stages(operation_id TEXT PRIMARY KEY,byte_length INTEGER NOT NULL CHECK(byte_length BETWEEN 0 AND 33554432),content_sha256 TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN('unconsumed','consumed','expired')),expires_at_ms TEXT NOT NULL);
CREATE INDEX native_file_stages_unconsumed ON native_file_stages(state,expires_at_ms);
CREATE TABLE native_editor_jobs(operation_id TEXT PRIMARY KEY,request_hash TEXT NOT NULL,blob_length INTEGER NOT NULL,blob_sha256 TEXT NOT NULL,fence_id TEXT NOT NULL,host_runtime_id TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN('running','succeeded','failed','outcomeUnknown')),result_json TEXT,completion_proof TEXT CHECK(completion_proof IN('joined','notStarted')),completed_at_ms TEXT);
CREATE INDEX native_editor_jobs_state ON native_editor_jobs(state);
PRAGMA user_version=6;",
            )?;
            tx.commit()?;
        }
        #[cfg(any(unix, windows))]
        if version < 7 {
            if version != 0 {
                migration_backup(&db, &path.with_extension("before-v7.sqlite"), 6)?;
            }
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(
                "CREATE TABLE native_evidence_bindings(
                    intent_id TEXT PRIMARY KEY REFERENCES native_intents(id) ON DELETE CASCADE,
                    store_root TEXT NOT NULL CHECK(length(store_root) BETWEEN 1 AND 4096),
                    parent_operation_id TEXT NOT NULL CHECK(length(parent_operation_id) BETWEEN 1 AND 256),
                    binding_json TEXT NOT NULL CHECK(length(binding_json) BETWEEN 1 AND 131072),
                    runtime_descriptor_json TEXT NOT NULL CHECK(length(runtime_descriptor_json) BETWEEN 1 AND 16384),
                    binding_sha256 TEXT NOT NULL CHECK(length(binding_sha256)=64),
                    created_at_ms TEXT NOT NULL,
                    verified_at_ms TEXT
                );
                PRAGMA user_version=7;",
            )?;
            tx.commit()?;
        }
        #[cfg(any(unix, windows))]
        if version < 8 {
            if version != 0 {
                migration_backup(&db, &path.with_extension("before-v8.sqlite"), 7)?;
            }
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(
                "ALTER TABLE native_editor_jobs ADD COLUMN acknowledged_at_ms TEXT;
                 PRAGMA user_version=8;",
            )?;
            tx.commit()?;
        }
        #[cfg(any(unix, windows))]
        if version < 9 {
            if version != 0 {
                migration_backup(&db, &path.with_extension("before-v9.sqlite"), 8)?;
            }
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(
                "ALTER TABLE native_intents ADD COLUMN acknowledged_at_ms TEXT;
                 ALTER TABLE native_evidence_bindings ADD COLUMN acknowledged_at_ms TEXT;
                 PRAGMA user_version=9;",
            )?;
            tx.commit()?;
        }
        #[cfg(any(unix, windows))]
        if version < 10 {
            if version != 0 {
                migration_backup(&db, &path.with_extension("before-v10.sqlite"), 9)?;
            }
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(
                "CREATE TABLE native_git_jobs(
                    operation_id TEXT PRIMARY KEY,
                    request_hash TEXT NOT NULL CHECK(length(request_hash)=64),
                    fence_id TEXT NOT NULL UNIQUE,
                    host_runtime_id TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN('preparing','prepared','running','succeeded','failed','outcomeUnknown')),
                    plan_hash TEXT CHECK(plan_hash IS NULL OR length(plan_hash)=64),
                    preview_json TEXT CHECK(preview_json IS NULL OR length(preview_json)<=131072),
                    custody_binding_json TEXT CHECK(custody_binding_json IS NULL OR length(custody_binding_json)<=131072),
                    custody_binding_sha256 TEXT CHECK(custody_binding_sha256 IS NULL OR length(custody_binding_sha256)=64),
                    result_json TEXT CHECK(result_json IS NULL OR length(result_json)<=131072),
                    execution_started_at_ms TEXT,
                    completion_proof TEXT CHECK(completion_proof IN('notStarted','custodyVerified')),
                    created_at_ms TEXT NOT NULL,
                    updated_at_ms TEXT NOT NULL,
                    completed_at_ms TEXT,
                    acknowledged_at_ms TEXT
                );
                CREATE INDEX native_git_jobs_state ON native_git_jobs(state);
                PRAGMA user_version=10;",
            )?;
            tx.commit()?;
        }
        #[cfg(any(unix, windows))]
        if version < 11 {
            if version != 0 {
                migration_backup(&db, &path.with_extension("before-v11.sqlite"), 10)?;
            }
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(
                "CREATE TABLE desktop_namespace_intents(
                    namespace_id TEXT PRIMARY KEY CHECK(length(namespace_id) BETWEEN 1 AND 128),
                    origin TEXT NOT NULL CHECK(origin IN('nativeEditor','remoteOperation')),
                    native_operation_id TEXT UNIQUE REFERENCES native_editor_jobs(operation_id) ON DELETE CASCADE,
                    native_fence_id TEXT REFERENCES native_intents(id) ON DELETE CASCADE,
                    remote_actor TEXT,
                    remote_workspace TEXT,
                    remote_operation_id TEXT,
                    remote_method TEXT CHECK(remote_method IS NULL OR remote_method IN('files.rename','files.remove')),
                    remote_parameter_hash TEXT CHECK(remote_parameter_hash IS NULL OR length(remote_parameter_hash)=64),
                    remote_workspace_fence TEXT,
                    host_runtime_id TEXT NOT NULL,
                    plan_json TEXT NOT NULL CHECK(length(plan_json) BETWEEN 1 AND 2097152),
                    plan_sha256 TEXT NOT NULL CHECK(length(plan_sha256)=64),
                    prepared_proof_sha256 TEXT NOT NULL CHECK(length(prepared_proof_sha256)=64),
                    prepared_proof_json TEXT NOT NULL CHECK(length(prepared_proof_json) BETWEEN 1 AND 262144),
                    source_pin_sha256 TEXT NOT NULL CHECK(length(source_pin_sha256)=64),
                    source_parent_pin_sha256 TEXT NOT NULL CHECK(length(source_parent_pin_sha256)=64),
                    destination_parent_pin_sha256 TEXT CHECK(destination_parent_pin_sha256 IS NULL OR length(destination_parent_pin_sha256)=64),
                    state TEXT NOT NULL CHECK(state IN('prepared','applied','noChange','retiredAfterPartialRemove','retiredRequestedRecovery')),
                    completion_proof_sha256 TEXT CHECK(completion_proof_sha256 IS NULL OR length(completion_proof_sha256)=64),
                    created_at_ms TEXT NOT NULL,
                    updated_at_ms TEXT NOT NULL,
                    CHECK((origin='nativeEditor' AND native_operation_id IS NOT NULL AND native_fence_id IS NOT NULL AND
                           remote_actor IS NULL AND remote_workspace IS NULL AND remote_operation_id IS NULL AND
                           remote_method IS NULL AND remote_parameter_hash IS NULL AND remote_workspace_fence IS NULL) OR
                          (origin='remoteOperation' AND native_operation_id IS NULL AND native_fence_id IS NULL AND
                           remote_actor IS NOT NULL AND remote_workspace IS NOT NULL AND remote_operation_id IS NOT NULL AND
                           remote_method IS NOT NULL AND remote_parameter_hash IS NOT NULL AND remote_workspace_fence IS NOT NULL)),
                    FOREIGN KEY(remote_actor,remote_workspace,remote_operation_id)
                        REFERENCES operations(actor,workspace,id) ON DELETE RESTRICT,
                    CHECK((state='prepared' AND completion_proof_sha256 IS NULL) OR
                          (state IN('applied','noChange','retiredAfterPartialRemove','retiredRequestedRecovery') AND completion_proof_sha256 IS NOT NULL)),
                    CHECK(state NOT IN('retiredAfterPartialRemove','retiredRequestedRecovery') OR origin='nativeEditor')
                );
                CREATE INDEX desktop_namespace_intents_state ON desktop_namespace_intents(state);
                PRAGMA user_version=11;",
            )?;
            tx.commit()?;
        }
        #[cfg(any(unix, windows))]
        if version < 12 {
            if version != 0 {
                migration_backup(&db, &path.with_extension("before-v12.sqlite"), 11)?;
            }
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(
                "CREATE TABLE workspace_removals(
                    workspace TEXT PRIMARY KEY REFERENCES projects(workspace),
                    attempt_id TEXT NOT NULL UNIQUE,
                    owner_runtime_id TEXT NOT NULL,
                    owner_generation TEXT NOT NULL,
                    source_context_json TEXT NOT NULL CHECK(length(source_context_json) BETWEEN 1 AND 4096),
                    fenced_context_json TEXT NOT NULL CHECK(length(fenced_context_json) BETWEEN 1 AND 4096),
                    source_revision TEXT NOT NULL,
                    workspace_fence TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN('stopping','uncertain','complete'))
                );
                CREATE INDEX workspace_removals_state ON workspace_removals(state);
                CREATE TABLE workspace_removal_sessions(
                    workspace TEXT NOT NULL,
                    attempt_id TEXT NOT NULL,
                    pane TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    session_epoch TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN('pending','cleanupConfirmed','outcomeUnknown')),
                    PRIMARY KEY(workspace,attempt_id,pane),
                    UNIQUE(workspace,attempt_id,session_id),
                    FOREIGN KEY(workspace) REFERENCES workspace_removals(workspace) ON DELETE RESTRICT
                );
                CREATE INDEX workspace_removal_sessions_state
                    ON workspace_removal_sessions(workspace,attempt_id,state);
                PRAGMA user_version=12;",
            )?;
            tx.commit()?;
        }
        #[cfg(any(unix, windows))]
        if version < 13 {
            if version != 0 {
                migration_backup(&db, &path.with_extension("before-v13.sqlite"), 12)?;
            }
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(
                "CREATE TABLE profile_purge(
                    id INTEGER PRIMARY KEY CHECK(id=1),
                    attempt_id TEXT NOT NULL UNIQUE,
                    host_id TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    owner_runtime_id TEXT NOT NULL,
                    owner_generation TEXT NOT NULL,
                    profile_device TEXT NOT NULL,
                    profile_inode TEXT NOT NULL,
                    phase TEXT NOT NULL CHECK(phase IN('started','hostAuthReset','gitCredentialsCleared','storeCleared','complete')),
                    uncertain INTEGER NOT NULL CHECK(uncertain IN(0,1))
                );
                PRAGMA user_version=13;",
            )?;
            tx.commit()?;
        }
        #[cfg(any(unix, windows))]
        if version < 14 {
            if version != 0 {
                migration_backup(&db, &path.with_extension("before-v14.sqlite"), 13)?;
            }
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(
                "CREATE TABLE profile_purge_attempt_ids(
                    operation_id TEXT PRIMARY KEY CHECK(length(operation_id)=36),
                    attempt_id TEXT NOT NULL CHECK(length(attempt_id)=36)
                );
                INSERT INTO profile_purge_attempt_ids(operation_id,attempt_id)
                    SELECT attempt_id,attempt_id FROM profile_purge WHERE id=1;
                CREATE INDEX profile_purge_attempt_ids_attempt
                    ON profile_purge_attempt_ids(attempt_id);
                PRAGMA user_version=14;",
            )?;
            tx.commit()?;
        }
        #[cfg(any(unix, windows))]
        {
            if !allow_profile_purge && profile_purge::profile_purge_incomplete(&db)? {
                return Err(StoreError::PurgeInProgress);
            }
            if let Some(identity) = profile_identity {
                profile_purge::validate_profile_identity(&db, identity)?;
            }
        }
        read_authorization_state(&db)?;
        let integrity: String = db.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        if integrity != "ok" {
            return Err(StoreError::Storage);
        }
        // Obtain and retain the WAL exclusive owner lock even on an empty store.
        db.execute_batch("BEGIN IMMEDIATE; COMMIT;")?;
        let identity = decode(&db.query_row::<String, _, _>(
            "SELECT value FROM metadata WHERE key='identity'",
            [],
            |r| r.get(0),
        )?)?;
        let runtime =
            RuntimeId::from_bytes(Uuid::new_v4().into_bytes()).map_err(|_| StoreError::Invalid)?;
        let generation = increment(
            db.query_row::<String, _, _>(
                "SELECT value FROM metadata WHERE key='owner_generation'",
                [],
                |r| r.get(0),
            )?
            .parse()
            .map_err(|_| StoreError::Storage)?,
        )?;
        #[cfg(any(unix, windows))]
        let native_clock_anchor_ms = read_native_clock_floor(&db)?;
        #[cfg(any(unix, windows))]
        let native_clock_anchor = Instant::now();
        let mut store = Self {
            db,
            identity,
            runtime,
            generation,
            limits,
            authorization_sealed: std::cell::Cell::new(false),
            #[cfg(any(unix, windows))]
            native_clock_anchor,
            #[cfg(any(unix, windows))]
            native_clock_anchor_ms,
            #[cfg(any(unix, windows))]
            public_configuration: None,
        };
        if !allow_profile_purge {
            store.recover()?;
        }
        Ok(store)
    }
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    /// Checkpoint and durably close the current WAL generation before an
    /// initialization receipt is advanced from Creating to Complete.
    pub fn checkpoint_initialization(&self) -> Result<()> {
        let (busy, _log_frames, _checkpointed_frames): (i64, i64, i64) =
            self.db
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?;
        if busy != 0 {
            return Err(StoreError::Busy);
        }
        Ok(())
    }
    /// Read the saved local setup preference. Older profiles without this
    /// optional metadata entry default to Manual; malformed stored values fail
    /// closed as storage errors.
    pub fn local_start_mode(&self) -> Result<lomi_remote_protocol::ipc::LocalStartMode> {
        use lomi_remote_protocol::ipc::LocalStartMode;
        let value: Option<String> = self
            .db
            .query_row(
                "SELECT value FROM metadata WHERE key='local_start_mode'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StoreError::Storage)?;
        match value {
            Some(value) => serde_json::from_str(&value).map_err(|_| StoreError::Storage),
            None => Ok(LocalStartMode::Manual),
        }
    }
    pub fn save_local_start_mode(
        &mut self,
        mode: lomi_remote_protocol::ipc::LocalStartMode,
    ) -> Result<()> {
        let value = serde_json::to_string(&mode).map_err(|_| StoreError::Invalid)?;
        self.db
            .execute(
                "INSERT INTO metadata(key,value) VALUES('local_start_mode',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                [value],
            )
            .map_err(|_| StoreError::Storage)?;
        Ok(())
    }

    pub fn seal_authorization(&self) {
        self.authorization_sealed.set(true);
    }
    pub fn authorization_state(&self) -> Result<AuthorizationState> {
        match read_authorization_state(&self.db) {
            Ok(mut state) => {
                state.locked |= self.authorization_sealed.get();
                Ok(state)
            }
            Err(error) => {
                self.seal_authorization();
                Err(error)
            }
        }
    }
    /// Persist the trusted clock high-water mark, including across owner restart.
    pub fn observe_authorization_clock(&mut self, now: u64) -> Result<u64> {
        let outcome = (|| {
            let tx = self
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut state = read_authorization_state(&tx)?;
            state.clock_floor = state.clock_floor.max(now);
            save_authorization_state(&tx, state)?;
            tx.commit()?;
            Ok(state.clock_floor)
        })();
        if outcome.is_err() {
            self.seal_authorization();
        }
        outcome
    }
    /// Each explicit call advances the generation; this is not a replay API.
    /// Fence every active workspace, preserving terminals and operation receipts.
    pub fn fence_authorization(
        &mut self,
        reason: AuthorizationFenceReason,
    ) -> Result<AuthorizationState> {
        let outcome = (|| {
            let tx = self
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut state = read_authorization_state(&tx)?;
            state.generation = increment(state.generation)?;
            state.locked = true;
            state.pending_cloud_revoke |= reason == AuthorizationFenceReason::LocalLogout;
            save_authorization_state(&tx, state)?;
            tx.execute("DELETE FROM metadata WHERE key IN ('login_generation','authorization_verified_generation',?1,?2)", params![AUTHORIZATION_REJECTION_KEY, DEFERRED_LOGIN_KEY])?;
            fence_workspaces(&tx, self.limits)?;
            tx.commit()?;
            Ok(state)
        })();
        if outcome.is_err() {
            self.seal_authorization();
        }
        outcome
    }
    /// Fence authority rejected by the configured service. If this rejection
    /// interrupted an explicit login, carry that operation into the new
    /// generation and durably defer it behind cloud-revoke acknowledgement.
    /// Passive rejection records only the exact configuration and generation;
    /// it never creates a login intent by itself.
    pub fn fence_rejected_credentials(
        &mut self,
        expected_generation: u64,
        expected_configuration: &ipc::LocalAuthConfiguration,
    ) -> Result<AuthorizationState> {
        let outcome = (|| {
            expected_configuration
                .validate()
                .map_err(|_| StoreError::Invalid)?;
            if self.auth_configuration()?.as_ref() != Some(expected_configuration) {
                return Err(StoreError::Fenced);
            }
            let tx = self
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut state = checked_authorization_generation(&tx, expected_generation)?;
            if Self::read_auth_configuration(&tx)?.as_ref() != Some(expected_configuration) {
                return Err(StoreError::Fenced);
            }
            let (rejection, deferred) =
                validate_rejection_metadata(&tx, state, Some(expected_configuration))?;
            if rejection.is_some() || deferred.is_some() || state.pending_cloud_revoke {
                return Err(StoreError::Fenced);
            }
            let active = read_login_intent_record(&tx)?;
            if active.is_some_and(|intent| intent.generation != expected_generation) {
                return Err(StoreError::Fenced);
            }

            state.generation = increment(state.generation)?;
            state.locked = true;
            state.pending_cloud_revoke = active.is_some();
            save_authorization_state(&tx, state)?;
            tx.execute(
                "DELETE FROM metadata WHERE key IN ('login_generation','authorization_verified_generation')",
                [],
            )?;
            fence_workspaces(&tx, self.limits)?;
            save_authorization_rejection(&tx, state.generation, expected_configuration)?;
            if let Some(intent) = active {
                save_deferred_login(
                    &tx,
                    LoginIntent {
                        operation_id: intent.operation_id,
                        generation: state.generation,
                    },
                )?;
            }
            tx.commit()?;
            Ok(state)
        })();
        match &outcome {
            Ok(_) | Err(StoreError::Fenced) => {}
            Err(_) => self.seal_authorization(),
        }
        outcome
    }
    /// Revoke acknowledgement never unlocks remote access.
    pub fn acknowledge_authorization_revoke(
        &mut self,
        expected_generation: u64,
    ) -> Result<AuthorizationState> {
        let configuration = self.rejection_configuration()?;
        self.acknowledge_authorization_revoke_with_configuration(
            expected_generation,
            configuration.as_ref(),
        )
    }
    fn acknowledge_authorization_revoke_with_configuration(
        &mut self,
        expected_generation: u64,
        configuration: Option<&ipc::LocalAuthConfiguration>,
    ) -> Result<AuthorizationState> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut state = checked_authorization_generation(&tx, expected_generation)?;
        let (rejection, deferred) = validate_rejection_metadata(&tx, state, configuration)?;
        if rejection.is_some() && Self::read_auth_configuration(&tx)?.as_ref() != configuration {
            return Err(StoreError::Fenced);
        }
        let promoted = if rejection.is_some() {
            Some(deferred.ok_or(StoreError::Fenced)?)
        } else {
            None
        };
        if promoted.is_some() && !state.pending_cloud_revoke {
            return Err(StoreError::Fenced);
        }
        if !state.pending_cloud_revoke {
            // Same-generation retries after a completed ACK are intentionally
            // inert. A later login may have recorded new cloud authority in
            // this generation, so a duplicate ACK must not clear that history.
            tx.commit()?;
            return Ok(state);
        }
        state.pending_cloud_revoke = false;
        if promoted.is_some() {
            // The confirmed ACK promotes the first explicit intent without
            // restoring consent or unlocking remote access.
            state.locked = true;
        }
        save_cloud_history(&tx, false)?;
        save_authorization_state(&tx, state)?;
        if let Some(intent) = promoted {
            tx.execute(
                "INSERT INTO metadata(key,value) VALUES('login_generation',?1)",
                [json(&intent)?],
            )?;
            tx.execute(
                "DELETE FROM metadata WHERE key IN (?1,?2)",
                params![AUTHORIZATION_REJECTION_KEY, DEFERRED_LOGIN_KEY],
            )?;
        }
        tx.commit()?;
        Ok(state)
    }
    pub fn cloud_authorization_may_exist(&self) -> Result<Option<bool>> {
        read_cloud_history(&self.db)
    }
    /// Persist before any exchange can leave this owner. Logout never erases it.
    pub fn mark_cloud_authorization_possible(&mut self, expected_generation: u64) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        checked_authorization_generation(&tx, expected_generation)?;
        save_cloud_history(&tx, true)?;
        tx.commit()?;
        Ok(())
    }
    /// Pre-exchange cancellation can finish locally only with positive durable
    /// evidence that no cloud authorization request could have been emitted.
    pub fn acknowledge_local_authorization_logout(
        &mut self,
        expected_generation: u64,
    ) -> Result<AuthorizationState> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut state = checked_authorization_generation(&tx, expected_generation)?;
        let (rejection, deferred) = validate_rejection_metadata(&tx, state, None)?;
        if rejection.is_some() || deferred.is_some() {
            return Err(StoreError::Fenced);
        }
        if read_cloud_history(&tx)? != Some(false) {
            return Err(StoreError::Fenced);
        }
        state.pending_cloud_revoke = false;
        save_authorization_state(&tx, state)?;
        tx.commit()?;
        Ok(state)
    }
    /// Loss of usable credentials suspends cloud admission without revoking a
    /// workspace's explicit consent. Only fresh verified authority may unlock.
    pub fn suspend_authorization(
        &mut self,
        expected_generation: u64,
    ) -> Result<AuthorizationState> {
        let outcome = (|| {
            let tx = self
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut state = checked_authorization_generation(&tx, expected_generation)?;
            state.locked = true;
            save_authorization_state(&tx, state)?;
            tx.commit()?;
            Ok(state)
        })();
        if outcome.is_err() {
            self.seal_authorization();
        }
        outcome
    }
    /// Trusted verified-login completion only; never restores workspace consent.
    pub fn enable_authorization(&mut self, expected_generation: u64) -> Result<AuthorizationState> {
        let outcome = (|| {
            let tx = self
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut state = checked_authorization_generation(&tx, expected_generation)?;
            let (rejection, deferred) = validate_rejection_metadata(&tx, state, None)?;
            if rejection.is_some() || deferred.is_some() {
                return Err(StoreError::Fenced);
            }
            if state.pending_cloud_revoke {
                return Err(StoreError::Fenced);
            }
            state.locked = false;
            save_verified_generation(&tx, expected_generation)?;
            save_authorization_state(&tx, state)?;
            tx.commit()?;
            Ok(state)
        })();
        match &outcome {
            Ok(_) => self.authorization_sealed.set(false),
            Err(StoreError::Fenced) => {}
            Err(_) => self.seal_authorization(),
        }
        outcome
    }
    pub fn verified_authorization_generation(&self) -> Result<Option<u64>> {
        let text: Option<String> = self
            .db
            .query_row(
                "SELECT value FROM metadata WHERE key='authorization_verified_generation'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let marker: Option<VerifiedGeneration> = text
            .map(|v| serde_json::from_str(&v).map_err(|_| StoreError::Storage))
            .transpose()?;
        let state = self.authorization_state()?;
        let configuration = self.rejection_configuration()?;
        let (rejection, deferred) =
            validate_rejection_metadata(&self.db, state, configuration.as_ref())?;
        if rejection.is_some() || deferred.is_some() {
            return Ok(None);
        }
        marker
            .map(|m| {
                if m.version != 1 || m.generation != state.generation || state.pending_cloud_revoke
                {
                    return Err(StoreError::Storage);
                }
                Ok(m.generation)
            })
            .transpose()
    }
    /// Public configuration only. The host validates the canonical trusted origin
    /// and platform selection before writing and after reading this typed value.
    pub fn auth_configuration(&self) -> Result<Option<ipc::LocalAuthConfiguration>> {
        #[cfg(any(unix, windows))]
        if self.public_configuration_state()?.is_some() {
            return Ok(self.public_current()?.configuration()?.authentication);
        }
        Self::read_auth_configuration(&self.db)
    }
    fn rejection_configuration(&self) -> Result<Option<ipc::LocalAuthConfiguration>> {
        if read_authorization_rejection(&self.db)?.is_some() {
            self.auth_configuration()
        } else {
            Ok(None)
        }
    }
    fn read_auth_configuration(db: &Connection) -> Result<Option<ipc::LocalAuthConfiguration>> {
        let value: Option<String> = db
            .query_row(
                "SELECT value FROM metadata WHERE key='auth_configuration'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        value
            .map(|text| {
                let config: ipc::LocalAuthConfiguration =
                    serde_json::from_str(&text).map_err(|_| StoreError::Storage)?;
                config.validate().map_err(|_| StoreError::Storage)?;
                Ok(config)
            })
            .transpose()
    }
    pub fn configure_auth(&mut self, config: &ipc::LocalAuthConfiguration) -> Result<()> {
        #[cfg(any(unix, windows))]
        if self.public_configuration_state()?.is_some() {
            return Err(StoreError::Fenced);
        }
        config.validate().map_err(|_| StoreError::Invalid)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(mut existing) = Self::read_auth_configuration(&tx)? {
            if existing == *config {
                tx.commit()?;
                return Ok(());
            }
            // Each separately trusted endpoint may fill only its own missing
            // slot. Full equality then fences every replacement/removal and all
            // identity/provider changes, including after local logout.
            if existing.remote_api_origin.is_none() {
                existing.remote_api_origin = config.remote_api_origin.clone();
            }
            if existing.relay_endpoint.is_none() {
                existing.relay_endpoint = config.relay_endpoint.clone();
            }
            if existing != *config {
                return Err(StoreError::IdempotencyConflict);
            }
        }
        tx.execute(
            "INSERT INTO metadata(key,value) VALUES('auth_configuration',?1)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [serde_json::to_string(config).map_err(|_| StoreError::Invalid)?],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn login_intent(&self) -> Result<Option<LoginIntent>> {
        let state = self.authorization_state()?;
        let configuration = self.rejection_configuration()?;
        let (rejection, _) = validate_rejection_metadata(&self.db, state, configuration.as_ref())?;
        if rejection.is_some() {
            return Ok(None);
        }
        let intent = read_login_intent_record(&self.db)?;
        if intent
            .is_some_and(|value| state.generation != value.generation || state.pending_cloud_revoke)
        {
            return Err(StoreError::Fenced);
        }
        Ok(intent)
    }
    /// A login operation held behind a confirmed remote-revocation ACK.
    /// This remains separate from `login_intent` until that ACK is durable.
    pub fn deferred_login_intent(&self) -> Result<Option<LoginIntent>> {
        let state = self.authorization_state()?;
        let configuration = self.rejection_configuration()?;
        let (_, deferred) = validate_rejection_metadata(&self.db, state, configuration.as_ref())?;
        Ok(deferred)
    }
    pub fn begin_login(&mut self, operation_id: OperationId) -> Result<LoginIntent> {
        let configuration = self.auth_configuration()?.ok_or(StoreError::Invalid)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut state = read_authorization_state(&tx)?;
        let (rejection, deferred) = validate_rejection_metadata(&tx, state, Some(&configuration))?;
        if Self::read_auth_configuration(&tx)?.as_ref() != Some(&configuration) {
            return Err(StoreError::Fenced);
        }
        if let Some(rejection) = rejection {
            if let Some(intent) = deferred {
                tx.commit()?;
                return Ok(intent);
            }
            if state.pending_cloud_revoke || rejection.generation != state.generation {
                return Err(StoreError::Fenced);
            }
            let intent = LoginIntent {
                operation_id,
                generation: state.generation,
            };
            state.pending_cloud_revoke = true;
            save_authorization_state(&tx, state)?;
            save_deferred_login(&tx, intent)?;
            tx.commit()?;
            return Ok(intent);
        }
        if state.pending_cloud_revoke {
            return Err(StoreError::Fenced);
        }
        if let Some(intent) = read_login_intent_record(&tx)? {
            if intent.generation != state.generation {
                return Err(StoreError::Fenced);
            }
            tx.commit()?;
            return Ok(intent);
        }
        let intent = LoginIntent {
            operation_id,
            generation: state.generation,
        };
        tx.execute(
            "INSERT INTO metadata(key,value) VALUES('login_generation',?1)",
            [serde_json::to_string(&intent).map_err(|_| StoreError::Invalid)?],
        )?;
        tx.commit()?;
        Ok(intent)
    }
    /// Only a worker with a freshly verified response may finish this intent.
    pub fn complete_login(&mut self, intent: LoginIntent) -> Result<AuthorizationState> {
        let outcome = (|| {
            let tx = self
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut state = checked_authorization_generation(&tx, intent.generation)?;
            let (rejection, deferred) = validate_rejection_metadata(&tx, state, None)?;
            if rejection.is_some() || deferred.is_some() {
                return Err(StoreError::Fenced);
            }
            if state.pending_cloud_revoke {
                return Err(StoreError::Fenced);
            }
            let text: Option<String> = tx
                .query_row(
                    "SELECT value FROM metadata WHERE key='login_generation'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            let current: LoginIntent = serde_json::from_str(&text.ok_or(StoreError::Fenced)?)
                .map_err(|_| StoreError::Storage)?;
            if current != intent {
                return Err(StoreError::Fenced);
            }
            state.locked = false;
            save_verified_generation(&tx, intent.generation)?;
            save_authorization_state(&tx, state)?;
            tx.execute("DELETE FROM metadata WHERE key='login_generation'", [])?;
            tx.commit()?;
            Ok(state)
        })();
        match &outcome {
            Ok(_) => self.authorization_sealed.set(false),
            Err(StoreError::Fenced) => {}
            Err(_) => self.seal_authorization(),
        }
        outcome
    }
    pub fn default_shell(&self) -> Result<Option<DefaultShellProfile>> {
        let wire: Option<String> = self
            .db
            .query_row("SELECT config FROM default_shell WHERE id=1", [], |r| {
                r.get(0)
            })
            .optional()?;
        wire.map(|wire| {
            let profile: DefaultShellProfile = decode(&wire)?;
            profile.validate().map_err(|_| StoreError::Storage)?;
            Ok(profile)
        })
        .transpose()
    }
    /// Initialize once from trusted local selection. Existing configuration wins,
    /// even when a later service environment supplies a different default shell.
    pub fn initialize_default_shell(
        &mut self,
        profile: DefaultShellProfile,
    ) -> Result<DefaultShellProfile> {
        if let Some(existing) = self.default_shell()? {
            return Ok(existing);
        }
        profile.validate()?;
        self.db.execute(
            "INSERT INTO default_shell(id,config) VALUES(1,?1)",
            [json(&profile)?],
        )?;
        Ok(profile)
    }

    pub fn register_shell_profile(
        &mut self,
        mut profile: ipc::LocalShellProfileRegister,
    ) -> Result<()> {
        if profile
            .derived_profile_id()
            .map_err(|_| StoreError::Invalid)?
            != profile.profile_id
            || !Path::new(profile.executable.as_str()).is_absolute()
            || !Path::new(profile.cwd.as_str()).is_absolute()
        {
            return Err(StoreError::Invalid);
        }
        profile
            .environment
            .0
            .sort_by(|a, b| a.name.as_str().cmp(b.name.as_str()));
        let name = format!(
            "shell_profile/{}/{}",
            key(profile.workspace_id),
            profile.profile_id.as_str()
        );
        let cwd_key = shell_profile_cwd_key(profile.workspace_id, &profile.profile_id);
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let project = project(&tx, profile.workspace_id)?;
        desktop_namespace::ensure_namespace_project_mutation_allowed(&tx, &project.local_root)?;
        if let Some(existing) = metadata_value(&tx, &name)? {
            let existing: ipc::LocalShellProfileRegister = decode(&existing)?;
            if existing != profile {
                return Err(StoreError::IdempotencyConflict);
            }
            let _ = read_shell_profile_cwd_override(&tx, &cwd_key)?;
            tx.commit()?;
            return Ok(());
        }
        if metadata_value(&tx, &cwd_key)?.is_some() {
            return Err(StoreError::Storage);
        }
        let workspace_prefix = format!("shell_profile/{}/", key(profile.workspace_id));
        let prefix_len = i64::try_from(workspace_prefix.len()).map_err(|_| StoreError::Storage)?;
        let profile_count: i64 = tx.query_row(
            "SELECT count(*) FROM metadata WHERE substr(key,1,?1)=?2",
            params![prefix_len, workspace_prefix],
            |row| row.get(0),
        )?;
        let profile_count = usize::try_from(profile_count).map_err(|_| StoreError::Storage)?;
        if profile_count > MAX_REGISTERED_SHELL_PROFILES_PER_WORKSPACE {
            return Err(StoreError::Storage);
        }
        if profile_count >= MAX_REGISTERED_SHELL_PROFILES_PER_WORKSPACE {
            return Err(StoreError::ResourceExhausted);
        }
        tx.execute(
            "INSERT INTO metadata(key,value) VALUES(?1,?2)",
            params![name, json(&profile)?],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn shell_profile(
        &self,
        workspace_id: WorkspaceId,
        profile_id: &HostProfileId,
    ) -> Result<Option<ipc::LocalShellProfileRegister>> {
        project(&self.db, workspace_id)?;
        let name = format!(
            "shell_profile/{}/{}",
            key(workspace_id),
            profile_id.as_str()
        );
        metadata_value(&self.db, &name)?
            .map(|wire| {
                let profile: ipc::LocalShellProfileRegister = decode(&wire)?;
                if profile.workspace_id != workspace_id
                    || &profile.profile_id != profile_id
                    || profile
                        .derived_profile_id()
                        .map_err(|_| StoreError::Storage)?
                        != *profile_id
                {
                    return Err(StoreError::Storage);
                }
                Ok(profile)
            })
            .transpose()
    }

    /// List only profile IDs and display labels for one workspace. The default
    /// profile occupies one of the protocol's 32 slots; launch configuration,
    /// executable paths, arguments, CWDs, and environment values stay local.
    pub fn shell_profiles(&self, workspace_id: WorkspaceId) -> Result<Vec<HostProfile>> {
        project(&self.db, workspace_id)?;
        let workspace_prefix = format!("shell_profile/{}/", key(workspace_id));
        let prefix_len = i64::try_from(workspace_prefix.len()).map_err(|_| StoreError::Storage)?;
        let mut query = self.db.prepare(
            "SELECT key,value FROM metadata WHERE substr(key,1,?1)=?2 ORDER BY key LIMIT ?3",
        )?;
        let rows = query
            .query_map(
                params![
                    prefix_len,
                    workspace_prefix,
                    i64::try_from(MAX_SHELL_PROFILES_PER_WORKSPACE)
                        .map_err(|_| StoreError::Storage)?
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if rows.len() > MAX_REGISTERED_SHELL_PROFILES_PER_WORKSPACE {
            return Err(StoreError::Storage);
        }

        let mut profiles = Vec::with_capacity(rows.len() + 1);
        profiles.push(HostProfile {
            profile_id: "default"
                .to_owned()
                .try_into()
                .map_err(|_| StoreError::Storage)?,
            name: "Default shell"
                .to_owned()
                .try_into()
                .map_err(|_| StoreError::Storage)?,
        });
        for (stored_key, wire) in rows {
            let profile_key = stored_key
                .strip_prefix(&workspace_prefix)
                .ok_or(StoreError::Storage)?;
            let key_profile_id =
                HostProfileId::try_from(profile_key.to_owned()).map_err(|_| StoreError::Storage)?;
            let profile: ipc::LocalShellProfileRegister = decode(&wire)?;
            if profile.workspace_id != workspace_id
                || profile.profile_id != key_profile_id
                || profile.profile_id.as_str() == "default"
                || profile.operator_intent != Confirmed::Confirmed
                || profile
                    .derived_profile_id()
                    .map_err(|_| StoreError::Storage)?
                    != profile.profile_id
                || !Path::new(profile.executable.as_str()).is_absolute()
                || !Path::new(profile.cwd.as_str()).is_absolute()
            {
                return Err(StoreError::Storage);
            }
            profiles.push(HostProfile {
                profile_id: profile.profile_id,
                name: DisplayText::try_from(profile.name.as_str().to_owned())
                    .map_err(|_| StoreError::Storage)?,
            });
        }
        Ok(profiles)
    }

    /// Return an immutable registered shell profile and its owner-only,
    /// workspace-relative CWD override, if a verified namespace move created
    /// one. The original profile DTO and its derived ID remain unchanged.
    pub fn shell_profile_with_cwd_override(
        &self,
        workspace_id: WorkspaceId,
        profile_id: &HostProfileId,
    ) -> Result<Option<(ipc::LocalShellProfileRegister, Option<PathBuf>)>> {
        let Some(profile) = self.shell_profile(workspace_id, profile_id)? else {
            if metadata_value(&self.db, &shell_profile_cwd_key(workspace_id, profile_id))?.is_some()
            {
                return Err(StoreError::Storage);
            }
            return Ok(None);
        };
        let name = shell_profile_cwd_key(workspace_id, profile_id);
        let override_path = read_shell_profile_cwd_override(&self.db, &name)?;
        Ok(Some((profile, override_path)))
    }

    pub fn runtime_id(&self) -> RuntimeId {
        self.runtime
    }
    /// Expire stage-only inputs and prune eligible terminal receipts. The
    /// returned operation IDs are converted to fixed filenames and unlinked by
    /// the host only after this transaction releases the Store lock.
    #[cfg(any(unix, windows))]
    pub fn expire_native_editor_stages(&mut self) -> Result<Vec<ipc::NativeIntentId>> {
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        let expired = prune_native_editor_stages(&tx, now)?;
        tx.commit()?;
        Ok(expired)
    }
    /// Acknowledge fixed-name unlink after the host has completed the
    /// filesystem operation. Expired rows remain durable until this call, so a
    /// crash between marking and unlinking is recovered on the next startup.
    #[cfg(any(unix, windows))]
    pub fn acknowledge_native_editor_stage_cleanup(
        &mut self,
        operation_ids: &[ipc::NativeIntentId],
    ) -> Result<()> {
        if operation_ids.len() > 4096 {
            return Err(StoreError::Invalid);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for operation_id in operation_ids {
            tx.execute(
                "DELETE FROM native_file_stages WHERE operation_id=?1 AND state='expired'",
                [key(*operation_id)],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    /// Register bounded, owner-local UTF-8 input. Stage rows are idempotent by
    /// operation ID and exact metadata. Expiration is a separate Store pass so
    /// the host can unlink expired files before the quota check below.
    #[cfg(any(unix, windows))]
    pub fn register_native_editor_stage(
        &mut self,
        operation_id: ipc::NativeIntentId,
        byte_length: u64,
        content_sha256: &str,
    ) -> Result<NativeEditorStageRegistration> {
        const MAX_INPUT_BYTES: u64 = 32 * 1024 * 1024;
        const MAX_INPUTS: usize = 32;
        const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
        const INPUT_TTL_MS: u64 = 10 * 60 * 1000;
        if byte_length > MAX_INPUT_BYTES || !valid_sha256(content_sha256) {
            return Err(StoreError::Invalid);
        }
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;

        let existing: Option<(i64, String, String)> = tx
            .query_row(
                "SELECT byte_length,content_sha256,state FROM native_file_stages WHERE operation_id=?1",
                [key(operation_id)],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let existing_job: Option<(i64, String)> = tx
            .query_row(
                "SELECT blob_length,blob_sha256 FROM native_editor_jobs WHERE operation_id=?1",
                [key(operation_id)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let existing_git_job: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM native_git_jobs WHERE operation_id=?1)",
            [key(operation_id)],
            |row| row.get(0),
        )?;
        if existing_git_job {
            tx.commit()?;
            return Err(StoreError::IdempotencyConflict);
        }
        if let Some((length, digest, _state)) = existing {
            let exact = u64::try_from(length).ok() == Some(byte_length) && digest == content_sha256;
            let writable = _state == "unconsumed";
            tx.commit()?;
            return if exact {
                Ok(NativeEditorStageRegistration { writable })
            } else {
                Err(StoreError::IdempotencyConflict)
            };
        }
        if let Some((length, digest)) = existing_job {
            let exact = u64::try_from(length).ok() == Some(byte_length) && digest == content_sha256;
            tx.commit()?;
            return if exact {
                Ok(NativeEditorStageRegistration { writable: false })
            } else {
                Err(StoreError::IdempotencyConflict)
            };
        }
        let (files, bytes): (i64, i64) = tx.query_row(
            "SELECT count(*),COALESCE(sum(byte_length),0) FROM native_file_stages WHERE state='unconsumed'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let new_total = u64::try_from(bytes)
            .ok()
            .and_then(|sum| sum.checked_add(byte_length));
        if usize::try_from(files).map_err(|_| StoreError::Storage)? >= MAX_INPUTS
            || new_total.is_none_or(|sum| sum > MAX_TOTAL_BYTES)
        {
            tx.commit()?;
            return Err(StoreError::ResourceExhausted);
        }
        let expires_at_ms = now
            .checked_add(INPUT_TTL_MS)
            .ok_or(StoreError::ResourceExhausted)?;
        tx.execute(
            "INSERT INTO native_file_stages(operation_id,byte_length,content_sha256,state,expires_at_ms) VALUES(?1,?2,?3,'unconsumed',?4)",
            params![key(operation_id), byte_length as i64, content_sha256, expires_at_ms.to_string()],
        )?;
        tx.commit()?;
        Ok(NativeEditorStageRegistration { writable: true })
    }

    /// Atomically consume staged input, create the durable no-exec job record,
    /// and acquire the same global fence used by native and remote file/Git
    /// writers. The returned `Started` is the only authorization to launch the
    /// host-owned worker; `Existing` must only be reported as status.
    #[cfg(any(unix, windows))]
    pub fn begin_native_editor_job(
        &mut self,
        operation_id: ipc::NativeIntentId,
        byte_length: u64,
        content_sha256: &str,
        request_hash: &str,
        connection: ipc::IpcNonce,
    ) -> Result<NativeEditorBegin> {
        self.begin_native_editor_job_inner(
            None,
            operation_id,
            byte_length,
            content_sha256,
            request_hash,
            connection,
        )
    }

    /// Start an editor job for a Host-validated workspace snapshot. The
    /// transaction rechecks its context, canonical root, and fence before it
    /// consumes staged input or grants worker-start authority.
    #[cfg(any(unix, windows))]
    pub fn begin_native_editor_job_for_workspace(
        &mut self,
        guard: &WorkspaceEffectGuard,
        operation_id: ipc::NativeIntentId,
        byte_length: u64,
        content_sha256: &str,
        request_hash: &str,
        connection: ipc::IpcNonce,
    ) -> Result<NativeEditorBegin> {
        self.begin_native_editor_job_inner(
            Some(guard),
            operation_id,
            byte_length,
            content_sha256,
            request_hash,
            connection,
        )
    }

    #[cfg(any(unix, windows))]
    fn begin_native_editor_job_inner(
        &mut self,
        workspace_guard: Option<&WorkspaceEffectGuard>,
        operation_id: ipc::NativeIntentId,
        byte_length: u64,
        content_sha256: &str,
        request_hash: &str,
        connection: ipc::IpcNonce,
    ) -> Result<NativeEditorBegin> {
        if byte_length > 32 * 1024 * 1024
            || !valid_sha256(content_sha256)
            || !valid_sha256(request_hash)
        {
            return Err(StoreError::Invalid);
        }
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        expire_native_intents(&tx, now)?;
        prune_native_editor_jobs(&tx, now)?;
        let existing: Option<(String, i64, String, String, Option<String>)> = tx
            .query_row(
                "SELECT request_hash,blob_length,blob_sha256,state,result_json FROM native_editor_jobs WHERE operation_id=?1",
                [key(operation_id)],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()?;
        if let Some((stored_hash, stored_length, stored_sha, state, result_json)) = existing {
            let exact = stored_hash == request_hash
                && u64::try_from(stored_length).ok() == Some(byte_length)
                && stored_sha == content_sha256;
            let status = if exact {
                Some(NativeEditorJobRecord {
                    operation_id,
                    state: native_editor_job_state(&state)?,
                    result_json,
                })
            } else {
                None
            };
            tx.commit()?;
            return status
                .map(NativeEditorBegin::Existing)
                .ok_or(StoreError::IdempotencyConflict);
        }
        let collides_with_git: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM native_git_jobs WHERE operation_id=?1)",
            [key(operation_id)],
            |row| row.get(0),
        )?;
        if collides_with_git {
            tx.commit()?;
            return Err(StoreError::IdempotencyConflict);
        }
        let staged: Option<(i64, String, String, String)> = tx
            .query_row(
                "SELECT byte_length,content_sha256,state,expires_at_ms FROM native_file_stages WHERE operation_id=?1",
                [key(operation_id)],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((staged_length, staged_sha, staged_state, expires_at_ms)) = staged else {
            tx.commit()?;
            return Err(StoreError::NotFound);
        };
        if staged_state != "unconsumed"
            || u64::try_from(staged_length).ok() != Some(byte_length)
            || staged_sha != content_sha256
            || canonical_u64(expires_at_ms)? <= now
        {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        if let Some(guard) = workspace_guard {
            workspace_removal::validate_workspace_effect_guard(&tx, guard)?;
        }
        // Native editor/Git jobs can write a linked worktree's shared Git
        // common directory, which may sit outside this workspace root. Keep
        // admission global until the Store persists that physical scope.
        workspace_removal::ensure_no_workspace_removal_in_progress(&tx)?;
        if count(&tx, "SELECT count(*) FROM native_editor_jobs")? >= 4096 {
            tx.commit()?;
            return Err(StoreError::ResourceExhausted);
        }
        if has_active_native_writer(&tx)? || remote_file_git_effect_pending(&tx)? {
            tx.commit()?;
            return Err(StoreError::NativeWriterBusy);
        }
        // Retain editor fences until their joined receipt ages out, and retain
        // verified external evidence for its receipt window. Unknown fences
        // are never pruned.
        prune_finished_native_intents(&tx, now)?;
        if count(&tx, "SELECT count(*) FROM native_intents")? >= MAX_NATIVE_INTENT_ROWS {
            tx.commit()?;
            return Err(StoreError::ResourceExhausted);
        }
        if count(
            &tx,
            "SELECT count(*) FROM native_intents WHERE state IN('registered','active','quarantine')",
        )? >= 256
        {
            tx.commit()?;
            return Err(StoreError::ResourceExhausted);
        }
        let fence_id = loop {
            let candidate = ipc::NativeIntentId::from_bytes(Uuid::new_v4().into_bytes())
                .map_err(|_| StoreError::Storage)?;
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM native_intents WHERE id=?1) OR EXISTS(SELECT 1 FROM native_editor_jobs WHERE operation_id=?1) OR EXISTS(SELECT 1 FROM native_git_jobs WHERE operation_id=?1) OR ?1=?2",
                params![key(candidate), key(operation_id)],
                |row| row.get(0),
            )?;
            if !exists {
                break candidate;
            }
        };
        let expires_at_ms = now
            .checked_add(ipc::NATIVE_LEASE_MAX_MS)
            .ok_or(StoreError::ResourceExhausted)?;
        tx.execute(
            "INSERT INTO native_intents(id,connection,scope,state,fence,expires_at_ms) VALUES(?1,?2,'unscoped','active','1',?3)",
            params![key(fence_id), key(connection), expires_at_ms.to_string()],
        )?;
        if tx.execute(
            "UPDATE native_file_stages SET state='consumed' WHERE operation_id=?1 AND state='unconsumed'",
            [key(operation_id)],
        )? != 1
        {
            return Err(StoreError::Fenced);
        }
        tx.execute(
            "INSERT INTO native_editor_jobs(operation_id,request_hash,blob_length,blob_sha256,fence_id,host_runtime_id,state,result_json) VALUES(?1,?2,?3,?4,?5,?6,'running',NULL)",
            params![
                key(operation_id),
                request_hash,
                byte_length as i64,
                content_sha256,
                key(fence_id),
                key(self.runtime),
            ],
        )?;
        tx.commit()?;
        Ok(NativeEditorBegin::Started {
            operation_id,
            fence_id,
        })
    }

    #[cfg(any(unix, windows))]
    pub fn native_editor_job(
        &self,
        operation_id: ipc::NativeIntentId,
    ) -> Result<NativeEditorJobRecord> {
        let (state, result_json): (String, Option<String>) = self
            .db
            .query_row(
                "SELECT state,result_json FROM native_editor_jobs WHERE operation_id=?1",
                [key(operation_id)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        Ok(NativeEditorJobRecord {
            operation_id,
            state: native_editor_job_state(&state)?,
            result_json,
        })
    }

    /// Record that the owner-only caller durably cleared its pending journal.
    /// Unknown or still-running effects can never be acknowledged for pruning.
    #[cfg(any(unix, windows))]
    pub fn acknowledge_native_editor_job(
        &mut self,
        operation_id: ipc::NativeIntentId,
    ) -> Result<()> {
        // Namespace records are validated through their strict typed reader
        // before entering the ACK transaction. The transaction below rechecks
        // their exact durable columns before allowing a recovered disposition.
        let namespace_record =
            if desktop_namespace::namespace_intent_exists(&self.db, operation_id)? {
                Some(self.desktop_namespace_intent(operation_id)?)
            } else {
                None
            };
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        let row: Option<Option<String>> = tx
            .query_row(
                "SELECT acknowledged_at_ms FROM native_editor_jobs WHERE operation_id=?1",
                [key(operation_id)],
                |row| row.get(0),
            )
            .optional()?;
        let Some(acknowledged_at) = row else {
            tx.commit()?;
            return Ok(());
        };
        if desktop_namespace::namespace_intent_prepared(&tx, operation_id)? {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        let disposition = workspace_binding_lookup::native_editor_disposition_with_namespace(
            &tx,
            self.runtime,
            operation_id,
            namespace_record.as_ref(),
        )?;
        if disposition.retirement == ipc::NativeEditorRetirement::Unresolved {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        if acknowledged_at.is_none()
            && tx.execute(
                "UPDATE native_editor_jobs SET acknowledged_at_ms=?2 WHERE operation_id=?1 AND acknowledged_at_ms IS NULL",
                params![key(operation_id), now.to_string()],
            )? != 1
        {
            return Err(StoreError::Fenced);
        }
        tx.commit()?;
        Ok(())
    }

    #[cfg(any(unix, windows))]
    pub fn native_editor_job_retry(
        &self,
        operation_id: ipc::NativeIntentId,
        byte_length: u64,
        content_sha256: &str,
        request_hash: &str,
    ) -> Result<Option<NativeEditorJobRecord>> {
        let row: Option<(String, i64, String, String, Option<String>)> = self
            .db
            .query_row(
                "SELECT request_hash,blob_length,blob_sha256,state,result_json FROM native_editor_jobs WHERE operation_id=?1",
                [key(operation_id)],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()?;
        let Some((stored_hash, stored_length, stored_sha, state, result_json)) = row else {
            return Ok(None);
        };
        if stored_hash != request_hash
            || u64::try_from(stored_length).ok() != Some(byte_length)
            || stored_sha != content_sha256
        {
            return Err(StoreError::IdempotencyConflict);
        }
        Ok(Some(NativeEditorJobRecord {
            operation_id,
            state: native_editor_job_state(&state)?,
            result_json,
        }))
    }

    /// Trusted internal completion after the host has joined the no-exec
    /// worker. Public native requestFinish/reconcile never call this path.
    #[cfg(any(unix, windows))]
    pub fn complete_native_editor_job(
        &mut self,
        operation_id: ipc::NativeIntentId,
        state: NativeEditorJobState,
        proof: NativeEditorCompletionProof,
        result_json: Option<String>,
    ) -> Result<()> {
        if state == NativeEditorJobState::Running
            || result_json
                .as_ref()
                .is_some_and(|value| value.len() > 131_072)
        {
            return Err(StoreError::Invalid);
        }
        let state_text = native_editor_job_state_text(state);
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        let (old_state, old_result, fence_id, host_runtime_id, old_proof): (
            String,
            Option<String>,
            String,
            String,
            Option<String>,
        ) = tx
            .query_row(
                "SELECT state,result_json,fence_id,host_runtime_id,completion_proof FROM native_editor_jobs WHERE operation_id=?1",
                [key(operation_id)],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        if desktop_namespace::namespace_intent_exists(&tx, operation_id)? {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        if host_runtime_id != key(self.runtime) {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        if proof == NativeEditorCompletionProof::NotStarted && state != NativeEditorJobState::Failed
        {
            return Err(StoreError::Invalid);
        }
        if old_state != "running" {
            let exact = old_state == state_text
                && old_result == result_json
                && old_proof.as_deref() == Some(native_editor_completion_proof_text(proof));
            tx.commit()?;
            return if exact {
                Ok(())
            } else {
                Err(StoreError::Fenced)
            };
        }
        // This method is reachable only after the host has joined the no-exec
        // worker or proved thread creation failed before any effect. Outcome
        // uncertainty concerns the filesystem result, not whether a writer is
        // still running, so the internal writer fence can now be released.
        // Restart recovery does not call this method: it leaves the fence in
        // quarantine and leaves finished_at_ms NULL.
        let next_fence_state = "finished";
        if tx.execute(
            "UPDATE native_intents SET state=?2 WHERE id=?1 AND state IN('active','quarantine')",
            params![fence_id, next_fence_state],
        )? != 1
        {
            return Err(StoreError::Fenced);
        }
        if tx.execute(
            "UPDATE native_editor_jobs SET state=?2,result_json=?3,completion_proof=?4,completed_at_ms=?5 WHERE operation_id=?1 AND state='running'",
            params![
                key(operation_id),
                state_text,
                result_json,
                native_editor_completion_proof_text(proof),
                now.to_string(),
            ],
        )? != 1
        {
            return Err(StoreError::Fenced);
        }
        // The writer is now known to have stopped. Persist the cleanup intent
        // with the receipt so a crash before unlink is recovered by the next
        // sweep, without repeatedly returning this consumed input forever.
        tx.execute(
            "UPDATE native_file_stages SET state='expired' WHERE operation_id=?1 AND state='consumed'",
            [key(operation_id)],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Register a local native writer intent. Workspace IDs are validated
    /// against the current Store, but are conservatively fenced as unscoped
    /// until the host can resolve and persist canonical workspace plus Git
    /// common/worktree identities. No caller can choose the physical scope.
    #[cfg(any(unix, windows))]
    pub fn register_native_intent(
        &mut self,
        request: &ipc::NativeIntentRequest,
        connection: ipc::IpcNonce,
    ) -> Result<ipc::NativeIntentId> {
        use ipc::NativeIntentScope;
        let scope = match &request.scope {
            NativeIntentScope::Workspace { workspace_id } => {
                project(&self.db, *workspace_id)?;
                format!("workspace:{}:unscoped", key(*workspace_id))
            }
            NativeIntentScope::Unscoped {} => "unscoped".to_owned(),
        };
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        workspace_removal::ensure_native_intent_scope_available(&tx, &scope)?;
        expire_native_intents(&tx, now)?;
        let registered: Option<(String, String)> = tx
            .query_row(
                "SELECT connection,scope FROM native_intents WHERE id=?1",
                [key(request.intent_id)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((existing_connection, existing_scope)) = registered {
            let exact_retry = existing_connection == key(connection) && existing_scope == scope;
            tx.commit()?;
            return if exact_retry {
                Ok(request.intent_id)
            } else {
                Err(StoreError::Fenced)
            };
        }
        let collides_with_git: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM native_git_jobs WHERE operation_id=?1)",
            [key(request.intent_id)],
            |row| row.get(0),
        )?;
        if collides_with_git {
            tx.commit()?;
            return Err(StoreError::IdempotencyConflict);
        }
        prune_native_editor_jobs(&tx, now)?;
        prune_finished_native_intents(&tx, now)?;
        if count(&tx, "SELECT count(*) FROM native_intents")? >= MAX_NATIVE_INTENT_ROWS {
            tx.commit()?;
            return Err(StoreError::ResourceExhausted);
        }
        if count(
            &tx,
            "SELECT count(*) FROM native_intents WHERE state IN('registered','active','quarantine')",
        )? >= 256
        {
            tx.commit()?;
            return Err(StoreError::ResourceExhausted);
        }
        tx.execute(
            "INSERT INTO native_intents(id,connection,scope,state,fence,expires_at_ms) VALUES(?1,?2,?3,'registered','0','0')",
            params![key(request.intent_id), key(connection), scope],
        )?;
        tx.commit()?;
        Ok(request.intent_id)
    }
    /// Return a bound lease for an exact same-connection retry, or prove that
    /// this ID is still an unbound Registered intent before helper capture.
    /// Binding metadata is immutable once inserted.
    #[cfg(any(unix, windows))]
    pub fn native_bind_preflight(
        &mut self,
        intent_id: ipc::NativeIntentId,
        connection: ipc::IpcNonce,
        store_root: &str,
        parent_operation_id: &str,
    ) -> Result<Option<ipc::NativeLease>> {
        if store_root.is_empty()
            || store_root.len() > 4096
            || parent_operation_id.is_empty()
            || parent_operation_id.len() > 256
        {
            return Err(StoreError::Invalid);
        }
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        expire_native_intents(&tx, now)?;
        let (lease, owner, state, _) = native_intent_row(&tx, intent_id)?;
        if owner != key(connection) {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        match native_evidence_binding(&tx, intent_id)? {
            Some(binding) => {
                if binding.store_root != store_root
                    || binding.parent_operation_id != parent_operation_id
                    || state == ipc::NativeWriterState::Registered
                {
                    tx.commit()?;
                    return Err(StoreError::IdempotencyConflict);
                }
                tx.commit()?;
                Ok(Some(lease))
            }
            None if state == ipc::NativeWriterState::Registered => {
                tx.commit()?;
                Ok(None)
            }
            None => {
                tx.commit()?;
                Err(StoreError::Fenced)
            }
        }
    }
    /// Atomically close an unbound Registered intent after Capture is known
    /// to be unsupported or invalid. The caller may report definitive refusal
    /// only after this transition commits; an Active/Quarantine race is unknown.
    #[cfg(any(unix, windows))]
    pub fn reject_unbound_native_intent(
        &mut self,
        intent_id: ipc::NativeIntentId,
        connection: ipc::IpcNonce,
    ) -> Result<()> {
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        let owner_state: Option<(String, String)> = tx
            .query_row(
                "SELECT connection,state FROM native_intents WHERE id=?1",
                [key(intent_id)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let binding_exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM native_evidence_bindings WHERE intent_id=?1)",
            [key(intent_id)],
            |row| row.get(0),
        )?;
        if owner_state
            .as_ref()
            .is_none_or(|(owner, state)| owner != &key(connection) || state != "registered")
            || binding_exists
        {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        if tx.execute(
            "UPDATE native_intents SET state='finished',expires_at_ms=?3 WHERE id=?1 AND connection=?2 AND state='registered'",
            params![key(intent_id), key(connection), now.to_string()],
        )? != 1
        {
            return Err(StoreError::Fenced);
        }
        tx.commit()?;
        Ok(())
    }
    /// Record that the owner-only caller durably persisted observation of a
    /// Finished native intent. A missing row is idempotent success; no effect
    /// status is implied by that response. Registered, Active, and Quarantine
    /// rows cannot be acknowledged or pruned.
    #[cfg(any(unix, windows))]
    pub fn acknowledge_native_intent(&mut self, intent_id: ipc::NativeIntentId) -> Result<()> {
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        expire_native_intents(&tx, now)?;
        let state: Option<String> = tx
            .query_row(
                "SELECT state FROM native_intents WHERE id=?1",
                [key(intent_id)],
                |row| row.get(0),
            )
            .optional()?;
        let Some(state) = state else {
            tx.commit()?;
            return Ok(());
        };
        if state != "finished" {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        let editor_fence: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM native_editor_jobs WHERE fence_id=?1)
                 OR EXISTS(SELECT 1 FROM native_git_jobs WHERE fence_id=?1)",
            [key(intent_id)],
            |row| row.get(0),
        )?;
        if editor_fence {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        let binding_status: Option<(Option<String>, Option<String>)> = tx
            .query_row(
                "SELECT verified_at_ms,acknowledged_at_ms FROM native_evidence_bindings WHERE intent_id=?1",
                [key(intent_id)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if binding_status
            .as_ref()
            .is_some_and(|(verified_at, _)| verified_at.is_none())
        {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        tx.execute(
            "UPDATE native_intents SET acknowledged_at_ms=COALESCE(acknowledged_at_ms,?2) WHERE id=?1 AND state='finished'",
            params![key(intent_id), now.to_string()],
        )?;
        if binding_status.is_some() {
            tx.execute(
                "UPDATE native_evidence_bindings SET acknowledged_at_ms=COALESCE(acknowledged_at_ms,?2) WHERE intent_id=?1 AND verified_at_ms IS NOT NULL",
                params![key(intent_id), now.to_string()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    /// Persist the trusted helper capture and activate its global writer fence
    /// in one Store transaction. The caller performs no external work while
    /// this transaction is open.
    #[cfg(any(unix, windows))]
    pub fn bind_registered_native_intent(
        &mut self,
        intent_id: ipc::NativeIntentId,
        connection: ipc::IpcNonce,
        store_root: &str,
        parent_operation_id: &str,
        binding_json: &str,
        runtime_descriptor_json: &str,
    ) -> Result<ipc::NativeLease> {
        if store_root.is_empty()
            || store_root.len() > 4096
            || parent_operation_id.is_empty()
            || parent_operation_id.len() > 256
            || binding_json.is_empty()
            || binding_json.len() > 131_072
            || runtime_descriptor_json.is_empty()
            || runtime_descriptor_json.len() > 16_384
        {
            return Err(StoreError::Invalid);
        }
        let binding_sha256 = format!("{:x}", Sha256::digest(binding_json.as_bytes()));
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        expire_native_intents(&tx, now)?;
        let (lease, owner, state, _) = native_intent_row(&tx, intent_id)?;
        if owner != key(connection) {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        let existing: Option<(String, String, String, String)> = tx
            .query_row(
                "SELECT store_root,parent_operation_id,binding_json,runtime_descriptor_json FROM native_evidence_bindings WHERE intent_id=?1",
                [key(intent_id)],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        if let Some((old_root, old_parent, old_binding, old_descriptor)) = existing {
            let exact = old_root == store_root
                && old_parent == parent_operation_id
                && old_binding == binding_json
                && old_descriptor == runtime_descriptor_json;
            tx.commit()?;
            return if exact {
                Ok(lease)
            } else {
                Err(StoreError::IdempotencyConflict)
            };
        }
        if state != ipc::NativeWriterState::Registered {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        prune_native_editor_jobs(&tx, now)?;
        prune_finished_native_intents(&tx, now)?;
        if count(&tx, "SELECT count(*) FROM native_evidence_bindings")? >= 4096 {
            tx.commit()?;
            return Err(StoreError::ResourceExhausted);
        }
        if has_active_native_writer(&tx)? || remote_file_git_effect_pending(&tx)? {
            tx.commit()?;
            return Err(StoreError::NativeWriterBusy);
        }
        let fence = increment(lease.fence.0)?;
        let expires_at_ms = now
            .checked_add(ipc::NATIVE_LEASE_MAX_MS)
            .ok_or(StoreError::ResourceExhausted)?;
        tx.execute(
            "INSERT INTO native_evidence_bindings(intent_id,store_root,parent_operation_id,binding_json,runtime_descriptor_json,binding_sha256,created_at_ms,verified_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,NULL)",
            params![
                key(intent_id),
                store_root,
                parent_operation_id,
                binding_json,
                runtime_descriptor_json,
                binding_sha256,
                now.to_string(),
            ],
        )?;
        if tx.execute(
            "UPDATE native_intents SET state='active',fence=?2,expires_at_ms=?3 WHERE id=?1 AND state='registered'",
            params![key(intent_id), fence.to_string(), expires_at_ms.to_string()],
        )? != 1
        {
            return Err(StoreError::Fenced);
        }
        tx.commit()?;
        Ok(native_lease(
            intent_id,
            fence,
            expires_at_ms,
            ipc::NativeWriterState::Active,
        ))
    }
    /// Quarantine an intent before external Verify I/O and return its immutable
    /// capture. A missing binding is a normal unknown state, never proof.
    #[cfg(any(unix, windows))]
    pub fn quarantine_native_intent_for_verification(
        &mut self,
        intent_id: ipc::NativeIntentId,
    ) -> Result<(ipc::NativeLease, Option<NativeEvidenceBinding>)> {
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        expire_native_intents(&tx, now)?;
        tx.execute(
            "UPDATE native_intents SET state='quarantine' WHERE id=?1 AND state='active'",
            [key(intent_id)],
        )?;
        tx.execute(
            "UPDATE native_git_jobs SET state='outcomeUnknown',result_json=NULL,completion_proof=NULL,
             completed_at_ms=NULL,updated_at_ms=?2 WHERE fence_id=?1 AND state='running'",
            params![key(intent_id), now.to_string()],
        )?;
        let (lease, _, _, _) = native_intent_row(&tx, intent_id)?;
        let binding = native_evidence_binding(&tx, intent_id)?;
        tx.commit()?;
        Ok((lease, binding))
    }
    /// Release only after the caller validates a tagged helper Verified reply.
    /// The hash ties that reply to the exact durable capture used for Verify.
    #[cfg(any(unix, windows))]
    pub fn finish_native_intent_if_binding_matches(
        &mut self,
        intent_id: ipc::NativeIntentId,
        binding_sha256: &str,
    ) -> Result<ipc::NativeLease> {
        if !valid_sha256(binding_sha256) {
            return Err(StoreError::Invalid);
        }
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        let (lease, _, state, _) = native_intent_row(&tx, intent_id)?;
        let stored_hash: Option<String> = tx
            .query_row(
                "SELECT binding_sha256 FROM native_evidence_bindings WHERE intent_id=?1",
                [key(intent_id)],
                |row| row.get(0),
            )
            .optional()?;
        if stored_hash.as_deref() != Some(binding_sha256) {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        if state == ipc::NativeWriterState::Finished {
            tx.commit()?;
            return Ok(lease);
        }
        if state != ipc::NativeWriterState::Quarantine {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        if tx.execute(
            "UPDATE native_intents SET state='finished' WHERE id=?1 AND state='quarantine'",
            [key(intent_id)],
        )? != 1
            || tx.execute(
                "UPDATE native_evidence_bindings SET verified_at_ms=?2 WHERE intent_id=?1 AND binding_sha256=?3",
                params![key(intent_id), now.to_string(), binding_sha256],
            )? != 1
        {
            return Err(StoreError::Fenced);
        }
        let (lease, _, _, _) = native_intent_row(&tx, intent_id)?;
        tx.commit()?;
        Ok(lease)
    }
    /// Atomically acquire the native lease only when no remote file/Git effect
    /// is running or uncertain. Remote effect admission uses this same database
    /// transaction boundary, so one side always observes the other's fence.
    #[cfg(any(unix, windows))]
    pub fn acquire_native_intent(
        &mut self,
        intent_id: ipc::NativeIntentId,
        connection: ipc::IpcNonce,
    ) -> Result<ipc::NativeLease> {
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        expire_native_intents(&tx, now)?;
        let row: Option<(String, String, String, String)> = tx
            .query_row(
                "SELECT connection,state,fence,scope FROM native_intents WHERE id=?1",
                [key(intent_id)],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((owner, state, fence, scope)) = row else {
            tx.commit()?;
            return Err(StoreError::NotFound);
        };
        if owner != key(connection) || state != "registered" {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        workspace_removal::ensure_native_intent_scope_available(&tx, &scope)?;
        let bound: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM native_evidence_bindings WHERE intent_id=?1)",
            [key(intent_id)],
            |row| row.get(0),
        )?;
        if !bound {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        if has_active_native_writer(&tx)? || remote_file_git_effect_pending(&tx)? {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        let fence = increment(canonical_u64(fence)?)?;
        let expires_at_ms = now
            .checked_add(ipc::NATIVE_LEASE_MAX_MS)
            .ok_or(StoreError::ResourceExhausted)?;
        if tx.execute(
            "UPDATE native_intents SET state='active',fence=?2,expires_at_ms=?3 WHERE id=?1 AND state='registered'",
            params![key(intent_id), fence.to_string(), expires_at_ms.to_string()],
        )? != 1
        {
            return Err(StoreError::Fenced);
        }
        tx.commit()?;
        Ok(native_lease(
            intent_id,
            fence,
            expires_at_ms,
            ipc::NativeWriterState::Active,
        ))
    }
    /// Check the connection-bound lease. Expiry revokes client authority only
    /// by moving Active to Quarantine; it never releases the writer barrier.
    #[cfg(any(unix, windows))]
    pub fn check_native_intent(
        &mut self,
        intent_id: ipc::NativeIntentId,
        connection: ipc::IpcNonce,
    ) -> Result<ipc::NativeLease> {
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        expire_native_intents(&tx, now)?;
        let lease = native_intent_row(&tx, intent_id)?;
        if lease.1 != key(connection) || lease.2 != ipc::NativeWriterState::Active {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        tx.commit()?;
        Ok(lease.0)
    }
    /// Extend an active, unexpired lease by the protocol maximum. A lease can
    /// never be revived after expiry or IPC loss has placed it in quarantine.
    #[cfg(any(unix, windows))]
    pub fn renew_native_intent(
        &mut self,
        intent_id: ipc::NativeIntentId,
        connection: ipc::IpcNonce,
    ) -> Result<ipc::NativeLease> {
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        expire_native_intents(&tx, now)?;
        let (lease, owner, state, old_expiry) = native_intent_row(&tx, intent_id)?;
        if owner != key(connection) || state != ipc::NativeWriterState::Active {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        let expires_at_ms = now
            .checked_add(ipc::NATIVE_LEASE_MAX_MS)
            .ok_or(StoreError::ResourceExhausted)?;
        if expires_at_ms <= old_expiry {
            tx.commit()?;
            return Err(StoreError::Fenced);
        }
        tx.execute(
            "UPDATE native_intents SET expires_at_ms=?2 WHERE id=?1 AND state='active'",
            params![key(intent_id), expires_at_ms.to_string()],
        )?;
        tx.commit()?;
        Ok(native_lease(
            intent_id,
            lease.fence.0,
            expires_at_ms,
            ipc::NativeWriterState::Active,
        ))
    }
    /// Requests and reconciliations are not evidence that an external native
    /// writer stopped. Both retain the durable quarantine fence until a trusted
    /// runtime verifier or explicit audited local operator resolution exists.
    #[cfg(any(unix, windows))]
    pub fn request_finish_native_intent(
        &mut self,
        intent_id: ipc::NativeIntentId,
    ) -> Result<ipc::NativeLease> {
        self.quarantine_native_intent(intent_id)
    }
    #[cfg(any(unix, windows))]
    pub fn reconcile_native_intent(
        &mut self,
        intent_id: ipc::NativeIntentId,
    ) -> Result<ipc::NativeLease> {
        self.quarantine_native_intent(intent_id)
    }
    #[cfg(any(unix, windows))]
    fn quarantine_native_intent(
        &mut self,
        intent_id: ipc::NativeIntentId,
    ) -> Result<ipc::NativeLease> {
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        tx.execute(
            "UPDATE native_intents SET state='quarantine' WHERE id=?1 AND state='active'",
            [key(intent_id)],
        )?;
        tx.execute(
            "UPDATE native_git_jobs SET state='outcomeUnknown',result_json=NULL,completion_proof=NULL,
             completed_at_ms=NULL,updated_at_ms=?2 WHERE fence_id=?1 AND state='running'",
            params![key(intent_id), now.to_string()],
        )?;
        let (lease, _, state, _) = native_intent_row(&tx, intent_id)?;
        tx.commit()?;
        Ok(native_lease(
            intent_id,
            lease.fence.0,
            lease.expires_at_ms.0,
            state,
        ))
    }
    /// Called when the owning local IPC stream closes. A lost Active intent
    /// remains quarantined and continues to fence remote file/Git effects.
    #[cfg(any(unix, windows))]
    pub fn quarantine_native_connection(&mut self, connection: ipc::IpcNonce) -> Result<()> {
        let has_cleanup: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM native_intents WHERE connection=?1 AND state IN('registered','active'))",
            [key(connection)],
            |row| row.get(0),
        )?;
        if !has_cleanup {
            return Ok(());
        }
        let previous_anchor = self.native_clock_anchor;
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        self.native_clock_anchor = anchor;
        self.native_clock_anchor_ms = anchor_ms;
        // A registered intent has not acquired authority and owns no effects;
        // deleting only that state avoids leaking slots across abandoned local
        // IPC sessions. Active rows are retained as quarantine below.
        tx.execute(
            "DELETE FROM native_intents WHERE connection=?1 AND state='registered'",
            [key(connection)],
        )?;
        tx.execute(
            "UPDATE native_intents SET state='quarantine' WHERE connection=?1 AND state='active'",
            [key(connection)],
        )?;
        tx.execute(
            "UPDATE native_git_jobs SET state='outcomeUnknown',result_json=NULL,completion_proof=NULL,
             completed_at_ms=NULL,updated_at_ms=?2
             WHERE state='running' AND fence_id IN(
                 SELECT id FROM native_intents WHERE connection=?1 AND state='quarantine'
             )",
            params![key(connection), now.to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }
    /// Read through the actual Store owner. Installers must not infer database
    /// compatibility from a binary version or an unlocked SQLite connection.
    pub fn maintenance_status(&self) -> Result<ipc::LocalMaintenanceStatus> {
        let schema: i64 = self
            .db
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        if schema != VERSION {
            return Err(StoreError::SchemaVersion);
        }
        Ok(ipc::LocalMaintenanceStatus {
            host_id: self.identity.host_id,
            runtime_id: self.runtime,
            profile_schema: DecimalU64(u64::try_from(schema).map_err(|_| StoreError::Storage)?),
            active_terminals: DecimalU64(count(
                &self.db,
                "SELECT count(*) FROM terminals WHERE status='Running'",
            )? as u64),
        })
    }
    pub fn checked_backup(&self, path: &Path) -> Result<()> {
        checked_backup(&self.db, path, VERSION)
    }
    pub fn add_project(&mut self, root: &Path, name: DisplayText) -> Result<ProjectRecord> {
        let root = prepare_project_root(root)?;
        self.insert_prepared_project(&root, name)
    }

    /// Insert a previously validated root using only Store/domain data and SQL.
    /// No filesystem work occurs here. The private token fields prevent callers
    /// from bypassing the canonical-directory and UTF-8 preparation checks.
    pub fn insert_prepared_project(
        &mut self,
        root: &ValidatedProjectRoot,
        name: DisplayText,
    ) -> Result<ProjectRecord> {
        self.insert_prepared_workspace(root, name, None)
    }

    /// The native desktop persists its stable ID before dispatch. A lost
    /// response can therefore be recovered without allocating a second owner.
    /// Re-import never re-enables sharing or revives a removed workspace.
    pub fn import_prepared_workspace(
        &mut self,
        root: &ValidatedProjectRoot,
        name: DisplayText,
        workspace_id: WorkspaceId,
    ) -> Result<ProjectRecord> {
        self.insert_prepared_workspace(root, name, Some(workspace_id))
    }

    fn insert_prepared_workspace(
        &mut self,
        root: &ValidatedProjectRoot,
        name: DisplayText,
        imported_id: Option<WorkspaceId>,
    ) -> Result<ProjectRecord> {
        let root_text = root.canonical.to_str().ok_or(StoreError::Invalid)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        #[cfg(any(unix, windows))]
        desktop_namespace::ensure_namespace_project_mutation_allowed(&tx, &root.canonical)?;
        let workspace_id = if let Some(workspace_id) = imported_id {
            let alias_key = format!("workspace_import/{}", key(workspace_id));
            if let Some(wire) = metadata_value(&tx, &alias_key)? {
                let alias: WorkspaceImportAlias = decode(&wire)?;
                if alias.canonical_root != root_text {
                    return Err(StoreError::IdempotencyConflict);
                }
                let existing = project(&tx, alias.workspace_id).map_err(|error| match error {
                    StoreError::NotFound => StoreError::IdempotencyConflict,
                    other => other,
                })?;
                if existing.local_root != root.canonical {
                    return Err(StoreError::Storage);
                }
                tx.commit()?;
                return Ok(existing);
            }
            let existing: Option<(String, bool)> = tx
                .query_row(
                    "SELECT root,removed FROM projects WHERE workspace=?1",
                    [key(workspace_id)],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if let Some((existing_root, removed)) = existing {
                if removed || existing_root != root_text {
                    return Err(StoreError::IdempotencyConflict);
                }
                let existing = project(&tx, workspace_id)?;
                remember_workspace_import(
                    &tx,
                    workspace_id,
                    workspace_id,
                    root_text,
                    self.limits.operations,
                )?;
                tx.commit()?;
                return Ok(existing);
            }
            if let Some(existing) = projects(&tx)?
                .into_iter()
                .find(|project| project.local_root == root.canonical && project.state.name == name)
            {
                remember_workspace_import(
                    &tx,
                    workspace_id,
                    existing.state.context.workspace_id,
                    root_text,
                    self.limits.operations,
                )?;
                tx.commit()?;
                return Ok(existing);
            }
            workspace_id
        } else {
            // Local Add has no caller-supplied stable ID. Reuse the existing
            // folder/name binding so retrying a lost reply cannot duplicate it.
            if let Some(existing) = projects(&tx)?
                .into_iter()
                .find(|project| project.local_root == root.canonical && project.state.name == name)
            {
                tx.commit()?;
                return Ok(existing);
            }
            WorkspaceId::from_bytes(Uuid::new_v4().into_bytes()).map_err(|_| StoreError::Invalid)?
        };
        let state = WorkspaceState {
            context: WorkspaceContext {
                workspace_id,
                workspace_epoch: WorkspaceEpoch::from_bytes(Uuid::new_v4().into_bytes())
                    .map_err(|_| StoreError::Invalid)?,
                runtime_id: self.runtime,
                runtime_generation: DecimalU64(self.generation),
                host_access_epoch: DecimalU64(0),
                grant_revision: DecimalU64(0),
            },
            domain_revision: DecimalU64(0),
            name,
            tabs: BoundedList(Vec::new()),
        };
        if count(&tx, "SELECT count(*) FROM projects")? >= self.limits.workspaces {
            return Err(StoreError::ResourceExhausted);
        }
        ensure_capacity(&tx, self.limits, 1, false)?;
        tx.execute(
            "INSERT INTO projects(workspace,root,state,consent,fence) VALUES(?1,?2,?3,0,'0')",
            params![key(workspace_id), root_text, json(&state)?],
        )?;
        append_event(&tx, &state, None)?;
        if let Some(import_id) = imported_id {
            remember_workspace_import(
                &tx,
                import_id,
                workspace_id,
                root_text,
                self.limits.operations,
            )?;
        }
        tx.commit()?;
        Ok(ProjectRecord {
            local_root: root.canonical.clone(),
            state,
            consent: false,
            fence: 0,
        })
    }
    pub fn list_projects(&self) -> Result<Vec<ProjectRecord>> {
        let records = projects(&self.db)?;
        #[cfg(any(unix, windows))]
        for record in &records {
            desktop_namespace::ensure_namespace_root_available(&self.db, &record.local_root)?;
        }
        Ok(records)
    }
    pub fn workspace(&self, id: WorkspaceId) -> Result<ProjectRecord> {
        let record = project(&self.db, id)?;
        #[cfg(any(unix, windows))]
        desktop_namespace::ensure_namespace_root_available(&self.db, &record.local_root)?;
        Ok(record)
    }
    /// Read the persisted projection for an owner-local publication status
    /// response. Unlike workspace(), this does not authorize root access and
    /// remains available while a namespace transaction temporarily reserves it.
    pub fn workspace_publication_record(&self, id: WorkspaceId) -> Result<ProjectRecord> {
        project(&self.db, id)
    }
    /// Rename a workspace with a compare-and-swap on its current display name.
    /// Its stable ID, local root, import aliases, consent, and fence are retained.
    pub fn rename_project(
        &mut self,
        id: WorkspaceId,
        expected_name: &ipc::LocalProjectName,
        name: &ipc::LocalProjectName,
    ) -> Result<ProjectRecord> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = project(&tx, id)?;
        #[cfg(any(unix, windows))]
        desktop_namespace::ensure_namespace_project_mutation_allowed(&tx, &record.local_root)?;
        if record.state.name.as_str() != expected_name.as_str() {
            return Err(StoreError::RevisionConflict);
        }
        let name =
            DisplayText::try_from(name.as_str().to_owned()).map_err(|_| StoreError::Invalid)?;
        if record.state.name == name {
            tx.commit()?;
            return Ok(record);
        }
        ensure_capacity(&tx, self.limits, 1, false)?;
        record.state.name = name;
        record.state.domain_revision = DecimalU64(increment(record.state.domain_revision.0)?);
        save_project(&tx, &record)?;
        append_event(&tx, &record.state, None)?;
        queue_publication(&tx, &record)?;
        tx.commit()?;
        Ok(record)
    }
    pub fn terminal_descriptors(&self, id: WorkspaceId) -> Result<Vec<TerminalDescriptor>> {
        project(&self.db, id)?;
        let mut q = self
            .db
            .prepare("SELECT pane,status FROM terminals WHERE workspace=?1 ORDER BY pane")?;
        let rows = q.query_map([key(id)], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        rows.map(|r| {
            let (p, s) = r?;
            Ok(TerminalDescriptor {
                pane_id: PaneId::try_from(p).map_err(|_| StoreError::Storage)?,
                status: decode(&format!("\"{s}\""))?,
            })
        })
        .collect()
    }
    /// Pure domain CAS: rename one existing terminal tab. Uses the canonical
    /// terminal.rename method and atomically commits state, receipt and event.
    pub fn rename_tab(
        &mut self,
        binding: &OperationBinding,
        expected: DecimalU64,
        tab_id: TabId,
        name: DisplayText,
    ) -> Result<Admission> {
        if binding.rights.original_method() != Method::TerminalRename {
            return Err(StoreError::Invalid);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(receipt) = existing(&tx, binding)? {
            return Ok(Admission {
                receipt,
                newly_admitted: false,
            });
        }
        ensure_capacity(&tx, self.limits, 1, true)?;
        let mut p = project(&tx, binding.rights.workspace())?;
        if p.state.domain_revision != expected {
            return Err(StoreError::RevisionConflict);
        }
        p.state
            .tabs
            .0
            .iter_mut()
            .find(|t| t.tab_id == tab_id)
            .ok_or(StoreError::NotFound)?
            .name = name;
        p.state.domain_revision = DecimalU64(increment(expected.0)?);
        let receipt = receipt(
            binding,
            OperationState::Succeeded,
            Effect::Committed,
            Some(OperationResult::Domain {
                domain_revision: p.state.domain_revision,
            }),
        )?;
        save_project(&tx, &p)?;
        insert_operation(&tx, binding, &receipt, p.fence, expected, 0)?;
        append_event(&tx, &p.state, Some(binding.rights.operation_id()))?;
        queue_publication(&tx, &p)?;
        tx.commit()?;
        Ok(Admission {
            receipt,
            newly_admitted: true,
        })
    }
    /// Atomic existing-pane layout CAS. The typed planner cannot supply an
    /// arbitrary projection or PTY effect; bindings remain caller-authorized.
    pub fn move_pane(
        &mut self,
        binding: &OperationBinding,
        expected: DecimalU64,
        layout: &TerminalMoveLayout,
    ) -> Result<Admission> {
        if binding.rights.original_method() != Method::TerminalMove {
            return Err(StoreError::Invalid);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(receipt) = existing(&tx, binding)? {
            return Ok(Admission {
                receipt,
                newly_admitted: false,
            });
        }
        ensure_capacity(&tx, self.limits, 1, true)?;
        let mut p = project(&tx, binding.rights.workspace())?;
        if p.state.domain_revision != expected {
            return Err(StoreError::RevisionConflict);
        }
        // Preserve the local planner's overflow-before-layout-error order.
        let next_revision = DecimalU64(increment(expected.0)?);
        p.state = plan_terminal_move(&p.state, layout).map_err(|error| match error {
            TerminalMoveError::InvalidArgument => StoreError::Invalid,
            TerminalMoveError::NotFound => StoreError::NotFound,
            TerminalMoveError::ResourceExhausted => StoreError::ResourceExhausted,
        })?;
        p.state.domain_revision = next_revision;
        let receipt = receipt(
            binding,
            OperationState::Succeeded,
            Effect::Committed,
            Some(OperationResult::Domain {
                domain_revision: p.state.domain_revision,
            }),
        )?;
        save_project(&tx, &p)?;
        insert_operation(&tx, binding, &receipt, p.fence, expected, 0)?;
        append_event(&tx, &p.state, Some(binding.rights.operation_id()))?;
        queue_publication(&tx, &p)?;
        tx.commit()?;
        Ok(Admission {
            receipt,
            newly_admitted: true,
        })
    }
    /// Persist intent and reserve event capacity before any external effect.
    pub fn admit_external(
        &mut self,
        binding: &OperationBinding,
        expected: DecimalU64,
    ) -> Result<Admission> {
        if !is_durable_mutation(binding.rights.original_method()) {
            return Err(StoreError::Invalid);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(receipt) = existing(&tx, binding)? {
            return Ok(Admission {
                receipt,
                newly_admitted: false,
            });
        }
        #[cfg(any(unix, windows))]
        desktop_namespace::ensure_namespace_mutation_allowed(&tx, binding)?;
        ensure_capacity(&tx, self.limits, 3, true)?;
        let p = project(&tx, binding.rights.workspace())?;
        if p.state.domain_revision != expected {
            return Err(StoreError::RevisionConflict);
        }
        let receipt = receipt(binding, OperationState::Accepted, Effect::None, None)?;
        insert_operation(&tx, binding, &receipt, p.fence, expected, 2)?;
        append_event(&tx, &p.state, Some(binding.rights.operation_id()))?;
        tx.commit()?;
        Ok(Admission {
            receipt,
            newly_admitted: true,
        })
    }
    /// One accepted -> running transition. Duplicate calls never return another
    /// permit; a running/uncertain operation must be inspected, never replayed.
    pub fn start_external(&mut self, binding: &OperationBinding) -> Result<ExternalPermit> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = existing(&tx, binding)?.ok_or(StoreError::NotFound)?;
        if old.state() != OperationState::Accepted {
            return Err(StoreError::AlreadyStarted);
        }
        #[cfg(any(unix, windows))]
        desktop_namespace::ensure_namespace_mutation_allowed(&tx, binding)?;
        #[cfg(any(unix, windows))]
        if is_remote_file_git_write(binding.rights.original_method())
            && has_active_native_writer(&tx)?
        {
            return Err(StoreError::NativeWriterBusy);
        }
        let p = project(&tx, binding.rights.workspace())?;
        let (fence, revision): (String, String) = tx.query_row(
            "SELECT fence,revision FROM operations WHERE actor=?1 AND workspace=?2 AND id=?3",
            op_params(binding),
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if fence != p.fence.to_string() {
            return Err(StoreError::Fenced);
        }
        if revision != p.state.domain_revision.0.to_string() {
            return Err(StoreError::RevisionConflict);
        }
        let running = receipt(binding, OperationState::Running, Effect::None, None)?;
        update_operation(&tx, binding, &running, 1)?;
        append_event(&tx, &p.state, Some(binding.rights.operation_id()))?;
        tx.commit()?;
        Ok(ExternalPermit {
            binding: binding.clone(),
            fence: p.fence,
            runtime: self.runtime,
        })
    }
    /// Persist intent and the single accepted-to-running transition in ONE
    /// transaction. A duplicate returns its stored receipt and never a permit; a
    /// new operation always returns the only permit for this binding. Event and
    /// capacity accounting is identical to `admit_external` followed by
    /// `start_external` (three events in total once completed), but there is no
    /// observable Accepted-without-permit state for a remote writer to strand.
    pub fn admit_start_external(
        &mut self,
        binding: &OperationBinding,
        expected: DecimalU64,
    ) -> Result<(Admission, Option<ExternalPermit>)> {
        self.admit_start_inner(binding, Some(expected))
    }
    /// Same atomic admit+start for operations whose preconditions are carried by
    /// their own parameters (file revisions) rather than the workspace domain
    /// revision. The stored revision is the one read inside this transaction.
    pub fn admit_start_external_unversioned(
        &mut self,
        binding: &OperationBinding,
    ) -> Result<(Admission, Option<ExternalPermit>)> {
        self.admit_start_inner(binding, None)
    }
    fn admit_start_inner(
        &mut self,
        binding: &OperationBinding,
        expected: Option<DecimalU64>,
    ) -> Result<(Admission, Option<ExternalPermit>)> {
        if !is_durable_mutation(binding.rights.original_method()) {
            return Err(StoreError::Invalid);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(receipt) = existing(&tx, binding)? {
            return Ok((
                Admission {
                    receipt,
                    newly_admitted: false,
                },
                None,
            ));
        }
        #[cfg(any(unix, windows))]
        desktop_namespace::ensure_namespace_mutation_allowed(&tx, binding)?;
        #[cfg(any(unix, windows))]
        if is_remote_file_git_write(binding.rights.original_method())
            && has_active_native_writer(&tx)?
        {
            return Err(StoreError::NativeWriterBusy);
        }
        ensure_capacity(&tx, self.limits, 3, true)?;
        let p = project(&tx, binding.rights.workspace())?;
        let expected = match expected {
            Some(expected) if p.state.domain_revision != expected => {
                return Err(StoreError::RevisionConflict);
            }
            Some(expected) => expected,
            None => p.state.domain_revision,
        };
        let running = receipt(binding, OperationState::Running, Effect::None, None)?;
        // One event for the admission and one for the start; the completion event
        // stays reserved exactly as in the two-step path.
        insert_operation(&tx, binding, &running, p.fence, expected, 1)?;
        append_event(&tx, &p.state, Some(binding.rights.operation_id()))?;
        append_event(&tx, &p.state, Some(binding.rights.operation_id()))?;
        tx.commit()?;
        Ok((
            Admission {
                receipt: running,
                newly_admitted: true,
            },
            Some(ExternalPermit {
                binding: binding.clone(),
                fence: p.fence,
                runtime: self.runtime,
            }),
        ))
    }
    /// Recheck immediately before an OS effect, serialized by the host executor.
    /// SQLite alone cannot fence arbitrary processes or make an OS effect atomic.
    pub fn check_external_fence(&self, permit: &ExternalPermit) -> Result<()> {
        if permit.runtime != self.runtime {
            return Err(StoreError::Fenced);
        }
        if project(&self.db, permit.binding.rights.workspace())?.fence != permit.fence {
            return Err(StoreError::Fenced);
        }
        if existing(&self.db, &permit.binding)?
            .ok_or(StoreError::NotFound)?
            .state()
            != OperationState::Running
        {
            return Err(StoreError::Fenced);
        }
        #[cfg(any(unix, windows))]
        if is_remote_file_git_write(permit.binding.rights.original_method())
            && has_active_native_writer(&self.db)?
        {
            return Err(StoreError::NativeWriterBusy);
        }
        Ok(())
    }
    /// Finalize a known/uncertain effect once. Optional projection must retain
    /// context and use the next domain revision. An uncertain restart may record
    /// exactly one proven stopped old session, with no claimed replacement result.
    /// Never executes an OS operation.
    pub fn complete_external(
        &mut self,
        permit: &ExternalPermit,
        state: OperationState,
        effect: Effect,
        result: Option<OperationResult>,
        projection: Option<WorkspaceState>,
    ) -> Result<OperationReceipt> {
        if permit.runtime != self.runtime || !state.is_final() {
            return Err(StoreError::Invalid);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        #[cfg(any(unix, windows))]
        if matches!(
            permit.binding.rights.original_method(),
            Method::FilesRename | Method::FilesRemove
        ) && desktop_namespace::remote_namespace_intent_prepared(&tx, &permit.binding)?
        {
            return Err(StoreError::Fenced);
        }
        let receipt = complete_external_in_transaction(
            &tx,
            &permit.binding,
            state,
            effect,
            result,
            projection,
        )?;
        tx.commit()?;
        Ok(receipt)
    }
    /// Foreign actor/workspace/method/hash bindings are indistinguishable from
    /// absence. Current authenticated rights are checked before any disclosure.
    pub fn lookup(
        &self,
        binding: &OperationBinding,
        current: &CapabilitySet,
    ) -> Result<Option<OperationReceipt>> {
        let Some(receipt) = find_receipt(&self.db, binding)? else {
            return Ok(None);
        };
        if receipt
            .authorize_disclosure(current, binding.rights.actor(), binding.rights.workspace())
            .is_err()
        {
            return Ok(None);
        }
        Ok(Some(receipt))
    }
    /// Status lookup from independently authenticated identity/current rights.
    /// Immutable stored rights govern disclosure; no fresh hash/method is needed.
    pub fn lookup_operation(
        &self,
        actor: ConsumerAuthorizationId,
        workspace: WorkspaceId,
        id: OperationId,
        current: &CapabilitySet,
    ) -> Result<Option<OperationReceipt>> {
        authorized_receipt(&self.db, actor, workspace, id, current)
    }
    /// Cancellation never claims an external effect has stopped. Accepted intent
    /// can be cancelled; running intent only records a cancellation request.
    pub fn cancel_operation(
        &mut self,
        actor: ConsumerAuthorizationId,
        workspace: WorkspaceId,
        id: OperationId,
        current: &CapabilitySet,
    ) -> Result<Option<OperationReceipt>> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(old) = authorized_receipt(&tx, actor, workspace, id, current)? else {
            return Ok(None);
        };
        if old.state().is_final() || old.cancel_requested() {
            return Ok(Some(old));
        }
        let p = project(&tx, workspace)?;
        let fence: String = tx.query_row(
            "SELECT fence FROM operations WHERE actor=?1 AND workspace=?2 AND id=?3",
            params![key(actor), key(workspace), key(id)],
            |r| r.get(0),
        )?;
        if fence != p.fence.to_string() {
            return Err(StoreError::Fenced);
        }
        let binding = binding_from_receipt(&old)?;
        let (state, reserved) = if old.state() == OperationState::Accepted {
            (OperationState::Cancelled, 0)
        } else {
            (OperationState::Running, 1)
        };
        let receipt = OperationReceipt::new(
            &binding.rights,
            binding.parameter_hash.clone(),
            state,
            true,
            old.effect(),
            None,
        )
        .map_err(|_| StoreError::Invalid)?;
        update_operation(&tx, &binding, &receipt, reserved)?;
        force_event_room(&tx, self.limits)?;
        append_event(&tx, &p.state, Some(id))?;
        tx.commit()?;
        Ok(Some(receipt))
    }
    /// Only the trusted coordinator may call this after the terminal service has
    /// confirmed shutdown. This records descriptors; it does not stop processes.
    /// Trusted exact-session observation. Idempotent and fenced against a
    /// restarted, removed or replaced pane; never carries terminal output.
    pub fn record_terminal_exit(&mut self, terminal: &TerminalContext) -> Result<bool> {
        self.transition_terminal(terminal, PaneState::Running, PaneState::Exited)
    }
    /// Called only while the service excludes new attachments to an exited
    /// model. Persist loss of retained RAM before removing the owned session.
    pub fn record_terminal_retired(&mut self, terminal: &TerminalContext) -> Result<bool> {
        self.transition_terminal(terminal, PaneState::Exited, PaneState::Stopped)
    }
    fn transition_terminal(
        &mut self,
        terminal: &TerminalContext,
        from: PaneState,
        to: PaneState,
    ) -> Result<bool> {
        fn visit(
            layout: &mut TerminalLayout,
            terminal: &TerminalContext,
            from: PaneState,
            to: PaneState,
        ) -> bool {
            match layout {
                TerminalLayout::Pane { pane } => {
                    if pane.pane_id != terminal.pane_id
                        || pane.session.as_ref() != Some(terminal)
                        || pane.state != from
                    {
                        return false;
                    }
                    pane.state = to;
                    if to == PaneState::Stopped {
                        pane.session = None;
                    }
                    true
                }
                TerminalLayout::Split { first, second, .. } => {
                    visit(first, terminal, from, to) || visit(second, terminal, from, to)
                }
            }
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut p = match project(&tx, terminal.workspace.workspace_id) {
            Ok(p) => p,
            Err(StoreError::NotFound) => return Ok(false),
            Err(e) => return Err(e),
        };
        if p.state.context != terminal.workspace {
            return Ok(false);
        }
        if !p
            .state
            .tabs
            .0
            .iter_mut()
            .any(|tab| visit(&mut tab.layout, terminal, from, to))
        {
            return Ok(false);
        }
        p.state.domain_revision = DecimalU64(increment(p.state.domain_revision.0)?);
        p.state.validate().map_err(|_| StoreError::Invalid)?;
        save_project(&tx, &p)?;
        sync_terminals(&tx, &p.state)?;
        force_event_room(&tx, self.limits)?;
        append_event(&tx, &p.state, None)?;
        queue_publication(&tx, &p)?;
        tx.commit()?;
        Ok(true)
    }
    pub fn record_clean_shutdown(&mut self) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for mut p in projects(&tx)? {
            let id = p.state.context.workspace_id;
            if count_for_workspace(
                &tx,
                "SELECT count(*) FROM terminals WHERE workspace=?1 AND status='Running'",
                id,
            )? == 0
            {
                continue;
            }
            for tab in &mut p.state.tabs.0 {
                stop_sessions(&mut tab.layout);
            }
            p.state.domain_revision = DecimalU64(increment(p.state.domain_revision.0)?);
            save_project(&tx, &p)?;
            tx.execute(
                "UPDATE terminals SET status='Stopped' WHERE workspace=?1 AND status='Running'",
                [key(id)],
            )?;
            force_event_room(&tx, self.limits)?;
            append_event(&tx, &p.state, None)?;
            queue_publication(&tx, &p)?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn share(&mut self, id: WorkspaceId, expected_fence: u64) -> Result<u64> {
        self.share_inner(id, expected_fence, None)
    }
    /// Setup-only consent commit. The authority, workspace context, root, and
    /// stable import alias are checked again inside the transaction that writes
    /// consent and its publication intent.
    pub fn share_if_authorized(
        &mut self,
        guard: &ipc::LocalWorkspaceConsentAuthorized,
        expected_fence: u64,
    ) -> Result<u64> {
        self.share_inner(guard.workspace_id, expected_fence, Some(guard))
    }
    fn share_inner(
        &mut self,
        id: WorkspaceId,
        expected_fence: u64,
        authorization: Option<&ipc::LocalWorkspaceConsentAuthorized>,
    ) -> Result<u64> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(authorization) = authorization {
            validate_workspace_consent_guard(
                &tx,
                &self.identity,
                self.runtime,
                self.authorization_sealed.get(),
                authorization,
            )?;
        }
        #[cfg(any(unix, windows))]
        desktop_namespace::ensure_namespace_share_allowed(&tx, id)?;
        ensure_capacity(&tx, self.limits, 1, false)?;
        let mut p = project(&tx, id)?;
        if p.fence != expected_fence {
            return Err(StoreError::Fenced);
        }
        p.fence = increment(p.fence)?;
        if !p.consent {
            rotate_workspace_epoch(&mut p.state)?;
        }
        p.consent = true;
        save_project(&tx, &p)?;
        append_event(&tx, &p.state, None)?;
        queue_publication(&tx, &p)?;
        tx.commit()?;
        Ok(p.fence)
    }
    /// Security operation: commits the monotonic fence and one coalesced revoke
    /// before returning, even at capacity. Overflow advances an explicit journal
    /// low-watermark so lagging readers must resync rather than miss events.
    pub fn unshare(&mut self, id: WorkspaceId) -> Result<u64> {
        self.unshare_inner(id, None)
    }
    /// Setup-only revocation uses the same exact captured workspace and
    /// authorization guard as a share, evaluated in the revocation transaction.
    pub fn unshare_if_authorized(
        &mut self,
        authorization: &ipc::LocalWorkspaceConsentAuthorized,
    ) -> Result<u64> {
        self.unshare_inner(authorization.workspace_id, Some(authorization))
    }
    fn unshare_inner(
        &mut self,
        id: WorkspaceId,
        authorization: Option<&ipc::LocalWorkspaceConsentAuthorized>,
    ) -> Result<u64> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(authorization) = authorization {
            validate_workspace_consent_guard(
                &tx,
                &self.identity,
                self.runtime,
                self.authorization_sealed.get(),
                authorization,
            )?;
        }
        let mut p = project(&tx, id)?;
        p.fence = increment(p.fence)?;
        rotate_workspace_epoch(&mut p.state)?;
        p.consent = false;
        save_project(&tx, &p)?;
        force_event_room(&tx, self.limits)?;
        append_event(&tx, &p.state, None)?;
        queue_publication(&tx, &p)?;
        tx.commit()?;
        Ok(p.fence)
    }
    /// Remove registration only, never the local directory or audit rows.
    /// This foundation permits only an empty workspace with no pending intent.
    /// Its coalesced revoke tombstone and durable fence remain in the database.
    pub fn remove_project(&mut self, id: WorkspaceId) -> Result<u64> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut p = project(&tx, id)?;
        #[cfg(any(unix, windows))]
        desktop_namespace::ensure_namespace_project_mutation_allowed(&tx, &p.local_root)?;
        if !p.state.tabs.0.is_empty()
            || count_for_workspace(
                &tx,
                "SELECT count(*) FROM operations WHERE workspace=?1 AND reserved>0",
                id,
            )? > 0
        {
            return Err(StoreError::Busy);
        }
        p.fence = increment(p.fence)?;
        p.consent = false;
        save_project(&tx, &p)?;
        force_event_room(&tx, self.limits)?;
        append_event(&tx, &p.state, None)?;
        queue_publication(&tx, &p)?;
        tx.execute(
            "UPDATE projects SET removed=1 WHERE workspace=?1",
            [key(id)],
        )?;
        tx.commit()?;
        Ok(p.fence)
    }
    pub fn pending_publications(&self) -> Result<Vec<Publication>> {
        let mut q = self
            .db
            .prepare("SELECT publication FROM outbox ORDER BY workspace")?;
        q.query_map([], |r| r.get::<_, String>(0))?
            .map(|v| decode(&v?))
            .collect()
    }
    /// Local coordinator compatibility API: a superseded token cannot be acknowledged.
    /// Cloud workers MUST use `acknowledge_publication_for_authorization` instead
    /// and independently enforce the same monotonic workspace fence in the cloud.
    pub fn acknowledge_publication(&mut self, publication: &Publication) -> Result<bool> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = acknowledge_publication(&tx, publication)?;
        tx.commit()?;
        Ok(changed)
    }
    /// Cloud workers MUST use this generation guard, in addition to publication
    /// CAS. The older acknowledgement API is for local coordinator callers only.
    pub fn acknowledge_publication_for_authorization(
        &mut self,
        expected_generation: u64,
        publication: &Publication,
    ) -> Result<bool> {
        if self.authorization_sealed.get() {
            return Err(StoreError::Fenced);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = checked_authorization_generation(&tx, expected_generation)?;
        if state.locked || state.pending_cloud_revoke {
            return Err(StoreError::Fenced);
        }
        let changed = acknowledge_publication(&tx, publication)?;
        tx.commit()?;
        Ok(changed)
    }
    pub fn events_after(&self, after: u64) -> Result<EventPage> {
        let low: u64 = self
            .db
            .query_row::<String, _, _>(
                "SELECT value FROM metadata WHERE key='low_watermark'",
                [],
                |r| r.get(0),
            )?
            .parse()
            .map_err(|_| StoreError::Storage)?;
        let mut q=self.db.prepare("SELECT sequence,workspace,operation,revision FROM events WHERE sequence>?1 ORDER BY sequence")?;
        let after = i64::try_from(after).map_err(|_| StoreError::Invalid)?;
        let rows = q.query_map([after], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        let events = rows
            .map(|r| {
                let (s, w, o, v) = r?;
                Ok(Event {
                    sequence: s as u64,
                    workspace_id: WorkspaceId::try_from(w).map_err(|_| StoreError::Storage)?,
                    operation_id: o
                        .map(OperationId::try_from)
                        .transpose()
                        .map_err(|_| StoreError::Storage)?,
                    domain_revision: DecimalU64(v.parse().map_err(|_| StoreError::Storage)?),
                })
            })
            .collect::<Result<_>>()?;
        Ok(EventPage {
            resync_required: (after as u64) < low,
            low_watermark: low,
            events,
        })
    }
    /// Explicit journal retention; callers use low-watermark/resync after pruning.
    pub fn prune_events_through(&mut self, sequence: u64) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        prune_events(&tx, sequence)?;
        tx.commit()?;
        Ok(())
    }
    fn recover(&mut self) -> Result<()> {
        #[cfg(any(unix, windows))]
        let previous_anchor = self.native_clock_anchor;
        #[cfg(any(unix, windows))]
        let previous_anchor_ms = self.native_clock_anchor_ms;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        #[cfg(any(unix, windows))]
        let (native_now, anchor, anchor_ms) =
            observe_native_clock(&tx, previous_anchor, previous_anchor_ms)?;
        #[cfg(any(unix, windows))]
        {
            self.native_clock_anchor = anchor;
            self.native_clock_anchor_ms = anchor_ms;
        }
        #[cfg(any(unix, windows))]
        tx.execute("DELETE FROM native_intents WHERE state='registered'", [])?;
        #[cfg(any(unix, windows))]
        tx.execute(
            "UPDATE native_intents SET state='quarantine' WHERE state='active'",
            [],
        )?;
        #[cfg(any(unix, windows))]
        tx.execute(
            "UPDATE native_editor_jobs SET state='outcomeUnknown',result_json=NULL,completion_proof=NULL,completed_at_ms=NULL WHERE state='running'",
            [],
        )?;
        #[cfg(any(unix, windows))]
        tx.execute(
            "UPDATE native_git_jobs SET state='outcomeUnknown',result_json=NULL,completion_proof=NULL,
             completed_at_ms=NULL,updated_at_ms=?1 WHERE state='running'",
            [native_now.to_string()],
        )?;
        tx.execute(
            "UPDATE metadata SET value=?1 WHERE key='owner_generation'",
            [self.generation.to_string()],
        )?;
        let receipts = {
            let mut q = tx.prepare("SELECT receipt FROM operations WHERE reserved>0")?;
            q.query_map([], |r| r.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for wire in receipts {
            let old: OperationReceipt = decode(&wire)?;
            let binding = binding_from_receipt(&old)?;
            let (state, effect) = if old.state() == OperationState::Running {
                (OperationState::OutcomeUnknown, Effect::Unknown)
            } else {
                (OperationState::Cancelled, Effect::None)
            };
            let final_receipt = OperationReceipt::new(
                &binding.rights,
                binding.parameter_hash.clone(),
                state,
                old.cancel_requested(),
                effect,
                None,
            )
            .map_err(|_| StoreError::Invalid)?;
            update_operation(&tx, &binding, &final_receipt, 0)?;
            let p = project(&tx, binding.rights.workspace())?;
            force_event_room(&tx, self.limits)?;
            append_event(&tx, &p.state, Some(binding.rights.operation_id()))?;
        }
        #[cfg(any(unix, windows))]
        workspace_removal::recover_workspace_removals(&tx, self.limits)?;
        for mut p in projects(&tx)? {
            let lost = count_for_workspace(
                &tx,
                "SELECT count(*) FROM terminals WHERE workspace=?1 AND status='Running'",
                p.state.context.workspace_id,
            )? > 0;
            let mut cleared_exit = false;
            for tab in &mut p.state.tabs.0 {
                cleared_exit |= clear_exited_sessions(&mut tab.layout);
                if lost {
                    lose_sessions(&mut tab.layout);
                }
            }
            if lost || cleared_exit {
                p.state.domain_revision = DecimalU64(increment(p.state.domain_revision.0)?);
                tx.execute(
                    "UPDATE terminals SET status='Lost' WHERE workspace=?1 AND status='Running'",
                    [key(p.state.context.workspace_id)],
                )?;
            }
            p.state.context.runtime_id = self.runtime;
            p.state.context.runtime_generation = DecimalU64(self.generation);
            for tab in &mut p.state.tabs.0 {
                refresh_session_context(&mut tab.layout, &p.state.context);
            }
            save_project(&tx, &p)?;
            if lost || cleared_exit {
                force_event_room(&tx, self.limits)?;
                append_event(&tx, &p.state, None)?;
            }
            // Supersede tokens from the previous owner. This is publication
            // intent only, never permission to contact the cloud or run a shell.
            if p.consent
                || tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM outbox WHERE workspace=?1)",
                    [key(p.state.context.workspace_id)],
                    |r| r.get::<_, bool>(0),
                )?
            {
                queue_publication(&tx, &p)?;
            }
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(any(unix, windows))]
fn native_lease(
    intent_id: ipc::NativeIntentId,
    fence: u64,
    expires_at_ms: u64,
    state: ipc::NativeWriterState,
) -> ipc::NativeLease {
    ipc::NativeLease {
        intent_id,
        fence: DecimalU64(fence),
        expires_at_ms: DecimalU64(expires_at_ms),
        state,
    }
}

#[cfg(any(unix, windows))]
fn native_writer_state(value: &str) -> Result<ipc::NativeWriterState> {
    match value {
        "registered" => Ok(ipc::NativeWriterState::Registered),
        "active" => Ok(ipc::NativeWriterState::Active),
        "quarantine" => Ok(ipc::NativeWriterState::Quarantine),
        "finished" => Ok(ipc::NativeWriterState::Finished),
        _ => Err(StoreError::Storage),
    }
}

#[cfg(any(unix, windows))]
fn native_editor_job_state(value: &str) -> Result<NativeEditorJobState> {
    match value {
        "running" => Ok(NativeEditorJobState::Running),
        "succeeded" => Ok(NativeEditorJobState::Succeeded),
        "failed" => Ok(NativeEditorJobState::Failed),
        "outcomeUnknown" => Ok(NativeEditorJobState::OutcomeUnknown),
        _ => Err(StoreError::Storage),
    }
}

#[cfg(any(unix, windows))]
fn native_editor_job_state_text(value: NativeEditorJobState) -> &'static str {
    match value {
        NativeEditorJobState::Running => "running",
        NativeEditorJobState::Succeeded => "succeeded",
        NativeEditorJobState::Failed => "failed",
        NativeEditorJobState::OutcomeUnknown => "outcomeUnknown",
    }
}

#[cfg(any(unix, windows))]
fn native_editor_completion_proof_text(value: NativeEditorCompletionProof) -> &'static str {
    match value {
        NativeEditorCompletionProof::Joined => "joined",
        NativeEditorCompletionProof::NotStarted => "notStarted",
    }
}

#[cfg(any(unix, windows))]
fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(any(unix, windows))]
fn native_intent_row(
    db: &Connection,
    intent_id: ipc::NativeIntentId,
) -> Result<(ipc::NativeLease, String, ipc::NativeWriterState, u64)> {
    let (connection, state, fence, expiry): (String, String, String, String) = db
        .query_row(
            "SELECT connection,state,fence,expires_at_ms FROM native_intents WHERE id=?1",
            [key(intent_id)],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?
        .ok_or(StoreError::NotFound)?;
    let state = native_writer_state(&state)?;
    let fence = canonical_u64(fence)?;
    let expiry = canonical_u64(expiry)?;
    Ok((
        native_lease(intent_id, fence, expiry, state),
        connection,
        state,
        expiry,
    ))
}

/// Millisecond wall-clock leases need a persisted high-water mark because
/// expiration may revoke native authority but is never allowed to release its
/// quarantine fence. A per-HostStore monotonic anchor also ensures wall-clock
/// rollback cannot extend an Active lease beyond its bounded TTL.
#[cfg(any(unix, windows))]
fn observe_native_clock(
    tx: &Transaction<'_>,
    previous_anchor: Instant,
    previous_anchor_ms: u64,
) -> Result<(u64, Instant, u64)> {
    let observed_at = Instant::now();
    let elapsed_ms = u64::try_from(
        observed_at
            .saturating_duration_since(previous_anchor)
            .as_millis(),
    )
    .map_err(|_| StoreError::ResourceExhausted)?;
    let monotonic = previous_anchor_ms
        .checked_add(elapsed_ms)
        .ok_or(StoreError::ResourceExhausted)?;
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StoreError::Storage)?
        .as_millis();
    let wall = u64::try_from(wall).map_err(|_| StoreError::ResourceExhausted)?;
    let floor = canonical_u64(tx.query_row(
        "SELECT floor_ms FROM native_clock WHERE id=1",
        [],
        |row| row.get(0),
    )?)?;
    let external = wall.max(floor);
    let now = external.max(monotonic);
    if now > floor
        && tx.execute(
            "UPDATE native_clock SET floor_ms=?1 WHERE id=1",
            [now.to_string()],
        )? != 1
    {
        return Err(StoreError::Storage);
    }
    // Keep the monotonic anchor across ordinary observations. Re-anchoring on
    // every check would discard sub-millisecond elapsed time and could extend
    // a lease indefinitely under rapid polling after wall-clock rollback.
    let (anchor, anchor_ms) = if external > monotonic {
        (observed_at, now)
    } else {
        (previous_anchor, previous_anchor_ms)
    };
    Ok((now, anchor, anchor_ms))
}

#[cfg(any(unix, windows))]
fn read_native_clock_floor(db: &Connection) -> Result<u64> {
    canonical_u64(
        db.query_row("SELECT floor_ms FROM native_clock WHERE id=1", [], |row| {
            row.get(0)
        })?,
    )
}

#[cfg(any(unix, windows))]
fn prune_native_editor_stages(
    tx: &Transaction<'_>,
    now_ms: u64,
) -> Result<Vec<ipc::NativeIntentId>> {
    let mut removed = prune_native_editor_jobs(tx, now_ms)?;
    let now = i64::try_from(now_ms).map_err(|_| StoreError::ResourceExhausted)?;
    tx.execute(
        "UPDATE native_file_stages SET state='expired' WHERE state='unconsumed' AND CAST(expires_at_ms AS INTEGER)<=?1",
        [now],
    )?;
    tx.execute(
        "UPDATE native_file_stages SET state='expired' WHERE state='consumed' AND operation_id IN (SELECT operation_id FROM native_editor_jobs WHERE completion_proof IN('joined','notStarted'))",
        [],
    )?;
    removed.extend(
        {
            let mut query =
                tx.prepare("SELECT operation_id FROM native_file_stages WHERE state='expired'")?;
            query
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        }
        .into_iter()
        .map(|id| ipc::NativeIntentId::try_from(id).map_err(|_| StoreError::Storage))
        .collect::<Result<Vec<_>>>()?,
    );
    let mut unique = std::collections::BTreeSet::new();
    removed.retain(|operation_id| unique.insert(*operation_id));
    Ok(removed)
}

#[cfg(any(unix, windows))]
fn prune_native_editor_jobs(tx: &Transaction<'_>, now_ms: u64) -> Result<Vec<ipc::NativeIntentId>> {
    const RECEIPT_RETENTION_MS: u64 = 24 * 60 * 60 * 1000;
    let cutoff = i64::try_from(now_ms.saturating_sub(RECEIPT_RETENTION_MS))
        .map_err(|_| StoreError::ResourceExhausted)?;
    native_git::prune_native_git_jobs(tx, now_ms)?;
    let expired = {
        let mut query = tx.prepare(
            "SELECT jobs.operation_id,jobs.fence_id FROM native_editor_jobs jobs JOIN native_intents fence ON fence.id=jobs.fence_id WHERE jobs.state IN('succeeded','failed') AND fence.state='finished' AND jobs.completion_proof IN('joined','notStarted') AND jobs.completed_at_ms IS NOT NULL AND jobs.acknowledged_at_ms IS NOT NULL AND CAST(jobs.acknowledged_at_ms AS INTEGER)<=?1 AND NOT EXISTS(SELECT 1 FROM desktop_namespace_intents namespace WHERE namespace.native_operation_id=jobs.operation_id AND namespace.state='prepared')",
        )?;
        query
            .query_map([cutoff], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    let mut operation_ids = Vec::with_capacity(expired.len());
    for (operation_id, fence_id) in expired {
        let operation_id =
            ipc::NativeIntentId::try_from(operation_id).map_err(|_| StoreError::Storage)?;
        tx.execute(
            "UPDATE native_file_stages SET state='expired' WHERE operation_id=?1 AND state='consumed'",
            [key(operation_id)],
        )?;
        tx.execute(
            "DELETE FROM native_editor_jobs WHERE operation_id=?1 AND state IN('succeeded','failed')",
            [key(operation_id)],
        )?;
        tx.execute(
            "DELETE FROM native_intents WHERE id=?1 AND state='finished'",
            [fence_id],
        )?;
        operation_ids.push(operation_id);
    }
    Ok(operation_ids)
}

#[cfg(any(unix, windows))]
fn prune_finished_native_intents(tx: &Transaction<'_>, now_ms: u64) -> Result<()> {
    const RECEIPT_RETENTION_MS: u64 = 24 * 60 * 60 * 1000;
    let cutoff = now_ms.saturating_sub(RECEIPT_RETENTION_MS).to_string();
    // Editor fences are owned by their durable joined-job receipt and are
    // removed only by prune_native_editor_jobs. Both externally verified
    // bindings and unbound rejection tombstones require an explicit caller
    // acknowledgement, then remain available for a 24-hour receipt window.
    // Active and Quarantine rows are untouched.
    tx.execute(
        "DELETE FROM native_intents
         WHERE state='finished'
           AND NOT EXISTS(SELECT 1 FROM native_editor_jobs jobs WHERE jobs.fence_id=native_intents.id)
           AND NOT EXISTS(SELECT 1 FROM native_git_jobs jobs WHERE jobs.fence_id=native_intents.id)
           AND (
               (NOT EXISTS(SELECT 1 FROM native_evidence_bindings bindings WHERE bindings.intent_id=native_intents.id)
                AND native_intents.acknowledged_at_ms IS NOT NULL
                AND CAST(native_intents.acknowledged_at_ms AS INTEGER)<=?1)
               OR EXISTS(
                   SELECT 1 FROM native_evidence_bindings bindings
                   WHERE bindings.intent_id=native_intents.id
                     AND bindings.verified_at_ms IS NOT NULL
                     AND bindings.acknowledged_at_ms IS NOT NULL
                     AND CAST(bindings.acknowledged_at_ms AS INTEGER)<=?1
               )
           )",
        [cutoff],
    )?;
    Ok(())
}

#[cfg(any(unix, windows))]
fn native_evidence_binding(
    db: &Connection,
    intent_id: ipc::NativeIntentId,
) -> Result<Option<NativeEvidenceBinding>> {
    let row: Option<(String, String, String, String, String)> = db
        .query_row(
            "SELECT store_root,parent_operation_id,binding_json,runtime_descriptor_json,binding_sha256 FROM native_evidence_bindings WHERE intent_id=?1",
            [key(intent_id)],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .optional()?;
    row.map(
        |(
            store_root,
            parent_operation_id,
            binding_json,
            runtime_descriptor_json,
            binding_sha256,
        )| {
            if store_root.is_empty()
                || store_root.len() > 4096
                || parent_operation_id.is_empty()
                || parent_operation_id.len() > 256
                || binding_json.is_empty()
                || binding_json.len() > 131_072
                || runtime_descriptor_json.is_empty()
                || runtime_descriptor_json.len() > 16_384
                || !valid_sha256(&binding_sha256)
                || format!("{:x}", Sha256::digest(binding_json.as_bytes())) != binding_sha256
            {
                return Err(StoreError::Storage);
            }
            Ok(NativeEvidenceBinding {
                intent_id,
                store_root,
                parent_operation_id,
                binding_json,
                runtime_descriptor_json,
                binding_sha256,
            })
        },
    )
    .transpose()
}

#[cfg(any(unix, windows))]
fn expire_native_intents(tx: &Transaction<'_>, now_ms: u64) -> Result<()> {
    let active = {
        let mut query =
            tx.prepare("SELECT id,expires_at_ms FROM native_intents WHERE state='active'")?;
        query
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (id, expiry) in active {
        if canonical_u64(expiry)? <= now_ms {
            tx.execute(
                "UPDATE native_intents SET state='quarantine' WHERE id=?1 AND state='active'",
                [&id],
            )?;
            tx.execute(
                "UPDATE native_git_jobs SET state='outcomeUnknown',result_json=NULL,
                 completion_proof=NULL,completed_at_ms=NULL,updated_at_ms=?2
                 WHERE fence_id=?1 AND state='running'",
                params![id, now_ms.to_string()],
            )?;
        }
    }
    Ok(())
}

#[cfg(any(unix, windows))]
fn has_active_native_writer(db: &Connection) -> Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM native_intents WHERE state IN('active','quarantine'))",
        [],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

#[cfg(any(unix, windows))]
fn is_remote_file_git_write(method: Method) -> bool {
    matches!(
        method,
        Method::FilesCreate
            | Method::FilesMkdir
            | Method::FilesRename
            | Method::FilesRemove
            | Method::GitStage
            | Method::GitUnstage
            | Method::GitCommit
            | Method::GitFetch
            | Method::GitPush
            | Method::GitPull
    )
}

/// Running receipts remain exclusive until their effect is finalized. An
/// OutcomeUnknown write also blocks acquisition: receipt uncertainty is not a
/// proof that a subprocess or external side effect stopped.
#[cfg(any(unix, windows))]
fn remote_file_git_effect_pending(db: &Connection) -> Result<bool> {
    let rows = {
        let mut query = db.prepare(
            "SELECT receipt FROM operations WHERE method IN('files.create','files.mkdir','files.rename','files.remove','git.stage','git.unstage','git.commit','git.fetch','git.push','git.pull')",
        )?;
        query
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for row in rows {
        let receipt: OperationReceipt = decode(&row)?;
        if matches!(
            receipt.state(),
            OperationState::Running | OperationState::OutcomeUnknown
        ) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn op_params(b: &OperationBinding) -> [String; 3] {
    [
        key(b.rights.actor()),
        key(b.rights.workspace()),
        key(b.rights.operation_id()),
    ]
}

pub(crate) fn complete_external_in_transaction(
    tx: &Transaction<'_>,
    binding: &OperationBinding,
    state: OperationState,
    effect: Effect,
    result: Option<OperationResult>,
    projection: Option<WorkspaceState>,
) -> Result<OperationReceipt> {
    if !state.is_final() {
        return Err(StoreError::Invalid);
    }
    let old = existing(tx, binding)?.ok_or(StoreError::NotFound)?;
    if old.state() != OperationState::Running {
        return Err(StoreError::AlreadyStarted);
    }
    let file_method = matches!(
        binding.rights.original_method(),
        Method::FilesCreate | Method::FilesMkdir | Method::FilesRename | Method::FilesRemove
    );
    let terminal_method = matches!(
        binding.rights.original_method(),
        Method::TerminalCreate
            | Method::TerminalSplit
            | Method::TerminalRename
            | Method::TerminalMove
            | Method::TerminalClose
            | Method::TerminalRestart
    );
    let mut p = if file_method && binding.rights.original_method() == Method::FilesRemove {
        project_row(tx, binding.rights.workspace(), true)?
    } else {
        project(tx, binding.rights.workspace())?
    };
    if terminal_method
        && matches!(effect, Effect::Committed | Effect::Partial)
        && projection.is_none()
    {
        return Err(StoreError::Invalid);
    }
    if !terminal_method && projection.is_some() {
        return Err(StoreError::Invalid);
    }
    if let Some(next) = projection {
        if next.context != p.state.context
            || next.domain_revision.0 != increment(p.state.domain_revision.0)?
            || !(matches!(effect, Effect::Committed | Effect::Partial)
                || (binding.rights.original_method() == Method::TerminalRestart
                    && state == OperationState::OutcomeUnknown
                    && effect == Effect::Unknown
                    && result.is_none()
                    && exact_stopped_projection(&p.state, &next)))
        {
            return Err(StoreError::Invalid);
        }
        next.validate().map_err(|_| StoreError::Invalid)?;
        p.state = next;
        save_project(tx, &p)?;
        sync_terminals(tx, &p.state)?;
    }
    if let Some(
        OperationResult::Domain { domain_revision }
        | OperationResult::Terminal {
            domain_revision, ..
        },
    ) = &result
        && *domain_revision != p.state.domain_revision
    {
        return Err(StoreError::Invalid);
    }
    if let Some(OperationResult::Terminal {
        pane_id,
        session_id,
        session_epoch,
        ..
    }) = &result
    {
        let mut pending: Vec<_> = p.state.tabs.0.iter().map(|t| &t.layout).collect();
        let mut bound = false;
        while let Some(node) = pending.pop() {
            match node {
                TerminalLayout::Pane { pane } => {
                    if pane.pane_id == *pane_id
                        && pane.session.as_ref().is_some_and(|s| {
                            s.session_id == *session_id && s.session_epoch == *session_epoch
                        })
                    {
                        bound = true;
                    }
                }
                TerminalLayout::Split { first, second, .. } => {
                    pending.push(first);
                    pending.push(second);
                }
            }
        }
        if !bound {
            return Err(StoreError::Invalid);
        }
    }
    let receipt = OperationReceipt::new(
        &binding.rights,
        binding.parameter_hash.clone(),
        state,
        old.cancel_requested(),
        effect,
        result,
    )
    .map_err(|_| StoreError::Invalid)?;
    update_operation(tx, binding, &receipt, 0)?;
    append_event(tx, &p.state, Some(binding.rights.operation_id()))?;
    // File and Git effects retain their own revision tokens and operation
    // events. Only terminal-domain mutations can change the Cloud resource
    // projection; re-publishing unchanged Git state would unnecessarily fence
    // every other connection until a new publication ACK arrives.
    if terminal_method {
        queue_publication(tx, &p)?;
    }
    Ok(receipt)
}

fn receipt(
    b: &OperationBinding,
    state: OperationState,
    effect: Effect,
    result: Option<OperationResult>,
) -> Result<OperationReceipt> {
    OperationReceipt::new(
        &b.rights,
        b.parameter_hash.clone(),
        state,
        false,
        effect,
        result,
    )
    .map_err(|_| StoreError::Invalid)
}
fn stored_wire(db: &Connection, b: &OperationBinding) -> Result<Option<(String, String, String)>> {
    db.query_row(
        "SELECT method,hash,receipt FROM operations WHERE actor=?1 AND workspace=?2 AND id=?3",
        op_params(b),
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .optional()
    .map_err(Into::into)
}
fn existing(db: &Connection, b: &OperationBinding) -> Result<Option<OperationReceipt>> {
    let Some((method, hash, wire)) = stored_wire(db, b)? else {
        return Ok(None);
    };
    if method != b.rights.original_method().as_str() || hash != json(&b.parameter_hash)? {
        return Err(StoreError::IdempotencyConflict);
    }
    let receipt: OperationReceipt = decode(&wire)?;
    let admitted = receipt.stored_rights();
    if admitted.actual_rights() != b.rights.actual_rights()
        || admitted.repository_execution() != b.rights.repository_execution()
    {
        return Err(StoreError::IdempotencyConflict);
    }
    Ok(Some(receipt))
}
fn find_receipt(db: &Connection, b: &OperationBinding) -> Result<Option<OperationReceipt>> {
    match existing(db, b) {
        Err(StoreError::IdempotencyConflict) => Ok(None),
        other => other,
    }
}
fn insert_operation(
    tx: &Transaction<'_>,
    b: &OperationBinding,
    r: &OperationReceipt,
    fence: u64,
    revision: DecimalU64,
    reserved: i64,
) -> Result<()> {
    tx.execute(
        "INSERT INTO operations VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            key(b.rights.actor()),
            key(b.rights.workspace()),
            key(b.rights.operation_id()),
            b.rights.original_method().as_str(),
            json(&b.parameter_hash)?,
            json(r)?,
            fence.to_string(),
            revision.0.to_string(),
            reserved
        ],
    )?;
    Ok(())
}
fn update_operation(
    tx: &Transaction<'_>,
    b: &OperationBinding,
    r: &OperationReceipt,
    reserved: i64,
) -> Result<()> {
    if tx.execute(
        "UPDATE operations SET receipt=?4,reserved=?5 WHERE actor=?1 AND workspace=?2 AND id=?3",
        params![
            key(b.rights.actor()),
            key(b.rights.workspace()),
            key(b.rights.operation_id()),
            json(r)?,
            reserved
        ],
    )? != 1
    {
        return Err(StoreError::NotFound);
    }
    Ok(())
}
fn ensure_capacity(
    db: &Connection,
    limits: Limits,
    events: usize,
    new_operation: bool,
) -> Result<()> {
    let used = count(db, "SELECT count(*) FROM events")?;
    let reserved = count(db, "SELECT COALESCE(sum(reserved),0) FROM operations")?;
    if used + reserved + events > limits.events
        || (new_operation && count(db, "SELECT count(*) FROM operations")? >= limits.operations)
    {
        return Err(StoreError::ResourceExhausted);
    }
    Ok(())
}
fn project(db: &Connection, id: WorkspaceId) -> Result<ProjectRecord> {
    #[cfg(any(unix, windows))]
    workspace_removal::ensure_workspace_available(db, id)?;
    project_row(db, id, false)
}
fn project_row(db: &Connection, id: WorkspaceId, include_removed: bool) -> Result<ProjectRecord> {
    let(root,state,consent,fence):(String,String,bool,String)=db.query_row("SELECT root,state,consent,fence FROM projects WHERE workspace=?1 AND (?2 OR removed=0)",params![key(id),include_removed],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?.ok_or(StoreError::NotFound)?;
    let state: WorkspaceState = decode(&state)?;
    state.validate().map_err(|_| StoreError::Storage)?;
    Ok(ProjectRecord {
        local_root: root.into(),
        state,
        consent,
        fence: fence.parse().map_err(|_| StoreError::Storage)?,
    })
}
fn projects(db: &Connection) -> Result<Vec<ProjectRecord>> {
    #[cfg(any(unix, windows))]
    let mut q = db.prepare(
        "SELECT workspace FROM projects WHERE removed=0
         AND workspace NOT IN (SELECT workspace FROM workspace_removals WHERE state IN('stopping','uncertain'))
         ORDER BY workspace",
    )?;
    #[cfg(not(any(unix, windows)))]
    let mut q = db.prepare("SELECT workspace FROM projects WHERE removed=0 ORDER BY workspace")?;
    let ids = q
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ids.into_iter()
        .map(|id| {
            project(
                db,
                WorkspaceId::try_from(id).map_err(|_| StoreError::Storage)?,
            )
        })
        .collect()
}
fn save_project(tx: &Transaction<'_>, p: &ProjectRecord) -> Result<()> {
    tx.execute(
        "UPDATE projects SET state=?2,consent=?3,fence=?4 WHERE workspace=?1",
        params![
            key(p.state.context.workspace_id),
            json(&p.state)?,
            p.consent,
            p.fence.to_string()
        ],
    )?;
    Ok(())
}
fn queue_publication(tx: &Transaction<'_>, p: &ProjectRecord) -> Result<()> {
    let publication = Publication {
        workspace_id: p.state.context.workspace_id,
        fence: p.fence,
        domain_revision: p.state.domain_revision,
        enabled: p.consent,
        token: Uuid::new_v4().to_string(),
    };
    tx.execute("INSERT INTO outbox VALUES(?1,?2) ON CONFLICT(workspace) DO UPDATE SET publication=excluded.publication",params![key(publication.workspace_id),json(&publication)?])?;
    Ok(())
}
fn append_event(
    tx: &Transaction<'_>,
    state: &WorkspaceState,
    operation: Option<OperationId>,
) -> Result<()> {
    tx.execute(
        "INSERT INTO events(workspace,operation,revision) VALUES(?1,?2,?3)",
        params![
            key(state.context.workspace_id),
            operation.map(key),
            state.domain_revision.0.to_string()
        ],
    )?;
    Ok(())
}
fn count_for_workspace(db: &Connection, sql: &str, id: WorkspaceId) -> Result<usize> {
    let n: i64 = db.query_row(sql, [key(id)], |r| r.get(0))?;
    usize::try_from(n).map_err(|_| StoreError::Storage)
}
fn prune_events(tx: &Transaction<'_>, sequence: u64) -> Result<()> {
    let max: i64 = tx.query_row("SELECT COALESCE(max(sequence),0) FROM events", [], |r| {
        r.get(0)
    })?;
    let old: u64 = tx
        .query_row::<String, _, _>(
            "SELECT value FROM metadata WHERE key='low_watermark'",
            [],
            |r| r.get(0),
        )?
        .parse()
        .map_err(|_| StoreError::Storage)?;
    if sequence > std::cmp::max(max as u64, old) {
        return Err(StoreError::Invalid);
    }
    tx.execute("DELETE FROM events WHERE sequence<=?1", [sequence as i64])?;
    tx.execute(
        "UPDATE metadata SET value=?1 WHERE key='low_watermark'",
        [old.max(sequence).to_string()],
    )?;
    Ok(())
}
fn force_event_room(tx: &Transaction<'_>, limits: Limits) -> Result<()> {
    while count(tx, "SELECT count(*) FROM events")?
        + count(tx, "SELECT COALESCE(sum(reserved),0) FROM operations")?
        >= limits.events
    {
        let first: i64 = tx.query_row("SELECT min(sequence) FROM events", [], |r| r.get(0))?;
        prune_events(tx, first as u64)?;
    }
    Ok(())
}
fn lose_sessions(layout: &mut TerminalLayout) {
    match layout {
        TerminalLayout::Pane { pane } => {
            if matches!(
                pane.state,
                PaneState::Starting | PaneState::Publishing | PaneState::Running
            ) {
                pane.session = None;
                pane.state = PaneState::Lost;
            }
        }
        TerminalLayout::Split { first, second, .. } => {
            lose_sessions(first);
            lose_sessions(second);
        }
    }
}
// Consent boundaries must survive coalescing the unshare publication away:
// cloud grants and pending pairings remain bound to the previous epoch.
fn rotate_workspace_epoch(state: &mut WorkspaceState) -> Result<()> {
    state.context.workspace_epoch =
        WorkspaceEpoch::from_bytes(Uuid::new_v4().into_bytes()).map_err(|_| StoreError::Invalid)?;
    for tab in &mut state.tabs.0 {
        refresh_session_context(&mut tab.layout, &state.context);
    }
    Ok(())
}
fn refresh_session_context(layout: &mut TerminalLayout, context: &WorkspaceContext) {
    match layout {
        TerminalLayout::Pane { pane } => {
            if let Some(session) = &mut pane.session {
                session.workspace = context.clone();
            }
        }
        TerminalLayout::Split { first, second, .. } => {
            refresh_session_context(first, context);
            refresh_session_context(second, context);
        }
    }
}
fn sync_terminals(tx: &Transaction<'_>, state: &WorkspaceState) -> Result<()> {
    let id = state.context.workspace_id;
    // Replace only descriptors still represented in the canonical projection.
    tx.execute("DELETE FROM terminals WHERE workspace=?1", [key(id)])?;
    let mut stack: Vec<_> = state.tabs.0.iter().map(|t| &t.layout).collect();
    while let Some(layout) = stack.pop() {
        match layout {
            TerminalLayout::Pane { pane } => {
                if matches!(pane.state, PaneState::Running) && pane.session.is_none() {
                    return Err(StoreError::Invalid);
                }
                if matches!(pane.state, PaneState::Stopped | PaneState::Lost)
                    && pane.session.is_some()
                {
                    return Err(StoreError::Invalid);
                }
                let status = match pane.state {
                    PaneState::Starting | PaneState::Publishing | PaneState::Running => "Running",
                    PaneState::Lost => "Lost",
                    PaneState::Stopped | PaneState::Exited => "Stopped",
                };
                tx.execute(
                    "INSERT INTO terminals VALUES(?1,?2,?3)",
                    params![key(id), key(pane.pane_id), status],
                )?;
            }
            TerminalLayout::Split { first, second, .. } => {
                stack.push(first);
                stack.push(second);
            }
        }
    }
    Ok(())
}
struct BackupDestination {
    path: PathBuf,
    #[cfg(windows)]
    guard: lomi_platform::windows::backup::Destination,
}
fn backup_destination(db: &Connection, path: &Path) -> Result<BackupDestination> {
    #[cfg(windows)]
    {
        let source = Path::new(db.path().ok_or(StoreError::Backup)?);
        let guard = lomi_platform::windows::backup::Destination::new(source, path)
            .map_err(|_| StoreError::Backup)?;
        Ok(BackupDestination {
            path: guard.path().to_owned(),
            guard,
        })
    }
    #[cfg(not(windows))]
    {
        // Backups stay inside the same protected profile directory as the DB.
        // Resolve aliases once and use the canonical parent for all later accesses.
        let source = Path::new(db.path().ok_or(StoreError::Backup)?)
            .canonicalize()
            .map_err(|_| StoreError::Backup)?;
        let parent = source.parent().ok_or(StoreError::Backup)?;
        let requested_parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if requested_parent
            .canonicalize()
            .map_err(|_| StoreError::Backup)?
            != parent
        {
            return Err(StoreError::Backup);
        }
        #[cfg(unix)]
        let directory = std::fs::File::open(parent).map_err(|_| StoreError::Backup)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if directory
                .metadata()
                .map_err(|_| StoreError::Backup)?
                .permissions()
                .mode()
                & 0o077
                != 0
            {
                return Err(StoreError::Backup);
            }
        }
        #[cfg(target_os = "macos")]
        reject_backup_acl_grants(&directory)?;
        Ok(BackupDestination {
            path: parent.join(path.file_name().ok_or(StoreError::Backup)?),
        })
    }
}
fn checked_backup(db: &Connection, path: &Path, version: i64) -> Result<()> {
    let destination = backup_destination(db, path)?;
    let path = destination.path.as_path();
    // Never replace an existing backup or accidentally back up over the live DB.
    #[cfg(not(windows))]
    let mut options = std::fs::OpenOptions::new();
    #[cfg(not(windows))]
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(windows))]
    let file = options.open(path).map_err(|_| StoreError::Backup)?;
    #[cfg(not(windows))]
    drop(file);
    #[cfg(windows)]
    let file = destination.guard.create().map_err(|_| StoreError::Backup)?;
    let result = (|| {
        db.backup(rusqlite::MAIN_DB, path, None)?;
        let backup = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let check: String = backup.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        let actual: i64 = backup.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let broken = count(&backup, "SELECT count(*) FROM pragma_foreign_key_check")?;
        if check != "ok" || actual != version || broken != 0 {
            return Err(StoreError::Backup);
        }
        drop(backup);
        #[cfg(windows)]
        destination
            .guard
            .sync(&file)
            .map_err(|_| StoreError::Backup)?;
        #[cfg(not(windows))]
        std::fs::File::open(path)
            .and_then(|f| f.sync_all())
            .map_err(|_| StoreError::Backup)?;
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)
                .and_then(|f| f.sync_all())
                .map_err(|_| StoreError::Backup)?;
        }
        Ok(())
    })();
    #[cfg(not(windows))]
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result.map_err(|_| StoreError::Backup)
}

/// Retain exactly one pre-migration backup. A crash before the schema commit
/// may leave it behind: reuse only an intact, logically identical snapshot.
/// Conflicting or incomplete backups are preserved and fail closed.
fn migration_backup(db: &Connection, path: &Path, version: i64) -> Result<()> {
    let destination = backup_destination(db, path)?;
    let path = &destination.path;
    #[cfg(windows)]
    let file = match destination
        .guard
        .existing()
        .map_err(|_| StoreError::Backup)?
    {
        Some(file) => file,
        None => return checked_backup(db, path, version),
    };
    #[cfg(not(windows))]
    match path.symlink_metadata() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return checked_backup(db, path, version);
        }
        Ok(metadata) if metadata.is_file() => {}
        _ => return Err(StoreError::Backup),
    }
    let result = (|| {
        let backup = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let integrity: String = backup.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        let actual: i64 = backup.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if integrity != "ok"
            || actual != version
            || count(&backup, "SELECT count(*) FROM pragma_foreign_key_check")? != 0
        {
            return Err(StoreError::Backup);
        }
        let schema = "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name";
        if database_rows(db, schema)? != database_rows(&backup, schema)? {
            return Err(StoreError::Backup);
        }
        // The schema already matches exactly. Compare every table, including
        // native fences, custody captures, operation journals and AUTOINCREMENT
        // state. A hand-maintained base-table list could accept a stale backup
        // after a later schema introduced another authority-bearing table.
        let tables = db
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for table in tables {
            let table = table.replace('"', "\"\"");
            let sql = format!("SELECT * FROM \"{table}\"");
            let columns = db.prepare(&sql)?.column_count();
            let order = (1..=columns)
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!("{sql} ORDER BY {order}");
            if database_rows(db, &sql)? != database_rows(&backup, &sql)? {
                return Err(StoreError::Backup);
            }
        }
        drop(backup);
        #[cfg(windows)]
        destination
            .guard
            .sync(&file)
            .map_err(|_| StoreError::Backup)?;
        #[cfg(not(windows))]
        std::fs::File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|_| StoreError::Backup)?;
        #[cfg(unix)]
        std::fs::File::open(path.parent().ok_or(StoreError::Backup)?)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| StoreError::Backup)?;
        Ok(())
    })();
    result.map_err(|_| StoreError::Backup)
}
fn fence_workspaces(tx: &Transaction<'_>, limits: Limits) -> Result<()> {
    for mut project in projects(tx)? {
        project.fence = increment(project.fence)?;
        project.consent = false;
        save_project(tx, &project)?;
        force_event_room(tx, limits)?;
        append_event(tx, &project.state, None)?;
        queue_publication(tx, &project)?;
    }
    Ok(())
}

/// The v1/v2 migration runs before migration 12 creates `workspace_removals`.
/// Keep this path independent from the current project-availability gate.
fn fence_workspaces_before_removal_schema(tx: &Transaction<'_>, limits: Limits) -> Result<()> {
    let ids = {
        let mut query =
            tx.prepare("SELECT workspace FROM projects WHERE removed=0 ORDER BY workspace")?;
        query
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for id in ids {
        let id = WorkspaceId::try_from(id).map_err(|_| StoreError::Storage)?;
        let mut project = project_row(tx, id, false)?;
        project.fence = increment(project.fence)?;
        project.consent = false;
        save_project(tx, &project)?;
        force_event_room(tx, limits)?;
        append_event(tx, &project.state, None)?;
        queue_publication(tx, &project)?;
    }
    Ok(())
}

fn canonical_u64(value: String) -> Result<u64> {
    let parsed: u64 = value.parse().map_err(|_| StoreError::Storage)?;
    if parsed.to_string() != value {
        return Err(StoreError::Storage);
    }
    Ok(parsed)
}
fn read_authorization_state(db: &Connection) -> Result<AuthorizationState> {
    if count(db, "SELECT count(*) FROM authorization_state")? != 1 {
        return Err(StoreError::Storage);
    }
    let (generation, locked, pending, floor): (String, i64, i64, String) = db.query_row(
        "SELECT generation,locked,pending_cloud_revoke,clock_floor FROM authorization_state WHERE id=1",
        [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    )?;
    if !matches!(locked, 0 | 1) || !matches!(pending, 0 | 1) || (pending == 1 && locked == 0) {
        return Err(StoreError::Storage);
    }
    Ok(AuthorizationState {
        generation: canonical_u64(generation)?,
        locked: locked == 1,
        pending_cloud_revoke: pending == 1,
        clock_floor: canonical_u64(floor)?,
    })
}
fn checked_authorization_generation(db: &Connection, expected: u64) -> Result<AuthorizationState> {
    let state = read_authorization_state(db)?;
    if state.generation != expected {
        return Err(StoreError::Fenced);
    }
    Ok(state)
}
fn validate_workspace_consent_guard(
    tx: &Transaction<'_>,
    identity: &Identity,
    runtime: RuntimeId,
    authorization_sealed: bool,
    guard: &ipc::LocalWorkspaceConsentAuthorized,
) -> Result<ProjectRecord> {
    if guard.operator_intent != Confirmed::Confirmed || authorization_sealed {
        return Err(StoreError::Fenced);
    }
    let identity_wire = metadata_value(tx, "identity")?.ok_or(StoreError::Storage)?;
    let durable_identity: Identity = decode(&identity_wire)?;
    if durable_identity != *identity || durable_identity.host_id != guard.expected_host_id {
        return Err(StoreError::Fenced);
    }

    let generation = guard.expected_authorization_generation.0;
    let authorization = checked_authorization_generation(tx, generation)?;
    if authorization.locked || authorization.pending_cloud_revoke {
        return Err(StoreError::Fenced);
    }
    let marker: Option<VerifiedGeneration> =
        metadata_value(tx, "authorization_verified_generation")?
            .map(|value| decode(&value))
            .transpose()?;
    let marker = marker.ok_or(StoreError::Fenced)?;
    if marker.version != 1 {
        return Err(StoreError::Storage);
    }
    if marker.generation != generation {
        return Err(StoreError::Fenced);
    }
    let configuration = HostStore::read_auth_configuration(tx)?;
    let (rejection, deferred) =
        validate_rejection_metadata(tx, authorization, configuration.as_ref())?;
    if rejection.is_some() || deferred.is_some() {
        return Err(StoreError::Fenced);
    }

    let project = project(tx, guard.workspace_id)?;
    let expected_root = guard.expected_root_path.as_str();
    if project.state.context != guard.expected_context
        || project.state.context.workspace_id != guard.workspace_id
        || project.state.context.runtime_id != runtime
        || project.local_root.to_str() != Some(expected_root)
    {
        return Err(StoreError::Fenced);
    }
    let alias_key = format!("workspace_import/{}", key(guard.expected_import_id));
    let alias_wire = metadata_value(tx, &alias_key)?.ok_or(StoreError::Fenced)?;
    let alias: WorkspaceImportAlias = decode(&alias_wire)?;
    if alias.workspace_id != guard.workspace_id || alias.canonical_root != expected_root {
        return Err(StoreError::Fenced);
    }
    #[cfg(any(unix, windows))]
    if desktop_namespace::namespace_pending_workspace_ids(tx, &[guard.workspace_id])?
        .contains(&guard.workspace_id)
    {
        return Err(StoreError::NativeWriterBusy);
    }
    Ok(project)
}
fn save_authorization_state(tx: &Transaction<'_>, state: AuthorizationState) -> Result<()> {
    if tx.execute("UPDATE authorization_state SET generation=?1,locked=?2,pending_cloud_revoke=?3,clock_floor=?4 WHERE id=1",
        params![state.generation.to_string(),state.locked,state.pending_cloud_revoke,state.clock_floor.to_string()])? != 1 {
        return Err(StoreError::Storage);
    }
    Ok(())
}
fn acknowledge_publication(tx: &Transaction<'_>, publication: &Publication) -> Result<bool> {
    let p = project_row(tx, publication.workspace_id, true)?;
    let changed = if p.fence == publication.fence && p.consent == publication.enabled {
        tx.execute(
            "DELETE FROM outbox WHERE workspace=?1 AND publication=?2",
            params![key(publication.workspace_id), json(publication)?],
        )?
    } else {
        0
    };
    Ok(changed == 1)
}

fn database_rows(db: &Connection, sql: &str) -> Result<Vec<Vec<rusqlite::types::Value>>> {
    let mut query = db.prepare(sql)?;
    let columns = query.column_count();
    query
        .query_map([], |row| (0..columns).map(|i| row.get(i)).collect())?
        .collect::<std::result::Result<_, _>>()
        .map_err(Into::into)
}

// Same private-profile policy as the platform owner: Darwin extended allow ACLs
// bypass mode bits. Deny-only entries may safely restrict access further. These
// declarations/constants are from Darwin sys/acl.h and introduce no dependency.
#[cfg(target_os = "macos")]
fn reject_backup_acl_grants(file: &std::fs::File) -> Result<()> {
    use std::{
        ffi::{c_int, c_void},
        os::fd::AsRawFd,
    };
    unsafe extern "C" {
        fn acl_get_fd_np(fd: c_int, kind: c_int) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, id: c_int, entry: *mut *mut c_void) -> c_int;
        fn acl_get_tag_type(entry: *mut c_void, tag: *mut c_int) -> c_int;
        fn acl_free(acl: *mut c_void) -> c_int;
    }
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
    if acl.is_null() {
        return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(StoreError::Backup)
        };
    }
    struct Acl(*mut c_void);
    impl Drop for Acl {
        fn drop(&mut self) {
            unsafe {
                acl_free(self.0);
            }
        }
    }
    let _guard = Acl(acl);
    let mut selector = 0;
    loop {
        let mut entry = std::ptr::null_mut();
        if unsafe { acl_get_entry(acl, selector, &mut entry) } != 0 {
            return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::InvalidInput {
                Ok(())
            } else {
                Err(StoreError::Backup)
            };
        }
        let mut tag = 0;
        if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 || tag != 2 {
            return Err(StoreError::Backup);
        }
        selector = -1;
    }
}

fn binding_from_receipt(receipt: &OperationReceipt) -> Result<OperationBinding> {
    let value = serde_json::to_value(receipt).map_err(|_| StoreError::Storage)?;
    let parameter_hash = value["parameterHash"]
        .as_str()
        .ok_or(StoreError::Storage)?
        .to_owned()
        .try_into()
        .map_err(|_| StoreError::Storage)?;
    Ok(OperationBinding {
        rights: receipt.stored_rights(),
        parameter_hash,
    })
}
fn authorized_receipt(
    db: &Connection,
    actor: ConsumerAuthorizationId,
    workspace: WorkspaceId,
    id: OperationId,
    current: &CapabilitySet,
) -> Result<Option<OperationReceipt>> {
    let wire: Option<String> = db
        .query_row(
            "SELECT receipt FROM operations WHERE actor=?1 AND workspace=?2 AND id=?3",
            params![key(actor), key(workspace), key(id)],
            |r| r.get(0),
        )
        .optional()?;
    let Some(wire) = wire else { return Ok(None) };
    let receipt: OperationReceipt = decode(&wire)?;
    if receipt.operation_id() != id {
        return Err(StoreError::Storage);
    }
    if receipt
        .authorize_disclosure(current, actor, workspace)
        .is_err()
    {
        return Ok(None);
    }
    Ok(Some(receipt))
}
fn stop_sessions(layout: &mut TerminalLayout) {
    match layout {
        TerminalLayout::Pane { pane } => {
            if matches!(
                pane.state,
                PaneState::Starting | PaneState::Publishing | PaneState::Running
            ) {
                pane.session = None;
                pane.state = PaneState::Stopped;
            }
        }
        TerminalLayout::Split { first, second, .. } => {
            stop_sessions(first);
            stop_sessions(second);
        }
    }
}

// The executor knows the old child stopped, while replacement startup may have
// run. Preserve only that proven termination alongside the uncertain receipt.
fn exact_stopped_projection(old: &WorkspaceState, next: &WorkspaceState) -> bool {
    fn walk(expected: &mut TerminalLayout, actual: &TerminalLayout, count: &mut usize) {
        match (expected, actual) {
            (TerminalLayout::Pane { pane }, TerminalLayout::Pane { pane: new }) => {
                if pane.session.is_some()
                    && new.session.is_none()
                    && new.state == PaneState::Stopped
                {
                    pane.session = None;
                    pane.state = PaneState::Stopped;
                    *count += 1;
                }
            }
            (
                TerminalLayout::Split { first, second, .. },
                TerminalLayout::Split {
                    first: a,
                    second: b,
                    ..
                },
            ) => {
                walk(first, a, count);
                walk(second, b, count);
            }
            _ => {}
        }
    }
    let mut expected = old.clone();
    expected.domain_revision = next.domain_revision;
    let mut count = 0;
    for (tab, actual) in expected.tabs.0.iter_mut().zip(&next.tabs.0) {
        walk(&mut tab.layout, &actual.layout, &mut count);
    }
    count == 1 && expected == *next
}

fn clear_exited_sessions(layout: &mut TerminalLayout) -> bool {
    match layout {
        TerminalLayout::Pane { pane } => {
            pane.state == PaneState::Exited && pane.session.take().is_some()
        }
        TerminalLayout::Split { first, second, .. } => {
            let a = clear_exited_sessions(first);
            clear_exited_sessions(second) || a
        }
    }
}
