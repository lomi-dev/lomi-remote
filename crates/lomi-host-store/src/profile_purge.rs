//! Durable, filesystem-free profile-purge stages.
//!
//! Host owns the exclusive native profile lock and exact provider operations.
//! This Store module fences retries, admits only a positively quiescent profile,
//! and removes a closed allowlist of mutable Host rows without replacing the
//! database or installation identity.

use super::*;
use rusqlite::{Connection, OptionalExtension, Transaction, params};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfilePurgePhase {
    Started,
    HostAuthReset,
    GitCredentialsCleared,
    StoreCleared,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfilePurgeRecord {
    pub attempt_id: OperationId,
    pub host_id: HostId,
    pub profile_id: IpcProfileId,
    pub owner_runtime_id: RuntimeId,
    pub owner_generation: u64,
    pub profile_device: u64,
    pub profile_inode: u64,
    pub phase: ProfilePurgePhase,
    pub uncertain: bool,
}

/// A Store capability for one profile-purge attempt. Fields are private so a
/// caller cannot invent an attempt, owner generation, or file identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfilePurgeAuthority {
    attempt_id: OperationId,
    host_id: HostId,
    profile_id: IpcProfileId,
    owner_runtime_id: RuntimeId,
    owner_generation: u64,
    profile_device: u64,
    profile_inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfilePurgeBegin {
    pub record: ProfilePurgeRecord,
    pub authority: Option<ProfilePurgeAuthority>,
}

/// Restricted Store surface for a Host-owned profile purge. Unlike HostStore,
/// this type exposes no workspace, RPC, authentication-write, or arbitrary SQL
/// methods. It is returned only by the identity-bound purge opener.
pub struct ProfilePurgeStore {
    store: HostStore,
}

#[cfg(any(unix, windows))]
impl HostStore {
    /// Open only the existing, identity-bound database for profile purge. The
    /// caller must hold the actual native OwnerLock and pass its observed
    /// profile file identity. This returns a restricted view, never HostStore.
    /// It deliberately skips normal startup recovery so running terminal IDs
    /// and native-writer evidence remain available to the purge admission gate.
    pub fn open_existing_for_profile_purge(
        path: &Path,
        limits: Limits,
        expected_identity: &Identity,
        profile_identity: (u64, u64),
    ) -> Result<ProfilePurgeStore> {
        let store = Self::open_internal(
            path,
            limits,
            Some(expected_identity.host_id),
            Some(expected_identity.profile_id),
            true,
            false,
            true,
            Some(profile_identity),
        )?;
        if store.identity != *expected_identity {
            return Err(StoreError::Fenced);
        }
        Ok(ProfilePurgeStore { store })
    }
}

fn phase_from_text(value: &str) -> Result<ProfilePurgePhase> {
    match value {
        "started" => Ok(ProfilePurgePhase::Started),
        "hostAuthReset" => Ok(ProfilePurgePhase::HostAuthReset),
        "gitCredentialsCleared" => Ok(ProfilePurgePhase::GitCredentialsCleared),
        "storeCleared" => Ok(ProfilePurgePhase::StoreCleared),
        "complete" => Ok(ProfilePurgePhase::Complete),
        _ => Err(StoreError::Storage),
    }
}

fn phase_text(value: ProfilePurgePhase) -> &'static str {
    match value {
        ProfilePurgePhase::Started => "started",
        ProfilePurgePhase::HostAuthReset => "hostAuthReset",
        ProfilePurgePhase::GitCredentialsCleared => "gitCredentialsCleared",
        ProfilePurgePhase::StoreCleared => "storeCleared",
        ProfilePurgePhase::Complete => "complete",
    }
}

fn typed<T>(value: String) -> Result<T>
where
    T: TryFrom<String>,
{
    value.try_into().map_err(|_| StoreError::Storage)
}

fn load_record(db: &Connection) -> Result<Option<ProfilePurgeRecord>> {
    let row = db
        .query_row(
            "SELECT attempt_id,host_id,profile_id,owner_runtime_id,owner_generation,
                    profile_device,profile_inode,phase,uncertain
             FROM profile_purge WHERE id=1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, bool>(8)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(
            attempt_id,
            host_id,
            profile_id,
            owner_runtime_id,
            owner_generation,
            profile_device,
            profile_inode,
            phase,
            uncertain,
        )| {
            Ok(ProfilePurgeRecord {
                attempt_id: typed(attempt_id)?,
                host_id: typed(host_id)?,
                profile_id: typed(profile_id)?,
                owner_runtime_id: typed(owner_runtime_id)?,
                owner_generation: owner_generation.parse().map_err(|_| StoreError::Storage)?,
                profile_device: profile_device.parse().map_err(|_| StoreError::Storage)?,
                profile_inode: profile_inode.parse().map_err(|_| StoreError::Storage)?,
                phase: phase_from_text(&phase)?,
                uncertain,
            })
        },
    )
    .transpose()
}

pub(super) fn profile_purge_incomplete(db: &Connection) -> Result<bool> {
    let row = load_record(db)?;
    Ok(row.is_some_and(|row| row.phase != ProfilePurgePhase::Complete))
}

pub(super) fn validate_profile_identity(
    db: &Connection,
    (device, inode): (u64, u64),
) -> Result<()> {
    if device == 0 || inode == 0 {
        return Err(StoreError::Invalid);
    }
    if load_record(db)?
        .is_some_and(|record| record.profile_device != device || record.profile_inode != inode)
    {
        return Err(StoreError::Fenced);
    }
    Ok(())
}

fn authority(store: &HostStore, record: &ProfilePurgeRecord) -> ProfilePurgeAuthority {
    ProfilePurgeAuthority {
        attempt_id: record.attempt_id,
        host_id: store.identity.host_id,
        profile_id: store.identity.profile_id,
        owner_runtime_id: store.runtime,
        owner_generation: store.generation,
        profile_device: record.profile_device,
        profile_inode: record.profile_inode,
    }
}

fn validate_authority(
    tx: &Transaction<'_>,
    host_id: HostId,
    profile_id: IpcProfileId,
    runtime: RuntimeId,
    generation: u64,
    authority: &ProfilePurgeAuthority,
) -> Result<ProfilePurgeRecord> {
    if authority.host_id != host_id
        || authority.profile_id != profile_id
        || authority.owner_runtime_id != runtime
        || authority.owner_generation != generation
    {
        return Err(StoreError::Fenced);
    }
    let record = load_record(tx)?.ok_or(StoreError::Fenced)?;
    if record.attempt_id != authority.attempt_id
        || record.host_id != authority.host_id
        || record.profile_id != authority.profile_id
        || record.owner_runtime_id != authority.owner_runtime_id
        || record.owner_generation != authority.owner_generation
        || record.profile_device != authority.profile_device
        || record.profile_inode != authority.profile_inode
        || record.phase == ProfilePurgePhase::Complete
    {
        return Err(StoreError::Fenced);
    }
    Ok(record)
}

fn exists(tx: &Transaction<'_>, sql: &str) -> Result<bool> {
    tx.query_row(sql, [], |row| row.get(0)).map_err(Into::into)
}

fn unresolved_terminal_layout(layout: &TerminalLayout) -> bool {
    match layout {
        TerminalLayout::Pane { pane } => pane.session.is_some() || pane.state != PaneState::Stopped,
        TerminalLayout::Split { first, second, .. } => {
            unresolved_terminal_layout(first) || unresolved_terminal_layout(second)
        }
    }
}

fn ensure_terminal_cleanup_confirmed(tx: &Transaction<'_>) -> Result<()> {
    if exists(
        tx,
        "SELECT EXISTS(SELECT 1 FROM terminals WHERE status!='Stopped')",
    )? {
        return Err(StoreError::NativeWriterBusy);
    }
    let states = {
        let mut query = tx.prepare("SELECT state FROM projects")?;
        query
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for wire in states {
        let state: WorkspaceState = super::decode(&wire)?;
        if state
            .tabs
            .0
            .iter()
            .any(|tab| unresolved_terminal_layout(&tab.layout))
        {
            return Err(StoreError::NativeWriterBusy);
        }
    }
    Ok(())
}

#[cfg(any(unix, windows))]
fn profile_purge_store_has_mutable_data(tx: &Transaction<'_>) -> Result<bool> {
    for query in [
        "SELECT EXISTS(SELECT 1 FROM projects)",
        "SELECT EXISTS(SELECT 1 FROM terminals)",
        "SELECT EXISTS(SELECT 1 FROM operations)",
        "SELECT EXISTS(SELECT 1 FROM events)",
        "SELECT EXISTS(SELECT 1 FROM outbox)",
        "SELECT EXISTS(SELECT 1 FROM default_shell)",
        "SELECT EXISTS(SELECT 1 FROM native_intents)",
        "SELECT EXISTS(SELECT 1 FROM native_evidence_bindings)",
        "SELECT EXISTS(SELECT 1 FROM native_file_stages)",
        "SELECT EXISTS(SELECT 1 FROM native_editor_jobs)",
        "SELECT EXISTS(SELECT 1 FROM native_git_jobs)",
        "SELECT EXISTS(SELECT 1 FROM desktop_namespace_intents)",
        "SELECT EXISTS(SELECT 1 FROM workspace_removals)",
        "SELECT EXISTS(SELECT 1 FROM workspace_removal_sessions)",
        "SELECT EXISTS(SELECT 1 FROM metadata WHERE key IN(
            'local_start_mode','login_generation','authorization_verified_generation',
            'authorization_rejection','deferred_login_intent','cloud_runtime_state',
            'host_publication_intent','host_acknowledged_publication','host_display_name'
         ) OR key GLOB 'shell_profile/*'
           OR key GLOB 'shell_profile_cwd/*'
           OR key GLOB 'workspace_import/*'
           OR key GLOB 'host_pairing_intent:*'
           OR key GLOB 'host_workspace_grant:*'
           OR key GLOB 'host_channel_intent:*'
           OR key GLOB 'host_channel_admission:*')",
    ] {
        if exists(tx, query)? {
            return Ok(true);
        }
    }
    Ok(false)
}

const MAX_PROFILE_PURGE_ATTEMPTS: i64 = 4096;

fn purge_operation_attempt(
    tx: &Transaction<'_>,
    operation_id: OperationId,
) -> Result<Option<OperationId>> {
    let wire: Option<String> = tx
        .query_row(
            "SELECT attempt_id FROM profile_purge_attempt_ids WHERE operation_id=?1",
            [key(operation_id)],
            |row| row.get(0),
        )
        .optional()?;
    wire.map(typed).transpose()
}

fn reserve_purge_operation(
    tx: &Transaction<'_>,
    operation_id: OperationId,
    attempt_id: OperationId,
) -> Result<()> {
    if purge_operation_attempt(tx, operation_id)?.is_some() {
        return Err(StoreError::IdempotencyConflict);
    }
    let count: i64 = tx.query_row(
        "SELECT count(*) FROM profile_purge_attempt_ids",
        [],
        |row| row.get(0),
    )?;
    if count >= MAX_PROFILE_PURGE_ATTEMPTS {
        return Err(StoreError::ResourceExhausted);
    }
    tx.execute(
        "INSERT INTO profile_purge_attempt_ids(operation_id,attempt_id) VALUES(?1,?2)",
        params![key(operation_id), key(attempt_id)],
    )?;
    Ok(())
}

fn ensure_quiescent(tx: &Transaction<'_>) -> Result<()> {
    // Every durable operation must have a terminal receipt and no retained
    // reservation. Do not purge an effect whose filesystem result is unknown.
    let receipts = {
        let mut query = tx.prepare("SELECT reserved,receipt FROM operations")?;
        query
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (reserved, wire) in receipts {
        let receipt: OperationReceipt = super::decode(&wire)?;
        if reserved != 0
            || !receipt.state().is_final()
            || matches!(
                receipt.state(),
                OperationState::Running | OperationState::OutcomeUnknown
            )
        {
            return Err(StoreError::Busy);
        }
    }

    // Do not run normal Store recovery before purge admission: it converts
    // running terminals to Lost and discards their exact session IDs. Only a
    // prior clean TerminalService shutdown is positive cleanup evidence.
    ensure_terminal_cleanup_confirmed(tx)?;

    #[cfg(any(unix, windows))]
    {
        if exists(
            tx,
            "SELECT EXISTS(SELECT 1 FROM native_intents WHERE state IN('registered','active','quarantine'))",
        )? || exists(
            tx,
            "SELECT EXISTS(SELECT 1 FROM native_editor_jobs
             WHERE state IN('running','outcomeUnknown')
                OR completion_proof IS NULL OR completed_at_ms IS NULL)",
        )? || exists(
            tx,
            "SELECT EXISTS(SELECT 1 FROM native_git_jobs
             WHERE state NOT IN('succeeded','failed')
                OR completion_proof IS NULL OR completed_at_ms IS NULL)",
        )? || exists(tx, "SELECT EXISTS(SELECT 1 FROM native_file_stages)")?
            || exists(
                tx,
                "SELECT EXISTS(SELECT 1 FROM desktop_namespace_intents
                 WHERE state NOT IN('applied','noChange'))",
            )?
            || exists(
                tx,
                "SELECT EXISTS(SELECT 1 FROM workspace_removals WHERE state IN('stopping','uncertain'))",
            )?
        {
            return Err(StoreError::NativeWriterBusy);
        }
    }

    // A prepared public-configuration write may have an external file effect
    // whose result has not yet been committed. Keep the entire setup document.
    if let Some(wire) = metadata_value(tx, "public_configuration_v1")? {
        let state: PublicConfigurationState = super::decode(&wire)?;
        if state.prepared.is_some() {
            return Err(StoreError::Busy);
        }
    }
    Ok(())
}

impl HostStore {
    /// Start or resume the durable local purge journal. The caller must already
    /// hold the platform OwnerLock matching `profile_identity`, have fenced
    /// cloud authority through the real logout path, and positively checked
    /// that the cloud revoke completed. This method never clears the auth
    /// bundle or filesystem data.
    #[cfg(any(unix, windows))]
    fn begin_profile_purge(
        &mut self,
        operation_id: OperationId,
        profile_identity: (u64, u64),
    ) -> Result<ProfilePurgeBegin> {
        if profile_identity.0 == 0 || profile_identity.1 == 0 {
            return Err(StoreError::Invalid);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let authorization = read_authorization_state(&tx)?;
        if !authorization.locked
            || authorization.pending_cloud_revoke
            || read_cloud_history(&tx)? != Some(false)
        {
            return Err(StoreError::Fenced);
        }
        if let Some(mut record) = load_record(&tx)? {
            if record.host_id != self.identity.host_id
                || record.profile_id != self.identity.profile_id
                || record.profile_device != profile_identity.0
                || record.profile_inode != profile_identity.1
            {
                return Err(StoreError::Fenced);
            }
            let prior_attempt = purge_operation_attempt(&tx, operation_id)?;
            if record.phase == ProfilePurgePhase::Complete {
                match prior_attempt {
                    Some(attempt_id) if attempt_id == record.attempt_id => {
                        let owner_generation: String = tx.query_row(
                            "SELECT value FROM metadata WHERE key='owner_generation'",
                            [],
                            |row| row.get(0),
                        )?;
                        let owner_generation = owner_generation
                            .parse::<u64>()
                            .map_err(|_| StoreError::Storage)?;
                        if owner_generation != record.owner_generation
                            || profile_purge_store_has_mutable_data(&tx)?
                        {
                            return Err(StoreError::IdempotencyConflict);
                        }
                        ensure_quiescent(&tx)?;
                        tx.commit()?;
                        return Ok(ProfilePurgeBegin {
                            record,
                            authority: None,
                        });
                    }
                    Some(_) => return Err(StoreError::IdempotencyConflict),
                    None => {}
                }

                // A different operation is a fresh explicit purge. The old
                // completed operation remains idempotent only while its Store
                // generation and mutable Store state are unchanged.
                ensure_quiescent(&tx)?;
                reserve_purge_operation(&tx, operation_id, operation_id)?;
                record.attempt_id = operation_id;
                record.owner_runtime_id = self.runtime;
                record.owner_generation = self.generation;
                record.phase = ProfilePurgePhase::Started;
                record.uncertain = false;
                tx.execute(
                    "UPDATE profile_purge SET attempt_id=?1,owner_runtime_id=?2,
                     owner_generation=?3,phase='started',uncertain=0 WHERE id=1",
                    params![
                        key(operation_id),
                        key(self.runtime),
                        self.generation.to_string(),
                    ],
                )?;
                tx.execute(
                    "UPDATE metadata SET value=?1 WHERE key='owner_generation'",
                    [self.generation.to_string()],
                )?;
                tx.commit()?;
                let authority = authority(self, &record);
                return Ok(ProfilePurgeBegin {
                    record,
                    authority: Some(authority),
                });
            }

            if let Err(error) = ensure_quiescent(&tx) {
                tx.execute("UPDATE profile_purge SET uncertain=1 WHERE id=1", [])?;
                tx.commit()?;
                return Err(error);
            }
            let restart_attempt = match prior_attempt {
                Some(attempt_id) if attempt_id == record.attempt_id => false,
                Some(_) => return Err(StoreError::IdempotencyConflict),
                None => true,
            };
            if restart_attempt {
                reserve_purge_operation(&tx, operation_id, operation_id)?;
                record.attempt_id = operation_id;
                record.phase = ProfilePurgePhase::Started;
            }
            record.owner_runtime_id = self.runtime;
            record.owner_generation = self.generation;
            record.uncertain = false;
            tx.execute(
                "UPDATE profile_purge SET attempt_id=?1,owner_runtime_id=?2,
                 owner_generation=?3,phase=?4,uncertain=0 WHERE id=1",
                params![
                    key(record.attempt_id),
                    key(self.runtime),
                    self.generation.to_string(),
                    phase_text(record.phase),
                ],
            )?;
            tx.execute(
                "UPDATE metadata SET value=?1 WHERE key='owner_generation'",
                [self.generation.to_string()],
            )?;
            tx.commit()?;
            let authority = authority(self, &record);
            return Ok(ProfilePurgeBegin {
                record,
                authority: Some(authority),
            });
        }

        ensure_quiescent(&tx)?;
        reserve_purge_operation(&tx, operation_id, operation_id)?;
        tx.execute(
            "UPDATE metadata SET value=?1 WHERE key='owner_generation'",
            [self.generation.to_string()],
        )?;
        tx.execute(
            "INSERT INTO profile_purge(
                id,attempt_id,host_id,profile_id,owner_runtime_id,owner_generation,
                profile_device,profile_inode,phase,uncertain
             ) VALUES(1,?1,?2,?3,?4,?5,?6,?7,'started',0)",
            params![
                key(operation_id),
                key(self.identity.host_id),
                key(self.identity.profile_id),
                key(self.runtime),
                self.generation.to_string(),
                profile_identity.0.to_string(),
                profile_identity.1.to_string(),
            ],
        )?;
        tx.commit()?;
        let record = load_record(&self.db)?.ok_or(StoreError::Storage)?;
        let authority = authority(self, &record);
        Ok(ProfilePurgeBegin {
            record,
            authority: Some(authority),
        })
    }

    #[cfg(any(unix, windows))]
    fn profile_purge_status(&self) -> Result<Option<ProfilePurgeRecord>> {
        load_record(&self.db)
    }

    #[cfg(any(unix, windows))]
    fn mark_profile_purge_uncertain(
        &mut self,
        authority: &ProfilePurgeAuthority,
    ) -> Result<ProfilePurgeRecord> {
        let host_id = self.identity.host_id;
        let profile_id = self.identity.profile_id;
        let runtime = self.runtime;
        let generation = self.generation;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = validate_authority(&tx, host_id, profile_id, runtime, generation, authority)?;
        tx.execute("UPDATE profile_purge SET uncertain=1 WHERE id=1", [])?;
        tx.commit()?;
        let mut record = record;
        record.uncertain = true;
        Ok(record)
    }

    #[cfg(any(unix, windows))]
    fn mark_profile_purge_host_auth_reset(
        &mut self,
        authority: &ProfilePurgeAuthority,
    ) -> Result<ProfilePurgeRecord> {
        self.advance_profile_purge(
            authority,
            ProfilePurgePhase::Started,
            ProfilePurgePhase::HostAuthReset,
        )
    }

    #[cfg(any(unix, windows))]
    fn mark_profile_purge_git_cleared(
        &mut self,
        authority: &ProfilePurgeAuthority,
    ) -> Result<ProfilePurgeRecord> {
        self.advance_profile_purge(
            authority,
            ProfilePurgePhase::HostAuthReset,
            ProfilePurgePhase::GitCredentialsCleared,
        )
    }

    fn advance_profile_purge(
        &mut self,
        authority: &ProfilePurgeAuthority,
        expected: ProfilePurgePhase,
        next: ProfilePurgePhase,
    ) -> Result<ProfilePurgeRecord> {
        let host_id = self.identity.host_id;
        let profile_id = self.identity.profile_id;
        let runtime = self.runtime;
        let generation = self.generation;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = validate_authority(&tx, host_id, profile_id, runtime, generation, authority)?;
        if record.phase != expected {
            return Err(StoreError::Fenced);
        }
        tx.execute(
            "UPDATE profile_purge SET phase=?1,uncertain=0 WHERE id=1 AND phase=?2",
            params![phase_text(next), phase_text(expected)],
        )?;
        tx.commit()?;
        let mut record = record;
        record.phase = next;
        record.uncertain = false;
        Ok(record)
    }

    /// Clear only reviewed, mutable Host rows after positive provider and
    /// writer cleanup. Identity, auth configuration, revoke history, monotonic
    /// clocks, initialization receipts and unknown metadata/tables survive.
    #[cfg(any(unix, windows))]
    fn clear_profile_purge_mutable_store(
        &mut self,
        authority: &ProfilePurgeAuthority,
    ) -> Result<ProfilePurgeRecord> {
        let host_id = self.identity.host_id;
        let profile_id = self.identity.profile_id;
        let runtime = self.runtime;
        let generation = self.generation;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = validate_authority(&tx, host_id, profile_id, runtime, generation, authority)?;
        if record.phase != ProfilePurgePhase::GitCredentialsCleared {
            return Err(StoreError::Fenced);
        }
        ensure_quiescent(&tx)?;

        tx.execute("DELETE FROM desktop_namespace_intents", [])?;
        tx.execute("DELETE FROM workspace_removal_sessions", [])?;
        tx.execute("DELETE FROM workspace_removals", [])?;
        tx.execute("DELETE FROM native_file_stages", [])?;
        tx.execute("DELETE FROM native_git_jobs", [])?;
        tx.execute("DELETE FROM native_editor_jobs", [])?;
        tx.execute("DELETE FROM native_intents", [])?;
        tx.execute("DELETE FROM terminals", [])?;
        tx.execute("DELETE FROM outbox", [])?;
        tx.execute("DELETE FROM operations", [])?;
        tx.execute("DELETE FROM events", [])?;
        tx.execute("DELETE FROM projects", [])?;
        tx.execute("DELETE FROM default_shell", [])?;
        tx.execute(
            "DELETE FROM metadata WHERE key IN(
                'local_start_mode','login_generation','authorization_verified_generation',
                'authorization_rejection','deferred_login_intent','cloud_runtime_state',
                'host_publication_intent','host_acknowledged_publication',
                'host_display_name'
             ) OR key GLOB 'shell_profile/*'
               OR key GLOB 'shell_profile_cwd/*'
               OR key GLOB 'workspace_import/*'
               OR key GLOB 'host_pairing_intent:*'
               OR key GLOB 'host_workspace_grant:*'
               OR key GLOB 'host_channel_intent:*'
               OR key GLOB 'host_channel_admission:*'",
            [],
        )?;
        tx.execute(
            "UPDATE profile_purge SET phase='storeCleared',uncertain=0 WHERE id=1 AND phase='gitCredentialsCleared'",
            [],
        )?;
        tx.commit()?;
        let mut record = record;
        record.phase = ProfilePurgePhase::StoreCleared;
        record.uncertain = false;
        Ok(record)
    }

    #[cfg(any(unix, windows))]
    fn complete_profile_purge(
        &mut self,
        authority: &ProfilePurgeAuthority,
    ) -> Result<ProfilePurgeRecord> {
        let host_id = self.identity.host_id;
        let profile_id = self.identity.profile_id;
        let runtime = self.runtime;
        let generation = self.generation;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = validate_authority(&tx, host_id, profile_id, runtime, generation, authority)?;
        if record.phase != ProfilePurgePhase::StoreCleared {
            return Err(StoreError::Fenced);
        }
        tx.execute(
            "UPDATE profile_purge SET phase='complete',uncertain=0 WHERE id=1 AND phase='storeCleared'",
            [],
        )?;
        tx.commit()?;
        let mut record = record;
        record.phase = ProfilePurgePhase::Complete;
        record.uncertain = false;
        Ok(record)
    }
}

#[cfg(any(unix, windows))]
impl ProfilePurgeStore {
    /// Persist the established local logout fence if remote authorization may
    /// still exist. This deliberately creates no purge journal, allowing the
    /// normal Host revoke worker to reopen and finish its existing ACK flow.
    pub fn ensure_revocation_fenced(&mut self) -> Result<AuthorizationState> {
        let state = self.store.authorization_state()?;
        if state.pending_cloud_revoke {
            return Ok(state);
        }
        if state.locked && self.store.cloud_authorization_may_exist()? == Some(false) {
            return Ok(state);
        }
        self.store
            .fence_authorization(AuthorizationFenceReason::LocalLogout)
    }

    pub fn authorization_state(&self) -> Result<AuthorizationState> {
        self.store.authorization_state()
    }

    pub fn auth_configuration(&self) -> Result<Option<ipc::LocalAuthConfiguration>> {
        self.store.auth_configuration()
    }

    pub fn begin(
        &mut self,
        operation_id: OperationId,
        profile_identity: (u64, u64),
    ) -> Result<ProfilePurgeBegin> {
        self.store
            .begin_profile_purge(operation_id, profile_identity)
    }

    pub fn status(&self) -> Result<Option<ProfilePurgeRecord>> {
        self.store.profile_purge_status()
    }

    pub fn mark_uncertain(
        &mut self,
        authority: &ProfilePurgeAuthority,
    ) -> Result<ProfilePurgeRecord> {
        self.store.mark_profile_purge_uncertain(authority)
    }

    pub fn mark_host_auth_reset(
        &mut self,
        authority: &ProfilePurgeAuthority,
    ) -> Result<ProfilePurgeRecord> {
        self.store.mark_profile_purge_host_auth_reset(authority)
    }

    pub fn mark_git_credentials_cleared(
        &mut self,
        authority: &ProfilePurgeAuthority,
    ) -> Result<ProfilePurgeRecord> {
        self.store.mark_profile_purge_git_cleared(authority)
    }

    pub fn clear_mutable_store(
        &mut self,
        authority: &ProfilePurgeAuthority,
    ) -> Result<ProfilePurgeRecord> {
        self.store.clear_profile_purge_mutable_store(authority)
    }

    pub fn complete(&mut self, authority: &ProfilePurgeAuthority) -> Result<ProfilePurgeRecord> {
        self.store.complete_profile_purge(authority)
    }
}
