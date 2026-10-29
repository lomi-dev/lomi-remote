//! Closed owner-locked maintenance access. This never allocates a runtime,
//! migrates a schema, creates a database or performs process/secret operations.
use super::*;
#[cfg(unix)]
use lomi_platform::unix as native;
#[cfg(windows)]
use lomi_platform::windows as native;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintenanceProfileObservation {
    pub identity: Identity,
    pub profile_schema: u64,
    pub authorization_generation: u64,
    pub remote_locked: bool,
    pub pending_cloud_revoke: bool,
}

/// Borrows the actual persistent native OwnerLock for the whole SQLite turn.
/// SQLite can recover committed WAL/rollback state in this owning account;
/// ordinary Host runtime recovery and schema migrations are never invoked.
pub struct MaintenanceProfileStore<'a> {
    db: Connection,
    owner: &'a native::OwnerLock,
    identity: Identity,
    schema: i64,
}
impl<'a> MaintenanceProfileStore<'a> {
    pub fn open_existing(owner: &'a native::OwnerLock, identity: &Identity) -> Result<Self> {
        let path = owner
            .validate_existing_database()
            .map_err(|_| StoreError::Storage)?;
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        db.busy_timeout(Duration::ZERO)?;
        db.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
        db.set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA,
            false,
        )?;
        verify_expected_identity(&db, Some(identity.host_id), Some(identity.profile_id))?;
        let schema = db.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))?;
        // The authorization table was introduced with schema 2. Unknown and
        // pre-authorization formats require explicit signed recovery instead.
        if !(2..=VERSION).contains(&schema) {
            return Err(StoreError::SchemaVersion);
        }
        read_authorization_state(&db)?;
        owner
            .validate_existing_database()
            .map_err(|_| StoreError::Storage)?;
        Ok(Self {
            db,
            owner,
            identity: identity.clone(),
            schema,
        })
    }
    pub fn observation(&self) -> Result<MaintenanceProfileObservation> {
        self.owner
            .validate_existing_database()
            .map_err(|_| StoreError::Storage)?;
        verify_expected_identity(
            &self.db,
            Some(self.identity.host_id),
            Some(self.identity.profile_id),
        )?;
        let state = read_authorization_state(&self.db)?;
        Ok(MaintenanceProfileObservation {
            identity: self.identity.clone(),
            profile_schema: self.schema as u64,
            authorization_generation: state.generation,
            remote_locked: state.locked,
            pending_cloud_revoke: state.pending_cloud_revoke,
        })
    }
    /// Idempotently ensure the established local logout fence before launching
    /// a revoke worker or repairing activation. No login or sharing is granted.
    pub fn ensure_logout_fenced(&mut self) -> Result<MaintenanceProfileObservation> {
        self.owner
            .validate_existing_database()
            .map_err(|_| StoreError::Storage)?;
        verify_expected_identity(
            &self.db,
            Some(self.identity.host_id),
            Some(self.identity.profile_id),
        )?;
        self.db.pragma_update(None, "synchronous", "FULL")?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut state = read_authorization_state(&tx)?;
        // A pre-exchange login can exist while locked with no Cloud history.
        // A rejected login can also be deferred behind an existing revoke.
        // Neither may survive this explicit logout or be promoted by its ACK.
        let has_login_intent = metadata_value(&tx, "login_generation")?.is_some()
            || metadata_value(&tx, DEFERRED_LOGIN_KEY)?.is_some();
        if has_login_intent
            || (!state.pending_cloud_revoke
                && !(state.locked && read_cloud_history(&tx)? == Some(false)))
        {
            state.generation = increment(state.generation)?;
            state.locked = true;
            state.pending_cloud_revoke = true;
            save_authorization_state(&tx, state)?;
            if count(&tx, "SELECT count(*) FROM projects WHERE removed=0")? > 200 {
                return Err(StoreError::ResourceExhausted);
            }
            if self.schema < 12 {
                fence_workspaces_before_removal_schema(&tx, Limits::default())?;
            } else {
                // Unfinished workspace removals already hold their own fence
                // and exact cleanup manifest. The ordinary helper preserves
                // those bindings while fencing every available workspace.
                fence_workspaces(&tx, Limits::default())?;
            }
        }
        tx.execute("DELETE FROM metadata WHERE key IN ('login_generation','authorization_verified_generation',?1,?2)", params![AUTHORIZATION_REJECTION_KEY, DEFERRED_LOGIN_KEY])?;
        tx.commit()?;
        self.observation()
    }
}
