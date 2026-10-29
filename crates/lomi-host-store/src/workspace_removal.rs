//! Durable, filesystem-free phases for removing a workspace registration.
//!
//! The Store records an early privacy fence and exact terminal identities. The
//! Host owns process cleanup and can checkpoint only exact identities captured
//! by a newly-created removal authority. Recovery never repeats that cleanup.

use super::*;
use lomi_remote_protocol::rpc::TerminalLayout;
use lomi_remote_protocol::{
    DecimalU64, OperationId, PaneId, RuntimeId, SessionEpoch, TerminalSessionId, WorkspaceContext,
    WorkspaceEpoch, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const MAX_REMOVAL_SESSIONS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceRemovalState {
    Stopping,
    Uncertain,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceRemovalSessionState {
    Pending,
    CleanupConfirmed,
    OutcomeUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRemovalSession {
    pub pane_id: PaneId,
    pub session_id: TerminalSessionId,
    pub session_epoch: SessionEpoch,
    pub state: WorkspaceRemovalSessionState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRemovalRecord {
    pub workspace_id: WorkspaceId,
    pub attempt_id: OperationId,
    pub owner_runtime_id: RuntimeId,
    pub owner_generation: u64,
    pub source_context: WorkspaceContext,
    pub fenced_context: WorkspaceContext,
    pub source_revision: DecimalU64,
    pub workspace_fence: u64,
    pub state: WorkspaceRemovalState,
    pub sessions: Vec<WorkspaceRemovalSession>,
}

/// A one-use authority minted only by a newly committed begin operation.
/// Cloning it cannot authorize another physical stop: Store rows accept only
/// monotonically checkpointed exact manifest identities and its pinned owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceRemovalAuthority {
    workspace_id: WorkspaceId,
    attempt_id: OperationId,
    owner_runtime_id: RuntimeId,
    owner_generation: u64,
    workspace_fence: u64,
    fenced_epoch: WorkspaceEpoch,
}

impl WorkspaceRemovalAuthority {
    pub fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub fn attempt_id(&self) -> OperationId {
        self.attempt_id
    }

    pub fn owner_runtime_id(&self) -> RuntimeId {
        self.owner_runtime_id
    }

    pub fn owner_generation(&self) -> u64 {
        self.owner_generation
    }

    pub fn workspace_fence(&self) -> u64 {
        self.workspace_fence
    }

    pub fn fenced_epoch(&self) -> WorkspaceEpoch {
        self.fenced_epoch
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRemovalBegin {
    pub record: WorkspaceRemovalRecord,
    /// `None` means this workspace already had a durable attempt. Repeated
    /// begin requests expose status but can never authorize PTY cleanup.
    pub authority: Option<WorkspaceRemovalAuthority>,
}

/// Store snapshot required to admit a Host-owned native effect for one
/// workspace. The Host constructs this from the trusted workspace record it
/// already validated before beginning the operation; every field is compared
/// again under the Store write transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceEffectGuard {
    workspace_id: WorkspaceId,
    expected_context: WorkspaceContext,
    local_root: PathBuf,
    expected_fence: u64,
}

impl WorkspaceEffectGuard {
    pub fn new(
        workspace_id: WorkspaceId,
        expected_context: WorkspaceContext,
        local_root: PathBuf,
        expected_fence: u64,
    ) -> Result<Self> {
        if expected_context.workspace_id != workspace_id
            || !local_root.is_absolute()
            || local_root.to_str().is_none()
        {
            return Err(StoreError::Invalid);
        }
        Ok(Self {
            workspace_id,
            expected_context,
            local_root,
            expected_fence,
        })
    }
}

/// Prevent normal project reads and writes while removal is incomplete. The
/// explicit status API below is the only path that reads the fenced record.
pub(super) fn ensure_workspace_available(db: &Connection, id: WorkspaceId) -> Result<()> {
    if workspace_removal_incomplete(db, id)? {
        Err(StoreError::Fenced)
    } else {
        Ok(())
    }
}

fn workspace_removal_incomplete(db: &Connection, id: WorkspaceId) -> Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM workspace_removals
         WHERE workspace=?1 AND state IN('stopping','uncertain'))",
        [key(id)],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

/// Native intent scopes are workspace-validated labels only: they do not bind
/// the eventual physical paths. Keep the global gate until native intents
/// carry a trusted canonical workspace/Git root.
pub(super) fn ensure_native_intent_scope_available(db: &Connection, scope: &str) -> Result<()> {
    if scope != "unscoped" {
        let workspace = scope
            .strip_prefix("workspace:")
            .and_then(|scope| scope.strip_suffix(":unscoped"))
            .ok_or(StoreError::Storage)?;
        let workspace =
            WorkspaceId::try_from(workspace.to_owned()).map_err(|_| StoreError::Storage)?;
        // Revalidate inside the registration/acquisition transaction to close
        // the read-before-write race with an empty legacy removal.
        super::project(db, workspace)?;
    }
    ensure_no_workspace_removal_in_progress(db)
}

pub(super) fn ensure_no_workspace_removal_in_progress(db: &Connection) -> Result<()> {
    let pending: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM workspace_removals
         WHERE state IN('stopping','uncertain'))",
        [],
        |row| row.get(0),
    )?;
    if pending {
        Err(StoreError::Busy)
    } else {
        Ok(())
    }
}

pub(super) fn ensure_root_not_removing(db: &Connection, root: &Path) -> Result<()> {
    let root = root.to_str().ok_or(StoreError::Invalid)?;
    let pending: bool = db.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM projects p
            JOIN workspace_removals r ON r.workspace=p.workspace
            WHERE p.root=?1 AND r.state IN('stopping','uncertain')
         )",
        [root],
        |row| row.get(0),
    )?;
    if pending {
        Err(StoreError::Fenced)
    } else {
        Ok(())
    }
}

pub(super) fn validate_workspace_effect_guard(
    db: &Connection,
    guard: &WorkspaceEffectGuard,
) -> Result<()> {
    let current = super::project(db, guard.workspace_id)?;
    if current.state.context != guard.expected_context
        || current.local_root != guard.local_root
        || current.fence != guard.expected_fence
    {
        return Err(StoreError::Fenced);
    }
    ensure_workspace_effect_root_available(db, &guard.local_root)
}

/// Native Git/editor paths may affect descendants of their workspace root.
/// Compare physical root overlap with every incomplete removal, including
/// ancestor and alias workspaces hidden from ordinary project reads.
fn ensure_workspace_effect_root_available(db: &Connection, root: &Path) -> Result<()> {
    let mut query = db.prepare(
        "SELECT p.root FROM projects p
         JOIN workspace_removals r ON r.workspace=p.workspace
         WHERE r.state IN('stopping','uncertain')",
    )?;
    let roots = query
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if roots
        .iter()
        .any(|pending| super::desktop_namespace::paths_overlap(root, Path::new(pending)))
    {
        Err(StoreError::Busy)
    } else {
        Ok(())
    }
}

impl HostStore {
    /// Install the durable privacy fence and bounded exact-session manifest.
    /// The caller must pass the context/revision it inspected under the
    /// workspace actor. Existing attempts are returned without stop authority.
    pub fn begin_workspace_removal(
        &mut self,
        workspace_id: WorkspaceId,
        expected_context: &WorkspaceContext,
        expected_revision: DecimalU64,
    ) -> Result<WorkspaceRemovalBegin> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(record) = load_workspace_removal(&tx, workspace_id)? {
            tx.commit()?;
            return Ok(WorkspaceRemovalBegin {
                record,
                authority: None,
            });
        }

        let mut project = super::project(&tx, workspace_id)?;
        if &project.state.context != expected_context
            || project.state.domain_revision != expected_revision
        {
            return Err(StoreError::RevisionConflict);
        }
        if expected_context.runtime_id != self.runtime
            || expected_context.runtime_generation.0 != self.generation
        {
            return Err(StoreError::Fenced);
        }
        ensure_removal_quiescent(&tx, workspace_id, &project.local_root)?;

        let source_context = project.state.context.clone();
        let source_revision = project.state.domain_revision;
        let sessions = capture_sessions(&project.state)?;
        let attempt_id = OperationId::from_bytes(Uuid::new_v4().into_bytes())
            .map_err(|_| StoreError::Storage)?;
        project.fence = increment(project.fence)?;
        project.consent = false;
        super::rotate_workspace_epoch(&mut project.state)?;
        for tab in &mut project.state.tabs.0 {
            super::refresh_session_context(&mut tab.layout, &project.state.context);
        }
        project.state.validate().map_err(|_| StoreError::Invalid)?;
        let fenced_context = project.state.context.clone();
        super::save_project(&tx, &project)?;
        super::force_event_room(&tx, self.limits)?;
        super::append_event(&tx, &project.state, None)?;
        super::queue_publication(&tx, &project)?;

        tx.execute(
            "INSERT INTO workspace_removals(
                workspace,attempt_id,owner_runtime_id,owner_generation,
                source_context_json,fenced_context_json,source_revision,
                workspace_fence,state
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'stopping')",
            params![
                key(workspace_id),
                key(attempt_id),
                key(self.runtime),
                self.generation.to_string(),
                super::json(&source_context)?,
                super::json(&fenced_context)?,
                source_revision.0.to_string(),
                project.fence.to_string(),
            ],
        )?;
        for session in &sessions {
            tx.execute(
                "INSERT INTO workspace_removal_sessions(
                    workspace,attempt_id,pane,session_id,session_epoch,state
                 ) VALUES(?1,?2,?3,?4,?5,'pending')",
                params![
                    key(workspace_id),
                    key(attempt_id),
                    key(session.pane_id),
                    key(session.session_id),
                    key(session.session_epoch),
                ],
            )?;
        }
        if sessions.is_empty() {
            finalize_workspace_removal_in_transaction(&tx, workspace_id, attempt_id, self.limits)?;
        }
        tx.commit()?;

        let record = load_workspace_removal(&self.db, workspace_id)?.ok_or(StoreError::Storage)?;
        let authority = (record.state == WorkspaceRemovalState::Stopping).then_some(
            WorkspaceRemovalAuthority {
                workspace_id,
                attempt_id,
                owner_runtime_id: self.runtime,
                owner_generation: self.generation,
                workspace_fence: record.workspace_fence,
                fenced_epoch: record.fenced_context.workspace_epoch,
            },
        );
        Ok(WorkspaceRemovalBegin { record, authority })
    }

    /// Read durable removal state without reopening ordinary workspace access.
    pub fn workspace_removal_status(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Option<WorkspaceRemovalRecord>> {
        load_workspace_removal(&self.db, workspace_id)
    }

    /// Record positive cleanup for one manifest session. This is a Store-only
    /// checkpoint; it performs no terminal/process work and accepts no unknown
    /// or replacement session identity.
    pub fn checkpoint_workspace_removal_session(
        &mut self,
        authority: &WorkspaceRemovalAuthority,
        session_id: TerminalSessionId,
        session_epoch: SessionEpoch,
    ) -> Result<WorkspaceRemovalRecord> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = validate_authority(&tx, self.runtime, self.generation, authority)?;
        if record.state != WorkspaceRemovalState::Stopping {
            return Err(StoreError::Fenced);
        }
        let changed = tx.execute(
            "UPDATE workspace_removal_sessions SET state='cleanupConfirmed'
             WHERE workspace=?1 AND attempt_id=?2 AND session_id=?3
               AND session_epoch=?4 AND state='pending'",
            params![
                key(authority.workspace_id),
                key(authority.attempt_id),
                key(session_id),
                key(session_epoch),
            ],
        )?;
        if changed == 0 {
            let already_confirmed: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM workspace_removal_sessions
                 WHERE workspace=?1 AND attempt_id=?2 AND session_id=?3
                   AND session_epoch=?4 AND state='cleanupConfirmed')",
                params![
                    key(authority.workspace_id),
                    key(authority.attempt_id),
                    key(session_id),
                    key(session_epoch),
                ],
                |row| row.get(0),
            )?;
            if !already_confirmed {
                return Err(StoreError::Fenced);
            }
        }
        tx.commit()?;
        load_workspace_removal(&self.db, authority.workspace_id)?.ok_or(StoreError::Storage)
    }

    /// Permanently fence an attempt whose physical cleanup was not positively
    /// confirmed. It can only be inspected or resolved by a later explicit
    /// product flow; this Store never retries cleanup.
    pub fn mark_workspace_removal_uncertain(
        &mut self,
        authority: &WorkspaceRemovalAuthority,
        unknown_session: Option<(TerminalSessionId, SessionEpoch)>,
    ) -> Result<WorkspaceRemovalRecord> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = validate_authority(&tx, self.runtime, self.generation, authority)?;
        if record.state == WorkspaceRemovalState::Complete {
            tx.commit()?;
            return Ok(record);
        }
        if let Some((session_id, session_epoch)) = unknown_session {
            let updated = tx.execute(
                "UPDATE workspace_removal_sessions SET state='outcomeUnknown'
                 WHERE workspace=?1 AND attempt_id=?2 AND session_id=?3
                   AND session_epoch=?4 AND state='pending'",
                params![
                    key(authority.workspace_id),
                    key(authority.attempt_id),
                    key(session_id),
                    key(session_epoch),
                ],
            )?;
            if updated == 0 {
                let exists: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM workspace_removal_sessions
                     WHERE workspace=?1 AND attempt_id=?2 AND session_id=?3
                       AND session_epoch=?4 AND state IN('cleanupConfirmed','outcomeUnknown'))",
                    params![
                        key(authority.workspace_id),
                        key(authority.attempt_id),
                        key(session_id),
                        key(session_epoch),
                    ],
                    |row| row.get(0),
                )?;
                if !exists {
                    return Err(StoreError::Fenced);
                }
            }
        }
        tx.execute(
            "UPDATE workspace_removals SET state='uncertain'
             WHERE workspace=?1 AND attempt_id=?2 AND state='stopping'",
            params![key(authority.workspace_id), key(authority.attempt_id)],
        )?;
        tx.commit()?;
        load_workspace_removal(&self.db, authority.workspace_id)?.ok_or(StoreError::Storage)
    }

    /// Complete only after every exact manifest session has persisted positive
    /// cleanup evidence. The transaction clears the persisted terminal layout,
    /// soft-removes registration, and preserves project files and audit rows.
    pub fn finalize_workspace_removal(
        &mut self,
        authority: &WorkspaceRemovalAuthority,
    ) -> Result<WorkspaceRemovalRecord> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = validate_authority(&tx, self.runtime, self.generation, authority)?;
        if record.state != WorkspaceRemovalState::Stopping {
            return Err(StoreError::Fenced);
        }
        finalize_workspace_removal_in_transaction(
            &tx,
            authority.workspace_id,
            authority.attempt_id,
            self.limits,
        )?;
        tx.commit()?;
        load_workspace_removal(&self.db, authority.workspace_id)?.ok_or(StoreError::Storage)
    }
}

fn ensure_removal_quiescent(
    tx: &Transaction<'_>,
    workspace_id: WorkspaceId,
    local_root: &Path,
) -> Result<()> {
    let pending_operations = {
        let mut query = tx.prepare("SELECT reserved,receipt FROM operations WHERE workspace=?1")?;
        query
            .query_map([key(workspace_id)], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (reserved, wire) in pending_operations {
        let receipt: OperationReceipt = super::decode(&wire)?;
        if reserved > 0
            || matches!(
                receipt.state(),
                OperationState::Running | OperationState::OutcomeUnknown
            )
        {
            return Err(StoreError::Busy);
        }
    }

    // Native leases do not persist a trusted canonical root scope, so active
    // and quarantined writers conservatively block removal across workspaces.
    if super::has_active_native_writer(tx)? {
        return Err(StoreError::NativeWriterBusy);
    }
    let pending_native_intent: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM native_intents WHERE state='registered')",
        [],
        |row| row.get(0),
    )?;
    if pending_native_intent {
        return Err(StoreError::NativeWriterBusy);
    }
    super::desktop_namespace::ensure_namespace_project_mutation_allowed(tx, local_root)?;
    Ok(())
}

fn capture_sessions(state: &WorkspaceState) -> Result<Vec<WorkspaceRemovalSession>> {
    fn visit(layout: &TerminalLayout, sessions: &mut Vec<WorkspaceRemovalSession>) {
        match layout {
            TerminalLayout::Pane { pane } => {
                if let Some(terminal) = &pane.session {
                    sessions.push(WorkspaceRemovalSession {
                        pane_id: pane.pane_id,
                        session_id: terminal.session_id,
                        session_epoch: terminal.session_epoch,
                        state: WorkspaceRemovalSessionState::Pending,
                    });
                }
            }
            TerminalLayout::Split { first, second, .. } => {
                visit(first, sessions);
                visit(second, sessions);
            }
        }
    }

    let mut sessions = Vec::new();
    for tab in &state.tabs.0 {
        visit(&tab.layout, &mut sessions);
    }
    if sessions.len() > MAX_REMOVAL_SESSIONS {
        return Err(StoreError::ResourceExhausted);
    }
    sessions.sort_by_key(|session| session.pane_id);
    let mut panes = BTreeSet::new();
    let mut session_ids = BTreeSet::new();
    if sessions
        .iter()
        .any(|session| !panes.insert(session.pane_id) || !session_ids.insert(session.session_id))
    {
        return Err(StoreError::Invalid);
    }
    Ok(sessions)
}

fn load_workspace_removal(
    db: &Connection,
    workspace_id: WorkspaceId,
) -> Result<Option<WorkspaceRemovalRecord>> {
    let header: Option<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )> = db
        .query_row(
            "SELECT attempt_id,owner_runtime_id,owner_generation,source_context_json,
                    fenced_context_json,source_revision,workspace_fence,state
             FROM workspace_removals WHERE workspace=?1",
            [key(workspace_id)],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()?;
    let Some((
        attempt_id,
        owner_runtime_id,
        owner_generation,
        source_context,
        fenced_context,
        source_revision,
        workspace_fence,
        state,
    )) = header
    else {
        return Ok(None);
    };
    let mut sessions = {
        let mut query = db.prepare(
            "SELECT pane,session_id,session_epoch,state
             FROM workspace_removal_sessions
             WHERE workspace=?1 AND attempt_id=?2 ORDER BY pane",
        )?;
        query
            .query_map(params![key(workspace_id), attempt_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?
            .map(|row| {
                let (pane, session_id, session_epoch, state) = row?;
                Ok(WorkspaceRemovalSession {
                    pane_id: PaneId::try_from(pane).map_err(|_| StoreError::Storage)?,
                    session_id: TerminalSessionId::try_from(session_id)
                        .map_err(|_| StoreError::Storage)?,
                    session_epoch: SessionEpoch::try_from(session_epoch)
                        .map_err(|_| StoreError::Storage)?,
                    state: parse_session_state(&state)?,
                })
            })
            .collect::<Result<Vec<_>>>()?
    };
    if sessions.len() > MAX_REMOVAL_SESSIONS {
        return Err(StoreError::Storage);
    }
    sessions.shrink_to_fit();
    Ok(Some(WorkspaceRemovalRecord {
        workspace_id,
        attempt_id: OperationId::try_from(attempt_id).map_err(|_| StoreError::Storage)?,
        owner_runtime_id: RuntimeId::try_from(owner_runtime_id).map_err(|_| StoreError::Storage)?,
        owner_generation: parse_decimal(&owner_generation)?,
        source_context: super::decode(&source_context)?,
        fenced_context: super::decode(&fenced_context)?,
        source_revision: DecimalU64(parse_decimal(&source_revision)?),
        workspace_fence: parse_decimal(&workspace_fence)?,
        state: parse_removal_state(&state)?,
        sessions,
    }))
}

fn parse_decimal(value: &str) -> Result<u64> {
    let parsed = value.parse::<u64>().map_err(|_| StoreError::Storage)?;
    if parsed.to_string() != value {
        return Err(StoreError::Storage);
    }
    Ok(parsed)
}

fn parse_removal_state(value: &str) -> Result<WorkspaceRemovalState> {
    match value {
        "stopping" => Ok(WorkspaceRemovalState::Stopping),
        "uncertain" => Ok(WorkspaceRemovalState::Uncertain),
        "complete" => Ok(WorkspaceRemovalState::Complete),
        _ => Err(StoreError::Storage),
    }
}

fn parse_session_state(value: &str) -> Result<WorkspaceRemovalSessionState> {
    match value {
        "pending" => Ok(WorkspaceRemovalSessionState::Pending),
        "cleanupConfirmed" => Ok(WorkspaceRemovalSessionState::CleanupConfirmed),
        "outcomeUnknown" => Ok(WorkspaceRemovalSessionState::OutcomeUnknown),
        _ => Err(StoreError::Storage),
    }
}

fn validate_authority(
    db: &Connection,
    runtime_id: RuntimeId,
    owner_generation: u64,
    authority: &WorkspaceRemovalAuthority,
) -> Result<WorkspaceRemovalRecord> {
    if authority.owner_runtime_id != runtime_id || authority.owner_generation != owner_generation {
        return Err(StoreError::Fenced);
    }
    let record = load_workspace_removal(db, authority.workspace_id)?.ok_or(StoreError::NotFound)?;
    if record.attempt_id != authority.attempt_id
        || record.owner_runtime_id != authority.owner_runtime_id
        || record.owner_generation != authority.owner_generation
        || record.workspace_fence != authority.workspace_fence
        || record.fenced_context.workspace_epoch != authority.fenced_epoch
    {
        return Err(StoreError::Fenced);
    }
    let project = super::project_row(db, authority.workspace_id, true)?;
    if project.fence != authority.workspace_fence || project.state.context != record.fenced_context
    {
        return Err(StoreError::Fenced);
    }
    Ok(record)
}

fn finalize_workspace_removal_in_transaction(
    tx: &Transaction<'_>,
    workspace_id: WorkspaceId,
    attempt_id: OperationId,
    limits: Limits,
) -> Result<()> {
    let record = load_workspace_removal(tx, workspace_id)?.ok_or(StoreError::NotFound)?;
    if record.attempt_id != attempt_id || record.state != WorkspaceRemovalState::Stopping {
        return Err(StoreError::Fenced);
    }
    let unconfirmed: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM workspace_removal_sessions
         WHERE workspace=?1 AND attempt_id=?2 AND state!='cleanupConfirmed')",
        params![key(workspace_id), key(attempt_id)],
        |row| row.get(0),
    )?;
    if unconfirmed {
        return Err(StoreError::Busy);
    }
    let mut project = super::project_row(tx, workspace_id, true)?;
    if project.fence != record.workspace_fence || project.state.context != record.fenced_context {
        return Err(StoreError::Fenced);
    }
    project.consent = false;
    project.state.tabs.0.clear();
    project.state.domain_revision = DecimalU64(super::increment(project.state.domain_revision.0)?);
    project.state.validate().map_err(|_| StoreError::Invalid)?;
    super::save_project(tx, &project)?;
    super::sync_terminals(tx, &project.state)?;
    super::force_event_room(tx, limits)?;
    super::append_event(tx, &project.state, None)?;
    super::queue_publication(tx, &project)?;
    if tx.execute(
        "UPDATE projects SET removed=1 WHERE workspace=?1 AND removed=0 AND fence=?2",
        params![key(workspace_id), record.workspace_fence.to_string()],
    )? != 1
    {
        return Err(StoreError::Fenced);
    }
    if tx.execute(
        "UPDATE workspace_removals SET state='complete'
         WHERE workspace=?1 AND attempt_id=?2 AND state='stopping'",
        params![key(workspace_id), key(attempt_id)],
    )? != 1
    {
        return Err(StoreError::Fenced);
    }
    Ok(())
}

/// Called only during Store recovery. Incomplete physical cleanup becomes
/// permanently uncertain; a fully checkpointed manifest can finish with SQL
/// alone because no process action needs to be repeated.
pub(super) fn recover_workspace_removals(tx: &Transaction<'_>, limits: Limits) -> Result<()> {
    tx.execute(
        "UPDATE workspace_removals SET state='uncertain'
         WHERE state='stopping' AND EXISTS(
             SELECT 1 FROM workspace_removal_sessions s
             WHERE s.workspace=workspace_removals.workspace
               AND s.attempt_id=workspace_removals.attempt_id
               AND s.state!='cleanupConfirmed'
         )",
        [],
    )?;
    let ready = {
        let mut query = tx.prepare(
            "SELECT workspace,attempt_id FROM workspace_removals r
             WHERE state='stopping' AND NOT EXISTS(
                 SELECT 1 FROM workspace_removal_sessions s
                 WHERE s.workspace=r.workspace AND s.attempt_id=r.attempt_id
                   AND s.state!='cleanupConfirmed'
             ) ORDER BY workspace",
        )?;
        query
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .map(|row| {
                let (workspace, attempt_id) = row?;
                Ok((
                    WorkspaceId::try_from(workspace).map_err(|_| StoreError::Storage)?,
                    OperationId::try_from(attempt_id).map_err(|_| StoreError::Storage)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?
    };
    for (workspace_id, attempt_id) in ready {
        finalize_workspace_removal_in_transaction(tx, workspace_id, attempt_id, limits)?;
    }
    Ok(())
}
