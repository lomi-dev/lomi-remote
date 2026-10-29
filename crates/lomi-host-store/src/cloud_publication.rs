//! Durable intent only: callers verify remote authority and response provenance.
use super::*;
use lomi_remote_protocol::http::{
    HostRuntimeGetResult, PublicationParams, PublicationResult, PublicationTerminals,
    PublicationWorkspaces, PublishedTerminal, PublishedWorkspace, RuntimeBinding,
};

const RUNTIME_KEY: &str = "cloud_runtime_state";
const INTENT_KEY: &str = "host_publication_intent";
const ACKNOWLEDGED_KEY: &str = "host_acknowledged_publication";
const MAX_RECORD_BYTES: usize = 2 * 1024 * 1024;
const MAX_SEQUENCE: u64 = i64::MAX as u64;

/// Trusted caller binding, never remote JSON. The caller independently validates
/// canonical Remote API origin, credential family and volatile logout state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudRuntimeScope {
    pub authorization_generation: u64,
    pub remote_api_origin: String,
    pub host_id: HostId,
    pub owner_runtime_id: RuntimeId,
    pub owner_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudRuntimeState {
    pub scope: CloudRuntimeScope,
    pub server_runtime: RuntimeBinding,
    pub acknowledged_publication_seq: DecimalU64,
}

/// Immutable whole-host snapshot. This contains no paths, names or titles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPublicationIntent {
    pub token: String,
    pub scope: CloudRuntimeScope,
    pub params: PublicationParams,
    pub workspace_publications: Vec<Publication>,
}

/// Exact last acknowledged membership, not current consent or remote authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostAcknowledgedPublication {
    pub state: CloudRuntimeState,
    pub workspaces: PublicationWorkspaces,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record<T> {
    version: u32,
    value: T,
}

// This is a bounded shape check, not URL canonicalization or an authority check.
fn validate_scope(scope: &CloudRuntimeScope) -> Result<()> {
    let origin = &scope.remote_api_origin;
    let authority = origin.strip_prefix("https://");
    if scope.owner_generation == 0
        || origin.len() > 2048
        || !origin.is_ascii()
        || origin
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        || authority.is_none_or(|a| {
            a.is_empty()
                || a.bytes()
                    .any(|b| matches!(b, b'/' | b'?' | b'#' | b'@' | b'\\' | b'%'))
        })
    {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
fn validate_runtime(runtime: &RuntimeBinding) -> Result<()> {
    if runtime.runtime_generation.0 == 0
        || runtime.runtime_generation.0 > MAX_SEQUENCE
        || runtime.host_access_epoch.0 == 0
        || runtime.host_access_epoch.0 > MAX_SEQUENCE
    {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
fn validate_state(state: &CloudRuntimeState) -> Result<()> {
    validate_scope(&state.scope)?;
    validate_runtime(&state.server_runtime)?;
    if state.server_runtime.runtime_id != state.scope.owner_runtime_id
        || state.acknowledged_publication_seq.0 > MAX_SEQUENCE
    {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
fn validate_intent(intent: &HostPublicationIntent) -> Result<()> {
    validate_scope(&intent.scope)?;
    validate_runtime(&intent.params.runtime)?;
    if intent.params.runtime.runtime_id != intent.scope.owner_runtime_id
        || Uuid::parse_str(&intent.token).is_err()
        || intent.params.expected_publication_seq.0 >= MAX_SEQUENCE
        || intent.params.publication_seq.0 != intent.params.expected_publication_seq.0 + 1
        || intent.workspace_publications.len() > 256
        || intent
            .workspace_publications
            .iter()
            .enumerate()
            .any(|(i, p)| {
                p.token.is_empty()
                    || p.token.len() > 128
                    || intent.workspace_publications[..i]
                        .iter()
                        .any(|old| old.workspace_id == p.workspace_id)
            })
    {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
fn read_record<T: DeserializeOwned>(db: &Connection, key: &str) -> Result<Option<T>> {
    // Check bytes before fetching/deserializing a possibly corrupted record.
    let length: Option<i64> = db
        .query_row(
            "SELECT length(CAST(value AS BLOB)) FROM metadata WHERE key=?1",
            [key],
            |r| r.get(0),
        )
        .optional()?;
    match length {
        None => return Ok(None),
        Some(n) if n <= 0 || n > MAX_RECORD_BYTES as i64 => return Err(StoreError::Storage),
        _ => (),
    }
    let wire: String = db.query_row("SELECT value FROM metadata WHERE key=?1", [key], |r| {
        r.get(0)
    })?;
    let record: Record<T> = decode(&wire)?;
    if record.version != 1 {
        return Err(StoreError::Storage);
    }
    Ok(Some(record.value))
}
fn write_record(tx: &Transaction<'_>, key: &str, value: &impl Serialize) -> Result<()> {
    let wire = json(&Record { version: 1, value })?;
    if wire.len() > MAX_RECORD_BYTES {
        return Err(StoreError::ResourceExhausted);
    }
    tx.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![key, wire])?;
    Ok(())
}
type PublicationRecords = (
    Option<CloudRuntimeState>,
    Option<HostPublicationIntent>,
    Option<HostAcknowledgedPublication>,
);
fn records(db: &Connection) -> Result<PublicationRecords> {
    let state: Option<CloudRuntimeState> = read_record(db, RUNTIME_KEY)?;
    let intent: Option<HostPublicationIntent> = read_record(db, INTENT_KEY)?;
    let acknowledged: Option<HostAcknowledgedPublication> = read_record(db, ACKNOWLEDGED_KEY)?;
    if let Some(state) = &state {
        validate_state(state).map_err(|_| StoreError::Storage)?;
        let identity: Identity = decode(&db.query_row::<String, _, _>(
            "SELECT value FROM metadata WHERE key='identity'",
            [],
            |r| r.get(0),
        )?)?;
        if state.scope.host_id != identity.host_id {
            return Err(StoreError::Storage);
        }
    }
    if let Some(intent) = &intent {
        validate_intent(intent).map_err(|_| StoreError::Storage)?;
        let state = state.as_ref().ok_or(StoreError::Storage)?;
        if intent.scope != state.scope
            || intent.params.runtime != state.server_runtime
            || intent.params.expected_publication_seq != state.acknowledged_publication_seq
        {
            return Err(StoreError::Storage);
        }
    }
    if let Some(acknowledged) = &acknowledged {
        validate_state(&acknowledged.state).map_err(|_| StoreError::Storage)?;
        if acknowledged.state.acknowledged_publication_seq.0 == 0
            || Some(&acknowledged.state) != state.as_ref()
        {
            return Err(StoreError::Storage);
        }
    }
    Ok((state, intent, acknowledged))
}
fn guard(
    db: &Connection,
    scope: &CloudRuntimeScope,
    runtime: RuntimeId,
    generation: u64,
    host: HostId,
) -> Result<()> {
    validate_scope(scope)?;
    let auth = checked_authorization_generation(db, scope.authorization_generation)?;
    if auth.locked
        || auth.pending_cloud_revoke
        || scope.host_id != host
        || scope.owner_runtime_id != runtime
        || scope.owner_generation != generation
    {
        return Err(StoreError::Fenced);
    }
    Ok(())
}

impl HostStore {
    /// Construct only after independently validating origin and credential family.
    pub fn cloud_runtime_scope(
        &self,
        authorization_generation: u64,
        remote_api_origin: String,
    ) -> Result<CloudRuntimeScope> {
        let scope = CloudRuntimeScope {
            authorization_generation,
            remote_api_origin,
            host_id: self.identity.host_id,
            owner_runtime_id: self.runtime,
            owner_generation: self.generation,
        };
        self.guard_cloud_scope(&scope)?;
        Ok(scope)
    }
    fn guard_cloud_scope(&self, scope: &CloudRuntimeScope) -> Result<()> {
        if self.authorization_sealed.get() {
            return Err(StoreError::Fenced);
        }
        guard(
            &self.db,
            scope,
            self.runtime,
            self.generation,
            self.identity.host_id,
        )
    }
    /// A current binding is never inferred from a predecessor's durable state.
    pub fn cloud_runtime_state(
        &self,
        scope: &CloudRuntimeScope,
    ) -> Result<Option<CloudRuntimeState>> {
        self.guard_cloud_scope(scope)?;
        let (state, _, _) = records(&self.db)?;
        if state.as_ref().is_some_and(|s| s.scope != *scope) {
            return Err(StoreError::Fenced);
        }
        Ok(state)
    }
    /// Historical membership only. Callers must independently check freshness,
    /// authority, current consent, workspace epoch and exact terminal membership.
    /// Legacy state without this record returns None and requires a fresh publish.
    pub fn acknowledged_host_publication(
        &self,
        expected: &CloudRuntimeState,
    ) -> Result<Option<HostAcknowledgedPublication>> {
        self.guard_cloud_scope(&expected.scope)?;
        let (state, _, acknowledged) = records(&self.db)?;
        if state.as_ref() != Some(expected) {
            return Err(StoreError::RevisionConflict);
        }
        Ok(acknowledged)
    }
    /// Reconciliation-only evidence, including after reopen/logout. Grants no
    /// authority to resend, adopt sessions, acknowledge or contact a remote API.
    pub fn pending_host_publication(&self) -> Result<Option<HostPublicationIntent>> {
        Ok(records(&self.db)?.1)
    }
    /// Reconciliation-only predecessor state; requires an authorized current
    /// owner but deliberately does not adopt the stored scope.
    pub fn cloud_runtime_reconciliation_state(
        &self,
        scope: &CloudRuntimeScope,
    ) -> Result<Option<CloudRuntimeState>> {
        self.guard_cloud_scope(scope)?;
        Ok(records(&self.db)?.0)
    }
    /// Install a verified fresh claim for this owner. Expected state is exact
    /// CAS; an unresolved snapshot must first be explicitly reconciled/invalidated.
    pub fn compare_and_set_cloud_runtime(
        &mut self,
        scope: &CloudRuntimeScope,
        expected: Option<&CloudRuntimeState>,
        server_runtime: RuntimeBinding,
        acknowledged_publication_seq: DecimalU64,
    ) -> Result<CloudRuntimeState> {
        self.guard_cloud_scope(scope)?;
        let next = CloudRuntimeState {
            scope: scope.clone(),
            server_runtime,
            acknowledged_publication_seq,
        };
        validate_state(&next)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        guard(
            &tx,
            scope,
            self.runtime,
            self.generation,
            self.identity.host_id,
        )?;
        let (old, intent, _) = records(&tx)?;
        if old.as_ref() != expected || intent.is_some() {
            return Err(StoreError::RevisionConflict);
        }
        // Replacement cannot silently adopt or reset an existing claim/sequence.
        if old.as_ref().is_some_and(|old| old != &next) {
            return Err(StoreError::RevisionConflict);
        }
        write_record(&tx, RUNTIME_KEY, &next)?;
        tx.commit()?;
        Ok(next)
    }
    /// Explicit reconciliation decision under the current authorized owner. Both
    /// state and intent must compare exactly; acknowledged membership is cleared
    /// with them, while all workspace outbox rows are preserved.
    pub fn invalidate_cloud_runtime(
        &mut self,
        current_scope: &CloudRuntimeScope,
        expected: &CloudRuntimeState,
        expected_intent: Option<&HostPublicationIntent>,
    ) -> Result<()> {
        self.guard_cloud_scope(current_scope)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        guard(
            &tx,
            current_scope,
            self.runtime,
            self.generation,
            self.identity.host_id,
        )?;
        let (state, intent, _) = records(&tx)?;
        if state.as_ref() != Some(expected) || intent.as_ref() != expected_intent {
            return Err(StoreError::RevisionConflict);
        }
        tx.execute(
            "DELETE FROM metadata WHERE key IN (?1,?2,?3)",
            params![RUNTIME_KEY, INTENT_KEY, ACKNOWLEDGED_KEY],
        )?;
        tx.commit()?;
        Ok(())
    }
    /// Freeze membership and all current workspace tokens in one transaction.
    /// Repeated preparation returns the original intent even after local edits.
    pub fn prepare_host_publication(
        &mut self,
        expected: &CloudRuntimeState,
    ) -> Result<HostPublicationIntent> {
        self.guard_cloud_scope(&expected.scope)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        guard(
            &tx,
            &expected.scope,
            self.runtime,
            self.generation,
            self.identity.host_id,
        )?;
        let (state, intent, _) = records(&tx)?;
        if state.as_ref() != Some(expected) {
            return Err(StoreError::RevisionConflict);
        }
        if let Some(intent) = intent {
            return Ok(intent);
        }
        let sequence = expected
            .acknowledged_publication_seq
            .0
            .checked_add(1)
            .filter(|n| *n <= MAX_SEQUENCE)
            .ok_or(StoreError::ResourceExhausted)?;
        let mut workspaces = Vec::new();
        for project in projects(&tx)?.into_iter().filter(|p| p.consent) {
            if project.state.context.runtime_id != self.runtime
                || project.state.context.runtime_generation.0 != self.generation
            {
                return Err(StoreError::Fenced);
            }
            let mut terminals = Vec::new();
            let mut stack: Vec<_> = project.state.tabs.0.iter().map(|tab| &tab.layout).collect();
            while let Some(layout) = stack.pop() {
                match layout {
                    TerminalLayout::Split { first, second, .. } => {
                        stack.push(first);
                        stack.push(second);
                    }
                    TerminalLayout::Pane { pane } if pane.state == PaneState::Running => {
                        let session = pane.session.as_ref().ok_or(StoreError::Storage)?;
                        let running: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM terminals WHERE workspace=?1 AND pane=?2 AND status='Running')", params![key(project.state.context.workspace_id), key(pane.pane_id)], |r| r.get(0))?;
                        if !running
                            || session.workspace != project.state.context
                            || session.pane_id != pane.pane_id
                        {
                            return Err(StoreError::Storage);
                        }
                        terminals.push(PublishedTerminal {
                            pane_id: pane.pane_id,
                            session_id: session.session_id,
                            session_epoch: session.session_epoch,
                        });
                    }
                    TerminalLayout::Pane { .. } => (),
                }
            }
            terminals.sort_by_key(|t| key(t.pane_id));
            workspaces.push(PublishedWorkspace {
                workspace_id: project.state.context.workspace_id,
                workspace_epoch: project.state.context.workspace_epoch,
                terminals: PublicationTerminals::try_from(terminals)
                    .map_err(|_| StoreError::Invalid)?,
            });
        }
        let workspace_publications = {
            let mut query = tx.prepare("SELECT publication FROM outbox ORDER BY workspace")?;
            query
                .query_map([], |r| r.get::<_, String>(0))?
                .map(|r| decode(&r?))
                .collect::<Result<Vec<Publication>>>()?
        };
        let intent = HostPublicationIntent {
            token: Uuid::new_v4().to_string(),
            scope: expected.scope.clone(),
            params: PublicationParams {
                runtime: expected.server_runtime.clone(),
                expected_publication_seq: expected.acknowledged_publication_seq,
                publication_seq: DecimalU64(sequence),
                workspaces: PublicationWorkspaces::try_from(workspaces)
                    .map_err(|_| StoreError::ResourceExhausted)?,
            },
            workspace_publications,
        };
        validate_intent(&intent)?;
        write_record(&tx, INTENT_KEY, &intent)?;
        tx.commit()?;
        Ok(intent)
    }
    /// Caller must verify response origin, authenticated family, current volatile
    /// authority and request association. A structurally valid DTO is insufficient.
    pub fn acknowledge_host_publication(
        &mut self,
        expected: &HostPublicationIntent,
        response: &PublicationResult,
    ) -> Result<CloudRuntimeState> {
        self.guard_cloud_scope(&expected.scope)?;
        if response.runtime != expected.params.runtime
            || response.publication_seq != expected.params.publication_seq
        {
            return Err(StoreError::Fenced);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        guard(
            &tx,
            &expected.scope,
            self.runtime,
            self.generation,
            self.identity.host_id,
        )?;
        let (state, intent, _) = records(&tx)?;
        if intent.as_ref() != Some(expected) {
            return Err(StoreError::RevisionConflict);
        }
        let mut state = state.ok_or(StoreError::Storage)?;
        for publication in &expected.workspace_publications {
            acknowledge_publication(&tx, publication)?;
        }
        state.acknowledged_publication_seq = response.publication_seq;
        write_record(&tx, RUNTIME_KEY, &state)?;
        write_record(
            &tx,
            ACKNOWLEDGED_KEY,
            &HostAcknowledgedPublication {
                state: state.clone(),
                workspaces: expected.params.workspaces.clone(),
            },
        )?;
        tx.execute("DELETE FROM metadata WHERE key=?1", [INTENT_KEY])?;
        tx.commit()?;
        Ok(state)
    }
    /// Lost PUT recovery requires a verified GET at the exact intended sequence.
    /// Advanced or different bindings are reconciliation conflicts, never success.
    pub fn acknowledge_host_publication_from_runtime(
        &mut self,
        expected: &HostPublicationIntent,
        response: &HostRuntimeGetResult,
    ) -> Result<CloudRuntimeState> {
        if response.host_id != expected.scope.host_id
            || response.host_access_epoch != expected.params.runtime.host_access_epoch
            || response.runtime_generation != expected.params.runtime.runtime_generation
            || response.runtime.as_ref() != Some(&expected.params.runtime)
            || response.publication_seq != expected.params.publication_seq
        {
            return Err(StoreError::Fenced);
        }
        self.acknowledge_host_publication(
            expected,
            &PublicationResult {
                runtime: expected.params.runtime.clone(),
                publication_seq: response.publication_seq,
            },
        )
    }
}
