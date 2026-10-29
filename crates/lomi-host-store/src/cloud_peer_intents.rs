//! Durable public pairing evidence, never cryptographic or network authority.
//!
//! Callers validate the separately configured origin, protected host/peer pins,
//! credential family, TLS provenance, canonical crypto, signed-body-to-metadata
//! agreement and volatile gates/freshness before prepare, send and ACK. This
//! module does not decode CBOR, verify signatures, deserialize policy tokens or
//! infer authority from a stored grant/publication sequence. Historical evidence
//! survives logout and owner replacement but is never adopted by a new owner.
use super::*;
use lomi_remote_protocol::http::{
    PairingDecisionParams, PairingProposal, PairingResult, RuntimeBinding,
};
use std::collections::BTreeSet;

pub const MAX_PAIRING_DECISION_INTENTS: usize = 64;
pub const MAX_ACKNOWLEDGED_WORKSPACE_GRANTS: usize = 256;
const INTENT_PREFIX: &str = "host_pairing_intent:";
const GRANT_PREFIX: &str = "host_workspace_grant:";
const MAX_RECORD_BYTES: usize = 128 * 1024;
const MAX_TOTAL_BYTES: usize = 8 * 1024 * 1024;
const MAX_COUNTER: u64 = i64::MAX as u64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudPairingScope {
    pub runtime_scope: CloudRuntimeScope,
    pub runtime: RuntimeBinding,
    pub workspace_id: WorkspaceId,
    pub workspace_epoch: WorkspaceEpoch,
    pub workspace_fence: u64,
}
/// Caller-verified public proof. In particular, the caller proves that grant ID,
/// window/account and original expiry match the opaque canonical signed bodies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingDecisionPreparation {
    pub scope: CloudPairingScope,
    pub pairing_id: PairingId,
    pub grant_id: GrantId,
    pub account_id: AccountId,
    pub window_identity_id: WindowIdentityId,
    pub proposal: PairingProposal,
    pub original_expires_at: u64,
    pub params: PairingDecisionParams,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingDecisionIntent {
    pub token: String,
    pub preparation: PairingDecisionPreparation,
}
/// Historical acknowledged wire evidence. This is not HostAuth's ApprovedGrant
/// token, and does not authorize channels or a later owner/credential family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcknowledgedWorkspaceGrant {
    pub intent: PairingDecisionIntent,
    pub response: PairingResult,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record<T> {
    version: u32,
    value: T,
}
#[derive(Default)]
struct Records {
    intents: Vec<PairingDecisionIntent>,
    grants: Vec<AcknowledgedWorkspaceGrant>,
    // Stored bytes plus each pending approval's eventual ACK growth.
    bytes: usize,
}
fn intent_key(id: PairingId) -> String {
    format!("{INTENT_PREFIX}{}", String::from(id))
}
fn grant_key(id: GrantId) -> String {
    format!("{GRANT_PREFIX}{}", String::from(id))
}
fn approves(params: &PairingDecisionParams) -> bool {
    matches!(params, PairingDecisionParams::Approve { .. })
}
fn validate_preparation(p: &PairingDecisionPreparation) -> Result<()> {
    let s = &p.scope;
    let origin = s.runtime_scope.remote_api_origin.strip_prefix("https://");
    let a = &p.proposal.authority;
    let runtime = match &p.params {
        PairingDecisionParams::Approve { runtime, .. }
        | PairingDecisionParams::Deny { runtime } => runtime,
    };
    if s.runtime_scope.owner_generation == 0
        || s.runtime_scope.remote_api_origin.len() > 2048
        || !s.runtime_scope.remote_api_origin.is_ascii()
        || s.runtime_scope
            .remote_api_origin
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        || origin.is_none_or(|value| {
            value.is_empty()
                || value
                    .bytes()
                    .any(|b| matches!(b, b'/' | b'?' | b'#' | b'@' | b'\\' | b'%'))
        })
        || s.runtime.runtime_id != s.runtime_scope.owner_runtime_id
        || s.runtime.runtime_generation.0 == 0
        || s.runtime.runtime_generation.0 > MAX_COUNTER
        || s.runtime.host_access_epoch.0 == 0
        || s.runtime.host_access_epoch.0 > MAX_COUNTER
        || s.workspace_fence == 0
        || p.original_expires_at == 0
        || p.original_expires_at > MAX_COUNTER
        || runtime != &s.runtime
        || a.runtime_id != s.runtime.runtime_id
        || a.runtime_generation != s.runtime.runtime_generation
        || a.access_epoch != s.runtime.host_access_epoch
        || a.workspace_epoch != s.workspace_epoch
        || a.grant_revision.0 == 0
        || a.grant_revision.0 > MAX_COUNTER
        || a.terminal_membership.is_some()
    {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
fn validate_intent(intent: &PairingDecisionIntent) -> Result<()> {
    validate_preparation(&intent.preparation)?;
    if !Uuid::parse_str(&intent.token).is_ok_and(|id| id.to_string() == intent.token) {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
fn validate_ack(intent: &PairingDecisionIntent, response: &PairingResult) -> Result<()> {
    let p = &intent.preparation;
    match (&p.params, response) {
        (
            PairingDecisionParams::Approve { grant, .. },
            PairingResult::Approved {
                pairing_id,
                proposal,
                grant: acknowledged,
                identities,
                authority,
            },
        ) if *pairing_id == p.pairing_id
            && proposal == &p.proposal
            && grant == acknowledged
            && identities == &p.proposal.identities
            && authority == &p.proposal.authority =>
        {
            Ok(())
        }
        (PairingDecisionParams::Deny { .. }, PairingResult::Denied { pairing_id })
            if *pairing_id == p.pairing_id =>
        {
            Ok(())
        }
        _ => Err(StoreError::Fenced),
    }
}
fn expected_approved_record(intent: &PairingDecisionIntent) -> Option<AcknowledgedWorkspaceGrant> {
    let p = &intent.preparation;
    let PairingDecisionParams::Approve { grant, .. } = &p.params else {
        return None;
    };
    Some(AcknowledgedWorkspaceGrant {
        intent: intent.clone(),
        response: PairingResult::Approved {
            pairing_id: p.pairing_id,
            proposal: p.proposal.clone(),
            grant: grant.clone(),
            identities: p.proposal.identities.clone(),
            authority: p.proposal.authority.clone(),
        },
    })
}
fn reserved_intent_bytes(intent: &PairingDecisionIntent, stored_bytes: usize) -> Result<usize> {
    match expected_approved_record(intent) {
        Some(acknowledged) => Ok(stored_bytes.max(encode(&acknowledged)?.len())),
        None => Ok(stored_bytes),
    }
}
fn encode(value: &impl Serialize) -> Result<String> {
    let wire = json(&Record { version: 1, value })?;
    if wire.len() > MAX_RECORD_BYTES {
        return Err(StoreError::ResourceExhausted);
    }
    Ok(wire)
}
fn decode_record<T: DeserializeOwned>(wire: &str) -> Result<T> {
    let record: Record<T> = decode(wire)?;
    if record.version != 1 {
        return Err(StoreError::Storage);
    }
    Ok(record.value)
}
fn records(db: &Connection) -> Result<Records> {
    // Budget and shape are checked before materializing any corrupted JSON.
    let (intents, grants, bytes, largest): (i64, i64, i64, i64) = db.query_row(
        "SELECT COALESCE(sum(key GLOB 'host_pairing_intent:*'),0),COALESCE(sum(key GLOB 'host_workspace_grant:*'),0),COALESCE(sum(length(CAST(value AS BLOB))),0),COALESCE(max(length(CAST(value AS BLOB))),0) FROM metadata WHERE key GLOB 'host_pairing_intent:*' OR key GLOB 'host_workspace_grant:*'",
        [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    if intents < 0
        || grants < 0
        || intents > MAX_PAIRING_DECISION_INTENTS as i64
        || grants > MAX_ACKNOWLEDGED_WORKSPACE_GRANTS as i64
        || bytes < 0
        || bytes > MAX_TOTAL_BYTES as i64
        || largest > MAX_RECORD_BYTES as i64
    {
        return Err(StoreError::Storage);
    }
    let mut out = Records {
        bytes: bytes as usize,
        ..Records::default()
    };
    let mut query = db.prepare("SELECT key,value FROM metadata WHERE key GLOB 'host_pairing_intent:*' OR key GLOB 'host_workspace_grant:*' ORDER BY key")?;
    for row in query.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
        let (key, wire) = row?;
        if key.starts_with(INTENT_PREFIX) {
            let intent: PairingDecisionIntent = decode_record(&wire)?;
            validate_intent(&intent).map_err(|_| StoreError::Storage)?;
            if key != intent_key(intent.preparation.pairing_id) {
                return Err(StoreError::Storage);
            }
            let reserved =
                reserved_intent_bytes(&intent, wire.len()).map_err(|_| StoreError::Storage)?;
            out.bytes = out.bytes.saturating_add(reserved - wire.len());
            if out.bytes > MAX_TOTAL_BYTES {
                return Err(StoreError::Storage);
            }
            out.intents.push(intent);
        } else {
            let grant: AcknowledgedWorkspaceGrant = decode_record(&wire)?;
            validate_intent(&grant.intent).map_err(|_| StoreError::Storage)?;
            validate_ack(&grant.intent, &grant.response).map_err(|_| StoreError::Storage)?;
            if !approves(&grant.intent.preparation.params)
                || key != grant_key(grant.intent.preparation.grant_id)
            {
                return Err(StoreError::Storage);
            }
            out.grants.push(grant);
        }
    }
    if out.grants.len()
        + out
            .intents
            .iter()
            .filter(|intent| approves(&intent.preparation.params))
            .count()
        > MAX_ACKNOWLEDGED_WORKSPACE_GRANTS
    {
        return Err(StoreError::Storage);
    }
    let mut tokens = BTreeSet::new();
    let mut pairings = BTreeSet::new();
    let mut grant_ids = BTreeSet::new();
    let identity: Identity = decode(&db.query_row::<String, _, _>(
        "SELECT value FROM metadata WHERE key='identity'",
        [],
        |r| r.get(0),
    )?)?;
    for intent in out
        .intents
        .iter()
        .chain(out.grants.iter().map(|grant| &grant.intent))
    {
        let p = &intent.preparation;
        if !tokens.insert(intent.token.clone())
            || !pairings.insert(p.pairing_id)
            || (approves(&p.params) && !grant_ids.insert(p.grant_id))
        {
            return Err(StoreError::Storage);
        }
        if p.scope.runtime_scope.host_id != identity.host_id {
            return Err(StoreError::Storage);
        }
    }
    Ok(out)
}
impl HostStore {
    pub(super) fn guard_pairing_scope(
        &self,
        scope: &CloudPairingScope,
        expires_at: u64,
    ) -> Result<()> {
        let state = self
            .cloud_runtime_state(&scope.runtime_scope)?
            .ok_or(StoreError::Fenced)?;
        if state.server_runtime != scope.runtime {
            return Err(StoreError::Fenced);
        }
        let authorization = checked_authorization_generation(
            &self.db,
            scope.runtime_scope.authorization_generation,
        )?;
        if authorization.clock_floor >= expires_at {
            return Err(StoreError::Fenced);
        }
        let p = project(&self.db, scope.workspace_id)?;
        if !p.consent
            || p.fence != scope.workspace_fence
            || p.state.context.workspace_epoch != scope.workspace_epoch
            || p.state.context.runtime_id != self.runtime
            || p.state.context.runtime_generation.0 != self.generation
        {
            return Err(StoreError::Fenced);
        }
        Ok(())
    }
    /// Reconciliation evidence only; valid after logout or reopen, not send authority.
    pub fn pending_pairing_decisions(&self) -> Result<Vec<PairingDecisionIntent>> {
        Ok(records(&self.db)?.intents)
    }
    /// Historical public evidence only; never a deserialized policy approval token.
    pub fn acknowledged_workspace_grants(&self) -> Result<Vec<AcknowledgedWorkspaceGrant>> {
        Ok(records(&self.db)?.grants)
    }
    /// Reserves both count and final ACK wire bytes before admitting an approval.
    /// Unresolved requests retain this capacity until exact ACK or explicit retirement.
    pub fn prepare_pairing_decision(
        &mut self,
        preparation: PairingDecisionPreparation,
        now: u64,
    ) -> Result<PairingDecisionIntent> {
        // Persist time separately so an expired/failed action cannot roll back the
        // clock observation and make an old request eligible on a later retry.
        self.observe_authorization_clock(now)?;
        validate_preparation(&preparation)?;
        // &mut self owns the operation; the unchecked constructor only permits
        // using existing read-only Store APIs on this same IMMEDIATE transaction.
        let tx = Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        self.guard_pairing_scope(&preparation.scope, preparation.original_expires_at)?;
        let all = records(&tx)?;
        if let Some(old) = all
            .intents
            .iter()
            .find(|i| i.preparation.pairing_id == preparation.pairing_id)
        {
            if old.preparation != preparation {
                return Err(StoreError::IdempotencyConflict);
            }
            let original = old.clone();
            tx.commit()?;
            return Ok(original);
        }
        if all
            .grants
            .iter()
            .any(|g| g.intent.preparation.pairing_id == preparation.pairing_id)
            || (approves(&preparation.params)
                && all
                    .intents
                    .iter()
                    .chain(all.grants.iter().map(|g| &g.intent))
                    .any(|i| {
                        approves(&i.preparation.params)
                            && i.preparation.grant_id == preparation.grant_id
                    }))
        {
            return Err(StoreError::IdempotencyConflict);
        }
        if all.intents.len() >= MAX_PAIRING_DECISION_INTENTS
            || (approves(&preparation.params)
                && all.grants.len()
                    + all
                        .intents
                        .iter()
                        .filter(|i| approves(&i.preparation.params))
                        .count()
                    >= MAX_ACKNOWLEDGED_WORKSPACE_GRANTS)
        {
            return Err(StoreError::ResourceExhausted);
        }
        let intent = PairingDecisionIntent {
            token: Uuid::new_v4().to_string(),
            preparation,
        };
        let wire = encode(&intent)?;
        if all
            .bytes
            .saturating_add(reserved_intent_bytes(&intent, wire.len())?)
            > MAX_TOTAL_BYTES
        {
            return Err(StoreError::ResourceExhausted);
        }
        tx.execute(
            "INSERT INTO metadata(key,value) VALUES(?1,?2)",
            params![intent_key(intent.preparation.pairing_id), wire],
        )?;
        tx.commit()?;
        Ok(intent)
    }
    /// Exact request read with current durable guards. Caller still checks volatile
    /// gates, credential family, pinned transport and monotonic freshness before IO.
    pub fn pairing_decision_for_send(
        &mut self,
        expected: &PairingDecisionIntent,
        now: u64,
    ) -> Result<PairingDecisionIntent> {
        self.observe_authorization_clock(now)?;
        validate_intent(expected)?;
        let tx = Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        self.guard_pairing_scope(
            &expected.preparation.scope,
            expected.preparation.original_expires_at,
        )?;
        let all = records(&tx)?;
        let current = all
            .intents
            .into_iter()
            .find(|i| i.preparation.pairing_id == expected.preparation.pairing_id)
            .ok_or(StoreError::RevisionConflict)?;
        if current != *expected {
            return Err(StoreError::RevisionConflict);
        }
        tx.commit()?;
        Ok(current)
    }
    /// Only a caller-authenticated, exact request-associated response may enter.
    /// Approved evidence installation and pending removal commit atomically.
    pub fn acknowledge_pairing_decision(
        &mut self,
        expected: &PairingDecisionIntent,
        response: &PairingResult,
        now: u64,
    ) -> Result<Option<AcknowledgedWorkspaceGrant>> {
        self.observe_authorization_clock(now)?;
        validate_intent(expected)?;
        validate_ack(expected, response)?;
        let tx = Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        self.guard_pairing_scope(
            &expected.preparation.scope,
            expected.preparation.original_expires_at,
        )?;
        let all = records(&tx)?;
        let acknowledged = AcknowledgedWorkspaceGrant {
            intent: expected.clone(),
            response: response.clone(),
        };
        let current = all
            .intents
            .iter()
            .find(|i| i.preparation.pairing_id == expected.preparation.pairing_id);
        if current != Some(expected) {
            if current.is_none()
                && approves(&expected.preparation.params)
                && all.grants.contains(&acknowledged)
            {
                tx.commit()?;
                return Ok(Some(acknowledged));
            }
            return Err(StoreError::RevisionConflict);
        }
        let result = if approves(&expected.preparation.params) {
            if all.grants.len() >= MAX_ACKNOWLEDGED_WORKSPACE_GRANTS {
                return Err(StoreError::ResourceExhausted);
            }
            let wire = encode(&acknowledged)?;
            // records() reserves this exact final wire before any request can
            // be sent. ACK consumes that reservation regardless of ACK order.
            tx.execute(
                "INSERT INTO metadata(key,value) VALUES(?1,?2)",
                params![grant_key(expected.preparation.grant_id), wire],
            )?;
            Some(acknowledged)
        } else {
            None
        };
        tx.execute(
            "DELETE FROM metadata WHERE key=?1",
            [intent_key(expected.preparation.pairing_id)],
        )?;
        tx.commit()?;
        Ok(result)
    }
    /// Explicit reconciliation decision only. Does not revoke anything remotely,
    /// acknowledge a decision, modify consent/outbox or authorize the current owner.
    pub fn retire_pairing_decision(&mut self, expected: &PairingDecisionIntent) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let all = records(&tx)?;
        if !all.intents.iter().any(|i| i == expected) {
            return Err(StoreError::RevisionConflict);
        }
        tx.execute(
            "DELETE FROM metadata WHERE key=?1",
            [intent_key(expected.preparation.pairing_id)],
        )?;
        tx.commit()?;
        Ok(())
    }
    /// Forget historical evidence explicitly; never a cloud grant revocation ACK.
    pub fn retire_acknowledged_workspace_grant(
        &mut self,
        expected: &AcknowledgedWorkspaceGrant,
    ) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let all = records(&tx)?;
        if !all.grants.iter().any(|g| g == expected) {
            return Err(StoreError::RevisionConflict);
        }
        tx.execute(
            "DELETE FROM metadata WHERE key=?1",
            [grant_key(expected.intent.preparation.grant_id)],
        )?;
        tx.commit()?;
        Ok(())
    }
}
