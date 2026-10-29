//! Exact public channel admission evidence, never network/cryptographic authority.
//!
//! The caller independently verifies TLS/current authority, pins, canonical signed
//! bodies and their metadata, protected identities and volatile gates/freshness.
//! No policy token, ticket, private key or monotonic deadline is persisted here.
//! This journal has its own 8 MiB reserved budget; together with pairing evidence
//! the two journals are bounded to 16 MiB, without cross-journal eviction.
use super::*;
use lomi_remote_protocol::http::{
    ChannelAdmissionInputs, ChannelAdmissionParams, ChannelResult, ChannelTarget, PairingResult,
};
use std::collections::BTreeSet;

pub const MAX_CHANNEL_ADMISSION_INTENTS: usize = 64;
pub const MAX_ACKNOWLEDGED_CHANNEL_ADMISSIONS: usize = 256;
const INTENT_PREFIX: &str = "host_channel_intent:";
const ACK_PREFIX: &str = "host_channel_admission:";
const MAX_RECORD_BYTES: usize = 256 * 1024;
const MAX_TOTAL_BYTES: usize = 8 * 1024 * 1024;
const MAX_COUNTER: u64 = i64::MAX as u64;

/// Caller-verified metadata for the exact authenticated proposal and signed wire.
/// Times are absolute seconds; retries never recompute the context, nonce or TTL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelAdmissionPreparation {
    pub scope: CloudPairingScope,
    pub channel_id: ChannelId,
    pub source_grant_id: GrantId,
    /// UUID token from the exact existing acknowledged workspace grant evidence.
    pub source_grant_token: String,
    pub target: ChannelTarget,
    pub inputs: ChannelAdmissionInputs,
    pub issued_at: u64,
    pub expires_at: u64,
    pub params: ChannelAdmissionParams,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelAdmissionIntent {
    pub token: String,
    pub preparation: ChannelAdmissionPreparation,
}
/// Historical public wire evidence only, never live channel authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcknowledgedChannelAdmission {
    pub intent: ChannelAdmissionIntent,
    pub response: ChannelResult,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record<T> {
    version: u32,
    value: T,
}
#[derive(Default)]
struct Records {
    intents: Vec<ChannelAdmissionIntent>,
    acknowledged: Vec<AcknowledgedChannelAdmission>,
    // Raw evidence bytes plus every pending record's final ACK growth.
    bytes: usize,
}
fn intent_key(id: ChannelId) -> String {
    format!("{INTENT_PREFIX}{}", String::from(id))
}
fn ack_key(id: ChannelId) -> String {
    format!("{ACK_PREFIX}{}", String::from(id))
}
fn valid_token(token: &str) -> bool {
    Uuid::parse_str(token).is_ok_and(|id| id.to_string() == token)
}
fn validate_preparation(p: &ChannelAdmissionPreparation) -> Result<()> {
    let s = &p.scope;
    let a = &p.inputs.authority;
    let origin = s.runtime_scope.remote_api_origin.strip_prefix("https://");
    if !valid_token(&p.source_grant_token)
        || s.runtime_scope.owner_generation == 0
        || s.runtime_scope.remote_api_origin.len() > 2048
        || !s.runtime_scope.remote_api_origin.is_ascii()
        || s.runtime_scope
            .remote_api_origin
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        || origin.is_none_or(|v| {
            v.is_empty()
                || v.bytes()
                    .any(|b| matches!(b, b'/' | b'?' | b'#' | b'@' | b'\\' | b'%'))
        })
        || s.runtime.runtime_id != s.runtime_scope.owner_runtime_id
        || s.runtime.runtime_generation.0 == 0
        || s.runtime.runtime_generation.0 > MAX_COUNTER
        || s.runtime.host_access_epoch.0 == 0
        || s.runtime.host_access_epoch.0 > MAX_COUNTER
        || s.workspace_fence == 0
        || p.params.runtime != s.runtime
        || p.issued_at == 0
        || p.expires_at > MAX_COUNTER
        || p.expires_at <= p.issued_at
        || p.expires_at - p.issued_at > 30
        || a.runtime_id != s.runtime.runtime_id
        || a.runtime_generation != s.runtime.runtime_generation
        || a.access_epoch != s.runtime.host_access_epoch
        || a.workspace_epoch != s.workspace_epoch
        || a.grant_revision.0 == 0
        || a.grant_revision.0 > MAX_COUNTER
    {
        return Err(StoreError::Invalid);
    }
    match (&p.target, &a.terminal_membership) {
        (
            ChannelTarget::Workspace {
                workspace_id,
                workspace_epoch,
            },
            None,
        ) if *workspace_id == s.workspace_id && *workspace_epoch == s.workspace_epoch => Ok(()),
        (
            ChannelTarget::Terminal {
                workspace_id,
                workspace_epoch,
                pane_id,
                session_id,
                session_epoch,
            },
            Some(m),
        ) if *workspace_id == s.workspace_id
            && *workspace_epoch == s.workspace_epoch
            && *pane_id == m.pane_id
            && *session_id == m.session_id
            && *session_epoch == m.session_epoch =>
        {
            Ok(())
        }
        _ => Err(StoreError::Invalid),
    }
}
fn validate_intent(intent: &ChannelAdmissionIntent) -> Result<()> {
    validate_preparation(&intent.preparation)?;
    if !valid_token(&intent.token) {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
fn acknowledged(intent: &ChannelAdmissionIntent) -> AcknowledgedChannelAdmission {
    let p = &intent.preparation;
    AcknowledgedChannelAdmission {
        intent: intent.clone(),
        response: ChannelResult::Admitted {
            channel_id: p.channel_id,
            inputs: p.inputs.clone(),
            admission: p.params.admission.clone(),
        },
    }
}
fn validate_ack(intent: &ChannelAdmissionIntent, response: &ChannelResult) -> Result<()> {
    if acknowledged(intent).response != *response {
        return Err(StoreError::Fenced);
    }
    Ok(())
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
fn reserved_bytes(intent: &ChannelAdmissionIntent, raw_bytes: usize) -> Result<usize> {
    Ok(raw_bytes.max(encode(&acknowledged(intent))?.len()))
}
fn records(db: &Connection) -> Result<Records> {
    let (pending, acks, bytes, largest): (i64,i64,i64,i64) = db.query_row(
        "SELECT COALESCE(sum(key GLOB 'host_channel_intent:*'),0),COALESCE(sum(key GLOB 'host_channel_admission:*'),0),COALESCE(sum(length(CAST(value AS BLOB))),0),COALESCE(max(length(CAST(value AS BLOB))),0) FROM metadata WHERE key GLOB 'host_channel_intent:*' OR key GLOB 'host_channel_admission:*'",
        [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    if pending < 0
        || acks < 0
        || bytes < 0
        || pending > MAX_CHANNEL_ADMISSION_INTENTS as i64
        || pending + acks > MAX_ACKNOWLEDGED_CHANNEL_ADMISSIONS as i64
        || bytes > MAX_TOTAL_BYTES as i64
        || largest > MAX_RECORD_BYTES as i64
    {
        return Err(StoreError::Storage);
    }
    let mut out = Records {
        bytes: bytes as usize,
        ..Records::default()
    };
    let mut query = db.prepare("SELECT key,value FROM metadata WHERE key GLOB 'host_channel_intent:*' OR key GLOB 'host_channel_admission:*' ORDER BY key")?;
    for row in query.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
        let (key, wire) = row?;
        if key.starts_with(INTENT_PREFIX) {
            let intent: ChannelAdmissionIntent = decode_record(&wire)?;
            validate_intent(&intent).map_err(|_| StoreError::Storage)?;
            if key != intent_key(intent.preparation.channel_id) {
                return Err(StoreError::Storage);
            }
            out.bytes = out.bytes.saturating_add(
                reserved_bytes(&intent, wire.len()).map_err(|_| StoreError::Storage)? - wire.len(),
            );
            if out.bytes > MAX_TOTAL_BYTES {
                return Err(StoreError::Storage);
            }
            out.intents.push(intent);
        } else {
            let ack: AcknowledgedChannelAdmission = decode_record(&wire)?;
            validate_intent(&ack.intent).map_err(|_| StoreError::Storage)?;
            validate_ack(&ack.intent, &ack.response).map_err(|_| StoreError::Storage)?;
            if key != ack_key(ack.intent.preparation.channel_id) {
                return Err(StoreError::Storage);
            }
            out.acknowledged.push(ack);
        }
    }
    let identity: Identity = decode(&db.query_row::<String, _, _>(
        "SELECT value FROM metadata WHERE key='identity'",
        [],
        |r| r.get(0),
    )?)?;
    let mut tokens = BTreeSet::new();
    let mut channels = BTreeSet::new();
    for intent in out
        .intents
        .iter()
        .chain(out.acknowledged.iter().map(|ack| &ack.intent))
    {
        if !tokens.insert(&intent.token)
            || !channels.insert(intent.preparation.channel_id)
            || intent.preparation.scope.runtime_scope.host_id != identity.host_id
        {
            return Err(StoreError::Storage);
        }
    }
    Ok(out)
}
impl HostStore {
    fn guard_channel_preparation(&self, p: &ChannelAdmissionPreparation) -> Result<()> {
        self.guard_pairing_scope(&p.scope, p.expires_at)?;
        let now = checked_authorization_generation(
            &self.db,
            p.scope.runtime_scope.authorization_generation,
        )?
        .clock_floor;
        if p.issued_at > now {
            return Err(StoreError::Fenced);
        }
        let source = self
            .acknowledged_workspace_grants()?
            .into_iter()
            .find(|g| {
                g.intent.token == p.source_grant_token
                    && g.intent.preparation.grant_id == p.source_grant_id
            })
            .ok_or(StoreError::Fenced)?;
        let original = &source.intent.preparation;
        let PairingResult::Approved {
            grant,
            identities,
            authority,
            ..
        } = &source.response
        else {
            return Err(StoreError::Storage);
        };
        let mut current = p.inputs.authority.clone();
        current.terminal_membership = None;
        if original.scope != p.scope
            || p.expires_at > original.original_expires_at
            || p.inputs.grant != *grant
            || p.inputs.identities != *identities
            || current != *authority
        {
            return Err(StoreError::Fenced);
        }
        let state = self
            .cloud_runtime_state(&p.scope.runtime_scope)?
            .ok_or(StoreError::Fenced)?;
        let published = self
            .acknowledged_host_publication(&state)?
            .ok_or(StoreError::Fenced)?;
        let workspace = published
            .workspaces
            .as_slice()
            .iter()
            .find(|w| {
                w.workspace_id == p.scope.workspace_id
                    && w.workspace_epoch == p.scope.workspace_epoch
            })
            .ok_or(StoreError::Fenced)?;
        if let ChannelTarget::Terminal {
            pane_id,
            session_id,
            session_epoch,
            ..
        } = &p.target
        {
            if !workspace.terminals.as_slice().iter().any(|t| {
                t.pane_id == *pane_id
                    && t.session_id == *session_id
                    && t.session_epoch == *session_epoch
            }) {
                return Err(StoreError::Fenced);
            }
            let local = project(&self.db, p.scope.workspace_id)?;
            let mut stack: Vec<_> = local.state.tabs.0.iter().map(|tab| &tab.layout).collect();
            let mut found = false;
            while let Some(layout) = stack.pop() {
                match layout {
                    TerminalLayout::Split { first, second, .. } => {
                        stack.push(first);
                        stack.push(second);
                    }
                    TerminalLayout::Pane { pane }
                        if pane.pane_id == *pane_id && pane.state == PaneState::Running =>
                    {
                        found = pane.session.as_ref().is_some_and(|s| {
                            s.session_id == *session_id
                                && s.session_epoch == *session_epoch
                                && s.workspace == local.state.context
                                && s.pane_id == *pane_id
                                && p.inputs
                                    .authority
                                    .terminal_membership
                                    .as_ref()
                                    .is_some_and(|m| m.terminal_profile == s.profile)
                        });
                    }
                    TerminalLayout::Pane { .. } => (),
                }
            }
            let running: bool = self.db.query_row("SELECT EXISTS(SELECT 1 FROM terminals WHERE workspace=?1 AND pane=?2 AND status='Running')",params![key(p.scope.workspace_id),key(*pane_id)],|r|r.get(0))?;
            if !found || !running {
                return Err(StoreError::Fenced);
            }
        }
        Ok(())
    }
    /// Historical reconciliation evidence; does not look up or revive the source grant.
    pub fn pending_channel_admissions(&self) -> Result<Vec<ChannelAdmissionIntent>> {
        Ok(records(&self.db)?.intents)
    }
    pub fn acknowledged_channel_admissions(&self) -> Result<Vec<AcknowledgedChannelAdmission>> {
        Ok(records(&self.db)?.acknowledged)
    }
    /// Reserves count and the complete final ACK record before the request is sendable.
    pub fn prepare_channel_admission(
        &mut self,
        preparation: ChannelAdmissionPreparation,
        now: u64,
    ) -> Result<ChannelAdmissionIntent> {
        self.observe_authorization_clock(now)?;
        validate_preparation(&preparation)?;
        let tx = Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        self.guard_channel_preparation(&preparation)?;
        let all = records(&tx)?;
        if let Some(old) = all
            .intents
            .iter()
            .find(|i| i.preparation.channel_id == preparation.channel_id)
        {
            if old.preparation != preparation {
                return Err(StoreError::IdempotencyConflict);
            }
            let old = old.clone();
            tx.commit()?;
            return Ok(old);
        }
        if all
            .acknowledged
            .iter()
            .any(|a| a.intent.preparation.channel_id == preparation.channel_id)
        {
            return Err(StoreError::IdempotencyConflict);
        }
        if all.intents.len() >= MAX_CHANNEL_ADMISSION_INTENTS
            || all.intents.len() + all.acknowledged.len() >= MAX_ACKNOWLEDGED_CHANNEL_ADMISSIONS
        {
            return Err(StoreError::ResourceExhausted);
        }
        let intent = ChannelAdmissionIntent {
            token: Uuid::new_v4().to_string(),
            preparation,
        };
        let wire = encode(&intent)?;
        if all
            .bytes
            .saturating_add(reserved_bytes(&intent, wire.len())?)
            > MAX_TOTAL_BYTES
        {
            return Err(StoreError::ResourceExhausted);
        }
        tx.execute(
            "INSERT INTO metadata(key,value) VALUES(?1,?2)",
            params![intent_key(intent.preparation.channel_id), wire],
        )?;
        tx.commit()?;
        Ok(intent)
    }
    /// Caller must also recheck fresh credentials, monotonic lease and volatile gates before IO.
    pub fn channel_admission_for_send(
        &mut self,
        expected: &ChannelAdmissionIntent,
        now: u64,
    ) -> Result<ChannelAdmissionIntent> {
        self.observe_authorization_clock(now)?;
        validate_intent(expected)?;
        let tx = Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        self.guard_channel_preparation(&expected.preparation)?;
        let all = records(&tx)?;
        if !all.intents.contains(expected) {
            return Err(StoreError::RevisionConflict);
        }
        tx.commit()?;
        Ok(expected.clone())
    }
    /// Accept only the authenticated response associated with this exact request.
    pub fn acknowledge_channel_admission(
        &mut self,
        expected: &ChannelAdmissionIntent,
        response: &ChannelResult,
        now: u64,
    ) -> Result<AcknowledgedChannelAdmission> {
        self.observe_authorization_clock(now)?;
        validate_intent(expected)?;
        validate_ack(expected, response)?;
        let tx = Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        self.guard_channel_preparation(&expected.preparation)?;
        let all = records(&tx)?;
        let ack = acknowledged(expected);
        if !all.intents.contains(expected) {
            if all.acknowledged.contains(&ack) {
                tx.commit()?;
                return Ok(ack);
            }
            return Err(StoreError::RevisionConflict);
        }
        let wire = encode(&ack)?; // Exact final wire was reserved before prepare committed.
        tx.execute(
            "INSERT INTO metadata(key,value) VALUES(?1,?2)",
            params![ack_key(expected.preparation.channel_id), wire],
        )?;
        tx.execute(
            "DELETE FROM metadata WHERE key=?1",
            [intent_key(expected.preparation.channel_id)],
        )?;
        tx.commit()?;
        Ok(ack)
    }
    /// Explicit historical retirement, not a remote close/revoke or admission ACK.
    pub fn retire_channel_admission(&mut self, expected: &ChannelAdmissionIntent) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !records(&tx)?.intents.contains(expected) {
            return Err(StoreError::RevisionConflict);
        }
        tx.execute(
            "DELETE FROM metadata WHERE key=?1",
            [intent_key(expected.preparation.channel_id)],
        )?;
        tx.commit()?;
        Ok(())
    }
    /// Forget exact historical evidence; grants no replacement channel authority.
    pub fn retire_acknowledged_channel_admission(
        &mut self,
        expected: &AcknowledgedChannelAdmission,
    ) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !records(&tx)?.acknowledged.contains(expected) {
            return Err(StoreError::RevisionConflict);
        }
        tx.execute(
            "DELETE FROM metadata WHERE key=?1",
            [ack_key(expected.intent.preparation.channel_id)],
        )?;
        tx.commit()?;
        Ok(())
    }
}
