use crate::{
    Capability, CapabilitySet, ConsumerAuthorizationId, Method, MethodRights, OperationId,
    WorkspaceId, is_git_mutation,
};

/// Trusted storage projection, never a request DTO. Construct only from an
/// independently authenticated actor and the rights recorded at admission.
///
/// ```compile_fail
/// use lomi_remote_protocol::StoredOperationRights;
/// let _: StoredOperationRights = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct StoredOperationRights {
    operation_id: OperationId,
    actor: ConsumerAuthorizationId,
    workspace: WorkspaceId,
    original_method: Method,
    actual_rights: CapabilitySet,
    repository_execution: bool,
}
impl StoredOperationRights {
    pub fn new(
        operation_id: OperationId,
        actor: ConsumerAuthorizationId,
        workspace: WorkspaceId,
        original_method: Method,
        actual_rights: CapabilitySet,
        repository_execution: bool,
    ) -> Result<Self, &'static str> {
        let MethodRights::Static(required) = original_method.rights() else {
            return Err("INVALID_ARGUMENT");
        };
        if repository_execution && !is_git_mutation(original_method.as_str()) {
            return Err("INVALID_ARGUMENT");
        }
        if required.iter().any(|right| !actual_rights.contains(*right)) {
            return Err("SCOPE_DENIED");
        }
        if repository_execution && !actual_rights.contains(Capability::GitExecute) {
            return Err("REPOSITORY_EXECUTION_REQUIRED");
        }
        // Retain only rights actually needed by this operation, not the whole
        // admitting grant. Unrelated later revocation must not hide its receipt.
        let mut effective = required.to_vec();
        if repository_execution {
            effective.push(Capability::GitExecute);
        }
        let actual_rights = CapabilitySet::try_from(effective)?;
        Ok(Self {
            operation_id,
            actor,
            workspace,
            original_method,
            actual_rights,
            repository_execution,
        })
    }
    pub fn original_method(&self) -> Method {
        self.original_method
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationAuthorizationError {
    /// Deliberately identical for absent records and foreign actor/workspace.
    NotFound,
    ScopeDenied,
    InvalidMethod,
}
impl CapabilitySet {
    /// Capability/binding check only. Caller supplies trusted current actor and
    /// workspace and an independently read storage record, never request claims.
    /// No receipt, state, tombstone or other existence information may be exposed
    /// before this succeeds. Freshness, fences and effects remain caller duties.
    pub fn authorize_operation(
        &self,
        method: Method,
        operation_id: OperationId,
        actor: ConsumerAuthorizationId,
        workspace: WorkspaceId,
        stored: Option<&StoredOperationRights>,
    ) -> Result<(), OperationAuthorizationError> {
        if !matches!(method, Method::OperationStatus | Method::OperationCancel) {
            return Err(OperationAuthorizationError::InvalidMethod);
        }
        let stored = stored
            .filter(|record| {
                record.operation_id == operation_id
                    && record.actor == actor
                    && record.workspace == workspace
            })
            .ok_or(OperationAuthorizationError::NotFound)?;
        if !self.contains(Capability::WorkspaceRead)
            || stored
                .actual_rights
                .0
                .iter()
                .any(|right| !self.contains(*right))
        {
            return Err(OperationAuthorizationError::ScopeDenied);
        }
        Ok(())
    }
}

use crate::{DecimalU64, Effect, InputBytes, SessionEpoch, TerminalSessionId, WorkspaceContext};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};

/// Explicit list: reads, operation lookup and ephemeral terminal I/O are excluded.
pub fn is_durable_mutation(method: Method) -> bool {
    matches!(
        method,
        Method::TerminalCreate
            | Method::TerminalSplit
            | Method::TerminalRename
            | Method::TerminalMove
            | Method::TerminalClose
            | Method::TerminalRestart
            | Method::FilesCreate
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
impl StoredOperationRights {
    pub fn operation_id(&self) -> OperationId {
        self.operation_id
    }
    pub fn actor(&self) -> ConsumerAuthorizationId {
        self.actor
    }
    pub fn workspace(&self) -> WorkspaceId {
        self.workspace
    }
    pub fn actual_rights(&self) -> &CapabilitySet {
        &self.actual_rights
    }
    pub fn repository_execution(&self) -> bool {
        self.repository_execution
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationStatusParams {
    pub context: WorkspaceContext,
    pub operation_id: OperationId,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationCancelParams {
    pub context: WorkspaceContext,
    pub operation_id: OperationId,
}
/// Status lookup route within the authenticated workspace channel. Never a URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationLookup {
    pub workspace_id: WorkspaceId,
    pub operation_id: OperationId,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Accepted,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    OutcomeUnknown,
}
impl OperationState {
    pub fn is_final(self) -> bool {
        !matches!(self, Self::Accepted | Self::Running)
    }
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Accepted,
                Self::Running | Self::Cancelled | Self::Failed
            ) | (
                Self::Running,
                Self::Succeeded | Self::Failed | Self::Cancelled | Self::OutcomeUnknown
            )
        )
    }
}
/// Parameter digest only, never used for terminal input. Lowercase SHA-256 hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OperationParameterHash(String);
impl TryFrom<String> for OperationParameterHash {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            Ok(Self(value))
        } else {
            Err("expected SHA-256 lowercase hex")
        }
    }
}
impl JsonSchema for OperationParameterHash {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "OperationParameterHash".into()
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({"type":"string","minLength":64,"maxLength":64,"pattern":"^[0-9a-f]{64}$"})
    }
}
impl From<OperationParameterHash> for String {
    fn from(value: OperationParameterHash) -> Self {
        value.0
    }
}
/// Only identifiers/revisions, no names, paths, commands or cached plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum OperationResult {
    Domain {
        #[serde(rename = "domainRevision")]
        domain_revision: DecimalU64,
    },
    Terminal {
        #[serde(rename = "domainRevision")]
        domain_revision: DecimalU64,
        #[serde(rename = "paneId")]
        pane_id: crate::PaneId,
        #[serde(rename = "sessionId")]
        session_id: TerminalSessionId,
        #[serde(rename = "sessionEpoch")]
        session_epoch: SessionEpoch,
    },
    File {
        #[serde(rename = "entryId")]
        entry_id: crate::EntryId,
        #[serde(rename = "fileRevision")]
        file_revision: crate::FileRevision,
    },
    Git {
        #[serde(rename = "repoStateToken")]
        repo_state_token: crate::RepoStateToken,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReceiptWire {
    operation_id: OperationId,
    actor: ConsumerAuthorizationId,
    workspace_id: WorkspaceId,
    original_method: Method,
    actual_rights: CapabilitySet,
    repository_execution: bool,
    parameter_hash: OperationParameterHash,
    state: OperationState,
    cancel_requested: bool,
    effect: Effect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    result: Option<OperationResult>,
}
/// Validated receipt DTO, not proof of persistence, admission, authority or fencing.
/// A consumer must authenticate current rights and row binding before disclosure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "ReceiptWire", into = "ReceiptWire")]
pub struct OperationReceipt(ReceiptWire);
impl TryFrom<ReceiptWire> for OperationReceipt {
    type Error = &'static str;
    fn try_from(mut wire: ReceiptWire) -> Result<Self, Self::Error> {
        if !is_durable_mutation(wire.original_method) {
            return Err("durable receipt requires durable mutation");
        }
        let stored = StoredOperationRights::new(
            wire.operation_id,
            wire.actor,
            wire.workspace_id,
            wire.original_method,
            wire.actual_rights.clone(),
            wire.repository_execution,
        )?;
        wire.actual_rights = stored.actual_rights;
        let valid_effect = match wire.state {
            OperationState::Accepted | OperationState::Running | OperationState::Cancelled => {
                wire.effect == Effect::None
            }
            OperationState::Succeeded => wire.effect == Effect::Committed,
            OperationState::Failed => matches!(
                wire.effect,
                Effect::None | Effect::Partial | Effect::Committed
            ),
            OperationState::OutcomeUnknown => wire.effect == Effect::Unknown,
        };
        if !valid_effect {
            return Err("effect does not match operation state");
        }
        if wire.state == OperationState::Succeeded && wire.result.is_none() {
            return Err("success requires minimal result");
        }
        if matches!(wire.effect, Effect::Partial | Effect::Committed) && wire.result.is_none() {
            return Err("known effect requires minimal result");
        }
        if matches!(
            wire.state,
            OperationState::Accepted | OperationState::Running | OperationState::Cancelled
        ) && wire.result.is_some()
        {
            return Err("uncommitted state cannot claim result");
        }
        if let Some(result) = &wire.result {
            let matches_method = match result {
                OperationResult::Domain { .. } => matches!(
                    wire.original_method,
                    Method::TerminalRename | Method::TerminalMove | Method::TerminalClose
                ),
                OperationResult::Terminal { .. } => matches!(
                    wire.original_method,
                    Method::TerminalCreate | Method::TerminalSplit | Method::TerminalRestart
                ),
                OperationResult::File { .. } => matches!(
                    wire.original_method,
                    Method::FilesCreate
                        | Method::FilesMkdir
                        | Method::FilesRename
                        | Method::FilesRemove
                ),
                OperationResult::Git { .. } => is_git_mutation(wire.original_method.as_str()),
            };
            if !matches_method {
                return Err("result does not match original method");
            }
        }
        Ok(Self(wire))
    }
}
impl From<OperationReceipt> for ReceiptWire {
    fn from(value: OperationReceipt) -> Self {
        value.0
    }
}
impl OperationReceipt {
    pub fn new(
        rights: &StoredOperationRights,
        parameter_hash: OperationParameterHash,
        state: OperationState,
        cancel_requested: bool,
        effect: Effect,
        result: Option<OperationResult>,
    ) -> Result<Self, &'static str> {
        ReceiptWire {
            operation_id: rights.operation_id,
            actor: rights.actor,
            workspace_id: rights.workspace,
            original_method: rights.original_method,
            actual_rights: rights.actual_rights.clone(),
            repository_execution: rights.repository_execution,
            parameter_hash,
            state,
            cancel_requested,
            effect,
            result,
        }
        .try_into()
    }
    pub fn state(&self) -> OperationState {
        self.0.state
    }
    pub fn effect(&self) -> Effect {
        self.0.effect
    }
    pub fn cancel_requested(&self) -> bool {
        self.0.cancel_requested
    }
    pub fn result(&self) -> Option<&OperationResult> {
        self.0.result.as_ref()
    }
    pub fn operation_id(&self) -> OperationId {
        self.0.operation_id
    }
    pub fn stored_rights(&self) -> StoredOperationRights {
        StoredOperationRights::new(
            self.0.operation_id,
            self.0.actor,
            self.0.workspace_id,
            self.0.original_method,
            self.0.actual_rights.clone(),
            self.0.repository_execution,
        )
        .expect("validated receipt")
    }
    /// Check externally authenticated binding before exposing this DTO.
    pub fn authorize_disclosure(
        &self,
        current: &CapabilitySet,
        actor: ConsumerAuthorizationId,
        workspace: WorkspaceId,
    ) -> Result<(), OperationAuthorizationError> {
        current.authorize_operation(
            Method::OperationStatus,
            self.0.operation_id,
            actor,
            workspace,
            Some(&self.stored_rights()),
        )
    }
}
/// A retained tombstone does not imply that the original operation had no effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TombstoneWire {
    operation_id: OperationId,
    actor: ConsumerAuthorizationId,
    workspace_id: WorkspaceId,
    original_method: Method,
    actual_rights: CapabilitySet,
    repository_execution: bool,
}
/// A validated privacy-minimal projection retained after final receipt eviction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "TombstoneWire", into = "TombstoneWire")]
pub struct OperationTombstone(TombstoneWire);
impl TryFrom<TombstoneWire> for OperationTombstone {
    type Error = &'static str;
    fn try_from(mut wire: TombstoneWire) -> Result<Self, Self::Error> {
        if !is_durable_mutation(wire.original_method) {
            return Err("tombstone requires durable mutation");
        }
        let stored = StoredOperationRights::new(
            wire.operation_id,
            wire.actor,
            wire.workspace_id,
            wire.original_method,
            wire.actual_rights.clone(),
            wire.repository_execution,
        )?;
        wire.actual_rights = stored.actual_rights;
        Ok(Self(wire))
    }
}
impl From<OperationTombstone> for TombstoneWire {
    fn from(value: OperationTombstone) -> Self {
        value.0
    }
}
impl OperationTombstone {
    pub fn from_receipt(receipt: &OperationReceipt) -> Result<Self, &'static str> {
        if !receipt.state().is_final() {
            return Err("unfinished intent cannot expire");
        }
        let r = &receipt.0;
        Ok(Self(TombstoneWire {
            operation_id: r.operation_id,
            actor: r.actor,
            workspace_id: r.workspace_id,
            original_method: r.original_method,
            actual_rights: r.actual_rights.clone(),
            repository_execution: r.repository_execution,
        }))
    }
    pub fn authorize_disclosure(
        &self,
        current: &CapabilitySet,
        actor: ConsumerAuthorizationId,
        workspace: WorkspaceId,
    ) -> Result<(), OperationAuthorizationError> {
        let rights = StoredOperationRights::new(
            self.0.operation_id,
            self.0.actor,
            self.0.workspace_id,
            self.0.original_method,
            self.0.actual_rights.clone(),
            self.0.repository_execution,
        )
        .map_err(|_| OperationAuthorizationError::NotFound)?;
        current.authorize_operation(
            Method::OperationStatus,
            self.0.operation_id,
            actor,
            workspace,
            Some(&rights),
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InputReceiptWire {
    session_id: TerminalSessionId,
    session_epoch: SessionEpoch,
    input_id: DecimalU64,
    input_seq: DecimalU64,
    submitted_bytes: InputBytes,
    accepted_bytes: InputBytes,
}
/// Ephemeral receipt in session-epoch RAM only. No input bytes or keystroke hash.
/// Acceptance counts PTY bytes; it does not mean shell execution or permit replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "InputReceiptWire", into = "InputReceiptWire")]
pub struct InputReceipt(InputReceiptWire);
impl TryFrom<InputReceiptWire> for InputReceipt {
    type Error = &'static str;
    fn try_from(wire: InputReceiptWire) -> Result<Self, Self::Error> {
        if wire.accepted_bytes.get() > wire.submitted_bytes.get() {
            return Err("accepted bytes exceed submitted bytes");
        }
        Ok(Self(wire))
    }
}
impl From<InputReceipt> for InputReceiptWire {
    fn from(value: InputReceipt) -> Self {
        value.0
    }
}
impl InputReceipt {
    pub fn new(
        session_id: TerminalSessionId,
        session_epoch: SessionEpoch,
        input_id: DecimalU64,
        input_seq: DecimalU64,
        submitted_bytes: InputBytes,
        accepted_bytes: InputBytes,
    ) -> Result<Self, &'static str> {
        InputReceiptWire {
            session_id,
            session_epoch,
            input_id,
            input_seq,
            submitted_bytes,
            accepted_bytes,
        }
        .try_into()
    }
    /// Correlate a response with the exact original input request. Never replay it.
    pub fn validate_binding(
        &self,
        session_id: TerminalSessionId,
        session_epoch: SessionEpoch,
        input_id: DecimalU64,
        input_seq: DecimalU64,
        submitted_bytes: InputBytes,
    ) -> Result<(), &'static str> {
        if self.0.session_id != session_id
            || self.0.session_epoch != session_epoch
            || self.0.input_id != input_id
            || self.0.input_seq != input_seq
            || self.0.submitted_bytes != submitted_bytes
        {
            return Err("input receipt binding mismatch");
        }
        Ok(())
    }
    pub fn accepted_bytes(&self) -> InputBytes {
        self.0.accepted_bytes
    }
}
